//! Bytes relayed per kernel process, and the stats socket `noded` reads
//! them from.
//!
//! A flow is counted against the process that connected (`SO_PEERCRED`),
//! named by its process id and its start time (field 22 of
//! `/proc/PID/stat`, clock ticks since boot): the pair names one process
//! for the life of the host, where a process id alone is reused. The
//! sandbox id in the flow header is not used: the connecting process
//! chooses it, and one kernel process serves one sandbox. Bytes are added
//! as they are relayed, so a counter grows while its flows run; it never
//! goes down.
//!
//! The stats socket (`--stats PATH`, apart from the flow socket and in a
//! directory of its own, so a kernel process does not see it) answers one
//! question per connection:
//!
//! ```text
//! -> TOKEN\n
//! -> PID:START PID:START ...\n          (at most 4096)
//! <- PID:START SENT RECEIVED\n          (one line per key asked, 0 0 when unknown)
//! <- .\n
//! ```
//!
//! `SENT` are the bytes delivered upstream, `RECEIVED` those delivered to
//! the kernel process. The token (`--stats-token-file`) keeps a kernel
//! process that can reach the socket anyway (a host without mount
//! namespaces) from learning other sandboxes' traffic.

use std::collections::{HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Most processes counted at once. When it is full, the entries of
/// processes that ended are dropped, the longest idle first (a process
/// that still runs keeps its counter, flows or not: dropping it would
/// start its count again from zero).
pub const MAX_PEERS: usize = 16384;
/// Most keys in one question.
pub const MAX_KEYS: usize = 4096;
/// Longest question line, in bytes.
const MAX_LINE: usize = 128 * 1024;
/// Time allowed for a question.
const QUESTION_TIMEOUT: Duration = Duration::from_secs(2);
/// Questions answered at once.
const MAX_QUESTIONS: usize = 8;

/// One process, for the life of the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    pub pid: u32,
    /// Clock ticks since boot when it started.
    pub start: u64,
}

impl Key {
    /// The key of a running process, from `/proc`.
    pub fn of(pid: u32) -> Option<Key> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        Some(Key {
            pid,
            start: start_ticks(&stat)?,
        })
    }

    fn parse(text: &str) -> Option<Key> {
        let (pid, start) = text.split_once(':')?;
        Some(Key {
            pid: pid.parse().ok()?,
            start: start.parse().ok()?,
        })
    }
}

/// Field 22 (`starttime`) of a `/proc/PID/stat` line. The command name
/// (field 2) may hold spaces and parentheses, so fields are counted after
/// its last `)`.
pub fn start_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // After `)`: field 3 is the first; 22 is the twentieth.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// One process's bytes.
#[derive(Debug)]
pub struct PeerBytes {
    pub sent: AtomicU64,
    pub received: AtomicU64,
    /// Milliseconds since the table's start of the last flow that began.
    last: AtomicU64,
}

/// The counters of every process with flows.
pub struct Usage {
    start: Instant,
    peers: Mutex<HashMap<Key, Arc<PeerBytes>>>,
}

impl Default for Usage {
    fn default() -> Usage {
        Usage {
            start: Instant::now(),
            peers: Mutex::new(HashMap::new()),
        }
    }
}

impl Usage {
    /// The counter for flows of `key`; `None` when the table is full of
    /// processes that still run (the flow is relayed, not counted).
    pub fn counter(&self, key: Key) -> Option<Arc<PeerBytes>> {
        let now = self.start.elapsed().as_millis() as u64;
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if !peers.contains_key(&key) && peers.len() >= MAX_PEERS {
            // Drop up to half: those whose process ended (so no flow of
            // theirs runs), the longest idle first. Their last values were
            // read long ago.
            let mut idle: Vec<(u64, Key)> = peers
                .iter()
                .filter(|(k, c)| Arc::strong_count(c) == 1 && Key::of(k.pid) != Some(**k))
                .map(|(k, c)| (c.last.load(Ordering::Relaxed), *k))
                .collect();
            idle.sort_unstable();
            for (_, k) in idle.iter().take(MAX_PEERS / 2) {
                peers.remove(k);
            }
            if peers.len() >= MAX_PEERS {
                return None;
            }
        }
        let counter = peers.entry(key).or_insert_with(|| {
            Arc::new(PeerBytes {
                sent: AtomicU64::new(0),
                received: AtomicU64::new(0),
                last: AtomicU64::new(now),
            })
        });
        counter.last.store(now, Ordering::Relaxed);
        Some(Arc::clone(counter))
    }

    /// Bytes sent and received by `key`'s flows; zeros when unknown.
    pub fn get(&self, key: Key) -> (u64, u64) {
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        peers.get(&key).map_or((0, 0), |c| {
            (
                c.sent.load(Ordering::Relaxed),
                c.received.load(Ordering::Relaxed),
            )
        })
    }

    /// Answers one question on `conn` (see the module documentation).
    pub fn answer(&self, conn: UnixStream, token: &str) -> io::Result<()> {
        self.answer_then(conn, token, || {})
    }

    /// As [`Usage::answer`]; `authenticated` runs once the token was
    /// presented.
    fn answer_then(
        &self,
        conn: UnixStream,
        token: &str,
        authenticated: impl FnOnce(),
    ) -> io::Result<()> {
        conn.set_read_timeout(Some(QUESTION_TIMEOUT))?;
        conn.set_write_timeout(Some(QUESTION_TIMEOUT))?;
        let mut reader = BufReader::new((&conn).take(MAX_LINE as u64 * 2));
        let line = |reader: &mut BufReader<_>| -> io::Result<String> {
            let mut buf = Vec::new();
            (&mut *reader)
                .take(MAX_LINE as u64)
                .read_until(b'\n', &mut buf)?;
            if buf.pop() != Some(b'\n') {
                return Err(io::ErrorKind::InvalidData.into());
            }
            String::from_utf8(buf).map_err(|_| io::ErrorKind::InvalidData.into())
        };
        let presented = line(&mut reader)?;
        if !same(presented.as_bytes(), token.as_bytes()) {
            let _ = (&conn).write_all(b"denied\n");
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        authenticated();
        let keys = line(&mut reader)?;
        let mut out = String::new();
        for (n, text) in keys.split_ascii_whitespace().enumerate() {
            if n >= MAX_KEYS {
                break;
            }
            let Some(key) = Key::parse(text) else {
                return Err(io::ErrorKind::InvalidData.into());
            };
            let (sent, received) = self.get(key);
            out.push_str(&format!("{}:{} {sent} {received}\n", key.pid, key.start));
        }
        out.push_str(".\n");
        (&conn).write_all(out.as_bytes())
    }
}

fn lock_waiting(
    waiting: &Mutex<VecDeque<(u64, UnixStream)>>,
) -> std::sync::MutexGuard<'_, VecDeque<(u64, UnixStream)>> {
    waiting.lock().unwrap_or_else(|e| e.into_inner())
}

/// Compares in time that depends on the lengths only.
fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Serves the stats socket at `path` on a thread of its own, until the
/// process ends. A stale socket file is replaced; any other file is an
/// error.
pub fn serve_stats(usage: Arc<Usage>, path: &Path, token: String) -> io::Result<PathBuf> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() || UnixStream::connect(path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a stale socket", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    let busy = Arc::new(AtomicUsize::new(0));
    // Connections that have not presented the token yet, oldest first.
    let waiting: Arc<Mutex<VecDeque<(u64, UnixStream)>>> = Arc::new(Mutex::new(VecDeque::new()));
    let token = Arc::new(token);
    thread::Builder::new()
        .name("egress-stats".into())
        .spawn(move || {
            let mut next = 0u64;
            for conn in listener.incoming() {
                let Ok(conn) = conn else {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                };
                if busy.load(Ordering::SeqCst) >= MAX_QUESTIONS {
                    // Room is made at the cost of whoever has waited
                    // longest without the token, so that connections which
                    // never present it cannot keep `noded` out. With every
                    // place taken by an authenticated question, this one
                    // is dropped.
                    let oldest = lock_waiting(&waiting).pop_front();
                    match oldest {
                        Some((_, old)) => {
                            let _ = old.shutdown(std::net::Shutdown::Both);
                        }
                        None => continue,
                    }
                }
                let Ok(handle) = conn.try_clone() else {
                    continue;
                };
                let id = next;
                next += 1;
                lock_waiting(&waiting).push_back((id, handle));
                busy.fetch_add(1, Ordering::SeqCst);
                let (usage, token, done, waiting2) = (
                    Arc::clone(&usage),
                    Arc::clone(&token),
                    Arc::clone(&busy),
                    Arc::clone(&waiting),
                );
                let forget = move |waiting: &Mutex<VecDeque<(u64, UnixStream)>>| {
                    lock_waiting(waiting).retain(|(i, _)| *i != id);
                };
                let spawned = thread::Builder::new()
                    .name("egress-stats-answer".into())
                    .spawn(move || {
                        let _ = usage.answer_then(conn, &token, || forget(&waiting2));
                        forget(&waiting2);
                        done.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    lock_waiting(&waiting).retain(|(i, _)| *i != id);
                    busy.fetch_sub(1, Ordering::SeqCst);
                }
            }
        })?;
    Ok(path.to_path_buf())
}

/// Asks the stats socket at `path` for the bytes of `keys` (at most
/// [`MAX_KEYS`]): `(key, sent, received)` for each, in the order the
/// proxy answered. What `noded` calls.
pub fn ask(
    path: &Path,
    token: &str,
    keys: &[Key],
    timeout: Duration,
) -> io::Result<Vec<(Key, u64, u64)>> {
    let conn = UnixStream::connect(path)?;
    conn.set_read_timeout(Some(timeout))?;
    conn.set_write_timeout(Some(timeout))?;
    let mut question = format!("{token}\n");
    for key in keys.iter().take(MAX_KEYS) {
        question.push_str(&format!("{}:{} ", key.pid, key.start));
    }
    question.push('\n');
    (&conn).write_all(question.as_bytes())?;
    // At most one line of three numbers per key, and the end.
    let limit = (keys.len().min(MAX_KEYS) as u64 + 1) * 80;
    let mut reader = BufReader::new((&conn).take(limit));
    let mut out = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let line = line.trim_end_matches('\n');
        if line == "." {
            return Ok(out);
        }
        let mut parts = line.split(' ');
        let parsed = (|| {
            let key = Key::parse(parts.next()?)?;
            let sent = parts.next()?.parse().ok()?;
            let received = parts.next()?.parse().ok()?;
            parts.next().is_none().then_some((key, sent, received))
        })();
        match parsed {
            Some(entry) if out.len() < keys.len() => out.push(entry),
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_ticks_skip_the_command_name() {
        let stat = "4711 (a) b (c)) S 1 4711 4711 0 -1 4194304 1 0 0 0 7 3 0 0 20 0 1 0 98765 1 2";
        assert_eq!(start_ticks(stat), Some(98765));
        assert_eq!(start_ticks("1 (x) S 1"), None);
        assert_eq!(start_ticks("no parenthesis"), None);
        let me = Key::of(std::process::id());
        #[cfg(target_os = "linux")]
        assert!(me.is_some_and(|k| k.start > 0));
        let _ = me;
    }

    #[test]
    fn counters_grow_and_the_table_is_bounded() {
        let usage = Usage::default();
        let a = Key { pid: 1, start: 2 };
        let c = usage.counter(a).unwrap();
        c.sent.fetch_add(10, Ordering::Relaxed);
        c.received.fetch_add(5, Ordering::Relaxed);
        assert_eq!(usage.get(a), (10, 5));
        assert_eq!(
            usage.get(Key { pid: 1, start: 3 }),
            (0, 0),
            "another process"
        );
        drop(c);
        // Full of processes that ended: room is made. (No process has
        // these start times.)
        for pid in 2..(MAX_PEERS as u32 + 10) {
            assert!(usage.counter(Key { pid, start: 1 }).is_some());
        }
        assert!(usage.peers.lock().unwrap().len() <= MAX_PEERS);
        // Full of processes with flows: the next is not counted.
        let held: Vec<_> = (0..MAX_PEERS as u32)
            .map(|i| {
                usage
                    .counter(Key {
                        pid: 100_000 + i,
                        start: 1,
                    })
                    .unwrap()
            })
            .collect();
        assert!(usage.counter(Key { pid: 9, start: 9 }).is_none());
        drop(held);
        // A process that still runs keeps its counter, idle or not.
        #[cfg(target_os = "linux")]
        {
            let me = Key::of(std::process::id()).unwrap();
            usage
                .counter(me)
                .unwrap()
                .sent
                .fetch_add(7, Ordering::Relaxed);
            for pid in 0..(2 * MAX_PEERS as u32) {
                usage.counter(Key {
                    pid: 200_000 + pid,
                    start: 1,
                });
            }
            assert_eq!(usage.get(me), (7, 0));
        }
    }

    #[test]
    fn the_stats_socket_answers_with_the_token_only() {
        let dir = std::env::temp_dir().join(format!("egress-stats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("stats.sock");
        let usage = Arc::new(Usage::default());
        let key = Key { pid: 42, start: 7 };
        usage
            .counter(key)
            .unwrap()
            .sent
            .fetch_add(1234, Ordering::Relaxed);
        serve_stats(Arc::clone(&usage), &path, "secret-token".into()).unwrap();
        let other = Key { pid: 43, start: 7 };
        let got = ask(&path, "secret-token", &[key, other], Duration::from_secs(2)).unwrap();
        assert_eq!(got, vec![(key, 1234, 0), (other, 0, 0)]);
        assert!(ask(&path, "wrong-token!", &[key], Duration::from_secs(2)).is_err());
        // Connections that never present the token do not keep others
        // out: the oldest of them makes room.
        let idle: Vec<UnixStream> = (0..MAX_QUESTIONS * 3)
            .map(|_| UnixStream::connect(&path).unwrap())
            .collect();
        std::thread::sleep(Duration::from_millis(100));
        let got = ask(&path, "secret-token", &[key], Duration::from_secs(2)).unwrap();
        assert_eq!(got, vec![(key, 1234, 0)]);
        drop(idle);
        // Garbage keys end the question.
        let conn = UnixStream::connect(&path).unwrap();
        (&conn).write_all(b"secret-token\nnot-a-key\n").unwrap();
        let mut answer = String::new();
        let _ = (&conn).read_to_string(&mut answer);
        assert_eq!(answer, "");
        // A second server on a live socket is refused.
        assert!(serve_stats(usage, &path, "x".into()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
