//! The listener and the per-flow state machine: header, limits, name
//! policy, resolution and address policy, upstream connect, verdict, sniff,
//! relay, audit.
//!
//! Each accepted flow runs on its own thread, and relaying uses one more.
//! [`Limits::max_flows`] bounds both.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::addr;
use crate::audit::{AuditSink, Record};
use crate::policy::Policy;
use crate::resolve::{Candidate, Resolver};
use crate::sniff::{sniff, Sniff};
use crate::wire::{Request, Status, WireError};

/// Bounds on everything a guest can influence.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Time allowed for the whole flow header to arrive.
    pub header_timeout: Duration,
    /// Concurrent flows, all sandboxes together.
    pub max_flows: usize,
    /// Concurrent flows of one sandbox.
    pub max_flows_per_sandbox: usize,
    /// Time allowed for resolving the flow's name.
    pub resolve_timeout: Duration,
    /// Time allowed for connecting upstream, across all addresses tried.
    pub connect_timeout: Duration,
    /// Allowed addresses tried, in resolver order.
    pub max_dial_addrs: usize,
    /// Bytes read from the guest while looking for the SNI or `Host`.
    pub sniff_max: usize,
    /// Time allowed for those bytes.
    pub sniff_timeout: Duration,
    /// A flow with no bytes moving either way for this long is closed.
    pub idle_timeout: Duration,
    /// Bytes buffered per direction while relaying.
    pub buffer: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            header_timeout: Duration::from_secs(5),
            max_flows: 1024,
            max_flows_per_sandbox: 64,
            resolve_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            max_dial_addrs: 4,
            sniff_max: 16 * 1024,
            sniff_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            buffer: 16 * 1024,
        }
    }
}

/// The proxy's configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub policy: Policy,
    pub limits: Limits,
    pub audit: AuditSink,
    pub resolver: Resolver,
}

impl Config {
    pub fn new(policy: Policy, audit: AuditSink) -> Config {
        Config {
            policy,
            limits: Limits::default(),
            audit,
            resolver: Resolver::System,
        }
    }
}

struct Shared {
    config: Config,
    active: AtomicUsize,
    per_sandbox: Mutex<HashMap<u64, usize>>,
    stop: AtomicBool,
}

/// A bound proxy.
pub struct Proxy {
    listener: UnixListener,
    path: PathBuf,
    shared: Arc<Shared>,
}

/// A proxy serving on its own thread.
pub struct ProxyHandle {
    path: PathBuf,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl Proxy {
    /// Listens on `path`. A stale socket file nobody listens on is
    /// replaced; any other existing file is an error.
    pub fn bind(path: impl AsRef<Path>, config: Config) -> io::Result<Proxy> {
        let path = path.as_ref().to_path_buf();
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            match UnixStream::connect(&path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("another proxy listens on {}", path.display()),
                    ))
                }
                Err(_) => std::fs::remove_file(&path)?,
            }
        }
        let listener = UnixListener::bind(&path)?;
        Ok(Proxy {
            listener,
            path,
            shared: Arc::new(Shared {
                config,
                active: AtomicUsize::new(0),
                per_sandbox: Mutex::new(HashMap::new()),
                stop: AtomicBool::new(false),
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts flows until [`ProxyHandle::stop`] (or forever).
    pub fn serve(&self) -> io::Result<()> {
        for conn in self.listener.incoming() {
            if self.shared.stop.load(Ordering::SeqCst) {
                return Ok(());
            }
            let conn = match conn {
                Ok(conn) => conn,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    // EMFILE and friends: back off instead of spinning.
                    eprintln!("hellovm-egress: accept: {err}");
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            self.dispatch(conn);
        }
        Ok(())
    }

    fn dispatch(&self, conn: UnixStream) {
        let limits = &self.shared.config.limits;
        if self.shared.active.fetch_add(1, Ordering::SeqCst) >= limits.max_flows {
            self.shared.active.fetch_sub(1, Ordering::SeqCst);
            // Do not let a full proxy block on this client.
            let _ = conn.set_nonblocking(true);
            let _ = (&conn).write_all(&Status::Limit.reply());
            self.shared.config.audit.write(&Record {
                reason: "limit",
                ..Record::default()
            });
            return;
        }
        let shared = Arc::clone(&self.shared);
        let spawned = thread::Builder::new()
            .name("egress-flow".into())
            .spawn(move || {
                let _active = ActiveGuard(&shared.active);
                handle(&shared, conn);
            });
        if spawned.is_err() {
            self.shared.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Serves on a new thread.
    pub fn spawn(self) -> ProxyHandle {
        let path = self.path.clone();
        let shared = Arc::clone(&self.shared);
        let thread = thread::Builder::new()
            .name("egress-accept".into())
            .spawn(move || {
                if let Err(err) = self.serve() {
                    eprintln!("hellovm-egress: {err}");
                }
            })
            .expect("starting the proxy thread");
        ProxyHandle {
            path,
            shared,
            thread: Some(thread),
        }
    }
}

impl ProxyHandle {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flows being handled right now.
    pub fn active_flows(&self) -> usize {
        self.shared.active.load(Ordering::SeqCst)
    }

    /// Stops accepting and removes the socket file. Flows already accepted
    /// run to their end.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop. If the socket file is already gone, nothing
        // can reach the loop: leave the thread blocked in `accept` rather
        // than wait for it.
        let woke = UnixStream::connect(&self.path).is_ok();
        if let Some(thread) = self.thread.take() {
            if woke {
                let _ = thread.join();
            }
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.shutdown();
        }
    }
}

struct ActiveGuard<'a>(&'a AtomicUsize);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One sandbox's flow slot.
struct SandboxSlot<'a> {
    shared: &'a Shared,
    id: u64,
}

impl Drop for SandboxSlot<'_> {
    fn drop(&mut self) {
        let mut map = self
            .shared
            .per_sandbox
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.id) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.id);
            }
        }
    }
}

fn take_slot(shared: &Shared, id: u64) -> Option<SandboxSlot<'_>> {
    let mut map = shared.per_sandbox.lock().unwrap_or_else(|e| e.into_inner());
    let n = map.entry(id).or_insert(0);
    if *n >= shared.config.limits.max_flows_per_sandbox {
        return None;
    }
    *n += 1;
    Some(SandboxSlot { shared, id })
}

/// Reads with one deadline for all reads together.
struct Deadline<'a> {
    sock: &'a UnixStream,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.sock.set_read_timeout(Some(left))?;
        let mut sock = self.sock;
        match sock.read(buf) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                Err(io::ErrorKind::TimedOut.into())
            }
            other => other,
        }
    }
}

fn handle(shared: &Shared, client: UnixStream) {
    let start = Instant::now();
    let mut rec = Record::default();
    flow(shared, client, &mut rec);
    rec.duration = start.elapsed();
    shared.config.audit.write(&rec);
}

fn refuse(client: &UnixStream, rec: &mut Record, status: Status, reason: &'static str) {
    rec.allowed = false;
    rec.reason = reason;
    let mut c = client;
    let _ = c.write_all(&status.reply());
    let _ = client.shutdown(Shutdown::Both);
}

fn flow(shared: &Shared, client: UnixStream, rec: &mut Record) {
    let limits = &shared.config.limits;
    let _ = client.set_write_timeout(Some(limits.header_timeout));
    let req = {
        let mut r = Deadline {
            sock: &client,
            until: Instant::now() + limits.header_timeout,
        };
        match Request::read_from(&mut r) {
            Ok(req) => req,
            Err(WireError::Io(_)) | Err(WireError::Malformed(_)) => {
                refuse(&client, rec, Status::BadRequest, "bad-request");
                return;
            }
        }
    };
    rec.sandbox = Some(req.sandbox_id);
    rec.host = Some(req.host.clone());
    rec.port = req.port;
    let Some(_slot) = take_slot(shared, req.sandbox_id) else {
        refuse(&client, rec, Status::Limit, "limit");
        return;
    };
    if !shared.config.policy.allows(&req.host, req.port) {
        refuse(&client, rec, Status::Denied, "policy");
        return;
    }
    let candidates =
        match shared
            .config
            .resolver
            .resolve(&req.host, req.port, limits.resolve_timeout)
        {
            Ok(c) if !c.is_empty() => c,
            _ => {
                refuse(&client, rec, Status::ResolveFailed, "resolve");
                return;
            }
        };
    let (allowed, first_blocked) = dialable(&candidates);
    if allowed.is_empty() {
        rec.addr = first_blocked;
        refuse(&client, rec, Status::BlockedAddress, "blocked-address");
        return;
    }
    let upstream = match dial(&allowed, limits) {
        Ok((sock, addr)) => {
            rec.addr = Some(addr);
            sock
        }
        Err(timed_out) => {
            if timed_out {
                refuse(&client, rec, Status::UpstreamTimeout, "upstream-timeout");
            } else {
                refuse(&client, rec, Status::UpstreamRefused, "upstream-refused");
            }
            return;
        }
    };
    if (&client).write_all(&Status::Ok.reply()).is_err() {
        rec.reason = "bad-request";
        return;
    }
    let first = match sniff_first(&client, &req, limits, rec) {
        Some(first) => first,
        None => {
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
            return;
        }
    };
    rec.allowed = true;
    rec.reason = "ok";
    relay(client, upstream, first, limits, rec);
}

/// The candidates that may be dialed, in order, and the first blocked one.
/// Only a loopback entry of the test table escapes [`addr::blocked`].
fn dialable(candidates: &[Candidate]) -> (Vec<SocketAddr>, Option<SocketAddr>) {
    let mut allowed = Vec::new();
    let mut first_blocked = None;
    for c in candidates {
        let exempt = c.test_loopback && c.addr.ip().is_loopback();
        if exempt || addr::blocked(c.addr.ip()).is_none() {
            allowed.push(c.addr);
        } else if first_blocked.is_none() {
            first_blocked = Some(c.addr);
        }
    }
    (allowed, first_blocked)
}

/// Tries `addrs` in order within the connect budget. `Err(true)` when the
/// last failure was a timeout.
fn dial(addrs: &[SocketAddr], limits: &Limits) -> Result<(TcpStream, SocketAddr), bool> {
    let deadline = Instant::now() + limits.connect_timeout;
    let tries = addrs.len().min(limits.max_dial_addrs.max(1));
    let mut timed_out = false;
    for (i, &addr) in addrs.iter().take(tries).enumerate() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(true);
        }
        let share = left / (tries - i) as u32;
        match TcpStream::connect_timeout(&addr, share.max(Duration::from_millis(1))) {
            Ok(sock) => {
                let _ = sock.set_nodelay(true);
                return Ok((sock, addr));
            }
            Err(err) => {
                timed_out = matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                );
            }
        }
    }
    Err(timed_out)
}

/// Reads the guest's first bytes until they name a host. Returns them when
/// the name matches the flow; otherwise records the reason and returns
/// `None`.
fn sniff_first(
    client: &UnixStream,
    req: &Request,
    limits: &Limits,
    rec: &mut Record,
) -> Option<Vec<u8>> {
    let mut r = Deadline {
        sock: client,
        until: Instant::now() + limits.sniff_timeout,
    };
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let verdict = loop {
        let decided = sniff(&buf);
        if decided != Sniff::NeedMore {
            break decided;
        }
        if buf.len() >= limits.sniff_max {
            break Sniff::Invalid("too long");
        }
        let want = (limits.sniff_max - buf.len()).min(chunk.len());
        match r.read(&mut chunk[..want]) {
            Ok(0) => {
                rec.reason = "unparsable";
                return None;
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                rec.reason = "sniff-timeout";
                return None;
            }
            Err(_) => {
                rec.reason = "unparsable";
                return None;
            }
        }
    };
    let reason = match verdict {
        Sniff::Tls(_) if req.port == 80 => "not-http",
        Sniff::Tls(name) if name != req.host => {
            rec.asked = Some(("sni", name));
            "sni-mismatch"
        }
        Sniff::Tls(_) => return Some(buf),
        Sniff::Http(..) if req.port == 443 => "not-tls",
        Sniff::Http(name, port) if name != req.host || port.is_some_and(|p| p != req.port) => {
            rec.asked = Some(("http_host", name));
            "host-mismatch"
        }
        Sniff::Http(..) => return Some(buf),
        Sniff::Invalid(_) | Sniff::NeedMore => "unparsable",
    };
    rec.reason = reason;
    None
}

/// What one relay direction needs.
trait Half: Read + Write + Send + 'static {
    fn shut(&self, how: Shutdown);
    fn timeouts(&self, read: Duration, write: Duration);
}

impl Half for TcpStream {
    fn shut(&self, how: Shutdown) {
        let _ = self.shutdown(how);
    }
    fn timeouts(&self, read: Duration, write: Duration) {
        let _ = self.set_read_timeout(Some(read));
        let _ = self.set_write_timeout(Some(write));
    }
}

impl Half for UnixStream {
    fn shut(&self, how: Shutdown) {
        let _ = self.shutdown(how);
    }
    fn timeouts(&self, read: Duration, write: Duration) {
        let _ = self.set_read_timeout(Some(read));
        let _ = self.set_write_timeout(Some(write));
    }
}

struct Clock {
    start: Instant,
    /// Milliseconds since `start` of the last byte moved either way.
    last: AtomicU64,
    idle: AtomicBool,
}

impl Clock {
    fn touch(&self) {
        self.last
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    fn idle_for(&self) -> Duration {
        let now = self.start.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(self.last.load(Ordering::Relaxed)))
    }
}

/// How often a relay direction wakes to check the idle timeout.
const TICK: Duration = Duration::from_millis(500);

fn pump<S: Half, D: Half>(
    mut src: S,
    mut dst: D,
    moved: &AtomicU64,
    clock: &Clock,
    limits: &Limits,
) {
    // The read timeout is a tick for the idle check. A write that makes no
    // progress for the idle timeout ends the flow. Both directions set both
    // timeouts on their own fds to the same values.
    let tick = TICK.min(limits.idle_timeout);
    src.timeouts(tick, limits.idle_timeout);
    dst.timeouts(tick, limits.idle_timeout);
    let mut buf = vec![0u8; limits.buffer.max(1)];
    loop {
        match src.read(&mut buf) {
            Ok(0) => {
                dst.shut(Shutdown::Write);
                return;
            }
            Ok(n) => {
                clock.touch();
                if dst.write_all(&buf[..n]).is_err() {
                    src.shut(Shutdown::Both);
                    dst.shut(Shutdown::Both);
                    return;
                }
                moved.fetch_add(n as u64, Ordering::Relaxed);
                clock.touch();
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if clock.idle_for() >= limits.idle_timeout {
                    clock.idle.store(true, Ordering::Relaxed);
                    src.shut(Shutdown::Both);
                    dst.shut(Shutdown::Both);
                    return;
                }
            }
            Err(_) => {
                src.shut(Shutdown::Both);
                dst.shut(Shutdown::Both);
                return;
            }
        }
    }
}

fn relay(
    client: UnixStream,
    mut upstream: TcpStream,
    first: Vec<u8>,
    limits: &Limits,
    rec: &mut Record,
) {
    let _ = upstream.set_write_timeout(Some(limits.idle_timeout));
    if upstream.write_all(&first).is_err() {
        rec.reason = "ok";
        let _ = client.shutdown(Shutdown::Both);
        return;
    }
    let up = Arc::new(AtomicU64::new(first.len() as u64));
    let down = Arc::new(AtomicU64::new(0));
    let clock = Arc::new(Clock {
        start: Instant::now(),
        last: AtomicU64::new(0),
        idle: AtomicBool::new(false),
    });
    let (Ok(client2), Ok(upstream2)) = (client.try_clone(), upstream.try_clone()) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let limits2 = limits.clone();
    let (up2, clock2) = (Arc::clone(&up), Arc::clone(&clock));
    let upward = thread::Builder::new()
        .name("egress-up".into())
        .spawn(move || pump(client2, upstream2, &up2, &clock2, &limits2));
    match upward {
        Ok(upward) => {
            pump(upstream, client, &down, &clock, limits);
            let _ = upward.join();
        }
        Err(_) => {
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
        }
    }
    rec.up = up.load(Ordering::Relaxed);
    rec.down = down.load(Ordering::Relaxed);
    if clock.idle.load(Ordering::Relaxed) {
        rec.reason = "idle-timeout";
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(addr: &str, test_loopback: bool) -> Candidate {
        Candidate {
            addr: addr.parse().unwrap(),
            test_loopback,
        }
    }

    #[test]
    fn only_test_table_loopback_escapes_the_block_list() {
        let (ok, blocked) = dialable(&[c("127.0.0.1:443", false), c("[::1]:443", false)]);
        assert!(ok.is_empty());
        assert_eq!(blocked, Some("127.0.0.1:443".parse().unwrap()));
        // The flag is honoured for loopback only.
        let (ok, _) = dialable(&[c("10.0.0.1:443", true), c("169.254.169.254:80", true)]);
        assert!(ok.is_empty());
        let (ok, blocked) = dialable(&[
            c("169.254.169.254:443", false),
            c("127.0.0.1:9", true),
            c("1.1.1.1:443", false),
        ]);
        assert_eq!(
            ok,
            vec![
                "127.0.0.1:9".parse().unwrap(),
                "1.1.1.1:443".parse().unwrap()
            ]
        );
        assert_eq!(blocked, Some("169.254.169.254:443".parse().unwrap()));
    }
}
