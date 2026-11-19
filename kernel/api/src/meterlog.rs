//! The usage log: one JSON object per line ([`crate::meter::Record`]),
//! appended by the API, one set of files per period.
//!
//! The records of the period that starts at `S` go to
//! `LOG.YYYYMMDDTHHMMSSZ.jsonl` (`S` in UTC), and once that file holds
//! `max_file_mb`, to `LOG.YYYYMMDDTHHMMSSZ.1.jsonl`, `.2.jsonl`, and so on.
//! Files are only appended to; old periods' files are the operator's to
//! keep, ship or delete. A writer thread appends what the meter made,
//! once a second, and syncs the file after each batch. When it cannot (a
//! full disk, a missing directory, permissions), the API keeps serving:
//! the records wait in memory (at most [`MAX_BACKLOG`]; past that the
//! oldest are dropped and counted), the error is logged once, and so is
//! the recovery.
//!
//! At start-up the API reads the current period's files (the totals, the
//! deletes still to do, the last counters of each sandbox) and the
//! previous period's (the last counters of sandboxes that ran across the
//! boundary), at most `max_read_mb` in all.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::meter::{utc_stamp, Line, Rebuilt};

/// Records kept in memory while the log cannot be written.
pub const MAX_BACKLOG: usize = 100_000;
/// Longest line read back; a longer one is not a record.
const MAX_LINE: usize = 16 * 1024;
/// Most files of one period.
const MAX_FILES: u32 = 10_000;

/// The file of `period_start`'s records with number `index`.
pub fn file_name(prefix: &Path, period_start: u64, index: u32) -> PathBuf {
    let stamp = utc_stamp(period_start);
    let mut name = prefix.as_os_str().to_owned();
    if index == 0 {
        name.push(format!(".{stamp}.jsonl"));
    } else {
        name.push(format!(".{stamp}.{index}.jsonl"));
    }
    PathBuf::from(name)
}

/// The writer's state, as operators see it.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct LogStatus {
    /// Whether the last write succeeded (or none was needed).
    pub healthy: bool,
    pub last_error: Option<String>,
    /// Records written since start.
    pub written: u64,
    /// Records waiting to be written.
    pub backlog: usize,
    /// Records dropped because too many waited.
    pub dropped: u64,
}

struct Open {
    period: u64,
    index: u32,
    file: File,
    size: u64,
}

struct State {
    lines: VecDeque<Line>,
    status: LogStatus,
    open: Option<Open>,
}

pub struct LogWriter {
    prefix: PathBuf,
    max_file: u64,
    state: Mutex<State>,
    wake: Condvar,
    /// Held while writing, so that batches reach the file in order.
    writing: Mutex<()>,
}

impl LogWriter {
    pub fn new(prefix: PathBuf, max_file_mb: u64) -> LogWriter {
        LogWriter {
            prefix,
            max_file: max_file_mb << 20,
            state: Mutex::new(State {
                lines: VecDeque::new(),
                status: LogStatus {
                    healthy: true,
                    ..LogStatus::default()
                },
                open: None,
            }),
            wake: Condvar::new(),
            writing: Mutex::new(()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queues records; the writer thread appends them.
    pub fn push(&self, lines: Vec<Line>) {
        if lines.is_empty() {
            return;
        }
        let mut state = self.lock();
        state.lines.extend(lines);
        let over = state.lines.len().saturating_sub(MAX_BACKLOG);
        if over > 0 {
            state.lines.drain(..over);
            state.status.dropped += over as u64;
            log::error!("usage log: {over} records dropped (more than {MAX_BACKLOG} waited)");
        }
        state.status.backlog = state.lines.len();
        drop(state);
        self.wake.notify_one();
    }

    pub fn status(&self) -> LogStatus {
        self.lock().status.clone()
    }

    /// Writes what is queued, for ever (on a thread of its own).
    pub fn run(&self) {
        loop {
            self.write_some();
            let state = self.lock();
            // After an error, wait a second before trying again.
            if state.lines.is_empty() || !state.status.healthy {
                drop(
                    self.wake
                        .wait_timeout(state, Duration::from_secs(1))
                        .map(|(s, _)| s),
                );
            }
        }
    }

    /// Writes everything queued, or until an error. File I/O happens
    /// with the queue's lock released, so queuing never waits for the
    /// disk; one batch is written at a time.
    pub fn write_some(&self) {
        let _writing = self.writing.lock().unwrap_or_else(|e| e.into_inner());
        let (lines, mut open) = {
            let mut state = self.lock();
            if state.lines.is_empty() {
                return;
            }
            (std::mem::take(&mut state.lines), state.open.take())
        };
        let mut done = 0;
        let mut result = Ok(());
        for line in &lines {
            match self.append(&mut open, line) {
                Ok(()) => done += 1,
                Err(err) => {
                    result = Err(err);
                    break;
                }
            }
        }
        if result.is_ok() {
            if let Some(o) = &open {
                result = o.file.sync_data();
            }
        }
        let mut state = self.lock();
        // What was not written goes back in front of what came meanwhile.
        let mut rest: VecDeque<Line> = lines.into_iter().skip(done).collect();
        rest.extend(std::mem::take(&mut state.lines));
        state.lines = rest;
        state.status.written += done as u64;
        state.status.backlog = state.lines.len();
        match result {
            Ok(()) => {
                state.open = open;
                if !state.status.healthy {
                    log::info!(
                        "usage log: writing again ({} records written meanwhile)",
                        done
                    );
                }
                state.status.healthy = true;
            }
            Err(err) => {
                // Reopened next time: the file may have been moved.
                let message = format!("{}: {err}", self.prefix.display());
                if state.status.healthy {
                    log::error!(
                        "usage log: cannot write {message}; usage is still counted, and its \
                         records wait in memory ({} now)",
                        state.lines.len()
                    );
                }
                state.status.healthy = false;
                state.status.last_error = Some(message);
            }
        }
    }

    fn append(&self, open: &mut Option<Open>, line: &Line) -> io::Result<()> {
        let needed = line.text.len() as u64 + 1;
        let fits =
            |o: &Open| o.period == line.period && o.size + needed <= self.max_file.max(needed);
        if !open.as_ref().is_some_and(fits) {
            let index = match open.as_ref() {
                // The same period's file is full: the next.
                Some(o) if o.period == line.period => o.index + 1,
                _ => self.last_index(line.period),
            };
            *open = Some(self.open(line.period, index, needed)?);
        }
        let Some(o) = open.as_mut() else {
            return Err(io::ErrorKind::Other.into());
        };
        let mut bytes = Vec::with_capacity(line.text.len() + 1);
        bytes.extend_from_slice(line.text.as_bytes());
        bytes.push(b'\n');
        o.file.write_all(&bytes)?;
        o.size += bytes.len() as u64;
        Ok(())
    }

    /// The highest numbered file of `period` that exists (0 if none).
    fn last_index(&self, period: u64) -> u32 {
        let mut index = 0;
        while index + 1 < MAX_FILES && file_name(&self.prefix, period, index + 1).exists() {
            index += 1;
        }
        index
    }

    /// Opens file `index` of `period` for appending, or a later one if
    /// it is full.
    fn open(&self, period: u64, mut index: u32, needed: u64) -> io::Result<Open> {
        loop {
            let path = file_name(&self.prefix, period, index);
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&path)?;
            let mut size = file.metadata()?.len();
            if size > 0 && size + needed > self.max_file && index + 1 < MAX_FILES {
                index += 1;
                continue;
            }
            // A line cut short by a crash: end it, so that the next
            // record starts a line of its own.
            if size > 0 {
                let mut last = [0u8; 1];
                file.seek(SeekFrom::Start(size - 1))?;
                file.read_exact(&mut last)?;
                if last[0] != b'\n' {
                    file.write_all(b"\n")?;
                    size += 1;
                }
            }
            return Ok(Open {
                period,
                index,
                file,
                size,
            });
        }
    }
}

/// Reads the log at start-up: the files of the period before `start` (for
/// the counters of sandboxes only) and of the one that starts at `start`,
/// at most `max_bytes` in all.
pub fn read(
    prefix: &Path,
    start: u64,
    period: impl Into<crate::meter::Periods>,
    max_bytes: u64,
    known: &dyn Fn(&str) -> bool,
) -> Rebuilt {
    let mut rebuilt = Rebuilt::default();
    let mut left = max_bytes;
    let periods = [(period.into().previous(start), false), (Some(start), true)];
    for (p, current) in periods {
        let Some(p) = p else { continue };
        for index in 0..MAX_FILES {
            let path = file_name(prefix, p, index);
            let Ok(file) = File::open(&path) else {
                break;
            };
            let mut reader = BufReader::new(file);
            loop {
                if left == 0 {
                    rebuilt.truncated = true;
                    return rebuilt;
                }
                let mut buf = Vec::new();
                let n = match (&mut reader)
                    .take((MAX_LINE as u64 + 1).min(left))
                    .read_until(b'\n', &mut buf)
                {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) => {
                        log::error!("usage log: reading {}: {err}", path.display());
                        break;
                    }
                };
                left = left.saturating_sub(n as u64);
                if buf.last() != Some(&b'\n') {
                    // Longer than a record: skip to the end of the line.
                    rebuilt.bad += 1;
                    let mut skip = Vec::new();
                    let skipped = (&mut reader)
                        .take(left)
                        .read_until(b'\n', &mut skip)
                        .unwrap_or(0);
                    left = left.saturating_sub(skipped as u64);
                    continue;
                }
                match std::str::from_utf8(&buf) {
                    Ok(text) => rebuilt.take(text.trim_end(), current, known),
                    Err(_) => rebuilt.bad += 1,
                }
            }
        }
    }
    rebuilt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::{Kind, Record};
    use hellovm_control::ids::SandboxId;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("meterlog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn line(period: u64, tenant: &str, cpu: u64) -> Line {
        let r = Record {
            v: 1,
            kind: Kind::Usage,
            ts: period * 1000,
            period,
            tenant: tenant.into(),
            sandbox: SandboxId::random().unwrap().to_string(),
            node: "n".into(),
            template: "python".into(),
            delta: hellovm_control::types::SandboxUsage {
                cpu_ms: cpu,
                ..Default::default()
            },
            total: Default::default(),
            memory_bytes: 0,
            end: None,
        };
        Line {
            period,
            text: serde_json::to_string(&r).unwrap(),
        }
    }

    #[test]
    fn names() {
        assert_eq!(
            file_name(Path::new("/var/log/usage"), 0, 0),
            PathBuf::from("/var/log/usage.19700101T000000Z.jsonl")
        );
        assert_eq!(
            file_name(Path::new("u"), 3600, 2),
            PathBuf::from("u.19700101T010000Z.2.jsonl")
        );
    }

    #[test]
    fn writes_rotate_and_read_back() {
        let d = dir("rotate");
        let prefix = d.join("usage");
        let w = LogWriter::new(prefix.clone(), 1);
        // About 400 bytes each: 3000 make more than 1 MiB.
        let lines: Vec<Line> = (0..3000).map(|i| line(3600, "a", i % 7)).collect();
        let sum: u64 = (0..3000).map(|i| i % 7).sum();
        w.push(lines);
        w.push(vec![line(7200, "a", 1000), line(0, "b", 5)]);
        w.write_some();
        let status = w.status();
        assert!(status.healthy, "{status:?}");
        assert_eq!((status.written, status.backlog), (3002, 0));
        assert!(file_name(&prefix, 3600, 1).exists(), "rotated by size");
        for i in [0, 1] {
            assert!(
                std::fs::metadata(file_name(&prefix, 3600, i))
                    .unwrap()
                    .len()
                    <= 1 << 20
            );
        }
        let known = |t: &str| t == "a" || t == "b";
        let r = read(&prefix, 3600, 3600, 1 << 30, &known);
        assert_eq!(r.totals["a"].cpu_ms, sum);
        assert_eq!(
            r.totals.get("b"),
            None,
            "the previous period's totals are not taken"
        );
        assert_eq!(r.records, 3001);
        let r = read(&prefix, 7200, 3600, 1 << 30, &known);
        assert_eq!(r.totals["a"].cpu_ms, 1000);
        // Bounded reads.
        let r = read(&prefix, 3600, 3600, 10_000, &known);
        assert!(r.truncated);
        assert!(r.records < 30);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_cut_line_and_garbage_are_skipped() {
        let d = dir("cut");
        let prefix = d.join("usage");
        let good = line(0, "a", 3);
        let file = file_name(&prefix, 0, 0);
        let long = "x".repeat(MAX_LINE * 2);
        std::fs::write(&file, format!("{}\n{long}\nnot json\n{{\"v\":1", good.text)).unwrap();
        let w = LogWriter::new(prefix.clone(), 256);
        w.push(vec![line(0, "a", 4)]);
        w.write_some();
        let r = read(&prefix, 0, 3600, 1 << 30, &|t| t == "a");
        assert_eq!(r.totals["a"].cpu_ms, 7);
        assert_eq!(r.bad, 3, "the long line, the garbage and the cut line");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_log_that_cannot_be_written_keeps_its_records() {
        let d = dir("fail");
        let prefix = d.join("missing/usage");
        let w = LogWriter::new(prefix.clone(), 256);
        w.push(vec![line(0, "a", 1), line(0, "a", 2)]);
        w.write_some();
        let s = w.status();
        assert!(!s.healthy && s.last_error.is_some(), "{s:?}");
        assert_eq!(s.backlog, 2);
        std::fs::create_dir_all(d.join("missing")).unwrap();
        w.push(vec![line(0, "a", 3)]);
        w.write_some();
        let s = w.status();
        assert!(s.healthy, "{s:?}");
        assert_eq!((s.written, s.backlog), (3, 0));
        let r = read(&prefix, 0, 3600, 1 << 30, &|t| t == "a");
        assert_eq!(r.totals["a"].cpu_ms, 6, "in order, none lost");
        // The backlog is bounded.
        let w = LogWriter::new(d.join("nowhere/usage"), 256);
        w.push((0..MAX_BACKLOG + 5).map(|_| line(0, "a", 1)).collect());
        let s = w.status();
        assert_eq!((s.backlog, s.dropped), (MAX_BACKLOG, 5));
        let _ = std::fs::remove_dir_all(&d);
    }
}
