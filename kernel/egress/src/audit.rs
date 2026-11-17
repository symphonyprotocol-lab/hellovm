//! One audit line per flow, written when the flow ends (or is refused):
//!
//! ```text
//! egress ts=1763380000.123 sandbox=00000000000004d2 host=pypi.org port=443 verdict=allow reason=ok addr=151.101.0.223:443 up=812 down=40213 ms=388 peer=4711
//! ```
//!
//! Fields, always in this order and always present:
//!
//! * `ts`: Unix time in seconds with milliseconds, when the line is written;
//! * `sandbox`: the sandbox id as 16 hex digits, `-` when the header could
//!   not be read;
//! * `host`, `port`: from the flow header (`-` and `0` when unreadable);
//! * `verdict`: `allow` (bytes were relayed) or `deny`;
//! * `reason`: for `allow`, `ok` or `idle-timeout`; for `deny`, one of
//!   `bad-request`, `limit`, `policy`, `resolve`, `blocked-address`,
//!   `upstream-refused`, `upstream-timeout`, `sni-mismatch`,
//!   `host-mismatch`, `not-tls`, `not-http`, `unparsable`, `sniff-timeout`;
//! * `addr`: the upstream address dialed, or for `blocked-address` the
//!   first blocked address, else `-`;
//! * `up`: bytes from the guest delivered upstream; `down`: bytes from
//!   upstream delivered to the guest;
//! * `ms`: the flow's duration;
//! * `peer`: the process id of the connecting kernel process as the host
//!   kernel reports it (`SO_PEERCRED`), `-` where that is unavailable.
//!   Unlike `sandbox`, the connecting process cannot choose it.
//!
//! Every allowed flow is logged. Refusals are rate-limited per peer
//! ([`crate::Limits::deny_audit_burst`], [`crate::Limits::deny_audit_per_sec`]),
//! so a sandbox that retries a refused connect in a loop cannot fill the
//! disk; the next line written for that peer ends with `suppressed=N`, the
//! number of its deny lines left out.
//!
//! Values never contain spaces: hostnames are validated before they are
//! logged, and a `sni` or `http_host` field is added (after `reason`) only on
//! a mismatch, holding the validated name the client asked for.

use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where audit lines go. Cloning shares the sink.
#[derive(Clone)]
pub struct AuditSink(Arc<Mutex<Box<dyn Write + Send>>>);

impl AuditSink {
    pub fn new(out: Box<dyn Write + Send>) -> AuditSink {
        AuditSink(Arc::new(Mutex::new(out)))
    }

    pub fn stdout() -> AuditSink {
        AuditSink::new(Box::new(io::stdout()))
    }

    pub fn write(&self, record: &Record) {
        let line = record.line();
        let mut out = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(err) = out.write_all(line.as_bytes()).and_then(|()| out.flush()) {
            eprintln!("hellovm-egress: writing the audit log: {err}");
        }
    }
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditSink")
    }
}

/// An in-memory sink, for tests.
#[derive(Clone, Default)]
pub struct MemorySink(pub Arc<Mutex<Vec<u8>>>);

impl Write for MemorySink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MemorySink {
    pub fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|e| e.into_inner()))
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// One flow's audit record.
#[derive(Clone, Debug, Default)]
pub struct Record {
    pub sandbox: Option<u64>,
    pub host: Option<String>,
    pub port: u16,
    pub allowed: bool,
    pub reason: &'static str,
    /// The client's own name, on an SNI or `Host` mismatch.
    pub asked: Option<(&'static str, String)>,
    pub addr: Option<SocketAddr>,
    pub up: u64,
    pub down: u64,
    pub duration: Duration,
    /// The connecting process, as the host kernel reports it.
    pub peer: Option<u32>,
    /// Deny lines of the same peer left out since its last written line.
    pub suppressed: u64,
}

impl Record {
    pub fn line(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut s = format!("egress ts={}.{:03}", now.as_secs(), now.subsec_millis());
        match self.sandbox {
            Some(id) => {
                let _ = write!(s, " sandbox={id:016x}");
            }
            None => s.push_str(" sandbox=-"),
        }
        let _ = write!(
            s,
            " host={} port={} verdict={} reason={}",
            self.host.as_deref().unwrap_or("-"),
            self.port,
            if self.allowed { "allow" } else { "deny" },
            self.reason
        );
        if let Some((key, name)) = &self.asked {
            let _ = write!(s, " {key}={name}");
        }
        match self.addr {
            Some(addr) => {
                let _ = write!(s, " addr={addr}");
            }
            None => s.push_str(" addr=-"),
        }
        let _ = write!(
            s,
            " up={} down={} ms={}",
            self.up,
            self.down,
            self.duration.as_millis()
        );
        match self.peer {
            Some(pid) => {
                let _ = write!(s, " peer={pid}");
            }
            None => s.push_str(" peer=-"),
        }
        if self.suppressed > 0 {
            let _ = write!(s, " suppressed={}", self.suppressed);
        }
        s.push('\n');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_format() {
        let r = Record {
            sandbox: Some(0x4d2),
            host: Some("pypi.org".into()),
            port: 443,
            allowed: false,
            reason: "sni-mismatch",
            asked: Some(("sni", "evil.example".into())),
            addr: Some("1.2.3.4:443".parse().unwrap()),
            up: 0,
            down: 0,
            duration: Duration::from_millis(12),
            ..Record::default()
        };
        let line = r.line();
        let rest = line.split_once(' ').unwrap().1.split_once(' ').unwrap().1;
        assert_eq!(
            rest,
            "sandbox=00000000000004d2 host=pypi.org port=443 verdict=deny reason=sni-mismatch sni=evil.example addr=1.2.3.4:443 up=0 down=0 ms=12 peer=-\n"
        );
        assert!(line.starts_with("egress ts="));
        let empty = Record {
            reason: "bad-request",
            ..Record::default()
        }
        .line();
        assert!(empty.contains(" sandbox=- host=- port=0 verdict=deny reason=bad-request addr=- "));
    }
}
