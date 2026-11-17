//! What the hellovm control plane shares: `hellovm-api` (tenants, sandbox
//! life cycle, placement) and `hellovm-noded` (one per host: templates and
//! the sandboxes cloned from them) talk HTTP/1.1 with JSON bodies to their
//! callers and to each other.
//!
//! - [`http`]: a small, strict HTTP/1.1 server and client with bounded
//!   sizes and timeouts everywhere.
//! - [`ids`]: random sandbox ids, bearer-token comparison.
//! - [`types`]: the JSON bodies both services speak.

pub mod http;
pub mod ids;
pub mod types;

/// A logger that writes `PREFIX: level: message` lines to stderr, at the
/// level `HELLOVM_LOG` names (default `info`).
pub fn init_logging(prefix: &'static str) {
    struct StderrLogger(&'static str);

    impl log::Log for StderrLogger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::max_level()
        }

        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                use std::io::Write;
                let level = record.level().as_str().to_lowercase();
                let _ = writeln!(std::io::stderr(), "{}: {level}: {}", self.0, record.args());
            }
        }

        fn flush(&self) {}
    }

    let level = std::env::var("HELLOVM_LOG")
        .ok()
        .and_then(|level| level.parse().ok())
        .unwrap_or(log::LevelFilter::Info);
    log::set_max_level(level);
    let _ = log::set_logger(Box::leak(Box::new(StderrLogger(prefix))));
}

/// Milliseconds since the Unix epoch.
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Makes sure this process may have `need` open files: raises the soft
/// limit to the hard one if that is what it takes, and fails with what to
/// change when the hard limit is too low. Services call it at start-up
/// with what their configuration can use, so that the limit is hit in the
/// log at start, not under load as failing requests.
pub fn ensure_fd_limit(need: u64) -> Result<(), String> {
    // SAFETY: an all-zero rlimit is valid; getrlimit fills it.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: plain getrlimit into our struct.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(format!(
            "reading the open-file limit: {}",
            std::io::Error::last_os_error()
        ));
    }
    let (soft, hard) = (limit.rlim_cur as u64, limit.rlim_max as u64);
    if soft >= need {
        return Ok(());
    }
    if hard < need {
        return Err(format!(
            "this configuration can use {need} open files, the limit is {hard}: \
             raise the open-file limit (ulimit -n, LimitNOFILE=) or lower the configured maximums"
        ));
    }
    limit.rlim_cur = need.max(soft) as libc::rlim_t;
    // SAFETY: plain setrlimit with a value at most the hard limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(format!(
            "raising the open-file limit to {need}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_fd_limit_is_checked() {
        // What the process has already is enough for a little.
        super::ensure_fd_limit(16).unwrap();
        let err = super::ensure_fd_limit(u64::MAX).unwrap_err();
        assert!(err.contains("open-file limit"), "{err}");
    }
}
