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
