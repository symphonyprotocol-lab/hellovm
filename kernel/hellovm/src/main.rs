//! `hellovm`: runs a Linux program inside the hellovm kernel.
//!
//! ```text
//! hellovm [--trace] [--timeout SECONDS] [--tty | --no-tty]
//!         [--egress SOCKET] [--sandbox-id ID] --root DIR
//!         [--env NAME=VALUE]... [--] PROGRAM [ARGS...]
//! ```
//!
//! `DIR` is the sandbox's read-only image: the program sees it as `/`, with
//! an in-memory writable layer on top (writes never reach `DIR`). `PROGRAM`
//! is a path inside the sandbox, e.g. `/bin/busybox`. The environment is
//! `PATH` and `HOME` plus every `--env`.
//!
//! The program's console output goes to hellovm's own stdout and stderr, its
//! input comes from hellovm's stdin, and hellovm exits with the program's exit
//! status (128 + signal number if it was killed; 125 if it could not be
//! started). The program's processes end when it ends. `--timeout` kills
//! every process of the sandbox after that many seconds (decimals allowed)
//! and makes hellovm exit with 124, like `timeout(1)`. `--trace` prints
//! every syscall the kernel handled to stderr.
//!
//! `--egress SOCKET` sends the sandbox's outbound TCP flows to the
//! `hellovm-egress` proxy listening on that Unix socket; without it nothing
//! leaves the sandbox. `--sandbox-id` names the sandbox to the proxy (16 hex
//! digits or a decimal number; random by default). When the program ends,
//! hellovm waits up to 10 s for bytes the sandbox already wrote to reach
//! the proxy. With the `insecure-test-hooks` feature, `--splice-to
//! 127.0.0.1:PORT` instead splices every flow to a loopback TCP address
//! with no policy (tests only).
//!
//! When hellovm's stdin and stdout are terminals (or with `--tty`), the
//! sandbox console is a terminal: fds 0, 1 and 2 are `/dev/console`, with
//! hellovm's own line discipline, job control and the host terminal's
//! window size, and the host terminal is put in raw mode while the program
//! runs (so Ctrl-C reaches the sandbox's foreground job, not hellovm).
//! `--no-tty` keeps plain streams.
//! `HELLOVM_LOG` sets the log level (`error`, `warn` (default), `info`,
//! `debug`, `trace`).

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: hellovm [--trace] [--timeout SECONDS] [--tty | --no-tty] \
     [--egress SOCKET] [--sandbox-id ID] --root DIR [--env NAME=VALUE]... [--] PROGRAM [ARGS...]";

/// How long hellovm waits, after the program ends, for outbound bytes the
/// sandbox already wrote to be delivered.
const EXIT_DRAIN: std::time::Duration = std::time::Duration::from_secs(10);

/// Exit status when the program was killed by `--timeout`.
const EXIT_TIMEOUT: u8 = 124;

const DEFAULT_ENV: [&str; 2] = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root",
];

struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let level = record.level().as_str().to_lowercase();
            let _ = writeln!(std::io::stderr(), "hellovm: {level}: {}", record.args());
        }
    }

    fn flush(&self) {}
}

fn init_logging() {
    let level = std::env::var("HELLOVM_LOG")
        .ok()
        .and_then(|level| level.parse().ok())
        .unwrap_or(log::LevelFilter::Warn);
    log::set_max_level(level);
    let _ = log::set_logger(&StderrLogger);
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Options {
    trace: bool,
    /// `Some(true)`: `--tty`; `Some(false)`: `--no-tty`; `None`: decide by
    /// whether stdin and stdout are terminals.
    tty: Option<bool>,
    timeout: Option<std::time::Duration>,
    root: PathBuf,
    /// The egress proxy's Unix socket.
    egress: Option<PathBuf>,
    /// Names the sandbox to the egress proxy.
    sandbox_id: Option<u64>,
    /// Test hook: splice outbound TCP to this loopback address.
    #[cfg(feature = "insecure-test-hooks")]
    splice_to: Option<std::net::SocketAddr>,
    env: Vec<Vec<u8>>,
    argv: Vec<Vec<u8>>,
}

fn parse_args(args: impl Iterator<Item = OsString>) -> Result<Options, String> {
    let mut trace = false;
    let mut tty = None;
    let mut timeout = None;
    let mut root = None;
    let mut egress = None;
    let mut sandbox_id = None;
    #[cfg(feature = "insecure-test-hooks")]
    let mut splice_to = None;
    let mut env: Vec<Vec<u8>> = DEFAULT_ENV.iter().map(|e| e.as_bytes().to_vec()).collect();
    let mut args = args.peekable();
    while let Some(arg) = args.peek() {
        match arg.to_str() {
            Some("--trace") => trace = true,
            Some("--tty") => tty = Some(true),
            Some("--no-tty") => tty = Some(false),
            Some("--root") => {
                args.next();
                root = Some(PathBuf::from(
                    args.next().ok_or("--root needs a directory")?,
                ));
                continue;
            }
            Some("--timeout") => {
                args.next();
                let value = args.next().ok_or("--timeout needs a number of seconds")?;
                let seconds = value
                    .to_str()
                    .and_then(|s| s.parse::<f64>().ok())
                    .and_then(|s| std::time::Duration::try_from_secs_f64(s).ok())
                    .ok_or_else(|| {
                        format!(
                            "--timeout {}: expected a number of seconds",
                            value.to_string_lossy()
                        )
                    })?;
                timeout = Some(seconds);
                continue;
            }
            Some("--egress") => {
                args.next();
                egress = Some(PathBuf::from(
                    args.next().ok_or("--egress needs a socket path")?,
                ));
                continue;
            }
            Some("--sandbox-id") => {
                args.next();
                let value = args.next().ok_or("--sandbox-id needs an id")?;
                let text = value.to_string_lossy();
                let id = if text.len() == 16 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
                    u64::from_str_radix(&text, 16).ok()
                } else {
                    text.parse::<u64>().ok()
                };
                sandbox_id = Some(id.ok_or_else(|| {
                    format!("--sandbox-id {text}: expected 16 hex digits or a decimal number")
                })?);
                continue;
            }
            #[cfg(feature = "insecure-test-hooks")]
            Some("--splice-to") => {
                args.next();
                let value = args.next().ok_or("--splice-to needs IP:PORT")?;
                let text = value.to_str().ok_or_else(|| {
                    format!(
                        "--splice-to {}: expected an IPv4 address and port",
                        value.to_string_lossy()
                    )
                })?;
                let addr: std::net::SocketAddr = text.parse().map_err(|_| {
                    format!("--splice-to {text}: expected an IPv4 address and port")
                })?;
                if !addr.ip().is_ipv4() || !addr.ip().is_loopback() {
                    return Err(format!(
                        "--splice-to {text}: test-only hook, and the address must be IPv4 loopback"
                    ));
                }
                splice_to = Some(addr);
                continue;
            }
            Some("--env") => {
                args.next();
                let var = args.next().ok_or("--env needs NAME=VALUE")?.into_vec();
                let Some(eq) = var.iter().position(|&b| b == b'=') else {
                    return Err(format!(
                        "--env {}: expected NAME=VALUE",
                        String::from_utf8_lossy(&var)
                    ));
                };
                env.retain(|e| !e.starts_with(&var[..=eq]));
                env.push(var);
                continue;
            }
            Some("--") => {
                args.next();
                break;
            }
            Some("-h" | "--help") => return Err(USAGE.to_string()),
            Some(flag) if flag.starts_with('-') => {
                return Err(format!("unknown option {flag}\n{USAGE}"))
            }
            _ => break,
        }
        args.next();
    }
    let argv: Vec<Vec<u8>> = args.map(OsString::into_vec).collect();
    if argv.is_empty() {
        return Err(USAGE.to_string());
    }
    let root = root.ok_or_else(|| format!("--root is required\n{USAGE}"))?;
    Ok(Options {
        trace,
        tty,
        timeout,
        root,
        egress,
        sandbox_id,
        #[cfg(feature = "insecure-test-hooks")]
        splice_to,
        env,
        argv,
    })
}

fn main() -> ExitCode {
    init_logging();
    let options = match parse_args(std::env::args_os().skip(1)) {
        Ok(options) => options,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(Ended::TimedOut(after)) => {
            eprintln!("hellovm: program timed out after {after:?}");
            ExitCode::from(EXIT_TIMEOUT)
        }
        Ok(Ended::Status(status)) => exit_code(status),
        Err(err) => {
            eprintln!("hellovm: {err}");
            ExitCode::from(125)
        }
    }
}

/// How a run ended.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum Ended {
    Status(hellovm_core::ExitStatus),
    /// Killed by `--timeout` after this long.
    TimedOut(std::time::Duration),
}

fn exit_code(status: hellovm_core::ExitStatus) -> ExitCode {
    match status {
        hellovm_core::ExitStatus::Exited(code) => ExitCode::from(code as u8),
        hellovm_core::ExitStatus::Signaled(signal) => {
            eprintln!("hellovm: program killed by signal {signal}");
            ExitCode::from((128 + signal).min(255) as u8)
        }
    }
}

#[cfg(target_os = "linux")]
fn run(options: &Options) -> Result<Ended, Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use hellovm_core::Kernel;
    use hellovm_host::{ImageDir, StdioHost};
    use hellovm_platform_seccomp::SeccompPlatform;

    let image = ImageDir::open(&options.root)
        .map_err(|err| format!("image {}: {err}", options.root.display()))?;
    let mut app = SeccompPlatform::new()?;
    let mut host = StdioHost::new(Some(image));
    if let Some(path) = &options.egress {
        host.set_egress(path);
    }
    #[cfg(feature = "insecure-test-hooks")]
    if let Some(addr) = options.splice_to {
        // Every issued fake IP is spliced here. The guest address is not dialed.
        host.set_splice_endpoint(addr);
    }
    let sandbox_id = match options.sandbox_id {
        Some(id) => id,
        None => {
            let mut bytes = [0u8; 8];
            hellovm_core::host::Host::random(&mut host, &mut bytes)?;
            u64::from_be_bytes(bytes)
        }
    };
    log::info!("sandbox id {sandbox_id:016x}");
    let mut kernel = Kernel::new(host).with_sandbox_id(sandbox_id);
    if options.trace {
        kernel = kernel.with_trace();
    }
    let terminal = options
        .tty
        .unwrap_or_else(|| host_tty::is_terminal(0) && host_tty::is_terminal(1));
    // Restores the host terminal when dropped.
    let _raw = if terminal {
        kernel = kernel.with_console(hellovm_core::ConsoleMode::Terminal);
        host_tty::RawMode::enter(0)
    } else {
        None
    };
    kernel.exec(&mut app, &options.argv[0], &options.argv, &options.env)?;
    if terminal {
        if let Some((rows, cols)) = host_tty::window_size(1) {
            kernel.set_window_size(rows, cols);
        }
    }
    // The watchdog thread is detached: it holds no more than the sandbox's
    // pidfds, and killing through it after the sandbox has ended does
    // nothing.
    let timed_out = Arc::new(AtomicBool::new(false));
    if let Some(timeout) = options.timeout {
        let killer = app.killer();
        let timed_out = Arc::clone(&timed_out);
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            timed_out.store(true, Ordering::SeqCst);
            if let Err(err) = killer.kill() {
                eprintln!("hellovm: cannot stop the program at its timeout: {err}");
            }
        });
    }
    let status = kernel.run(&mut app);
    for record in kernel.trace() {
        eprintln!("hellovm: trace: {record}");
    }
    // The helpers that deliver what the guest wrote are threads of this
    // process: give them a bounded time before exit ends them.
    if !kernel.host_mut().drain_streams(EXIT_DRAIN) {
        log::warn!("outbound streams still had undelivered bytes after {EXIT_DRAIN:?}");
    }
    let status = status?;
    match (status, options.timeout) {
        (hellovm_core::ExitStatus::Signaled(9), Some(timeout))
            if timed_out.load(Ordering::SeqCst) =>
        {
            Ok(Ended::TimedOut(timeout))
        }
        _ => Ok(Ended::Status(status)),
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_options: &Options) -> Result<Ended, Box<dyn std::error::Error>> {
    Err("no platform for this host yet: only Linux (seccomp) is implemented".into())
}

/// The host terminal hellovm runs in, if any.
#[cfg(target_os = "linux")]
mod host_tty {
    /// Whether `fd` is a terminal.
    pub fn is_terminal(fd: i32) -> bool {
        // SAFETY: plain libc call.
        unsafe { libc::isatty(fd) == 1 }
    }

    /// The window size of the terminal at `fd`.
    pub fn window_size(fd: i32) -> Option<(u16, u16)> {
        // SAFETY: TIOCGWINSZ writes one winsize to the pointer.
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_row > 0 {
                Some((ws.ws_row, ws.ws_col))
            } else {
                None
            }
        }
    }

    /// The host terminal in raw mode; dropping it restores the settings.
    pub struct RawMode {
        fd: i32,
        saved: libc::termios,
    }

    impl RawMode {
        pub fn enter(fd: i32) -> Option<RawMode> {
            if !is_terminal(fd) {
                return None;
            }
            // SAFETY: tcgetattr/tcsetattr with valid pointers.
            unsafe {
                let mut saved: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(fd, &mut saved) != 0 {
                    return None;
                }
                let mut raw = saved;
                libc::cfmakeraw(&mut raw);
                if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                    return None;
                }
                Some(RawMode { fd, saved })
            }
        }
    }

    impl Drop for RawMode {
        fn drop(&mut self) {
            // SAFETY: restoring settings read by tcgetattr.
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
        }
    }
}
