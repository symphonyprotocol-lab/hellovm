//! `cansol`: runs a Linux program inside the cansol kernel.
//!
//! ```text
//! cansol [--trace] [--] PROGRAM [ARGS...]
//! ```
//!
//! The program's console output goes to cansol's own stdout and stderr, and
//! cansol exits with the program's exit status (128 + signal number if it
//! was killed). `--trace` prints every syscall the kernel handled to stderr.
//! `CANSOL_LOG` sets the log level (`error`, `warn` (default), `info`,
//! `debug`, `trace`).

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "usage: cansol [--trace] [--] PROGRAM [ARGS...]";

struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let level = record.level().as_str().to_lowercase();
            let _ = writeln!(std::io::stderr(), "cansol: {level}: {}", record.args());
        }
    }

    fn flush(&self) {}
}

fn init_logging() {
    let level = std::env::var("CANSOL_LOG")
        .ok()
        .and_then(|level| level.parse().ok())
        .unwrap_or(log::LevelFilter::Warn);
    log::set_max_level(level);
    let _ = log::set_logger(&StderrLogger);
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Options {
    trace: bool,
    argv: Vec<OsString>,
}

fn parse_args(args: impl Iterator<Item = OsString>) -> Result<Options, String> {
    let mut trace = false;
    let mut args = args.peekable();
    while let Some(arg) = args.peek() {
        match arg.to_str() {
            Some("--trace") => trace = true,
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
    let argv: Vec<OsString> = args.collect();
    if argv.is_empty() {
        return Err(USAGE.to_string());
    }
    Ok(Options { trace, argv })
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
        Ok(cansol_core::ExitStatus::Exited(code)) => ExitCode::from(code as u8),
        Ok(cansol_core::ExitStatus::Signaled(signal)) => {
            eprintln!("cansol: program killed by signal {signal}");
            ExitCode::from((128 + signal).min(255) as u8)
        }
        Err(err) => {
            eprintln!("cansol: {err}");
            ExitCode::from(125)
        }
    }
}

#[cfg(target_os = "linux")]
fn run(options: &Options) -> Result<cansol_core::ExitStatus, Box<dyn std::error::Error>> {
    use cansol_core::Kernel;
    use cansol_host::StdioHost;
    use cansol_platform_seccomp::SeccompApp;

    let program = std::path::Path::new(&options.argv[0]);
    let mut app = SeccompApp::spawn(program, &options.argv)?;
    let mut kernel = Kernel::new(StdioHost);
    if options.trace {
        kernel = kernel.with_trace();
    }
    let status = kernel.run(&mut app);
    for record in kernel.trace() {
        eprintln!("cansol: trace: {record}");
    }
    Ok(status?)
}

#[cfg(not(target_os = "linux"))]
fn run(_options: &Options) -> Result<cansol_core::ExitStatus, Box<dyn std::error::Error>> {
    Err("no platform for this host yet: only Linux (seccomp) is implemented".into())
}
