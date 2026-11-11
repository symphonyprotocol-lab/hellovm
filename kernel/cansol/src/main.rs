//! `cansol`: runs a Linux program inside the cansol kernel.
//!
//! ```text
//! cansol [--trace] --root DIR [--env NAME=VALUE]... [--] PROGRAM [ARGS...]
//! ```
//!
//! `DIR` is the sandbox's read-only image: the program sees it as `/`, with
//! an in-memory writable layer on top (writes never reach `DIR`). `PROGRAM`
//! is a path inside the sandbox, e.g. `/bin/busybox`. The environment is
//! `PATH` and `HOME` plus every `--env`.
//!
//! The program's console output goes to cansol's own stdout and stderr, its
//! input comes from cansol's stdin, and cansol exits with the program's exit
//! status (128 + signal number if it was killed; 125 if it could not be
//! started). `--trace` prints every syscall the kernel handled to stderr.
//! `CANSOL_LOG` sets the log level (`error`, `warn` (default), `info`,
//! `debug`, `trace`).

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: cansol [--trace] --root DIR [--env NAME=VALUE]... [--] PROGRAM [ARGS...]";

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
    root: PathBuf,
    env: Vec<Vec<u8>>,
    argv: Vec<Vec<u8>>,
}

fn parse_args(args: impl Iterator<Item = OsString>) -> Result<Options, String> {
    let mut trace = false;
    let mut root = None;
    let mut env: Vec<Vec<u8>> = DEFAULT_ENV.iter().map(|e| e.as_bytes().to_vec()).collect();
    let mut args = args.peekable();
    while let Some(arg) = args.peek() {
        match arg.to_str() {
            Some("--trace") => trace = true,
            Some("--root") => {
                args.next();
                root = Some(PathBuf::from(args.next().ok_or("--root needs a directory")?));
                continue;
            }
            Some("--env") => {
                args.next();
                let var = args.next().ok_or("--env needs NAME=VALUE")?.into_vec();
                let Some(eq) = var.iter().position(|&b| b == b'=') else {
                    return Err(format!("--env {}: expected NAME=VALUE", String::from_utf8_lossy(&var)));
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
        root,
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
    use cansol_host::{ImageDir, StdioHost};
    use cansol_platform_seccomp::SeccompApp;

    let image = ImageDir::open(&options.root)
        .map_err(|err| format!("image {}: {err}", options.root.display()))?;
    let mut app = SeccompApp::new()?;
    let mut kernel = Kernel::new(StdioHost::new(Some(image)));
    if options.trace {
        kernel = kernel.with_trace();
    }
    kernel.exec(&mut app, &options.argv[0], &options.argv, &options.env)?;
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
