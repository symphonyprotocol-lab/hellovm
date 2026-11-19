//! `hellovm`: runs a Linux program inside the hellovm kernel.
//!
//! ```text
//! hellovm [--trace] [--timeout SECONDS] [--tty | --no-tty]
//!         [--egress SOCKET] [--sandbox-id ID] [--fs-limit BYTES]
//!         [--sandbox require|best-effort|off] --root DIR
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
//! every syscall the kernel handled to stderr. `--fs-limit` caps the
//! in-memory writable layer (file contents plus a small cost per file;
//! default 2 GiB): writes past it fail with `ENOSPC`.
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
//!
//! Before it reads the program, hellovm takes away its own privileges
//! (`hellovm-sandbox`): it closes inherited fds, enters user, mount,
//! network and IPC namespaces with an empty root, lowers its resource
//! limits, sets `no_new_privs`, restricts itself with Landlock to reading
//! the image, becomes non-dumpable and installs a seccomp allowlist.
//! `--sandbox best-effort` (the default) uses every layer the host allows
//! and logs the reason for each one it skips (as a warning when what is
//! left is less than `require` asks for); `--sandbox require` refuses
//! to start (exit 125) when a required layer is unavailable; `--sandbox
//! off` uses none. `HELLOVM_LOG=debug` lists the active layers.
//!
//! Warm clones (see README, "Warm clones"):
//!
//! ```text
//! hellovm --template SOCKET [options as above, but not --tty or --timeout]
//!         --root DIR PROGRAM [ARGS...]
//! hellovm --clone SOCKET [--sandbox-id ID] [--input DATA] [--timeout SECONDS]
//! hellovm --clone SOCKET --ready
//! ```
//!
//! `--template` runs the program as a template: with no console input,
//! until it reads `/dev/hellovm-clone`; then the sandbox is frozen and
//! hellovm serves clones of it on the Unix socket `SOCKET` (created; it
//! must not exist) until it is killed. Its clones die with it. `--clone`
//! asks such a template for a clone whose console is this process's stdin,
//! stdout and stderr, whose read of `/dev/hellovm-clone` returns `DATA`
//! (then end of file), and exits with the clone's status (125 if it could
//! not be made). `--ready` only waits until the template is frozen.
//!
//! `HELLOVM_LOG` sets the log level (`error`, `warn` (default), `info`,
//! `debug`, `trace`).
//!
//! On macOS on Apple silicon, programs run on the HVF platform
//! (Hypervisor.framework; aarch64 Linux programs only, on one vCPU), and
//! only the first form works, without
//! `--egress` and `--template`/`--clone`. Nothing hardens the kernel
//! process there: `--sandbox require` refuses to start. The executable
//! must be signed with the hypervisor entitlement (see README, "The HVF
//! platform").

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::ExitCode;

use hellovm_sandbox::Mode as SandboxMode;

#[cfg(target_os = "linux")]
mod template;

const USAGE: &str = "usage: hellovm [--trace] [--timeout SECONDS] [--tty | --no-tty] \
     [--egress SOCKET] [--sandbox-id ID] [--fs-limit BYTES] [--sandbox require|best-effort|off] --root DIR \
     [--env NAME=VALUE]... [--] PROGRAM [ARGS...]
       hellovm --template SOCKET [options] --root DIR PROGRAM [ARGS...]
       hellovm --clone SOCKET [--sandbox-id ID] [--input DATA] [--timeout SECONDS] [--ready]";

/// How long hellovm waits, after the program ends, for outbound bytes the
/// sandbox already wrote to be delivered.
#[cfg(target_os = "linux")]
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

#[cfg_attr(
    not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))),
    allow(dead_code)
)]
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
    /// `--fs-limit BYTES`: the writable layer's limit.
    fs_limit: Option<u64>,
    /// Test hook: splice outbound TCP to this loopback address.
    #[cfg(feature = "insecure-test-hooks")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    splice_to: Option<std::net::SocketAddr>,
    /// Test hook: serve programs on stdin (`hellovm::session`).
    #[cfg(feature = "insecure-test-hooks")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    session: bool,
    /// Test hook: try to break out of the hardened process, then exit.
    #[cfg(feature = "insecure-test-hooks")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fence_test: Option<String>,
    sandbox: SandboxMode,
    env: Vec<Vec<u8>>,
    argv: Vec<Vec<u8>>,
    /// `--template SOCKET`.
    template: Option<PathBuf>,
    /// `--clone SOCKET`.
    clone: Option<PathBuf>,
    /// `--input DATA` (with `--clone`).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    input: Vec<u8>,
    /// `--ready` (with `--clone`).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ready: bool,
}

fn parse_args(args: impl Iterator<Item = OsString>) -> Result<Options, String> {
    let mut trace = false;
    let mut tty = None;
    let mut timeout = None;
    let mut root = None;
    let mut egress = None;
    let mut sandbox_id = None;
    let mut fs_limit = None;
    #[cfg(feature = "insecure-test-hooks")]
    let mut splice_to = None;
    #[cfg(feature = "insecure-test-hooks")]
    let mut session = false;
    #[cfg(feature = "insecure-test-hooks")]
    let mut fence_test = None;
    let mut sandbox = SandboxMode::default();
    let mut template = None;
    let mut clone = None;
    let mut input = Vec::new();
    let mut ready = false;
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
            Some("--template") => {
                args.next();
                template = Some(PathBuf::from(
                    args.next().ok_or("--template needs a socket path")?,
                ));
                continue;
            }
            Some("--clone") => {
                args.next();
                clone = Some(PathBuf::from(
                    args.next().ok_or("--clone needs a socket path")?,
                ));
                continue;
            }
            Some("--input") => {
                args.next();
                input = args.next().ok_or("--input needs data")?.into_vec();
                continue;
            }
            Some("--ready") => ready = true,
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
            Some("--fs-limit") => {
                args.next();
                let value = args.next().ok_or("--fs-limit needs a number of bytes")?;
                let text = value.to_string_lossy();
                fs_limit = Some(
                    text.parse::<u64>()
                        .ok()
                        .filter(|&n| n > 0)
                        .ok_or_else(|| format!("--fs-limit {text}: expected a number of bytes"))?,
                );
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
            Some("--sandbox") => {
                args.next();
                let value = args
                    .next()
                    .ok_or("--sandbox needs require, best-effort or off")?;
                sandbox = value.to_string_lossy().parse()?;
                continue;
            }
            Some(flag) if flag.starts_with("--sandbox=") => {
                sandbox = flag["--sandbox=".len()..].parse()?;
            }
            #[cfg(feature = "insecure-test-hooks")]
            Some("--insecure-test-session") => session = true,
            #[cfg(feature = "insecure-test-hooks")]
            Some("--insecure-fence-test") => {
                args.next();
                let value = args.next().ok_or("--insecure-fence-test needs a test")?;
                fence_test = Some(value.to_string_lossy().into_owned());
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
    if let Some(clone) = clone {
        if !argv.is_empty() || template.is_some() {
            return Err(format!("--clone takes no program\n{USAGE}"));
        }
        return Ok(Options {
            trace,
            tty,
            timeout,
            root: PathBuf::new(),
            egress,
            sandbox_id,
            fs_limit,
            #[cfg(feature = "insecure-test-hooks")]
            splice_to,
            #[cfg(feature = "insecure-test-hooks")]
            session,
            #[cfg(feature = "insecure-test-hooks")]
            fence_test,
            sandbox,
            env,
            argv,
            template,
            clone: Some(clone),
            input,
            ready,
        });
    }
    if !input.is_empty() || ready {
        return Err(format!("--input and --ready go with --clone\n{USAGE}"));
    }
    if template.is_some() && (tty == Some(true) || timeout.is_some()) {
        return Err(format!(
            "--template: a template has no terminal and no --timeout (a clone can have one)\n{USAGE}"
        ));
    }
    #[cfg(feature = "insecure-test-hooks")]
    let needs_program = !session && fence_test.is_none();
    #[cfg(not(feature = "insecure-test-hooks"))]
    let needs_program = true;
    if argv.is_empty() && needs_program {
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
        fs_limit,
        #[cfg(feature = "insecure-test-hooks")]
        splice_to,
        #[cfg(feature = "insecure-test-hooks")]
        session,
        #[cfg(feature = "insecure-test-hooks")]
        fence_test,
        sandbox,
        env,
        argv,
        template,
        clone: None,
        input,
        ready,
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
    #[cfg(target_os = "linux")]
    if let Some(socket) = &options.clone {
        return ExitCode::from(template::client(
            socket,
            options.sandbox_id,
            &options.input,
            options.ready,
            options.timeout,
        ));
    }
    // Before anything opens an fd of its own.
    #[cfg(target_os = "linux")]
    let fds = if options.sandbox == SandboxMode::Off {
        Err("--sandbox=off".to_string())
    } else {
        hellovm_sandbox::close_inherited_fds()
    };
    #[cfg(not(target_os = "linux"))]
    let fds: Result<usize, String> = Err("not Linux".into());
    match run(&options, fds) {
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
#[cfg_attr(
    not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))),
    allow(dead_code)
)]
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

/// Applies `hellovm-sandbox` to this process, after checking that the
/// platform can still do without `/proc` what it will have to. Moves
/// `image` to where the hardening left the directory, and returns where
/// the egress socket is now reachable and whether Landlock is active.
#[cfg(target_os = "linux")]
fn harden(
    options: &Options,
    image: &mut hellovm_host::ImageDir,
    egress: Option<PathBuf>,
    fds: Result<usize, String>,
    warm: bool,
) -> Result<(Option<PathBuf>, bool), Box<dyn std::error::Error>> {
    #[cfg(feature = "insecure-test-hooks")]
    let (tcp_port, learn, skip_landlock) = (
        options.splice_to.map(|addr| addr.port()),
        // A fence test's attempts are what the allowlist must refuse:
        // they are enforced, never recorded as something it should allow.
        std::env::var_os("HELLOVM_SECCOMP_LEARN")
            .filter(|_| options.fence_test.is_none())
            .map(PathBuf::from),
        std::env::var_os("HELLOVM_TEST_NO_LANDLOCK").is_some(),
    );
    #[cfg(not(feature = "insecure-test-hooks"))]
    let (tcp_port, learn, skip_landlock) = (None, None, false);
    hellovm_platform_seccomp::check_clean_spawn()?;
    let hardened = hellovm_sandbox::apply(hellovm_sandbox::Config {
        mode: options.sandbox,
        image: image.dir_fd(),
        image_path: image.root(),
        egress,
        tcp_port,
        learn,
        skip_landlock,
        warm,
        fds,
    })?;
    if let Some(dir) = hardened.image {
        image.rebind(dir);
    }
    let landlock = hardened.report.active(hellovm_sandbox::Layer::Landlock);
    Ok((hardened.report.egress, landlock))
}

#[cfg(target_os = "linux")]
fn run(options: &Options, fds: Result<usize, String>) -> Result<Ended, Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use hellovm_core::Kernel;
    use hellovm_host::{ImageDir, StdioHost};
    use hellovm_platform_seccomp::SeccompPlatform;

    let image = ImageDir::open(&options.root)
        .map_err(|err| format!("image {}: {err}", options.root.display()))?;
    let egress = options
        .egress
        .as_deref()
        .map(std::path::absolute)
        .transpose()?;
    #[cfg(feature = "insecure-test-hooks")]
    if options.session {
        return run_session(options, image, egress, fds);
    }
    if let Some(socket) = &options.template {
        drop(image);
        return template::run(options, socket, fds);
    }
    // Takes the host profile the sandbox and the platform share.
    let mut app = SeccompPlatform::new()?;
    // Before the hardening: the host opens what it needs from the host's
    // filesystem (`/dev/urandom`) now.
    let mut host = StdioHost::new(Some(image));
    #[cfg(feature = "insecure-test-hooks")]
    if let Some(addr) = options.splice_to {
        // Every issued fake IP is spliced here. The guest address is not dialed.
        host.set_splice_endpoint(addr);
    }
    let image = host.image_mut().expect("the host has the image");
    if let (Some(path), _) = harden(options, image, egress, fds, false)? {
        host.set_egress(path);
    }
    #[cfg(feature = "insecure-test-hooks")]
    if let Some(test) = &options.fence_test {
        fence_test(test);
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
    if let Some(bytes) = options.fs_limit {
        kernel = kernel.with_fs_limit(bytes);
    }
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

/// `--insecure-test-session`: see `hellovm::session`.
#[cfg(all(target_os = "linux", feature = "insecure-test-hooks"))]
fn run_session(
    options: &Options,
    image: hellovm_host::ImageDir,
    egress: Option<PathBuf>,
    fds: Result<usize, String>,
) -> Result<Ended, Box<dyn std::error::Error>> {
    let mut host = hellovm_host::CaptureHost::new(Some(image));
    hellovm_platform_seccomp::host_profile()?;
    let image = host.image_mut().expect("the host has the image");
    let (egress, _) = harden(options, image, egress, fds, false)?;
    if let Some(addr) = options.splice_to {
        host.set_splice_endpoint(addr);
    }
    let mut kernel = hellovm_core::Kernel::new(host);
    if let Some(id) = options.sandbox_id {
        kernel = kernel.with_sandbox_id(id);
    }
    if options.trace {
        kernel = kernel.with_trace();
    }
    if let Some(path) = egress {
        kernel.host_mut().set_egress(path);
    }
    hellovm::session::serve(kernel)?;
    Ok(Ended::Status(hellovm_core::ExitStatus::Exited(0)))
}

/// `--insecure-fence-test`: from inside the hardened kernel process, tries
/// something the hardening must stop, reports and exits: 0 when it was
/// refused, 1 when it worked (a process the hardening kills never gets
/// to report).
#[cfg(all(target_os = "linux", feature = "insecure-test-hooks"))]
fn fence_test(test: &str) -> ! {
    let outcome: Result<String, String> = match test {
        "open-host-file" => match std::fs::read("/etc/passwd") {
            Ok(data) => Ok(format!("read {} bytes", data.len())),
            Err(err) => Err(err.to_string()),
        },
        t if t.starts_with("tcp-connect:") => match std::net::TcpStream::connect(&t[12..]) {
            Ok(_) => Ok("connected".into()),
            Err(err) => Err(err.to_string()),
        },
        "unix-connect-abstract" => {
            use std::os::linux::net::SocketAddrExt;
            match std::os::unix::net::SocketAddr::from_abstract_name(b"hellovm-fence-test")
                .and_then(|addr| std::os::unix::net::UnixStream::connect_addr(&addr))
            {
                Ok(_) => Ok("connected".into()),
                Err(err) => Err(err.to_string()),
            }
        }
        "open-above-image" => {
            // Every directory fd the kernel process holds, and `..` from it.
            let found = (3..256).find(|&fd| {
                // SAFETY: openat with a valid C string.
                let up = unsafe {
                    libc::openat(
                        fd,
                        c"../../../../../../../../etc/passwd".as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC,
                    )
                };
                up >= 0
            });
            match found {
                Some(fd) => Ok(format!("opened /etc/passwd above fd {fd}")),
                None => Err("no fd leads above the image".into()),
            }
        }
        "read-parent-memory" => {
            let mut byte = 0u8;
            let local = libc::iovec {
                iov_base: (&mut byte as *mut u8).cast(),
                iov_len: 1,
            };
            // An address nothing is mapped at: with access, EFAULT.
            let remote = libc::iovec {
                iov_base: 0x1000 as *mut libc::c_void,
                iov_len: 1,
            };
            // SAFETY: valid iovecs; reads at most one byte into `byte`.
            let ret = unsafe { libc::process_vm_readv(libc::getppid(), &local, 1, &remote, 1, 0) };
            let err = std::io::Error::last_os_error();
            if ret >= 0 || err.raw_os_error() == Some(libc::EFAULT) {
                Ok("the parent's memory is accessible".into())
            } else {
                Err(err.to_string())
            }
        }
        "forbidden-syscall" => {
            // setns(-1, 0): harmless even if it ran (EBADF), and never
            // made by the kernel process.
            // SAFETY: plain syscall with integer arguments.
            let ret = unsafe { libc::syscall(libc::SYS_setns, -1, 0) };
            Ok(format!(
                "setns returned {ret}: {}",
                std::io::Error::last_os_error()
            ))
        }
        "ptrace-attach" => {
            // SAFETY: plain syscall with integer arguments.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_ptrace,
                    libc::PTRACE_ATTACH,
                    libc::getppid(),
                    0usize,
                    0usize,
                )
            };
            if ret == 0 {
                Ok("attached to the parent".into())
            } else {
                Err(std::io::Error::last_os_error().to_string())
            }
        }
        other => {
            eprintln!("fence: unknown test {other}");
            std::process::exit(2);
        }
    };
    match outcome {
        Ok(what) => {
            println!("fence: {test}: allowed: {what}");
            std::process::exit(1);
        }
        Err(why) => {
            println!("fence: {test}: refused: {why}");
            std::process::exit(0);
        }
    }
}

/// macOS on Apple silicon: the HVF platform. No hardening, no egress, no
/// warm clones.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run(
    options: &Options,
    _fds: Result<usize, String>,
) -> Result<Ended, Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use hellovm_core::Kernel;
    use hellovm_host::{ImageDir, StdioHost};
    use hellovm_platform_hvf::{HvfConfig, HvfPlatform};

    if options.template.is_some() || options.clone.is_some() {
        return Err("warm clones (--template, --clone) need Linux".into());
    }
    if options.egress.is_some() {
        return Err("--egress is not supported on macOS yet".into());
    }
    match options.sandbox {
        SandboxMode::Require => {
            return Err(
                "--sandbox require: the kernel process cannot be hardened on macOS (yet)".into(),
            )
        }
        SandboxMode::BestEffort => {
            log::warn!("no hardening of the kernel process on macOS (--sandbox off to silence)")
        }
        SandboxMode::Off => {}
    }
    let image = ImageDir::open(&options.root)
        .map_err(|err| format!("image {}: {err}", options.root.display()))?;
    let mut app = HvfPlatform::new(HvfConfig::default())?;
    let host = StdioHost::new(Some(image));
    let mut kernel = Kernel::new(host);
    if let Some(id) = options.sandbox_id {
        kernel = kernel.with_sandbox_id(id);
    }
    if let Some(bytes) = options.fs_limit {
        kernel = kernel.with_fs_limit(bytes);
    }
    if options.trace {
        kernel = kernel.with_trace();
    }
    let terminal = options
        .tty
        .unwrap_or_else(|| host_tty::is_terminal(0) && host_tty::is_terminal(1));
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
    let timed_out = Arc::new(AtomicBool::new(false));
    if let Some(timeout) = options.timeout {
        let killer = app.killer();
        let timed_out = Arc::clone(&timed_out);
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            timed_out.store(true, Ordering::SeqCst);
            killer.kill();
        });
    }
    let status = kernel.run(&mut app);
    for record in kernel.trace() {
        eprintln!("hellovm: trace: {record}");
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

#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
fn run(
    _options: &Options,
    _fds: Result<usize, String>,
) -> Result<Ended, Box<dyn std::error::Error>> {
    Err(
        "no platform for this host: hellovm runs programs on Linux (seccomp) \
         and on macOS on Apple silicon (Hypervisor.framework)"
            .into(),
    )
}

/// The host terminal hellovm runs in, if any.
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
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
