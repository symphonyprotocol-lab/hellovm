//! Helpers shared by the end-to-end tests: temporary image directories and
//! running a program from one under the seccomp platform, in a hardened
//! kernel process ([`Session`]).
//!
//! `HELLOVM_REQUIRE_E2E=1` is the only value that turns a missing busybox,
//! CPython or native test guest into a failure. Any other value keeps the
//! skip-and-return behaviour.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use hellovm::session::{self, Reply, Request, RunOutput};
use hellovm_core::errno::Errno;
use hellovm_core::{ExitStatus, KernelError, SyscallRecord};

/// True only when `HELLOVM_REQUIRE_E2E` is exactly `1`.
pub fn e2e_required() -> bool {
    std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1")
}

/// `reason` names what is missing and how to install it, with no
/// `SKIPPING` prefix. An optional run prints `SKIPPING {reason}` so
/// `run-e2e.sh` can see the skip. When [`e2e_required`] is set, the test
/// panics with `required e2e dependency missing: {reason}`.
pub fn skip_or_fail(reason: &str) {
    if e2e_required() {
        panic!("required e2e dependency missing: {reason}");
    } else {
        eprintln!("SKIPPING {reason}");
    }
}

/// Host busybox (`$HELLOVM_BUSYBOX`, default `/bin/busybox`).
///
/// `None` means the binary is missing and the caller should return: the
/// skip was printed. When e2e is required this panics instead of returning
/// `None`, and the message names Debian/Ubuntu `busybox-static`.
pub fn require_busybox(what: &str) -> Option<String> {
    let path = std::env::var("HELLOVM_BUSYBOX").unwrap_or_else(|_| "/bin/busybox".into());
    if Path::new(&path).exists() {
        return Some(path);
    }
    skip_or_fail(&format!(
        "{what}: {path} not found (install Debian/Ubuntu busybox-static, not a musl binary from busybox.net)"
    ));
    None
}

/// Native `hellovm-test-guest` program. An empty path means it was not built
/// (cross-compiling). Returns false when the caller should return.
pub fn require_guest(path: &str, name: &str) -> bool {
    if !path.is_empty() {
        return true;
    }
    skip_or_fail(&format!(
        "the {name} guest is not built when cross-compiling (need a native Linux build so hellovm-test-guest guests are not empty; install gcc and libc6-dev)"
    ));
    false
}

/// A directory under the system temp dir, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("hellovm-test-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Writes a file (creating parent directories).
    pub fn write(&self, rel: &str, data: &[u8]) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }

    /// Copies a host executable into the image at `rel`.
    pub fn install(&self, host_path: &str, rel: &str) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::copy(host_path, &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    pub fn symlink(&self, target: &str, rel: &str) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, path).unwrap();
    }

    pub fn mkdir(&self, rel: &str) {
        fs::create_dir_all(self.0.join(rel)).unwrap();
    }

    /// Copies a host file to the same path in the image (following
    /// symlinks), unless it is there already.
    pub fn copy_host_file(&self, host_path: &Path) {
        let dest = self.0.join(host_path.strip_prefix("/").unwrap());
        if dest.exists() {
            return;
        }
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::copy(host_path, &dest)
            .unwrap_or_else(|err| panic!("copying {}: {err}", host_path.display()));
    }

    /// Copies a host executable or library to the same path in the image,
    /// with the shared libraries and the program interpreter it needs (as
    /// `ldd` lists them).
    pub fn install_with_libs(&self, host_path: &Path) {
        self.copy_host_file(host_path);
        for lib in shared_libraries(host_path) {
            self.copy_host_file(&lib);
        }
    }

    /// Copies a host directory tree to the same path in the image, keeping
    /// symlinks as symlinks.
    pub fn copy_host_tree(&self, host_dir: &Path) {
        for entry in fs::read_dir(host_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).unwrap();
            let dest = self.0.join(path.strip_prefix("/").unwrap());
            if meta.is_dir() {
                fs::create_dir_all(&dest).unwrap();
                self.copy_host_tree(&path);
            } else if meta.file_type().is_symlink() {
                let target = fs::read_link(&path).unwrap();
                let _ = std::os::unix::fs::symlink(target, dest);
            } else if meta.is_file() {
                self.copy_host_file(&path);
            }
        }
    }
}

/// The shared libraries (and program interpreter) a host binary needs,
/// from `ldd`. Empty for static binaries.
pub fn shared_libraries(binary: &Path) -> Vec<PathBuf> {
    let output = std::process::Command::new("ldd")
        .arg(binary)
        .output()
        .expect("run ldd");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter(|w| w.starts_with('/'))
        .map(PathBuf::from)
        .collect()
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// How long one program may run before the test kills its session, so
/// that a hanging test fails instead of blocking the run.
pub const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// How a [`Session`] is started.
#[derive(Clone, Debug, Default)]
pub struct SessionOptions {
    pub trace: bool,
    pub egress: Option<PathBuf>,
    pub splice: Option<std::net::SocketAddr>,
    pub sandbox_id: Option<u64>,
}

/// One sandbox (one kernel, one filesystem) in its own hardened kernel
/// process: `hellovm --insecure-test-session`, which applies exactly the
/// hardening a normal `hellovm` run does (`--sandbox best-effort`) before
/// it serves the programs the test runs. Every in-process scenario of the
/// end-to-end tests goes through one, so each runs with least privilege.
pub struct Session {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: ChildStdout,
}

impl Session {
    pub fn start(image: &Path, options: &SessionOptions) -> Session {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hellovm"));
        command
            .arg("--insecure-test-session")
            .arg("--root")
            .arg(image);
        if options.trace {
            command.arg("--trace");
        }
        if let Some(egress) = &options.egress {
            command.arg("--egress").arg(egress);
        }
        if let Some(addr) = options.splice {
            command.arg("--splice-to").arg(addr.to_string());
        }
        if let Some(id) = options.sandbox_id {
            command.arg("--sandbox-id").arg(id.to_string());
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start hellovm --insecure-test-session");
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        Session {
            child: Some(child),
            input: Some(input),
            output,
        }
    }

    fn request(&mut self, request: Request) -> Reply {
        let pid = self.child.as_ref().unwrap().id() as libc::pid_t;
        let done = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let thread_done = std::sync::Arc::clone(&done);
        let watchdog = std::thread::spawn(move || {
            let (lock, cvar) = &*thread_done;
            let guard = lock.lock().unwrap();
            let (guard, timeout) = cvar.wait_timeout_while(guard, LIMIT, |d| !*d).unwrap();
            if timeout.timed_out() && !*guard {
                eprintln!("watchdog: the sandbox ran for {LIMIT:?}; killing it");
                // SAFETY: plain syscall; the child is not reaped before the
                // session is dropped, so the pid still names it.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        });
        let reply = session::send(self.input.as_mut().unwrap(), &request.encode())
            .and_then(|()| session::receive(&mut self.output));
        {
            let (lock, cvar) = &*done;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        watchdog.join().unwrap();
        match reply {
            Ok(Some(body)) => Reply::decode(&body).expect("decode a session reply"),
            Ok(None) | Err(_) => {
                let status = self
                    .child
                    .as_mut()
                    .unwrap()
                    .wait()
                    .expect("wait for the session");
                panic!("the hardened kernel process ended: {status}")
            }
        }
    }

    /// Runs `argv` with `env` and `stdin` as console input; waits up to
    /// `drain` for outbound bytes afterwards.
    pub fn run(
        &mut self,
        argv: &[&str],
        env: &[&str],
        stdin: &[u8],
        drain: std::time::Duration,
    ) -> Result<RunOutput, KernelError> {
        let bytes = |list: &[&str]| -> Vec<Vec<u8>> {
            list.iter().map(|a| a.as_bytes().to_vec()).collect()
        };
        match self.request(Request::Run {
            argv: bytes(argv),
            env: bytes(env),
            stdin: stdin.to_vec(),
            drain_ms: drain.as_millis() as u32,
        }) {
            Reply::Ran(out) => Ok(out),
            Reply::ExecFailed {
                path,
                errno,
                reason,
            } => Err(KernelError::Exec {
                path,
                errno: Errno(errno),
                reason,
            }),
            Reply::Failed(msg) => panic!("{argv:?}: {msg}"),
            other => panic!("unexpected reply {other:?}"),
        }
    }

    pub fn set_fs_limit(&mut self, bytes: u64) {
        match self.request(Request::SetFsLimit(bytes)) {
            Reply::Done => {}
            other => panic!("unexpected reply {other:?}"),
        }
    }

    pub fn issue_fake_ip(&mut self) -> Option<[u8; 4]> {
        match self.request(Request::IssueFakeIp) {
            Reply::FakeIp(ip) => ip,
            other => panic!("unexpected reply {other:?}"),
        }
    }
}

impl Drop for Session {
    /// Ends the session like `hellovm` ends: closing its input makes the
    /// kernel process deliver the outbound bytes its programs already wrote
    /// (for at most 10 s) and exit. That happens in the background, as the
    /// helpers of an in-process kernel used to keep delivering after it was
    /// dropped; the process is killed if it is still there after 30 s.
    fn drop(&mut self) {
        drop(self.input.take());
        let Some(mut child) = self.child.take() else {
            return;
        };
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(30) {
                if let Ok(Some(_)) = child.try_wait() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        });
    }
}

/// The outcome of running a program.
#[derive(Debug)]
pub struct Run {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    /// Every syscall the program made.
    pub trace: Vec<SyscallRecord>,
}

/// Runs `argv` (argv[0] is the path inside the sandbox) with `image` as the
/// root, `stdin` as console input and a trace.
pub fn try_run(image: &Path, argv: &[&str], stdin: &[u8]) -> Result<Run, KernelError> {
    let mut session = Session::start(
        image,
        &SessionOptions {
            trace: true,
            ..SessionOptions::default()
        },
    );
    let out = session.run(
        argv,
        &["PATH=/bin", "HOME=/"],
        stdin,
        std::time::Duration::ZERO,
    )?;
    Ok(Run {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        trace: out.trace,
    })
}

pub fn run(image: &Path, argv: &[&str]) -> Run {
    try_run(image, argv, b"").unwrap_or_else(|err| panic!("{argv:?}: {err}"))
}

/// One sandbox (one kernel, one filesystem) running programs one after
/// another, like the commands of a session.
pub struct Sandbox {
    session: Session,
}

/// What one program in a [`Sandbox`] did.
#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn code(&self) -> i32 {
        match self.status {
            ExitStatus::Exited(code) => code,
            ExitStatus::Signaled(sig) => 128 + sig as i32,
        }
    }
}

impl Sandbox {
    pub fn new(image: &Path) -> Sandbox {
        Sandbox {
            session: Session::start(image, &SessionOptions::default()),
        }
    }

    /// Limits the in-memory filesystem layer ([`hellovm_core::Kernel::set_fs_limit`]).
    pub fn set_fs_limit(&mut self, bytes: u64) {
        self.session.set_fs_limit(bytes);
    }

    /// Runs `argv` with `stdin` as console input.
    pub fn run_with_input(&mut self, argv: &[&str], stdin: &[u8]) -> Output {
        let out = self
            .session
            .run(
                argv,
                &["PATH=/bin", "HOME=/root"],
                stdin,
                std::time::Duration::ZERO,
            )
            .unwrap_or_else(|err| panic!("exec {argv:?}: {err}"));
        Output {
            status: out.status,
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    pub fn run(&mut self, argv: &[&str]) -> Output {
        self.run_with_input(argv, b"")
    }

    /// Runs a busybox applet: `/bin/busybox <args>`.
    pub fn bb(&mut self, args: &[&str]) -> Output {
        let mut argv = vec!["/bin/busybox"];
        argv.extend_from_slice(args);
        self.run(&argv)
    }

    /// Runs a busybox applet that must succeed and returns its stdout.
    pub fn ok(&mut self, args: &[&str]) -> String {
        let out = self.bb(args);
        assert_eq!(out.status, ExitStatus::Exited(0), "{args:?}: {out:?}");
        out.stdout
    }
}

/// A `hellovm --template SOCKET` process (warm clones, see `tests/warm.rs`)
/// whose image is the host's `/`. Killed on drop, which kills its clones.
pub struct Template {
    child: Child,
    pub socket: PathBuf,
    _dir: TempDir,
    output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

/// Collects everything `reader` produces into `into`, on a thread.
fn collect(
    mut reader: impl std::io::Read + Send + 'static,
    into: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = reader.read(&mut chunk) {
            if n == 0 {
                break;
            }
            into.lock().unwrap().extend_from_slice(&chunk[..n]);
        }
    })
}

/// What a finished clone did.
#[derive(Debug)]
pub struct CloneRun {
    pub status: hellovm::warm::Status,
    pub started: hellovm::warm::Started,
    pub stdout: String,
    pub stderr: String,
}

/// A clone that runs, with pipes for its console.
pub struct RunningClone {
    pub conn: hellovm::warm::WarmClone,
    pub started: hellovm::warm::Started,
    pub stdin: Option<std::io::PipeWriter>,
    stdout: std::io::BufReader<std::io::PipeReader>,
    stderr: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    stderr_done: std::thread::JoinHandle<()>,
}

impl RunningClone {
    /// The next line of the clone's stdout (empty at end of file).
    pub fn line(&mut self) -> String {
        let mut line = String::new();
        std::io::BufRead::read_line(&mut self.stdout, &mut line).unwrap();
        line
    }

    /// Writes to the clone's stdin.
    pub fn send(&mut self, data: &[u8]) {
        std::io::Write::write_all(self.stdin.as_mut().unwrap(), data).unwrap();
    }

    /// Kills the clone by closing the connection; returns the rest of its
    /// stdout (up to the end of file its death causes).
    pub fn kill(mut self) -> String {
        self.conn.kill();
        // stdin stays open until the clone is gone, so that it cannot see
        // end of input first.
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut self.stdout, &mut rest).unwrap();
        rest
    }

    /// Closes stdin, reads the rest of the output and waits for the end.
    pub fn finish(mut self) -> CloneRun {
        self.stdin = None;
        let mut stdout = String::new();
        std::io::Read::read_to_string(&mut self.stdout, &mut stdout).unwrap();
        let status = self.conn.wait().expect("the clone's exit status");
        self.stderr_done.join().unwrap();
        let stderr = String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned();
        CloneRun {
            status,
            started: self.started,
            stdout,
            stderr,
        }
    }
}

impl Template {
    /// Starts `argv` as a template; `options` go before `--root`.
    pub fn start(argv: &[&str], options: &[&str]) -> Template {
        Template::start_with_env(argv, options, &[])
    }

    /// [`Template::start`] with environment variables for the kernel
    /// process (test hooks).
    pub fn start_with_env(argv: &[&str], options: &[&str], env: &[(&str, &str)]) -> Template {
        let dir = TempDir::new("template");
        let socket = dir.path().join("template.sock");
        let mut child = Command::new(env!("CARGO_BIN_EXE_hellovm"))
            .arg("--template")
            .arg(&socket)
            .args(options)
            .args(["--root", "/", "--"])
            .args(argv)
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start hellovm --template");
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        collect(child.stdout.take().unwrap(), output.clone());
        collect(child.stderr.take().unwrap(), output.clone());
        Template {
            child,
            socket,
            _dir: dir,
            output,
        }
    }

    /// The template's kernel process.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// What the template process printed (its guest's console before the
    /// freeze, and hellovm's messages).
    pub fn output(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    /// Waits until the template is frozen: the bytes and areas of its
    /// snapshot, or the error it answered.
    pub fn ready(&self) -> std::io::Result<(u64, u32)> {
        let start = std::time::Instant::now();
        while !self.socket.exists() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(30),
                "no control socket after 30 s:\n{}",
                self.output()
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // The socket file is there from `bind` on, a moment before the
        // template listens on it.
        loop {
            match hellovm::warm::wait_ready(&self.socket) {
                Err(err)
                    if err.kind() == std::io::ErrorKind::ConnectionRefused
                        && start.elapsed() < std::time::Duration::from_secs(1) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2))
                }
                other => return other,
            }
        }
    }

    /// Waits for the template process to end.
    pub fn wait(&mut self) -> std::process::ExitStatus {
        self.child.wait().unwrap()
    }

    /// Asks for a clone with pipes as its console and waits until it runs.
    pub fn spawn(&self, sandbox_id: Option<u64>, input: &[u8]) -> std::io::Result<RunningClone> {
        use std::os::fd::AsFd;
        let (in_r, in_w) = std::io::pipe()?;
        let (out_r, out_w) = std::io::pipe()?;
        let (err_r, err_w) = std::io::pipe()?;
        let mut conn = hellovm::warm::WarmClone::request(
            &self.socket,
            sandbox_id,
            input,
            [in_r.as_fd(), out_w.as_fd(), err_w.as_fd()],
        )?;
        // Only the clone holds them now: its end of output is end of file.
        drop((in_r, out_w, err_w));
        let started = conn.start()?;
        let stderr = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stderr_done = collect(err_r, stderr.clone());
        Ok(RunningClone {
            conn,
            started,
            stdin: Some(in_w),
            stdout: std::io::BufReader::new(out_r),
            stderr,
            stderr_done,
        })
    }

    /// Runs a clone to its end with `stdin` as its input.
    pub fn run(&self, input: &[u8], stdin: &[u8]) -> CloneRun {
        let mut clone = self
            .spawn(None, input)
            .unwrap_or_else(|err| panic!("a clone: {err}\n{}", self.output()));
        let stdin = stdin.to_vec();
        let mut writer = clone.stdin.take().unwrap();
        let feeder = std::thread::spawn(move || {
            let _ = std::io::Write::write_all(&mut writer, &stdin);
        });
        let run = clone.finish();
        feeder.join().unwrap();
        run
    }
}

impl Drop for Template {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
