//! Warm clones on macOS (the HVF platform), end to end: `hellovm
//! --template` with CPython and busybox from the guest image
//! (`HELLOVM_HVF_GUESTS`), clones made through the control socket
//! (`hellovm::warm`) and the `--clone` command line, all under `--sandbox
//! require`. The macOS counterpart of `warm.rs`: what a clone sees, that
//! clones are isolated from the template and from each other, input and
//! exit status, `--ready`, `--timeout`, a template that dies, requesters
//! that break the protocol, many clones.
//!
//! One VM at a time, as in every HVF test (`hvf_support::serial`): the
//! template's kernel process has exited before the first clone starts,
//! and each clone's kernel process is gone before the next one starts.
//! The tests that need several clones alive at once (several VMs) run
//! only with `HELLOVM_HVF_CONCURRENT=1`.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod hvf_support;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hellovm::warm::{Frame, Started, Status, WarmClone};
use hvf_support::{guest_image, hellovm, progress};

/// A template that preloads modules and state, then runs the code each
/// clone gets as its input.
const PYTHON_TEMPLATE: &str = r#"
import json, hashlib, decimal, os, sys, time
preloaded = sorted(m for m in ("json", "hashlib", "decimal") if m in sys.modules)
data = bytearray(b"template")
big = bytearray(8 << 20)
big[::4096] = b"t" * (len(big) // 4096)
r, w = os.pipe()
os.write(w, b"pipe-data")
frozen_at = time.monotonic()
print("template ready", flush=True)
code = open("/dev/hellovm-clone", "rb").read()
exec(compile(code, "<clone>", "exec"))
"#;

fn collect(
    mut reader: impl Read + Send + 'static,
    into: Arc<Mutex<Vec<u8>>>,
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

/// `hellovm --template`: the supervisor process, its socket and output.
struct Template {
    child: Child,
    socket: PathBuf,
    dir: PathBuf,
    output: Arc<Mutex<Vec<u8>>>,
}

impl Drop for Template {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Its clones stop with it; none may outlive the test.
        wait_no_children(self.child.id());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A short socket path: `sun_path` holds 104 bytes.
fn socket_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = PathBuf::from(format!(
        "/tmp/hvw.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

impl Template {
    fn start(
        exe: &Path,
        root: &Path,
        argv: &[&str],
        options: &[&str],
        env: &[(&str, &str)],
    ) -> Template {
        progress(&format!(
            "hvf_warm: template {:?}",
            &argv[..argv.len().min(2)]
        ));
        let dir = socket_dir();
        let socket = dir.join("t.sock");
        let mut child = Command::new(exe)
            .arg("--template")
            .arg(&socket)
            .args(["--sandbox", "require"])
            .args(options)
            .arg("--root")
            .arg(root)
            .arg("--")
            .args(argv)
            .envs(env.iter().copied())
            // Measuring what the profile lacks (README, "Warm clones on
            // macOS"): every kernel process learns.
            .envs(
                std::env::var("HVF_WARM_LEARN")
                    .ok()
                    .map(|_| ("HELLOVM_SEATBELT_LEARN", "1")),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start hellovm --template");
        let output = Arc::new(Mutex::new(Vec::new()));
        collect(child.stdout.take().unwrap(), output.clone());
        collect(child.stderr.take().unwrap(), output.clone());
        Template {
            child,
            socket,
            dir,
            output,
        }
    }

    fn output(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    /// Waits until the template is frozen (its snapshot's bytes and
    /// areas), or the error it answered.
    fn ready(&self) -> std::io::Result<(u64, u32)> {
        let start = Instant::now();
        while !self.socket.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "no control socket after 30 s:\n{}",
                self.output()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        loop {
            match hellovm::warm::wait_ready(&self.socket) {
                Err(err)
                    if err.kind() == std::io::ErrorKind::ConnectionRefused
                        && start.elapsed() < Duration::from_secs(2) =>
                {
                    std::thread::sleep(Duration::from_millis(2))
                }
                other => return other,
            }
        }
    }

    fn ready_ok(&self) -> (u64, u32) {
        self.ready()
            .unwrap_or_else(|err| panic!("the template is not ready: {err}\n{}", self.output()))
    }

    /// Asks for a clone with pipes for its console, and waits until it runs.
    fn spawn(&self, sandbox_id: Option<u64>, input: &[u8]) -> std::io::Result<RunningClone> {
        let (in_r, in_w) = std::io::pipe()?;
        let (out_r, out_w) = std::io::pipe()?;
        let (err_r, err_w) = std::io::pipe()?;
        let mut conn = WarmClone::request(
            &self.socket,
            sandbox_id,
            input,
            [in_r.as_fd(), out_w.as_fd(), err_w.as_fd()],
        )?;
        drop((in_r, out_w, err_w));
        let started = conn.start()?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
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

    /// Runs a clone to its end with `stdin` as its input, and waits until
    /// its kernel process is gone.
    fn run(&self, input: &[u8], stdin: &[u8]) -> CloneRun {
        let mut clone = self
            .spawn(None, input)
            .unwrap_or_else(|err| panic!("a clone: {err}\n{}", self.output()));
        clone.send(stdin);
        clone.finish()
    }
}

/// Waits until process `pid` is gone (a clone's kernel process: reaped by
/// the supervisor right after it exits).
fn wait_gone(pid: u32) {
    let start = Instant::now();
    // SAFETY: plain kill with signal 0 (a check, no signal).
    while unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "process {pid} still exists"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// The children of `pid` (the supervisor's: kernel processes).
fn children(pid: u32) -> Vec<u32> {
    let out = Command::new("pgrep")
        .args(["-P", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

fn wait_no_children(pid: u32) {
    let start = Instant::now();
    loop {
        let left = children(pid);
        if left.is_empty() {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "kernel processes of {pid} still exist: {left:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[derive(Debug)]
struct CloneRun {
    status: Status,
    started: Started,
    stdout: String,
    stderr: String,
}

struct RunningClone {
    conn: WarmClone,
    started: Started,
    stdin: Option<std::io::PipeWriter>,
    stdout: std::io::BufReader<std::io::PipeReader>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_done: std::thread::JoinHandle<()>,
}

impl RunningClone {
    fn line(&mut self) -> String {
        let mut line = String::new();
        std::io::BufRead::read_line(&mut self.stdout, &mut line).unwrap();
        line
    }

    fn send(&mut self, data: &[u8]) {
        self.stdin.as_mut().unwrap().write_all(data).unwrap();
    }

    /// Closes stdin, reads the rest, waits for the status and for the
    /// kernel process to be gone.
    fn finish(mut self) -> CloneRun {
        self.stdin = None;
        let mut stdout = String::new();
        self.stdout.read_to_string(&mut stdout).unwrap();
        let status = self.conn.wait().expect("the clone's exit status");
        self.stderr_done.join().unwrap();
        let stderr = String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned();
        wait_gone(self.started.pid);
        CloneRun {
            status,
            started: self.started,
            stdout,
            stderr,
        }
    }
}

/// The signed `hellovm` and the guest image, or `None` (skipped).
fn setup() -> Option<(&'static Path, PathBuf)> {
    let exe = hellovm()?;
    let root = guest_image()?;
    Some((exe, root))
}

fn python(exe: &Path, root: &Path) -> Template {
    Template::start(
        exe,
        root,
        &["/usr/bin/python3", "-c", PYTHON_TEMPLATE],
        &[],
        &[],
    )
}

#[test]
fn python_clones_see_the_preloaded_state() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let template = python(exe, &root);
    let (stored, areas) = template.ready_ok();
    assert!(
        stored > 8 << 20 && areas > 10,
        "{stored} bytes, {areas} areas"
    );
    assert!(
        template.output().contains("template ready"),
        "{}",
        template.output()
    );
    // The template's kernel process has exited: only the supervisor is
    // left until a clone is asked for.
    wait_no_children(template.child.id());

    progress("hvf_warm: preloaded: first clone");
    let one = template.run(
        b"print(preloaded, 'decimal' in sys.modules, bytes(data).decode(), sum(range(10)), big.count(b't'))",
        b"",
    );
    assert_eq!(
        one.status,
        Status::Exited(0),
        "{one:?}\n{}",
        template.output()
    );
    assert_eq!(
        one.stdout, "['decimal', 'hashlib', 'json'] True template 45 2048\n",
        "{one:?}"
    );
    // Different code, its own stdin and its own exit status.
    progress("hvf_warm: preloaded: second clone");
    let two = template.run(
        b"import hashlib\nprint(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\nsys.exit(3)",
        b"abc",
    );
    assert_eq!(two.status, Status::Exited(3), "{two:?}");
    assert_eq!(
        two.stdout,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
    );
    // stderr is the clone's own; a signal is reported as such.
    progress("hvf_warm: preloaded: third clone");
    let three = template.run(
        b"print('to stderr', file=sys.stderr, flush=True)\nimport signal\nos.kill(os.getpid(), signal.SIGTERM)",
        b"",
    );
    assert_eq!(three.status, Status::Signaled(15), "{three:?}");
    assert_eq!(three.stderr, "to stderr\n");
    // The template's monotonic clock goes on in the clone.
    progress("hvf_warm: preloaded: clock");
    let clock = template.run(
        b"now = time.monotonic()\nprint(now >= frozen_at, now - frozen_at < 600)",
        b"",
    );
    assert_eq!(clock.stdout, "True True\n", "{clock:?}");
    // The template's output before the freeze is not repeated.
    assert_eq!(one.stdout.matches("template ready").count(), 0);
}

#[test]
fn clones_are_isolated_from_the_template_and_each_other() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let template = python(exe, &root);
    template.ready_ok();
    let look = br#"
print(bytes(data).decode(), big[:4].decode(), os.path.exists("/tmp/written"), os.read(r, 100).decode(), flush=True)
"#;
    // A changes memory (a page it only read before, and 8 MiB), the
    // writable layer and the template's pipe.
    progress("hvf_warm: isolation: A");
    let a = template.run(
        &[
            look.as_slice(),
            br#"
data[:] = b"clone-a"
big[:] = b"A" * len(big)
open("/tmp/written", "w").write("a")
os.write(w, b"from-a")
print(bytes(data).decode(), big[:4].decode(), os.path.exists("/tmp/written"), os.read(r, 100).decode(), flush=True)
"#,
        ]
        .concat(),
        b"",
    );
    assert_eq!(
        a.stdout, "template t\0\0\0 False pipe-data\nclone-a AAAA True from-a\n",
        "{a:?}"
    );
    // B, after A, sees the template as it was.
    progress("hvf_warm: isolation: B");
    let b = template.run(look, b"");
    assert_eq!(b.stdout, "template t\0\0\0 False pipe-data\n", "{b:?}");
    let c = template.spawn(Some(0xc), look).unwrap().finish();
    assert_eq!(c.stdout, b.stdout);
    // Sandbox ids: the requested one, else a random one, never shared;
    // each clone a kernel process of its own.
    assert_eq!(c.started.sandbox_id, 0xc);
    let ids: BTreeSet<u64> = [
        a.started.sandbox_id,
        b.started.sandbox_id,
        c.started.sandbox_id,
    ]
    .into_iter()
    .collect();
    assert_eq!(ids.len(), 3);
    let pids: BTreeSet<u32> = [a.started.pid, b.started.pid, c.started.pid]
        .into_iter()
        .collect();
    assert_eq!(pids.len(), 3);
    assert!(!pids.contains(&template.child.id()));
}

/// One template in every state the README lists as clonable at once (as
/// `warm.rs`): threads parked in `futex`, a pipe read and a sleep, a
/// thread running pure Python, a child blocked in a pipe read, a zombie
/// and a stopped one, a loopback listener with a queued connection, an
/// `alarm`.
const STATES: &str = r#"
import os, socket, sys, threading, time, signal
ev = threading.Event()
woke = []
t_event = threading.Thread(target=lambda: (ev.wait(), woke.append("event")))
t_event.start()
pr, pw = os.pipe()
got = []
t_pipe = threading.Thread(target=lambda: got.append(os.read(pr, 100)))
t_pipe.start()
t_sleep = threading.Thread(target=lambda: (time.sleep(0.3), woke.append("sleep")))
t_sleep.start()
spins = [0]
def spin():
    while True:
        spins[0] += 1
t_spin = threading.Thread(target=spin, daemon=True)
t_spin.start()
cr, cw = os.pipe()
child = os.fork()
if child == 0:
    os._exit(40 + len(os.read(cr, 100)))
zombie = os.fork()
if zombie == 0:
    os._exit(7)
stopped = os.fork()
if stopped == 0:
    time.sleep(0.2)
    os._exit(9)
os.kill(stopped, signal.SIGSTOP)
os.waitpid(stopped, os.WUNTRACED)
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen()
cli = socket.create_connection(srv.getsockname())
cli.sendall(b"queued")
signal.signal(signal.SIGALRM, lambda *a: woke.append("alarm"))
signal.alarm(1)
while spins[0] < 1000:
    time.sleep(0.01)
print("states set", flush=True)
code = open("/dev/hellovm-clone", "rb").read()
exec(compile(code, "<clone>", "exec"))
"#;

const CHECK_STATES: &[u8] = br#"
before = spins[0]
ev.set(); t_event.join()
os.write(pw, b"to-thread"); t_pipe.join()
t_sleep.join()
os.write(cw, b"xyz")
print("child", os.waitpid(child, 0)[1] >> 8)
print("zombie", os.waitpid(zombie, 0)[1] >> 8)
os.kill(stopped, signal.SIGCONT)
print("stopped", os.waitpid(stopped, 0)[1] >> 8)
a, _ = srv.accept()
print("socket", a.recv(100))
time.sleep(0.05)
print("spinning", spins[0] > before)
while "alarm" not in woke:
    time.sleep(0.05)
print("woke", sorted(woke), got)
"#;

#[test]
fn a_template_in_every_clonable_state() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let template = Template::start(exe, &root, &["/usr/bin/python3", "-c", STATES], &[], &[]);
    template.ready_ok();
    assert!(
        template.output().contains("states set"),
        "{}",
        template.output()
    );
    // Twice: the second clone finds the same frozen state.
    for i in 0..2 {
        progress(&format!("hvf_warm: states: clone {i}"));
        let run = template.run(CHECK_STATES, b"");
        assert_eq!(
            run.status,
            Status::Exited(0),
            "{run:?}\n{}",
            template.output()
        );
        assert_eq!(
            run.stdout,
            "child 43\nzombie 7\nstopped 9\nsocket b'queued'\nspinning True\n\
             woke ['alarm', 'event', 'sleep'] [b'to-thread']\n",
            "{run:?}"
        );
    }
}

#[test]
fn a_busybox_shell_template() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    // A shell with a background job waiting at the freeze.
    let script =
        "sleep 100 & read x < /dev/hellovm-clone; echo \"clone says $x\" | tr a-z A-Z; kill $!; wait $!";
    let template = Template::start(exe, &root, &["/bin/sh", "-c", script], &[], &[]);
    template.ready_ok();
    for word in ["one", "two"] {
        progress(&format!("hvf_warm: busybox clone {word}"));
        let run = template.run(format!("{word}\n").as_bytes(), b"");
        assert_eq!(
            run.stdout,
            format!("CLONE SAYS {}\n", word.to_uppercase()),
            "{run:?}"
        );
        assert_eq!(run.status, Status::Exited(143), "{run:?}");
    }
}

/// A template that ends, or freezes in a state that cannot be cloned,
/// answers every request with the reason and exits.
fn refused(exe: &Path, root: &Path, argv: &[&str], why: &str) {
    let mut template = Template::start(exe, root, argv, &[], &[]);
    let err = template
        .ready()
        .expect_err("the template must not become ready");
    assert!(
        err.to_string().contains(why),
        "expected {why:?}, got {err}\n{}",
        template.output()
    );
    let status = template.child.wait().unwrap();
    assert!(!status.success() || why.contains("ended"), "{status:?}");
}

#[test]
fn states_that_are_not_clonable() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    refused(
        exe,
        &root,
        &["/usr/bin/python3", "-c", "print('no clone point')"],
        "the template ended before its clone point",
    );
    refused(
        exe,
        &root,
        &[
            "/usr/bin/python3",
            "-c",
            "import mmap, os, time\nm = mmap.mmap(-1, 4096)\nif os.fork() == 0:\n    time.sleep(100)\nopen('/dev/hellovm-clone').read()",
        ],
        "MAP_SHARED memory",
    );
    // Command-line combinations a template refuses.
    for bad in [&["--tty"][..], &["--timeout", "1"]] {
        let mut args = vec!["--template", "/nonexistent/sock"];
        args.extend(bad);
        args.extend(["--root", "/", "/bin/true"]);
        let out = Command::new(exe).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    // The internal role is not for a template either.
    let out = Command::new(exe)
        .args([
            "--template",
            "/nonexistent/sock",
            "--warm-role",
            "clone",
            "--root",
            "/",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn the_clone_cli() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let template = python(exe, &root);
    progress("hvf_warm: cli --ready");
    let ready = Command::new(exe)
        .arg("--clone")
        .arg(&template.socket)
        .arg("--ready")
        .output()
        .unwrap();
    assert!(ready.status.success(), "{ready:?}\n{}", template.output());
    progress("hvf_warm: cli input and status");
    let mut child = Command::new(exe)
        .arg("--clone")
        .arg(&template.socket)
        .args(["--input", "print(sys.stdin.read().upper()); sys.exit(4)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"shout").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "SHOUT\n");
    assert_eq!(out.status.code(), Some(4));
    wait_no_children(template.child.id());
    // --timeout kills the clone, and its kernel process stops.
    progress("hvf_warm: cli --timeout");
    let start = Instant::now();
    let out = Command::new(exe)
        .arg("--clone")
        .arg(&template.socket)
        .args(["--timeout", "0.5", "--input", "import time; time.sleep(30)"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(124), "{out:?}");
    wait_no_children(template.child.id());
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
    // The template still makes clones.
    assert_eq!(template.run(b"print(1)", b"").stdout, "1\n");
}

#[test]
fn a_dying_template_takes_its_clones() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let mut template = python(exe, &root);
    template.ready_ok();
    progress("hvf_warm: dying template");
    let mut clone = template
        .spawn(
            None,
            b"print('up', flush=True)\nsys.stdin.readline()\nprint('not reached')",
        )
        .unwrap();
    assert_eq!(clone.line(), "up\n");
    let kernel = clone.started.pid;
    template.child.kill().unwrap();
    template.child.wait().unwrap();
    // The clone's kernel process stops its apps and exits: its console
    // reaches end of file with nothing more written.
    wait_gone(kernel);
    let mut rest = String::new();
    clone.stdout.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "");
    assert!(
        clone.conn.wait().is_err(),
        "no exit status from a dead template"
    );
}

/// Resident memory of a process, in KiB.
fn rss_kib(pid: u32) -> u64 {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

/// Requesters that break the protocol get an error or nothing, and none
/// of them panics the supervisor or makes it grow; it serves others
/// meanwhile and after.
#[test]
fn hostile_requesters_cannot_break_the_template() {
    use std::os::unix::net::UnixStream;
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let template = python(exe, &root);
    template.ready_ok();
    let supervisor = template.child.id();
    let error_of = |stream: &mut UnixStream| -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        match Frame::read_from(stream) {
            Ok(Some(Frame::Error(why))) => why,
            other => panic!("expected an error frame, got {other:?}"),
        }
    };
    progress("hvf_warm: hostile requesters");
    // Garbage, a wrong version, an input longer than allowed.
    for bytes in [&b"GET / HTTP/1.1\r\n\r\n"[..], b"HVMC\x09C\0\0", &{
        let mut r = b"HVMC\x01C\0\0".to_vec();
        r.extend_from_slice(&[0; 8]);
        r.extend_from_slice(&u32::MAX.to_le_bytes());
        r
    }] {
        let mut s = UnixStream::connect(&template.socket).unwrap();
        s.write_all(bytes).unwrap();
        assert!(!error_of(&mut s).is_empty());
    }
    // A clone request without its fds, and one with an ingress channel
    // (not on macOS).
    let request = |ingress: bool| hellovm::warm::Request {
        kind: hellovm::warm::Kind::Clone,
        sandbox_id: None,
        ingress,
        input: b"print(1)".to_vec(),
    };
    let mut s = UnixStream::connect(&template.socket).unwrap();
    s.write_all(&request(false).encode()).unwrap();
    assert!(error_of(&mut s).contains("needs 3 fds"));
    let (a, b) = UnixStream::pair().unwrap();
    let fds = [a.as_fd(), a.as_fd(), a.as_fd(), b.as_fd()].map(|fd| {
        use std::os::fd::AsRawFd;
        fd.as_raw_fd()
    });
    let mut s = UnixStream::connect(&template.socket).unwrap();
    hellovm::warm::send_with_fds(&s, &request(true).encode(), &fds).unwrap();
    assert!(error_of(&mut s).contains("ingress"), "ingress");
    // Many connections that close at once, or after half a request, or
    // with too many fds.
    // macOS refuses a connect while the listener's backlog is full, until
    // the supervisor has accepted some.
    let connect = || loop {
        match UnixStream::connect(&template.socket) {
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::thread::sleep(Duration::from_millis(1))
            }
            other => break other.unwrap(),
        }
    };
    let flood = || {
        for i in 0..300 {
            let mut s = connect();
            match i % 3 {
                0 => {}
                1 => s.write_all(b"HVMC\x01C").unwrap(),
                _ => {
                    let many = [a.as_fd(); 8].map(|fd| {
                        use std::os::fd::AsRawFd;
                        fd.as_raw_fd()
                    });
                    let _ = hellovm::warm::send_with_fds(&s, &request(false).encode(), &many);
                }
            }
        }
        // Served (and dropped) before the next step.
        assert_eq!(
            template.run(b"print('after a flood')", b"").stdout,
            "after a flood\n"
        );
    };
    // Each connection has a request buffer (64 KiB) while it is open, at
    // most 128 at once: whatever comes, the supervisor grows by that and
    // what the allocator keeps of it, no more.
    let before = rss_kib(supervisor);
    let mut peak = before;
    for _ in 0..5 {
        flood();
        peak = peak.max(rss_kib(supervisor));
    }
    assert!(
        peak < before + 32 * 1024,
        "the supervisor grew from {before} to {peak} KiB"
    );
    // An idle connection is answered after the request timeout; meanwhile
    // the template serves others.
    let mut idle = UnixStream::connect(&template.socket).unwrap();
    idle.write_all(b"HVMC\x01C").unwrap();
    let start = Instant::now();
    let run = template.run(b"print('served')", b"");
    assert_eq!(run.stdout, "served\n", "{run:?}");
    assert!(error_of(&mut idle).contains("no complete request"));
    assert!(start.elapsed() >= hellovm::warm::REQUEST_TIMEOUT - Duration::from_secs(1));
    let after = rss_kib(supervisor);
    assert!(
        after < before + 32 * 1024,
        "the supervisor grew to {after} KiB"
    );
    // Still alive, still serving.
    assert_eq!(template.run(b"print(2)", b"").stdout, "2\n");
    assert!(children(supervisor).is_empty());
}

/// `--fs-limit` is kernel state: every clone keeps the template's.
#[test]
fn the_fs_limit_holds_in_every_clone() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let template = Template::start(
        exe,
        &root,
        &["/usr/bin/python3", "-c", PYTHON_TEMPLATE],
        &["--fs-limit", "4000000"],
        &[],
    );
    template.ready_ok();
    progress("hvf_warm: fs limit");
    let run = template.run(
        br#"
try:
    open("/tmp/fill", "wb").write(b"x" * 8000000)
    print("written")
except OSError as e:
    print("refused", e.errno)
"#,
        b"",
    );
    assert_eq!(run.stdout, "refused 28\n", "{run:?}");
}

/// The kernel processes are hardened like any sandbox's: the template's
/// and each clone's enter the same Seatbelt profile.
#[test]
fn template_and_clones_are_confined() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let template = Template::start(
        exe,
        &root,
        &["/usr/bin/python3", "-c", PYTHON_TEMPLATE],
        &[],
        &[("HELLOVM_LOG", "debug")],
    );
    template.ready_ok();
    progress("hvf_warm: confinement");
    let run = template.run(b"print('confined')", b"");
    assert_eq!(run.stdout, "confined\n");
    let output = template.output();
    // One template kernel process, one clone.
    assert_eq!(
        output.matches("Seatbelt profile: active (7 rules)").count(),
        2,
        "{output}"
    );
    assert_eq!(
        output
            .matches("no debugger (PT_DENY_ATTACH): active")
            .count(),
        2
    );
    assert_eq!(output.matches("resource limits: active").count(), 2);
    // A clone cannot open what the image does not have, as any sandbox.
    let run = template.run(
        b"import os\ntry:\n    os.stat('/Users')\nexcept OSError as e:\n    print(e.errno)",
        b"",
    );
    assert_eq!(run.stdout, "2\n", "{run:?}");
}

#[test]
fn many_clones_one_after_another() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let template = python(exe, &root);
    template.ready_ok();
    let start = Instant::now();
    for i in 0..30 {
        progress(&format!("hvf_warm: clone {i} of 30"));
        let run = template.run(format!("print({i} * 2)").as_bytes(), b"");
        assert_eq!(run.stdout, format!("{}\n", i * 2), "clone {i}: {run:?}");
        assert_eq!(run.status, Status::Exited(0));
    }
    eprintln!("30 clones one after another: {:?}", start.elapsed());
}

/// Several clones alive at once (several VMs): only with
/// `HELLOVM_HVF_CONCURRENT=1`.
fn concurrent() -> bool {
    let on = std::env::var("HELLOVM_HVF_CONCURRENT").as_deref() == Ok("1");
    if !on {
        eprintln!("SKIPPING: several VMs at once need HELLOVM_HVF_CONCURRENT=1");
    }
    on
}

#[test]
fn clones_at_once_are_isolated_and_one_can_be_killed() {
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    if !concurrent() {
        return;
    }
    let template = python(exe, &root);
    template.ready_ok();
    progress("hvf_warm: concurrent: A changes, waits");
    let mut a = template
        .spawn(
            Some(0xa),
            br#"
data[:] = b"clone-a"
open("/tmp/written", "w").write("a")
print("a changed", flush=True)
sys.stdin.readline()
print(bytes(data).decode(), os.path.exists("/tmp/written"), flush=True)
"#,
        )
        .unwrap();
    assert_eq!(a.line(), "a changed\n");
    progress("hvf_warm: concurrent: B looks while A lives");
    let b = template.run(
        b"print(bytes(data).decode(), os.path.exists('/tmp/written'))",
        b"",
    );
    assert_eq!(b.stdout, "template False\n", "{b:?}");
    // D waits too; killing it (closing its connection) leaves A running.
    progress("hvf_warm: concurrent: D killed");
    let mut d = template
        .spawn(None, b"print('up', flush=True)\nsys.stdin.readline()")
        .unwrap();
    assert_eq!(d.line(), "up\n");
    let d_kernel = d.started.pid;
    d.conn.kill();
    wait_gone(d_kernel);
    a.send(b"\n");
    let a = a.finish();
    assert_eq!(a.stdout.lines().last(), Some("clone-a True"), "{a:?}");
    // Several at once, each with its own output.
    progress("hvf_warm: concurrent: 4 at once");
    let clones: Vec<_> = (0..4)
        .map(|i| {
            template
                .spawn(
                    None,
                    format!("sys.stdin.read()\nprint({i} + 1000)").as_bytes(),
                )
                .unwrap()
        })
        .collect();
    let kernels: BTreeSet<u32> = clones.iter().map(|c| c.started.pid).collect();
    assert_eq!(kernels.len(), 4);
    for (i, clone) in clones.into_iter().enumerate() {
        let run = clone.finish();
        assert_eq!(run.stdout, format!("{}\n", i + 1000), "clone {i}: {run:?}");
    }
}

/// Imports a working set of the standard library, then waits at the clone
/// point (end of file at once when not a template) and prints a line (as
/// `warm_bench.rs` on Linux). A clone with input `wait` then waits for its
/// stdin, so that its memory can be measured.
const BENCH: &str = r#"
import asyncio, json, decimal, hashlib, http.client, email.parser, ssl
import xml.etree.ElementTree, urllib.request, argparse, dataclasses, pathlib, sqlite3, sys
code = open("/dev/hellovm-clone", "rb").read()
print("hello", flush=True)
if code == b"wait":
    sys.stdin.read()
"#;

/// A process's physical footprint (what Activity Monitor calls its
/// memory), in bytes.
fn footprint(pid: u32) -> u64 {
    // SAFETY: zeroed plain-old-data; the call fills it.
    let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: a valid pointer to a rusage_info_v2 for RUSAGE_INFO_V2.
    let ret = unsafe {
        libc::proc_pid_rusage(
            pid as libc::c_int,
            libc::RUSAGE_INFO_V2,
            (&mut info as *mut libc::rusage_info_v2).cast(),
        )
    };
    if ret == 0 {
        info.ri_phys_footprint
    } else {
        0
    }
}

fn stats(name: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    println!(
        "{name:<44} min {:>8.2} ms  median {:>8.2} ms  max {:>8.2} ms  (n={})",
        ms(samples[0]),
        ms(samples[samples.len() / 2]),
        ms(samples[samples.len() - 1]),
        samples.len()
    );
}

/// Warm-clone timings and memory on macOS (not a gate; ignored):
///
/// ```sh
/// HELLOVM_HVF_GUESTS=$PWD/target/hvf-guests/root cargo test --release -p hellovm \
///     --test hvf_warm -- --ignored --nocapture warm_clone_timings
/// ```
///
/// `HELLOVM_BENCH_CLONES` sets the number of clones (default 30). One
/// clone at a time.
#[test]
#[ignore]
fn warm_clone_timings() {
    use std::io::BufRead;
    let _serial = hvf_support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let n: usize = std::env::var("HELLOVM_BENCH_CLONES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let mut cold = Vec::new();
    for _ in 0..5 {
        progress("hvf_warm: bench cold start");
        let start = Instant::now();
        let mut child = Command::new(exe)
            .args(["--sandbox", "require", "--no-tty", "--root"])
            .arg(&root)
            .args(["/usr/bin/python3", "-c", BENCH])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        cold.push(start.elapsed());
        assert_eq!(line, "hello\n");
        assert!(child.wait().unwrap().success());
    }
    let start = Instant::now();
    let template = Template::start(
        exe,
        &root,
        &["/usr/bin/python3", "-c", BENCH],
        &[],
        &[("HELLOVM_LOG", "debug")],
    );
    let (stored, areas) = template.ready_ok();
    let frozen = start.elapsed();
    let supervisor = footprint(template.child.id());
    let mut to_start = Vec::new();
    let mut to_line = Vec::new();
    let mut to_exit = Vec::new();
    for i in 0..n {
        progress(&format!("hvf_warm: bench clone {i}"));
        let start = Instant::now();
        let mut clone = template.spawn(None, b"").unwrap();
        to_start.push(start.elapsed());
        assert_eq!(clone.line(), "hello\n");
        to_line.push(start.elapsed());
        let status = clone.conn.wait().unwrap();
        to_exit.push(start.elapsed());
        assert_eq!(status, Status::Exited(0));
        clone.stdin = None;
        wait_gone(clone.started.pid);
    }
    // One clone's memory once it has printed its line.
    progress("hvf_warm: bench clone memory");
    let mut clone = template.spawn(None, b"wait").unwrap();
    assert_eq!(clone.line(), "hello\n");
    let kernel = footprint(clone.started.pid);
    let run = clone.finish();
    assert_eq!(run.status, Status::Exited(0));
    let output = template.output();
    let copied: Vec<u64> = output
        .lines()
        .filter_map(|l| l.split("clone: ").nth(1)?.split(' ').next()?.parse().ok())
        .collect();
    println!();
    println!(
        "template: frozen {:.1} ms after start; snapshot {:.1} MiB stored in {areas} areas",
        frozen.as_secs_f64() * 1000.0,
        stored as f64 / (1 << 20) as f64
    );
    for line in output.lines().filter(|l| l.contains("template saved")) {
        println!("{line}");
    }
    stats("cold hellovm: start to first line", cold);
    stats("clone: request to first instruction (S)", to_start);
    stats("clone: request to first line", to_line);
    stats("clone: request to exit status", to_exit);
    let mib = |b: u64| b as f64 / (1 << 20) as f64;
    println!(
        "app memory copied from the snapshot per clone: {:.1} MiB (median of {})",
        mib(copied.get(copied.len() / 2).copied().unwrap_or(0) * 4096),
        copied.len()
    );
    println!(
        "footprint: a waiting clone's kernel process {:.1} MiB, the supervisor {:.1} MiB",
        mib(kernel),
        mib(supervisor)
    );
    for line in output.lines().filter(|l| l.contains("clone: s")).take(6) {
        println!("{line}");
    }
}
