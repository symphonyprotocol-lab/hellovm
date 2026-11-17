//! Warm clones end to end: `hellovm --template` with the host's CPython
//! (image `/`, like the egress tests), clones made through the control
//! socket (`hellovm::warm`), isolation between template and clones, many
//! clones, the states a template may and may not be frozen in.
//!
//! The templates run hardened like every other test (`--sandbox
//! best-effort`, the default), so each clone's kernel process has the
//! same confinement plus a Landlock domain of its own.

#![cfg(target_os = "linux")]

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use common::Template;
use hellovm::warm::Status;

fn require_python() -> bool {
    if Path::new("/usr/bin/python3").exists() {
        return true;
    }
    common::skip_or_fail("warm clones: /usr/bin/python3 not found (install python3)");
    false
}

/// A template that preloads some modules and state, then runs the code
/// each clone gets as its input.
const PYTHON_TEMPLATE: &str = r#"
import json, hashlib, decimal, os, sys
preloaded = sorted(m for m in ("json", "hashlib", "decimal") if m in sys.modules)
data = bytearray(b"template")
r, w = os.pipe()
os.write(w, b"pipe-data")
print("template ready", flush=True)
code = open("/dev/hellovm-clone", "rb").read()
exec(compile(code, "<clone>", "exec"))
"#;

fn python_template() -> Template {
    Template::start(&["/usr/bin/python3", "-c", PYTHON_TEMPLATE], &[])
}

fn ready(template: &Template) -> (u64, u32) {
    template
        .ready()
        .unwrap_or_else(|err| panic!("the template is not ready: {err}\n{}", template.output()))
}

#[test]
fn python_clones_see_the_preloaded_state() {
    if !require_python() {
        return;
    }
    let template = python_template();
    let (stored, areas) = ready(&template);
    assert!(stored > 1 << 20 && areas > 10, "{stored} bytes, {areas} areas");
    assert!(template.output().contains("template ready"), "{}", template.output());

    let one = template.run(
        b"print(preloaded, 'decimal' in sys.modules, bytes(data).decode(), sum(range(10)))",
        b"",
    );
    assert_eq!(one.status, Status::Exited(0), "{one:?}");
    assert_eq!(
        one.stdout,
        "['decimal', 'hashlib', 'json'] True template 45\n",
        "{one:?}"
    );
    // Different code, its own stdin, and its own exit status.
    let two = template.run(
        b"import hashlib\nprint(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\nsys.exit(3)",
        b"abc",
    );
    assert_eq!(two.status, Status::Exited(3), "{two:?}");
    assert_eq!(
        two.stdout,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
    );
    // stderr is the clone's own too; a signal is reported as such.
    let three = template.run(
        b"print('to stderr', file=sys.stderr, flush=True)\nimport signal\nos.kill(os.getpid(), signal.SIGTERM)",
        b"",
    );
    assert_eq!(three.status, Status::Signaled(15), "{three:?}");
    assert_eq!(three.stderr, "to stderr\n");
    // The template's output before the freeze is not repeated.
    assert_eq!(one.stdout.matches("template ready").count(), 0);
}

#[test]
fn clones_are_isolated_from_the_template_and_each_other() {
    if !require_python() {
        return;
    }
    let template = python_template();
    ready(&template);
    let look = br#"
print(bytes(data).decode(), os.path.exists("/tmp/written"), os.read(r, 100).decode(), flush=True)
"#;
    // A changes memory, the writable layer and the template's pipe, then
    // waits while B and C look.
    let mut a = template
        .spawn(Some(0xa), &[look.as_slice(), br#"
data[:] = b"clone-a"
open("/tmp/written", "w").write("a")
os.write(w, b"from-a")
print("a changed", flush=True)
sys.stdin.readline()
print(bytes(data).decode(), os.path.exists("/tmp/written"), os.read(r, 100).decode(), flush=True)
"#]
        .concat())
        .unwrap();
    assert_eq!(a.line(), "template False pipe-data\n");
    assert_eq!(a.line(), "a changed\n");
    let b = template.run(look, b"");
    assert_eq!(b.stdout, "template False pipe-data\n", "{b:?}");
    // A sees its own changes.
    a.send(b"\n");
    let a = a.finish();
    assert_eq!(a.stdout.lines().last(), Some("clone-a True from-a"), "{a:?}");
    assert_eq!(a.status, Status::Exited(0));
    // A clone made after A ended sees the template as it was.
    let c = template.run(look, b"");
    assert_eq!(c.stdout, "template False pipe-data\n", "{c:?}");

    // Sandbox ids: the requested one, else a random one, never shared.
    assert_eq!(a.started.sandbox_id, 0xa);
    let ids: BTreeSet<u64> = [a.started.sandbox_id, b.started.sandbox_id, c.started.sandbox_id]
        .into_iter()
        .collect();
    assert_eq!(ids.len(), 3);
    // Each clone is a kernel process of its own.
    let pids: BTreeSet<u32> = [a.started.pid, b.started.pid, c.started.pid]
        .into_iter()
        .collect();
    assert_eq!(pids.len(), 3);
}

#[test]
fn killing_a_clone_leaves_the_others_running() {
    if !require_python() {
        return;
    }
    let template = python_template();
    ready(&template);
    let wait = b"print('up', flush=True)\nprint('got', sys.stdin.readline().strip(), flush=True)";
    let mut d = template.spawn(None, wait).unwrap();
    let mut e = template.spawn(None, wait).unwrap();
    assert_eq!(d.line(), "up\n");
    assert_eq!(e.line(), "up\n");
    let d_kernel = d.started.pid;
    // Closing the connection kills the clone: its console reaches end of
    // file and its kernel process goes away.
    assert_eq!(d.kill(), "");
    let start = Instant::now();
    while Path::new(&format!("/proc/{d_kernel}")).exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "clone D still runs");
        std::thread::sleep(Duration::from_millis(10));
    }
    e.send(b"still-here\n");
    let e = e.finish();
    assert_eq!(e.stdout, "got still-here\n", "{e:?}");
    assert_eq!(e.status, Status::Exited(0));
    // And the template still makes clones.
    assert_eq!(template.run(b"print(1)", b"").stdout, "1\n");
}

#[test]
fn fifty_clones_one_after_another_and_at_once() {
    if !require_python() {
        return;
    }
    let template = python_template();
    ready(&template);
    let start = Instant::now();
    for i in 0..50 {
        let run = template.run(format!("print({i} * 2)").as_bytes(), b"");
        assert_eq!(run.stdout, format!("{}\n", i * 2), "clone {i}: {run:?}");
        assert_eq!(run.status, Status::Exited(0));
    }
    eprintln!("50 clones one after another: {:?}", start.elapsed());

    let start = Instant::now();
    let clones: Vec<_> = (0..50)
        .map(|i| {
            template
                .spawn(
                    None,
                    format!("sys.stdin.read()\nprint({i} + 1000)").as_bytes(),
                )
                .unwrap_or_else(|err| panic!("clone {i}: {err}\n{}", template.output()))
        })
        .collect();
    // All 50 exist at once before any ends.
    let kernels: BTreeSet<u32> = clones.iter().map(|c| c.started.pid).collect();
    assert_eq!(kernels.len(), 50);
    for (i, clone) in clones.into_iter().enumerate() {
        let run = clone.finish();
        assert_eq!(run.stdout, format!("{}\n", i + 1000), "clone {i}: {run:?}");
    }
    eprintln!("50 clones at once: {:?}", start.elapsed());
}

/// One template in every state the README lists as clonable at once:
/// threads parked in `futex` (an `Event`), in a pipe read and in a sleep;
/// a thread running pure Python (interrupted for the freeze); a child
/// process blocked in a pipe read and a zombie; a loopback listener with a
/// queued connection and data; a pipe with data; an `alarm`.
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
    if !require_python() {
        return;
    }
    let template = Template::start(&["/usr/bin/python3", "-c", STATES], &[]);
    ready(&template);
    assert!(template.output().contains("states set"), "{}", template.output());
    // Twice: the second clone finds the same frozen state.
    for _ in 0..2 {
        let run = template.run(CHECK_STATES, b"");
        assert_eq!(run.status, Status::Exited(0), "{run:?}");
        assert_eq!(
            run.stdout,
            "child 43\nzombie 7\nsocket b'queued'\nspinning True\n\
             woke ['alarm', 'event', 'sleep'] [b'to-thread']\n",
            "{run:?}"
        );
    }
}

#[test]
fn a_busybox_shell_template() {
    let Some(busybox) = common::require_busybox("warm clones") else {
        return;
    };
    // A shell with a pipeline and a background job waiting at the freeze.
    let script = "sleep 100 & read x < /dev/hellovm-clone; echo \"clone says $x\"; kill $!; wait $!";
    let template = Template::start(&[&busybox, "sh", "-c", script], &[]);
    ready(&template);
    for word in ["one", "two"] {
        let run = template.run(format!("{word}\n").as_bytes(), b"");
        assert_eq!(run.stdout, format!("clone says {word}\n"), "{run:?}");
        assert_eq!(run.status, Status::Exited(143), "{run:?}");
    }
}

/// A template that ends, or reaches its clone point in a state that is not
/// clonable, answers every request with the reason and exits.
fn refused(argv: &[&str], options: &[&str], why: &str) {
    let mut template = Template::start(argv, options);
    let err = template
        .ready()
        .expect_err("the template must not become ready");
    assert!(
        err.to_string().contains(why),
        "expected {why:?}, got {err}\n{}",
        template.output()
    );
    assert!(!template.wait().success() || why.contains("ended"));
}

#[test]
fn states_that_are_not_clonable() {
    if !require_python() {
        return;
    }
    refused(
        &["/usr/bin/python3", "-c", "print('no clone point')"],
        &[],
        "the template ended before its clone point",
    );
    // Shared memory with a second address space (it could be shared).
    refused(
        &[
            "/usr/bin/python3",
            "-c",
            "import mmap, os, time\nm = mmap.mmap(-1, 4096)\nif os.fork() == 0:\n    time.sleep(100)\nopen('/dev/hellovm-clone').read()",
        ],
        &[],
        "MAP_SHARED memory",
    );
    // An outbound connection still open: spliced to a local listener (a
    // test hook standing in for the egress proxy).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = std::thread::spawn(move || listener.accept().map(|(s, _)| s));
    refused(
        &[
            "/usr/bin/python3",
            "-c",
            "import socket\ns = socket.create_connection(('example.test', 80))\nopen('/dev/hellovm-clone').read()",
        ],
        &["--splice-to", &format!("127.0.0.1:{port}")],
        "outbound connection(s) through the egress proxy are open",
    );
    drop(accept.join());
    // Command-line combinations a template refuses.
    for bad in [["--tty"], ["--timeout"]] {
        let mut args = vec!["--template", "/nonexistent/sock"];
        args.extend(bad);
        if bad[0] == "--timeout" {
            args.push("1");
        }
        args.extend(["--root", "/", "/bin/true"]);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hellovm"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn a_program_with_a_clone_point_runs_alone_too() {
    if !require_python() {
        return;
    }
    // Outside a template the clone point is at end of file at once.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_hellovm"))
        .args([
            "--root",
            "/",
            "/usr/bin/python3",
            "-c",
            "print(repr(open('/dev/hellovm-clone', 'rb').read()))",
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "b''\n");
    assert!(out.status.success());
}

#[test]
fn the_clone_cli() {
    if !require_python() {
        return;
    }
    let template = python_template();
    ready(&template);
    let hellovm = env!("CARGO_BIN_EXE_hellovm");
    let ready = std::process::Command::new(hellovm)
        .arg("--clone")
        .arg(&template.socket)
        .arg("--ready")
        .output()
        .unwrap();
    assert!(ready.status.success(), "{ready:?}");
    let mut child = std::process::Command::new(hellovm)
        .arg("--clone")
        .arg(&template.socket)
        .args(["--input", "print(sys.stdin.read().upper()); sys.exit(4)"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), b"shout").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "SHOUT\n");
    assert_eq!(out.status.code(), Some(4));
    // --timeout kills the clone.
    let out = std::process::Command::new(hellovm)
        .arg("--clone")
        .arg(&template.socket)
        .args(["--timeout", "0.5", "--input", "import time; time.sleep(30)"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(124), "{out:?}");
}
