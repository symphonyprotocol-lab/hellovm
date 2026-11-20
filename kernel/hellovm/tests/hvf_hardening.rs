//! The hardening of the kernel process on macOS (README, "Hardening").
//!
//! The break-out tests run inside the confined kernel process: `hellovm
//! --insecure-fence-test TEST` (a test hook, `src/fence_macos.rs`) makes
//! the VM and vCPU, opens the image, enters the sandbox exactly as a real
//! run does, then tries one forbidden thing itself and reports. Each must
//! be refused (an error) or kill the process (a system call outside the
//! profile's allowlists); the same attempts with `--sandbox off` show that
//! they would work otherwise. Only files, sockets, name resolution and
//! signals are tried: see `fence_macos.rs` for what was removed and why.
//!
//! The tests run one at a time, whatever `--test-threads` says
//! (`hvf_support::serial`), and are named mildest first. Before every
//! attempt the test appends a line to `kernel/target/hvf-test-steps.log`
//! and syncs it.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod hvf_support;

use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use hvf_support::{guest_image, hellovm, progress};

/// A directory with an image (`image/inner.txt`) and a file next to it
/// that the kernel process must not read (`secret.txt`).
struct Fence {
    dir: PathBuf,
}

impl Fence {
    fn new() -> Fence {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "hellovm-fence-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("image")).unwrap();
        std::fs::write(dir.join("image/inner.txt"), "inside the image\n").unwrap();
        std::fs::write(dir.join("secret.txt"), "SECRET\n").unwrap();
        // Canonical (/tmp is a symlink to /private/tmp).
        Fence {
            dir: std::fs::canonicalize(&dir).unwrap(),
        }
    }

    fn image(&self) -> PathBuf {
        self.dir.join("image")
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).to_str().unwrap().to_string()
    }
}

impl Drop for Fence {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Refused,
    Allowed,
    /// SIGKILL: a system call the profile does not allow.
    Killed,
}

fn fence_test(exe: &Path, fence: &Fence, mode: &str, test: &str) -> (Outcome, Output) {
    progress(&format!("fence --sandbox {mode} {test}"));
    let out = Command::new(exe)
        .args(["--sandbox", mode, "--no-tty", "--root"])
        .arg(fence.image())
        .args(["--insecure-fence-test", test])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let outcome = match (out.status.code(), out.status.signal()) {
        (Some(0), _) if stdout.contains(": refused: ") => Outcome::Refused,
        (Some(1), _) if stdout.contains(": allowed: ") => Outcome::Allowed,
        (None, Some(9)) => Outcome::Killed,
        _ => panic!("{test} ({mode}): unexpected result {out:?}"),
    };
    eprintln!("{mode} {test}: {outcome:?} {}", stdout.trim());
    (outcome, out)
}

/// Each attempt is refused or kills the confined process; with
/// `--sandbox off` (when `control`) each works.
fn refused_when_confined(exe: &Path, fence: &Fence, attempts: &[String], control: bool) {
    for test in attempts {
        let (outcome, out) = fence_test(exe, fence, "require", test);
        assert_ne!(outcome, Outcome::Allowed, "{test}: {out:?}");
    }
    if control {
        for test in attempts {
            let (outcome, out) = fence_test(exe, fence, "off", test);
            assert_eq!(outcome, Outcome::Allowed, "{test}: {out:?}");
        }
    }
}

fn run(exe: &Path, root: &Path, mode: &str, argv: &[&str], env: &[(&str, &str)]) -> Output {
    progress(&format!("run --sandbox {mode} {argv:?} {env:?}"));
    Command::new(exe)
        .args(["--sandbox", mode, "--no-tty", "--root"])
        .arg(root)
        .args(argv)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// Step 1: a hello world under `--sandbox require`, and nothing on stderr
/// but the program's own output (no warning) in every mode.
#[test]
fn s1_hello_world_under_require() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let root = hvf_support::image("hello1", hellovm_test_guest::HELLO);
    for mode in ["require", "best-effort", "off"] {
        let out = run(exe, &root, mode, &["/hello1"], &[]);
        assert_eq!(
            out.status.code(),
            Some(hellovm_test_guest::HELLO_EXIT_CODE),
            "{mode}: {out:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            hellovm_test_guest::HELLO_STDOUT,
            "{mode}"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            hellovm_test_guest::HELLO_STDERR,
            "{mode}"
        );
    }
}

/// Step 2: files. Reading the image works; reading a file outside it (by
/// an absolute path, through `..`, or `openat` above every fd held),
/// listing a directory outside it, and creating a file (outside the image
/// or inside it) are refused.
#[test]
fn s2_files_outside_the_image_are_refused() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let fence = Fence::new();
    let (outcome, out) = fence_test(exe, &fence, "require", "read-image:inner.txt");
    assert_eq!(outcome, Outcome::Allowed, "{out:?}");
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users".into());
    let attempts = [
        "read:/etc/passwd".to_string(),
        format!("read:{home}/Library/Preferences/.GlobalPreferences.plist"),
        format!("read:{}", fence.path("secret.txt")),
        format!("read:{}/../secret.txt", fence.image().display()),
        "read-above-image:secret.txt".into(),
        "list:/".into(),
        format!("list:{home}"),
        format!("write:{}", fence.path("written.txt")),
        format!("write:{}/written.txt", fence.image().display()),
    ];
    refused_when_confined(exe, &fence, &attempts[..8], true);
    // Writing into the image is refused when confined; unconfined it
    // works, so it gets no control (the image must stay unchanged).
    refused_when_confined(exe, &fence, &attempts[8..], false);
    assert!(!fence.image().join("written.txt").exists());
    assert_eq!(
        std::fs::read_to_string(fence.dir.join("secret.txt")).unwrap(),
        "SECRET\n"
    );
}

/// Step 3: sockets. TCP, UDP and Unix sockets to listeners of this test,
/// a system Unix socket and name resolution are refused; nothing reaches
/// the listeners.
#[test]
fn s3_sockets_are_refused() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let fence = Fence::new();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_nonblocking(true).unwrap();
    let unix_path = fence.dir.join("listener.sock");
    let unix = std::os::unix::net::UnixListener::bind(&unix_path).unwrap();
    unix.set_nonblocking(true).unwrap();
    let attempts = [
        format!("tcp:{}", tcp.local_addr().unwrap()),
        format!("udp:{}", udp.local_addr().unwrap()),
        format!("unix:{}", unix_path.display()),
        "resolve:localhost".to_string(),
    ];
    refused_when_confined(exe, &fence, &attempts, false);
    assert!(tcp.accept().is_err(), "a TCP connection arrived");
    assert!(unix.accept().is_err(), "a Unix connection arrived");
    let mut buf = [0u8; 16];
    assert!(udp.recv(&mut buf).is_err(), "a datagram arrived");
    refused_when_confined(exe, &fence, &attempts, true);
    assert!(tcp.accept().is_ok());
    assert!(unix.accept().is_ok());
    std::thread::sleep(Duration::from_millis(100));
    assert!(udp.recv(&mut buf).is_ok());
    let (outcome, out) = fence_test(exe, &fence, "require", "unix:/var/run/mDNSResponder");
    assert_ne!(outcome, Outcome::Allowed, "{out:?}");
}

/// Step 4: signals. `SIGTERM` to a process of this user is refused and it
/// lives on; unconfined, it ends it.
#[test]
fn s4_signals_are_refused() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let fence = Fence::new();
    let mut child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
    let test = format!("signal:{}", child.id());
    let (outcome, out) = fence_test(exe, &fence, "require", &test);
    std::thread::sleep(Duration::from_millis(100));
    let alive = child.try_wait().unwrap().is_none();
    if !alive || outcome == Outcome::Allowed {
        let _ = child.kill();
        panic!("{test}: {outcome:?}, target alive: {alive}: {out:?}");
    }
    let (outcome, out) = fence_test(exe, &fence, "off", &test);
    assert_eq!(outcome, Outcome::Allowed, "{out:?}");
    assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGTERM));
}

/// Step 5: inherited fds are closed and the environment is empty in the
/// confined process; the debug log lists every layer as active.
#[test]
fn s5_fds_environment_and_layers() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let fence = Fence::new();
    let inherited = std::fs::File::open(fence.dir.join("secret.txt")).unwrap();
    let raw = std::os::fd::AsRawFd::as_raw_fd(&inherited);
    let mut cmd = Command::new(exe);
    cmd.args(["--sandbox", "require", "--no-tty", "--root"])
        .arg(fence.image())
        .args(["--insecure-fence-test", "state"])
        .env("HELLOVM_LOG", "debug")
        .env("HELLOVM_SOME_TOKEN", "do-not-leak")
        .stdin(Stdio::null());
    // SAFETY: dup2 in the child before exec: fd 9 is inherited.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 9) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    progress("fence --sandbox require state (fd 9 inherited)");
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // 0-2, the image directory and /dev/urandom.
    assert_eq!(
        stdout.trim(),
        "fence: state: allowed: fds=[0, 1, 2, 3, 4] env=0",
        "{out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    for layer in [
        "inherited fds closed: active (1 closed)",
        "resource limits: active (core 0, nofile 256, nproc 1)",
        "environment cleared: active",
        "no debugger (PT_DENY_ATTACH): active",
        "Seatbelt profile: active",
    ] {
        assert!(stderr.contains(layer), "{layer}: {stderr}");
    }
    let (outcome, out) = fence_test(exe, &fence, "require", "env");
    assert_eq!(outcome, Outcome::Refused, "{out:?}");
}

/// Step 6: `--sandbox require` refuses to start (125) when the sandbox
/// cannot be entered (a test hook hands Seatbelt a profile it rejects);
/// `best-effort` runs the program and says that the kernel process is not
/// confined.
#[test]
fn s6_require_fails_when_the_sandbox_cannot_be_entered() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let root = hvf_support::image("broken", hellovm_test_guest::HELLO);
    let broken = [("HELLOVM_TEST_SEATBELT_BROKEN", "1")];
    let out = run(exe, &root, "require", &["/broken"], &broken);
    assert_eq!(out.status.code(), Some(125), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Seatbelt profile: skipped: sandbox_init_with_parameters"),
        "{stderr}"
    );
    let out = run(exe, &root, "best-effort", &["/broken"], &broken);
    assert_eq!(
        out.status.code(),
        Some(hellovm_test_guest::HELLO_EXIT_CODE),
        "{out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("the kernel process is not confined"),
        "{stderr}"
    );
}

/// Step 7: with a terminal (a pty from script(1)) the confined kernel
/// process runs the program as the console and restores the terminal.
#[test]
fn s7_a_terminal_works_under_require() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let root = hvf_support::image("tty", hellovm_test_guest::HELLO);
    progress("run --sandbox require --tty under script(1)");
    let out = Command::new("/usr/bin/script")
        .args(["-q", "/dev/null"])
        .arg(exe)
        .args(["--sandbox", "require", "--tty", "--root"])
        .arg(&root)
        .arg("/tty")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    assert!(
        text.contains(hellovm_test_guest::HELLO_STDOUT.trim()),
        "{out:?}"
    );
    assert!(!text.contains("hellovm:"), "{out:?}");
    assert_eq!(out.status.code(), Some(hellovm_test_guest::HELLO_EXIT_CODE));
}

/// Step 8: a denial in the confined process reaches the unified log, where
/// an operator sees it with
/// `log show --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "hellovm("'`.
/// Not run by default because it does not pass reliably, for a reason
/// that is not known: it passed in the first run, and after the denials
/// the other tests cause, the log showed none from hellovm for the more
/// than 15 minutes it was watched. The kernel limiting Sandbox reports
/// would explain that, but this was not confirmed. Try it alone, long
/// after the others:
/// `cargo test -p hellovm --test hvf_hardening -- --ignored s8`.
#[test]
#[ignore = "denials stopped reaching the log after the other tests; cause unknown"]
fn s8_denials_reach_the_unified_log() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let fence = Fence::new();
    // A path of its own: Seatbelt does not report a denial again that it
    // reported recently, even for another process.
    let target = format!(
        "/etc/hellovm-log-check-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    progress(&format!(
        "fence --sandbox require read:{target} (log check)"
    ));
    let mut child = Command::new(exe)
        .args(["--sandbox", "require", "--no-tty", "--root"])
        .arg(fence.image())
        .args(["--insecure-fence-test", &format!("read:{target}")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(child.wait().unwrap().success(), "{stdout}");
    // Seatbelt reports the denied open of a missing file as a test for
    // its existence.
    let wanted = format!("hellovm({pid}) deny(1) file-test-existence {target}");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let log = Command::new("/usr/bin/log")
            .args(["show", "--last", "2m", "--style", "compact", "--predicate"])
            .arg(format!(
                "sender == \"Sandbox\" AND eventMessage CONTAINS \"hellovm({pid})\""
            ))
            .output();
        let text = match log {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
            other => {
                if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") {
                    panic!("log show failed: {other:?}");
                }
                eprintln!("SKIPPING: cannot read the unified log: {other:?}");
                return;
            }
        };
        if text.contains(&wanted) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "no report {wanted:?} in:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// A guest program gives the same output and status under `--sandbox
/// require` as without the sandbox, and contains `expected`.
fn same_under_require(argv: &[&str], status: i32, expected: &str) {
    let Some(exe) = hellovm() else {
        return;
    };
    let Some(root) = guest_image() else {
        return;
    };
    let off = run(exe, &root, "off", argv, &[]);
    let hardened = run(exe, &root, "require", argv, &[]);
    assert_eq!(
        hardened.status.code(),
        Some(status),
        "{argv:?}: {hardened:?}"
    );
    assert_eq!(off.status.code(), Some(status), "{argv:?}: {off:?}");
    assert_eq!(
        String::from_utf8_lossy(&hardened.stdout),
        String::from_utf8_lossy(&off.stdout),
        "{argv:?}"
    );
    assert!(
        String::from_utf8_lossy(&hardened.stdout).contains(expected),
        "{argv:?}: {hardened:?}"
    );
}

/// Step 9: the busybox pipeline of `platform-hvf/tests/guests.rs`.
#[test]
fn s9a_busybox_pipeline_under_require() {
    let _serial = hvf_support::serial();
    same_under_require(
        &[
            "/bin/sh",
            "-c",
            "seq 1 20000 | grep 7 | sort -rn | uniq | head -3; \
             echo $(seq 1 100 | wc -l) lines; \
             for i in 1 2 3; do echo $i; done | tr 123 abc | sed s/b/B/ | cat; \
             sleep 0.05 & wait $! && echo background done; \
             yes | head -1000 | wc -c",
        ],
        0,
        "19997\n19987\n19979\n100 lines\na\nB\nc\nbackground done\n2000",
    );
}

/// Step 9: CPython with files and `subprocess`.
#[test]
fn s9b_python_under_require() {
    let _serial = hvf_support::serial();
    let script = r#"
import os, sys, json, hashlib, subprocess, tempfile
d = tempfile.mkdtemp()
path = os.path.join(d, "x.json")
with open(path, "w") as f:
    json.dump({"n": [i * i for i in range(10)]}, f)
with open(path) as f:
    print("json", sum(json.load(f)["n"]))
os.remove(path)
os.rmdir(d)
print("sha256", hashlib.sha256(b"hellovm").hexdigest()[:16])
out = subprocess.run(["/bin/sh", "-c", "echo $((6 * 7)) | cat"], capture_output=True, text=True)
print("subprocess", out.returncode, out.stdout.strip())
out = subprocess.run([sys.executable, "-c", "import os; print(os.getppid())"], capture_output=True, text=True)
print("python child of", out.stdout.strip())
"#;
    same_under_require(
        &["/usr/bin/python3", "-c", script],
        0,
        "json 285\nsha256 3e11897887607fd8\nsubprocess 0 42\npython child of 1",
    );
}

/// Step 9: the C guests (static, static-PIE, dynamic; processes, signals,
/// threads), each its own run.
#[test]
fn s9c_c_guests_under_require() {
    let _serial = hvf_support::serial();
    for (argv, status, expected) in [
        (
            &["/guests/smoke", "one", "two words"][..],
            3,
            "malloc ok, mmap ok: zz, pid 1",
        ),
        (
            &["/guests/forks"],
            0,
            "busy child: parent ran, child ended by 9",
        ),
        (&["/guests/signals"], 0, "clone sharing refused: -1 1"),
        (&["/guests/threads"], 7, "fork: child-threads=1"),
        (&["/guests/pie", "arg"], 0, "pagesz=4096"),
        (
            &["/guests/dynamic", "hello"],
            0,
            "dynamic: arg=hello sqrt2=1.4142 interp=yes exe=/guests/dynamic",
        ),
    ] {
        same_under_require(argv, status, expected);
    }
}

/// Step 9: the fork bomb ends; `--timeout` stops a spinning shell from
/// the watchdog thread.
#[test]
fn s9d_fork_bomb_and_timeout_under_require() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let Some(root) = guest_image() else {
        return;
    };
    let out = run(exe, &root, "require", &["/guests/forks", "bomb", "60"], &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let start = Instant::now();
    let out = run(
        exe,
        &root,
        "require",
        &["--timeout", "0.3", "/bin/sh", "-c", "while :; do :; done"],
        &[],
    );
    assert_eq!(out.status.code(), Some(124), "{out:?}");
    assert!(start.elapsed() < Duration::from_secs(10));
}
