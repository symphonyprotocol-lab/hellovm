//! End-to-end tests of the U2 acceptance target: a busybox shell that runs
//! external commands, pipelines, background jobs and signal handlers.
//!
//! Every applet is installed as its own `/bin/<name>` symlink to busybox,
//! so the shell's external commands go through `fork`/`vfork` and `execve`
//! of a real file. `$HELLOVM_BUSYBOX` overrides the host busybox (default
//! `/bin/busybox`). Without one the tests are skipped, unless
//! `HELLOVM_REQUIRE_E2E=1`, which fails them and names Debian/Ubuntu
//! `busybox-static`.

#![cfg(target_os = "linux")]

mod common;

use std::time::{Duration, Instant};

use common::{Output, Sandbox, TempDir};
use hellovm_core::ExitStatus;

const APPLETS: &[&str] = &[
    "sh", "ls", "wc", "sort", "echo", "cat", "find", "grep", "sleep", "kill", "ps", "true",
    "false", "seq", "tr", "head", "yes", "xargs", "env", "printf", "sed", "uniq", "tee",
];

fn busybox() -> Option<String> {
    common::require_busybox("shell test")
}

fn image(busybox: &str) -> TempDir {
    let image = TempDir::new("shell");
    image.install(busybox, "bin/busybox");
    for applet in APPLETS {
        image.symlink("busybox", &format!("bin/{applet}"));
    }
    image.write("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n");
    image.write("etc/group", b"root:x:0:\n");
    image.write("data/a.txt", b"apple\n");
    image.write("data/b.txt", b"banana\n");
    image.write("data/sub/c.txt", b"cherry\n");
    image.mkdir("root");
    image
}

macro_rules! setup {
    () => {{
        let Some(busybox) = busybox() else { return };
        let image = image(&busybox);
        let sandbox = Sandbox::new(image.path());
        (image, sandbox)
    }};
}

fn sh(sb: &mut Sandbox, script: &str) -> Output {
    sb.run(&["/bin/sh", "-c", script])
}

/// Runs a script that must succeed and returns its stdout.
fn ok(sb: &mut Sandbox, script: &str) -> String {
    let out = sh(sb, script);
    assert_eq!(out.status, ExitStatus::Exited(0), "{script}: {out:?}");
    out.stdout
}

#[test]
fn pipelines() {
    let (_image, mut sb) = setup!();
    let entries = ok(&mut sb, "ls /").lines().count();
    assert_eq!(ok(&mut sb, "ls / | wc -l").trim(), entries.to_string());
    assert_eq!(
        ok(&mut sb, "for f in a b; do echo $f; done | sort -r"),
        "b\na\n"
    );
    assert_eq!(
        ok(
            &mut sb,
            "cat /data/a.txt /data/b.txt | tr a-z A-Z | sort | uniq"
        ),
        "APPLE\nBANANA\n"
    );
    // More than a pipe's capacity flows through a three-stage pipeline.
    assert_eq!(ok(&mut sb, "seq 1 50000 | grep 7 | wc -l").trim(), "17195");
    // The writer of a pipe whose reader is gone dies of SIGPIPE; the
    // pipeline's status is the last command's.
    assert_eq!(ok(&mut sb, "yes | head -n 3"), "y\ny\ny\n");
}

#[test]
fn find_exec_and_xargs() {
    let (_image, mut sb) = setup!();
    assert_eq!(
        ok(&mut sb, "find /data -name '*.txt' -exec cat {} \\; | sort"),
        "apple\nbanana\ncherry\n"
    );
    assert_eq!(
        ok(&mut sb, "find /data -type f | sort | xargs cat"),
        "apple\nbanana\ncherry\n"
    );
}

#[test]
fn substitution_lists_and_exit_statuses() {
    let (_image, mut sb) = setup!();
    assert_eq!(ok(&mut sb, "echo \"<$(cat /data/a.txt)>\""), "<apple>\n");
    assert_eq!(ok(&mut sb, "x=$(echo a; echo b); echo $x"), "a b\n");
    assert_eq!(ok(&mut sb, "true && echo yes || echo no"), "yes\n");
    assert_eq!(ok(&mut sb, "false && echo yes || echo no"), "no\n");
    assert_eq!(ok(&mut sb, "sh -c 'exit 7'; echo $?"), "7\n");
    assert_eq!(sh(&mut sb, "exit 3").status, ExitStatus::Exited(3));
    assert_eq!(sh(&mut sb, "false | true").status, ExitStatus::Exited(0));
    assert_eq!(sh(&mut sb, "true | false").status, ExitStatus::Exited(1));
    // A command killed by a signal: 128 + signal in the shell, and the
    // sandbox's first process killed by a signal ends the sandbox so.
    assert_eq!(ok(&mut sb, "sh -c 'kill -9 $$'; echo $?"), "137\n");
    assert_eq!(
        sh(&mut sb, "kill -TERM $$").status,
        ExitStatus::Signaled(15)
    );
    assert_eq!(ok(&mut sb, "/bin/missing 2>/dev/null; echo $?"), "127\n");
}

#[test]
fn background_jobs_and_wait() {
    let (_image, mut sb) = setup!();
    let started = Instant::now();
    let out = ok(
        &mut sb,
        "sleep 0.3 & a=$!; sleep 0.3 & b=$!; echo started; wait $a; echo a=$?; wait $b; echo b=$?",
    );
    assert_eq!(out, "started\na=0\nb=0\n");
    // The two sleeps ran at the same time.
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(3000), "{elapsed:?}");
    assert_eq!(
        ok(&mut sb, "(sleep 0.1; echo inner) & echo outer; wait"),
        "outer\ninner\n"
    );
    assert_eq!(ok(&mut sb, "sleep 10 & kill $!; wait $!; echo $?"), "143\n");
}

#[test]
fn traps_and_kill() {
    let (_image, mut sb) = setup!();
    assert_eq!(
        ok(
            &mut sb,
            "trap 'echo got USR1' USR1; kill -USR1 $$; echo after"
        ),
        "got USR1\nafter\n"
    );
    // A handler runs while the shell waits for a child; the wait then
    // goes on.
    assert_eq!(
        ok(
            &mut sb,
            "trap 'echo got TERM' TERM; (sleep 0.2; kill -TERM $$) & sleep 0.5; wait; echo done"
        ),
        "got TERM\ndone\n"
    );
    assert_eq!(ok(&mut sb, "trap 'echo bye' EXIT; echo hi"), "hi\nbye\n");
    // An ignored signal does nothing.
    assert_eq!(
        ok(&mut sb, "trap '' INT; kill -INT $$; echo alive"),
        "alive\n"
    );
}

#[test]
fn timeout_kills_a_sandbox_whose_children_spin() {
    let Some(busybox) = busybox() else { return };
    let image = image(&busybox);
    let started = Instant::now();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hellovm"))
        .args(["--timeout", "1", "--root"])
        .arg(image.path())
        .args([
            "/bin/sh",
            "-c",
            "sh -c 'while :; do :; done' & sh -c 'while :; do :; done' & wait",
        ])
        .output()
        .expect("run hellovm");
    assert_eq!(output.status.code(), Some(124), "{output:?}");
    assert!(started.elapsed() < Duration::from_secs(30));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("timed out"), "{stderr}");
}
