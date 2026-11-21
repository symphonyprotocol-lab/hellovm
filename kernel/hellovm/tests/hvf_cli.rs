//! The `hellovm` command line on macOS on Apple silicon (the HVF
//! platform): a program's output and exit status come through, and
//! `--timeout` stops a program that never makes a syscall. Every run is
//! hardened (`--sandbox require`); `hvf_hardening.rs` tests the hardening
//! itself. See `hvf_support` for signing, skipping, and why the tests run
//! one at a time.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod hvf_support;

use std::path::Path;
use std::process::{Command, Output};

use hvf_support::{guest_image, hellovm, image, progress};

fn run(exe: &Path, name: &str, guest: &str, extra: &[&str]) -> Output {
    progress(&format!("hvf_cli: {name} {extra:?}"));
    let root = image(name, guest);
    Command::new(exe)
        .args(["--sandbox", "require", "--no-tty"])
        .args(extra)
        .arg("--root")
        .arg(&root)
        .arg(format!("/{name}"))
        .output()
        .unwrap()
}

#[test]
fn hello_world_through_the_command_line() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let out = run(exe, "hello", hellovm_test_guest::HELLO, &[]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        hellovm_test_guest::HELLO_STDOUT
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        hellovm_test_guest::HELLO_STDERR
    );
    assert_eq!(out.status.code(), Some(hellovm_test_guest::HELLO_EXIT_CODE));
}

#[test]
fn timeout_stops_a_spinning_program() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let start = std::time::Instant::now();
    let out = run(exe, "spin", hellovm_test_guest::SPIN, &["--timeout", "0.3"]);
    assert_eq!(out.status.code(), Some(124));
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    assert!(String::from_utf8_lossy(&out.stderr).contains("timed out"));
}

/// The system starts a worker thread in the confined process when an
/// event source fires that a system library registered there (memory
/// pressure, a notification); the thread gives itself back with
/// `workq_kernreturn` and ends when left idle. The profile once killed the
/// process for that call. `HELLOVM_TEST_WORKER` has one started after the
/// process confined itself; the program then runs long enough for the
/// thread to come, go idle and end.
#[test]
fn a_worker_thread_of_the_system_does_not_kill_the_confined_process() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    progress("hvf_cli: spin with a system worker thread");
    let root = image("spin", hellovm_test_guest::SPIN);
    let out = Command::new(exe)
        .env("HELLOVM_TEST_WORKER", "1")
        .args(["--sandbox", "require", "--no-tty", "--timeout", "7"])
        .arg("--root")
        .arg(&root)
        .arg("/spin")
        .output()
        .unwrap();
    // Killed by the profile it would be signal 9, without a code.
    assert_eq!(
        out.status.code(),
        Some(124),
        "{:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unsupported_options_are_refused() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let root = image("refused", hellovm_test_guest::HELLO);
    let args = ["--template", "/nonexistent.sock"];
    progress(&format!("hvf_cli: refused {args:?}"));
    let out = Command::new(exe)
        .args(args)
        .arg("--root")
        .arg(&root)
        .arg("/refused")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125), "{args:?}");
    assert!(out.stdout.is_empty());
}

/// A busybox shell pipeline and a CPython script that starts processes,
/// through the signed command line.
#[test]
fn shell_pipeline_and_python_through_the_command_line() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let Some(root) = guest_image() else {
        return;
    };
    let run = |argv: &[&str]| {
        progress(&format!("hvf_cli: {argv:?}"));
        Command::new(exe)
            .args(["--sandbox", "require", "--no-tty", "--root"])
            .arg(&root)
            .args(argv)
            .output()
            .unwrap()
    };
    let out = run(&[
        "/bin/sh",
        "-c",
        "seq 1 1000 | grep 9 | sort -rn | head -2 | tr 9 n; echo $(ls /guests | wc -l) guests",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "nnn\nnn8\n7 guests\n",
        "{out:?}"
    );
    assert_eq!(out.status.code(), Some(0));
    let out = run(&[
        "/usr/bin/python3",
        "-c",
        "import subprocess; print(subprocess.check_output(['/bin/sh', '-c', 'echo $((6 * 7))'], text=True).strip())",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "42\n", "{out:?}");
    assert_eq!(out.status.code(), Some(0));
}

/// A buffer of the confined kernel process that grows large (here a file
/// in the writable layer, 48 MiB written 64 KiB at a time) does not get
/// the process killed: the system's `realloc` of a large block makes Mach
/// calls the profile refuses, so hellovm does not use it for large blocks
/// (see `main.rs`, `Confined`).
#[test]
fn a_buffer_that_grows_large_does_not_kill_the_confined_process() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let Some(root) = guest_image() else {
        return;
    };
    progress("hvf_cli: a file that grows to 48 MiB");
    let out = Command::new(exe)
        .args(["--sandbox", "require", "--no-tty", "--root"])
        .arg(&root)
        .args([
            "/usr/bin/python3",
            "-c",
            "import os\nf = open('/tmp/big', 'wb', buffering=0)\nfor _ in range(768):\n    f.write(b'x' * 65536)\nf.close()\nprint(os.path.getsize('/tmp/big'))",
        ])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "50331648\n",
        "{:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0));
}

/// `--vcpus`: the checks of `kernel/test-guest/c/smp.c` and threads of
/// CPU work on one vCPU and on four, confined (`--sandbox require`: the
/// vCPU threads need nothing the profile refuses), `--timeout` stopping
/// eight threads that never make a system call, and counts out of range
/// refused.
#[test]
fn vcpus_through_the_command_line() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let Some(root) = guest_image() else {
        return;
    };
    let run = |args: &[&str]| {
        progress(&format!("hvf_cli: {args:?}"));
        Command::new(exe)
            .args(["--sandbox", "require", "--no-tty", "--root"])
            .arg(&root)
            .args(args)
            .output()
            .unwrap()
    };
    for vcpus in ["1", "4"] {
        let out = run(&["--vcpus", vcpus, "/guests/smp", "all"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{vcpus}: {out:?}");
        assert_eq!(stdout.matches(": ok").count(), 7, "{vcpus}: {stdout}");
        let out = run(&["--vcpus", vcpus, "/guests/smp", "scale", "4", "10000000"]);
        assert_eq!(out.status.code(), Some(0), "{vcpus}: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).starts_with("scale: threads=4 sum="),
            "{out:?}"
        );
    }
    let start = std::time::Instant::now();
    let out = run(&[
        "--vcpus",
        "4",
        "--timeout",
        "0.3",
        "/guests/smp",
        "scale",
        "8",
        "1000000000000",
    ]);
    assert_eq!(out.status.code(), Some(124), "{out:?}");
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    for bad in ["0", "65", "many"] {
        let out = run(&["--vcpus", bad, "/guests/smp", "all"]);
        assert_eq!(out.status.code(), Some(2), "--vcpus {bad}: {out:?}");
        assert!(out.stdout.is_empty());
    }
}
