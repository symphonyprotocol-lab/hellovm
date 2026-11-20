//! The `hellovm` command line on macOS on Apple silicon (the HVF
//! platform): a program's output and exit status come through, and
//! `--timeout` stops a program that never makes a syscall. Every run is
//! hardened (`--sandbox require`); `hvf_hardening.rs` tests the hardening
//! itself. See `hvf_support` for signing and skipping.

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
    let Some(exe) = hellovm() else {
        return;
    };
    let start = std::time::Instant::now();
    let out = run(exe, "spin", hellovm_test_guest::SPIN, &["--timeout", "0.3"]);
    assert_eq!(out.status.code(), Some(124));
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    assert!(String::from_utf8_lossy(&out.stderr).contains("timed out"));
}

#[test]
fn unsupported_options_are_refused() {
    let Some(exe) = hellovm() else {
        return;
    };
    let root = image("refused", hellovm_test_guest::HELLO);
    for args in [
        &["--egress", "/nonexistent.sock"][..],
        &["--template", "/nonexistent.sock"],
    ] {
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
}

/// A busybox shell pipeline and a CPython script that starts processes,
/// through the signed command line.
#[test]
fn shell_pipeline_and_python_through_the_command_line() {
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
        "nnn\nnn8\n6 guests\n",
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
