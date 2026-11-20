//! The `hellovm` command line on macOS on Apple silicon (the HVF
//! platform): a program's output and exit status come through, and
//! `--timeout` stops a program that never makes a syscall.
//!
//! The test signs the `hellovm` binary with the hypervisor entitlement
//! first (as `kernel/platform-hvf/sign-and-run.sh` does for test
//! binaries); without it, or when signing fails, it is skipped, unless
//! `HELLOVM_REQUIRE_E2E=1`.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

fn hellovm() -> Option<&'static Path> {
    static SIGNED: OnceLock<Option<PathBuf>> = OnceLock::new();
    SIGNED
        .get_or_init(|| {
            let exe = PathBuf::from(env!("CARGO_BIN_EXE_hellovm"));
            // Empty when this Mac lacks the tools to build the guests.
            if hellovm_test_guest::HELLO.is_empty() {
                if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") {
                    panic!("HELLOVM_REQUIRE_E2E=1 but the test guests were not built");
                }
                eprintln!("SKIPPING: the test guests were not built on this Mac");
                return None;
            }
            let entitlements =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../platform-hvf/hellovm.entitlements");
            let signed = Command::new("codesign")
                .args(["--force", "--sign", "-", "--entitlements"])
                .arg(&entitlements)
                .arg(&exe)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false);
            if signed && hellovm_platform_hvf_usable(&exe) {
                return Some(exe);
            }
            if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") {
                panic!("HELLOVM_REQUIRE_E2E=1 but hellovm cannot use the HVF platform");
            }
            eprintln!("SKIPPING: hellovm could not be signed for Hypervisor.framework");
            None
        })
        .as_deref()
}

/// Runs the hello world once to see whether the signed binary may use the
/// hypervisor (exit 125 with "HV_DENIED" if not).
fn hellovm_platform_hvf_usable(exe: &Path) -> bool {
    let root = image("probe", hellovm_test_guest::HELLO);
    let out = Command::new(exe)
        .args(["--sandbox", "off", "--no-tty", "--root"])
        .arg(&root)
        .arg("/probe")
        .output();
    matches!(out, Ok(out) if !String::from_utf8_lossy(&out.stderr).contains("HV_DENIED"))
}

fn image(name: &str, guest: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hellovm-hvf-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(guest, dir.join(name)).unwrap();
    dir
}

fn run(exe: &Path, name: &str, guest: &str, extra: &[&str]) -> Output {
    let root = image(name, guest);
    Command::new(exe)
        .args(["--sandbox", "off", "--no-tty"])
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
        &["--sandbox", "require"][..],
        &["--egress", "/nonexistent.sock"],
    ] {
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

/// The image `kernel/platform-hvf/build-guests.sh` assembles (busybox,
/// CPython), from `HELLOVM_HVF_GUESTS`.
fn guest_image() -> Option<PathBuf> {
    match std::env::var_os("HELLOVM_HVF_GUESTS") {
        Some(root) => Some(PathBuf::from(root)),
        None if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
            panic!("HELLOVM_REQUIRE_E2E=1 but HELLOVM_HVF_GUESTS is not set")
        }
        None => {
            eprintln!("SKIPPING: set HELLOVM_HVF_GUESTS (see platform-hvf/build-guests.sh)");
            None
        }
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
        Command::new(exe)
            .args(["--sandbox", "off", "--no-tty", "--root"])
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
