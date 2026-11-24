//! The `hellovm` command line with the KVM platform (`--platform kvm`, on
//! arm64 Linux with `/dev/kvm`): output and exit status come through,
//! `--timeout` stops programs that never make a system call, a busybox
//! pipeline and CPython run, `--vcpus` runs threads in parallel, the
//! kernel process is confined (every layer `--sandbox require` asks for,
//! and the KVM allowlist), and memory the guest frees goes back to the
//! host. Without `/dev/kvm` the tests print `SKIPPING` and pass, unless
//! `HELLOVM_REQUIRE_E2E=1`; the tests that need busybox and CPython take
//! the image of `kernel/platform-hvf/build-guests.sh` from
//! `HELLOVM_KVM_GUESTS`.

#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

#[path = "vm_memory/mod.rs"]
mod vm_memory;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;

/// One sandbox at a time: the host may have few CPUs.
static SERIAL: Mutex<()> = Mutex::new(());

fn require() -> bool {
    std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1")
}

/// Whether the KVM platform can run here.
fn kvm() -> bool {
    match hellovm_platform_kvm::check_access() {
        Ok(()) => true,
        Err(err) if require() => panic!("HELLOVM_REQUIRE_E2E=1 but KVM is unavailable: {err}"),
        Err(err) => {
            eprintln!("SKIPPING: KVM is unavailable: {err}");
            false
        }
    }
}

fn guest_image() -> Option<PathBuf> {
    match std::env::var_os("HELLOVM_KVM_GUESTS") {
        Some(root) => Some(PathBuf::from(root)),
        None if require() => panic!("HELLOVM_REQUIRE_E2E=1 but HELLOVM_KVM_GUESTS is not set"),
        None => {
            eprintln!("SKIPPING: set HELLOVM_KVM_GUESTS (see platform-hvf/build-guests.sh)");
            None
        }
    }
}

fn exe() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_hellovm"))
}

/// A directory with one guest in it, as `/name`.
fn image(name: &str, guest: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hellovm-kvm-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(guest, dir.join(name)).unwrap();
    dir
}

fn hellovm(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(exe());
    command
        .args([
            "--platform",
            "kvm",
            "--sandbox",
            "require",
            "--no-tty",
            "--root",
        ])
        .arg(root)
        .args(args);
    command
}

fn run(root: &Path, args: &[&str]) -> Output {
    hellovm(root, args).output().unwrap()
}

#[test]
fn hello_world_through_the_command_line() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if !kvm() {
        return;
    }
    let root = image("hello", hellovm_test_guest::HELLO);
    let out = run(&root, &["/hello"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        hellovm_test_guest::HELLO_STDOUT,
        "{out:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        hellovm_test_guest::HELLO_STDERR
    );
    assert_eq!(out.status.code(), Some(hellovm_test_guest::HELLO_EXIT_CODE));
}

/// Every layer is active and the seccomp filter is the KVM one (the debug
/// log lists the layers).
#[test]
fn the_kernel_process_is_confined() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if !kvm() {
        return;
    }
    let root = image("hello", hellovm_test_guest::HELLO);
    let out = hellovm(&root, &["/hello"])
        .env("HELLOVM_LOG", "debug")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(42), "{stderr}");
    for layer in [
        "inherited fds closed: active",
        "resource limits: active",
        "no_new_privs: active",
        "not dumpable: active",
        "seccomp allowlist: active",
    ] {
        assert!(stderr.contains(layer), "{layer}: {stderr}");
    }
    assert!(
        stderr.contains("Landlock: active") || stderr.contains("namespaces: active"),
        "{stderr}"
    );
}

#[test]
fn timeout_stops_a_spinning_program() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if !kvm() {
        return;
    }
    let root = image("spin", hellovm_test_guest::SPIN);
    let start = std::time::Instant::now();
    let out = run(&root, &["--timeout", "0.3", "/spin"]);
    assert_eq!(out.status.code(), Some(124), "{out:?}");
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    assert!(String::from_utf8_lossy(&out.stderr).contains("timed out"));
}

#[test]
fn unsupported_options_are_refused() {
    let root = std::env::temp_dir();
    for args in [
        &[
            "--platform",
            "kvm",
            "--template",
            "/tmp/x",
            "--root",
            "/",
            "/x",
        ][..],
        &["--vcpus", "2", "--root", "/", "/x"],
        &["--platform", "kvm", "--vcpus", "0", "--root", "/", "/x"],
        &["--platform", "vmware", "--root", "/", "/x"],
    ] {
        let out = Command::new(exe()).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
    }
    drop(root);
}

/// A busybox shell pipeline and a CPython script that starts processes.
#[test]
fn shell_pipeline_and_python_through_the_command_line() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if !kvm() {
        return;
    }
    let Some(root) = guest_image() else {
        return;
    };
    let out = run(
        &root,
        &[
            "/bin/sh",
            "-c",
            "seq 1 1000 | grep 9 | sort -rn | head -2 | tr 9 n; echo $(ls /guests | wc -l) guests",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "nnn\nnn8\n7 guests\n",
        "{out:?}"
    );
    assert_eq!(out.status.code(), Some(0));
    let out = run(
        &root,
        &[
            "/usr/bin/python3",
            "-c",
            "import subprocess; print(subprocess.check_output(['/bin/sh', '-c', 'echo $((6 * 7))'], text=True).strip())",
        ],
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "42\n", "{out:?}");
    assert_eq!(out.status.code(), Some(0));
}

/// `--vcpus`: the checks of `kernel/test-guest/c/smp.c` and threads of CPU
/// work on one vCPU and on four, confined (the vCPU threads start after
/// the hardening and need nothing the allowlist refuses), and `--timeout`
/// stopping eight threads that never make a system call.
#[test]
fn vcpus_through_the_command_line() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if !kvm() {
        return;
    }
    let Some(root) = guest_image() else {
        return;
    };
    for vcpus in ["1", "4"] {
        let out = run(&root, &["--vcpus", vcpus, "/guests/smp", "all"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{vcpus}: {out:?}");
        assert_eq!(stdout.matches(": ok").count(), 7, "{vcpus}: {stdout}");
        let out = run(
            &root,
            &["--vcpus", vcpus, "/guests/smp", "scale", "4", "10000000"],
        );
        assert_eq!(out.status.code(), Some(0), "{vcpus}: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).starts_with("scale: threads=4 sum="),
            "{out:?}"
        );
    }
    let start = std::time::Instant::now();
    let out = run(
        &root,
        &[
            "--vcpus",
            "4",
            "--timeout",
            "0.3",
            "/guests/smp",
            "scale",
            "8",
            "1000000000000",
        ],
    );
    assert_eq!(out.status.code(), Some(124), "{out:?}");
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
}

/// The resident size of process `pid` (`VmRSS`), in bytes; 0 when it
/// cannot be read.
fn resident(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|kib| {
            kib.trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<u64>()
                .ok()
        })
        .map_or(0, |kib| kib << 10)
}

/// Memory a guest frees goes back to the host: CPython touches 256 MiB,
/// frees it, reads 256 MiB of new memory (zero), and runs 50 processes
/// that touch and free 8 MiB each; the kernel process's resident size,
/// read from outside, follows. Confined, on one vCPU and on four.
#[test]
fn freed_memory_goes_back_to_the_host() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if !kvm() {
        return;
    }
    let Some(root) = guest_image() else {
        return;
    };
    for vcpus in ["1", "4"] {
        let mut child = hellovm(
            &root,
            &[
                "--vcpus",
                vcpus,
                "/usr/bin/python3",
                "-c",
                vm_memory::FREE_AND_REUSE,
            ],
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
        let pid = child.id();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mib = vm_memory::memory_goes_back(
            || resident(pid),
            pid,
            || {
                let mut line = String::new();
                std::io::BufRead::read_line(&mut stdout, &mut line).unwrap();
                line
            },
            || std::io::Write::write_all(&mut stdin, b"\n").unwrap(),
        );
        eprintln!(
            "kvm_cli: {vcpus} vCPUs: resident {:.1} MiB at start, {:.1} touched, {:.1} freed, \
             {:.1} after the forks",
            mib[0], mib[1], mib[2], mib[3]
        );
        drop(stdin);
        assert!(child.wait().unwrap().success());
    }
}
