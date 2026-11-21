//! What the HVF command-line tests share: a copy of the `hellovm` binary
//! signed with the hypervisor entitlement (as `kernel/platform-hvf/sign-and-run.sh`
//! signs test binaries), images, and the guest image of
//! `kernel/platform-hvf/build-guests.sh`. Without the entitlement, or the
//! guests, the tests skip, unless `HELLOVM_REQUIRE_E2E=1`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

pub fn hellovm() -> Option<&'static Path> {
    static SIGNED: OnceLock<Option<PathBuf>> = OnceLock::new();
    SIGNED
        .get_or_init(|| {
            let Some(exe) = copy_to_sign() else {
                if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") {
                    panic!("HELLOVM_REQUIRE_E2E=1 but hellovm could not be copied");
                }
                eprintln!("SKIPPING: hellovm could not be copied to sign it");
                return None;
            };
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

/// A copy of the `hellovm` binary to sign, `kernel/target/hvf-signed/hellovm`.
/// Not the binary cargo built: every cargo invocation puts the unsigned
/// one back in its place, also while another test process is running
/// its signed one. The copy is replaced (a rename) by each test process,
/// under the lock of `serial`, so never while a test runs it.
fn copy_to_sign() -> Option<PathBuf> {
    let dir = target_dir().join("hvf-signed");
    std::fs::create_dir_all(&dir).ok()?;
    let fresh = dir.join(format!("hellovm.{}", std::process::id()));
    std::fs::copy(env!("CARGO_BIN_EXE_hellovm"), &fresh).ok()?;
    let exe = dir.join("hellovm");
    std::fs::rename(&fresh, &exe).ok()?;
    Some(exe)
}

/// Runs the hello world once to see whether the signed binary may use the
/// hypervisor (exit 125 with "HV_DENIED" if not).
fn hellovm_platform_hvf_usable(exe: &Path) -> bool {
    progress("probe: hello world with --sandbox off");
    let root = image("probe", hellovm_test_guest::HELLO);
    let out = Command::new(exe)
        .args(["--sandbox", "off", "--no-tty", "--root"])
        .arg(&root)
        .arg("/probe")
        .output();
    matches!(out, Ok(out) if !String::from_utf8_lossy(&out.stderr).contains("HV_DENIED"))
}

pub fn image(name: &str, guest: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hellovm-hvf-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(guest, dir.join(name)).unwrap();
    dir
}

/// The image `kernel/platform-hvf/build-guests.sh` assembles (busybox,
/// CPython), from `HELLOVM_HVF_GUESTS`.
pub fn guest_image() -> Option<PathBuf> {
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

/// The step log: `kernel/target/hvf-test-steps.log`.
const STEP_LOG: &str = "hvf-test-steps.log";
/// Past this size the step log is moved aside (`.old`) and started anew.
const STEP_LOG_MAX: u64 = 1 << 20;

fn target_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Held by a test while it runs.
pub struct Serial {
    _process: std::sync::MutexGuard<'static, ()>,
    /// Closing it releases the lock between processes.
    _file: Option<std::fs::File>,
}

/// One test with a VM at a time, whatever `--test-threads` says and
/// however many test binaries cargo starts: a lock in this process and a
/// lock file under `kernel/target` between processes (`hvf_cli` and
/// `hvf_hardening` are separate binaries). Every test here takes it first.
/// Two runs of an earlier version of these tests, in parallel, coincided
/// with kernel panics of the host (README, "Hardening").
pub fn serial() -> Serial {
    use std::os::fd::AsRawFd;
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A test that failed while it held the lock leaves nothing to repair.
    let process = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    let path = target_dir().join("hvf-tests.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    loop {
        // SAFETY: flock on an fd this function owns.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        // Without the lock the tests must not run side by side.
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::Interrupted,
            "locking {}: {err}",
            path.display()
        );
    }
    Serial {
        _process: process,
        _file: Some(file),
    }
}

/// Appends `what` to the step log and syncs it to disk before the caller
/// starts the step, so that if the host goes down the last line names
/// what was running. The first line a test process writes says that a
/// new run starts there.
pub fn progress(what: &str) {
    use std::io::Write;
    static STARTED: OnceLock<()> = OnceLock::new();
    let dir = target_dir();
    let path = dir.join(STEP_LOG);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let pid = std::process::id();
    let mut text = String::new();
    let first = STARTED.set(()).is_ok();
    if first {
        if std::fs::metadata(&path).is_ok_and(|meta| meta.len() > STEP_LOG_MAX) {
            let _ = std::fs::rename(&path, dir.join(format!("{STEP_LOG}.old")));
        }
        let exe = std::env::current_exe().unwrap_or_default();
        let name = exe.file_name().unwrap_or_default().to_string_lossy();
        text = format!("{now:?} pid {pid} ---- run starts: {name}\n");
    }
    text.push_str(&format!("{now:?} pid {pid} {what}\n"));
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        // One write, so that lines of two processes do not interleave.
        let _ = file.write_all(text.as_bytes());
        let _ = file.sync_all();
    }
    if first {
        if let Ok(dir) = std::fs::File::open(&dir) {
            let _ = dir.sync_all();
        }
    }
}

/// A process's physical footprint (what Activity Monitor calls its
/// memory), in bytes; 0 when it cannot be read.
pub fn phys_footprint(pid: u32) -> u64 {
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

/// Python for [`memory_goes_back`]: at each line it prints, it waits for
/// one on stdin. It touches 256 MiB, frees it, then reads 256 MiB of new
/// memory, which must be zero, and frees that; then 50 processes that
/// each touch and free 8 MiB.
pub const FREE_AND_REUSE: &str = r#"
import os, sys
def step(s):
    print(s, flush=True)
    sys.stdin.readline()
step("start")
b = b"\x01" * (256 << 20)
step("touched")
del b
step("freed")
c = bytearray(256 << 20)
print("zero", c.count(0) == len(c), flush=True)
sys.stdin.readline()
del c
for _ in range(50):
    pid = os.fork()
    if pid == 0:
        x = b"\x02" * (8 << 20)
        os._exit(0 if x[-1] == 2 else 1)
    assert os.waitpid(pid, 0)[1] == 0
step("forked")
"#;

/// Drives [`FREE_AND_REUSE`] in the kernel process `pid` (`line` reads
/// its next line, `send` answers it) and checks that its footprint
/// follows: up by 256 MiB, back to near the start once freed and once the
/// 50 processes are done, and the new memory zero. Returns the footprints
/// at start, touched, freed and at the end, in MiB.
pub fn memory_goes_back(
    pid: u32,
    mut line: impl FnMut() -> String,
    mut send: impl FnMut(),
) -> [f64; 4] {
    const MIB: f64 = 1024.0 * 1024.0;
    // Some slack over the start: the pools keep up to 4 MiB of free app
    // memory and 1 MiB of tables until the sandbox is idle for 20 ms, and
    // the kernel's own heap and the guest's page cache move a little.
    const SLACK: u64 = 24 << 20;
    let settled = |limit: u64| {
        let start = std::time::Instant::now();
        loop {
            let now = phys_footprint(pid);
            if now <= limit || start.elapsed() > std::time::Duration::from_secs(5) {
                return now;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    };
    assert_eq!(line(), "start\n");
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = phys_footprint(pid);
    assert!(start > 0, "no footprint for {pid}");
    send();
    assert_eq!(line(), "touched\n");
    let touched = phys_footprint(pid);
    assert!(
        touched > start + (250 << 20),
        "touched: {touched} from {start}"
    );
    send();
    assert_eq!(line(), "freed\n");
    let freed = settled(start + SLACK);
    assert!(freed <= start + SLACK, "freed: {freed}, start {start}");
    send();
    assert_eq!(
        line(),
        "zero True\n",
        "memory handed out again was not zero"
    );
    send();
    assert_eq!(line(), "forked\n");
    let end = settled(start + SLACK);
    assert!(
        end <= start + SLACK,
        "after the forks: {end}, start {start}"
    );
    send();
    [start, touched, freed, end].map(|b| b as f64 / MIB)
}
