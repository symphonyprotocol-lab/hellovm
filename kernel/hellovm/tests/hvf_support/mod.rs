//! What the HVF command-line tests share: the `hellovm` binary signed
//! with the hypervisor entitlement (as `kernel/platform-hvf/sign-and-run.sh`
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

/// Appends `what` to `kernel/target/p1c-progress.log` and syncs it to disk
/// before the caller starts the step, so that if the host goes down the
/// last line names what was running. (Two runs of these tests coincided
/// with kernel panics of the host; see README, "Hardening".)
pub fn progress(what: &str) {
    use std::io::Write;
    static DIR_SYNCED: OnceLock<()> = OnceLock::new();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("p1c-progress.log");
    let line = format!(
        "{:?} pid {} {what}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default(),
        std::process::id()
    );
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = file.write_all(line.as_bytes());
        let _ = file.sync_all();
    }
    DIR_SYNCED.get_or_init(|| {
        if let Ok(dir) = std::fs::File::open(&dir) {
            let _ = dir.sync_all();
        }
    });
}
