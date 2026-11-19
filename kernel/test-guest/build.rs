//! Builds the test guests: the assembly programs in `asm/` (static,
//! libc-free, non-PIE) and the C programs in `c/` (static-PIE against the
//! system libc).
//!
//! `DYNAMIC_GUESTS` are linked dynamically against the build host's libc;
//! tests run them in an image assembled from the host's own libraries.
//!
//! They are built for the target architecture with the C compiler driver
//! (`cc`, or `$HELLOVM_GUEST_CC` when cross-compiling). C guests need the
//! target's static libc, so they are only built natively; when
//! cross-compiling their paths are empty.
//!
//! On macOS on Apple silicon (the HVF platform's host) the assembly guests
//! and `HVF_GUESTS` are built as aarch64 Linux executables with the
//! system's clang (`--target=aarch64-linux-gnu`) and the `rust-lld` of the
//! Rust toolchain as the linker; there is no Linux libc there, so no C
//! guests. Other targets build no guests and the crate is empty.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const ASM_GUESTS: &[&str] = &["hello", "enosys"];
const C_GUESTS: &[&str] = &["pie", "signals", "threads", "forks"];
/// C guests linked dynamically against the build host's libc.
const DYNAMIC_GUESTS: &[&str] = &["dynamic", "netcheck"];
/// aarch64-only assembly guests for the HVF platform's tests (`asm/hvf`).
const HVF_GUESTS: &[&str] = &[
    "getpid_loop",
    "segv",
    "odd_regs",
    "spin",
    "dit",
    "reserve",
    "icache",
];

fn build(cc: &str, name: &str, src: &Path, out: &Path, flags: &[&str]) {
    if let Err(why) = try_build(cc, name, src, out, flags) {
        panic!("{why}");
    }
}

fn try_build(cc: &str, name: &str, src: &Path, out: &Path, flags: &[&str]) -> Result<(), String> {
    let output = Command::new(cc)
        .args(flags)
        .args(["-Wl,--build-id=none", "-o"])
        .arg(out)
        .arg(src)
        .output()
        .map_err(|err| format!("running {cc}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "building guest {name} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn main() {
    println!("cargo:rerun-if-changed=asm");
    println!("cargo:rerun-if-changed=c");
    println!("cargo:rerun-if-env-changed=HELLOVM_GUEST_CC");
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if os == "macos" && arch == "aarch64" {
        build_for_hvf();
        return;
    }
    if os != "linux" {
        return;
    }
    let native = env::var("TARGET") == env::var("HOST");
    let cc = match env::var("HELLOVM_GUEST_CC") {
        Ok(cc) => cc,
        Err(_) if native => "cc".to_string(),
        Err(_) => panic!("cross-compiling: set HELLOVM_GUEST_CC to a C compiler for the target"),
    };
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    for guest in ASM_GUESTS {
        let src = manifest_dir.join("asm").join(format!("{guest}.S"));
        let out = out_dir.join(guest);
        build(&cc, guest, &src, &out, &["-nostdlib", "-static", "-no-pie"]);
        println!(
            "cargo:rustc-env=HELLOVM_GUEST_{}={}",
            guest.to_uppercase(),
            out.display()
        );
    }
    for guest in C_GUESTS {
        let var = format!("HELLOVM_GUEST_{}", guest.to_uppercase());
        if !native {
            println!("cargo:rustc-env={var}=");
            continue;
        }
        let src = manifest_dir.join("c").join(format!("{guest}.c"));
        let out = out_dir.join(guest);
        build(
            &cc,
            guest,
            &src,
            &out,
            &["-static-pie", "-fPIE", "-O2", "-pthread"],
        );
        println!("cargo:rustc-env={var}={}", out.display());
    }
    for guest in DYNAMIC_GUESTS {
        let var = format!("HELLOVM_GUEST_{}", guest.to_uppercase());
        if !native {
            println!("cargo:rustc-env={var}=");
            continue;
        }
        let src = manifest_dir.join("c").join(format!("{guest}.c"));
        let out = out_dir.join(guest);
        build(&cc, guest, &src, &out, &["-O2", "-lm"]);
        println!("cargo:rustc-env={var}={}", out.display());
    }
}

/// The assembly guests, as aarch64 Linux executables, on a macOS host.
///
/// A Mac without the tools for that (the Rust toolchain's `rust-lld`, a
/// clang that targets aarch64 Linux) still builds the workspace: the
/// guests' paths are then empty, a warning says why, and the tests that
/// need them skip (or fail under `HELLOVM_REQUIRE_E2E=1`). Before the HVF
/// platform this crate was empty on macOS, and nothing there needed them.
fn build_for_hvf() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let guests: Vec<(&str, PathBuf)> = ASM_GUESTS
        .iter()
        .map(|g| (*g, manifest_dir.join("asm").join(format!("{g}.S"))))
        .chain(
            HVF_GUESTS
                .iter()
                .map(|g| (*g, manifest_dir.join("asm/hvf").join(format!("{g}.S")))),
        )
        .collect();
    let built = hvf_guests(&guests, &out_dir);
    if let Err(why) = &built {
        for line in why.lines() {
            println!("cargo:warning=test guests for the HVF platform not built: {line}");
        }
    }
    for (guest, _) in &guests {
        let path = match &built {
            Ok(()) => out_dir.join(guest).display().to_string(),
            Err(_) => String::new(),
        };
        println!(
            "cargo:rustc-env=HELLOVM_GUEST_{}={path}",
            guest.to_uppercase()
        );
    }
}

fn hvf_guests(guests: &[(&str, PathBuf)], out_dir: &Path) -> Result<(), String> {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let sysroot = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .map_err(|err| format!("running {rustc}: {err}"))?;
    let sysroot = String::from_utf8(sysroot.stdout).map_err(|_| "a sysroot that is not UTF-8")?;
    let host = env::var("HOST").map_err(|_| "no HOST")?;
    let lld = PathBuf::from(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin/gcc-ld/ld.lld");
    if !lld.exists() {
        return Err(format!(
            "no {} (the Rust toolchain's rust-lld, which rustup installs) to link them",
            lld.display()
        ));
    }
    let cc = env::var("HELLOVM_GUEST_CC").unwrap_or_else(|_| "clang".into());
    let fuse_ld = format!("-fuse-ld={}", lld.display());
    let flags = [
        "--target=aarch64-linux-gnu",
        "-nostdlib",
        "-static",
        fuse_ld.as_str(),
    ];
    for (guest, src) in guests {
        try_build(&cc, guest, src, &out_dir.join(guest), &flags)?;
    }
    Ok(())
}
