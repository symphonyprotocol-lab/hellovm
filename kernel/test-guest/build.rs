//! Assembles the test guests in `asm/` into static, libc-free executables.
//!
//! They are built for the target architecture with the C compiler driver
//! (`cc`, or `$CANSOL_GUEST_CC` when cross-compiling). Only Linux targets
//! build guests; elsewhere the crate is empty.

use std::env;
use std::path::PathBuf;
use std::process::Command;

const GUESTS: &[&str] = &["hello", "enosys"];

fn main() {
    println!("cargo:rerun-if-changed=asm");
    println!("cargo:rerun-if-env-changed=CANSOL_GUEST_CC");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let cc = match env::var("CANSOL_GUEST_CC") {
        Ok(cc) => cc,
        Err(_) if env::var("TARGET") == env::var("HOST") => "cc".to_string(),
        Err(_) => panic!("cross-compiling: set CANSOL_GUEST_CC to a C compiler for the target"),
    };
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    for guest in GUESTS {
        let src = manifest_dir.join("asm").join(format!("{guest}.S"));
        let out = out_dir.join(guest);
        let output = Command::new(&cc)
            .args([
                "-nostdlib",
                "-static",
                "-no-pie",
                "-Wl,--build-id=none",
                "-o",
            ])
            .arg(&out)
            .arg(&src)
            .output()
            .unwrap_or_else(|err| panic!("running {cc}: {err}"));
        if !output.status.success() {
            panic!(
                "building guest {guest} failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        println!(
            "cargo:rustc-env=CANSOL_GUEST_{}={}",
            guest.to_uppercase(),
            out.display()
        );
    }
}
