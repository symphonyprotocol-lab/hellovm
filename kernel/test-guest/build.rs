//! Builds the test guests: the assembly programs in `asm/` (static,
//! libc-free, non-PIE) and the C programs in `c/` (static-PIE against the
//! system libc).
//!
//! They are built for the target architecture with the C compiler driver
//! (`cc`, or `$HELLOVM_GUEST_CC` when cross-compiling). C guests need the
//! target's static libc, so they are only built natively; when
//! cross-compiling their paths are empty. Only Linux targets build guests;
//! elsewhere the crate is empty.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const ASM_GUESTS: &[&str] = &["hello", "enosys"];
const C_GUESTS: &[&str] = &["pie"];

fn build(cc: &str, name: &str, src: &Path, out: &Path, flags: &[&str]) {
    let output = Command::new(cc)
        .args(flags)
        .args(["-Wl,--build-id=none", "-o"])
        .arg(out)
        .arg(src)
        .output()
        .unwrap_or_else(|err| panic!("running {cc}: {err}"));
    if !output.status.success() {
        panic!(
            "building guest {name} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn main() {
    println!("cargo:rerun-if-changed=asm");
    println!("cargo:rerun-if-changed=c");
    println!("cargo:rerun-if-env-changed=HELLOVM_GUEST_CC");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
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
        build(&cc, guest, &src, &out, &["-static-pie", "-fPIE", "-O2"]);
        println!("cargo:rustc-env={var}={}", out.display());
    }
}
