//! `HELLOVM_BUILD`: a fingerprint of this crate's sources, for the
//! snapshots of warm-clone templates (`hellovm_core::snap`, `src/mmu.rs`). A snapshot is the
//! fields of the kernel's state in declaration order, so its format
//! changes with the sources; a clone's kernel process, which may be
//! another build than its template's (the executable was replaced
//! meanwhile), refuses a snapshot whose fingerprint is not its own.

use std::path::{Path, PathBuf};

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("{}: {err}", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");
    let mut files = Vec::new();
    sources(Path::new("src"), &mut files);
    // FNV-1a, 64 bits, over each file's name and bytes.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for path in &files {
        feed(path.to_string_lossy().as_bytes());
        feed(&[0]);
        feed(&std::fs::read(path).unwrap_or_else(|err| panic!("{}: {err}", path.display())));
        feed(&[0]);
    }
    println!("cargo:rustc-env=HELLOVM_BUILD={hash:016x}");
}
