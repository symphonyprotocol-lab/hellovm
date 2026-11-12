//! CPython from the build host, in an image assembled from the host's own
//! files: the interpreter, its shared libraries, the standard library and
//! busybox as `/bin/sh`.
//!
//! The scripts are in `tests/python/`. The tests are skipped, loudly, when
//! the host has no `/usr/bin/python3`.

#![cfg(target_os = "linux")]

mod common;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use common::{Sandbox, TempDir};
use hellovm_core::ExitStatus;

/// The image, built once for all tests in this file.
fn image() -> Option<&'static Path> {
    static IMAGE: OnceLock<Option<TempDir>> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            let python = std::fs::canonicalize("/usr/bin/python3").ok()?;
            let busybox =
                std::env::var("HELLOVM_BUSYBOX").unwrap_or_else(|_| "/bin/busybox".into());
            if !Path::new(&busybox).exists() {
                return None;
            }
            let version = python.file_name()?.to_str()?.to_string();
            let stdlib = PathBuf::from("/usr/lib").join(&version);
            if !stdlib.is_dir() {
                return None;
            }
            let image = TempDir::new("python");
            image.install_with_libs(&python);
            image.symlink(&version, "usr/bin/python3");
            image.copy_host_tree(&stdlib);
            // Extension modules and their libraries.
            for entry in std::fs::read_dir(stdlib.join("lib-dynload")).ok()? {
                image.install_with_libs(&entry.ok()?.path());
            }
            image.install(&busybox, "bin/busybox");
            for applet in ["sh", "tr", "echo", "cat"] {
                image.symlink("busybox", &format!("bin/{applet}"));
            }
            image.mkdir("root");
            let scripts = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/python");
            for entry in std::fs::read_dir(scripts).ok()? {
                let path = entry.ok()?.path();
                let name = path.file_name()?.to_str()?.to_string();
                image.write(&format!("scripts/{name}"), &std::fs::read(&path).ok()?);
            }
            Some(image)
        })
        .as_ref()
        .map(TempDir::path)
}

macro_rules! sandbox {
    () => {{
        let Some(image) = image() else {
            eprintln!("SKIPPING python test: no /usr/bin/python3 or busybox on this host");
            return;
        };
        Sandbox::new(image)
    }};
}

fn python(sb: &mut Sandbox, args: &[&str]) -> String {
    let mut argv = vec!["/usr/bin/python3"];
    argv.extend_from_slice(args);
    let out = sb.run(&argv);
    assert_eq!(out.status, ExitStatus::Exited(0), "{args:?}: {out:?}");
    out.stdout
}

#[test]
fn python_prints() {
    let mut sb = sandbox!();
    assert_eq!(python(&mut sb, &["-c", "print(sum(range(10)))"]), "45\n");
}

#[test]
fn python_subprocess() {
    let mut sb = sandbox!();
    assert_eq!(
        python(&mut sb, &["/scripts/subproc.py"]),
        "subprocess: 0 child 42\ncommunicate: 3 got hello\ncheck_output: ['a', 'c']\n"
    );
}

#[test]
fn python_threading() {
    let mut sb = sandbox!();
    assert_eq!(
        python(&mut sb, &["/scripts/threads.py"]),
        "threads: 8 True\nqueue: 4950\nevent: True\n"
    );
}

#[test]
fn python_files() {
    let mut sb = sandbox!();
    assert_eq!(
        python(&mut sb, &["/scripts/files.py"]),
        "json: {'a': [1, 2, 3]}\nlistdir: ['data.json.bak']\nsize: 1048576\nremoved: True\n"
    );
}
