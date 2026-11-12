//! CPython from the build host, in an image assembled from the host's own
//! files: the interpreter, its shared libraries, the standard library and
//! busybox as `/bin/sh`.
//!
//! The scripts are in `tests/python/`. Without `/usr/bin/python3`, its
//! standard library under `/usr/lib/python3.X`, or busybox, the tests are
//! skipped unless `HELLOVM_REQUIRE_E2E=1`, which fails them and names the
//! missing piece.

#![cfg(target_os = "linux")]

mod common;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use common::{Sandbox, TempDir};
use hellovm_core::ExitStatus;

/// The image, built once for all tests in this file.
///
/// The error string names the missing piece: `/usr/bin/python3`, its
/// stdlib directory `/usr/lib/python3.X`, or busybox.
fn image() -> Result<&'static Path, String> {
    static IMAGE: OnceLock<Result<TempDir, String>> = OnceLock::new();
    IMAGE
        .get_or_init(assemble_image)
        .as_ref()
        .map(TempDir::path)
        .map_err(String::clone)
}

fn assemble_image() -> Result<TempDir, String> {
    let python = std::fs::canonicalize("/usr/bin/python3").map_err(|err| {
        format!(
            "no /usr/bin/python3 ({err}); install the distro python3 package \
             (the tests hard-code /usr/bin/python3)"
        )
    })?;
    let busybox = std::env::var("HELLOVM_BUSYBOX").unwrap_or_else(|_| "/bin/busybox".into());
    if !Path::new(&busybox).exists() {
        return Err(format!(
            "no busybox at {busybox}; install Debian/Ubuntu busybox-static \
             (not a musl binary from busybox.net)"
        ));
    }
    let version = python
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("python real path {} has no file name", python.display()))?
        .to_string();
    let stdlib = PathBuf::from("/usr/lib").join(&version);
    if !stdlib.is_dir() {
        return Err(format!(
            "no stdlib directory {} (resolved {} from /usr/bin/python3; expected /usr/lib/python3.X)",
            stdlib.display(),
            python.display()
        ));
    }
    let image = TempDir::new("python");
    image.install_with_libs(&python);
    image.symlink(&version, "usr/bin/python3");
    image.copy_host_tree(&stdlib);
    // Extension modules and their libraries.
    let dynload = stdlib.join("lib-dynload");
    let entries = std::fs::read_dir(&dynload)
        .map_err(|err| format!("cannot read {} ({err})", dynload.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("reading {}: {err}", dynload.display()))?;
        image.install_with_libs(&entry.path());
    }
    image.install(&busybox, "bin/busybox");
    for applet in ["sh", "tr", "echo", "cat"] {
        image.symlink("busybox", &format!("bin/{applet}"));
    }
    image.mkdir("root");
    let scripts = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/python");
    let entries = std::fs::read_dir(&scripts)
        .map_err(|err| format!("cannot read {} ({err})", scripts.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|err| format!("reading {}: {err}", scripts.display()))?
            .path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("script {} has no name", path.display()))?
            .to_string();
        let bytes =
            std::fs::read(&path).map_err(|err| format!("reading {}: {err}", path.display()))?;
        image.write(&format!("scripts/{name}"), &bytes);
    }
    Ok(image)
}

macro_rules! sandbox {
    () => {{
        let image = match image() {
            Ok(image) => image,
            Err(err) => {
                common::skip_or_fail(&format!("python test: {err}"));
                return;
            }
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
