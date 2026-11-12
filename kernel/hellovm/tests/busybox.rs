//! End-to-end tests with a real program: a statically linked busybox from
//! the host (Debian's `busybox-static` in the dev container), run under
//! the kernel against a small image directory.
//!
//! The busybox binary is copied into each test's image as `/bin/busybox`.
//! `$HELLOVM_BUSYBOX` overrides its host path (default `/bin/busybox`); the
//! tests are skipped, loudly, when it does not exist.
//!
//! U1 has no `fork`, so each command is one applet. Multi-step scenarios run
//! applets one after another in the same sandbox (same filesystem), and
//! `sh -c` scripts use only builtins and redirections.

#![cfg(target_os = "linux")]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use common::{Sandbox, TempDir};
use hellovm_core::ExitStatus;

const DATA: &str = "line one\nline two\nline three\n";

fn busybox() -> Option<String> {
    let path = std::env::var("HELLOVM_BUSYBOX").unwrap_or_else(|_| "/bin/busybox".into());
    if Path::new(&path).exists() {
        Some(path)
    } else {
        eprintln!("SKIPPING busybox test: {path} not found (install busybox-static)");
        None
    }
}

/// A small image: busybox, /bin/sh, user and group files, a data directory.
fn image(busybox: &str) -> TempDir {
    let image = TempDir::new("busybox");
    image.install(busybox, "bin/busybox");
    image.symlink("busybox", "bin/sh");
    image.write("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n");
    image.write("etc/group", b"root:x:0:\n");
    image.write("data/f", DATA.as_bytes());
    image.write("data/sub/inner", b"inner\n");
    image.mkdir("root");
    image
}

macro_rules! setup {
    () => {{
        let Some(busybox) = busybox() else { return };
        let image = image(&busybox);
        let sandbox = Sandbox::new(image.path());
        (image, sandbox)
    }};
}

#[test]
fn echo_and_exit_codes() {
    let (_image, mut sb) = setup!();
    assert_eq!(sb.ok(&["echo", "hello", "world"]), "hello world\n");
    assert_eq!(sb.bb(&["false"]).status, ExitStatus::Exited(1));
    assert_eq!(sb.bb(&["true"]).status, ExitStatus::Exited(0));
    // argv[0] dispatch through the /bin/sh symlink.
    let out = sb.run(&["/bin/sh", "-c", "exit 7"]);
    assert_eq!(out.status, ExitStatus::Exited(7));
}

#[test]
fn cat_head_wc() {
    let (_image, mut sb) = setup!();
    assert_eq!(sb.ok(&["cat", "/data/f"]), DATA);
    assert_eq!(
        sb.ok(&["head", "-n", "2", "/data/f"]),
        "line one\nline two\n"
    );
    let wc = sb.ok(&["wc", "/data/f"]);
    let fields: Vec<_> = wc.split_whitespace().collect();
    assert_eq!(fields, ["3", "6", "29", "/data/f"]);
    // Console input.
    let out = sb.run_with_input(&["/bin/busybox", "wc", "-l"], b"a\nb\n");
    assert_eq!(out.stdout.trim(), "2");
    let out = sb.run_with_input(&["/bin/busybox", "cat"], b"from stdin");
    assert_eq!(out.stdout, "from stdin");
    // A missing file.
    let out = sb.bb(&["cat", "/data/missing"]);
    assert_eq!(out.status, ExitStatus::Exited(1));
    assert!(out.stderr.contains("No such file or directory"), "{out:?}");
}

#[test]
fn ls_l_and_stat() {
    let (_image, mut sb) = setup!();
    let ls = sb.ok(&["ls", "-l", "/data"]);
    let lines: Vec<_> = ls.lines().collect();
    assert_eq!(lines[0], "total 8", "{ls}");
    assert!(
        lines[1].starts_with("-rw-r--r--    1 root     root            29 "),
        "{ls}"
    );
    assert!(lines[1].ends_with(" f"), "{ls}");
    assert!(
        lines[2].starts_with("drwxr-xr-x") && lines[2].ends_with(" sub"),
        "{ls}"
    );
    assert_eq!(
        sb.ok(&["stat", "-c", "%s %F %a %U", "/data/f"]),
        "29 regular file 644 root\n"
    );
    assert_eq!(sb.ok(&["stat", "-c", "%F", "/data/sub"]), "directory\n");
    let full = sb.ok(&["stat", "/data/f"]);
    assert!(
        full.contains("File: /data/f") && full.contains("Size: 29"),
        "{full}"
    );
    assert_eq!(
        sb.ok(&["ls", "/"]),
        "bin\ndata\ndev\netc\nproc\nroot\ntmp\n"
    );
    assert_eq!(sb.ok(&["ls", "/dev/null"]), "/dev/null\n");
}

#[test]
fn mkdir_ls_touch() {
    let (_image, mut sb) = setup!();
    sb.ok(&["mkdir", "-p", "/tmp/a/b/c"]);
    sb.ok(&["mkdir", "/data/new"]);
    assert_eq!(sb.ok(&["ls", "/tmp/a/b"]), "c\n");
    assert_eq!(sb.ok(&["ls", "/data"]), "f\nnew\nsub\n");
    let out = sb.bb(&["mkdir", "/data/new"]);
    assert_eq!(out.status, ExitStatus::Exited(1));
    assert!(out.stderr.contains("File exists"), "{out:?}");
    sb.ok(&["touch", "/tmp/a/empty"]);
    assert_eq!(
        sb.ok(&["stat", "-c", "%s %F", "/tmp/a/empty"]),
        "0 regular empty file\n"
    );
    sb.ok(&["touch", "-d", "2001-02-03 04:05:06", "/data/f"]);
    assert_eq!(sb.ok(&["stat", "-c", "%Y", "/data/f"]), "981173106\n");
    sb.ok(&["rmdir", "/tmp/a/b/c"]);
    assert_eq!(sb.ok(&["ls", "/tmp/a/b"]), "");
}

#[test]
fn cp_mv_rm() {
    let (_image, mut sb) = setup!();
    sb.ok(&["cp", "/data/f", "/tmp/copy"]);
    assert_eq!(sb.ok(&["cat", "/tmp/copy"]), DATA);
    sb.ok(&["cp", "-r", "/data/sub", "/tmp/subcopy"]);
    assert_eq!(sb.ok(&["cat", "/tmp/subcopy/inner"]), "inner\n");
    sb.ok(&["mv", "/tmp/copy", "/tmp/moved"]);
    assert_eq!(sb.ok(&["ls", "/tmp"]), "moved\nsubcopy\n");
    // Moving and removing image files and directories.
    sb.ok(&["mv", "/data/f", "/data/g"]);
    sb.ok(&["mv", "/data/sub", "/tmp/sub"]);
    assert_eq!(sb.ok(&["cat", "/tmp/sub/inner"]), "inner\n");
    assert_eq!(sb.ok(&["ls", "/data"]), "g\n");
    sb.ok(&["rm", "/data/g"]);
    sb.ok(&["rm", "-r", "/tmp/sub"]);
    assert_eq!(sb.ok(&["ls", "/data"]), "");
    assert_eq!(sb.bb(&["cat", "/data/g"]).status, ExitStatus::Exited(1));
    assert_eq!(sb.ok(&["ls", "/tmp"]), "moved\nsubcopy\n");
}

#[test]
fn symlinks_and_readlink() {
    let (_image, mut sb) = setup!();
    sb.ok(&["ln", "-s", "/data/f", "/tmp/abs"]);
    sb.ok(&["ln", "-s", "../data/sub", "/tmp/rel"]);
    assert_eq!(sb.ok(&["readlink", "/tmp/abs"]), "/data/f\n");
    assert_eq!(sb.ok(&["readlink", "/tmp/rel"]), "../data/sub\n");
    assert_eq!(
        sb.ok(&["readlink", "-f", "/tmp/rel/inner"]),
        "/data/sub/inner\n"
    );
    assert_eq!(sb.ok(&["cat", "/tmp/abs"]), DATA);
    assert_eq!(sb.ok(&["cat", "/tmp/rel/inner"]), "inner\n");
    let ls = sb.ok(&["ls", "-l", "/tmp/abs"]);
    assert!(
        ls.starts_with("lrwxrwxrwx") && ls.ends_with("/tmp/abs -> /data/f\n"),
        "{ls}"
    );
    sb.ok(&["ln", "/data/f", "/tmp/hard"]);
    assert_eq!(sb.ok(&["stat", "-c", "%h", "/tmp/hard"]), "2\n");
}

#[test]
fn shell_builtins_and_redirections() {
    let (_image, mut sb) = setup!();
    let script = r#"
        total=0
        for i in 1 2 3 4; do total=$((total + i)); done
        echo "sum=$total" > /tmp/out
        echo appended >> /tmp/out
        while read -r line; do echo "got:$line"; done < /tmp/out
        if [ -f /tmp/out ] && [ ! -e /tmp/none ]; then echo tests-ok; fi
        cd /data/sub && echo "pwd=$PWD"
        read -r first < /data/f
        printf '%s|%s\n' "$first" "$HOME"
        echo to-stderr >&2
        exit 3
    "#;
    let out = sb.run(&["/bin/sh", "-c", script]);
    assert_eq!(out.status, ExitStatus::Exited(3), "{out:?}");
    assert_eq!(
        out.stdout,
        "got:sum=10\ngot:appended\ntests-ok\npwd=/data/sub\nline one|/root\n"
    );
    assert_eq!(out.stderr, "to-stderr\n");
    // The file the script wrote is still there for the next command.
    assert_eq!(sb.ok(&["cat", "/tmp/out"]), "sum=10\nappended\n");
}

/// Every file under `dir`, with its contents (symlinks as their target).
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(dir).unwrap().display().to_string();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                out.insert(rel + "/", Vec::new());
                stack.push(path);
            } else if meta.is_symlink() {
                out.insert(
                    rel,
                    fs::read_link(&path)
                        .unwrap()
                        .into_os_string()
                        .into_encoded_bytes(),
                );
            } else {
                let mut data = fs::read(&path).unwrap();
                data.extend(
                    format!(
                        "@{:o}",
                        std::os::unix::fs::PermissionsExt::mode(&meta.permissions())
                    )
                    .bytes(),
                );
                out.insert(rel, data);
            }
        }
    }
    out
}

#[test]
fn writes_never_reach_the_host_image() {
    let (image, mut sb) = setup!();
    let before = snapshot(image.path());
    let out = sb.run(&[
        "/bin/sh",
        "-c",
        "echo changed > /data/f; echo new > /data/new; echo x >> /etc/passwd",
    ]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    sb.ok(&["rm", "/data/sub/inner"]);
    sb.ok(&["rmdir", "/data/sub"]);
    sb.ok(&["mkdir", "/data/dir"]);
    sb.ok(&["chmod", "600", "/etc/group"]);
    sb.ok(&["mv", "/etc/passwd", "/etc/passwd.old"]);
    sb.ok(&["ln", "-s", "x", "/bin/link"]);
    sb.ok(&["rm", "/bin/sh"]);
    // The sandbox sees its changes...
    assert_eq!(sb.ok(&["cat", "/data/f"]), "changed\n");
    assert_eq!(sb.ok(&["ls", "/data"]), "dir\nf\nnew\n");
    assert_eq!(sb.ok(&["stat", "-c", "%a", "/etc/group"]), "600\n");
    // ...the host image does not.
    assert_eq!(snapshot(image.path()), before);
}

#[test]
fn dot_dot_and_symlinks_cannot_escape_the_root() {
    let Some(busybox) = busybox() else { return };
    // base/secret.txt lives next to the image, outside it.
    let base = TempDir::new("escape");
    base.write("secret.txt", b"TOP SECRET\n");
    let root = base.path().join("image");
    let image = TempDir(root.clone());
    image.install(&busybox, "bin/busybox");
    image.symlink("busybox", "bin/sh");
    image.write("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n");
    // Image symlinks that point outside the image on the host.
    image.symlink("../secret.txt", "rel");
    image.symlink("/../../secret.txt", "abs");
    image.symlink("../../../../../../..", "up");
    let host_secret = base.path().join("secret.txt").display().to_string();
    image.symlink(&host_secret, "hostpath");
    let mut sb = Sandbox::new(&root);
    sb.ok(&["ln", "-s", "../../../../../..", "/tmp/updir"]);

    let attempts = [
        "/../secret.txt",
        "/../../../../secret.txt",
        "../secret.txt",
        "/rel",
        "/abs",
        "/up/secret.txt",
        "/hostpath",
        "/tmp/updir/secret.txt",
        "/tmp/../../secret.txt",
        host_secret.as_str(),
    ];
    for path in attempts {
        let out = sb.bb(&["cat", path]);
        assert_eq!(out.status, ExitStatus::Exited(1), "cat {path}: {out:?}");
        assert!(!out.stdout.contains("SECRET"), "cat {path}: {out:?}");
    }
    // `..` at the root is the root.
    assert_eq!(
        sb.ok(&["ls", "/../../.."]),
        "abs\nbin\ndev\netc\nhostpath\nproc\nrel\ntmp\nup\n"
    );
    assert_eq!(sb.ok(&["ls", "/up"]), sb.ok(&["ls", "/"]));
    let out = sb.run(&[
        "/bin/sh",
        "-c",
        "cd /../../..; echo $PWD; read -r l < secret.txt; echo $l",
    ]);
    assert!(!out.stdout.contains("SECRET"), "{out:?}");
    // (busybox prints "//" here on a real Linux root as well.)
    assert_eq!(sb.ok(&["readlink", "-f", "/rel"]), "//secret.txt\n");
    // Writes through escaping links stay inside, too.
    let out = sb.run(&[
        "/bin/sh",
        "-c",
        "echo pwned > /up/secret.txt; echo pwned > /rel",
    ]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert_eq!(
        fs::read(base.path().join("secret.txt")).unwrap(),
        b"TOP SECRET\n"
    );
    assert_eq!(sb.ok(&["cat", "/secret.txt"]), "pwned\n");
}

#[test]
fn writing_through_a_dangling_symlink_creates_its_target() {
    let (_image, mut sandbox) = setup!();
    sandbox.ok(&["ln", "-s", "/tmp/target", "/tmp/link"]);
    sandbox.ok(&["sh", "-c", "echo hi > /tmp/link"]);
    assert_eq!(sandbox.ok(&["cat", "/tmp/target"]), "hi\n");
    assert_eq!(sandbox.ok(&["readlink", "/tmp/link"]), "/tmp/target\n");
}

#[test]
fn removing_image_directories_leaves_the_root_usable() {
    let Some(busybox) = busybox() else { return };
    let image = image(&busybox);
    for dir in ["mnt", "media", "srv"] {
        image.mkdir(dir);
    }
    let mut sandbox = Sandbox::new(image.path());
    sandbox.ok(&["rmdir", "/mnt", "/media", "/srv"]);
    let listing = sandbox.ok(&["ls", "/"]);
    assert!(
        listing.contains("bin") && !listing.contains("mnt"),
        "{listing}"
    );
    sandbox.ok(&["touch", "/created"]);
    assert!(sandbox.ok(&["ls", "/"]).contains("created"));
}

#[test]
fn the_in_memory_layer_is_limited() {
    let Some(busybox) = busybox() else { return };
    let image = image(&busybox);
    let mut sandbox = Sandbox::new(image.path());
    sandbox.kernel.set_fs_limit(1 << 20);
    let out = sandbox.bb(&["dd", "if=/dev/zero", "of=/tmp/big", "bs=65536", "count=64"]);
    assert_ne!(out.code(), 0, "{out:?}");
    assert!(out.stderr.contains("No space left"), "{out:?}");
    // Freeing space makes room again.
    sandbox.ok(&["rm", "/tmp/big"]);
    sandbox.ok(&["dd", "if=/dev/zero", "of=/tmp/small", "bs=65536", "count=4"]);
}

#[test]
fn timeout_stops_a_program_that_spins() {
    let Some(busybox) = busybox() else { return };
    let image = image(&busybox);
    let started = std::time::Instant::now();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hellovm"))
        .args(["--timeout", "0.5", "--root"])
        .arg(image.path())
        .args(["/bin/busybox", "sh", "-c", "while :; do :; done"])
        .output()
        .expect("run hellovm");
    assert_eq!(output.status.code(), Some(124), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("timed out"), "{stderr}");
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
}
