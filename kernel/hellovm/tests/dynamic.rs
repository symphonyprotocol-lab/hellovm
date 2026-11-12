//! Dynamically linked programs and `/proc`.
//!
//! The dynamic guest (`test-guest/c/dynamic.c`) is linked against the build
//! host's glibc and runs in an image assembled from the host's own
//! libraries: the kernel loads it and the program interpreter named by its
//! `PT_INTERP`, which then maps libc with file-backed `mmap`.

#![cfg(target_os = "linux")]

mod common;

use std::path::Path;

use common::{run, Sandbox, TempDir};
use hellovm_core::ExitStatus;
use hellovm_test_guest as guest;

#[test]
fn a_dynamically_linked_program_runs() {
    if !common::require_guest(guest::DYNAMIC, "dynamic") {
        return;
    }
    let image = TempDir::new("dynamic");
    image.install_with_libs(Path::new(guest::DYNAMIC));
    let guest_path = guest::DYNAMIC;
    let out = run(image.path(), &[guest_path, "hello"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert_eq!(
        out.stdout,
        format!("dynamic: arg=hello sqrt2=1.4142 interp=yes exe={guest_path}\n")
    );
    // Without the interpreter in the image, exec fails cleanly.
    let image = TempDir::new("dynamic-no-interp");
    image.copy_host_file(Path::new(guest::DYNAMIC));
    match common::try_run(image.path(), &[guest_path], b"") {
        Err(hellovm_core::KernelError::Exec { errno, .. }) => assert_eq!(errno.0, 2),
        other => panic!("{other:?}"),
    }
}

#[test]
fn proc_shows_the_sandbox_processes() {
    let Some(path) = common::require_busybox("dynamic test") else {
        return;
    };
    let image = TempDir::new("proc");
    image.install(&path, "bin/busybox");
    for applet in [
        "sh", "ps", "cat", "readlink", "ls", "sleep", "head", "grep", "wc",
    ] {
        image.symlink("busybox", &format!("bin/{applet}"));
    }
    image.write("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n");
    let mut sb = Sandbox::new(image.path());
    let sh = |sb: &mut Sandbox, script: &str| {
        let out = sb.run(&["/bin/sh", "-c", script]);
        assert_eq!(out.status, ExitStatus::Exited(0), "{script}: {out:?}");
        out.stdout
    };
    // (busybox runs some applets inside the shell, without exec: the exe
    // of `sh -c readlink` is /bin/sh.)
    assert_eq!(sh(&mut sb, "readlink /proc/self/exe"), "/bin/sh\n");
    let out = sb.run(&["/bin/readlink", "/proc/self/exe"]);
    assert_eq!(out.stdout, "/bin/readlink\n");
    assert_eq!(sh(&mut sb, "cat /proc/self/comm"), "cat\n");
    assert_eq!(sh(&mut sb, "cd /tmp && readlink /proc/self/cwd"), "/tmp\n");
    // The shell is pid 1, its children follow.
    // (A lone command is exec'd by `sh -c`; `; true` keeps the shell.)
    let stat = sh(&mut sb, "cat /proc/1/stat; true");
    assert!(stat.starts_with("1 (sh) "), "{stat}");
    let ps = sh(&mut sb, "sleep 2 & ps");
    let lines: Vec<_> = ps.lines().collect();
    assert!(lines[0].starts_with("PID"), "{ps}");
    assert!(lines.iter().any(|l| l.contains("sleep 2")), "{ps}");
    assert!(
        lines.iter().any(|l| l.trim_start().starts_with("1 root")),
        "{ps}"
    );
    // Open fds, maps and global files.
    // As on Linux, ls also sees the fd it reads the directory with.
    let fds = sh(&mut sb, "ls /proc/self/fd 3</etc/passwd");
    assert_eq!(fds, "0\n1\n2\n3\n4\n");
    let link = sh(&mut sb, "readlink /proc/self/fd/3 3</etc/passwd");
    assert_eq!(link, "/etc/passwd\n");
    let maps = sh(&mut sb, "cat /proc/self/maps");
    assert!(
        maps.contains("[stack]") && maps.contains("/bin/cat"),
        "{maps}"
    );
    let meminfo = sh(&mut sb, "head -1 /proc/meminfo");
    assert!(meminfo.starts_with("MemTotal:"), "{meminfo}");
    assert!(sh(&mut sb, "ls /").contains("proc\n"));
    // /proc is read-only.
    let out = sb.run(&["/bin/sh", "-c", "echo x > /proc/self/comm"]);
    assert_ne!(out.status, ExitStatus::Exited(0));
}
