//! End-to-end tests: the tiny test guests under the seccomp platform.
//!
//! The kernel loads each guest from an image directory itself (there is no
//! host `execve` of the guest), and every syscall it makes is trapped, so
//! the only way its output can appear anywhere is through the kernel. The
//! tests check that directly: output shows up in an in-memory host, and the
//! syscall trace shows each call handled by the kernel.

#![cfg(target_os = "linux")]

mod common;

use std::process::Command;

use common::{run, try_run, TempDir};
use hellovm_core::{ExitStatus, KernelError, Outcome, Sysno};
use hellovm_test_guest as guest;

fn image_with(guest_path: &str, name: &str) -> TempDir {
    let image = TempDir::new(name);
    image.install(guest_path, name);
    image
}

#[test]
fn hello_world_output_goes_through_the_kernel() {
    let image = image_with(guest::HELLO, "hello");
    let out = run(image.path(), &["/hello"]);

    assert_eq!(out.status, ExitStatus::Exited(guest::HELLO_EXIT_CODE));
    assert_eq!(out.stdout, guest::HELLO_STDOUT);
    assert_eq!(out.stderr, guest::HELLO_STDERR);
    let trace: Vec<_> = out
        .kernel
        .trace()
        .iter()
        .map(|r| (r.sysno, r.args[0], r.outcome))
        .collect();
    assert_eq!(
        trace,
        vec![
            (
                Some(Sysno::Write),
                1,
                Outcome::Returned(guest::HELLO_STDOUT.len() as i64)
            ),
            (
                Some(Sysno::Write),
                2,
                Outcome::Returned(guest::HELLO_STDERR.len() as i64)
            ),
            (
                Some(Sysno::ExitGroup),
                guest::HELLO_EXIT_CODE as u64,
                Outcome::Ended
            ),
        ]
    );
}

#[test]
fn syscalls_are_emulated_not_forwarded() {
    let image = image_with(guest::ENOSYS, "enosys");
    // The guest exits with the negated getpid result: the sandbox pid 1, not
    // the host pid of the app process.
    let out = run(image.path(), &["/enosys"]);
    let trace = out.kernel.trace();
    assert_eq!(trace.len(), 2);
    assert_eq!(trace[0].sysno, Some(Sysno::Getpid));
    assert_eq!(trace[0].outcome, Outcome::Returned(1));
    // exit_group(-1) has status 255.
    assert_eq!(out.status, ExitStatus::Exited(255));
}

#[test]
fn missing_and_unsupported_programs_fail_to_start() {
    let image = image_with(guest::HELLO, "hello");
    image.write("script", b"#!/bin/sh\necho hi\n");
    std::fs::set_permissions(
        image.path().join("script"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    image.write("data", b"not a program");
    std::fs::set_permissions(
        image.path().join("data"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    // The script's interpreter, /bin/sh, does not exist in this image.
    for (path, errno) in [("/nonexistent", 2), ("/script", 2), ("/data", 8), ("/", 13)] {
        match try_run(image.path(), &[path], b"") {
            Err(KernelError::Exec { errno: e, .. }) => assert_eq!(e.0, errno, "{path}"),
            other => panic!("{path}: {other:?}"),
        }
    }
}

#[test]
fn static_pie_with_glibc() {
    if guest::PIE.is_empty() {
        eprintln!("skipping: the static-PIE guest is not built when cross-compiling");
        return;
    }
    let image = image_with(guest::PIE, "pie");
    let out = run(image.path(), &["/pie", "arg"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stderr);
    let line = out.stdout.trim_end();
    let main: u64 = u64::from_str_radix(
        line.split_whitespace()
            .next()
            .unwrap()
            .trim_start_matches("main=0x"),
        16,
    )
    .unwrap();
    assert!(main > 0x1_0000_0000, "relocated to a high base: {line}");
    assert!(
        line.ends_with("argc=2 argv1=arg tls=42 big=x small pagesz=4096 random=yes")
            || line.contains("argc=2 argv1=arg tls=42 big=x small pagesz="),
        "{line}"
    );
    // The big allocation was an mmap, freed with munmap.
    let calls: Vec<_> = out.kernel.trace().iter().filter_map(|r| r.sysno).collect();
    assert!(calls.contains(&Sysno::Mmap), "{calls:?}");
    assert!(calls.contains(&Sysno::Munmap), "{calls:?}");
}

#[test]
fn many_apps_in_parallel() {
    let image = image_with(guest::HELLO, "hello");
    let root = image.path().to_path_buf();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let root = root.clone();
            std::thread::spawn(move || {
                let out = run(&root, &["/hello"]);
                (out.status, out.stdout)
            })
        })
        .collect();
    for handle in handles {
        let (status, stdout) = handle.join().unwrap();
        assert_eq!(status, ExitStatus::Exited(guest::HELLO_EXIT_CODE));
        assert_eq!(stdout, guest::HELLO_STDOUT);
    }
}

#[test]
fn cli_prints_output_and_propagates_the_exit_code() {
    let image = image_with(guest::HELLO, "hello");
    let output = Command::new(env!("CARGO_BIN_EXE_hellovm"))
        .arg("--trace")
        .arg("--root")
        .arg(image.path())
        .arg("/hello")
        .output()
        .expect("run hellovm");

    assert_eq!(output.status.code(), Some(guest::HELLO_EXIT_CODE));
    assert_eq!(String::from_utf8_lossy(&output.stdout), guest::HELLO_STDOUT);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with(guest::HELLO_STDERR), "{stderr}");
    assert!(stderr.contains("hellovm: trace: write(1, "), "{stderr}");
    assert!(
        stderr.contains("hellovm: trace: exit_group(42) = ?"),
        "{stderr}"
    );
}

#[test]
fn cli_reports_programs_that_cannot_start() {
    let image = TempDir::new("empty");
    let output = Command::new(env!("CARGO_BIN_EXE_hellovm"))
        .arg("--root")
        .arg(image.path())
        .arg("/bin/missing")
        .output()
        .expect("run hellovm");
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("/bin/missing: no such file"), "{stderr}");
}
