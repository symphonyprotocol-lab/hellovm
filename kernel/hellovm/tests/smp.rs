//! Threads that run at the same time (`test-guest/c/smp.c`): on the
//! seccomp platform every thread is a host process of its own, so they
//! always do. The same lines as on the HVF platform
//! (`platform-hvf/tests/guests.rs`).

#![cfg(target_os = "linux")]

mod common;

use common::{run, TempDir};
use hellovm_core::ExitStatus;
use hellovm_test_guest as guest;

#[test]
fn threads_in_parallel() {
    if !common::require_guest(guest::SMP, "smp") {
        return;
    }
    let image = TempDir::new("smp");
    image.install(guest::SMP, "smp");
    let out = run(image.path(), &["/smp", "all"]);
    let lines: Vec<_> = out.stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "fork-while-writing: ok",
            "mprotect-while-writing: ok rounds=20",
            "munmap-while-writing: ok rounds=20",
            "cow-concurrent-writers: ok rounds=10",
            "futex-ping-pong: ok rounds=20000",
            "signal-to-running-thread: ok rounds=20",
            "syscalls-next-to-spinners: ok",
        ],
        "{out:?}"
    );
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    for (check, status, line) in [
        ("exit-group", 7, "exit-group: exiting"),
        (
            "exit-group-from-thread",
            8,
            "exit-group-from-thread: exiting",
        ),
        ("exec", 0, "exec-while-spinning: ok"),
    ] {
        let out = run(image.path(), &["/smp", check]);
        let lines: Vec<_> = out.stdout.lines().collect();
        assert_eq!(lines, [line], "{out:?}");
        assert_eq!(out.status, ExitStatus::Exited(status), "{out:?}");
    }
    let out = run(image.path(), &["/smp", "scale", "4", "1000000"]);
    assert!(
        out.stdout
            .starts_with("scale: threads=4 sum=afd9208ee957921b ms="),
        "{out:?}"
    );
}
