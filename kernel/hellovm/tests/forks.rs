//! Processes end to end, with a glibc program (`test-guest/c/forks.c`):
//! fork and copy-on-write, shared memory, exec, vfork, posix_spawn, a
//! child that never makes a system call, and a fork bomb. The HVF
//! platform's tests (`platform-hvf/tests/guests.rs`) expect the same
//! lines.

#![cfg(target_os = "linux")]

mod common;

use common::{run, TempDir};
use hellovm_core::ExitStatus;
use hellovm_test_guest as guest;

#[test]
fn fork_exec_vfork_and_copy_on_write() {
    if !common::require_guest(guest::FORKS, "forks") {
        return;
    }
    let image = TempDir::new("forks");
    image.install(guest::FORKS, "forks");
    let out = run(image.path(), &["/forks"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    let expected = [
        "fork: child exited 42",
        "cow: parent-saw=1ppp child-kept-its-own=yes",
        "shared: parent-sees=CD private-untouched=0",
        "shared: child-sees=P",
        "zero: child=ok parent=kept",
        "big shared: child 0, parent-sees=Sp",
        "exec: child forked",
        "fork+exec: status 7",
        "exec: child vforked",
        "vfork+exec: status 7",
        "vfork+_exit: status 5",
        "exec: child spawned",
        "posix_spawn: status 7",
        "fork of fork: 13, parent still 10",
        "big: 64 MiB child=ok parent=ok",
        "wait: 5 children, sum 15",
        "pipe: writer 0 reader 0",
        "busy child: parent ran, child ended by 9",
    ];
    let lines: Vec<_> = out.stdout.lines().collect();
    assert_eq!(lines, expected, "{out:?}");
}

/// The core's limit on processes stops the bomb: forks fail with
/// `EAGAIN`, everything ends and is reaped.
#[test]
fn a_fork_bomb_ends() {
    if !common::require_guest(guest::FORKS, "forks") {
        return;
    }
    let image = TempDir::new("forks-bomb");
    image.install(guest::FORKS, "forks");
    let out = run(image.path(), &["/forks", "bomb", "60"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    assert_eq!(
        out.stdout, "bomb: ended, forks failed: yes, other errors: 0\n",
        "{out:?}"
    );
}
