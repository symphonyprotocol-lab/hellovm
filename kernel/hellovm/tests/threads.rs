//! Threads end to end, with a glibc program (`test-guest/c/threads.c`).

#![cfg(target_os = "linux")]

mod common;

use common::{run, TempDir};
use hellovm_core::ExitStatus;
use hellovm_test_guest as guest;

#[test]
fn pthreads_work() {
    if !common::require_guest(guest::THREADS, "threads") {
        return;
    }
    let image = TempDir::new("threads");
    image.install(guest::THREADS, "threads");
    let out = run(image.path(), &["/threads"]);
    let expected = [
        "join: counter=16000 tls-sum=288 distinct-tids=1",
        "broadcast: all woke",
        "timedwait: timed out",
        "pthread_kill: pending-while-blocked=1 handled-by-target=1",
        "robust: owner died",
        "fork: child-threads=1",
    ];
    let lines: Vec<_> = out.stdout.lines().collect();
    assert_eq!(lines, expected, "{out:?}");
    // exit() in a thread ended the process, with its main thread parked in
    // pause().
    assert_eq!(out.status, ExitStatus::Exited(7));
}
