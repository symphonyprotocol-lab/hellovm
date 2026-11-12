//! Signal delivery end to end, with a glibc program (`test-guest/c/signals.c`)
//! that handles faults, timers and interrupted syscalls itself.

#![cfg(target_os = "linux")]

mod common;

use common::{run, TempDir};
use hellovm_core::ExitStatus;
use hellovm_test_guest as guest;

#[test]
fn signals_reach_handlers_with_correct_frames() {
    if guest::SIGNALS.is_empty() {
        eprintln!("skipping: the signals guest is not built when cross-compiling");
        return;
    }
    let image = TempDir::new("signals");
    image.install(guest::SIGNALS, "signals");
    let out = run(image.path(), &["/signals"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
    let expected = [
        "segv: caught at 0x10",
        "raise: 10",
        "blocked: pending=1 got=0",
        "unblocked: got=10",
        "alarm: 14",
        "sigsuspend: -1 Interrupted system call got=10 still-blocked=1",
        "altstack: 1",
        "ticks: ok fp: ok",
        "read restart: 1 data",
        "read eintr: -1 Interrupted system call",
        "child term: signaled=1 sig=15 core=0",
        "child segv: signaled=1 sig=11 core=1",
        "stopped: 1 sig=19",
        "continued and exited: 5 sigchld=1",
    ];
    let lines: Vec<_> = out.stdout.lines().collect();
    assert_eq!(lines, expected, "stderr: {}", out.stderr);
}
