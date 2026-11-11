//! End-to-end tests: real guest programs under the seccomp platform.
//!
//! The app process starts with no host fds at all and every syscall it makes
//! is trapped, so the only way its output can appear anywhere is through the
//! kernel process. The tests check that directly: the output shows up in an
//! in-memory host, and the syscall trace shows each call handled by the
//! kernel.

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use cansol_core::{ExitStatus, Kernel, Outcome, Sysno};
use cansol_host::CaptureHost;
use cansol_platform_seccomp::SeccompApp;
use cansol_test_guest as guest;

fn spawn(program: &str) -> SeccompApp {
    SeccompApp::spawn(Path::new(program), &[OsString::from(program)]).expect("spawn guest")
}

#[test]
fn hello_world_output_goes_through_the_kernel() {
    let mut app = spawn(guest::HELLO);
    let mut kernel = Kernel::new(CaptureHost::default()).with_trace();

    let status = kernel.run(&mut app).expect("run guest");

    assert_eq!(status, ExitStatus::Exited(guest::HELLO_EXIT_CODE));
    let host = kernel.host();
    assert_eq!(String::from_utf8_lossy(&host.stdout), guest::HELLO_STDOUT);
    assert_eq!(String::from_utf8_lossy(&host.stderr), guest::HELLO_STDERR);

    let trace: Vec<_> = kernel
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
                Outcome::Exited(guest::HELLO_EXIT_CODE)
            ),
        ]
    );
}

#[test]
fn other_syscalls_are_refused_not_forwarded() {
    let mut app = spawn(guest::ENOSYS);
    let mut kernel = Kernel::new(CaptureHost::default()).with_trace();

    let status = kernel.run(&mut app).expect("run guest");

    // A forwarded getpid would have returned the app's pid instead.
    assert_eq!(status, ExitStatus::Exited(38));
    let trace = kernel.trace();
    assert_eq!(trace.len(), 2);
    assert_eq!(trace[0].sysno, Some(Sysno::Getpid));
    assert_eq!(trace[0].outcome, Outcome::Returned(-38));
    assert_eq!(trace[1].sysno, Some(Sysno::ExitGroup));
}

#[test]
fn spawning_a_missing_program_fails() {
    let err = SeccompApp::spawn(
        Path::new("/nonexistent/cansol-guest"),
        &[OsString::from("guest")],
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
}

#[test]
fn many_apps_in_parallel() {
    let handles: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                let mut app = spawn(guest::HELLO);
                let mut kernel = Kernel::new(CaptureHost::default());
                let status = kernel.run(&mut app).unwrap();
                (status, kernel.into_host().stdout)
            })
        })
        .collect();
    for handle in handles {
        let (status, stdout) = handle.join().unwrap();
        assert_eq!(status, ExitStatus::Exited(guest::HELLO_EXIT_CODE));
        assert_eq!(stdout, guest::HELLO_STDOUT.as_bytes());
    }
}

#[test]
fn cli_prints_output_and_propagates_the_exit_code() {
    let output = Command::new(env!("CARGO_BIN_EXE_cansol"))
        .args(["--trace", guest::HELLO])
        .output()
        .expect("run cansol");

    assert_eq!(output.status.code(), Some(guest::HELLO_EXIT_CODE));
    assert_eq!(String::from_utf8_lossy(&output.stdout), guest::HELLO_STDOUT);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with(guest::HELLO_STDERR), "{stderr}");
    assert!(stderr.contains("cansol: trace: write(1, "), "{stderr}");
    assert!(
        stderr.contains("cansol: trace: exit_group(42) = ?"),
        "{stderr}"
    );
}

#[test]
fn cli_reports_refused_syscalls() {
    let output = Command::new(env!("CARGO_BIN_EXE_cansol"))
        .arg(guest::ENOSYS)
        .output()
        .expect("run cansol");

    assert_eq!(output.status.code(), Some(38));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unimplemented syscall") && stderr.contains("(getpid)"),
        "{stderr}"
    );
}
