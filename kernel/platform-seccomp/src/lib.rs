//! The seccomp platform: runs a Linux app as a child process of the kernel
//! process and traps every one of its syscalls with seccomp.
//!
//! This first version uses seccomp user notification: each app syscall
//! blocks the app and wakes the kernel process, which reads the arguments
//! (and app memory, with `process_vm_readv`) and sends the result back. That
//! costs two context switches per syscall; a faster signal-based trap with
//! shared memory is planned.
//!
//! The filter sends *every* syscall of the app's native architecture to the
//! kernel and kills the app on any other syscall ABI (i386 `int 0x80`,
//! 32-bit arm). The only syscall ever allowed to run on the host is the
//! bootstrap `execve`, see [`spawn`](crate::SeccompApp::spawn).
//!
//! Linux only; on other hosts this crate is empty.

#![cfg(target_os = "linux")]

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the seccomp platform supports x86_64 and aarch64 hosts only");

mod app;
mod filter;
mod notify;
mod spawn;
mod sys;

pub use app::SeccompApp;
