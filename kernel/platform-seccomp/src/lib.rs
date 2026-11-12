//! The seccomp platform: runs a Linux app as a traced child process of the
//! kernel process and traps every one of its syscalls with seccomp.
//!
//! Every app thread is a host process. The app's filter returns
//! `SECCOMP_RET_TRACE` for *every* syscall of its native architecture and
//! kills it on any other syscall ABI (i386 `int 0x80`, 32-bit arm). Each
//! syscall stops the app for the kernel's event-loop thread, the ptrace
//! tracer of all of a sandbox's app processes, which emulates it and skips
//! it. The tracer also changes address spaces and creates processes by
//! injecting `mmap`, `munmap`, `mprotect` and `clone` through a trusted
//! stub page; see `spawn` for the mechanism, the reasoning, the safety
//! argument with many threads and processes, and the residual host-syscall
//! surface, and `wake` for how the event loop waits. A faster signal-based
//! trap with shared memory is planned.
//!
//! Linux only; on other hosts this crate is empty.

#![cfg(target_os = "linux")]

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the seccomp platform supports x86_64 and aarch64 hosts only");

mod app;
mod filter;
mod regs;
mod spawn;
mod stub;
mod sys;
mod tracer;
mod wake;

pub use app::{AppKiller, SeccompPlatform};
