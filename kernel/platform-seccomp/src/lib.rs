//! The seccomp platform: runs a Linux app as a traced child process of the
//! kernel process and traps every one of its syscalls with seccomp.
//!
//! The app's filter returns `SECCOMP_RET_TRACE` for *every* syscall of its
//! native architecture and kills it on any other syscall ABI (i386
//! `int 0x80`, 32-bit arm). Each syscall stops the app for the kernel
//! process, its ptrace tracer, which emulates it and skips it. The tracer
//! also changes the app's address space by injecting `mmap`, `munmap` and
//! `mprotect` through a trusted stub page; see `spawn` for the mechanism,
//! the reasoning and the residual host-syscall surface. A faster
//! signal-based trap with shared memory is planned.
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

pub use app::{AppKiller, SeccompApp};
