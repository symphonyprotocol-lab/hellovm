//! The seccomp platform: runs a Linux app as a traced child process of the
//! kernel process and traps every one of its syscalls with seccomp.
//!
//! Every app thread is a host process. Without the fast path below, the
//! app's filter returns `SECCOMP_RET_TRACE` for *every* syscall of its
//! native architecture and kills it on any other syscall ABI (i386 `int
//! 0x80`, 32-bit arm). Each syscall stops the app for the kernel's
//! event-loop thread, the ptrace tracer of all of a sandbox's app
//! processes, which emulates it and skips it. The tracer also changes address spaces and creates processes by
//! injecting `mmap`, `munmap`, `mprotect` and `clone` through a trusted
//! stub page; see `spawn` for the mechanism, the reasoning, the safety
//! argument with many threads and processes, and the residual host-syscall
//! surface, and `wake` for how the event loop waits.
//!
//! The fast path: most syscalls do not stop the app for ptrace at all.
//! The filter sends them to the kernel process as seccomp user
//! notifications (`filter::notify`), which the event loop receives and the
//! core answers with the emulated result; the syscall never runs on the
//! host. Only syscalls whose emulation changes registers or the address
//! space, and the injected ones, still stop for the tracer; a notified
//! task the core needs in a ptrace stop after all is converted (see
//! `app`). `HELLOVM_SECCOMP_NOTIF=0` turns the fast path off.
//!
//! Linux only; on other hosts this crate is empty.

#![cfg(target_os = "linux")]

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the seccomp platform supports x86_64 and aarch64 hosts only");

mod app;
mod filter;
mod notify;
mod profile;
mod regs;
mod snapshot;
mod spawn;
mod stub;
mod sys;
mod tracer;
mod wake;

pub use app::{check_clean_spawn, AppKiller, SeccompPlatform};
pub use profile::{host_profile, HostProfile};
