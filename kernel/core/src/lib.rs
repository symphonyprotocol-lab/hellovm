//! The hellovm kernel core.
//!
//! This crate implements Linux syscall semantics for a sandboxed program. It
//! is deliberately independent of the machine it runs on: everything it needs
//! from the outside world goes through two small trait families.
//!
//! * [`platform`]: how app code runs, how its syscalls are trapped and how
//!   its address space is changed (seccomp, later KVM and
//!   Hypervisor.framework).
//! * [`host`]: the services of the host OS the kernel itself uses (console,
//!   the read-only image, random bytes, clocks).
//!
//! The core owns the sandbox's state: processes and threads (`task`),
//! memory maps ([`mm`]), the executable loader ([`elf`]), the filesystem
//! ([`vfs`]), fd tables and open files ([`fd`]), pipes, signals
//! ([`signal`]) and the console (`tty`). The kernel serves all of a
//! sandbox's threads from one event loop (`kernel`), parking syscalls that
//! have to wait instead of blocking.
//! Syscalls are always *emulated*, never forwarded to the host kernel: the
//! host may be macOS, which has no Linux syscalls at all.

#![forbid(unsafe_code)]

pub mod abi;
pub mod arch;
pub mod elf;
pub mod errno;
pub mod fd;
pub mod host;
mod kernel;
pub mod mm;
mod pipe;
pub mod platform;
pub mod signal;
mod syscall;
mod task;
#[cfg(test)]
mod testutil;
mod tty;
pub mod vfs;

pub use arch::{Arch, Sysno};
pub use kernel::{ConsoleMode, ExitStatus, Kernel, KernelError, Outcome, SyscallRecord};
