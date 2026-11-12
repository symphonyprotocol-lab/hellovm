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
//! The core owns the app's state: its memory map ([`mm`]), the executable
//! loader ([`elf`]), the filesystem ([`vfs`]) and the fd table ([`fd`]).
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
pub mod platform;
mod syscall;
#[cfg(test)]
mod testutil;
pub mod vfs;

pub use arch::{Arch, Sysno};
pub use kernel::{ExitStatus, Kernel, KernelError, Outcome, SyscallRecord};
