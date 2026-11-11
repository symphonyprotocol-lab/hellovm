//! The cansol kernel core.
//!
//! This crate implements Linux syscall semantics for a sandboxed program. It
//! is deliberately independent of the machine it runs on: everything it needs
//! from the outside world goes through two small trait families.
//!
//! * [`platform`]: how app code runs, how its syscalls are trapped and how
//!   its memory is accessed (seccomp, later KVM and Hypervisor.framework).
//! * [`host`]: the services of the host OS the kernel itself uses (console
//!   output today; files, sockets, memory, time and threads later).
//!
//! Syscalls are always *emulated*, never forwarded to the host kernel: the
//! host may be macOS, which has no Linux syscalls at all.

#![forbid(unsafe_code)]

pub mod arch;
pub mod errno;
pub mod host;
mod kernel;
pub mod platform;
mod syscall;

pub use arch::{Arch, Sysno};
pub use kernel::{ExitStatus, Kernel, KernelError, Outcome, SyscallRecord};
