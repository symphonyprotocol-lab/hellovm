//! The platform layer interface.
//!
//! A platform answers three questions for the kernel core: how app code runs,
//! how its syscalls are intercepted, and how its address space is managed.
//! The core drives an app with a loop of [`Platform::run`] calls, each of
//! which resumes the app until it traps again.
//!
//! This is a first cut for milestone U0: one app thread, and address-space
//! operations that platforms may leave unimplemented. It will be revised in
//! U1 (ELF loading, memory management) and U2 (threads).

use std::fmt;

use crate::arch::Arch;

/// An address in the app's address space.
pub type GuestAddr = u64;

/// A syscall made by the app, as raw register values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallTrap {
    /// The raw syscall number, in the numbering of [`Platform::arch`].
    pub nr: u64,
    pub args: [u64; 6],
}

/// Why the app stopped running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trap {
    /// The app made a syscall. It stays stopped until the next
    /// [`Platform::run`] delivers the result.
    Syscall(SyscallTrap),
    /// The app hit a CPU exception (bad memory access, illegal instruction,
    /// ...), reported as the Linux signal it maps to.
    Fault(Fault),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// Linux signal number (e.g. 11 for `SIGSEGV`).
    pub signal: u32,
    /// Whether the app is gone and cannot be resumed. Platforms that only
    /// observe faults after the fact (seccomp user notification) set this.
    pub fatal: bool,
}

/// How to resume the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// First run: start the app at its entry point.
    Start,
    /// Complete the pending syscall with this return value (`-errno` for
    /// errors, as the guest sees it).
    Return(i64),
}

#[derive(Debug)]
pub enum PlatformError {
    /// The platform does not implement this operation.
    Unsupported(&'static str),
    /// Guest memory at this range could not be accessed.
    BadAddress { addr: GuestAddr, len: usize },
    /// The app disappeared without the kernel ending it.
    AppGone(String),
    /// A host call made by the platform failed.
    Host(std::io::Error),
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformError::Unsupported(what) => write!(f, "unsupported by this platform: {what}"),
            PlatformError::BadAddress { addr, len } => {
                write!(f, "bad guest address {addr:#x} (+{len})")
            }
            PlatformError::AppGone(why) => write!(f, "app is gone: {why}"),
            PlatformError::Host(err) => write!(f, "host error: {err}"),
        }
    }
}

impl std::error::Error for PlatformError {}

impl From<std::io::Error> for PlatformError {
    fn from(err: std::io::Error) -> Self {
        PlatformError::Host(err)
    }
}

/// Access to the app's memory.
pub trait AppMemory {
    /// Fills `buf` from guest memory at `addr`. Fails unless all of it could
    /// be read.
    fn read(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), PlatformError>;

    /// Writes `data` to guest memory at `addr`. Fails unless all of it could
    /// be written.
    fn write(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError>;
}

/// Page protection bits, with Linux `PROT_*` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prot(pub u32);

impl Prot {
    pub const NONE: Prot = Prot(0);
    pub const READ: Prot = Prot(1);
    pub const WRITE: Prot = Prot(2);
    pub const EXEC: Prot = Prot(4);
}

/// Changes to the app's address space.
pub trait AddressSpace {
    /// Maps zeroed anonymous memory at a fixed, page-aligned address.
    fn map(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), PlatformError>;
    fn unmap(&mut self, addr: GuestAddr, len: u64) -> Result<(), PlatformError>;
    fn protect(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), PlatformError>;
}

/// One running app (a single thread and its address space, for now).
pub trait Platform: AppMemory + AddressSpace {
    /// The syscall ABI of the app.
    fn arch(&self) -> Arch;

    /// Resumes the app and runs it until it traps.
    fn run(&mut self, resume: Resume) -> Result<Trap, PlatformError>;

    /// Stops the app for good. Used when the kernel emulates its exit.
    fn terminate(&mut self) -> Result<(), PlatformError>;
}
