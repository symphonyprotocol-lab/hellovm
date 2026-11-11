//! The platform layer interface.
//!
//! A platform answers three questions for the kernel core: how app code runs,
//! how its syscalls are intercepted, and how its address space is managed.
//! The core drives an app with a loop of [`Platform::run`] calls, each of
//! which resumes the app until it traps again.
//!
//! The core owns every decision about the app's address space: it keeps the
//! map of memory areas, picks addresses and loads ELF images. A platform only
//! carries out the resulting page-level operations ([`AddressSpace`]) and
//! copies bytes in and out ([`AppMemory`]). This is the same split whether
//! the host kernel manages the page tables (seccomp) or cansol does (KVM,
//! Hypervisor.framework).
//!
//! The interface models one app thread; threads come with milestone U2.

use std::fmt;
use std::ops::Range;

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
    /// ...) or received a host signal, reported as the Linux signal it maps
    /// to.
    Fault(Fault),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// Linux signal number (e.g. 11 for `SIGSEGV`).
    pub signal: u32,
    /// The faulting address, when the platform knows it.
    pub addr: Option<GuestAddr>,
    /// Whether the app is gone and cannot be resumed.
    pub fatal: bool,
}

/// How to resume the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// First run: start at `entry` with the stack pointer at `stack` and
    /// every other general-purpose register zero.
    Start { entry: GuestAddr, stack: GuestAddr },
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
    /// The app did something the platform cannot allow; it has been killed.
    Violation(String),
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
            PlatformError::Violation(why) => write!(f, "app killed: {why}"),
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
///
/// Accesses follow the app's page protections only as far as the platform
/// enforces them; the core must not rely on writes to read-only pages
/// failing or succeeding.
pub trait AppMemory {
    /// Fills `buf` from guest memory at `addr`. Fails unless all of it could
    /// be read.
    fn read(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), PlatformError>;

    /// Writes `data` to guest memory at `addr`. Fails unless all of it could
    /// be written. Pages must be writable.
    fn write(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError>;
}

/// Page protection bits, with Linux `PROT_*` values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Prot(pub u32);

impl Prot {
    pub const NONE: Prot = Prot(0);
    pub const READ: Prot = Prot(1);
    pub const WRITE: Prot = Prot(2);
    pub const EXEC: Prot = Prot(4);
    pub const RW: Prot = Prot(3);
    pub const ALL: Prot = Prot(7);

    pub const fn contains(self, other: Prot) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Prot) -> Prot {
        Prot(self.0 | other.0)
    }
}

impl fmt::Display for Prot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flag = |bit: Prot, c: char| if self.contains(bit) { c } else { '-' };
        write!(
            f,
            "{}{}{}",
            flag(Prot::READ, 'r'),
            flag(Prot::WRITE, 'w'),
            flag(Prot::EXEC, 'x')
        )
    }
}

/// The shape of the app's address space, fixed for the app's lifetime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressSpaceInfo {
    /// The page size; every address and length passed to [`AddressSpace`]
    /// is a multiple of it. Also reported to the guest as `AT_PAGESZ`.
    pub page_size: u64,
    /// Lowest address the core may map.
    pub min_addr: GuestAddr,
    /// One past the highest address the core may map.
    pub max_addr: GuestAddr,
    /// Page-aligned ranges inside `min_addr..max_addr` the platform uses
    /// itself. The core never maps, unmaps or re-protects them.
    pub reserved: Vec<Range<GuestAddr>>,
}

/// Changes to the app's address space. Every address and length is a
/// multiple of the page size and lies outside the reserved ranges.
pub trait AddressSpace {
    /// Maps zero-filled private memory at a fixed address, replacing
    /// whatever was mapped there.
    fn map(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), PlatformError>;
    /// Unmaps a range; parts that are not mapped are ignored.
    fn unmap(&mut self, addr: GuestAddr, len: u64) -> Result<(), PlatformError>;
    /// Changes the protection of a fully mapped range.
    fn protect(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), PlatformError>;
}

/// What the guest is told about the CPU it runs on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuInfo {
    /// `AT_HWCAP` and `AT_HWCAP2` for the initial auxiliary vector.
    pub hwcap: u64,
    pub hwcap2: u64,
}

/// One running app (a single thread and its address space, for now).
pub trait Platform: AppMemory + AddressSpace {
    /// The syscall ABI of the app.
    fn arch(&self) -> Arch;

    /// The address space the core may lay out. It starts out empty apart
    /// from the reserved ranges.
    fn address_space(&self) -> AddressSpaceInfo;

    /// CPU features the guest may use.
    fn cpu_info(&self) -> CpuInfo;

    /// Sets the thread pointer register for the next resume (x86_64
    /// `arch_prctl(ARCH_SET_FS)`; aarch64 apps set `tpidr_el0` themselves).
    fn set_thread_pointer(&mut self, value: u64) -> Result<(), PlatformError>;

    /// Resumes the app and runs it until it traps.
    fn run(&mut self, resume: Resume) -> Result<Trap, PlatformError>;

    /// Stops the app for good. Used when the kernel emulates its exit.
    fn terminate(&mut self) -> Result<(), PlatformError>;
}
