//! The platform layer interface.
//!
//! A platform answers three questions for the kernel core: how app code runs,
//! how its syscalls and faults are intercepted, and how its address spaces
//! are managed. One [`Platform`] value serves one sandbox: every thread of
//! every process in it is a *task* of that platform, named by a
//! [`TaskKey`].
//!
//! # Tasks and address spaces
//!
//! A task is one app thread: a register context bound to an address space.
//! [`Platform::spawn`] creates a task with a fresh, empty address space (for
//! the first process and for every `execve`); [`Platform::clone_task`]
//! creates a task that is a copy of a stopped task, with either a copy of its
//! address space (`fork`) or the same one (threads, `vfork`). The core keeps
//! all process semantics (pids, thread groups, fd tables, signals) to
//! itself: to the platform, a process is just the set of tasks that share an
//! address space.
//!
//! The core owns every decision about an address space: it keeps the map of
//! memory areas, picks addresses and loads ELF images. A platform only
//! carries out the resulting page-level operations ([`AddressSpace`]) and
//! copies bytes in and out ([`AppMemory`]), always on behalf of a task, and
//! the change applies to every task that shares the address space. This is
//! the same split whether the host kernel manages the page tables (seccomp)
//! or hellovm does (KVM, Hypervisor.framework).
//!
//! # The event loop
//!
//! The core runs a sandbox as one event loop, on one host thread, over all of
//! its tasks. A task is either *running* (the platform executes its code) or
//! *stopped* (it trapped and the core holds it). Starting and resuming a task
//! ([`Platform::resume`]) never blocks; the only place the kernel waits is
//! [`Platform::wait`], which returns the next trap of any running task, or
//! nothing when its timeout passes or a [`Waker`] fires.
//!
//! A syscall that has to wait (a pipe read, `wait4`, a `futex` wait, a sleep,
//! `poll`) does not block anything on the host: the core keeps its task
//! stopped, *parked*, and the loop goes on serving the other tasks. When the
//! condition may have changed, the core retries the syscall; when it holds,
//! the core resumes the task with the result. Timeouts are deadlines on the
//! core's monotonic clock that bound the next [`Platform::wait`]. Events from
//! outside the loop (console input arriving on a host thread) call the
//! platform's [`Waker`].
//!
//! The shape maps onto every planned platform: on seccomp a task is a host
//! process or thread traced by the kernel's event-loop thread and `wait`
//! waits for ptrace stops; on KVM and Hypervisor.framework a task is a vCPU
//! context, `resume` hands it to a vCPU thread and `wait` collects VM exits
//! from a queue, and address spaces are page tables that hellovm builds
//! itself (so `clone_task` with a copied address space is copy-on-write done
//! by the platform).

use std::fmt;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use crate::arch::Arch;

/// An address in the app's address space.
pub type GuestAddr = u64;

/// The platform's name for one task (app thread). Unique among the live
/// tasks of a platform; never reused while the core may still hold it.
pub type TaskKey = u64;

/// A syscall made by the app, as raw register values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallTrap {
    /// The raw syscall number, in the numbering of [`Platform::arch`].
    pub nr: u64,
    pub args: [u64; 6],
}

/// Why a task stopped running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trap {
    /// The task made a syscall. It stays stopped until [`Platform::resume`]
    /// delivers the result.
    Syscall(SyscallTrap),
    /// The task hit a CPU exception (bad memory access, illegal
    /// instruction, ...), reported as the Linux signal it maps to. The task
    /// is stopped at the faulting instruction; resuming it unchanged
    /// re-executes it.
    Fault(Fault),
    /// The task was stopped by [`Platform::interrupt`] (or by a stray
    /// asynchronous host event): nothing happened to the app, its context is
    /// intact and it can be resumed as it is.
    Interrupted,
    /// The task ended without the kernel asking (it was killed from outside
    /// the sandbox, e.g. by a timeout). It no longer exists.
    Gone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// Linux signal number (e.g. 11 for `SIGSEGV`).
    pub signal: u32,
    /// The Linux `si_code` (e.g. `SEGV_MAPERR`), when the platform knows it.
    pub code: i32,
    /// The faulting address, when the platform knows it.
    pub addr: Option<GuestAddr>,
}

/// A trap of one task, as [`Platform::wait`] reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub task: TaskKey,
    pub trap: Trap,
}

/// How to resume a stopped task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// First run of a task made by [`Platform::spawn`]: start at `entry`
    /// with the stack pointer at `stack` and every other general-purpose
    /// register zero.
    Start { entry: GuestAddr, stack: GuestAddr },
    /// Complete the pending syscall with this return value (`-errno` for
    /// errors, as the guest sees it).
    Return(i64),
    /// Continue with the current register context: the one the task stopped
    /// with, or the one last set with [`Platform::set_context`]. A pending
    /// syscall is dropped without running and without touching any
    /// register; a pending fault is dropped too (the task re-executes the
    /// instruction unless its context was changed).
    Continue,
}

#[derive(Debug)]
pub enum PlatformError {
    /// The platform does not implement this operation.
    Unsupported(&'static str),
    /// Guest memory at this range could not be accessed.
    BadAddress { addr: GuestAddr, len: usize },
    /// The task disappeared without the kernel ending it.
    AppGone(String),
    /// The app did something the platform cannot allow; it has been killed.
    Violation(String),
    /// The platform cannot create another task.
    NoResources(String),
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
            PlatformError::NoResources(why) => write!(f, "out of resources: {why}"),
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

/// Access to an app's memory.
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

/// The shape of an address space, the same for every address space of a
/// platform.
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

/// Whether a mapping's pages are private to its address space or shared
/// with the address spaces it is copied into by [`Platform::clone_task`]
/// (`MAP_SHARED` anonymous memory).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Sharing {
    #[default]
    Private,
    Shared,
}

/// Changes to an address space. Every address and length is a multiple of
/// the page size and lies outside the reserved ranges.
pub trait AddressSpace {
    /// Maps zero-filled memory at a fixed address, replacing whatever was
    /// mapped there.
    fn map(
        &mut self,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
        sharing: Sharing,
    ) -> Result<(), PlatformError>;
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

/// The user-visible register state of an aarch64 task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aarch64Context {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    /// The SIMD and floating-point registers.
    pub v: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
    /// `tpidr_el0`, the thread pointer.
    pub tpidr: u64,
}

/// The user-visible register state of an x86_64 task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X86_64Context {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rip: u64,
    pub rsp: u64,
    pub eflags: u64,
    /// `fs_base`, the thread pointer.
    pub fs_base: u64,
    /// The x87/SSE state in `fxsave` format.
    pub fxsave: Box<[u8; 512]>,
}

/// A task's complete user-visible register state, as signal frames save and
/// restore it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Context {
    Aarch64(Box<Aarch64Context>),
    X86_64(Box<X86_64Context>),
}

impl Context {
    pub fn arch(&self) -> Arch {
        match self {
            Context::Aarch64(_) => Arch::Aarch64,
            Context::X86_64(_) => Arch::X86_64,
        }
    }

    pub fn pc(&self) -> u64 {
        match self {
            Context::Aarch64(c) => c.pc,
            Context::X86_64(c) => c.rip,
        }
    }

    pub fn set_pc(&mut self, pc: u64) {
        match self {
            Context::Aarch64(c) => c.pc = pc,
            Context::X86_64(c) => c.rip = pc,
        }
    }

    pub fn sp(&self) -> u64 {
        match self {
            Context::Aarch64(c) => c.sp,
            Context::X86_64(c) => c.rsp,
        }
    }

    pub fn set_sp(&mut self, sp: u64) {
        match self {
            Context::Aarch64(c) => c.sp = sp,
            Context::X86_64(c) => c.rsp = sp,
        }
    }

    /// Sets the syscall return value register.
    pub fn set_ret(&mut self, value: i64) {
        match self {
            Context::Aarch64(c) => c.x[0] = value as u64,
            Context::X86_64(c) => c.rax = value as u64,
        }
    }

    pub fn thread_pointer(&self) -> u64 {
        match self {
            Context::Aarch64(c) => c.tpidr,
            Context::X86_64(c) => c.fs_base,
        }
    }

    pub fn set_thread_pointer(&mut self, value: u64) {
        match self {
            Context::Aarch64(c) => c.tpidr = value,
            Context::X86_64(c) => c.fs_base = value,
        }
    }

    /// Makes the task, which stopped right after the syscall instruction of
    /// `trap`, execute that syscall again when it resumes (syscall restart).
    pub fn restart_syscall(&mut self, trap: &SyscallTrap) {
        match self {
            Context::Aarch64(c) => {
                c.pc = c.pc.wrapping_sub(4);
                c.x[0] = trap.args[0];
                c.x[8] = trap.nr;
            }
            Context::X86_64(c) => {
                c.rip = c.rip.wrapping_sub(2);
                c.rax = trap.nr;
            }
        }
    }

    /// An all-zero context for `arch`.
    pub fn zeroed(arch: Arch) -> Context {
        match arch {
            Arch::Aarch64 => Context::Aarch64(Box::new(Aarch64Context {
                x: [0; 31],
                sp: 0,
                pc: 0,
                pstate: 0,
                v: [0; 32],
                fpsr: 0,
                fpcr: 0,
                tpidr: 0,
            })),
            Arch::X86_64 => Context::X86_64(Box::new(X86_64Context {
                r15: 0,
                r14: 0,
                r13: 0,
                r12: 0,
                rbp: 0,
                rbx: 0,
                r11: 0,
                r10: 0,
                r9: 0,
                r8: 0,
                rax: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                rip: 0,
                rsp: 0,
                eflags: 0x202,
                fs_base: 0,
                fxsave: Box::new([0; 512]),
            })),
        }
    }
}

/// Wakes the kernel's event loop from [`Platform::wait`], from any thread.
#[derive(Clone)]
pub struct Waker(Arc<dyn Fn() + Send + Sync>);

impl Waker {
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Waker {
        Waker(Arc::new(wake))
    }

    /// A waker that does nothing (for hosts that never need one).
    pub fn noop() -> Waker {
        Waker::new(|| {})
    }

    pub fn wake(&self) {
        (self.0)()
    }
}

impl fmt::Debug for Waker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Waker")
    }
}

/// One sandbox's tasks. See the module documentation.
///
/// Every method that names a task requires it to be live; the memory and
/// address-space methods and the context methods also require it to be
/// stopped (a task is stopped from the trap [`Platform::wait`] reports until
/// the next [`Platform::resume`]).
pub trait Platform {
    /// The syscall ABI of the apps.
    fn arch(&self) -> Arch;

    /// The shape of every address space. A new address space is empty apart
    /// from the reserved ranges.
    fn address_space(&self) -> AddressSpaceInfo;

    /// CPU features the guest may use.
    fn cpu_info(&self) -> CpuInfo;

    /// Creates a stopped task with a fresh, empty address space. It first
    /// runs with [`Resume::Start`].
    fn spawn(&mut self) -> Result<TaskKey, PlatformError>;

    /// Creates a stopped task whose context is a copy of `parent`'s, which
    /// must be stopped. With `share_memory` it uses `parent`'s address space
    /// (threads, `vfork`); otherwise it gets a copy of it, as `fork` does
    /// (shared mappings stay shared). It first runs with
    /// [`Resume::Continue`], normally after [`Platform::set_context`].
    fn clone_task(&mut self, parent: TaskKey, share_memory: bool)
        -> Result<TaskKey, PlatformError>;

    /// Ends a task for good. An address space goes away with its last task.
    fn kill(&mut self, task: TaskKey) -> Result<(), PlatformError>;

    /// The register context of a stopped task. At a syscall trap it is the
    /// context right after the syscall instruction, with the syscall's
    /// number and arguments still in their registers.
    fn context(&mut self, task: TaskKey) -> Result<Context, PlatformError>;

    /// Replaces the register context of a stopped task, for its next
    /// [`Resume::Continue`]. The platform keeps the app from gaining
    /// privileges through it (processor mode and system flags are not taken
    /// from `context`).
    fn set_context(&mut self, task: TaskKey, context: &Context) -> Result<(), PlatformError>;

    /// Resumes a stopped task. Never blocks; the task's next trap is
    /// reported by [`Platform::wait`].
    fn resume(&mut self, task: TaskKey, resume: Resume) -> Result<(), PlatformError>;

    /// Makes a running task trap with [`Trap::Interrupted`] soon (to deliver
    /// a signal to code that makes no syscalls). It may also trap for
    /// another reason first; an interrupt that arrives after that shows up
    /// as a later, spurious [`Trap::Interrupted`].
    fn interrupt(&mut self, task: TaskKey) -> Result<(), PlatformError>;

    /// Waits for the next trap of a running task, for at most `timeout`
    /// (forever if `None`). Returns `None` on timeout or when a [`Waker`]
    /// of this platform was called.
    fn wait(&mut self, timeout: Option<Duration>) -> Result<Option<Event>, PlatformError>;

    /// A handle that makes [`Platform::wait`] return early.
    fn waker(&self) -> Waker;

    /// Reads memory of a stopped task's address space.
    fn read(&mut self, task: TaskKey, addr: GuestAddr, buf: &mut [u8])
        -> Result<(), PlatformError>;

    /// Writes memory of a stopped task's address space.
    fn write(&mut self, task: TaskKey, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError>;

    /// See [`AddressSpace::map`].
    fn map(
        &mut self,
        task: TaskKey,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
        sharing: Sharing,
    ) -> Result<(), PlatformError>;

    /// See [`AddressSpace::unmap`].
    fn unmap(&mut self, task: TaskKey, addr: GuestAddr, len: u64) -> Result<(), PlatformError>;

    /// See [`AddressSpace::protect`].
    fn protect(
        &mut self,
        task: TaskKey,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
    ) -> Result<(), PlatformError>;
}

/// One stopped task of a platform, as [`AppMemory`] and [`AddressSpace`].
pub struct TaskMem<'a, P: ?Sized> {
    pub platform: &'a mut P,
    pub task: TaskKey,
}

impl<'a, P: Platform + ?Sized> TaskMem<'a, P> {
    pub fn new(platform: &'a mut P, task: TaskKey) -> Self {
        TaskMem { platform, task }
    }
}

impl<P: Platform + ?Sized> AppMemory for TaskMem<'_, P> {
    fn read(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), PlatformError> {
        self.platform.read(self.task, addr, buf)
    }

    fn write(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError> {
        self.platform.write(self.task, addr, data)
    }
}

impl<P: Platform + ?Sized> AddressSpace for TaskMem<'_, P> {
    fn map(
        &mut self,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
        sharing: Sharing,
    ) -> Result<(), PlatformError> {
        self.platform.map(self.task, addr, len, prot, sharing)
    }

    fn unmap(&mut self, addr: GuestAddr, len: u64) -> Result<(), PlatformError> {
        self.platform.unmap(self.task, addr, len)
    }

    fn protect(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), PlatformError> {
        self.platform.protect(self.task, addr, len, prot)
    }
}
