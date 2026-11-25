//! What [`VmPlatform`](crate::VmPlatform) needs from a hypervisor: a VM
//! with the platform's memory in it, and vCPUs that run an app at EL0
//! and leave the VM when it takes an exception or is stopped from
//! outside.
//!
//! Both backends run the same guest: the app at EL0 under the platform's
//! stage-1 tables (`mmu`), and at EL1 a shim of a few instructions that
//! leaves the VM at once. How the shim leaves, and how the host reads and
//! sets the app's registers, differs: on Hypervisor.framework the vectors
//! are `hvc` and the host reads the vCPU's registers directly; on KVM the
//! shim saves them to memory the host reads (see `hellovm-platform-kvm`).

use std::io;
use std::time::Instant;

use hellovm_core::platform::Aarch64Context;

use crate::mmu::{Backing, MmuError, Phys};

/// A VM of one hypervisor, with its memory regions mapped.
pub trait Hypervisor: Sized + 'static {
    /// In messages: "HVF", "KVM".
    const NAME: &'static str;
    /// The start of a warm-clone snapshot's magic.
    const SNAPSHOT_PREFIX: &'static str;
    /// A warm-clone template writes the frames between two saved ones as
    /// zeros when there are fewer than this many (see `Phys::save`): for
    /// a backend whose clones map the snapshot's written pages from its
    /// file, a run at a time (KVM), so that a fragmented template does not
    /// become thousands of mappings. 0: never (HVF copies frame by frame).
    const SNAPSHOT_GAP: u64 = 0;
    /// Whether the platform makes every vCPU when it is made, on the
    /// calling thread, and starts the other vCPUs' threads only at its
    /// first `wait`: so that a kernel process that confines itself in
    /// between has no thread of its own before then (on Linux, namespaces
    /// and Landlock apply to the calling thread only). A backend may say
    /// so only if its vCPUs may move to another thread before they first
    /// run (KVM's may). Hypervisor.framework binds a vCPU to the thread
    /// that made it: there each vCPU's thread makes it, with the platform.
    const DEFER_THREADS: bool = false;
    /// Host memory the pools live in.
    type Mem: Backing + Send + 'static;
    /// Lets another thread make a vCPU of this VM.
    type Token: Clone + Send + 'static;
    type Vcpu: Vcpu<Kicker = Self::Kicker>;
    type Kicker: Kicker;

    /// Makes the VM with its shim and the two pools (page tables of
    /// `table_memory` bytes, app memory of `memory` bytes, both multiples
    /// of 16 KiB) mapped at their guest-physical addresses (`layout`).
    fn create(memory: usize, table_memory: usize) -> io::Result<(Self, Self::Mem, Self::Mem)>;

    /// Writes the `TTBR1_EL1` tree every vCPU uses (the shim, and what
    /// else the backend's shim needs) and returns its root.
    fn shim_space(&self, phys: &mut Phys<Self::Mem>) -> Result<u64, MmuError>;

    /// How many vCPUs the hypervisor lets this VM have.
    fn max_vcpus(&self) -> u32;

    fn token(&self) -> Self::Token;

    /// Makes vCPU `index` for the calling thread, which runs it from then
    /// on (with [`Hypervisor::DEFER_THREADS`], until it moves to its own).
    fn vcpu(token: Self::Token, index: usize) -> io::Result<Self::Vcpu>;

    /// The platform is going (every vCPU but the event loop's is gone):
    /// unmaps the memory regions (of the sizes given) from the VM.
    fn release(&mut self, table_memory: usize, memory: usize);
}

/// Forces a vCPU out of [`Vcpu::run`] from any thread; if it is not in a
/// run, its next run ends at once (or soon after, with the app's
/// registers saved).
pub trait Kicker: Send + Sync + 'static {
    fn kick(&self);
}

/// A register [`Vcpu::reg`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reg {
    /// `x0` to `x30`.
    X(u8),
    Pc,
    Cpsr,
    ElrEl1,
    SpsrEl1,
    EsrEl1,
    FarEl1,
    SpEl0,
}

/// What [`Vcpu::enter`] invalidates before the app runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flush {
    None,
    /// The whole TLB and the instruction cache (`tlbi vmalle1is`, `ic
    /// ialluis`).
    All,
    /// One page of one address space: the `tlbi vae1is` operand.
    Page(u64),
}

/// The ID registers the platform reads once.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdRegs {
    pub pfr0: u64,
    pub isar0: u64,
    pub isar1: u64,
    pub mmfr0: u64,
}

/// Where a vCPU stopped from outside (a kick, its timer) found the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stopped {
    /// In the app: it continues at `pc` with these `PSTATE` bits.
    At { pc: u64, pstate: u64 },
    /// In an exception vector of the shim, on its way out with an
    /// exception of the app: run on, without entering again, to let it
    /// leave.
    InVector,
    /// In a flush routine, before the app ran: it starts over from where
    /// it was to resume, with the whole TLB flushed.
    Flushing,
    /// Somewhere it can never be (a bug of the VM setup).
    Lost(String),
}

/// How [`Vcpu::run`] ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    Stopped(Stopped),
    /// The app took an exception to EL1 and it came out through the
    /// shim's vector `slot`: [`Reg::ElrEl1`], [`Reg::SpsrEl1`],
    /// [`Reg::EsrEl1`] and [`Reg::FarEl1`] describe it, and the general
    /// registers are the app's.
    Vector(u16),
    /// An exception taken straight to the hypervisor (`syndrome` is
    /// `ESR_EL2`, with its fault addresses): Hypervisor.framework's traps
    /// of `wfi`/`wfe`, or anything that means the VM is not as built.
    Direct {
        syndrome: u64,
        virtual_address: u64,
        physical_address: u64,
    },
    /// An exit the platform has no use for: the task ends.
    Unexpected(String),
}

/// A vCPU, owned by the thread that made it.
pub trait Vcpu {
    type Kicker: Kicker;

    fn kicker(&self) -> Self::Kicker;

    fn id_regs(&self) -> io::Result<IdRegs>;

    /// The system registers every vCPU starts with: `tcr` (`TCR_EL1`) and
    /// the root of the shim's tree (`TTBR1_EL1`); `TTBR0_EL1` is 0.
    fn set_up(&mut self, tcr: u64, shim_root: u64) -> io::Result<()>;

    /// The app's registers (`pc` and `pstate` are left 0: the platform
    /// keeps those itself).
    fn read_context(&self) -> io::Result<Box<Aarch64Context>>;

    /// Sets the app's registers but `pc` and `pstate`.
    fn write_context(&mut self, context: &Aarch64Context) -> io::Result<()>;

    fn reg(&self, reg: Reg) -> io::Result<u64>;

    fn set_x0(&mut self, value: u64) -> io::Result<()>;

    fn set_ttbr0(&mut self, value: u64) -> io::Result<()>;

    /// Ends the next run at `deadline` (`None`: no deadline).
    fn arm_timer(&mut self, deadline: Option<Instant>) -> io::Result<()>;

    /// Points the vCPU at the app, at `pc` with `pstate` (EL0t), through
    /// `flush` first.
    fn enter(&mut self, pc: u64, pstate: u64, flush: Flush) -> io::Result<()>;

    /// Runs until the next exit.
    fn run(&mut self) -> io::Result<Exit>;
}
