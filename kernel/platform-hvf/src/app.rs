//! [`HvfPlatform`]: the [`Platform`] implementation.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hellovm_core::arch::Arch;
use hellovm_core::platform::{
    Aarch64Context, AddressSpaceInfo, Context, CpuInfo, Event, Fault, GuestAddr, Platform,
    PlatformError, Prot, Resume, Sharing, SyscallTrap, TaskKey, Trap, Waker,
};

use crate::exit::{self, AppException, SEGV_ACCERR, SEGV_MAPERR};
use crate::layout::{self, FLUSH_OFFSET, FLUSH_PAGE_OFFSET, MAX_ADDR, MIN_ADDR, PAGE, SHIM_VA};
use crate::mmu::{Access, Backing, Demand, MmuError, Phys, Stale};
use crate::sys::{
    self, sysreg, HostMem, HvVcpuExit, Vcpu, VcpuKicker, Vm, HV_EXIT_REASON_CANCELED,
    HV_EXIT_REASON_EXCEPTION, HV_EXIT_REASON_VTIMER_ACTIVATED, HV_MEMORY_EXEC, HV_MEMORY_READ,
    HV_MEMORY_WRITE, HV_REG_CPSR, HV_REG_FPCR, HV_REG_FPSR, HV_REG_PC,
};

const SIGKILL: u32 = 9;
const SI_KERNEL: i32 = 0x80;

/// How long a task runs before another runnable task gets the vCPU.
const SLICE: Duration = Duration::from_millis(5);

/// How long an idle vCPU thread, or the event loop, polls for work
/// before it sleeps: a task that goes back and forth between the core and
/// another vCPU (a system call, a pipe round trip) then waits for no
/// host thread to wake up.
const SPIN: Duration = Duration::from_micros(50);

/// Polls `done` for at most `limit` (and not past `deadline`).
fn spin_until(limit: Duration, deadline: Option<Instant>, done: impl Fn() -> bool) -> bool {
    let start = Instant::now();
    let end = match deadline {
        Some(deadline) => deadline.min(start + limit),
        None => start + limit,
    };
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::hint::spin_loop();
    }
}

/// How long what vCPU 0 would run next may wait while the event loop is
/// busy before another vCPU runs it ([`HvfPlatform::let_go`]).
const HOLD: Duration = SPIN;

/// Most vCPUs a platform makes, whatever the framework allows.
pub const MAX_VCPUS: usize = 64;

/// vCPUs when [`HvfConfig::vcpus`] is 0: one per host CPU, at most this.
const DEFAULT_VCPUS: usize = 8;

/// How much memory a platform reserves for its apps, and how many vCPUs
/// run them.
#[derive(Clone, Copy, Debug)]
pub struct HvfConfig {
    /// App memory (every page any app of the sandbox touches), in bytes.
    pub memory: u64,
    /// Page-table memory, in bytes.
    pub table_memory: u64,
    /// vCPUs, each on its own host thread: threads of the apps run in
    /// parallel on them. 0 is the default: one per host CPU, at most 8.
    /// At most [`MAX_VCPUS`] and what the framework allows.
    pub vcpus: usize,
}

impl Default for HvfConfig {
    fn default() -> Self {
        HvfConfig {
            memory: 2 << 30,
            table_memory: 64 << 20,
            vcpus: 0,
        }
    }
}

impl Backing for HostMem {
    fn bytes(&self) -> &[u8] {
        self.slice(0, self.len())
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.slice_mut(0, self.len())
    }

    fn sync_icache(&mut self, offset: usize, len: usize) {
        self.check_range(offset, len);
        // SAFETY: in bounds (checked); the call only maintains caches.
        sys::icache_invalidate(unsafe { self.ptr().add(offset) }, len);
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) {
        HostMem::read_at(self, offset, buf)
    }

    fn write_at(&mut self, offset: usize, data: &[u8]) {
        HostMem::write_at(self, offset, data)
    }

    fn copy_at(&mut self, from: usize, to: usize, len: usize) {
        HostMem::copy_at(self, from, to, len)
    }

    fn zero_at(&mut self, offset: usize, len: usize) {
        HostMem::zero_at(self, offset, len)
    }

    fn store_u64(&mut self, offset: usize, value: u64) {
        HostMem::store_u64(self, offset, value)
    }
}

/// How often the platform invalidated TLB entries ([`HvfPlatform::flushes`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flushes {
    /// The whole TLB (and the instruction cache).
    pub all: u64,
    /// One page of one address space.
    pub page: u64,
}

/// Where an asynchronous exit found the vCPU.
enum Interrupted {
    /// The app's position is saved: resume it later.
    Settled,
    /// In an exception vector: run on to its `hvc`.
    InVector,
    /// Somewhere it can never be (a bug of the VM setup).
    Lost(String),
}

/// Why a task is stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Made by `spawn`, never run.
    New,
    Stopped,
    /// Resumed: a vCPU will run it.
    Runnable,
}

struct Task {
    space: u64,
    state: State,
    /// Where the app continues, and its condition flags: kept here, not in
    /// the vCPU, which stops in the shim.
    pc: u64,
    pstate: u64,
    /// The rest of the register context, while it is in no vCPU.
    saved: Option<Box<Aarch64Context>>,
    /// The vCPU whose registers are the task's (`saved` is `None`).
    loaded: Option<usize>,
    /// A system call's result for `x0`, set by the vCPU it is loaded in
    /// before it runs.
    x0: Option<u64>,
    /// The vCPU running it now (from claiming it to letting go of it).
    on: Option<usize>,
    /// [`Platform::interrupt`] was called.
    interrupt: bool,
    /// [`Platform::kill`] waits for the vCPU running it to let go.
    kill: bool,
    /// How long it ran, in nanoseconds, give or take (see
    /// [`Sched::pick`]).
    runtime: u64,
}

struct Space {
    /// The guest-physical address of its level-0 table.
    root: u64,
    /// Its address space identifier; 0 is shared by the spaces that found
    /// none free (see [`Runner::set_space`]).
    asid: u16,
    users: usize,
}

/// Tasks, address spaces and what the threads tell each other, behind
/// [`Smp::sched`].
struct Sched {
    tasks: BTreeMap<TaskKey, Task>,
    spaces: HashMap<u64, Space>,
    /// Traps of tasks the other vCPUs ran, for [`Platform::wait`]. At most
    /// one per task: a task traps once and then waits for the core.
    events: VecDeque<Event>,
    next_key: TaskKey,
    next_space: u64,
    /// ASIDs of spaces that are gone, and the lowest never used.
    free_asids: Vec<u16>,
    next_asid: u32,
    /// One past the highest ASID (256 or 65536).
    asid_limit: u32,
    /// The least runtime of a task chosen to run (it only grows).
    min_runtime: u64,
    woken: bool,
    /// vCPU 0, the event loop's, is in (or about to enter) a run: events
    /// and wakers kick it.
    loop_in_run: bool,
    killed: bool,
    /// The platform is going: the vCPU threads end.
    quit: bool,
    /// The state was logged when the killer came (debug log only).
    dumped: bool,
    /// Per vCPU: the event loop asks it to save the registers of this
    /// task, loaded in it, into the task.
    unload: Vec<Option<TaskKey>>,
    /// Per vCPU: its thread waits for a task.
    idle: Vec<bool>,
}

impl Sched {
    /// An ASID for a new space: 0 when none is free.
    fn alloc_asid(&mut self) -> u16 {
        if let Some(asid) = self.free_asids.pop() {
            return asid;
        }
        if self.next_asid < self.asid_limit {
            self.next_asid += 1;
            return (self.next_asid - 1) as u16;
        }
        0
    }

    /// A new space with the tables at `root`.
    fn add_space(&mut self, root: u64) -> u64 {
        let id = self.next_space;
        self.next_space += 1;
        let asid = self.alloc_asid();
        self.spaces.insert(
            id,
            Space {
                root,
                asid,
                users: 1,
            },
        );
        id
    }

    fn task(&mut self, key: TaskKey) -> Result<&mut Task, PlatformError> {
        self.tasks
            .get_mut(&key)
            .ok_or_else(|| PlatformError::AppGone(format!("no task {key}")))
    }

    fn stopped(&mut self, key: TaskKey) -> Result<&mut Task, PlatformError> {
        let task = self.task(key)?;
        if task.state == State::Runnable {
            return Err(PlatformError::Violation(format!("task {key} is running")));
        }
        Ok(task)
    }

    /// The root and ASID of a stopped task's space.
    fn space_of(&mut self, key: TaskKey) -> Result<(u64, u16), PlatformError> {
        let space = self.stopped(key)?.space;
        let space = &self.spaces[&space];
        Ok((space.root, space.asid))
    }

    /// The runnable task vCPU `vcpu` runs next, and whether another task
    /// waits to run.
    ///
    /// Each task has a runtime, the time it spent in a vCPU, and the
    /// runnable task with the least runtime runs next. A task that mostly
    /// waits (for a pipe, a child) runs as soon as it can; a task that
    /// never traps uses up its slice and lets the others run. A task that
    /// becomes runnable starts at most one slice behind the least runtime
    /// of a task chosen to run, so time it spent waiting gives it no claim
    /// on a vCPU later. A task whose registers are in another vCPU waits
    /// for that one, and spaces with ASID 0 run on vCPU 0 only (see
    /// [`Runner::set_space`]).
    fn pick(&self, vcpu: usize) -> Option<(TaskKey, bool)> {
        let mut best: Option<(u64, TaskKey)> = None;
        let mut waiting = 0;
        for (&key, task) in &self.tasks {
            if task.state != State::Runnable || task.on.is_some() || task.interrupt || task.kill {
                continue;
            }
            waiting += 1;
            if task.loaded.is_some_and(|other| other != vcpu)
                || (vcpu != 0 && self.spaces[&task.space].asid == 0)
            {
                continue;
            }
            if best.is_none_or(|best| task.runtime < best.0) {
                best = Some((task.runtime, key));
            }
        }
        best.map(|(_, key)| (key, waiting > 1))
    }

    /// The runtime a task that becomes runnable starts from.
    fn catch_up(&self, runtime: u64) -> u64 {
        runtime.max(self.min_runtime.saturating_sub(SLICE.as_nanos() as u64))
    }
}

/// No invalidation is pending for a vCPU ([`Slot::pending`]).
const PENDING_NONE: u64 = 0;
/// The whole TLB.
const PENDING_ALL: u64 = u64::MAX;

/// The `tlbi vae1is` operand for the page of `va` in the space with `asid`.
fn page_operand(asid: u16, va: u64) -> u64 {
    u64::from(asid) << 48 | (va >> 12) & 0xfff_ffff_ffff
}

/// What the threads know of one vCPU without a lock.
struct Slot {
    kicker: OnceLock<VcpuKicker>,
    /// Counts the wake-ups of its thread (with the scheduler locked), which
    /// polls it before it sleeps.
    wakes: AtomicU64,
    /// Odd from just before the vCPU takes its pending invalidations for a
    /// run until `hv_vcpu_run` returns, even otherwise. A change to page
    /// tables waits until each vCPU that was in a run of that space has
    /// left it ([`Smp::invalidate`]).
    epoch: AtomicU64,
    /// The root of the space of its current run.
    root: AtomicU64,
    /// TLB entries to invalidate before the app runs on it again:
    /// [`PENDING_NONE`], [`PENDING_ALL`], or the `tlbi vae1is` operand of
    /// one page (never 0: the ASID and page number of an app address).
    pending: AtomicU64,
}

impl Slot {
    fn kick(&self) {
        if let Some(kicker) = self.kicker.get() {
            kicker.kick();
        }
    }

    fn add_pending(&self, add: u64) {
        let mut old = self.pending.load(SeqCst);
        loop {
            let new = match old {
                PENDING_NONE => add,
                old if old == add => return,
                _ => PENDING_ALL,
            };
            match self.pending.compare_exchange(old, new, SeqCst, SeqCst) {
                Ok(_) => return,
                Err(now) => old = now,
            }
        }
    }
}

/// What the event loop and the vCPU threads share.
struct Smp {
    sched: Mutex<Sched>,
    /// The event loop waits here: for events, wakers, tasks let go.
    loop_cv: Condvar,
    /// Counts the event loop's wake-ups (with the scheduler locked), which
    /// it polls before it sleeps.
    loop_wakes: AtomicU64,
    /// Each vCPU thread waits on its own (index 0 unused) for a task to
    /// run, so that a task made runnable wakes one thread, not all.
    vcpu_cvs: Vec<Condvar>,
    /// The pools and the page tables. Held from a change to the tables
    /// until no vCPU can use what it made stale (see [`Smp::change`]).
    phys: Mutex<Phys<HostMem>>,
    slots: Vec<Slot>,
    /// `mach_absolute_time` ticks per second.
    ticks_per_sec: u64,
    flushes_all: AtomicU64,
    flushes_page: AtomicU64,
}

impl Smp {
    fn lock(&self) -> MutexGuard<'_, Sched> {
        self.sched.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn phys(&self) -> MutexGuard<'_, Phys<HostMem>> {
        self.phys.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wait_loop<'a>(&self, guard: MutexGuard<'a, Sched>) -> MutexGuard<'a, Sched> {
        self.loop_cv.wait(guard).unwrap_or_else(|e| e.into_inner())
    }

    fn wait_loop_for<'a>(
        &self,
        guard: MutexGuard<'a, Sched>,
        time: Duration,
    ) -> MutexGuard<'a, Sched> {
        self.loop_cv
            .wait_timeout(guard, time)
            .unwrap_or_else(|e| e.into_inner())
            .0
    }

    /// Wakes every vCPU thread.
    fn wake_all(&self) {
        for (slot, cv) in self.slots.iter().zip(&self.vcpu_cvs) {
            slot.wakes.fetch_add(1, SeqCst);
            cv.notify_all();
        }
    }

    /// Wakes vCPU thread `index`.
    fn wake(&self, index: usize) {
        self.slots[index].wakes.fetch_add(1, SeqCst);
        self.vcpu_cvs[index].notify_one();
    }

    /// Wakes the event loop if it waits (it is not in a run).
    fn wake_loop(&self) {
        self.loop_wakes.fetch_add(1, SeqCst);
        self.loop_cv.notify_all();
    }

    /// `key` became runnable: wakes the vCPU thread its registers are in,
    /// or one that is idle. A busy one takes it when its slice ends.
    fn wake_for(&self, sched: &mut Sched, key: TaskKey) {
        let waiting = |task: &Task| task.state == State::Runnable && task.on.is_none();
        let index = match sched
            .tasks
            .get(&key)
            .filter(|task| waiting(task))
            .map(|task| task.loaded)
        {
            Some(Some(0)) | None => return,
            Some(Some(index)) => index,
            Some(None) => match (1..self.slots.len()).find(|&index| sched.idle[index]) {
                Some(index) => index,
                None => return,
            },
        };
        // Not idle any more as far as other wakers are concerned.
        sched.idle[index] = false;
        self.wake(index);
    }

    /// Tells the event loop that something changed for it.
    fn notify_loop(&self, sched: &Sched) {
        if sched.loop_in_run {
            self.slots[0].kick();
        }
        self.wake_loop();
    }

    /// Changes the page tables of the space at `root` (ASID `asid`) with
    /// `f`. When the change leaves TLB entries stale, every vCPU must
    /// invalidate them before it runs an app again, and every vCPU that
    /// is running that space now is made to leave the VM first; the lock
    /// on the tables is held until then, so no other change (which could
    /// free and hand out a frame the stale entries still reach) comes in
    /// between.
    fn change<R>(&self, root: u64, asid: u16, f: impl FnOnce(&mut Phys<HostMem>) -> R) -> R {
        let mut phys = self.phys();
        let result = f(&mut phys);
        let stale = phys.take_stale();
        self.invalidate(root, asid, stale);
        drop(phys);
        result
    }

    /// See [`Smp::change`]. Called with the tables locked.
    ///
    /// A vCPU's epoch is odd from just before it takes its pending
    /// invalidations until it leaves the VM. The pending ones are added
    /// first, then the epochs read (all sequentially consistent): a vCPU
    /// either takes them before its next run, or is seen in a run here,
    /// and then is kicked out of it and waited for. A vCPU that leaves
    /// takes them before it runs the app again. The invalidation itself
    /// is the shim's `tlbi ...is`, which reaches every CPU of the host, so
    /// whichever vCPU runs that space next on any CPU, nothing stale is
    /// left by then.
    fn invalidate(&self, root: u64, asid: u16, stale: Stale) {
        let add = match stale {
            Stale::Clean => return,
            Stale::All => PENDING_ALL,
            Stale::Page { root: at, va } if at == root => page_operand(asid, va),
            Stale::Page { .. } => PENDING_ALL,
        };
        for slot in &self.slots {
            slot.add_pending(add);
        }
        for slot in &self.slots {
            let epoch = slot.epoch.load(SeqCst);
            if epoch % 2 == 0 || slot.root.load(SeqCst) != root {
                continue;
            }
            // In a run of this space: out with it. A kick can come just
            // before the vCPU enters the VM; kicks repeat until it left.
            let mut spins = 0u32;
            while slot.epoch.load(SeqCst) == epoch {
                if spins.is_multiple_of(4096) {
                    slot.kick();
                }
                spins = spins.wrapping_add(1);
                std::hint::spin_loop();
            }
        }
    }

    /// Ends a task that no vCPU runs; its address space goes with its last
    /// task. Its ASID is free again only once its tables are freed and
    /// every vCPU will flush the TLB before it runs an app again.
    fn remove(&self, mut sched: MutexGuard<'_, Sched>, key: TaskKey) {
        sched.events.retain(|event| event.task != key);
        let Some(task) = sched.tasks.remove(&key) else {
            return;
        };
        debug_assert!(task.on.is_none());
        let space = sched.spaces.get_mut(&task.space).expect("task's space");
        space.users -= 1;
        if space.users > 0 {
            return;
        }
        let Some(space) = sched.spaces.remove(&task.space) else {
            return;
        };
        drop(sched);
        // Frees its tables: `Stale::All`, for every vCPU.
        self.change(space.root, space.asid, |phys| phys.destroy(space.root));
        if space.asid != 0 {
            self.lock().free_asids.push(space.asid);
        }
    }

    /// Ends a task the platform cannot run any more and reports it to
    /// the event loop as [`Trap::Gone`].
    fn lose(&self, sched: MutexGuard<'_, Sched>, key: TaskKey) {
        self.remove(sched, key);
        let mut sched = self.lock();
        sched.events.push_back(Event {
            task: key,
            trap: Trap::Gone,
        });
        self.notify_loop(&sched);
    }

    fn flushes(&self) -> Flushes {
        Flushes {
            all: self.flushes_all.load(SeqCst),
            page: self.flushes_page.load(SeqCst),
        }
    }
}

/// Ends every app of an [`HvfPlatform`] from any thread (for timeouts):
/// the platform reports each task as [`Trap::Gone`].
#[derive(Clone)]
pub struct AppKiller {
    smp: Arc<Smp>,
}

impl AppKiller {
    pub fn kill(&self) {
        let mut sched = self.smp.lock();
        sched.killed = true;
        sched.woken = true;
        for slot in &self.smp.slots {
            slot.kick();
        }
        self.smp.wake_loop();
        self.smp.wake_all();
    }
}

/// The task a [`Runner`] runs.
struct Current {
    key: TaskKey,
    root: u64,
    asid: u16,
    pc: u64,
    pstate: u64,
}

/// How a run ended.
enum Stop {
    /// The app trapped.
    Trap(Trap),
    /// Stopped from outside (a kick, the timer): the task is still
    /// runnable.
    Settled,
    /// The platform cannot run the task any more.
    Gone(String),
}

/// One vCPU, on the thread that made it.
struct Runner {
    index: usize,
    vcpu: Vcpu,
    /// The task whose registers are in the vCPU.
    loaded: Option<TaskKey>,
    /// `TTBR0_EL1` as last set.
    ttbr0: u64,
    /// Flush the whole TLB before the app runs (beyond the pending ones
    /// of [`Slot::pending`]).
    flush: bool,
    /// Only one page: the `tlbi vae1is` operand for the shim's page flush
    /// routine.
    flush_page: Option<u64>,
    timer_armed: bool,
    /// The deadline the armed timer has.
    armed_for: Option<Instant>,
    /// The task this vCPU gave a slice and when it ends: a task keeps its
    /// slice across the traps the core answers in between.
    slice: Option<(TaskKey, Instant)>,
    /// The space that last ran with ASID 0 since the TLB was last
    /// flushed, if any (vCPU 0 only).
    asid0_root: Option<u64>,
}

fn host_err(err: sys::HvError) -> PlatformError {
    PlatformError::Host(err.into())
}

fn mmu_err(err: MmuError, addr: u64, len: u64) -> PlatformError {
    match err {
        MmuError::BadAddress => PlatformError::BadAddress {
            addr,
            len: len.try_into().unwrap_or(usize::MAX),
        },
        MmuError::NoMemory => PlatformError::NoResources("the sandbox's memory is used up".into()),
    }
}

/// The system registers every vCPU starts with.
fn set_up(vcpu: &Vcpu, tcr: u64, shim_root: u64) -> Result<(), sys::HvError> {
    for (reg, value) in [
        (sysreg::MAIR_EL1, layout::MAIR_EL1),
        (sysreg::TCR_EL1, tcr),
        (sysreg::TTBR1_EL1, shim_root),
        (sysreg::TTBR0_EL1, 0),
        (sysreg::VBAR_EL1, SHIM_VA),
        (sysreg::CPACR_EL1, layout::CPACR_EL1),
        (sysreg::CNTKCTL_EL1, layout::CNTKCTL_EL1),
        (sysreg::CNTV_CTL_EL0, 0),
        (sysreg::SP_EL1, 0),
        (sysreg::TPIDRRO_EL0, 0),
        (sysreg::SCTLR_EL1, layout::SCTLR_EL1),
    ] {
        vcpu.set_sys_reg(reg, value)?;
    }
    Ok(())
}

impl Runner {
    fn new(index: usize, vcpu: Vcpu) -> Runner {
        Runner {
            index,
            vcpu,
            loaded: None,
            ttbr0: 0,
            flush: true,
            flush_page: None,
            timer_armed: false,
            armed_for: None,
            slice: None,
            asid0_root: None,
        }
    }

    /// The end of `key`'s slice on this vCPU: a new one, unless `key` is
    /// the task that had the last one and it has not ended.
    fn slice_end(&mut self, key: TaskKey) -> Option<Instant> {
        let now = Instant::now();
        match self.slice {
            Some((last, end)) if last == key && end > now => Some(end),
            _ => {
                let end = now.checked_add(SLICE)?;
                self.slice = Some((key, end));
                Some(end)
            }
        }
    }

    fn read_vcpu(&self) -> Result<Box<Aarch64Context>, sys::HvError> {
        let v = &self.vcpu;
        let mut c = Box::new(Aarch64Context {
            x: [0; 31],
            sp: v.sys_reg(sysreg::SP_EL0)?,
            pc: 0,
            pstate: 0,
            v: [0; 32],
            fpsr: v.reg(HV_REG_FPSR)? as u32,
            fpcr: v.reg(HV_REG_FPCR)? as u32,
            tpidr: v.sys_reg(sysreg::TPIDR_EL0)?,
        });
        for (i, x) in c.x.iter_mut().enumerate() {
            *x = v.reg(i as u32)?;
        }
        for (i, q) in c.v.iter_mut().enumerate() {
            *q = v.simd(i as u32)?;
        }
        Ok(c)
    }

    fn write_vcpu(&self, c: &Aarch64Context) -> Result<(), sys::HvError> {
        let v = &self.vcpu;
        for (i, &x) in c.x.iter().enumerate() {
            v.set_reg(i as u32, x)?;
        }
        for (i, &q) in c.v.iter().enumerate() {
            v.set_simd(i as u32, q)?;
        }
        v.set_sys_reg(sysreg::SP_EL0, c.sp)?;
        v.set_sys_reg(sysreg::TPIDR_EL0, c.tpidr)?;
        v.set_reg(HV_REG_FPSR, u64::from(c.fpsr))?;
        v.set_reg(HV_REG_FPCR, u64::from(c.fpcr))?;
        Ok(())
    }

    /// Claims `key` for this vCPU (`sched` locked): what [`Runner::load`]
    /// needs to put it into the vCPU.
    fn claim(&self, sched: &mut Sched, key: TaskKey) -> (Current, Claimed) {
        sched.min_runtime = sched.min_runtime.max(sched.tasks[&key].runtime);
        let task = sched.tasks.get_mut(&key).expect("a runnable task");
        task.on = Some(self.index);
        let context = if task.loaded == Some(self.index) {
            None
        } else {
            task.saved.take()
        };
        let x0 = task.x0.take();
        task.loaded = Some(self.index);
        let space = &sched.spaces[&task.space];
        let current = Current {
            key,
            root: space.root,
            asid: space.asid,
            pc: task.pc,
            pstate: task.pstate,
        };
        let previous = self.loaded.filter(|&loaded| loaded != key);
        (
            current,
            Claimed {
                context,
                x0,
                previous,
            },
        )
    }

    /// Puts a claimed task into the vCPU (the scheduler not locked): the
    /// registers of the task loaded before it go back to that task first.
    fn load(
        &mut self,
        smp: &Smp,
        current: &Current,
        claimed: Claimed,
    ) -> Result<(), PlatformError> {
        if let Some(previous) = claimed.previous {
            self.unload(smp, previous)?;
        }
        if let Some(context) = claimed.context {
            self.write_vcpu(&context).map_err(host_err)?;
        }
        if let Some(x0) = claimed.x0 {
            self.vcpu.set_reg(0, x0).map_err(host_err)?;
        }
        self.loaded = Some(current.key);
        self.set_space(current.root, current.asid)
    }

    /// Saves the vCPU's registers into `key`, if they are still its. A
    /// system call's result that waited for this vCPU to run the task
    /// goes into them: whoever reads the task's registers next (the core,
    /// for a signal frame) must see it.
    ///
    /// If the vCPU cannot be read, the task has no registers any more and
    /// ends ([`Trap::Gone`]); it must not stay loaded in a vCPU that
    /// nothing will ask again.
    fn unload(&mut self, smp: &Smp, key: TaskKey) -> Result<(), PlatformError> {
        let mut context = match self.read_vcpu() {
            Ok(context) => context,
            Err(err) => {
                if self.loaded == Some(key) {
                    self.loaded = None;
                }
                let sched = smp.lock();
                if sched
                    .tasks
                    .get(&key)
                    .is_some_and(|task| task.loaded == Some(self.index))
                {
                    log::error!(
                        "HVF platform: vCPU {}: {err}; task {key}, loaded in it, ends",
                        self.index
                    );
                    smp.lose(sched, key);
                } else {
                    smp.wake_loop();
                }
                return Err(host_err(err));
            }
        };
        let mut sched = smp.lock();
        if let Some(task) = sched.tasks.get_mut(&key) {
            if task.loaded == Some(self.index) {
                if let Some(x0) = task.x0.take() {
                    context.x[0] = x0;
                }
                task.saved = Some(context);
                task.loaded = None;
                // Waiting to run, now on any vCPU.
                if task.state == State::Runnable && task.on.is_none() {
                    smp.wake_for(&mut sched, key);
                }
            }
        }
        if self.loaded == Some(key) {
            self.loaded = None;
        }
        // The event loop may wait for it (`HvfPlatform::unload_from`).
        smp.wake_loop();
        drop(sched);
        Ok(())
    }

    /// Points `TTBR0_EL1` at a space.
    ///
    /// Each space has its own ASID, so the TLB may hold entries of every
    /// space at once and a switch needs no flush. An entry is stale only
    /// if a space's tables changed since it was cached, and every such
    /// change makes every vCPU invalidate it before it runs an app again
    /// ([`Smp::invalidate`]). An ASID is reused only after its space is
    /// gone, which freed the space's tables and so flushes too. Spaces
    /// that found no free ASID share ASID 0 and run on vCPU 0 only:
    /// switching between two of them flushes the whole TLB (of every CPU:
    /// `tlbi vmalle1is`), so no other vCPU, wherever it runs, could meet
    /// an entry of the one before.
    fn set_space(&mut self, root: u64, asid: u16) -> Result<(), PlatformError> {
        let ttbr0 = root | u64::from(asid) << 48;
        if self.ttbr0 != ttbr0 {
            self.vcpu
                .set_sys_reg(sysreg::TTBR0_EL1, ttbr0)
                .map_err(host_err)?;
            self.ttbr0 = ttbr0;
        }
        if asid == 0 {
            if self.asid0_root.is_some_and(|other| other != root) {
                self.flush = true;
            }
            self.asid0_root = Some(root);
        }
        Ok(())
    }

    /// Sets the timer that ends the next run at `deadline`.
    fn arm_timer(&mut self, smp: &Smp, deadline: Option<Instant>) -> Result<(), sys::HvError> {
        match deadline {
            None => {
                if self.timer_armed {
                    self.vcpu.set_sys_reg(sysreg::CNTV_CTL_EL0, 0)?;
                    self.timer_armed = false;
                }
            }
            // Armed for it already (a trap since does not disarm it).
            Some(deadline) if self.timer_armed && self.armed_for == Some(deadline) => {}
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                let ticks = (left.as_nanos() * u128::from(smp.ticks_per_sec) / 1_000_000_000)
                    .min(u128::from(u64::MAX / 2)) as u64;
                let cval = self.vcpu.guest_counter()?.saturating_add(ticks);
                self.vcpu.set_sys_reg(sysreg::CNTV_CVAL_EL0, cval)?;
                // ENABLE, interrupt not masked: the framework exits with
                // HV_EXIT_REASON_VTIMER_ACTIVATED when it fires.
                self.vcpu.set_sys_reg(sysreg::CNTV_CTL_EL0, 1)?;
                self.vcpu.set_vtimer_mask(false)?;
                self.timer_armed = true;
                self.armed_for = Some(deadline);
            }
        }
        Ok(())
    }

    /// Starts a run of the space at `root`: the epoch goes odd, and the
    /// invalidations other threads left for this vCPU are taken.
    fn begin_run(&mut self, smp: &Smp, root: u64) {
        let slot = &smp.slots[self.index];
        slot.root.store(root, SeqCst);
        slot.epoch.fetch_add(1, SeqCst);
        match slot.pending.swap(PENDING_NONE, SeqCst) {
            PENDING_NONE => {}
            PENDING_ALL => self.flush = true,
            page => match self.flush_page {
                None => self.flush_page = Some(page),
                Some(same) if same == page => {}
                Some(_) => self.flush = true,
            },
        }
    }

    /// Points the vCPU at the app: straight to EL0, or through one of the
    /// shim's flush routines if page tables changed.
    fn enter(&mut self, smp: &Smp, current: &Current) -> Result<(), sys::HvError> {
        let (pc, pstate) = (current.pc, current.pstate & layout::PSTATE_APP_MASK);
        if self.flush {
            if current.asid != 0 {
                self.asid0_root = None;
            }
            self.vcpu.set_sys_reg(sysreg::ELR_EL1, pc)?;
            self.vcpu.set_sys_reg(sysreg::SPSR_EL1, pstate)?;
            self.vcpu.set_reg(HV_REG_PC, SHIM_VA + FLUSH_OFFSET)?;
            self.vcpu.set_reg(HV_REG_CPSR, layout::PSTATE_EL1H_MASKED)?;
            self.flush = false;
            self.flush_page = None;
            smp.flushes_all.fetch_add(1, SeqCst);
        } else if let Some(operand) = self.flush_page.take() {
            // The routine takes its operand in x0 and gives the app its
            // own back from TPIDR_EL1.
            let x0 = self.vcpu.reg(0)?;
            self.vcpu.set_sys_reg(sysreg::TPIDR_EL1, x0)?;
            self.vcpu.set_reg(0, operand)?;
            self.vcpu.set_sys_reg(sysreg::ELR_EL1, pc)?;
            self.vcpu.set_sys_reg(sysreg::SPSR_EL1, pstate)?;
            self.vcpu.set_reg(HV_REG_PC, SHIM_VA + FLUSH_PAGE_OFFSET)?;
            self.vcpu.set_reg(HV_REG_CPSR, layout::PSTATE_EL1H_MASKED)?;
            smp.flushes_page.fetch_add(1, SeqCst);
        } else {
            self.vcpu.set_reg(HV_REG_PC, pc)?;
            self.vcpu.set_reg(HV_REG_CPSR, pstate)?;
        }
        Ok(())
    }

    /// Runs the loaded task until it traps, the deadline passes or the
    /// vCPU is kicked. Takes no lock but the tables' (for a page fault).
    fn run(
        &mut self,
        smp: &Smp,
        current: &mut Current,
        deadline: Option<Instant>,
    ) -> Result<Stop, PlatformError> {
        self.arm_timer(smp, deadline).map_err(host_err)?;
        // Faults on a page that is ready, in a row: (page, count).
        let mut retries = (u64::MAX, 0u32);
        let mut reenter = true;
        // Stopped from outside while in a vector: the run ends once the
        // vector's exception is handled.
        let mut stopped = false;
        loop {
            self.begin_run(smp, current.root);
            let entered = if reenter {
                self.enter(smp, current)
            } else {
                Ok(())
            };
            let exit = entered.and_then(|()| self.vcpu.run());
            smp.slots[self.index].epoch.fetch_add(1, SeqCst);
            let exit = exit.map_err(host_err)?;
            reenter = true;
            let stop = match exit.reason {
                HV_EXIT_REASON_CANCELED | HV_EXIT_REASON_VTIMER_ACTIVATED => {
                    if exit.reason == HV_EXIT_REASON_VTIMER_ACTIVATED {
                        self.vcpu
                            .set_sys_reg(sysreg::CNTV_CTL_EL0, 0)
                            .map_err(host_err)?;
                        self.timer_armed = false;
                    }
                    match self.interrupted_at(current)? {
                        Interrupted::Settled => Some(Stop::Settled),
                        // In a vector, about to leave the VM with an
                        // exception of the app: let it, with the vCPU's
                        // state as it is.
                        Interrupted::InVector => {
                            reenter = false;
                            stopped = true;
                            None
                        }
                        Interrupted::Lost(why) => Some(Stop::Gone(why)),
                    }
                }
                HV_EXIT_REASON_EXCEPTION => self.on_exception(smp, current, &exit, &mut retries)?,
                other => Some(Stop::Gone(format!("unexpected exit reason {other}"))),
            };
            if let Some(stop) = stop {
                return Ok(stop);
            }
            // The exception needed nothing from the core (a page that got
            // memory, a skipped instruction), but the timer that ended the
            // slice, or the kick, is spent: the run ends here, or the app
            // would go on with neither.
            if stopped && reenter {
                return Ok(Stop::Settled);
            }
        }
    }

    /// Saves where the app was when the vCPU was stopped from outside (by
    /// `hv_vcpus_exit` or the timer), which can be anywhere.
    fn interrupted_at(&mut self, current: &mut Current) -> Result<Interrupted, PlatformError> {
        let cpsr = self.vcpu.reg(HV_REG_CPSR).map_err(host_err)?;
        let pc = self.vcpu.reg(HV_REG_PC).map_err(host_err)?;
        if cpsr & 0xf == 0 {
            // In the app (EL0t).
            current.pc = pc;
            current.pstate = cpsr & layout::PSTATE_APP_MASK;
            return Ok(Interrupted::Settled);
        }
        if (SHIM_VA..SHIM_VA + FLUSH_OFFSET).contains(&pc) {
            return Ok(Interrupted::InVector);
        }
        if (SHIM_VA + FLUSH_PAGE_OFFSET..SHIM_VA + PAGE).contains(&pc) {
            // In the page flush routine: x0 may still be its operand. The
            // app's own is in TPIDR_EL1; it starts over from `pc`, with a
            // whole flush.
            let x0 = self.vcpu.sys_reg(sysreg::TPIDR_EL1).map_err(host_err)?;
            self.vcpu.set_reg(0, x0).map_err(host_err)?;
            self.flush = true;
            return Ok(Interrupted::Settled);
        }
        if (SHIM_VA + FLUSH_OFFSET..SHIM_VA + PAGE).contains(&pc) {
            // In the flush routine, before the app ran: it starts over
            // from `pc`, flushing again.
            self.flush = true;
            return Ok(Interrupted::Settled);
        }
        Ok(Interrupted::Lost(format!(
            "stopped at EL1 outside the shim, pc {pc:#x} cpsr {cpsr:#x}"
        )))
    }

    /// Decodes an exception exit. `None` means: resume the app.
    /// `retries` counts faults in a row on a page that was ready.
    fn on_exception(
        &mut self,
        smp: &Smp,
        current: &mut Current,
        exit: &HvVcpuExit,
        retries: &mut (u64, u32),
    ) -> Result<Option<Stop>, PlatformError> {
        let v = &self.vcpu;
        let (esr, far, pc) = match exit::hvc_immediate(exit.syndrome) {
            // `hvc` is undefined at EL0, so this came from a vector of the
            // shim: the registers are the app's, ELR/SPSR/ESR/FAR say what
            // happened.
            Some(slot) => {
                let pc = v.sys_reg(sysreg::ELR_EL1).map_err(host_err)?;
                let pstate = v.sys_reg(sysreg::SPSR_EL1).map_err(host_err)?;
                current.pc = pc;
                current.pstate = pstate & layout::PSTATE_APP_MASK;
                match slot {
                    layout::VECTOR_LOWER_SYNC => {}
                    layout::VECTOR_LOWER_IRQ | layout::VECTOR_LOWER_FIQ => {
                        // Nothing raises interrupts in this VM; harmless.
                        return Ok(Some(Stop::Trap(Trap::Interrupted)));
                    }
                    slot => {
                        return Ok(Some(Stop::Gone(format!(
                            "exception at vector {slot} (SError, or one taken at EL1), \
                             pc {pc:#x} spsr {pstate:#x}"
                        ))));
                    }
                }
                let esr = v.sys_reg(sysreg::ESR_EL1).map_err(host_err)?;
                let far = match exit::exception_class(esr) {
                    0x20 | 0x22 | 0x24 => v.sys_reg(sysreg::FAR_EL1).map_err(host_err)?,
                    0x26 => v.sys_reg(sysreg::SP_EL0).map_err(host_err)?,
                    _ => 0,
                };
                (esr, far, pc)
            }
            None => {
                // Taken straight to EL2. From the app (EL0t) it is one the
                // framework traps (`wfi`, `wfe`); anything else, or a fault
                // in stage 2, means the VM is not as this platform built it.
                let cpsr = v.reg(HV_REG_CPSR).map_err(host_err)?;
                let pc = v.reg(HV_REG_PC).map_err(host_err)?;
                let class = exit::exception_class(exit.syndrome);
                if cpsr & 0xf != 0 || matches!(class, 0x20 | 0x24) {
                    return Ok(Some(Stop::Gone(format!(
                        "exit to the host with syndrome {:#x} at pc {pc:#x}, cpsr {cpsr:#x}, \
                         address {:#x} (guest-physical {:#x})",
                        exit.syndrome, exit.virtual_address, exit.physical_address
                    ))));
                }
                current.pc = pc;
                current.pstate = cpsr & layout::PSTATE_APP_MASK;
                (exit.syndrome, exit.virtual_address, pc)
            }
        };
        match exit::decode(esr, far, pc) {
            AppException::Syscall => {
                let mut regs = [0u64; 7];
                for (i, reg) in regs.iter_mut().enumerate().take(6) {
                    *reg = v.reg(i as u32).map_err(host_err)?;
                }
                regs[6] = v.reg(8).map_err(host_err)?;
                let trap = SyscallTrap {
                    nr: regs[6],
                    args: [regs[0], regs[1], regs[2], regs[3], regs[4], regs[5]],
                };
                Ok(Some(Stop::Trap(Trap::Syscall(trap))))
            }
            AppException::Skip => {
                current.pc = current.pc.wrapping_add(4);
                Ok(None)
            }
            AppException::Fault(fault) => Ok(Some(Stop::Trap(Trap::Fault(fault)))),
            AppException::Translation { addr, access } => {
                Ok(self.page_fault(smp, current, addr, access, SEGV_MAPERR, retries))
            }
            AppException::Permission { addr, access } => {
                Ok(self.page_fault(smp, current, addr, access, SEGV_ACCERR, retries))
            }
        }
    }

    /// A translation or permission fault at `addr`: memory on first touch,
    /// a copy for a copy-on-write page, or `SIGSEGV` (with `code` when the
    /// page is not mapped, or allows the access after all).
    fn page_fault(
        &mut self,
        smp: &Smp,
        current: &Current,
        addr: u64,
        access: Access,
        code: i32,
        retries: &mut (u64, u32),
    ) -> Option<Stop> {
        let fault = |code| {
            Stop::Trap(Trap::Fault(Fault {
                signal: 11,
                code,
                addr: Some(addr),
            }))
        };
        let root = current.root;
        match smp.change(root, current.asid, |phys| phys.demand(root, addr, access)) {
            Demand::Filled => None,
            // The TLB may still hold what the page was before it changed
            // (here or by another vCPU, as when two threads touch a new
            // page at once and this one came second): invalidate and
            // retry, a few times. That page only at first; the whole TLB
            // if that did not help.
            Demand::Present if retries.0 != addr >> 12 || retries.1 < 4 => {
                *retries = match *retries {
                    (page, n) if page == addr >> 12 => (page, n + 1),
                    _ => (addr >> 12, 1),
                };
                let operand = page_operand(current.asid, addr);
                match self.flush_page {
                    None if retries.1 == 1 => self.flush_page = Some(operand),
                    Some(same) if same == operand && retries.1 == 1 => {}
                    _ => self.flush = true,
                }
                None
            }
            Demand::Present | Demand::Unmapped => Some(fault(code)),
            Demand::Denied => Some(fault(SEGV_ACCERR)),
            // The sandbox's memory is used up: this process ends, as the
            // OOM killer would end it on Linux, and the others go on.
            Demand::NoMemory => {
                log::warn!(
                    "HVF platform: task {}: out of memory at {addr:#x}; killing it",
                    current.key
                );
                Some(Stop::Trap(Trap::Fault(Fault {
                    signal: SIGKILL,
                    code: SI_KERNEL,
                    addr: Some(addr),
                })))
            }
        }
    }
}

/// What claiming a task found ([`Runner::claim`]).
struct Claimed {
    /// Its registers, unless they are in this vCPU already.
    context: Option<Box<Aarch64Context>>,
    x0: Option<u64>,
    /// The task loaded in this vCPU before.
    previous: Option<TaskKey>,
}

/// After a run: the task's position and runtime back into the scheduler,
/// and the vCPU lets go of it.
fn settle(sched: &mut Sched, current: &Current, started: Instant) {
    if let Some(task) = sched.tasks.get_mut(&current.key) {
        task.pc = current.pc;
        task.pstate = current.pstate;
        task.on = None;
        let ran = started.elapsed().as_nanos() as u64;
        task.runtime = task.runtime.saturating_add(ran);
    }
}

/// The thread of vCPU `index` (not 0): runs the tasks the scheduler gives
/// it until the platform goes.
fn vcpu_thread(smp: Arc<Smp>, mut runner: Runner) {
    let index = runner.index;
    // Polled for work since it last ran a task.
    let mut spun = false;
    // The vCPU failed: it runs no task any more.
    let mut broken = false;
    let mut sched = smp.lock();
    loop {
        if sched.quit {
            break;
        }
        if let Some(key) = sched.unload[index].take() {
            if runner.loaded == Some(key) {
                drop(sched);
                if let Err(err) = runner.unload(&smp, key) {
                    log::error!("HVF platform: vCPU {index}: {err}");
                    broken = true;
                }
                sched = smp.lock();
            }
            smp.wake_loop();
            continue;
        }
        let picked = if sched.killed || broken {
            None
        } else {
            sched.pick(index)
        };
        let Some((key, _)) = picked else {
            // Idle: poll for a while, then sleep. Wakers see it as idle
            // from here on.
            sched.idle[index] = !broken;
            let slot = &smp.slots[index];
            let wakes = slot.wakes.load(SeqCst);
            if !spun && !broken {
                drop(sched);
                spin_until(SPIN, None, || slot.wakes.load(SeqCst) != wakes);
                sched = smp.lock();
                spun = true;
            }
            if slot.wakes.load(SeqCst) == wakes && !sched.quit {
                sched = smp.vcpu_cvs[index]
                    .wait(sched)
                    .unwrap_or_else(|e| e.into_inner());
            }
            sched.idle[index] = false;
            continue;
        };
        spun = false;
        let (mut current, claimed) = runner.claim(&mut sched, key);
        drop(sched);
        let started = Instant::now();
        let slice_end = runner.slice_end(key);
        let result = runner
            .load(&smp, &current, claimed)
            .and_then(|()| runner.run(&smp, &mut current, slice_end));
        sched = smp.lock();
        settle(&mut sched, &current, started);
        let Some(task) = sched.tasks.get_mut(&key) else {
            continue;
        };
        if task.kill {
            // `kill` waits for this.
            smp.wake_loop();
            continue;
        }
        let event = match result {
            Ok(Stop::Trap(trap)) => {
                task.state = State::Stopped;
                Some(trap)
            }
            Ok(Stop::Settled) if task.interrupt => {
                task.interrupt = false;
                task.state = State::Stopped;
                Some(Trap::Interrupted)
            }
            Ok(Stop::Settled) => {
                // The slice ended or something kicked it: still runnable,
                // and maybe the event loop's vCPU is idle while it waits.
                smp.wake_loop();
                None
            }
            Ok(Stop::Gone(why)) => {
                log::error!("HVF platform: task {key}: {why}; ending it");
                runner.loaded = None;
                smp.lose(sched, key);
                sched = smp.lock();
                None
            }
            Err(err) => {
                // The vCPU failed: the task goes, and this vCPU runs
                // nothing any more. Its thread stays until the platform
                // goes, as the others do.
                log::error!("HVF platform: vCPU {index}: {err}; task {key} ends");
                runner.loaded = None;
                broken = true;
                smp.lose(sched, key);
                sched = smp.lock();
                None
            }
        };
        if let Some(trap) = event {
            sched.events.push_back(Event { task: key, trap });
            smp.notify_loop(&sched);
        }
    }
    drop(sched);
    // The vCPU is destroyed here, on its thread.
    drop(runner);
}

/// The Hypervisor.framework platform. See the crate documentation.
///
/// One per process (the framework allows one VM per process), used from
/// the thread that made it: vCPU 0 belongs to that thread and runs in
/// [`Platform::wait`]; the others have threads of their own.
pub struct HvfPlatform {
    // Field order is drop order: vCPU 0, then the VM (which removes the
    // stage-2 mappings), then the memory behind them. `Drop` ends the
    // other vCPUs' threads first.
    runner: Runner,
    threads: Vec<JoinHandle<()>>,
    vm: Vm,
    smp: Arc<Smp>,
    _shim: HostMem,
    info: AddressSpaceInfo,
    cpu: CpuInfo,
    vcpus: usize,
    /// Since when what vCPU 0 would run next has waited ([`Self::let_go`]).
    held_since: Option<Instant>,
    _not_send: PhantomData<*const ()>,
}

/// `AT_HWCAP` from the ID registers the vCPU reports, limited to features
/// that need nothing from the kernel. Not reported: `CPUID` (EL0 reads of
/// ID registers are not emulated), pointer authentication (not enabled),
/// SVE and SME.
fn hwcap(pfr0: u64, isar0: u64, isar1: u64) -> u64 {
    let field = |reg: u64, shift: u32| (reg >> shift) & 0xf;
    let mut cap = 0;
    let mut set = |bit: u32, on: bool| {
        if on {
            cap |= 1 << bit;
        }
    };
    let fp = field(pfr0, 16);
    let simd = field(pfr0, 20);
    set(0, fp != 0xf); // FP
    set(1, simd != 0xf); // ASIMD
    set(3, field(isar0, 4) >= 1); // AES
    set(4, field(isar0, 4) >= 2); // PMULL
    set(5, field(isar0, 8) >= 1); // SHA1
    set(6, field(isar0, 12) >= 1); // SHA2
    set(7, field(isar0, 16) >= 1); // CRC32
    set(8, field(isar0, 20) >= 2); // ATOMICS
    set(9, fp == 1); // FPHP
    set(10, simd == 1); // ASIMDHP
    set(12, field(isar0, 28) >= 1); // ASIMDRDM
    set(13, field(isar1, 12) >= 1); // JSCVT
    set(14, field(isar1, 16) >= 1); // FCMA
    set(15, field(isar1, 20) >= 1); // LRCPC
    set(16, field(isar1, 0) >= 1); // DCPOP
    set(17, field(isar0, 32) >= 1); // SHA3
    set(20, field(isar0, 44) >= 1); // ASIMDDP
    set(21, field(isar0, 12) >= 2); // SHA512
    set(23, field(isar0, 48) >= 1); // ASIMDFHM
    set(24, field(pfr0, 48) >= 1); // DIT
    set(26, field(isar1, 20) >= 2); // ILRCPC
    set(27, field(isar0, 52) >= 1); // FLAGM
    set(29, field(isar1, 36) >= 1); // SB
    cap
}

/// How many vCPUs to make: as asked, or the default, within the bounds.
fn vcpu_count(asked: usize, framework_max: u32) -> usize {
    let wanted = match asked {
        0 => std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(DEFAULT_VCPUS),
        n => n,
    };
    wanted
        .min(MAX_VCPUS)
        .min(framework_max.max(1) as usize)
        .max(1)
}

impl HvfPlatform {
    /// A platform for one sandbox, with its VM and vCPUs. Fails with
    /// `PermissionDenied` when the executable lacks the hypervisor
    /// entitlement, and with `ResourceBusy` while another platform of this
    /// process exists.
    pub fn new(config: HvfConfig) -> io::Result<HvfPlatform> {
        let round = |n: u64| {
            n.max(sys::HOST_PAGE as u64)
                .next_multiple_of(sys::HOST_PAGE as u64)
        };
        let memory = round(config.memory);
        let table_memory = round(config.table_memory);
        if layout::TABLES_IPA + table_memory > layout::RAM_IPA || memory > 32 << 30 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HVF platform: at most 32 GiB of memory and 3 GiB of page tables",
            ));
        }
        if config.vcpus > MAX_VCPUS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("HVF platform: at most {MAX_VCPUS} vCPUs"),
            ));
        }
        let vm = Vm::create()?;
        let shim = HostMem::new(layout::SHIM_REGION as usize)?;
        let tables = HostMem::new(table_memory as usize)?;
        let ram = HostMem::new(memory as usize)?;
        let mut shim = shim;
        let code = layout::shim_code();
        shim.slice_mut(0, code.len()).copy_from_slice(&code);
        shim.sync_icache(0, code.len());
        // SAFETY: each region lives in `HvfPlatform` until after the VM is
        // destroyed (field order), and holds only what the guest may see:
        // the shim, the guest's page tables (read only) and app memory.
        unsafe {
            vm.map(
                shim.ptr(),
                layout::SHIM_IPA,
                shim.len(),
                HV_MEMORY_READ | HV_MEMORY_EXEC,
            )?;
            vm.map(
                tables.ptr(),
                layout::TABLES_IPA,
                tables.len(),
                HV_MEMORY_READ,
            )?;
            vm.map(
                ram.ptr(),
                layout::RAM_IPA,
                ram.len(),
                HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
            )?;
        }
        let mut phys = Phys::new(tables, ram);
        let shim_root = phys
            .shim_space()
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "page tables"))?;
        let vcpus = vcpu_count(config.vcpus, vm.max_vcpus().unwrap_or(1));
        if config.vcpus > vcpus {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("HVF platform: this host allows at most {vcpus} vCPUs"),
            ));
        }
        let vcpu = Vcpu::create(vm.token())?;

        let mmfr0 = vcpu.sys_reg(sysreg::ID_AA64MMFR0_EL1)?;
        if (mmfr0 >> 28) & 0xf == 0xf {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HVF platform: the vCPU does not support 4 KiB translation granules",
            ));
        }
        // The guest-physical layout fits in 36 bits; use what the vCPU has
        // up to 48 (`IPS` takes the `PARange` encoding).
        let ips = (mmfr0 & 0xf).min(5);
        let asid16 = (mmfr0 >> 4) & 0xf == 2;
        let cpu = CpuInfo {
            hwcap: hwcap(
                vcpu.sys_reg(sysreg::ID_AA64PFR0_EL1)?,
                vcpu.sys_reg(sysreg::ID_AA64ISAR0_EL1)?,
                vcpu.sys_reg(sysreg::ID_AA64ISAR1_EL1)?,
            ),
            hwcap2: 0,
        };
        let tcr = layout::tcr_el1(ips, asid16);
        set_up(&vcpu, tcr, shim_root)?;
        let mut timebase = sys::MachTimebaseInfo::default();
        sys::timebase(&mut timebase);
        let ticks_per_sec = if timebase.numer == 0 {
            24_000_000
        } else {
            1_000_000_000 * u64::from(timebase.denom) / u64::from(timebase.numer)
        };
        let slots = (0..vcpus)
            .map(|_| Slot {
                kicker: OnceLock::new(),
                wakes: AtomicU64::new(0),
                epoch: AtomicU64::new(0),
                root: AtomicU64::new(0),
                pending: AtomicU64::new(PENDING_NONE),
            })
            .collect::<Vec<_>>();
        let _ = slots[0].kicker.set(vcpu.kicker());
        let smp = Arc::new(Smp {
            sched: Mutex::new(Sched {
                tasks: BTreeMap::new(),
                spaces: HashMap::new(),
                events: VecDeque::new(),
                next_key: 1,
                next_space: 1,
                free_asids: Vec::new(),
                next_asid: 1,
                asid_limit: if asid16 { 1 << 16 } else { 1 << 8 },
                min_runtime: 0,
                woken: false,
                loop_in_run: false,
                killed: false,
                quit: false,
                dumped: false,
                unload: vec![None; vcpus],
                idle: vec![false; vcpus],
            }),
            loop_cv: Condvar::new(),
            loop_wakes: AtomicU64::new(0),
            vcpu_cvs: (0..vcpus).map(|_| Condvar::new()).collect(),
            phys: Mutex::new(phys),
            slots,
            ticks_per_sec,
            flushes_all: AtomicU64::new(0),
            flushes_page: AtomicU64::new(0),
        });
        let mut platform = HvfPlatform {
            runner: Runner::new(0, vcpu),
            threads: Vec::new(),
            vm,
            smp,
            _shim: shim,
            info: AddressSpaceInfo {
                page_size: PAGE,
                min_addr: MIN_ADDR,
                max_addr: MAX_ADDR,
                reserved: Vec::new(),
            },
            cpu,
            vcpus,
            held_since: None,
            _not_send: PhantomData,
        };
        // The other vCPUs, each made by its own thread (a vCPU belongs to
        // the thread that made it). Made now, before the kernel process
        // hardens itself, so that it never needs to make a thread or a
        // vCPU afterwards.
        let token = platform.vm.token();
        for index in 1..vcpus {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let smp = Arc::clone(&platform.smp);
            let thread = std::thread::Builder::new()
                .name(format!("hellovm-vcpu{index}"))
                .spawn(move || {
                    let made = Vcpu::create(token).and_then(|vcpu| {
                        set_up(&vcpu, tcr, shim_root)?;
                        Ok(vcpu)
                    });
                    match made {
                        Ok(vcpu) => {
                            let _ = smp.slots[index].kicker.set(vcpu.kicker());
                            let _ = ready_tx.send(Ok(()));
                            vcpu_thread(smp, Runner::new(index, vcpu));
                        }
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                        }
                    }
                })?;
            platform.threads.push(thread);
            match ready_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => {
                    return Err(io::Error::other("HVF platform: a vCPU thread ended"));
                }
            }
        }
        Ok(platform)
    }

    /// A handle that ends every app from any thread.
    pub fn killer(&self) -> AppKiller {
        AppKiller {
            smp: Arc::clone(&self.smp),
        }
    }

    /// App memory and page-table memory in use, in bytes.
    pub fn memory_in_use(&self) -> (u64, u64) {
        let phys = self.smp.phys();
        (phys.ram_in_use(), phys.tables_in_use())
    }

    /// How often TLB entries were invalidated so far (by any vCPU).
    pub fn flushes(&self) -> Flushes {
        self.smp.flushes()
    }

    /// How many vCPUs the platform runs apps on.
    pub fn vcpus(&self) -> usize {
        self.vcpus
    }

    fn lock(&self) -> MutexGuard<'_, Sched> {
        self.smp.lock()
    }

    /// Makes vCPU `index` (not 0) save the registers of `key`, loaded in
    /// it, into the task. The vCPU is not running anything else: it
    /// would have saved them before.
    fn unload_from<'a>(
        &'a self,
        mut sched: MutexGuard<'a, Sched>,
        index: usize,
        key: TaskKey,
    ) -> MutexGuard<'a, Sched> {
        while sched
            .tasks
            .get(&key)
            .is_some_and(|task| task.loaded == Some(index))
        {
            sched.unload[index] = Some(key);
            self.smp.wake(index);
            sched = self.smp.wait_loop_for(sched, Duration::from_millis(10));
        }
        sched
    }

    /// With other vCPUs, when `wait` returns without running what vCPU 0
    /// would run next: once that task has waited for [`HOLD`], it goes to
    /// another vCPU (its registers saved if they are in vCPU 0), so that
    /// a busy event loop does not keep it from running. Before that it
    /// stays, since a task on vCPU 0 makes system calls without moving
    /// between threads.
    fn let_go(&mut self, sched: &mut Sched) -> Result<(), PlatformError> {
        if self.vcpus == 1 {
            return Ok(());
        }
        let Some((next, _)) = sched.pick(0) else {
            self.held_since = None;
            return Ok(());
        };
        let since = *self.held_since.get_or_insert_with(Instant::now);
        if since.elapsed() < HOLD {
            return Ok(());
        }
        self.held_since = None;
        if self.runner.loaded == Some(next) {
            let context = self.runner.read_vcpu().map_err(host_err)?;
            let task = sched.tasks.get_mut(&next).expect("picked");
            task.saved = Some(context);
            task.loaded = None;
            self.runner.loaded = None;
        }
        self.smp.wake_for(sched, next);
        Ok(())
    }

    /// Ends a task the platform cannot run any more, as [`Trap::Gone`].
    fn gone(&mut self, key: TaskKey, why: &str) -> Event {
        log::error!("HVF platform: task {key}: {why}; ending it");
        if self.runner.loaded == Some(key) {
            self.runner.loaded = None;
        }
        let sched = self.lock();
        self.smp.remove(sched, key);
        Event {
            task: key,
            trap: Trap::Gone,
        }
    }

    /// After the killer: waits until no other vCPU runs a task, then
    /// reports each task as gone.
    fn end_all(&mut self, deadline: Option<Instant>) -> Option<Event> {
        let smp = Arc::clone(&self.smp);
        let mut sched = smp.lock();
        if log::log_enabled!(log::Level::Debug) && !std::mem::replace(&mut sched.dumped, true) {
            for (key, task) in &sched.tasks {
                log::debug!(
                    "HVF platform: killed: task {key}: space {} {:?} pc {:#x} runtime {} ns, \
                     on vCPU {:?}, loaded in {:?}, interrupt {}",
                    task.space,
                    task.state,
                    task.pc,
                    task.runtime,
                    task.on,
                    task.loaded,
                    task.interrupt
                );
            }
            for (index, slot) in smp.slots.iter().enumerate() {
                log::debug!(
                    "HVF platform: killed: vCPU {index}: epoch {}, root {:#x}, pending {:#x}",
                    slot.epoch.load(SeqCst),
                    slot.root.load(SeqCst),
                    slot.pending.load(SeqCst)
                );
            }
        }
        while sched.tasks.values().any(|task| task.on.is_some()) {
            for slot in &self.smp.slots[1..] {
                slot.kick();
            }
            sched = self.smp.wait_loop_for(sched, Duration::from_millis(1));
        }
        let Some(&key) = sched.tasks.keys().next() else {
            // Nothing left: a waker or the deadline.
            loop {
                if std::mem::take(&mut sched.woken) {
                    return None;
                }
                match deadline {
                    None => sched = self.smp.wait_loop(sched),
                    Some(deadline) => {
                        let left = deadline.saturating_duration_since(Instant::now());
                        if left.is_zero() {
                            return None;
                        }
                        sched = self.smp.wait_loop_for(sched, left);
                    }
                }
            }
        };
        if self.runner.loaded == Some(key) {
            self.runner.loaded = None;
        }
        smp.remove(sched, key);
        Some(Event {
            task: key,
            trap: Trap::Gone,
        })
    }

    /// Nothing for vCPU 0 to run: waits for an event, a waker, a task
    /// another vCPU let go, or the deadline. Returns whether something
    /// came before the deadline.
    fn idle(&self, deadline: Option<Instant>) -> bool {
        let mut sched = self.lock();
        let mut spun = self.vcpus == 1;
        loop {
            if sched.woken || sched.killed || !sched.events.is_empty() || sched.pick(0).is_some() {
                return true;
            }
            let wakes = self.smp.loop_wakes.load(SeqCst);
            if !spun {
                // Another vCPU's task may trap any moment: poll first.
                drop(sched);
                spin_until(SPIN, deadline, || self.smp.loop_wakes.load(SeqCst) != wakes);
                sched = self.lock();
                spun = true;
                continue;
            }
            if self.smp.loop_wakes.load(SeqCst) != wakes {
                continue;
            }
            match deadline {
                None => sched = self.smp.wait_loop(sched),
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return false;
                    }
                    sched = self.smp.wait_loop_for(sched, left);
                }
            }
        }
    }

    fn set_x0(&mut self, key: TaskKey, value: u64) -> Result<(), PlatformError> {
        let mut sched = self.lock();
        let task = sched.task(key)?;
        match task.loaded {
            Some(0) => self.runner.vcpu.set_reg(0, value).map_err(host_err),
            Some(_) => {
                task.x0 = Some(value);
                Ok(())
            }
            None => {
                task.saved.as_mut().expect("saved registers").x[0] = value;
                Ok(())
            }
        }
    }

    fn stop_threads(&mut self) {
        {
            let mut sched = self.lock();
            sched.quit = true;
            for slot in &self.smp.slots {
                slot.kick();
            }
            self.smp.wake_all();
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl Platform for HvfPlatform {
    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn address_space(&self) -> AddressSpaceInfo {
        self.info.clone()
    }

    fn cpu_info(&self) -> CpuInfo {
        self.cpu
    }

    fn spawn(&mut self) -> Result<TaskKey, PlatformError> {
        let root = self
            .smp
            .phys()
            .new_space()
            .map_err(|err| mmu_err(err, 0, 0))?;
        let mut sched = self.lock();
        let space = sched.add_space(root);
        let key = sched.next_key;
        sched.next_key += 1;
        let Context::Aarch64(saved) = Context::zeroed(Arch::Aarch64) else {
            unreachable!("asked for aarch64");
        };
        let runtime = sched.min_runtime;
        sched.tasks.insert(
            key,
            Task {
                space,
                state: State::New,
                pc: 0,
                pstate: 0,
                saved: Some(saved),
                loaded: None,
                x0: None,
                on: None,
                interrupt: false,
                kill: false,
                runtime,
            },
        );
        Ok(key)
    }

    fn clone_task(
        &mut self,
        parent: TaskKey,
        share_memory: bool,
    ) -> Result<TaskKey, PlatformError> {
        let Context::Aarch64(saved) = self.context(parent)? else {
            unreachable!("aarch64 contexts only");
        };
        let mut sched = self.lock();
        let task = sched.stopped(parent)?;
        let (pc, pstate, space) = (task.pc, task.pstate, task.space);
        let space = if share_memory {
            sched.spaces.get_mut(&space).expect("task's space").users += 1;
            space
        } else {
            let (root, asid) = (sched.spaces[&space].root, sched.spaces[&space].asid);
            drop(sched);
            // The parent's writable pages become read only, also for its
            // other threads that run now (`Smp::change`).
            let copy = self
                .smp
                .change(root, asid, |phys| phys.fork(root))
                .map_err(|err| match err {
                    MmuError::NoMemory => PlatformError::NoResources(
                        "the sandbox's memory or page tables are used up".into(),
                    ),
                    MmuError::BadAddress => PlatformError::Violation("bad address space".into()),
                })?;
            sched = self.lock();
            sched.add_space(copy)
        };
        let key = sched.next_key;
        sched.next_key += 1;
        let runtime = sched.min_runtime;
        sched.tasks.insert(
            key,
            Task {
                space,
                state: State::Stopped,
                pc,
                pstate,
                saved: Some(saved),
                loaded: None,
                x0: None,
                on: None,
                interrupt: false,
                kill: false,
                runtime,
            },
        );
        Ok(key)
    }

    fn kill(&mut self, key: TaskKey) -> Result<(), PlatformError> {
        let smp = Arc::clone(&self.smp);
        let mut sched = smp.lock();
        // A task this platform already ended (reported as `Trap::Gone`)
        // is killed already.
        if !sched.tasks.contains_key(&key) && key < sched.next_key {
            return Ok(());
        }
        sched.task(key)?;
        // Running on another vCPU: it lets go of it first.
        while let Some(task) = sched.tasks.get_mut(&key) {
            let Some(index) = task.on else {
                break;
            };
            task.kill = true;
            smp.slots[index].kick();
            sched = smp.wait_loop_for(sched, Duration::from_millis(1));
        }
        if self.runner.loaded == Some(key) {
            self.runner.loaded = None;
        }
        smp.remove(sched, key);
        Ok(())
    }

    fn context(&mut self, key: TaskKey) -> Result<Context, PlatformError> {
        let mut sched = self.lock();
        let loaded = sched.stopped(key)?.loaded;
        let mut context = match loaded {
            Some(0) => self.runner.read_vcpu().map_err(host_err)?,
            Some(index) => {
                sched = self.unload_from(sched, index, key);
                let task = sched.stopped(key)?;
                task.saved.clone().expect("saved registers")
            }
            None => sched.stopped(key)?.saved.clone().expect("saved registers"),
        };
        let task = sched.stopped(key)?;
        context.pc = task.pc;
        context.pstate = task.pstate;
        Ok(Context::Aarch64(context))
    }

    fn set_context(&mut self, key: TaskKey, context: &Context) -> Result<(), PlatformError> {
        let Context::Aarch64(context) = context else {
            return Err(PlatformError::Unsupported("x86_64 contexts on aarch64"));
        };
        let mut sched = self.lock();
        let loaded = sched.stopped(key)?.loaded;
        if let Some(index) = loaded.filter(|&index| index != 0) {
            sched = self.unload_from(sched, index, key);
        }
        let task = sched.stopped(key)?;
        task.pc = context.pc;
        task.pstate = context.pstate & layout::PSTATE_APP_MASK;
        if task.loaded == Some(0) {
            return self.runner.write_vcpu(context).map_err(host_err);
        }
        task.saved = Some(context.clone());
        task.x0 = None;
        Ok(())
    }

    fn resume(&mut self, key: TaskKey, resume: Resume) -> Result<(), PlatformError> {
        self.lock().stopped(key)?;
        match resume {
            Resume::Start { entry, stack } => {
                let Context::Aarch64(mut context) = Context::zeroed(Arch::Aarch64) else {
                    unreachable!("asked for aarch64");
                };
                context.pc = entry;
                context.sp = stack;
                self.set_context(key, &Context::Aarch64(context))?;
            }
            Resume::Return(value) => self.set_x0(key, value as u64)?,
            Resume::Continue => {}
        }
        let mut sched = self.lock();
        let runtime = sched.task(key)?.runtime;
        let runtime = sched.catch_up(runtime);
        // What vCPU 0 would run next, before and after.
        let before = sched.pick(0).map(|(first, _)| first);
        let task = sched.task(key)?;
        task.state = State::Runnable;
        task.runtime = runtime;
        if self.vcpus > 1 {
            // The event loop's own vCPU runs what it would run next as
            // soon as `wait` is called, and a system call round trip on it
            // moves no task between threads: the other vCPUs get what it
            // will not run.
            let after = sched.pick(0).map(|(first, _)| first);
            if after != Some(key) {
                self.smp.wake_for(&mut sched, key);
            }
            if let Some(displaced) = before.filter(|&before| Some(before) != after) {
                self.smp.wake_for(&mut sched, displaced);
            }
        }
        Ok(())
    }

    fn interrupt(&mut self, key: TaskKey) -> Result<(), PlatformError> {
        let mut sched = self.lock();
        let task = sched.task(key)?;
        task.interrupt = true;
        if let Some(index) = task.on {
            self.smp.slots[index].kick();
        }
        Ok(())
    }

    fn wait(&mut self, timeout: Option<Duration>) -> Result<Option<Event>, PlatformError> {
        let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
        let smp = Arc::clone(&self.smp);
        loop {
            let mut sched = smp.lock();
            if sched.killed {
                drop(sched);
                return Ok(self.end_all(deadline));
            }
            if let Some(event) = sched.events.pop_front() {
                self.let_go(&mut sched)?;
                return Ok(Some(event));
            }
            let interrupted = sched.tasks.iter_mut().find(|(_, task)| {
                task.interrupt && task.state == State::Runnable && task.on.is_none()
            });
            if let Some((&key, task)) = interrupted {
                task.interrupt = false;
                task.state = State::Stopped;
                return Ok(Some(Event {
                    task: key,
                    trap: Trap::Interrupted,
                }));
            }
            if std::mem::take(&mut sched.woken) {
                self.let_go(&mut sched)?;
                return Ok(None);
            }
            let Some((key, contended)) = sched.pick(0) else {
                self.let_go(&mut sched)?;
                drop(sched);
                if !self.idle(deadline) {
                    return Ok(None);
                }
                continue;
            };
            let (mut current, claimed) = self.runner.claim(&mut sched, key);
            self.held_since = None;
            sched.loop_in_run = true;
            drop(sched);
            let started = Instant::now();
            // Preemption: while another task waits to run (and always
            // when other vCPUs may make one runnable), this one runs for
            // one slice at most, so an app that never traps cannot keep
            // the others from running.
            let slice_end = if contended || self.vcpus > 1 {
                self.runner.slice_end(key)
            } else {
                None
            };
            let until = match (deadline, slice_end) {
                (Some(deadline), Some(slice_end)) => Some(deadline.min(slice_end)),
                (deadline, slice_end) => deadline.or(slice_end),
            };
            let result = self
                .runner
                .load(&smp, &current, claimed)
                .and_then(|()| self.runner.run(&smp, &mut current, until));
            let mut sched = smp.lock();
            sched.loop_in_run = false;
            settle(&mut sched, &current, started);
            match result {
                Ok(Stop::Trap(trap)) => {
                    if let Some(task) = sched.tasks.get_mut(&key) {
                        task.state = State::Stopped;
                    }
                    return Ok(Some(Event { task: key, trap }));
                }
                Ok(Stop::Settled) => {
                    if std::mem::take(&mut sched.woken)
                        || deadline.is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        self.let_go(&mut sched)?;
                        return Ok(None);
                    }
                    // The slice ended, or an event came: on with the loop.
                }
                Ok(Stop::Gone(why)) => {
                    drop(sched);
                    return Ok(Some(self.gone(key, &why)));
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn waker(&self) -> Waker {
        let smp = Arc::clone(&self.smp);
        Waker::new(move || {
            let mut sched = smp.lock();
            sched.woken = true;
            smp.notify_loop(&sched);
        })
    }

    fn read(&mut self, key: TaskKey, addr: GuestAddr, buf: &mut [u8]) -> Result<(), PlatformError> {
        let (root, _) = self.lock().space_of(key)?;
        self.smp
            .phys()
            .read(root, addr, buf)
            .map_err(|err| mmu_err(err, addr, buf.len() as u64))
    }

    fn write(&mut self, key: TaskKey, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError> {
        let (root, asid) = self.lock().space_of(key)?;
        self.smp
            .change(root, asid, |phys| phys.write(root, addr, data))
            .map_err(|err| mmu_err(err, addr, data.len() as u64))
    }

    fn map(
        &mut self,
        key: TaskKey,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
        sharing: Sharing,
    ) -> Result<(), PlatformError> {
        let (root, asid) = self.lock().space_of(key)?;
        self.smp
            .change(root, asid, |phys| {
                phys.map(root, addr, len, prot, sharing == Sharing::Shared)
            })
            .map_err(|err| mmu_err(err, addr, len))
    }

    fn unmap(&mut self, key: TaskKey, addr: GuestAddr, len: u64) -> Result<(), PlatformError> {
        let (root, asid) = self.lock().space_of(key)?;
        self.smp
            .change(root, asid, |phys| phys.unmap(root, addr, len))
            .map_err(|err| mmu_err(err, addr, len))
    }

    fn protect(
        &mut self,
        key: TaskKey,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
    ) -> Result<(), PlatformError> {
        let (root, asid) = self.lock().space_of(key)?;
        self.smp
            .change(root, asid, |phys| phys.protect(root, addr, len, prot))
            .map_err(|err| mmu_err(err, addr, len))
    }
}

impl Drop for HvfPlatform {
    fn drop(&mut self) {
        // The other vCPUs first, each destroyed by its own thread.
        self.stop_threads();
        // Stage-2 mappings go with the VM; unmapping first keeps the order
        // obvious and the memory unreachable even if destroying fails.
        let (tables, ram) = {
            let phys = self.smp.phys();
            (phys.tables_backing().len(), phys.ram_backing().len())
        };
        for (ipa, len) in [
            (layout::SHIM_IPA, layout::SHIM_REGION as usize),
            (layout::TABLES_IPA, tables),
            (layout::RAM_IPA, ram),
        ] {
            if let Err(err) = self.vm.unmap(ipa, len) {
                log::warn!("{err}");
            }
        }
    }
}
#[cfg(test)]
mod breakdown {
    use super::*;

    #[test]
    #[ignore = "benchmark"]
    fn exit_cost_breakdown() {
        let _guard = super::vm_tests::VM
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig {
            vcpus: 1,
            ..HvfConfig::default()
        }) {
            Ok(p) => p,
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                return;
            }
        };
        let t = p.spawn().unwrap();
        p.map(t, 0x10000, PAGE, Prot::ALL, Sharing::Private)
            .unwrap();
        let code: Vec<u8> = [0xd400_0001u32, 0x17ff_ffff]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        p.write(t, 0x10000, &code).unwrap();
        p.resume(
            t,
            Resume::Start {
                entry: 0x10000,
                stack: 0,
            },
        )
        .unwrap();
        p.wait(None).unwrap().unwrap();
        const N: u32 = 1_000_000;
        // Bare: set PC, run, nothing read.
        let start = Instant::now();
        for _ in 0..N {
            p.runner.vcpu.set_reg(HV_REG_PC, 0x10000).unwrap();
            p.runner.vcpu.set_reg(HV_REG_CPSR, 0).unwrap();
            p.runner.vcpu.run().unwrap();
        }
        let bare = start.elapsed() / N;
        let start = Instant::now();
        let mut sum = 0u64;
        for _ in 0..N {
            sum = sum.wrapping_add(p.runner.vcpu.reg(3).unwrap());
        }
        let get = start.elapsed() / N;
        let start = Instant::now();
        for _ in 0..N {
            sum = sum.wrapping_add(p.runner.vcpu.sys_reg(sysreg::ELR_EL1).unwrap());
        }
        let sys = start.elapsed() / N;
        let start = Instant::now();
        for _ in 0..N {
            p.runner.vcpu.set_reg(0, sum).unwrap();
        }
        let set = start.elapsed() / N;
        eprintln!("bare exit {bare:?}, get_reg {get:?}, get_sys_reg {sys:?}, set_reg {set:?}");
    }
}

/// What needs the platform's insides: spaces beyond the ASIDs there are.
#[cfg(test)]
mod vm_tests {
    use super::*;

    /// One VM per process: the tests of this crate that make one take
    /// turns.
    pub(super) static VM: Mutex<()> = Mutex::new(());

    const CODE: u64 = 0x10_000;
    const DATA: u64 = 0x20_000;

    fn word(trap: Trap) -> u64 {
        match trap {
            Trap::Syscall(SyscallTrap { args, .. }) => args[0],
            other => panic!("not a syscall: {other:?}"),
        }
    }

    /// The timer (or a waker) may stop the vCPU inside the page flush
    /// routine, while `x0` holds the routine's operand and the app's own
    /// `x0` waits in `TPIDR_EL1`: the app gets its own back, and the whole
    /// TLB is flushed instead.
    #[test]
    fn an_interrupted_page_flush_gives_the_app_its_x0_back() {
        let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig {
            vcpus: 1,
            ..HvfConfig::default()
        }) {
            Ok(p) => p,
            Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
                panic!("HELLOVM_REQUIRE_E2E=1 but the HVF platform is unavailable: {err}")
            }
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                return;
            }
        };
        let t = p.spawn().unwrap();
        p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
        // Loop: svc.
        let code: Vec<u8> = [0xd400_0001u32, 0x17ff_ffff]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        p.write(t, CODE, &code).unwrap();
        p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
            .unwrap();
        let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
            unreachable!()
        };
        ctx.pc = CODE;
        ctx.x[0] = 0x1111;
        p.set_context(t, &Context::Aarch64(ctx)).unwrap();
        p.resume(t, Resume::Continue).unwrap();
        assert_eq!(word(p.wait(None).unwrap().unwrap().trap), 0x1111);
        // The vCPU as an exit inside the routine leaves it, at each of
        // its instructions: before and after `x0` is the app's again.
        for (at, x0) in [
            (0u64, 0xdead_0000_0000_0123u64),
            (12, 0xdead_0000_0000_0123),
            (16, 0x2222),
        ] {
            p.runner.flush = false;
            p.runner
                .vcpu
                .set_sys_reg(sysreg::TPIDR_EL1, 0x2222)
                .unwrap();
            p.runner.vcpu.set_reg(0, x0).unwrap();
            p.runner
                .vcpu
                .set_reg(HV_REG_PC, SHIM_VA + FLUSH_PAGE_OFFSET + at)
                .unwrap();
            p.runner
                .vcpu
                .set_reg(HV_REG_CPSR, layout::PSTATE_EL1H_MASKED)
                .unwrap();
            let mut current = Current {
                key: t,
                root: 0,
                asid: 0,
                pc: 0,
                pstate: 0,
            };
            assert!(matches!(
                p.runner.interrupted_at(&mut current).unwrap(),
                Interrupted::Settled
            ));
            assert!(p.runner.flush, "the whole TLB is flushed instead");
            assert_eq!(p.runner.vcpu.reg(0).unwrap(), 0x2222);
            // And the app runs on with it.
            p.resume(t, Resume::Continue).unwrap();
            assert_eq!(
                word(p.wait(None).unwrap().unwrap().trap),
                0x2222,
                "at +{at}"
            );
        }
    }

    /// The core answers a system call of a task whose registers are in
    /// another vCPU, and reads the registers before that vCPU has run the
    /// task again (as it does to deliver a signal that came in between):
    /// they have the result, and so does the app when it runs.
    #[test]
    fn registers_read_before_the_task_runs_again_have_the_result() {
        let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig {
            vcpus: 2,
            ..HvfConfig::default()
        }) {
            Ok(p) => p,
            Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
                panic!("HELLOVM_REQUIRE_E2E=1 but the HVF platform is unavailable: {err}")
            }
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                return;
            }
        };
        let t = p.spawn().unwrap();
        p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
        // Loop: svc.
        let code: Vec<u8> = [0xd400_0001u32, 0x17ff_ffff]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        p.write(t, CODE, &code).unwrap();
        p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
            .unwrap();
        let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
            unreachable!()
        };
        ctx.pc = CODE;
        ctx.x[0] = 0x1111;
        p.set_context(t, &Context::Aarch64(ctx)).unwrap();
        // Runnable without a call of `wait`, so that vCPU 1 runs it, not
        // the event loop's.
        {
            let mut sched = p.lock();
            sched.tasks.get_mut(&t).unwrap().state = State::Runnable;
            p.smp.wake(1);
        }
        let start = Instant::now();
        while p.lock().events.is_empty() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "vCPU 1 ran nothing"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(word(p.wait(None).unwrap().unwrap().trap), 0x1111);
        assert_eq!(p.lock().tasks[&t].loaded, Some(1));
        p.set_x0(t, 0x7777).unwrap();
        let Context::Aarch64(ctx) = p.context(t).unwrap() else {
            unreachable!()
        };
        assert_eq!(ctx.x[0], 0x7777, "the result is in the registers read");
        p.set_context(t, &Context::Aarch64(ctx)).unwrap();
        p.resume(t, Resume::Continue).unwrap();
        assert_eq!(word(p.wait(None).unwrap().unwrap().trap), 0x7777);
        p.kill(t).unwrap();
    }

    /// With ASIDs used up, new spaces share ASID 0, and switching between
    /// two of them flushes: each process still reads its own page.
    #[test]
    fn spaces_beyond_the_asids_share_one_and_flush() {
        let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig {
            vcpus: 1,
            ..HvfConfig::default()
        }) {
            Ok(p) => p,
            Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
                panic!("HELLOVM_REQUIRE_E2E=1 but the HVF platform is unavailable: {err}")
            }
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                return;
            }
        };
        // ASID 1 only; every other space gets 0.
        p.lock().asid_limit = 2;
        let t = p.spawn().unwrap();
        p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
        // Loop: x0 = [x1]; svc; [x1] = x2; svc.
        let code: Vec<u8> = [
            0xf940_0020u32,
            0xd400_0001,
            0xf900_0022,
            0xd400_0001,
            0x17ff_fffc,
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        p.write(t, CODE, &code).unwrap();
        p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
            .unwrap();
        p.map(t, DATA, PAGE, Prot::RW, Sharing::Private).unwrap();
        let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
            unreachable!()
        };
        ctx.pc = CODE;
        ctx.x[1] = DATA;
        p.set_context(t, &Context::Aarch64(ctx)).unwrap();
        p.resume(t, Resume::Continue).unwrap();
        let ev = p.wait(None).unwrap().unwrap();
        assert_eq!(word(ev.trap), 0);
        let mut tasks = vec![t];
        for _ in 0..3 {
            tasks.push(p.clone_task(t, false).unwrap());
        }
        let asids: Vec<u16> = tasks
            .iter()
            .map(|t| {
                let sched = p.lock();
                sched.spaces[&sched.tasks[t].space].asid
            })
            .collect();
        assert_eq!(asids, [1, 0, 0, 0]);
        // Each stores its own value, then all read theirs, in turn, many
        // times.
        for (i, &t) in tasks.iter().enumerate() {
            let mut ctx = match p.context(t).unwrap() {
                Context::Aarch64(c) => c,
                Context::X86_64(_) => unreachable!(),
            };
            ctx.x[2] = 0x100 + i as u64;
            p.set_context(t, &Context::Aarch64(ctx)).unwrap();
        }
        let step = |p: &mut HvfPlatform, t: TaskKey| {
            p.resume(t, Resume::Continue).unwrap();
            let ev = p.wait(None).unwrap().unwrap();
            assert_eq!(ev.task, t);
            ev.trap
        };
        for &t in &tasks {
            step(&mut p, t);
        }
        for round in 0..50 {
            for (i, &t) in tasks.iter().enumerate() {
                assert_eq!(word(step(&mut p, t)), 0x100 + i as u64, "round {round}");
                step(&mut p, t);
            }
        }
        for t in tasks {
            p.kill(t).unwrap();
        }
    }

    /// The timer can end a slice while the vCPU is in an exception vector,
    /// on its way out with an exception of the app. When that exception
    /// needs nothing from the core (here a page that gets its memory on
    /// first touch), the run still ends there; before, the app went on
    /// with no timer and kept the vCPU until something else stopped it.
    #[test]
    fn a_slice_that_ends_in_a_vector_still_ends() {
        let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig {
            vcpus: 1,
            ..HvfConfig::default()
        }) {
            Ok(p) => p,
            Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
                panic!("HELLOVM_REQUIRE_E2E=1 but the HVF platform is unavailable: {err}")
            }
            Err(err) => {
                eprintln!("SKIPPING: {err}");
                return;
            }
        };
        const BASE: u64 = 0x1000_0000;
        const LEN: u64 = 64 << 20;
        let t = p.spawn().unwrap();
        p.map(t, CODE, PAGE, Prot::RW, Sharing::Private).unwrap();
        // Touch every page: str x2, [x1]; add x1, x1, #4096; cmp x1, x3;
        // b.ne back; then spin: b .
        let code: Vec<u8> = [
            0xf900_0022u32,
            0x9140_0421,
            0xeb03_003f,
            0x54ff_ffa1,
            0x1400_0000,
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        p.write(t, CODE, &code).unwrap();
        p.protect(t, CODE, PAGE, Prot(Prot::READ.0 | Prot::EXEC.0))
            .unwrap();
        p.map(t, BASE, LEN, Prot::RW, Sharing::Private).unwrap();
        let Context::Aarch64(mut ctx) = Context::zeroed(Arch::Aarch64) else {
            unreachable!()
        };
        ctx.pc = CODE;
        ctx.x[1] = BASE;
        ctx.x[3] = BASE + LEN;
        p.set_context(t, &Context::Aarch64(ctx)).unwrap();
        p.resume(t, Resume::Continue).unwrap();
        // A waker, should a run not end by itself.
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchdog = {
            let (waker, done) = (p.waker(), Arc::clone(&done));
            std::thread::spawn(move || {
                let lock = Mutex::new(());
                let cv = Condvar::new();
                let mut guard = lock.lock().unwrap();
                while !done.load(SeqCst) {
                    guard = cv
                        .wait_timeout(guard, Duration::from_millis(500))
                        .unwrap()
                        .0;
                    waker.wake();
                }
            })
        };
        let start = Instant::now();
        let mut slowest = Duration::ZERO;
        while start.elapsed() < Duration::from_secs(1) {
            let before = Instant::now();
            assert!(p.wait(Some(Duration::from_micros(20))).unwrap().is_none());
            slowest = slowest.max(before.elapsed());
        }
        done.store(true, SeqCst);
        watchdog.join().unwrap();
        assert!(p.memory_in_use().0 >= LEN, "the app touched every page");
        assert!(
            slowest < Duration::from_millis(100),
            "a wait of 20 us took {slowest:?}"
        );
        p.kill(t).unwrap();
    }
}
