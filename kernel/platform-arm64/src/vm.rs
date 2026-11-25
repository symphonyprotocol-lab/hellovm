//! [`VmPlatform`]: the [`Platform`] implementation, for any
//! [`Hypervisor`].

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hellovm_core::arch::Arch;
use hellovm_core::platform::{
    Aarch64Context, AddressSpaceInfo, Context, CpuInfo, Event, Fault, FrozenSpace, GuestAddr,
    Platform, PlatformError, Prot, Resume, Sharing, SyscallTrap, TaskKey, Trap, Waker,
};
use hellovm_core::snap::{Reader, Snap, Writer};

use crate::backend::{Exit, Flush, Hypervisor, Kicker, Reg, Stopped, Vcpu};
use crate::exit::{self, AppException, SEGV_ACCERR, SEGV_MAPERR};
use crate::layout::{self, MAX_ADDR, MIN_ADDR, PAGE};
use crate::mmu::{Access, Backing, Demand, MmuError, Origin, Phys, SaveStats, Stale, Trimmed};

const SIGKILL: u32 = 9;
const SI_KERNEL: i32 = 0x80;

/// How long a task runs before another runnable task gets the vCPU.
const SLICE: Duration = Duration::from_millis(5);

/// How long an idle vCPU thread, or the event loop, polls for work
/// before it sleeps: a task that goes back and forth between the core and
/// another vCPU (a system call, a pipe round trip) then waits for no
/// host thread to wake up.
const SPIN: Duration = Duration::from_micros(50);

/// How long the event loop has had nothing to do before the free memory
/// the pools still hold goes back to the host (see [`Phys::trim`]).
const IDLE_TRIM: Duration = Duration::from_millis(20);

/// How long memory beyond the pools' reserve stays free before it goes
/// back to the host while the sandbox is busy: memory freed and used again
/// sooner (a process that exits and the next one, an interpreter's heap
/// that shrinks and grows) never makes the trip (see the README).
const GIVE_BACK_AGE: Duration = Duration::from_millis(100);

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
/// busy before another vCPU runs it ([`VmPlatform::let_go`]).
const HOLD: Duration = SPIN;

/// Most vCPUs a platform makes, whatever the framework allows.
pub const MAX_VCPUS: usize = 64;

/// vCPUs when [`VmConfig::vcpus`] is 0: one per host CPU, at most this.
const DEFAULT_VCPUS: usize = 8;

/// How much memory a platform reserves for its apps, and how many vCPUs
/// run them.
#[derive(Clone, Copy, Debug)]
pub struct VmConfig {
    /// App memory (every page any app of the sandbox touches), in bytes.
    pub memory: u64,
    /// Page-table memory, in bytes.
    pub table_memory: u64,
    /// vCPUs, each on its own host thread: threads of the apps run in
    /// parallel on them. 0 is the default: one per host CPU, at most 8.
    /// At most [`MAX_VCPUS`] and what the hypervisor allows.
    pub vcpus: usize,
}

impl Default for VmConfig {
    fn default() -> Self {
        VmConfig {
            memory: 2 << 30,
            table_memory: 64 << 20,
            vcpus: 0,
        }
    }
}

/// How often the platform invalidated TLB entries ([`VmPlatform::flushes`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flushes {
    /// The whole TLB (and the instruction cache).
    pub all: u64,
    /// One page of one address space.
    pub page: u64,
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
struct Slot<K> {
    kicker: OnceLock<K>,
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

impl<K: Kicker> Slot<K> {
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
struct Smp<H: Hypervisor> {
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
    phys: Mutex<Phys<H::Mem>>,
    slots: Vec<Slot<H::Kicker>>,
    flushes_all: AtomicU64,
    flushes_page: AtomicU64,
    /// The pools' clock ([`Phys::set_clock`]) counts nanoseconds from this.
    epoch: Instant,
    /// When free memory the pools hold will have been free for
    /// [`GIVE_BACK_AGE`] ([`Phys::trim_aged`]), on that clock; `u64::MAX`
    /// when nothing will.
    trim_due: AtomicU64,
}

impl<H: Hypervisor> Smp<H> {
    fn lock(&self) -> MutexGuard<'_, Sched> {
        self.sched.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn phys(&self) -> MutexGuard<'_, Phys<H::Mem>> {
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
    ///
    /// Then free memory that has been free for [`GIVE_BACK_AGE`] goes
    /// back to the host ([`Smp::trim_aged`]): by now no vCPU can reach a
    /// free frame (each one freed was reachable only through the entries
    /// this or an earlier change made stale).
    fn change<R>(&self, root: u64, asid: u16, f: impl FnOnce(&mut Phys<H::Mem>) -> R) -> R {
        let mut phys = self.phys();
        phys.set_clock(self.clock());
        let result = f(&mut phys);
        let stale = phys.take_stale();
        self.invalidate(root, asid, stale);
        self.trim_aged(&mut phys);
        drop(phys);
        result
    }

    /// Nanoseconds since the platform was made.
    fn clock(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }

    /// Gives back the free memory that has been free long enough, and
    /// records when the next will be. Called with the tables locked,
    /// when no vCPU can reach a free frame.
    fn trim_aged(&self, phys: &mut Phys<H::Mem>) {
        let age = GIVE_BACK_AGE.as_nanos() as u64;
        let (_, due) = phys.trim_aged(self.clock(), age);
        self.trim_due.store(due.unwrap_or(u64::MAX), SeqCst);
    }

    /// When the event loop must call [`Smp::trim_aged`] next, if ever.
    fn trim_deadline(&self) -> Option<Instant> {
        let due = self.trim_due.load(SeqCst);
        (due != u64::MAX).then(|| self.epoch + Duration::from_nanos(due))
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

/// Ends every app of a [`VmPlatform`] from any thread (for timeouts):
/// the platform reports each task as [`Trap::Gone`].
pub struct AppKiller<H: Hypervisor> {
    smp: Arc<Smp<H>>,
}

impl<H: Hypervisor> Clone for AppKiller<H> {
    fn clone(&self) -> Self {
        AppKiller {
            smp: Arc::clone(&self.smp),
        }
    }
}

impl<H: Hypervisor> AppKiller<H> {
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
struct Runner<H: Hypervisor> {
    index: usize,
    vcpu: H::Vcpu,
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
    /// The task this vCPU gave a slice and when it ends: a task keeps its
    /// slice across the traps the core answers in between.
    slice: Option<(TaskKey, Instant)>,
    /// The space that last ran with ASID 0 since the TLB was last
    /// flushed, if any (vCPU 0 only).
    asid0_root: Option<u64>,
}

fn host_err(err: io::Error) -> PlatformError {
    PlatformError::Host(err)
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

impl<H: Hypervisor> Runner<H> {
    fn new(index: usize, vcpu: H::Vcpu) -> Runner<H> {
        Runner {
            index,
            vcpu,
            loaded: None,
            ttbr0: 0,
            flush: true,
            flush_page: None,
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

    fn read_vcpu(&self) -> io::Result<Box<Aarch64Context>> {
        self.vcpu.read_context()
    }

    fn write_vcpu(&mut self, c: &Aarch64Context) -> io::Result<()> {
        self.vcpu.write_context(c)
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
        smp: &Smp<H>,
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
            self.vcpu.set_x0(x0).map_err(host_err)?;
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
    fn unload(&mut self, smp: &Smp<H>, key: TaskKey) -> Result<(), PlatformError> {
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
                        "{} platform: vCPU {}: {err}; task {key}, loaded in it, ends",
                        H::NAME,
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
        // The event loop may wait for it (`VmPlatform::unload_from`).
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
            self.vcpu.set_ttbr0(ttbr0).map_err(host_err)?;
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

    /// Starts a run of the space at `root`: the epoch goes odd, and the
    /// invalidations other threads left for this vCPU are taken.
    fn begin_run(&mut self, smp: &Smp<H>, root: u64) {
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
    fn enter(&mut self, smp: &Smp<H>, current: &Current) -> io::Result<()> {
        let (pc, pstate) = (current.pc, current.pstate & layout::PSTATE_APP_MASK);
        let flush = if self.flush {
            if current.asid != 0 {
                self.asid0_root = None;
            }
            self.flush = false;
            self.flush_page = None;
            smp.flushes_all.fetch_add(1, SeqCst);
            Flush::All
        } else if let Some(operand) = self.flush_page.take() {
            smp.flushes_page.fetch_add(1, SeqCst);
            Flush::Page(operand)
        } else {
            Flush::None
        };
        self.vcpu.enter(pc, pstate, flush)
    }

    /// Runs the loaded task until it traps, the deadline passes or the
    /// vCPU is kicked. Takes no lock but the tables' (for a page fault).
    fn run(
        &mut self,
        smp: &Smp<H>,
        current: &mut Current,
        deadline: Option<Instant>,
    ) -> Result<Stop, PlatformError> {
        self.vcpu.arm_timer(deadline).map_err(host_err)?;
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
            let stop = match exit {
                Exit::Stopped(at) => match at {
                    Stopped::At { pc, pstate } => {
                        current.pc = pc;
                        current.pstate = pstate & layout::PSTATE_APP_MASK;
                        Some(Stop::Settled)
                    }
                    // In a flush routine, before the app ran: it starts
                    // over from `pc`, flushing again.
                    Stopped::Flushing => {
                        self.flush = true;
                        Some(Stop::Settled)
                    }
                    // In a vector, about to leave the VM with an
                    // exception of the app: let it, with the vCPU's
                    // state as it is.
                    Stopped::InVector => {
                        reenter = false;
                        stopped = true;
                        None
                    }
                    Stopped::Lost(why) => Some(Stop::Gone(why)),
                },
                Exit::Unexpected(why) => Some(Stop::Gone(why)),
                exit => self.on_exception(smp, current, &exit, &mut retries)?,
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

    /// Decodes an exception exit. `None` means: resume the app.
    /// `retries` counts faults in a row on a page that was ready.
    fn on_exception(
        &mut self,
        smp: &Smp<H>,
        current: &mut Current,
        exit: &Exit,
        retries: &mut (u64, u32),
    ) -> Result<Option<Stop>, PlatformError> {
        let v = &self.vcpu;
        let (esr, far, pc) = match *exit {
            // From a vector of the shim (only EL0 exceptions get there and
            // out): the registers are the app's, ELR/SPSR/ESR/FAR say what
            // happened.
            Exit::Vector(slot) => {
                let pc = v.reg(Reg::ElrEl1).map_err(host_err)?;
                let pstate = v.reg(Reg::SpsrEl1).map_err(host_err)?;
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
                let esr = v.reg(Reg::EsrEl1).map_err(host_err)?;
                let far = match exit::exception_class(esr) {
                    0x20 | 0x22 | 0x24 => v.reg(Reg::FarEl1).map_err(host_err)?,
                    0x26 => v.reg(Reg::SpEl0).map_err(host_err)?,
                    _ => 0,
                };
                (esr, far, pc)
            }
            Exit::Direct {
                syndrome,
                virtual_address,
                physical_address,
            } => {
                // Taken straight to EL2. From the app (EL0t) it is one the
                // framework traps (`wfi`, `wfe`); anything else, or a fault
                // in stage 2, means the VM is not as this platform built it.
                let cpsr = v.reg(Reg::Cpsr).map_err(host_err)?;
                let pc = v.reg(Reg::Pc).map_err(host_err)?;
                let class = exit::exception_class(syndrome);
                if cpsr & 0xf != 0 || matches!(class, 0x20 | 0x24) {
                    return Ok(Some(Stop::Gone(format!(
                        "exit to the host with syndrome {syndrome:#x} at pc {pc:#x}, \
                         cpsr {cpsr:#x}, address {virtual_address:#x} \
                         (guest-physical {physical_address:#x})",
                    ))));
                }
                current.pc = pc;
                current.pstate = cpsr & layout::PSTATE_APP_MASK;
                (syndrome, virtual_address, pc)
            }
            Exit::Stopped(_) | Exit::Unexpected(_) => {
                return Ok(Some(Stop::Gone("not an exception".into())));
            }
        };
        match exit::decode(esr, far, pc) {
            AppException::Syscall => {
                let mut regs = [0u64; 7];
                for (i, reg) in regs.iter_mut().enumerate().take(6) {
                    *reg = v.reg(Reg::X(i as u8)).map_err(host_err)?;
                }
                regs[6] = v.reg(Reg::X(8)).map_err(host_err)?;
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
        smp: &Smp<H>,
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
                    "{} platform: task {}: out of memory at {addr:#x}; killing it",
                    H::NAME,
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

/// A vCPU made on one thread, to be run on another
/// ([`Hypervisor::DEFER_THREADS`]).
struct Unbound<T>(T);

// SAFETY: only made for a backend with `DEFER_THREADS`, whose vCPUs may
// move to another thread before they first run (the trait's contract);
// the vCPU is used on one thread at a time, first the one that made it
// (set-up only), then its own.
unsafe impl<T> Send for Unbound<T> {}

impl<T> Unbound<T> {
    /// Takes the whole value (a closure that named the field would
    /// capture the field alone, which is not `Send`).
    fn into_inner(self) -> T {
        self.0
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
fn vcpu_thread<H: Hypervisor>(smp: Arc<Smp<H>>, mut runner: Runner<H>) {
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
                    log::error!("{} platform: vCPU {index}: {err}", H::NAME);
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
                log::error!("{} platform: task {key}: {why}; ending it", H::NAME);
                runner.loaded = None;
                smp.lose(sched, key);
                sched = smp.lock();
                None
            }
            Err(err) => {
                // The vCPU failed: the task goes, and this vCPU runs
                // nothing any more. Its thread stays until the platform
                // goes, as the others do.
                log::error!("{} platform: vCPU {index}: {err}; task {key} ends", H::NAME);
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

/// The platform on a VM of hypervisor `H`. See the crate documentation.
///
/// Used from the thread that made it: vCPU 0 belongs to that thread and
/// runs in [`Platform::wait`]; the others have threads of their own.
pub struct VmPlatform<H: Hypervisor> {
    // Field order is drop order: vCPU 0, then the VM (which removes the
    // stage-2 mappings), then the memory behind them. `Drop` ends the
    // other vCPUs' threads first.
    runner: Runner<H>,
    threads: Vec<JoinHandle<()>>,
    vm: H,
    smp: Arc<Smp<H>>,
    info: AddressSpaceInfo,
    cpu: CpuInfo,
    vcpus: usize,
    /// Since when what vCPU 0 would run next has waited ([`Self::let_go`]).
    held_since: Option<Instant>,
    /// A frozen template's tasks ([`Platform::freeze`]), or a clone's
    /// before [`Platform::thaw`] ([`VmPlatform::load_frozen`]).
    frozen: Option<Vec<FrozenTasks>>,
    config: VmConfig,
    /// vCPUs made but whose threads have not started yet
    /// ([`Hypervisor::DEFER_THREADS`]).
    deferred: Vec<Unbound<Runner<H>>>,
    _not_send: PhantomData<*const ()>,
}

/// The tasks of one frozen address space: its tables and their registers.
struct FrozenTasks {
    root: u64,
    /// Boxed as a task keeps them (`Task::saved`).
    #[allow(clippy::vec_box)]
    contexts: Vec<Box<Aarch64Context>>,
}

hellovm_core::snap_struct!(FrozenTasks { root, contexts });

/// After [`Hypervisor::SNAPSHOT_PREFIX`], the first bytes of
/// [`VmPlatform::save_frozen`]'s output: a fingerprint of this crate's
/// sources (`build.rs`); the core's follows it
/// ([`hellovm_core::snap::BUILD`]: the registers and the pools' state are
/// written with its encoding).
const SNAPSHOT_MAGIC: &[u8] = concat!(env!("HELLOVM_BUILD"), "\0").as_bytes();

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
fn vcpu_count(asked: usize, hypervisor_max: u32) -> usize {
    let wanted = match asked {
        0 => std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(DEFAULT_VCPUS),
        n => n,
    };
    wanted
        .min(MAX_VCPUS)
        .min(hypervisor_max.max(1) as usize)
        .max(1)
}

/// The host page the pools take memory in (`mmu`): regions are
/// multiples of it.
const REGION_GRANULE: u64 = 16 * 1024;

impl<H: Hypervisor> VmPlatform<H> {
    /// A platform for one sandbox, with its VM and vCPUs. The errors are
    /// the hypervisor's (on macOS `PermissionDenied` when the executable
    /// lacks the hypervisor entitlement, and `ResourceBusy` while another
    /// platform of this process exists).
    pub fn new(config: VmConfig) -> io::Result<VmPlatform<H>> {
        let round = |n: u64| n.max(REGION_GRANULE).next_multiple_of(REGION_GRANULE);
        let memory = round(config.memory);
        let table_memory = round(config.table_memory);
        if layout::TABLES_IPA + table_memory > layout::RAM_IPA || memory > 32 << 30 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} platform: at most 32 GiB of memory and 3 GiB of page tables",
                    H::NAME
                ),
            ));
        }
        if config.vcpus > MAX_VCPUS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} platform: at most {MAX_VCPUS} vCPUs", H::NAME),
            ));
        }
        let (vm, tables, ram) = H::create(memory as usize, table_memory as usize)?;
        let mut phys = Phys::new(tables, ram);
        let shim_root = vm
            .shim_space(&mut phys)
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "page tables"))?;
        let vcpus = vcpu_count(config.vcpus, vm.max_vcpus());
        if config.vcpus > vcpus {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} platform: this host allows at most {vcpus} vCPUs",
                    H::NAME
                ),
            ));
        }
        let mut vcpu = H::vcpu(vm.token(), 0)?;

        let id = vcpu.id_regs()?;
        let mmfr0 = id.mmfr0;
        if (mmfr0 >> 28) & 0xf == 0xf {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{} platform: the vCPU does not support 4 KiB translation granules",
                    H::NAME
                ),
            ));
        }
        // The guest-physical layout fits in 36 bits; use what the vCPU has
        // up to 48 (`IPS` takes the `PARange` encoding).
        let ips = (mmfr0 & 0xf).min(5);
        let asid16 = (mmfr0 >> 4) & 0xf == 2;
        let cpu = CpuInfo {
            hwcap: hwcap(id.pfr0, id.isar0, id.isar1),
            hwcap2: 0,
        };
        let tcr = layout::tcr_el1(ips, asid16);
        vcpu.set_up(tcr, shim_root)?;
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
            flushes_all: AtomicU64::new(0),
            flushes_page: AtomicU64::new(0),
            epoch: Instant::now(),
            trim_due: AtomicU64::new(u64::MAX),
        });
        let mut platform = VmPlatform {
            runner: Runner::new(0, vcpu),
            threads: Vec::new(),
            vm,
            smp,
            info: AddressSpaceInfo {
                page_size: PAGE,
                min_addr: MIN_ADDR,
                max_addr: MAX_ADDR,
                reserved: Vec::new(),
            },
            cpu,
            vcpus,
            held_since: None,
            frozen: None,
            config: VmConfig {
                memory,
                table_memory,
                vcpus: config.vcpus,
            },
            deferred: Vec::new(),
            _not_send: PhantomData,
        };
        let token = platform.vm.token();
        if H::DEFER_THREADS {
            // Every vCPU made here, on this thread; their threads start
            // at the first `wait` (`start_threads`).
            for index in 1..vcpus {
                let mut vcpu = H::vcpu(token.clone(), index)?;
                vcpu.set_up(tcr, shim_root)?;
                let _ = platform.smp.slots[index].kicker.set(vcpu.kicker());
                platform.deferred.push(Unbound(Runner::new(index, vcpu)));
            }
            return Ok(platform);
        }
        // The other vCPUs, each made by its own thread (a vCPU belongs to
        // the thread that made it). Made now, before the kernel process
        // hardens itself, so that it never needs to make a thread or a
        // vCPU afterwards.
        for index in 1..vcpus {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let smp = Arc::clone(&platform.smp);
            let token = token.clone();
            let thread = std::thread::Builder::new()
                .name(format!("hellovm-vcpu{index}"))
                .spawn(move || {
                    let made = H::vcpu(token, index).and_then(|mut vcpu| {
                        vcpu.set_up(tcr, shim_root)?;
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
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    return Err(io::Error::other(format!(
                        "{} platform: a vCPU thread ended",
                        H::NAME
                    )));
                }
            }
        }
        Ok(platform)
    }

    /// The VM.
    pub fn hypervisor(&self) -> &H {
        &self.vm
    }

    /// Starts the threads of the vCPUs made in [`VmPlatform::new`] when
    /// the backend defers them ([`Hypervisor::DEFER_THREADS`]): called by
    /// the first `wait`, once the kernel process has confined itself.
    fn start_threads(&mut self) -> io::Result<()> {
        while let Some(Unbound(runner)) = self.deferred.pop() {
            let smp = Arc::clone(&self.smp);
            let index = runner.index;
            let runner = Unbound(runner);
            let thread = std::thread::Builder::new()
                .name(format!("hellovm-vcpu{index}"))
                .spawn(move || vcpu_thread(smp, runner.into_inner()))?;
            self.threads.push(thread);
        }
        Ok(())
    }

    /// A handle that ends every app from any thread.
    pub fn killer(&self) -> AppKiller<H> {
        AppKiller {
            smp: Arc::clone(&self.smp),
        }
    }

    /// App memory and page-table memory in use, in bytes.
    pub fn memory_in_use(&self) -> (u64, u64) {
        let phys = self.smp.phys();
        (phys.ram_in_use(), phys.tables_in_use())
    }

    /// Free memory the pools still hold (whole host pages not given back
    /// yet), in bytes, and what went back to the host so far.
    pub fn memory_kept(&self) -> (u64, Trimmed) {
        let phys = self.smp.phys();
        (phys.whole_free(), phys.trimmed())
    }

    /// Gives back to the host all the free memory the pools still hold.
    fn trim_all(&self) {
        let mut phys = self.smp.phys();
        phys.trim(0, 0);
        self.smp.trim_due.store(u64::MAX, SeqCst);
    }

    /// Gives back what has been free long enough once that is due.
    fn trim_if_due(&self) {
        if self
            .smp
            .trim_deadline()
            .is_some_and(|due| due <= Instant::now())
        {
            let mut phys = self.smp.phys();
            self.smp.trim_aged(&mut phys);
        }
    }

    /// How often TLB entries were invalidated so far (by any vCPU).
    pub fn flushes(&self) -> Flushes {
        self.smp.flushes()
    }

    /// How many vCPUs the platform runs apps on.
    pub fn vcpus(&self) -> usize {
        self.vcpus
    }

    /// The bytes of app memory and of page tables, as made (rounded to
    /// the host page): what a snapshot's two regions must hold.
    pub fn pool_sizes(&self) -> (u64, u64) {
        (self.config.memory, self.config.table_memory)
    }

    /// Saves a template that [`Platform::freeze`] froze, for its clones
    /// (see the `mmu` module for how): the used page tables into `tables`,
    /// the app frames that are not all zero into `ram` (each at its own
    /// offset), both as large as [`VmPlatform::pool_sizes`] says and
    /// zero. Returns the rest, for [`VmPlatform::load_frozen`].
    pub fn save_frozen(
        &mut self,
        tables: &mut [u8],
        ram: &mut [u8],
        w: &mut Writer<'_>,
    ) -> Result<SaveStats, PlatformError> {
        let Some(frozen) = &self.frozen else {
            return Err(PlatformError::Violation("nothing is frozen".into()));
        };
        let (memory, table_memory) = self.pool_sizes();
        if ram.len() as u64 != memory || tables.len() as u64 != table_memory {
            return Err(PlatformError::Violation(
                "snapshot regions of the wrong size".into(),
            ));
        }
        w.bytes(H::SNAPSHOT_PREFIX.as_bytes());
        w.bytes(SNAPSHOT_MAGIC);
        w.bytes(hellovm_core::snap::BUILD.as_bytes());
        memory.put(w);
        table_memory.put(w);
        let stats = self.smp.phys().save(tables, ram, w);
        frozen.put(w);
        Ok(stats)
    }

    /// Makes this new platform (nothing spawned yet, made with the
    /// template's [`VmPlatform::pool_sizes`]) a clone of a saved
    /// template, ready for [`Platform::thaw`]: `meta` from
    /// [`VmPlatform::save_frozen`], `tables` the saved page tables (the
    /// used part), `origin` the saved app memory, copied page by page as
    /// the clone touches it.
    pub fn load_frozen(
        &mut self,
        meta: &[u8],
        tables: &[u8],
        origin: Box<dyn Origin>,
    ) -> Result<(), String> {
        let bad = |e: hellovm_core::snap::Bad| e.to_string();
        let mut r = Reader::new(meta);
        let core = hellovm_core::snap::BUILD.as_bytes();
        let prefix = H::SNAPSHOT_PREFIX.as_bytes();
        if r.take(prefix.len()).map_err(bad)? != prefix
            || r.take(SNAPSHOT_MAGIC.len()).map_err(bad)? != SNAPSHOT_MAGIC
            || r.take(core.len()).map_err(bad)? != core
        {
            return Err(format!(
                "not a snapshot of this build's {} platform",
                H::NAME
            ));
        }
        let memory = u64::get(&mut r).map_err(bad)?;
        let table_memory = u64::get(&mut r).map_err(bad)?;
        let pools = crate::mmu::Saved::get(&mut r).map_err(bad)?;
        let frozen = Vec::<FrozenTasks>::get(&mut r).map_err(bad)?;
        r.finish().map_err(bad)?;
        if (memory, table_memory) != self.pool_sizes() {
            return Err(format!(
                "the template has {memory} bytes of memory and {table_memory} of page tables, \
                 this VM {:?}",
                self.pool_sizes()
            ));
        }
        if !self.lock().tasks.is_empty() || self.frozen.is_some() {
            return Err("the platform is in use".into());
        }
        if frozen.iter().any(|f| f.contexts.is_empty()) {
            return Err("a frozen address space without tasks".into());
        }
        let roots: Vec<u64> = frozen.iter().map(|f| f.root).collect();
        let mut sorted = roots.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != roots.len() {
            return Err("two frozen address spaces with the same tables".into());
        }
        self.smp.phys().load(pools, tables, origin, &roots)?;
        self.frozen = Some(frozen);
        Ok(())
    }

    /// App frames a clone copied from its template so far.
    pub fn frames_loaded(&self) -> u64 {
        self.smp.phys().loaded()
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
        log::error!("{} platform: task {key}: {why}; ending it", H::NAME);
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
                    "{} platform: killed: task {key}: space {} {:?} pc {:#x} runtime {} ns, \
                     on vCPU {:?}, loaded in {:?}, interrupt {}",
                    H::NAME,
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
                    "{} platform: killed: vCPU {index}: epoch {}, root {:#x}, pending {:#x}",
                    H::NAME,
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
        // Free memory the pools kept goes back to the host once the event
        // loop has had nothing to do for a while.
        let mut trim_at = None;
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
            let now = Instant::now();
            let trim = *trim_at.get_or_insert(now + IDLE_TRIM);
            if trim <= now {
                trim_at = Some(now + Duration::from_secs(3600));
                drop(sched);
                self.trim_all();
                sched = self.lock();
                continue;
            }
            let until = match deadline {
                Some(deadline) if deadline < trim => deadline,
                _ => trim,
            };
            let left = until.saturating_duration_since(now);
            if deadline == Some(until) && left.is_zero() {
                return false;
            }
            sched = self.smp.wait_loop_for(sched, left);
        }
    }

    fn set_x0(&mut self, key: TaskKey, value: u64) -> Result<(), PlatformError> {
        let smp = Arc::clone(&self.smp);
        let mut sched = smp.lock();
        let task = sched.task(key)?;
        match task.loaded {
            // vCPU 0 is this thread's: nothing else reaches it.
            Some(0) => {
                drop(sched);
                self.runner.vcpu.set_x0(value).map_err(host_err)
            }
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

impl<H: Hypervisor> Platform for VmPlatform<H> {
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
            drop(sched);
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
        if !self.deferred.is_empty() {
            self.start_threads().map_err(host_err)?;
        }
        let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
        let smp = Arc::clone(&self.smp);
        loop {
            self.trim_if_due();
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
            // Memory due to go back ends the run in time, also of an app
            // that never makes a system call.
            let until = [deadline, slice_end, smp.trim_deadline()]
                .into_iter()
                .flatten()
                .min();
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

    /// Keeps the registers and the address space of every task: nothing
    /// is ended, since the tasks' memory is what
    /// [`VmPlatform::save_frozen`] saves next. The kernel process then
    /// exits; the clones are new processes ([`VmPlatform::load_frozen`]).
    fn freeze(&mut self, spaces: &[FrozenSpace]) -> Result<(), PlatformError> {
        let mut frozen = Vec::new();
        for space in spaces {
            let mut contexts = Vec::new();
            let mut root = None;
            for &key in &space.tasks {
                let Context::Aarch64(context) = self.context(key)? else {
                    unreachable!("aarch64 contexts only");
                };
                let mut sched = self.lock();
                let task = sched.stopped(key)?;
                let at = task.space;
                let at = sched.spaces[&at].root;
                if root.is_some_and(|root| root != at) {
                    return Err(PlatformError::Violation(
                        "the threads of one address space are in two".into(),
                    ));
                }
                root = Some(at);
                contexts.push(context);
            }
            let Some(root) = root else {
                return Err(PlatformError::Violation(
                    "an address space without tasks".into(),
                ));
            };
            frozen.push(FrozenTasks { root, contexts });
        }
        self.frozen = Some(frozen);
        Ok(())
    }

    /// A clone's tasks, from [`VmPlatform::load_frozen`]: one address
    /// space per frozen one, with the template's tables, and a stopped
    /// task per frozen task with its registers.
    fn thaw(&mut self) -> Result<Vec<Vec<TaskKey>>, PlatformError> {
        let frozen = self
            .frozen
            .take()
            .ok_or_else(|| PlatformError::Violation("nothing to thaw".into()))?;
        let mut sched = self.lock();
        if !sched.tasks.is_empty() {
            return Err(PlatformError::Violation("the platform is in use".into()));
        }
        let mut keys = Vec::new();
        for space in frozen {
            let id = sched.add_space(space.root);
            sched.spaces.get_mut(&id).expect("just added").users = space.contexts.len();
            let mut these = Vec::new();
            for context in space.contexts {
                let key = sched.next_key;
                sched.next_key += 1;
                sched.tasks.insert(
                    key,
                    Task {
                        space: id,
                        state: State::Stopped,
                        pc: context.pc,
                        pstate: context.pstate & layout::PSTATE_APP_MASK,
                        saved: Some(context),
                        loaded: None,
                        x0: None,
                        on: None,
                        interrupt: false,
                        kill: false,
                        runtime: 0,
                    },
                );
                these.push(key);
            }
            keys.push(these);
        }
        Ok(keys)
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

impl<H: Hypervisor> Drop for VmPlatform<H> {
    fn drop(&mut self) {
        // The other vCPUs first, each destroyed by its own thread.
        self.stop_threads();
        // Stage-2 mappings go with the VM; unmapping first keeps the order
        // obvious and the memory unreachable even if destroying fails.
        let (tables, ram) = {
            let phys = self.smp.phys();
            (phys.tables_backing().len(), phys.ram_backing().len())
        };
        self.vm.release(tables, ram);
    }
}

#[cfg(feature = "testing")]
#[path = "testing.rs"]
pub mod testing;
