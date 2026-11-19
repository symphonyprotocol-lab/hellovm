//! [`HvfPlatform`]: the [`Platform`] implementation.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
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

/// How much memory a platform reserves for its apps.
#[derive(Clone, Copy, Debug)]
pub struct HvfConfig {
    /// App memory (every page any app of the sandbox touches), in bytes.
    pub memory: u64,
    /// Page-table memory, in bytes.
    pub table_memory: u64,
}

impl Default for HvfConfig {
    fn default() -> Self {
        HvfConfig {
            memory: 2 << 30,
            table_memory: 64 << 20,
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
        let bytes = self.slice_mut(offset, len);
        sys::icache_invalidate(bytes.as_mut_ptr(), bytes.len());
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
    /// Resumed: [`Platform::wait`] will run it.
    Runnable,
}

struct Task {
    space: u64,
    state: State,
    /// Where the app continues, and its condition flags: kept here, not in
    /// the vCPU, which stops in the shim.
    pc: u64,
    pstate: u64,
    /// The rest of the register context while the task is not the one in
    /// the vCPU.
    saved: Option<Box<Aarch64Context>>,
    /// [`Platform::interrupt`] was called.
    interrupt: bool,
    /// How long it ran, in nanoseconds, give or take (see
    /// [`HvfPlatform::next_runnable`]).
    runtime: u64,
}

struct Space {
    /// The guest-physical address of its level-0 table.
    root: u64,
    /// Its address space identifier; 0 is shared by the spaces that found
    /// none free (see [`HvfPlatform::load`]).
    asid: u16,
    users: usize,
}

#[derive(Default)]
struct WakeState {
    woken: bool,
    /// The vCPU is in (or about to enter) `hv_vcpu_run`.
    in_run: bool,
    killed: bool,
}

/// What the waker and the killer share with the event loop.
struct Shared {
    state: Mutex<WakeState>,
    cond: Condvar,
    kicker: VcpuKicker,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, WakeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wake(&self) {
        let mut state = self.lock();
        state.woken = true;
        if state.in_run {
            self.kicker.kick();
        }
        self.cond.notify_all();
    }

    fn kill(&self) {
        let mut state = self.lock();
        state.killed = true;
        state.woken = true;
        self.kicker.kick();
        self.cond.notify_all();
    }
}

/// Ends every app of an [`HvfPlatform`] from any thread (for timeouts):
/// the platform reports each task as [`Trap::Gone`].
#[derive(Clone)]
pub struct AppKiller {
    shared: Arc<Shared>,
}

impl AppKiller {
    pub fn kill(&self) {
        self.shared.kill();
    }
}

/// The Hypervisor.framework platform. See the crate documentation.
///
/// One per process (the framework allows one VM per process), used from
/// the thread that made it (the vCPU belongs to that thread).
pub struct HvfPlatform {
    // Field order is drop order: the vCPU, then the VM (which removes the
    // stage-2 mappings), then the memory behind them.
    vcpu: Vcpu,
    vm: Vm,
    phys: Phys<HostMem>,
    _shim: HostMem,
    info: AddressSpaceInfo,
    cpu: CpuInfo,
    tasks: BTreeMap<TaskKey, Task>,
    spaces: HashMap<u64, Space>,
    next_key: TaskKey,
    next_space: u64,
    /// ASIDs of spaces that are gone, and the lowest never used.
    free_asids: Vec<u16>,
    next_asid: u32,
    /// One past the highest ASID (256 or 65536).
    asid_limit: u32,
    /// The space that last ran with ASID 0 since the TLB was last
    /// flushed, if any.
    asid0_root: Option<u64>,
    /// The task whose registers are in the vCPU.
    loaded: Option<TaskKey>,
    /// `TTBR0_EL1` as last set.
    ttbr0: u64,
    /// Page tables changed in a way the TLB may have cached: run the
    /// shim's flush routine before the app.
    flush: bool,
    /// Only one page changed: the `tlbi vae1is` operand (ASID and page
    /// number) for the shim's page flush routine.
    flush_page: Option<u64>,
    /// How often each flush routine ran.
    flushes: Flushes,
    timer_armed: bool,
    /// The least runtime of a task chosen to run (it only grows).
    min_runtime: u64,
    /// `mach_absolute_time` ticks per second.
    ticks_per_sec: u64,
    shared: Arc<Shared>,
    _not_send: PhantomData<*const ()>,
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

impl HvfPlatform {
    /// A platform for one sandbox, with its VM and vCPU. Fails with
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
        let vcpu = Vcpu::create(&vm)?;

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
        for (reg, value) in [
            (sysreg::MAIR_EL1, layout::MAIR_EL1),
            (sysreg::TCR_EL1, layout::tcr_el1(ips, asid16)),
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
        let mut timebase = sys::MachTimebaseInfo::default();
        sys::timebase(&mut timebase);
        let ticks_per_sec = if timebase.numer == 0 {
            24_000_000
        } else {
            1_000_000_000 * u64::from(timebase.denom) / u64::from(timebase.numer)
        };
        let shared = Arc::new(Shared {
            state: Mutex::default(),
            cond: Condvar::new(),
            kicker: vcpu.kicker(),
        });
        Ok(HvfPlatform {
            vcpu,
            vm,
            phys,
            _shim: shim,
            info: AddressSpaceInfo {
                page_size: PAGE,
                min_addr: MIN_ADDR,
                max_addr: MAX_ADDR,
                reserved: Vec::new(),
            },
            cpu,
            tasks: BTreeMap::new(),
            spaces: HashMap::new(),
            next_key: 1,
            next_space: 1,
            free_asids: Vec::new(),
            next_asid: 1,
            asid_limit: if asid16 { 1 << 16 } else { 1 << 8 },
            asid0_root: None,
            loaded: None,
            ttbr0: 0,
            flush: true,
            flush_page: None,
            flushes: Flushes::default(),
            timer_armed: false,
            min_runtime: 0,
            ticks_per_sec,
            shared,
            _not_send: PhantomData,
        })
    }

    /// A handle that ends every app from any thread.
    pub fn killer(&self) -> AppKiller {
        AppKiller {
            shared: Arc::clone(&self.shared),
        }
    }

    /// App memory and page-table memory in use, in bytes.
    pub fn memory_in_use(&self) -> (u64, u64) {
        (self.phys.ram_in_use(), self.phys.tables_in_use())
    }

    /// How often TLB entries were invalidated so far.
    pub fn flushes(&self) -> Flushes {
        self.flushes
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

    fn root(&mut self, key: TaskKey) -> Result<u64, PlatformError> {
        let space = self.stopped(key)?.space;
        Ok(self.spaces[&space].root)
    }

    /// Saves the vCPU's registers into the loaded task.
    fn unload(&mut self) -> Result<(), PlatformError> {
        let Some(key) = self.loaded.take() else {
            return Ok(());
        };
        let context = self.read_vcpu().map_err(host_err)?;
        if let Some(task) = self.tasks.get_mut(&key) {
            task.saved = Some(context);
        }
        Ok(())
    }

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

    /// Puts `key`'s registers and address space into the vCPU.
    ///
    /// Each space has its own ASID, so the TLB may hold entries of every
    /// space at once and a switch needs no flush. An entry is stale only
    /// if a space's tables changed since it was cached, and every such
    /// change makes the next entry into the app invalidate it: the whole
    /// TLB, or that page of that ASID (`Phys::take_stale`, [`Self::enter`]).
    /// An ASID is reused only after its space is
    /// gone, which frees the space's tables and so flushes too. Spaces
    /// that found no free ASID share ASID 0: switching between two of
    /// them flushes.
    fn load(&mut self, key: TaskKey) -> Result<(), PlatformError> {
        if self.loaded != Some(key) {
            self.unload()?;
            let task = self.task(key)?;
            let context = task
                .saved
                .take()
                .expect("a task not loaded has saved registers");
            self.write_vcpu(&context).map_err(host_err)?;
            self.loaded = Some(key);
        }
        let space = &self.spaces[&self.tasks[&key].space];
        let (root, asid) = (space.root, space.asid);
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

    fn set_x0(&mut self, key: TaskKey, value: u64) -> Result<(), PlatformError> {
        if self.loaded == Some(key) {
            return self.vcpu.set_reg(0, value).map_err(host_err);
        }
        let task = self.task(key)?;
        task.saved.as_mut().expect("saved registers").x[0] = value;
        Ok(())
    }

    /// Ends a task; its address space goes with its last task.
    fn remove(&mut self, key: TaskKey) {
        let Some(task) = self.tasks.remove(&key) else {
            return;
        };
        if self.loaded == Some(key) {
            self.loaded = None;
        }
        let space = self.spaces.get_mut(&task.space).expect("task's space");
        space.users -= 1;
        if space.users == 0 {
            let (root, asid) = (space.root, space.asid);
            self.spaces.remove(&task.space);
            // Frees its tables, so the TLB is flushed before the app runs
            // again: its frames and its ASID can be reused safely.
            self.phys.destroy(root);
            if self.ttbr0 & layout::pte::ADDR_MASK == root {
                self.ttbr0 = 0;
            }
            if self.asid0_root == Some(root) {
                self.asid0_root = None;
            }
            if asid != 0 {
                self.free_asids.push(asid);
            }
        }
    }

    /// Sets the timer that ends the next run at `deadline`.
    fn arm_timer(&mut self, deadline: Option<Instant>) -> Result<(), sys::HvError> {
        match deadline {
            None => {
                if self.timer_armed {
                    self.vcpu.set_sys_reg(sysreg::CNTV_CTL_EL0, 0)?;
                    self.timer_armed = false;
                }
            }
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                let ticks = (left.as_nanos() * u128::from(self.ticks_per_sec) / 1_000_000_000)
                    .min(u128::from(u64::MAX / 2)) as u64;
                let cval = self.vcpu.guest_counter()?.saturating_add(ticks);
                self.vcpu.set_sys_reg(sysreg::CNTV_CVAL_EL0, cval)?;
                // ENABLE, interrupt not masked: the framework exits with
                // HV_EXIT_REASON_VTIMER_ACTIVATED when it fires.
                self.vcpu.set_sys_reg(sysreg::CNTV_CTL_EL0, 1)?;
                self.vcpu.set_vtimer_mask(false)?;
                self.timer_armed = true;
            }
        }
        Ok(())
    }

    /// Points the vCPU at the app: straight to EL0, or through the shim's
    /// flush routine if page tables changed.
    fn enter(&mut self, key: TaskKey) -> Result<(), sys::HvError> {
        // The only way into the app: no stale entry survives to run it.
        match self.phys.take_stale() {
            Stale::Clean => {}
            Stale::All => self.flush = true,
            Stale::Page { root, va } => {
                let asid = self
                    .spaces
                    .values()
                    .find(|s| s.root == root)
                    .map(|s| s.asid);
                match (asid, self.flush_page) {
                    (Some(asid), None) => {
                        self.flush_page = Some(u64::from(asid) << 48 | (va >> 12) & 0xfff_ffff_ffff)
                    }
                    _ => self.flush = true,
                }
            }
        }
        let task = &self.tasks[&key];
        let (pc, pstate) = (task.pc, task.pstate & layout::PSTATE_APP_MASK);
        if self.flush {
            let asid = self.spaces[&task.space].asid;
            if asid != 0 {
                self.asid0_root = None;
            }
            self.vcpu.set_sys_reg(sysreg::ELR_EL1, pc)?;
            self.vcpu.set_sys_reg(sysreg::SPSR_EL1, pstate)?;
            self.vcpu.set_reg(HV_REG_PC, SHIM_VA + FLUSH_OFFSET)?;
            self.vcpu.set_reg(HV_REG_CPSR, layout::PSTATE_EL1H_MASKED)?;
            self.flush = false;
            self.flush_page = None;
            self.flushes.all += 1;
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
            self.flushes.page += 1;
        } else {
            self.vcpu.set_reg(HV_REG_PC, pc)?;
            self.vcpu.set_reg(HV_REG_CPSR, pstate)?;
        }
        Ok(())
    }

    /// The runnable task to run next, and whether another one is waiting.
    ///
    /// Scheduling on the one vCPU: each task has a runtime, the time it
    /// spent in the vCPU, and the runnable task with the least runtime
    /// runs next. A task that mostly waits (for a pipe, a child) runs as
    /// soon as it can; a task that never traps uses up its slice and lets
    /// the others run (see [`Platform::wait`]). A task that becomes
    /// runnable starts at most one slice behind the least runtime of a
    /// task chosen to run, so time it spent waiting gives it no claim on
    /// the vCPU later.
    fn next_runnable(&self) -> Option<(TaskKey, bool)> {
        let mut best: Option<(u64, TaskKey)> = None;
        let mut runnable = 0;
        for (&key, task) in &self.tasks {
            if task.state == State::Runnable {
                runnable += 1;
                if best.is_none_or(|best| task.runtime < best.0) {
                    best = Some((task.runtime, key));
                }
            }
        }
        best.map(|(_, key)| (key, runnable > 1))
    }

    /// The runtime a task that becomes runnable starts from.
    fn catch_up(&self, runtime: u64) -> u64 {
        runtime.max(self.min_runtime.saturating_sub(SLICE.as_nanos() as u64))
    }

    /// No task to run: waits for a waker or the deadline.
    fn idle(&self, deadline: Option<Instant>) -> Option<Event> {
        let mut state = self.shared.lock();
        loop {
            if state.woken {
                state.woken = false;
                return None;
            }
            match deadline {
                None => {
                    state = self
                        .shared
                        .cond
                        .wait(state)
                        .unwrap_or_else(|e| e.into_inner())
                }
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return None;
                    }
                    state = self
                        .shared
                        .cond
                        .wait_timeout(state, left)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            }
        }
    }

    /// Ends a task the platform cannot run any more, as [`Trap::Gone`].
    fn gone(&mut self, key: TaskKey, why: &str) -> Event {
        log::error!("HVF platform: task {key}: {why}; ending it");
        self.remove(key);
        Event {
            task: key,
            trap: Trap::Gone,
        }
    }

    fn stop(&mut self, key: TaskKey, trap: Trap) -> Option<Event> {
        let task = self.tasks.get_mut(&key).expect("the running task");
        task.state = State::Stopped;
        Some(Event { task: key, trap })
    }

    /// Runs `key` until it traps, the deadline passes or a waker fires.
    fn run(
        &mut self,
        key: TaskKey,
        deadline: Option<Instant>,
    ) -> Result<Option<Event>, PlatformError> {
        self.load(key)?;
        self.arm_timer(deadline).map_err(host_err)?;
        // Faults on a page that is ready, in a row: (page, count).
        let mut retries = (u64::MAX, 0u32);
        let mut reenter = true;
        loop {
            if reenter {
                self.enter(key).map_err(host_err)?;
            }
            reenter = true;
            let exit = self.vcpu.run().map_err(host_err)?;
            let event = match exit.reason {
                HV_EXIT_REASON_CANCELED | HV_EXIT_REASON_VTIMER_ACTIVATED => {
                    if exit.reason == HV_EXIT_REASON_VTIMER_ACTIVATED {
                        self.vcpu
                            .set_sys_reg(sysreg::CNTV_CTL_EL0, 0)
                            .map_err(host_err)?;
                        self.timer_armed = false;
                    }
                    match self.interrupted_at(key)? {
                        Interrupted::Settled => return Ok(None),
                        // In a vector, about to leave the VM with an
                        // exception of the app: let it, with the vCPU's
                        // state as it is.
                        Interrupted::InVector => {
                            reenter = false;
                            continue;
                        }
                        Interrupted::Lost(why) => Some(self.gone(key, &why)),
                    }
                }
                HV_EXIT_REASON_EXCEPTION => self.on_exception(key, &exit, &mut retries)?,
                other => Some(self.gone(key, &format!("unexpected exit reason {other}"))),
            };
            if let Some(event) = event {
                return Ok(Some(event));
            }
        }
    }

    /// Saves where the app was when the vCPU was stopped from outside (by
    /// `hv_vcpus_exit` or the timer), which can be anywhere.
    fn interrupted_at(&mut self, key: TaskKey) -> Result<Interrupted, PlatformError> {
        let cpsr = self.vcpu.reg(HV_REG_CPSR).map_err(host_err)?;
        let pc = self.vcpu.reg(HV_REG_PC).map_err(host_err)?;
        if cpsr & 0xf == 0 {
            // In the app (EL0t).
            let task = self.tasks.get_mut(&key).expect("the running task");
            task.pc = pc;
            task.pstate = cpsr & layout::PSTATE_APP_MASK;
            return Ok(Interrupted::Settled);
        }
        if (SHIM_VA..SHIM_VA + FLUSH_OFFSET).contains(&pc) {
            return Ok(Interrupted::InVector);
        }
        if (SHIM_VA + FLUSH_PAGE_OFFSET..SHIM_VA + PAGE).contains(&pc) {
            // In the page flush routine: x0 may still be its operand. The
            // app's own is in TPIDR_EL1; it starts over from `task.pc`,
            // with a whole flush.
            let x0 = self.vcpu.sys_reg(sysreg::TPIDR_EL1).map_err(host_err)?;
            self.vcpu.set_reg(0, x0).map_err(host_err)?;
            self.flush = true;
            return Ok(Interrupted::Settled);
        }
        if (SHIM_VA + FLUSH_OFFSET..SHIM_VA + PAGE).contains(&pc) {
            // In the flush routine, before the app ran: it starts over
            // from `task.pc`, flushing again.
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
        key: TaskKey,
        exit: &HvVcpuExit,
        retries: &mut (u64, u32),
    ) -> Result<Option<Event>, PlatformError> {
        let v = &self.vcpu;
        let (esr, far, pc) = match exit::hvc_immediate(exit.syndrome) {
            // `hvc` is undefined at EL0, so this came from a vector of the
            // shim: the registers are the app's, ELR/SPSR/ESR/FAR say what
            // happened.
            Some(slot) => {
                let pc = v.sys_reg(sysreg::ELR_EL1).map_err(host_err)?;
                let pstate = v.sys_reg(sysreg::SPSR_EL1).map_err(host_err)?;
                let task = self.tasks.get_mut(&key).expect("the running task");
                task.pc = pc;
                task.pstate = pstate & layout::PSTATE_APP_MASK;
                match slot {
                    layout::VECTOR_LOWER_SYNC => {}
                    layout::VECTOR_LOWER_IRQ | layout::VECTOR_LOWER_FIQ => {
                        // Nothing raises interrupts in this VM; harmless.
                        return Ok(self.stop(key, Trap::Interrupted));
                    }
                    slot => {
                        let why = format!(
                            "exception at vector {slot} (SError, or one taken at EL1), \
                             pc {pc:#x} spsr {pstate:#x}"
                        );
                        return Ok(Some(self.gone(key, &why)));
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
                    let why = format!(
                        "exit to the host with syndrome {:#x} at pc {pc:#x}, cpsr {cpsr:#x}, \
                         address {:#x} (guest-physical {:#x})",
                        exit.syndrome, exit.virtual_address, exit.physical_address
                    );
                    return Ok(Some(self.gone(key, &why)));
                }
                let task = self.tasks.get_mut(&key).expect("the running task");
                task.pc = pc;
                task.pstate = cpsr & layout::PSTATE_APP_MASK;
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
                Ok(self.stop(key, Trap::Syscall(trap)))
            }
            AppException::Skip => {
                let task = self.tasks.get_mut(&key).expect("the running task");
                task.pc = task.pc.wrapping_add(4);
                Ok(None)
            }
            AppException::Fault(fault) => Ok(self.stop(key, Trap::Fault(fault))),
            AppException::Translation { addr, access } => {
                Ok(self.page_fault(key, addr, access, SEGV_MAPERR, retries))
            }
            AppException::Permission { addr, access } => {
                Ok(self.page_fault(key, addr, access, SEGV_ACCERR, retries))
            }
        }
    }

    /// A translation or permission fault at `addr`: memory on first touch,
    /// a copy for a copy-on-write page, or `SIGSEGV` (with `code` when the
    /// page is not mapped, or allows the access after all).
    fn page_fault(
        &mut self,
        key: TaskKey,
        addr: u64,
        access: Access,
        code: i32,
        retries: &mut (u64, u32),
    ) -> Option<Event> {
        let space = self.tasks[&key].space;
        let root = self.spaces[&space].root;
        let fault = |code| {
            Trap::Fault(Fault {
                signal: 11,
                code,
                addr: Some(addr),
            })
        };
        match self.phys.demand(root, addr, access) {
            Demand::Filled => None,
            // The TLB may still hold what the page was before it changed:
            // flush and retry, a few times.
            Demand::Present if retries.0 != addr >> 12 || retries.1 < 4 => {
                *retries = match *retries {
                    (page, n) if page == addr >> 12 => (page, n + 1),
                    _ => (addr >> 12, 1),
                };
                self.flush = true;
                None
            }
            Demand::Present | Demand::Unmapped => self.stop(key, fault(code)),
            Demand::Denied => self.stop(key, fault(SEGV_ACCERR)),
            // The sandbox's memory is used up: this process ends, as the
            // OOM killer would end it on Linux, and the others go on.
            Demand::NoMemory => {
                log::warn!("HVF platform: task {key}: out of memory at {addr:#x}; killing it");
                self.stop(
                    key,
                    Trap::Fault(Fault {
                        signal: SIGKILL,
                        code: SI_KERNEL,
                        addr: Some(addr),
                    }),
                )
            }
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
        let root = self.phys.new_space().map_err(|err| mmu_err(err, 0, 0))?;
        let space = self.add_space(root);
        let key = self.next_key;
        self.next_key += 1;
        let Context::Aarch64(saved) = Context::zeroed(Arch::Aarch64) else {
            unreachable!("asked for aarch64");
        };
        self.tasks.insert(
            key,
            Task {
                space,
                state: State::New,
                pc: 0,
                pstate: 0,
                saved: Some(saved),
                interrupt: false,
                runtime: self.min_runtime,
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
        let task = self.stopped(parent)?;
        let (pc, pstate, space) = (task.pc, task.pstate, task.space);
        let space = if share_memory {
            self.spaces.get_mut(&space).expect("task's space").users += 1;
            space
        } else {
            let root = self.spaces[&space].root;
            let copy = self.phys.fork(root).map_err(|err| match err {
                MmuError::NoMemory => PlatformError::NoResources(
                    "the sandbox's memory or page tables are used up".into(),
                ),
                MmuError::BadAddress => PlatformError::Violation("bad address space".into()),
            })?;
            self.add_space(copy)
        };
        let key = self.next_key;
        self.next_key += 1;
        self.tasks.insert(
            key,
            Task {
                space,
                state: State::Stopped,
                pc,
                pstate,
                saved: Some(saved),
                interrupt: false,
                runtime: self.min_runtime,
            },
        );
        Ok(key)
    }

    fn kill(&mut self, key: TaskKey) -> Result<(), PlatformError> {
        // A task this platform already ended (reported as `Trap::Gone`)
        // is killed already.
        if !self.tasks.contains_key(&key) && key < self.next_key {
            return Ok(());
        }
        self.task(key)?;
        self.remove(key);
        Ok(())
    }

    fn context(&mut self, key: TaskKey) -> Result<Context, PlatformError> {
        let task = self.stopped(key)?;
        let (pc, pstate, saved) = (task.pc, task.pstate, task.saved.clone());
        let mut context = match saved {
            Some(saved) => saved,
            None => self.read_vcpu().map_err(host_err)?,
        };
        context.pc = pc;
        context.pstate = pstate;
        Ok(Context::Aarch64(context))
    }

    fn set_context(&mut self, key: TaskKey, context: &Context) -> Result<(), PlatformError> {
        let Context::Aarch64(context) = context else {
            return Err(PlatformError::Unsupported("x86_64 contexts on aarch64"));
        };
        let loaded = self.loaded == Some(key);
        let task = self.stopped(key)?;
        task.pc = context.pc;
        task.pstate = context.pstate & layout::PSTATE_APP_MASK;
        if !loaded {
            task.saved = Some(context.clone());
            return Ok(());
        }
        self.write_vcpu(context).map_err(host_err)
    }

    fn resume(&mut self, key: TaskKey, resume: Resume) -> Result<(), PlatformError> {
        self.stopped(key)?;
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
        let runtime = self.task(key)?.runtime;
        let runtime = self.catch_up(runtime);
        let task = self.task(key)?;
        task.state = State::Runnable;
        task.runtime = runtime;
        Ok(())
    }

    fn interrupt(&mut self, key: TaskKey) -> Result<(), PlatformError> {
        self.task(key)?.interrupt = true;
        Ok(())
    }

    fn wait(&mut self, timeout: Option<Duration>) -> Result<Option<Event>, PlatformError> {
        let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
        loop {
            if self.shared.lock().killed {
                let Some(&key) = self.tasks.keys().next() else {
                    return Ok(self.idle(deadline));
                };
                self.remove(key);
                return Ok(Some(Event {
                    task: key,
                    trap: Trap::Gone,
                }));
            }
            let interrupted = self
                .tasks
                .iter_mut()
                .find(|(_, task)| task.interrupt && task.state == State::Runnable);
            if let Some((&key, task)) = interrupted {
                task.interrupt = false;
                task.state = State::Stopped;
                return Ok(Some(Event {
                    task: key,
                    trap: Trap::Interrupted,
                }));
            }
            let Some((key, contended)) = self.next_runnable() else {
                return Ok(self.idle(deadline));
            };
            let started = Instant::now();
            self.min_runtime = self.min_runtime.max(self.tasks[&key].runtime);
            // Preemption: while another task waits to run, this one runs
            // for one slice at most, so an app that never traps cannot
            // keep the others from running.
            let slice_end = contended
                .then(|| Instant::now().checked_add(SLICE))
                .flatten();
            let until = match (deadline, slice_end) {
                (Some(deadline), Some(slice_end)) => Some(deadline.min(slice_end)),
                (deadline, slice_end) => deadline.or(slice_end),
            };
            {
                let mut state = self.shared.lock();
                if state.woken {
                    state.woken = false;
                    return Ok(None);
                }
                state.in_run = true;
            }
            let result = self.run(key, until);
            if let Some(task) = self.tasks.get_mut(&key) {
                let ran = started.elapsed().as_nanos() as u64;
                task.runtime = task.runtime.saturating_add(ran);
            }
            let mut state = self.shared.lock();
            state.in_run = false;
            match result {
                Ok(None) => {
                    if std::mem::take(&mut state.woken)
                        || deadline.is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        return Ok(None);
                    }
                    // The slice ended: on to the next runnable task.
                }
                other => return other,
            }
        }
    }

    fn waker(&self) -> Waker {
        let shared = Arc::clone(&self.shared);
        Waker::new(move || shared.wake())
    }

    fn read(&mut self, key: TaskKey, addr: GuestAddr, buf: &mut [u8]) -> Result<(), PlatformError> {
        let root = self.root(key)?;
        self.phys
            .read(root, addr, buf)
            .map_err(|err| mmu_err(err, addr, buf.len() as u64))
    }

    fn write(&mut self, key: TaskKey, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError> {
        let root = self.root(key)?;
        self.phys
            .write(root, addr, data)
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
        let root = self.root(key)?;
        self.phys
            .map(root, addr, len, prot, sharing == Sharing::Shared)
            .map_err(|err| mmu_err(err, addr, len))
    }

    fn unmap(&mut self, key: TaskKey, addr: GuestAddr, len: u64) -> Result<(), PlatformError> {
        let root = self.root(key)?;
        self.phys
            .unmap(root, addr, len)
            .map_err(|err| mmu_err(err, addr, len))
    }

    fn protect(
        &mut self,
        key: TaskKey,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
    ) -> Result<(), PlatformError> {
        let root = self.root(key)?;
        self.phys
            .protect(root, addr, len, prot)
            .map_err(|err| mmu_err(err, addr, len))
    }
}

impl Drop for HvfPlatform {
    fn drop(&mut self) {
        // Stage-2 mappings go with the VM; unmapping first keeps the order
        // obvious and the memory unreachable even if destroying fails.
        for (ipa, len) in [
            (layout::SHIM_IPA, layout::SHIM_REGION as usize),
            (layout::TABLES_IPA, self.phys.tables_backing().len()),
            (layout::RAM_IPA, self.phys.ram_backing().len()),
        ] {
            if let Err(err) = self.vm.unmap(ipa, len) {
                log::warn!("{err}");
            }
        }
    }
}

/// Where a system call round trip's time goes (README, "The HVF
/// platform"): `cargo test --release -p hellovm-platform-hvf --lib --
/// --ignored --nocapture exit_cost`.
#[cfg(test)]
mod breakdown {
    use super::*;

    #[test]
    #[ignore = "benchmark"]
    fn exit_cost_breakdown() {
        let _guard = super::vm_tests::VM
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig::default()) {
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
            p.vcpu.set_reg(HV_REG_PC, 0x10000).unwrap();
            p.vcpu.set_reg(HV_REG_CPSR, 0).unwrap();
            p.vcpu.run().unwrap();
        }
        let bare = start.elapsed() / N;
        let start = Instant::now();
        let mut sum = 0u64;
        for _ in 0..N {
            sum = sum.wrapping_add(p.vcpu.reg(3).unwrap());
        }
        let get = start.elapsed() / N;
        let start = Instant::now();
        for _ in 0..N {
            sum = sum.wrapping_add(p.vcpu.sys_reg(sysreg::ELR_EL1).unwrap());
        }
        let sys = start.elapsed() / N;
        let start = Instant::now();
        for _ in 0..N {
            p.vcpu.set_reg(0, sum).unwrap();
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

    /// With ASIDs used up, new spaces share ASID 0, and switching between
    /// two of them flushes: each process still reads its own page.
    #[test]
    fn spaces_beyond_the_asids_share_one_and_flush() {
        let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
        let mut p = match HvfPlatform::new(HvfConfig::default()) {
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
        p.asid_limit = 2;
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
            .map(|t| p.spaces[&p.tasks[t].space].asid)
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
}
