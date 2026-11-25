//! [`Kvm`]: KVM as the hypervisor of the shared arm64 platform
//! (`hellovm-platform-arm64`).
//!
//! Nothing interrupts the app: the VM has no interrupt controller and no
//! timer interrupts (virtual interrupt lines did not reach the guest
//! under the nested virtualization of the Mac this was built on, and are
//! not needed). A kick ([`KvmKicker`], from any thread: a waker, an event
//! for the event loop, a TLB shootdown, the killer; and the clock thread
//! when a vCPU's deadline has passed) sets the stop flag in the vCPU's
//! frame and `immediate_exit` in its `kvm_run`, and sends the vCPU's
//! thread a signal, so that `KVM_RUN` returns `EINTR` (at once, if the
//! vCPU was not in it). The vCPU then leaves through the shim:
//!
//! * at EL0 (the app was running; `PSTATE` read with
//!   `KVM_GET_ONE_REG`): the host has KVM inject a synchronous external
//!   data abort (`KVM_SET_VCPU_EVENTS`), which KVM enters itself, in
//!   software, at the shim's vector for EL0; the vector saves the app's
//!   registers and exits as for any exception;
//! * at EL1 (in the shim): it runs on and leaves by itself, through the
//!   exit of the save routine or the stop check before the restore
//!   routine's `eret`; if it was stopped after that check had loaded
//!   the flag and before the `eret`, the host moves its `PC` back to the
//!   check first.
//!
//! The stop flag is cleared by the exit it causes.
//!
//! Every vCPU is made with the VM, on the calling thread, and the clock
//! and vCPU threads start later (`Hypervisor::DEFER_THREADS`), once the
//! kernel process has confined itself: on Linux a process that has a
//! second thread can neither enter a user namespace nor put its other
//! threads under Landlock.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use hellovm_core::platform::Aarch64Context;
use hellovm_platform_arm64::layout::{self, sysreg, PAGE, SHIM_VA};
use hellovm_platform_arm64::mmu::{MmuError, Phys};
use hellovm_platform_arm64::{
    Backing, El1Page, Exit, Flush, Hypervisor, IdRegs, Kicker, Reg, Stopped, Vcpu, MAX_VCPUS,
};

use crate::shim::{self, frame, EXIT_IPA, EXIT_VA, FRAMES_IPA, FRAMES_VA};
use crate::sys::{self, HostMem, VcpuFd, VmFd};

/// `MAIR_EL1`: attribute 0 as on HVF (normal write-back memory), 1 is
/// device memory (nGnRE), for the exit page.
const MAIR_EL1: u64 = layout::MAIR_EL1 | 0x04 << 8;

/// Memory slots.
const SLOT_SHIM: u32 = 0;
const SLOT_TABLES: u32 = 1;
const SLOT_RAM: u32 = 2;
const SLOT_FRAMES: u32 = 3;

impl Backing for HostMem {
    fn bytes(&self) -> &[u8] {
        self.slice(0, self.len())
    }

    fn len(&self) -> usize {
        HostMem::len(self)
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.slice_mut(0, self.len())
    }

    fn sync_icache(&mut self, offset: usize, len: usize) {
        self.check_range(offset, len);
        // SAFETY: in bounds (checked); only cache maintenance.
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

    fn give_back(&mut self, offset: usize, len: usize) {
        HostMem::give_back(self, offset, len)
    }

    fn take_back(&mut self, _offset: usize, _len: usize) {}
}

/// Makes a vCPU leave the VM (now, or at once in its next run): see the
/// module documentation.
#[derive(Clone)]
pub struct KvmKicker {
    /// The frames, kept mapped as long as a kicker lives.
    frames: Arc<HostMem>,
    /// This vCPU's frame in them.
    frame: usize,
    run: Arc<sys::RunMap>,
    /// The thread that runs the vCPU (0 before it first ran).
    tid: Arc<AtomicI32>,
}

impl KvmKicker {
    fn stop_flag(&self) -> &AtomicU64 {
        // SAFETY: the stop word of this vCPU's frame, in bounds and
        // aligned (frames are pages of `frames`, which `self` keeps
        // mapped); shared with the shim and the vCPU's thread, which use
        // it only through atomic accesses and the shim's loads.
        unsafe { AtomicU64::from_ptr(self.frames.ptr().add(self.frame + frame::STOP).cast()) }
    }
}

impl Kicker for KvmKicker {
    #[inline]
    fn kick(&self) {
        // A stop asked for already and not yet made covers this one (its
        // signal is on its way, or `immediate_exit` waits for the next
        // run): a TLB shootdown that kicks again and again while it waits
        // for the vCPU costs no more signals.
        if self.stop_flag().swap(1, SeqCst) != 0 {
            return;
        }
        self.run.set_immediate_exit(true);
        let tid = self.tid.load(SeqCst);
        if tid != 0 {
            sys::kick_thread(tid);
        }
    }
}

/// The deadlines of the vCPUs, kept by the clock thread, which starts
/// with the first deadline (after the kernel process confined itself).
struct Clock {
    state: Mutex<ClockState>,
    cv: Condvar,
    thread: Mutex<Option<JoinHandle<()>>>,
}

struct ClockState {
    deadlines: Vec<Option<Instant>>,
    kickers: Vec<Option<KvmKicker>>,
    quit: bool,
}

impl Clock {
    fn lock(&self) -> std::sync::MutexGuard<'_, ClockState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The clock thread: kicks each vCPU whose deadline passed.
    #[inline]
    fn run(&self) {
        let mut state = self.lock();
        while !state.quit {
            let now = Instant::now();
            let mut next: Option<Instant> = None;
            for index in 0..state.deadlines.len() {
                match state.deadlines[index] {
                    Some(at) if at <= now => {
                        state.deadlines[index] = None;
                        if let Some(kicker) = &state.kickers[index] {
                            kicker.kick();
                        }
                    }
                    Some(at) => next = Some(next.map_or(at, |n: Instant| n.min(at))),
                    None => {}
                }
            }
            state = match next {
                Some(at) => {
                    self.cv
                        .wait_timeout(state, at.saturating_duration_since(now))
                        .unwrap_or_else(|e| e.into_inner())
                        .0
                }
                None => self.cv.wait(state).unwrap_or_else(|e| e.into_inner()),
            };
        }
    }

    fn set(self: &Arc<Self>, index: usize, deadline: Option<Instant>) -> io::Result<()> {
        if deadline.is_some() {
            let mut thread = self.thread.lock().unwrap_or_else(|e| e.into_inner());
            if thread.is_none() {
                let clock = Arc::clone(self);
                *thread = Some(
                    std::thread::Builder::new()
                        .name("hellovm-clock".into())
                        .spawn(move || clock.run())?,
                );
            }
        }
        let mut state = self.lock();
        let earlier = match (deadline, state.deadlines[index]) {
            (Some(new), Some(old)) => new < old,
            (Some(_), None) => true,
            (None, _) => false,
        };
        state.deadlines[index] = deadline;
        drop(state);
        if earlier {
            self.cv.notify_one();
        }
        Ok(())
    }
}

/// What a vCPU thread needs to make its vCPU.
#[derive(Clone)]
pub struct KvmToken {
    vm: Arc<OwnedFd>,
    run_len: usize,
    init: sys::VcpuInit,
    /// The frames region (its pages are the vCPUs').
    frames: Arc<HostMem>,
    clock: Arc<Clock>,
    vcpu_fds: Arc<Mutex<Vec<RawFd>>>,
}

/// A VM of KVM with the shim, the vCPUs' frames and the clock thread.
pub struct Kvm {
    // Field order is drop order: the clock thread is stopped in `release`.
    vm: VmFd,
    _shim: HostMem,
    frames: Arc<HostMem>,
    run_len: usize,
    init: sys::VcpuInit,
    max_vcpus: u32,
    clock: Arc<Clock>,
    vcpu_fds: Arc<Mutex<Vec<RawFd>>>,
}

impl Kvm {
    /// The fds a confined kernel process keeps using: each vCPU's (for
    /// `KVM_RUN`, and to stop it: `KVM_GET_ONE_REG`, `KVM_SET_ONE_REG`,
    /// `KVM_SET_VCPU_EVENTS`).
    pub fn vcpu_fds(&self) -> Vec<RawFd> {
        self.vcpu_fds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn stop_clock(&mut self) {
        self.clock.lock().quit = true;
        self.clock.cv.notify_all();
        let thread = self
            .clock
            .thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }
}

impl Drop for Kvm {
    fn drop(&mut self) {
        self.stop_clock();
    }
}

impl Hypervisor for Kvm {
    const NAME: &'static str = "KVM";
    const SNAPSHOT_PREFIX: &'static str = "hellovm-kvm-";
    // The kernel process confines itself after the platform is made,
    // and on Linux that must happen before it has a second thread.
    const DEFER_THREADS: bool = true;
    type Mem = HostMem;
    type Token = KvmToken;
    type Vcpu = KvmVcpu;
    type Kicker = KvmKicker;

    fn create(memory: usize, table_memory: usize) -> io::Result<(Kvm, HostMem, HostMem)> {
        let host_page = page_size();
        if host_page > sys::HOST_PAGE {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "KVM platform: host pages of {host_page} bytes (at most {} supported)",
                    sys::HOST_PAGE
                ),
            ));
        }
        let kvm = sys::Kvm::open()?;
        for (cap, name) in sys::CAPS {
            if kvm.extension(cap) <= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("KVM platform: the host's KVM lacks {name}"),
                ));
            }
        }
        let run_len = kvm.vcpu_mmap_size()?;
        let vm = kvm.create_vm()?;
        // `/dev/kvm` itself is not needed any more.
        drop(kvm);
        let max_vcpus = match vm.extension(sys::KVM_CAP_MAX_VCPUS) {
            n if n > 0 => n,
            _ => vm.extension(sys::KVM_CAP_NR_VCPUS).max(1),
        } as u32;
        let init = vm.preferred_target()?;
        sys::install_kick_handler()?;
        let mut shim = HostMem::new(layout::SHIM_REGION as usize)?;
        let frames = Arc::new(HostMem::new(
            (MAX_VCPUS * PAGE as usize).next_multiple_of(sys::HOST_PAGE),
        )?);
        let tables = HostMem::new(table_memory)?;
        let ram = HostMem::new(memory)?;
        let (code, _, _) = shim::code();
        shim.slice_mut(0, code.len()).copy_from_slice(code);
        shim.sync_icache(0, code.len());
        // SAFETY: each region lives until after the VM is closed (the
        // shim and frames in `Kvm`, after its fd; the pools in the
        // platform, which drops its `Kvm` first) and holds only what the
        // guest may see: the shim, its frames, the page tables (read
        // only) and app memory.
        unsafe {
            vm.map(SLOT_SHIM, shim.ptr(), layout::SHIM_IPA, shim.len(), true)?;
            vm.map(
                SLOT_TABLES,
                tables.ptr(),
                layout::TABLES_IPA,
                tables.len(),
                true,
            )?;
            vm.map(SLOT_RAM, ram.ptr(), layout::RAM_IPA, ram.len(), false)?;
            vm.map(SLOT_FRAMES, frames.ptr(), FRAMES_IPA, frames.len(), false)?;
        }
        let clock = Arc::new(Clock {
            state: Mutex::new(ClockState {
                deadlines: vec![None; MAX_VCPUS],
                kickers: vec![None; MAX_VCPUS],
                quit: false,
            }),
            cv: Condvar::new(),
            thread: Mutex::new(None),
        });
        let kvm = Kvm {
            vm,
            _shim: shim,
            frames,
            run_len,
            init,
            max_vcpus,
            clock,
            vcpu_fds: Arc::new(Mutex::new(Vec::new())),
        };
        Ok((kvm, tables, ram))
    }

    fn shim_space(&self, phys: &mut Phys<HostMem>) -> Result<u64, MmuError> {
        let mut extra: Vec<El1Page> = (0..MAX_VCPUS as u64)
            .map(|i| El1Page {
                va: FRAMES_VA + i * PAGE,
                ipa: FRAMES_IPA + i * PAGE,
                writable: true,
                attr_index: 0,
            })
            .collect();
        extra.push(El1Page {
            va: EXIT_VA,
            ipa: EXIT_IPA,
            writable: true,
            attr_index: 1,
        });
        phys.shim_space_with(&extra)
    }

    fn max_vcpus(&self) -> u32 {
        self.max_vcpus
    }

    fn token(&self) -> KvmToken {
        KvmToken {
            vm: self.vm.shared(),
            run_len: self.run_len,
            init: self.init,
            frames: Arc::clone(&self.frames),
            clock: Arc::clone(&self.clock),
            vcpu_fds: Arc::clone(&self.vcpu_fds),
        }
    }

    fn vcpu(token: KvmToken, index: usize) -> io::Result<KvmVcpu> {
        if index >= MAX_VCPUS {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: `vm` is the VM's fd, open as long as the `Kvm`, which
        // outlives every vCPU.
        let fd = unsafe { sys::create_vcpu(token.vm.as_raw_fd(), index as u64)? };
        let fd = VcpuFd::new(fd, token.run_len)?;
        fd.init(&token.init)?;
        token
            .vcpu_fds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(fd.raw());
        let kicker = KvmKicker {
            frames: Arc::clone(&token.frames),
            frame: index * PAGE as usize,
            run: fd.run_map(),
            tid: Arc::new(AtomicI32::new(0)),
        };
        token.clock.lock().kickers[index] = Some(kicker.clone());
        Ok(KvmVcpu {
            fd,
            // SAFETY: page `index` of the frames (`index` < MAX_VCPUS),
            // which the kicker keeps mapped.
            frame: unsafe { token.frames.ptr().add(index * PAGE as usize) },
            index,
            kicker,
            clock: token.clock,
            armed: None,
            broken: None,
            injected: false,
        })
    }

    /// Stops the clock thread. The memory slots stay: closing the VM's
    /// and vCPUs' fds ends the VM, and the confined process may not
    /// change its memory slots (`allowlist::kvm_entries`); memory unmapped
    /// before the last fd is closed is taken out of the VM by KVM itself
    /// (its MMU notifier), and no vCPU runs again by then.
    fn release(&mut self, _table_memory: usize, _memory: usize) {
        self.stop_clock();
    }
}

fn page_size() -> usize {
    // SAFETY: plain libc call.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).unwrap_or(4096)
}

/// A vCPU of the VM, with its frame.
pub struct KvmVcpu {
    fd: VcpuFd,
    /// The host's view of this vCPU's frame page: written by the shim
    /// only while the vCPU runs, by this thread only while it does not.
    frame: *mut u8,
    index: usize,
    kicker: KvmKicker,
    clock: Arc<Clock>,
    /// The deadline given to the clock thread.
    armed: Option<Instant>,
    /// Why the vCPU cannot run any more, after an exit that left it
    /// somewhere it cannot go on from.
    broken: Option<String>,
    /// An external abort was injected to stop it, and its exit has not
    /// come yet.
    injected: bool,
}

impl KvmVcpu {
    fn get(&self, offset: usize) -> u64 {
        assert!(offset + 8 <= frame::SIZE && offset.is_multiple_of(8));
        // SAFETY: in the frame page (checked), aligned; not written while
        // this thread reads (the vCPU is not running).
        unsafe { std::ptr::read_volatile(self.frame.add(offset).cast::<u64>()) }
    }

    fn put(&mut self, offset: usize, value: u64) {
        assert!(offset + 8 <= frame::SIZE && offset.is_multiple_of(8));
        // SAFETY: as in `get`.
        unsafe { std::ptr::write_volatile(self.frame.add(offset).cast::<u64>(), value) }
    }

    /// After `KVM_RUN` returned `EINTR` with the stop flag set: makes the
    /// vCPU leave through the shim when it runs again (see the module
    /// documentation).
    fn steer_out(&mut self) -> io::Result<()> {
        let pstate = self.fd.get_reg(sys::REG_PSTATE)?;
        if pstate & 0xf == 0 {
            // In the app.
            self.fd.inject_external_abort()?;
            self.injected = true;
            return Ok(());
        }
        let check = SHIM_VA + shim::check_offset();
        let pc = self.fd.get_reg(sys::REG_PC)?;
        // `ldr` and `cbnz` of the check, then `ldp` and `eret`: past the
        // `ldr` the flag is not looked at again (at the `cbnz`, `x0` may
        // hold the flag as it was before this kick set it).
        if (check + 4..=check + 12).contains(&pc) {
            self.fd.set_reg(sys::REG_PC, check)?;
        }
        Ok(())
    }

    /// The exit details, for a message.
    fn describe(&self, reason: u32) -> String {
        match reason {
            sys::KVM_EXIT_MMIO => {
                let (addr, len, write) = self.fd.mmio();
                format!(
                    "MMIO {} of {len} bytes at guest-physical {addr:#x}",
                    if write { "write" } else { "read" }
                )
            }
            sys::KVM_EXIT_FAIL_ENTRY => {
                format!("KVM_EXIT_FAIL_ENTRY, reason {:#x}", self.fd.detail())
            }
            sys::KVM_EXIT_INTERNAL_ERROR => {
                format!(
                    "KVM_EXIT_INTERNAL_ERROR, suberror {}",
                    self.fd.detail() as u32
                )
            }
            sys::KVM_EXIT_SYSTEM_EVENT => {
                format!("KVM_EXIT_SYSTEM_EVENT, type {}", self.fd.detail() as u32)
            }
            other => format!("KVM exit reason {other}"),
        }
    }
}

impl Vcpu for KvmVcpu {
    type Kicker = KvmKicker;

    fn kicker(&self) -> KvmKicker {
        self.kicker.clone()
    }

    fn id_regs(&self) -> io::Result<IdRegs> {
        let get = |reg| self.fd.get_reg(sys::sysreg_id(reg));
        Ok(IdRegs {
            mmfr0: get(sysreg::ID_AA64MMFR0_EL1)?,
            pfr0: get(sysreg::ID_AA64PFR0_EL1)?,
            isar0: get(sysreg::ID_AA64ISAR0_EL1)?,
            isar1: get(sysreg::ID_AA64ISAR1_EL1)?,
        })
    }

    fn set_up(&mut self, tcr: u64, shim_root: u64) -> io::Result<()> {
        for (reg, value) in [
            (sysreg::MAIR_EL1, MAIR_EL1),
            (sysreg::TCR_EL1, tcr),
            (sysreg::TTBR1_EL1, shim_root),
            (sysreg::TTBR0_EL1, 0),
            (sysreg::VBAR_EL1, SHIM_VA),
            (sysreg::CPACR_EL1, layout::CPACR_EL1),
            (sysreg::CNTKCTL_EL1, layout::CNTKCTL_EL1),
            (sysreg::TPIDRRO_EL0, 0),
            (sysreg::SCTLR_EL1, layout::SCTLR_EL1_TRAP_WFX),
        ] {
            self.fd.set_reg(sys::sysreg_id(reg), value)?;
        }
        // The frame is all zero (fresh memory). The vCPU starts in the
        // restore routine, at EL1 with every interrupt masked: the first
        // run enters the app as every later one does.
        let (_, _, restore) = shim::code();
        self.fd
            .set_reg(sys::REG_SP_EL1, FRAMES_VA + self.index as u64 * PAGE)?;
        self.fd.set_reg(sys::REG_PC, SHIM_VA + restore)?;
        self.fd
            .set_reg(sys::REG_PSTATE, layout::PSTATE_EL1H_MASKED)?;
        Ok(())
    }

    fn read_context(&self) -> io::Result<Box<Aarch64Context>> {
        let mut c = Box::new(Aarch64Context {
            x: [0; 31],
            sp: self.get(frame::SP_EL0),
            pc: 0,
            pstate: 0,
            v: [0; 32],
            fpsr: self.get(frame::FPSR) as u32,
            fpcr: self.get(frame::FPCR) as u32,
            tpidr: self.get(frame::TPIDR),
        });
        for (i, x) in c.x.iter_mut().enumerate() {
            *x = self.get(frame::X + 8 * i);
        }
        for (i, q) in c.v.iter_mut().enumerate() {
            let at = frame::V + 16 * i;
            *q = u128::from(self.get(at)) | u128::from(self.get(at + 8)) << 64;
        }
        Ok(c)
    }

    fn write_context(&mut self, c: &Aarch64Context) -> io::Result<()> {
        for (i, &x) in c.x.iter().enumerate() {
            self.put(frame::X + 8 * i, x);
        }
        for (i, &q) in c.v.iter().enumerate() {
            let at = frame::V + 16 * i;
            self.put(at, q as u64);
            self.put(at + 8, (q >> 64) as u64);
        }
        self.put(frame::SP_EL0, c.sp);
        self.put(frame::TPIDR, c.tpidr);
        self.put(frame::FPSR, u64::from(c.fpsr));
        self.put(frame::FPCR, u64::from(c.fpcr));
        Ok(())
    }

    #[inline]
    fn reg(&self, reg: Reg) -> io::Result<u64> {
        Ok(match reg {
            Reg::X(i) => self.get(frame::X + 8 * usize::from(i.min(30))),
            Reg::Pc | Reg::ElrEl1 => self.get(frame::ELR),
            Reg::Cpsr | Reg::SpsrEl1 => self.get(frame::SPSR),
            Reg::EsrEl1 => self.get(frame::ESR),
            Reg::FarEl1 => self.get(frame::FAR),
            Reg::SpEl0 => self.get(frame::SP_EL0),
        })
    }

    #[inline]
    fn set_x0(&mut self, value: u64) -> io::Result<()> {
        self.put(frame::X, value);
        Ok(())
    }

    #[inline]
    fn set_ttbr0(&mut self, value: u64) -> io::Result<()> {
        self.put(frame::TTBR0, value);
        Ok(())
    }

    #[inline]
    fn arm_timer(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        // A deadline that passed goes to the clock again: the kick it
        // made may have been spent on a run that ended for another reason
        // (the vCPU lowers its line after every run).
        if self.armed != deadline || deadline.is_some_and(|at| at <= Instant::now()) {
            self.clock.set(self.index, deadline)?;
            self.armed = deadline;
        }
        Ok(())
    }

    #[inline]
    fn enter(&mut self, pc: u64, pstate: u64, flush: Flush) -> io::Result<()> {
        self.put(frame::ELR, pc);
        self.put(frame::SPSR, pstate);
        let (kind, operand) = match flush {
            Flush::None => (shim::FLUSH_NONE, 0),
            Flush::All => (shim::FLUSH_ALL, 0),
            Flush::Page(operand) => (shim::FLUSH_PAGE, operand),
        };
        self.put(frame::FLUSH, kind);
        self.put(frame::OPERAND, operand);
        Ok(())
    }

    #[inline]
    fn run(&mut self) -> io::Result<Exit> {
        if let Some(why) = &self.broken {
            return Err(io::Error::other(format!(
                "KVM platform: vCPU {}: {why}",
                self.index
            )));
        }
        self.kicker.tid.store(sys::gettid(), SeqCst);
        loop {
            if !self.fd.run()? {
                // A kick (or another signal): `immediate_exit` is spent.
                self.kicker.run.set_immediate_exit(false);
                if self.kicker.stop_flag().load(SeqCst) != 0 {
                    self.steer_out()?;
                }
                continue;
            }
            let reason = self.fd.exit_reason();
            let (addr, len, write) = self.fd.mmio();
            if reason != sys::KVM_EXIT_MMIO || addr != EXIT_IPA || len != 8 || !write {
                // The vCPU did not leave through the shim's exit: there is
                // no saved state to go on from.
                let why = self.describe(reason);
                self.broken = Some(format!("stopped by {why}"));
                return Ok(Exit::Unexpected(why));
            }
            let slot = self.get(frame::SLOT);
            let injected = std::mem::take(&mut self.injected);
            if slot == shim::SLOT_STOPPED
                || (injected && slot == u64::from(layout::VECTOR_LOWER_SYNC))
            {
                self.kicker.stop_flag().store(0, SeqCst);
                if self.armed.is_some_and(|at| at <= Instant::now()) {
                    self.armed = None;
                }
                return Ok(Exit::Stopped(Stopped::At {
                    pc: self.get(frame::ELR),
                    pstate: self.get(frame::SPSR),
                }));
            }
            return Ok(Exit::Vector(slot.min(15) as u16));
        }
    }
}
