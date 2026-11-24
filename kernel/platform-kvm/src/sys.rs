//! Minimal bindings to KVM on arm64 Linux (`/dev/kvm`) and the host
//! memory the platform gives the VM.
//!
//! Written from the Linux UAPI headers (`include/uapi/linux/kvm.h`,
//! `arch/arm64/include/uapi/asm/kvm.h`) and
//! `Documentation/virt/kvm/api.rst`, not generated. Only what this crate
//! uses is declared.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

const KVMIO: u64 = 0xae;

const fn io(nr: u64) -> u64 {
    KVMIO << 8 | nr
}

const fn iow(nr: u64, size: u64) -> u64 {
    1 << 30 | size << 16 | KVMIO << 8 | nr
}

const fn ior(nr: u64, size: u64) -> u64 {
    2 << 30 | size << 16 | KVMIO << 8 | nr
}

pub const KVM_GET_API_VERSION: u64 = io(0x00);
pub const KVM_CREATE_VM: u64 = io(0x01);
pub const KVM_CHECK_EXTENSION: u64 = io(0x03);
pub const KVM_GET_VCPU_MMAP_SIZE: u64 = io(0x04);
pub const KVM_CREATE_VCPU: u64 = io(0x41);
pub const KVM_SET_USER_MEMORY_REGION: u64 = iow(0x46, 32);
pub const KVM_IRQ_LINE: u64 = iow(0x61, 8);
pub const KVM_RUN: u64 = io(0x80);
pub const KVM_GET_ONE_REG: u64 = iow(0xab, 16);
pub const KVM_SET_ONE_REG: u64 = iow(0xac, 16);
pub const KVM_ARM_VCPU_INIT: u64 = iow(0xae, 32);
pub const KVM_ARM_PREFERRED_TARGET: u64 = ior(0xaf, 32);

pub const KVM_API_VERSION: i32 = 12;

pub const KVM_CAP_USER_MEMORY: u64 = 3;
pub const KVM_CAP_NR_VCPUS: u64 = 9;
pub const KVM_CAP_MAX_VCPUS: u64 = 66;
pub const KVM_CAP_ONE_REG: u64 = 70;
pub const KVM_CAP_READONLY_MEM: u64 = 81;

pub const KVM_MEM_READONLY: u32 = 1 << 1;

pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_FAIL_ENTRY: u32 = 9;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
pub const KVM_EXIT_SYSTEM_EVENT: u32 = 24;

/// `KVM_IRQ_LINE` on a VM without an in-kernel interrupt controller: the
/// IRQ input of a vCPU (`KVM_ARM_IRQ_TYPE_CPU`, `KVM_ARM_IRQ_CPU_IRQ`).
pub fn cpu_irq_line(vcpu: usize) -> u32 {
    // `vcpu_index` in bits 23:16, `vcpu2_index` (the index's next bits)
    // in 31:28; type CPU (0) in 27:24, IRQ (0) in 15:0.
    let vcpu = vcpu as u32;
    (vcpu & 0xff) << 16 | ((vcpu >> 8) & 0xf) << 28
}

/// `KVM_REG_ARM64 | KVM_REG_SIZE_U64`.
const REG_ARM64_U64: u64 = 0x6000_0000_0000_0000 | 0x0030_0000_0000_0000;
const KVM_REG_ARM_CORE: u64 = 0x0010 << 16;
const KVM_REG_ARM64_SYSREG: u64 = 0x0013 << 16;

/// The `ONE_REG` id of a system register (`layout::sysreg` encoding).
pub fn sysreg_id(encoding: u16) -> u64 {
    REG_ARM64_U64 | KVM_REG_ARM64_SYSREG | u64::from(encoding)
}

/// The `ONE_REG` id of a core register at `offset` bytes into `struct
/// kvm_regs`.
const fn core_id(offset: u64) -> u64 {
    REG_ARM64_U64 | KVM_REG_ARM_CORE | (offset / 4)
}

/// `regs.pc`: after `regs.regs[31]` and `regs.sp`.
pub const REG_PC: u64 = core_id(32 * 8);
/// `regs.pstate`.
pub const REG_PSTATE: u64 = core_id(33 * 8);
/// `sp_el1`, after `struct user_pt_regs`.
pub const REG_SP_EL1: u64 = core_id(34 * 8);

/// `struct kvm_vcpu_init`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VcpuInit {
    pub target: u32,
    pub features: [u32; 7],
}

/// `struct kvm_userspace_memory_region`.
#[repr(C)]
struct MemoryRegion {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
}

/// `struct kvm_one_reg`.
#[repr(C)]
struct OneReg {
    id: u64,
    addr: u64,
}

/// `struct kvm_irq_level`.
#[repr(C)]
struct IrqLevel {
    irq: u32,
    level: u32,
}

/// Offsets in `struct kvm_run` (the same on every architecture up to the
/// union).
pub mod run {
    pub const EXIT_REASON: usize = 8;
    /// The union of exit details starts here.
    pub const UNION: usize = 32;
    /// `mmio.phys_addr`, `mmio.len`, `mmio.is_write`.
    pub const MMIO_PHYS_ADDR: usize = UNION;
    pub const MMIO_LEN: usize = UNION + 16;
    pub const MMIO_IS_WRITE: usize = UNION + 20;
    /// The first 8 bytes of the union: `hw.hardware_exit_reason`,
    /// `fail_entry.hardware_entry_failure_reason`, `internal.suberror`
    /// (u32), `system_event.type` (u32).
    pub const DETAIL: usize = UNION;
}

fn last_error(call: &str) -> io::Error {
    let err = io::Error::last_os_error();
    io::Error::new(err.kind(), format!("{call}: {err}"))
}

/// `ioctl(fd, request, arg)`, returning its non-negative result.
///
/// # Safety
///
/// `arg` must be what `request` expects of it: an integer, or a pointer
/// to a valid object of the right type and size for the call to read or
/// write.
unsafe fn ioctl(fd: RawFd, request: u64, arg: u64, call: &str) -> io::Result<i32> {
    // SAFETY: the caller passes what `request` expects.
    let ret = unsafe { libc::ioctl(fd, request as _, arg) };
    if ret < 0 {
        Err(last_error(call))
    } else {
        Ok(ret)
    }
}

/// `/dev/kvm`, for making one VM.
pub struct Kvm {
    fd: OwnedFd,
}

impl Kvm {
    pub fn open() -> io::Result<Kvm> {
        // SAFETY: a plain open of a NUL-terminated path.
        let fd = unsafe { libc::open(c"/dev/kvm".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(last_error("open /dev/kvm"));
        }
        // SAFETY: a new fd this process owns.
        let kvm = Kvm {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        // SAFETY: no argument.
        let version = unsafe {
            ioctl(
                kvm.fd.as_raw_fd(),
                KVM_GET_API_VERSION,
                0,
                "KVM_GET_API_VERSION",
            )?
        };
        if version != KVM_API_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("KVM API version {version}, not {KVM_API_VERSION}"),
            ));
        }
        Ok(kvm)
    }

    /// `KVM_CHECK_EXTENSION` on `/dev/kvm`.
    pub fn extension(&self, cap: u64) -> i32 {
        // SAFETY: an integer argument.
        unsafe {
            ioctl(
                self.fd.as_raw_fd(),
                KVM_CHECK_EXTENSION,
                cap,
                "KVM_CHECK_EXTENSION",
            )
        }
        .unwrap_or(0)
    }

    /// The size of a vCPU's `struct kvm_run` mapping.
    pub fn vcpu_mmap_size(&self) -> io::Result<usize> {
        // SAFETY: no argument.
        let size = unsafe {
            ioctl(
                self.fd.as_raw_fd(),
                KVM_GET_VCPU_MMAP_SIZE,
                0,
                "KVM_GET_VCPU_MMAP_SIZE",
            )?
        };
        Ok(size as usize)
    }

    /// A new VM with the default guest-physical address size (40 bits).
    pub fn create_vm(&self) -> io::Result<VmFd> {
        // SAFETY: an integer argument (the machine type, 0).
        let fd = unsafe { ioctl(self.fd.as_raw_fd(), KVM_CREATE_VM, 0, "KVM_CREATE_VM")? };
        // SAFETY: a new fd this process owns.
        Ok(VmFd {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }
}

/// A VM.
pub struct VmFd {
    fd: OwnedFd,
}

impl VmFd {
    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// `KVM_CHECK_EXTENSION` on the VM.
    pub fn extension(&self, cap: u64) -> i32 {
        // SAFETY: an integer argument.
        unsafe { ioctl(self.raw(), KVM_CHECK_EXTENSION, cap, "KVM_CHECK_EXTENSION") }.unwrap_or(0)
    }

    /// Maps `len` bytes of this process's memory at `host` into the VM at
    /// `ipa` as memory slot `slot`, read only for the VM if `readonly`
    /// (its writes then exit as MMIO).
    ///
    /// # Safety
    ///
    /// `host..host + len` must stay mapped in this process, and must not
    /// be anything the guest may not see, until the slot is removed or the
    /// VM is closed.
    pub unsafe fn map(
        &self,
        slot: u32,
        host: *mut u8,
        ipa: u64,
        len: usize,
        readonly: bool,
    ) -> io::Result<()> {
        let region = MemoryRegion {
            slot,
            flags: if readonly { KVM_MEM_READONLY } else { 0 },
            guest_phys_addr: ipa,
            memory_size: len as u64,
            userspace_addr: host as u64,
        };
        // SAFETY: a valid region; the caller keeps the memory mapped.
        unsafe {
            ioctl(
                self.raw(),
                KVM_SET_USER_MEMORY_REGION,
                &region as *const MemoryRegion as u64,
                "KVM_SET_USER_MEMORY_REGION",
            )?
        };
        Ok(())
    }

    /// Removes memory slot `slot` (a size of 0).
    pub fn unmap(&self, slot: u32) -> io::Result<()> {
        let region = MemoryRegion {
            slot,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
        };
        // SAFETY: a valid region; removing a slot only changes the VM.
        unsafe {
            ioctl(
                self.raw(),
                KVM_SET_USER_MEMORY_REGION,
                &region as *const MemoryRegion as u64,
                "KVM_SET_USER_MEMORY_REGION",
            )?
        };
        Ok(())
    }

    /// The vCPU target this host prefers, for [`VcpuFd::init`].
    pub fn preferred_target(&self) -> io::Result<VcpuInit> {
        let mut init = VcpuInit::default();
        // SAFETY: `init` is a `struct kvm_vcpu_init` the call fills.
        unsafe {
            ioctl(
                self.raw(),
                KVM_ARM_PREFERRED_TARGET,
                &mut init as *mut VcpuInit as u64,
                "KVM_ARM_PREFERRED_TARGET",
            )?
        };
        Ok(init)
    }
}

/// Makes vCPU `id` of the VM whose fd is `vm`.
///
/// # Safety
///
/// `vm` must be an open VM fd.
pub unsafe fn create_vcpu(vm: RawFd, id: u64) -> io::Result<OwnedFd> {
    // SAFETY: an integer argument; `vm` is a VM fd (the caller's word).
    let fd = unsafe { ioctl(vm, KVM_CREATE_VCPU, id, "KVM_CREATE_VCPU")? };
    // SAFETY: a new fd this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Sets the IRQ input of a vCPU (see [`cpu_irq_line`]) on the VM `vm`
/// (from any thread).
pub fn irq_line(vm: RawFd, irq: u32, level: bool) -> io::Result<()> {
    let line = IrqLevel {
        irq,
        level: u32::from(level),
    };
    // SAFETY: a valid `struct kvm_irq_level`.
    unsafe {
        ioctl(
            vm,
            KVM_IRQ_LINE,
            &line as *const IrqLevel as u64,
            "KVM_IRQ_LINE",
        )?
    };
    Ok(())
}

/// A vCPU's fd and its `struct kvm_run` mapping.
pub struct VcpuFd {
    fd: OwnedFd,
    run: *mut u8,
    run_len: usize,
}

impl VcpuFd {
    pub fn new(fd: OwnedFd, run_len: usize) -> io::Result<VcpuFd> {
        if run_len < 4096 {
            return Err(io::Error::other(format!(
                "KVM_GET_VCPU_MMAP_SIZE {run_len}"
            )));
        }
        // SAFETY: maps the vCPU's run structure, as the API says; nothing
        // else in the process is affected.
        let run = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                run_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if run == libc::MAP_FAILED {
            return Err(last_error("mmap of kvm_run"));
        }
        Ok(VcpuFd {
            fd,
            run: run.cast(),
            run_len,
        })
    }

    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn init(&self, init: &VcpuInit) -> io::Result<()> {
        // SAFETY: a valid `struct kvm_vcpu_init`.
        unsafe {
            ioctl(
                self.raw(),
                KVM_ARM_VCPU_INIT,
                init as *const VcpuInit as u64,
                "KVM_ARM_VCPU_INIT",
            )?
        };
        Ok(())
    }

    pub fn get_reg(&self, id: u64) -> io::Result<u64> {
        let mut value = 0u64;
        let reg = OneReg {
            id,
            addr: &mut value as *mut u64 as u64,
        };
        // SAFETY: a valid `struct kvm_one_reg` whose `addr` points to 8
        // writable bytes (every id used here is a 64-bit register).
        unsafe {
            ioctl(
                self.raw(),
                KVM_GET_ONE_REG,
                &reg as *const OneReg as u64,
                "KVM_GET_ONE_REG",
            )?
        };
        Ok(value)
    }

    pub fn set_reg(&self, id: u64, value: u64) -> io::Result<()> {
        let reg = OneReg {
            id,
            addr: &value as *const u64 as u64,
        };
        // SAFETY: as in `get_reg`; the call only reads the 8 bytes.
        unsafe {
            ioctl(
                self.raw(),
                KVM_SET_ONE_REG,
                &reg as *const OneReg as u64,
                "KVM_SET_ONE_REG",
            )?
        };
        Ok(())
    }

    /// `KVM_RUN`: `Ok(true)` when the vCPU exited (see [`VcpuFd::exit_reason`]),
    /// `Ok(false)` when a signal interrupted the call.
    pub fn run(&self) -> io::Result<bool> {
        // SAFETY: no argument; the run structure is mapped (`new`).
        match unsafe { ioctl(self.raw(), KVM_RUN, 0, "KVM_RUN") } {
            Ok(_) => Ok(true),
            Err(err) if matches!(err.raw_os_error(), Some(libc::EINTR | libc::EAGAIN)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn run_u64(&self, offset: usize) -> u64 {
        assert!(offset + 8 <= self.run_len && offset.is_multiple_of(8));
        // SAFETY: in bounds and aligned (checked); KVM writes the run
        // structure only during `KVM_RUN` on this thread.
        unsafe { std::ptr::read_volatile(self.run.add(offset).cast::<u64>()) }
    }

    fn run_u32(&self, offset: usize) -> u32 {
        assert!(offset + 4 <= self.run_len && offset.is_multiple_of(4));
        // SAFETY: as in `run_u64`.
        unsafe { std::ptr::read_volatile(self.run.add(offset).cast::<u32>()) }
    }

    fn run_u8(&self, offset: usize) -> u8 {
        assert!(offset < self.run_len);
        // SAFETY: as in `run_u64`.
        unsafe { std::ptr::read_volatile(self.run.add(offset)) }
    }

    pub fn exit_reason(&self) -> u32 {
        self.run_u32(run::EXIT_REASON)
    }

    /// An MMIO exit's guest-physical address, size and direction.
    pub fn mmio(&self) -> (u64, u32, bool) {
        (
            self.run_u64(run::MMIO_PHYS_ADDR),
            self.run_u32(run::MMIO_LEN),
            self.run_u8(run::MMIO_IS_WRITE) != 0,
        )
    }

    /// The first word of the exit's details (see [`run::DETAIL`]).
    pub fn detail(&self) -> u64 {
        self.run_u64(run::DETAIL)
    }
}

impl Drop for VcpuFd {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly what `new` mapped.
        unsafe { libc::munmap(self.run.cast(), self.run_len) };
    }
}

/// Makes instructions written to `ptr..ptr + len` through this process's
/// mapping visible to instruction fetch on every core (the guest's
/// included): cleans the data cache to the point of unification and
/// invalidates the instruction cache, by address, as Linux's
/// `__clear_cache` does (`SCTLR_EL1.UCI` lets user space do it).
pub fn icache_invalidate(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    let ctr: u64;
    // SAFETY: reading CTR_EL0 is allowed at EL0 on Linux (`SCTLR_EL1.UCT`).
    unsafe { std::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    let dline = 4usize << ((ctr >> 16) & 0xf);
    let iline = 4usize << (ctr & 0xf);
    let start = ptr as usize;
    let end = start + len;
    let mut at = start & !(dline - 1);
    while at < end {
        // SAFETY: cache maintenance of this process's own memory; it
        // writes nothing.
        unsafe { std::arch::asm!("dc cvau, {}", in(reg) at, options(nostack)) };
        at += dline;
    }
    // SAFETY: a barrier.
    unsafe { std::arch::asm!("dsb ish", options(nostack)) };
    let mut at = start & !(iline - 1);
    while at < end {
        // SAFETY: as above.
        unsafe { std::arch::asm!("ic ivau, {}", in(reg) at, options(nostack)) };
        at += iline;
    }
    // SAFETY: barriers.
    unsafe { std::arch::asm!("dsb ish", "isb", options(nostack)) };
}

/// The granule of the pools' give-back (4 frames), and of every region.
pub const HOST_PAGE: usize = 16 * 1024;

/// Anonymous, zero-filled host memory, released on drop.
pub struct HostMem {
    ptr: *mut u8,
    len: usize,
}

impl HostMem {
    /// Reserves `len` bytes (a multiple of [`HOST_PAGE`]); pages cost host
    /// memory only once touched.
    pub fn new(len: usize) -> io::Result<HostMem> {
        if len == 0 || !len.is_multiple_of(HOST_PAGE) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: a fresh private anonymous mapping; nothing else is
        // affected.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(last_error("mmap"));
        }
        Ok(HostMem {
            ptr: ptr.cast(),
            len,
        })
    }

    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Panics unless `offset..offset + len` is inside the mapping.
    pub fn check_range(&self, offset: usize, len: usize) {
        assert!(offset <= self.len && len <= self.len - offset);
    }

    /// The bytes at `offset..offset + len`. Only for memory the guest
    /// cannot write (the shim, the page tables): app memory goes through
    /// the copies below, since an app on another vCPU may write it at any
    /// time.
    pub fn slice(&self, offset: usize, len: usize) -> &[u8] {
        self.check_range(offset, len);
        // SAFETY: in bounds (checked); the mapping lives as long as `self`.
        unsafe { std::slice::from_raw_parts(self.ptr.add(offset), len) }
    }

    pub fn slice_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        self.check_range(offset, len);
        // SAFETY: as in `slice`, and `&mut self` makes this the only view.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.add(offset), len) }
    }

    /// Copies out of the mapping without a reference to it: the guest may
    /// be writing the same bytes.
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) {
        self.check_range(offset, buf.len());
        // SAFETY: in bounds (checked); `buf` is host memory, never inside
        // the mapping.
        unsafe { std::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), buf.len()) }
    }

    /// Copies into the mapping without a reference to it.
    pub fn write_at(&mut self, offset: usize, data: &[u8]) {
        self.check_range(offset, data.len());
        // SAFETY: as in `read_at`.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len()) }
    }

    /// Copies `len` bytes within the mapping; the ranges do not overlap.
    pub fn copy_at(&mut self, from: usize, to: usize, len: usize) {
        self.check_range(from, len);
        self.check_range(to, len);
        assert!(from + len <= to || to + len <= from);
        // SAFETY: both in bounds and apart (checked).
        unsafe { std::ptr::copy_nonoverlapping(self.ptr.add(from), self.ptr.add(to), len) }
    }

    pub fn zero_at(&mut self, offset: usize, len: usize) {
        self.check_range(offset, len);
        // SAFETY: in bounds (checked).
        unsafe { std::ptr::write_bytes(self.ptr.add(offset), 0, len) }
    }

    /// One aligned 64-bit store, which a table walk on another vCPU sees
    /// whole or not at all.
    pub fn store_u64(&mut self, offset: usize, value: u64) {
        self.check_range(offset, 8);
        assert!(offset.is_multiple_of(8));
        // SAFETY: in bounds and 8-aligned (the mapping is page aligned);
        // an atomic store, which aarch64 makes single-copy atomic.
        unsafe {
            AtomicU64::from_ptr(self.ptr.add(offset).cast()).store(value.to_le(), Ordering::Release)
        }
    }

    /// Gives `offset..offset + len` (whole host pages) back to the host
    /// (`MADV_DONTNEED`): the pages are freed at once and no longer count
    /// in the process's resident memory, and KVM removes them from the
    /// VM's stage-2 tables (its MMU notifier); the next access, by the
    /// host or the VM, gets a new zero page.
    pub fn give_back(&mut self, offset: usize, len: usize) {
        self.check_range(offset, len);
        assert!(offset.is_multiple_of(HOST_PAGE) && len.is_multiple_of(HOST_PAGE));
        // SAFETY: whole pages inside the mapping (checked); the advice
        // changes what backs them, not whether they are mapped.
        let rc = unsafe { libc::madvise(self.ptr.add(offset).cast(), len, libc::MADV_DONTNEED) };
        if rc != 0 {
            // Memory that did not go back is only memory kept: frames are
            // zeroed when handed out again either way.
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                log::warn!("KVM platform: madvise: {}", io::Error::last_os_error());
            }
        }
    }
}

// SAFETY: a plain anonymous mapping, usable from any thread; access to
// its bytes goes through `&self`/`&mut self` (and so through the mutex
// the platform keeps its pools behind).
unsafe impl Send for HostMem {}
// SAFETY: as for `Send`: `&HostMem` only reads.
unsafe impl Sync for HostMem {}

impl Drop for HostMem {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly what `new` mapped. The VM's memory slots
        // of it are removed first (see `Kvm::release`).
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}
