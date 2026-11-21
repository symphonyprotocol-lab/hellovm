//! Minimal bindings to Hypervisor.framework (Apple silicon) and the few
//! libSystem calls the platform needs.
//!
//! Written from the macOS 27 SDK headers (`Hypervisor.framework/Headers`:
//! `hv_vm.h`, `hv_vcpu.h`, `hv_vcpu_types.h`, `hv_error.h`), not generated.
//! Only what this crate uses is declared. The safe wrappers below own the
//! process's one VM ([`Vm`]) and one vCPU ([`Vcpu`]).

use std::ffi::c_void;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

pub type HvReturn = i32;
pub type HvVcpu = u64;
pub type HvIpa = u64;

pub const HV_SUCCESS: HvReturn = 0;
const HV_ERROR: HvReturn = 0xfae9_4001_u32 as i32;
const HV_BUSY: HvReturn = 0xfae9_4002_u32 as i32;
const HV_BAD_ARGUMENT: HvReturn = 0xfae9_4003_u32 as i32;
const HV_NO_RESOURCES: HvReturn = 0xfae9_4005_u32 as i32;
const HV_NO_DEVICE: HvReturn = 0xfae9_4006_u32 as i32;
pub const HV_DENIED: HvReturn = 0xfae9_4007_u32 as i32;
pub const HV_UNSUPPORTED: HvReturn = 0xfae9_400f_u32 as i32;

pub const HV_MEMORY_READ: u64 = 1 << 0;
pub const HV_MEMORY_WRITE: u64 = 1 << 1;
pub const HV_MEMORY_EXEC: u64 = 1 << 2;

pub const HV_EXIT_REASON_CANCELED: u32 = 0;
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;

/// `hv_vcpu_exit_t`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HvVcpuExit {
    pub reason: u32,
    /// ESR_EL2 of the exit (`hv_exception_syndrome_t`).
    pub syndrome: u64,
    /// FAR_EL2 (`hv_exception_address_t`).
    pub virtual_address: u64,
    /// HPFAR_EL2-derived IPA (`hv_ipa_t`).
    pub physical_address: u64,
}

/// `hv_reg_t`: X0..X30 are 0..30.
pub const HV_REG_PC: u32 = 31;
pub const HV_REG_FPCR: u32 = 32;
pub const HV_REG_FPSR: u32 = 33;
pub const HV_REG_CPSR: u32 = 34;

/// `hv_sys_reg_t`: the system register encodings, `op0:op1:CRn:CRm:op2`.
pub mod sysreg {
    pub const ID_AA64PFR0_EL1: u16 = 0xc020;
    pub const ID_AA64ISAR0_EL1: u16 = 0xc030;
    pub const ID_AA64ISAR1_EL1: u16 = 0xc031;
    pub const ID_AA64MMFR0_EL1: u16 = 0xc038;
    pub const SCTLR_EL1: u16 = 0xc080;
    pub const CPACR_EL1: u16 = 0xc082;
    pub const TTBR0_EL1: u16 = 0xc100;
    pub const TTBR1_EL1: u16 = 0xc101;
    pub const TCR_EL1: u16 = 0xc102;
    pub const SPSR_EL1: u16 = 0xc200;
    pub const ELR_EL1: u16 = 0xc201;
    pub const SP_EL0: u16 = 0xc208;
    pub const ESR_EL1: u16 = 0xc290;
    pub const FAR_EL1: u16 = 0xc300;
    pub const MAIR_EL1: u16 = 0xc510;
    pub const VBAR_EL1: u16 = 0xc600;
    pub const CNTKCTL_EL1: u16 = 0xc708;
    pub const TPIDR_EL1: u16 = 0xc684;
    pub const TPIDR_EL0: u16 = 0xde82;
    pub const TPIDRRO_EL0: u16 = 0xde83;
    pub const CNTV_CTL_EL0: u16 = 0xdf19;
    pub const CNTV_CVAL_EL0: u16 = 0xdf1a;
    pub const SP_EL1: u16 = 0xe208;
}

#[link(name = "Hypervisor", kind = "framework")]
extern "C" {
    fn hv_vm_create(config: *mut c_void) -> HvReturn;
    fn hv_vm_destroy() -> HvReturn;
    fn hv_vm_map(addr: *mut c_void, ipa: HvIpa, size: usize, flags: u64) -> HvReturn;
    fn hv_vm_unmap(ipa: HvIpa, size: usize) -> HvReturn;
    fn hv_vcpu_create(
        vcpu: *mut HvVcpu,
        exit: *mut *const HvVcpuExit,
        config: *mut c_void,
    ) -> HvReturn;
    fn hv_vcpu_destroy(vcpu: HvVcpu) -> HvReturn;
    fn hv_vcpu_get_reg(vcpu: HvVcpu, reg: u32, value: *mut u64) -> HvReturn;
    fn hv_vcpu_set_reg(vcpu: HvVcpu, reg: u32, value: u64) -> HvReturn;
    fn hv_vcpu_get_simd_fp_reg(vcpu: HvVcpu, reg: u32, value: *mut u8) -> HvReturn;
    // Really `(hv_vcpu_t, hv_simd_fp_reg_t, hv_simd_fp_uchar16_t)`: the
    // value is a 16-byte vector passed by value, in `v0`, which stable
    // Rust cannot declare. Only its address is used (see
    // `Vcpu::set_simd`).
    fn hv_vcpu_set_simd_fp_reg();
    fn hv_vcpu_get_sys_reg(vcpu: HvVcpu, reg: u16, value: *mut u64) -> HvReturn;
    fn hv_vcpu_set_sys_reg(vcpu: HvVcpu, reg: u16, value: u64) -> HvReturn;
    fn hv_vcpu_run(vcpu: HvVcpu) -> HvReturn;
    fn hv_vcpus_exit(vcpus: *const HvVcpu, count: u32) -> HvReturn;
    fn hv_vcpu_set_vtimer_mask(vcpu: HvVcpu, masked: bool) -> HvReturn;
    fn hv_vcpu_get_vtimer_offset(vcpu: HvVcpu, offset: *mut u64) -> HvReturn;
    fn hv_vm_get_max_vcpu_count(max_vcpu_count: *mut u32) -> HvReturn;
}

extern "C" {
    /// libSystem: invalidates the instruction cache for a range of the
    /// calling process's memory (`<libkern/OSCacheControl.h>`).
    fn sys_icache_invalidate(start: *mut c_void, len: usize);
    /// libSystem: the counter `CNTVCT_EL0` of the guest is derived from
    /// (`<mach/mach_time.h>`).
    fn mach_absolute_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

/// `mach_timebase_info_data_t`: `mach_absolute_time` ticks times
/// `numer / denom` are nanoseconds.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MachTimebaseInfo {
    pub numer: u32,
    pub denom: u32,
}

pub fn timebase(info: &mut MachTimebaseInfo) {
    // SAFETY: writes one `mach_timebase_info_data_t` to a valid pointer.
    unsafe { mach_timebase_info(info) };
}

/// A failed Hypervisor.framework call.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HvError {
    pub call: &'static str,
    pub code: HvReturn,
}

impl HvError {
    fn name(&self) -> &'static str {
        match self.code {
            HV_ERROR => "HV_ERROR",
            HV_BUSY => "HV_BUSY",
            HV_BAD_ARGUMENT => "HV_BAD_ARGUMENT",
            HV_NO_RESOURCES => "HV_NO_RESOURCES",
            HV_NO_DEVICE => "HV_NO_DEVICE",
            HV_DENIED => "HV_DENIED",
            HV_UNSUPPORTED => "HV_UNSUPPORTED",
            _ => "unknown error",
        }
    }
}

impl fmt::Display for HvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed: {} ({:#x})",
            self.call,
            self.name(),
            self.code as u32
        )?;
        if self.code == HV_DENIED {
            write!(
                f,
                "; the executable needs the com.apple.security.hypervisor entitlement \
                 (see README, \"The HVF platform\")"
            )?;
        }
        Ok(())
    }
}

impl fmt::Debug for HvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for HvError {}

impl From<HvError> for std::io::Error {
    fn from(err: HvError) -> Self {
        let kind = match err.code {
            HV_DENIED => std::io::ErrorKind::PermissionDenied,
            HV_UNSUPPORTED => std::io::ErrorKind::Unsupported,
            HV_BUSY => std::io::ErrorKind::ResourceBusy,
            HV_NO_RESOURCES => std::io::ErrorKind::OutOfMemory,
            _ => std::io::ErrorKind::Other,
        };
        std::io::Error::new(kind, err)
    }
}

fn check(call: &'static str, code: HvReturn) -> Result<(), HvError> {
    if code == HV_SUCCESS {
        Ok(())
    } else {
        Err(HvError { call, code })
    }
}

/// Hypervisor.framework allows one VM per process.
static VM_TAKEN: AtomicBool = AtomicBool::new(false);

/// The process's VM. Creating a second one while this one lives fails
/// with `HV_BUSY` (checked here, before the framework is asked).
#[derive(Debug)]
pub struct Vm {
    _private: (),
}

impl Vm {
    pub fn create() -> Result<Vm, HvError> {
        if VM_TAKEN.swap(true, Ordering::AcqRel) {
            return Err(HvError {
                call: "hv_vm_create (one VM per process)",
                code: HV_BUSY,
            });
        }
        // SAFETY: plain call; a null config asks for the default VM.
        let ret = unsafe { hv_vm_create(std::ptr::null_mut()) };
        if let Err(err) = check("hv_vm_create", ret) {
            VM_TAKEN.store(false, Ordering::Release);
            return Err(err);
        }
        Ok(Vm { _private: () })
    }

    /// Maps `size` bytes of this process's memory at `host` into the
    /// guest-physical address space at `ipa`.
    ///
    /// # Safety
    ///
    /// `host..host + size` must stay mapped in this process, and must not
    /// be anything the guest may not see, until it is unmapped from the VM
    /// or the VM is destroyed.
    pub unsafe fn map(
        &self,
        host: *mut u8,
        ipa: HvIpa,
        size: usize,
        flags: u64,
    ) -> Result<(), HvError> {
        // SAFETY: the caller keeps the range mapped (see above).
        check("hv_vm_map", unsafe {
            hv_vm_map(host.cast(), ipa, size, flags)
        })
    }

    /// Proof that the VM exists, for making vCPUs on other threads.
    pub fn token(&self) -> VmToken {
        VmToken { _private: () }
    }

    /// How many vCPUs the framework lets a VM have.
    pub fn max_vcpus(&self) -> Result<u32, HvError> {
        let mut max = 0;
        // SAFETY: valid out-pointer.
        check("hv_vm_get_max_vcpu_count", unsafe {
            hv_vm_get_max_vcpu_count(&mut max)
        })?;
        Ok(max)
    }

    pub fn unmap(&self, ipa: HvIpa, size: usize) -> Result<(), HvError> {
        // SAFETY: only changes the VM's stage-2 tables.
        check("hv_vm_unmap", unsafe { hv_vm_unmap(ipa, size) })
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        // SAFETY: the VM exists; its vCPU (dropped before it, see
        // `HvfPlatform`) is gone.
        let ret = unsafe { hv_vm_destroy() };
        if ret != HV_SUCCESS {
            log::warn!(
                "hv_vm_destroy: {:?}",
                HvError {
                    call: "",
                    code: ret
                }
            );
        }
        VM_TAKEN.store(false, Ordering::Release);
    }
}

/// The vCPU, owned by the thread that created it: every call except
/// [`VcpuKicker::kick`] must come from that thread, which the platform
/// guarantees by being neither `Send` nor `Sync`.
/// A [`Vm`] exists (see [`Vm::token`]); vCPUs are made with it, each
/// on the thread that will run it.
#[derive(Clone, Copy, Debug)]
pub struct VmToken {
    _private: (),
}

pub struct Vcpu {
    id: HvVcpu,
    exit: *const HvVcpuExit,
}

impl Vcpu {
    /// Creates a vCPU for the calling thread. The VM must exist.
    pub fn create(_vm: VmToken) -> Result<Vcpu, HvError> {
        let mut id = 0;
        let mut exit = std::ptr::null();
        // SAFETY: both out-pointers are valid; a null config is the default.
        check("hv_vcpu_create", unsafe {
            hv_vcpu_create(&mut id, &mut exit, std::ptr::null_mut())
        })?;
        if exit.is_null() {
            return Err(HvError {
                call: "hv_vcpu_create (no exit information)",
                code: HV_ERROR,
            });
        }
        Ok(Vcpu { id, exit })
    }

    pub fn kicker(&self) -> VcpuKicker {
        VcpuKicker { id: self.id }
    }

    pub fn reg(&self, reg: u32) -> Result<u64, HvError> {
        let mut value = 0;
        // SAFETY: valid out-pointer; the vCPU belongs to this thread.
        check("hv_vcpu_get_reg", unsafe {
            hv_vcpu_get_reg(self.id, reg, &mut value)
        })?;
        Ok(value)
    }

    pub fn set_reg(&self, reg: u32, value: u64) -> Result<(), HvError> {
        // SAFETY: plain call on this thread's vCPU.
        check("hv_vcpu_set_reg", unsafe {
            hv_vcpu_set_reg(self.id, reg, value)
        })
    }

    pub fn simd(&self, reg: u32) -> Result<u128, HvError> {
        let mut value = [0u8; 16];
        // SAFETY: `value` is 16 writable bytes, the size of
        // `hv_simd_fp_uchar16_t`; the vCPU belongs to this thread.
        check("hv_vcpu_get_simd_fp_reg", unsafe {
            hv_vcpu_get_simd_fp_reg(self.id, reg, value.as_mut_ptr())
        })?;
        Ok(u128::from_le_bytes(value))
    }

    pub fn set_simd(&self, reg: u32, value: u128) -> Result<(), HvError> {
        let bytes = value.to_le_bytes();
        // SAFETY: loads 16 bytes from a 16-byte array; NEON is part of the
        // aarch64-apple-darwin baseline.
        let vector = unsafe { std::arch::aarch64::vld1q_u8(bytes.as_ptr()) };
        let ret: u64;
        // SAFETY: calls `hv_vcpu_set_simd_fp_reg(vcpu, reg, value)` by the
        // AAPCS64: the vCPU in x0, the register number in w1, the vector
        // in v0, the result in w0; every register the C ABI lets the
        // callee change is marked clobbered, and the call may use the
        // stack. The vCPU belongs to this thread.
        unsafe {
            std::arch::asm!(
                "blr {f}",
                f = in(reg) hv_vcpu_set_simd_fp_reg as *const () as usize,
                in("x0") self.id,
                in("x1") u64::from(reg),
                in("v0") vector,
                lateout("x0") ret,
                clobber_abi("C"),
            );
        }
        check("hv_vcpu_set_simd_fp_reg", ret as u32 as HvReturn)
    }

    pub fn sys_reg(&self, reg: u16) -> Result<u64, HvError> {
        let mut value = 0;
        // SAFETY: valid out-pointer; the vCPU belongs to this thread.
        check("hv_vcpu_get_sys_reg", unsafe {
            hv_vcpu_get_sys_reg(self.id, reg, &mut value)
        })?;
        Ok(value)
    }

    pub fn set_sys_reg(&self, reg: u16, value: u64) -> Result<(), HvError> {
        // SAFETY: plain call on this thread's vCPU.
        check("hv_vcpu_set_sys_reg", unsafe {
            hv_vcpu_set_sys_reg(self.id, reg, value)
        })
    }

    pub fn set_vtimer_mask(&self, masked: bool) -> Result<(), HvError> {
        // SAFETY: plain call on this thread's vCPU.
        check("hv_vcpu_set_vtimer_mask", unsafe {
            hv_vcpu_set_vtimer_mask(self.id, masked)
        })
    }

    /// The guest's virtual counter now (`CNTVCT_EL0` as the guest reads
    /// it).
    pub fn guest_counter(&self) -> Result<u64, HvError> {
        let mut offset = 0;
        // SAFETY: valid out-pointer; the vCPU belongs to this thread.
        check("hv_vcpu_get_vtimer_offset", unsafe {
            hv_vcpu_get_vtimer_offset(self.id, &mut offset)
        })?;
        // SAFETY: plain libSystem call.
        Ok(unsafe { mach_absolute_time() }.wrapping_sub(offset))
    }

    /// Runs the vCPU until its next exit.
    pub fn run(&self) -> Result<HvVcpuExit, HvError> {
        // SAFETY: plain call on this thread's vCPU.
        check("hv_vcpu_run", unsafe { hv_vcpu_run(self.id) })?;
        // SAFETY: `exit` points to the framework's exit record for this
        // vCPU, valid until the vCPU is destroyed and written only by
        // `hv_vcpu_run` on this thread.
        Ok(unsafe { std::ptr::read_volatile(self.exit) })
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        // SAFETY: called on the owning thread (`Vcpu` is not `Send`).
        let ret = unsafe { hv_vcpu_destroy(self.id) };
        if ret != HV_SUCCESS {
            log::warn!(
                "hv_vcpu_destroy: {:?}",
                HvError {
                    call: "",
                    code: ret
                }
            );
        }
    }
}

/// Forces the vCPU out of [`Vcpu::run`] from any thread.
#[derive(Clone, Copy, Debug)]
pub struct VcpuKicker {
    id: HvVcpu,
}

impl VcpuKicker {
    /// If the vCPU is running it exits with `HV_EXIT_REASON_CANCELED`;
    /// otherwise its next run returns that at once.
    pub fn kick(&self) {
        // SAFETY: `hv_vcpus_exit` may be called from any thread; a vCPU id
        // that no longer exists only makes it fail.
        unsafe { hv_vcpus_exit(&self.id, 1) };
    }
}

/// Makes instructions written to `ptr..ptr + len` through this process's
/// mapping visible to instruction fetch, on every core (the guest's
/// included: the invalidation is by physical line, broadcast).
pub fn icache_invalidate(ptr: *mut u8, len: usize) {
    // SAFETY: cache maintenance only; it never writes memory.
    unsafe { sys_icache_invalidate(ptr.cast(), len) }
}

/// The host's 16 KiB page size, the granule of `hv_vm_map` by default.
pub const HOST_PAGE: usize = 16 * 1024;

/// Anonymous, zero-filled host memory, released on drop.
pub struct HostMem {
    ptr: *mut u8,
    len: usize,
}

impl HostMem {
    /// Reserves `len` bytes (a multiple of [`HOST_PAGE`]); pages cost host
    /// memory only once touched.
    pub fn new(len: usize) -> std::io::Result<HostMem> {
        assert!(len > 0 && len.is_multiple_of(HOST_PAGE));
        // SAFETY: a fresh private anonymous mapping; nothing else is
        // affected.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
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

    /// The bytes at `offset..offset + len`.
    pub fn slice(&self, offset: usize, len: usize) -> &[u8] {
        assert!(offset <= self.len && len <= self.len - offset);
        // SAFETY: in bounds (checked); the mapping lives as long as `self`.
        // Only for memory the guest cannot write (the shim, the page
        // tables): app memory goes through the copies below, since an app
        // on another vCPU may write it at any time.
        unsafe { std::slice::from_raw_parts(self.ptr.add(offset), len) }
    }

    /// Panics unless `offset..offset + len` is inside the mapping.
    pub fn check_range(&self, offset: usize, len: usize) {
        assert!(offset <= self.len && len <= self.len - offset);
    }

    /// Copies out of the mapping without a reference to it: the guest may
    /// be writing the same bytes.
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) {
        self.check_range(offset, buf.len());
        // SAFETY: in bounds (checked); `buf` is host memory, never inside
        // the mapping (the platform's buffers are its own).
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
            std::sync::atomic::AtomicU64::from_ptr(self.ptr.add(offset).cast())
                .store(value.to_le(), Ordering::Release)
        }
    }

    pub fn slice_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        assert!(offset <= self.len && len <= self.len - offset);
        // SAFETY: as in `slice`, and `&mut self` makes this the only view.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.add(offset), len) }
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
        // SAFETY: unmaps exactly what `new` mapped. The VM's stage-2
        // mapping of it is removed first (see `HvfPlatform::drop`).
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

/// A shared mapping of a file (a warm-clone snapshot, POSIX shared
/// memory): writable for the template that saves into it, read only for
/// its clones. Unmapped on drop.
pub struct SharedMap {
    ptr: *mut u8,
    len: usize,
    writable: bool,
}

impl SharedMap {
    /// Maps `len` bytes of `fd` at `offset` (multiples of [`HOST_PAGE`]).
    /// A read-only mapping cannot be made writable later: the fd of a
    /// clone is opened read only, so the host refuses that.
    pub fn map(
        fd: std::os::fd::BorrowedFd<'_>,
        offset: u64,
        len: usize,
        writable: bool,
    ) -> std::io::Result<SharedMap> {
        use std::os::fd::AsRawFd;
        if len == 0 || !len.is_multiple_of(HOST_PAGE) || !offset.is_multiple_of(HOST_PAGE as u64) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let prot = if writable {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        let offset = libc::off_t::try_from(offset)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        // SAFETY: a new shared mapping of the file; nothing else in the
        // process is affected.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(SharedMap {
            ptr: ptr.cast(),
            len,
            writable,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes. Only the template's kernel process writes them, before
    /// any clone exists: for a clone they never change.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping lives as long as `self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// The bytes, writable (a mapping made writable).
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        assert!(self.writable, "a read-only snapshot mapping");
        // SAFETY: as in `bytes`; `&mut self` makes this the only view in
        // this process.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

// SAFETY: a plain shared mapping; access goes through `&self`/`&mut self`.
unsafe impl Send for SharedMap {}
// SAFETY: as for `Send`.
unsafe impl Sync for SharedMap {}

impl Drop for SharedMap {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly what `map` mapped.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

impl crate::mmu::Origin for SharedMap {
    fn read_frame(&self, index: usize, out: &mut [u8]) {
        let page = crate::layout::PAGE as usize;
        let at = index.checked_mul(page).filter(|&at| at + page <= self.len);
        match at {
            Some(at) => {
                // SAFETY: in bounds (checked); a copy without a reference,
                // like guest memory (nothing writes it any more).
                unsafe { std::ptr::copy_nonoverlapping(self.ptr.add(at), out.as_mut_ptr(), page) }
            }
            None => out.fill(0),
        }
    }
}
