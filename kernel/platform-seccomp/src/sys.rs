//! Raw Linux ABI for seccomp, ptrace and the few newer syscalls that the
//! `libc` crate may not expose on every target.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

use hellovm_core::Arch;

pub const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;

/// `seccomp(SECCOMP_SET_MODE_FILTER)` flag: return a listener fd for the
/// filter's `SECCOMP_RET_USER_NOTIF` results (close-on-exec).
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

/// The listener `ioctl`s (`linux/seccomp.h`; the same numbers on every
/// architecture).
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
pub const SECCOMP_IOCTL_NOTIF_SET_FLAGS: libc::c_ulong = 0x4008_2104;
/// Wake the task that made the syscall, and the listener, on the CPU of the
/// waker (Linux 6.6): a round trip without cross-CPU wake-ups.
pub const SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP: u64 = 1;

/// `struct seccomp_data`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// `struct seccomp_notif`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// `struct seccomp_notif_resp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// The host's internal "restart this syscall" results, which a tracer
/// sees in the return register when a signal interrupted a syscall
/// (`linux/errno.h`: `ERESTARTSYS`, `ERESTARTNOINTR`, `ERESTARTNOHAND`,
/// `ERESTART_RESTARTBLOCK`).
#[cfg(target_arch = "x86_64")]
pub const RESTART_ERRNOS: [i64; 4] = [512, 513, 514, 516];

// Syscalls added after 2019 have the same number on every architecture.
pub const SYS_CLOSE_RANGE: libc::c_long = 436;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

pub const PTRACE_TRACEME: libc::c_long = 0;
pub const PTRACE_CONT: libc::c_long = 7;
pub const PTRACE_SYSCALL: libc::c_long = 24;
pub const PTRACE_SETOPTIONS: libc::c_long = 0x4200;
pub const PTRACE_GETEVENTMSG: libc::c_long = 0x4201;
pub const PTRACE_GETSIGINFO: libc::c_long = 0x4202;
pub const PTRACE_GETREGSET: libc::c_long = 0x4204;
pub const PTRACE_SETREGSET: libc::c_long = 0x4205;

pub const PTRACE_O_TRACESYSGOOD: libc::c_long = 0x1;
pub const PTRACE_O_TRACEFORK: libc::c_long = 0x2;
pub const PTRACE_O_TRACEVFORK: libc::c_long = 0x4;
pub const PTRACE_O_TRACECLONE: libc::c_long = 0x8;
pub const PTRACE_O_TRACEEXEC: libc::c_long = 0x10;
pub const PTRACE_O_TRACESECCOMP: libc::c_long = 0x80;
pub const PTRACE_O_EXITKILL: libc::c_long = 0x10_0000;

pub const PTRACE_EVENT_FORK: i32 = 1;
pub const PTRACE_EVENT_VFORK: i32 = 2;
pub const PTRACE_EVENT_CLONE: i32 = 3;
pub const PTRACE_EVENT_EXEC: i32 = 4;
pub const PTRACE_EVENT_SECCOMP: i32 = 7;

pub const NT_PRSTATUS: libc::c_long = 1;
pub const NT_PRFPREG: libc::c_long = 2;
/// The regset with the extended FP/SIMD state (`Tracee::xstate`).
#[cfg(target_arch = "x86_64")]
pub const NT_XSTATE: libc::c_long = 0x202; // NT_X86_XSTATE
#[cfg(target_arch = "aarch64")]
pub const NT_XSTATE: libc::c_long = 0x405; // NT_ARM_SVE
/// More than any extended state is long (AVX-512 with AMX: 11 KiB; SVE
/// with 2048-bit vectors: 9 KiB).
pub const XSTATE_MAX: usize = 64 << 10;
#[cfg(target_arch = "aarch64")]
pub const NT_ARM_TLS: libc::c_long = 0x401;
#[cfg(target_arch = "aarch64")]
pub const NT_ARM_SYSTEM_CALL: libc::c_long = 0x404;
#[cfg(target_arch = "aarch64")]
pub const NT_ARM_PACA_KEYS: libc::c_long = 0x407;
#[cfg(target_arch = "aarch64")]
pub const NT_ARM_PACG_KEYS: libc::c_long = 0x408;

/// `clone` flags the platform passes when it makes an app process fork.
pub const CLONE_VM: u64 = 0x100;
pub const CLONE_PARENT: u64 = 0x8000;

/// `waitpid` flags.
pub const WALL: libc::c_int = 0x4000_0000;
pub const WNOTHREAD: libc::c_int = 0x2000_0000;

/// The seccomp `AUDIT_ARCH_*` value for a guest architecture.
pub fn audit_arch(arch: Arch) -> u32 {
    match arch {
        Arch::X86_64 => AUDIT_ARCH_X86_64,
        Arch::Aarch64 => AUDIT_ARCH_AARCH64,
    }
}

fn check(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// A raw `ptrace` call. Async-signal-safe.
///
/// # Safety
///
/// `addr` and `data` must be valid for `request`.
pub unsafe fn ptrace(
    request: libc::c_long,
    pid: libc::pid_t,
    addr: usize,
    data: usize,
) -> libc::c_long {
    libc::syscall(libc::SYS_ptrace, request, pid as libc::c_long, addr, data)
}

/// A checked `ptrace` call for requests whose result is only success or
/// failure.
///
/// # Safety
///
/// `addr` and `data` must be valid for `request`.
pub unsafe fn ptrace_checked(
    request: libc::c_long,
    pid: libc::pid_t,
    addr: usize,
    data: usize,
) -> io::Result<()> {
    check(ptrace(request, pid, addr, data)).map(drop)
}

/// A close-on-exec memfd holding `data`, sealed against writes.
pub fn sealed_memfd(name: &std::ffi::CStr, data: &[u8]) -> io::Result<OwnedFd> {
    // SAFETY: `name` is a valid C string.
    let fd = check(unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    })?;
    // SAFETY: on success the syscall returned a new fd that we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    let mut file = std::fs::File::from(fd);
    std::io::Write::write_all(&mut file, data)?;
    let fd = OwnedFd::from(file);
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: plain fcntl on an fd we own.
    check(unsafe {
        libc::fcntl(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            libc::F_ADD_SEALS,
            seals,
        )
    } as libc::c_long)?;
    Ok(fd)
}

/// The host page size.
pub fn page_size() -> u64 {
    // SAFETY: plain libc call.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as u64
    } else {
        4096
    }
}
