//! Raw Linux ABI for seccomp, ptrace and the few newer syscalls that the
//! `libc` crate may not expose on every target.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

use hellovm_core::Arch;

pub const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;

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
#[cfg(target_arch = "aarch64")]
pub const NT_ARM_TLS: libc::c_long = 0x401;
#[cfg(target_arch = "aarch64")]
pub const NT_ARM_SYSTEM_CALL: libc::c_long = 0x404;

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
