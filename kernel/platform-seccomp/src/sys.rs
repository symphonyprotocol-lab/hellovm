//! Raw Linux ABI for seccomp user notification and the few newer syscalls
//! that the `libc` crate may not expose on every target.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use cansol_core::Arch;

pub const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
pub const SECCOMP_GET_NOTIF_SIZES: libc::c_ulong = 3;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// Syscalls added after 2019 have the same number on every architecture.
pub const SYS_PIDFD_OPEN: libc::c_long = 434;
pub const SYS_CLOSE_RANGE: libc::c_long = 436;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

/// `struct seccomp_data`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// `struct seccomp_notif`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// `struct seccomp_notif_resp`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// `struct seccomp_notif_sizes`
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SeccompNotifSizes {
    seccomp_notif: u16,
    seccomp_notif_resp: u16,
    seccomp_data: u16,
}

const fn iowr(nr: u32, size: usize) -> u32 {
    // _IOC(_IOC_READ | _IOC_WRITE, '!', nr, size) in the generic encoding,
    // which both x86_64 and aarch64 use.
    (3 << 30) | ((size as u32) << 16) | ((b'!' as u32) << 8) | nr
}

pub const SECCOMP_IOCTL_NOTIF_RECV: u32 = iowr(0, std::mem::size_of::<SeccompNotif>());
pub const SECCOMP_IOCTL_NOTIF_SEND: u32 = iowr(1, std::mem::size_of::<SeccompNotifResp>());

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

/// Fails unless the running kernel's notification structs match ours.
pub fn check_notif_sizes() -> io::Result<()> {
    let mut sizes = SeccompNotifSizes::default();
    // SAFETY: SECCOMP_GET_NOTIF_SIZES writes a `seccomp_notif_sizes` to the
    // pointer, which points to one.
    check(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut SeccompNotifSizes,
        )
    })?;
    if usize::from(sizes.seccomp_notif) != std::mem::size_of::<SeccompNotif>()
        || usize::from(sizes.seccomp_notif_resp) != std::mem::size_of::<SeccompNotifResp>()
        || usize::from(sizes.seccomp_data) != std::mem::size_of::<SeccompData>()
    {
        return Err(io::Error::other(format!(
            "unexpected seccomp notification sizes {sizes:?}"
        )));
    }
    Ok(())
}

pub fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall without pointers.
    let fd = check(unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) })?;
    // SAFETY: on success the syscall returned a new fd that we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

/// A connected `AF_UNIX` `SOCK_SEQPACKET` pair, both ends close-on-exec.
pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two fds to the array.
    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success both fds are new and ours.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Control message buffer for one fd, suitably aligned.
#[repr(C, align(8))]
struct CmsgBuf([u8; 32]);

const _: () = assert!(std::mem::size_of::<libc::cmsghdr>() + 8 <= 32);

/// Sends a one-byte message on `sock`, carrying `fd` with `SCM_RIGHTS` if it
/// is not negative. Async-signal-safe; returns the raw `sendmsg` result.
///
/// # Safety
///
/// `sock` must be a valid socket and `fd` a valid fd or negative.
pub unsafe fn send_fd(sock: libc::c_int, fd: libc::c_int) -> isize {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut cmsg = CmsgBuf([0; 32]);
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if fd >= 0 {
        let fd_len = std::mem::size_of::<libc::c_int>() as libc::c_uint;
        msg.msg_control = cmsg.0.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(fd_len) as _;
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(fd_len) as _;
        ptr::write_unaligned(libc::CMSG_DATA(hdr).cast::<libc::c_int>(), fd);
    }
    libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL)
}

/// Receives one message sent by [`send_fd`] and returns the fd it carried,
/// if any.
pub fn recv_fd(sock: &OwnedFd) -> io::Result<Option<OwnedFd>> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut cmsg = CmsgBuf([0; 32]);
    // SAFETY: an all-zero msghdr is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.0.as_mut_ptr().cast();
    msg.msg_controllen = cmsg.0.len() as _;
    // SAFETY: `msg` points to valid buffers for the data and control parts.
    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel filled in `msg`, so the CMSG_* walk stays within
    // `cmsg`.
    unsafe {
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        if !hdr.is_null()
            && (*hdr).cmsg_level == libc::SOL_SOCKET
            && (*hdr).cmsg_type == libc::SCM_RIGHTS
        {
            let fd = ptr::read_unaligned(libc::CMSG_DATA(hdr).cast::<libc::c_int>());
            return Ok(Some(OwnedFd::from_raw_fd(fd)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_match_linux_headers() {
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, 0xc050_2100);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, 0xc018_2101);
    }

    #[test]
    fn kernel_struct_sizes() {
        check_notif_sizes().unwrap();
    }
}
