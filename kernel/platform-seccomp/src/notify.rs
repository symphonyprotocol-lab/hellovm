//! The kernel process's end of seccomp user notifications: one listener
//! per filter, that is per app process spawned with the [`crate::filter::notify`]
//! filter (its forks and threads inherit the filter, so they share the
//! listener; an `execve` spawns a new process with a new filter).
//!
//! A notified syscall waits in the host kernel until the listener answers
//! it with a return value ([`Listener::reply`]). The answer never lets the
//! syscall run (no `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, no fd injection), so
//! the host only ever executes it as "return this value".

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use crate::sys;

/// A received notification.
#[derive(Clone, Copy, Debug)]
pub struct Notification {
    pub id: u64,
    /// The task's host pid (in the namespace of the receiving thread).
    pub pid: libc::pid_t,
    /// The address after the syscall instruction.
    pub ip: u64,
    pub nr: u64,
    pub args: [u64; 6],
}

#[derive(Debug)]
pub struct Listener {
    fd: OwnedFd,
}

impl Listener {
    /// Wraps a listener fd and asks the host for synchronous wake-ups where
    /// it has them (Linux 6.6; older hosts work, with the wake-ups of any
    /// other blocking call).
    pub fn new(fd: OwnedFd) -> Listener {
        // SAFETY: plain ioctl on an fd we own; failure only means the host
        // does not know the flag.
        unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                sys::SECCOMP_IOCTL_NOTIF_SET_FLAGS as _,
                sys::SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP,
            )
        };
        Listener { fd }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Receives one pending notification. Call it only after `poll`
    /// reported the listener readable: the host blocks otherwise. `None`
    /// when the notification went away in between (its task was
    /// interrupted by a signal or killed).
    pub fn receive(&self) -> io::Result<Option<Notification>> {
        let mut notif = sys::SeccompNotif::default();
        loop {
            // SAFETY: RECV writes one `struct seccomp_notif`, which must be
            // zeroed on entry.
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    sys::SECCOMP_IOCTL_NOTIF_RECV as _,
                    &mut notif as *mut sys::SeccompNotif,
                )
            };
            if ret == 0 {
                return Ok(Some(Notification {
                    id: notif.id,
                    pid: notif.pid as libc::pid_t,
                    ip: notif.data.instruction_pointer,
                    nr: notif.data.nr as u32 as u64,
                    args: notif.data.args,
                }));
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => notif = sys::SeccompNotif::default(),
                Some(libc::ENOENT) => return Ok(None),
                _ => return Err(err),
            }
        }
    }

    /// Completes notification `id` with `value` as the syscall's return
    /// value (`-errno` for errors). `false` when the notification is gone:
    /// its task was interrupted by a signal (it is then in, or about to be
    /// in, a signal-delivery-stop) or killed.
    pub fn reply(&self, id: u64, value: i64) -> io::Result<bool> {
        let resp = sys::SeccompNotifResp {
            id,
            val: value,
            error: 0,
            flags: 0,
        };
        loop {
            // SAFETY: SEND reads one `struct seccomp_notif_resp`.
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    sys::SECCOMP_IOCTL_NOTIF_SEND as _,
                    &resp as *const sys::SeccompNotifResp,
                )
            };
            if ret == 0 {
                return Ok(true);
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ENOENT) => return Ok(false),
                _ => return Err(err),
            }
        }
    }
}
