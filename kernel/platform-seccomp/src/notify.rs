//! Waiting for and answering seccomp user notifications.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use cansol_core::errno::MAX_ERRNO;

use crate::sys::{
    SeccompNotif, SeccompNotifResp, SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND,
};

/// Something that happened to the app.
#[derive(Clone, Copy, Debug)]
pub enum Event {
    /// The app made a syscall and is blocked until it is answered.
    Syscall(SeccompNotif),
    /// The app process is gone (and reaped); this is its wait status.
    Died(libc::c_int),
}

/// The kernel-process side of one app process: its pid, a pidfd for it and
/// the seccomp listener of its filter.
///
/// The child is reaped only in [`Child::next_event`] or [`Child::kill`], so
/// until then its pid cannot be reused and is safe to use for `kill` and
/// `process_vm_readv`.
#[derive(Debug)]
pub struct Child {
    pub pid: libc::pid_t,
    pub pidfd: OwnedFd,
    pub listener: OwnedFd,
    pub reaped: bool,
}

impl Child {
    /// Blocks until the app makes a syscall or dies.
    pub fn next_event(&mut self) -> io::Result<Event> {
        let mut watch_listener = true;
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: self.pidfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let nfds = if watch_listener { 2 } else { 1 };
            // SAFETY: `fds` holds at least `nfds` valid pollfd structs.
            let ret = unsafe { libc::poll(fds.as_mut_ptr(), nfds, -1) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            // A dead app comes first: its listener may also report POLLHUP.
            if fds[0].revents & libc::POLLIN != 0 {
                return self.reap().map(Event::Died);
            }
            let revents = fds[1].revents;
            if revents & libc::POLLIN != 0 {
                match self.recv() {
                    Ok(notif) => return Ok(Event::Syscall(notif)),
                    // The notifying thread died or was interrupted before we
                    // got to it; wait again.
                    Err(err) if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::EINTR)) => {
                        continue
                    }
                    Err(err) => return Err(err),
                }
            }
            if revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                // No task uses the filter any more: the app is exiting. Wait
                // for the pidfd alone.
                watch_listener = false;
            }
        }
    }

    fn recv(&self) -> io::Result<SeccompNotif> {
        // The kernel requires a zeroed buffer.
        let mut notif = SeccompNotif::default();
        // SAFETY: the RECV ioctl writes one `seccomp_notif` to the pointer.
        let ret = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                SECCOMP_IOCTL_NOTIF_RECV as _,
                &mut notif as *mut SeccompNotif,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(notif)
    }

    fn send(&self, resp: &SeccompNotifResp) -> io::Result<()> {
        // SAFETY: the SEND ioctl reads one `seccomp_notif_resp` from the
        // pointer.
        let ret = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                SECCOMP_IOCTL_NOTIF_SEND as _,
                resp as *const SeccompNotifResp,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // ENOENT: the app was interrupted or killed meanwhile; the next
            // event tells what happened.
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(err);
            }
        }
        Ok(())
    }

    /// Completes the syscall `id` with `ret` (`-errno` for errors).
    pub fn reply(&self, id: u64, ret: i64) -> io::Result<()> {
        let mut resp = SeccompNotifResp {
            id,
            ..Default::default()
        };
        if (-MAX_ERRNO..0).contains(&ret) {
            resp.error = ret as i32;
        } else {
            resp.val = ret;
        }
        self.send(&resp)
    }

    /// Lets the host kernel execute syscall `id` as is.
    ///
    /// Only ever used for the bootstrap `execve`, which the kernel process
    /// issued itself (see `spawn`). Never use it for app syscalls: the
    /// arguments could change between the check and the host executing it,
    /// and forwarding app syscalls is against the design anyway.
    pub fn continue_bootstrap_syscall(&self, id: u64) -> io::Result<()> {
        self.send(&SeccompNotifResp {
            id,
            flags: crate::sys::SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            ..Default::default()
        })
    }

    fn reap(&mut self) -> io::Result<libc::c_int> {
        let mut status = 0;
        loop {
            // SAFETY: `status` is a valid out pointer.
            let ret = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if ret == self.pid {
                self.reaped = true;
                return Ok(status);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// Kills the app process and reaps it. Does nothing if already reaped.
    pub fn kill(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        // SAFETY: plain syscall. The pid still names our unreaped child.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        self.reap().map(drop)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
