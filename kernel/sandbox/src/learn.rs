//! Measuring the kernel process's syscalls (test builds only).
//!
//! With `HELLOVM_SECCOMP_LEARN=FILE` (and the `insecure-test-hooks`
//! feature), [`crate::apply`] installs, instead of the allowlist, the same
//! filter shape with `SECCOMP_RET_USER_NOTIF` for every syscall made from
//! the kernel process's code. A supervisor thread, created before the
//! filter and therefore not under it, receives each one, appends a line
//!
//! ```text
//! <nr> <arg0> ... <arg5>
//! ```
//!
//! (hex) to `FILE` and lets the syscall continue
//! (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`). Everything else (app syscalls,
//! the other layers) is as in a normal run. Running the whole test suite
//! this way lists every syscall, with its arguments, that the kernel
//! process makes; `kernel/sandbox/learn-summary.py` condenses the file.
//!
//! The supervisor makes raw syscalls only and never allocates: a thread it
//! serves may be stopped inside `malloc` holding the allocator lock.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Notif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
struct NotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

/// Installs `prog` with a listener on the calling thread only and serves
/// it from a new, unfiltered thread that appends to `out`.
///
/// The calling thread must be the process's only other thread: threads it
/// creates later inherit the filter.
pub fn install(prog: &mut [libc::sock_filter], out: OwnedFd) -> io::Result<()> {
    // The supervisor exists (unfiltered) before the filter does. It learns
    // the listener fd through an atomic: any syscall the installing thread
    // made to hand it over would itself wait for the supervisor.
    static LISTENER: AtomicI32 = AtomicI32::new(-1);
    std::thread::Builder::new()
        .name("seccomp-learn".into())
        .spawn(move || loop {
            let fd = LISTENER.load(Ordering::Acquire);
            if fd >= 0 {
                serve(fd, out.as_raw_fd());
            }
            if fd == -2 {
                return;
            }
            std::thread::yield_now();
        })?;
    let fprog = libc::sock_fprog {
        len: prog.len() as libc::c_ushort,
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: valid program; NO_NEW_PRIVS is set by the caller.
    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1 as libc::c_ulong,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const libc::sock_fprog,
        )
    };
    if listener < 0 {
        let err = io::Error::last_os_error();
        LISTENER.store(-2, Ordering::Release);
        return Err(err);
    }
    LISTENER.store(listener as RawFd, Ordering::Release);
    Ok(())
}

fn serve(listener: RawFd, out: RawFd) -> ! {
    loop {
        // SAFETY: all-zero is valid, and the kernel requires it.
        let mut req: Notif = unsafe { std::mem::zeroed() };
        // SAFETY: RECV fills one Notif.
        if unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV as _, &mut req) } != 0 {
            let errno = io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::EINTR) || errno == Some(libc::ENOENT) {
                continue;
            }
            // The filter is gone with every task that had it.
            loop {
                // SAFETY: plain syscall; parks this thread forever.
                unsafe { libc::pause() };
            }
        }
        let mut line = [0u8; 8 * 17 + 1];
        let mut len = 0;
        let mut put = |v: u64| {
            for shift in (0..16).rev() {
                let digit = ((v >> (shift * 4)) & 0xf) as u8;
                line[len] = b"0123456789abcdef"[digit as usize];
                len += 1;
            }
            line[len] = b' ';
            len += 1;
        };
        put(req.data.nr as u32 as u64);
        for arg in req.data.args {
            put(arg);
        }
        line[len - 1] = b'\n';
        // SAFETY: writes `len` initialised bytes; O_APPEND keeps lines whole.
        unsafe { libc::write(out, line.as_ptr().cast(), len) };
        let resp = NotifResp {
            id: req.id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        // SAFETY: SEND reads one NotifResp. A failure means the task died.
        unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND as _, &resp) };
    }
}
