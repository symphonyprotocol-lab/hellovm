//! The syscall dispatcher and the emulated syscalls.

use crate::arch::Sysno;
use crate::errno::{EBADF, EFAULT, EIO, ENOSYS};
use crate::host::{ConsoleStream, Host};
use crate::platform::{AppMemory, SyscallTrap};

/// What the kernel does after handling a syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Resume the app with this return value.
    Return(i64),
    /// End the app with this exit status (0..=255).
    Exit(i32),
}

/// Largest number of bytes a single `write` moves. Bigger writes return a
/// short count, which Linux allows and callers must handle anyway.
pub(crate) const MAX_WRITE: usize = 64 * 1024;

pub(crate) fn dispatch<H, M>(
    host: &mut H,
    mem: &mut M,
    sysno: Option<Sysno>,
    trap: &SyscallTrap,
) -> Action
where
    H: Host + ?Sized,
    M: AppMemory + ?Sized,
{
    let [a0, a1, a2, ..] = trap.args;
    match sysno {
        Some(Sysno::Write) => Action::Return(sys_write(host, mem, a0, a1, a2)),
        // With a single thread, `exit` ends the whole app like `exit_group`.
        // Once threads exist (U2), `exit` ends only the calling thread.
        Some(Sysno::Exit) | Some(Sysno::ExitGroup) => Action::Exit((a0 & 0xff) as i32),
        _ => {
            let name = sysno.map_or("?", Sysno::name);
            log::warn!(
                "unimplemented syscall {} ({name}), args {:#x?}: returning ENOSYS",
                trap.nr,
                trap.args
            );
            Action::Return(-ENOSYS)
        }
    }
}

fn sys_write<H, M>(host: &mut H, mem: &mut M, fd: u64, buf: u64, count: u64) -> i64
where
    H: Host + ?Sized,
    M: AppMemory + ?Sized,
{
    // The fd argument is an `unsigned int`; the upper half is ignored.
    let stream = match fd as u32 {
        1 => ConsoleStream::Stdout,
        2 => ConsoleStream::Stderr,
        _ => return -EBADF,
    };
    let len = count.min(MAX_WRITE as u64) as usize;
    if len == 0 {
        return 0;
    }
    let mut data = vec![0u8; len];
    if mem.read(buf, &mut data).is_err() {
        return -EFAULT;
    }
    match host.console_write(stream, &data) {
        Ok(written) => written as i64,
        Err(err) => {
            // Host errno values are not guest errno values; do not pass
            // them through.
            log::warn!("console write failed on the host: {err}");
            -EIO
        }
    }
}
