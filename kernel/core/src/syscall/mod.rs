//! The syscall dispatcher and helpers shared by the handlers.
//!
//! Handlers are methods on [`Ctx`], grouped by area: `fs` (files, paths,
//! fds), `mem` (memory) and `misc` (identity, time, signals, limits).
//! Every guest pointer is accessed through the platform's [`AppMemory`];
//! a failed access is `EFAULT`, never a kernel error.

mod fs;
mod mem;
mod misc;

use crate::arch::{Arch, Sysno};
use crate::errno::{Errno, SysResult, EFAULT, ENAMETOOLONG, ENOSYS};
use crate::host::Host;
use crate::kernel::{now, Process};
use crate::platform::{GuestAddr, Platform, SyscallTrap};
use crate::vfs::{Timespec, Vfs, PATH_MAX};

/// What the kernel does after handling a syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Resume the app with this return value.
    Return(i64),
    /// End the app with this exit status (0..=255).
    Exit(i32),
    /// End the app as killed by this signal.
    Signal(u32),
}

/// Largest number of bytes a single `read`/`write`-like call moves. Bigger
/// requests return a short count, which Linux allows and callers handle.
pub(crate) const MAX_IO: usize = 4 << 20;

/// Everything a syscall handler may touch.
pub(crate) struct Ctx<'a, H: ?Sized, P: ?Sized> {
    pub host: &'a mut H,
    pub app: &'a mut P,
    pub vfs: &'a mut Vfs,
    pub proc: &'a mut Process,
    pub arch: Arch,
}

/// The guest's `AT_FDCWD`.
pub(crate) const AT_FDCWD: i64 = -100;

/// An `int` argument (fds, flags): the low 32 bits, sign-extended.
pub(crate) fn int(arg: u64) -> i64 {
    arg as u32 as i32 as i64
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    pub fn now(&mut self) -> Timespec {
        now(self.host)
    }

    pub fn read_mem(&mut self, addr: GuestAddr, len: usize) -> SysResult<Vec<u8>> {
        let mut buf = vec![0; len];
        self.app.read(addr, &mut buf).map_err(|_| Errno(EFAULT))?;
        Ok(buf)
    }

    pub fn read_array<const N: usize>(&mut self, addr: GuestAddr) -> SysResult<[u8; N]> {
        let mut buf = [0; N];
        self.app.read(addr, &mut buf).map_err(|_| Errno(EFAULT))?;
        Ok(buf)
    }

    pub fn read_u64(&mut self, addr: GuestAddr) -> SysResult<u64> {
        self.read_array(addr).map(u64::from_le_bytes)
    }

    pub fn read_u32(&mut self, addr: GuestAddr) -> SysResult<u32> {
        self.read_array(addr).map(u32::from_le_bytes)
    }

    pub fn write_mem(&mut self, addr: GuestAddr, data: &[u8]) -> SysResult<()> {
        self.app.write(addr, data).map_err(|_| Errno(EFAULT))
    }

    pub fn write_u64(&mut self, addr: GuestAddr, value: u64) -> SysResult<()> {
        self.write_mem(addr, &value.to_le_bytes())
    }

    pub fn write_u32(&mut self, addr: GuestAddr, value: u32) -> SysResult<()> {
        self.write_mem(addr, &value.to_le_bytes())
    }

    /// Reads a NUL-terminated string of at most `max` bytes including the
    /// NUL; longer is `ENAMETOOLONG`.
    pub fn read_cstr(&mut self, addr: GuestAddr, max: usize) -> SysResult<Vec<u8>> {
        // Read up to page boundaries (4 KiB, the smallest page size) so that
        // a string ending just before an unmapped page is still readable.
        const CHUNK: u64 = 4096;
        let mut out = Vec::new();
        let mut at = addr;
        while out.len() < max {
            let n = ((CHUNK - at % CHUNK) as usize).min(max - out.len());
            let chunk = self.read_mem(at, n)?;
            if let Some(end) = chunk.iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..end]);
                return Ok(out);
            }
            out.extend_from_slice(&chunk);
            at = at.checked_add(n as u64).ok_or(Errno(EFAULT))?;
        }
        Err(Errno(ENAMETOOLONG))
    }

    pub fn read_path(&mut self, addr: GuestAddr) -> SysResult<Vec<u8>> {
        self.read_cstr(addr, PATH_MAX)
    }
}

fn unimplemented(nr: u64, sysno: Option<Sysno>, args: &[u64; 6]) -> SysResult<u64> {
    let name = sysno.map_or("?", Sysno::name);
    log::warn!("unimplemented syscall {nr} ({name}), args {args:#x?}: returning ENOSYS");
    Err(Errno(ENOSYS))
}

pub(crate) fn dispatch<H, P>(
    ctx: &mut Ctx<'_, H, P>,
    sysno: Option<Sysno>,
    trap: &SyscallTrap,
) -> Action
where
    H: Host + ?Sized,
    P: Platform + ?Sized,
{
    use Sysno::*;
    let a = trap.args;
    let ret = match sysno {
        // Process lifetime. With a single thread, `exit` ends the whole app
        // like `exit_group`; once threads exist (U2) it ends one thread.
        Some(Exit | ExitGroup) => return Action::Exit((a[0] & 0xff) as i32),
        Some(Kill) => match ctx.sys_kill(int(a[0]), int(a[1])) {
            Ok(Some(signal)) => return Action::Signal(signal),
            other => other.map(|_| 0),
        },
        Some(Tkill) => match ctx.sys_kill(int(a[0]), int(a[1])) {
            Ok(Some(signal)) => return Action::Signal(signal),
            other => other.map(|_| 0),
        },
        Some(Tgkill) => match ctx.sys_kill(int(a[1]), int(a[2])) {
            Ok(Some(signal)) => return Action::Signal(signal),
            other => other.map(|_| 0),
        },

        // File I/O.
        Some(Read) => ctx.sys_read(int(a[0]), a[1], a[2], None),
        Some(Write) => ctx.sys_write(int(a[0]), a[1], a[2], None),
        Some(Pread64) => ctx.sys_pread(int(a[0]), a[1], a[2], a[3]),
        Some(Pwrite64) => ctx.sys_pwrite(int(a[0]), a[1], a[2], a[3]),
        Some(Readv) => ctx.sys_readv(int(a[0]), a[1], a[2], None),
        Some(Writev) => ctx.sys_writev(int(a[0]), a[1], a[2], None),
        Some(Preadv) => ctx.sys_readv(int(a[0]), a[1], a[2], Some(a[3])),
        Some(Pwritev) => ctx.sys_writev(int(a[0]), a[1], a[2], Some(a[3])),
        Some(Sendfile) => ctx.sys_sendfile(int(a[0]), int(a[1]), a[2], a[3]),
        Some(Lseek) => ctx.sys_lseek(int(a[0]), a[1] as i64, int(a[2])),
        Some(Open) => ctx.sys_openat(AT_FDCWD, a[0], a[1], a[2]),
        Some(Creat) => ctx.sys_creat(a[0], a[1]),
        Some(Openat) => ctx.sys_openat(int(a[0]), a[1], a[2], a[3]),
        Some(Close) => ctx.sys_close(int(a[0])),
        Some(CloseRange) => ctx.sys_close_range(a[0], a[1], a[2]),
        Some(Dup) => ctx.sys_dup(int(a[0])),
        Some(Dup2) => ctx.sys_dup2(int(a[0]), int(a[1])),
        Some(Dup3) => ctx.sys_dup3(int(a[0]), int(a[1]), a[2]),
        Some(Fcntl) => ctx.sys_fcntl(int(a[0]), int(a[1]), a[2]),
        Some(Ioctl) => ctx.sys_ioctl(int(a[0]), a[1], a[2]),
        Some(Poll) => ctx.sys_poll(a[0], a[1], Some(int(a[2]))),
        Some(Ppoll) => ctx.sys_ppoll(a[0], a[1], a[2]),
        Some(Select) => ctx.sys_select(int(a[0]), a[1], a[2], a[3]),
        Some(Pselect6) => ctx.sys_select(int(a[0]), a[1], a[2], a[3]),
        Some(Fsync | Fdatasync) => ctx.sys_fsync(int(a[0])),
        Some(Sync) => Ok(0),
        Some(Fadvise64 | Flock) => ctx.sys_fsync(int(a[0])),
        Some(Ftruncate) => ctx.sys_ftruncate(int(a[0]), a[1] as i64),
        Some(Truncate) => ctx.sys_truncate(a[0], a[1] as i64),

        // Metadata.
        Some(Fstat) => ctx.sys_fstat(int(a[0]), a[1]),
        Some(Stat) => ctx.sys_newfstatat(AT_FDCWD, a[0], a[1], 0),
        Some(Lstat) => ctx.sys_newfstatat(AT_FDCWD, a[0], a[1], fs::AT_SYMLINK_NOFOLLOW),
        Some(Newfstatat) => ctx.sys_newfstatat(int(a[0]), a[1], a[2], a[3]),
        Some(Statx) => ctx.sys_statx(int(a[0]), a[1], a[2], a[4]),
        Some(Statfs) => ctx.sys_statfs_path(a[0], a[1]),
        Some(Fstatfs) => ctx.sys_fstatfs(int(a[0]), a[1]),
        Some(Access) => ctx.sys_faccessat(AT_FDCWD, a[0], a[1], 0),
        Some(Faccessat) => ctx.sys_faccessat(int(a[0]), a[1], a[2], 0),
        Some(Faccessat2) => ctx.sys_faccessat(int(a[0]), a[1], a[2], a[3]),
        Some(Readlink) => ctx.sys_readlinkat(AT_FDCWD, a[0], a[1], a[2]),
        Some(Readlinkat) => ctx.sys_readlinkat(int(a[0]), a[1], a[2], a[3]),
        Some(Getdents64) => ctx.sys_getdents64(int(a[0]), a[1], a[2]),

        // Namespace changes.
        Some(Mkdir) => ctx.sys_mkdirat(AT_FDCWD, a[0], a[1]),
        Some(Mkdirat) => ctx.sys_mkdirat(int(a[0]), a[1], a[2]),
        Some(Mknod) => ctx.sys_mknodat(AT_FDCWD, a[0], a[1]),
        Some(Mknodat) => ctx.sys_mknodat(int(a[0]), a[1], a[2]),
        Some(Unlink) => ctx.sys_unlinkat(AT_FDCWD, a[0], 0),
        Some(Rmdir) => ctx.sys_unlinkat(AT_FDCWD, a[0], fs::AT_REMOVEDIR),
        Some(Unlinkat) => ctx.sys_unlinkat(int(a[0]), a[1], a[2]),
        Some(Rename) => ctx.sys_renameat(AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        Some(Renameat) => ctx.sys_renameat(int(a[0]), a[1], int(a[2]), a[3], 0),
        Some(Renameat2) => ctx.sys_renameat(int(a[0]), a[1], int(a[2]), a[3], a[4]),
        Some(Symlink) => ctx.sys_symlinkat(a[0], AT_FDCWD, a[1]),
        Some(Symlinkat) => ctx.sys_symlinkat(a[0], int(a[1]), a[2]),
        Some(Link) => ctx.sys_linkat(AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        Some(Linkat) => ctx.sys_linkat(int(a[0]), a[1], int(a[2]), a[3], a[4]),
        Some(Chmod) => ctx.sys_fchmodat(AT_FDCWD, a[0], a[1], 0),
        Some(Fchmodat) => ctx.sys_fchmodat(int(a[0]), a[1], a[2], 0),
        Some(Fchmodat2) => ctx.sys_fchmodat(int(a[0]), a[1], a[2], a[3]),
        Some(Fchmod) => ctx.sys_fchmod(int(a[0]), a[1]),
        Some(Chown) => ctx.sys_fchownat(AT_FDCWD, a[0], a[1], a[2], 0),
        Some(Lchown) => ctx.sys_fchownat(AT_FDCWD, a[0], a[1], a[2], fs::AT_SYMLINK_NOFOLLOW),
        Some(Fchownat) => ctx.sys_fchownat(int(a[0]), a[1], a[2], a[3], a[4]),
        Some(Fchown) => ctx.sys_fchown(int(a[0]), a[1], a[2]),
        Some(Utimensat) => ctx.sys_utimensat(int(a[0]), a[1], a[2], a[3]),
        Some(Getcwd) => ctx.sys_getcwd(a[0], a[1]),
        Some(Chdir) => ctx.sys_chdir(a[0]),
        Some(Fchdir) => ctx.sys_fchdir(int(a[0])),
        Some(Umask) => ctx.sys_umask(a[0]),

        // Memory.
        Some(Brk) => ctx.sys_brk(a[0]),
        Some(Mmap) => ctx.sys_mmap(a[0], a[1], a[2], a[3], int(a[4]), a[5]),
        Some(Munmap) => ctx.sys_munmap(a[0], a[1]),
        Some(Mprotect) => ctx.sys_mprotect(a[0], a[1], a[2]),
        Some(Mremap) => ctx.sys_mremap(a[0], a[1], a[2], a[3], a[4]),
        Some(Madvise | Msync) => Ok(0),

        // Identity, time, signals, limits and the rest.
        Some(Getpid | Gettid | Getpgrp | Getsid | Getpgid) => Ok(misc::PID),
        Some(Getppid) => Ok(0),
        Some(Getuid | Geteuid | Getgid | Getegid) => Ok(0),
        Some(Getresuid | Getresgid) => ctx.sys_getresid(a[0], a[1], a[2]),
        Some(Getgroups) => Ok(0),
        Some(Setuid | Setgid | Setgroups | Setpgid) => Ok(0),
        Some(Setsid) => Err(Errno(crate::errno::EPERM)),
        Some(SetTidAddress) => Ok(misc::PID),
        Some(SetRobustList) => Ok(0),
        Some(Uname) => ctx.sys_uname(a[0]),
        Some(Sysinfo) => ctx.sys_sysinfo(a[0]),
        Some(Prctl) => ctx.sys_prctl(int(a[0]), a[1]),
        Some(ArchPrctl) => ctx.sys_arch_prctl(a[0], a[1]),
        Some(Getrandom) => ctx.sys_getrandom(a[0], a[1], a[2]),
        Some(ClockGettime) => ctx.sys_clock_gettime(int(a[0]), a[1]),
        Some(ClockGetres) => ctx.sys_clock_getres(int(a[0]), a[1]),
        Some(Gettimeofday) => ctx.sys_gettimeofday(a[0], a[1]),
        Some(Time) => ctx.sys_time(a[0]),
        Some(Times) => ctx.sys_times(a[0]),
        Some(Getrusage) => ctx.sys_getrusage(a[1]),
        Some(Nanosleep) => ctx.sys_nanosleep(a[0]),
        Some(ClockNanosleep) => ctx.sys_clock_nanosleep(int(a[0]), a[1], a[2]),
        Some(SchedYield) => Ok(0),
        Some(SchedGetaffinity) => ctx.sys_sched_getaffinity(a[1], a[2]),
        Some(Getcpu) => ctx.sys_getcpu(a[0], a[1]),
        Some(Getpriority) => Ok(20),
        Some(Setpriority) => Ok(0),
        Some(Prlimit64) => ctx.sys_prlimit64(int(a[0]), a[1], a[2], a[3]),
        Some(Getrlimit) => ctx.sys_prlimit64(0, a[0], 0, a[1]),
        Some(Setrlimit) => ctx.sys_prlimit64(0, a[0], a[1], 0),
        Some(RtSigaction) => ctx.sys_rt_sigaction(int(a[0]), a[1], a[2], a[3]),
        Some(RtSigprocmask) => ctx.sys_rt_sigprocmask(int(a[0]), a[1], a[2], a[3]),
        Some(Sigaltstack) => ctx.sys_sigaltstack(a[1]),
        Some(Alarm | Setitimer | Getitimer) => ctx.sys_timers(sysno.unwrap()),
        Some(Futex) => ctx.sys_futex(a[0], int(a[1]), a[2]),
        Some(Wait4 | Waitid) => Err(Errno(crate::errno::ECHILD)),
        // Deliberately refused: glibc falls back without restartable
        // sequences.
        Some(Rseq) => Err(Errno(ENOSYS)),
        _ => unimplemented(trap.nr, sysno, &a),
    };
    Action::Return(match ret {
        Ok(value) => value as i64,
        Err(errno) => errno.ret(),
    })
}
