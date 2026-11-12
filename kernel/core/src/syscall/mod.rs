//! The syscall dispatcher and helpers shared by the handlers.
//!
//! Handlers are methods on [`Ctx`], the view of the sandbox from one thread,
//! grouped by area: `fs` (files, paths, fds, pipes, polling), `mem`
//! (memory), `proc` (processes: clone, exec, exit, wait, ids), `signal`
//! (signals, timers, delivery), `futex` and `misc` (identity, time,
//! limits). Every guest pointer is accessed through the platform; a failed
//! access is `EFAULT`, never a kernel error.
//!
//! A handler that has to wait calls [`Ctx::park`] and returns its error: the
//! kernel loop parks the thread and runs the handler again when something
//! changed (see `kernel.rs`). So a handler must not change anything before
//! it decides to park.

mod fs;
mod futex;
mod mem;
mod misc;
mod proc;
mod procfs;
mod signal;
mod tty;

use std::time::Duration;

pub(crate) use proc::{load_program, reap};
pub(crate) use tty::{pull_terminal_input, set_window_size};

use crate::arch::{Arch, Sysno};
use crate::errno::{Errno, SysResult, EFAULT, ENAMETOOLONG, ENOSYS};
use crate::fd::{FileId, FileObject, OpenFile};
use crate::host::Host;
use crate::kernel::now;
use crate::platform::{GuestAddr, Platform, SyscallTrap, TaskKey};
use crate::task::{Parked, Pid, Process, Restart, State, Tid, WaitKind};
use crate::vfs::{Timespec, Vfs, PATH_MAX};

/// What the kernel does after handling a syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Resume the thread with this return value.
    Return(i64),
    /// Park the thread until the syscall can complete.
    Park(Wait),
    /// Resume the thread with its (changed) context.
    Continue,
    /// Start a new program in the thread.
    Start { entry: GuestAddr, stack: GuestAddr },
    /// The thread is gone.
    Done,
}

/// How a parked syscall waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Wait {
    pub kind: WaitKind,
    /// Relative to the first attempt.
    pub timeout: Option<Duration>,
    pub restart: Restart,
}

/// The error a handler returns after [`Ctx::park`]; never seen by the
/// guest.
const PARKED: Errno = Errno(-1);

/// Largest number of bytes a single `read`/`write`-like call moves. Bigger
/// requests return a short count, which Linux allows and callers handle.
pub(crate) const MAX_IO: usize = 4 << 20;

/// Everything a syscall handler may touch: the sandbox, seen from one
/// thread.
pub(crate) struct Ctx<'a, H: ?Sized, P: ?Sized> {
    pub host: &'a mut H,
    pub plat: &'a mut P,
    pub vfs: &'a mut Vfs,
    pub st: &'a mut State,
    pub arch: Arch,
    pub tid: Tid,
    pub pid: Pid,
    /// The thread's platform task.
    pub task: TaskKey,
    /// When retrying a parked syscall: how it was parked.
    pub parked: Option<Parked>,
    /// Set by [`Ctx::park`] and by handlers that end in something other than
    /// a return value.
    pub action: Option<Action>,
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

    pub fn proc(&self) -> &Process {
        self.st.proc(self.pid)
    }

    pub fn proc_mut(&mut self) -> &mut Process {
        self.st.proc_mut(self.pid)
    }

    /// Parks the thread; the handler returns the error this gives.
    pub fn park(&mut self, kind: WaitKind, timeout: Option<Duration>, restart: Restart) -> Errno {
        self.action = Some(Action::Park(Wait {
            kind,
            timeout,
            restart,
        }));
        PARKED
    }

    /// Parks the thread until the sandbox's state changes.
    pub fn park_retry(&mut self, timeout: Option<Duration>, restart: Restart) -> Errno {
        self.park(WaitKind::Retry, timeout, restart)
    }

    /// Parks the thread until `timeout` passes or a signal handler runs.
    pub fn park_sleep(&mut self, timeout: Option<Duration>) -> Errno {
        self.park(WaitKind::Sleep, timeout, Restart::Never)
    }

    /// Whether this is the last attempt of a parked syscall whose timeout
    /// passed.
    pub fn timed_out(&self) -> bool {
        self.parked.is_some_and(|p| p.timed_out)
    }

    /// The description behind `fd` in this process.
    pub fn file(&self, fd: i64) -> SysResult<(FileId, &OpenFile)> {
        let id = self.proc().fds.get(fd)?;
        Ok((id, self.st.files.get(id)))
    }

    /// Installs a new description at the lowest free fd `>= min`.
    pub fn install(&mut self, file: OpenFile, min: usize, cloexec: bool) -> SysResult<i64> {
        let st = &mut *self.st;
        let proc = st.procs.get_mut(&self.pid).expect("live process");
        match proc.fds.install(&mut st.files, file.clone(), min, cloexec) {
            Ok(fd) => Ok(fd),
            Err(err) => {
                // Undo what opening it did.
                self.release(Some(file));
                Err(err)
            }
        }
    }

    pub fn read_mem(&mut self, addr: GuestAddr, len: usize) -> SysResult<Vec<u8>> {
        let mut buf = vec![0; len];
        self.plat
            .read(self.task, addr, &mut buf)
            .map_err(|_| Errno(EFAULT))?;
        Ok(buf)
    }

    pub fn read_array<const N: usize>(&mut self, addr: GuestAddr) -> SysResult<[u8; N]> {
        let mut buf = [0; N];
        self.plat
            .read(self.task, addr, &mut buf)
            .map_err(|_| Errno(EFAULT))?;
        Ok(buf)
    }

    pub fn read_u64(&mut self, addr: GuestAddr) -> SysResult<u64> {
        self.read_array(addr).map(u64::from_le_bytes)
    }

    pub fn read_u32(&mut self, addr: GuestAddr) -> SysResult<u32> {
        self.read_array(addr).map(u32::from_le_bytes)
    }

    pub fn write_mem(&mut self, addr: GuestAddr, data: &[u8]) -> SysResult<()> {
        self.plat
            .write(self.task, addr, data)
            .map_err(|_| Errno(EFAULT))
    }

    /// Writes as much of `data` as the guest memory at `addr` takes, page
    /// by page, and returns how many bytes were written.
    pub fn write_mem_prefix(&mut self, addr: GuestAddr, data: &[u8]) -> usize {
        if self.plat.write(self.task, addr, data).is_ok() {
            return data.len();
        }
        // 4 KiB is the smallest page size, so no writable page is skipped.
        const CHUNK: u64 = 4096;
        let mut done = 0;
        while done < data.len() {
            let Some(at) = addr.checked_add(done as u64) else {
                break;
            };
            let n = ((CHUNK - at % CHUNK) as usize).min(data.len() - done);
            if self
                .plat
                .write(self.task, at, &data[done..done + n])
                .is_err()
            {
                break;
            }
            done += n;
        }
        done
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

    /// Releases a description that lost its last fd.
    pub fn release(&mut self, file: Option<OpenFile>) {
        let Some(file) = file else {
            return;
        };
        match file.object {
            FileObject::Node(ino) => self.vfs.closed(ino),
            FileObject::PipeRead(id) => {
                self.st.pipes.close_end(id, false);
                self.st.changed = true;
            }
            FileObject::PipeWrite(id) => {
                self.st.pipes.close_end(id, true);
                self.st.changed = true;
            }
            FileObject::Proc { .. } => {
                let held = file.contents.as_ref().map_or(0, Vec::len);
                self.st.proc_bytes = self.st.proc_bytes.saturating_sub(held);
            }
            FileObject::ConsoleIn | FileObject::ConsoleOut(_) | FileObject::Tty => {}
        }
    }

    pub fn release_all(&mut self, files: Vec<OpenFile>) {
        for file in files {
            self.release(Some(file));
        }
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
    ctx.action = None;
    let ret = match sysno {
        // Processes.
        Some(Exit) => ctx.sys_exit(a[0]),
        Some(ExitGroup) => ctx.sys_exit_group(a[0]),
        Some(Clone) => ctx.sys_clone(a),
        Some(Clone3) => Err(Errno(ENOSYS)),
        Some(Fork) => ctx.sys_clone([crate::signal::SIGCHLD as u64, 0, 0, 0, 0, 0]),
        Some(Vfork) => ctx.sys_clone([
            proc::CLONE_VM | proc::CLONE_VFORK | crate::signal::SIGCHLD as u64,
            0,
            0,
            0,
            0,
            0,
        ]),
        Some(Execve) => ctx.sys_execveat(AT_FDCWD, a[0], a[1], a[2], 0),
        Some(Execveat) => ctx.sys_execveat(int(a[0]), a[1], a[2], a[3], a[4]),
        Some(Wait4) => ctx.sys_wait4(int(a[0]), a[1], int(a[2]), a[3]),
        Some(Waitid) => ctx.sys_waitid(int(a[0]), int(a[1]), a[2], int(a[3])),
        Some(Getpid) => Ok(u64::from(ctx.pid)),
        Some(Gettid) => Ok(u64::from(ctx.tid)),
        Some(Getppid) => Ok(u64::from(ctx.proc().ppid)),
        Some(Getpgrp) => Ok(u64::from(ctx.proc().pgid)),
        Some(Getpgid) => ctx.sys_getpgid(int(a[0])),
        Some(Getsid) => ctx.sys_getsid(int(a[0])),
        Some(Setpgid) => ctx.sys_setpgid(int(a[0]), int(a[1])),
        Some(Setsid) => ctx.sys_setsid(),
        Some(SetTidAddress) => ctx.sys_set_tid_address(a[0]),
        Some(SetRobustList) => ctx.sys_set_robust_list(a[0], a[1]),
        Some(GetRobustList) => ctx.sys_get_robust_list(int(a[0]), a[1], a[2]),
        Some(Prlimit64) => ctx.sys_prlimit64(int(a[0]), a[1], a[2], a[3]),
        Some(Getrlimit) => ctx.sys_prlimit64(0, a[0], 0, a[1]),
        Some(Setrlimit) => ctx.sys_prlimit64(0, a[0], a[1], 0),

        // Signals and timers.
        Some(Kill) => ctx.sys_kill(int(a[0]), int(a[1])),
        Some(Tkill) => ctx.sys_tgkill(-1, int(a[0]), int(a[1])),
        Some(Tgkill) => ctx.sys_tgkill(int(a[0]), int(a[1]), int(a[2])),
        Some(RtSigqueueinfo) => ctx.sys_rt_sigqueueinfo(int(a[0]), None, int(a[1]), a[2]),
        Some(RtTgsigqueueinfo) => {
            ctx.sys_rt_sigqueueinfo(int(a[0]), Some(int(a[1])), int(a[2]), a[3])
        }
        Some(RtSigaction) => ctx.sys_rt_sigaction(int(a[0]), a[1], a[2], a[3]),
        Some(RtSigprocmask) => ctx.sys_rt_sigprocmask(int(a[0]), a[1], a[2], a[3]),
        Some(RtSigreturn) => ctx.sys_rt_sigreturn(),
        Some(RtSigsuspend) => ctx.sys_rt_sigsuspend(a[0], a[1]),
        Some(RtSigpending) => ctx.sys_rt_sigpending(a[0], a[1]),
        Some(RtSigtimedwait) => ctx.sys_rt_sigtimedwait(a[0], a[1], a[2], a[3]),
        Some(Pause) => ctx.sys_pause(),
        Some(Sigaltstack) => ctx.sys_sigaltstack(a[0], a[1]),
        Some(Alarm) => ctx.sys_alarm(a[0]),
        Some(Setitimer) => ctx.sys_setitimer(int(a[0]), a[1], a[2]),
        Some(Getitimer) => ctx.sys_getitimer(int(a[0]), a[1]),
        Some(Futex) => ctx.sys_futex(a[0], int(a[1]), a[2], a[3], a[4], a[5]),
        Some(RestartSyscall) => Err(Errno(crate::errno::EINTR)),

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
        Some(Pipe) => ctx.sys_pipe2(a[0], 0),
        Some(Pipe2) => ctx.sys_pipe2(a[0], a[1]),
        Some(Fcntl) => ctx.sys_fcntl(int(a[0]), int(a[1]), a[2]),
        Some(Ioctl) => ctx.sys_ioctl(int(a[0]), a[1], a[2]),
        Some(Poll) => ctx.sys_poll(a[0], a[1], Some(int(a[2]))),
        Some(Ppoll) => ctx.sys_ppoll(a[0], a[1], a[2], a[3], a[4]),
        Some(Select) => ctx.sys_select(int(a[0]), [a[1], a[2], a[3]], a[4], false, 0),
        Some(Pselect6) => ctx.sys_select(int(a[0]), [a[1], a[2], a[3]], a[4], true, a[5]),
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
        Some(Madvise | Msync | Mlock | Munlock) => Ok(0),

        // Identity, time, limits and the rest.
        Some(Getuid | Geteuid | Getgid | Getegid) => Ok(0),
        Some(Getresuid | Getresgid) => ctx.sys_getresid(a[0], a[1], a[2]),
        Some(Getgroups) => Ok(0),
        Some(Setuid | Setgid | Setgroups | Setreuid | Setregid | Setresuid | Setresgid) => Ok(0),
        Some(Setfsuid | Setfsgid) => Ok(0),
        Some(Capget) => ctx.sys_capget(a[1]),
        Some(Personality) => Ok(0),
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
        Some(Nanosleep) => ctx.sys_nanosleep(a[0], a[1]),
        Some(ClockNanosleep) => ctx.sys_clock_nanosleep(int(a[0]), a[1], a[2], a[3]),
        Some(SchedYield) => Ok(0),
        Some(SchedGetaffinity) => ctx.sys_sched_getaffinity(a[1], a[2]),
        Some(SchedSetaffinity) => Ok(0),
        Some(SchedGetparam) => ctx.sys_sched_getparam(a[1]),
        Some(SchedGetscheduler | SchedGetPriorityMin | SchedGetPriorityMax) => Ok(0),
        Some(SchedSetscheduler) => Ok(0),
        Some(Getcpu) => ctx.sys_getcpu(a[0], a[1]),
        Some(Getpriority) => Ok(20),
        Some(Setpriority) => Ok(0),
        Some(Membarrier) => Ok(0),
        // Deliberately refused: glibc falls back without restartable
        // sequences, and without clone3. epoll is not implemented yet;
        // CPython's subprocess and selectors fall back to poll.
        Some(Rseq | EpollCreate1) => Err(Errno(ENOSYS)),
        _ => unimplemented(trap.nr, sysno, &a),
    };
    if let Some(action) = ctx.action.take() {
        return action;
    }
    Action::Return(match ret {
        Ok(value) => value as i64,
        Err(errno) => errno.ret(),
    })
}
