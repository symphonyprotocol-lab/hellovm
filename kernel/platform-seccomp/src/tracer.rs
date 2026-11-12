//! The kernel process's ptrace handle on app processes.

use std::io;
use std::mem;

use crate::regs::{FpRegs, Regs};
use crate::sys::{self, ptrace, ptrace_checked};

/// Why a tracee stopped (or ended), as `waitpid` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// `PTRACE_EVENT_SECCOMP`: the filter returned `SECCOMP_RET_TRACE` for a
    /// syscall, which has not run yet.
    Seccomp,
    /// A syscall stop. The platform only ever resumes with `PTRACE_SYSCALL`
    /// from a seccomp or exec stop, so this is always a syscall *exit* stop.
    SyscallExit,
    /// `PTRACE_EVENT_EXEC`: an `execve` succeeded.
    Exec,
    /// `PTRACE_EVENT_FORK`/`VFORK`/`CLONE`: the tracee created this new,
    /// automatically traced process.
    NewChild(libc::pid_t),
    /// A signal is about to be delivered (signal-delivery-stop).
    Signal(i32),
    /// Some other ptrace event, as the raw wait status.
    Other(i32),
    /// The process exited with this status (it is reaped).
    Exited(i32),
    /// The process was killed by this signal (it is reaped).
    Killed(i32),
}

impl Stop {
    pub fn ended(self) -> bool {
        matches!(self, Stop::Exited(_) | Stop::Killed(_))
    }
}

/// How to resume a tracee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Run {
    /// `PTRACE_CONT`: until the next seccomp stop or signal.
    Cont,
    /// `PTRACE_SYSCALL`: from a seccomp stop, until the syscall's exit stop.
    Syscall,
}

fn decode(pid: libc::pid_t, status: libc::c_int) -> Stop {
    if libc::WIFEXITED(status) {
        return Stop::Exited(libc::WEXITSTATUS(status));
    }
    if libc::WIFSIGNALED(status) {
        return Stop::Killed(libc::WTERMSIG(status));
    }
    let sig = libc::WSTOPSIG(status);
    let event = status >> 16;
    match (sig, event) {
        (libc::SIGTRAP, sys::PTRACE_EVENT_SECCOMP) => Stop::Seccomp,
        (libc::SIGTRAP, sys::PTRACE_EVENT_EXEC) => Stop::Exec,
        (
            libc::SIGTRAP,
            sys::PTRACE_EVENT_FORK | sys::PTRACE_EVENT_VFORK | sys::PTRACE_EVENT_CLONE,
        ) => {
            let mut child: libc::c_ulong = 0;
            // SAFETY: GETEVENTMSG writes one unsigned long to `data`.
            let ret = unsafe {
                ptrace(
                    sys::PTRACE_GETEVENTMSG,
                    pid,
                    0,
                    &mut child as *mut libc::c_ulong as usize,
                )
            };
            if ret < 0 {
                Stop::Other(status)
            } else {
                Stop::NewChild(child as libc::pid_t)
            }
        }
        (_, 0) if sig == libc::SIGTRAP | 0x80 => Stop::SyscallExit,
        (_, 0) => Stop::Signal(sig),
        _ => Stop::Other(status),
    }
}

/// Waits for a state change of `pid` (`-1`: any child or tracee of the
/// calling thread). With `nohang`, returns `None` when there is none.
pub fn waitpid(pid: libc::pid_t, nohang: bool) -> io::Result<Option<(libc::pid_t, Stop)>> {
    let mut flags = sys::WALL | sys::WNOTHREAD;
    if nohang {
        flags |= libc::WNOHANG;
    }
    let mut status = 0;
    loop {
        // SAFETY: `status` is a valid out pointer.
        let ret = unsafe { libc::waitpid(pid, &mut status, flags) };
        if ret > 0 {
            return Ok(Some((ret, decode(ret, status))));
        }
        if ret == 0 {
            return Ok(None);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// A traced child process.
///
/// ptrace ties the tracee to the *thread* that traces it, so every call must
/// come from that thread. The process is reaped only by a wait, so until
/// then its pid cannot be reused.
#[derive(Debug)]
pub struct Tracee {
    pub pid: libc::pid_t,
    reaped: bool,
}

impl Tracee {
    pub fn new(pid: libc::pid_t) -> Tracee {
        Tracee { pid, reaped: false }
    }

    /// Blocks until the tracee stops or ends.
    pub fn wait(&mut self) -> io::Result<Stop> {
        if self.reaped {
            return Err(io::Error::other("the app process is already reaped"));
        }
        let (_, stop) = waitpid(self.pid, false)?.expect("blocking wait");
        if stop.ended() {
            self.reaped = true;
        }
        Ok(stop)
    }

    /// Records that a wait for any process reaped this one.
    pub fn mark_reaped(&mut self) {
        self.reaped = true;
    }

    pub fn set_options(&self) -> io::Result<()> {
        let options = sys::PTRACE_O_TRACESYSGOOD
            | sys::PTRACE_O_TRACEEXEC
            | sys::PTRACE_O_TRACESECCOMP
            | sys::PTRACE_O_TRACEFORK
            | sys::PTRACE_O_TRACEVFORK
            | sys::PTRACE_O_TRACECLONE
            | sys::PTRACE_O_EXITKILL;
        // SAFETY: SETOPTIONS takes the options as `data`.
        unsafe { ptrace_checked(sys::PTRACE_SETOPTIONS, self.pid, 0, options as usize) }
    }

    /// Resumes the stopped tracee, delivering `signal` if it is not 0.
    pub fn resume(&self, run: Run, signal: i32) -> io::Result<()> {
        let request = match run {
            Run::Cont => sys::PTRACE_CONT,
            Run::Syscall => sys::PTRACE_SYSCALL,
        };
        // SAFETY: CONT and SYSCALL take the signal as `data`.
        unsafe { ptrace_checked(request, self.pid, 0, signal as usize) }
    }

    fn get_regset<T>(&self, kind: libc::c_long, out: &mut T) -> io::Result<()> {
        let mut iov = libc::iovec {
            iov_base: (out as *mut T).cast(),
            iov_len: mem::size_of::<T>(),
        };
        // SAFETY: GETREGSET writes at most `iov_len` bytes to `iov_base`,
        // which points to a `T` of that size.
        unsafe {
            ptrace_checked(
                sys::PTRACE_GETREGSET,
                self.pid,
                kind as usize,
                &mut iov as *mut libc::iovec as usize,
            )?;
        }
        if iov.iov_len != mem::size_of::<T>() {
            return Err(io::Error::other("short register set from ptrace"));
        }
        Ok(())
    }

    fn set_regset<T>(&self, kind: libc::c_long, value: &T) -> io::Result<()> {
        let mut iov = libc::iovec {
            iov_base: (value as *const T as *mut T).cast(),
            iov_len: mem::size_of::<T>(),
        };
        // SAFETY: SETREGSET reads `iov_len` bytes from `iov_base`.
        unsafe {
            ptrace_checked(
                sys::PTRACE_SETREGSET,
                self.pid,
                kind as usize,
                &mut iov as *mut libc::iovec as usize,
            )
        }
    }

    pub fn regs(&self) -> io::Result<Regs> {
        let mut regs = Regs::default();
        self.get_regset(sys::NT_PRSTATUS, &mut regs)?;
        Ok(regs)
    }

    pub fn set_regs(&self, regs: &Regs) -> io::Result<()> {
        self.set_regset(sys::NT_PRSTATUS, regs)
    }

    pub fn fp_regs(&self) -> io::Result<FpRegs> {
        let mut fp = FpRegs::default();
        self.get_regset(sys::NT_PRFPREG, &mut fp)?;
        Ok(fp)
    }

    pub fn set_fp_regs(&self, fp: &FpRegs) -> io::Result<()> {
        self.set_regset(sys::NT_PRFPREG, fp)
    }

    /// `tpidr_el0` (aarch64; on x86_64 the thread pointer is in [`Regs`]).
    #[cfg(target_arch = "aarch64")]
    pub fn tls(&self) -> io::Result<u64> {
        let mut tls = 0u64;
        self.get_regset(sys::NT_ARM_TLS, &mut tls)?;
        Ok(tls)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn set_tls(&self, tls: u64) -> io::Result<()> {
        self.set_regset(sys::NT_ARM_TLS, &tls)
    }

    /// At a seccomp stop: makes the pending syscall a no-op, with every
    /// register (the return value included) as in `regs`.
    pub fn skip_syscall(&self, regs: &Regs) -> io::Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            // orig_rax = -1 skips the syscall; rax is returned as is.
            let mut regs = *regs;
            regs.orig_rax = u64::MAX;
            self.set_regs(&regs)
        }
        #[cfg(target_arch = "aarch64")]
        {
            // x8 is only read at syscall entry; the number the kernel acts
            // on lives in NT_ARM_SYSTEM_CALL. -1 skips the syscall and x0 is
            // returned as is.
            self.set_regs(regs)?;
            self.set_regset(sys::NT_ARM_SYSTEM_CALL, &(-1i32))
        }
    }

    /// The `si_code` and fault address of the signal the tracee is stopped
    /// for. `si_code <= 0` means it was sent by a process, not raised by
    /// the CPU.
    pub fn siginfo(&self) -> Option<(i32, u64)> {
        // SAFETY: an all-zero siginfo_t is valid.
        let mut info: libc::siginfo_t = unsafe { mem::zeroed() };
        // SAFETY: GETSIGINFO writes one siginfo_t to `data`.
        let ret = unsafe {
            ptrace(
                sys::PTRACE_GETSIGINFO,
                self.pid,
                0,
                &mut info as *mut libc::siginfo_t as usize,
            )
        };
        if ret < 0 {
            return None;
        }
        // SAFETY: for fault signals the union holds the fault address; for
        // others the value is not used.
        let addr = unsafe { info.si_addr() } as u64;
        Some((info.si_code, addr))
    }

    /// Kills the tracee and reaps it. Does nothing if already reaped.
    pub fn kill(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        // SAFETY: plain syscall. The pid still names our unreaped child.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        loop {
            match self.wait() {
                Ok(stop) if stop.ended() => return Ok(()),
                // Stops that were already queued before the kill.
                Ok(_) => continue,
                Err(err) if err.raw_os_error() == Some(libc::ECHILD) => {
                    self.reaped = true;
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
        }
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
