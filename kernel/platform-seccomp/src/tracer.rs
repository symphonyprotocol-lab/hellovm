//! The kernel process's ptrace handle on the app process.

use std::io;
use std::mem;

use crate::regs::Regs;
use crate::sys::{self, ptrace, ptrace_checked};

/// Why the tracee stopped (or ended), as `waitpid` reports it.
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
    /// A signal is about to be delivered (signal-delivery-stop).
    Signal(i32),
    /// Some other ptrace event, as the raw wait status.
    Other(i32),
    /// The process exited with this status (it is reaped).
    Exited(i32),
    /// The process was killed by this signal (it is reaped).
    Killed(i32),
}

/// How to resume the tracee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Run {
    /// `PTRACE_CONT`: until the next seccomp stop or signal.
    Cont,
    /// `PTRACE_SYSCALL`: from a seccomp stop, until the syscall's exit stop.
    Syscall,
}

/// A traced child process.
///
/// ptrace ties the tracee to the *thread* that forked it, so every call must
/// come from that thread. The process is reaped only in [`Tracee::wait`] or
/// [`Tracee::kill`], so until then its pid cannot be reused.
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
        let mut status = 0;
        loop {
            // SAFETY: `status` is a valid out pointer.
            let ret = unsafe { libc::waitpid(self.pid, &mut status, libc::__WALL) };
            if ret == self.pid {
                break;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
        if libc::WIFEXITED(status) {
            self.reaped = true;
            return Ok(Stop::Exited(libc::WEXITSTATUS(status)));
        }
        if libc::WIFSIGNALED(status) {
            self.reaped = true;
            return Ok(Stop::Killed(libc::WTERMSIG(status)));
        }
        let sig = libc::WSTOPSIG(status);
        let event = status >> 16;
        Ok(match (sig, event) {
            (libc::SIGTRAP, sys::PTRACE_EVENT_SECCOMP) => Stop::Seccomp,
            (libc::SIGTRAP, sys::PTRACE_EVENT_EXEC) => Stop::Exec,
            (_, 0) if sig == libc::SIGTRAP | 0x80 => Stop::SyscallExit,
            (_, 0) => Stop::Signal(sig),
            _ => Stop::Other(status),
        })
    }

    pub fn set_options(&self) -> io::Result<()> {
        let options = sys::PTRACE_O_TRACESYSGOOD
            | sys::PTRACE_O_TRACEEXEC
            | sys::PTRACE_O_TRACESECCOMP
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

    pub fn regs(&self) -> io::Result<Regs> {
        let mut regs = Regs::default();
        let mut iov = libc::iovec {
            iov_base: (&mut regs as *mut Regs).cast(),
            iov_len: mem::size_of::<Regs>(),
        };
        // SAFETY: GETREGSET writes at most `iov_len` bytes to `iov_base`,
        // which points to a `Regs` of that size.
        unsafe {
            ptrace_checked(
                sys::PTRACE_GETREGSET,
                self.pid,
                sys::NT_PRSTATUS as usize,
                &mut iov as *mut libc::iovec as usize,
            )?;
        }
        if iov.iov_len != mem::size_of::<Regs>() {
            return Err(io::Error::other("short register set from ptrace"));
        }
        Ok(regs)
    }

    pub fn set_regs(&self, regs: &Regs) -> io::Result<()> {
        let mut iov = libc::iovec {
            iov_base: (regs as *const Regs as *mut Regs).cast(),
            iov_len: mem::size_of::<Regs>(),
        };
        // SAFETY: SETREGSET reads `iov_len` bytes from `iov_base`.
        unsafe {
            ptrace_checked(
                sys::PTRACE_SETREGSET,
                self.pid,
                sys::NT_PRSTATUS as usize,
                &mut iov as *mut libc::iovec as usize,
            )
        }
    }

    /// At a seccomp stop: makes the pending syscall a no-op that returns
    /// `ret`, with every other register as in `regs`.
    pub fn skip_syscall(&self, regs: &Regs, ret: i64) -> io::Result<()> {
        let mut regs = *regs;
        regs.set_ret(ret);
        #[cfg(target_arch = "x86_64")]
        {
            // orig_rax = -1 skips the syscall; rax is returned as is.
            regs.orig_rax = u64::MAX;
            self.set_regs(&regs)
        }
        #[cfg(target_arch = "aarch64")]
        {
            // x8 is only read at syscall entry; the number the kernel acts
            // on lives in NT_ARM_SYSTEM_CALL. -1 skips the syscall and x0 is
            // returned as is.
            self.set_regs(&regs)?;
            let mut nr: i32 = -1;
            let mut iov = libc::iovec {
                iov_base: (&mut nr as *mut i32).cast(),
                iov_len: mem::size_of::<i32>(),
            };
            // SAFETY: SETREGSET reads `iov_len` bytes from `iov_base`.
            unsafe {
                ptrace_checked(
                    sys::PTRACE_SETREGSET,
                    self.pid,
                    sys::NT_ARM_SYSTEM_CALL as usize,
                    &mut iov as *mut libc::iovec as usize,
                )
            }
        }
    }

    /// The fault address of the signal the tracee is stopped for, if the
    /// signal has one.
    pub fn fault_addr(&self, signal: i32) -> Option<u64> {
        if !matches!(
            signal,
            libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE | libc::SIGTRAP
        ) {
            return None;
        }
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
        if ret < 0 || info.si_code <= 0 {
            // Sent by a process, not raised by the CPU.
            return None;
        }
        // SAFETY: for these signals the union holds the fault address.
        Some(unsafe { info.si_addr() } as u64)
    }

    /// Kills the tracee and reaps it. Does nothing if already reaped.
    pub fn kill(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        // SAFETY: plain syscall. The pid still names our unreaped child.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        loop {
            match self.wait()? {
                Stop::Exited(_) | Stop::Killed(_) => return Ok(()),
                // Stops that were already queued before the kill.
                _ => continue,
            }
        }
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
