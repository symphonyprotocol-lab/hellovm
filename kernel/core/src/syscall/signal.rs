//! Signal syscalls, signal delivery and interval timers.
//!
//! A signal is delivered when its thread is about to resume ([`Ctx::resume`]):
//! after a syscall, after an interrupted parked syscall, after a fault, or
//! after the platform interrupted it on the kernel's request. The kernel then
//! runs the default action or writes a signal frame and resumes the thread in
//! the handler.

use std::time::Duration;

use crate::abi;
use crate::errno::{Errno, SysResult, EAGAIN, EFAULT, EINTR, EINVAL, ENOMEM, EPERM, ESRCH};
use crate::host::Host;
use crate::kernel::{ExitStatus, KernelError};
use crate::platform::{Fault, GuestAddr, Platform};
use crate::signal::{
    self, bit, AltStack, FrameParams, SigAction, SigInfo, SA_NODEFER, SA_RESETHAND, SA_RESTART,
    SIGKILL, SIGSEGV, SIGSTOP, SIG_DFL, SIG_IGN, SS_AUTODISARM, SS_DISABLE, SS_ONSTACK,
    UNBLOCKABLE,
};
use crate::task::{ChildEvent, Disposition, Next, Restart, State, ThreadState};

use super::{Action, Ctx};

const SIG_BLOCK: i64 = 0;
const SIG_UNBLOCK: i64 = 1;
const SIG_SETMASK: i64 = 2;

const ITIMER_REAL: i64 = 0;

fn timeval(d: Duration) -> [u8; 16] {
    abi::encode_pair(d.as_secs() as i64, i64::from(d.subsec_micros()))
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    /// Resumes this thread with `next`, delivering a pending signal first if
    /// there is one it must act on.
    ///
    /// A parked syscall that is interrupted (`Next::Interrupted`) only ends
    /// if a handler runs or its process ends. Otherwise (the signal was
    /// taken by another thread, had no effect, or stopped the process) the
    /// thread simply stays parked, with its deadline: nothing is restarted,
    /// so a sleep or a timed wait does not start over.
    pub(crate) fn resume(&mut self, mut next: Next) -> Result<(), KernelError> {
        let tid = self.tid;
        let mut handled = false;
        let stays_parked =
            matches!(next, Next::Interrupted(..)) && self.st.thread(tid).parked().is_some();
        loop {
            if self.proc().stopped {
                if !stays_parked {
                    self.st.thread_mut(tid).state = ThreadState::Held(next);
                }
                return Ok(());
            }
            let Some(info) = self.st.take_signal(tid) else {
                break;
            };
            match self.st.disposition(self.pid, info.signo) {
                Disposition::Ignore | Disposition::Continue => continue,
                Disposition::Kill { core } => {
                    self.exit_process(ExitStatus::Signaled(info.signo), core);
                    return Ok(());
                }
                Disposition::Stop => self.stop_process(info.signo),
                Disposition::Handler(action) => {
                    match self.setup_frame(next, &info, &action) {
                        Ok(()) => {
                            next = Next::Continue;
                            handled = true;
                        }
                        Err(()) => {
                            self.exit_process(ExitStatus::Signaled(SIGSEGV), true);
                            return Ok(());
                        }
                    }
                    break;
                }
            }
        }
        if !handled && stays_parked {
            return Ok(());
        }
        if !handled {
            // A syscall that completes on its own puts back the mask that
            // rt_sigsuspend, ppoll or pselect6 replaced.
            let thread = self.st.thread_mut(tid);
            if let Some(mask) = thread.saved_mask.take() {
                thread.sigmask = mask;
            }
        }
        if let Next::Interrupted(trap, _) = next {
            // Interrupted without a handler running: restart it.
            let mut context = self.plat.context(self.task)?;
            context.restart_syscall(&trap);
            self.plat.set_context(self.task, &context)?;
        }
        self.plat.resume(self.task, next.resume())?;
        let thread = self.st.thread_mut(tid);
        thread.state = ThreadState::Running;
        // Whatever interrupt was requested before has served its purpose:
        // the thread was stopped and its signals were looked at. The
        // platform may have consumed the request without reporting it (it
        // arrived during a syscall the kernel was already handling), and
        // after `execve` it concerned another task. A request that is still
        // on its way only causes one spurious `Trap::Interrupted`.
        thread.interrupt_sent = false;
        Ok(())
    }

    /// Writes the frame for running `action`'s handler for `info` and points
    /// the thread at it.
    fn setup_frame(&mut self, next: Next, info: &SigInfo, action: &SigAction) -> Result<(), ()> {
        let mut context = self.plat.context(self.task).map_err(|_| ())?;
        match next {
            Next::Return(value) => context.set_ret(value),
            Next::Interrupted(trap, restart) => {
                let partial = std::mem::take(&mut self.st.thread_mut(self.tid).io_done);
                if partial > 0 {
                    // A blocking write that already moved data reports it.
                    context.set_ret(partial as i64);
                } else if restart == Restart::IfSaRestart && action.flags & SA_RESTART != 0 {
                    context.restart_syscall(&trap);
                } else {
                    self.report_sleep_left();
                    context.set_ret(-EINTR);
                }
            }
            Next::Continue | Next::Start { .. } => {}
        }
        let trampoline = self
            .proc()
            .mm
            .map_or(0, |mm| self.st.mms.get(mm).trampoline);
        let thread = self.st.thread(self.tid);
        let saved_mask = thread.saved_mask.unwrap_or(thread.sigmask);
        let altstack = thread.altstack;
        let params = FrameParams {
            info,
            action,
            saved_mask,
            altstack,
            trampoline,
        };
        let frame = signal::build_frame(&context, &params).map_err(|_| {
            log::info!("signal {}: no room for a signal frame", info.signo);
        })?;
        self.write_mem(frame.addr, &frame.bytes).map_err(|_| {
            log::info!(
                "signal {}: the stack at {:#x} is not writable",
                info.signo,
                frame.addr
            );
        })?;
        self.plat
            .set_context(self.task, &frame.context)
            .map_err(|_| ())?;
        let sig = info.signo;
        let thread = self.st.thread_mut(self.tid);
        thread.saved_mask = None;
        let mut mask = thread.sigmask | action.mask;
        if action.flags & SA_NODEFER == 0 {
            mask |= bit(sig);
        }
        thread.sigmask = mask & !UNBLOCKABLE;
        if altstack.flags & SS_AUTODISARM != 0 && altstack.contains(frame.addr + 1) {
            thread.altstack = AltStack::disabled();
        }
        if action.flags & SA_RESETHAND != 0 {
            self.proc_mut().actions[sig as usize - 1] = SigAction::default();
        }
        Ok(())
    }

    /// For a relative `nanosleep`/`clock_nanosleep` that a handler
    /// interrupts: writes the time left to its `rem` argument, if any.
    fn report_sleep_left(&mut self) {
        let Some(parked) = self.st.thread(self.tid).parked().copied() else {
            return;
        };
        const TIMER_ABSTIME: u64 = 1;
        let args = parked.trap.args;
        let rem = match parked.sysno {
            Some(crate::Sysno::Nanosleep) => args[1],
            Some(crate::Sysno::ClockNanosleep) if args[1] & TIMER_ABSTIME == 0 => args[3],
            _ => 0,
        };
        let (Some(deadline), true) = (parked.deadline, rem != 0) else {
            return;
        };
        let left = deadline.saturating_sub(self.host.clock_monotonic());
        let raw = abi::encode_pair(left.as_secs() as i64, i64::from(left.subsec_nanos()));
        // A bad `rem` pointer does not change the outcome (EINTR).
        let _ = self.write_mem(rem, &raw);
    }

    /// Stops this process for job control.
    fn stop_process(&mut self, sig: u32) {
        let proc = self.proc_mut();
        if proc.stopped {
            return;
        }
        proc.stopped = true;
        proc.event = Some(ChildEvent::Stopped(sig));
        let ppid = proc.ppid;
        self.st.changed = true;
        self.st
            .notify_parent(ppid, self.pid, signal::CLD_STOPPED, sig as i32);
    }

    /// Raises the signal for a fault of this thread. A fault signal that is
    /// blocked or ignored kills the process, as on Linux.
    pub(crate) fn force_signal(&mut self, fault: Fault) {
        let sig = fault.signal;
        if !signal::valid(i64::from(sig)) {
            self.exit_process(ExitStatus::Signaled(SIGKILL), false);
            return;
        }
        let blocked = self.st.thread(self.tid).sigmask & bit(sig) != 0;
        let action = self.proc().action(sig);
        if blocked || action.handler == SIG_IGN {
            self.proc_mut().actions[sig as usize - 1] = SigAction::default();
            self.st.thread_mut(self.tid).sigmask &= !bit(sig);
        }
        let info = SigInfo {
            signo: sig,
            code: fault.code,
            addr: fault.addr.unwrap_or(0),
            ..SigInfo::default()
        };
        self.st.thread_mut(self.tid).pending.push(info);
    }

    pub fn sys_kill(&mut self, pid: i64, sig: i64) -> SysResult<u64> {
        if !(0..=signal::NSIG as i64).contains(&sig) {
            return Err(Errno(EINVAL));
        }
        let targets: Vec<_> = match pid {
            p if p > 0 => match self.st.procs.get(&(p as u32)) {
                Some(_) => vec![p as u32],
                None => vec![],
            },
            0 => self.st.group(self.proc().pgid),
            -1 => self
                .st
                .procs
                .values()
                .filter(|p| p.alive() && p.pid != State::INIT && p.pid != self.pid)
                .map(|p| p.pid)
                .collect(),
            p if p == i64::from(i32::MIN) => vec![],
            p => self.st.group((-p) as u32),
        };
        if targets.is_empty() {
            return Err(Errno(ESRCH));
        }
        if sig != 0 {
            for target in targets {
                self.st
                    .post_signal(target, None, SigInfo::user(sig as u32, self.pid));
            }
        }
        Ok(0)
    }

    pub fn sys_tgkill(&mut self, tgid: i64, tid: i64, sig: i64) -> SysResult<u64> {
        if !(0..=signal::NSIG as i64).contains(&sig) || tid <= 0 || (tgid <= 0 && tgid != -1) {
            return Err(Errno(EINVAL));
        }
        let thread = self.st.threads.get(&(tid as u32)).ok_or(Errno(ESRCH))?;
        let pid = thread.pid;
        if tgid != -1 && i64::from(pid) != tgid {
            return Err(Errno(ESRCH));
        }
        if sig != 0 {
            let info = SigInfo {
                code: signal::SI_TKILL,
                ..SigInfo::user(sig as u32, self.pid)
            };
            self.st.post_signal(pid, Some(tid as u32), info);
        }
        Ok(0)
    }

    pub fn sys_rt_sigqueueinfo(
        &mut self,
        tgid: i64,
        tid: Option<i64>,
        sig: i64,
        info_addr: GuestAddr,
    ) -> SysResult<u64> {
        if !signal::valid(sig) {
            return Err(Errno(EINVAL));
        }
        let mut info = SigInfo::decode(&self.read_array(info_addr)?);
        // Only the kernel may claim to be the kernel.
        if (info.code >= 0 || info.code == signal::SI_TKILL) && tgid != i64::from(self.pid) {
            return Err(Errno(EPERM));
        }
        info.signo = sig as u32;
        let pid = u32::try_from(tgid).map_err(|_| Errno(ESRCH))?;
        if !self.st.procs.contains_key(&pid) {
            return Err(Errno(ESRCH));
        }
        let thread = match tid {
            Some(tid) => {
                let tid = u32::try_from(tid).map_err(|_| Errno(ESRCH))?;
                match self.st.threads.get(&tid) {
                    Some(t) if t.pid == pid => Some(tid),
                    _ => return Err(Errno(ESRCH)),
                }
            }
            None => None,
        };
        if !self.st.post_signal(pid, thread, info) {
            return Err(Errno(EAGAIN));
        }
        Ok(0)
    }

    pub fn sys_rt_sigaction(
        &mut self,
        sig: i64,
        act: GuestAddr,
        old: GuestAddr,
        size: u64,
    ) -> SysResult<u64> {
        if size != 8 || !signal::valid(sig) {
            return Err(Errno(EINVAL));
        }
        let sig = sig as u32;
        if act != 0 && (sig == SIGKILL || sig == SIGSTOP) {
            return Err(Errno(EINVAL));
        }
        let current = self.proc().action(sig);
        let new = if act != 0 {
            Some(SigAction::decode(&self.read_array(act)?))
        } else {
            None
        };
        if old != 0 {
            self.write_mem(old, &current.encode())?;
        }
        if let Some(mut new) = new {
            new.mask &= !UNBLOCKABLE;
            self.proc_mut().actions[sig as usize - 1] = new;
            // Signals that are ignored now are dropped.
            let ignored = new.handler == SIG_IGN
                || (new.handler == SIG_DFL
                    && signal::default_action(sig) == signal::DefaultAction::Ignore);
            if ignored {
                let proc = self.proc_mut();
                proc.pending.discard(bit(sig));
                for tid in proc.threads.clone() {
                    self.st.thread_mut(tid).pending.discard(bit(sig));
                }
            }
        }
        Ok(0)
    }

    pub fn sys_rt_sigprocmask(
        &mut self,
        how: i64,
        set: GuestAddr,
        old: GuestAddr,
        size: u64,
    ) -> SysResult<u64> {
        if size != 8 {
            return Err(Errno(EINVAL));
        }
        let new = if set != 0 {
            Some(self.read_u64(set)?)
        } else {
            None
        };
        let current = self.st.thread(self.tid).sigmask;
        if old != 0 {
            self.write_u64(old, current)?;
        }
        if let Some(set) = new {
            let mask = match how {
                SIG_BLOCK => current | set,
                SIG_UNBLOCK => current & !set,
                SIG_SETMASK => set,
                _ => return Err(Errno(EINVAL)),
            };
            self.st.thread_mut(self.tid).sigmask = mask & !UNBLOCKABLE;
            // A process-directed signal blocked here may be another
            // thread's to take now, and the other way round.
            self.st.changed = true;
        }
        Ok(0)
    }

    pub fn sys_rt_sigreturn(&mut self) -> SysResult<u64> {
        let restored = (|| {
            let context = self.plat.context(self.task).map_err(|_| ())?;
            let (addr, len) = signal::frame_location(&context);
            if self.arch == crate::Arch::Aarch64 && addr % 16 != 0 {
                return Err(());
            }
            let frame = self.read_mem(addr, len).map_err(|_| ())?;
            let (mut restored, mask, altstack) = signal::read_frame(&context, &frame);
            if let crate::platform::Context::X86_64(c) = &mut restored {
                let (fp, fp_len) = signal::x86_64_fpstate(&frame);
                if fp != 0 {
                    let fx = self.read_mem(fp, fp_len).map_err(|_| ())?;
                    c.fxsave.copy_from_slice(&fx);
                }
            }
            Ok((restored, mask, altstack))
        })();
        let Ok((context, mask, altstack)) = restored else {
            log::info!("rt_sigreturn with a bad frame");
            self.exit_process(ExitStatus::Signaled(SIGSEGV), true);
            self.action = Some(Action::Done);
            return Ok(0);
        };
        self.plat
            .set_context(self.task, &context)
            .map_err(|_| Errno(EFAULT))?;
        let sp = context.sp();
        let thread = self.st.thread_mut(self.tid);
        thread.sigmask = mask & !UNBLOCKABLE;
        // Like Linux's restore_altstack: a bad stack_t is ignored.
        if !thread.altstack.contains(sp) && altstack.flags & !(SS_DISABLE | SS_AUTODISARM) == 0 {
            thread.altstack = if altstack.flags & SS_DISABLE != 0 {
                AltStack::disabled()
            } else {
                altstack
            };
        }
        self.st.changed = true;
        self.action = Some(Action::Continue);
        Ok(0)
    }

    pub fn sys_rt_sigsuspend(&mut self, set: GuestAddr, size: u64) -> SysResult<u64> {
        if size != 8 {
            return Err(Errno(EINVAL));
        }
        if self.parked.is_none() {
            let mask = self.read_u64(set)?;
            let thread = self.st.thread_mut(self.tid);
            thread.saved_mask = Some(thread.sigmask);
            thread.sigmask = mask & !UNBLOCKABLE;
            self.st.changed = true;
        }
        Err(self.park_sleep(None))
    }

    pub fn sys_pause(&mut self) -> SysResult<u64> {
        Err(self.park_sleep(None))
    }

    pub fn sys_rt_sigpending(&mut self, set: GuestAddr, size: u64) -> SysResult<u64> {
        if size > 8 {
            return Err(Errno(EINVAL));
        }
        let thread = self.st.thread(self.tid);
        let pending = (thread.pending.set() | self.proc().pending.set()) & thread.sigmask;
        self.write_mem(set, &pending.to_le_bytes()[..size as usize])?;
        Ok(0)
    }

    pub fn sys_rt_sigtimedwait(
        &mut self,
        set: GuestAddr,
        info: GuestAddr,
        timeout: GuestAddr,
        size: u64,
    ) -> SysResult<u64> {
        if size != 8 {
            return Err(Errno(EINVAL));
        }
        let wanted = self.read_u64(set)? & !UNBLOCKABLE;
        let timeout = if timeout != 0 {
            Some(self.read_timespec(timeout)?)
        } else {
            None
        };
        let tid = self.tid;
        let taken = match self.st.thread_mut(tid).pending.take(wanted) {
            Some(i) => Some(i),
            None => self.proc_mut().pending.take(wanted),
        };
        if let Some(found) = taken {
            if info != 0 {
                self.write_mem(info, &found.encode())?;
            }
            return Ok(u64::from(found.signo));
        }
        if self.timed_out() || timeout.is_some_and(|t| t.is_zero()) {
            return Err(Errno(EAGAIN));
        }
        Err(self.park_retry(timeout, Restart::Never))
    }

    pub fn sys_sigaltstack(&mut self, new: GuestAddr, old: GuestAddr) -> SysResult<u64> {
        let sp = self
            .plat
            .context(self.task)
            .map(|c| c.sp())
            .map_err(|_| Errno(EFAULT))?;
        let current = self.st.thread(self.tid).altstack;
        if old != 0 {
            let mut report = current;
            report.flags = current.reported_flags(sp);
            self.write_mem(old, &report.encode())?;
        }
        if new != 0 {
            let mut stack = AltStack::decode(&self.read_array(new)?);
            if current.contains(sp) {
                return Err(Errno(EPERM));
            }
            let mode = stack.flags & !SS_AUTODISARM;
            if mode != 0 && mode != SS_DISABLE && mode != SS_ONSTACK {
                return Err(Errno(EINVAL));
            }
            if mode == SS_DISABLE {
                stack = AltStack::disabled();
            } else {
                if stack.size < signal::min_stack_size(self.arch) {
                    return Err(Errno(ENOMEM));
                }
                stack.flags &= SS_AUTODISARM;
            }
            self.st.thread_mut(self.tid).altstack = stack;
        }
        Ok(0)
    }

    /// The remaining time of this process's real-time timer.
    fn itimer_left(&mut self) -> Duration {
        let now = self.host.clock_monotonic();
        self.proc()
            .itimer
            .deadline
            .map_or(Duration::ZERO, |d| d.saturating_sub(now))
    }

    pub fn sys_alarm(&mut self, seconds: u64) -> SysResult<u64> {
        let left = self.itimer_left();
        let now = self.host.clock_monotonic();
        let timer = &mut self.proc_mut().itimer;
        timer.interval = Duration::ZERO;
        timer.deadline =
            (seconds != 0).then(|| now.saturating_add(Duration::from_secs(seconds.min(1 << 31))));
        let mut secs = left.as_secs();
        if left.subsec_nanos() >= 500_000_000 || (secs == 0 && !left.is_zero()) {
            secs += 1;
        }
        Ok(secs)
    }

    fn read_timeval(&mut self, addr: GuestAddr) -> SysResult<Duration> {
        let (sec, usec) = abi::decode_pair(&self.read_array(addr)?);
        if sec < 0 || !(0..1_000_000).contains(&usec) {
            return Err(Errno(EINVAL));
        }
        Ok(Duration::new(sec as u64, usec as u32 * 1000))
    }

    pub fn sys_setitimer(&mut self, which: i64, new: GuestAddr, old: GuestAddr) -> SysResult<u64> {
        if !(0..=2).contains(&which) {
            return Err(Errno(EINVAL));
        }
        if which != ITIMER_REAL {
            log::warn!("setitimer: only ITIMER_REAL is implemented; timer {which} never fires");
            if old != 0 {
                self.write_mem(old, &[0; 32])?;
            }
            return Ok(0);
        }
        let new = if new != 0 {
            let interval = self.read_timeval(new)?;
            let value = self.read_timeval(new + 16)?;
            Some((interval, value))
        } else {
            None
        };
        if old != 0 {
            self.sys_getitimer(which, old)?;
        }
        if let Some((interval, value)) = new {
            let now = self.host.clock_monotonic();
            let timer = &mut self.proc_mut().itimer;
            timer.interval = interval;
            timer.deadline = (!value.is_zero()).then(|| now.saturating_add(value));
        }
        Ok(0)
    }

    pub fn sys_getitimer(&mut self, which: i64, out: GuestAddr) -> SysResult<u64> {
        if !(0..=2).contains(&which) {
            return Err(Errno(EINVAL));
        }
        let mut buf = [0u8; 32];
        if which == ITIMER_REAL {
            let interval = self.proc().itimer.interval;
            let left = self.itimer_left();
            buf[..16].copy_from_slice(&timeval(interval));
            buf[16..].copy_from_slice(&timeval(left));
        }
        self.write_mem(out, &buf)?;
        Ok(0)
    }

    pub(crate) fn read_timespec(&mut self, addr: GuestAddr) -> SysResult<Duration> {
        let (sec, nsec) = abi::decode_pair(&self.read_array(addr)?);
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return Err(Errno(EINVAL));
        }
        Ok(Duration::new(sec as u64, nsec as u32))
    }
}
