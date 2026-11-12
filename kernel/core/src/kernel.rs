//! The kernel: one sandbox's filesystem, processes and threads, and the
//! event loop that runs them.
//!
//! # The event loop
//!
//! [`Kernel::run`] serves every thread of the sandbox from the calling host
//! thread. Each iteration:
//!
//! 1. resumes the threads that are ready (their syscall completed, a signal
//!    handler was set up, a program was loaded);
//! 2. if the sandbox's state changed (data in a pipe, a child exited, a
//!    signal was posted, console input arrived), revisits the parked
//!    threads: a deliverable signal interrupts a parked syscall, the others
//!    retry it; and running threads with a signal to act on are interrupted
//!    through the platform;
//! 3. expires deadlines (sleeps, timeouts, interval timers);
//! 4. waits in [`Platform::wait`] for the next trap, bounded by the nearest
//!    deadline, and handles it: a syscall is dispatched and either completes
//!    at once or parks its thread; a fault becomes a signal.
//!
//! A parked syscall leaves no trace until it completes: a handler that
//! decides to wait has not changed anything yet, so it can simply be run
//! again later. Waits that are woken explicitly rather than retried
//! (`futex`, `vfork`) say so in [`WaitKind`].
//!
//! The sandbox lives as long as its first process, which plays the role of
//! init: orphans are reparented to it, and when it ends every other process
//! is killed and [`Kernel::run`] returns its status.

use std::fmt;
use std::time::Duration;

use crate::arch::{Arch, Sysno};
use crate::errno::{Errno, MAX_ERRNO};
use crate::fd::{Access, FileObject, OpenFile};
use crate::host::{ConsoleStream, Host};
use crate::platform::{Event, Platform, PlatformError, SyscallTrap, Trap};
use crate::syscall::{self, Action, Ctx};
use crate::task::{Next, Parked, Process, State, Thread, ThreadState, Tid, WaitKind};
use crate::tty::Console;
use crate::vfs::{Ino, Timespec, Vfs};

/// How a process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// It called `exit` or `exit_group` with this status (0..=255).
    Exited(i32),
    /// It was killed by this Linux signal.
    Signaled(u32),
}

impl ExitStatus {
    /// The `wait4` status word. `core` marks a signal whose default action
    /// dumps core (no core file is ever written).
    pub(crate) fn wait_status(self, core: bool) -> i32 {
        match self {
            ExitStatus::Exited(code) => (code & 0xff) << 8,
            ExitStatus::Signaled(sig) => sig as i32 | if core { 0x80 } else { 0 },
        }
    }
}

#[derive(Debug)]
pub enum KernelError {
    Platform(PlatformError),
    /// The program could not be started.
    Exec {
        path: String,
        errno: Errno,
        reason: String,
    },
    /// `run` without a successful `exec`.
    NoProgram,
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Platform(err) => write!(f, "platform: {err}"),
            KernelError::Exec { path, reason, .. } => write!(f, "{path}: {reason}"),
            KernelError::NoProgram => f.write_str("no program loaded"),
        }
    }
}

impl std::error::Error for KernelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KernelError::Platform(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PlatformError> for KernelError {
    fn from(err: PlatformError) -> Self {
        KernelError::Platform(err)
    }
}

/// The result of one handled syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Returned(i64),
    /// The thread continued with a new context (`rt_sigreturn`, `execve`).
    Continued,
    /// The thread or process ended.
    Ended,
}

/// One entry of the syscall trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallRecord {
    /// The guest thread that made the syscall.
    pub tid: u32,
    pub arch: Arch,
    pub nr: u64,
    pub sysno: Option<Sysno>,
    pub args: [u64; 6],
    pub outcome: Outcome,
}

impl fmt::Display for SyscallRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nargs = match self.sysno {
            Some(sysno) => {
                f.write_str(sysno.name())?;
                sysno.arg_count()
            }
            None => {
                write!(f, "syscall_{}", self.nr)?;
                6
            }
        };
        f.write_str("(")?;
        for (i, arg) in self.args[..nargs].iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            if *arg < 4096 {
                write!(f, "{arg}")?;
            } else {
                write!(f, "{arg:#x}")?;
            }
        }
        f.write_str(")")?;
        match self.outcome {
            Outcome::Returned(ret) if (-MAX_ERRNO..0).contains(&ret) => {
                write!(f, " = -1 (errno {})", -ret)
            }
            Outcome::Returned(ret) if !(-4096..=4096).contains(&ret) => write!(f, " = {ret:#x}"),
            Outcome::Returned(ret) => write!(f, " = {ret}"),
            Outcome::Continued | Outcome::Ended => f.write_str(" = ?"),
        }
    }
}

/// How the sandbox console appears to the guest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConsoleMode {
    /// fd 0 reads the host's console input, fds 1 and 2 write its output
    /// and error streams; none of them is a terminal.
    #[default]
    Streams,
    /// fds 0, 1 and 2 are one terminal (`/dev/console`) with a line
    /// discipline, job control and window size; its output goes to the
    /// host's output stream.
    Terminal,
}

/// The current wall-clock time from the host, as a VFS timestamp.
pub(crate) fn now<H: Host + ?Sized>(host: &mut H) -> Timespec {
    let t = host.clock_realtime();
    Timespec {
        sec: t.as_secs() as i64,
        nsec: t.subsec_nanos(),
    }
}

/// A kernel instance serving one sandbox: its filesystem and its processes.
pub struct Kernel<H> {
    host: H,
    trace: Option<Vec<SyscallRecord>>,
    vfs: Vfs,
    st: State,
    /// The directory the next program starts in (the last one's current
    /// directory, as for the commands of a session).
    cwd: Ino,
    console_mode: ConsoleMode,
    /// The platform's architecture, once a program was loaded.
    arch: Option<Arch>,
}

impl<H: Host> Kernel<H> {
    /// A kernel whose filesystem is the host's image (if any) under an
    /// empty in-memory layer.
    pub fn new(mut host: H) -> Self {
        let time = now(&mut host);
        let mut vfs = Vfs::new(&mut host, time);
        let root = vfs.root();
        vfs.opened(root);
        Kernel {
            host,
            trace: None,
            vfs,
            st: State::new(Console::new()),
            cwd: root,
            console_mode: ConsoleMode::Streams,
            arch: None,
        }
    }

    /// Limits the sandbox's in-memory filesystem layer to `bytes` (file
    /// contents plus a small fixed cost per file); writes beyond it fail
    /// with `ENOSPC`. The default is [`crate::vfs::DEFAULT_UPPER_LIMIT`].
    pub fn with_fs_limit(mut self, bytes: u64) -> Self {
        self.set_fs_limit(bytes);
        self
    }

    /// See [`Kernel::with_fs_limit`].
    pub fn set_fs_limit(&mut self, bytes: u64) {
        self.vfs.set_upper_limit(bytes);
    }

    /// Records every syscall the app makes; see [`Kernel::trace`].
    pub fn with_trace(mut self) -> Self {
        self.trace = Some(Vec::new());
        self
    }

    /// Sets how the console appears to the next program.
    pub fn with_console(mut self, mode: ConsoleMode) -> Self {
        self.console_mode = mode;
        self
    }

    /// Sets the terminal's window size (when the console is a terminal);
    /// its foreground process group gets `SIGWINCH`.
    pub fn set_window_size(&mut self, rows: u16, cols: u16) {
        syscall::set_window_size(&mut self.st, rows, cols);
    }

    /// The syscalls handled so far, if tracing is on.
    pub fn trace(&self) -> &[SyscallRecord] {
        self.trace.as_deref().unwrap_or(&[])
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Issues the next fake IP from `198.51.100.0/24` and records it.
    ///
    /// This is the 002a test helper. A later guest `connect` to the address
    /// is spliced to the configured host endpoint; the address itself is
    /// never a host dial target. Returns `None` once `.1` through `.254`
    /// have all been issued. The address is never a NIC, loopback,
    /// wildcard, or `198.18.0.0/15` address.
    pub fn issue_fake_ip(&mut self) -> Option<[u8; 4]> {
        self.st.net.issue_fake_ip()
    }

    pub fn into_host(self) -> H {
        self.host
    }

    /// Loads the program at `path` (in the sandbox filesystem) into a new
    /// task of `platform`, as the sandbox's first process, and prepares it
    /// to start with `argv` and `envp`.
    pub fn exec<P: Platform + ?Sized>(
        &mut self,
        platform: &mut P,
        path: &[u8],
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
    ) -> Result<(), KernelError> {
        if !self.st.procs.is_empty() {
            self.end_all(platform);
        }
        self.arch = Some(platform.arch());
        let display = String::from_utf8_lossy(path).into_owned();
        let loaded = syscall::load_program(
            &mut self.host,
            platform,
            &mut self.vfs,
            self.cwd,
            path,
            argv,
            envp,
        )
        .map_err(|err| KernelError::Exec {
            path: display.clone(),
            errno: err.errno,
            reason: err.reason,
        })?;
        let start = self.host.clock_monotonic();
        let pid = self.st.alloc_pid().expect("an empty sandbox has room");
        // Each program gets a fresh view of console input; a terminal is
        // controlled by its session.
        self.st.console = match self.console_mode {
            ConsoleMode::Streams => Console::new(),
            ConsoleMode::Terminal => Console::terminal(pid),
        };
        let mut proc = Process::new(pid, self.cwd, start);
        self.vfs.opened(self.cwd);
        self.install_console(&mut proc);
        let task = loaded.task;
        let mm = self.st.mms.add(loaded.mm, loaded.trampoline);
        proc.mm = Some(mm);
        proc.threads.push(pid);
        proc.name = loaded.name;
        proc.exe = loaded.exe;
        proc.cmdline = loaded.cmdline;
        self.st.procs.insert(pid, proc);
        let next = Next::Start {
            entry: loaded.entry,
            stack: loaded.stack,
        };
        self.st
            .threads
            .insert(pid, Thread::new(pid, pid, task, ThreadState::Ready(next)));
        self.st.tasks.insert(task, pid);
        self.st.init_status = None;
        Ok(())
    }

    fn install_console(&mut self, proc: &mut Process) {
        let files = &mut self.st.files;
        let objects: [(FileObject, Access); 3] = match self.console_mode {
            ConsoleMode::Streams => [
                (FileObject::ConsoleIn, Access::Read),
                (FileObject::ConsoleOut(ConsoleStream::Stdout), Access::Write),
                (FileObject::ConsoleOut(ConsoleStream::Stderr), Access::Write),
            ],
            ConsoleMode::Terminal => [(FileObject::Tty, Access::ReadWrite); 3],
        };
        for (object, access) in objects {
            proc.fds
                .install(files, OpenFile::new(object, access), 0, false)
                .expect("a new fd table has room");
        }
    }

    /// Runs the sandbox until its first process ends, handling all syscalls
    /// of all of its processes, and returns how that process ended. Every
    /// process still alive then is killed.
    ///
    /// The filesystem and the first process's current directory stay, so
    /// the next [`Kernel::exec`] runs another program in the same sandbox,
    /// as successive commands of a session.
    pub fn run<P: Platform + ?Sized>(
        &mut self,
        platform: &mut P,
    ) -> Result<ExitStatus, KernelError> {
        if self.st.procs.is_empty() {
            return Err(KernelError::NoProgram);
        }
        self.host.set_console_waker(platform.waker());
        let result = self.event_loop(platform);
        self.end_all(platform);
        if let Some(cwd) = self.st.init_cwd.take() {
            self.vfs.closed(self.cwd);
            self.cwd = cwd;
        }
        result
    }

    fn ctx<'a, P: Platform + ?Sized>(
        &'a mut self,
        platform: &'a mut P,
        tid: Tid,
        parked: Option<Parked>,
    ) -> Ctx<'a, H, P> {
        let arch = platform.arch();
        let thread = self.st.thread(tid);
        let (pid, task) = (thread.pid, thread.task);
        Ctx {
            host: &mut self.host,
            plat: platform,
            vfs: &mut self.vfs,
            st: &mut self.st,
            arch,
            tid,
            pid,
            task,
            parked,
            action: None,
        }
    }

    fn event_loop<P: Platform + ?Sized>(
        &mut self,
        platform: &mut P,
    ) -> Result<ExitStatus, KernelError> {
        self.st.changed = true;
        loop {
            if let Some(status) = self.st.init_status {
                return Ok(status);
            }
            self.resume_ready(platform)?;
            if self.st.init_status.is_some() {
                continue;
            }
            if std::mem::take(&mut self.st.changed) {
                self.revisit(platform)?;
                continue;
            }
            let now = self.host.clock_monotonic();
            let deadline = self.next_deadline();
            if let Some(deadline) = deadline {
                if deadline <= now {
                    self.expire(platform, now)?;
                    continue;
                }
            }
            let timeout = deadline.map(|d| d - now);
            match platform.wait(timeout)? {
                Some(event) => self.handle_event(platform, event)?,
                // A timeout (handled at the top) or a wake-up: console
                // input may have arrived.
                None => {
                    if self.st.console.tty.is_some() {
                        syscall::pull_terminal_input(&mut self.st, &mut self.host);
                    }
                    self.st.changed = true;
                }
            }
        }
    }

    /// Resumes every thread that is ready.
    fn resume_ready<P: Platform + ?Sized>(&mut self, platform: &mut P) -> Result<(), KernelError> {
        loop {
            let ready: Vec<(Tid, Next)> = self
                .st
                .threads
                .values()
                .filter_map(|t| match t.state {
                    ThreadState::Ready(next) => Some((t.tid, next)),
                    _ => None,
                })
                .collect();
            if ready.is_empty() {
                return Ok(());
            }
            for (tid, next) in ready {
                if !self.st.threads.contains_key(&tid) {
                    continue;
                }
                self.ctx(platform, tid, None).resume(next)?;
            }
        }
    }

    /// Something changed: interrupt or retry parked syscalls, interrupt
    /// running threads that have a signal to act on, and let held threads
    /// go when their process was continued.
    fn revisit<P: Platform + ?Sized>(&mut self, platform: &mut P) -> Result<(), KernelError> {
        let tids: Vec<Tid> = self.st.threads.keys().copied().collect();
        for tid in tids {
            let Some(thread) = self.st.threads.get(&tid) else {
                continue;
            };
            let stopped = self.st.proc(thread.pid).stopped;
            match thread.state {
                ThreadState::Running => {
                    if !thread.interrupt_sent && self.st.has_signal_to_act_on(tid) {
                        let task = thread.task;
                        self.st.thread_mut(tid).interrupt_sent = true;
                        platform.interrupt(task)?;
                    } else if stopped && !thread.interrupt_sent {
                        // Stop it so that it can be held.
                        let task = thread.task;
                        self.st.thread_mut(tid).interrupt_sent = true;
                        platform.interrupt(task)?;
                    }
                }
                ThreadState::Held(next) => {
                    if !stopped {
                        self.st.thread_mut(tid).state = ThreadState::Ready(next);
                    }
                }
                ThreadState::Parked(parked) => {
                    if let WaitKind::Vfork(_) = parked.kind {
                        // The child runs on the parent's memory, so no
                        // handler may run in the parent; but SIGKILL must
                        // still end it.
                        let kill = crate::signal::bit(crate::signal::SIGKILL);
                        if self.st.deliverable(tid) & kill != 0 {
                            self.ctx(platform, tid, None)
                                .exit_process(ExitStatus::Signaled(crate::signal::SIGKILL), false);
                        }
                    } else if self.st.has_signal_to_act_on(tid) {
                        let next = Next::Interrupted(parked.trap, parked.restart);
                        self.ctx(platform, tid, None).resume(next)?;
                    } else if parked.kind == WaitKind::Retry && !stopped {
                        self.retry(platform, tid, parked)?;
                    }
                }
                ThreadState::Ready(_) => {}
            }
        }
        Ok(())
    }

    fn retry<P: Platform + ?Sized>(
        &mut self,
        platform: &mut P,
        tid: Tid,
        parked: Parked,
    ) -> Result<(), KernelError> {
        let (tid, action) = self.dispatch(platform, tid, Some(parked), parked.sysno, &parked.trap);
        self.complete(
            platform,
            tid,
            parked.sysno,
            &parked.trap,
            action,
            Some(parked),
        )
    }

    /// Runs a syscall handler for `tid`. Returns the thread's tid afterwards
    /// (`execve` in a non-leader thread gives it the process's pid).
    fn dispatch<P: Platform + ?Sized>(
        &mut self,
        platform: &mut P,
        tid: Tid,
        parked: Option<Parked>,
        sysno: Option<Sysno>,
        trap: &SyscallTrap,
    ) -> (Tid, Action) {
        let mut ctx = self.ctx(platform, tid, parked);
        let action = syscall::dispatch(&mut ctx, sysno, trap);
        (ctx.tid, action)
    }

    /// The nearest deadline of a parked syscall or an interval timer.
    fn next_deadline(&self) -> Option<Duration> {
        let parked = self
            .st
            .threads
            .values()
            .filter_map(|t| t.parked().and_then(|p| p.deadline));
        let timers = self.st.procs.values().filter_map(|p| p.itimer.deadline);
        parked.chain(timers).min()
    }

    fn expire<P: Platform + ?Sized>(
        &mut self,
        platform: &mut P,
        now: Duration,
    ) -> Result<(), KernelError> {
        let pids: Vec<_> = self
            .st
            .procs
            .values()
            .filter(|p| p.itimer.deadline.is_some_and(|d| d <= now))
            .map(|p| p.pid)
            .collect();
        for pid in pids {
            let proc = self.st.proc_mut(pid);
            let timer = &mut proc.itimer;
            timer.deadline = if timer.interval.is_zero() {
                None
            } else {
                Some(now.saturating_add(timer.interval))
            };
            self.st.post_signal(
                pid,
                None,
                crate::signal::SigInfo::kernel(crate::signal::SIGALRM),
            );
        }
        let expired: Vec<(Tid, Parked)> = self
            .st
            .threads
            .values()
            .filter_map(|t| {
                t.parked()
                    .filter(|p| p.deadline.is_some_and(|d| d <= now))
                    .map(|p| (t.tid, *p))
            })
            .collect();
        for (tid, mut parked) in expired {
            parked.timed_out = true;
            parked.deadline = None;
            match parked.kind {
                WaitKind::Futex { .. } => {
                    self.st.thread_mut(tid).state =
                        ThreadState::Ready(Next::Return(-crate::errno::ETIMEDOUT));
                    self.record(
                        tid,
                        parked.sysno,
                        &parked.trap,
                        Outcome::Returned(-crate::errno::ETIMEDOUT),
                    );
                }
                _ => self.retry(platform, tid, parked)?,
            }
        }
        self.st.changed = true;
        Ok(())
    }

    fn handle_event<P: Platform + ?Sized>(
        &mut self,
        platform: &mut P,
        event: Event,
    ) -> Result<(), KernelError> {
        let Some(&tid) = self.st.tasks.get(&event.task) else {
            log::debug!("event {event:?} of a task the kernel no longer has");
            return Ok(());
        };
        match event.trap {
            Trap::Syscall(trap) => {
                self.st.thread_mut(tid).state = ThreadState::Ready(Next::Continue);
                let sysno = platform.arch().sysno(trap.nr);
                let (tid, action) = self.dispatch(platform, tid, None, sysno, &trap);
                self.complete(platform, tid, sysno, &trap, action, None)
            }
            Trap::Fault(fault) => {
                self.st.thread_mut(tid).state = ThreadState::Ready(Next::Continue);
                log::debug!("thread {tid}: fault {fault:?}");
                let mut ctx = self.ctx(platform, tid, None);
                ctx.force_signal(fault);
                ctx.resume(Next::Continue)
            }
            Trap::Interrupted => {
                let thread = self.st.thread_mut(tid);
                thread.interrupt_sent = false;
                thread.state = ThreadState::Ready(Next::Continue);
                self.ctx(platform, tid, None).resume(Next::Continue)
            }
            Trap::Gone => {
                log::info!("thread {tid} was killed from outside the sandbox");
                self.st.tasks.remove(&event.task);
                self.st.init_status = Some(ExitStatus::Signaled(crate::signal::SIGKILL));
                Ok(())
            }
        }
    }

    /// Acts on what a syscall handler decided.
    fn complete<P: Platform + ?Sized>(
        &mut self,
        platform: &mut P,
        tid: Tid,
        sysno: Option<Sysno>,
        trap: &SyscallTrap,
        action: Action,
        parked: Option<Parked>,
    ) -> Result<(), KernelError> {
        match action {
            Action::Return(ret) => {
                self.record(tid, sysno, trap, Outcome::Returned(ret));
                self.ctx(platform, tid, None).resume(Next::Return(ret))
            }
            Action::Continue => {
                self.record(tid, sysno, trap, Outcome::Continued);
                self.ctx(platform, tid, None).resume(Next::Continue)
            }
            Action::Start { entry, stack } => {
                self.record(tid, sysno, trap, Outcome::Continued);
                self.ctx(platform, tid, None)
                    .resume(Next::Start { entry, stack })
            }
            Action::Park(wait) => {
                let now = self.host.clock_monotonic();
                let deadline = match parked {
                    Some(p) => p.deadline,
                    None => wait.timeout.map(|t| now.saturating_add(t)),
                };
                if let Some(thread) = self.st.threads.get_mut(&tid) {
                    thread.state = ThreadState::Parked(Parked {
                        trap: *trap,
                        sysno,
                        kind: wait.kind,
                        deadline,
                        restart: wait.restart,
                        timed_out: false,
                    });
                }
                Ok(())
            }
            Action::Done => {
                self.record(tid, sysno, trap, Outcome::Ended);
                Ok(())
            }
        }
    }

    fn record(&mut self, tid: Tid, sysno: Option<Sysno>, trap: &SyscallTrap, outcome: Outcome) {
        let Some(arch) = self.arch else {
            return;
        };
        let record = SyscallRecord {
            tid,
            arch,
            nr: trap.nr,
            sysno,
            args: trap.args,
            outcome,
        };
        log::debug!("[{tid}] {record}");
        if let Some(trace) = &mut self.trace {
            trace.push(record);
        }
    }

    /// Kills every process and forgets them all.
    fn end_all<P: Platform + ?Sized>(&mut self, platform: &mut P) {
        let pids: Vec<_> = self.st.procs.keys().copied().collect();
        for pid in pids {
            let Some(&tid) = self.st.proc(pid).threads.first() else {
                continue;
            };
            self.ctx(platform, tid, None)
                .exit_process(ExitStatus::Signaled(crate::signal::SIGKILL), false);
        }
        let pids: Vec<_> = self.st.procs.keys().copied().collect();
        for pid in pids {
            crate::syscall::reap(&mut self.st, pid);
        }
        debug_assert!(self.st.threads.is_empty());
        self.st.tasks.clear();
        self.st.changed = false;
        self.st.init_status = None;
        self.st.reset_pids();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::tests::sample;
    use crate::errno::{
        EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN, EBADF, ECONNABORTED, ECONNREFUSED,
        ECONNRESET, EEXIST, EFAULT, EHOSTUNREACH, EINPROGRESS, EINTR, ENETUNREACH, ENOENT, ENOSYS,
        ENOTDIR, EPIPE,
    };
    use crate::platform::Context;
    use crate::signal::{SA_RESTORER, SA_SIGINFO, SIGCHLD, SIGPIPE, SIGUSR1};
    use crate::testutil::{MockEntry, MockHost, MockPlatform};

    const SCRATCH: u64 = 0x7000_0000;
    const INIT: u64 = 1;

    fn host_with_prog(arch: Arch) -> MockHost {
        MockHost::with_image(&[
            ("bin", MockEntry::Dir),
            ("bin/prog", MockEntry::File(sample(arch, 2, 0x40_0000))),
            ("etc", MockEntry::Dir),
            ("etc/motd", MockEntry::File(b"hello image\n".to_vec())),
            ("etc/link", MockEntry::Symlink(b"motd".to_vec())),
        ])
    }

    /// A kernel with /bin/prog loaded as init, whose task follows the first
    /// script (later tasks take the next ones), with scratch memory holding
    /// `data`.
    fn setup_scripts(
        arch: Arch,
        scripts: Vec<Vec<Trap>>,
        data: &[(u64, &[u8])],
    ) -> (Kernel<MockHost>, MockPlatform) {
        let host = host_with_prog(arch);
        let mut plat = MockPlatform::with_scripts(arch, &host, scripts);
        let mut kernel = Kernel::new(host).with_trace();
        kernel
            .exec(&mut plat, b"/bin/prog", &[b"prog".to_vec()], &[])
            .unwrap();
        let mem = plat.mem(INIT);
        mem.poke(SCRATCH, &[0; 0x4000]);
        for (addr, bytes) in data {
            mem.poke(*addr, bytes);
        }
        (kernel, plat)
    }

    fn setup(
        arch: Arch,
        traps: Vec<Trap>,
        data: &[(u64, &[u8])],
    ) -> (Kernel<MockHost>, MockPlatform) {
        setup_scripts(arch, vec![traps], data)
    }

    fn sc(arch: Arch, sysno: Sysno, args: &[u64]) -> Trap {
        MockPlatform::syscall(arch, sysno, args)
    }

    fn returns(plat: &MockPlatform, task: u64) -> Vec<i64> {
        plat.task(task).returns.clone()
    }

    #[test]
    fn exec_loads_and_starts_the_program() {
        let arch = Arch::Aarch64;
        let (mut kernel, mut plat) = setup(arch, vec![sc(arch, Sysno::ExitGroup, &[3])], &[]);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(3));
        let (entry, sp) = plat.task(INIT).started.unwrap();
        assert_eq!(entry, 0x40_1000);
        assert_eq!(plat.mem(INIT).peek(sp, 8), 1u64.to_le_bytes());
        assert!(plat.task(INIT).killed);
        // run again without exec
        assert!(matches!(kernel.run(&mut plat), Err(KernelError::NoProgram)));
    }

    #[test]
    fn exec_errors() {
        let host = MockHost::with_image(&[
            (
                "dyn",
                MockEntry::File({
                    let mut f = sample(Arch::Aarch64, 2, 0x40_0000);
                    // Turn the second PT_LOAD into PT_INTERP pointing at text.
                    let ph = 64 + 56;
                    f[ph..ph + 4].copy_from_slice(&3u32.to_le_bytes());
                    f
                }),
            ),
            ("script", MockEntry::File(b"#!/bin/sh\n".to_vec())),
            ("bad", MockEntry::File(b"\x7fELF".to_vec())),
        ]);
        let mut plat = MockPlatform::new(Arch::Aarch64, &host);
        let mut kernel = Kernel::new(host);
        let mut err = |path: &[u8]| match kernel.exec(&mut plat, path, &[], &[]) {
            Err(KernelError::Exec { errno, reason, .. }) => (errno, reason),
            other => panic!("{other:?}"),
        };
        assert_eq!(err(b"/missing").0, Errno(ENOENT));
        // The interpreter named by PT_INTERP does not exist.
        assert_eq!(err(b"/dyn").0, Errno(ENOENT));
        // A script whose interpreter does not exist.
        assert_eq!(err(b"/script").0, Errno(ENOENT));
        assert_eq!(err(b"/bad").0, Errno(crate::errno::ENOEXEC));
        assert_eq!(err(b"/dev").0, Errno(crate::errno::EACCES));
        // Every task created along the way was discarded.
        assert!(plat.tasks.values().all(|t| t.killed));
    }

    #[test]
    fn write_and_exit_on_every_arch() {
        for arch in Arch::ALL {
            let traps = vec![
                sc(arch, Sysno::Write, &[1, SCRATCH, 5]),
                sc(arch, Sysno::Write, &[2, SCRATCH + 6, 5]),
                sc(arch, Sysno::ExitGroup, &[0x1_07]),
            ];
            let (mut kernel, mut plat) = setup(arch, traps, &[(SCRATCH, b"hello world")]);
            assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(7));
            assert_eq!(returns(&plat, INIT), vec![5, 5]);
            assert_eq!(kernel.host().stdout, b"hello");
            assert_eq!(kernel.host().stderr, b"world");
            let names: Vec<_> = kernel.trace().iter().map(|r| r.sysno).collect();
            assert_eq!(
                names,
                vec![
                    Some(Sysno::Write),
                    Some(Sysno::Write),
                    Some(Sysno::ExitGroup)
                ]
            );
        }
    }

    #[test]
    fn write_errors() {
        let arch = Arch::Aarch64;
        let traps = vec![
            sc(arch, Sysno::Write, &[3, SCRATCH, 1]),
            sc(arch, Sysno::Write, &[1, 0x10_0000_0000, 1]),
            sc(arch, Sysno::Write, &[1, SCRATCH, 0]),
            sc(arch, Sysno::Write, &[0, SCRATCH, 1]),
            sc(arch, Sysno::Exit, &[0]),
        ];
        let (mut kernel, mut plat) = setup(arch, traps, &[]);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        assert_eq!(returns(&plat, INIT), vec![-EBADF, -EFAULT, 0, -EBADF]);
        assert!(kernel.host().stdout.is_empty());
    }

    #[test]
    fn unknown_syscalls_are_enosys() {
        for arch in Arch::ALL {
            let traps = vec![
                sc(arch, Sysno::Eventfd2, &[0, 0]),
                sc(arch, Sysno::Clone3, &[SCRATCH, 88]),
                Trap::Syscall(SyscallTrap {
                    nr: 100_000,
                    args: [0; 6],
                }),
                sc(arch, Sysno::ExitGroup, &[38]),
            ];
            let (mut kernel, mut plat) = setup(arch, traps, &[]);
            assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(38));
            assert_eq!(returns(&plat, INIT), vec![-ENOSYS; 3]);
            assert_eq!(kernel.trace()[2].sysno, None);
        }
    }

    #[test]
    fn file_syscalls() {
        let arch = Arch::Aarch64;
        let at_fdcwd = (-100i64) as u64;
        let path = |off: u64| SCRATCH + off;
        let buf = SCRATCH + 0x2000;
        let o_creat_wr = 0o100 | 0o1;
        let traps = vec![
            // 0: open + read an image file through a symlink.
            sc(arch, Sysno::Openat, &[at_fdcwd, path(0), 0, 0]),
            sc(arch, Sysno::Read, &[3, buf, 100]),
            sc(arch, Sysno::Write, &[1, buf, 12]),
            sc(arch, Sysno::Close, &[3]),
            // 4: mkdir, create, write, pread back.
            sc(arch, Sysno::Mkdirat, &[at_fdcwd, path(0x100), 0o755]),
            sc(arch, Sysno::Mkdirat, &[at_fdcwd, path(0x100), 0o755]),
            sc(
                arch,
                Sysno::Openat,
                &[at_fdcwd, path(0x200), o_creat_wr, 0o644],
            ),
            sc(arch, Sysno::Write, &[3, path(0x300), 4]),
            sc(arch, Sysno::Pread64, &[3, buf, 4, 0]),
            sc(arch, Sysno::Openat, &[at_fdcwd, path(0x200), 2, 0]),
            sc(arch, Sysno::Pread64, &[4, buf, 4, 1]),
            // 11: chdir + getcwd, relative open, fstat.
            sc(arch, Sysno::Chdir, &[path(0x100)]),
            sc(arch, Sysno::Getcwd, &[buf, 100]),
            sc(
                arch,
                Sysno::Newfstatat,
                &[at_fdcwd, path(0x400), buf + 0x100, 0],
            ),
            sc(arch, Sysno::Fstat, &[1, buf + 0x200]),
            // 15: errors.
            sc(arch, Sysno::Openat, &[at_fdcwd, path(0x500), 0, 0]),
            sc(arch, Sysno::Openat, &[at_fdcwd, path(0x600), 0, 0]),
            sc(
                arch,
                Sysno::Openat,
                &[at_fdcwd, path(0x200), o_creat_wr | 0o200, 0],
            ),
            // 18: getdents64 of the new directory.
            sc(arch, Sysno::Openat, &[at_fdcwd, path(0x700), 0, 0]),
            sc(arch, Sysno::Getdents64, &[5, buf + 0x400, 0x400]),
            sc(arch, Sysno::Getdents64, &[5, buf + 0x400, 0x400]),
            // 21: dup2 onto stdout and write through it.
            sc(arch, Sysno::Dup3, &[4, 1, 0]),
            sc(arch, Sysno::Write, &[1, path(0x300), 4]),
            sc(arch, Sysno::Lseek, &[4, 0, 2]),
            // 24: memory.
            sc(arch, Sysno::Brk, &[0]),
            sc(arch, Sysno::Mmap, &[0, 0x2000, 3, 0x22, u64::MAX, 0]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let data: Vec<(u64, &[u8])> = vec![
            (path(0), b"/etc/link\0"),
            (path(0x100), b"/tmp/d\0"),
            (path(0x200), b"/tmp/d/f\0"),
            (path(0x300), b"data"),
            (path(0x400), b"f\0"),
            (path(0x500), b"/nope\0"),
            (path(0x600), b"/etc/motd/x\0"),
            (path(0x700), b".\0"),
        ];
        let (mut kernel, mut plat) = setup(arch, traps, &data);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let r = returns(&plat, INIT);
        assert_eq!(&r[..4], &[3, 12, 12, 0]);
        assert_eq!(kernel.host().stdout, b"hello image\n");
        // pread on the write-only fd fails; the second, read-write open works.
        assert_eq!(&r[4..11], &[0, -EEXIST, 3, 4, -EBADF, 4, 3]);
        assert_eq!(&r[11..15], &[0, 7, 0, 0]);
        let mem = plat.mem(INIT);
        assert_eq!(mem.peek(buf, 7), b"/tmp/d\0");
        // newfstatat of "f": regular, 4 bytes (aarch64 layout).
        let st = mem.peek(buf + 0x100, 128);
        assert_eq!(u32::from_le_bytes(st[16..20].try_into().unwrap()), 0o100644);
        assert_eq!(u64::from_le_bytes(st[48..56].try_into().unwrap()), 4);
        // fstat of the console: a character device.
        let st = mem.peek(buf + 0x200, 128);
        assert_eq!(
            u32::from_le_bytes(st[16..20].try_into().unwrap()) & 0o170000,
            0o020000
        );
        assert_eq!(&r[15..18], &[-ENOENT, -ENOTDIR, -EEXIST]);
        assert_eq!(r[18], 5);
        // ".", "..", "f": three 24-byte records.
        assert_eq!(&r[19..21], &[72, 0]);
        assert_eq!(&mem.peek(buf + 0x400 + 48 + 19, 2), b"f\0");
        assert_eq!(&r[21..24], &[1, 4, 4]);
        assert_eq!(
            kernel.host().stdout,
            b"hello image\n",
            "fd 1 is the file now"
        );
        assert_eq!(r[24], 0x40_6000, "brk starts after the image");
        assert!(r[25] > 0x40_0000);
        // The image is unchanged; the file lives in the upper layer, and
        // the next program starts in /tmp/d, where this one ended.
        let f = kernel
            .vfs
            .resolve(&mut kernel.host, 2, b"/tmp/d/f", true)
            .unwrap();
        assert_eq!(kernel.vfs.read_all(&mut kernel.host, f).unwrap(), b"data");
        assert_eq!(kernel.vfs.dir_path(kernel.cwd).unwrap(), b"/tmp/d");
        assert_eq!(kernel.st.files.len(), 0, "every description was released");
    }

    #[test]
    fn reads_are_short_or_efault_and_only_consume_what_arrived() {
        let arch = Arch::Aarch64;
        let at_fdcwd = (-100i64) as u64;
        let iov = SCRATCH + 0x100;
        let traps = vec![
            sc(arch, Sysno::Openat, &[at_fdcwd, SCRATCH, 0, 0]),
            // A bad buffer consumes nothing.
            sc(arch, Sysno::Read, &[3, 0x10_0000_0000, 5]),
            // Four bytes fit before the end of the mapped memory.
            sc(arch, Sysno::Read, &[3, SCRATCH + 0x3ffc, 12]),
            sc(arch, Sysno::Read, &[3, SCRATCH + 0x1000, 100]),
            // iovec lengths that overflow when added.
            sc(arch, Sysno::Lseek, &[3, 0, 0]),
            sc(arch, Sysno::Readv, &[3, iov, 2]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let mut iovecs = Vec::new();
        for _ in 0..2 {
            iovecs.extend_from_slice(&(SCRATCH + 0x2000).to_le_bytes());
            iovecs.extend_from_slice(&u64::MAX.to_le_bytes());
        }
        let (mut kernel, mut plat) =
            setup(arch, traps, &[(SCRATCH, b"/etc/motd\0"), (iov, &iovecs)]);
        kernel.run(&mut plat).unwrap();
        assert_eq!(returns(&plat, INIT), vec![3, -EFAULT, 4, 8, 0, 12]);
        let mem = plat.mem(INIT);
        assert_eq!(mem.peek(SCRATCH + 0x3ffc, 4), b"hell");
        assert_eq!(mem.peek(SCRATCH + 0x1000, 8), b"o image\n");
        assert_eq!(mem.peek(SCRATCH + 0x2000, 12), b"hello image\n");
    }

    #[test]
    fn sleeps_and_timeouts_wait_without_blocking_the_kernel() {
        let arch = Arch::Aarch64;
        let mut timeout = Vec::new();
        timeout.extend_from_slice(&0i64.to_le_bytes());
        timeout.extend_from_slice(&1000i64.to_le_bytes());
        let mut bad = Vec::new();
        bad.extend_from_slice(&0i64.to_le_bytes());
        bad.extend_from_slice(&2_000_000_000i64.to_le_bytes());
        let mut two_secs = Vec::new();
        two_secs.extend_from_slice(&2i64.to_le_bytes());
        two_secs.extend_from_slice(&0i64.to_le_bytes());
        let traps = vec![
            sc(arch, Sysno::Pselect6, &[0, 0, 0, 0, SCRATCH, 0]),
            sc(arch, Sysno::Pselect6, &[0, 0, 0, 0, SCRATCH + 0x100, 0]),
            sc(arch, Sysno::Nanosleep, &[SCRATCH + 0x200, 0]),
            // Console input: EOF, so poll reports it readable at once.
            sc(arch, Sysno::Ppoll, &[SCRATCH + 0x300, 1, 0, 0, 8]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let mut pollfd = Vec::new();
        pollfd.extend_from_slice(&0i32.to_le_bytes());
        pollfd.extend_from_slice(&1u16.to_le_bytes());
        pollfd.extend_from_slice(&0u16.to_le_bytes());
        let (mut kernel, mut plat) = setup(
            arch,
            traps,
            &[
                (SCRATCH, &timeout),
                (SCRATCH + 0x100, &bad),
                (SCRATCH + 0x200, &two_secs),
                (SCRATCH + 0x300, &pollfd),
            ],
        );
        let start = kernel.host().clock.get();
        kernel.run(&mut plat).unwrap();
        assert_eq!(returns(&plat, INIT), vec![0, -crate::errno::EINVAL, 0, 1]);
        let slept = kernel.host().clock.get() - start;
        assert_eq!(slept, Duration::from_nanos(2_000_001_000));
        assert_eq!(
            &plat.mem(INIT).peek(SCRATCH + 0x306, 2),
            &1u16.to_le_bytes()
        );
    }

    #[test]
    fn x86_64_stat_layout_reaches_the_guest() {
        let arch = Arch::X86_64;
        let traps = vec![
            sc(arch, Sysno::Stat, &[SCRATCH, SCRATCH + 0x100]),
            sc(arch, Sysno::Open, &[SCRATCH, 0o200000, 0]),
            sc(arch, Sysno::Open, &[SCRATCH + 0x40, 0o200000, 0]),
            sc(arch, Sysno::ArchPrctl, &[0x1002, 0x1234_5000]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let (mut kernel, mut plat) = setup(
            arch,
            traps,
            &[(SCRATCH, b"/etc/motd\0"), (SCRATCH + 0x40, b"/etc\0")],
        );
        kernel.run(&mut plat).unwrap();
        // O_DIRECTORY (x86_64 value) on a file fails; on a directory works.
        assert_eq!(returns(&plat, INIT), vec![0, -ENOTDIR, 3]);
        let st = plat.mem(INIT).peek(SCRATCH + 0x100, 144);
        assert_eq!(
            u64::from_le_bytes(st[16..24].try_into().unwrap()),
            1,
            "nlink"
        );
        assert_eq!(u32::from_le_bytes(st[24..28].try_into().unwrap()), 0o100755);
        assert_eq!(u64::from_le_bytes(st[48..56].try_into().unwrap()), 12);
        // arch_prctl continues with a new context: thread pointer set,
        // return value 0.
        let Context::X86_64(c) = &plat.task(INIT).context else {
            panic!()
        };
        assert_eq!((c.fs_base, c.rax), (0x1234_5000, 0));
    }

    #[test]
    fn fault_ends_the_app() {
        let traps = vec![Trap::Fault(crate::platform::Fault {
            signal: 11,
            code: 1,
            addr: Some(0),
        })];
        let (mut kernel, mut plat) = setup(Arch::X86_64, traps, &[]);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Signaled(11));
        assert!(plat.task(INIT).killed);
    }

    #[test]
    fn signals_to_self() {
        let arch = Arch::Aarch64;
        let traps = vec![
            sc(arch, Sysno::Kill, &[1, 0]),
            sc(arch, Sysno::Kill, &[1, 17]),
            sc(arch, Sysno::Kill, &[99, 15]),
            sc(arch, Sysno::Tgkill, &[1, 1, 6]),
        ];
        let (mut kernel, mut plat) = setup(arch, traps, &[]);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Signaled(6));
        assert_eq!(returns(&plat, INIT), vec![0, 0, -crate::errno::ESRCH]);
    }

    #[test]
    fn fork_and_wait() {
        let arch = Arch::Aarch64;
        let parent = vec![
            sc(arch, Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0]),
            sc(arch, Sysno::Wait4, &[u64::MAX, SCRATCH, 0, 0]),
            sc(arch, Sysno::Wait4, &[u64::MAX, SCRATCH, 0, 0]),
            sc(arch, Sysno::Getppid, &[]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let child = vec![
            sc(arch, Sysno::Getpid, &[]),
            sc(arch, Sysno::Getppid, &[]),
            sc(arch, Sysno::ExitGroup, &[3]),
        ];
        let (mut kernel, mut plat) = setup_scripts(arch, vec![parent, child], &[]);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        // The parent got pid 2, waited until the child exited (status
        // 3 << 8), then had no children left.
        assert_eq!(returns(&plat, INIT), vec![2, 2, -crate::errno::ECHILD, 0]);
        assert_eq!(plat.mem(INIT).peek(SCRATCH, 4), (3u32 << 8).to_le_bytes());
        // The child's clone returned 0 (through its context), then it saw
        // its own pid and its parent.
        let child = plat.task(2);
        assert_eq!(child.returns, vec![2, 1]);
        assert!(kernel.st.procs.is_empty(), "everything was reaped");
    }

    #[test]
    fn pipes_carry_data_to_eof_and_break_with_sigpipe() {
        let arch = Arch::Aarch64;
        let buf = SCRATCH + 0x100;
        let parent = vec![
            sc(arch, Sysno::Pipe2, &[SCRATCH, 0]),
            sc(arch, Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0]),
            sc(arch, Sysno::Close, &[4]),
            // Parks until the child wrote, then reads it, then EOF.
            sc(arch, Sysno::Read, &[3, buf, 100]),
            sc(arch, Sysno::Read, &[3, buf + 2, 100]),
            sc(arch, Sysno::Wait4, &[u64::MAX, 0, 0, 0]),
            // A pipe without readers: EPIPE, then SIGPIPE ends the process.
            sc(arch, Sysno::Pipe2, &[SCRATCH, 0]),
            sc(arch, Sysno::Close, &[4]),
            sc(arch, Sysno::Write, &[5, buf, 1]),
        ];
        let child = vec![
            sc(arch, Sysno::Close, &[3]),
            sc(arch, Sysno::Write, &[4, SCRATCH + 0x200, 2]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let (mut kernel, mut plat) =
            setup_scripts(arch, vec![parent, child], &[(SCRATCH + 0x200, b"hi")]);
        assert_eq!(
            kernel.run(&mut plat).unwrap(),
            ExitStatus::Signaled(SIGPIPE)
        );
        // The write failed with EPIPE, but SIGPIPE ended the process before
        // it returned.
        assert_eq!(returns(&plat, INIT), vec![0, 2, 0, 2, 0, 2, 0, 0]);
        let last = kernel.trace().last().unwrap();
        assert_eq!(
            (last.sysno, last.outcome),
            (Some(Sysno::Write), Outcome::Returned(-EPIPE))
        );
        assert_eq!(plat.mem(INIT).peek(buf, 2), b"hi");
        assert_eq!(kernel.st.pipes.live(), 0, "the pipes are gone");
    }

    fn sin(ip: [u8; 4], port: u16) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[..2].copy_from_slice(&2u16.to_le_bytes());
        addr[2..4].copy_from_slice(&port.to_be_bytes());
        addr[4..8].copy_from_slice(&ip);
        addr
    }

    #[test]
    fn sockets_loopback_errors_half_close_and_splice() {
        let arch = Arch::X86_64;
        let listen = sin([127, 0, 0, 1], 19000);
        let meta = sin([169, 254, 169, 254], 80);
        let rfc = sin([10, 1, 2, 3], 80);
        let off = sin([151, 101, 64, 223], 443);
        let hostu = sin([192, 0, 2, 99], 80);
        let gw = sin([192, 0, 2, 1], 80);
        let gwbind = sin([192, 0, 2, 1], 9);
        let fakebind = sin([198, 51, 100, 9], 9);
        let privb = sin([10, 0, 0, 1], 9);
        let udp_dst = sin([8, 8, 8, 8], 53);
        let udp_lo = sin([127, 0, 0, 1], 19001);
        let none = sin([127, 0, 0, 1], 1);
        let buf = SCRATCH + 0x800;
        let pollfd = SCRATCH + 0x900;
        let opt = SCRATCH + 0x920;
        let optlen = SCRATCH + 0x930;
        let alen = SCRATCH + 0x940;
        let outaddr = SCRATCH + 0x960;
        let ifreq = SCRATCH + 0x980;
        // Addresses laid out at SCRATCH. The fake-IP sockaddr is poked after
        // the kernel issues one.
        let mut data: Vec<(u64, Vec<u8>)> = vec![
            (SCRATCH, listen.to_vec()),
            (SCRATCH + 0x20, meta.to_vec()),
            (SCRATCH + 0x40, rfc.to_vec()),
            (SCRATCH + 0x60, off.to_vec()),
            (SCRATCH + 0x80, hostu.to_vec()),
            (SCRATCH + 0xa0, gw.to_vec()),
            (SCRATCH + 0xc0, gwbind.to_vec()),
            (SCRATCH + 0xe0, fakebind.to_vec()),
            (SCRATCH + 0x100, privb.to_vec()),
            (SCRATCH + 0x120, udp_dst.to_vec()),
            (SCRATCH + 0x140, udp_lo.to_vec()),
            (SCRATCH + 0x160, none.to_vec()),
            (SCRATCH + 0x180, b"hello-world".to_vec()),
            (buf, vec![0; 32]),
            (optlen, 4u32.to_le_bytes().to_vec()),
            (alen, 16u32.to_le_bytes().to_vec()),
            (ifreq, b"eth0".to_vec()),
        ];
        let _ = &mut data;
        let owned: Vec<(u64, Vec<u8>)> = data;
        let refs: Vec<(u64, &[u8])> = owned.iter().map(|(a, b)| (*a, b.as_slice())).collect();

        let nonblock = 1u64 | 0o4000;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Listen, &[3, 1]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[4, SCRATCH, 16]),
            sc(arch, Sysno::Accept, &[3, outaddr, alen]),
            sc(arch, Sysno::Sendto, &[4, SCRATCH + 0x180, 5, 0, 0, 0]),
            sc(arch, Sysno::Recvfrom, &[5, buf, 16, 0, 0, 0]),
            sc(arch, Sysno::Shutdown, &[4, 1]),
            sc(arch, Sysno::Recvfrom, &[5, buf + 8, 16, 0, 0, 0]),
            sc(arch, Sysno::Sendto, &[5, SCRATCH + 0x180 + 6, 5, 0, 0, 0]),
            sc(arch, Sysno::Recvfrom, &[4, buf + 16, 16, 0, 0, 0]),
            // Queue of 1 is full once another client connects before accept.
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[6, SCRATCH, 16]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[7, SCRATCH, 16]),
            sc(arch, Sysno::Connect, &[7, SCRATCH + 0x20, 16]),
            sc(arch, Sysno::Connect, &[7, SCRATCH + 0x40, 16]),
            sc(arch, Sysno::Connect, &[7, SCRATCH + 0x60, 16]),
            sc(arch, Sysno::Connect, &[7, SCRATCH + 0x80, 16]),
            sc(arch, Sysno::Connect, &[7, SCRATCH + 0xa0, 16]),
            sc(arch, Sysno::Bind, &[7, SCRATCH + 0xc0, 16]),
            sc(arch, Sysno::Bind, &[7, SCRATCH + 0xe0, 16]),
            sc(arch, Sysno::Bind, &[7, SCRATCH + 0x100, 16]),
            sc(arch, Sysno::Socket, &[2, 2, 0]),
            sc(
                arch,
                Sysno::Sendto,
                &[8, SCRATCH + 0x180, 4, 0, SCRATCH + 0x120, 16],
            ),
            sc(arch, Sysno::Socket, &[2, 2, 0]),
            sc(arch, Sysno::Bind, &[9, SCRATCH + 0x140, 16]),
            sc(
                arch,
                Sysno::Sendto,
                &[8, SCRATCH + 0x180, 4, 0, SCRATCH + 0x140, 16],
            ),
            sc(arch, Sysno::Recvfrom, &[9, buf, 8, 0, 0, 0]),
            sc(arch, Sysno::Socket, &[2, nonblock, 0]),
            // Drop the queued connection so the non-blocking connect can proceed.
            sc(arch, Sysno::Accept, &[3, outaddr, alen]),
            sc(arch, Sysno::Connect, &[10, SCRATCH, 16]),
            sc(arch, Sysno::Poll, &[pollfd, 1, 0]),
            sc(arch, Sysno::Getsockopt, &[10, 1, 4, opt, optlen]),
            sc(arch, Sysno::Socket, &[2, nonblock, 0]),
            sc(arch, Sysno::Connect, &[12, SCRATCH + 0x160, 16]),
            sc(arch, Sysno::Getsockopt, &[12, 1, 4, opt + 8, optlen]),
            sc(arch, Sysno::Socket, &[10, 1, 0]),
            sc(arch, Sysno::Socket, &[16, 3, 0]),
            sc(arch, Sysno::Socket, &[1, 1, 0]),
            sc(arch, Sysno::Ioctl, &[3, 0x8915, ifreq]),
            // Peer close, then a write with MSG_NOSIGNAL.
            sc(arch, Sysno::Close, &[5]),
            sc(arch, Sysno::Sendto, &[4, buf, 1, 0x4000, 0, 0]),
            // No endpoint configured: an issued fake IP is still unreachable.
            sc(arch, Sysno::Connect, &[7, SCRATCH + 0x1a0, 16]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let (mut kernel, mut plat) = setup(arch, traps, &refs);
        let fake = kernel.issue_fake_ip().unwrap();
        assert!(fake[0] == 198 && fake[1] == 51 && fake[2] == 100);
        plat.mem(INIT).poke(SCRATCH + 0x1a0, &sin(fake, 443));
        // pollfd for fd 10, POLLOUT.
        let mut pfd = [0u8; 8];
        pfd[..4].copy_from_slice(&10i32.to_le_bytes());
        pfd[4..6].copy_from_slice(&4u16.to_le_bytes());
        plat.mem(INIT).poke(pollfd, &pfd);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        // The first connection was accepted, so the queue is empty and the
        // next connect succeeds. A third connect finds the queue full.
        assert_eq!(plat.mem(INIT).peek(buf, 5), b"hello");
        assert_eq!(plat.mem(INIT).peek(buf + 16, 5), b"world");
        assert_eq!(got[0], 3, "socket");
        assert_eq!(got[6], 5, "send {got:?}");
        assert_eq!(got[7], 5, "recv {got:?}");
        assert_eq!(got[9], 0, "half-close eof {got:?}");
        assert_eq!(got[11], 5, "reply {got:?}");
        // Index of the full-queue connect: socket 6 connect (success), socket 7 connect (refused).
        assert_eq!(got[13], 0, "second connect queued {got:?}");
        assert_eq!(got[15], -ECONNREFUSED, "full backlog {got:?}");
        assert_eq!(got[16], -ENETUNREACH, "metadata {got:?}");
        assert_eq!(got[17], -ENETUNREACH, "rfc1918 {got:?}");
        assert_eq!(got[18], -ENETUNREACH, "off-list {got:?}");
        assert_eq!(got[19], -EHOSTUNREACH, "nic {got:?}");
        assert_eq!(got[20], -ECONNREFUSED, "gateway {got:?}");
        assert_eq!(got[21], -EADDRNOTAVAIL, "bind gateway {got:?}");
        assert_eq!(got[22], -EADDRNOTAVAIL, "bind fake {got:?}");
        assert_eq!(got[23], -EADDRNOTAVAIL, "bind rfc1918 {got:?}");
        assert_eq!(got[25], -ENETUNREACH, "udp {got:?}");
        assert_eq!(got[29], 4, "udp echo {got:?}");
        assert_eq!(got[31], 11, "accept drained the queue {got:?}");
        assert_eq!(got[32], -EINPROGRESS, "nonblock connect {got:?}");
        assert_eq!(got[33], 1, "poll {got:?}");
        assert_eq!(plat.mem(INIT).peek(opt, 4), 0u32.to_le_bytes(), "SO_ERROR");
        assert_eq!(got[36], -EINPROGRESS, "nonblock refuse {got:?}");
        assert_eq!(
            i32::from_le_bytes(plat.mem(INIT).peek(opt + 8, 4).try_into().unwrap()),
            ECONNREFUSED as i32,
            "SO_ERROR after refuse"
        );
        assert_eq!(got[38], -EAFNOSUPPORT, "ipv6 {got:?}");
        assert_eq!(got[39], -EAFNOSUPPORT, "netlink {got:?}");
        assert_eq!(got[40], -EAFNOSUPPORT, "unix {got:?}");
        assert_eq!(got[43], -EPIPE, "nosignal {got:?}");
        assert_eq!(got[44], -ENETUNREACH, "unconfigured fake ip {got:?}");
        // SIOCGIFADDR wrote 192.0.2.2 at ifreq+20.
        assert_eq!(&plat.mem(INIT).peek(ifreq + 20, 4), &[192, 0, 2, 2]);
    }

    #[test]
    fn splice_echoes_the_configured_peer_not_the_fake_ip() {
        let arch = Arch::X86_64;
        let mut host = host_with_prog(arch);
        host.splice = true;
        host.splice_echo = true;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Sendto, &[3, SCRATCH + 0x40, 4, 0, 0, 0]),
            sc(arch, Sysno::Recvfrom, &[3, SCRATCH + 0x80, 8, 0, 0, 0]),
            sc(arch, Sysno::Shutdown, &[3, 1]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let mut plat = MockPlatform::with_scripts(arch, &host, vec![traps]);
        let mut kernel = Kernel::new(host).with_trace();
        kernel
            .exec(&mut plat, b"/bin/prog", &[b"prog".to_vec()], &[])
            .unwrap();
        plat.mem(INIT).poke(SCRATCH, &[0; 0x1000]);
        let ip = kernel.issue_fake_ip().unwrap();
        plat.mem(INIT).poke(SCRATCH, &sin(ip, 443));
        plat.mem(INIT).poke(SCRATCH + 0x40, b"ping");
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        assert_eq!(returns(&plat, INIT), vec![3, 0, 4, 4, 0]);
        assert_eq!(plat.mem(INIT).peek(SCRATCH + 0x80, 4), b"ping");
        let host = kernel.host();
        let flow = host.splice_flows().next().unwrap();
        assert_eq!(flow.dest_ip, ip);
        assert_eq!(flow.dest_port, 443);
        assert_eq!(host.splice_outbound(crate::host::HostStreamId(0)), b"ping");
    }

    fn poll_memory(fd: i32, events: u16) -> [u8; 8] {
        let mut raw = [0u8; 8];
        raw[..4].copy_from_slice(&fd.to_le_bytes());
        raw[4..6].copy_from_slice(&events.to_le_bytes());
        raw
    }

    fn revents_of(bytes: &[u8]) -> u16 {
        u16::from_le_bytes([bytes[6], bytes[7]])
    }

    /// Peer close must stay visible to `poll`, including unread data.
    #[test]
    fn poll_after_peer_close_reports_rdhup() {
        let arch = Arch::X86_64;
        let listen = sin([127, 0, 0, 1], 19000);
        let poll_at = SCRATCH + 0x200;
        let buf = SCRATCH + 0x300;
        // POLLIN|POLLOUT|POLLRDHUP
        let asked = 1u16 | 4 | 0x2000;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Listen, &[3, 4]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[4, SCRATCH, 16]),
            sc(arch, Sysno::Accept, &[3, 0, 0]),
            sc(arch, Sysno::Sendto, &[4, SCRATCH + 0x100, 2, 0, 0, 0]),
            sc(arch, Sysno::Shutdown, &[4, 1]),
            sc(arch, Sysno::Poll, &[poll_at, 1, 0]),
            sc(arch, Sysno::Recvfrom, &[5, buf, 8, 0, 0, 0]),
            sc(arch, Sysno::Close, &[4]),
            sc(arch, Sysno::Poll, &[poll_at + 16, 1, 0]),
            // First write after the clean close is accepted; the second is EPIPE.
            sc(arch, Sysno::Sendto, &[5, buf, 1, 0x4000, 0, 0]),
            sc(arch, Sysno::Sendto, &[5, buf, 1, 0x4000, 0, 0]),
            // connect again on the accepted socket must not start a new connection.
            sc(arch, Sysno::Connect, &[5, SCRATCH, 16]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let owned = [
            (SCRATCH, listen.to_vec()),
            (SCRATCH + 0x100, b"hi".to_vec()),
            (poll_at, poll_memory(5, asked).to_vec()),
            (poll_at + 16, poll_memory(5, asked).to_vec()),
        ];
        let refs: Vec<(u64, &[u8])> = owned.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let (mut kernel, mut plat) = setup(arch, traps, &refs);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[8], 1, "poll after FIN {got:?}");
        assert_eq!(
            revents_of(&plat.mem(INIT).peek(poll_at, 8)),
            0x2005,
            "FIN is POLLIN|POLLOUT|POLLRDHUP, not POLLHUP"
        );
        assert_eq!(got[9], 2, "unread FIN data {got:?}");
        assert_eq!(got[11], 1, "poll after clean close {got:?}");
        assert_ne!(
            revents_of(&plat.mem(INIT).peek(poll_at + 16, 8)) & 0x2001,
            0,
            "peer close must not look like a fresh socket"
        );
        assert_eq!(got[12], 1, "first write after clean close {got:?}");
        assert_eq!(got[13], -EPIPE, "second write {got:?}");
        assert_eq!(got[14], -crate::errno::EISCONN, "reconnect {got:?}");
    }

    #[test]
    fn reset_recv_is_econnreset_and_fresh_socket_polls_out_hup() {
        let arch = Arch::X86_64;
        let listen = sin([127, 0, 0, 1], 19002);
        let closed = sin([127, 0, 0, 1], 1);
        let opt = SCRATCH + 0x220;
        let optlen = SCRATCH + 0x230;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Listen, &[3, 4]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[4, SCRATCH, 16]),
            sc(arch, Sysno::Accept, &[3, 0, 0]),
            // Server writes bytes the client never reads, then the client closes: RST.
            sc(arch, Sysno::Sendto, &[5, SCRATCH + 0x100, 6, 0, 0, 0]),
            sc(arch, Sysno::Close, &[4]),
            sc(arch, Sysno::Recvfrom, &[5, SCRATCH + 0x180, 8, 0x40, 0, 0]),
            sc(arch, Sysno::Sendto, &[5, SCRATCH + 0x100, 1, 0x4000, 0, 0]),
            // fd 4 was closed, so the next socket reuses it.
            sc(arch, Sysno::Socket, &[2, 1 | 0o4000, 0]),
            sc(arch, Sysno::Connect, &[4, SCRATCH + 0x40, 16]),
            sc(arch, Sysno::Connect, &[4, SCRATCH + 0x40, 16]),
            sc(arch, Sysno::Connect, &[4, SCRATCH + 0x40, 16]),
            // Blocking refuse leaves SO_ERROR at 0.
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[6, SCRATCH + 0x40, 16]),
            sc(arch, Sysno::Getsockopt, &[6, 1, 4, opt, optlen]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let owned = [
            (SCRATCH, listen.to_vec()),
            (SCRATCH + 0x40, closed.to_vec()),
            (SCRATCH + 0x100, b"UNREAD".to_vec()),
            (optlen, 4u32.to_le_bytes().to_vec()),
        ];
        let refs: Vec<(u64, &[u8])> = owned.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let (mut kernel, mut plat) = setup(arch, traps, &refs);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[8], -ECONNRESET, "reset recv {got:?}");
        assert_eq!(got[9], -EPIPE, "reset write {got:?}");
        assert_eq!(got[11], -EINPROGRESS, "nb refuse {got:?}");
        assert_eq!(
            got[12], -ECONNREFUSED,
            "second connect returns SO_ERROR {got:?}"
        );
        assert_eq!(got[13], -EINPROGRESS, "third connect retries {got:?}");
        assert_eq!(got[15], -ECONNREFUSED, "blocking refuse {got:?}");
        assert_eq!(got[16], 0, "getsockopt {got:?}");
        assert_eq!(plat.mem(INIT).peek(opt, 4), 0u32.to_le_bytes());
    }

    #[test]
    fn fresh_and_refused_poll_masks() {
        let arch = Arch::X86_64;
        let closed = sin([127, 0, 0, 1], 1);
        let poll_at = SCRATCH + 0x200;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Poll, &[poll_at, 1, 0]),
            sc(arch, Sysno::Socket, &[2, 1 | 0o4000, 0]),
            sc(arch, Sysno::Connect, &[4, SCRATCH, 16]),
            sc(arch, Sysno::Poll, &[poll_at + 16, 1, 0]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let owned = [(SCRATCH, closed.to_vec())];
        let refs: Vec<(u64, &[u8])> = owned.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let (mut kernel, mut plat) = setup(arch, traps, &refs);
        plat.mem(INIT).poke(poll_at, &poll_memory(3, 1 | 4));
        plat.mem(INIT).poke(poll_at + 16, &poll_memory(4, 1 | 4));
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        assert_eq!(
            revents_of(&plat.mem(INIT).peek(poll_at, 8)),
            0x14,
            "fresh TCP socket"
        );
        assert_eq!(
            revents_of(&plat.mem(INIT).peek(poll_at + 16, 8)),
            0x1d,
            "refused non-blocking connect"
        );
    }

    #[test]
    fn msg_peek_dontwait_and_shut_rd() {
        let arch = Arch::X86_64;
        let listen = sin([127, 0, 0, 1], 19003);
        let buf = SCRATCH + 0x300;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Listen, &[3, 1]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[4, SCRATCH, 16]),
            sc(arch, Sysno::Accept, &[3, 0, 0]),
            sc(arch, Sysno::Sendto, &[4, SCRATCH + 0x100, 2, 0, 0, 0]),
            sc(arch, Sysno::Recvfrom, &[5, buf, 8, 2, 0, 0]),
            sc(arch, Sysno::Recvfrom, &[5, buf + 8, 8, 0, 0, 0]),
            sc(arch, Sysno::Recvfrom, &[5, buf, 8, 0x40, 0, 0]),
            sc(arch, Sysno::Shutdown, &[5, 0]),
            sc(arch, Sysno::Recvfrom, &[5, buf, 8, 0, 0, 0]),
            // UDP SHUT_WR honours MSG_NOSIGNAL (no signal, still EPIPE).
            sc(arch, Sysno::Socket, &[2, 2, 0]),
            sc(arch, Sysno::Shutdown, &[6, 1]),
            sc(arch, Sysno::Sendto, &[6, buf, 1, 0x4000, SCRATCH, 16]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let owned = [
            (SCRATCH, listen.to_vec()),
            (SCRATCH + 0x100, b"ab".to_vec()),
        ];
        let refs: Vec<(u64, &[u8])> = owned.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let (mut kernel, mut plat) = setup(arch, traps, &refs);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[7], 2, "peek {got:?}");
        assert_eq!(plat.mem(INIT).peek(buf, 2), b"ab");
        assert_eq!(got[8], 2, "recv after peek {got:?}");
        assert_eq!(plat.mem(INIT).peek(buf + 8, 2), b"ab");
        assert_eq!(got[9], -EAGAIN, "dontwait {got:?}");
        assert_eq!(got[11], 0, "shut_rd {got:?}");
        assert_eq!(got[14], -EPIPE, "udp shut_wr {got:?}");
    }

    #[test]
    fn bind_wildcard_conflicts_with_a_specific_address() {
        let arch = Arch::X86_64;
        let wild = sin([0, 0, 0, 0], 19010);
        let spec = sin([127, 0, 0, 1], 19010);
        let spec2 = sin([127, 0, 0, 1], 19011);
        let wild2 = sin([0, 0, 0, 0], 19011);
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[4, SCRATCH + 0x20, 16]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[5, SCRATCH + 0x40, 16]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[6, SCRATCH + 0x60, 16]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let owned = [
            (SCRATCH, wild.to_vec()),
            (SCRATCH + 0x20, spec.to_vec()),
            (SCRATCH + 0x40, spec2.to_vec()),
            (SCRATCH + 0x60, wild2.to_vec()),
        ];
        let refs: Vec<(u64, &[u8])> = owned.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let (mut kernel, mut plat) = setup(arch, traps, &refs);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[1], 0, "wildcard bind {got:?}");
        assert_eq!(got[3], -EADDRINUSE, "specific after wildcard {got:?}");
        assert_eq!(got[5], 0, "specific bind {got:?}");
        assert_eq!(got[7], -EADDRINUSE, "wildcard after specific {got:?}");
    }

    #[test]
    fn host_peer_close_half_close_and_failed_connect() {
        let arch = Arch::X86_64;
        // Break writes: EPIPE, and MSG_NOSIGNAL so the process continues.
        let mut host = host_with_prog(arch);
        host.splice = true;
        host.splice_break_writes = true;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Sendto, &[3, SCRATCH + 0x40, 1, 0x4000, 0, 0]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let mut plat = MockPlatform::with_scripts(arch, &host, vec![traps.clone()]);
        let mut kernel = Kernel::new(host).with_trace();
        kernel
            .exec(&mut plat, b"/bin/prog", &[b"prog".to_vec()], &[])
            .unwrap();
        plat.mem(INIT).poke(SCRATCH, &[0; 0x200]);
        let ip = kernel.issue_fake_ip().unwrap();
        plat.mem(INIT).poke(SCRATCH, &sin(ip, 443));
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        assert_eq!(returns(&plat, INIT)[2], -EPIPE, "host write failure");

        // Peer half-close: recv is EOF, a later write still works.
        let mut host = host_with_prog(arch);
        host.splice = true;
        host.splice_peer_fin = true;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Recvfrom, &[3, SCRATCH + 0x80, 4, 0, 0, 0]),
            sc(arch, Sysno::Sendto, &[3, SCRATCH + 0x40, 2, 0, 0, 0]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let mut plat = MockPlatform::with_scripts(arch, &host, vec![traps]);
        let mut kernel = Kernel::new(host);
        kernel
            .exec(&mut plat, b"/bin/prog", &[b"prog".to_vec()], &[])
            .unwrap();
        plat.mem(INIT).poke(SCRATCH, &[0; 0x200]);
        let ip = kernel.issue_fake_ip().unwrap();
        plat.mem(INIT).poke(SCRATCH, &sin(ip, 443));
        plat.mem(INIT).poke(SCRATCH + 0x40, b"ok");
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[2], 0, "host FIN is EOF {got:?}");
        assert_eq!(got[3], 2, "write after host FIN {got:?}");

        // The connect itself fails.
        let mut host = host_with_prog(arch);
        host.splice = true;
        host.splice_fail_connect = true;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Socket, &[2, 1 | 0o4000, 0]),
            sc(arch, Sysno::Connect, &[4, SCRATCH, 16]),
            sc(arch, Sysno::Poll, &[SCRATCH + 0x100, 1, 0]),
            sc(
                arch,
                Sysno::Getsockopt,
                &[4, 1, 4, SCRATCH + 0x120, SCRATCH + 0x130],
            ),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let mut plat = MockPlatform::with_scripts(arch, &host, vec![traps]);
        let mut kernel = Kernel::new(host);
        kernel
            .exec(&mut plat, b"/bin/prog", &[b"prog".to_vec()], &[])
            .unwrap();
        plat.mem(INIT).poke(SCRATCH, &[0; 0x200]);
        let ip = kernel.issue_fake_ip().unwrap();
        plat.mem(INIT).poke(SCRATCH, &sin(ip, 443));
        plat.mem(INIT).poke(SCRATCH + 0x100, &poll_memory(4, 4));
        plat.mem(INIT).poke(SCRATCH + 0x130, &4u32.to_le_bytes());
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[1], -ECONNREFUSED, "blocking failed splice {got:?}");
        assert_eq!(got[3], -EINPROGRESS, "nonblock failed splice {got:?}");
        assert_eq!(got[4], 1, "poll {got:?}");
        assert_eq!(revents_of(&plat.mem(INIT).peek(SCRATCH + 0x100, 8)) & 4, 4);
        assert_eq!(
            i32::from_le_bytes(plat.mem(INIT).peek(SCRATCH + 0x120, 4).try_into().unwrap()),
            ECONNREFUSED as i32
        );
    }

    #[test]
    fn nonblocking_splice_connect_then_pollout_and_so_error() {
        let arch = Arch::X86_64;
        let mut host = host_with_prog(arch);
        host.splice = true;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1 | 0o4000, 0]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Poll, &[SCRATCH + 0x100, 1, 0]),
            sc(
                arch,
                Sysno::Getsockopt,
                &[3, 1, 4, SCRATCH + 0x120, SCRATCH + 0x130],
            ),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let mut plat = MockPlatform::with_scripts(arch, &host, vec![traps]);
        let mut kernel = Kernel::new(host);
        kernel
            .exec(&mut plat, b"/bin/prog", &[b"prog".to_vec()], &[])
            .unwrap();
        plat.mem(INIT).poke(SCRATCH, &[0; 0x200]);
        let ip = kernel.issue_fake_ip().unwrap();
        plat.mem(INIT).poke(SCRATCH, &sin(ip, 443));
        plat.mem(INIT).poke(SCRATCH + 0x100, &poll_memory(3, 4));
        plat.mem(INIT).poke(SCRATCH + 0x130, &4u32.to_le_bytes());
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[1], -EINPROGRESS, "{got:?}");
        assert_eq!(got[2], 1, "{got:?}");
        assert_ne!(revents_of(&plat.mem(INIT).peek(SCRATCH + 0x100, 8)) & 4, 0);
        assert_eq!(plat.mem(INIT).peek(SCRATCH + 0x120, 4), 0u32.to_le_bytes());
    }

    /// Closing the accepted socket must not leave its slot id on the peer.
    /// The next socket reuses that slot and must not see the old connection's bytes.
    #[test]
    fn clean_close_does_not_leak_into_a_reused_slot() {
        let arch = Arch::X86_64;
        let listen = sin([127, 0, 0, 1], 19030);
        let buf = SCRATCH + 0x180;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Listen, &[3, 4]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[4, SCRATCH, 16]),
            sc(arch, Sysno::Accept, &[3, 0, 0]),
            sc(arch, Sysno::Close, &[5]),
            // fd 5 and the accepted socket's slot are both free.
            sc(arch, Sysno::Socket, &[2, 1 | 0o4000, 0]),
            sc(arch, Sysno::Connect, &[5, SCRATCH, 16]),
            sc(arch, Sysno::Accept, &[3, 0, 0]),
            sc(arch, Sysno::Sendto, &[4, SCRATCH + 0x100, 5, 0, 0, 0]),
            sc(arch, Sysno::Sendto, &[4, SCRATCH + 0x100, 5, 0x4000, 0, 0]),
            sc(arch, Sysno::Recvfrom, &[5, buf, 8, 0x40, 0, 0]),
            sc(arch, Sysno::Close, &[4]),
            sc(arch, Sysno::Recvfrom, &[5, buf, 8, 0x40, 0, 0]),
            sc(arch, Sysno::Sendto, &[5, SCRATCH + 0x120, 2, 0, 0, 0]),
            sc(arch, Sysno::Recvfrom, &[6, buf + 8, 8, 0, 0, 0]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let owned = [
            (SCRATCH, listen.to_vec()),
            (SCRATCH + 0x100, b"LEAK1".to_vec()),
            (SCRATCH + 0x120, b"hi".to_vec()),
            (buf, b"ZZZZZZZZ".to_vec()),
        ];
        let refs: Vec<(u64, &[u8])> = owned.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let (mut kernel, mut plat) = setup(arch, traps, &refs);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[10], 5, "first write after clean close {got:?}");
        assert_eq!(got[11], -EPIPE, "second write {got:?}");
        assert_eq!(got[12], -EAGAIN, "reused socket must not see LEAK {got:?}");
        assert_eq!(plat.mem(INIT).peek(buf, 5), b"ZZZZZ");
        assert_eq!(got[14], -EAGAIN, "close of the old peer is not EOF {got:?}");
        assert_eq!(got[15], 2, "new connection send {got:?}");
        assert_eq!(got[16], 2, "new connection recv {got:?}");
        assert_eq!(plat.mem(INIT).peek(buf + 8, 2), b"hi");
    }

    /// After `SO_ERROR` is read, one `connect` is `ECONNABORTED` and the next retries.
    #[test]
    fn connect_retries_against_a_listener_started_after_the_failure() {
        let arch = Arch::X86_64;
        let dead = sin([127, 0, 0, 1], 1);
        let live = sin([127, 0, 0, 1], 19031);
        let opt = SCRATCH + 0x200;
        let optlen = SCRATCH + 0x210;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1 | 0o4000, 0]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Getsockopt, &[3, 1, 4, opt, optlen]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Bind, &[4, SCRATCH + 0x20, 16]),
            sc(arch, Sysno::Listen, &[4, 4]),
            sc(arch, Sysno::Connect, &[3, SCRATCH + 0x20, 16]),
            sc(arch, Sysno::Getsockopt, &[3, 1, 4, opt + 4, optlen]),
            sc(arch, Sysno::Accept, &[4, 0, 0]),
            sc(arch, Sysno::Sendto, &[3, SCRATCH + 0x80, 2, 0, 0, 0]),
            sc(arch, Sysno::Recvfrom, &[5, SCRATCH + 0x90, 8, 0, 0, 0]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let owned = [
            (SCRATCH, dead.to_vec()),
            (SCRATCH + 0x20, live.to_vec()),
            (SCRATCH + 0x80, b"ok".to_vec()),
            (optlen, 4u32.to_le_bytes().to_vec()),
        ];
        let refs: Vec<(u64, &[u8])> = owned.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let (mut kernel, mut plat) = setup(arch, traps, &refs);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[1], -EINPROGRESS, "first refuse {got:?}");
        assert_eq!(got[2], 0, "getsockopt {got:?}");
        assert_eq!(
            i32::from_le_bytes(plat.mem(INIT).peek(opt, 4).try_into().unwrap()),
            ECONNREFUSED as i32
        );
        assert_eq!(got[3], -ECONNABORTED, "one-shot abort {got:?}");
        assert_eq!(got[7], -EINPROGRESS, "retry reaches the listener {got:?}");
        assert_eq!(plat.mem(INIT).peek(opt + 4, 4), 0u32.to_le_bytes());
        assert_eq!(got[10], 2, "send on the retried socket {got:?}");
        assert_eq!(got[11], 2, "accept side {got:?}");
        assert_eq!(plat.mem(INIT).peek(SCRATCH + 0x90, 2), b"ok");
    }

    #[test]
    fn blocking_host_connect_failure_is_one_shot() {
        let arch = Arch::X86_64;
        let mut host = host_with_prog(arch);
        host.splice = true;
        host.splice_fail_connect = true;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let mut plat = MockPlatform::with_scripts(arch, &host, vec![traps]);
        let mut kernel = Kernel::new(host);
        kernel
            .exec(&mut plat, b"/bin/prog", &[b"prog".to_vec()], &[])
            .unwrap();
        plat.mem(INIT).poke(SCRATCH, &[0; 0x40]);
        let ip = kernel.issue_fake_ip().unwrap();
        plat.mem(INIT).poke(SCRATCH, &sin(ip, 443));
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[1], -ECONNREFUSED, "blocking failure {got:?}");
        assert_eq!(got[2], -ECONNABORTED, "one-shot {got:?}");
        assert_eq!(got[3], -ECONNREFUSED, "the next call retries {got:?}");
    }

    #[test]
    fn dns_tcp_poll_stops_when_the_buffer_is_full() {
        let arch = Arch::X86_64;
        let dns = sin([192, 0, 2, 1], 53);
        let poll_at = SCRATCH + 0x40;
        let traps = vec![
            sc(arch, Sysno::Socket, &[2, 1, 0]),
            sc(arch, Sysno::Connect, &[3, SCRATCH, 16]),
            sc(
                arch,
                Sysno::Sendto,
                &[3, SCRATCH + 0x80, 16 * 1024, 0, 0, 0],
            ),
            sc(arch, Sysno::Poll, &[poll_at, 1, 0]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let mut payload = vec![0xffu8; 16 * 1024];
        payload[0] = 0xff;
        payload[1] = 0xff;
        let owned = [(SCRATCH, dns.to_vec()), (SCRATCH + 0x80, payload)];
        let refs: Vec<(u64, &[u8])> = owned.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let (mut kernel, mut plat) = setup(arch, traps, &refs);
        plat.mem(INIT).poke(poll_at, &poll_memory(3, 4));
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(0));
        let got = returns(&plat, INIT);
        assert_eq!(got[2], 16 * 1024, "dns send {got:?}");
        assert_eq!(got[3], 0, "poll {got:?}");
        assert_eq!(revents_of(&plat.mem(INIT).peek(poll_at, 8)) & 4, 0);
    }

    fn action(handler: u64, flags: u64, restorer: u64) -> Vec<u8> {
        let mut action = Vec::new();
        for v in [handler, flags, restorer, 0] {
            action.extend_from_slice(&v.to_le_bytes());
        }
        action
    }

    #[test]
    fn handlers_run_on_a_frame_and_return_through_sigreturn() {
        let arch = Arch::Aarch64;
        let act = SCRATCH + 0x100;
        let handler = 0x40_1100u64;
        let traps = vec![
            sc(arch, Sysno::RtSigaction, &[SIGUSR1 as u64, act, 0, 8]),
            // The signal is posted by kill and handled before kill returns.
            sc(arch, Sysno::Kill, &[1, SIGUSR1 as u64]),
            // In the handler: SIGUSR1 is blocked.
            sc(arch, Sysno::RtSigprocmask, &[0, 0, SCRATCH, 8]),
            sc(arch, Sysno::RtSigreturn, &[]),
            // Back: the mask is restored.
            sc(arch, Sysno::RtSigprocmask, &[0, 0, SCRATCH + 8, 8]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let (mut kernel, mut plat) = setup(
            arch,
            traps,
            &[(act, &action(handler, SA_SIGINFO | SA_RESTORER, 0x40_1200))],
        );
        if let Context::Aarch64(c) = &mut plat.tasks.get_mut(&INIT).unwrap().context {
            c.x[19] = 0x1919;
        }
        kernel.run(&mut plat).unwrap();
        assert_eq!(returns(&plat, INIT), vec![0, 0, 0]);
        let mem = plat.mem(INIT);
        assert_eq!(mem.peek(SCRATCH, 8), (1u64 << (SIGUSR1 - 1)).to_le_bytes());
        assert_eq!(mem.peek(SCRATCH + 8, 8), 0u64.to_le_bytes());
        let task = plat.task(INIT);
        // Resumed twice with a new context: into the handler, then back.
        let [Context::Aarch64(into), Context::Aarch64(back)] = &task.continued[..] else {
            panic!("{:?}", task.continued)
        };
        assert_eq!(into.pc, handler);
        assert_eq!(into.x[0], SIGUSR1 as u64);
        assert_eq!(into.x[30], 0x40_1200, "SA_RESTORER is the return address");
        assert_eq!(into.sp % 16, 0);
        assert_eq!(back.pc, 0x40_1000, "back where kill was made");
        assert_eq!(back.x[0], 0, "with kill's return value");
        assert_eq!(back.x[19], 0x1919, "registers survive the handler");
    }

    #[test]
    fn interrupted_syscalls_fail_with_eintr_or_restart() {
        let arch = Arch::Aarch64;
        for (flags, restarted) in [
            (SA_RESTORER, false),
            (SA_RESTORER | crate::signal::SA_RESTART, true),
        ] {
            let act = SCRATCH + 0x100;
            let parent = vec![
                sc(arch, Sysno::RtSigaction, &[SIGUSR1 as u64, act, 0, 8]),
                sc(arch, Sysno::Pipe2, &[SCRATCH, 0]),
                sc(arch, Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0]),
                // Parks: nothing is written to the pipe. The child's signal
                // interrupts it.
                sc(arch, Sysno::Read, &[3, SCRATCH + 0x200, 10]),
                sc(arch, Sysno::RtSigreturn, &[]),
                sc(arch, Sysno::ExitGroup, &[0]),
            ];
            let child = vec![
                sc(arch, Sysno::Kill, &[1, SIGUSR1 as u64]),
                sc(arch, Sysno::ExitGroup, &[0]),
            ];
            let (mut kernel, mut plat) = setup_scripts(
                arch,
                vec![parent, child],
                &[(act, &action(0x40_1100, flags, 0x40_1200))],
            );
            kernel.run(&mut plat).unwrap();
            let task = plat.task(INIT);
            let Context::Aarch64(back) = task.continued.last().unwrap() else {
                panic!()
            };
            if restarted {
                // Back at the svc instruction with read's arguments.
                assert_eq!(back.pc, 0x40_1000 - 4);
                assert_eq!((back.x[0], back.x[8]), (3, 63));
            } else {
                assert_eq!(back.pc, 0x40_1000);
                assert_eq!(back.x[0] as i64, -EINTR);
            }
        }
    }

    #[test]
    fn threads_wait_and_wake_on_futexes() {
        let arch = Arch::Aarch64;
        let word = SCRATCH + 0x40;
        // VM FS FILES SIGHAND THREAD CHILD_CLEARTID CHILD_SETTID
        let flags = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x20_0000 | 0x100_0000;
        let main = vec![
            sc(arch, Sysno::Clone, &[flags, SCRATCH + 0x1000, 0, 0, word]),
            // The child set *word = its tid; wait while it is 2.
            sc(arch, Sysno::Futex, &[word, 0, 2, 0, 0, 0]),
            sc(arch, Sysno::Gettid, &[]),
            sc(arch, Sysno::ExitGroup, &[5]),
        ];
        let thread = vec![
            sc(arch, Sysno::Getpid, &[]),
            sc(arch, Sysno::Gettid, &[]),
            // Thread exit clears *word and wakes the futex.
            sc(arch, Sysno::Exit, &[0]),
        ];
        let (mut kernel, mut plat) = setup_scripts(arch, vec![main, thread], &[]);
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(5));
        assert_eq!(returns(&plat, INIT), vec![2, 0, 1]);
        assert_eq!(plat.task(2).returns, vec![1, 2]);
        assert_eq!(plat.mem(INIT).peek(word, 4), 0u32.to_le_bytes());
        let Context::Aarch64(c) = &plat.task(2).continued[0] else {
            panic!()
        };
        assert_eq!(c.sp, SCRATCH + 0x1000, "the thread runs on its own stack");
    }

    #[test]
    fn a_thread_that_execs_becomes_the_process() {
        let arch = Arch::Aarch64;
        let path = SCRATCH + 0x10;
        let argv = SCRATCH + 0x40;
        let thread_flags = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000; // VM FS FILES SIGHAND THREAD
        let main = vec![
            sc(
                arch,
                Sysno::Clone,
                &[thread_flags, SCRATCH + 0x1000, 0, 0, 0],
            ),
            // Parks forever; the exec ends this thread.
            sc(arch, Sysno::Futex, &[SCRATCH + 0x80, 0, 0, 0, 0, 0]),
        ];
        let thread = vec![sc(arch, Sysno::Execve, &[path, argv, 0])];
        let program = vec![
            sc(arch, Sysno::Getpid, &[]),
            sc(arch, Sysno::Gettid, &[]),
            sc(arch, Sysno::ExitGroup, &[9]),
        ];
        let mut argv_bytes = Vec::new();
        argv_bytes.extend_from_slice(&path.to_le_bytes());
        argv_bytes.extend_from_slice(&0u64.to_le_bytes());
        let (mut kernel, mut plat) = setup_scripts(
            arch,
            vec![main, thread, program],
            &[(path, b"/bin/prog\0"), (argv, &argv_bytes)],
        );
        assert_eq!(kernel.run(&mut plat).unwrap(), ExitStatus::Exited(9));
        assert!(plat.task(INIT).killed && plat.task(2).killed);
        assert_eq!(plat.task(3).returns, vec![1, 1]);
        assert!(plat.task(3).started.is_some());
    }

    #[test]
    fn proc_is_generated_from_the_process_table() {
        let arch = Arch::Aarch64;
        let at_fdcwd = (-100i64) as u64;
        let buf = SCRATCH + 0x1000;
        let traps = vec![
            sc(arch, Sysno::Readlinkat, &[at_fdcwd, SCRATCH, buf, 64]),
            // Relative to /proc/self, through "..".
            sc(arch, Sysno::Chdir, &[SCRATCH + 0x100]),
            sc(arch, Sysno::Openat, &[at_fdcwd, SCRATCH + 0x200, 0, 0]),
            sc(arch, Sysno::Read, &[3, buf + 0x100, 200]),
            sc(arch, Sysno::Openat, &[at_fdcwd, SCRATCH + 0x300, 0, 0]),
            sc(arch, Sysno::Getdents64, &[4, buf + 0x400, 0x400]),
            // Writing is refused.
            sc(arch, Sysno::Openat, &[at_fdcwd, SCRATCH + 0x200, 1, 0]),
            sc(arch, Sysno::ExitGroup, &[0]),
        ];
        let (mut kernel, mut plat) = setup(
            arch,
            traps,
            &[
                (SCRATCH, b"/proc/self/exe\0"),
                (SCRATCH + 0x100, b"/tmp\0"),
                (SCRATCH + 0x200, b"../proc/1/stat\0"),
                (SCRATCH + 0x300, b"/proc/self/fd\0"),
            ],
        );
        kernel.run(&mut plat).unwrap();
        let r = returns(&plat, INIT);
        assert_eq!(r[0], 9);
        let mem = plat.mem(INIT);
        assert_eq!(mem.peek(buf, 9), b"/bin/prog");
        assert_eq!(r[1..3], [0, 3]);
        let stat = mem.peek(buf + 0x100, r[3] as usize);
        assert!(
            stat.starts_with(b"1 (prog) R 0 1 1 "),
            "{}",
            String::from_utf8_lossy(&stat)
        );
        assert_eq!(r[4], 4);
        // ".", "..", and fds 0..=4.
        let listing = mem.peek(buf + 0x400, r[5] as usize);
        let names: Vec<_> = listing
            .windows(2)
            .filter(|w| w[1] == 0 && w[0].is_ascii_digit())
            .map(|w| w[0] - b'0')
            .collect();
        assert_eq!(names, [0, 1, 2, 3, 4]);
        assert_eq!(r[6], -crate::errno::EACCES);
    }

    #[test]
    fn the_terminal_cooks_input_and_raises_signals() {
        let arch = Arch::Aarch64;
        let buf = SCRATCH + 0x100;
        let mut noflsh = crate::tty::Termios::default();
        noflsh.lflag |= crate::tty::NOFLSH;
        let traps = vec![
            sc(arch, Sysno::Ioctl, &[0, 0x5401, buf]), // TCGETS: a terminal
            sc(arch, Sysno::Ioctl, &[0, 0x5402, buf + 0x200]), // TCSETS
            sc(arch, Sysno::Ioctl, &[1, 0x540f, buf + 0x40]), // TIOCGPGRP
            // Gets the line; the ^C after it raises SIGINT for the
            // foreground group, which ends this process before the read
            // returns.
            sc(arch, Sysno::Read, &[0, buf + 0x80, 100]),
        ];
        let host = host_with_prog(arch);
        let mut plat = MockPlatform::with_scripts(arch, &host, vec![traps]);
        let mut kernel = Kernel::new(host)
            .with_trace()
            .with_console(ConsoleMode::Terminal);
        kernel
            .exec(&mut plat, b"/bin/prog", &[b"prog".to_vec()], &[])
            .unwrap();
        plat.mem(INIT).poke(SCRATCH, &[0; 0x1000]);
        plat.mem(INIT).poke(buf + 0x200, &noflsh.encode());
        kernel.host_mut().stdin.extend(b"hi\r\x03");
        kernel.host_mut().stdin_open = true;
        assert_eq!(
            kernel.run(&mut plat).unwrap(),
            ExitStatus::Signaled(crate::signal::SIGINT)
        );
        assert_eq!(returns(&plat, INIT), vec![0, 0, 0]);
        let mem = plat.mem(INIT);
        assert_eq!(mem.peek(buf, 36), crate::tty::Termios::default().encode());
        assert_eq!(mem.peek(buf + 0x40, 4), 1u32.to_le_bytes());
        assert_eq!(mem.peek(buf + 0x80, 3), b"hi\n");
        let last = kernel.trace().last().unwrap();
        assert_eq!(last.outcome, Outcome::Returned(3));
        // The echo: the line (CR echoed as CR NL) and ^C.
        assert_eq!(kernel.host().stdout, b"hi\r\n^C");
    }

    #[test]
    fn hostile_arguments_fail_cleanly() {
        let arch = Arch::Aarch64;
        let mut huge = Vec::new();
        huge.extend_from_slice(&i64::MAX.to_le_bytes());
        huge.extend_from_slice(&999_999_999i64.to_le_bytes());
        let mut itimer = Vec::new();
        for v in [i64::MAX, 999_999, i64::MAX, 999_999] {
            itimer.extend_from_slice(&v.to_le_bytes());
        }
        let parent = vec![
            // A timer and a deadline in the far future.
            sc(arch, Sysno::Setitimer, &[0, SCRATCH + 0x100, 0]),
            sc(arch, Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0]),
            sc(arch, Sysno::Ppoll, &[0, 0, SCRATCH, 0, 8]),
        ];
        let child = vec![
            // Unknown clone flags, a bad exit signal, a bad futex address.
            sc(arch, Sysno::Clone, &[0x4000_0000_0000 | 17, 0, 0, 0, 0]),
            sc(arch, Sysno::Clone, &[200, 0, 0, 0, 0]),
            sc(arch, Sysno::Futex, &[SCRATCH + 1, 0, 0, 0, 0, 0]),
            sc(arch, Sysno::Futex, &[0x10_0000_0000, 0, 0, 0, 0, 0]),
            // Signal numbers out of range.
            sc(arch, Sysno::Kill, &[1, 65]),
            sc(arch, Sysno::RtSigaction, &[0, 0, 0, 8]),
            // An execve with argv pointing nowhere.
            sc(arch, Sysno::Execve, &[SCRATCH + 0x200, 0x10_0000_0000, 0]),
            // A bad rt_sigreturn frame kills the process with SIGSEGV.
            sc(arch, Sysno::RtSigreturn, &[]),
        ];
        let (mut kernel, mut plat) = setup_scripts(
            arch,
            vec![parent, child],
            &[
                (SCRATCH, &huge),
                (SCRATCH + 0x100, &itimer),
                (SCRATCH + 0x200, b"/bin/prog\0"),
            ],
        );
        // The child's sp is 0, so rt_sigreturn's frame is unreadable: it
        // dies of SIGSEGV. The parent waits until the mock clock reaches
        // the far deadlines (no overflow), and the timer's SIGALRM ends it.
        assert_eq!(
            kernel.run(&mut plat).unwrap(),
            ExitStatus::Signaled(crate::signal::SIGALRM)
        );
        assert_eq!(
            plat.task(2).returns,
            vec![
                -crate::errno::EINVAL,
                -crate::errno::EINVAL,
                -crate::errno::EINVAL,
                -EFAULT,
                -crate::errno::EINVAL,
                -crate::errno::EINVAL,
                -EFAULT,
            ]
        );
    }
}
