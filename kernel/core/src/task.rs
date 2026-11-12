//! Processes and threads: the sandbox's task state.
//!
//! A *process* (thread group) owns an fd table, a current directory, signal
//! dispositions and an address space; a *thread* has a register context
//! (one platform task), a signal mask, pending thread-directed signals and
//! an alternate signal stack. Processes that share an address space without
//! being one thread group (`vfork`, `clone(CLONE_VM)`) point at the same
//! [`Mm`] entry. Guest pids and tids are the kernel's own numbers; the
//! platform's task keys never reach the guest.
//!
//! Everything here is plain data plus the rules that need no platform
//! access: pid allocation, signal posting and selection, process-group
//! queries. The kernel loop (`kernel.rs`) drives the platform.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use crate::arch::Sysno;
use crate::fd::{FdTable, Files};
use crate::kernel::ExitStatus;
use crate::mm::Mm;
use crate::pipe::Pipes;
use crate::platform::{GuestAddr, Resume, SyscallTrap, TaskKey};
use crate::signal::{
    self, bit, AltStack, DefaultAction, SigAction, SigInfo, SigQueue, SIGCHLD, SIGCONT, SIGKILL,
    SIGSTOP, SIG_DFL, SIG_IGN, UNBLOCKABLE,
};
use crate::tty::Console;
use crate::vfs::Ino;

pub type Pid = u32;
pub type Tid = u32;
pub(crate) type MmId = usize;

/// Largest pid; pids wrap around below it.
pub const PID_MAX: Pid = 32768;
/// Most threads (of all processes, zombies included) in one sandbox.
pub const MAX_TASKS: usize = 1024;

/// Most bytes of generated `/proc` file contents all open files of a
/// sandbox hold together (each open keeps a snapshot); opens beyond it fail
/// with `ENOMEM`.
pub const MAX_PROC_BYTES: usize = 16 << 20;

/// Default and maximum of a resource limit.
pub(crate) type Rlimit = (u64, u64);

pub(crate) const RLIM_INFINITY: u64 = u64::MAX;

pub(crate) fn default_rlimits() -> [Rlimit; 16] {
    let mut rlimits = [(RLIM_INFINITY, RLIM_INFINITY); 16];
    rlimits[3] = (crate::mm::STACK_SIZE, RLIM_INFINITY); // RLIMIT_STACK
    rlimits[4] = (0, RLIM_INFINITY); // RLIMIT_CORE
    rlimits[6] = (MAX_TASKS as u64, MAX_TASKS as u64); // RLIMIT_NPROC
    rlimits[7] = (crate::fd::MAX_FDS as u64, crate::fd::MAX_FDS as u64); // RLIMIT_NOFILE
    rlimits[8] = (8 << 20, 8 << 20); // RLIMIT_MEMLOCK
    rlimits
}

/// An address space as the core sees it, shared by the processes and
/// threads that use it.
#[derive(Debug)]
pub(crate) struct MmEntry {
    pub mm: Mm,
    /// Threads using it.
    pub users: u32,
    /// The sigreturn trampoline, if one is mapped (aarch64).
    pub trampoline: GuestAddr,
}

/// How a process changed state, as `wait4`/`waitid` report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildEvent {
    Stopped(u32),
    Continued,
}

/// A process's life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Life {
    Alive,
    /// Exited, not yet waited for.
    Zombie(ExitStatus),
}

/// A real-time interval timer (`ITIMER_REAL`, `alarm`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Itimer {
    /// Expiry on the monotonic clock; `None` when disarmed.
    pub deadline: Option<Duration>,
    pub interval: Duration,
}

#[derive(Debug)]
pub(crate) struct Process {
    pub pid: Pid,
    pub ppid: Pid,
    pub pgid: Pid,
    pub sid: Pid,
    /// Live threads, the first one being the leader as long as it lives.
    pub threads: Vec<Tid>,
    pub mm: Option<MmId>,
    pub fds: FdTable,
    /// Current directory; held open in the VFS so it stays alive.
    pub cwd: Ino,
    pub umask: u32,
    pub actions: [SigAction; signal::NSIG as usize],
    /// Process-directed pending signals.
    pub pending: SigQueue,
    /// `comm`, at most 15 bytes.
    pub name: Vec<u8>,
    /// The path the program was executed as (`/proc/<pid>/exe`).
    pub exe: Vec<u8>,
    /// `argv`, NUL-separated (`/proc/<pid>/cmdline`).
    pub cmdline: Vec<u8>,
    pub rlimits: [Rlimit; 16],
    pub life: Life,
    /// The signal that ended it dumps core (reported in wait statuses; no
    /// core file is written).
    pub core_dumped: bool,
    /// Stopped by a job-control signal.
    pub stopped: bool,
    /// A stop or continue not yet reported to the parent.
    pub event: Option<ChildEvent>,
    /// The thread of the parent waiting for this `vfork` child to exec or
    /// exit.
    pub vfork_parent: Option<Tid>,
    pub itimer: Itimer,
    /// Signal sent to the parent when the process ends (0 for none).
    pub exit_signal: u32,
    /// Monotonic time at creation (`/proc/<pid>/stat`).
    pub start_time: Duration,
    /// Set after `execve`, so that `setpgid` from the parent fails.
    pub execed: bool,
}

impl Process {
    pub fn new(pid: Pid, cwd: Ino, start_time: Duration) -> Process {
        Process {
            pid,
            ppid: 0,
            pgid: pid,
            sid: pid,
            threads: Vec::new(),
            mm: None,
            fds: FdTable::default(),
            cwd,
            umask: 0o022,
            actions: [SigAction::default(); signal::NSIG as usize],
            pending: SigQueue::default(),
            name: Vec::new(),
            exe: Vec::new(),
            cmdline: Vec::new(),
            rlimits: default_rlimits(),
            life: Life::Alive,
            core_dumped: false,
            stopped: false,
            event: None,
            vfork_parent: None,
            itimer: Itimer::default(),
            exit_signal: SIGCHLD,
            start_time,
            execed: false,
        }
    }

    pub fn action(&self, sig: u32) -> SigAction {
        self.actions[sig as usize - 1]
    }

    pub fn alive(&self) -> bool {
        self.life == Life::Alive
    }
}

/// How a parked syscall is restarted when a signal handler interrupts it
/// (Linux's `-ERESTARTSYS` and `-ERESTARTNOHAND`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Restart {
    /// Restarted after a handler with `SA_RESTART`, else `EINTR`.
    IfSaRestart,
    /// Always `EINTR` after a handler.
    Never,
}

/// What a parked thread waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitKind {
    /// Some condition its syscall checks: retry the syscall whenever the
    /// sandbox's state changed.
    Retry,
    /// A `futex` wake on this address of this address space.
    Futex {
        mm: MmId,
        addr: GuestAddr,
        bitset: u32,
    },
    /// Nothing the sandbox's state can provide: only its deadline or a
    /// signal handler ends the wait (`nanosleep`, `pause`). Never retried
    /// on changes.
    Sleep,
    /// The `vfork` child to exec or exit; only `SIGKILL` ends the wait
    /// early.
    Vfork(Pid),
}

/// A parked syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Parked {
    pub trap: SyscallTrap,
    pub sysno: Option<Sysno>,
    pub kind: WaitKind,
    /// When it times out (monotonic clock).
    pub deadline: Option<Duration>,
    pub restart: Restart,
    /// The deadline passed; the retry must complete the syscall.
    pub timed_out: bool,
}

/// What a stopped thread resumes with, before signal delivery is decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// Complete the syscall with this value.
    Return(i64),
    /// The syscall was interrupted by a signal: restart it or fail with
    /// `EINTR`, depending on the handler that runs.
    Interrupted(SyscallTrap, Restart),
    /// Continue with the current context.
    Continue,
    /// First run of a new program.
    Start { entry: GuestAddr, stack: GuestAddr },
}

impl Next {
    pub fn resume(self) -> Resume {
        match self {
            Next::Return(value) => Resume::Return(value),
            Next::Interrupted(..) | Next::Continue => Resume::Continue,
            Next::Start { entry, stack } => Resume::Start { entry, stack },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ThreadState {
    /// The platform is running it.
    Running,
    /// Stopped in a syscall the kernel holds.
    Parked(Parked),
    /// Stopped and about to be resumed.
    Ready(Next),
    /// Stopped because its process is stopped (job control); resumes with
    /// this when the process continues.
    Held(Next),
}

#[derive(Debug)]
pub(crate) struct Thread {
    pub tid: Tid,
    pub pid: Pid,
    pub task: TaskKey,
    pub state: ThreadState,
    pub sigmask: u64,
    /// The mask to restore after a handler interrupts `rt_sigsuspend`,
    /// `ppoll` or `pselect6` with a temporary mask.
    pub saved_mask: Option<u64>,
    pub pending: SigQueue,
    pub altstack: AltStack,
    pub clear_child_tid: GuestAddr,
    pub robust_list: (GuestAddr, u64),
    /// The platform was asked to interrupt it since it was last resumed.
    pub interrupt_sent: bool,
    /// While parked in a blocking pipe `write`: the bytes its earlier
    /// attempts already wrote.
    pub io_done: usize,
}

impl Thread {
    pub fn new(tid: Tid, pid: Pid, task: TaskKey, state: ThreadState) -> Thread {
        Thread {
            tid,
            pid,
            task,
            state,
            sigmask: 0,
            saved_mask: None,
            pending: SigQueue::default(),
            altstack: AltStack::disabled(),
            clear_child_tid: 0,
            robust_list: (0, 0),
            interrupt_sent: false,
            io_done: 0,
        }
    }

    pub fn parked(&self) -> Option<&Parked> {
        match &self.state {
            ThreadState::Parked(p) => Some(p),
            _ => None,
        }
    }
}

/// What a signal will do to a thread when it is delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    Ignore,
    Handler(SigAction),
    Kill { core: bool },
    Stop,
    Continue,
}

/// Address spaces, by id.
#[derive(Debug, Default)]
pub(crate) struct Mms {
    slots: Vec<Option<MmEntry>>,
    free: Vec<MmId>,
}

impl Mms {
    pub fn add(&mut self, mm: Mm, trampoline: GuestAddr) -> MmId {
        let entry = MmEntry {
            mm,
            users: 1,
            trampoline,
        };
        if let Some(id) = self.free.pop() {
            self.slots[id] = Some(entry);
            return id;
        }
        self.slots.push(Some(entry));
        self.slots.len() - 1
    }

    pub fn get(&self, id: MmId) -> &MmEntry {
        self.slots[id].as_ref().expect("live mm")
    }

    pub fn get_mut(&mut self, id: MmId) -> &mut MmEntry {
        self.slots[id].as_mut().expect("live mm")
    }

    /// Drops one user; frees the entry with its last one.
    pub fn release(&mut self, id: MmId) {
        let entry = self.get_mut(id);
        entry.users -= 1;
        if entry.users == 0 {
            self.slots[id] = None;
            self.free.push(id);
        }
    }
}

/// Every task-related piece of a sandbox's state, apart from the
/// filesystem.
#[derive(Debug)]
pub(crate) struct State {
    pub procs: BTreeMap<Pid, Process>,
    pub threads: BTreeMap<Tid, Thread>,
    /// Platform task to thread.
    pub tasks: HashMap<TaskKey, Tid>,
    pub files: Files,
    pub pipes: Pipes,
    pub mms: Mms,
    pub console: Console,
    next_pid: Pid,
    /// Bytes of generated `/proc` file contents held by open files; see
    /// [`MAX_PROC_BYTES`].
    pub proc_bytes: usize,
    /// Something happened that parked syscalls may be waiting for.
    pub changed: bool,
    /// How the first process ended; the sandbox ends with it.
    pub init_status: Option<ExitStatus>,
    /// The first process's current directory when it ended (held open).
    pub init_cwd: Option<Ino>,
}

impl State {
    pub fn new(console: Console) -> State {
        State {
            procs: BTreeMap::new(),
            threads: BTreeMap::new(),
            tasks: HashMap::new(),
            files: Files::default(),
            pipes: Pipes::default(),
            mms: Mms::default(),
            console,
            next_pid: 1,
            proc_bytes: 0,
            changed: false,
            init_status: None,
            init_cwd: None,
        }
    }

    /// The first process of the sandbox, which plays init.
    pub const INIT: Pid = 1;

    /// Starts numbering pids from 1 again (the sandbox is empty).
    pub fn reset_pids(&mut self) {
        self.next_pid = 1;
    }

    pub fn proc(&self, pid: Pid) -> &Process {
        self.procs.get(&pid).expect("live process")
    }

    pub fn proc_mut(&mut self, pid: Pid) -> &mut Process {
        self.procs.get_mut(&pid).expect("live process")
    }

    pub fn thread(&self, tid: Tid) -> &Thread {
        self.threads.get(&tid).expect("live thread")
    }

    pub fn thread_mut(&mut self, tid: Tid) -> &mut Thread {
        self.threads.get_mut(&tid).expect("live thread")
    }

    /// Whether `id` is in use as a pid, tid, process group or session.
    fn pid_in_use(&self, id: Pid) -> bool {
        self.procs.contains_key(&id)
            || self.threads.contains_key(&id)
            || self.procs.values().any(|p| p.pgid == id || p.sid == id)
    }

    /// A fresh pid (or tid), or `None` if the sandbox has too many tasks.
    pub fn alloc_pid(&mut self) -> Option<Pid> {
        if self.threads.len() + self.procs.len() >= 2 * MAX_TASKS || self.threads.len() >= MAX_TASKS
        {
            return None;
        }
        for _ in 0..PID_MAX {
            let pid = self.next_pid;
            self.next_pid = if pid + 1 >= PID_MAX { 2 } else { pid + 1 };
            if !self.pid_in_use(pid) {
                return Some(pid);
            }
        }
        None
    }

    /// The members of process group `pgid`.
    pub fn group(&self, pgid: Pid) -> Vec<Pid> {
        self.procs
            .values()
            .filter(|p| p.pgid == pgid && p.alive())
            .map(|p| p.pid)
            .collect()
    }

    /// What `sig` does to process `pid` right now.
    pub fn disposition(&self, pid: Pid, sig: u32) -> Disposition {
        if sig == SIGKILL {
            return Disposition::Kill { core: false };
        }
        if sig == SIGSTOP {
            return Disposition::Stop;
        }
        let action = self.proc(pid).action(sig);
        match action.handler {
            SIG_IGN => Disposition::Ignore,
            SIG_DFL => match signal::default_action(sig) {
                DefaultAction::Terminate => Disposition::Kill { core: false },
                DefaultAction::Core => Disposition::Kill { core: true },
                DefaultAction::Ignore => Disposition::Ignore,
                DefaultAction::Stop => Disposition::Stop,
                DefaultAction::Continue => Disposition::Continue,
            },
            _ => Disposition::Handler(action),
        }
    }

    /// Posts a signal to a process (`thread == None`) or one of its threads.
    /// Ignored signals are dropped; `SIGCONT` continues a stopped process
    /// and `SIGKILL` and stop signals take effect at once. The kernel loop
    /// then delivers it: to a parked thread by interrupting its syscall, to
    /// a running one by interrupting the platform task.
    pub fn post_signal(&mut self, pid: Pid, thread: Option<Tid>, info: SigInfo) -> bool {
        let sig = info.signo;
        let Some(proc) = self.procs.get(&pid) else {
            return false;
        };
        if !proc.alive() {
            return true;
        }
        self.changed = true;
        if sig == SIGCONT || sig == SIGKILL {
            self.continue_process(pid);
        }
        let stop_set =
            bit(SIGSTOP) | bit(signal::SIGTSTP) | bit(signal::SIGTTIN) | bit(signal::SIGTTOU);
        if sig == SIGCONT {
            let proc = self.proc_mut(pid);
            proc.pending.discard(stop_set);
            for tid in proc.threads.clone() {
                self.thread_mut(tid).pending.discard(stop_set);
            }
        } else if stop_set & bit(sig) != 0 {
            let proc = self.proc_mut(pid);
            proc.pending.discard(bit(SIGCONT));
        }
        match self.disposition(pid, sig) {
            // Ignored signals are not even queued (unless blocked, when the
            // disposition may change before they are unblocked; queue those).
            Disposition::Ignore | Disposition::Continue => {
                let blocked = match thread {
                    Some(tid) => self.thread(tid).sigmask & bit(sig) != 0,
                    None => self
                        .proc(pid)
                        .threads
                        .iter()
                        .all(|&t| self.thread(t).sigmask & bit(sig) != 0),
                };
                if !blocked || sig == SIGCONT {
                    return true;
                }
            }
            _ => {}
        }
        match thread {
            Some(tid) => self.thread_mut(tid).pending.push(info),
            None => self.proc_mut(pid).pending.push(info),
        }
    }

    /// Ends the job-control stop of a process.
    pub fn continue_process(&mut self, pid: Pid) {
        let proc = self.proc_mut(pid);
        if !proc.stopped {
            return;
        }
        proc.stopped = false;
        proc.event = Some(ChildEvent::Continued);
        let ppid = proc.ppid;
        self.changed = true;
        self.notify_parent(ppid, pid, signal::CLD_CONTINUED, signal::SIGCONT as i32);
    }

    /// Sends `SIGCHLD` to `ppid` about `pid`, unless the parent asked not to
    /// hear about stops and continues.
    pub fn notify_parent(&mut self, ppid: Pid, pid: Pid, code: i32, status: i32) {
        let Some(parent) = self.procs.get(&ppid) else {
            return;
        };
        let action = parent.action(SIGCHLD);
        let stop_or_cont = code == signal::CLD_STOPPED || code == signal::CLD_CONTINUED;
        if stop_or_cont && action.flags & signal::SA_NOCLDSTOP != 0 {
            return;
        }
        let info = SigInfo {
            signo: SIGCHLD,
            code,
            pid,
            status,
            ..SigInfo::default()
        };
        self.post_signal(ppid, None, info);
    }

    /// The signals a thread may receive now: pending for it or its process
    /// and not blocked.
    pub fn deliverable(&self, tid: Tid) -> u64 {
        let t = self.thread(tid);
        let p = self.proc(t.pid);
        (t.pending.set() | p.pending.set()) & !(t.sigmask & !UNBLOCKABLE)
    }

    /// Whether a deliverable signal would interrupt this thread: run a
    /// handler or end or stop its process.
    pub fn has_signal_to_act_on(&self, tid: Tid) -> bool {
        let set = self.deliverable(tid);
        let pid = self.thread(tid).pid;
        (1..=signal::NSIG)
            .filter(|&s| set & bit(s) != 0)
            .any(|s| !matches!(self.disposition(pid, s), Disposition::Ignore))
    }

    /// Takes the next deliverable signal of a thread, thread-directed and
    /// synchronous ones first.
    pub fn take_signal(&mut self, tid: Tid) -> Option<SigInfo> {
        let t = self.thread(tid);
        let allowed = !(t.sigmask & !UNBLOCKABLE);
        let pid = t.pid;
        let sync_first = signal::SYNCHRONOUS;
        let t = self.thread_mut(tid);
        if let Some(info) = t.pending.take(allowed & sync_first) {
            return Some(info);
        }
        if let Some(info) = t.pending.take(allowed) {
            return Some(info);
        }
        self.proc_mut(pid).pending.take(allowed)
    }

    /// The live children of `pid`.
    pub fn children(&self, pid: Pid) -> Vec<Pid> {
        self.procs
            .values()
            .filter(|p| p.ppid == pid)
            .map(|p| p.pid)
            .collect()
    }
}
