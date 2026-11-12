//! Processes: loading programs, `execve`, `clone`/`fork`/`vfork`, exit,
//! `wait4`/`waitid`, process groups and sessions, limits.
//!
//! `execve` loads the new program into a *new* address space (a new
//! platform task) and only then retires the old one, so a failed `execve`
//! leaves the caller untouched, and a `vfork` child that execs leaves its
//! parent's memory alone. `fork` copies the address space through the
//! platform ([`Platform::clone_task`]), which on seccomp is the host's own
//! copy-on-write `fork`.

use crate::elf::{self, ElfError, Placement, StackParams};
use crate::errno::{
    Errno, SysResult, E2BIG, EACCES, ECHILD, EFAULT, EINVAL, ELOOP, ENOENT, ENOEXEC, ENOMEM,
    ENOTDIR, EPERM, ESRCH,
};
use crate::host::Host;
use crate::kernel::ExitStatus;
use crate::mm::{Mm, VmaKind};
use crate::platform::{GuestAddr, Platform, Prot, TaskKey, TaskMem};
use crate::signal::{self, SigAction, SIG_DFL, SIG_IGN};
use crate::task::{
    Life, Next, Pid, Process, Restart, State, Thread, ThreadState, Tid, WaitKind, RLIM_INFINITY,
};
use crate::vfs::{FileType, Ino, Vfs};

use super::{Action, Ctx};

pub(crate) const CLONE_VM: u64 = 0x100;
const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_PTRACE: u64 = 0x2000;
pub(crate) const CLONE_VFORK: u64 = 0x4000;
const CLONE_PARENT: u64 = 0x8000;
const CLONE_THREAD: u64 = 0x1_0000;
const CLONE_SYSVSEM: u64 = 0x4_0000;
const CLONE_SETTLS: u64 = 0x8_0000;
const CLONE_PARENT_SETTID: u64 = 0x10_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x20_0000;
const CLONE_DETACHED: u64 = 0x40_0000;
const CLONE_UNTRACED: u64 = 0x80_0000;
const CLONE_CHILD_SETTID: u64 = 0x100_0000;
const CLONE_IO: u64 = 0x8000_0000;
/// Every flag `clone` accepts (no namespaces, no pidfds).
const CLONE_SUPPORTED: u64 = 0xff
    | CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_PTRACE
    | CLONE_VFORK
    | CLONE_PARENT
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_DETACHED
    | CLONE_UNTRACED
    | CLONE_CHILD_SETTID
    | CLONE_IO;

const WNOHANG: i64 = 1;
const WUNTRACED: i64 = 2;
const WEXITED: i64 = 4;
const WCONTINUED: i64 = 8;
const WNOWAIT: i64 = 0x0100_0000;
const WNOTHREAD: i64 = 0x2000_0000;
const WALL: i64 = 0x4000_0000;
const WCLONE: i64 = 0x8000_0000_u32 as i32 as i64;

const P_ALL: i64 = 0;
const P_PID: i64 = 1;
const P_PGID: i64 = 2;

/// Most bytes of argument and environment strings (`ARG_MAX`-like; the
/// stack builder enforces its own limit too).
const MAX_ARGS_BYTES: usize = 2 << 20;
/// Most argument plus environment strings.
const MAX_ARGS: usize = 1 << 17;
/// Longest `#!` line Linux looks at.
const SHEBANG_MAX: usize = 256;
/// Most nested `#!` interpreters.
const MAX_SHEBANG_DEPTH: u32 = 4;

/// Why a program could not be loaded.
#[derive(Debug)]
pub(crate) struct LoadError {
    pub errno: Errno,
    pub reason: String,
}

impl LoadError {
    fn errno(errno: Errno) -> LoadError {
        let reason = match errno.0 {
            ENOENT => "no such file or directory".to_string(),
            EACCES => "permission denied".to_string(),
            ENOTDIR => "not a directory".to_string(),
            ELOOP => "too many levels of symbolic links".to_string(),
            _ => format!("cannot load ({errno})"),
        };
        LoadError { errno, reason }
    }

    fn elf(err: ElfError) -> LoadError {
        LoadError {
            errno: err.errno(),
            reason: err.to_string(),
        }
    }
}

/// A program loaded into a new task, not started yet.
pub(crate) struct Loaded {
    pub task: TaskKey,
    pub mm: Mm,
    pub trampoline: GuestAddr,
    pub entry: GuestAddr,
    pub stack: GuestAddr,
    pub name: Vec<u8>,
    pub exe: Vec<u8>,
    pub cmdline: Vec<u8>,
}

/// Reads an executable for `execve`: a regular file with an exec bit.
fn read_executable<H: Host + ?Sized>(
    host: &mut H,
    vfs: &mut Vfs,
    start: Ino,
    path: &[u8],
) -> Result<Vec<u8>, LoadError> {
    let ino = vfs
        .resolve(host, start, path, true)
        .map_err(LoadError::errno)?;
    if vfs.file_type(ino) != FileType::Regular || vfs.perm(ino) & 0o111 == 0 {
        return Err(LoadError::errno(Errno(EACCES)));
    }
    vfs.read_all(host, ino).map_err(LoadError::errno)
}

/// Splits a `#!` line into the interpreter and its optional argument.
fn parse_shebang(file: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), LoadError> {
    let line = &file[2..file.len().min(SHEBANG_MAX)];
    let line = match line.iter().position(|&b| b == b'\n') {
        Some(end) => &line[..end],
        None => line,
    };
    let is_space = |b: &u8| *b == b' ' || *b == b'\t';
    let line: &[u8] = {
        let start = line.iter().position(|b| !is_space(b)).unwrap_or(line.len());
        let end = line
            .iter()
            .rposition(|b| !is_space(b))
            .map_or(start, |e| e + 1);
        &line[start..end.max(start)]
    };
    if line.is_empty() || line.contains(&0) {
        return Err(LoadError::errno(Errno(ENOEXEC)));
    }
    let split = line.iter().position(is_space);
    Ok(match split {
        None => (line.to_vec(), None),
        Some(at) => {
            let rest = &line[at..];
            let arg_start = rest.iter().position(|b| !is_space(b)).unwrap_or(rest.len());
            (line[..at].to_vec(), Some(rest[arg_start..].to_vec()))
        }
    })
}

/// Loads the program at `path` (relative to `start`; `#!` interpreters are
/// looked up from `cwd`) into a new task with a fresh address space,
/// together with its program interpreter if it is dynamically linked, and
/// builds its initial stack.
pub(crate) fn load_program<H: Host + ?Sized, P: Platform + ?Sized>(
    host: &mut H,
    plat: &mut P,
    vfs: &mut Vfs,
    start: Ino,
    path: &[u8],
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
) -> Result<Loaded, LoadError> {
    let arch = plat.arch();
    let mut argv = argv.to_vec();
    let mut path = path.to_vec();
    let mut dir = start;
    let mut depth = 0;
    let (file, parsed) = loop {
        let file = read_executable(host, vfs, dir, &path)?;
        if file.starts_with(b"#!") {
            depth += 1;
            if depth > MAX_SHEBANG_DEPTH {
                return Err(LoadError::errno(Errno(ELOOP)));
            }
            let (interp, arg) = parse_shebang(&file)?;
            let mut new_argv = vec![interp.clone()];
            new_argv.extend(arg);
            new_argv.push(path.clone());
            new_argv.extend(argv.iter().skip(1).cloned());
            argv = new_argv;
            path = interp;
            dir = vfs.root();
            continue;
        }
        let parsed = elf::parse(&file, arch).map_err(LoadError::elf)?;
        break (file, parsed);
    };
    let interp = match &parsed.interpreter {
        Some(interp_path) => {
            let interp_file = read_executable(host, vfs, vfs.root(), interp_path)?;
            let interp_parsed = elf::parse(&interp_file, arch).map_err(LoadError::elf)?;
            if interp_parsed.interpreter.is_some() {
                return Err(LoadError {
                    errno: Errno(ELOOP),
                    reason: "the program interpreter has an interpreter".into(),
                });
            }
            Some((interp_file, interp_parsed))
        }
        None => None,
    };
    let mut random = [0u8; 16];
    host.random(&mut random).map_err(|err| LoadError {
        errno: Errno::from_host(&err),
        reason: format!("no random bytes: {err}"),
    })?;

    let task = plat.spawn().map_err(|err| LoadError {
        errno: Errno(crate::errno::EAGAIN),
        reason: format!("cannot create a task: {err}"),
    })?;
    let info = plat.address_space();
    let cpu = plat.cpu_info();
    let mut space = TaskMem::new(plat, task);
    let mut mm = Mm::new(&info);
    let result = (|| {
        let image = elf::load(&mut mm, &mut space, &file, &parsed, Placement::Program)
            .map_err(LoadError::elf)?;
        mm.set_brk_start(image.end);
        let (entry, interp_base) = match &interp {
            Some((interp_file, interp_parsed)) => {
                let loaded = elf::load(
                    &mut mm,
                    &mut space,
                    interp_file,
                    interp_parsed,
                    Placement::Interpreter,
                )
                .map_err(LoadError::elf)?;
                (loaded.entry, loaded.bias)
            }
            None => (image.entry, 0),
        };
        let trampoline = map_trampoline(&mut mm, &mut space, arch).map_err(LoadError::errno)?;
        let params = StackParams {
            arch,
            argv: &argv,
            envp,
            execfn: &path,
            image: &image,
            cpu,
            interp_base,
            random,
        };
        let stack = elf::build_stack(&mut mm, &mut space, &params).map_err(LoadError::errno)?;
        log::debug!(
            "loaded {}: entry {entry:#x}, stack {stack:#x}, brk {:#x}, bias {:#x}, interpreter base {interp_base:#x}",
            String::from_utf8_lossy(&path),
            image.end,
            image.bias
        );
        Ok((entry, stack, trampoline))
    })();
    match result {
        Ok((entry, stack, trampoline)) => {
            let shown = argv.first().unwrap_or(&path);
            let name = shown.rsplit(|&b| b == b'/').next().unwrap_or(shown);
            let mut cmdline = Vec::new();
            for arg in &argv {
                cmdline.extend_from_slice(arg);
                cmdline.push(0);
            }
            Ok(Loaded {
                task,
                mm,
                trampoline,
                entry,
                stack,
                name: name[..name.len().min(15)].to_vec(),
                exe: path,
                cmdline,
            })
        }
        Err(err) => {
            if let Err(kill_err) = plat.kill(task) {
                log::warn!("discarding a half-loaded task: {kill_err}");
            }
            Err(err)
        }
    }
}

/// Maps the sigreturn trampoline (aarch64 only; x86_64 handlers must have
/// `SA_RESTORER`). Returns its address, or 0.
fn map_trampoline<P: Platform + ?Sized>(
    mm: &mut Mm,
    space: &mut TaskMem<'_, P>,
    arch: crate::Arch,
) -> SysResult<GuestAddr> {
    if arch != crate::Arch::Aarch64 {
        return Ok(0);
    }
    let page = mm.page_size();
    let addr = mm.free_area(page, page).ok_or(Errno(ENOMEM))?;
    mm.map_fixed(space, addr, page, Prot::RW, VmaKind::Vdso)?;
    use crate::platform::AppMemory;
    space
        .write(addr, &signal::AARCH64_TRAMPOLINE)
        .map_err(|_| Errno(ENOMEM))?;
    mm.mprotect(space, addr, page, u64::from(Prot::READ.union(Prot::EXEC).0))?;
    Ok(addr)
}

/// Removes a process that has ended (a zombie) from the sandbox.
pub(crate) fn reap(st: &mut State, _vfs: &mut Vfs, pid: Pid) {
    if let Some(proc) = st.procs.get(&pid) {
        debug_assert!(!proc.alive() && proc.threads.is_empty());
        st.procs.remove(&pid);
        st.changed = true;
    }
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    /// Reads a NULL-terminated array of string pointers (`argv`, `envp`),
    /// adding to `total` the bytes it takes.
    fn read_string_array(&mut self, addr: GuestAddr, total: &mut usize) -> SysResult<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        if addr == 0 {
            return Ok(out);
        }
        for i in 0.. {
            if i >= MAX_ARGS {
                return Err(Errno(E2BIG));
            }
            let at = addr.checked_add(i as u64 * 8).ok_or(Errno(EFAULT))?;
            let ptr = self.read_u64(at)?;
            if ptr == 0 {
                break;
            }
            let left = MAX_ARGS_BYTES.saturating_sub(*total);
            let s = self.read_cstr(ptr, left.max(1)).map_err(|err| {
                if err == Errno(crate::errno::ENAMETOOLONG) {
                    Errno(E2BIG)
                } else {
                    err
                }
            })?;
            *total += s.len() + 1;
            out.push(s);
        }
        Ok(out)
    }

    pub fn sys_execveat(
        &mut self,
        dirfd: i64,
        path_addr: GuestAddr,
        argv_addr: GuestAddr,
        envp_addr: GuestAddr,
        flags: u64,
    ) -> SysResult<u64> {
        const AT_EMPTY_PATH: u64 = 0x1000;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
            return Err(Errno(EINVAL));
        }
        let path = self.read_path(path_addr)?;
        if path.is_empty() {
            // fexecve: not supported (the file has no path to load from).
            return Err(Errno(ENOENT));
        }
        let start = self.start_dir_for(dirfd, &path)?;
        let mut total = 0;
        let argv = self.read_string_array(argv_addr, &mut total)?;
        let envp = self.read_string_array(envp_addr, &mut total)?;
        let loaded = load_program(self.host, self.plat, self.vfs, start, &path, &argv, &envp)
            .map_err(|err| {
                log::debug!("execve {}: {}", String::from_utf8_lossy(&path), err.reason);
                err.errno
            })?;
        self.commit_exec(loaded);
        Ok(0)
    }

    /// Replaces the process image with a loaded program: from here on the
    /// old program is gone.
    fn commit_exec(&mut self, loaded: Loaded) {
        let pid = self.pid;
        // Other threads end (they are killed, not waited for).
        let others: Vec<Tid> = self
            .proc()
            .threads
            .iter()
            .copied()
            .filter(|&t| t != self.tid)
            .collect();
        for tid in others {
            self.drop_thread(tid);
        }
        // The exec'ing thread becomes the leader, with tid == pid.
        if self.tid != pid {
            let mut thread = self.st.threads.remove(&self.tid).expect("live thread");
            thread.tid = pid;
            self.st.tasks.insert(thread.task, pid);
            self.st.threads.insert(pid, thread);
            self.tid = pid;
        }
        // The old address space: this thread's task goes; the address
        // space survives as long as someone else (a vfork parent) uses it.
        let old_task = self.task;
        self.st.tasks.remove(&old_task);
        if let Err(err) = self.plat.kill(old_task) {
            log::warn!("ending the old task after execve: {err}");
        }
        if let Some(mm) = self.proc().mm {
            self.st.mms.release(mm);
        }
        let mm = self.st.mms.add(loaded.mm, loaded.trampoline);
        self.task = loaded.task;
        self.st.tasks.insert(loaded.task, pid);
        let released = {
            let st = &mut *self.st;
            let proc = st.procs.get_mut(&pid).expect("live process");
            proc.mm = Some(mm);
            proc.threads = vec![pid];
            proc.name = loaded.name;
            proc.exe = loaded.exe;
            proc.cmdline = loaded.cmdline;
            proc.execed = true;
            for action in proc.actions.iter_mut() {
                if action.handler != SIG_IGN {
                    *action = SigAction::default();
                } else {
                    action.flags = 0;
                }
            }
            proc.fds.close_on_exec(&mut st.files)
        };
        self.release_all(released);
        let thread = self.st.thread_mut(pid);
        thread.task = loaded.task;
        thread.altstack = signal::AltStack::disabled();
        thread.clear_child_tid = 0;
        thread.robust_list = (0, 0);
        self.wake_vfork_parent(pid);
        self.action = Some(Action::Start {
            entry: loaded.entry,
            stack: loaded.stack,
        });
    }

    /// Lets the parent of a `vfork` child continue.
    fn wake_vfork_parent(&mut self, child: Pid) {
        let Some(parent) = self.st.proc_mut(child).vfork_parent.take() else {
            return;
        };
        if let Some(thread) = self.st.threads.get_mut(&parent) {
            if matches!(thread.state, ThreadState::Parked(p) if p.kind == WaitKind::Vfork(child)) {
                thread.state = ThreadState::Ready(Next::Return(i64::from(child)));
            }
        }
    }

    pub fn sys_clone(&mut self, a: [u64; 6]) -> SysResult<u64> {
        let flags = a[0];
        let (stack, ptid, ctid, tls) = match self.arch {
            crate::Arch::X86_64 => (a[1], a[2], a[3], a[4]),
            crate::Arch::Aarch64 => (a[1], a[2], a[4], a[3]),
        };
        if flags & !CLONE_SUPPORTED != 0 {
            log::warn!("clone: unsupported flags {:#x}", flags & !CLONE_SUPPORTED);
            return Err(Errno(EINVAL));
        }
        if flags & CLONE_PIDFD != 0 {
            return Err(Errno(EINVAL));
        }
        let thread = flags & CLONE_THREAD != 0;
        if (thread && flags & CLONE_SIGHAND == 0)
            || (flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0)
        {
            return Err(Errno(EINVAL));
        }
        let exit_signal = (flags & 0xff) as u32;
        if exit_signal > signal::NSIG {
            return Err(Errno(EINVAL));
        }
        let share_vm = flags & CLONE_VM != 0;
        let child = self.st.alloc_pid().ok_or(Errno(crate::errno::EAGAIN))?;
        let task = self.plat.clone_task(self.task, share_vm).map_err(|err| {
            log::warn!("clone: the platform cannot create a task: {err}");
            Errno(crate::errno::EAGAIN)
        })?;
        let setup = (|| -> SysResult<()> {
            let mut context = self.plat.context(self.task).map_err(|_| Errno(EFAULT))?;
            context.set_ret(0);
            if stack != 0 {
                context.set_sp(stack);
            }
            if flags & CLONE_SETTLS != 0 {
                context.set_thread_pointer(tls);
            }
            self.plat
                .set_context(task, &context)
                .map_err(|_| Errno(EFAULT))?;
            if flags & CLONE_CHILD_SETTID != 0 {
                self.plat
                    .write(task, ctid, &child.to_le_bytes())
                    .map_err(|_| Errno(EFAULT))?;
            }
            if flags & CLONE_PARENT_SETTID != 0 {
                self.write_u32(ptid, child)?;
            }
            Ok(())
        })();
        if let Err(err) = setup {
            let _ = self.plat.kill(task);
            return Err(err);
        }

        let parent_thread = self.st.thread(self.tid);
        let mut new = Thread::new(child, child, task, ThreadState::Ready(Next::Continue));
        new.sigmask = parent_thread.sigmask;
        if !share_vm || flags & CLONE_VFORK != 0 {
            new.altstack = parent_thread.altstack;
        }
        if flags & CLONE_CHILD_CLEARTID != 0 {
            new.clear_child_tid = ctid;
        }
        let mm = self.proc().mm;
        if thread {
            new.pid = self.pid;
            self.proc_mut().threads.push(child);
            if let Some(mm) = mm {
                self.st.mms.get_mut(mm).users += 1;
            }
        } else {
            let now = self.host.clock_monotonic();
            let st = &mut *self.st;
            let parent = st.procs.get(&self.pid).expect("live process");
            let mut proc = Process::new(child, parent.cwd, now);
            proc.ppid = if flags & CLONE_PARENT != 0 {
                parent.ppid
            } else {
                self.pid
            };
            proc.pgid = parent.pgid;
            proc.sid = parent.sid;
            proc.umask = parent.umask;
            proc.actions = parent.actions;
            proc.name = parent.name.clone();
            proc.exe = parent.exe.clone();
            proc.cmdline = parent.cmdline.clone();
            proc.rlimits = parent.rlimits;
            proc.exit_signal = exit_signal;
            proc.threads.push(child);
            proc.fds = parent.fds.fork(&mut st.files);
            proc.mm = mm.map(|mm| {
                if share_vm {
                    st.mms.get_mut(mm).users += 1;
                    mm
                } else {
                    let entry = st.mms.get(mm);
                    let copy = entry.mm.clone();
                    let trampoline = entry.trampoline;
                    st.mms.add(copy, trampoline)
                }
            });
            if flags & CLONE_VFORK != 0 {
                proc.vfork_parent = Some(self.tid);
            }
            self.vfs.opened(proc.cwd);
            st.procs.insert(child, proc);
        }
        self.st.threads.insert(child, new);
        self.st.tasks.insert(task, child);
        self.st.changed = true;
        if flags & CLONE_VFORK != 0 {
            return Err(self.park(WaitKind::Vfork(child), None, Restart::Never));
        }
        Ok(u64::from(child))
    }

    /// Ends one thread's task and forgets the thread (its process goes on).
    pub(crate) fn drop_thread(&mut self, tid: Tid) {
        let Some(thread) = self.st.threads.remove(&tid) else {
            return;
        };
        self.st.tasks.remove(&thread.task);
        if let Err(err) = self.plat.kill(thread.task) {
            log::warn!("ending thread {tid}: {err}");
        }
        let pid = thread.pid;
        if let Some(proc) = self.st.procs.get_mut(&pid) {
            proc.threads.retain(|&t| t != tid);
            if let Some(mm) = proc.mm {
                self.st.mms.release(mm);
            }
        }
        self.st.changed = true;
    }

    pub fn sys_exit(&mut self, code: u64) -> SysResult<u64> {
        let status = ExitStatus::Exited((code & 0xff) as i32);
        if self.proc().threads.len() <= 1 {
            self.exit_process(status, false);
        } else {
            self.exit_thread();
        }
        self.action = Some(Action::Done);
        Ok(0)
    }

    pub fn sys_exit_group(&mut self, code: u64) -> SysResult<u64> {
        self.exit_process(ExitStatus::Exited((code & 0xff) as i32), false);
        self.action = Some(Action::Done);
        Ok(0)
    }

    /// Ends this thread, which is not the last one of its process:
    /// `CLONE_CHILD_CLEARTID` and the robust futex list are honoured first.
    fn exit_thread(&mut self) {
        let tid = self.tid;
        self.exit_robust_list();
        let clear = self.st.thread(tid).clear_child_tid;
        if clear != 0 && self.write_u32(clear, 0).is_ok() {
            self.futex_wake_addr(clear, 1, u32::MAX);
        }
        self.drop_thread(tid);
    }

    /// Ends this thread's process with `status`. All of its threads go,
    /// its resources are released, its children go to init and its parent
    /// is told.
    pub(crate) fn exit_process(&mut self, status: ExitStatus, core: bool) {
        let pid = self.pid;
        if !self.st.procs.get(&pid).is_some_and(Process::alive) {
            return;
        }
        for tid in self.proc().threads.clone() {
            self.drop_thread(tid);
        }
        let (released, cwd) = {
            let st = &mut *self.st;
            let proc = st.procs.get_mut(&pid).expect("live process");
            proc.mm = None;
            proc.itimer = Default::default();
            proc.pending = Default::default();
            proc.life = Life::Zombie(status);
            proc.core_dumped = core;
            (proc.fds.close_all(&mut st.files), proc.cwd)
        };
        self.release_all(released);
        if pid == State::INIT {
            self.st.init_cwd = Some(cwd);
            self.st.init_status = Some(status);
        } else {
            self.vfs.closed(cwd);
        }
        // Orphans go to init.
        for child in self.st.children(pid) {
            self.st.proc_mut(child).ppid = State::INIT;
            if !self.st.proc(child).alive() && self.st.procs.contains_key(&State::INIT) {
                let status = self.zombie_wait_status(child);
                self.st
                    .notify_parent(State::INIT, child, status.0, status.1);
            }
        }
        self.wake_vfork_parent(pid);
        self.st.changed = true;
        let (ppid, exit_signal) = {
            let proc = self.st.proc(pid);
            (proc.ppid, proc.exit_signal)
        };
        let Some(parent) = self.st.procs.get(&ppid).filter(|p| p.alive()) else {
            return;
        };
        let action = parent.action(signal::SIGCHLD);
        if action.handler == SIG_IGN || action.flags & signal::SA_NOCLDWAIT != 0 {
            // The parent does not want zombies.
            reap(self.st, self.vfs, pid);
            return;
        }
        if exit_signal != 0 {
            let (code, status) = self.zombie_wait_status(pid);
            let info = signal::SigInfo {
                signo: exit_signal,
                code,
                pid,
                status,
                ..Default::default()
            };
            self.st.post_signal(ppid, None, info);
        }
    }

    /// The `si_code` and `si_status` of a zombie.
    fn zombie_wait_status(&self, pid: Pid) -> (i32, i32) {
        let proc = self.st.proc(pid);
        match proc.life {
            Life::Zombie(ExitStatus::Exited(code)) => (signal::CLD_EXITED, code),
            Life::Zombie(ExitStatus::Signaled(sig)) if proc.core_dumped => {
                (signal::CLD_DUMPED, sig as i32)
            }
            Life::Zombie(ExitStatus::Signaled(sig)) => (signal::CLD_KILLED, sig as i32),
            Life::Alive => (0, 0),
        }
    }

    /// The children of this process that a wait for `pid` (in `wait4`'s
    /// encoding) covers.
    fn waitable(&self, pid: i64) -> Vec<Pid> {
        let me = self.proc();
        let pgid = me.pgid;
        self.st
            .children(self.pid)
            .into_iter()
            .filter(|&c| {
                let child = self.st.proc(c);
                match pid {
                    -1 => true,
                    0 => child.pgid == pgid,
                    p if p > 0 => i64::from(c) == p,
                    p => i64::from(child.pgid) == -p,
                }
            })
            .collect()
    }

    pub fn sys_wait4(
        &mut self,
        pid: i64,
        status_addr: GuestAddr,
        options: i64,
        rusage: GuestAddr,
    ) -> SysResult<u64> {
        if options & !(WNOHANG | WUNTRACED | WCONTINUED | WNOTHREAD | WALL | WCLONE) != 0 {
            return Err(Errno(EINVAL));
        }
        let children = self.waitable(pid);
        if children.is_empty() {
            return Err(Errno(ECHILD));
        }
        for child in children {
            let proc = self.st.proc(child);
            let status = match (proc.life, proc.event) {
                (Life::Zombie(status), _) => status.wait_status(proc.core_dumped),
                (Life::Alive, Some(crate::task::ChildEvent::Stopped(sig)))
                    if options & WUNTRACED != 0 =>
                {
                    ((sig as i32) << 8) | 0x7f
                }
                (Life::Alive, Some(crate::task::ChildEvent::Continued))
                    if options & WCONTINUED != 0 =>
                {
                    0xffff
                }
                _ => continue,
            };
            if status_addr != 0 {
                self.write_u32(status_addr, status as u32)?;
            }
            if rusage != 0 {
                self.write_mem(rusage, &[0; 144])?;
            }
            if self.st.proc(child).alive() {
                self.st.proc_mut(child).event = None;
            } else {
                reap(self.st, self.vfs, child);
            }
            return Ok(u64::from(child));
        }
        if options & WNOHANG != 0 {
            return Ok(0);
        }
        Err(self.park_retry(None, Restart::IfSaRestart))
    }

    pub fn sys_waitid(
        &mut self,
        idtype: i64,
        id: i64,
        infop: GuestAddr,
        options: i64,
    ) -> SysResult<u64> {
        if options
            & !(WNOHANG | WUNTRACED | WEXITED | WCONTINUED | WNOWAIT | WNOTHREAD | WALL | WCLONE)
            != 0
            || options & (WEXITED | WUNTRACED | WCONTINUED) == 0
        {
            return Err(Errno(EINVAL));
        }
        let selector = match idtype {
            P_ALL => -1,
            P_PID if id > 0 => id,
            P_PGID if id > 0 => -id,
            P_PGID if id == 0 => 0,
            _ => return Err(Errno(EINVAL)),
        };
        let children = self.waitable(selector);
        if children.is_empty() {
            return Err(Errno(ECHILD));
        }
        for child in children {
            let proc = self.st.proc(child);
            let (code, status, consume) = match (proc.life, proc.event) {
                (Life::Zombie(_), _) if options & WEXITED != 0 => {
                    let (code, status) = self.zombie_wait_status(child);
                    (code, status, true)
                }
                (Life::Alive, Some(crate::task::ChildEvent::Stopped(sig)))
                    if options & WUNTRACED != 0 =>
                {
                    (signal::CLD_STOPPED, sig as i32, true)
                }
                (Life::Alive, Some(crate::task::ChildEvent::Continued))
                    if options & WCONTINUED != 0 =>
                {
                    (signal::CLD_CONTINUED, signal::SIGCONT as i32, true)
                }
                _ => continue,
            };
            if infop != 0 {
                let info = signal::SigInfo {
                    signo: signal::SIGCHLD,
                    code,
                    pid: child,
                    status,
                    ..Default::default()
                };
                self.write_mem(infop, &info.encode())?;
            }
            if consume && options & WNOWAIT == 0 {
                if self.st.proc(child).alive() {
                    self.st.proc_mut(child).event = None;
                } else {
                    reap(self.st, self.vfs, child);
                }
            }
            return Ok(0);
        }
        if options & WNOHANG != 0 {
            if infop != 0 {
                self.write_mem(infop, &[0; 128])?;
            }
            return Ok(0);
        }
        Err(self.park_retry(None, Restart::IfSaRestart))
    }

    /// The process `pid` names (0: this one).
    fn target_proc(&self, pid: i64) -> SysResult<Pid> {
        if pid == 0 {
            return Ok(self.pid);
        }
        let pid = u32::try_from(pid).map_err(|_| Errno(ESRCH))?;
        match self.st.procs.get(&pid) {
            Some(p) if p.alive() => Ok(pid),
            _ => Err(Errno(ESRCH)),
        }
    }

    pub fn sys_getpgid(&mut self, pid: i64) -> SysResult<u64> {
        let pid = self.target_proc(pid)?;
        Ok(u64::from(self.st.proc(pid).pgid))
    }

    pub fn sys_getsid(&mut self, pid: i64) -> SysResult<u64> {
        let pid = self.target_proc(pid)?;
        Ok(u64::from(self.st.proc(pid).sid))
    }

    pub fn sys_setpgid(&mut self, pid: i64, pgid: i64) -> SysResult<u64> {
        if pgid < 0 {
            return Err(Errno(EINVAL));
        }
        let target = self.target_proc(pid)?;
        let me = self.proc();
        let (my_sid, my_pid) = (me.sid, me.pid);
        let t = self.st.proc(target);
        if target != my_pid {
            if t.ppid != my_pid {
                return Err(Errno(ESRCH));
            }
            if t.execed {
                return Err(Errno(EACCES));
            }
        }
        if t.sid != my_sid || t.sid == target {
            return Err(Errno(EPERM));
        }
        let pgid = if pgid == 0 { target } else { pgid as Pid };
        if pgid != target
            && !self
                .st
                .procs
                .values()
                .any(|p| p.pgid == pgid && p.sid == my_sid && p.alive())
        {
            return Err(Errno(EPERM));
        }
        self.st.proc_mut(target).pgid = pgid;
        self.st.changed = true;
        Ok(0)
    }

    pub fn sys_setsid(&mut self) -> SysResult<u64> {
        let pid = self.pid;
        if self.st.procs.values().any(|p| p.pgid == pid) {
            return Err(Errno(EPERM));
        }
        let proc = self.proc_mut();
        proc.sid = pid;
        proc.pgid = pid;
        self.st.console.session_left(pid);
        Ok(u64::from(pid))
    }

    pub fn sys_set_tid_address(&mut self, addr: GuestAddr) -> SysResult<u64> {
        self.st.thread_mut(self.tid).clear_child_tid = addr;
        Ok(u64::from(self.tid))
    }

    pub fn sys_set_robust_list(&mut self, head: GuestAddr, len: u64) -> SysResult<u64> {
        // sizeof(struct robust_list_head) on 64-bit.
        if len != 24 {
            return Err(Errno(EINVAL));
        }
        self.st.thread_mut(self.tid).robust_list = (head, len);
        Ok(0)
    }

    pub fn sys_get_robust_list(
        &mut self,
        tid: i64,
        head_addr: GuestAddr,
        len_addr: GuestAddr,
    ) -> SysResult<u64> {
        let tid = if tid == 0 {
            self.tid
        } else {
            u32::try_from(tid).map_err(|_| Errno(ESRCH))?
        };
        let (head, len) = self.st.threads.get(&tid).ok_or(Errno(ESRCH))?.robust_list;
        self.write_u64(head_addr, head)?;
        self.write_u64(len_addr, len)?;
        Ok(0)
    }

    /// Releases the robust futexes this exiting thread holds: each gets
    /// `FUTEX_OWNER_DIED` and one waiter is woken. Bounded, like Linux's
    /// `ROBUST_LIST_LIMIT`; a bad list is abandoned silently.
    fn exit_robust_list(&mut self) {
        const LIMIT: usize = 2048;
        const FUTEX_WAITERS: u32 = 0x8000_0000;
        const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
        const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
        let (head, _) = self.st.thread(self.tid).robust_list;
        if head == 0 {
            return;
        }
        let tid = self.tid;
        let Ok(raw) = self.read_mem(head, 24) else {
            return;
        };
        let word = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        let (mut entry, offset, pending) = (word(0), word(1) as i64, word(2));
        let handle = |ctx: &mut Self, entry: u64| {
            let addr = entry.wrapping_add(offset as u64);
            let Ok(val) = ctx.read_u32(addr) else {
                return;
            };
            if val & FUTEX_TID_MASK != tid {
                return;
            }
            let new = (val & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
            if ctx.write_u32(addr, new).is_ok() && val & FUTEX_WAITERS != 0 {
                ctx.futex_wake_addr(addr, 1, u32::MAX);
            }
        };
        let mut seen = 0;
        while entry != head && entry != 0 && seen < LIMIT {
            let Ok(next) = self.read_u64(entry) else {
                break;
            };
            if entry != pending {
                handle(self, entry);
            }
            entry = next;
            seen += 1;
        }
        if pending != 0 {
            handle(self, pending);
        }
    }

    pub fn sys_prlimit64(
        &mut self,
        pid: i64,
        resource: u64,
        new: GuestAddr,
        old: GuestAddr,
    ) -> SysResult<u64> {
        let pid = self.target_proc(pid)?;
        let resource = usize::try_from(resource)
            .ok()
            .filter(|&r| r < self.proc().rlimits.len())
            .ok_or(Errno(EINVAL))?;
        if old != 0 {
            let (cur, max) = self.st.proc(pid).rlimits[resource];
            let mut buf = [0u8; 16];
            buf[..8].copy_from_slice(&cur.to_le_bytes());
            buf[8..].copy_from_slice(&max.to_le_bytes());
            self.write_mem(old, &buf)?;
        }
        if new != 0 {
            let buf: [u8; 16] = self.read_array(new)?;
            let cur = u64::from_le_bytes(buf[..8].try_into().unwrap());
            let max = u64::from_le_bytes(buf[8..].try_into().unwrap());
            if cur > max {
                return Err(Errno(EINVAL));
            }
            let (_, old_max) = self.st.proc(pid).rlimits[resource];
            if max > old_max && old_max != RLIM_INFINITY {
                // Raising a hard limit is allowed for root; the fd table
                // and the process table cannot grow, though.
                if resource == 7 || resource == 6 {
                    return Err(Errno(EPERM));
                }
            }
            self.st.proc_mut(pid).rlimits[resource] = (cur, max);
        }
        Ok(0)
    }
}

/// Signal dispositions a new process inherits: handlers reset (used by
/// tests).
#[allow(dead_code)]
pub(crate) fn reset_handlers(actions: &mut [SigAction]) {
    for action in actions {
        if action.handler != SIG_IGN && action.handler != SIG_DFL {
            *action = SigAction::default();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shebang_lines() {
        let (i, a) = parse_shebang(b"#!/bin/sh\necho").unwrap();
        assert_eq!((i, a), (b"/bin/sh".to_vec(), None));
        let (i, a) = parse_shebang(b"#!  /usr/bin/env   python3 -u  \n").unwrap();
        assert_eq!(i, b"/usr/bin/env");
        assert_eq!(a.unwrap(), b"python3 -u");
        assert!(parse_shebang(b"#!   \n").is_err());
    }
}
