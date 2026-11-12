//! [`SeccompPlatform`], the seccomp implementation of the platform trait.
//!
//! Every task is a host process, traced by the thread that created the
//! platform (see `spawn` for the mechanism and its safety argument). The
//! platform keeps, per task, where it is stopped and the app registers it
//! will resume with; everything the app does goes through the core.

use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hellovm_core::platform::{
    AddressSpaceInfo, Context, CpuInfo, Event, Fault, GuestAddr, Platform, PlatformError, Prot,
    Resume, Sharing, SyscallTrap, TaskKey, Trap, Waker,
};
use hellovm_core::{Arch, Sysno};

use crate::regs::{self, Regs, SYSCALL_INSN_LEN};
use crate::spawn;
use crate::stub;
use crate::sys;
use crate::tracer::{self, Run, Stop, Tracee};
use crate::wake;

/// Linux `mmap` flags used for injected mappings.
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;

/// The lowest address the core may map. Linux refuses user mappings below
/// `vm.mmap_min_addr`, whose usual default is 64 KiB.
const MIN_ADDR: u64 = 0x1_0000;

/// The host signal [`Platform::interrupt`] sends. It is never delivered:
/// the tracer sees it at the signal-delivery-stop and drops it. Its default
/// action is to do nothing, in case the task is not traced any more.
const INTERRUPT_SIGNAL: i32 = libc::SIGURG;

/// Where a stopped task is stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopKind {
    /// At the seccomp stop of an app syscall, which has not run.
    Seccomp,
    /// At a syscall-exit stop of a syscall the kernel process made the task
    /// execute (an injected one, or a skipped app syscall).
    SyscallExit,
    /// At a signal-delivery-stop (a fault, an interrupt, or the first stop
    /// of a new process). The signal is dropped when the task resumes.
    Signal,
}

#[derive(Debug)]
enum State {
    Running,
    Stopped(StopKind),
}

#[derive(Debug)]
struct Task {
    tracee: Tracee,
    state: State,
    /// While stopped: the registers the app resumes with.
    regs: Regs,
    /// The registers were changed by the core and must be written back.
    dirty: bool,
}

/// The live tasks' pidfds, shared with every [`AppKiller`].
#[derive(Debug, Default)]
struct Registry {
    killed: bool,
    pidfds: HashMap<libc::pid_t, OwnedFd>,
}

fn send_kill(pidfd: &OwnedFd) {
    // SAFETY: plain syscall on an fd we own. ESRCH (already gone) is fine.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
}

/// One sandbox's app processes, traced by the thread that created it.
///
/// It must be used from that thread (a ptrace rule), so it is neither `Send`
/// nor `Sync`.
#[derive(Debug)]
pub struct SeccompPlatform {
    arch: Arch,
    info: AddressSpaceInfo,
    hwcap: CpuInfo,
    tasks: HashMap<TaskKey, Task>,
    registry: Arc<Mutex<Registry>>,
    nr_mmap: u64,
    nr_munmap: u64,
    nr_mprotect: u64,
    nr_clone: u64,
    _not_send: PhantomData<*const ()>,
}

impl SeccompPlatform {
    /// A platform for one sandbox. No app process exists until the core
    /// spawns one.
    pub fn new() -> io::Result<SeccompPlatform> {
        let arch = Arch::native().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "unsupported host architecture")
        })?;
        wake::install()?;
        let page_size = sys::page_size();
        let number = |sysno: Sysno| arch.syscall_nr(sysno).expect("generic syscall");
        let stub_range = stub::STUB_BASE..stub::STUB_BASE + stub::STUB_RESERVED;
        let mut platform = SeccompPlatform {
            arch,
            info: AddressSpaceInfo {
                page_size,
                min_addr: MIN_ADDR.max(page_size),
                max_addr: 0,
                reserved: vec![stub_range],
            },
            hwcap: host_cpu_info(),
            tasks: HashMap::new(),
            registry: Arc::default(),
            nr_mmap: number(Sysno::Mmap),
            nr_munmap: number(Sysno::Munmap),
            nr_mprotect: number(Sysno::Mprotect),
            nr_clone: number(Sysno::Clone),
            _not_send: PhantomData,
        };
        // The address space's extent is set by the first spawn, from what
        // the host gave that process (its stack sits at the top of the user
        // range).
        let _ = &mut platform;
        Ok(platform)
    }

    /// A handle that ends every app process of this platform from any
    /// thread, for timeouts and cancellation: the apps may be running code
    /// that never makes a syscall, and then the thread driving them is
    /// blocked in [`Platform::wait`].
    pub fn killer(&self) -> AppKiller {
        AppKiller {
            registry: Arc::clone(&self.registry),
        }
    }

    /// The host pid of a task (for tests and diagnostics).
    pub fn host_pid(&self, task: TaskKey) -> Option<libc::pid_t> {
        self.tasks.get(&task).map(|t| t.tracee.pid)
    }

    /// The number of live tasks.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    fn task(&mut self, key: TaskKey) -> Result<&mut Task, PlatformError> {
        self.tasks
            .get_mut(&key)
            .ok_or_else(|| PlatformError::AppGone(format!("no task {key}")))
    }

    fn stopped(&mut self, key: TaskKey) -> Result<(&mut Task, StopKind), PlatformError> {
        let task = self.task(key)?;
        match task.state {
            State::Stopped(kind) => Ok((task, kind)),
            State::Running => Err(PlatformError::Unsupported("operation on a running task")),
        }
    }

    /// Starts tracking a new, stopped host process.
    fn register(
        &mut self,
        tracee: Tracee,
        regs: Regs,
        kind: StopKind,
    ) -> Result<TaskKey, PlatformError> {
        let pid = tracee.pid;
        // SAFETY: plain syscall; the process is our unreaped child or
        // tracee, so the pid names it. A non-negative result is our fd.
        let pidfd = unsafe {
            let fd = libc::syscall(libc::SYS_pidfd_open, pid, 0);
            if fd < 0 {
                return Err(PlatformError::Host(io::Error::last_os_error()));
            }
            OwnedFd::from_raw_fd(fd as i32)
        };
        {
            let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
            if registry.killed {
                send_kill(&pidfd);
            }
            registry.pidfds.insert(pid, pidfd);
        }
        let key = pid as TaskKey;
        self.tasks.insert(
            key,
            Task {
                tracee,
                state: State::Stopped(kind),
                regs,
                dirty: false,
            },
        );
        Ok(key)
    }

    fn forget(&mut self, key: TaskKey) -> Option<Task> {
        let task = self.tasks.remove(&key)?;
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        registry.pidfds.remove(&task.tracee.pid);
        Some(task)
    }

    fn spawn_task(&mut self) -> Result<TaskKey, PlatformError> {
        let spawned = spawn::spawn(self.arch)?;
        let max_addr = spawned.top & !(self.info.page_size - 1);
        if self.info.max_addr == 0 {
            self.info.max_addr = max_addr;
        }
        let key = self.register(spawned.tracee, spawned.regs, StopKind::SyscallExit)?;
        for &(start, len) in &spawned.foreign {
            let ret = self
                .inject(key, sys_nr(self.nr_munmap), [start, len, 0, 0, 0, 0])
                .map(|(ret, _)| ret);
            match ret {
                Ok(0) => {}
                other => {
                    let _ = self.kill(key);
                    return Err(PlatformError::Host(io::Error::other(format!(
                        "clearing the app address space: munmap({start:#x}, {len:#x}) = {other:?}"
                    ))));
                }
            }
        }
        let pid = self.tasks[&key].tracee.pid;
        let (left, _) = spawn::foreign_mappings(pid)?;
        if !left.is_empty() {
            let _ = self.kill(key);
            return Err(PlatformError::Host(io::Error::other(format!(
                "host mappings left in the app address space: {left:#x?}"
            ))));
        }
        Ok(key)
    }

    fn violation(&mut self, key: TaskKey, what: String) -> PlatformError {
        log::error!("task {key}: {what}; killing it");
        if let Some(mut task) = self.forget(key) {
            let _ = task.tracee.kill();
        }
        PlatformError::Violation(what)
    }

    /// Waits for the next stop of task `key` during an injection, dropping
    /// signals that do not concern it (interrupts sent while it was
    /// running).
    fn wait_injected(&mut self, key: TaskKey, run: Run) -> Result<Stop, PlatformError> {
        loop {
            let task = self.task(key)?;
            let stop = task.tracee.wait()?;
            match stop {
                Stop::Signal(sig) if !is_fault(sig) => task.tracee.resume(run, 0)?,
                stop if stop.ended() => {
                    self.forget(key);
                    return Err(PlatformError::AppGone(format!("ended: {stop:?}")));
                }
                stop => return Ok(stop),
            }
        }
    }

    /// Makes stopped task `key` execute syscall `nr` with `args` from the
    /// stub and returns the raw result, and the new process if the syscall
    /// created one. The task's app registers are restored when it resumes.
    fn inject(
        &mut self,
        key: TaskKey,
        nr: u64,
        args: [u64; 6],
    ) -> Result<(i64, Option<libc::pid_t>), PlatformError> {
        let (task, kind) = self.stopped(key)?;
        if kind == StopKind::Seccomp {
            // Skip the app's own syscall to reach its exit stop. The app
            // registers stay in `task.regs`.
            let regs = task.regs;
            task.tracee.skip_syscall(&regs)?;
            task.tracee.resume(Run::Syscall, 0)?;
            match self.wait_injected(key, Run::Syscall)? {
                Stop::SyscallExit => {}
                stop => {
                    return Err(self.violation(key, format!("unexpected stop {stop:?} at skip")))
                }
            }
        }
        let task = self.task(key)?;
        task.state = State::Stopped(StopKind::SyscallExit);
        task.dirty = true;
        let mut regs = task.regs;
        regs.prepare_syscall(stub::STUB_SYSCALL, nr, args);
        task.tracee.set_regs(&regs)?;
        task.tracee.resume(Run::Cont, 0)?;
        match self.wait_injected(key, Run::Cont)? {
            Stop::Seccomp => {}
            stop => {
                return Err(self.violation(key, format!("injected syscall: unexpected {stop:?}")))
            }
        }
        // Only the exact syscall prepared above may run.
        let task = self.task(key)?;
        let at = task.tracee.regs()?;
        if at.pc() != stub::STUB_SYSCALL + SYSCALL_INSN_LEN || at.syscall() != (nr, args) {
            let what = format!(
                "injected syscall {nr} {args:#x?} stopped as {:?} at {:#x}",
                at.syscall(),
                at.pc()
            );
            return Err(self.violation(key, what));
        }
        task.tracee.resume(Run::Syscall, 0)?;
        let mut child = None;
        loop {
            match self.wait_injected(key, Run::Syscall)? {
                Stop::SyscallExit => break,
                Stop::NewChild(pid) if nr == self.nr_clone && child.is_none() => {
                    child = Some(pid);
                    self.task(key)?.tracee.resume(Run::Syscall, 0)?;
                }
                stop => {
                    return Err(
                        self.violation(key, format!("injected syscall: unexpected {stop:?}"))
                    )
                }
            }
        }
        let ret = self.task(key)?.tracee.regs()?.ret();
        Ok((ret, child))
    }

    /// Checks a range the core wants changed, independently of the core:
    /// page-aligned, inside the app's address range and clear of the stub.
    fn check_range(&self, addr: GuestAddr, len: u64) -> Result<(), PlatformError> {
        let page = self.info.page_size;
        let bad = || PlatformError::BadAddress {
            addr,
            len: len as usize,
        };
        let end = addr.checked_add(len).ok_or_else(bad)?;
        if !addr.is_multiple_of(page)
            || !len.is_multiple_of(page)
            || len == 0
            || addr < self.info.min_addr
            || end > self.info.max_addr
            || self
                .info
                .reserved
                .iter()
                .any(|r: &Range<u64>| addr < r.end && end > r.start)
        {
            return Err(bad());
        }
        Ok(())
    }

    fn checked_inject(
        &mut self,
        key: TaskKey,
        what: &str,
        nr: u64,
        args: [u64; 6],
    ) -> Result<i64, PlatformError> {
        let (ret, _) = self.inject(key, nr, args)?;
        if (-4095..0).contains(&ret) {
            // A host errno: for the kernel process's log only.
            let err = io::Error::from_raw_os_error((-ret) as i32);
            return Err(PlatformError::Host(io::Error::new(
                err.kind(),
                format!("{what} in the app process failed: {err}"),
            )));
        }
        Ok(ret)
    }

    /// Turns a stop of a running task into the event the core sees.
    fn on_stop(&mut self, pid: libc::pid_t, stop: Stop) -> Result<Option<Event>, PlatformError> {
        let key = pid as TaskKey;
        let Some(task) = self.tasks.get_mut(&key) else {
            if !stop.ended() {
                // A process the platform does not know (a child whose
                // parent died while creating it): it must not run.
                log::warn!("unknown tracee {pid} stopped ({stop:?}); killing it");
                let mut stray = Tracee::new(pid);
                let _ = stray.kill();
            }
            return Ok(None);
        };
        if stop.ended() {
            task.tracee.mark_reaped();
            self.forget(key);
            return Ok(Some(Event {
                task: key,
                trap: Trap::Gone,
            }));
        }
        if !matches!(task.state, State::Running) {
            return Err(self.violation(key, format!("stop {stop:?} of a stopped task")));
        }
        let trap = match stop {
            Stop::Seccomp => {
                let regs = task.tracee.regs()?;
                let (nr, args) = regs.syscall();
                task.regs = regs;
                task.dirty = false;
                task.state = State::Stopped(StopKind::Seccomp);
                Trap::Syscall(SyscallTrap { nr, args })
            }
            Stop::Signal(sig) => {
                let regs = task.tracee.regs()?;
                task.regs = regs;
                task.dirty = false;
                task.state = State::Stopped(StopKind::Signal);
                match task.tracee.siginfo() {
                    Some((code, addr)) if is_fault(sig) && code > 0 => Trap::Fault(Fault {
                        signal: sig as u32,
                        code,
                        addr: Some(addr),
                    }),
                    _ => Trap::Interrupted,
                }
            }
            other => return Err(self.violation(key, format!("unexpected stop {other:?}"))),
        };
        Ok(Some(Event { task: key, trap }))
    }
}

/// Signals the CPU raises for a fault of the task itself.
fn is_fault(sig: i32) -> bool {
    matches!(
        sig,
        libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE | libc::SIGTRAP | libc::SIGSYS
    )
}

fn sys_nr(nr: u64) -> u64 {
    nr
}

fn host_cpu_info() -> CpuInfo {
    // SAFETY: plain libc calls.
    unsafe {
        CpuInfo {
            hwcap: libc::getauxval(libc::AT_HWCAP),
            hwcap2: libc::getauxval(libc::AT_HWCAP2),
        }
    }
}

fn vm_io(
    pid: libc::pid_t,
    addr: GuestAddr,
    buf: *mut u8,
    len: usize,
    write: bool,
) -> Result<(), PlatformError> {
    if len == 0 {
        return Ok(());
    }
    let local = libc::iovec {
        iov_base: buf.cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: `local` describes a buffer of `len` bytes owned by the
    // caller (only read for writes); `remote` is only interpreted in the
    // app process.
    let n = unsafe {
        if write {
            libc::process_vm_writev(pid, &local, 1, &remote, 1, 0)
        } else {
            libc::process_vm_readv(pid, &local, 1, &remote, 1, 0)
        }
    };
    if n != len as isize {
        return Err(PlatformError::BadAddress { addr, len });
    }
    Ok(())
}

impl Platform for SeccompPlatform {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn address_space(&self) -> AddressSpaceInfo {
        self.info.clone()
    }

    fn cpu_info(&self) -> CpuInfo {
        self.hwcap
    }

    fn spawn(&mut self) -> Result<TaskKey, PlatformError> {
        self.spawn_task()
    }

    fn clone_task(
        &mut self,
        parent: TaskKey,
        share_memory: bool,
    ) -> Result<TaskKey, PlatformError> {
        let mut flags = sys::CLONE_PARENT | libc::SIGCHLD as u64;
        if share_memory {
            flags |= sys::CLONE_VM;
        }
        let (ret, child) = self.inject(parent, self.nr_clone, [flags, 0, 0, 0, 0, 0])?;
        let Some(child) = child else {
            if ret < 0 {
                return Err(PlatformError::NoResources(format!(
                    "clone in the app process failed: {}",
                    io::Error::from_raw_os_error((-ret) as i32)
                )));
            }
            return Err(PlatformError::Violation(format!(
                "clone returned {ret} without a fork event"
            )));
        };
        let mut tracee = Tracee::new(child);
        // The child starts with a SIGSTOP, before running any instruction.
        loop {
            match tracee.wait()? {
                Stop::Signal(libc::SIGSTOP) => break,
                Stop::Signal(sig) if !is_fault(sig) => tracee.resume(Run::Cont, 0)?,
                stop => {
                    let _ = tracee.kill();
                    return Err(PlatformError::Violation(format!(
                        "new app process {child}: unexpected first stop {stop:?}"
                    )));
                }
            }
        }
        // It resumes with the parent's app registers (its own are a copy
        // of the injected call's). Its FP state and thread pointer are the
        // parent's already: injection never touches them.
        let regs = self.task(parent)?.regs;
        let key = self.register(tracee, regs, StopKind::Signal)?;
        self.task(key)?.dirty = true;
        Ok(key)
    }

    fn kill(&mut self, key: TaskKey) -> Result<(), PlatformError> {
        if let Some(mut task) = self.forget(key) {
            task.tracee.kill()?;
        }
        Ok(())
    }

    fn context(&mut self, key: TaskKey) -> Result<Context, PlatformError> {
        let (task, _) = self.stopped(key)?;
        let fp = task.tracee.fp_regs()?;
        #[cfg(target_arch = "aarch64")]
        let tls = task.tracee.tls()?;
        #[cfg(target_arch = "x86_64")]
        let tls = 0;
        Ok(regs::to_context(&task.regs, &fp, tls))
    }

    fn set_context(&mut self, key: TaskKey, context: &Context) -> Result<(), PlatformError> {
        let (task, _) = self.stopped(key)?;
        let (regs, fp, _tls) = regs::from_context(context, &task.regs).ok_or(
            PlatformError::Unsupported("a context of another architecture"),
        )?;
        task.tracee.set_fp_regs(&fp)?;
        #[cfg(target_arch = "aarch64")]
        task.tracee.set_tls(_tls)?;
        task.regs = regs;
        task.dirty = true;
        Ok(())
    }

    fn resume(&mut self, key: TaskKey, resume: Resume) -> Result<(), PlatformError> {
        let (task, kind) = self.stopped(key)?;
        match resume {
            Resume::Start { entry, stack } => task.regs.start(entry, stack),
            Resume::Return(ret) => task.regs.set_ret(ret),
            Resume::Continue => {}
        }
        let regs = task.regs;
        match kind {
            StopKind::Seccomp => task.tracee.skip_syscall(&regs)?,
            StopKind::SyscallExit | StopKind::Signal => task.tracee.set_regs(&regs)?,
        }
        task.tracee.resume(Run::Cont, 0)?;
        task.state = State::Running;
        task.dirty = false;
        Ok(())
    }

    fn interrupt(&mut self, key: TaskKey) -> Result<(), PlatformError> {
        let task = self.task(key)?;
        let pid = task.tracee.pid;
        // SAFETY: plain syscall; the pid names our unreaped tracee.
        unsafe { libc::syscall(libc::SYS_tgkill, pid, pid, INTERRUPT_SIGNAL) };
        Ok(())
    }

    fn wait(&mut self, timeout: Option<Duration>) -> Result<Option<Event>, PlatformError> {
        // A timeout too far away to represent is no timeout.
        let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
        let mut slept = false;
        loop {
            let seen = wake::generation();
            loop {
                match tracer::waitpid(-1, true) {
                    Ok(Some((pid, stop))) => {
                        if let Some(event) = self.on_stop(pid, stop)? {
                            return Ok(Some(event));
                        }
                    }
                    Ok(None) => break,
                    Err(err) if err.raw_os_error() == Some(libc::ECHILD) => break,
                    Err(err) => return Err(err.into()),
                }
            }
            // Nothing happened after a wake-up: let the core look again.
            if slept {
                return Ok(None);
            }
            let left = match deadline {
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(None);
                    }
                    Some(deadline - now)
                }
                None => None,
            };
            wake::sleep(seen, left);
            slept = true;
        }
    }

    fn waker(&self) -> Waker {
        wake::waker()
    }

    fn read(&mut self, key: TaskKey, addr: GuestAddr, buf: &mut [u8]) -> Result<(), PlatformError> {
        let pid = self.task(key)?.tracee.pid;
        vm_io(pid, addr, buf.as_mut_ptr(), buf.len(), false)
    }

    fn write(&mut self, key: TaskKey, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError> {
        let pid = self.task(key)?.tracee.pid;
        vm_io(pid, addr, data.as_ptr() as *mut u8, data.len(), true)
    }

    fn map(
        &mut self,
        key: TaskKey,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
        sharing: Sharing,
    ) -> Result<(), PlatformError> {
        self.check_range(addr, len)?;
        let kind = match sharing {
            Sharing::Private => MAP_PRIVATE,
            Sharing::Shared => MAP_SHARED,
        };
        let flags = kind | MAP_ANONYMOUS | MAP_FIXED;
        let prot = u64::from(prot.0 & Prot::ALL.0);
        let args = [addr, len, prot, flags, u64::MAX, 0];
        let ret = self.checked_inject(key, "mmap", self.nr_mmap, args)?;
        if ret as u64 != addr {
            return Err(self.violation(key, format!("mmap returned {ret:#x}, not {addr:#x}")));
        }
        Ok(())
    }

    fn unmap(&mut self, key: TaskKey, addr: GuestAddr, len: u64) -> Result<(), PlatformError> {
        self.check_range(addr, len)?;
        self.checked_inject(key, "munmap", self.nr_munmap, [addr, len, 0, 0, 0, 0])?;
        Ok(())
    }

    fn protect(
        &mut self,
        key: TaskKey,
        addr: GuestAddr,
        len: u64,
        prot: Prot,
    ) -> Result<(), PlatformError> {
        self.check_range(addr, len)?;
        let prot = u64::from(prot.0 & Prot::ALL.0);
        self.checked_inject(
            key,
            "mprotect",
            self.nr_mprotect,
            [addr, len, prot, 0, 0, 0],
        )?;
        Ok(())
    }
}

impl Drop for SeccompPlatform {
    fn drop(&mut self) {
        let keys: Vec<_> = self.tasks.keys().copied().collect();
        for key in keys {
            let _ = self.kill(key);
        }
    }
}

/// Ends every app process of a sandbox from any thread. See
/// [`SeccompPlatform::killer`].
#[derive(Clone, Debug)]
pub struct AppKiller {
    registry: Arc<Mutex<Registry>>,
}

impl AppKiller {
    /// Kills every app process, and every one created from now on.
    /// [`Platform::wait`] then reports them as [`Trap::Gone`]. Processes
    /// that already ended are not affected: a pidfd never names another
    /// process.
    pub fn kill(&self) -> io::Result<()> {
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        registry.killed = true;
        for pidfd in registry.pidfds.values() {
            send_kill(pidfd);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maps(p: &SeccompPlatform, key: TaskKey) -> String {
        std::fs::read_to_string(format!("/proc/{}/maps", p.host_pid(key).unwrap())).unwrap()
    }

    #[test]
    fn starts_with_only_the_stub() {
        let mut p = SeccompPlatform::new().unwrap();
        let key = p.spawn().unwrap();
        let maps = maps(&p, key);
        let lines: Vec<_> = maps
            .lines()
            .filter(|l| !l.ends_with("[vsyscall]"))
            .collect();
        assert_eq!(lines.len(), 1, "{maps}");
        assert!(
            lines[0].starts_with(&format!("{:x}-", stub::STUB_BASE)),
            "{maps}"
        );
        let info = p.address_space();
        assert!(info.max_addr > stub::STUB_BASE + stub::STUB_RESERVED);
    }

    #[test]
    fn map_protect_unmap_and_memory_access() {
        let mut p = SeccompPlatform::new().unwrap();
        let t = p.spawn().unwrap();
        let page = p.address_space().page_size;
        let addr = 0x2000_0000;
        p.map(t, addr, 4 * page, Prot::RW, Sharing::Private)
            .unwrap();
        p.write(t, addr + 10, b"hello").unwrap();
        let mut buf = [0; 5];
        p.read(t, addr + 10, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        p.protect(t, addr, page, Prot::READ).unwrap();
        assert!(p.write(t, addr, b"x").is_err(), "page is read-only");
        p.unmap(t, addr + page, page).unwrap();
        assert!(p.read(t, addr + page, &mut buf).is_err());
        let maps = maps(&p, t);
        assert!(
            maps.contains(&format!("{:x}-{:x} r--p", addr, addr + page)),
            "{maps}"
        );
        assert!(
            maps.contains(&format!("{:x}-{:x} rw-p", addr + 2 * page, addr + 4 * page)),
            "{maps}"
        );
    }

    #[test]
    fn refuses_ranges_outside_the_app_area() {
        let mut p = SeccompPlatform::new().unwrap();
        let t = p.spawn().unwrap();
        let page = p.address_space().page_size;
        assert!(p
            .map(t, stub::STUB_BASE, page, Prot::RW, Sharing::Private)
            .is_err());
        assert!(p.map(t, 0, page, Prot::RW, Sharing::Private).is_err());
        assert!(p
            .map(t, 0x2000_0001, page, Prot::RW, Sharing::Private)
            .is_err());
        assert!(p.unmap(t, u64::MAX - page + 1, page).is_err());
        // The stub is still there and working.
        p.map(t, 0x2000_0000, page, Prot::RW, Sharing::Private)
            .unwrap();
    }

    #[test]
    fn fork_copies_and_shares_memory() {
        let mut p = SeccompPlatform::new().unwrap();
        let parent = p.spawn().unwrap();
        let page = p.address_space().page_size;
        let private = 0x2000_0000;
        let shared = 0x3000_0000;
        p.map(parent, private, page, Prot::RW, Sharing::Private)
            .unwrap();
        p.map(parent, shared, page, Prot::RW, Sharing::Shared)
            .unwrap();
        p.write(parent, private, b"before").unwrap();
        let forked = p.clone_task(parent, false).unwrap();
        let thread = p.clone_task(parent, true).unwrap();
        assert_ne!(p.host_pid(forked), p.host_pid(parent));
        p.write(parent, private, b"parent").unwrap();
        p.write(forked, shared, b"forked").unwrap();
        let mut buf = [0; 6];
        p.read(forked, private, &mut buf).unwrap();
        assert_eq!(&buf, b"before", "copy-on-write");
        p.read(thread, private, &mut buf).unwrap();
        assert_eq!(&buf, b"parent", "same address space");
        p.read(parent, shared, &mut buf).unwrap();
        assert_eq!(&buf, b"forked", "MAP_SHARED stays shared across fork");
        // Injection works in the new processes too.
        p.map(forked, 0x4000_0000, page, Prot::RW, Sharing::Private)
            .unwrap();
        assert!(p.read(parent, 0x4000_0000, &mut buf).is_err());
        p.map(thread, 0x5000_0000, page, Prot::RW, Sharing::Private)
            .unwrap();
        p.read(parent, 0x5000_0000, &mut buf).unwrap();
        p.kill(parent).unwrap();
        p.read(thread, private, &mut buf).unwrap();
        assert_eq!(p.task_count(), 2);
    }

    /// Code that loops forever at `addr`: `b .` / `jmp .`.
    fn spin_at(p: &mut SeccompPlatform, t: TaskKey, addr: u64) {
        let page = p.address_space().page_size;
        #[cfg(target_arch = "aarch64")]
        let code = [0x00, 0x00, 0x00, 0x14];
        #[cfg(target_arch = "x86_64")]
        let code = [0xeb, 0xfe];
        p.map(t, addr, 2 * page, Prot::RW, Sharing::Private)
            .unwrap();
        p.write(t, addr, &code).unwrap();
        p.protect(t, addr, page, Prot::READ.union(Prot::EXEC))
            .unwrap();
    }

    #[test]
    fn interrupt_stops_a_spinning_task() {
        let mut p = SeccompPlatform::new().unwrap();
        let t = p.spawn().unwrap();
        let page = p.address_space().page_size;
        let addr = 0x2000_0000;
        spin_at(&mut p, t, addr);
        p.resume(
            t,
            Resume::Start {
                entry: addr,
                stack: addr + 2 * page,
            },
        )
        .unwrap();
        assert_eq!(p.wait(Some(Duration::from_millis(50))).unwrap(), None);
        p.interrupt(t).unwrap();
        let event = p.wait(Some(Duration::from_secs(10))).unwrap().unwrap();
        assert_eq!(
            event,
            Event {
                task: t,
                trap: Trap::Interrupted
            }
        );
        assert_eq!(p.context(t).unwrap().pc(), addr);
        // Resuming continues the loop.
        p.resume(t, Resume::Continue).unwrap();
        assert_eq!(p.wait(Some(Duration::from_millis(50))).unwrap(), None);
    }

    #[test]
    fn killer_ends_every_task() {
        let mut p = SeccompPlatform::new().unwrap();
        let t = p.spawn().unwrap();
        let page = p.address_space().page_size;
        let addr = 0x2000_0000;
        spin_at(&mut p, t, addr);
        let u = p.clone_task(t, false).unwrap();
        let mut context = p.context(t).unwrap();
        context.set_pc(addr);
        p.resume(
            t,
            Resume::Start {
                entry: addr,
                stack: addr + 2 * page,
            },
        )
        .unwrap();
        p.set_context(u, &context).unwrap();
        p.resume(u, Resume::Continue).unwrap();
        let killer = p.killer();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            killer.kill().unwrap();
            killer
        });
        let mut gone = Vec::new();
        while gone.len() < 2 {
            let event = p.wait(Some(Duration::from_secs(10))).unwrap();
            if let Some(Event {
                task,
                trap: Trap::Gone,
            }) = event
            {
                gone.push(task);
            }
        }
        gone.sort();
        let mut expected = vec![t, u];
        expected.sort();
        assert_eq!(gone, expected);
        // Killing again, and spawning after the kill, end at once.
        let killer = thread.join().unwrap();
        killer.kill().unwrap();
        assert_eq!(p.task_count(), 0);
    }
}
