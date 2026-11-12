//! [`SeccompApp`], the seccomp implementation of the platform traits.

use std::io;
use std::marker::PhantomData;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use hellovm_core::platform::{
    AddressSpace, AddressSpaceInfo, AppMemory, CpuInfo, Fault, GuestAddr, Platform, PlatformError,
    Prot, Resume, SyscallTrap, Trap,
};
use hellovm_core::{Arch, Sysno};

use crate::regs::{Regs, SYSCALL_INSN_LEN};
use crate::spawn;
use crate::stub;
use crate::sys;
use crate::tracer::{Run, Stop, Tracee};

/// Linux `mmap` flags used for injected mappings.
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;

/// The lowest address the core may map. Linux refuses user mappings below
/// `vm.mmap_min_addr`, whose usual default is 64 KiB.
const MIN_ADDR: u64 = 0x1_0000;

#[derive(Debug)]
enum State {
    /// At a syscall-exit stop of a syscall the kernel process made the app
    /// execute (the bootstrap `execveat` or an injected call). The app
    /// resumes with `saved`.
    AtExit { saved: Regs },
    /// At the seccomp stop of an app syscall, which has not run.
    AtEntry { regs: Regs },
    /// At a signal-delivery stop; the app can only be terminated.
    AtSignal,
    /// The process is gone.
    Dead,
}

/// An app running as a traced child process under a seccomp filter.
///
/// It must be used from the thread that created it (a ptrace rule), so it is
/// neither `Send` nor `Sync`.
#[derive(Debug)]
pub struct SeccompApp {
    tracee: Tracee,
    /// A pidfd of the app process, shared with every [`AppKiller`].
    pidfd: Arc<OwnedFd>,
    arch: Arch,
    state: State,
    started: bool,
    info: AddressSpaceInfo,
    hwcap: CpuInfo,
    thread_pointer: Option<u64>,
    nr_mmap: u64,
    nr_munmap: u64,
    nr_mprotect: u64,
    _not_send: PhantomData<*const ()>,
}

impl SeccompApp {
    /// Starts an app process with an empty address space (apart from the
    /// platform's reserved stub page). The core loads a program into it and
    /// starts it with [`Resume::Start`].
    pub fn new() -> io::Result<SeccompApp> {
        let arch = Arch::native().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "unsupported host architecture")
        })?;
        let spawned = spawn::spawn(arch)?;
        // The process is our unreaped child, so the pid cannot have been
        // reused: the pidfd names the app for good.
        // SAFETY: plain syscall; a non-negative result is a new fd we own.
        let pidfd = unsafe {
            let fd = libc::syscall(libc::SYS_pidfd_open, spawned.tracee.pid, 0);
            if fd < 0 {
                let err = io::Error::last_os_error();
                return Err(io::Error::new(err.kind(), format!("pidfd_open: {err}")));
            }
            OwnedFd::from_raw_fd(fd as i32)
        };
        let page_size = sys::page_size();
        let number = |sysno: Sysno| arch.syscall_nr(sysno).expect("generic syscall");
        let max_addr = spawned.top & !(page_size - 1);
        let stub_range = stub::STUB_BASE..stub::STUB_BASE + stub::STUB_RESERVED;
        let mut app = SeccompApp {
            tracee: spawned.tracee,
            pidfd: Arc::new(pidfd),
            arch,
            state: State::AtExit {
                saved: spawned.regs,
            },
            started: false,
            info: AddressSpaceInfo {
                page_size,
                min_addr: MIN_ADDR.max(page_size),
                max_addr,
                reserved: vec![stub_range],
            },
            hwcap: host_cpu_info(),
            thread_pointer: None,
            nr_mmap: number(Sysno::Mmap),
            nr_munmap: number(Sysno::Munmap),
            nr_mprotect: number(Sysno::Mprotect),
            _not_send: PhantomData,
        };
        for &(start, len) in &spawned.foreign {
            let ret = app
                .inject(app.nr_munmap, [start, len, 0, 0, 0, 0])
                .map_err(|err| {
                    io::Error::other(format!("clearing the app address space: {err}"))
                })?;
            if ret != 0 {
                return Err(io::Error::other(format!(
                    "clearing the app address space: munmap({start:#x}, {len:#x}) = {ret}"
                )));
            }
        }
        let (left, _) = spawn::foreign_mappings(app.tracee.pid)?;
        if !left.is_empty() {
            return Err(io::Error::other(format!(
                "host mappings left in the app address space: {left:#x?}"
            )));
        }
        Ok(app)
    }

    /// The host pid of the app process.
    pub fn pid(&self) -> libc::pid_t {
        self.tracee.pid
    }

    /// A handle that ends the app from any thread, for timeouts and
    /// cancellation: the app may be running code that never makes a
    /// syscall, and then the thread driving it is blocked in
    /// [`Platform::run`].
    pub fn killer(&self) -> AppKiller {
        AppKiller {
            pidfd: Arc::clone(&self.pidfd),
        }
    }

    /// The app process is gone (a ptrace request failed with `ESRCH`):
    /// reaps it and reports how it ended.
    fn gone(&mut self) -> Result<Trap, PlatformError> {
        loop {
            match self.tracee.wait()? {
                Stop::Killed(sig) => return Ok(self.killed(sig)),
                Stop::Exited(code) => {
                    self.state = State::Dead;
                    return Err(PlatformError::AppGone(format!("exited with {code}")));
                }
                // Stops queued before it died.
                _ => continue,
            }
        }
    }

    fn killed(&mut self, sig: i32) -> Trap {
        self.state = State::Dead;
        Trap::Fault(Fault {
            signal: sig as u32,
            addr: None,
            fatal: true,
        })
    }

    fn kill(&mut self) {
        self.state = State::Dead;
        let _ = self.tracee.kill();
    }

    fn violation(&mut self, what: String) -> PlatformError {
        self.kill();
        PlatformError::Violation(what)
    }

    /// Moves from a seccomp stop to a syscall-exit stop by skipping the app
    /// syscall, so that syscalls can be injected.
    fn enter_exit_stop(&mut self) -> Result<(), PlatformError> {
        match self.state {
            State::AtExit { .. } => Ok(()),
            State::AtEntry { regs } => {
                self.tracee.skip_syscall(&regs, 0)?;
                self.tracee.resume(Run::Syscall, 0)?;
                match self.wait_quietly(Run::Syscall)? {
                    Stop::SyscallExit => {
                        self.state = State::AtExit { saved: regs };
                        Ok(())
                    }
                    stop => Err(self.violation(format!("unexpected stop {stop:?} at skip"))),
                }
            }
            State::AtSignal => Err(PlatformError::Unsupported("resuming after a signal")),
            State::Dead => Err(PlatformError::AppGone("already ended".into())),
        }
    }

    /// Waits for the next stop, suppressing signals that do not affect the
    /// app (see [`ignored_signal`]). Other signals are not expected while
    /// the kernel process drives the app; they end it.
    ///
    /// `run` is how the tracee was resumed; it is resumed the same way after
    /// a suppressed signal.
    fn wait_quietly(&mut self, run: Run) -> Result<Stop, PlatformError> {
        loop {
            match self.tracee.wait()? {
                Stop::Signal(sig) if ignored_signal(sig) => {
                    self.tracee.resume(run, 0)?;
                }
                Stop::Killed(sig) => {
                    self.state = State::Dead;
                    return Err(PlatformError::AppGone(format!("killed by signal {sig}")));
                }
                Stop::Exited(code) => {
                    self.state = State::Dead;
                    return Err(PlatformError::AppGone(format!("exited with {code}")));
                }
                stop => return Ok(stop),
            }
        }
    }

    /// Makes the app execute syscall `nr` with `args` from the stub and
    /// returns the raw result. The app's own registers are restored when it
    /// resumes.
    fn inject(&mut self, nr: u64, args: [u64; 6]) -> Result<i64, PlatformError> {
        self.enter_exit_stop()?;
        let State::AtExit { saved } = self.state else {
            unreachable!("enter_exit_stop leaves the app at an exit stop");
        };
        let mut regs = saved;
        regs.prepare_syscall(stub::STUB_SYSCALL, nr, args);
        self.tracee.set_regs(&regs)?;
        self.tracee.resume(Run::Cont, 0)?;
        match self.wait_quietly(Run::Cont)? {
            Stop::Seccomp => {}
            stop => return Err(self.violation(format!("injected syscall: unexpected {stop:?}"))),
        }
        // Only the exact syscall prepared above may run.
        let at = self.tracee.regs()?;
        if at.pc() != stub::STUB_SYSCALL + SYSCALL_INSN_LEN || at.syscall() != (nr, args) {
            let what = format!(
                "injected syscall {nr} {args:#x?} stopped as {:?} at {:#x}",
                at.syscall(),
                at.pc()
            );
            return Err(self.violation(what));
        }
        self.tracee.resume(Run::Syscall, 0)?;
        match self.wait_quietly(Run::Syscall)? {
            Stop::SyscallExit => {}
            stop => return Err(self.violation(format!("injected syscall: unexpected {stop:?}"))),
        }
        Ok(self.tracee.regs()?.ret())
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
        what: &str,
        nr: u64,
        args: [u64; 6],
    ) -> Result<i64, PlatformError> {
        let ret = self.inject(nr, args)?;
        if (-4095..0).contains(&ret) {
            // A host errno: for the kernel process's log only.
            return Err(PlatformError::Host(io::Error::new(
                io::Error::from_raw_os_error((-ret) as i32).kind(),
                format!(
                    "{what} in the app process failed: {}",
                    io::Error::from_raw_os_error((-ret) as i32)
                ),
            )));
        }
        Ok(ret)
    }

    fn trap(&mut self) -> Result<Trap, PlatformError> {
        loop {
            match self.tracee.wait()? {
                Stop::Signal(sig) if ignored_signal(sig) => {
                    self.tracee.resume(Run::Cont, 0)?;
                }
                Stop::Seccomp => {
                    let regs = self.tracee.regs()?;
                    let (nr, args) = regs.syscall();
                    self.state = State::AtEntry { regs };
                    return Ok(Trap::Syscall(SyscallTrap { nr, args }));
                }
                Stop::Signal(sig) => {
                    let addr = self.tracee.fault_addr(sig);
                    self.state = State::AtSignal;
                    return Ok(Trap::Fault(Fault {
                        signal: sig as u32,
                        addr,
                        fatal: false,
                    }));
                }
                // Killed from outside the sandbox, e.g. by an
                // [`AppKiller`]: the app ended by that signal.
                Stop::Killed(sig) => return Ok(self.killed(sig)),
                Stop::Exited(code) => {
                    self.state = State::Dead;
                    return Err(PlatformError::AppGone(format!("exited with {code}")));
                }
                stop => return Err(self.violation(format!("unexpected stop {stop:?}"))),
            }
        }
    }
}

/// Signals whose default action is to do nothing. The app cannot have
/// handlers (signal delivery is not emulated yet) and never sees them.
fn ignored_signal(sig: i32) -> bool {
    matches!(
        sig,
        libc::SIGCHLD
            | libc::SIGCONT
            | libc::SIGURG
            | libc::SIGWINCH
            | libc::SIGSTOP
            | libc::SIGTSTP
            | libc::SIGTTIN
            | libc::SIGTTOU
    )
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

impl AppMemory for SeccompApp {
    fn read(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), PlatformError> {
        if buf.is_empty() {
            return Ok(());
        }
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: `local` describes `buf`, which is writable for its length;
        // `remote` is only interpreted in the app process.
        let n = unsafe { libc::process_vm_readv(self.tracee.pid, &local, 1, &remote, 1, 0) };
        if n != buf.len() as isize {
            return Err(PlatformError::BadAddress {
                addr,
                len: buf.len(),
            });
        }
        Ok(())
    }

    fn write(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), PlatformError> {
        if data.is_empty() {
            return Ok(());
        }
        let local = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: data.len(),
        };
        // SAFETY: `local` describes `data`, which is only read; `remote` is
        // only interpreted in the app process.
        let n = unsafe { libc::process_vm_writev(self.tracee.pid, &local, 1, &remote, 1, 0) };
        if n != data.len() as isize {
            return Err(PlatformError::BadAddress {
                addr,
                len: data.len(),
            });
        }
        Ok(())
    }
}

/// Address-space changes are injected syscalls; see `spawn` for the
/// mechanism and its residual host-syscall surface.
impl AddressSpace for SeccompApp {
    fn map(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), PlatformError> {
        self.check_range(addr, len)?;
        let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
        let prot = u64::from(prot.0 & Prot::ALL.0);
        let args = [addr, len, prot, flags, u64::MAX, 0];
        let ret = self.checked_inject("mmap", self.nr_mmap, args)?;
        if ret as u64 != addr {
            return Err(self.violation(format!("mmap returned {ret:#x}, not {addr:#x}")));
        }
        Ok(())
    }

    fn unmap(&mut self, addr: GuestAddr, len: u64) -> Result<(), PlatformError> {
        self.check_range(addr, len)?;
        self.checked_inject("munmap", self.nr_munmap, [addr, len, 0, 0, 0, 0])?;
        Ok(())
    }

    fn protect(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), PlatformError> {
        self.check_range(addr, len)?;
        let prot = u64::from(prot.0 & Prot::ALL.0);
        self.checked_inject("mprotect", self.nr_mprotect, [addr, len, prot, 0, 0, 0])?;
        Ok(())
    }
}

impl Platform for SeccompApp {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn address_space(&self) -> AddressSpaceInfo {
        self.info.clone()
    }

    fn cpu_info(&self) -> CpuInfo {
        self.hwcap
    }

    fn set_thread_pointer(&mut self, value: u64) -> Result<(), PlatformError> {
        if self.arch != Arch::X86_64 {
            return Err(PlatformError::Unsupported("set_thread_pointer"));
        }
        self.thread_pointer = Some(value);
        Ok(())
    }

    fn run(&mut self, resume: Resume) -> Result<Trap, PlatformError> {
        match self.resume_app(resume) {
            // The app was killed while it was stopped for the kernel.
            Err(PlatformError::Host(err))
                if err.raw_os_error() == Some(libc::ESRCH)
                    && !matches!(self.state, State::Dead) =>
            {
                self.gone()
            }
            other => other,
        }
    }

    fn terminate(&mut self) -> Result<(), PlatformError> {
        self.state = State::Dead;
        self.tracee.kill()?;
        Ok(())
    }
}

/// Ends an app from any thread. See [`SeccompApp::killer`].
#[derive(Clone, Debug)]
pub struct AppKiller {
    pidfd: Arc<OwnedFd>,
}

impl AppKiller {
    /// Kills the app process. [`Platform::run`] then reports it as ended by
    /// `SIGKILL`. Does nothing if the app has already ended: the pidfd
    /// never names another process.
    pub fn kill(&self) -> io::Result<()> {
        // SAFETY: plain syscall on an fd we own.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(err);
            }
        }
        Ok(())
    }
}

impl SeccompApp {
    fn resume_app(&mut self, resume: Resume) -> Result<Trap, PlatformError> {
        let thread_pointer = self.thread_pointer.take();
        let with_tp = |mut regs: Regs| {
            if let Some(tp) = thread_pointer {
                regs.set_thread_pointer(tp);
            }
            regs
        };
        match (&self.state, resume) {
            (State::AtExit { saved }, Resume::Start { entry, stack }) if !self.started => {
                let mut regs = *saved;
                regs.start(entry, stack);
                self.tracee.set_regs(&with_tp(regs))?;
                self.started = true;
            }
            (State::AtExit { saved }, Resume::Return(ret)) if self.started => {
                let mut regs = with_tp(*saved);
                regs.set_ret(ret);
                self.tracee.set_regs(&regs)?;
            }
            (State::AtEntry { regs }, Resume::Return(ret)) => {
                self.tracee.skip_syscall(&with_tp(*regs), ret)?;
            }
            (State::Dead, _) => return Err(PlatformError::AppGone("already ended".into())),
            (state, resume) => {
                panic!("run({resume:?}) does not fit app state {state:?}");
            }
        }
        self.tracee.resume(Run::Cont, 0)?;
        self.trap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maps(app: &SeccompApp) -> String {
        std::fs::read_to_string(format!("/proc/{}/maps", app.pid())).unwrap()
    }

    #[test]
    fn starts_with_only_the_stub() {
        let app = SeccompApp::new().unwrap();
        let maps = maps(&app);
        let lines: Vec<_> = maps
            .lines()
            .filter(|l| !l.ends_with("[vsyscall]"))
            .collect();
        assert_eq!(lines.len(), 1, "{maps}");
        assert!(
            lines[0].starts_with(&format!("{:x}-", stub::STUB_BASE)),
            "{maps}"
        );
        let info = app.address_space();
        assert!(info.max_addr > stub::STUB_BASE + stub::STUB_RESERVED);
    }

    #[test]
    fn map_protect_unmap_and_memory_access() {
        let mut app = SeccompApp::new().unwrap();
        let page = app.address_space().page_size;
        let addr = 0x2000_0000;
        app.map(addr, 4 * page, Prot::RW).unwrap();
        app.write(addr + 10, b"hello").unwrap();
        let mut buf = [0; 5];
        app.read(addr + 10, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        app.protect(addr, page, Prot::READ).unwrap();
        assert!(app.write(addr, b"x").is_err(), "page is read-only");
        app.unmap(addr + page, page).unwrap();
        assert!(app.read(addr + page, &mut buf).is_err());
        let maps = maps(&app);
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
        let mut app = SeccompApp::new().unwrap();
        let page = app.address_space().page_size;
        assert!(app.map(stub::STUB_BASE, page, Prot::RW).is_err());
        assert!(app.map(0, page, Prot::RW).is_err());
        assert!(app.map(0x2000_0001, page, Prot::RW).is_err());
        assert!(app.unmap(u64::MAX - page + 1, page).is_err());
        // The stub is still there and working.
        app.map(0x2000_0000, page, Prot::RW).unwrap();
    }

    #[test]
    fn killer_ends_an_app_that_never_traps() {
        let mut app = SeccompApp::new().unwrap();
        let page = app.address_space().page_size;
        let addr = 0x2000_0000;
        // A branch to itself.
        #[cfg(target_arch = "aarch64")]
        let code = [0x00, 0x00, 0x00, 0x14];
        #[cfg(target_arch = "x86_64")]
        let code = [0xeb, 0xfe];
        app.map(addr, 2 * page, Prot::RW).unwrap();
        app.write(addr, &code).unwrap();
        app.protect(addr, page, Prot::READ.union(Prot::EXEC))
            .unwrap();
        let killer = app.killer();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            killer.kill().unwrap();
            killer
        });
        let trap = app
            .run(Resume::Start {
                entry: addr,
                stack: addr + 2 * page,
            })
            .unwrap();
        assert_eq!(
            trap,
            Trap::Fault(Fault {
                signal: libc::SIGKILL as u32,
                addr: None,
                fatal: true,
            })
        );
        // Killing an app that is gone is not an error.
        let killer = thread.join().unwrap();
        killer.kill().unwrap();
        assert!(matches!(
            app.run(Resume::Return(0)),
            Err(PlatformError::AppGone(_))
        ));
    }
}
