//! [`SeccompApp`], the seccomp implementation of the platform traits.

use std::ffi::OsString;
use std::io;
use std::path::Path;

use cansol_core::platform::{
    AddressSpace, AppMemory, Fault, GuestAddr, Platform, PlatformError, Prot, Resume, SyscallTrap,
    Trap,
};
use cansol_core::Arch;

use crate::notify::{Child, Event};
use crate::spawn;
use crate::sys;

#[derive(Debug)]
enum State {
    /// Spawned, waiting for `Resume::Start`; holds the first event.
    NotStarted(Event),
    /// Blocked in the syscall with this notification id.
    InSyscall(u64),
    /// The process is gone.
    Dead,
}

/// An app running as a child process under a seccomp filter.
#[derive(Debug)]
pub struct SeccompApp {
    child: Child,
    arch: Arch,
    state: State,
}

impl SeccompApp {
    /// Starts `program` with arguments `argv` (including `argv[0]`) and an
    /// empty environment. The app is stopped before it runs any code that
    /// makes a syscall; it continues on the first [`Platform::run`].
    ///
    /// The host kernel builds the app's initial stack and loads the ELF
    /// image here (via `execve`). In U1 the kernel core takes this over.
    pub fn spawn(program: &Path, argv: &[OsString]) -> io::Result<SeccompApp> {
        let arch = Arch::native().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "unsupported host architecture")
        })?;
        let spawned = spawn::spawn(arch, program, argv)?;
        Ok(SeccompApp {
            child: spawned.child,
            arch,
            state: State::NotStarted(spawned.first),
        })
    }

    /// The host pid of the app process.
    pub fn pid(&self) -> libc::pid_t {
        self.child.pid
    }

    fn trap_for(&mut self, event: Event) -> Result<Trap, PlatformError> {
        match event {
            Event::Syscall(notif) => {
                if notif.pid as libc::pid_t != self.child.pid {
                    // Impossible while clone() is not emulated.
                    return Err(PlatformError::AppGone(format!(
                        "syscall from unknown task {}",
                        notif.pid
                    )));
                }
                // The filter kills on any other arch, so this always holds.
                debug_assert_eq!(notif.data.arch, sys::audit_arch(self.arch));
                self.state = State::InSyscall(notif.id);
                Ok(Trap::Syscall(SyscallTrap {
                    nr: u64::from(notif.data.nr as u32),
                    args: notif.data.args,
                }))
            }
            Event::Died(status) => {
                self.state = State::Dead;
                if libc::WIFSIGNALED(status) {
                    Ok(Trap::Fault(Fault {
                        signal: libc::WTERMSIG(status) as u32,
                        fatal: true,
                    }))
                } else {
                    // Every exit is trapped and emulated, so the process can
                    // only end by a signal. Anything else is a bug.
                    Err(PlatformError::AppGone(format!(
                        "app process ended on the host with wait status {status:#x}"
                    )))
                }
            }
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
        let n = unsafe { libc::process_vm_readv(self.child.pid, &local, 1, &remote, 1, 0) };
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
        let n = unsafe { libc::process_vm_writev(self.child.pid, &local, 1, &remote, 1, 0) };
        if n != data.len() as isize {
            return Err(PlatformError::BadAddress {
                addr,
                len: data.len(),
            });
        }
        Ok(())
    }
}

/// The host kernel owns the app's address space on this platform, and with
/// user notification the kernel process cannot make the app call `mmap`.
/// Implementing these needs a syscall-injection stub in the app (U1).
impl AddressSpace for SeccompApp {
    fn map(&mut self, _addr: GuestAddr, _len: u64, _prot: Prot) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("map"))
    }

    fn unmap(&mut self, _addr: GuestAddr, _len: u64) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("unmap"))
    }

    fn protect(&mut self, _addr: GuestAddr, _len: u64, _prot: Prot) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("protect"))
    }
}

impl Platform for SeccompApp {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn run(&mut self, resume: Resume) -> Result<Trap, PlatformError> {
        let state = std::mem::replace(&mut self.state, State::Dead);
        let event = match (state, resume) {
            (State::NotStarted(first), Resume::Start) => first,
            (State::InSyscall(id), Resume::Return(ret)) => {
                self.child.reply(id, ret)?;
                self.child.next_event()?
            }
            (State::Dead, _) => return Err(PlatformError::AppGone("already ended".into())),
            (state, resume) => {
                panic!("run({resume:?}) does not fit app state {state:?}");
            }
        };
        self.trap_for(event)
    }

    fn terminate(&mut self) -> Result<(), PlatformError> {
        self.state = State::Dead;
        self.child.kill()?;
        Ok(())
    }
}
