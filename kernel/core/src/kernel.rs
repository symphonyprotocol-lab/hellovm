//! The kernel run loop.

use std::fmt;

use crate::arch::{Arch, Sysno};
use crate::errno::MAX_ERRNO;
use crate::host::Host;
use crate::platform::{Platform, PlatformError, Resume, SyscallTrap, Trap};
use crate::syscall::{self, Action};

/// How an app ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// The app called `exit` or `exit_group` with this status (0..=255).
    Exited(i32),
    /// The app was killed by this Linux signal.
    Signaled(u32),
}

#[derive(Debug)]
pub enum KernelError {
    Platform(PlatformError),
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Platform(err) => write!(f, "platform: {err}"),
        }
    }
}

impl std::error::Error for KernelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KernelError::Platform(err) => Some(err),
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
    Exited(i32),
}

/// One entry of the syscall trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallRecord {
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
            Outcome::Returned(ret) => write!(f, " = {ret}"),
            Outcome::Exited(_) => f.write_str(" = ?"),
        }
    }
}

/// A kernel instance serving one app.
pub struct Kernel<H> {
    host: H,
    trace: Option<Vec<SyscallRecord>>,
}

impl<H: Host> Kernel<H> {
    pub fn new(host: H) -> Self {
        Kernel { host, trace: None }
    }

    /// Records every syscall the app makes; see [`Kernel::trace`].
    pub fn with_trace(mut self) -> Self {
        self.trace = Some(Vec::new());
        self
    }

    /// The syscalls handled so far, if tracing is on.
    pub fn trace(&self) -> &[SyscallRecord] {
        self.trace.as_deref().unwrap_or(&[])
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn into_host(self) -> H {
        self.host
    }

    /// Runs the app until it exits or dies, handling all of its syscalls.
    pub fn run<P: Platform + ?Sized>(&mut self, app: &mut P) -> Result<ExitStatus, KernelError> {
        let arch = app.arch();
        let mut resume = Resume::Start;
        loop {
            let trap = match app.run(resume)? {
                Trap::Syscall(trap) => trap,
                Trap::Fault(fault) => {
                    if !fault.fatal {
                        // No signal delivery yet: a fault ends the app, as an
                        // unhandled fault does on Linux.
                        app.terminate()?;
                    }
                    return Ok(ExitStatus::Signaled(fault.signal));
                }
            };
            let sysno = arch.sysno(trap.nr);
            let action = syscall::dispatch(&mut self.host, app, sysno, &trap);
            self.record(arch, sysno, &trap, action);
            match action {
                Action::Return(ret) => resume = Resume::Return(ret),
                Action::Exit(status) => {
                    app.terminate()?;
                    return Ok(ExitStatus::Exited(status));
                }
            }
        }
    }

    fn record(&mut self, arch: Arch, sysno: Option<Sysno>, trap: &SyscallTrap, action: Action) {
        let record = SyscallRecord {
            arch,
            nr: trap.nr,
            sysno,
            args: trap.args,
            outcome: match action {
                Action::Return(ret) => Outcome::Returned(ret),
                Action::Exit(status) => Outcome::Exited(status),
            },
        };
        log::debug!("{record}");
        if let Some(trace) = &mut self.trace {
            trace.push(record);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;

    use super::*;
    use crate::errno::{EBADF, EFAULT, ENOSYS};
    use crate::host::ConsoleStream;
    use crate::platform::{AddressSpace, AppMemory, Fault, GuestAddr, Prot};
    use crate::syscall::MAX_WRITE;

    #[derive(Default)]
    struct Capture {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    impl Host for Capture {
        fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize> {
            match stream {
                ConsoleStream::Stdout => self.stdout.extend_from_slice(data),
                ConsoleStream::Stderr => self.stderr.extend_from_slice(data),
            }
            Ok(data.len())
        }
    }

    /// A scripted app: a fixed list of traps and one block of memory.
    struct MockApp {
        arch: Arch,
        traps: VecDeque<Trap>,
        mem_base: GuestAddr,
        mem: Vec<u8>,
        returns: Vec<i64>,
        terminated: bool,
    }

    impl MockApp {
        fn new(arch: Arch, mem: &[u8], traps: Vec<Trap>) -> Self {
            MockApp {
                arch,
                traps: traps.into(),
                mem_base: 0x10000,
                mem: mem.to_vec(),
                returns: Vec::new(),
                terminated: false,
            }
        }

        fn syscall(arch: Arch, sysno: Sysno, args: &[u64]) -> Trap {
            let mut all = [0; 6];
            all[..args.len()].copy_from_slice(args);
            Trap::Syscall(SyscallTrap {
                nr: arch.syscall_nr(sysno).unwrap(),
                args: all,
            })
        }
    }

    impl AppMemory for MockApp {
        fn read(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), PlatformError> {
            let bad = PlatformError::BadAddress {
                addr,
                len: buf.len(),
            };
            let start = addr.checked_sub(self.mem_base).ok_or(bad)? as usize;
            let src = self
                .mem
                .get(start..start + buf.len())
                .ok_or(PlatformError::BadAddress {
                    addr,
                    len: buf.len(),
                })?;
            buf.copy_from_slice(src);
            Ok(())
        }

        fn write(&mut self, _addr: GuestAddr, _data: &[u8]) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported("mock write"))
        }
    }

    impl AddressSpace for MockApp {
        fn map(&mut self, _: GuestAddr, _: u64, _: Prot) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported("map"))
        }
        fn unmap(&mut self, _: GuestAddr, _: u64) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported("unmap"))
        }
        fn protect(&mut self, _: GuestAddr, _: u64, _: Prot) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported("protect"))
        }
    }

    impl Platform for MockApp {
        fn arch(&self) -> Arch {
            self.arch
        }

        fn run(&mut self, resume: Resume) -> Result<Trap, PlatformError> {
            assert!(!self.terminated);
            if let Resume::Return(ret) = resume {
                self.returns.push(ret);
            }
            self.traps
                .pop_front()
                .ok_or_else(|| PlatformError::AppGone("script ended".into()))
        }

        fn terminate(&mut self) -> Result<(), PlatformError> {
            self.terminated = true;
            Ok(())
        }
    }

    #[test]
    fn write_and_exit_on_every_arch() {
        for arch in Arch::ALL {
            let base = 0x10000;
            let traps = vec![
                MockApp::syscall(arch, Sysno::Write, &[1, base, 5]),
                MockApp::syscall(arch, Sysno::Write, &[2, base + 6, 5]),
                MockApp::syscall(arch, Sysno::ExitGroup, &[0x1_07]),
            ];
            let mut app = MockApp::new(arch, b"hello world", traps);
            let mut kernel = Kernel::new(Capture::default()).with_trace();
            assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Exited(7));
            assert!(app.terminated);
            assert_eq!(app.returns, vec![5, 5]);
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
            MockApp::syscall(arch, Sysno::Write, &[3, 0x10000, 1]),
            MockApp::syscall(arch, Sysno::Write, &[1, 0x20000, 1]),
            MockApp::syscall(arch, Sysno::Write, &[1, 0x10000, 0]),
            MockApp::syscall(arch, Sysno::Exit, &[0]),
        ];
        let mut app = MockApp::new(arch, b"x", traps);
        let mut kernel = Kernel::new(Capture::default());
        assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Exited(0));
        assert_eq!(app.returns, vec![-EBADF, -EFAULT, 0]);
        assert!(kernel.host().stdout.is_empty());
    }

    #[test]
    fn large_write_is_short() {
        let arch = Arch::X86_64;
        let mem = vec![b'a'; MAX_WRITE + 10];
        let traps = vec![
            MockApp::syscall(arch, Sysno::Write, &[1, 0x10000, mem.len() as u64]),
            MockApp::syscall(arch, Sysno::Exit, &[0]),
        ];
        let mut app = MockApp::new(arch, &mem, traps);
        let mut kernel = Kernel::new(Capture::default());
        kernel.run(&mut app).unwrap();
        assert_eq!(app.returns, vec![MAX_WRITE as i64]);
    }

    #[test]
    fn everything_else_is_enosys() {
        for arch in Arch::ALL {
            let traps = vec![
                MockApp::syscall(arch, Sysno::Getpid, &[]),
                MockApp::syscall(arch, Sysno::Execve, &[0x10000, 0, 0]),
                Trap::Syscall(SyscallTrap {
                    nr: 100_000,
                    args: [0; 6],
                }),
                MockApp::syscall(arch, Sysno::ExitGroup, &[38]),
            ];
            let mut app = MockApp::new(arch, b"", traps);
            let mut kernel = Kernel::new(Capture::default()).with_trace();
            assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Exited(38));
            assert_eq!(app.returns, vec![-ENOSYS; 3]);
            assert_eq!(kernel.trace()[2].sysno, None);
        }
    }

    #[test]
    fn fault_ends_the_app() {
        let traps = vec![Trap::Fault(Fault {
            signal: 11,
            fatal: true,
        })];
        let mut app = MockApp::new(Arch::X86_64, b"", traps);
        let mut kernel = Kernel::new(Capture::default());
        assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Signaled(11));
    }

    #[test]
    fn trace_format() {
        let record = SyscallRecord {
            arch: Arch::X86_64,
            nr: 1,
            sysno: Some(Sysno::Write),
            args: [1, 0x400100, 13, 0, 0, 0],
            outcome: Outcome::Returned(13),
        };
        assert_eq!(record.to_string(), "write(1, 0x400100, 13) = 13");
        let record = SyscallRecord {
            sysno: Some(Sysno::Getpid),
            nr: 39,
            outcome: Outcome::Returned(-ENOSYS),
            ..record
        };
        assert_eq!(record.to_string(), "getpid() = -1 (errno 38)");
    }
}
