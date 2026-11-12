//! The kernel: one sandbox's filesystem and process, and the run loop.

use std::fmt;

use crate::arch::{Arch, Sysno};
use crate::elf::{self, ElfError, StackParams};
use crate::errno::{Errno, MAX_ERRNO};
use crate::fd::FdTable;
use crate::host::Host;
use crate::mm::Mm;
use crate::platform::{GuestAddr, Platform, PlatformError, Resume, SyscallTrap, Trap};
use crate::syscall::{self, Action};
use crate::vfs::{FileType, Ino, Timespec, Vfs};

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
    Exited(i32),
    Signaled(u32),
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
            Outcome::Returned(ret) if !(-4096..=4096).contains(&ret) => write!(f, " = {ret:#x}"),
            Outcome::Returned(ret) => write!(f, " = {ret}"),
            Outcome::Exited(_) | Outcome::Signaled(_) => f.write_str(" = ?"),
        }
    }
}

/// Default and maximum of a resource limit.
pub(crate) type Rlimit = (u64, u64);

pub(crate) const RLIM_INFINITY: u64 = u64::MAX;

/// The state of the app's (single) process.
#[derive(Clone, Debug)]
pub(crate) struct Process {
    pub mm: Option<Mm>,
    pub fds: FdTable,
    /// Current directory; held open in the VFS so it stays alive.
    pub cwd: Ino,
    pub umask: u32,
    /// `struct sigaction` of each signal (1..=64): handler, flags,
    /// restorer, mask.
    pub sigactions: [[u64; 4]; 64],
    pub sigmask: u64,
    /// `comm`, at most 15 bytes.
    pub name: Vec<u8>,
    pub start: Option<(GuestAddr, GuestAddr)>,
    pub rlimits: [Rlimit; 16],
    pub thread_pointer: u64,
}

impl Process {
    fn new(cwd: Ino) -> Process {
        let mut rlimits = [(RLIM_INFINITY, RLIM_INFINITY); 16];
        rlimits[3] = (crate::mm::STACK_SIZE, RLIM_INFINITY); // RLIMIT_STACK
        rlimits[4] = (0, RLIM_INFINITY); // RLIMIT_CORE
        rlimits[7] = (crate::fd::MAX_FDS as u64, crate::fd::MAX_FDS as u64); // RLIMIT_NOFILE
        rlimits[8] = (8 << 20, 8 << 20); // RLIMIT_MEMLOCK
        Process {
            mm: None,
            fds: FdTable::with_console(),
            cwd,
            umask: 0o022,
            sigactions: [[0; 4]; 64],
            sigmask: 0,
            name: Vec::new(),
            start: None,
            rlimits,
            thread_pointer: 0,
        }
    }
}

/// The current wall-clock time from the host, as a VFS timestamp.
pub(crate) fn now<H: Host + ?Sized>(host: &mut H) -> Timespec {
    let t = host.clock_realtime();
    Timespec {
        sec: t.as_secs() as i64,
        nsec: t.subsec_nanos(),
    }
}

/// A kernel instance serving one app: its filesystem and its process.
pub struct Kernel<H> {
    host: H,
    trace: Option<Vec<SyscallRecord>>,
    vfs: Vfs,
    proc: Process,
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
            proc: Process::new(root),
        }
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

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    pub fn into_host(self) -> H {
        self.host
    }

    /// Loads the program at `path` (in the sandbox filesystem) into `app`,
    /// which must have a fresh address space, and prepares it to start with
    /// `argv` and `envp`.
    pub fn exec<P: Platform + ?Sized>(
        &mut self,
        app: &mut P,
        path: &[u8],
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
    ) -> Result<(), KernelError> {
        let display = String::from_utf8_lossy(path).into_owned();
        let fail = |errno: Errno, reason: String| KernelError::Exec {
            path: display.clone(),
            errno,
            reason,
        };
        let errno_fail = |errno: Errno| {
            let reason = match errno.0 {
                crate::errno::ENOENT => "no such file or directory".to_string(),
                crate::errno::EACCES => "permission denied".to_string(),
                crate::errno::ENOTDIR => "not a directory".to_string(),
                crate::errno::ELOOP => "too many levels of symbolic links".to_string(),
                _ => format!("cannot load ({errno})"),
            };
            fail(errno, reason)
        };
        let ino = self
            .vfs
            .resolve(&mut self.host, self.proc.cwd, path, true)
            .map_err(errno_fail)?;
        if self.vfs.file_type(ino) != FileType::Regular || self.vfs.perm(ino) & 0o111 == 0 {
            return Err(errno_fail(Errno(crate::errno::EACCES)));
        }
        let file = self.vfs.read_all(&mut self.host, ino).map_err(errno_fail)?;
        let arch = app.arch();
        let elf_fail = |err: ElfError| fail(err.errno(), err.to_string());
        let parsed = elf::parse(&file, arch).map_err(elf_fail)?;
        let mut mm = Mm::new(&app.address_space());
        let image = elf::load(&mut mm, app, &file, &parsed).map_err(elf_fail)?;
        mm.set_brk_start(image.end);
        let mut random = [0u8; 16];
        self.host
            .random(&mut random)
            .map_err(|err| fail(Errno::from_host(&err), format!("no random bytes: {err}")))?;
        let params = StackParams {
            arch,
            argv,
            envp,
            execfn: path,
            image: &image,
            cpu: app.cpu_info(),
            random,
        };
        let sp = elf::build_stack(&mut mm, app, &params).map_err(errno_fail)?;
        let name = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
        self.proc.name = name[..name.len().min(15)].to_vec();
        self.proc.mm = Some(mm);
        self.proc.start = Some((image.entry, sp));
        log::debug!(
            "loaded {display}: entry {:#x}, stack {sp:#x}, brk {:#x}, bias {:#x}",
            image.entry,
            image.end,
            image.bias
        );
        Ok(())
    }

    /// Runs the loaded program until it exits or dies, handling all of its
    /// syscalls.
    pub fn run<P: Platform + ?Sized>(&mut self, app: &mut P) -> Result<ExitStatus, KernelError> {
        let (entry, stack) = self.proc.start.take().ok_or(KernelError::NoProgram)?;
        let arch = app.arch();
        let mut resume = Resume::Start { entry, stack };
        loop {
            let trap = match app.run(resume)? {
                Trap::Syscall(trap) => trap,
                Trap::Fault(fault) => {
                    log::info!(
                        "app stopped by signal {} (address {:x?})",
                        fault.signal,
                        fault.addr
                    );
                    if !fault.fatal {
                        // No signal delivery yet: a fault ends the app, as an
                        // unhandled fault does on Linux.
                        app.terminate()?;
                    }
                    return Ok(ExitStatus::Signaled(fault.signal));
                }
            };
            let sysno = arch.sysno(trap.nr);
            let action = syscall::dispatch(
                &mut syscall::Ctx {
                    host: &mut self.host,
                    app: &mut *app,
                    vfs: &mut self.vfs,
                    proc: &mut self.proc,
                    arch,
                },
                sysno,
                &trap,
            );
            self.record(arch, sysno, &trap, action);
            match action {
                Action::Return(ret) => resume = Resume::Return(ret),
                Action::Exit(status) => {
                    app.terminate()?;
                    return Ok(ExitStatus::Exited(status));
                }
                Action::Signal(signal) => {
                    app.terminate()?;
                    return Ok(ExitStatus::Signaled(signal));
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
                Action::Signal(signal) => Outcome::Signaled(signal),
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
    use super::*;
    use crate::elf::tests::sample;
    use crate::errno::{EBADF, EEXIST, EFAULT, ENOENT, ENOEXEC, ENOSYS, ENOTDIR};
    use crate::testutil::{MockApp, MockEntry, MockHost};

    const SCRATCH: u64 = 0x7000_0000;

    fn host_with_prog(arch: Arch) -> MockHost {
        MockHost::with_image(&[
            ("bin", MockEntry::Dir),
            ("bin/prog", MockEntry::File(sample(arch, 2, 0x40_0000))),
            ("etc", MockEntry::Dir),
            ("etc/motd", MockEntry::File(b"hello image\n".to_vec())),
            ("etc/link", MockEntry::Symlink(b"motd".to_vec())),
        ])
    }

    /// A kernel with /bin/prog loaded into a mock app that will make
    /// `traps`, and scratch memory holding `data`.
    fn setup(arch: Arch, traps: Vec<Trap>, data: &[(u64, &[u8])]) -> (Kernel<MockHost>, MockApp) {
        let mut kernel = Kernel::new(host_with_prog(arch)).with_trace();
        let mut app = MockApp::with_traps(arch, traps);
        kernel
            .exec(&mut app, b"/bin/prog", &[b"prog".to_vec()], &[])
            .unwrap();
        app.poke(SCRATCH, &[0; 0x4000]);
        for (addr, bytes) in data {
            app.poke(*addr, bytes);
        }
        (kernel, app)
    }

    fn sc(arch: Arch, sysno: Sysno, args: &[u64]) -> Trap {
        MockApp::syscall(arch, sysno, args)
    }

    #[test]
    fn exec_loads_and_starts_the_program() {
        let arch = Arch::Aarch64;
        let (mut kernel, mut app) = setup(arch, vec![sc(arch, Sysno::ExitGroup, &[3])], &[]);
        assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Exited(3));
        let (entry, sp) = app.started.unwrap();
        assert_eq!(entry, 0x40_1000);
        assert_eq!(app.peek(sp, 8), 1u64.to_le_bytes());
        assert!(app.terminated);
        // run again without exec
        assert!(matches!(kernel.run(&mut app), Err(KernelError::NoProgram)));
    }

    #[test]
    fn exec_errors() {
        let mut kernel = Kernel::new(MockHost::with_image(&[
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
        ]));
        let mut app = MockApp::new(Arch::Aarch64);
        let err = |r: Result<(), KernelError>| match r {
            Err(KernelError::Exec { errno, reason, .. }) => (errno, reason),
            other => panic!("{other:?}"),
        };
        let (errno, _) = err(kernel.exec(&mut app, b"/missing", &[], &[]));
        assert_eq!(errno, Errno(ENOENT));
        let (errno, reason) = err(kernel.exec(&mut app, b"/dyn", &[], &[]));
        assert_eq!(errno, Errno(ENOEXEC));
        assert!(reason.contains("dynamically linked"), "{reason}");
        let (errno, _) = err(kernel.exec(&mut app, b"/script", &[], &[]));
        assert_eq!(errno, Errno(ENOEXEC));
        let (errno, _) = err(kernel.exec(&mut app, b"/dev", &[], &[]));
        assert_eq!(errno, Errno(crate::errno::EACCES));
    }

    #[test]
    fn write_and_exit_on_every_arch() {
        for arch in Arch::ALL {
            let traps = vec![
                sc(arch, Sysno::Write, &[1, SCRATCH, 5]),
                sc(arch, Sysno::Write, &[2, SCRATCH + 6, 5]),
                sc(arch, Sysno::ExitGroup, &[0x1_07]),
            ];
            let (mut kernel, mut app) = setup(arch, traps, &[(SCRATCH, b"hello world")]);
            assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Exited(7));
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
            sc(arch, Sysno::Write, &[3, SCRATCH, 1]),
            sc(arch, Sysno::Write, &[1, 0x10_0000_0000, 1]),
            sc(arch, Sysno::Write, &[1, SCRATCH, 0]),
            sc(arch, Sysno::Write, &[0, SCRATCH, 1]),
            sc(arch, Sysno::Exit, &[0]),
        ];
        let (mut kernel, mut app) = setup(arch, traps, &[]);
        assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Exited(0));
        assert_eq!(app.returns, vec![-EBADF, -EFAULT, 0, -EBADF]);
        assert!(kernel.host().stdout.is_empty());
    }

    #[test]
    fn unknown_syscalls_are_enosys() {
        for arch in Arch::ALL {
            let traps = vec![
                sc(arch, Sysno::Execve, &[SCRATCH, 0, 0]),
                sc(arch, Sysno::Socket, &[2, 1, 0]),
                Trap::Syscall(SyscallTrap {
                    nr: 100_000,
                    args: [0; 6],
                }),
                sc(arch, Sysno::ExitGroup, &[38]),
            ];
            let (mut kernel, mut app) = setup(arch, traps, &[]);
            assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Exited(38));
            assert_eq!(app.returns, vec![-ENOSYS; 3]);
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
        let (mut kernel, mut app) = setup(arch, traps, &data);
        assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Exited(0));
        let r = app.returns.clone();
        assert_eq!(&r[..4], &[3, 12, 12, 0]);
        assert_eq!(kernel.host().stdout, b"hello image\n");
        // pread on the write-only fd fails; the second, read-write open works.
        assert_eq!(&r[4..11], &[0, -EEXIST, 3, 4, -EBADF, 4, 3]);
        assert_eq!(&r[11..15], &[0, 7, 0, 0]);
        assert_eq!(app.peek(buf, 7), b"/tmp/d\0");
        // newfstatat of "f": regular, 4 bytes (aarch64 layout).
        let st = app.peek(buf + 0x100, 128);
        assert_eq!(u32::from_le_bytes(st[16..20].try_into().unwrap()), 0o100644);
        assert_eq!(u64::from_le_bytes(st[48..56].try_into().unwrap()), 4);
        // fstat of the console: a character device.
        let st = app.peek(buf + 0x200, 128);
        assert_eq!(
            u32::from_le_bytes(st[16..20].try_into().unwrap()) & 0o170000,
            0o020000
        );
        assert_eq!(&r[15..18], &[-ENOENT, -ENOTDIR, -EEXIST]);
        assert_eq!(r[18], 5);
        // ".", "..", "f": three 24-byte records.
        assert_eq!(&r[19..21], &[72, 0]);
        assert_eq!(&app.peek(buf + 0x400 + 48 + 19, 2), b"f\0");
        assert_eq!(&r[21..24], &[1, 4, 4]);
        assert_eq!(
            kernel.host().stdout,
            b"hello image\n",
            "fd 1 is the file now"
        );
        assert_eq!(r[24], 0x40_6000, "brk starts after the image");
        assert!(r[25] > 0x40_0000);
        // The image is unchanged; the file lives in the upper layer.
        let f = kernel
            .vfs
            .resolve(&mut kernel.host, 2, b"/tmp/d/f", true)
            .unwrap();
        // fd 4 was at offset 0 (pread does not move it), so the write through
        // fd 1 overwrote the data.
        assert_eq!(kernel.vfs.read_all(&mut kernel.host, f).unwrap(), b"data");
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
        let (mut kernel, mut app) = setup(
            arch,
            traps,
            &[(SCRATCH, b"/etc/motd\0"), (SCRATCH + 0x40, b"/etc\0")],
        );
        kernel.run(&mut app).unwrap();
        // O_DIRECTORY (x86_64 value) on a file fails; on a directory works.
        assert_eq!(app.returns, vec![0, -ENOTDIR, 3, 0]);
        let st = app.peek(SCRATCH + 0x100, 144);
        assert_eq!(
            u64::from_le_bytes(st[16..24].try_into().unwrap()),
            1,
            "nlink"
        );
        assert_eq!(u32::from_le_bytes(st[24..28].try_into().unwrap()), 0o100755);
        assert_eq!(u64::from_le_bytes(st[48..56].try_into().unwrap()), 12);
        assert_eq!(app.thread_pointer, Some(0x1234_5000));
    }

    #[test]
    fn fault_ends_the_app() {
        let traps = vec![Trap::Fault(crate::platform::Fault {
            signal: 11,
            addr: Some(0),
            fatal: false,
        })];
        let (mut kernel, mut app) = setup(Arch::X86_64, traps, &[]);
        assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Signaled(11));
        assert!(app.terminated);
    }

    #[test]
    fn self_kill_ends_the_app() {
        let arch = Arch::Aarch64;
        let traps = vec![
            sc(arch, Sysno::Kill, &[1, 0]),
            sc(arch, Sysno::Kill, &[1, 17]),
            sc(arch, Sysno::Kill, &[99, 15]),
            sc(arch, Sysno::Tgkill, &[1, 1, 6]),
        ];
        let (mut kernel, mut app) = setup(arch, traps, &[]);
        assert_eq!(kernel.run(&mut app).unwrap(), ExitStatus::Signaled(6));
        assert_eq!(app.returns, vec![0, 0, -crate::errno::ESRCH]);
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
