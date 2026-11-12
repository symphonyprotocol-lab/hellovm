//! Starting an app process: an empty address space under the seccomp
//! filter, traced by the kernel process.
//!
//! # The problem
//!
//! The kernel core loads ELF images and lays out the app's memory itself, so
//! the platform must be able to create, remove and re-protect mappings *in
//! the app process* and start it at an entry point with a stack the core
//! built. On this platform the host kernel owns the page tables, and only the
//! app process itself can change its mappings (`mmap` has no "other process"
//! variant). At the same time, untrusted app code must never get a host
//! syscall executed with arguments it controls.
//!
//! # The mechanism: ptrace-driven syscall injection through a stub page
//!
//! The kernel process (K) traces the app process (C) with ptrace, and C's
//! seccomp filter returns `SECCOMP_RET_TRACE` for every syscall of the
//! native ABI (and kills on any other ABI). Every app syscall therefore
//! stops C *before* it runs, with K as the tracer:
//!
//! * To emulate a syscall, K reads the registers, lets the core compute the
//!   result, and skips the syscall (`orig_rax = -1` on x86_64,
//!   `NT_ARM_SYSTEM_CALL = -1` on aarch64) with the result in the return
//!   register. The host kernel never executes it.
//! * To change C's address space, K uses C's one trusted syscall
//!   instruction, in a stub page at a fixed address ([`crate::stub`]): from a
//!   syscall-exit stop it sets *all* the registers itself (pc = the stub
//!   instruction, number and arguments of `mmap`, `munmap` or `mprotect`) and
//!   resumes. The syscall traps to K again (seccomp stop); K checks that the
//!   stop is exactly the one it prepared (pc, number, arguments) and only
//!   then lets it run (`PTRACE_SYSCALL`; seccomp re-runs the filter after a
//!   tracer stop and allows it). At the exit stop K reads the result and
//!   restores the app's registers.
//! * Starting the app is setting pc and sp from a syscall-exit stop.
//!
//! C has a single thread (`clone` is emulated and refused in U1) and is
//! stopped whenever K touches its registers, so nothing in C can change a
//! register between K writing it and the host executing the syscall.
//!
//! # Bootstrap
//!
//! 1. K generates the stub executable into a sealed memfd and prepares the
//!    filter, the `execveat` arguments and a shared page for error reports,
//!    all before forking. After `fork`, C only makes raw syscalls and memory
//!    stores (K may be multi-threaded, so C must not allocate).
//! 2. C sets `PR_SET_PDEATHSIG`, closes every fd except the stub memfd, calls
//!    `PTRACE_TRACEME` and stops itself with `SIGSTOP`. K sets the ptrace
//!    options (`EXITKILL`: C dies with its tracer; `TRACESECCOMP`; exec and
//!    syscall-stop reporting) and resumes it.
//! 3. C sets `PR_SET_NO_NEW_PRIVS`, installs the filter and calls
//!    `execveat(stub_fd, "", ..., AT_EMPTY_PATH)`. That traps; K checks it
//!    is exactly the call it prepared and lets it run. C now has a fresh
//!    address space (stub, stack, vdso, vvar), an empty fd table (the memfd
//!    is close-on-exec) and default signal handlers.
//! 4. At the `execveat` exit stop, K reads `/proc/<pid>/maps` and unmaps
//!    everything except the stub page by injection. The core then sees an
//!    empty address space with one reserved range, the stub.
//!
//! # Residual host-syscall surface
//!
//! Once the app's own code can run, the host kernel executes exactly these
//! syscalls in C, and only with numbers and arguments written by K into C's
//! registers while C is stopped:
//!
//! * `mmap(addr, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)`
//! * `munmap(addr, len)`
//! * `mprotect(addr, len, prot)`
//!
//! with `prot` limited to `PROT_READ | PROT_WRITE | PROT_EXEC`, `addr` and
//! `len` page-aligned and inside the app's address range, never touching the
//! stub's range ([`crate::SeccompApp`] checks this independently of the
//! core). The values are chosen by the core, in response to app requests it
//! has validated. Before the app runs, the host also executes the bootstrap
//! `execveat` of the generated stub. On x86_64 the legacy vsyscall page is
//! still present (it cannot be unmapped); its emulation goes through seccomp
//! like a real syscall, so it is trapped and emulated as well.
//!
//! # Rejected alternatives
//!
//! * **Seccomp user notification (U0) plus an in-app stub that the filter
//!   lets through by instruction pointer.** The filter would have to allow
//!   `mmap`/`mprotect` from the stub address; the app can jump to that
//!   address with registers of its choice, so this hands it host syscalls
//!   with arbitrary arguments. Pinning arguments in BPF is not possible for
//!   all of them.
//! * **A stub that executes requests from shared memory**, synchronised
//!   with K. The app could race the stub (it can rewrite the request memory
//!   or jump into the stub mid-way) unless the stub runs in a separate
//!   thread or process the app cannot reach, which is the ptrace design
//!   with more moving parts.
//! * **Moving to the signal-based trap now** (SIGSYS handler in the app).
//!   The handler runs in the app's address space with the app's privileges;
//!   any host syscall it can make, the app can make too. It does not solve
//!   address-space control by itself.
//! * **`pidfd_getfd`, `process_madvise`-style remote operations.** There is
//!   no remote `mmap`/`mprotect` in Linux, and `pidfd_getfd` is denied by
//!   Docker's default seccomp profile without `CAP_SYS_PTRACE`.
//! * **Building the image with `execve` of the real program** (U0). The
//!   host kernel would parse an untrusted ELF file and build the stack, and
//!   the core could not own the address space layout.
//!
//! ptrace of one's own child needs no capabilities and is allowed by
//! Docker's default seccomp profile on Linux 4.8 and newer (strace works in a
//! default container). The cost is a few more host syscalls per trapped
//! syscall than user notification (wait, get/set registers, resume); the
//! planned signal-based fast path is unaffected by this choice.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};

use hellovm_core::{Arch, Sysno};

use crate::filter;
use crate::regs::Regs;
use crate::stub;
use crate::sys;
use crate::tracer::{Run, Stop, Tracee};

/// Bootstrap stages, reported in the handshake when one fails.
const STAGE_PDEATHSIG: i32 = 1;
const STAGE_TRACEME: i32 = 2;
const STAGE_NO_NEW_PRIVS: i32 = 3;
const STAGE_SECCOMP: i32 = 4;
const STAGE_EXEC: i32 = 5;

fn stage_name(stage: i32) -> &'static str {
    match stage {
        STAGE_PDEATHSIG => "prctl(PR_SET_PDEATHSIG)",
        STAGE_TRACEME => "ptrace(PTRACE_TRACEME)",
        STAGE_NO_NEW_PRIVS => "prctl(PR_SET_NO_NEW_PRIVS)",
        STAGE_SECCOMP => "installing the seccomp filter",
        STAGE_EXEC => "execveat of the stub",
        _ => "an unknown step",
    }
}

/// Shared between K and C through a `MAP_SHARED` page.
#[repr(C)]
struct Handshake {
    /// The failed stage, or 0.
    stage: AtomicI32,
    /// errno of the failed stage.
    errno: AtomicI32,
}

impl Handshake {
    fn error(&self) -> Option<io::Error> {
        let stage = self.stage.load(Ordering::Acquire);
        if stage == 0 {
            return None;
        }
        let err = io::Error::from_raw_os_error(self.errno.load(Ordering::Relaxed));
        Some(io::Error::new(
            err.kind(),
            format!("app bootstrap failed at {}: {err}", stage_name(stage)),
        ))
    }

    /// Records a failure. Async-signal-safe.
    fn fail(&self, stage: i32, errno: i32) {
        self.errno.store(errno, Ordering::Relaxed);
        self.stage.store(stage, Ordering::Release);
    }
}

/// A shared anonymous mapping holding a [`Handshake`].
struct SharedPage {
    ptr: *mut libc::c_void,
    len: usize,
}

impl SharedPage {
    fn new() -> io::Result<Self> {
        let len = sys::page_size() as usize;
        // SAFETY: anonymous mapping with no address hint; checked below.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(SharedPage { ptr, len })
    }

    fn handshake(&self) -> &Handshake {
        // SAFETY: the mapping is page-aligned, zero-filled, large enough for
        // a Handshake (all-zero atomics are valid) and lives as long as self.
        unsafe { &*(self.ptr as *const Handshake) }
    }
}

impl Drop for SharedPage {
    fn drop(&mut self) {
        // SAFETY: unmapping exactly the mapping created in `new`.
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}

/// A freshly spawned app process, stopped at the exit of its `execveat` of
/// the stub.
pub struct Spawned {
    pub tracee: Tracee,
    /// The registers at that stop.
    pub regs: Regs,
    /// Every mapping other than the stub, to be unmapped.
    pub foreign: Vec<(u64, u64)>,
    /// One past the highest of those mappings.
    pub top: u64,
}

fn context(err: io::Error, what: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{what}: {err}"))
}

fn errno() -> i32 {
    // SAFETY: reads the calling thread's errno; async-signal-safe.
    unsafe { *libc::__errno_location() }
}

fn unexpected(stop: Stop, hs: &Handshake, what: &str) -> io::Error {
    hs.error()
        .unwrap_or_else(|| io::Error::other(format!("{what}: unexpected stop {stop:?}")))
}

/// Starts an app process running the stub under the filter, traced by the
/// calling thread.
pub fn spawn(arch: Arch) -> io::Result<Spawned> {
    let execveat_nr = arch
        .syscall_nr(Sysno::Execveat)
        .expect("execveat exists on every architecture");

    // Everything C needs is prepared before the fork.
    let stub_fd: OwnedFd = sys::sealed_memfd(c"hellovm-stub", &stub::elf(arch))
        .map_err(|err| context(err, "creating the stub memfd"))?;
    let empty = CString::default();
    let arg0 = CString::new("hellovm-stub").unwrap();
    let argv: [*const libc::c_char; 2] = [arg0.as_ptr(), ptr::null()];
    let envp: [*const libc::c_char; 1] = [ptr::null()];
    let mut filter = filter::trace_all(sys::audit_arch(arch));
    let prog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_mut_ptr(),
    };
    let page = SharedPage::new()?;
    let hs = page.handshake();

    // SAFETY: plain syscall.
    let parent = unsafe { libc::getpid() };
    // SAFETY: the child branch below only makes async-signal-safe calls on
    // data prepared above and never returns.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: we are the freshly forked child; all pointers point to
        // data prepared before the fork.
        unsafe {
            child_bootstrap(
                hs,
                parent,
                stub_fd.as_raw_fd(),
                &prog,
                empty.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        }
    }
    // From here on, dropping `tracee` kills and reaps C.
    let mut tracee = Tracee::new(pid);

    // Step 2: C stops itself after PTRACE_TRACEME.
    match tracee.wait()? {
        Stop::Signal(libc::SIGSTOP) => {}
        stop => return Err(unexpected(stop, hs, "waiting for the app to stop")),
    }
    tracee
        .set_options()
        .map_err(|e| context(e, "PTRACE_SETOPTIONS"))?;
    tracee.resume(Run::Cont, 0)?;

    // Step 3: the only syscall the app process makes on its own is the
    // prepared execveat.
    match tracee.wait()? {
        Stop::Seccomp => {}
        stop => return Err(unexpected(stop, hs, "waiting for execveat")),
    }
    let (nr, args) = tracee.regs()?.syscall();
    if nr != execveat_nr
        || args[0] != stub_fd.as_raw_fd() as u64
        || args[1] != empty.as_ptr() as u64
        || args[2] != argv.as_ptr() as u64
        || args[3] != envp.as_ptr() as u64
        || args[4] != libc::AT_EMPTY_PATH as u64
    {
        return Err(hs.error().unwrap_or_else(|| {
            io::Error::other(format!(
                "unexpected first syscall {nr} {args:#x?} from the app process"
            ))
        }));
    }
    tracee.resume(Run::Syscall, 0)?;
    match tracee.wait()? {
        Stop::Exec => tracee.resume(Run::Syscall, 0)?,
        Stop::SyscallExit => {
            let ret = tracee.regs()?.ret();
            return Err(context(
                io::Error::from_raw_os_error((-ret) as i32),
                "execveat of the stub",
            ));
        }
        stop => return Err(unexpected(stop, hs, "waiting for the stub exec")),
    }
    match tracee.wait()? {
        Stop::SyscallExit => {}
        stop => return Err(unexpected(stop, hs, "waiting for the stub exec to return")),
    }
    let regs = tracee.regs()?;
    if regs.pc() != stub::STUB_SYSCALL {
        return Err(io::Error::other(format!(
            "the stub started at {:#x}, not {:#x}",
            regs.pc(),
            stub::STUB_SYSCALL
        )));
    }

    // Step 4: find everything the host put into the new address space.
    let (foreign, top) = foreign_mappings(pid)?;
    Ok(Spawned {
        tracee,
        regs,
        foreign,
        top,
    })
}

/// The mappings of `pid` other than the stub, and one past the highest of
/// them. The vsyscall page (x86_64) lies outside the user address range and
/// is not a real mapping, so it is left out.
pub fn foreign_mappings(pid: libc::pid_t) -> io::Result<(Vec<(u64, u64)>, u64)> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|err| context(err, "reading the app's memory map"))?;
    let mut foreign = Vec::new();
    let mut top = 0;
    for line in maps.lines() {
        if line.ends_with("[vsyscall]") {
            continue;
        }
        let range = line.split_whitespace().next().unwrap_or("");
        let parse = |s: Option<&str>| s.and_then(|s| u64::from_str_radix(s, 16).ok());
        let mut bounds = range.split('-');
        let (Some(start), Some(end)) = (parse(bounds.next()), parse(bounds.next())) else {
            return Err(io::Error::other(format!("bad maps line {line:?}")));
        };
        top = top.max(end);
        let stub_end = stub::STUB_BASE + stub::STUB_RESERVED;
        if start >= stub::STUB_BASE && end <= stub_end {
            continue;
        }
        if start < stub_end && end > stub::STUB_BASE {
            return Err(io::Error::other(format!(
                "a host mapping overlaps the stub: {line:?}"
            )));
        }
        foreign.push((start, end - start));
    }
    Ok((foreign, top))
}

/// C's side of the bootstrap. See the module documentation.
///
/// # Safety
///
/// Must only be called in a freshly forked child, with pointers to data that
/// was valid at the time of the fork.
unsafe fn child_bootstrap(
    hs: &Handshake,
    parent: libc::pid_t,
    stub_fd: libc::c_int,
    prog: *const libc::sock_fprog,
    empty: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> ! {
    let fail = |stage: i32| -> ! {
        hs.fail(stage, errno());
        libc::_exit(127)
    };

    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
        fail(STAGE_PDEATHSIG);
    }
    // K may have died before PDEATHSIG was armed.
    if libc::getppid() != parent {
        libc::_exit(127);
    }
    close_all_fds_except(stub_fd);

    if sys::ptrace(sys::PTRACE_TRACEME, 0, 0, 0) != 0 {
        fail(STAGE_TRACEME);
    }
    libc::kill(libc::getpid(), libc::SIGSTOP);

    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        fail(STAGE_NO_NEW_PRIVS);
    }
    if libc::syscall(
        libc::SYS_seccomp,
        sys::SECCOMP_SET_MODE_FILTER,
        0 as libc::c_ulong,
        prog,
    ) != 0
    {
        fail(STAGE_SECCOMP);
    }

    // From here on every syscall stops for K.
    libc::syscall(
        libc::SYS_execveat,
        stub_fd as libc::c_long,
        empty,
        argv,
        envp,
        libc::AT_EMPTY_PATH as libc::c_long,
    );

    // K saw the failure at the syscall exit and kills us; this is a
    // fallback that makes no syscall.
    hs.fail(STAGE_EXEC, errno());
    die_without_syscalls()
}

/// Closes every fd except `keep`. Async-signal-safe.
unsafe fn close_all_fds_except(keep: libc::c_int) {
    let keep = keep as libc::c_uint;
    let ok = (keep == 0
        || libc::syscall(
            sys::SYS_CLOSE_RANGE,
            0 as libc::c_long,
            (keep - 1) as libc::c_long,
            0 as libc::c_long,
        ) == 0)
        && libc::syscall(
            sys::SYS_CLOSE_RANGE,
            (keep + 1) as libc::c_long,
            libc::c_uint::MAX as libc::c_long,
            0 as libc::c_long,
        ) == 0;
    if !ok {
        // close_range needs Linux 5.9.
        for fd in 0..65536 {
            if fd != keep as libc::c_int {
                libc::close(fd);
            }
        }
    }
}

/// Kills the calling process with `SIGILL` without making a syscall (if it
/// is traced, the tracer sees the signal first).
fn die_without_syscalls() -> ! {
    // SAFETY: executes an undefined instruction.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!("ud2", options(noreturn));
        #[cfg(target_arch = "aarch64")]
        std::arch::asm!("udf #0", options(noreturn));
    }
}
