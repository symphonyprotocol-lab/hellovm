//! Starting an app process under the seccomp filter.
//!
//! # How the child gets from the filter to the target program
//!
//! The filter traps *every* syscall, so once the app process has installed
//! it, it can no longer hand its listener fd to the kernel process itself,
//! and its `execve` of the target is trapped like everything else. The
//! steps, with K the kernel process, C the app process and H a short-lived
//! helper:
//!
//! 1. K prepares everything C needs before forking (filter program, C
//!    strings, argv/envp arrays, a `SOCK_SEQPACKET` socketpair) and maps a
//!    shared anonymous page for a [`Handshake`]. After `fork`, C and H only
//!    make raw syscalls and memory stores: K may be multi-threaded, so they
//!    must not allocate.
//! 2. C sets `PR_SET_PDEATHSIG`, resets `SIGILL` to its default action and
//!    closes every fd except its end of the socketpair. The app gets no host
//!    fds at all: its fds are virtual and live in the kernel core.
//! 3. C creates H with `clone(CLONE_FILES | CLONE_PARENT)`: H shares C's fd
//!    table but not its seccomp filter (C has none yet), and is K's child,
//!    so K reaps it.
//! 4. C sets `PR_SET_NO_NEW_PRIVS`, installs the filter with
//!    `SECCOMP_FILTER_FLAG_NEW_LISTENER` and stores the listener fd number in
//!    the shared page (a memory store, not a syscall).
//! 5. H sees the number, sends that fd to K over the socketpair with
//!    `SCM_RIGHTS` (H is unfiltered, and the fd is in the table it shares
//!    with C) and exits.
//! 6. C calls `execve(target)`, which traps. K checks that it is exactly the
//!    call it prepared (an `execve` from C with the path pointer K built) and
//!    answers it with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. This is the only
//!    syscall the host ever executes on the app's behalf, and it is issued
//!    by our own trusted code, so the time-of-check/time-of-use caveat of
//!    `CONTINUE` does not apply. The listener and the socket are
//!    close-on-exec, so the app starts with an empty fd table.
//! 7. If `execve` fails, C stores errno in the shared page and kills itself
//!    with an illegal instruction (any syscall would trap). K sees the death
//!    and reports the stored errno.
//!
//! Rejected alternatives: allowing `execve` in the filter (the app could
//! exec arbitrary host binaries); allowing a syscall guarded by a secret
//! argument "cookie" or by instruction pointer (permanent holes in the
//! filter); `pidfd_getfd` from K (needs ptrace rights, which the default
//! Docker/containerd seccomp profiles deny without `CAP_SYS_PTRACE`); and a
//! plain `CLONE_FILES` child (C could no longer close its inherited fds
//! without closing K's).
//!
//! U1 removes the `execve` altogether: the kernel core will load ELF images
//! itself, and the app will start from a small trusted stub instead.

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use cansol_core::{Arch, Sysno};

use crate::filter;
use crate::notify::{Child, Event};
use crate::sys;

/// How long the bootstrap up to the listener hand-off may take.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);

/// Bootstrap stages, reported in the handshake when one fails.
const STAGE_PDEATHSIG: i32 = 1;
const STAGE_SIGNALS: i32 = 2;
const STAGE_HELPER: i32 = 3;
const STAGE_NO_NEW_PRIVS: i32 = 4;
const STAGE_SECCOMP: i32 = 5;
const STAGE_SEND_LISTENER: i32 = 6;
const STAGE_EXEC: i32 = 7;

fn stage_name(stage: i32) -> &'static str {
    match stage {
        STAGE_PDEATHSIG => "prctl(PR_SET_PDEATHSIG)",
        STAGE_SIGNALS => "resetting SIGILL",
        STAGE_HELPER => "creating the helper process",
        STAGE_NO_NEW_PRIVS => "prctl(PR_SET_NO_NEW_PRIVS)",
        STAGE_SECCOMP => "installing the seccomp filter",
        STAGE_SEND_LISTENER => "sending the seccomp listener",
        STAGE_EXEC => "execve",
        _ => "an unknown step",
    }
}

/// Shared between K, C and H through a `MAP_SHARED` page.
#[repr(C)]
struct Handshake {
    /// C's listener fd, or -1 until it exists.
    listener_fd: AtomicI32,
    /// H's pid, or 0 until it exists.
    helper_pid: AtomicI32,
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
        let len = 4096;
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
        let page = SharedPage { ptr, len };
        page.handshake().listener_fd.store(-1, Ordering::Relaxed);
        Ok(page)
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

/// A freshly spawned app, stopped at its first event after `execve`.
pub struct Spawned {
    pub child: Child,
    pub first: Event,
}

fn context(err: io::Error, what: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{what}: {err}"))
}

fn errno() -> i32 {
    // SAFETY: reads the calling thread's errno; async-signal-safe.
    unsafe { *libc::__errno_location() }
}

/// Kills and reaps C and, if it exists, H. Both are unreaped children of
/// ours, so their pids cannot have been reused.
fn abort_bootstrap(pid: libc::pid_t, hs: &Handshake) {
    let helper = hs.helper_pid.load(Ordering::Acquire);
    // SAFETY: plain syscalls on our own unreaped children.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, ptr::null_mut(), 0);
        if helper > 0 {
            libc::kill(helper, libc::SIGKILL);
            libc::waitpid(helper, ptr::null_mut(), 0);
        }
    }
}

/// Starts `program` with `argv` and an empty environment under the filter.
pub fn spawn(arch: Arch, program: &Path, argv: &[OsString]) -> io::Result<Spawned> {
    sys::check_notif_sizes().map_err(|err| context(err, "seccomp(SECCOMP_GET_NOTIF_SIZES)"))?;

    // Everything C and H need is prepared before the fork.
    let path = CString::new(program.as_os_str().as_bytes())?;
    let args = argv
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv_ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(ptr::null());
    let envp_ptrs: [*const libc::c_char; 1] = [ptr::null()];
    let mut filter = filter::notify_all(sys::audit_arch(arch));
    let prog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_mut_ptr(),
    };
    let page = SharedPage::new()?;
    let hs = page.handshake();
    let (k_sock, c_sock) = sys::seqpacket_pair()?;

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
                c_sock.as_raw_fd(),
                &prog,
                path.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            )
        }
    }
    drop(c_sock);

    let pidfd = match sys::pidfd_open(pid) {
        Ok(fd) => fd,
        Err(err) => {
            abort_bootstrap(pid, hs);
            return Err(context(err, "pidfd_open"));
        }
    };
    let listener = match receive_listener(&k_sock, &pidfd, hs) {
        Ok(fd) => fd,
        Err(err) => {
            abort_bootstrap(pid, hs);
            return Err(err);
        }
    };
    // H exits right after sending.
    let helper = hs.helper_pid.load(Ordering::Acquire);
    if helper > 0 {
        // SAFETY: plain syscall on our own unreaped child.
        unsafe { libc::waitpid(helper, ptr::null_mut(), 0) };
    }

    let mut child = Child {
        pid,
        pidfd,
        listener,
        reaped: false,
    };

    // The first trapped syscall must be C's own execve.
    match child.next_event()? {
        Event::Syscall(notif)
            if notif.pid as libc::pid_t == pid
                && notif.data.arch == sys::audit_arch(arch)
                && arch.syscall_nr(Sysno::Execve) == Some(u64::from(notif.data.nr as u32))
                && notif.data.args[0] == path.as_ptr() as u64 =>
        {
            child.continue_bootstrap_syscall(notif.id)?;
        }
        other => {
            return Err(io::Error::other(format!(
                "unexpected first event from the app process: {other:?}"
            )));
        }
    }

    let first = child.next_event()?;
    if let (Event::Died(_), Some(err)) = (first, hs.error()) {
        return Err(context(err, &program.display().to_string()));
    }
    Ok(Spawned { child, first })
}

/// Waits for H to send C's listener fd.
fn receive_listener(sock: &OwnedFd, pidfd: &OwnedFd, hs: &Handshake) -> io::Result<OwnedFd> {
    let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
    loop {
        let mut fds = [
            libc::pollfd {
                fd: sock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(hs.error().unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "app bootstrap timed out")
            }));
        }
        let timeout = left.as_millis().min(100) as libc::c_int + 1;
        // SAFETY: `fds` holds two valid pollfd structs.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if ret < 0 && errno() != libc::EINTR {
            return Err(io::Error::last_os_error());
        }
        if fds[0].revents != 0 {
            if let Some(fd) = sys::recv_fd(sock)? {
                return Ok(fd);
            }
            // H sends a message without an fd when the bootstrap failed.
            return Err(hs.error().unwrap_or_else(|| {
                io::Error::other("app bootstrap failed: no listener received")
            }));
        }
        if fds[1].revents != 0 || hs.stage.load(Ordering::Acquire) != 0 {
            return Err(hs
                .error()
                .unwrap_or_else(|| io::Error::other("app process died during bootstrap")));
        }
    }
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
    sock: libc::c_int,
    prog: *const libc::sock_fprog,
    path: *const libc::c_char,
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
    // A SIGILL handler inherited from K would make syscalls after an exec
    // failure; make sure SIGILL kills.
    if libc::signal(libc::SIGILL, libc::SIG_DFL) == libc::SIG_ERR {
        fail(STAGE_SIGNALS);
    }
    close_all_fds_except(sock);

    let helper = libc::syscall(
        libc::SYS_clone,
        (libc::CLONE_FILES | libc::CLONE_PARENT | libc::SIGCHLD) as libc::c_ulong,
        0usize,
        0usize,
        0usize,
        0usize,
    );
    if helper == 0 {
        helper_main(hs, parent, sock);
    }
    if helper < 0 {
        fail(STAGE_HELPER);
    }
    hs.helper_pid.store(helper as i32, Ordering::Release);

    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        fail(STAGE_NO_NEW_PRIVS);
    }
    let fd = libc::syscall(
        libc::SYS_seccomp,
        sys::SECCOMP_SET_MODE_FILTER,
        sys::SECCOMP_FILTER_FLAG_NEW_LISTENER,
        prog,
    );
    if fd < 0 {
        fail(STAGE_SECCOMP);
    }
    hs.listener_fd.store(fd as i32, Ordering::Release);

    // From here on every syscall traps to K.
    libc::execve(path, argv, envp);

    hs.fail(STAGE_EXEC, errno());
    die_without_syscalls()
}

/// Closes every fd except `keep`. Async-signal-safe.
unsafe fn close_all_fds_except(keep: libc::c_int) {
    let keep = keep as libc::c_uint;
    let ok = (keep == 0 || libc::syscall(sys::SYS_CLOSE_RANGE, 0, keep - 1, 0) == 0)
        && libc::syscall(sys::SYS_CLOSE_RANGE, keep + 1, libc::c_uint::MAX, 0) == 0;
    if !ok {
        // close_range needs Linux 5.9.
        for fd in 0..65536 {
            if fd != keep as libc::c_int {
                libc::close(fd);
            }
        }
    }
}

/// H: waits for C's listener and sends it to K. Async-signal-safe.
unsafe fn helper_main(hs: &Handshake, parent: libc::pid_t, sock: libc::c_int) -> ! {
    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    if libc::getppid() != parent {
        libc::_exit(1);
    }
    let pause = libc::timespec {
        tv_sec: 0,
        tv_nsec: 20_000,
    };
    // 10 s at most (the sleeps are a lower bound).
    let mut fd = -1;
    for _ in 0..500_000 {
        fd = hs.listener_fd.load(Ordering::Acquire);
        if fd >= 0 || hs.stage.load(Ordering::Acquire) != 0 {
            break;
        }
        libc::nanosleep(&pause, ptr::null_mut());
    }
    if sys::send_fd(sock, fd) < 0 {
        hs.fail(STAGE_SEND_LISTENER, errno());
    }
    libc::_exit(0)
}

/// Kills the calling process with `SIGILL` without making a syscall.
fn die_without_syscalls() -> ! {
    // SAFETY: executes an undefined instruction; SIGILL has its default
    // action, so the process dies here.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!("ud2", options(noreturn));
        #[cfg(target_arch = "aarch64")]
        std::arch::asm!("udf #0", options(noreturn));
    }
}
