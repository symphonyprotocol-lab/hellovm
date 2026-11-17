//! The syscalls the kernel process makes once it is confined, measured
//! with `HELLOVM_SECCOMP_LEARN` over the whole test suite (see `learn`),
//! with argument checks where an argument decides what the call can reach.
//!
//! The measurement covers the kernel process's own threads (event loop,
//! console reader, outbound-stream helpers, the `--timeout` watchdog) and
//! the bootstrap of every app process up to its `execveat` of the stub,
//! which runs the kernel's code. It was taken on aarch64, with Debian
//! bookworm's glibc 2.36 and with Ubuntu 26.04's glibc 2.43 (which adds
//! `fstat`, the termios2 `ioctl`s and `MADV_GUARD_INSTALL`); the x86_64 list
//! is the same calls by name (plus `poll`, which x86_64 glibc uses where
//! aarch64 has only `ppoll`). The development machines are aarch64, so the
//! x86_64 list is measured by CI instead: the `test-x86_64` job runs the
//! test suite once in measuring mode and then the test
//! `every_measured_syscall_is_allowed` below over what it recorded, which
//! names any syscall the list lacks. Run the same two steps after changing
//! what the kernel process does (see README).
//!
//! A few calls were not seen in the measurement but are on known C-library
//! or `std` paths, and are allowed so that a rare path does not kill the
//! kernel: `clock_gettime`/`gettimeofday` (made by the vDSO itself when the
//! host clock cannot be read from user space, e.g. some hypervisor
//! clocksources), `restart_syscall` (the host restarts an interrupted
//! `clock_nanosleep` or timed `futex` wait with it after the event loop's
//! `SIGCHLD` handler ran; found by a flaky `--timeout` test, not by the
//! measurement), `getrandom` (`std`'s hash seeds in a new thread),
//! `mremap` (`realloc` of a large buffer) and `tgkill(SIGABRT)` (`abort`
//! after a panic).

use crate::filter::{Check, Entry, Rule};

use libc::*;

fn allow(nr: c_long) -> Entry {
    Entry {
        nr: nr as u32,
        rule: Rule::Allow,
    }
}

fn checked(nr: c_long, checks: Vec<Check>) -> Entry {
    Entry {
        nr: nr as u32,
        rule: Rule::Checked(checks),
    }
}

fn one_of(arg: usize, values: &[c_int]) -> Check {
    Check::OneOf(arg, values.iter().map(|&v| v as u32).collect())
}

/// `clone` flags of `pthread_create`.
const THREAD: c_int = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID;
/// `clone` flags of `fork` (a new app process, before its `execveat`).
const FORK: c_int = SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;

const PTRACE_REQUESTS: [c_int; 8] = [
    PTRACE_TRACEME as c_int,
    PTRACE_CONT as c_int,
    PTRACE_SYSCALL as c_int,
    PTRACE_SETOPTIONS as c_int,
    PTRACE_GETEVENTMSG as c_int,
    PTRACE_GETSIGINFO as c_int,
    PTRACE_GETREGSET as c_int,
    PTRACE_SETREGSET as c_int,
];

/// The allowlist. `stub_fd` is the only fd `execveat` may execute;
/// `tcp` also allows `AF_INET` sockets (the `--splice-to` test hook).
pub fn entries(stub_fd: i32, tcp: bool) -> Vec<Entry> {
    let mut domains = vec![AF_UNIX];
    if tcp {
        domains.push(AF_INET);
    }
    #[allow(unused_mut)]
    let mut list = vec![
        // Most frequent first: the filter checks the entries in order.
        // Driving app processes (`hellovm-platform-seccomp`).
        checked(
            SYS_ptrace,
            vec![Check::HighZero(0), one_of(0, &PTRACE_REQUESTS)],
        ),
        allow(SYS_wait4),
        allow(SYS_process_vm_readv),
        allow(SYS_process_vm_writev),
        allow(SYS_futex),
        allow(SYS_rt_sigreturn),
        // I/O on fds the kernel holds: the console, image files, sockets
        // to the egress proxy, pipes of std.
        allow(SYS_read),
        allow(SYS_write),
        allow(SYS_pread64),
        allow(SYS_close),
        allow(SYS_close_range),
        allow(SYS_ppoll),
        checked(
            SYS_fcntl,
            vec![one_of(1, &[F_GETFD, F_SETFD, F_GETFL, F_DUPFD_CLOEXEC])],
        ),
        checked(
            SYS_ioctl,
            vec![Check::OneOf(
                1,
                vec![
                    TCGETS as u32,
                    TCSETS as u32,
                    // glibc 2.42+ (Ubuntu 26.04) tcgetattr/tcsetattr.
                    TCGETS2 as u32,
                    TCSETS2 as u32,
                    TIOCGWINSZ as u32,
                    FIONBIO as u32,
                ],
            )],
        ),
        // The image directory, walked from its fd (`ImageDir`): read-only
        // opens, never creating or writing anything.
        checked(
            SYS_openat,
            vec![Check::Subset(
                2,
                (O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_DIRECTORY | O_LARGEFILE) as u32,
            )],
        ),
        allow(SYS_newfstatat),
        // glibc 2.43 (Ubuntu 26.04) fstat; older ones use newfstatat.
        allow(SYS_fstat),
        allow(SYS_statx),
        allow(SYS_readlinkat),
        allow(SYS_getdents64),
        // Memory, never executable.
        allow(SYS_brk),
        checked(
            SYS_mmap,
            vec![Check::Subset(2, (PROT_READ | PROT_WRITE) as u32)],
        ),
        checked(
            SYS_mprotect,
            vec![Check::Subset(2, (PROT_READ | PROT_WRITE) as u32)],
        ),
        allow(SYS_munmap),
        allow(SYS_mremap),
        allow(SYS_madvise),
        // Threads and synchronisation.
        checked(SYS_clone, vec![one_of(0, &[THREAD, FORK])]),
        Entry {
            // glibc tries clone3 first and falls back to clone.
            nr: SYS_clone3 as u32,
            rule: Rule::Errno(ENOSYS as u32),
        },
        allow(SYS_set_robust_list),
        allow(SYS_rseq),
        allow(SYS_sched_getaffinity),
        allow(SYS_exit),
        allow(SYS_exit_group),
        allow(SYS_gettid),
        allow(SYS_getpid),
        allow(SYS_getppid),
        // Signals: the SIGCHLD handler of the event loop, std's guard pages.
        allow(SYS_rt_sigaction),
        allow(SYS_rt_sigprocmask),
        allow(SYS_restart_syscall),
        allow(SYS_sigaltstack),
        // Time.
        allow(SYS_clock_nanosleep),
        allow(SYS_clock_gettime),
        allow(SYS_gettimeofday),
        allow(SYS_getrandom),
        checked(SYS_pidfd_open, vec![one_of(1, &[0])]),
        checked(SYS_pidfd_send_signal, vec![one_of(1, &[SIGKILL])]),
        // SIGKILL to an app process, SIGSTOP of a new one to itself. A
        // filter cannot tell whose pid it is: see the crate documentation
        // for what keeps these, `ptrace` and `process_vm_*` to K's own
        // app processes.
        checked(SYS_kill, vec![one_of(1, &[SIGKILL, SIGSTOP])]),
        // SIGURG interrupts a running app task; SIGABRT is abort().
        checked(SYS_tgkill, vec![one_of(2, &[SIGURG, SIGABRT])]),
        // The bootstrap of a new app process (its own code is K's until
        // the execveat).
        checked(
            SYS_prctl,
            vec![one_of(
                0,
                &[PR_SET_PDEATHSIG, PR_SET_NAME, PR_SET_NO_NEW_PRIVS],
            )],
        ),
        allow(SYS_setsid),
        checked(SYS_seccomp, vec![one_of(0, &[1]), one_of(1, &[0])]),
        checked(
            SYS_execveat,
            vec![one_of(0, &[stub_fd]), one_of(4, &[AT_EMPTY_PATH])],
        ),
        // Outbound streams to the egress proxy: Unix stream sockets only.
        checked(
            SYS_socket,
            vec![
                one_of(0, &domains),
                one_of(
                    1,
                    &[
                        SOCK_STREAM | SOCK_CLOEXEC,
                        SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    ],
                ),
            ],
        ),
        allow(SYS_connect),
        allow(SYS_sendto),
        allow(SYS_recvfrom),
        allow(SYS_setsockopt),
        allow(SYS_shutdown),
    ];
    #[cfg(target_arch = "x86_64")]
    list.push(allow(SYS_poll));
    list
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_syscall_has_one_rule() {
        for tcp in [false, true] {
            let entries = super::entries(5, tcp);
            let mut nrs: Vec<u32> = entries.iter().map(|e| e.nr).collect();
            nrs.sort_unstable();
            nrs.dedup();
            assert_eq!(nrs.len(), entries.len(), "a syscall is listed twice");
        }
    }

    /// With `HELLOVM_SECCOMP_LEARNED=FILE`, a recording made by running
    /// the tests with `HELLOVM_SECCOMP_LEARN=FILE` (see `learn`): the real
    /// filter must let every recorded syscall through. Without the
    /// variable there is nothing to check.
    #[test]
    fn every_measured_syscall_is_allowed() {
        use crate::filter::{self, tests::data, Judge};
        let Some(path) = std::env::var_os("HELLOVM_SECCOMP_LEARNED") else {
            return;
        };
        let text = std::fs::read_to_string(&path).expect("reading the recording");
        let mut calls = std::collections::BTreeSet::new();
        for line in text.lines() {
            let fields: Vec<u64> = line
                .split_whitespace()
                .map(|f| u64::from_str_radix(f, 16).expect("a hex field"))
                .collect();
            assert_eq!(fields.len(), 7, "bad line {line:?}");
            calls.insert(fields);
        }
        assert!(
            calls.len() >= 100,
            "only {} distinct calls recorded: the measuring run did not work",
            calls.len()
        );
        let arch = crate::harden::audit_arch();
        let code = [0x10_0000..0x20_0000, 0x40_0000..0x50_0000];
        // The stub fd does not matter: the measuring filter lets `execveat`
        // through without recording it. `tcp`: the `--splice-to` tests.
        let entries = super::entries(3, true);
        let prog = filter::build(arch, &code, Judge::Allowlist(&entries)).unwrap();
        let mut refused = Vec::new();
        for call in &calls {
            let args: [u64; 6] = call[1..].try_into().unwrap();
            let action = crate::bpf::run(&prog, &data(arch, call[0] as u32, 0x18_0000, args));
            let errno = action & 0xffff_0000 == filter::SECCOMP_RET_ERRNO;
            if action != filter::SECCOMP_RET_ALLOW && !errno {
                refused.push(format!("syscall {} {args:x?}", call[0]));
            }
        }
        assert!(
            refused.is_empty(),
            "the kernel process made syscalls its allowlist refuses on this architecture:\n{}",
            refused.join("\n")
        );
    }
}
