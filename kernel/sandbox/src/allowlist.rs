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
pub fn entries(stub_fd: i32, tcp: bool, warm: bool) -> Vec<Entry> {
    let mut domains = vec![AF_UNIX];
    if tcp {
        domains.push(AF_INET);
    }
    let mut fcntls = vec![F_GETFD, F_SETFD, F_GETFL, F_DUPFD_CLOEXEC];
    if warm {
        // A warm-clone template seals its snapshot.
        fcntls.push(F_ADD_SEALS);
    }
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
        checked(SYS_fcntl, vec![one_of(1, &fcntls)]),
        checked(SYS_ioctl, vec![Check::OneOf(1, TERMINAL_IOCTLS.to_vec())]),
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
    if warm {
        // Warm clones (`hellovm --template`) only: the template accepts
        // requests on its control socket (bound before the hardening) and
        // receives each clone's stdio fds with them; a clone's kernel
        // process puts itself in a Landlock domain of its own (a ruleset
        // without rules: only reduces what it may do).
        list.extend([
            checked(SYS_accept4, vec![one_of(3, &[SOCK_CLOEXEC])]),
            checked(SYS_recvmsg, vec![one_of(2, &[MSG_CMSG_CLOEXEC])]),
            allow(SYS_landlock_create_ruleset),
            checked(SYS_landlock_restrict_self, vec![one_of(1, &[0])]),
        ]);
    }
    list
}

/// `KVM_RUN` and `KVM_IRQ_LINE` (`linux/kvm.h`: `_IO(0xae, 0x80)` and
/// `_IOW(0xae, 0x61, struct kvm_irq_level)`).
pub const KVM_RUN: u32 = 0xae80;
pub const KVM_IRQ_LINE: u32 = 0x4008_ae61;

/// The terminal `ioctl`s both lists allow on any fd.
const TERMINAL_IOCTLS: [u32; 6] = [
    TCGETS as u32,
    TCSETS as u32,
    // glibc 2.42+ (Ubuntu 26.04) tcgetattr/tcsetattr.
    TCGETS2 as u32,
    TCSETS2 as u32,
    TIOCGWINSZ as u32,
    FIONBIO as u32,
];

/// The allowlist of a kernel process that runs its guest on the KVM
/// platform (`hellovm-platform-kvm`): `vm` is the VM's fd, `vcpus` the
/// vCPUs' fds. There are no app processes, so nothing of `ptrace`,
/// `process_vm_*`, `wait4`, `fork`, `execveat`, `kill`, pidfds,
/// `setsid` or `seccomp` (the seccomp platform's list has them). The
/// only `ioctl`s on KVM fds are `KVM_RUN` on a vCPU's fd and
/// `KVM_IRQ_LINE` (a vCPU's IRQ input, which makes it leave the VM) on
/// the VM's: the VM, its memory slots, its vCPUs and their registers are
/// all set up before the process confines itself, and `/dev/kvm` is
/// closed by then. Nothing can make another VM, map other memory into
/// this one, or change a vCPU's registers through KVM.
///
/// Measured with `HELLOVM_SECCOMP_LEARN` over the KVM suites (see
/// README, "The KVM platform"); the rest is as in [`entries`].
pub fn kvm_entries(vm: i32, vcpus: &[i32], tcp: bool) -> Vec<Entry> {
    let mut domains = vec![AF_UNIX];
    if tcp {
        domains.push(AF_INET);
    }
    let vcpus: Vec<u32> = vcpus.iter().map(|&fd| fd as u32).collect();
    vec![
        // Most frequent first: the filter checks the entries in order.
        checked_any(
            SYS_ioctl,
            vec![
                vec![Check::OneOf(0, vcpus), Check::OneOf(1, vec![KVM_RUN])],
                vec![one_of(0, &[vm]), Check::OneOf(1, vec![KVM_IRQ_LINE])],
                vec![Check::OneOf(1, TERMINAL_IOCTLS.to_vec())],
            ],
        ),
        allow(SYS_futex),
        allow(SYS_rt_sigreturn),
        // I/O on fds the kernel holds: the console, image files, sockets
        // to the egress proxy, pipes of std.
        allow(SYS_read),
        allow(SYS_write),
        allow(SYS_pread64),
        allow(SYS_close),
        allow(SYS_ppoll),
        checked(
            SYS_fcntl,
            vec![one_of(1, &[F_GETFD, F_SETFD, F_GETFL, F_DUPFD_CLOEXEC])],
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
        allow(SYS_fstat),
        allow(SYS_statx),
        allow(SYS_readlinkat),
        allow(SYS_getdents64),
        // Memory, never executable; `madvise` gives guest memory back.
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
        // Threads (the vCPUs' and the clock's start after the hardening)
        // and synchronisation.
        checked(SYS_clone, vec![one_of(0, &[THREAD])]),
        Entry {
            // glibc tries clone3 first and falls back to clone.
            nr: SYS_clone3 as u32,
            rule: Rule::Errno(ENOSYS as u32),
        },
        allow(SYS_set_robust_list),
        allow(SYS_rseq),
        allow(SYS_sched_getaffinity),
        allow(SYS_sched_yield),
        allow(SYS_exit),
        allow(SYS_exit_group),
        allow(SYS_gettid),
        allow(SYS_getpid),
        checked(SYS_prctl, vec![one_of(0, &[PR_SET_NAME])]),
        // Signals: std's guard pages.
        allow(SYS_rt_sigaction),
        allow(SYS_rt_sigprocmask),
        allow(SYS_restart_syscall),
        allow(SYS_sigaltstack),
        // Time.
        allow(SYS_clock_nanosleep),
        allow(SYS_clock_gettime),
        allow(SYS_gettimeofday),
        allow(SYS_getrandom),
        // SIGABRT is abort() after a panic.
        checked(SYS_tgkill, vec![one_of(2, &[SIGABRT])]),
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
    ]
}

fn checked_any(nr: c_long, groups: Vec<Vec<Check>>) -> Entry {
    Entry {
        nr: nr as u32,
        rule: Rule::AnyOf(groups),
    }
}

#[cfg(test)]
mod tests {
    /// The KVM list: one rule per syscall, and none of what only app
    /// processes need.
    #[test]
    fn kvm_list_has_no_process_control() {
        use libc::*;
        let entries = super::kvm_entries(4, &[5, 6], true);
        let mut nrs: Vec<u32> = entries.iter().map(|e| e.nr).collect();
        nrs.sort_unstable();
        nrs.dedup();
        assert_eq!(nrs.len(), entries.len(), "a syscall is listed twice");
        for nr in [
            SYS_ptrace,
            SYS_process_vm_readv,
            SYS_process_vm_writev,
            SYS_wait4,
            SYS_execveat,
            SYS_execve,
            SYS_kill,
            SYS_pidfd_open,
            SYS_pidfd_send_signal,
            SYS_setsid,
            SYS_seccomp,
            SYS_accept4,
            SYS_landlock_restrict_self,
        ] {
            assert!(!nrs.contains(&(nr as u32)), "syscall {nr}");
        }
    }

    /// `KVM_RUN` only on a vCPU's fd, `KVM_IRQ_LINE` only on the VM's,
    /// and no other KVM `ioctl` (`KVM_CREATE_VCPU`, `KVM_SET_ONE_REG`,
    /// `KVM_SET_USER_MEMORY_REGION`, `KVM_CREATE_VM` on any fd).
    #[test]
    fn kvm_ioctls_are_only_run_and_the_irq_line() {
        use crate::filter::{self, tests::data, Judge};
        let arch = crate::harden::audit_arch();
        let entries = super::kvm_entries(4, &[5, 6], false);
        let prog = filter::build(
            arch,
            std::slice::from_ref(&filter::EVERY_ADDRESS),
            Judge::Allowlist(&entries),
        )
        .unwrap();
        let ioctl = |fd: u64, req: u64| {
            crate::bpf::run(
                &prog,
                &data(arch, libc::SYS_ioctl as u32, 0x1000, [fd, req, 0, 0, 0, 0]),
            )
        };
        let (allow, kill) = (filter::SECCOMP_RET_ALLOW, filter::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(ioctl(5, 0xae80), allow);
        assert_eq!(ioctl(6, 0xae80), allow);
        assert_eq!(ioctl(4, 0x4008_ae61), allow);
        assert_eq!(ioctl(4, 0xae80), kill);
        assert_eq!(ioctl(5, 0x4008_ae61), kill);
        for req in [0xae01u64, 0xae41, 0x4010_aeac, 0x4020_ae46, 0x4020_aeae] {
            for fd in [3, 4, 5, 6] {
                assert_eq!(ioctl(fd, req), kill, "ioctl {req:#x} on fd {fd}");
            }
        }
        assert_eq!(ioctl(0, u64::from(libc::TCGETS as u32)), allow);
        // No syscall is left to a tracer: there are no app processes.
        let other = crate::bpf::run(
            &prog,
            &data(arch, libc::SYS_ptrace as u32, u64::MAX, [0; 6]),
        );
        assert_eq!(other, kill);
    }

    #[test]
    fn every_syscall_has_one_rule() {
        for (tcp, warm) in [(false, false), (true, false), (false, true), (true, true)] {
            let entries = super::entries(5, tcp, warm);
            let mut nrs: Vec<u32> = entries.iter().map(|e| e.nr).collect();
            nrs.sort_unstable();
            nrs.dedup();
            assert_eq!(nrs.len(), entries.len(), "a syscall is listed twice");
        }
    }

    /// What only a warm-clone template needs is refused to every other
    /// sandbox.
    #[test]
    fn warm_clone_syscalls_are_for_templates_only() {
        use crate::filter::{Check, Rule};
        use libc::*;
        let only = [
            SYS_accept4,
            SYS_recvmsg,
            SYS_landlock_create_ruleset,
            SYS_landlock_restrict_self,
        ];
        let has = |warm: bool, nr: c_long| {
            super::entries(5, true, warm)
                .iter()
                .any(|e| e.nr == nr as u32)
        };
        for nr in only {
            assert!(has(true, nr) && !has(false, nr), "syscall {nr}");
        }
        let seals = |warm: bool| {
            super::entries(5, false, warm).iter().any(|e| {
                e.nr == SYS_fcntl as u32
                    && matches!(&e.rule, Rule::Checked(checks) if checks.iter().any(
                        |c| matches!(c, Check::OneOf(1, v) if v.contains(&(F_ADD_SEALS as u32)))
                    ))
            })
        };
        assert!(seals(true) && !seals(false));
    }

    /// With `HELLOVM_SECCOMP_LEARNED_KVM=FILE`, a recording made by
    /// running the KVM suites with `HELLOVM_SECCOMP_LEARN=FILE` (see
    /// README, "The KVM platform"): the KVM filter must let every recorded
    /// syscall through. The fds of the recorded `KVM_RUN`s are taken as
    /// the vCPUs' and those of `KVM_IRQ_LINE` as the VM's (each run has
    /// its own), so for those two it checks the requests, not the fds.
    #[test]
    fn every_measured_kvm_syscall_is_allowed() {
        use crate::filter::{self, tests::data, Judge};
        let Some(path) = std::env::var_os("HELLOVM_SECCOMP_LEARNED_KVM") else {
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
            calls.len() >= 30,
            "only {} distinct calls recorded: the measuring run did not work",
            calls.len()
        );
        let ioctl = libc::SYS_ioctl as u64;
        let fds = |request: u32| -> Vec<i32> {
            let mut fds: Vec<i32> = calls
                .iter()
                .filter(|c| c[0] == ioctl && c[2] as u32 == request)
                .map(|c| c[1] as i32)
                .collect();
            fds.sort_unstable();
            fds.dedup();
            fds
        };
        let (vms, vcpus) = (fds(super::KVM_IRQ_LINE), fds(super::KVM_RUN));
        assert!(!vcpus.is_empty(), "no KVM_RUN recorded");
        let arch = crate::harden::audit_arch();
        let mut refused = Vec::new();
        for vm in vms.iter().copied().chain(vms.is_empty().then_some(-1)) {
            let entries = super::kvm_entries(vm, &vcpus, true);
            let prog = filter::build(
                arch,
                std::slice::from_ref(&filter::EVERY_ADDRESS),
                Judge::Allowlist(&entries),
            )
            .unwrap();
            for call in &calls {
                if call[0] == ioctl && call[2] as u32 == super::KVM_IRQ_LINE && call[1] as i32 != vm
                {
                    continue;
                }
                let args: [u64; 6] = call[1..].try_into().unwrap();
                let action = crate::bpf::run(&prog, &data(arch, call[0] as u32, 0x1000, args));
                let errno = action & 0xffff_0000 == filter::SECCOMP_RET_ERRNO;
                if action != filter::SECCOMP_RET_ALLOW && !errno {
                    refused.push(format!("syscall {} {args:x?}", call[0]));
                }
            }
        }
        refused.sort();
        refused.dedup();
        assert!(
            refused.is_empty(),
            "the kernel process on the KVM platform made syscalls its allowlist refuses:\n{}",
            refused.join("\n")
        );
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
        // through without recording it. `tcp`: the `--splice-to` tests;
        // `warm`: the template tests.
        let entries = super::entries(3, true, true);
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
