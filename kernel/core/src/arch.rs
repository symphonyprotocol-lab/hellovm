//! Guest CPU architectures and their syscall numbering.
//!
//! The kernel core works with [`Sysno`], an architecture-neutral identifier
//! for a syscall. Each guest architecture has its own table that maps the raw
//! number found in the syscall register to a [`Sysno`]. Adding a syscall means
//! adding a variant to [`Sysno`] and an entry to each table that has it.
//!
//! The tables only list syscalls the kernel knows by name. A raw number with
//! no entry is still handled (it fails with `ENOSYS`), it just has no name in
//! logs and traces.

use std::fmt;

/// A guest CPU architecture, i.e. a Linux syscall ABI the kernel can serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// All architectures the kernel core knows.
    pub const ALL: [Arch; 2] = [Arch::X86_64, Arch::Aarch64];

    /// The architecture this crate was compiled for, if it is a supported
    /// guest architecture. Platforms that run guest code natively (seccomp)
    /// can only run guests of this architecture.
    pub const fn native() -> Option<Arch> {
        if cfg!(target_arch = "x86_64") {
            Some(Arch::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Arch::Aarch64)
        } else {
            None
        }
    }

    /// Maps a raw syscall number of this architecture to a [`Sysno`].
    pub fn sysno(self, nr: u64) -> Option<Sysno> {
        match self {
            Arch::X86_64 => x86_64::lookup(nr),
            Arch::Aarch64 => aarch64::lookup(nr),
        }
    }

    /// The raw number of `sysno` on this architecture, if it exists there.
    pub fn syscall_nr(self, sysno: Sysno) -> Option<u64> {
        match self {
            Arch::X86_64 => x86_64::number(sysno),
            Arch::Aarch64 => aarch64::number(sysno),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

macro_rules! sysnos {
    ($($variant:ident => ($name:literal, $nargs:literal)),* $(,)?) => {
        /// An architecture-neutral syscall identifier.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Sysno {
            $($variant,)*
        }

        impl Sysno {
            /// The syscall's Linux name, as used in traces.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Sysno::$variant => $name,)*
                }
            }

            /// The number of arguments the syscall takes (for traces).
            pub const fn arg_count(self) -> usize {
                match self {
                    $(Sysno::$variant => $nargs,)*
                }
            }
        }
    };
}

// Every syscall the kernel emulates or knows it refuses, so that traces and
// logs show names. The list grows as emulation does.
sysnos! {
    Read => ("read", 3),
    Write => ("write", 3),
    Open => ("open", 3),
    Close => ("close", 1),
    Stat => ("stat", 2),
    Fstat => ("fstat", 2),
    Lstat => ("lstat", 2),
    Poll => ("poll", 3),
    Lseek => ("lseek", 3),
    Mmap => ("mmap", 6),
    Mprotect => ("mprotect", 3),
    Munmap => ("munmap", 2),
    Brk => ("brk", 1),
    RtSigaction => ("rt_sigaction", 4),
    RtSigprocmask => ("rt_sigprocmask", 4),
    RtSigreturn => ("rt_sigreturn", 0),
    Ioctl => ("ioctl", 3),
    Pread64 => ("pread64", 4),
    Pwrite64 => ("pwrite64", 4),
    Readv => ("readv", 3),
    Writev => ("writev", 3),
    Access => ("access", 2),
    Pipe => ("pipe", 1),
    Select => ("select", 5),
    SchedYield => ("sched_yield", 0),
    Mremap => ("mremap", 5),
    Msync => ("msync", 3),
    Mincore => ("mincore", 3),
    Madvise => ("madvise", 3),
    Dup => ("dup", 1),
    Dup2 => ("dup2", 2),
    Pause => ("pause", 0),
    Nanosleep => ("nanosleep", 2),
    Getitimer => ("getitimer", 2),
    Alarm => ("alarm", 1),
    Setitimer => ("setitimer", 3),
    Getpid => ("getpid", 0),
    Sendfile => ("sendfile", 4),
    Socket => ("socket", 3),
    Clone => ("clone", 5),
    Fork => ("fork", 0),
    Vfork => ("vfork", 0),
    Execve => ("execve", 3),
    Exit => ("exit", 1),
    Wait4 => ("wait4", 4),
    Kill => ("kill", 2),
    Uname => ("uname", 1),
    Fcntl => ("fcntl", 3),
    Flock => ("flock", 2),
    Fsync => ("fsync", 1),
    Fdatasync => ("fdatasync", 1),
    Truncate => ("truncate", 2),
    Ftruncate => ("ftruncate", 2),
    Getdents => ("getdents", 3),
    Getcwd => ("getcwd", 2),
    Chdir => ("chdir", 1),
    Fchdir => ("fchdir", 1),
    Rename => ("rename", 2),
    Mkdir => ("mkdir", 2),
    Rmdir => ("rmdir", 1),
    Creat => ("creat", 2),
    Link => ("link", 2),
    Unlink => ("unlink", 1),
    Symlink => ("symlink", 2),
    Readlink => ("readlink", 3),
    Chmod => ("chmod", 2),
    Fchmod => ("fchmod", 2),
    Chown => ("chown", 3),
    Fchown => ("fchown", 3),
    Lchown => ("lchown", 3),
    Umask => ("umask", 1),
    Gettimeofday => ("gettimeofday", 2),
    Getrlimit => ("getrlimit", 2),
    Getrusage => ("getrusage", 2),
    Sysinfo => ("sysinfo", 1),
    Times => ("times", 1),
    Getuid => ("getuid", 0),
    Getgid => ("getgid", 0),
    Setuid => ("setuid", 1),
    Setgid => ("setgid", 1),
    Geteuid => ("geteuid", 0),
    Getegid => ("getegid", 0),
    Setpgid => ("setpgid", 2),
    Getppid => ("getppid", 0),
    Getpgrp => ("getpgrp", 0),
    Setsid => ("setsid", 0),
    Getgroups => ("getgroups", 2),
    Setgroups => ("setgroups", 2),
    Getresuid => ("getresuid", 3),
    Getresgid => ("getresgid", 3),
    Getpgid => ("getpgid", 1),
    Getsid => ("getsid", 1),
    Sigaltstack => ("sigaltstack", 2),
    Utime => ("utime", 2),
    Mknod => ("mknod", 3),
    Statfs => ("statfs", 2),
    Fstatfs => ("fstatfs", 2),
    Getpriority => ("getpriority", 2),
    Setpriority => ("setpriority", 3),
    Prctl => ("prctl", 5),
    ArchPrctl => ("arch_prctl", 2),
    Setrlimit => ("setrlimit", 2),
    Sync => ("sync", 0),
    Gettid => ("gettid", 0),
    Tkill => ("tkill", 2),
    Time => ("time", 1),
    Futex => ("futex", 6),
    SchedGetaffinity => ("sched_getaffinity", 3),
    Getdents64 => ("getdents64", 3),
    SetTidAddress => ("set_tid_address", 1),
    Fadvise64 => ("fadvise64", 4),
    ClockGettime => ("clock_gettime", 2),
    ClockGetres => ("clock_getres", 2),
    ClockNanosleep => ("clock_nanosleep", 4),
    ExitGroup => ("exit_group", 1),
    Tgkill => ("tgkill", 3),
    Utimes => ("utimes", 2),
    Waitid => ("waitid", 5),
    Openat => ("openat", 4),
    Mkdirat => ("mkdirat", 3),
    Mknodat => ("mknodat", 4),
    Fchownat => ("fchownat", 5),
    Futimesat => ("futimesat", 3),
    Newfstatat => ("newfstatat", 4),
    Unlinkat => ("unlinkat", 3),
    Renameat => ("renameat", 4),
    Linkat => ("linkat", 5),
    Symlinkat => ("symlinkat", 3),
    Readlinkat => ("readlinkat", 4),
    Fchmodat => ("fchmodat", 3),
    Faccessat => ("faccessat", 3),
    Pselect6 => ("pselect6", 6),
    Ppoll => ("ppoll", 5),
    SetRobustList => ("set_robust_list", 2),
    GetRobustList => ("get_robust_list", 3),
    Utimensat => ("utimensat", 4),
    Dup3 => ("dup3", 3),
    Pipe2 => ("pipe2", 2),
    Preadv => ("preadv", 4),
    Pwritev => ("pwritev", 4),
    Prlimit64 => ("prlimit64", 4),
    Getcpu => ("getcpu", 3),
    Renameat2 => ("renameat2", 5),
    Getrandom => ("getrandom", 3),
    Execveat => ("execveat", 5),
    Membarrier => ("membarrier", 2),
    CopyFileRange => ("copy_file_range", 6),
    Statx => ("statx", 5),
    Rseq => ("rseq", 4),
    Clone3 => ("clone3", 2),
    CloseRange => ("close_range", 3),
    Faccessat2 => ("faccessat2", 4),
    Fchmodat2 => ("fchmodat2", 4),
    RtSigsuspend => ("rt_sigsuspend", 2),
    RtSigpending => ("rt_sigpending", 2),
    RtSigtimedwait => ("rt_sigtimedwait", 4),
    RtSigqueueinfo => ("rt_sigqueueinfo", 3),
    RtTgsigqueueinfo => ("rt_tgsigqueueinfo", 4),
    Setreuid => ("setreuid", 2),
    Setregid => ("setregid", 2),
    Setresuid => ("setresuid", 3),
    Setresgid => ("setresgid", 3),
    Setfsuid => ("setfsuid", 1),
    Setfsgid => ("setfsgid", 1),
    Socketpair => ("socketpair", 4),
    Eventfd2 => ("eventfd2", 2),
    EpollCreate1 => ("epoll_create1", 1),
    EpollCtl => ("epoll_ctl", 4),
    EpollPwait => ("epoll_pwait", 6),
    SchedSetaffinity => ("sched_setaffinity", 3),
    SchedGetparam => ("sched_getparam", 2),
    SchedGetscheduler => ("sched_getscheduler", 1),
    SchedSetscheduler => ("sched_setscheduler", 3),
    SchedGetPriorityMax => ("sched_get_priority_max", 1),
    SchedGetPriorityMin => ("sched_get_priority_min", 1),
    Mlock => ("mlock", 2),
    Munlock => ("munlock", 2),
    PidfdOpen => ("pidfd_open", 2),
    PidfdSendSignal => ("pidfd_send_signal", 4),
    Capget => ("capget", 2),
    Personality => ("personality", 1),
    RestartSyscall => ("restart_syscall", 0),
    Vhangup => ("vhangup", 0),
}

macro_rules! syscall_table {
    ($(#[$meta:meta])* $module:ident { $($variant:ident = $nr:literal),* $(,)? }) => {
        $(#[$meta])*
        pub mod $module {
            use super::Sysno;

            /// Maps a raw syscall number to a [`Sysno`].
            pub fn lookup(nr: u64) -> Option<Sysno> {
                match nr {
                    $($nr => Some(Sysno::$variant),)*
                    _ => None,
                }
            }

            /// Maps a [`Sysno`] to its raw number, if this table has it.
            pub fn number(sysno: Sysno) -> Option<u64> {
                #[allow(unreachable_patterns)]
                match sysno {
                    $(Sysno::$variant => Some($nr),)*
                    _ => None,
                }
            }
        }
    };
}

syscall_table! {
    /// x86_64 syscall numbers (`arch/x86/entry/syscalls/syscall_64.tbl`).
    x86_64 {
        Read = 0,
        Write = 1,
        Open = 2,
        Close = 3,
        Stat = 4,
        Fstat = 5,
        Lstat = 6,
        Poll = 7,
        Lseek = 8,
        Mmap = 9,
        Mprotect = 10,
        Munmap = 11,
        Brk = 12,
        RtSigaction = 13,
        RtSigprocmask = 14,
        RtSigreturn = 15,
        Ioctl = 16,
        Pread64 = 17,
        Pwrite64 = 18,
        Readv = 19,
        Writev = 20,
        Access = 21,
        Pipe = 22,
        Select = 23,
        SchedYield = 24,
        Mremap = 25,
        Msync = 26,
        Mincore = 27,
        Madvise = 28,
        Dup = 32,
        Dup2 = 33,
        Pause = 34,
        Nanosleep = 35,
        Getitimer = 36,
        Alarm = 37,
        Setitimer = 38,
        Getpid = 39,
        Sendfile = 40,
        Socket = 41,
        Clone = 56,
        Fork = 57,
        Vfork = 58,
        Execve = 59,
        Exit = 60,
        Wait4 = 61,
        Kill = 62,
        Uname = 63,
        Fcntl = 72,
        Flock = 73,
        Fsync = 74,
        Fdatasync = 75,
        Truncate = 76,
        Ftruncate = 77,
        Getdents = 78,
        Getcwd = 79,
        Chdir = 80,
        Fchdir = 81,
        Rename = 82,
        Mkdir = 83,
        Rmdir = 84,
        Creat = 85,
        Link = 86,
        Unlink = 87,
        Symlink = 88,
        Readlink = 89,
        Chmod = 90,
        Fchmod = 91,
        Chown = 92,
        Fchown = 93,
        Lchown = 94,
        Umask = 95,
        Gettimeofday = 96,
        Getrlimit = 97,
        Getrusage = 98,
        Sysinfo = 99,
        Times = 100,
        Getuid = 102,
        Getgid = 104,
        Setuid = 105,
        Setgid = 106,
        Geteuid = 107,
        Getegid = 108,
        Setpgid = 109,
        Getppid = 110,
        Getpgrp = 111,
        Setsid = 112,
        Getgroups = 115,
        Setgroups = 116,
        Getresuid = 118,
        Getresgid = 120,
        Getpgid = 121,
        Getsid = 124,
        Sigaltstack = 131,
        Utime = 132,
        Mknod = 133,
        Statfs = 137,
        Fstatfs = 138,
        Getpriority = 140,
        Setpriority = 141,
        Prctl = 157,
        ArchPrctl = 158,
        Setrlimit = 160,
        Sync = 162,
        Gettid = 186,
        Tkill = 200,
        Time = 201,
        Futex = 202,
        SchedGetaffinity = 204,
        Getdents64 = 217,
        SetTidAddress = 218,
        Fadvise64 = 221,
        ClockGettime = 228,
        ClockGetres = 229,
        ClockNanosleep = 230,
        ExitGroup = 231,
        Tgkill = 234,
        Utimes = 235,
        Waitid = 247,
        Openat = 257,
        Mkdirat = 258,
        Mknodat = 259,
        Fchownat = 260,
        Futimesat = 261,
        Newfstatat = 262,
        Unlinkat = 263,
        Renameat = 264,
        Linkat = 265,
        Symlinkat = 266,
        Readlinkat = 267,
        Fchmodat = 268,
        Faccessat = 269,
        Pselect6 = 270,
        Ppoll = 271,
        SetRobustList = 273,
        GetRobustList = 274,
        Utimensat = 280,
        Dup3 = 292,
        Pipe2 = 293,
        Preadv = 295,
        Pwritev = 296,
        Prlimit64 = 302,
        Getcpu = 309,
        Renameat2 = 316,
        Getrandom = 318,
        Execveat = 322,
        Membarrier = 324,
        CopyFileRange = 326,
        Statx = 332,
        Rseq = 334,
        Clone3 = 435,
        CloseRange = 436,
        Faccessat2 = 439,
        Fchmodat2 = 452,
        RtSigsuspend = 130,
        RtSigpending = 127,
        RtSigtimedwait = 128,
        RtSigqueueinfo = 129,
        RtTgsigqueueinfo = 297,
        Setreuid = 113,
        Setregid = 114,
        Setresuid = 117,
        Setresgid = 119,
        Setfsuid = 122,
        Setfsgid = 123,
        Socketpair = 53,
        Eventfd2 = 290,
        EpollCreate1 = 291,
        EpollCtl = 233,
        EpollPwait = 281,
        SchedSetaffinity = 203,
        SchedGetparam = 143,
        SchedGetscheduler = 145,
        SchedSetscheduler = 144,
        SchedGetPriorityMax = 146,
        SchedGetPriorityMin = 147,
        Mlock = 149,
        Munlock = 150,
        PidfdOpen = 434,
        PidfdSendSignal = 424,
        Capget = 125,
        Personality = 135,
        RestartSyscall = 219,
        Vhangup = 153,
    }
}

syscall_table! {
    /// aarch64 syscall numbers (the generic table, `include/uapi/asm-generic/unistd.h`).
    aarch64 {
        Getcwd = 17,
        Dup = 23,
        Dup3 = 24,
        Fcntl = 25,
        Ioctl = 29,
        Flock = 32,
        Mknodat = 33,
        Mkdirat = 34,
        Unlinkat = 35,
        Symlinkat = 36,
        Linkat = 37,
        Renameat = 38,
        Statfs = 43,
        Fstatfs = 44,
        Truncate = 45,
        Ftruncate = 46,
        Faccessat = 48,
        Chdir = 49,
        Fchdir = 50,
        Fchmod = 52,
        Fchmodat = 53,
        Fchownat = 54,
        Fchown = 55,
        Openat = 56,
        Close = 57,
        Pipe2 = 59,
        Getdents64 = 61,
        Lseek = 62,
        Read = 63,
        Write = 64,
        Readv = 65,
        Writev = 66,
        Pread64 = 67,
        Pwrite64 = 68,
        Preadv = 69,
        Pwritev = 70,
        Sendfile = 71,
        Pselect6 = 72,
        Ppoll = 73,
        Readlinkat = 78,
        Newfstatat = 79,
        Fstat = 80,
        Sync = 81,
        Fsync = 82,
        Fdatasync = 83,
        Utimensat = 88,
        Exit = 93,
        ExitGroup = 94,
        Waitid = 95,
        SetTidAddress = 96,
        Futex = 98,
        SetRobustList = 99,
        GetRobustList = 100,
        Nanosleep = 101,
        Getitimer = 102,
        Setitimer = 103,
        ClockGettime = 113,
        ClockGetres = 114,
        ClockNanosleep = 115,
        SchedGetaffinity = 123,
        SchedYield = 124,
        Kill = 129,
        Tkill = 130,
        Tgkill = 131,
        Sigaltstack = 132,
        RtSigaction = 134,
        RtSigprocmask = 135,
        RtSigreturn = 139,
        Setpriority = 140,
        Getpriority = 141,
        Setgid = 144,
        Setuid = 146,
        Getresuid = 148,
        Getresgid = 150,
        Times = 153,
        Setpgid = 154,
        Getpgid = 155,
        Getsid = 156,
        Setsid = 157,
        Getgroups = 158,
        Setgroups = 159,
        Uname = 160,
        Getrlimit = 163,
        Setrlimit = 164,
        Getrusage = 165,
        Umask = 166,
        Prctl = 167,
        Getcpu = 168,
        Gettimeofday = 169,
        Getpid = 172,
        Getppid = 173,
        Getuid = 174,
        Geteuid = 175,
        Getgid = 176,
        Getegid = 177,
        Gettid = 178,
        Sysinfo = 179,
        Socket = 198,
        Brk = 214,
        Munmap = 215,
        Mremap = 216,
        Clone = 220,
        Execve = 221,
        Mmap = 222,
        Fadvise64 = 223,
        Mprotect = 226,
        Msync = 227,
        Mincore = 232,
        Madvise = 233,
        Wait4 = 260,
        Prlimit64 = 261,
        Renameat2 = 276,
        Getrandom = 278,
        Execveat = 281,
        Membarrier = 283,
        CopyFileRange = 285,
        Statx = 291,
        Rseq = 293,
        Clone3 = 435,
        CloseRange = 436,
        Faccessat2 = 439,
        Fchmodat2 = 452,
        RtSigsuspend = 133,
        RtSigpending = 136,
        RtSigtimedwait = 137,
        RtSigqueueinfo = 138,
        RtTgsigqueueinfo = 240,
        Setreuid = 145,
        Setregid = 143,
        Setresuid = 147,
        Setresgid = 149,
        Setfsuid = 151,
        Setfsgid = 152,
        Socketpair = 199,
        Eventfd2 = 19,
        EpollCreate1 = 20,
        EpollCtl = 21,
        EpollPwait = 22,
        SchedSetaffinity = 122,
        SchedGetparam = 121,
        SchedGetscheduler = 120,
        SchedSetscheduler = 119,
        SchedGetPriorityMax = 125,
        SchedGetPriorityMin = 126,
        Mlock = 228,
        Munlock = 229,
        PidfdOpen = 434,
        PidfdSendSignal = 424,
        Capget = 90,
        Personality = 92,
        RestartSyscall = 128,
        Vhangup = 58,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_round_trip() {
        for arch in Arch::ALL {
            for nr in 0..1024 {
                if let Some(sysno) = arch.sysno(nr) {
                    assert_eq!(arch.syscall_nr(sysno), Some(nr), "{arch} {sysno:?}");
                }
            }
        }
    }

    #[test]
    fn architectures_differ() {
        assert_eq!(Arch::X86_64.syscall_nr(Sysno::Write), Some(1));
        assert_eq!(Arch::Aarch64.syscall_nr(Sysno::Write), Some(64));
        assert_eq!(Arch::X86_64.sysno(231), Some(Sysno::ExitGroup));
        assert_eq!(Arch::Aarch64.sysno(94), Some(Sysno::ExitGroup));
        // arch_prctl and the legacy path syscalls only exist on x86_64.
        assert_eq!(Arch::Aarch64.syscall_nr(Sysno::ArchPrctl), None);
        assert_eq!(Arch::Aarch64.syscall_nr(Sysno::Open), None);
        assert_eq!(Arch::X86_64.syscall_nr(Sysno::Newfstatat), Some(262));
        assert_eq!(Arch::Aarch64.syscall_nr(Sysno::Newfstatat), Some(79));
        assert_eq!(Arch::Aarch64.sysno(281), Some(Sysno::Execveat));
        assert_eq!(Arch::X86_64.sysno(322), Some(Sysno::Execveat));
    }
}
