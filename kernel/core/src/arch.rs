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

// Only the syscalls a static hello world and a minimal libc start-up touch are
// named for now; the list grows as emulation does.
sysnos! {
    Read => ("read", 3),
    Write => ("write", 3),
    Writev => ("writev", 3),
    Openat => ("openat", 4),
    Close => ("close", 1),
    Fstat => ("fstat", 2),
    Ioctl => ("ioctl", 3),
    Mmap => ("mmap", 6),
    Munmap => ("munmap", 2),
    Mprotect => ("mprotect", 3),
    Brk => ("brk", 1),
    RtSigaction => ("rt_sigaction", 4),
    RtSigprocmask => ("rt_sigprocmask", 4),
    Getpid => ("getpid", 0),
    Gettid => ("gettid", 0),
    Getuid => ("getuid", 0),
    Uname => ("uname", 1),
    ArchPrctl => ("arch_prctl", 2),
    SetTidAddress => ("set_tid_address", 1),
    ClockGettime => ("clock_gettime", 2),
    Execve => ("execve", 3),
    Exit => ("exit", 1),
    ExitGroup => ("exit_group", 1),
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
        Close = 3,
        Fstat = 5,
        Mmap = 9,
        Mprotect = 10,
        Munmap = 11,
        Brk = 12,
        RtSigaction = 13,
        RtSigprocmask = 14,
        Ioctl = 16,
        Writev = 20,
        Getpid = 39,
        Execve = 59,
        Exit = 60,
        Uname = 63,
        Getuid = 102,
        ArchPrctl = 158,
        Gettid = 186,
        SetTidAddress = 218,
        ClockGettime = 228,
        ExitGroup = 231,
        Openat = 257,
    }
}

syscall_table! {
    /// aarch64 syscall numbers (the generic table, `include/uapi/asm-generic/unistd.h`).
    aarch64 {
        Ioctl = 29,
        Openat = 56,
        Close = 57,
        Read = 63,
        Write = 64,
        Writev = 66,
        Fstat = 80,
        Exit = 93,
        ExitGroup = 94,
        SetTidAddress = 96,
        ClockGettime = 113,
        RtSigaction = 134,
        RtSigprocmask = 135,
        Uname = 160,
        Getpid = 172,
        Getuid = 174,
        Gettid = 178,
        Brk = 214,
        Munmap = 215,
        Execve = 221,
        Mmap = 222,
        Mprotect = 226,
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
        // arch_prctl only exists on x86_64.
        assert_eq!(Arch::Aarch64.syscall_nr(Sysno::ArchPrctl), None);
    }
}
