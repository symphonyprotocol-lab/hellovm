//! The kernel process's own seccomp filter.
//!
//! # Telling the kernel process from its app processes
//!
//! App processes are forked from the kernel process (K), so they inherit
//! this filter, and their own filter (`SECCOMP_RET_TRACE` for everything,
//! see `hellovm-platform-seccomp`) stacks on top of it. Seccomp runs every
//! filter and the most severe action wins, so if this filter simply killed
//! every syscall outside K's allowlist, it would kill app processes making
//! syscalls K never makes (the guest's `open`, which is trapped and
//! emulated), before K ever saw them.
//!
//! So the filter judges a syscall by where it was made from
//! (`seccomp_data.instruction_pointer`):
//!
//! * From inside one of K's executable mappings (its binary, the C
//!   library, the dynamic linker, the vDSO; taken once at start-up, see
//!   `hellovm_platform_seccomp::HostProfile`): K's allowlist, with argument
//!   checks; anything else **kills the process**. This is every syscall K
//!   and its helper threads make, and the bootstrap of a new app process
//!   before it `execveat`s the stub (it runs K's code).
//! * From anywhere else: `SECCOMP_RET_TRACE`. In an app process that is
//!   what its own filter returns anyway, so nothing changes for the guest:
//!   K sees the stop and emulates or skips the syscall, or lets an
//!   injected one through. In K itself (which nobody traces) a syscall
//!   from outside its code (say, from a copy of a code page an attacker
//!   made) fails with `ENOSYS` and is not executed.
//!
//! App code can never run at an address in K's code ranges: the platform
//! reserves them in every app address space, and an app process starts
//! from an empty one. Even if it did, the result would only be that the
//! app process is killed or still trapped (`ALLOW` combined with the app's
//! `TRACE` is `TRACE`), never a syscall that runs unseen.
//!
//! Non-native syscall ABIs (i386 `int 0x80`, x32, arm32) kill, as they do
//! in app processes.
//!
//! # What this cannot stop
//!
//! K drives its app processes with ptrace and can make them execute any
//! syscall through the stub (that is the design: `mmap`, `munmap`,
//! `mprotect`, `clone` with arguments it writes). An attacker who gets
//! *arbitrary code execution* in K can do the same with other syscalls,
//! or fork a child of its own and trace it. Against that, the layers that
//! app processes inherit are the fence: Landlock, the namespaces and the
//! resource limits. This filter shrinks the host kernel's attack surface
//! reachable from K, turns a confused-deputy bug (K making a syscall it
//! should not) into a dead process, and makes an exploit go through the
//! ptrace dance instead of calling `socket` or `open` directly.

use std::ops::Range;

use crate::bpf::{self, Asm, Target};

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// A condition on the low 32 bits of a syscall argument.
#[derive(Clone, Debug)]
pub enum Check {
    /// The argument is one of these values.
    OneOf(usize, Vec<u32>),
    /// The argument has no bit outside this mask.
    Subset(usize, u32),
    /// The high 32 bits of the argument are zero (for `long` arguments
    /// the host kernel uses in full).
    HighZero(usize),
}

/// What happens to an allowed syscall number.
#[derive(Clone, Debug)]
pub enum Rule {
    Allow,
    /// Fails with this errno (for syscalls the C library tries and has a
    /// fallback for, such as `clone3`).
    Errno(u32),
    /// Allowed when every check passes; otherwise the process is killed.
    Checked(Vec<Check>),
}

/// One allowlist entry.
#[derive(Clone, Debug)]
pub struct Entry {
    pub nr: u32,
    pub rule: Rule,
}

/// Emits the instruction-pointer test: jumps to `inside` when the IP is in
/// one of `code` (end inclusive), falls through otherwise.
fn ip_in_ranges(asm: &mut Asm, code: &[Range<u64>], inside: bpf::Label) {
    for range in code {
        let next = asm.label();
        let check_end = asm.label();
        let hit = asm.label();
        let (s_hi, s_lo) = ((range.start >> 32) as u32, range.start as u32);
        // Inclusive end: the IP seccomp sees is just past the syscall
        // instruction.
        let end = range.end;
        let (e_hi, e_lo) = ((end >> 32) as u32, end as u32);
        // ip >= start
        asm.load(bpf::IP_HI);
        asm.jgt(s_hi, Target::To(check_end), Target::Next);
        asm.jeq(s_hi, Target::Next, Target::To(next));
        asm.load(bpf::IP_LO);
        asm.jge(s_lo, Target::Next, Target::To(next));
        // ip <= end
        asm.here(check_end);
        asm.load(bpf::IP_HI);
        asm.jgt(e_hi, Target::To(next), Target::Next);
        asm.jeq(e_hi, Target::Next, Target::To(hit));
        asm.load(bpf::IP_LO);
        asm.jgt(e_lo, Target::To(next), Target::To(hit));
        // A long jump, so that any number of ranges assembles.
        asm.here(hit);
        asm.ja(inside);
        asm.here(next);
    }
}

fn emit_check(asm: &mut Asm, check: &Check, fail: bpf::Label) {
    match check {
        Check::OneOf(arg, values) => {
            let ok = asm.label();
            asm.load(bpf::arg_lo(*arg));
            for &v in values {
                asm.jeq(v, Target::To(ok), Target::Next);
            }
            asm.ja(fail);
            asm.here(ok);
        }
        Check::Subset(arg, mask) => {
            asm.load(bpf::arg_lo(*arg));
            asm.jset(!mask, Target::To(fail), Target::Next);
        }
        Check::HighZero(arg) => {
            asm.load(bpf::arg_hi(*arg));
            asm.jeq(0, Target::Next, Target::To(fail));
        }
    }
}

/// How syscalls made from K's own code are judged.
pub enum Judge<'a> {
    /// The allowlist; anything else kills.
    Allowlist(&'a [Entry]),
    /// Every syscall but `execveat` (this number) goes to the learning
    /// supervisor (`learn`).
    #[cfg_attr(not(feature = "insecure-test-hooks"), allow(dead_code))]
    Learn { execveat: u32 },
}

/// The filter: see the module documentation.
pub fn build(
    audit_arch: u32,
    code: &[Range<u64>],
    judge: Judge<'_>,
) -> Result<Vec<libc::sock_filter>, String> {
    let mut asm = Asm::default();
    let native = asm.label();
    let inside = asm.label();
    asm.load(bpf::ARCH);
    asm.jeq(audit_arch, Target::To(native), Target::Next);
    asm.ret(SECCOMP_RET_KILL_PROCESS);
    asm.here(native);
    ip_in_ranges(&mut asm, code, inside);
    asm.ret(SECCOMP_RET_TRACE);
    asm.here(inside);
    match judge {
        Judge::Learn { execveat } => {
            // A new app process's `execveat` of the stub runs K's code
            // under the app's TRACE filter too; USER_NOTIF would outrank
            // TRACE and let it run unseen, so it is allowed (the allowlist
            // allows it as well).
            let other = asm.label();
            asm.load(bpf::NR);
            asm.jeq(execveat, Target::Next, Target::To(other));
            asm.ret(SECCOMP_RET_ALLOW);
            asm.here(other);
            asm.ret(SECCOMP_RET_USER_NOTIF);
        }
        Judge::Allowlist(entries) => {
            asm.load(bpf::NR);
            for entry in entries {
                let skip = asm.label();
                asm.jeq(entry.nr, Target::Next, Target::To(skip));
                match &entry.rule {
                    Rule::Allow => asm.ret(SECCOMP_RET_ALLOW),
                    Rule::Errno(errno) => asm.ret(SECCOMP_RET_ERRNO | (errno & 0xffff)),
                    Rule::Checked(checks) => {
                        let fail = asm.label();
                        for check in checks {
                            emit_check(&mut asm, check, fail);
                        }
                        asm.ret(SECCOMP_RET_ALLOW);
                        asm.here(fail);
                        asm.ret(SECCOMP_RET_KILL_PROCESS);
                    }
                }
                asm.here(skip);
                // Bodies end in a return, so A must be reloaded.
                if matches!(entry.rule, Rule::Checked(_)) {
                    asm.load(bpf::NR);
                }
            }
            asm.ret(SECCOMP_RET_KILL_PROCESS);
        }
    }
    asm.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCH: u32 = 0xc000_00b7;

    fn data(arch: u32, nr: u32, ip: u64, args: [u64; 6]) -> [u8; 64] {
        let mut d = [0u8; 64];
        d[0..4].copy_from_slice(&nr.to_ne_bytes());
        d[4..8].copy_from_slice(&arch.to_ne_bytes());
        d[8..16].copy_from_slice(&ip.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            d[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
        }
        d
    }

    fn rules() -> Vec<Entry> {
        vec![
            Entry {
                nr: 1,
                rule: Rule::Allow,
            },
            Entry {
                nr: 2,
                rule: Rule::Errno(38),
            },
            Entry {
                nr: 3,
                rule: Rule::Checked(vec![
                    Check::OneOf(0, vec![1, 7]),
                    Check::Subset(1, 0b11),
                    Check::HighZero(2),
                ]),
            },
        ]
    }

    #[test]
    fn judges_by_instruction_pointer_and_arguments() {
        let code = [
            0x5555_0000_1000..0x5555_0000_3000,
            0x7fff_0000_0000..0x7fff_0001_0000,
        ];
        let entries = rules();
        let prog = build(ARCH, &code, Judge::Allowlist(&entries)).unwrap();
        let run = |arch, nr, ip, args| bpf::run(&prog, &data(arch, nr, ip, args));
        let k = 0x5555_0000_2000;
        // Foreign ABI: killed wherever it comes from.
        assert_eq!(run(0x4000_0003, 1, k, [0; 6]), SECCOMP_RET_KILL_PROCESS);
        assert_eq!(
            run(0x4000_0003, 1, 0x1000, [0; 6]),
            SECCOMP_RET_KILL_PROCESS
        );
        // Outside K's code: deferred to a tracer (the app's own filter).
        for ip in [
            0x1000,
            0x5555_0000_0fff,
            0x5555_0000_3001,
            0x7ffe_ffff_ffff,
            0x7fff_0001_0001,
            u64::MAX,
        ] {
            assert_eq!(run(ARCH, 99, ip, [0; 6]), SECCOMP_RET_TRACE, "{ip:#x}");
        }
        // Inside, both ends included.
        for ip in [
            0x5555_0000_1000,
            0x5555_0000_3000,
            0x7fff_0000_0000,
            0x7fff_0001_0000,
        ] {
            assert_eq!(run(ARCH, 1, ip, [0; 6]), SECCOMP_RET_ALLOW, "{ip:#x}");
            assert_eq!(
                run(ARCH, 99, ip, [0; 6]),
                SECCOMP_RET_KILL_PROCESS,
                "{ip:#x}"
            );
        }
        assert_eq!(run(ARCH, 2, k, [0; 6]), SECCOMP_RET_ERRNO | 38);
        assert_eq!(run(ARCH, 3, k, [7, 0b10, 5, 0, 0, 0]), SECCOMP_RET_ALLOW);
        assert_eq!(
            run(ARCH, 3, k, [1 | 1 << 40, 0, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            run(ARCH, 3, k, [2, 0, 0, 0, 0, 0]),
            SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            run(ARCH, 3, k, [1, 0b100, 0, 0, 0, 0]),
            SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            run(ARCH, 3, k, [1, 0, 1 << 32, 0, 0, 0]),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn many_ranges_and_the_real_allowlist_assemble() {
        let code: Vec<_> = (0..64u64).map(|i| i << 32..(i << 32) + 0x1000).collect();
        let entries = crate::allowlist::entries(7, true);
        let prog = build(ARCH, &code, Judge::Allowlist(&entries)).unwrap();
        assert!(prog.len() < 4096);
        let read = libc::SYS_read as u32;
        assert_eq!(
            bpf::run(&prog, &data(ARCH, read, 63 << 32, [0; 6])),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            bpf::run(&prog, &data(ARCH, read, 64 << 32, [0; 6])),
            SECCOMP_RET_TRACE
        );
        let learn = build(ARCH, &code, Judge::Learn { execveat: 5 }).unwrap();
        assert_eq!(
            bpf::run(&learn, &data(ARCH, 5, 1 << 32, [0; 6])),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            bpf::run(&learn, &data(ARCH, 6, 1 << 32, [0; 6])),
            SECCOMP_RET_USER_NOTIF
        );
        assert_eq!(
            bpf::run(&learn, &data(ARCH, 6, 1 << 31, [0; 6])),
            SECCOMP_RET_TRACE
        );
    }
}
