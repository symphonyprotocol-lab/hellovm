//! The app's seccomp BPF filter.
//!
//! Two variants, both killing the process on syscalls of any other ABI and
//! allowing nothing outright:
//!
//! * [`trace_all`]: every syscall stops for the tracer
//!   (`SECCOMP_RET_TRACE`). Without a tracer attached, `RET_TRACE` syscalls
//!   fail with `ENOSYS`, so the filter fails closed.
//! * [`notify`]: most syscalls go to the kernel process as a seccomp user
//!   notification (`SECCOMP_RET_USER_NOTIF`), which the kernel process
//!   answers with the emulated result; the syscall never runs on the host.
//!   The rest still stop for the tracer: the syscalls whose emulation
//!   always changes the task's registers or address space (see
//!   [`trace_numbers`]), every syscall made from the stub's instruction
//!   (the injected ones), the legacy vsyscall page (x86_64), and the
//!   bootstrap's hand-over of the listener. Without a listener (the kernel
//!   process died), `RET_USER_NOTIF` syscalls fail with `ENOSYS`: this
//!   variant fails closed too.
//!
//! Which variant a syscall takes only decides how fast the kernel process
//! sees it, never whether it runs: an app that makes a syscall look like a
//! traced one (calls it from the stub, or with the hand-over's arguments)
//! only takes the slower path.

use hellovm_core::{Arch, Sysno};

use crate::regs::SYSCALL_INSN_LEN;
use crate::stub;
use crate::sys::{SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_TRACE, SECCOMP_RET_USER_NOTIF};

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

/// Offsets in `struct seccomp_data`.
const NR_OFFSET: u32 = 0;
const ARCH_OFFSET: u32 = 4;
const IP_LO_OFFSET: u32 = 8;
const IP_HI_OFFSET: u32 = 12;
const ARG0_LO_OFFSET: u32 = 16;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k,
    }
}

/// A filter that stops every syscall of `audit_arch` for the tracer
/// (`SECCOMP_RET_TRACE`) and kills the process on syscalls of any other ABI.
pub fn trace_all(audit_arch: u32) -> Vec<libc::sock_filter> {
    vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, ARCH_OFFSET),
        jeq(audit_arch, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    ]
}

/// The syscalls that [`notify`] still sends to the tracer by number: the
/// core's emulation of them changes the address space (`mmap`, `munmap`,
/// `mprotect`, `mremap`, `brk`), creates or replaces tasks (`clone`,
/// `clone3`, `fork`, `vfork`, `execve`, `execveat`) or sets registers
/// (`rt_sigreturn`, x86_64 `arch_prctl`), all of which need the task in a
/// ptrace stop. A notified syscall can still need one (a signal delivered
/// on its return); the platform then converts it (see `app`), which costs
/// a little more than a traced stop, so the common cases are listed here.
pub fn trace_numbers(arch: Arch) -> Vec<u32> {
    [
        Sysno::Mmap,
        Sysno::Munmap,
        Sysno::Mprotect,
        Sysno::Mremap,
        Sysno::Brk,
        Sysno::Clone,
        Sysno::Clone3,
        Sysno::Fork,
        Sysno::Vfork,
        Sysno::Execve,
        Sysno::Execveat,
        Sysno::RtSigreturn,
        Sysno::ArchPrctl,
    ]
    .into_iter()
    .filter_map(|sysno| arch.syscall_nr(sysno))
    .map(|nr| nr as u32)
    .collect()
}

/// One instruction of [`notify`] before its jumps are resolved.
enum Insn {
    Plain(libc::sock_filter),
    /// `jeq k`: to the `RET_TRACE` at the end if equal, else skip `jf`.
    JeqTrace {
        k: u32,
        jf: u8,
    },
}

/// The filter with the user-notification fast path (see the module
/// documentation). `trace` lists the syscall numbers that stop for the
/// tracer ([`trace_numbers`]); `sendmsg` with `handoff_fd` as its first
/// argument does too (the bootstrap hands the listener to the kernel
/// process with it). `x86_64` adds the legacy vsyscall page (its addresses
/// are the only ones with all high 32 bits set) to what is traced.
pub fn notify(
    audit_arch: u32,
    trace: &[u32],
    sendmsg: u32,
    handoff_fd: u32,
    x86_64: bool,
) -> Vec<libc::sock_filter> {
    let stub_ret = stub::STUB_SYSCALL + SYSCALL_INSN_LEN;
    let mut prog = vec![
        Insn::Plain(stmt(BPF_LD | BPF_W | BPF_ABS, ARCH_OFFSET)),
        Insn::Plain(jeq(audit_arch, 1, 0)),
        Insn::Plain(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)),
        // The stub's syscall instruction: injected syscalls (and app code
        // that jumps there).
        Insn::Plain(stmt(BPF_LD | BPF_W | BPF_ABS, IP_LO_OFFSET)),
        Insn::Plain(jeq(stub_ret as u32, 0, 2)),
        Insn::Plain(stmt(BPF_LD | BPF_W | BPF_ABS, IP_HI_OFFSET)),
        Insn::JeqTrace {
            k: (stub_ret >> 32) as u32,
            jf: 0,
        },
    ];
    if x86_64 {
        prog.extend([
            Insn::Plain(stmt(BPF_LD | BPF_W | BPF_ABS, IP_HI_OFFSET)),
            Insn::JeqTrace { k: u32::MAX, jf: 0 },
        ]);
    }
    prog.push(Insn::Plain(stmt(BPF_LD | BPF_W | BPF_ABS, NR_OFFSET)));
    prog.extend(trace.iter().map(|&k| Insn::JeqTrace { k, jf: 0 }));
    prog.extend([
        Insn::Plain(jeq(sendmsg, 0, 2)),
        Insn::Plain(stmt(BPF_LD | BPF_W | BPF_ABS, ARG0_LO_OFFSET)),
        Insn::JeqTrace {
            k: handoff_fd,
            jf: 0,
        },
        Insn::Plain(stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)),
    ]);
    let trace_at = prog.len();
    let mut out: Vec<libc::sock_filter> = prog
        .into_iter()
        .enumerate()
        .map(|(i, insn)| match insn {
            Insn::Plain(insn) => insn,
            Insn::JeqTrace { k, jf } => {
                let jt = u8::try_from(trace_at - i - 1).expect("filter too long for a jump");
                jeq(k, jt, jf)
            }
        })
        .collect();
    out.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_TRACE));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys;

    /// Runs a classic-BPF seccomp program (only the instructions the
    /// builders above emit) on one `seccomp_data`.
    fn run(prog: &[libc::sock_filter], data: &sys::SeccompData) -> u32 {
        let word = |off: u32| -> u32 {
            let bytes: [u8; 64] = unsafe { std::mem::transmute(*data) };
            u32::from_le_bytes(bytes[off as usize..off as usize + 4].try_into().unwrap())
        };
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let insn = prog[pc];
            match insn.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => acc = word(insn.k),
                c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += usize::from(if acc == insn.k { insn.jt } else { insn.jf });
                }
                c if c == BPF_RET | BPF_K => return insn.k,
                c => panic!("unexpected opcode {c:#x}"),
            }
            pc += 1;
        }
    }

    fn data(nr: u32, ip: u64, arg0: u64) -> sys::SeccompData {
        sys::SeccompData {
            nr: nr as i32,
            arch: sys::AUDIT_ARCH_AARCH64,
            instruction_pointer: ip,
            args: [arg0, 0, 0, 0, 0, 0],
        }
    }

    #[test]
    fn notify_routes_syscalls() {
        let arch = Arch::native().unwrap();
        let trace = trace_numbers(arch);
        let (sendmsg, handoff) = (211, 9);
        let prog = notify(sys::AUDIT_ARCH_AARCH64, &trace, sendmsg, handoff, true);
        let app = 0x4000_1234;
        let stub_ret = stub::STUB_SYSCALL + SYSCALL_INSN_LEN;
        // An ordinary syscall from app code: notified.
        assert_eq!(run(&prog, &data(63, app, 0)), SECCOMP_RET_USER_NOTIF);
        // The traced numbers.
        for &nr in &trace {
            assert_eq!(run(&prog, &data(nr, app, 0)), SECCOMP_RET_TRACE, "{nr}");
        }
        // Anything from the stub, also with an untraced number.
        assert_eq!(run(&prog, &data(63, stub_ret, 0)), SECCOMP_RET_TRACE);
        // Same low word, other high word: not the stub.
        let lookalike = (stub_ret & 0xffff_ffff) | (1 << 40);
        assert_eq!(run(&prog, &data(63, lookalike, 0)), SECCOMP_RET_USER_NOTIF);
        // The vsyscall page.
        assert_eq!(
            run(&prog, &data(96, 0xffff_ffff_ff60_0000, 0)),
            SECCOMP_RET_TRACE
        );
        // The hand-over, and other sendmsg calls.
        assert_eq!(
            run(&prog, &data(sendmsg, app, handoff.into())),
            SECCOMP_RET_TRACE
        );
        assert_eq!(run(&prog, &data(sendmsg, app, 3)), SECCOMP_RET_USER_NOTIF);
        // Another ABI.
        let mut other = data(63, app, 0);
        other.arch = 0x4000_0003;
        assert_eq!(run(&prog, &other), SECCOMP_RET_KILL_PROCESS);
    }
}
