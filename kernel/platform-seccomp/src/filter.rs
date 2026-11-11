//! The app's seccomp BPF filter.

use crate::sys::{SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_TRACE};

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

/// Offset of `arch` in `struct seccomp_data`.
const ARCH_OFFSET: u32 = 4;

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
///
/// Nothing is allowed outright. Without a tracer attached, `RET_TRACE`
/// syscalls fail with `ENOSYS`, so the filter fails closed.
pub fn trace_all(audit_arch: u32) -> Vec<libc::sock_filter> {
    vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, ARCH_OFFSET),
        jeq(audit_arch, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    ]
}
