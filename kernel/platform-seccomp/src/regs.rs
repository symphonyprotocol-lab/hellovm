//! The app's registers, as `PTRACE_GETREGSET` returns them
//! (`NT_PRSTATUS`, `NT_PRFPREG`), the per-architecture rules for syscalls,
//! and the conversion to and from the core's [`Context`].
//!
//! A context the core sets comes from guest data (a signal frame), so only
//! user-controllable state is taken from it: on aarch64 the condition flags
//! of `pstate` (the exception level, interrupt masks and the rest are kept
//! from the stopped task), on x86_64 the arithmetic and direction flags of
//! `eflags` and never the segment registers.

use hellovm_core::platform::Context;

/// aarch64 `struct user_pt_regs`.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// The stub's syscall instruction followed by a trap: `svc #0; udf #0`.
#[cfg(target_arch = "aarch64")]
pub const SYSCALL_INSN: [u8; 8] = [0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x00];
/// Length of the syscall instruction alone.
#[cfg(target_arch = "aarch64")]
pub const SYSCALL_INSN_LEN: u64 = 4;

#[cfg(target_arch = "aarch64")]
impl Regs {
    /// The syscall number and arguments at a syscall entry stop.
    pub fn syscall(&self) -> (u64, [u64; 6]) {
        let x = &self.x;
        (x[8], [x[0], x[1], x[2], x[3], x[4], x[5]])
    }

    /// The syscall return value at a syscall exit stop.
    pub fn ret(&self) -> i64 {
        self.x[0] as i64
    }

    pub fn set_ret(&mut self, value: i64) {
        self.x[0] = value as u64;
    }

    pub fn pc(&self) -> u64 {
        self.pc
    }

    /// Sets up the registers so that resuming at `insn`, a syscall
    /// instruction, makes syscall `nr` with `args`.
    pub fn prepare_syscall(&mut self, insn: u64, nr: u64, args: [u64; 6]) {
        self.pc = insn;
        self.x[8] = nr;
        self.x[..6].copy_from_slice(&args);
    }

    /// The register state of a freshly started program: every
    /// general-purpose register zero (x0 is the `rtld_fini` pointer for
    /// libc), `sp` and `pc` as given. `pstate` is kept from the host's
    /// `execve` (EL0, interrupts enabled).
    pub fn start(&mut self, entry: u64, stack: u64) {
        self.x = [0; 31];
        self.sp = stack;
        self.pc = entry;
    }
}

/// aarch64 `struct user_fpsimd_state`.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FpRegs {
    pub v: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
    pub reserved: [u32; 2],
}

/// The `pstate` bits the app may set: the condition flags N, Z, C and V.
#[cfg(target_arch = "aarch64")]
const PSTATE_USER: u64 = 0xf000_0000;

/// The context of a task with these registers.
#[cfg(target_arch = "aarch64")]
pub fn to_context(regs: &Regs, fp: &FpRegs, tls: u64) -> Context {
    use hellovm_core::platform::Aarch64Context;
    Context::Aarch64(Box::new(Aarch64Context {
        x: regs.x,
        sp: regs.sp,
        pc: regs.pc,
        pstate: regs.pstate,
        v: fp.v,
        fpsr: fp.fpsr,
        fpcr: fp.fpcr,
        tpidr: tls,
    }))
}

/// The registers for `context`, with what the app may not choose taken
/// from `current`. `None` if the context is for another architecture.
#[cfg(target_arch = "aarch64")]
pub fn from_context(context: &Context, current: &Regs) -> Option<(Regs, FpRegs, u64)> {
    let Context::Aarch64(c) = context else {
        return None;
    };
    let regs = Regs {
        x: c.x,
        sp: c.sp,
        pc: c.pc,
        pstate: (current.pstate & !PSTATE_USER) | (c.pstate & PSTATE_USER),
    };
    let fp = FpRegs {
        v: c.v,
        fpsr: c.fpsr,
        fpcr: c.fpcr,
        reserved: [0; 2],
    };
    Some((regs, fp, c.tpidr))
}

/// x86_64 `struct user_regs_struct`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

/// The stub's syscall instruction followed by a trap: `syscall; ud2`.
#[cfg(target_arch = "x86_64")]
pub const SYSCALL_INSN: [u8; 4] = [0x0f, 0x05, 0x0f, 0x0b];
/// Length of the syscall instruction alone.
#[cfg(target_arch = "x86_64")]
pub const SYSCALL_INSN_LEN: u64 = 2;

#[cfg(target_arch = "x86_64")]
impl Regs {
    /// The syscall number and arguments at a syscall entry stop.
    pub fn syscall(&self) -> (u64, [u64; 6]) {
        (
            self.orig_rax,
            [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9],
        )
    }

    /// The syscall return value at a syscall exit stop.
    pub fn ret(&self) -> i64 {
        self.rax as i64
    }

    pub fn set_ret(&mut self, value: i64) {
        self.rax = value as u64;
    }

    pub fn pc(&self) -> u64 {
        self.rip
    }

    /// Sets up the registers so that resuming at `insn`, a syscall
    /// instruction, makes syscall `nr` with `args`.
    pub fn prepare_syscall(&mut self, insn: u64, nr: u64, args: [u64; 6]) {
        self.rip = insn;
        self.rax = nr;
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9] = args;
    }

    /// The register state of a freshly started program: every
    /// general-purpose register zero (rdx is the `rtld_fini` pointer for
    /// libc), `rsp` and `rip` as given. Segment registers and flags are kept
    /// from the host's `execve`.
    pub fn start(&mut self, entry: u64, stack: u64) {
        self.r15 = 0;
        self.r14 = 0;
        self.r13 = 0;
        self.r12 = 0;
        self.rbp = 0;
        self.rbx = 0;
        self.r11 = 0;
        self.r10 = 0;
        self.r9 = 0;
        self.r8 = 0;
        self.rax = 0;
        self.rcx = 0;
        self.rdx = 0;
        self.rsi = 0;
        self.rdi = 0;
        self.orig_rax = u64::MAX;
        self.rip = entry;
        self.rsp = stack;
        self.fs_base = 0;
        self.gs_base = 0;
    }
}

/// x86_64 `struct user_fpregs_struct` (the `fxsave` area).
#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpRegs {
    pub bytes: [u8; 512],
}

#[cfg(target_arch = "x86_64")]
impl Default for FpRegs {
    fn default() -> Self {
        FpRegs { bytes: [0; 512] }
    }
}

/// The `eflags` bits the app may set: CF, PF, AF, ZF, SF, DF, OF and AC.
#[cfg(target_arch = "x86_64")]
const EFLAGS_USER: u64 = 0x4_0cd5;

/// The highest user-space address plus one (47-bit address space): a
/// thread pointer the app sets must be below it.
#[cfg(target_arch = "x86_64")]
const USER_END: u64 = 1 << 47;

#[cfg(target_arch = "x86_64")]
pub fn to_context(regs: &Regs, fp: &FpRegs, _tls: u64) -> Context {
    use hellovm_core::platform::X86_64Context;
    Context::X86_64(Box::new(X86_64Context {
        r15: regs.r15,
        r14: regs.r14,
        r13: regs.r13,
        r12: regs.r12,
        rbp: regs.rbp,
        rbx: regs.rbx,
        r11: regs.r11,
        r10: regs.r10,
        r9: regs.r9,
        r8: regs.r8,
        rax: regs.rax,
        rcx: regs.rcx,
        rdx: regs.rdx,
        rsi: regs.rsi,
        rdi: regs.rdi,
        rip: regs.rip,
        rsp: regs.rsp,
        eflags: regs.eflags,
        fs_base: regs.fs_base,
        fxsave: Box::new(fp.bytes),
    }))
}

#[cfg(target_arch = "x86_64")]
pub fn from_context(context: &Context, current: &Regs) -> Option<(Regs, FpRegs, u64)> {
    let Context::X86_64(c) = context else {
        return None;
    };
    let mut regs = *current;
    regs.r15 = c.r15;
    regs.r14 = c.r14;
    regs.r13 = c.r13;
    regs.r12 = c.r12;
    regs.rbp = c.rbp;
    regs.rbx = c.rbx;
    regs.r11 = c.r11;
    regs.r10 = c.r10;
    regs.r9 = c.r9;
    regs.r8 = c.r8;
    regs.rax = c.rax;
    regs.rcx = c.rcx;
    regs.rdx = c.rdx;
    regs.rsi = c.rsi;
    regs.rdi = c.rdi;
    regs.rip = c.rip;
    regs.rsp = c.rsp;
    regs.eflags = (current.eflags & !EFLAGS_USER) | (c.eflags & EFLAGS_USER);
    regs.orig_rax = u64::MAX;
    if c.fs_base < USER_END {
        regs.fs_base = c.fs_base;
    }
    let mut fp = FpRegs::default();
    fp.bytes.copy_from_slice(&c.fxsave[..]);
    // MXCSR bits the CPU rejects would make ptrace fail: keep the
    // documented ones (0xffff).
    let mxcsr = u32::from_le_bytes(fp.bytes[24..28].try_into().unwrap()) & 0xffff;
    fp.bytes[24..28].copy_from_slice(&mxcsr.to_le_bytes());
    Some((regs, fp, 0))
}
