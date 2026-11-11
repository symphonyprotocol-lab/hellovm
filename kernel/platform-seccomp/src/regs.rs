//! The app's general-purpose registers, as `PTRACE_GETREGSET(NT_PRSTATUS)`
//! returns them, and the per-architecture rules for syscalls.

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

    /// aarch64 apps set `tpidr_el0` themselves.
    pub fn set_thread_pointer(&mut self, _value: u64) {}
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

    pub fn set_thread_pointer(&mut self, value: u64) {
        self.fs_base = value;
    }
}
