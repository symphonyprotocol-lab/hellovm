//! Signals: numbers, default actions, pending queues, `struct sigaction`,
//! `siginfo_t` and the signal frames of both architectures.
//!
//! Delivery itself (choosing a thread, interrupting a syscall, running the
//! default action) lives in the kernel loop; this module holds the data and
//! the byte layouts. A handler runs on a frame the kernel writes to the app's
//! stack, laid out exactly as Linux lays out `struct rt_sigframe` on that
//! architecture, so that `ucontext_t` inspection, `siglongjmp` and libc's
//! restorers work; `rt_sigreturn` reads it back. Everything read back from
//! a frame is guest data: registers are taken as they are (the platform
//! keeps the processor mode out of the app's reach), the signal mask is
//! sanitized, and nothing in it is trusted further.

use std::collections::VecDeque;

use crate::arch::Arch;
use crate::platform::{Aarch64Context, Context, X86_64Context};

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGXCPU: u32 = 24;
pub const SIGXFSZ: u32 = 25;
pub const SIGVTALRM: u32 = 26;
pub const SIGPROF: u32 = 27;
pub const SIGWINCH: u32 = 28;
pub const SIGSYS: u32 = 31;
/// Highest signal number.
pub const NSIG: u32 = 64;
/// First real-time signal.
pub const SIGRTMIN: u32 = 32;

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

pub const SA_NOCLDSTOP: u64 = 1;
pub const SA_NOCLDWAIT: u64 = 2;
pub const SA_SIGINFO: u64 = 4;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_ONSTACK: u64 = 0x0800_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;

pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;
pub const SS_AUTODISARM: u32 = 1 << 31;

/// `si_code` values.
pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 0x80;
pub const SI_QUEUE: i32 = -1;
pub const SI_TKILL: i32 = -6;
pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_DUMPED: i32 = 3;
pub const CLD_STOPPED: i32 = 5;
pub const CLD_CONTINUED: i32 = 6;

/// The bit of `sig` in a signal set.
pub const fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

/// Signals that can be neither caught, blocked nor ignored.
pub const UNBLOCKABLE: u64 = bit(SIGKILL) | bit(SIGSTOP);

/// Signals raised synchronously by a fault of the receiving thread.
pub const SYNCHRONOUS: u64 =
    bit(SIGSEGV) | bit(SIGBUS) | bit(SIGILL) | bit(SIGFPE) | bit(SIGTRAP) | bit(SIGSYS);

pub fn valid(sig: i64) -> bool {
    (1..=NSIG as i64).contains(&sig)
}

/// What a signal does when its disposition is `SIG_DFL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    Terminate,
    /// Terminate with a core dump (reported as such in the wait status;
    /// hellovm never writes a core file).
    Core,
    Ignore,
    Stop,
    Continue,
}

pub fn default_action(sig: u32) -> DefaultAction {
    match sig {
        SIGCHLD | SIGURG | SIGWINCH => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Continue,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,
        SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGBUS | SIGFPE | SIGSEGV | SIGXCPU | SIGXFSZ
        | SIGSYS => DefaultAction::Core,
        _ => DefaultAction::Terminate,
    }
}

/// A `struct sigaction` as the kernel ABI has it (the same layout on x86_64
/// and aarch64).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

impl SigAction {
    pub const SIZE: usize = 32;

    pub fn decode(raw: &[u8; 32]) -> SigAction {
        let f = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        SigAction {
            handler: f(0),
            flags: f(1),
            restorer: f(2),
            mask: f(3),
        }
    }

    pub fn encode(&self) -> [u8; 32] {
        let mut raw = [0u8; 32];
        for (i, v) in [self.handler, self.flags, self.restorer, self.mask]
            .iter()
            .enumerate()
        {
            raw[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        raw
    }
}

/// The information delivered with a signal (`siginfo_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigInfo {
    pub signo: u32,
    pub code: i32,
    pub errno: i32,
    /// Sender pid (kill, sigqueue) or child pid (`SIGCHLD`).
    pub pid: u32,
    pub uid: u32,
    /// `SIGCHLD`: exit code or signal.
    pub status: i32,
    /// Faults: the faulting address.
    pub addr: u64,
    /// `sigqueue`: the value.
    pub value: u64,
}

impl SigInfo {
    /// A signal sent by a process (`kill`).
    pub fn user(signo: u32, pid: u32) -> SigInfo {
        SigInfo {
            signo,
            code: SI_USER,
            pid,
            ..SigInfo::default()
        }
    }

    /// A signal the kernel raises itself (`SIGPIPE`, `SIGALRM`, tty
    /// signals).
    pub fn kernel(signo: u32) -> SigInfo {
        SigInfo {
            signo,
            code: SI_KERNEL,
            ..SigInfo::default()
        }
    }

    /// `siginfo_t` (128 bytes).
    pub fn encode(&self) -> [u8; 128] {
        let mut b = [0u8; 128];
        b[0..4].copy_from_slice(&self.signo.to_le_bytes());
        b[4..8].copy_from_slice(&self.errno.to_le_bytes());
        b[8..12].copy_from_slice(&self.code.to_le_bytes());
        let fault = SYNCHRONOUS & bit(self.signo) != 0 && self.code > 0;
        if fault {
            b[16..24].copy_from_slice(&self.addr.to_le_bytes());
        } else {
            b[16..20].copy_from_slice(&self.pid.to_le_bytes());
            b[20..24].copy_from_slice(&self.uid.to_le_bytes());
            if self.signo == SIGCHLD {
                b[24..28].copy_from_slice(&self.status.to_le_bytes());
            } else {
                b[24..32].copy_from_slice(&self.value.to_le_bytes());
            }
        }
        b
    }

    /// Reads a `siginfo_t` the guest supplied (`rt_sigqueueinfo`).
    pub fn decode(b: &[u8; 128]) -> SigInfo {
        let i32_at = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        SigInfo {
            signo: i32_at(0) as u32,
            errno: i32_at(4),
            code: i32_at(8),
            pid: i32_at(16) as u32,
            uid: i32_at(20) as u32,
            status: 0,
            addr: 0,
            value: u64::from_le_bytes(b[24..32].try_into().unwrap()),
        }
    }
}

/// Most real-time signals queued on one thread or process
/// (`RLIMIT_SIGPENDING` in spirit).
pub const MAX_QUEUED: usize = 256;

/// Pending signals: one per standard signal, a queue for real-time ones.
#[derive(Clone, Debug, Default)]
pub struct SigQueue {
    queue: VecDeque<SigInfo>,
}

impl SigQueue {
    /// The set of pending signals.
    pub fn set(&self) -> u64 {
        self.queue.iter().fold(0, |set, i| set | bit(i.signo))
    }

    /// Queues `info`. A standard signal that is already pending is merged
    /// with it; returns false if a real-time signal could not be queued.
    pub fn push(&mut self, info: SigInfo) -> bool {
        if info.signo < SIGRTMIN {
            if self.queue.iter().any(|i| i.signo == info.signo) {
                return true;
            }
        } else if self.queue.len() >= MAX_QUEUED {
            return false;
        }
        self.queue.push_back(info);
        true
    }

    /// Takes the lowest-numbered pending signal in `allowed`.
    pub fn take(&mut self, allowed: u64) -> Option<SigInfo> {
        let set = self.set() & allowed;
        if set == 0 {
            return None;
        }
        let sig = set.trailing_zeros() + 1;
        let pos = self.queue.iter().position(|i| i.signo == sig)?;
        self.queue.remove(pos)
    }

    /// Drops every pending instance of the signals in `set`.
    pub fn discard(&mut self, set: u64) {
        self.queue.retain(|i| bit(i.signo) & set == 0);
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// A thread's alternate signal stack (`stack_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AltStack {
    pub sp: u64,
    pub flags: u32,
    pub size: u64,
}

impl AltStack {
    pub fn disabled() -> AltStack {
        AltStack {
            sp: 0,
            flags: SS_DISABLE,
            size: 0,
        }
    }

    pub fn enabled(&self) -> bool {
        self.flags & SS_DISABLE == 0 && self.size > 0
    }

    /// Whether `sp` is on this stack.
    pub fn contains(&self, sp: u64) -> bool {
        self.enabled() && sp > self.sp && sp - self.sp <= self.size
    }

    pub fn encode(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&self.sp.to_le_bytes());
        b[8..12].copy_from_slice(&self.flags.to_le_bytes());
        b[16..24].copy_from_slice(&self.size.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; 24]) -> AltStack {
        AltStack {
            sp: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            flags: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            size: u64::from_le_bytes(b[16..24].try_into().unwrap()),
        }
    }

    /// The `ss_flags` `sigaltstack` reports for a thread at `sp`.
    pub fn reported_flags(&self, sp: u64) -> u32 {
        if !self.enabled() {
            SS_DISABLE
        } else if self.contains(sp) {
            SS_ONSTACK
        } else {
            self.flags & SS_AUTODISARM
        }
    }
}

/// `MINSIGSTKSZ` of an architecture.
pub fn min_stack_size(arch: Arch) -> u64 {
    match arch {
        Arch::Aarch64 => 5120,
        Arch::X86_64 => 2048,
    }
}

/// A signal frame ready to be written to the app's stack.
#[derive(Debug)]
pub struct Frame {
    /// Where to write `bytes`.
    pub addr: u64,
    pub bytes: Vec<u8>,
    /// The context the handler starts with.
    pub context: Context,
}

/// What [`build_frame`] needs besides the interrupted context.
#[derive(Clone, Copy, Debug)]
pub struct FrameParams<'a> {
    pub info: &'a SigInfo,
    pub action: &'a SigAction,
    /// The mask to restore when the handler returns.
    pub saved_mask: u64,
    pub altstack: AltStack,
    /// Where `rt_sigreturn` is called from when the action has no
    /// `SA_RESTORER` (aarch64; 0 if there is no trampoline).
    pub trampoline: u64,
}

/// Why a frame cannot be built; the signal then kills the process with
/// `SIGSEGV`, as on Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadFrame;

/// The stack pointer a handler's frame goes below.
fn frame_top(ctx: &Context, p: &FrameParams<'_>) -> u64 {
    let sp = ctx.sp();
    if p.action.flags & SA_ONSTACK != 0 && p.altstack.enabled() && !p.altstack.contains(sp) {
        p.altstack.sp.wrapping_add(p.altstack.size)
    } else {
        sp
    }
}

/// The frame for running a handler on a thread whose context is `ctx`.
pub fn build_frame(ctx: &Context, p: &FrameParams<'_>) -> Result<Frame, BadFrame> {
    match ctx {
        Context::Aarch64(c) => build_aarch64(c, p),
        Context::X86_64(c) => build_x86_64(c, p),
    }
}

/// Reads the frame of `rt_sigreturn` into the context `current` (which
/// supplies whatever the frame does not hold). Returns the restored context,
/// signal mask and alternate stack.
pub fn read_frame(current: &Context, frame: &[u8]) -> (Context, u64, AltStack) {
    match current {
        Context::Aarch64(c) => read_aarch64(c, frame),
        Context::X86_64(c) => read_x86_64(c, frame),
    }
}

/// Where `rt_sigreturn` finds the frame, and how long it is.
pub fn frame_location(ctx: &Context) -> (u64, usize) {
    match ctx {
        Context::Aarch64(c) => (c.sp, A64_FRAME_SIZE),
        // The handler's `ret` popped `pretcode`.
        Context::X86_64(c) => (c.rsp.wrapping_sub(8), X64_FRAME_SIZE),
    }
}

fn put(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn get(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

// ----- aarch64 -----
//
// struct rt_sigframe { siginfo_t info; struct ucontext uc; }, with
// ucontext { uc_flags, uc_link, stack_t uc_stack, sigset_t uc_sigmask,
// __unused[120], struct sigcontext uc_mcontext (16-aligned) } and
// sigcontext { fault_address, regs[31], sp, pc, pstate, __reserved[4096] }.
// __reserved holds an fpsimd_context record and a terminator. A frame
// record { fp, lr } sits right above the frame, as Linux places it.

const A64_UC: usize = 128;
const A64_UC_STACK: usize = A64_UC + 16;
const A64_UC_SIGMASK: usize = A64_UC + 40;
const A64_MCONTEXT: usize = A64_UC + 176;
const A64_REGS: usize = A64_MCONTEXT + 8;
const A64_SP: usize = A64_MCONTEXT + 256;
const A64_PC: usize = A64_MCONTEXT + 264;
const A64_PSTATE: usize = A64_MCONTEXT + 272;
const A64_RESERVED: usize = A64_MCONTEXT + 288;
const A64_FRAME_SIZE: usize = A64_RESERVED + 4096;
const FPSIMD_MAGIC: u32 = 0x4650_8001;
const FPSIMD_SIZE: usize = 528;

fn build_aarch64(c: &Aarch64Context, p: &FrameParams<'_>) -> Result<Frame, BadFrame> {
    let restorer = if p.action.flags & SA_RESTORER != 0 {
        p.action.restorer
    } else {
        p.trampoline
    };
    if restorer == 0 {
        return Err(BadFrame);
    }
    let top = frame_top(&Context::Aarch64(Box::new(c.clone())), p);
    let record = top.checked_sub(16).ok_or(BadFrame)? & !15;
    let addr = record.checked_sub(A64_FRAME_SIZE as u64).ok_or(BadFrame)? & !15;
    let mut b = vec![0u8; (top - addr) as usize];
    b[..128].copy_from_slice(&p.info.encode());
    b[A64_UC_STACK..A64_UC_STACK + 24].copy_from_slice(&p.altstack.encode());
    let stack_flags = p.altstack.reported_flags(c.sp);
    b[A64_UC_STACK + 8..A64_UC_STACK + 12].copy_from_slice(&stack_flags.to_le_bytes());
    put(&mut b, A64_UC_SIGMASK, p.saved_mask);
    put(&mut b, A64_MCONTEXT, p.info.addr);
    for (i, x) in c.x.iter().enumerate() {
        put(&mut b, A64_REGS + i * 8, *x);
    }
    put(&mut b, A64_SP, c.sp);
    put(&mut b, A64_PC, c.pc);
    put(&mut b, A64_PSTATE, c.pstate);
    let fp = A64_RESERVED;
    b[fp..fp + 4].copy_from_slice(&FPSIMD_MAGIC.to_le_bytes());
    b[fp + 4..fp + 8].copy_from_slice(&(FPSIMD_SIZE as u32).to_le_bytes());
    b[fp + 8..fp + 12].copy_from_slice(&c.fpsr.to_le_bytes());
    b[fp + 12..fp + 16].copy_from_slice(&c.fpcr.to_le_bytes());
    for (i, v) in c.v.iter().enumerate() {
        let at = fp + 16 + i * 16;
        b[at..at + 16].copy_from_slice(&v.to_le_bytes());
    }
    // The terminator record after it is already zero.
    let rec = (record - addr) as usize;
    put(&mut b, rec, c.x[29]);
    put(&mut b, rec + 8, c.x[30]);

    let mut h = c.clone();
    h.x[0] = u64::from(p.info.signo);
    h.x[1] = addr;
    h.x[2] = addr + A64_UC as u64;
    h.x[29] = record;
    h.x[30] = restorer;
    h.sp = addr;
    h.pc = p.action.handler;
    Ok(Frame {
        addr,
        bytes: b,
        context: Context::Aarch64(Box::new(h)),
    })
}

fn read_aarch64(c: &Aarch64Context, b: &[u8]) -> (Context, u64, AltStack) {
    let mut r = c.clone();
    for (i, x) in r.x.iter_mut().enumerate() {
        *x = get(b, A64_REGS + i * 8);
    }
    r.sp = get(b, A64_SP);
    r.pc = get(b, A64_PC);
    r.pstate = get(b, A64_PSTATE);
    // Find the FP/SIMD record among the records in __reserved.
    let mut at = A64_RESERVED;
    while at + 8 <= A64_FRAME_SIZE {
        let magic = u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(b[at + 4..at + 8].try_into().unwrap()) as usize;
        if magic == 0 || size < 8 || at + size > A64_FRAME_SIZE {
            break;
        }
        if magic == FPSIMD_MAGIC && size >= FPSIMD_SIZE {
            r.fpsr = u32::from_le_bytes(b[at + 8..at + 12].try_into().unwrap());
            r.fpcr = u32::from_le_bytes(b[at + 12..at + 16].try_into().unwrap());
            for (i, v) in r.v.iter_mut().enumerate() {
                let o = at + 16 + i * 16;
                *v = u128::from_le_bytes(b[o..o + 16].try_into().unwrap());
            }
            break;
        }
        at += size;
    }
    let mask = get(b, A64_UC_SIGMASK);
    let stack = AltStack::decode(b[A64_UC_STACK..A64_UC_STACK + 24].try_into().unwrap());
    (Context::Aarch64(Box::new(r)), mask, stack)
}

// ----- x86_64 -----
//
// struct rt_sigframe { char *pretcode; struct ucontext uc; siginfo_t info; }
// with ucontext { uc_flags, uc_link, stack_t uc_stack, struct sigcontext
// uc_mcontext, sigset_t uc_sigmask }; the fxsave area (64-aligned) lies
// below the red zone, above the frame, and uc_mcontext.fpstate points to it.

const X64_UC: usize = 8;
const X64_UC_STACK: usize = X64_UC + 16;
const X64_MCONTEXT: usize = X64_UC + 40;
const X64_UC_SIGMASK: usize = X64_UC + 296;
const X64_INFO: usize = X64_UC + 304;
const X64_FRAME_SIZE: usize = X64_INFO + 128;
const X64_FXSAVE_SIZE: usize = 512;
const X64_REDZONE: u64 = 128;
/// sigcontext field offsets, in u64 slots from uc_mcontext.
const X64_SC_RIP: usize = 16;
const X64_SC_EFLAGS: usize = 17;
const X64_SC_CSGSFS: usize = 18;
const X64_SC_TRAPNO: usize = 20;
const X64_SC_CR2: usize = 22;
const X64_SC_FPSTATE: usize = 23;

/// The general registers in sigcontext order (r8..r15, rdi, rsi, rbp, rbx,
/// rdx, rax, rcx, rsp).
fn x64_gregs(c: &X86_64Context) -> [u64; 16] {
    [
        c.r8, c.r9, c.r10, c.r11, c.r12, c.r13, c.r14, c.r15, c.rdi, c.rsi, c.rbp, c.rbx, c.rdx,
        c.rax, c.rcx, c.rsp,
    ]
}

fn build_x86_64(c: &X86_64Context, p: &FrameParams<'_>) -> Result<Frame, BadFrame> {
    if p.action.flags & SA_RESTORER == 0 || p.action.restorer == 0 {
        return Err(BadFrame);
    }
    let ctx = Context::X86_64(Box::new(c.clone()));
    let mut top = frame_top(&ctx, p);
    if top == c.rsp {
        top = top.checked_sub(X64_REDZONE).ok_or(BadFrame)?;
    }
    let fpstate = top.checked_sub(X64_FXSAVE_SIZE as u64).ok_or(BadFrame)? & !63;
    let addr = (fpstate.checked_sub(X64_FRAME_SIZE as u64).ok_or(BadFrame)? & !15) - 8;
    let mut b = vec![0u8; (fpstate - addr) as usize + X64_FXSAVE_SIZE];
    put(&mut b, 0, p.action.restorer);
    b[X64_UC_STACK..X64_UC_STACK + 24].copy_from_slice(&p.altstack.encode());
    let stack_flags = p.altstack.reported_flags(c.rsp);
    b[X64_UC_STACK + 8..X64_UC_STACK + 12].copy_from_slice(&stack_flags.to_le_bytes());
    for (i, r) in x64_gregs(c).iter().enumerate() {
        put(&mut b, X64_MCONTEXT + i * 8, *r);
    }
    put(&mut b, X64_MCONTEXT + X64_SC_RIP * 8, c.rip);
    put(&mut b, X64_MCONTEXT + X64_SC_EFLAGS * 8, c.eflags);
    // cs = 0x33, ss = 0x2b: the user segments Linux reports.
    put(
        &mut b,
        X64_MCONTEXT + X64_SC_CSGSFS * 8,
        0x002b_0000_0000_0033,
    );
    if SYNCHRONOUS & bit(p.info.signo) != 0 {
        put(&mut b, X64_MCONTEXT + X64_SC_TRAPNO * 8, 14);
        put(&mut b, X64_MCONTEXT + X64_SC_CR2 * 8, p.info.addr);
    }
    put(&mut b, X64_MCONTEXT + X64_SC_FPSTATE * 8, fpstate);
    put(&mut b, X64_UC_SIGMASK, p.saved_mask);
    b[X64_INFO..X64_INFO + 128].copy_from_slice(&p.info.encode());
    let fp = (fpstate - addr) as usize;
    b[fp..fp + X64_FXSAVE_SIZE].copy_from_slice(&c.fxsave[..]);

    let mut h = c.clone();
    h.rdi = u64::from(p.info.signo);
    h.rsi = addr + X64_INFO as u64;
    h.rdx = addr + X64_UC as u64;
    h.rax = 0;
    h.rsp = addr;
    h.rip = p.action.handler;
    // The direction flag is clear on entry to a handler (ABI).
    h.eflags &= !0x400;
    Ok(Frame {
        addr,
        bytes: b,
        context: Context::X86_64(Box::new(h)),
    })
}

fn read_x86_64(c: &X86_64Context, b: &[u8]) -> (Context, u64, AltStack) {
    let mut r = c.clone();
    let g = |i: usize| get(b, X64_MCONTEXT + i * 8);
    [
        r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.rdi, r.rsi, r.rbp, r.rbx, r.rdx,
        r.rax, r.rcx, r.rsp,
    ] = std::array::from_fn(g);
    r.rip = g(X64_SC_RIP);
    r.eflags = g(X64_SC_EFLAGS);
    let mask = get(b, X64_UC_SIGMASK);
    let stack = AltStack::decode(b[X64_UC_STACK..X64_UC_STACK + 24].try_into().unwrap());
    (Context::X86_64(Box::new(r)), mask, stack)
}

/// Where an x86_64 frame says its `fxsave` area is (0 for none), and its
/// size; `rt_sigreturn` reads it separately.
pub fn x86_64_fpstate(frame: &[u8]) -> (u64, usize) {
    (
        get(frame, X64_MCONTEXT + X64_SC_FPSTATE * 8),
        X64_FXSAVE_SIZE,
    )
}

/// The aarch64 sigreturn trampoline (`mov x8, #139; svc #0`), mapped into
/// every address space for handlers installed without `SA_RESTORER`
/// (glibc on aarch64 relies on the vDSO's for that, and there is no vDSO).
pub const AARCH64_TRAMPOLINE: [u8; 8] = [0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4];

#[cfg(test)]
mod tests {
    use super::*;

    fn a64() -> Aarch64Context {
        let Context::Aarch64(c) = Context::zeroed(Arch::Aarch64) else {
            unreachable!()
        };
        *c
    }

    #[test]
    fn queue_merges_standard_and_queues_realtime() {
        let mut q = SigQueue::default();
        assert!(q.push(SigInfo::user(SIGINT, 3)));
        assert!(q.push(SigInfo::user(SIGINT, 4)));
        assert!(q.push(SigInfo::user(SIGRTMIN, 5)));
        assert!(q.push(SigInfo::user(SIGRTMIN, 6)));
        assert!(q.push(SigInfo::user(SIGHUP, 7)));
        assert_eq!(q.set(), bit(SIGINT) | bit(SIGRTMIN) | bit(SIGHUP));
        assert_eq!(q.take(!0).unwrap().signo, SIGHUP);
        assert_eq!(q.take(!bit(SIGINT)).unwrap().pid, 5);
        assert_eq!(q.take(!bit(SIGINT)).unwrap().pid, 6);
        assert_eq!(q.take(!bit(SIGINT)), None);
        assert_eq!(q.take(!0).unwrap().pid, 3);
        assert!(q.is_empty());
    }

    #[test]
    fn aarch64_frame_round_trips() {
        let mut c = a64();
        for (i, x) in c.x.iter_mut().enumerate() {
            *x = 0x100 + i as u64;
        }
        c.sp = 0x7fff_0000_1238;
        c.pc = 0x40_1000;
        c.pstate = 0x6000_0000;
        c.v[3] = 0x1234_5678_9abc_def0_1122_3344_5566_7788;
        c.fpsr = 0x10;
        c.fpcr = 0x0300_0000;
        let action = SigAction {
            handler: 0x40_2000,
            flags: SA_SIGINFO,
            restorer: 0,
            mask: 0,
        };
        let info = SigInfo::user(SIGUSR1, 42);
        let params = FrameParams {
            info: &info,
            action: &action,
            saved_mask: 0xff00,
            altstack: AltStack::disabled(),
            trampoline: 0x7000_0000,
        };
        let frame = build_frame(&Context::Aarch64(Box::new(c.clone())), &params).unwrap();
        assert_eq!(frame.addr % 16, 0);
        assert!(frame.addr + frame.bytes.len() as u64 <= c.sp);
        let Context::Aarch64(h) = &frame.context else {
            panic!()
        };
        assert_eq!(h.pc, 0x40_2000);
        assert_eq!(h.x[0], SIGUSR1 as u64);
        assert_eq!(h.x[1], frame.addr);
        assert_eq!(h.x[30], 0x7000_0000, "trampoline without SA_RESTORER");
        assert_eq!(h.sp, frame.addr);
        assert_eq!(&frame.bytes[..4], &SIGUSR1.to_le_bytes());
        // rt_sigreturn reads it back from sp.
        let (loc, len) = frame_location(&frame.context);
        assert_eq!(loc, frame.addr);
        let (back, mask, _) = read_frame(&frame.context, &frame.bytes[..len]);
        assert_eq!(mask, 0xff00);
        let Context::Aarch64(back) = back else {
            panic!()
        };
        assert_eq!(back.x, c.x);
        assert_eq!((back.sp, back.pc, back.pstate), (c.sp, c.pc, c.pstate));
        assert_eq!((back.v, back.fpsr, back.fpcr), (c.v, c.fpsr, c.fpcr));
    }

    #[test]
    fn x86_64_frame_round_trips_and_needs_a_restorer() {
        let Context::X86_64(mut c) = Context::zeroed(Arch::X86_64) else {
            unreachable!()
        };
        c.rax = 1;
        c.rbx = 2;
        c.r15 = 15;
        c.rsp = 0x7fff_0000_1000;
        c.rip = 0x40_1000;
        c.fxsave[0] = 0x7f;
        c.fxsave[511] = 9;
        let action = SigAction {
            handler: 0x40_2000,
            flags: SA_SIGINFO,
            restorer: 0x40_3000,
            mask: 0,
        };
        let info = SigInfo::user(SIGTERM, 1);
        let ctx = Context::X86_64(c.clone());
        let params = FrameParams {
            info: &info,
            action: &action,
            saved_mask: 5,
            altstack: AltStack::disabled(),
            trampoline: 0,
        };
        assert_eq!(build_frame(&ctx, &params).unwrap_err(), BadFrame);
        let with_restorer = SigAction {
            flags: SA_SIGINFO | SA_RESTORER,
            ..action
        };
        let params = FrameParams {
            action: &with_restorer,
            ..params
        };
        let frame = build_frame(&ctx, &params).unwrap();
        assert_eq!((frame.addr + 8) % 16, 0, "ABI: rsp + 8 is 16-aligned");
        assert!(frame.addr + frame.bytes.len() as u64 <= c.rsp - 128);
        assert_eq!(get(&frame.bytes, 0), 0x40_3000);
        let Context::X86_64(h) = &frame.context else {
            panic!()
        };
        assert_eq!(
            (h.rip, h.rdi, h.rsp),
            (0x40_2000, SIGTERM as u64, frame.addr)
        );
        // The handler returns through pretcode; rsp is then frame + 8.
        let mut after = frame.context.clone();
        after.set_sp(frame.addr + 8);
        let (loc, len) = frame_location(&after);
        assert_eq!(loc, frame.addr);
        assert!(len <= frame.bytes.len());
        let (back, mask, _) = read_frame(&after, &frame.bytes[..len]);
        assert_eq!(mask, 5);
        let Context::X86_64(back) = back else {
            panic!()
        };
        assert_eq!((back.rax, back.rbx, back.r15), (1, 2, 15));
        assert_eq!((back.rsp, back.rip), (c.rsp, c.rip));
        let (fp, fp_len) = x86_64_fpstate(&frame.bytes);
        let off = (fp - frame.addr) as usize;
        assert_eq!(fp % 64, 0);
        assert_eq!(&frame.bytes[off..off + fp_len], &c.fxsave[..]);
    }

    #[test]
    fn altstack_is_used_once() {
        let mut c = a64();
        c.sp = 0x7fff_0000_0000;
        let action = SigAction {
            handler: 1,
            flags: SA_ONSTACK | SA_RESTORER,
            restorer: 2,
            mask: 0,
        };
        let alt = AltStack {
            sp: 0x5000_0000,
            flags: 0,
            size: 0x10000,
        };
        let info = SigInfo::kernel(SIGSEGV);
        let params = FrameParams {
            info: &info,
            action: &action,
            saved_mask: 0,
            altstack: alt,
            trampoline: 0,
        };
        let frame = build_frame(&Context::Aarch64(Box::new(c.clone())), &params).unwrap();
        assert!(alt.contains(frame.addr));
        // Already on the alternate stack: the next frame goes below.
        let nested = build_frame(&frame.context, &params).unwrap();
        assert!(nested.addr < frame.addr);
    }
}
