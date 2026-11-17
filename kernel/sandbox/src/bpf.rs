//! A tiny classic-BPF assembler for seccomp filters, with labels.
//!
//! Conditional jumps reach at most 255 instructions ahead; [`Asm::finish`]
//! reports a filter that needs a longer one (the filter builder keeps its
//! blocks short, and a unit test builds every filter).

pub const BPF_LD: u16 = 0x00;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;

/// Offsets in `struct seccomp_data`.
pub const NR: u32 = 0;
pub const ARCH: u32 = 4;
pub const IP_LO: u32 = 8;
pub const IP_HI: u32 = 12;

/// Offset of the low word of syscall argument `i`.
pub const fn arg_lo(i: usize) -> u32 {
    16 + 8 * i as u32
}

/// Offset of the high word of syscall argument `i`.
pub const fn arg_hi(i: usize) -> u32 {
    arg_lo(i) + 4
}

/// A jump target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label(usize);

/// Where a conditional jump goes.
#[derive(Clone, Copy, Debug)]
pub enum Target {
    /// The next instruction.
    Next,
    To(Label),
}

#[derive(Clone, Copy, Debug)]
enum Item {
    Stmt(u16, u32),
    Jump {
        op: u16,
        k: u32,
        t: Target,
        f: Target,
    },
    Ja(Label),
    Here(Label),
}

#[derive(Default)]
pub struct Asm {
    items: Vec<Item>,
    labels: usize,
}

impl Asm {
    pub fn label(&mut self) -> Label {
        self.labels += 1;
        Label(self.labels - 1)
    }

    /// Places `label` before the next instruction.
    pub fn here(&mut self, label: Label) {
        self.items.push(Item::Here(label));
    }

    /// `A = seccomp_data[offset]` (32 bits).
    pub fn load(&mut self, offset: u32) {
        self.items
            .push(Item::Stmt(BPF_LD | BPF_W | BPF_ABS, offset));
    }

    pub fn ret(&mut self, action: u32) {
        self.items.push(Item::Stmt(BPF_RET | BPF_K, action));
    }

    pub fn ja(&mut self, to: Label) {
        self.items.push(Item::Ja(to));
    }

    /// `if A == k goto t else goto f`.
    pub fn jeq(&mut self, k: u32, t: Target, f: Target) {
        self.jump(BPF_JEQ, k, t, f);
    }

    /// `if A > k goto t else goto f`.
    pub fn jgt(&mut self, k: u32, t: Target, f: Target) {
        self.jump(BPF_JGT, k, t, f);
    }

    /// `if A >= k goto t else goto f`.
    pub fn jge(&mut self, k: u32, t: Target, f: Target) {
        self.jump(BPF_JGE, k, t, f);
    }

    /// `if A & k != 0 goto t else goto f`.
    pub fn jset(&mut self, k: u32, t: Target, f: Target) {
        self.jump(BPF_JSET, k, t, f);
    }

    fn jump(&mut self, op: u16, k: u32, t: Target, f: Target) {
        self.items.push(Item::Jump { op, k, t, f });
    }

    /// The program, or a description of the jump that is too long.
    pub fn finish(self) -> Result<Vec<libc::sock_filter>, String> {
        let mut at = vec![usize::MAX; self.labels];
        let mut pc = 0;
        for item in &self.items {
            match item {
                Item::Here(label) => at[label.0] = pc,
                _ => pc += 1,
            }
        }
        let mut out = Vec::with_capacity(pc);
        for item in &self.items {
            let pc = out.len();
            let offset = |target: Label| -> Result<usize, String> {
                let to = at[target.0];
                if to == usize::MAX {
                    return Err(format!("label {} never placed", target.0));
                }
                to.checked_sub(pc + 1)
                    .ok_or_else(|| format!("backward jump at {pc}"))
            };
            let short = |target: Target| -> Result<u8, String> {
                match target {
                    Target::Next => Ok(0),
                    Target::To(label) => {
                        let off = offset(label)?;
                        u8::try_from(off).map_err(|_| format!("jump of {off} at {pc}"))
                    }
                }
            };
            match *item {
                Item::Here(_) => continue,
                Item::Stmt(code, k) => out.push(libc::sock_filter {
                    code,
                    jt: 0,
                    jf: 0,
                    k,
                }),
                Item::Ja(to) => out.push(libc::sock_filter {
                    code: BPF_JMP | BPF_JA,
                    jt: 0,
                    jf: 0,
                    k: offset(to)? as u32,
                }),
                Item::Jump { op, k, t, f } => out.push(libc::sock_filter {
                    code: BPF_JMP | op | BPF_K,
                    jt: short(t)?,
                    jf: short(f)?,
                    k,
                }),
            }
        }
        Ok(out)
    }
}

/// Runs a filter over `data` (a `struct seccomp_data`), for tests: only
/// the instructions [`Asm`] emits are supported.
#[cfg(test)]
pub fn run(prog: &[libc::sock_filter], data: &[u8; 64]) -> u32 {
    let word =
        |off: u32| u32::from_ne_bytes(data[off as usize..off as usize + 4].try_into().unwrap());
    let mut a = 0u32;
    let mut pc = 0usize;
    loop {
        let insn = prog[pc];
        pc += 1;
        match insn.code {
            c if c == BPF_LD | BPF_W | BPF_ABS => a = word(insn.k),
            c if c == BPF_RET | BPF_K => return insn.k,
            c if c == BPF_JMP | BPF_JA => pc += insn.k as usize,
            c => {
                let taken = match c & 0xf0 {
                    BPF_JEQ => a == insn.k,
                    BPF_JGT => a > insn.k,
                    BPF_JGE => a >= insn.k,
                    BPF_JSET => a & insn.k != 0,
                    _ => panic!("unsupported insn {c:#x}"),
                };
                pc += if taken { insn.jt } else { insn.jf } as usize;
            }
        }
    }
}
