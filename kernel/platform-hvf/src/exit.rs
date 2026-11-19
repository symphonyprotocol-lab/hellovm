//! Decoding an exception of the app (an exception syndrome, `ESR_ELx`)
//! into what the core understands.
//!
//! Every input is a value the app controls or influences: these functions
//! never panic and treat every syndrome they do not know as an illegal
//! instruction, as Linux does for unknown EL0 exceptions.

use hellovm_core::platform::Fault;

use crate::mmu::Access;

const SIGILL: u32 = 4;
const SIGTRAP: u32 = 5;
const SIGBUS: u32 = 7;
const SIGFPE: u32 = 8;
const SIGSEGV: u32 = 11;

const ILL_ILLOPC: i32 = 1;
const ILL_ILLOPN: i32 = 2;
const TRAP_BRKPT: i32 = 1;
const TRAP_HWBKPT: i32 = 4;
const BUS_ADRALN: i32 = 1;
const BUS_OBJERR: i32 = 3;
const FPE_FLTUNK: i32 = 14;
pub const SEGV_MAPERR: i32 = 1;
pub const SEGV_ACCERR: i32 = 2;

/// Exception classes (`ESR_ELx.EC`).
mod ec {
    pub const UNKNOWN: u64 = 0x00;
    pub const WFX: u64 = 0x01;
    pub const FP_ACCESS: u64 = 0x07;
    pub const BTI: u64 = 0x0d;
    pub const ILLEGAL_STATE: u64 = 0x0e;
    pub const SVC64: u64 = 0x15;
    pub const HVC64: u64 = 0x16;
    pub const SYSREG: u64 = 0x18;
    pub const FPAC: u64 = 0x1c;
    pub const IABT_LOWER: u64 = 0x20;
    pub const PC_ALIGN: u64 = 0x22;
    pub const DABT_LOWER: u64 = 0x24;
    pub const SP_ALIGN: u64 = 0x26;
    pub const FP_EXC64: u64 = 0x2c;
    pub const BREAKPOINT_LOWER: u64 = 0x30;
    pub const STEP_LOWER: u64 = 0x32;
    pub const WATCHPOINT_LOWER: u64 = 0x34;
    pub const BRK64: u64 = 0x3c;
}

pub fn exception_class(esr: u64) -> u64 {
    (esr >> 26) & 0x3f
}

/// The `hvc` immediate, when `syndrome` (`ESR_EL2`) is an `hvc` exit.
pub fn hvc_immediate(syndrome: u64) -> Option<u16> {
    (exception_class(syndrome) == ec::HVC64).then_some(syndrome as u16)
}

/// What a synchronous exception of the app means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppException {
    /// `svc`: a system call.
    Syscall,
    /// A translation fault: the page may be mapped but not yet backed.
    /// `addr` has its top byte (ignored by the hardware for EL0) removed.
    Translation { addr: u64, access: Access },
    /// A CPU exception, as a signal.
    Fault(Fault),
    /// `wfi`/`wfe`: nothing to do; skip the instruction.
    Skip,
}

fn fault(signal: u32, code: i32, addr: Option<u64>) -> AppException {
    AppException::Fault(Fault { signal, code, addr })
}

/// Removes the top byte of an EL0 address (`TCR_EL1.TBI0`), as Linux's
/// `untagged_addr` does: bit 55 (which half of the address space) is
/// copied into it.
pub fn untag(addr: u64) -> u64 {
    (((addr << 8) as i64) >> 8) as u64
}

/// Decodes an exception the app took to EL1 (`esr` and `far` are
/// `ESR_EL1` and `FAR_EL1`, `pc` is `ELR_EL1`), or one it took straight to
/// EL2 (then `esr` is the exit's syndrome). For a stack-pointer alignment
/// fault, `far` is the stack pointer (Linux reports it as the address).
pub fn decode(esr: u64, far: u64, pc: u64) -> AppException {
    let iss = esr & 0x1ff_ffff;
    match exception_class(esr) {
        ec::SVC64 => AppException::Syscall,
        ec::WFX => AppException::Skip,
        class @ (ec::DABT_LOWER | ec::IABT_LOWER) => {
            let fsc = iss & 0x3f;
            // FnV: FAR is not valid.
            let addr = (iss & (1 << 10) == 0).then_some(untag(far));
            // WnR says write, except for a cache maintenance or address
            // translation instruction (CM), which always sets it and writes
            // nothing a page's protection is about (`ic ivau` and `dc cvau`
            // over read-only code are what `__clear_cache` does): Linux
            // takes those as reads, and so does this. `dc zva`, which does
            // write, then gets its page as a read would and, if the page is
            // read only, a permission fault next.
            let access = if class == ec::IABT_LOWER {
                Access::Exec
            } else if iss & (1 << 6) != 0 && iss & (1 << 8) == 0 {
                Access::Write
            } else {
                Access::Read
            };
            match fsc {
                // Address size fault (an address past the 48 bits).
                0b00_0000..=0b00_0011 => fault(SIGSEGV, SEGV_MAPERR, addr),
                // Translation fault, levels 0 to 3.
                0b00_0100..=0b00_0111 => match addr {
                    Some(addr) => AppException::Translation { addr, access },
                    None => fault(SIGSEGV, SEGV_MAPERR, None),
                },
                // Access flag fault (never set up) and permission fault.
                0b00_1000..=0b00_1011 => fault(SIGSEGV, SEGV_MAPERR, addr),
                0b00_1100..=0b00_1111 => fault(SIGSEGV, SEGV_ACCERR, addr),
                0b10_0001 => fault(SIGBUS, BUS_ADRALN, addr),
                _ => fault(SIGBUS, BUS_OBJERR, addr),
            }
        }
        ec::PC_ALIGN => fault(SIGBUS, BUS_ADRALN, Some(far)),
        ec::SP_ALIGN => fault(SIGBUS, BUS_ADRALN, Some(far)),
        ec::BRK64 => fault(SIGTRAP, TRAP_BRKPT, Some(pc)),
        ec::BREAKPOINT_LOWER | ec::STEP_LOWER | ec::WATCHPOINT_LOWER => {
            fault(SIGTRAP, TRAP_HWBKPT, Some(pc))
        }
        ec::FP_EXC64 => fault(SIGFPE, FPE_FLTUNK, Some(pc)),
        ec::FPAC => fault(SIGILL, ILL_ILLOPN, Some(pc)),
        ec::UNKNOWN | ec::SYSREG | ec::ILLEGAL_STATE | ec::FP_ACCESS | ec::BTI => {
            fault(SIGILL, ILL_ILLOPC, Some(pc))
        }
        _ => fault(SIGILL, ILL_ILLOPC, Some(pc)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esr(class: u64, iss: u64) -> u64 {
        (class << 26) | (1 << 25) | iss
    }

    #[test]
    fn common_exceptions() {
        assert_eq!(decode(esr(0x15, 0), 0, 0x1000), AppException::Syscall);
        assert_eq!(
            decode(esr(0x24, 0x47), 0x1234, 0),
            AppException::Translation {
                addr: 0x1234,
                access: Access::Write
            }
        );
        assert_eq!(
            decode(esr(0x20, 0x0f), 0x5000, 0x5000),
            AppException::Fault(Fault {
                signal: SIGSEGV,
                code: SEGV_ACCERR,
                addr: Some(0x5000)
            })
        );
        assert_eq!(
            decode(esr(0x00, 0), 0, 0x4000),
            AppException::Fault(Fault {
                signal: SIGILL,
                code: ILL_ILLOPC,
                addr: Some(0x4000)
            })
        );
        assert_eq!(
            decode(esr(0x24, 0x05), 0xff00_0000_0000_1000, 0),
            AppException::Translation {
                addr: 0x1000,
                access: Access::Read
            },
            "the top byte is ignored"
        );
        // Cache maintenance sets WnR whatever it does: taken as a read.
        assert_eq!(
            decode(esr(0x24, 0x100 | 0x40 | 0x07), 0x7000, 0),
            AppException::Translation {
                addr: 0x7000,
                access: Access::Read
            }
        );
        assert_eq!(untag(0x00ff_0000_0000_0000), 0xffff_0000_0000_0000);
        assert_eq!(hvc_immediate(esr(0x16, 8)), Some(8));
        assert_eq!(hvc_immediate(esr(0x17, 8)), None);
    }

    #[test]
    fn no_syndrome_panics() {
        // Every class, a spread of ISS values, extreme addresses.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for class in 0..64u64 {
            for _ in 0..512 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let _ = decode((class << 26) | (x & 0x3ff_ffff), x, x.rotate_left(17));
                let _ = decode((class << 26) | (x & 0x3f), u64::MAX, u64::MAX);
                let _ = hvc_immediate(x);
            }
        }
    }
}
