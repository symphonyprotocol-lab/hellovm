//! The KVM platform's shim: the EL1 code of the VM, and the register
//! frames it shares with the host.
//!
//! On KVM the host could read and set the vCPU's registers only with one
//! `KVM_GET_ONE_REG`/`KVM_SET_ONE_REG` system call per register, and an
//! `hvc` from EL1 is KVM's own (PSCI), never the host's. So the shim
//! does more than on Hypervisor.framework:
//!
//! * Each of the 16 vectors stores `x0` and `x1` into the vCPU's frame
//!   (`SP_EL1` points at it), puts its slot number in `x0` and branches
//!   to the save routine. An exception taken to EL1 changes no general
//!   register, so the frame gets the app's.
//! * The save routine stores the rest of the app's registers there (the
//!   general ones, `SP_EL0`, `ELR_EL1`, `SPSR_EL1`, `ESR_EL1`, `FAR_EL1`,
//!   `TPIDR_EL0`, the SIMD and FP registers), then stores a zero to the
//!   exit page, which no memory slot backs: KVM leaves `KVM_RUN` with
//!   `KVM_EXIT_MMIO` for that address. The host reads the frame.
//! * When the host runs the vCPU again, KVM completes the store and the
//!   vCPU goes on with the next instruction, the restore routine: it sets
//!   `TTBR0_EL1` from the frame, invalidates the TLB if the frame asks
//!   (all of it and the instruction cache, or one page of one address
//!   space), loads every register from the frame and `eret`s to the app
//!   at the frame's `ELR_EL1` with its `SPSR_EL1`. Just before the
//!   `eret` it checks the frame's stop flag (a kick): if it is set, it
//!   leaves again the same way instead (the frame still holds every
//!   register of the app), and starts over when run again.
//!
//! A system call round trip is then one `KVM_RUN`, and nothing else. The
//! code is assembled into this crate (`global_asm!`, in a data section:
//! the host never runs it) and copied to the VM's shim page; it uses no
//! absolute address but the exit page's.
//!
//! The frames are pages of their own, mapped for EL1 only and never
//! executable, at [`FRAMES_VA`] (vCPU `i`'s at `FRAMES_VA + i * 4096`).
//! EL0 cannot reach them: the app at EL0 reaches EL1 only by an
//! exception, which runs the shim.

use hellovm_platform_arm64::layout::{PAGE, SHIM_VA};

/// Guest-physical base of the frames region (one page per vCPU).
pub const FRAMES_IPA: u64 = 0x10_0000;
/// Where the frames are at stage 1 (EL1 only): just after the shim page.
pub const FRAMES_VA: u64 = SHIM_VA + PAGE;
/// The exit page: no memory slot backs it, so a store to it leaves
/// `KVM_RUN` (`KVM_EXIT_MMIO`).
pub const EXIT_IPA: u64 = 0x3000_0000;
/// Where the exit page is at stage 1 (EL1 only, device memory).
pub const EXIT_VA: u64 = SHIM_VA + 0x10_0000;

/// Offsets in a frame.
pub mod frame {
    /// `x0` to `x30`.
    pub const X: usize = 0x000;
    pub const SP_EL0: usize = 0x0f8;
    pub const ELR: usize = 0x100;
    pub const SPSR: usize = 0x108;
    pub const ESR: usize = 0x110;
    pub const FAR: usize = 0x118;
    pub const TPIDR: usize = 0x120;
    pub const FPSR: usize = 0x128;
    pub const FPCR: usize = 0x130;
    /// The vector the exit came through (written by the shim).
    pub const SLOT: usize = 0x138;
    /// `TTBR0_EL1` for the app (written by the host).
    pub const TTBR0: usize = 0x140;
    /// What to invalidate before the app runs: 0 nothing, 1 the whole
    /// TLB and the instruction cache, 2 one page (written by the host).
    pub const FLUSH: usize = 0x148;
    /// The `tlbi vae1is` operand for `FLUSH` 2.
    pub const OPERAND: usize = 0x150;
    /// Not 0: the vCPU is to leave before it returns to the app (written
    /// by a kicker at any time, with an atomic store).
    pub const STOP: usize = 0x158;
    /// `v0` to `v31`, 16 bytes each.
    pub const V: usize = 0x160;
    pub const SIZE: usize = V + 32 * 16;
}

pub const FLUSH_NONE: u64 = 0;
pub const FLUSH_ALL: u64 = 1;
pub const FLUSH_PAGE: u64 = 2;

/// The `SLOT` of an exit the restore routine made because `STOP` was set
/// (not a vector: the frame holds the app's registers as the host left
/// them).
pub const SLOT_STOPPED: u64 = 16;

std::arch::global_asm!(
    r#"
    .pushsection .rodata.hellovm_kvm_shim, "a"
    .balign 4096
    .global hellovm_kvm_shim_start
hellovm_kvm_shim_start:
    .irp slot, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    .balign 0x80
    stp x0, x1, [sp]
    mov x0, #\slot
    b hellovm_kvm_shim_save
    .endr

    .balign 0x80
hellovm_kvm_shim_save:
    str x0, [sp, #{slot}]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    mrs x0, sp_el0
    stp x30, x0, [sp, #240]
    mrs x0, elr_el1
    mrs x1, spsr_el1
    stp x0, x1, [sp, #{elr}]
    mrs x0, esr_el1
    mrs x1, far_el1
    stp x0, x1, [sp, #{esr}]
    mrs x0, tpidr_el0
    mrs x1, fpsr
    stp x0, x1, [sp, #{tpidr}]
    mrs x0, fpcr
    str x0, [sp, #{fpcr}]
    add x1, sp, #{v}
    stp q0, q1, [x1, #0]
    stp q2, q3, [x1, #32]
    stp q4, q5, [x1, #64]
    stp q6, q7, [x1, #96]
    stp q8, q9, [x1, #128]
    stp q10, q11, [x1, #160]
    stp q12, q13, [x1, #192]
    stp q14, q15, [x1, #224]
    stp q16, q17, [x1, #256]
    stp q18, q19, [x1, #288]
    stp q20, q21, [x1, #320]
    stp q22, q23, [x1, #352]
    stp q24, q25, [x1, #384]
    stp q26, q27, [x1, #416]
    stp q28, q29, [x1, #448]
    stp q30, q31, [x1, #480]
    movz x0, #{exit_3}, lsl #48
    movk x0, #{exit_2}, lsl #32
    movk x0, #{exit_1}, lsl #16
    movk x0, #{exit_0}
    .global hellovm_kvm_shim_exit
hellovm_kvm_shim_exit:
    str xzr, [x0]
    .global hellovm_kvm_shim_restore
hellovm_kvm_shim_restore:
    ldr x0, [sp, #{ttbr0}]
    msr ttbr0_el1, x0
    isb
    ldr x0, [sp, #{flush}]
    cbz x0, 3f
    dsb ishst
    cmp x0, #{flush_all}
    b.ne 2f
    tlbi vmalle1is
    ic ialluis
    b 4f
2:
    ldr x1, [sp, #{operand}]
    tlbi vae1is, x1
4:
    dsb ish
    isb
3:
    add x1, sp, #{v}
    ldp q0, q1, [x1, #0]
    ldp q2, q3, [x1, #32]
    ldp q4, q5, [x1, #64]
    ldp q6, q7, [x1, #96]
    ldp q8, q9, [x1, #128]
    ldp q10, q11, [x1, #160]
    ldp q12, q13, [x1, #192]
    ldp q14, q15, [x1, #224]
    ldp q16, q17, [x1, #256]
    ldp q18, q19, [x1, #288]
    ldp q20, q21, [x1, #320]
    ldp q22, q23, [x1, #352]
    ldp q24, q25, [x1, #384]
    ldp q26, q27, [x1, #416]
    ldp q28, q29, [x1, #448]
    ldp q30, q31, [x1, #480]
    ldr x0, [sp, #{fpcr}]
    msr fpcr, x0
    ldp x0, x1, [sp, #{tpidr}]
    msr tpidr_el0, x0
    msr fpsr, x1
    ldp x0, x1, [sp, #{elr}]
    msr elr_el1, x0
    msr spsr_el1, x1
    ldp x30, x0, [sp, #240]
    msr sp_el0, x0
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    .global hellovm_kvm_shim_check
hellovm_kvm_shim_check:
    ldr x0, [sp, #{stop}]
    cbnz x0, 5f
    ldp x0, x1, [sp]
    eret
5:
    mov x0, #{slot_stopped}
    str x0, [sp, #{slot}]
    movz x0, #{exit_3}, lsl #48
    movk x0, #{exit_2}, lsl #32
    movk x0, #{exit_1}, lsl #16
    movk x0, #{exit_0}
    .global hellovm_kvm_shim_stop_exit
hellovm_kvm_shim_stop_exit:
    str xzr, [x0]
    b hellovm_kvm_shim_restore
    .global hellovm_kvm_shim_end
hellovm_kvm_shim_end:
    .popsection
"#,
    slot = const frame::SLOT,
    elr = const frame::ELR,
    esr = const frame::ESR,
    tpidr = const frame::TPIDR,
    fpcr = const frame::FPCR,
    v = const frame::V,
    ttbr0 = const frame::TTBR0,
    flush = const frame::FLUSH,
    operand = const frame::OPERAND,
    stop = const frame::STOP,
    slot_stopped = const SLOT_STOPPED,
    flush_all = const FLUSH_ALL,
    exit_3 = const (EXIT_VA >> 48) & 0xffff,
    exit_2 = const (EXIT_VA >> 32) & 0xffff,
    exit_1 = const (EXIT_VA >> 16) & 0xffff,
    exit_0 = const EXIT_VA & 0xffff,
);

extern "C" {
    static hellovm_kvm_shim_check: u8;
    static hellovm_kvm_shim_start: u8;
    static hellovm_kvm_shim_exit: u8;
    static hellovm_kvm_shim_restore: u8;
    static hellovm_kvm_shim_end: u8;
}

/// Where in the shim the stop check is (`ldr`, `cbnz`, `ldp`, `eret`):
/// a vCPU stopped between the check and the `eret` would return to the
/// app with the stop flag set, so the host moves it back to the check.
pub fn check_offset() -> u64 {
    // Only the symbols' addresses are taken.
    (&raw const hellovm_kvm_shim_check as usize - &raw const hellovm_kvm_shim_start as usize) as u64
}

/// The shim's machine code (at most a page) and the offsets of the exit
/// store and of the restore routine in it.
pub fn code() -> (&'static [u8], u64, u64) {
    // SAFETY: the four symbols are in the one section above, in this
    // order, around bytes that never change; only their addresses are
    // taken.
    unsafe {
        let start = &raw const hellovm_kvm_shim_start;
        let exit = &raw const hellovm_kvm_shim_exit;
        let restore = &raw const hellovm_kvm_shim_restore;
        let end = &raw const hellovm_kvm_shim_end;
        let len = end as usize - start as usize;
        (
            std::slice::from_raw_parts(start, len),
            (exit as usize - start as usize) as u64,
            (restore as usize - start as usize) as u64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shim_fits_and_its_vectors_are_in_place() {
        let (code, exit, restore) = code();
        assert!(code.len() <= PAGE as usize, "{} bytes", code.len());
        assert_eq!(restore, exit + 4);
        let word = |off: usize| u32::from_le_bytes(code[off..off + 4].try_into().unwrap());
        // Every vector: stp x0, x1, [sp]; mov x0, #slot; b save.
        for slot in 0..16usize {
            assert_eq!(word(slot * 0x80), 0xa900_07e0, "stp at slot {slot}");
            assert_eq!(word(slot * 0x80 + 4), 0xd280_0000 | (slot as u32) << 5);
            assert_eq!(word(slot * 0x80 + 8) >> 26, 0b000101, "b at slot {slot}");
        }
        assert_eq!(word(exit as usize), 0xf900_001f, "str xzr, [x0]");
        assert_eq!(word(code.len() - 4) >> 26, 0b000101, "b restore");
        assert_eq!(word(code.len() - 8), 0xf900_001f, "str xzr, [x0]");
        assert!(frame::SIZE <= PAGE as usize);
    }
}
