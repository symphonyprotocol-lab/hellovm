//! The VM layout: guest-physical regions, the shim, and the EL1 system
//! register values. See the crate documentation for the reasoning.

/// The guest page size: the stage-1 translation granule hellovm uses, and
/// the page size the core sees (`AT_PAGESZ`).
pub const PAGE: u64 = 4096;

/// Lowest address the core may map (as on the seccomp platform).
pub const MIN_ADDR: u64 = 0x1_0000;
/// One past the highest EL0 address: 48-bit virtual addresses
/// (`TCR_EL1.T0SZ = 16`), as on Linux with 4 KiB pages.
pub const MAX_ADDR: u64 = 1 << 48;

/// Guest-physical address of the shim page: vectors and the TLB flush
/// routine. Stage 2 maps it read and execute only.
pub const SHIM_IPA: u64 = 0x1_0000;
/// Size of the shim's stage-2 region (one host page).
pub const SHIM_REGION: u64 = 16 * 1024;
/// Guest-physical base of the page-table region. Stage 2 maps it read
/// only: the table walker reads it, nothing in the VM can write it.
pub const TABLES_IPA: u64 = 0x4000_0000;
/// Guest-physical base of the memory the app's pages come from. Stage 2
/// maps it read, write and execute.
pub const RAM_IPA: u64 = 0x1_0000_0000;

/// Virtual address of the shim page, in the upper (`TTBR1_EL1`) half,
/// mapped for EL1 only.
pub const SHIM_VA: u64 = 0xffff_0000_0000_0000;
/// Offset of the TLB flush routine in the shim page.
pub const FLUSH_OFFSET: u64 = 0x800;
/// Offset of the routine that invalidates one page's TLB entries.
pub const FLUSH_PAGE_OFFSET: u64 = 0x900;

/// Exception vector offsets come in 16 slots of 0x80 bytes; slot `i`
/// executes `hvc #i`. Slots 8 to 11 are exceptions from EL0 (AArch64):
/// synchronous, IRQ, FIQ, SError.
pub const VECTOR_LOWER_SYNC: u16 = 8;
pub const VECTOR_LOWER_IRQ: u16 = 9;
pub const VECTOR_LOWER_FIQ: u16 = 10;

const HVC: u32 = 0xd400_0002;
/// `b .-4`: branch back to the `hvc` before it.
const B_BACK: u32 = 0x17ff_ffff;
const DSB_ISHST: u32 = 0xd503_3a9f;
const TLBI_VMALLE1IS: u32 = 0xd508_831f;
const IC_IALLUIS: u32 = 0xd508_711f;
const DSB_ISH: u32 = 0xd503_3b9f;
const ISB: u32 = 0xd503_3fdf;
const ERET: u32 = 0xd69f_03e0;
const TLBI_VAE1IS_X0: u32 = 0xd508_8320;
const MRS_X0_TPIDR_EL1: u32 = 0xd538_d080;

/// The shim page: 4 KiB of machine code.
///
/// * `0x000..0x800`, the vector table (`VBAR_EL1`): every slot is
///   `hvc #slot; b .-4`. An exception taken to EL1 changes no general
///   register, so the host reads the app's registers as they were, and
///   `ELR_EL1`, `SPSR_EL1`, `ESR_EL1` and `FAR_EL1` describe it. The host
///   never resumes in a vector: it returns to EL0 by setting `PC` and
///   `CPSR` itself (if it ever did, the branch re-exits).
/// * `0x800`, the flush routine, entered at EL1 by the host after it
///   changed page tables: invalidates this VM's stage-1 TLB entries and
///   instruction cache on every core, then `eret`s to the app with
///   `ELR_EL1` and `SPSR_EL1` the host set.
/// * `0x900`, the page flush routine: invalidates the TLB entries of one
///   page of one address space (`tlbi vae1is`, with the ASID and page
///   number the host put in `x0`), restores the app's `x0` from
///   `TPIDR_EL1` (where the host saved it; EL0 cannot read it), then
///   `eret`s like the flush routine.
/// * The rest is zero, which is `udf #0`.
pub fn shim_code() -> Vec<u8> {
    let mut words = vec![0u32; (PAGE / 4) as usize];
    for slot in 0..16u32 {
        let at = (slot * 0x80 / 4) as usize;
        words[at] = HVC | (slot << 5);
        words[at + 1] = B_BACK;
    }
    let flush = [DSB_ISHST, TLBI_VMALLE1IS, IC_IALLUIS, DSB_ISH, ISB, ERET];
    let at = (FLUSH_OFFSET / 4) as usize;
    words[at..at + flush.len()].copy_from_slice(&flush);
    let page = [
        DSB_ISHST,
        TLBI_VAE1IS_X0,
        DSB_ISH,
        MRS_X0_TPIDR_EL1,
        ISB,
        ERET,
    ];
    let at = (FLUSH_PAGE_OFFSET / 4) as usize;
    words[at..at + page.len()].copy_from_slice(&page);
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// `SCTLR_EL1`: the MMU and caches on, and what EL0 may do.
pub const SCTLR_EL1: u64 = {
    const M: u64 = 1 << 0; // stage-1 translation
    const C: u64 = 1 << 2; // data cacheable
    const SA: u64 = 1 << 3; // EL1 stack alignment check
    const SA0: u64 = 1 << 4; // EL0 stack alignment check (as Linux)
    const SED: u64 = 1 << 8; // no AArch32 SETEND
    const EOS: u64 = 1 << 11; // exception exit is context synchronizing (RES1 in v8.0)
    const I: u64 = 1 << 12; // instruction cacheable
    const DZE: u64 = 1 << 14; // EL0 may use DC ZVA (glibc's memset does)
    const UCT: u64 = 1 << 15; // EL0 may read CTR_EL0
    const NTWI: u64 = 1 << 16; // WFI is not trapped to EL1 ...
    const NTWE: u64 = 1 << 18; // ... nor WFE (Hypervisor.framework traps both to the host)
    const TSCXT: u64 = 1 << 20; // RES1 in v8.0
    const EIS: u64 = 1 << 22; // exception entry is context synchronizing (RES1 in v8.0)
    const SPAN: u64 = 1 << 23; // RES1 in v8.0
    const UCI: u64 = 1 << 26; // EL0 cache maintenance by VA (JITs)
    const NTLSMD: u64 = 1 << 28; // RES1 in v8.0
    const LSMAOE: u64 = 1 << 29; // RES1 in v8.0
                                 // Not set: A (alignment faults), WXN, UMA (EL0 DAIF access), the
                                 // pointer-authentication enables (PAC instructions stay NOPs) and EE
                                 // and E0E (little-endian).
    M | C
        | SA
        | SA0
        | SED
        | EOS
        | I
        | DZE
        | UCT
        | NTWI
        | NTWE
        | TSCXT
        | EIS
        | SPAN
        | UCI
        | NTLSMD
        | LSMAOE
};

/// `TCR_EL1` for both halves, with `ips` (`TCR_EL1.IPS`, the
/// intermediate physical address size) from `ID_AA64MMFR0_EL1.PARange`,
/// and 16-bit ASIDs if `asid16` (else 8-bit). The ASID is taken from
/// `TTBR0_EL1` (`A1` clear).
pub const fn tcr_el1(ips: u64, asid16: bool) -> u64 {
    const T0SZ: u64 = 16; // 48-bit EL0 addresses
    const IRGN0_WBWA: u64 = 1 << 8;
    const ORGN0_WBWA: u64 = 1 << 10;
    const SH0_INNER: u64 = 3 << 12;
    const TG0_4K: u64 = 0 << 14;
    const T1SZ: u64 = 16 << 16;
    const IRGN1_WBWA: u64 = 1 << 24;
    const ORGN1_WBWA: u64 = 1 << 26;
    const SH1_INNER: u64 = 3 << 28;
    const TG1_4K: u64 = 2 << 30;
    const TBI0: u64 = 1 << 37; // top-byte-ignore for EL0, as Linux
    const AS: u64 = 1 << 36;
    // Not set: HA and HD (bits 39 and 40), so the hardware never updates
    // descriptors and `pte::SW_SHARED` (DBM) stays a software bit.
    (if asid16 { AS } else { 0 })
        | T0SZ
        | IRGN0_WBWA
        | ORGN0_WBWA
        | SH0_INNER
        | TG0_4K
        | T1SZ
        | IRGN1_WBWA
        | ORGN1_WBWA
        | SH1_INNER
        | TG1_4K
        | ((ips & 7) << 32)
        | TBI0
}

/// `MAIR_EL1`: attribute 0 is normal memory, write-back cacheable, the
/// same as the host's mapping of it (so host and guest stay coherent).
pub const MAIR_EL1: u64 = 0xff;

/// `CPACR_EL1`: FP and SIMD do not trap (`FPEN = 0b11`).
pub const CPACR_EL1: u64 = 3 << 20;

/// `CNTKCTL_EL1`: EL0 may read the virtual counter (`EL0VCTEN`) and
/// nothing else of the timers.
pub const CNTKCTL_EL1: u64 = 1 << 1;

/// `CPSR` to run the shim's flush routine: EL1 with `SP_EL1`, every
/// interrupt masked.
pub const PSTATE_EL1H_MASKED: u64 = 0x3c5;
/// The `PSTATE` bits that are the app's and kept across every exit: the
/// condition flags, and `DIT` (data-independent timing, which an app sets
/// with `msr dit` and must find still set after a system call; `hwcap`
/// reports it). Everything else (the exception level, interrupt masks,
/// single-step, illegal state) is the platform's: an app runs in EL0t.
pub const PSTATE_APP_MASK: u64 = 0xf000_0000 | PSTATE_DIT;
/// `PSTATE.DIT`, as in `SPSR_ELx`.
pub const PSTATE_DIT: u64 = 1 << 24;

/// Stage-1 descriptor bits (4 KiB granule).
pub mod pte {
    pub const VALID: u64 = 1 << 0;
    /// Table descriptor (levels 0 to 2) or page descriptor (level 3).
    pub const TABLE_OR_PAGE: u64 = 1 << 1;
    /// `AP[1]`: EL0 may access.
    pub const AP_EL0: u64 = 1 << 6;
    /// `AP[2]`: read-only (at every level that may access).
    pub const AP_RO: u64 = 1 << 7;
    pub const SH_INNER: u64 = 3 << 8;
    /// Access flag: set up front, so no access-flag faults happen.
    pub const AF: u64 = 1 << 10;
    pub const NG: u64 = 1 << 11;
    /// Software bit: the page belongs to a shared mapping (`MAP_SHARED`),
    /// so a copy of its address space shares its memory instead of
    /// copying it. In hardware this is `DBM`, which is ignored while
    /// `TCR_EL1.HD` is clear, as it is here (Linux uses the same bit as a
    /// software bit for the same reason).
    pub const SW_SHARED: u64 = 1 << 51;
    /// Software bit of a descriptor that is not valid (the hardware
    /// ignores all of such a descriptor): a shared page, or reservation,
    /// with no memory of its own yet that was there when its address
    /// space was copied. Its address field is then not a frame but the
    /// number of the shared object it takes its memory from (see `mmu`).
    pub const SW_LAZY: u64 = 1 << 2;
    pub const PXN: u64 = 1 << 53;
    pub const UXN: u64 = 1 << 54;
    /// Software bit: the page is part of the address space (the core
    /// mapped it), even if the descriptor is not valid (`PROT_NONE`, or no
    /// memory yet).
    pub const SW_MAPPED: u64 = 1 << 55;
    /// Software bits: the `PROT_*` value the core asked for (3 bits).
    pub const SW_PROT_SHIFT: u32 = 56;
    pub const SW_PROT_MASK: u64 = 7 << SW_PROT_SHIFT;
    /// Output address bits `[47:12]`.
    pub const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shim_vectors_and_flush_routine() {
        let code = shim_code();
        assert_eq!(code.len(), PAGE as usize);
        let word = |off: usize| u32::from_le_bytes(code[off..off + 4].try_into().unwrap());
        assert_eq!(word(0), 0xd400_0002, "hvc #0");
        assert_eq!(word(0x400), 0xd400_0102, "hvc #8 for EL0 synchronous");
        assert_eq!(word(0x780), 0xd400_01e2, "hvc #15");
        assert_eq!(word(0x404), B_BACK);
        assert_eq!(word(FLUSH_OFFSET as usize + 20), ERET);
        assert_eq!(word(FLUSH_PAGE_OFFSET as usize + 4), TLBI_VAE1IS_X0);
        assert_eq!(word(FLUSH_PAGE_OFFSET as usize + 20), ERET);
        assert_eq!(word(0xffc), 0, "udf");
    }

    #[test]
    fn tcr_fields() {
        let tcr = tcr_el1(2, false);
        assert_eq!(tcr & 0x3f, 16);
        assert_eq!((tcr >> 16) & 0x3f, 16);
        assert_eq!((tcr >> 14) & 3, 0, "TG0 4K");
        assert_eq!((tcr >> 30) & 3, 2, "TG1 4K");
        assert_eq!((tcr >> 32) & 7, 2);
        assert_eq!((tcr >> 37) & 1, 1);
        assert_eq!((tcr >> 36) & 1, 0, "8-bit ASIDs");
        assert_eq!(
            (tcr >> 39) & 3,
            0,
            "no hardware access or dirty flag updates"
        );
        assert_eq!((tcr_el1(2, true) >> 36) & 1, 1, "16-bit ASIDs");
    }
}
