//! The stub program the app process starts as.
//!
//! It is a minimal static ELF executable, generated here rather than built,
//! whose single page holds one syscall instruction followed by a trap. The
//! app process `execve`s it to get a fresh address space; the kernel process
//! then unmaps everything else and uses the syscall instruction to make the
//! app process execute `mmap`, `munmap` and `mprotect` (see `spawn`). The
//! stub's own code never runs on its own.

use hellovm_core::Arch;

use crate::regs::SYSCALL_INSN;

/// Where the stub is loaded. Low enough for every user address space size
/// (39-bit aarch64 included), far from where non-PIE executables, the heap
/// and the core's top-down mappings go.
pub const STUB_BASE: u64 = 0x0000_000f_fff0_0000;
/// The range the platform reserves for the stub: 64 KiB, so that it covers
/// one page for every page size Linux supports.
pub const STUB_RESERVED: u64 = 0x1_0000;
/// Offset of the code in the file and in the page.
const CODE_OFFSET: u64 = 0x100;
/// Address of the stub's syscall instruction.
pub const STUB_SYSCALL: u64 = STUB_BASE + CODE_OFFSET;

const PT_LOAD: u32 = 1;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

fn machine(arch: Arch) -> u16 {
    match arch {
        Arch::X86_64 => 62,
        Arch::Aarch64 => 183,
    }
}

fn phdr(out: &mut Vec<u8>, kind: u32, flags: u32, vaddr: u64, size: u64, align: u64) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    out.extend_from_slice(&vaddr.to_le_bytes()); // p_vaddr
    out.extend_from_slice(&vaddr.to_le_bytes()); // p_paddr
    out.extend_from_slice(&size.to_le_bytes()); // p_filesz
    out.extend_from_slice(&size.to_le_bytes()); // p_memsz
    out.extend_from_slice(&align.to_le_bytes());
}

/// The stub executable for the host architecture `arch`.
pub fn elf(arch: Arch) -> Vec<u8> {
    let file_len = CODE_OFFSET + SYSCALL_INSN.len() as u64;
    let mut out = Vec::with_capacity(file_len as usize);
    // e_ident: magic, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_SYSV.
    out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
    out.extend_from_slice(&machine(arch).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // e_version
    out.extend_from_slice(&STUB_SYSCALL.to_le_bytes()); // e_entry
    out.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    out.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    out.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    out.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    out.extend_from_slice(&2u16.to_le_bytes()); // e_phnum
    out.extend_from_slice(&[0; 6]); // e_shentsize, e_shnum, e_shstrndx
    phdr(
        &mut out,
        PT_LOAD,
        PF_R | PF_X,
        STUB_BASE,
        file_len,
        STUB_RESERVED,
    );
    // A non-executable stack, so that the host never applies
    // READ_IMPLIES_EXEC to the process.
    phdr(&mut out, PT_GNU_STACK, PF_R | PF_W, 0, 0, 16);
    out.resize(CODE_OFFSET as usize, 0);
    out.extend_from_slice(&SYSCALL_INSN);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let elf = elf(Arch::native().unwrap());
        assert_eq!(&elf[..4], b"\x7fELF");
        assert_eq!(elf.len() as u64, CODE_OFFSET + SYSCALL_INSN.len() as u64);
        assert_eq!(&elf[CODE_OFFSET as usize..], &SYSCALL_INSN);
        assert_eq!(STUB_BASE % STUB_RESERVED, 0);
    }
}
