//! Loading ELF executables and building the initial stack.
//!
//! Supported: 64-bit little-endian `ET_EXEC` (non-PIE) and `ET_DYN`
//! (static-PIE and dynamically linked) for the app's architecture. An
//! executable with `PT_INTERP` is loaded together with its program
//! interpreter; `AT_BASE` is the address where that interpreter was mapped
//! (`syscall/proc.rs`, `load_program`).
//!
//! The file is parsed from an in-memory copy; nothing in it is trusted.
//! Every offset and size is bounds-checked, and the image may only land in
//! free, non-reserved parts of the address space.

use std::fmt;

use crate::arch::Arch;
use crate::errno::{Errno, SysResult, E2BIG, ENOEXEC, ENOMEM};
use crate::mm::{Mm, VmaKind, STACK_SIZE};
use crate::platform::{AddressSpace, AppMemory, CpuInfo, GuestAddr, Prot};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const MAX_PHNUM: usize = 256;

// Auxiliary vector keys.
pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;

/// Why an executable cannot be loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// Not an ELF file at all.
    NotElf,
    /// An ELF file this kernel cannot run (class, endianness, type, ...).
    Unsupported(String),
    /// For another architecture.
    WrongMachine { found: u16 },
    /// Inconsistent headers.
    Malformed(&'static str),
    /// The image does not fit the address space.
    NoRoom,
}

impl ElfError {
    pub fn errno(&self) -> Errno {
        match self {
            ElfError::NoRoom => Errno(ENOMEM),
            _ => Errno(ENOEXEC),
        }
    }
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::NotElf => f.write_str("not an ELF executable"),
            ElfError::Unsupported(what) => write!(f, "unsupported ELF file: {what}"),
            ElfError::WrongMachine { found } => {
                write!(
                    f,
                    "ELF file is for another architecture (e_machine {found})"
                )
            }
            ElfError::Malformed(what) => write!(f, "malformed ELF file: {what}"),
            ElfError::NoRoom => f.write_str("the program does not fit the address space"),
        }
    }
}

impl std::error::Error for ElfError {}

/// A `PT_LOAD` segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Segment {
    vaddr: u64,
    memsz: u64,
    offset: u64,
    filesz: u64,
    prot: Prot,
}

/// A parsed, validated executable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Elf {
    pub pie: bool,
    /// The program interpreter (`PT_INTERP`) of a dynamically linked
    /// executable: the dynamic loader, which the kernel loads as well and
    /// starts instead of the program.
    pub interpreter: Option<Vec<u8>>,
    entry: u64,
    phoff: u64,
    phnum: u64,
    segments: Vec<Segment>,
    phdr_vaddr: Option<u64>,
    align: u64,
}

fn machine(arch: Arch) -> u16 {
    match arch {
        Arch::X86_64 => 62,
        Arch::Aarch64 => 183,
    }
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Parses and validates the headers of an executable for `arch`.
pub fn parse(file: &[u8], arch: Arch) -> Result<Elf, ElfError> {
    if file.len() < 4 || &file[..4] != b"\x7fELF" {
        return Err(ElfError::NotElf);
    }
    if file.len() < EHDR_SIZE {
        return Err(ElfError::Malformed("truncated header"));
    }
    if file[4] != 2 || file[5] != 1 || file[6] != 1 {
        return Err(ElfError::Unsupported(
            "not a 64-bit little-endian ELF version 1 file".into(),
        ));
    }
    let e_type = u16_at(file, 16);
    let e_machine = u16_at(file, 18);
    if e_machine != machine(arch) {
        return Err(ElfError::WrongMachine { found: e_machine });
    }
    let pie = match e_type {
        ET_EXEC => false,
        ET_DYN => true,
        other => return Err(ElfError::Unsupported(format!("e_type {other}"))),
    };
    let entry = u64_at(file, 24);
    let phoff = u64_at(file, 32);
    let phentsize = u16_at(file, 54) as usize;
    let phnum = u16_at(file, 56) as usize;
    if phentsize != PHDR_SIZE {
        return Err(ElfError::Malformed("bad program header size"));
    }
    if phnum == 0 || phnum > MAX_PHNUM {
        return Err(ElfError::Malformed("bad program header count"));
    }
    let table_end = (phoff as usize)
        .checked_add(phnum * PHDR_SIZE)
        .filter(|&end| phoff <= file.len() as u64 && end <= file.len())
        .ok_or(ElfError::Malformed("program headers outside the file"))?;
    let table = &file[phoff as usize..table_end];

    let mut segments = Vec::new();
    let mut interpreter = None;
    let mut phdr_vaddr = None;
    let mut align = 1u64;
    for ph in table.as_chunks::<PHDR_SIZE>().0 {
        let p_type = u32_at(ph, 0);
        let p_flags = u32_at(ph, 4);
        let offset = u64_at(ph, 8);
        let vaddr = u64_at(ph, 16);
        let filesz = u64_at(ph, 32);
        let memsz = u64_at(ph, 40);
        let p_align = u64_at(ph, 48);
        match p_type {
            PT_INTERP => {
                let end = offset
                    .checked_add(filesz)
                    .filter(|&end| end <= file.len() as u64)
                    .ok_or(ElfError::Malformed("PT_INTERP outside the file"))?;
                let mut path = file[offset as usize..end as usize].to_vec();
                if path.last() == Some(&0) {
                    path.pop();
                }
                if path.is_empty() || path.len() >= crate::vfs::PATH_MAX || path.contains(&0) {
                    return Err(ElfError::Malformed("bad PT_INTERP"));
                }
                interpreter = Some(path);
            }
            PT_PHDR => phdr_vaddr = Some(vaddr),
            PT_LOAD => {
                if offset
                    .checked_add(filesz)
                    .is_none_or(|end| end > file.len() as u64)
                {
                    return Err(ElfError::Malformed("segment outside the file"));
                }
                if filesz > memsz || vaddr.checked_add(memsz).is_none() {
                    return Err(ElfError::Malformed("bad segment size"));
                }
                if p_align > 1 {
                    if !p_align.is_power_of_two() {
                        return Err(ElfError::Malformed("bad segment alignment"));
                    }
                    align = align.max(p_align);
                }
                let mut prot = Prot::NONE;
                for (flag, bit) in [(PF_R, Prot::READ), (PF_W, Prot::WRITE), (PF_X, Prot::EXEC)] {
                    if p_flags & flag != 0 {
                        prot = prot.union(bit);
                    }
                }
                if memsz > 0 {
                    segments.push(Segment {
                        vaddr,
                        memsz,
                        offset,
                        filesz,
                        prot,
                    });
                }
            }
            _ => {}
        }
    }
    if segments.is_empty() {
        return Err(ElfError::Malformed("no loadable segments"));
    }
    segments.sort_by_key(|s| s.vaddr);
    for pair in segments.windows(2) {
        if pair[0].vaddr + pair[0].memsz > pair[1].vaddr {
            return Err(ElfError::Malformed("overlapping segments"));
        }
    }
    // Without PT_PHDR, the headers are where the segment holding their file
    // offset maps them (as Linux computes AT_PHDR).
    let phdr_vaddr = phdr_vaddr.or_else(|| {
        segments
            .iter()
            .find(|s| s.offset <= phoff && table_end as u64 <= s.offset + s.filesz)
            .map(|s| s.vaddr + (phoff - s.offset))
    });
    Ok(Elf {
        pie,
        interpreter,
        entry,
        phoff,
        phnum: phnum as u64,
        segments,
        phdr_vaddr,
        align,
    })
}

/// Where an executable was loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadedImage {
    pub entry: GuestAddr,
    /// Address of the program headers in memory (0 if not mapped).
    pub phdr: GuestAddr,
    pub phnum: u64,
    /// What was added to every address of a static-PIE (0 otherwise).
    pub bias: u64,
    /// First page after the image: the start of the `brk` heap.
    pub end: GuestAddr,
}

/// Where to put a position-independent image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// The executable: like `ELF_ET_DYN_BASE`, two thirds of the way up, so
    /// that the heap has room above and the mapping area below the stack.
    Program,
    /// The program interpreter: anywhere in the mapping area, like a shared
    /// library.
    Interpreter,
}

/// Maps the segments of `elf` (parsed from `file`) into the address space.
pub fn load<P: AddressSpace + AppMemory + ?Sized>(
    mm: &mut Mm,
    space: &mut P,
    file: &[u8],
    elf: &Elf,
    placement: Placement,
) -> Result<LoadedImage, ElfError> {
    let page = mm.page_size();
    let align = elf.align.max(page);
    let bias = if elf.pie {
        let first = elf.segments[0].vaddr & !(align - 1);
        let last = elf.segments.last().expect("at least one segment");
        let span = (last.vaddr + last.memsz)
            .checked_sub(first)
            .and_then(|span| mm.page_up(span))
            .ok_or(ElfError::NoRoom)?;
        let base = match placement {
            Placement::Program => (mm.max_addr() / 3 * 2) & !(align - 1),
            Placement::Interpreter => mm.free_area(span, align).ok_or(ElfError::NoRoom)?,
        };
        base.wrapping_sub(first)
    } else {
        0
    };

    // Page-aligned spans of the segments. Nothing here may cost time or
    // memory in proportion to a segment's size, which the file controls.
    let mut spans: Vec<(u64, u64, Prot)> = Vec::new();
    let mut image_end = 0;
    for seg in &elf.segments {
        if seg.vaddr % page != seg.offset % page {
            return Err(ElfError::Malformed("segment offset and address disagree"));
        }
        let start = seg.vaddr.checked_add(bias).ok_or(ElfError::NoRoom)?;
        let end = start.checked_add(seg.memsz).ok_or(ElfError::NoRoom)?;
        let end = mm.page_up(end).ok_or(ElfError::NoRoom)?;
        if end > mm.max_addr() {
            return Err(ElfError::NoRoom);
        }
        image_end = image_end.max(end);
        spans.push((mm.page_down(start), end, seg.prot));
    }
    // Cut the spans where any of them starts or ends. Each piece gets the
    // protection of every span covering it (a page shared by two segments
    // gets both). Then join the pieces into runs of contiguous pages, and
    // of contiguous pages with equal protection.
    let mut cuts: Vec<u64> = spans.iter().flat_map(|s| [s.0, s.1]).collect();
    cuts.sort_unstable();
    cuts.dedup();
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut prot_runs: Vec<(u64, u64, Prot)> = Vec::new();
    for cut in cuts.windows(2) {
        let (start, end) = (cut[0], cut[1]);
        let mut covering = spans.iter().filter(|s| s.0 <= start && end <= s.1);
        let Some(first) = covering.next() else {
            continue;
        };
        let prot = covering.fold(first.2, |prot, s| prot.union(s.2));
        match runs.last_mut() {
            Some(run) if run.1 == start => run.1 = end,
            _ => runs.push((start, end)),
        }
        match prot_runs.last_mut() {
            Some(run) if run.1 == start && run.2 == prot => run.1 = end,
            _ => prot_runs.push((start, end, prot)),
        }
    }
    for &(start, end) in &runs {
        if !mm.vmas().is_free(start, end) {
            return Err(ElfError::NoRoom);
        }
        mm.map_fixed(space, start, end - start, Prot::RW, VmaKind::Image)
            .map_err(|_| ElfError::NoRoom)?;
    }
    for seg in &elf.segments {
        let data = &file[seg.offset as usize..(seg.offset + seg.filesz) as usize];
        space
            .write(seg.vaddr + bias, data)
            .map_err(|_| ElfError::NoRoom)?;
    }
    for &(start, end, prot) in &prot_runs {
        if prot != Prot::RW {
            mm.mprotect(space, start, end - start, u64::from(prot.0))
                .map_err(|_| ElfError::NoRoom)?;
        }
    }
    Ok(LoadedImage {
        entry: elf.entry.wrapping_add(bias),
        phdr: elf.phdr_vaddr.map_or(0, |v| v.wrapping_add(bias)),
        phnum: elf.phnum,
        bias,
        end: image_end,
    })
}

/// What the new program is told about itself.
pub struct StackParams<'a> {
    pub arch: Arch,
    pub argv: &'a [Vec<u8>],
    pub envp: &'a [Vec<u8>],
    /// The path the program was executed as (`AT_EXECFN`).
    pub execfn: &'a [u8],
    pub image: &'a LoadedImage,
    pub cpu: CpuInfo,
    /// Where the program interpreter was loaded (`AT_BASE`), 0 without one.
    pub interp_base: u64,
    /// The 16 bytes `AT_RANDOM` points to.
    pub random: [u8; 16],
}

/// Maps the main thread's stack and writes argc, argv, envp and the
/// auxiliary vector to it, as the Linux ABI (x86_64 and aarch64 alike)
/// requires. Returns the initial stack pointer.
pub fn build_stack<P: AddressSpace + AppMemory + ?Sized>(
    mm: &mut Mm,
    space: &mut P,
    params: &StackParams<'_>,
) -> SysResult<GuestAddr> {
    let strings_len: usize = params
        .argv
        .iter()
        .chain(params.envp)
        .map(|s| s.len() + 1)
        .sum::<usize>()
        + params.execfn.len()
        + 1;
    if strings_len as u64 > STACK_SIZE / 4 {
        return Err(Errno(E2BIG));
    }
    let top = mm.map_stack(space)?;

    // The string area, low to high: AT_RANDOM bytes, the platform name,
    // argv strings, envp strings, the executable name, an 8-byte NULL.
    let mut blob = Vec::with_capacity(strings_len + 64);
    blob.extend_from_slice(&params.random);
    let platform_off = blob.len();
    blob.extend_from_slice(params.arch.name().as_bytes());
    blob.push(0);
    let offsets = |strings: &[Vec<u8>], blob: &mut Vec<u8>| -> Vec<usize> {
        strings
            .iter()
            .map(|s| {
                let off = blob.len();
                blob.extend_from_slice(s);
                blob.push(0);
                off
            })
            .collect()
    };
    let argv_offs = offsets(params.argv, &mut blob);
    let envp_offs = offsets(params.envp, &mut blob);
    let execfn_off = blob.len();
    blob.extend_from_slice(params.execfn);
    blob.push(0);
    blob.extend_from_slice(&[0; 8]);
    let blob_start = (top - blob.len() as u64) & !15;
    let at = |off: usize| blob_start + off as u64;

    let image = params.image;
    let auxv = [
        (AT_PHDR, image.phdr),
        (AT_PHENT, PHDR_SIZE as u64),
        (AT_PHNUM, image.phnum),
        (AT_PAGESZ, mm.page_size()),
        (AT_BASE, params.interp_base),
        (AT_FLAGS, 0),
        (AT_ENTRY, image.entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_RANDOM, at(0)),
        (AT_HWCAP, params.cpu.hwcap),
        (AT_HWCAP2, params.cpu.hwcap2),
        (AT_CLKTCK, 100),
        (AT_PLATFORM, at(platform_off)),
        (AT_EXECFN, at(execfn_off)),
        (AT_NULL, 0),
    ];
    let mut words = vec![params.argv.len() as u64];
    words.extend(argv_offs.iter().map(|&o| at(o)));
    words.push(0);
    words.extend(envp_offs.iter().map(|&o| at(o)));
    words.push(0);
    for (key, value) in auxv {
        words.extend([key, value]);
    }
    let sp = (blob_start - words.len() as u64 * 8) & !15;

    let mut stack = vec![0u8; (top - sp) as usize];
    for (i, word) in words.iter().enumerate() {
        stack[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    let blob_at = (blob_start - sp) as usize;
    stack[blob_at..blob_at + blob.len()].copy_from_slice(&blob);
    space.write(sp, &stack).map_err(|err| {
        log::warn!("writing the initial stack failed: {err}");
        Errno(ENOMEM)
    })?;
    Ok(sp)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::testutil::MockApp;

    /// A segment for [`build_elf`]: vaddr, file offset, file data, memsz,
    /// PF_* flags.
    pub struct Seg<'a> {
        pub vaddr: u64,
        pub offset: u64,
        pub data: &'a [u8],
        pub memsz: u64,
        pub flags: u32,
    }

    /// A minimal ELF file with the given segments; program headers follow
    /// the ELF header at offset 64 and are covered by the first segment if
    /// it starts at offset 0.
    pub fn build_elf(
        arch: Arch,
        e_type: u16,
        entry: u64,
        segs: &[Seg],
        interp: Option<&[u8]>,
    ) -> Vec<u8> {
        let phnum = segs.len() + usize::from(interp.is_some());
        let mut out = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        out.resize(16, 0);
        out.extend_from_slice(&e_type.to_le_bytes());
        out.extend_from_slice(&machine(arch).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&entry.to_le_bytes());
        out.extend_from_slice(&64u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&64u16.to_le_bytes());
        out.extend_from_slice(&56u16.to_le_bytes());
        out.extend_from_slice(&(phnum as u16).to_le_bytes());
        out.extend_from_slice(&[0; 6]);
        let interp_off = 64 + phnum * 56;
        let ph = |out: &mut Vec<u8>,
                  ty: u32,
                  flags: u32,
                  off: u64,
                  vaddr: u64,
                  filesz: u64,
                  memsz: u64| {
            out.extend_from_slice(&ty.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&off.to_le_bytes());
            out.extend_from_slice(&vaddr.to_le_bytes());
            out.extend_from_slice(&vaddr.to_le_bytes());
            out.extend_from_slice(&filesz.to_le_bytes());
            out.extend_from_slice(&memsz.to_le_bytes());
            out.extend_from_slice(&0x1000u64.to_le_bytes());
        };
        if let Some(interp) = interp {
            ph(
                &mut out,
                PT_INTERP,
                PF_R,
                interp_off as u64,
                0,
                interp.len() as u64,
                interp.len() as u64,
            );
        }
        for s in segs {
            ph(
                &mut out,
                PT_LOAD,
                s.flags,
                s.offset,
                s.vaddr,
                s.data.len() as u64,
                s.memsz,
            );
        }
        if let Some(interp) = interp {
            out.extend_from_slice(interp);
        }
        let header_len = out.len();
        for s in segs {
            let end = s.offset as usize + s.data.len();
            if out.len() < end {
                out.resize(end, 0);
            }
            // The first segment at offset 0 covers the headers; keep them.
            let start = (s.offset as usize).max(if s.offset == 0 { header_len } else { 0 });
            let skip = start - s.offset as usize;
            out[start..end].copy_from_slice(&s.data[skip..]);
        }
        out
    }

    /// A typical static executable: text (with the headers) and data+bss.
    pub fn sample(arch: Arch, e_type: u16, base: u64) -> Vec<u8> {
        let text = vec![0xaa; 0x1800];
        build_elf(
            arch,
            e_type,
            base + 0x1000,
            &[
                Seg {
                    vaddr: base,
                    offset: 0,
                    data: &text,
                    memsz: 0x1800,
                    flags: PF_R | PF_X,
                },
                Seg {
                    vaddr: base + 0x2800,
                    offset: 0x1800,
                    data: b"initialized data",
                    memsz: 0x3000,
                    flags: PF_R | PF_W,
                },
            ],
            None,
        )
    }

    fn setup() -> (Mm, MockApp) {
        let app = MockApp::new(Arch::Aarch64);
        (Mm::new(&app.address_space()), app)
    }

    #[test]
    fn loads_a_static_executable() {
        let (mut mm, mut app) = setup();
        let file = sample(Arch::Aarch64, ET_EXEC, 0x40_0000);
        let elf = parse(&file, Arch::Aarch64).unwrap();
        assert!(!elf.pie);
        let image = load(&mut mm, &mut app, &file, &elf, Placement::Program).unwrap();
        assert_eq!(image.entry, 0x40_1000);
        assert_eq!(image.bias, 0);
        assert_eq!(image.phdr, 0x40_0040, "computed from the first segment");
        assert_eq!(image.phnum, 2);
        assert_eq!(image.end, 0x40_6000);
        assert_eq!(app.prot(0x40_0000), Some(Prot(5)));
        assert_eq!(app.prot(0x40_1000), Some(Prot(5)));
        assert_eq!(app.prot(0x40_2000), Some(Prot(3)));
        assert_eq!(app.prot(0x40_5000), Some(Prot(3)));
        assert!(!app.is_mapped(0x40_6000));
        assert_eq!(app.peek(0x40_0000, 4), b"\x7fELF");
        assert_eq!(app.peek(0x40_0100, 2), [0xaa, 0xaa]);
        assert_eq!(app.peek(0x40_2800, 16), b"initialized data");
        // The bss and the rest of the text page are zero.
        assert_eq!(app.peek(0x40_2810, 0x10), [0; 0x10]);
        assert_eq!(app.peek(0x40_1800, 0x10), [0; 0x10]);
    }

    #[test]
    fn shared_pages_get_both_protections() {
        let (mut mm, mut app) = setup();
        let file = build_elf(
            Arch::Aarch64,
            ET_EXEC,
            0x40_0000,
            &[
                Seg {
                    vaddr: 0x40_0000,
                    offset: 0,
                    data: &[1; 0x1100],
                    memsz: 0x1100,
                    flags: PF_R | PF_X,
                },
                Seg {
                    vaddr: 0x40_1100,
                    offset: 0x1100,
                    data: &[2; 0x10],
                    memsz: 0x2000,
                    flags: PF_R | PF_W,
                },
            ],
            None,
        );
        let elf = parse(&file, Arch::Aarch64).unwrap();
        load(&mut mm, &mut app, &file, &elf, Placement::Program).unwrap();
        assert_eq!(app.prot(0x40_0000), Some(Prot(5)));
        assert_eq!(app.prot(0x40_1000), Some(Prot(7)));
        assert_eq!(app.prot(0x40_2000), Some(Prot(3)));
        assert_eq!(app.peek(0x40_10ff, 3), [1, 2, 2]);
    }

    #[test]
    fn static_pie_is_relocated() {
        let (mut mm, mut app) = setup();
        let file = sample(Arch::Aarch64, ET_DYN, 0);
        let elf = parse(&file, Arch::Aarch64).unwrap();
        assert!(elf.pie);
        let image = load(&mut mm, &mut app, &file, &elf, Placement::Program).unwrap();
        assert_ne!(image.bias, 0);
        assert_eq!(image.bias % 0x1000, 0);
        assert_eq!(image.entry, image.bias + 0x1000);
        assert_eq!(image.phdr, image.bias + 0x40);
        assert_eq!(app.peek(image.bias, 4), b"\x7fELF");
        assert!(image.end < mm.max_addr());
    }

    #[test]
    fn rejects_bad_files() {
        let arch = Arch::Aarch64;
        assert_eq!(parse(b"#!/bin/sh\n", arch), Err(ElfError::NotElf));
        let file = sample(arch, ET_EXEC, 0x40_0000);
        assert_eq!(
            parse(&file[..40], arch),
            Err(ElfError::Malformed("truncated header"))
        );
        assert_eq!(
            parse(&file, Arch::X86_64),
            Err(ElfError::WrongMachine { found: 183 })
        );
        let mut bad = file.clone();
        bad[16] = 1; // ET_REL
        assert!(matches!(parse(&bad, arch), Err(ElfError::Unsupported(_))));
        let mut bad = file.clone();
        bad[56] = 200; // phnum points past the end
        assert!(matches!(parse(&bad, arch), Err(ElfError::Malformed(_))));
        let dynamic = build_elf(
            arch,
            ET_DYN,
            0x1000,
            &[Seg {
                vaddr: 0,
                offset: 0,
                data: &[0; 0x200],
                memsz: 0x200,
                flags: PF_R,
            }],
            Some(b"/lib/ld-linux-aarch64.so.1\0"),
        );
        let parsed = parse(&dynamic, arch).unwrap();
        assert_eq!(
            parsed.interpreter.as_deref(),
            Some(&b"/lib/ld-linux-aarch64.so.1"[..])
        );
        // A segment whose file range lies outside the file.
        let mut bad = file.clone();
        bad.truncate(0x1808);
        assert!(matches!(parse(&bad, arch), Err(ElfError::Malformed(_))));
    }

    #[test]
    fn refuses_to_load_over_reserved_ranges() {
        let (mut mm, mut app) = setup();
        let file = sample(Arch::Aarch64, ET_EXEC, app.reserved());
        let elf = parse(&file, Arch::Aarch64).unwrap();
        assert_eq!(
            load(&mut mm, &mut app, &file, &elf, Placement::Program),
            Err(ElfError::NoRoom)
        );
    }

    #[test]
    fn huge_segments_are_refused_without_walking_their_pages() {
        let (mut mm, mut app) = setup();
        let file = build_elf(
            Arch::Aarch64,
            ET_EXEC,
            0x40_0000,
            &[Seg {
                vaddr: 0x40_0000,
                offset: 0,
                data: &[0; 0x200],
                memsz: 1 << 60,
                flags: PF_R | PF_W,
            }],
            None,
        );
        let elf = parse(&file, Arch::Aarch64).unwrap();
        assert_eq!(
            load(&mut mm, &mut app, &file, &elf, Placement::Program),
            Err(ElfError::NoRoom)
        );
        assert!(!app.is_mapped(0x40_0000));
    }

    fn read_u64(app: &mut MockApp, addr: u64) -> u64 {
        u64::from_le_bytes(app.peek(addr, 8).try_into().unwrap())
    }

    fn read_str(app: &mut MockApp, addr: u64) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0.. {
            let b = app.peek(addr + i, 1)[0];
            if b == 0 {
                break;
            }
            out.push(b);
        }
        out
    }

    #[test]
    fn initial_stack_layout() {
        let (mut mm, mut app) = setup();
        let image = LoadedImage {
            entry: 0x40_1000,
            phdr: 0x40_0040,
            phnum: 6,
            bias: 0,
            end: 0x50_0000,
        };
        let argv = vec![b"/bin/busybox".to_vec(), b"echo".to_vec(), b"hi".to_vec()];
        let envp = vec![b"PATH=/bin".to_vec()];
        let params = StackParams {
            arch: Arch::Aarch64,
            argv: &argv,
            envp: &envp,
            execfn: b"/bin/busybox",
            image: &image,
            cpu: CpuInfo {
                hwcap: 7,
                hwcap2: 9,
            },
            interp_base: 0,
            random: [3; 16],
        };
        let sp = build_stack(&mut mm, &mut app, &params).unwrap();
        assert_eq!(sp % 16, 0);
        assert_eq!(read_u64(&mut app, sp), 3);
        for (i, arg) in argv.iter().enumerate() {
            let ptr = read_u64(&mut app, sp + 8 + 8 * i as u64);
            assert_eq!(&read_str(&mut app, ptr), arg);
        }
        assert_eq!(read_u64(&mut app, sp + 32), 0);
        let env = read_u64(&mut app, sp + 40);
        assert_eq!(read_str(&mut app, env), b"PATH=/bin");
        assert_eq!(read_u64(&mut app, sp + 48), 0);
        let mut auxv = BTreeMap::new();
        let mut at = sp + 56;
        loop {
            let (k, v) = (read_u64(&mut app, at), read_u64(&mut app, at + 8));
            if k == AT_NULL {
                break;
            }
            auxv.insert(k, v);
            at += 16;
        }
        assert_eq!(auxv[&AT_PHDR], 0x40_0040);
        assert_eq!(auxv[&AT_PHNUM], 6);
        assert_eq!(auxv[&AT_PHENT], 56);
        assert_eq!(auxv[&AT_PAGESZ], 0x1000);
        assert_eq!(auxv[&AT_ENTRY], 0x40_1000);
        assert_eq!(auxv[&AT_HWCAP], 7);
        assert_eq!(auxv[&AT_HWCAP2], 9);
        assert_eq!(auxv[&AT_SECURE], 0);
        assert_eq!(app.peek(auxv[&AT_RANDOM], 16), [3; 16]);
        assert_eq!(read_str(&mut app, auxv[&AT_PLATFORM]), b"aarch64");
        assert_eq!(read_str(&mut app, auxv[&AT_EXECFN]), b"/bin/busybox");
        let stack = mm.vmas().find(sp).unwrap();
        assert_eq!(stack.kind, VmaKind::Stack);
        assert_eq!(stack.end - stack.start, STACK_SIZE);
    }

    #[test]
    fn huge_arguments_are_refused() {
        let (mut mm, mut app) = setup();
        let image = LoadedImage {
            entry: 0,
            phdr: 0,
            phnum: 0,
            bias: 0,
            end: 0,
        };
        let argv = vec![vec![b'a'; (STACK_SIZE / 4) as usize]];
        let params = StackParams {
            arch: Arch::X86_64,
            argv: &argv,
            envp: &[],
            execfn: b"x",
            image: &image,
            cpu: CpuInfo::default(),
            interp_base: 0,
            random: [0; 16],
        };
        assert_eq!(build_stack(&mut mm, &mut app, &params), Err(Errno(E2BIG)));
    }
}
