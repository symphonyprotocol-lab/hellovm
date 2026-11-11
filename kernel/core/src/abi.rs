//! Guest ABI encodings that differ between architectures or are easy to get
//! wrong: open flags, `struct stat`, `statx`, `dirent64`, `statfs`,
//! `utsname`.
//!
//! Everything is encoded little-endian (both supported architectures are).

use crate::arch::Arch;
use crate::fd::Access;
use crate::vfs::{Stat, Timespec};

/// Decoded `open` flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenFlags {
    /// `O_ACCMODE` bits as given (0 read, 1 write, 2 read-write).
    pub accmode: u64,
    pub creat: bool,
    pub excl: bool,
    pub trunc: bool,
    pub append: bool,
    pub nonblock: bool,
    pub directory: bool,
    pub nofollow: bool,
    pub cloexec: bool,
    pub path: bool,
    pub tmpfile: bool,
}

// Flags with the same value on x86_64 and aarch64 (octal, as in the
// headers).
pub const O_ACCMODE: u64 = 0o3;
pub const O_CREAT: u64 = 0o100;
pub const O_EXCL: u64 = 0o200;
pub const O_NOCTTY: u64 = 0o400;
pub const O_TRUNC: u64 = 0o1000;
pub const O_APPEND: u64 = 0o2000;
pub const O_NONBLOCK: u64 = 0o4000;
pub const O_CLOEXEC: u64 = 0o2_000_000;
pub const O_PATH: u64 = 0o10_000_000;
const O_TMPFILE_BASE: u64 = 0o20_000_000;

/// Flags whose values differ by architecture.
struct ArchOpenFlags {
    directory: u64,
    nofollow: u64,
    largefile: u64,
}

fn arch_open_flags(arch: Arch) -> ArchOpenFlags {
    match arch {
        Arch::X86_64 => ArchOpenFlags {
            directory: 0o200_000,
            nofollow: 0o400_000,
            largefile: 0o100_000,
        },
        Arch::Aarch64 => ArchOpenFlags {
            directory: 0o40_000,
            nofollow: 0o100_000,
            largefile: 0o400_000,
        },
    }
}

pub fn decode_open_flags(arch: Arch, raw: u64) -> OpenFlags {
    let a = arch_open_flags(arch);
    let has = |bit: u64| raw & bit != 0;
    OpenFlags {
        accmode: raw & O_ACCMODE,
        creat: has(O_CREAT),
        excl: has(O_EXCL),
        trunc: has(O_TRUNC),
        append: has(O_APPEND),
        nonblock: has(O_NONBLOCK),
        directory: has(a.directory),
        nofollow: has(a.nofollow),
        cloexec: has(O_CLOEXEC),
        path: has(O_PATH),
        tmpfile: raw & O_TMPFILE_BASE != 0,
    }
}

/// The `O_DIRECTORY` value of `arch` (for building flags in tests).
pub fn o_directory(arch: Arch) -> u64 {
    arch_open_flags(arch).directory
}

/// The `O_NOFOLLOW` value of `arch`.
pub fn o_nofollow(arch: Arch) -> u64 {
    arch_open_flags(arch).nofollow
}

/// The file status flags `F_GETFL` reports. 64-bit Linux always includes
/// `O_LARGEFILE`.
pub fn encode_status_flags(arch: Arch, access: Access, append: bool, nonblock: bool) -> u64 {
    let a = arch_open_flags(arch);
    let mut flags = match access {
        Access::Read => 0,
        Access::Write => 1,
        Access::ReadWrite => 2,
        Access::Path => O_PATH,
    };
    if append {
        flags |= O_APPEND;
    }
    if nonblock {
        flags |= O_NONBLOCK;
    }
    if access != Access::Path {
        flags |= a.largefile;
    }
    flags
}

fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

/// `struct stat` as `fstat`/`newfstatat` return it.
pub fn encode_stat(arch: Arch, st: &Stat) -> Vec<u8> {
    match arch {
        Arch::Aarch64 => {
            // asm-generic/stat.h, 128 bytes.
            let mut b = vec![0u8; 128];
            put(&mut b, 0, &st.dev.to_le_bytes());
            put(&mut b, 8, &st.ino.to_le_bytes());
            put(&mut b, 16, &st.mode.to_le_bytes());
            put(&mut b, 20, &st.nlink.to_le_bytes());
            put(&mut b, 24, &st.uid.to_le_bytes());
            put(&mut b, 28, &st.gid.to_le_bytes());
            put(&mut b, 32, &st.rdev.to_le_bytes());
            put(&mut b, 48, &st.size.to_le_bytes());
            put(&mut b, 56, &st.blksize.to_le_bytes());
            put(&mut b, 64, &st.blocks.to_le_bytes());
            put_times(&mut b, 72, st);
            b
        }
        Arch::X86_64 => {
            // arch/x86/include/uapi/asm/stat.h, 144 bytes.
            let mut b = vec![0u8; 144];
            put(&mut b, 0, &st.dev.to_le_bytes());
            put(&mut b, 8, &st.ino.to_le_bytes());
            put(&mut b, 16, &u64::from(st.nlink).to_le_bytes());
            put(&mut b, 24, &st.mode.to_le_bytes());
            put(&mut b, 28, &st.uid.to_le_bytes());
            put(&mut b, 32, &st.gid.to_le_bytes());
            put(&mut b, 40, &st.rdev.to_le_bytes());
            put(&mut b, 48, &st.size.to_le_bytes());
            put(&mut b, 56, &u64::from(st.blksize).to_le_bytes());
            put(&mut b, 64, &st.blocks.to_le_bytes());
            put_times(&mut b, 72, st);
            b
        }
    }
}

/// atime, mtime, ctime as (seconds, nanoseconds) pairs of 64-bit words.
fn put_times(b: &mut [u8], off: usize, st: &Stat) {
    for (i, t) in [st.atime, st.mtime, st.ctime].iter().enumerate() {
        put(b, off + i * 16, &t.sec.to_le_bytes());
        put(b, off + i * 16 + 8, &u64::from(t.nsec).to_le_bytes());
    }
}

/// `STATX_BASIC_STATS`: everything [`encode_statx`] fills in.
pub const STATX_BASIC_STATS: u32 = 0x7ff;

/// `struct statx` (the same on every architecture, 256 bytes).
pub fn encode_statx(st: &Stat) -> Vec<u8> {
    let mut b = vec![0u8; 256];
    put(&mut b, 0, &STATX_BASIC_STATS.to_le_bytes());
    put(&mut b, 4, &st.blksize.to_le_bytes());
    put(&mut b, 16, &st.nlink.to_le_bytes());
    put(&mut b, 20, &st.uid.to_le_bytes());
    put(&mut b, 24, &st.gid.to_le_bytes());
    put(&mut b, 28, &(st.mode as u16).to_le_bytes());
    put(&mut b, 32, &st.ino.to_le_bytes());
    put(&mut b, 40, &st.size.to_le_bytes());
    put(&mut b, 48, &st.blocks.to_le_bytes());
    // atime, btime (left zero), ctime, mtime: 16-byte timestamps.
    let ts = |b: &mut [u8], off: usize, t: Timespec| {
        put(b, off, &t.sec.to_le_bytes());
        put(b, off + 8, &t.nsec.to_le_bytes());
    };
    ts(&mut b, 64, st.atime);
    ts(&mut b, 96, st.ctime);
    ts(&mut b, 112, st.mtime);
    let (rmaj, rmin) = split_dev(st.rdev);
    let (dmaj, dmin) = split_dev(st.dev);
    put(&mut b, 128, &rmaj.to_le_bytes());
    put(&mut b, 132, &rmin.to_le_bytes());
    put(&mut b, 136, &dmaj.to_le_bytes());
    put(&mut b, 140, &dmin.to_le_bytes());
    b
}

/// Linux `major`/`minor` of an encoded device number.
pub fn split_dev(dev: u64) -> (u32, u32) {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major as u32, minor as u32)
}

/// Length of one `dirent64` record for `name`.
pub fn dirent64_len(name: &[u8]) -> usize {
    (19 + name.len() + 1).next_multiple_of(8)
}

/// Appends one `struct linux_dirent64` (the same on every architecture).
pub fn push_dirent64(out: &mut Vec<u8>, ino: u64, next_off: i64, kind: u8, name: &[u8]) {
    let len = dirent64_len(name);
    let start = out.len();
    out.extend_from_slice(&ino.to_le_bytes());
    out.extend_from_slice(&next_off.to_le_bytes());
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.push(kind);
    out.extend_from_slice(name);
    out.resize(start + len, 0);
}

/// `struct statfs` (all-long fields; the same layout on both
/// architectures, 120 bytes).
pub fn encode_statfs(fs_type: u64, bsize: u64, blocks: u64, free: u64, files: u64, ffree: u64) -> Vec<u8> {
    let mut b = vec![0u8; 120];
    let words = [fs_type, bsize, blocks, free, free, files, ffree];
    for (i, w) in words.iter().enumerate() {
        put(&mut b, i * 8, &w.to_le_bytes());
    }
    // f_fsid (8 bytes) stays zero; f_namelen, f_frsize, f_flags.
    put(&mut b, 64, &255u64.to_le_bytes());
    put(&mut b, 72, &bsize.to_le_bytes());
    put(&mut b, 80, &0u64.to_le_bytes());
    b
}

/// `struct utsname`: six 65-byte NUL-terminated fields.
pub fn encode_utsname(fields: [&str; 6]) -> Vec<u8> {
    let mut b = vec![0u8; 65 * 6];
    for (i, field) in fields.iter().enumerate() {
        let bytes = &field.as_bytes()[..field.len().min(64)];
        put(&mut b, i * 65, bytes);
    }
    b
}

/// `struct timespec` / `struct timeval` (two 64-bit words).
pub fn encode_pair(a: i64, b: i64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

pub fn decode_pair(bytes: &[u8; 16]) -> (i64, i64) {
    (
        i64::from_le_bytes(bytes[..8].try_into().unwrap()),
        i64::from_le_bytes(bytes[8..].try_into().unwrap()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Stat {
        Stat {
            dev: 0x2a,
            ino: 77,
            mode: 0o100644,
            nlink: 3,
            uid: 1000,
            gid: 100,
            rdev: 0x103,
            size: 12345,
            blksize: 4096,
            blocks: 32,
            atime: Timespec { sec: 1, nsec: 2 },
            mtime: Timespec { sec: 3, nsec: 4 },
            ctime: Timespec { sec: 5, nsec: 6 },
        }
    }

    fn u32_at(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    fn u64_at(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    #[test]
    fn stat_layout_aarch64() {
        let b = encode_stat(Arch::Aarch64, &sample());
        assert_eq!(b.len(), 128);
        assert_eq!(u64_at(&b, 8), 77);
        assert_eq!(u32_at(&b, 16), 0o100644);
        assert_eq!(u32_at(&b, 20), 3);
        assert_eq!(u32_at(&b, 24), 1000);
        assert_eq!(u64_at(&b, 32), 0x103);
        assert_eq!(u64_at(&b, 48), 12345);
        assert_eq!(u32_at(&b, 56), 4096);
        assert_eq!(u64_at(&b, 64), 32);
        assert_eq!((u64_at(&b, 72), u64_at(&b, 80)), (1, 2));
        assert_eq!((u64_at(&b, 88), u64_at(&b, 96)), (3, 4));
        assert_eq!((u64_at(&b, 104), u64_at(&b, 112)), (5, 6));
    }

    #[test]
    fn stat_layout_x86_64() {
        let b = encode_stat(Arch::X86_64, &sample());
        assert_eq!(b.len(), 144);
        assert_eq!(u64_at(&b, 8), 77);
        assert_eq!(u64_at(&b, 16), 3, "nlink is 64-bit and comes before mode");
        assert_eq!(u32_at(&b, 24), 0o100644);
        assert_eq!(u32_at(&b, 28), 1000);
        assert_eq!(u32_at(&b, 32), 100);
        assert_eq!(u64_at(&b, 40), 0x103);
        assert_eq!(u64_at(&b, 48), 12345);
        assert_eq!(u64_at(&b, 56), 4096);
        assert_eq!(u64_at(&b, 64), 32);
        assert_eq!((u64_at(&b, 88), u64_at(&b, 96)), (3, 4));
    }

    #[test]
    fn statx_layout() {
        let b = encode_statx(&sample());
        assert_eq!(b.len(), 256);
        assert_eq!(u32_at(&b, 0), STATX_BASIC_STATS);
        assert_eq!(u32_at(&b, 16), 3);
        assert_eq!(u16::from_le_bytes([b[28], b[29]]), 0o100644);
        assert_eq!(u64_at(&b, 40), 12345);
        assert_eq!(u64_at(&b, 112), 3, "mtime");
        assert_eq!((u32_at(&b, 128), u32_at(&b, 132)), (1, 3));
    }

    #[test]
    fn open_flags_differ_by_arch() {
        // O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_RDONLY as each libc
        // encodes it.
        let arm = decode_open_flags(Arch::Aarch64, 0o40_000 | 0o100_000 | O_CLOEXEC);
        assert!(arm.directory && arm.nofollow && arm.cloexec && !arm.creat);
        let x86 = decode_open_flags(Arch::X86_64, 0o200_000 | 0o400_000 | O_CLOEXEC);
        assert!(x86.directory && x86.nofollow && x86.cloexec);
        // The aarch64 O_DIRECTORY bit is O_DIRECT on x86_64: not a directory.
        assert!(!decode_open_flags(Arch::X86_64, 0o40_000).directory);
        let w = decode_open_flags(Arch::X86_64, 0o1 | O_CREAT | O_TRUNC | O_APPEND);
        assert_eq!(w.accmode, 1);
        assert!(w.creat && w.trunc && w.append);
        assert_eq!(
            encode_status_flags(Arch::X86_64, Access::Write, true, false),
            1 | O_APPEND | 0o100_000
        );
        assert_eq!(
            encode_status_flags(Arch::Aarch64, Access::ReadWrite, false, true),
            2 | O_NONBLOCK | 0o400_000
        );
    }

    #[test]
    fn dirent64_records_are_aligned() {
        let mut out = Vec::new();
        push_dirent64(&mut out, 5, 1, 4, b".");
        assert_eq!(out.len(), 24);
        push_dirent64(&mut out, 6, 2, 8, b"hello.txt");
        assert_eq!(out.len(), 24 + 32);
        assert_eq!(u16::from_le_bytes([out[16], out[17]]), 24);
        assert_eq!(out[18], 4);
        assert_eq!(&out[19..21], b".\0");
        assert_eq!(&out[24 + 19..24 + 28], b"hello.txt");
        assert_eq!(out[24 + 28], 0);
    }

    #[test]
    fn misc_layouts() {
        let u = encode_utsname(["Linux", "cansol", "6.1.0", "#1", "aarch64", "(none)"]);
        assert_eq!(u.len(), 390);
        assert_eq!(&u[65..71], b"cansol");
        assert_eq!(u[70], 0);
        let s = encode_statfs(0x794c_7630, 4096, 100, 50, 10, 5);
        assert_eq!(s.len(), 120);
        assert_eq!(u64_at(&s, 0), 0x794c_7630);
        assert_eq!(u64_at(&s, 32), 50);
        assert_eq!(u64_at(&s, 64), 255);
        assert_eq!(split_dev(crate::vfs::makedev(136, 300)), (136, 300));
        assert_eq!(decode_pair(&encode_pair(-3, 9)), (-3, 9));
    }
}
