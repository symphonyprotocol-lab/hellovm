//! Warm clones on the seccomp platform: the memory of a frozen template in
//! one sealed memfd, and new app processes that map it copy-on-write.
//!
//! # Freeze
//!
//! [`crate::SeccompPlatform::prepare_snapshots`] creates the memfd before
//! the kernel process confines itself (it never needs `memfd_create` or
//! `ftruncate` afterwards): empty, [`CAPACITY`] bytes long and sparse, so
//! that it costs nothing until written. When the core freezes the template
//! ([`hellovm_core::platform::Platform::freeze`]), every area of every
//! address space is read with `process_vm_readv` from the first task of its
//! space, except the areas the core knows to be all zero (anonymous memory
//! that was never writable: address-space reservations, guard pages), which
//! are not read at all. An area the app cannot read (`PROT_NONE`,
//! execute-only) is made readable first by an injected `mprotect`: the
//! template's processes end right after, so nothing observes it.
//!
//! Only the pages that are not all zero go into the file, appended one
//! after the other as *extents*: runs of such pages, with the zero pages
//! between two runs, or between a run and the area's start or end, stored
//! too when they are fewer than [`GAP`] (so that a fragmented heap does not
//! become thousands of extents, and an area that is mostly data is one). The file thus has
//! no holes below its end, and how much address space a template has mapped
//! does not matter, only how much it holds. Each task's registers, FP/SIMD
//! state (the extended state included: AVX, SVE), thread pointer and
//! (aarch64) pointer-authentication keys are kept, the template's app
//! processes are killed, and the file is sealed (`F_SEAL_WRITE |
//! F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`): from then on no process, not
//! even a compromised clone kernel process holding the fd, can change it, so
//! what a clone reads from it is what the template had.
//!
//! # Thaw
//!
//! A clone is a fork of the template's kernel process, so it has the
//! platform value with the capture and the memfd at the same fd number.
//! Per address space it spawns a fresh app process (the normal bootstrap,
//! with the memfd left open in it, see [`crate::spawn::spawn`]) and injects,
//! for each private area, an anonymous mapping of the whole area (unless
//! one extent covers it) and then, for each of its extents,
//!
//! ```text
//! mmap(start, len, prot, MAP_PRIVATE | MAP_FIXED, memfd, offset)
//! ```
//!
//! The host kernel then shares the template's pages between all clones and
//! copies a page only when a clone writes it (a private mapping of a file),
//! and a sealed file is never written, so the clones cannot see each
//! other's writes. Only pages the file really has are ever mapped from it:
//! a private mapping of a *hole* of a memfd would make the host allocate
//! the page in the file at the first touch, read or write, which the seals
//! do not prevent, and every clone would grow the file all clones share
//! (and pay for each page it writes twice). The memory that was zero in
//! the template is plain anonymous memory in the clone instead.
//!
//! A `MAP_SHARED` area is mapped as fresh shared anonymous memory and its
//! extents are copied into it from the file (the core only lets a template
//! with a single address space have one, so it is shared with nobody yet).
//! Then `close(memfd)` is injected, so the app process holds no host fd
//! again, the first task gets its registers back, and every other task of
//! the space is an injected `clone(CLONE_VM)` of it with its own registers.
//!
//! The pointer-authentication keys (aarch64, `NT_ARM_PACA_KEYS` and
//! `NT_ARM_PACG_KEYS`) matter because the app processes are new: the host
//! gives every process new keys at `execve`, and a return address the
//! template signed (`paciasp`) would fail authentication in the clone
//! (`SIGILL` with FPAC). Distributions that build with
//! `-mbranch-protection` (Ubuntu) need this; Debian bookworm does not. On a
//! host with pointer authentication whose kernel does not let a tracer set
//! the keys (no `CONFIG_CHECKPOINT_RESTORE`), freezing fails. Like the
//! stack canary, the keys are therefore the same in every clone.
//!
//! These injected syscalls are added to the residual host-syscall surface
//! of `spawn`: `mmap` of the memfd (only that fd, `MAP_PRIVATE | MAP_FIXED`,
//! a range the platform checked) and `close` of it, both before any app
//! code has run in the process. The app still never makes a host syscall
//! itself.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use hellovm_core::platform::Prot;

use crate::regs::{FpRegs, PacKeys, Regs};

/// Size of the snapshot memfd: the most memory (pages that are not zero)
/// all the address spaces of a template may hold. Sparse, so its size
/// costs nothing.
pub const CAPACITY: u64 = 1 << 40;

/// Zero pages between two runs of data (or the ends of the area) are
/// stored with them when they are fewer bytes than this: one more extent costs every clone an injected
/// `mmap`, a stored zero page costs the template a page once.
pub const GAP: u64 = 128 << 10;

/// How much of an area is copied at a time.
pub const CHUNK: usize = 1 << 20;

/// A run of pages of an area that the file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    /// Where it starts in the area.
    pub at: u64,
    pub len: u64,
    /// Where it starts in the file.
    pub offset: u64,
}

/// One area of a frozen address space. What its extents do not cover is
/// zero.
#[derive(Clone, Debug)]
pub struct AreaImage {
    pub start: u64,
    pub len: u64,
    pub prot: Prot,
    pub shared: bool,
    pub extents: Vec<Extent>,
}

/// One frozen task.
#[derive(Clone, Debug)]
pub struct TaskImage {
    pub regs: Regs,
    pub fp: FpRegs,
    /// The extended FP/SIMD state (AVX, SVE), where the host has one.
    pub xstate: Option<Vec<u8>>,
    /// The thread pointer where it is not in [`Regs`] (aarch64).
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    pub tls: u64,
    /// Its pointer-authentication keys, where the host has them.
    pub pac: Option<PacKeys>,
}

#[derive(Clone, Debug, Default)]
pub struct SpaceImage {
    pub areas: Vec<AreaImage>,
    pub tasks: Vec<TaskImage>,
}

/// The platform's warm-clone state.
#[derive(Debug)]
pub enum Snapshots {
    /// The file exists and is empty: the template has not frozen yet.
    Prepared(OwnedFd),
    /// The template froze: the sealed file and what goes where.
    Frozen {
        file: OwnedFd,
        spaces: Vec<SpaceImage>,
        /// Bytes stored: the length of the file's contents.
        stored: u64,
    },
}

fn check(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// The empty, sparse snapshot file. It is not close-on-exec: a clone's app
/// processes keep it open through their `execveat` of the stub until the
/// kernel process closes it in them.
pub fn create_file() -> io::Result<OwnedFd> {
    // SAFETY: a valid C string and flags.
    let fd = check(unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"hellovm-snapshot".as_ptr(),
            libc::MFD_ALLOW_SEALING,
        )
    })?;
    // SAFETY: a new fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    // SAFETY: plain syscall on our fd.
    check(unsafe { libc::ftruncate(fd.as_raw_fd(), CAPACITY as libc::off_t) } as libc::c_long)?;
    Ok(fd)
}

/// Seals the file against any change.
pub fn seal(file: BorrowedFd<'_>) -> io::Result<()> {
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: plain fcntl.
    check(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } as libc::c_long)
        .map(drop)
}

fn zero_page(page: &[u8]) -> bool {
    let (head, words, tail) = {
        // SAFETY: any bytes are valid u64s.
        unsafe { page.align_to::<u64>() }
    };
    head.iter().all(|&b| b == 0) && words.iter().all(|&w| w == 0) && tail.iter().all(|&b| b == 0)
}

/// Appends the pages of a template to the file, in the order they come.
/// The file's position is where the next page goes: nothing else moves it.
pub struct Writer<'a> {
    file: BorrowedFd<'a>,
    /// Bytes written so far.
    offset: u64,
    page: u64,
    zeros: Vec<u8>,
}

impl<'a> Writer<'a> {
    /// For a file nothing was written to yet.
    pub fn new(file: BorrowedFd<'a>, page: u64) -> Writer<'a> {
        Writer {
            file,
            offset: 0,
            page,
            zeros: Vec::new(),
        }
    }

    pub fn stored(&self) -> u64 {
        self.offset
    }

    fn append(&mut self, mut data: &[u8]) -> io::Result<()> {
        if self.offset + data.len() as u64 > CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("the template holds more than {} GiB", CAPACITY >> 30),
            ));
        }
        self.offset += data.len() as u64;
        while !data.is_empty() {
            // SAFETY: the buffer is valid for its length.
            let n = unsafe { libc::write(self.file.as_raw_fd(), data.as_ptr().cast(), data.len()) };
            match n {
                n if n > 0 => data = &data[n as usize..],
                0 => return Err(io::ErrorKind::WriteZero.into()),
                _ => {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
        }
        Ok(())
    }

    fn append_zeros(&mut self, mut len: u64) -> io::Result<()> {
        if self.zeros.is_empty() {
            self.zeros = vec![0; GAP as usize];
        }
        while len > 0 {
            let n = len.min(self.zeros.len() as u64) as usize;
            let zeros = std::mem::take(&mut self.zeros);
            let result = self.append(&zeros[..n]);
            self.zeros = zeros;
            result?;
            len -= n as u64;
        }
        Ok(())
    }

    /// Ends an area after its last [`Writer::store`]: few zero pages at
    /// its end are stored with its last extent.
    pub fn finish(&mut self, extents: &mut [Extent], gap: u64) -> io::Result<()> {
        if let Some(last) = extents.last_mut() {
            if gap > 0 && gap < GAP {
                last.len += gap;
                self.append_zeros(gap)?;
            }
        }
        Ok(())
    }

    /// Stores the next piece of an area: `data` (whole pages) is what the
    /// area has at `at`, and follows what the previous call for this area
    /// stored. `extents` is the area's list so far, `gap` the zero bytes
    /// seen since its last extent.
    pub fn store(
        &mut self,
        extents: &mut Vec<Extent>,
        gap: &mut u64,
        at: u64,
        data: &[u8],
    ) -> io::Result<()> {
        let page = self.page as usize;
        let mut i = 0;
        while i < data.len() {
            let zero = zero_page(&data[i..(i + page).min(data.len())]);
            let mut end = i + page;
            while end < data.len() && zero_page(&data[end..(end + page).min(data.len())]) == zero {
                end += page;
            }
            let end = end.min(data.len());
            let run = (end - i) as u64;
            if zero {
                *gap += run;
            } else {
                match extents.last_mut() {
                    Some(last) if *gap < GAP && last.at + last.len + *gap == at + i as u64 => {
                        let between = *gap;
                        last.len += between + run;
                        self.append_zeros(between)?;
                    }
                    // Few zero pages at the start of the area: stored too,
                    // so that an area that is nearly all data is one extent
                    // (one mapping in a clone instead of two).
                    None if *gap < GAP => {
                        let before = *gap;
                        extents.push(Extent {
                            at: 0,
                            len: before + run,
                            offset: self.offset,
                        });
                        self.append_zeros(before)?;
                    }
                    _ => extents.push(Extent {
                        at: at + i as u64,
                        len: run,
                        offset: self.offset,
                    }),
                }
                *gap = 0;
                self.append(&data[i..end])?;
            }
            i = end;
        }
        Ok(())
    }
}

/// Reads `buf.len()` bytes of the file at `offset`.
pub fn load(file: BorrowedFd<'_>, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: the buffer is valid for the remaining length.
        let n = unsafe {
            libc::pread(
                file.as_raw_fd(),
                buf[done..].as_mut_ptr().cast(),
                buf.len() - done,
                (offset + done as u64) as libc::off_t,
            )
        };
        match n {
            n if n > 0 => done += n as usize,
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            _ => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn stores_only_data_as_extents_and_seals() {
        let file = create_file().unwrap();
        let page = crate::sys::page_size() as usize;
        let far = (GAP as usize).div_ceil(page) + 1;
        // Zeros for longer than GAP, then data at pages far+1 and far+3 (a
        // short gap: one extent with page far+2), then after another long
        // gap two pages split over two calls and one last zero page.
        let mut data = vec![0u8; (2 * far + 12) * page];
        data[(far + 1) * page + 7] = 42;
        data[(far + 3) * page] = 1;
        let second = 2 * far + 9;
        data[second * page..(second + 2) * page].fill(7);
        let mut writer = Writer::new(file.as_fd(), page as u64);
        let (mut extents, mut gap) = (Vec::new(), 0);
        let cut = (second + 1) * page;
        writer
            .store(&mut extents, &mut gap, 0, &data[..cut])
            .unwrap();
        writer
            .store(&mut extents, &mut gap, cut as u64, &data[cut..])
            .unwrap();
        writer.finish(&mut extents, gap).unwrap();
        let p = page as u64;
        assert_eq!(
            extents,
            [
                Extent {
                    at: (far as u64 + 1) * p,
                    len: 3 * p,
                    offset: 0
                },
                // With the zero page that ends the area.
                Extent {
                    at: second as u64 * p,
                    len: 3 * p,
                    offset: 3 * p
                },
            ]
        );
        assert_eq!(writer.stored(), 6 * p);
        for extent in &extents {
            let mut back = vec![9u8; extent.len as usize];
            load(file.as_fd(), extent.offset, &mut back).unwrap();
            let at = extent.at as usize;
            assert_eq!(back, data[at..at + back.len()]);
        }
        // A small area with zeros around its data is one extent.
        let small = &data[far * page..(far + 6) * page];
        let (mut extents, mut gap) = (Vec::new(), 0);
        writer.store(&mut extents, &mut gap, 0, small).unwrap();
        writer.finish(&mut extents, gap).unwrap();
        assert_eq!(
            extents,
            [Extent {
                at: 0,
                len: 6 * p,
                offset: 6 * p
            }]
        );
        // Every page below the end is allocated: no hole a clone could
        // fill. (`st_blocks` counts 512-byte units.)
        // SAFETY: an all-zero stat is valid; fstat fills it.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: plain fstat on our fd.
        assert_eq!(unsafe { libc::fstat(file.as_raw_fd(), &mut stat) }, 0);
        assert_eq!(stat.st_blocks as u64 * 512, 12 * p);
        seal(file.as_fd()).unwrap();
        // SAFETY: plain syscall.
        let ret = unsafe { libc::pwrite(file.as_raw_fd(), b"x".as_ptr().cast(), 1, 0) };
        assert!(ret < 0, "sealed against writes");
    }
}
