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
//! address space is laid out in the file one after the other, page-aligned,
//! and copied there with `process_vm_readv` from the first task of its
//! space. An area the app cannot read (`PROT_NONE`, execute-only) is made
//! readable first by an injected `mprotect`: the template's processes end
//! right after, so nothing observes it. Pages that are all zero are not
//! written and stay holes of the file (untouched heap, stacks and
//! reservations cost nothing). Each task's registers, FP/SIMD state,
//! thread pointer and (aarch64) pointer-authentication keys are kept, the template's app processes are killed, and
//! the file is sealed (`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
//! F_SEAL_SEAL`): from then on no process, not even a compromised clone
//! kernel process holding the fd, can change it, so what a clone reads from
//! it is what the template had.
//!
//! # Thaw
//!
//! A clone is a fork of the template's kernel process, so it has the
//! platform value with the capture and the memfd at the same fd number.
//! Per address space it spawns a fresh app process (the normal bootstrap,
//! with the memfd left open in it, see [`crate::spawn::spawn`]) and injects,
//! for each private area,
//!
//! ```text
//! mmap(start, len, prot, MAP_PRIVATE | MAP_FIXED, memfd, offset)
//! ```
//!
//! The host kernel then shares the template's pages between all clones and
//! copies a page only when a clone writes it (a private mapping of a file),
//! and a sealed file is never written, so the clones cannot see each
//! other's writes. A `MAP_SHARED` area is instead mapped as fresh shared
//! anonymous memory and filled from the file (the core only lets a template
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

/// Size of the snapshot memfd: the most memory, holes included, all the
/// address spaces of a template may have mapped. Sparse, so its size costs
/// nothing.
pub const CAPACITY: u64 = 1 << 40;

/// How much of an area is copied at a time.
pub const CHUNK: usize = 1 << 20;

/// One area of a frozen address space and where its contents are in the
/// file.
#[derive(Clone, Copy, Debug)]
pub struct AreaImage {
    pub start: u64,
    pub len: u64,
    pub prot: Prot,
    pub shared: bool,
    pub offset: u64,
}

/// One frozen task.
#[derive(Clone, Copy, Debug)]
pub struct TaskImage {
    pub regs: Regs,
    pub fp: FpRegs,
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
        /// Bytes actually stored (non-zero pages).
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

/// A shared writable window onto part of the file.
struct Window {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Window {
    fn map(file: BorrowedFd<'_>, offset: u64, len: usize) -> io::Result<Window> {
        // SAFETY: a new mapping chosen by the host; checked below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                offset as libc::off_t,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Window { ptr, len })
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // SAFETY: unmapping exactly what `map` mapped.
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}

/// Stores `data`, which belongs at `offset` of the file, skipping pages
/// that are all zero (they read as zero from a hole). Returns the bytes
/// stored.
pub fn store(file: BorrowedFd<'_>, offset: u64, data: &[u8], page: usize) -> io::Result<u64> {
    let pages = data.chunks(page).enumerate().filter(|(_, p)| !zero_page(p));
    let mut window: Option<Window> = None;
    let mut stored = 0;
    for (i, bytes) in pages {
        let window = match &window {
            Some(window) => window,
            None => window.insert(Window::map(file, offset, data.len())?),
        };
        // SAFETY: the window is `data.len()` bytes long and the page lies
        // inside it; nothing else in this process uses the window.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (window.ptr as *mut u8).add(i * page),
                bytes.len(),
            );
        }
        stored += bytes.len() as u64;
    }
    Ok(stored)
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
    fn stores_only_non_zero_pages_and_seals() {
        let file = create_file().unwrap();
        let page = crate::sys::page_size() as usize;
        let mut data = vec![0u8; 4 * page];
        data[page + 7] = 42;
        data[3 * page] = 1;
        let stored = store(file.as_fd(), 8 * page as u64, &data, page).unwrap();
        assert_eq!(stored, 2 * page as u64);
        let mut back = vec![9u8; 4 * page];
        load(file.as_fd(), 8 * page as u64, &mut back).unwrap();
        assert_eq!(back, data);
        seal(file.as_fd()).unwrap();
        assert!(
            Window::map(file.as_fd(), 0, page).is_err(),
            "sealed against writes"
        );
        // SAFETY: plain syscall.
        let ret = unsafe { libc::pwrite(file.as_raw_fd(), b"x".as_ptr().cast(), 1, 0) };
        assert!(ret < 0);
    }
}
