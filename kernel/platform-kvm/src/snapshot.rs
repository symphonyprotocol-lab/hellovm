//! Warm clones on KVM: a clone's app memory is its template's, mapped
//! from the snapshot file (see README, "Warm clones on KVM").
//!
//! The template's kernel process writes each app frame that is not all
//! zero into the snapshot (a memfd) at the frame's own offset, and the
//! frames between two of them as zeros when fewer than
//! [`Hypervisor::SNAPSHOT_GAP`](hellovm_platform_arm64::Hypervisor::SNAPSHOT_GAP)
//! lie between; the rest of the file is a hole. A clone's kernel process
//! maps each run of written pages over the same offsets of its own app
//! memory, privately: the host shares those pages between the template's
//! file and every clone and copies one only when a clone writes it (in
//! the host's page fault, within `KVM_RUN`: no exit to the kernel
//! process). Everything else stays the clone's own anonymous memory,
//! zero, as the template's was. Holes are never mapped: the host fills a
//! hole of a memfd at the first touch through any mapping, so a clone
//! that could touch them would grow the file all clones share.
//!
//! The runs come from the host (`lseek` with `SEEK_DATA` and `SEEK_HOLE`,
//! made before the clone's kernel process confines itself), not from
//! anything the template wrote: the template's kernel process ran guest
//! code and the bytes it wrote are read only once the clone is confined.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use crate::sys::host_page_size;
use crate::KvmPlatform;

/// Most runs a clone maps: each is a mapping of its own (Linux allows
/// 65,530 per process by default). A template padded as the platform
/// pads has at most 16,384 in 2 GiB of app memory.
pub const MAX_RUNS: usize = 16_384;

/// What [`map_frozen_memory`] mapped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mapped {
    pub runs: usize,
    pub bytes: u64,
}

/// The runs of pages of the file `fd` that hold data in `at..at + len`, as
/// offsets from `at` and lengths, in whole host pages; more than `max` is
/// an error.
pub fn written_runs(fd: RawFd, at: u64, len: u64, max: usize) -> io::Result<Vec<(u64, u64)>> {
    let page = host_page_size() as u64;
    let end = at.checked_add(len).ok_or(io::ErrorKind::InvalidInput)?;
    if !at.is_multiple_of(page) || !len.is_multiple_of(page) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let seek = |from: u64, whence: libc::c_int| -> io::Result<Option<u64>> {
        let from = libc::off_t::try_from(from).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: plain lseek on an fd the caller holds.
        let to = unsafe { libc::lseek(fd, from, whence) };
        if to >= 0 {
            return Ok(Some(to as u64));
        }
        match io::Error::last_os_error() {
            // No data at or after `from`.
            err if err.raw_os_error() == Some(libc::ENXIO) => Ok(None),
            err => Err(err),
        }
    };
    let mut runs = Vec::new();
    let mut pos = at;
    while pos < end {
        let Some(data) = seek(pos, libc::SEEK_DATA)? else {
            break;
        };
        let start = (data - data % page).max(pos);
        if start >= end {
            break;
        }
        let hole = seek(data, libc::SEEK_HOLE)?.unwrap_or(end);
        let stop = hole.next_multiple_of(page).min(end);
        if stop <= start {
            return Err(io::Error::other("the snapshot's file moved under it"));
        }
        if runs.len() == max {
            return Err(io::Error::other(format!(
                "the snapshot's app memory is in more than {max} runs"
            )));
        }
        runs.push((start - at, stop - start));
        pos = stop;
    }
    Ok(runs)
}

/// Maps the app memory of the snapshot `fd`, whose app memory region
/// starts at `at`, into this clone's app memory (see the module
/// documentation), before [`KvmPlatform::load_frozen`] without an origin.
/// Only on a platform where nothing has run yet.
pub fn map_frozen_memory(app: &mut KvmPlatform, fd: BorrowedFd<'_>, at: u64) -> io::Result<Mapped> {
    let (memory, _) = app.pool_sizes();
    let runs = written_runs(fd.as_raw_fd(), at, memory, MAX_RUNS)?;
    let mapped = app.with_app_memory(|mem| -> io::Result<Mapped> {
        let mut mapped = Mapped::default();
        for &(offset, len) in &runs {
            mem.map_file_private(offset as usize, len as usize, fd.as_raw_fd(), at + offset)?;
            mapped.runs += 1;
            mapped.bytes += len;
        }
        Ok(mapped)
    });
    mapped.unwrap_or_else(|| Err(io::Error::other("the platform's app memory is in use")))
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn memfd(len: u64) -> OwnedFd {
        // SAFETY: plain calls; the fd is owned below.
        unsafe {
            let fd = libc::memfd_create(c"runs".as_ptr(), libc::MFD_CLOEXEC);
            assert!(fd >= 0);
            assert_eq!(libc::ftruncate(fd, len as libc::off_t), 0);
            OwnedFd::from_raw_fd(fd)
        }
    }

    fn write(fd: &OwnedFd, at: u64, data: &[u8]) {
        // SAFETY: a valid buffer.
        let n = unsafe {
            libc::pwrite(
                fd.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                at as libc::off_t,
            )
        };
        assert_eq!(n, data.len() as isize);
    }

    /// The runs are what the file holds, in host pages, inside the range
    /// asked for; zero bytes written count, holes do not.
    #[test]
    fn written_runs_are_the_files_data() {
        let page = super::host_page_size() as u64;
        let fd = memfd(64 * page);
        assert_eq!(
            super::written_runs(fd.as_raw_fd(), 0, 64 * page, 8).unwrap(),
            []
        );
        write(&fd, 0, b"header");
        write(&fd, 8 * page + 5, b"x");
        write(&fd, 9 * page, &vec![0; page as usize]);
        write(&fd, 20 * page, b"y");
        write(&fd, 63 * page, b"last");
        let runs = super::written_runs(fd.as_raw_fd(), 8 * page, 56 * page, 8).unwrap();
        assert_eq!(runs, [(0, 2 * page), (12 * page, page), (55 * page, page)]);
        // Only inside the range.
        let runs = super::written_runs(fd.as_raw_fd(), 8 * page, 4 * page, 8).unwrap();
        assert_eq!(runs, [(0, 2 * page)]);
        // Too many runs is an error, as is a range not in whole pages.
        assert!(super::written_runs(fd.as_raw_fd(), 0, 64 * page, 3).is_err());
        assert!(super::written_runs(fd.as_raw_fd(), 1, page, 8).is_err());
    }
}
