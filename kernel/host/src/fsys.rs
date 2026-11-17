//! The few `*at` calls [`crate::ImageDir`] needs and `std` does not offer:
//! every lookup is relative to a directory fd and never follows a symlink.
//! POSIX calls only, so this works on Linux and macOS.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

fn name(name: &[u8]) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in a name"))
}

/// `openat(dir, name, flags | O_CLOEXEC | O_NOFOLLOW)`.
pub fn open_at(dir: BorrowedFd<'_>, entry: &[u8], flags: libc::c_int) -> io::Result<OwnedFd> {
    let entry = name(entry)?;
    // SAFETY: valid C string; on success the fd is new and ours.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            entry.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: see above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// What [`stat_at`] reports.
pub struct Stat {
    pub mode: u32,
    pub size: u64,
    pub nlink: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
}

// The field types differ between Linux and macOS.
#[allow(clippy::unnecessary_cast)]
fn convert(st: &libc::stat) -> Stat {
    Stat {
        mode: st.st_mode as u32,
        size: st.st_size as u64,
        nlink: st.st_nlink as u64,
        mtime: st.st_mtime as i64,
        mtime_nsec: st.st_mtime_nsec as i64,
    }
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`, or `fstat(dir)` for `None`.
pub fn stat_at(dir: BorrowedFd<'_>, entry: Option<&[u8]>) -> io::Result<Stat> {
    // SAFETY: an all-zero stat is a valid out buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = match entry {
        // SAFETY: valid fd and out pointer.
        None => unsafe { libc::fstat(dir.as_raw_fd(), &mut st) },
        Some(entry) => {
            let entry = name(entry)?;
            // SAFETY: valid C string and out pointer.
            unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    entry.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            }
        }
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(convert(&st))
}

/// `readlinkat(dir, name)`; targets longer than 4096 bytes are an error.
pub fn read_link_at(dir: BorrowedFd<'_>, entry: &[u8]) -> io::Result<Vec<u8>> {
    let entry = name(entry)?;
    let mut buf = vec![0u8; 4097];
    // SAFETY: valid C string; the buffer has the length passed.
    let len = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            entry.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = len as usize;
    if len == buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "symlink target too long",
        ));
    }
    buf.truncate(len);
    Ok(buf)
}

/// The names in the directory `dir` (consumed), without `.` and `..`.
pub fn list(dir: OwnedFd) -> io::Result<Vec<Vec<u8>>> {
    let raw = std::os::fd::IntoRawFd::into_raw_fd(dir);
    // SAFETY: `raw` is an open directory fd; fdopendir takes it over.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so the fd is still ours.
        drop(unsafe { OwnedFd::from_raw_fd(raw) });
        return Err(err);
    }
    let mut names = Vec::new();
    let result = loop {
        // SAFETY: errno is thread-local; reset it to tell end from error.
        unsafe { *errno_location() = 0 };
        // SAFETY: `stream` is a valid DIR*.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: as above.
            let errno = unsafe { *errno_location() };
            break if errno == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(errno))
            };
        }
        // SAFETY: readdir returned a valid dirent with a NUL-terminated name.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    };
    // SAFETY: closes the stream and its fd exactly once.
    unsafe { libc::closedir(stream) };
    result.map(|()| names)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn errno_location() -> *mut libc::c_int {
    libc::__errno_location()
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
unsafe fn errno_location() -> *mut libc::c_int {
    libc::__error()
}
