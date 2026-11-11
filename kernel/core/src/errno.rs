//! Linux errno values as seen by the guest.
//!
//! These are the guest's numbers, which are the same on x86_64 and aarch64.
//! They must never be mixed with host errno values (macOS numbers differ):
//! host errors are translated with [`Errno::from_host`], never passed
//! through.

use std::fmt;
use std::io;

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const EIO: i64 = 5;
pub const ENXIO: i64 = 6;
pub const E2BIG: i64 = 7;
pub const ENOEXEC: i64 = 8;
pub const EBADF: i64 = 9;
pub const ECHILD: i64 = 10;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const EBUSY: i64 = 16;
pub const EEXIST: i64 = 17;
pub const EXDEV: i64 = 18;
pub const ENODEV: i64 = 19;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const EMFILE: i64 = 24;
pub const ENOTTY: i64 = 25;
pub const EFBIG: i64 = 27;
pub const ENOSPC: i64 = 28;
pub const ESPIPE: i64 = 29;
pub const EROFS: i64 = 30;
pub const EMLINK: i64 = 31;
pub const ERANGE: i64 = 34;
pub const ENAMETOOLONG: i64 = 36;
pub const ENOSYS: i64 = 38;
pub const ENOTEMPTY: i64 = 39;
pub const ELOOP: i64 = 40;
pub const ENODATA: i64 = 61;
pub const EOVERFLOW: i64 = 75;
pub const EOPNOTSUPP: i64 = 95;
pub const ETIMEDOUT: i64 = 110;

/// Largest errno value; a syscall return in `-MAX_ERRNO..=-1` is an error.
pub const MAX_ERRNO: i64 = 4095;

/// A guest errno value (positive).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Errno(pub i64);

impl Errno {
    /// The syscall return value for this error.
    pub const fn ret(self) -> i64 {
        -self.0
    }

    /// Translates a host I/O error into a guest errno by its kind. Host
    /// errno numbers are deliberately ignored.
    pub fn from_host(err: &io::Error) -> Errno {
        use io::ErrorKind::*;
        Errno(match err.kind() {
            NotFound => ENOENT,
            PermissionDenied => EACCES,
            AlreadyExists => EEXIST,
            InvalidInput => EINVAL,
            NotADirectory => ENOTDIR,
            IsADirectory => EISDIR,
            DirectoryNotEmpty => ENOTEMPTY,
            ReadOnlyFilesystem => EROFS,
            OutOfMemory => ENOMEM,
            InvalidFilename => ENAMETOOLONG,
            Unsupported => EOPNOTSUPP,
            _ => EIO,
        })
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

/// The result of a syscall handler: a value or a guest errno.
pub type SysResult<T> = Result<T, Errno>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_errors_are_translated_by_kind() {
        // A host errno number that means something else on the guest.
        let err = io::Error::new(io::ErrorKind::NotFound, "x");
        assert_eq!(Errno::from_host(&err), Errno(ENOENT));
        let err = io::Error::other("x");
        assert_eq!(Errno::from_host(&err), Errno(EIO));
    }
}
