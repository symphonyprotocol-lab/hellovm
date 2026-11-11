//! Linux errno values as seen by the guest.
//!
//! These are the guest's numbers, which are the same on x86_64 and aarch64.
//! They must never be mixed with host errno values (macOS numbers differ):
//! host errors are translated, not passed through.

pub const EIO: i64 = 5;
pub const EBADF: i64 = 9;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const ENOSYS: i64 = 38;

/// Largest errno value; a syscall return in `-MAX_ERRNO..=-1` is an error.
pub const MAX_ERRNO: i64 = 4095;
