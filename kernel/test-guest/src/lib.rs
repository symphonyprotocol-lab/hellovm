//! Paths of the test guests built by this crate's build script.
//!
//! Each guest is a static, libc-free Linux executable for the target
//! architecture. Linux targets only.

#![forbid(unsafe_code)]

/// Writes [`HELLO_STDOUT`] to fd 1 and [`HELLO_STDERR`] to fd 2, checking
/// that each `write` returns the full length, then calls
/// `exit_group(HELLO_EXIT_CODE)`. Exits with 1 if a write came up short.
#[cfg(target_os = "linux")]
pub const HELLO: &str = env!("CANSOL_GUEST_HELLO");

pub const HELLO_STDOUT: &str = "Hello from inside the cansol sandbox!\n";
pub const HELLO_STDERR: &str = "This line went to stderr.\n";
pub const HELLO_EXIT_CODE: i32 = 42;

/// Calls `getpid` and exits with the negated return value. The kernel
/// emulates `getpid` (the sandbox pid is 1, so the exit status is 255); a
/// call that reached the host would return the app process's host pid.
#[cfg(target_os = "linux")]
pub const ENOSYS: &str = env!("CANSOL_GUEST_ENOSYS");

/// A static-PIE C program linked against glibc. Prints one line:
/// `main=<addr> argc=<n> argv1=<arg> tls=42 big=x small pagesz=<n>
/// random=yes`. Empty when cross-compiling (no target libc).
#[cfg(target_os = "linux")]
pub const PIE: &str = env!("CANSOL_GUEST_PIE");
