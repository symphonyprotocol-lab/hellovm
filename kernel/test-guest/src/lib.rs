//! Paths of the test guests built by this crate's build script.
//!
//! The assembly guests are static, libc-free Linux executables for the
//! target architecture; the C guests use the build host's glibc. Linux
//! targets, and macOS on Apple silicon (aarch64 Linux executables for the
//! HVF platform: the assembly guests and the `asm/hvf` ones only).

#![forbid(unsafe_code)]

/// Writes [`HELLO_STDOUT`] to fd 1 and [`HELLO_STDERR`] to fd 2, checking
/// that each `write` returns the full length, then calls
/// `exit_group(HELLO_EXIT_CODE)`. Exits with 1 if a write came up short.
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
pub const HELLO: &str = env!("HELLOVM_GUEST_HELLO");

pub const HELLO_STDOUT: &str = "Hello from inside the hellovm sandbox!\n";
pub const HELLO_STDERR: &str = "This line went to stderr.\n";
pub const HELLO_EXIT_CODE: i32 = 42;

/// Calls `getpid` and exits with the negated return value. The kernel
/// emulates `getpid` (the sandbox pid is 1, so the exit status is 255); a
/// call that reached the host would return the app process's host pid.
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
pub const ENOSYS: &str = env!("HELLOVM_GUEST_ENOSYS");

/// A static-PIE C program linked against glibc. Prints one line:
/// `main=<addr> argc=<n> argv1=<arg> tls=42 big=x small pagesz=<n>
/// random=yes`. Empty when cross-compiling (no target libc).
#[cfg(target_os = "linux")]
pub const PIE: &str = env!("HELLOVM_GUEST_PIE");

/// A static-PIE glibc program that checks signal delivery: fault handlers,
/// masks, timers, the alternate stack, restarts, child statuses and FP
/// state across asynchronous handlers. Prints one line per check (see
/// `hellovm/tests/signals.rs`). Empty when cross-compiling.
#[cfg(target_os = "linux")]
pub const SIGNALS: &str = env!("HELLOVM_GUEST_SIGNALS");

/// A dynamically linked glibc program. Prints `dynamic: arg=<arg>
/// sqrt2=1.4142 interp=yes exe=<path>`. Empty when cross-compiling.
#[cfg(target_os = "linux")]
pub const DYNAMIC: &str = env!("HELLOVM_GUEST_DYNAMIC");

/// A static-PIE glibc program that checks threads: join, TLS, contended
/// mutexes and condition variables, timed waits, signals to one thread,
/// robust mutexes, fork from a threaded process and exit from a thread.
/// Prints one line per check (see `hellovm/tests/threads.rs`) and exits
/// with 7. Empty when cross-compiling.
#[cfg(target_os = "linux")]
pub const THREADS: &str = env!("HELLOVM_GUEST_THREADS");

/// Dynamically linked glibc program that exercises emulated IPv4 sockets: loopback,
/// address classification, half-close, `MSG_NOSIGNAL`, ioctl, `/proc/net`,
/// virtual DNS, and `getaddrinfo` / `getifaddrs`. Empty when cross-compiling.
#[cfg(target_os = "linux")]
pub const NETCHECK: &str = env!("HELLOVM_GUEST_NETCHECK");

/// aarch64 Linux, built on macOS for the HVF platform: calls `getpid` N
/// times (N is the decimal `argv[1]`, default 1), checking each result is
/// 1, then exits with 0 (1 on a wrong result).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const GETPID_LOOP: &str = env!("HELLOVM_GUEST_GETPID_LOOP");

/// aarch64 Linux, built on macOS: loads from address 0x10 (unmapped); the
/// kernel kills it with `SIGSEGV`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const SEGV: &str = env!("HELLOVM_GUEST_SEGV");

/// aarch64 Linux, built on macOS: system calls with odd register values
/// (number -1, huge lengths, addresses at the top of the address space),
/// then prints `survived` and calls `rt_sigreturn` with an unmapped stack
/// (killed with `SIGSEGV`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const ODD_REGS: &str = env!("HELLOVM_GUEST_ODD_REGS");

/// aarch64 Linux, built on macOS: sets `PSTATE.DIT`, makes a system call,
/// and exits with 0 if it is still set (1 if not).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const DIT: &str = env!("HELLOVM_GUEST_DIT");

/// aarch64 Linux, built on macOS: reserves 64 GiB with `PROT_NONE`, uses
/// a few pages in the middle, unmaps it; then maps, touches and unmaps a
/// page at 2000 places a gigabyte apart. Exits with 0, or the number of
/// the step that failed.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const RESERVE: &str = env!("HELLOVM_GUEST_RESERVE");

/// aarch64 Linux, built on macOS: cache maintenance (`ic ivau`, `dc cvau`)
/// over read-only executable pages that were never touched. Exits with 0.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const ICACHE: &str = env!("HELLOVM_GUEST_ICACHE");

/// aarch64 Linux, built on macOS: spins forever, making no system call.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const SPIN: &str = env!("HELLOVM_GUEST_SPIN");
