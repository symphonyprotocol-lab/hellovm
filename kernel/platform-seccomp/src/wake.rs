//! Waiting for "a tracee stopped, a timeout passed, or someone woke us".
//!
//! `waitpid` can wait for tracee stops but has no timeout and cannot be
//! woken by another thread. So the event loop waits on a futex instead: a
//! process-wide generation counter that is bumped, and its waiters woken,
//! by
//!
//! * a `SIGCHLD` handler: the host kernel sends `SIGCHLD` to the tracer
//!   for every ptrace stop and every exit of a tracee or child;
//! * [`Waker`]s handed out to other threads (console input).
//!
//! The loop reads the counter, drains `waitpid(WNOHANG)`, and only then
//! sleeps in `FUTEX_WAIT` on the value it read, so a stop that happens in
//! between changes the counter and the sleep returns at once: no wake-up is
//! lost. Wake-ups meant for another sandbox in the same host process (the
//! counter is shared) are harmless: that loop finds nothing and returns
//! `None`, which the core treats as "check again".
//!
//! The handler is installed once per host process with `SA_RESTART` and
//! without `SA_NOCLDSTOP`; it only does an atomic add and a `FUTEX_WAKE`,
//! both async-signal-safe.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Once;
use std::time::Duration;

use hellovm_core::platform::Waker;

static GENERATION: AtomicU32 = AtomicU32::new(0);
static INSTALL: Once = Once::new();

fn bump() {
    GENERATION.fetch_add(1, Ordering::SeqCst);
    // SAFETY: FUTEX_WAKE on a static atomic; async-signal-safe.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            GENERATION.as_ptr(),
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            i32::MAX,
        );
    }
}

extern "C" fn on_sigchld(_sig: libc::c_int) {
    // Keep errno intact for the interrupted code.
    // SAFETY: reading and restoring the calling thread's errno.
    let saved = unsafe { *libc::__errno_location() };
    bump();
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = saved };
}

/// Installs the `SIGCHLD` handler (once per process).
pub fn install() -> std::io::Result<()> {
    let mut result = Ok(());
    INSTALL.call_once(|| {
        // SAFETY: a zeroed sigaction with a valid handler and flags.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_sigchld as extern "C" fn(libc::c_int) as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) != 0 {
                result = Err(std::io::Error::last_os_error());
            }
        }
    });
    result
}

/// The current generation; pass it to [`sleep`].
pub fn generation() -> u32 {
    GENERATION.load(Ordering::SeqCst)
}

/// Sleeps until the generation differs from `seen` or `timeout` passes.
pub fn sleep(seen: u32, timeout: Option<Duration>) {
    let ts = timeout.map(|t| libc::timespec {
        tv_sec: t.as_secs().min(i64::MAX as u64) as libc::time_t,
        tv_nsec: t.subsec_nanos() as libc::c_long,
    });
    let ts_ptr = ts
        .as_ref()
        .map_or(std::ptr::null(), |t| t as *const libc::timespec);
    // SAFETY: FUTEX_WAIT on a static atomic with a valid (or null)
    // relative timeout. EINTR, EAGAIN and ETIMEDOUT all mean "look again".
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            GENERATION.as_ptr(),
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            seen,
            ts_ptr,
        );
    }
}

/// A waker for the event loop.
pub fn waker() -> Waker {
    Waker::new(bump)
}
