//! Waiting for "a notification came, a tracee stopped, a timeout passed,
//! or someone woke us".
//!
//! Notifications arrive on listener fds, which `ppoll` waits for. Tracee
//! stops cannot be polled: the host reports them to the tracer process
//! with `SIGCHLD` (and `waitpid`). Wakers are other threads. All three end
//! the event loop's `ppoll` the same way: a **thread-directed `SIGURG`** to
//! the event-loop thread ([`KICK`]).
//!
//! * The event-loop thread keeps `SIGURG` blocked, and unblocks it only
//!   inside the `ppoll` it sleeps in, atomically (`ppoll`'s signal mask). A
//!   kick that comes while the loop is busy stays pending and ends the next
//!   sleep at once, so no wake-up is lost between looking and sleeping. A
//!   `ppoll` that only looks ([`Loop::poll`] with a zero timeout) keeps
//!   `SIGURG` blocked: it must not swallow a kick the sleep after it needs.
//!   `ppoll` is never restarted after a handler, whatever `SA_RESTART` says.
//! * `SIGCHLD` is process-directed: any thread may run its handler. The
//!   handler kicks every registered event-loop thread of the process
//!   ([`Loop`]); a loop that finds nothing for it returns `None`, which the
//!   core treats as "check again".
//! * A [`Waker`] counts its wake-up in its own loop's counter and kicks
//!   that loop's thread; the loop reports a wake-up whenever the count
//!   moved since it last looked, even if the kick came while it was busy.
//!
//! The handlers are installed once per host process with `SA_RESTART` (an
//! interrupted call elsewhere is restarted) and do only async-signal-safe
//! work: atomic loads, `getpid` and `tgkill`.

use std::cell::Cell;
use std::io;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use hellovm_core::platform::Waker;

/// The signal that ends an event loop's `ppoll`. The platform also sends it
/// to app processes to interrupt them (`Platform::interrupt`); those are
/// other processes.
pub const KICK: libc::c_int = libc::SIGURG;

/// The event-loop threads of this process, 0 for a free slot.
const SLOTS: usize = 256;
static LOOPS: [AtomicI32; SLOTS] = [const { AtomicI32::new(0) }; SLOTS];
static INSTALL: Once = Once::new();

thread_local! {
    /// The loops of this thread, and whether `KICK` was blocked before the
    /// first of them blocked it.
    static ON_THREAD: Cell<(usize, bool)> = const { Cell::new((0, false)) };
}

fn pid() -> libc::pid_t {
    // SAFETY: plain syscall; async-signal-safe.
    unsafe { libc::getpid() }
}

fn tid() -> libc::pid_t {
    // SAFETY: plain syscall.
    unsafe { libc::gettid() }
}

fn kick(tid: libc::pid_t) {
    if tid > 0 {
        // SAFETY: plain syscall; a thread of this process.
        unsafe { libc::syscall(libc::SYS_tgkill, pid(), tid, KICK) };
    }
}

extern "C" fn on_sigchld(_sig: libc::c_int) {
    // Keep errno intact for the interrupted code.
    // SAFETY: reading and restoring the calling thread's errno.
    let saved = unsafe { *libc::__errno_location() };
    for slot in &LOOPS {
        kick(slot.load(Ordering::Relaxed));
    }
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = saved };
}

extern "C" fn on_kick(_sig: libc::c_int) {}

/// Installs the handlers (once per process).
pub fn install() -> io::Result<()> {
    let mut result = Ok(());
    INSTALL.call_once(|| {
        for (sig, handler) in [
            (libc::SIGCHLD, on_sigchld as extern "C" fn(libc::c_int)),
            (KICK, on_kick as extern "C" fn(libc::c_int)),
        ] {
            // SAFETY: a zeroed sigaction with a valid handler and flags.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = handler as usize;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(sig, &action, std::ptr::null_mut()) != 0 {
                    result = Err(io::Error::last_os_error());
                    return;
                }
            }
        }
    });
    result
}

/// `KICK` alone, as a signal set.
fn kick_set() -> libc::sigset_t {
    // SAFETY: sigset operations on a local value.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, KICK);
        set
    }
}

/// Blocks `KICK` on the calling thread. Returns the mask to sleep with
/// (the thread's mask with `KICK` unblocked) and whether `KICK` was
/// blocked already.
fn block_kick() -> (libc::sigset_t, bool) {
    let set = kick_set();
    // SAFETY: pthread_sigmask on the calling thread with valid sets;
    // sigset operations on local values.
    unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        let was_blocked = libc::sigismember(&old, KICK) == 1;
        let mut sleep_mask = old;
        libc::sigdelset(&mut sleep_mask, KICK);
        (sleep_mask, was_blocked)
    }
}

#[derive(Debug)]
struct Shared {
    /// The loop's thread, 0 once the loop is gone.
    tid: AtomicI32,
    /// Waker wake-ups so far (wrapping).
    wakes: AtomicU32,
}

/// One event loop: registered for `SIGCHLD` kicks on the thread that made
/// it, which must be the one that waits.
#[derive(Debug)]
pub struct Loop {
    slot: usize,
    /// The thread the loop waits on.
    thread: libc::pid_t,
    shared: Arc<Shared>,
    /// The thread's signal mask with `KICK` unblocked, for sleeping.
    sleep_mask: libc::sigset_t,
}

impl Loop {
    pub fn new() -> io::Result<Loop> {
        install()?;
        let tid = tid();
        let slot = LOOPS
            .iter()
            .position(|slot| {
                slot.compare_exchange(0, tid, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            })
            .ok_or_else(|| io::Error::other("too many seccomp event loops in one process"))?;
        let (sleep_mask, was_blocked) = block_kick();
        ON_THREAD.with(|on| {
            let (count, before) = on.get();
            on.set((count + 1, if count == 0 { was_blocked } else { before }));
        });
        Ok(Loop {
            slot,
            thread: tid,
            shared: Arc::new(Shared {
                tid: AtomicI32::new(tid),
                wakes: AtomicU32::new(0),
            }),
            sleep_mask,
        })
    }

    /// Moves the loop to the calling thread if it is not the one that made
    /// it: in a process forked from the one that made it (a warm clone,
    /// which runs a copy of the template's platform), the thread is a new
    /// one. Wakers handed out before the fork keep working: they share the
    /// loop's counter and now kick this thread.
    pub fn rebind(&mut self) {
        let tid = tid();
        if tid == self.thread {
            return;
        }
        let (sleep_mask, _) = block_kick();
        self.sleep_mask = sleep_mask;
        self.thread = tid;
        LOOPS[self.slot].store(tid, Ordering::SeqCst);
        self.shared.tid.store(tid, Ordering::SeqCst);
    }

    /// The number of waker wake-ups so far (wrapping).
    pub fn wakes(&self) -> u32 {
        self.shared.wakes.load(Ordering::SeqCst)
    }

    /// A waker for this loop.
    pub fn waker(&self) -> Waker {
        let shared = Arc::clone(&self.shared);
        Waker::new(move || {
            // Count first: a loop that wakes up must see the new count.
            shared.wakes.fetch_add(1, Ordering::SeqCst);
            kick(shared.tid.load(Ordering::SeqCst));
        })
    }

    /// Waits until one of `fds` is ready, a kick comes or `timeout` passes.
    /// With a zero timeout it only looks, and leaves a pending kick
    /// pending. Returns the number of ready fds (0 after a kick or the
    /// timeout).
    pub fn poll(&self, fds: &mut [libc::pollfd], timeout: Option<Duration>) -> io::Result<usize> {
        let ts = timeout.map(|t| libc::timespec {
            tv_sec: t.as_secs().min(i64::MAX as u64) as libc::time_t,
            tv_nsec: t.subsec_nanos() as libc::c_long,
        });
        let ts_ptr = ts
            .as_ref()
            .map_or(std::ptr::null(), |t| t as *const libc::timespec);
        let mask = if timeout == Some(Duration::ZERO) {
            std::ptr::null()
        } else {
            &self.sleep_mask as *const libc::sigset_t
        };
        // SAFETY: `fds` is a valid array of pollfds; the timeout and mask
        // pointers are valid or null.
        let n = unsafe { libc::ppoll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ts_ptr, mask) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            return Ok(0);
        }
        Err(err)
    }
}

impl Drop for Loop {
    fn drop(&mut self) {
        LOOPS[self.slot].store(0, Ordering::SeqCst);
        self.shared.tid.store(0, Ordering::SeqCst);
        // The last loop of the thread puts `KICK` back as it found it. (A
        // loop dropped on another thread leaves that thread's mask alone.)
        if tid() != self.thread {
            return;
        }
        ON_THREAD.with(|on| {
            let (count, before) = on.get();
            let count = count.saturating_sub(1);
            on.set((count, before));
            if count == 0 && !before {
                let set = kick_set();
                // SAFETY: pthread_sigmask on the calling thread.
                unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
            }
        });
    }
}
