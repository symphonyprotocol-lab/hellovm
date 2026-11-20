//! Outbound streams on macOS: one I/O thread moves every stream's bytes.
//!
//! On Linux each stream has helper threads of its own (`stream.rs`). The
//! confined kernel process on macOS should not make threads as the guest
//! asks, nor end them (a thread's end can need Mach traps the Seatbelt
//! profile does not allow), so there the I/O runs on one thread made with
//! the endpoint, before the process confines itself: `hellovm-net`. It
//! holds every stream's socket in non-blocking mode and waits in `poll`
//! for the sockets and for a pipe the kernel's thread writes to when a
//! stream has something for it ([`Poller::kick`]). It never blocks on one
//! stream, so a peer that stops reading or never answers holds up no other
//! stream. What it reads and the progress it makes reach the kernel
//! through the stream's [`hellovm_core::platform::Waker`], as on Linux.
//!
//! The streams' state ([`Shared`]) and the kernel's side
//! ([`super::StreamTable`]) are the same as on Linux; this module only
//! replaces the helper threads, and does what they do: the egress flow
//! header and its verdict ([`VERDICT_TIMEOUT`]), half-close after the
//! outbound buffer drains, a graceful close that still delivers queued
//! bytes unless the peer accepts nothing for [`NO_PROGRESS`].
//!
//! The system calls it makes once the process is confined: `socket`
//! (`AF_UNIX`, `SOCK_STREAM`), `fcntl(F_SETFD)`, `fcntl(F_SETFL)`,
//! `connect` (to the egress socket only), `read`, `write`, `shutdown`,
//! `poll` and `close`. See `hellovm-sandbox`'s Seatbelt profile.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hellovm_egress_wire::{Status, REPLY};

use super::{
    helper_guard, Endpoint, HelperGuard, Phase, Shared, CAP, CHUNK, NO_PROGRESS, VERDICT_TIMEOUT,
};

/// A stream for the I/O thread to open.
pub(super) struct Job {
    pub endpoint: Endpoint,
    /// The egress flow header (`None` for the splice test hook).
    pub header: Option<Vec<u8>>,
    pub shared: Arc<Shared>,
}

/// The kernel's thread's side of the I/O thread.
pub(super) struct Poller {
    jobs: Mutex<Vec<Job>>,
    /// The pipe's write end: a byte here wakes the I/O thread.
    wake: OwnedFd,
    /// A byte is in the pipe the I/O thread has not taken yet: kicks
    /// between two of its rounds write one byte, not one each.
    kicked: AtomicBool,
}

impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Poller")
    }
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(last_error())
    } else {
        Ok(ret)
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // F_SETFL with O_NONBLOCK alone: a new socket or pipe has no other
    // status flag to keep. (`std`'s `set_nonblocking` is an `ioctl`,
    // which the Seatbelt profile does not allow.)
    // SAFETY: fcntl on an fd the caller owns, with integer arguments.
    cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) })?;
    Ok(())
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on an fd the caller owns, with integer arguments.
    cvt(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    Ok(())
}

fn read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: reads at most `buf.len()` bytes into `buf`.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(last_error())
    } else {
        Ok(n as usize)
    }
}

fn write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: writes at most `buf.len()` bytes from `buf`. The peer having
    // gone is EPIPE: Rust programs ignore SIGPIPE.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(last_error())
    } else {
        Ok(n as usize)
    }
}

fn shutdown(fd: RawFd, how: libc::c_int) {
    // SAFETY: shutdown on an fd the caller owns.
    unsafe { libc::shutdown(fd, how) };
}

fn would_block(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn refused(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, why)
}

/// A non-blocking Unix stream socket, connecting to `path`. A Unix socket
/// connects at once or fails; `EINPROGRESS` is still taken as "wait until
/// writable", and a failure then shows when the header is written.
fn connect_unix(path: &Path) -> io::Result<OwnedFd> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: zeroed plain-old-data struct.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(refused("the egress socket path does not fit"));
    }
    for (dst, &src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = src as libc::c_char;
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    addr.sun_len = len as u8;
    // SAFETY: plain socket call.
    let fd = cvt(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) })?;
    // SAFETY: the fd was just made and nothing else owns it.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(fd)?;
    set_nonblocking(fd)?;
    // SAFETY: `addr` is a valid sockaddr_un of `len` bytes.
    let ret = unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), len) };
    if ret != 0 {
        let err = last_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(err);
        }
    }
    Ok(sock)
}

/// The connection of a job, or why there is none.
fn dial(endpoint: &Endpoint) -> io::Result<OwnedFd> {
    match endpoint {
        Endpoint::Egress(path) => {
            connect_unix(path).map_err(|_| refused("egress proxy unreachable"))
        }
        // Test hook, never used by a confined process: a blocking
        // connect to a loopback address, which does not wait.
        #[cfg(feature = "insecure-test-hooks")]
        Endpoint::Splice(addr) => {
            let sock = std::net::TcpStream::connect_timeout(addr, super::CONNECT_TIMEOUT)?;
            let _ = sock.set_nodelay(true);
            let fd = OwnedFd::from(sock);
            set_nonblocking(fd.as_raw_fd())?;
            Ok(fd)
        }
    }
}

/// Where a stream is.
enum State {
    /// Sending the flow header, then waiting for the proxy's verdict.
    Verdict {
        header: Vec<u8>,
        sent: usize,
        reply: [u8; REPLY],
        got: usize,
        deadline: Instant,
    },
    Up,
}

/// One stream the I/O thread holds.
struct Entry {
    shared: Arc<Shared>,
    sock: OwnedFd,
    state: State,
    /// Bytes taken from the outbound buffer and not yet written.
    pending: Vec<u8>,
    /// The guest has closed and the peer has taken nothing since.
    idle_since: Option<Instant>,
    /// Nothing more is read (end of file, an error, or the guest closed).
    read_done: bool,
    /// Nothing more is written (half-closed).
    write_done: bool,
    /// Counts it, as a helper thread is counted, for the tests.
    _guard: HelperGuard,
}

/// What the I/O thread does next for an entry.
enum Next {
    Keep,
    /// Drop it: its socket closes.
    Drop,
}

impl Entry {
    fn new(job: Job, sock: OwnedFd) -> Entry {
        let state = match job.header {
            Some(header) => State::Verdict {
                header,
                sent: 0,
                reply: [0; REPLY],
                got: 0,
                deadline: Instant::now() + VERDICT_TIMEOUT,
            },
            None => {
                // No verdict to wait for: connected.
                job.shared
                    .inner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .phase = Phase::Up;
                job.shared.wake();
                State::Up
            }
        };
        Entry {
            shared: job.shared,
            sock,
            state,
            pending: Vec::new(),
            idle_since: None,
            read_done: false,
            write_done: false,
            _guard: helper_guard(),
        }
    }

    fn fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    /// What to wait for in `poll`, and until when at most.
    fn interest(&self) -> (libc::c_short, Option<Instant>) {
        match &self.state {
            State::Verdict {
                header,
                sent,
                deadline,
                ..
            } => {
                let events = if *sent < header.len() {
                    libc::POLLOUT
                } else {
                    libc::POLLIN
                };
                (events, Some(*deadline))
            }
            State::Up => {
                let inner = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                let mut events = 0;
                if !self.read_done && !inner.closing && inner.inbound.len() < CAP {
                    events |= libc::POLLIN;
                }
                if !self.write_done && (!self.pending.is_empty() || !inner.outbound.is_empty()) {
                    events |= libc::POLLOUT;
                }
                (events, self.idle_since.map(|since| since + NO_PROGRESS))
            }
        }
    }

    /// Does what can be done now without blocking. `readable`: `poll`
    /// said the socket has something to read (or an error or hang-up).
    fn step(&mut self, readable: bool, buf: &mut [u8]) -> Next {
        match self.state {
            State::Verdict { .. } => self.verdict(),
            State::Up => self.move_bytes(readable, buf),
        }
    }

    fn fail(&self, kind: io::ErrorKind) -> Next {
        {
            let mut inner = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.phase = Phase::Failed;
            inner.connect_error = Some(kind);
        }
        self.shared.wake();
        Next::Drop
    }

    fn verdict(&mut self) -> Next {
        {
            let inner = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            // Closed before it connected: nobody waits for the verdict.
            if inner.abort || inner.closing {
                return Next::Drop;
            }
        }
        let fd = self.fd();
        let State::Verdict {
            header,
            sent,
            reply,
            got,
            deadline,
        } = &mut self.state
        else {
            return Next::Keep;
        };
        while *sent < header.len() {
            match write(fd, &header[*sent..]) {
                Ok(0) => return self.fail(io::ErrorKind::ConnectionRefused),
                Ok(n) => *sent += n,
                Err(err) if would_block(&err) => break,
                Err(_) => return self.fail(io::ErrorKind::ConnectionRefused),
            }
        }
        while *sent == header.len() && *got < REPLY {
            match read(fd, &mut reply[*got..]) {
                Ok(0) => return self.fail(io::ErrorKind::ConnectionRefused),
                Ok(n) => *got += n,
                Err(err) if would_block(&err) => break,
                Err(_) => return self.fail(io::ErrorKind::ConnectionRefused),
            }
        }
        if *got < REPLY {
            if Instant::now() >= *deadline {
                return self.fail(io::ErrorKind::TimedOut);
            }
            return Next::Keep;
        }
        match Status::parse_reply(reply) {
            Some(Status::Ok) => {}
            Some(Status::UpstreamTimeout) => return self.fail(io::ErrorKind::TimedOut),
            Some(_) | None => return self.fail(io::ErrorKind::ConnectionRefused),
        }
        self.state = State::Up;
        {
            let mut inner = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.abort || inner.closing {
                return Next::Drop;
            }
            inner.phase = Phase::Up;
        }
        self.shared.wake();
        Next::Keep
    }

    /// Both ways: closes with the guest's close once queued bytes are out.
    fn finish(&self) -> Next {
        shutdown(self.fd(), libc::SHUT_RDWR);
        Next::Drop
    }

    fn broken(&self) -> Next {
        {
            let mut inner = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.broken = true;
            inner.read_eof = true;
        }
        self.shared.wake();
        self.finish()
    }

    fn move_bytes(&mut self, readable: bool, buf: &mut [u8]) -> Next {
        let fd = self.fd();
        let mut inner = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.abort {
            return Next::Drop;
        }
        let mut wake = false;
        if !self.read_done && inner.closing {
            // The guest will not read again.
            self.read_done = true;
        }
        if !self.read_done && readable && inner.inbound.len() < CAP {
            let room = (CAP - inner.inbound.len()).min(buf.len());
            match read(fd, &mut buf[..room]) {
                Ok(0) => {
                    inner.read_eof = true;
                    self.read_done = true;
                    wake = true;
                }
                Ok(n) => {
                    inner.inbound.extend(&buf[..n]);
                    wake = true;
                }
                Err(err) if would_block(&err) => {}
                Err(_) => {
                    inner.read_eof = true;
                    inner.broken = true;
                    self.read_done = true;
                    wake = true;
                }
            }
        }
        let mut next = Next::Keep;
        // At most a buffer's worth per step, so that one busy stream does
        // not keep the thread from the others.
        let mut budget = CAP;
        while !self.write_done && matches!(next, Next::Keep) {
            if self.pending.is_empty() {
                if !inner.outbound.is_empty() {
                    let n = inner.outbound.len().min(CHUNK);
                    self.pending.extend(inner.outbound.drain(..n));
                    // Room in the outbound buffer: the guest may write.
                    wake = true;
                } else if inner.closing {
                    next = self.finish();
                    break;
                } else if inner.shut_wr {
                    // Half-close: reading goes on for the reply.
                    shutdown(fd, libc::SHUT_WR);
                    self.write_done = true;
                    break;
                } else {
                    break;
                }
            }
            if budget == 0 {
                break;
            }
            let before = self.pending.len();
            let closing = inner.closing;
            drop(inner);
            next = self.write_pending(closing);
            inner = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            let written = before - self.pending.len();
            if written == 0 {
                break;
            }
            budget = budget.saturating_sub(written);
        }
        if self.write_done && matches!(next, Next::Keep) && inner.closing {
            next = self.finish();
        }
        drop(inner);
        if wake {
            self.shared.wake();
        }
        if matches!(next, Next::Keep) && self.read_done && self.write_done {
            return Next::Drop;
        }
        next
    }

    fn write_pending(&mut self, closing: bool) -> Next {
        match write(self.fd(), &self.pending) {
            Ok(0) => self.broken(),
            Ok(n) => {
                self.pending.drain(..n);
                // The peer took bytes: a slow reader does not run out of time.
                self.idle_since = None;
                self.shared.wake();
                Next::Keep
            }
            Err(err) if would_block(&err) => {
                if closing {
                    let since = *self.idle_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= NO_PROGRESS {
                        return self.finish();
                    }
                }
                Next::Keep
            }
            // EPIPE or a reset: the peer is gone.
            Err(_) => self.broken(),
        }
    }
}

impl Poller {
    /// Makes the pipe and starts the I/O thread. Call it before the
    /// process confines itself.
    pub fn start() -> io::Result<Arc<Poller>> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe writes two fds into the array.
        cvt(unsafe { libc::pipe(fds.as_mut_ptr()) })?;
        // SAFETY: both fds were just made and nothing else owns them.
        let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        for fd in [&rd, &wr] {
            set_cloexec(fd.as_raw_fd())?;
            set_nonblocking(fd.as_raw_fd())?;
        }
        let poller = Arc::new(Poller {
            jobs: Mutex::new(Vec::new()),
            wake: wr,
            kicked: AtomicBool::new(false),
        });
        let thread_poller = Arc::clone(&poller);
        // Detached, and it never returns: it ends with the process.
        thread::Builder::new()
            .name("hellovm-net".into())
            .spawn(move || thread_poller.run(rd))?;
        Ok(poller)
    }

    /// Hands a new stream to the I/O thread.
    pub fn add(&self, job: Job) {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(job);
        self.kick();
    }

    /// Something changed for a stream: the I/O thread looks at every
    /// stream again.
    pub fn kick(&self) {
        if !self.kicked.swap(true, Ordering::AcqRel) {
            // A full pipe already holds a byte the thread will see.
            let _ = write(self.wake.as_raw_fd(), &[1]);
        }
    }

    fn run(&self, wake: OwnedFd) -> ! {
        let mut entries: VecDeque<Entry> = VecDeque::new();
        let mut buf = vec![0u8; CHUNK];
        let mut pollfds: Vec<libc::pollfd> = Vec::new();
        let mut kicked = true;
        loop {
            if kicked {
                self.kicked.store(false, Ordering::Release);
                let mut sink = [0u8; 64];
                while matches!(read(wake.as_raw_fd(), &mut sink), Ok(n) if n > 0) {}
                let jobs =
                    std::mem::take(&mut *self.jobs.lock().unwrap_or_else(|e| e.into_inner()));
                for job in jobs {
                    match dial(&job.endpoint) {
                        Ok(sock) => entries.push_back(Entry::new(job, sock)),
                        Err(err) => {
                            {
                                let mut inner =
                                    job.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                                inner.phase = Phase::Failed;
                                inner.connect_error = Some(err.kind());
                            }
                            job.shared.wake();
                        }
                    }
                }
            }
            // Every stream is looked at after a kick (the kernel's side
            // changed something, which `poll` cannot see), only those
            // `poll` named otherwise.
            let mut i = 0;
            entries.retain_mut(|entry| {
                let revents = pollfds.get(i + 1).map_or(0, |p| p.revents);
                i += 1;
                if !kicked && revents == 0 && !entry.due() {
                    return true;
                }
                let readable = revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
                matches!(entry.step(readable, &mut buf), Next::Keep)
            });
            pollfds.clear();
            pollfds.push(libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            let mut deadline: Option<Instant> = None;
            for entry in &entries {
                let (events, until) = entry.interest();
                pollfds.push(libc::pollfd {
                    // Nothing to wait for: left out (a negative fd), or a
                    // peer that hung up would wake `poll` again and again
                    // until the guest closes.
                    fd: if events == 0 { -1 } else { entry.fd() },
                    events,
                    revents: 0,
                });
                if let Some(until) = until {
                    deadline = Some(deadline.map_or(until, |d| d.min(until)));
                }
            }
            let timeout = match deadline {
                None => -1,
                Some(at) => {
                    // Rounded up, so a deadline is not woken for early.
                    let left = at.saturating_duration_since(Instant::now());
                    let ms = left.as_micros().div_ceil(1000);
                    ms.min(i32::MAX as u128) as libc::c_int
                }
            };
            // SAFETY: `pollfds` holds `len` valid pollfd structs.
            let ret =
                unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout) };
            if ret < 0 {
                // EINTR, or EAGAIN for a moment of no kernel memory: look
                // at everything again, a little later for the latter.
                if !would_block(&last_error()) {
                    pause(Duration::from_millis(10));
                }
                for p in &mut pollfds {
                    p.revents = 0;
                }
                kicked = true;
                continue;
            }
            kicked = pollfds[0].revents != 0;
        }
    }
}

impl Entry {
    /// A deadline of this entry has passed.
    fn due(&self) -> bool {
        let now = Instant::now();
        match &self.state {
            State::Verdict { deadline, .. } => now >= *deadline,
            State::Up => self
                .idle_since
                .is_some_and(|since| now >= since + NO_PROGRESS),
        }
    }
}

/// Sleeps for `duration` without `nanosleep`, which on macOS asks the
/// clock service through Mach IPC that the confined process may not use
/// (see `hellovm-sandbox`): a timed condition variable wait needs only
/// `psynch_cvwait`.
pub fn pause(duration: Duration) {
    let deadline = Instant::now() + duration;
    let lock = Mutex::new(());
    let never = std::sync::Condvar::new();
    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        guard = match never.wait_timeout(guard, deadline - now) {
            Ok((guard, _)) => guard,
            Err(err) => err.into_inner().0,
        };
    }
}
