//! Host byte streams for guest TCP flows that leave the sandbox.
//!
//! The kernel thread never blocks on the network. Each stream has a reader
//! thread and a writer thread (the same shape as the stdin helper). The
//! guest destination IP is recorded on [`OutboundFlow`] and is never
//! dialed. Every stream goes to the one configured [`Endpoint`]:
//!
//! * [`Endpoint::Egress`]: the egress proxy's Unix socket. The helper sends
//!   the flow header ([`hellovm_egress::wire`]: sandbox id, the hostname
//!   the kernel bound, the port) and waits for the proxy's verdict, so the
//!   guest's `connect` completes only once the proxy has connected
//!   upstream. A refusal is a connect error of kind `ConnectionRefused`
//!   (the guest sees `ECONNREFUSED`), an upstream connect timeout or no
//!   verdict within [`VERDICT_TIMEOUT`] is `TimedOut` (`ETIMEDOUT`), and an
//!   unreachable proxy is `ConnectionRefused` too. A flow without a
//!   hostname is refused before anything is dialed.
//! * `Endpoint::Splice` (feature `insecure-test-hooks` only): a loopback
//!   TCP address every flow is spliced to, with no header and no policy.
//!
//! Half-close is `shutdown(Shutdown::Write)` after the outbound buffer
//! drains, so the peer reads EOF while the guest can still receive.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hellovm_egress::wire::{Request, Status, REPLY};

/// How long the helper waits for the egress proxy's verdict. The proxy
/// bounds its own work (header 5 s, resolution 5 s, upstream connect 10 s),
/// so this only fires when the proxy is wedged. Reported as `TimedOut`.
pub const VERDICT_TIMEOUT: Duration = Duration::from_secs(30);

/// A splice connect that the guest abandons must not block its helper
/// thread forever. Reported as `TimedOut` (`ETIMEDOUT` for a blocking
/// guest connect).
#[cfg(feature = "insecure-test-hooks")]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds one `write` so the loop can notice close, progress, and errors.
/// It is not a deadline for the drain.
const WRITE_POLL: Duration = Duration::from_millis(250);

/// After close, give up only when the peer accepts nothing for this long.
/// A slow reader that keeps taking bytes resets the timer.
const NO_PROGRESS: Duration = Duration::from_secs(45);

/// Where outbound streams go.
#[derive(Clone, Debug)]
pub enum Endpoint {
    /// The egress proxy's Unix socket.
    Egress(PathBuf),
    /// Test hook: splice every flow to this loopback TCP address.
    #[cfg(feature = "insecure-test-hooks")]
    Splice(std::net::SocketAddr),
}

/// The connection a stream runs on.
enum Conn {
    Unix(UnixStream),
    #[cfg_attr(not(feature = "insecure-test-hooks"), allow(dead_code))]
    Tcp(TcpStream),
}

impl Conn {
    fn try_clone(&self) -> io::Result<Conn> {
        Ok(match self {
            Conn::Unix(s) => Conn::Unix(s.try_clone()?),
            Conn::Tcp(s) => Conn::Tcp(s.try_clone()?),
        })
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Conn::Unix(s) => s.shutdown(how),
            Conn::Tcp(s) => s.shutdown(how),
        }
    }

    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        match self {
            Conn::Unix(s) => s.set_write_timeout(d),
            Conn::Tcp(s) => s.set_write_timeout(d),
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Unix(s) => s.read(buf),
            Conn::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Unix(s) => s.write(buf),
            Conn::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn refused(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, why)
}

/// Opens a flow at the egress proxy and waits for its verdict.
fn egress_connect(path: &PathBuf, req: &[u8]) -> io::Result<Conn> {
    let sock = UnixStream::connect(path).map_err(|_| refused("egress proxy unreachable"))?;
    sock.set_write_timeout(Some(VERDICT_TIMEOUT))?;
    sock.set_read_timeout(Some(VERDICT_TIMEOUT))?;
    (&sock)
        .write_all(req)
        .map_err(|_| refused("egress proxy closed the flow"))?;
    let mut reply = [0u8; REPLY];
    match (&sock).read_exact(&mut reply) {
        Ok(()) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no verdict from the egress proxy",
            ))
        }
        Err(_) => return Err(refused("egress proxy closed the flow")),
    }
    match Status::parse_reply(&reply) {
        Some(Status::Ok) => {
            sock.set_write_timeout(None)?;
            sock.set_read_timeout(None)?;
            Ok(Conn::Unix(sock))
        }
        Some(Status::UpstreamTimeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "egress upstream connect timed out",
        )),
        Some(_) => Err(refused("egress proxy refused the flow")),
        None => Err(refused("egress proxy sent a bad verdict")),
    }
}

use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
static LIVE_HELPERS: AtomicUsize = AtomicUsize::new(0);

struct HelperGuard;

impl Drop for HelperGuard {
    fn drop(&mut self) {
        #[cfg(test)]
        LIVE_HELPERS.fetch_sub(1, Ordering::Relaxed);
    }
}

fn helper_guard() -> HelperGuard {
    #[cfg(test)]
    LIVE_HELPERS.fetch_add(1, Ordering::Relaxed);
    HelperGuard
}

use hellovm_core::host::{HostStreamId, OutboundFlow, StreamStatus};
use hellovm_core::platform::Waker;

const CAP: usize = 64 * 1024;
const CHUNK: usize = 8 * 1024;

#[derive(Debug)]
enum Phase {
    Connecting,
    Up,
    Failed,
}

struct Inner {
    phase: Phase,
    inbound: VecDeque<u8>,
    outbound: VecDeque<u8>,
    shut_wr: bool,
    /// Guest closed the socket. The writer drains `outbound`, then half-closes.
    closing: bool,
    /// Give up without delivering queued bytes (connect abandoned before it
    /// finished, or an explicit abort).
    abort: bool,
    read_eof: bool,
    broken: bool,
    connect_error: Option<io::ErrorKind>,
    /// A clone used to unblock the reader and writer on close. `shutdown`
    /// returns immediately; it does not read or write payload.
    control: Option<Conn>,
}

struct Shared {
    inner: Mutex<Inner>,
    cv: Condvar,
    waker: Mutex<Waker>,
    /// The table's count of streams whose helpers are still alive, including
    /// ones the guest closed that are still draining.
    live: Arc<AtomicUsize>,
}

impl Drop for Shared {
    /// The last of the table entry, the reader and the writer has let go.
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Shared {
    fn wake(self: &Arc<Self>) {
        self.waker.lock().unwrap_or_else(|e| e.into_inner()).wake();
    }
}

/// Streams whose helper threads may be alive at once (two threads each),
/// counting closed streams that are still draining. Past this, a guest
/// `connect` fails with `EAGAIN` instead of exhausting host threads.
const MAX_LIVE_STREAMS: usize = 512;

/// Most recent flows kept for [`StreamTable::flows`].
const FLOW_LOG: usize = 1024;

/// The configured endpoint and the streams currently open to it.
#[derive(Default)]
pub struct StreamTable {
    endpoint: Option<Endpoint>,
    streams: HashMap<u64, Arc<Shared>>,
    next: u64,
    /// The last [`FLOW_LOG`] flows, oldest first.
    flows: Vec<OutboundFlow>,
    live: Arc<AtomicUsize>,
}

impl StreamTable {
    pub fn set_endpoint(&mut self, endpoint: Endpoint) {
        self.endpoint = Some(endpoint);
    }

    pub fn configured(&self) -> bool {
        self.endpoint.is_some()
    }

    pub fn flows(&self) -> &[OutboundFlow] {
        &self.flows
    }

    pub fn open(&mut self, flow: OutboundFlow, waker: Waker) -> io::Result<HostStreamId> {
        let Some(endpoint) = self.endpoint.clone() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no outbound endpoint configured",
            ));
        };
        if self.live.load(Ordering::Relaxed) >= MAX_LIVE_STREAMS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many outbound streams are open or draining",
            ));
        }
        // The flow header is built from what the kernel derived. A fake IP
        // with no name bound cannot be named to the proxy: refuse it here.
        let header = match &endpoint {
            Endpoint::Egress(_) => {
                let host = flow.host.clone().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "flow names no host")
                })?;
                let req = Request {
                    sandbox_id: flow.sandbox_id,
                    port: flow.dest_port,
                    host,
                };
                Some(req.encode().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "flow names no valid host")
                })?)
            }
            #[cfg(feature = "insecure-test-hooks")]
            Endpoint::Splice(_) => None,
        };
        // `flow.dest_ip` is kept for tests and audit. The dial below uses the
        // endpoint only.
        if self.flows.len() >= FLOW_LOG {
            self.flows.remove(0);
        }
        self.flows.push(flow);
        self.live.fetch_add(1, Ordering::Relaxed);
        let id = self.next;
        self.next += 1;
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                phase: Phase::Connecting,
                inbound: VecDeque::new(),
                outbound: VecDeque::new(),
                shut_wr: false,
                closing: false,
                abort: false,
                read_eof: false,
                broken: false,
                connect_error: None,
                control: None,
            }),
            cv: Condvar::new(),
            waker: Mutex::new(waker),
            live: Arc::clone(&self.live),
        });
        let helper = Arc::clone(&shared);
        // Register only once the helper runs: a failed spawn must not leave
        // an entry the kernel will never close.
        thread::Builder::new()
            .name(format!("hellovm-stream-{id}"))
            .spawn(move || drive(endpoint, header, helper))
            .map_err(io::Error::other)?;
        self.streams.insert(id, shared);
        Ok(HostStreamId(id))
    }

    pub fn connect_result(&mut self, id: HostStreamId) -> io::Result<()> {
        let shared = self.shared(id)?;
        let inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.phase {
            Phase::Connecting => Err(io::ErrorKind::WouldBlock.into()),
            Phase::Up => Ok(()),
            Phase::Failed => Err(io::Error::new(
                inner
                    .connect_error
                    .unwrap_or(io::ErrorKind::ConnectionRefused),
                "outbound connect failed",
            )),
        }
    }

    pub fn status(&mut self, id: HostStreamId) -> io::Result<StreamStatus> {
        let shared = self.shared(id)?;
        let inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        Ok(StreamStatus {
            established: !matches!(inner.phase, Phase::Connecting),
            failed: matches!(inner.phase, Phase::Failed),
            readable: !inner.inbound.is_empty() || inner.read_eof,
            writable: matches!(inner.phase, Phase::Up)
                && !inner.shut_wr
                && !inner.broken
                && inner.outbound.len() < CAP,
            broken: inner.broken,
            shut_write: inner.shut_wr,
        })
    }

    pub fn read(&mut self, id: HostStreamId, buf: &mut [u8]) -> io::Result<usize> {
        let shared = self.shared(id)?;
        let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.inbound.is_empty() {
            // A reset is `ECONNRESET`. A bare FIN is EOF.
            return if inner.broken {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "outbound peer reset",
                ))
            } else if inner.read_eof {
                Ok(0)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            };
        }
        let n = buf.len().min(inner.inbound.len());
        for (dst, src) in buf.iter_mut().zip(inner.inbound.drain(..n)) {
            *dst = src;
        }
        drop(inner);
        shared.cv.notify_all();
        Ok(n)
    }

    pub fn write(&mut self, id: HostStreamId, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let shared = self.shared(id)?;
        let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.broken || inner.shut_wr {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "outbound peer is gone",
            ));
        }
        if !matches!(inner.phase, Phase::Up) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let room = CAP.saturating_sub(inner.outbound.len());
        if room == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = data.len().min(room);
        inner.outbound.extend(&data[..n]);
        drop(inner);
        shared.cv.notify_all();
        Ok(n)
    }

    pub fn shutdown_write(&mut self, id: HostStreamId) -> io::Result<()> {
        let shared = self.shared(id)?;
        let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.shut_wr = true;
        drop(inner);
        shared.cv.notify_all();
        Ok(())
    }

    pub fn close(&mut self, id: HostStreamId) {
        let Some(shared) = self.streams.remove(&id.0) else {
            return;
        };
        {
            let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            // Graceful: the writer flushes bytes the guest already queued,
            // then half-closes. Do not discard the queue or `shutdown(Both)`.
            inner.closing = true;
            inner.shut_wr = true;
            if !matches!(inner.phase, Phase::Up) {
                // Still connecting. The helper must not block past the timeout.
                inner.abort = true;
            }
            // The guest will not read again, so the reader can stop now. It
            // may be blocked in `read` on a peer that never sends or closes;
            // when the guest had half-closed earlier, the writer has already
            // exited and nothing else would wake it. Shutting the read side
            // sends nothing to the peer and does not affect the write drain.
            if let Some(control) = &inner.control {
                let _ = control.shutdown(Shutdown::Read);
            }
        }
        shared.cv.notify_all();
    }
}

impl std::fmt::Debug for StreamTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamTable")
            .field("endpoint", &self.endpoint)
            .field("streams", &self.streams.len())
            .field("flows", &self.flows.len())
            .finish()
    }
}

impl StreamTable {
    /// Closes every stream still open (gracefully: queued bytes are still
    /// flushed), then waits until every helper has finished or `limit` has
    /// passed. Returns whether all finished. hellovm calls this before it
    /// exits, so bytes a guest wrote just before the sandbox ended are not
    /// cut off by process exit, without waiting forever on a peer that
    /// never reads.
    pub fn drain(&mut self, limit: Duration) -> bool {
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        for id in ids {
            self.close(HostStreamId(id));
        }
        let start = Instant::now();
        while self.live.load(Ordering::Relaxed) > 0 {
            if start.elapsed() >= limit {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
        true
    }

    fn shared(&self, id: HostStreamId) -> io::Result<Arc<Shared>> {
        self.streams
            .get(&id.0)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "outbound stream is closed"))
    }
}

fn drive(endpoint: Endpoint, header: Option<Vec<u8>>, shared: Arc<Shared>) {
    let connected = match &endpoint {
        Endpoint::Egress(path) => egress_connect(path, header.as_deref().unwrap_or_default()),
        #[cfg(feature = "insecure-test-hooks")]
        Endpoint::Splice(addr) => TcpStream::connect_timeout(addr, CONNECT_TIMEOUT).map(|s| {
            let _ = s.set_nodelay(true);
            Conn::Tcp(s)
        }),
    };
    let stream = match connected {
        Ok(stream) => stream,
        Err(err) => {
            {
                let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.phase = Phase::Failed;
                inner.connect_error = Some(err.kind());
            }
            shared.wake();
            return;
        }
    };
    let reader = match stream.try_clone() {
        Ok(reader) => reader,
        Err(err) => {
            fail(&shared, err.kind());
            return;
        }
    };
    let writer = match stream.try_clone() {
        Ok(writer) => writer,
        Err(err) => {
            fail(&shared, err.kind());
            return;
        }
    };
    {
        let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.abort || inner.closing {
            drop(inner);
            drop(stream);
            return;
        }
        inner.control = Some(stream);
        inner.phase = Phase::Up;
    }
    shared.wake();
    let reader_shared = Arc::clone(&shared);
    let _ = thread::Builder::new()
        .name("hellovm-stream-read".into())
        .spawn(move || read_loop(reader, reader_shared));
    write_loop(writer, shared);
}

fn fail(shared: &Shared, kind: io::ErrorKind) {
    {
        let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.phase = Phase::Failed;
        inner.connect_error = Some(kind);
    }
    shared
        .waker
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .wake();
}

fn finish_stream(sock: &Conn) {
    // `Read` unblocks the reader even when the remote never closes.
    let _ = sock.shutdown(Shutdown::Write);
    let _ = sock.shutdown(Shutdown::Read);
}

fn read_loop(mut sock: Conn, shared: Arc<Shared>) {
    let _guard = helper_guard();
    let mut buf = [0u8; CHUNK];
    loop {
        {
            let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            while inner.inbound.len() >= CAP && !inner.closing && !inner.abort {
                inner = shared.cv.wait(inner).unwrap_or_else(|e| e.into_inner());
            }
            if inner.abort || inner.closing {
                return;
            }
        }
        match sock.read(&mut buf) {
            Ok(0) => {
                let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.read_eof = true;
                drop(inner);
                shared.wake();
                return;
            }
            Ok(n) => {
                let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.inbound.extend(&buf[..n]);
                drop(inner);
                shared.wake();
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.read_eof = true;
                inner.broken = true;
                drop(inner);
                shared.wake();
                return;
            }
        }
    }
}

fn write_loop(mut sock: Conn, shared: Arc<Shared>) {
    let _guard = helper_guard();
    // Set on this fd. A timeout applied to the control dup does not
    // interrupt a write that is already blocked here. The timeout only
    // returns control to this loop; it does not abandon queued bytes.
    let _ = sock.set_write_timeout(Some(WRITE_POLL));
    let mut pending: Vec<u8> = Vec::new();
    let mut idle_since: Option<Instant> = None;
    loop {
        let closing = {
            let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.abort {
                return;
            }
            if pending.is_empty() {
                while inner.outbound.is_empty() && !inner.shut_wr && !inner.closing && !inner.abort
                {
                    inner = shared.cv.wait(inner).unwrap_or_else(|e| e.into_inner());
                }
                if inner.abort {
                    return;
                }
                if inner.outbound.is_empty() && inner.closing {
                    drop(inner);
                    // Full close: also drop the read side so the reader
                    // thread exits when the remote never does.
                    finish_stream(&sock);
                    return;
                }
                if inner.outbound.is_empty() && inner.shut_wr {
                    drop(inner);
                    // Half-close. The reader stays up for the reply.
                    let _ = sock.shutdown(Shutdown::Write);
                    return;
                }
                let n = inner.outbound.len().min(CHUNK);
                pending = inner.outbound.drain(..n).collect();
            }
            inner.closing
        };
        match sock.write(&pending) {
            Ok(0) => {
                mark_broken(&shared);
                finish_stream(&sock);
                return;
            }
            Ok(n) => {
                pending.drain(..n);
                // The peer took bytes. A slow reader does not hit the cap.
                idle_since = None;
                shared.wake();
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                if closing {
                    let start = *idle_since.get_or_insert_with(Instant::now);
                    if start.elapsed() >= NO_PROGRESS {
                        finish_stream(&sock);
                        return;
                    }
                }
            }
            // EPIPE or reset: the reader is gone.
            Err(_) => {
                mark_broken(&shared);
                finish_stream(&sock);
                return;
            }
        }
    }
}

fn mark_broken(shared: &Shared) {
    {
        let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.broken = true;
        inner.read_eof = true;
    }
    shared
        .waker
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .wake();
}

/// The helper lifecycle, against a plain TCP peer through the test splice
/// endpoint. The egress handshake is covered by `egress_tests`.
#[cfg(all(test, feature = "insecure-test-hooks"))]
mod tests {
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use hellovm_core::host::OutboundFlow;
    use hellovm_core::platform::Waker;

    use super::{Endpoint, StreamTable, LIVE_HELPERS};

    /// Peer reset, not a peer that stays open without reading. The 45s
    /// no-progress bound for that case is not exercised here.
    #[test]
    fn close_ends_helpers_when_the_peer_resets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (release, wait) = mpsc::channel();
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let _ = wait.recv_timeout(Duration::from_secs(5));
            drop(sock);
        });
        let baseline = LIVE_HELPERS.load(std::sync::atomic::Ordering::Relaxed);
        let mut table = StreamTable::default();
        table.set_endpoint(Endpoint::Splice(addr));
        let id = table
            .open(
                OutboundFlow {
                    sandbox_id: 0,
                    guest_pid: 1,
                    dest_ip: [198, 51, 100, 1],
                    dest_port: 9,
                    host: None,
                },
                Waker::new(|| {}),
            )
            .unwrap();
        let start = Instant::now();
        loop {
            match table.connect_result(id) {
                Ok(()) => break,
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    assert!(start.elapsed() < Duration::from_secs(2), "connect");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("connect: {err}"),
            }
        }
        let block = vec![0u8; 64 * 1024];
        let mut saw_block = false;
        for _ in 0..64 {
            match table.write(id, &block) {
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    saw_block = true;
                    break;
                }
                Err(err) => panic!("write: {err}"),
            }
        }
        assert!(saw_block, "the splice buffer should fill");
        let started = Instant::now();
        table.close(id);
        // Dropping the accepted socket without reading is a reset. The
        // helper must stop on that error. A peer that never reads and never
        // closes is bounded by `NO_PROGRESS` (45s); this test does not cover it.
        let _ = release.send(());
        while LIVE_HELPERS.load(std::sync::atomic::Ordering::Relaxed) > baseline {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "helpers still live after close"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let _ = release.send(());
        server.join().unwrap();
    }

    /// The guest half-closes, then closes, while the peer neither sends nor
    /// closes. The writer exited at the half-close; the reader must not be
    /// left blocked in `read` holding the connection.
    #[test]
    fn close_after_half_close_ends_the_reader_when_the_peer_is_silent() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (release, wait) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            // Hold the connection open, silently, until the test ends.
            let _ = wait.recv_timeout(Duration::from_secs(10));
            drop(sock);
        });
        let mut table = StreamTable::default();
        table.set_endpoint(Endpoint::Splice(addr));
        let id = table
            .open(
                OutboundFlow {
                    sandbox_id: 0,
                    guest_pid: 1,
                    dest_ip: [198, 51, 100, 1],
                    dest_port: 9,
                    host: None,
                },
                Waker::new(|| {}),
            )
            .unwrap();
        let start = Instant::now();
        while table.connect_result(id).is_err() {
            assert!(start.elapsed() < Duration::from_secs(2), "connect");
            thread::sleep(Duration::from_millis(5));
        }
        table.shutdown_write(id).unwrap();
        thread::sleep(Duration::from_millis(50));
        table.close(id);
        let closed = Instant::now();
        while table.live.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            assert!(
                closed.elapsed() < Duration::from_secs(2),
                "the reader is still blocked after close"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let _ = release.send(());
        server.join().unwrap();
    }
}

/// The egress handshake against an in-process proxy.
#[cfg(test)]
mod egress_tests {
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant};

    use hellovm_core::host::{HostStreamId, OutboundFlow};
    use hellovm_core::platform::Waker;
    use hellovm_egress::audit::{AuditSink, MemorySink};
    use hellovm_egress::policy::Policy;
    use hellovm_egress::resolve::Resolver;
    use hellovm_egress::sniff::client_hello_for_test;
    use hellovm_egress::{Config, Limits, Proxy, ProxyHandle};

    use super::{Endpoint, StreamTable};

    fn sock(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hvhost-{tag}-{}.sock", std::process::id()))
    }

    fn proxy(tag: &str, policy: &str, table: &str) -> (ProxyHandle, MemorySink) {
        let mut p = Policy::new();
        p.add_file(policy).unwrap();
        let audit = MemorySink::default();
        let config = Config {
            policy: p,
            limits: Limits::default(),
            audit: AuditSink::new(Box::new(audit.clone())),
            resolver: Resolver::parse_test_table(table).unwrap(),
        };
        (Proxy::bind(sock(tag), config).unwrap().spawn(), audit)
    }

    fn flow(host: Option<&str>, port: u16) -> OutboundFlow {
        OutboundFlow {
            sandbox_id: 0x51,
            guest_pid: 1,
            dest_ip: [198, 51, 100, 1],
            dest_port: port,
            host: host.map(str::to_string),
        }
    }

    fn connect_result(table: &mut StreamTable, id: HostStreamId) -> std::io::Result<()> {
        let start = Instant::now();
        loop {
            match table.connect_result(id) {
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    assert!(start.elapsed() < Duration::from_secs(10), "connect");
                    thread::sleep(Duration::from_millis(5));
                }
                other => return other,
            }
        }
    }

    #[test]
    fn an_allowed_flow_moves_bytes_both_ways() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hello = client_hello_for_test(&["echo.test"]);
        let want = hello.len() + 4;
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut got = vec![0u8; want];
            s.read_exact(&mut got).unwrap();
            s.write_all(b"pong").unwrap();
            got
        });
        let (proxy, audit) = proxy(
            "allow",
            "allow echo.test:443",
            &format!("echo.test 127.0.0.1:{port}"),
        );
        let mut table = StreamTable::default();
        table.set_endpoint(Endpoint::Egress(proxy.path().to_path_buf()));
        let id = table
            .open(flow(Some("echo.test"), 443), Waker::new(|| {}))
            .unwrap();
        connect_result(&mut table, id).unwrap();
        let mut out = hello.clone();
        out.extend_from_slice(b"ping");
        let mut sent = 0;
        while sent < out.len() {
            sent += table.write(id, &out[sent..]).unwrap();
        }
        let mut buf = [0u8; 4];
        let start = Instant::now();
        let mut n = 0;
        while n < 4 {
            match table.read(id, &mut buf[n..]) {
                Ok(k) => n += k,
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    assert!(start.elapsed() < Duration::from_secs(10), "read");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("read: {err}"),
            }
        }
        assert_eq!(&buf, b"pong");
        assert_eq!(&server.join().unwrap()[hello.len()..], b"ping");
        assert!(table.drain(Duration::from_secs(5)), "drained");
        drop(proxy);
        let lines = audit.lines();
        assert!(
            lines[0].contains(" sandbox=0000000000000051 host=echo.test port=443 verdict=allow "),
            "{lines:?}"
        );
    }

    #[test]
    fn refusals_are_connection_refused() {
        let (proxy, _audit) = proxy("deny", "allow other.test", "");
        let mut table = StreamTable::default();
        table.set_endpoint(Endpoint::Egress(proxy.path().to_path_buf()));
        let id = table
            .open(flow(Some("evil.test"), 443), Waker::new(|| {}))
            .unwrap();
        let err = connect_result(&mut table, id).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
        table.close(id);
        // Not resolvable (empty test table) is a refusal too.
        let id = table
            .open(flow(Some("other.test"), 443), Waker::new(|| {}))
            .unwrap();
        let err = connect_result(&mut table, id).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
    }

    #[test]
    fn a_missing_proxy_is_connection_refused() {
        let mut table = StreamTable::default();
        table.set_endpoint(Endpoint::Egress(sock("absent")));
        let id = table
            .open(flow(Some("a.test"), 443), Waker::new(|| {}))
            .unwrap();
        let err = connect_result(&mut table, id).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
    }

    #[test]
    fn a_flow_without_a_name_is_not_opened() {
        let mut table = StreamTable::default();
        table.set_endpoint(Endpoint::Egress(sock("noname")));
        let err = table.open(flow(None, 443), Waker::new(|| {})).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(table.flows().is_empty());
    }
}
