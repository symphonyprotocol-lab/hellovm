//! Host byte streams for guest TCP sockets spliced to a configured endpoint.
//!
//! The kernel thread never blocks on the network. Each stream has a reader
//! thread and a writer thread (the same shape as the stdin helper). The
//! guest destination IP is recorded on [`OutboundFlow`] and is not dialed:
//! every stream connects to the one [`SpliceTable`] endpoint. 002b replaces
//! that endpoint with the egress proxy's Unix socket and sends the flow
//! metadata in the handshake; this type is the hook that call sits on.
//!
//! Half-close is `TcpStream::shutdown(Shutdown::Write)` after the outbound
//! buffer drains, so the peer reads EOF while the guest can still receive.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// A connect that the guest abandons must not block its helper thread forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
    control: Option<TcpStream>,
}

struct Shared {
    inner: Mutex<Inner>,
    cv: Condvar,
    waker: Mutex<Waker>,
}

impl Shared {
    fn wake(self: &Arc<Self>) {
        self.waker.lock().unwrap_or_else(|e| e.into_inner()).wake();
    }
}

/// Configured splice endpoint and the streams currently open to it.
#[derive(Default)]
pub struct SpliceTable {
    endpoint: Option<SocketAddr>,
    streams: HashMap<u64, Arc<Shared>>,
    next: u64,
    flows: Vec<OutboundFlow>,
}

impl SpliceTable {
    pub fn set_endpoint(&mut self, addr: SocketAddr) {
        self.endpoint = Some(addr);
    }

    pub fn configured(&self) -> bool {
        self.endpoint.is_some()
    }

    pub fn flows(&self) -> &[OutboundFlow] {
        &self.flows
    }

    pub fn open(&mut self, flow: OutboundFlow, waker: Waker) -> io::Result<HostStreamId> {
        let Some(addr) = self.endpoint else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no splice endpoint configured",
            ));
        };
        // `flow.dest_ip` is stored for the test (and, later, the egress
        // audit record). The dial below uses `addr` only.
        self.flows.push(flow);
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
        });
        self.streams.insert(id, Arc::clone(&shared));
        thread::Builder::new()
            .name(format!("hellovm-splice-{id}"))
            .spawn(move || drive(addr, shared))
            .map_err(io::Error::other)?;
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
                "splice connect failed",
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
                    "splice peer reset",
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
                "splice peer is gone",
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
        }
        shared.cv.notify_all();
    }
}

impl std::fmt::Debug for SpliceTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpliceTable")
            .field("endpoint", &self.endpoint)
            .field("streams", &self.streams.len())
            .field("flows", &self.flows.len())
            .finish()
    }
}

impl SpliceTable {
    fn shared(&self, id: HostStreamId) -> io::Result<Arc<Shared>> {
        self.streams
            .get(&id.0)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "splice stream is closed"))
    }
}

fn drive(addr: SocketAddr, shared: Arc<Shared>) {
    let stream = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
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
    let _ = stream.set_nodelay(true);
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
        .name("hellovm-splice-read".into())
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

fn read_loop(mut sock: TcpStream, shared: Arc<Shared>) {
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

fn write_loop(mut sock: TcpStream, shared: Arc<Shared>) {
    loop {
        let chunk = {
            let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            while inner.outbound.is_empty() && !inner.shut_wr && !inner.closing && !inner.abort {
                inner = shared.cv.wait(inner).unwrap_or_else(|e| e.into_inner());
            }
            if inner.abort {
                return;
            }
            if inner.outbound.is_empty() && (inner.shut_wr || inner.closing) {
                drop(inner);
                let _ = sock.shutdown(Shutdown::Write);
                return;
            }
            let n = inner.outbound.len().min(CHUNK);
            inner.outbound.drain(..n).collect::<Vec<u8>>()
        };
        let mut off = 0;
        while off < chunk.len() {
            match sock.write(&chunk[off..]) {
                Ok(0) => {
                    mark_broken(&shared);
                    return;
                }
                Ok(n) => off += n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    mark_broken(&shared);
                    return;
                }
            }
        }
        shared.wake();
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
