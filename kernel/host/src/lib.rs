//! Implementations of the hellovm host interface ([`hellovm_core::host::Host`]).
//!
//! Only portable `std` APIs (plus Unix file extensions) are used, so these
//! work on Linux and macOS hosts alike.
//!
//! * [`ImageDir`] serves a host directory as the sandbox's read-only image.
//! * [`StdioHost`] connects the sandbox console to the kernel process's own
//!   stdin, stdout and stderr. Its stdin is read by a helper thread, so that
//!   the kernel never blocks on it.
//! * [`CaptureHost`] keeps console output in memory and feeds console input
//!   from memory (for tests and embedding).
//!
//! Both send outbound guest flows to the egress proxy set with
//! `set_egress` (see `stream.rs`); with the `insecure-test-hooks` feature,
//! `set_splice_endpoint` sends them to a loopback TCP address instead.

#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod fsys;
mod image;
mod stream;

use hellovm_core::host::{
    ConsoleStream, Host, HostStat, HostStreamId, ImagePath, InboundConn, OutboundFlow, StreamStatus,
};

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hellovm_core::platform::Waker;

use stream::{Endpoint, StreamTable};

pub use stream::{
    InboundQueue, INBOUND_ACCEPTED, INBOUND_REFUSED, MAX_LIVE_INBOUND, MAX_QUEUED_INBOUND,
    VERDICT_TIMEOUT,
};

pub use image::ImageDir;

/// Sleeps without `nanosleep`, which the confined kernel process on macOS
/// may not use (see `stream_poll.rs`).
#[cfg(target_os = "macos")]
pub use stream::pause as sleep_confined;

/// The services every host implementation shares: the image, randomness and
/// clocks.
#[derive(Debug)]
struct Common {
    image: Option<ImageDir>,
    start: Instant,
    /// What the monotonic clock read at `start` (zero, but for a warm
    /// clone that is a new process: its template's clock).
    origin: Duration,
    /// `/dev/urandom`, opened once: a confined kernel process cannot open
    /// it later.
    urandom: Option<File>,
}

impl Common {
    fn new(image: Option<ImageDir>) -> Common {
        Common {
            image,
            start: Instant::now(),
            origin: Duration::ZERO,
            urandom: File::open("/dev/urandom").ok(),
        }
    }

    fn random(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match &mut self.urandom {
            Some(file) => file.read_exact(buf),
            None => random(buf),
        }
    }

    fn image(&mut self) -> io::Result<&mut ImageDir> {
        self.image
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no image"))
    }
}

fn random(buf: &mut [u8]) -> io::Result<()> {
    File::open("/dev/urandom")?.read_exact(buf)
}

fn realtime() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Implements the image, random and clock parts of [`Host`] by delegating
/// to a `common: Common` field.
macro_rules! common_host_methods {
    () => {
        fn has_image(&self) -> bool {
            self.common.image.is_some()
        }

        fn image_stat(&mut self, path: &ImagePath) -> io::Result<HostStat> {
            self.common.image()?.stat(path)
        }

        fn image_read_link(&mut self, path: &ImagePath) -> io::Result<Vec<u8>> {
            self.common.image()?.read_link(path)
        }

        fn image_read_dir(&mut self, path: &ImagePath) -> io::Result<Vec<Vec<u8>>> {
            self.common.image()?.read_dir(path)
        }

        fn image_read(
            &mut self,
            path: &ImagePath,
            offset: u64,
            buf: &mut [u8],
        ) -> io::Result<usize> {
            self.common.image()?.read(path, offset, buf)
        }

        fn random(&mut self, buf: &mut [u8]) -> io::Result<()> {
            self.common.random(buf)
        }

        fn clock_realtime(&mut self) -> Duration {
            realtime()
        }

        fn clock_monotonic(&mut self) -> Duration {
            self.common.origin + self.common.start.elapsed()
        }
    };
}

macro_rules! splice_host_methods {
    () => {
        fn egress_configured(&self) -> bool {
            self.splice.configured()
        }

        fn open_stream(&mut self, flow: OutboundFlow, waker: Waker) -> io::Result<HostStreamId> {
            self.splice.open(flow, waker)
        }

        fn stream_connect_result(&mut self, id: HostStreamId) -> io::Result<()> {
            self.splice.connect_result(id)
        }

        fn stream_status(&mut self, id: HostStreamId) -> io::Result<StreamStatus> {
            self.splice.status(id)
        }

        fn stream_read(&mut self, id: HostStreamId, buf: &mut [u8]) -> io::Result<usize> {
            self.splice.read(id, buf)
        }

        fn stream_write(&mut self, id: HostStreamId, data: &[u8]) -> io::Result<usize> {
            self.splice.write(id, data)
        }

        fn stream_shutdown_write(&mut self, id: HostStreamId) -> io::Result<()> {
            self.splice.shutdown_write(id)
        }

        fn stream_close(&mut self, id: HostStreamId) {
            self.splice.close(id);
        }

        fn settle_streams(&mut self, limit: Duration) -> bool {
            self.splice.settle(limit)
        }

        fn set_inbound_waker(&mut self, waker: Waker) {
            self.inbound_waker = Some(waker.clone());
            self.splice.set_inbound_waker(waker);
        }

        fn inbound_pending(&self) -> bool {
            self.splice.inbound_pending()
        }

        fn take_inbound(&mut self) -> Option<InboundConn> {
            self.splice.take_inbound()
        }

        fn answer_inbound(&mut self, stream: HostStreamId, accepted: bool) {
            let waker = self.inbound_waker.clone().unwrap_or_else(Waker::noop);
            self.splice.answer_inbound(stream, accepted, waker);
        }
    };
}

/// Most stdin bytes the reader thread buffers ahead of the kernel.
const STDIN_AHEAD: usize = 64 * 1024;

#[derive(Default)]
struct Input {
    buf: VecDeque<u8>,
    eof: bool,
    waker: Option<Waker>,
}

/// Where console input comes from.
#[derive(Debug)]
enum InputSource {
    /// The process's stdin.
    Stdin,
    /// This file (a warm clone's stdin).
    File(#[cfg_attr(target_os = "macos", allow(dead_code))] File),
    /// Nothing: console input is at end of file (a warm-clone template).
    Closed,
}

/// stdin, read by a helper thread.
#[derive(Default)]
struct StdinReader {
    input: Mutex<Input>,
    /// Signalled when the kernel took input (room for more).
    room: Condvar,
}

impl StdinReader {
    fn run(&self, file: Option<File>) {
        let mut chunk = [0u8; 4096];
        loop {
            {
                let mut input = self.input.lock().unwrap_or_else(|e| e.into_inner());
                while input.buf.len() >= STDIN_AHEAD {
                    input = self.room.wait(input).unwrap_or_else(|e| e.into_inner());
                }
            }
            let result = match &file {
                Some(file) => (&*file).read(&mut chunk),
                None => io::stdin().lock().read(&mut chunk),
            };
            let done = !matches!(result, Ok(n) if n > 0)
                && !matches!(&result, Err(e) if e.kind() == io::ErrorKind::Interrupted);
            let waker = {
                let mut input = self.input.lock().unwrap_or_else(|e| e.into_inner());
                match result {
                    Ok(0) => input.eof = true,
                    Ok(n) => input.buf.extend(&chunk[..n]),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => {
                        log::warn!("reading stdin: {err}; treating it as closed");
                        input.eof = true;
                    }
                }
                input.waker.clone()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
            if done {
                return;
            }
        }
    }
}

/// Connects the sandbox console to the kernel process's stdio, or to
/// other files ([`StdioHost::set_console`]).
pub struct StdioHost {
    common: Common,
    input: InputSource,
    /// Output files instead of the process's stdout and stderr.
    output: Option<(File, File)>,
    stdin: Option<Arc<StdinReader>>,
    /// Given to the stdin reader when it starts.
    waker: Option<Waker>,
    splice: StreamTable,
    /// Given to each inbound stream.
    inbound_waker: Option<Waker>,
    /// macOS: the stdin reader's copy of a console input file, made by
    /// [`StdioHost::set_console`]: a confined kernel process may not
    /// duplicate an fd (`fcntl(F_DUPFD_CLOEXEC)`) when the reader starts.
    #[cfg(target_os = "macos")]
    reader_file: Option<File>,
}

impl std::fmt::Debug for StdioHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioHost").finish_non_exhaustive()
    }
}

impl StdioHost {
    /// The image, to move it when the kernel process confines itself
    /// (see [`ImageDir::rebind`]).
    pub fn image_mut(&mut self) -> Option<&mut ImageDir> {
        self.common.image.as_mut()
    }

    pub fn new(image: Option<ImageDir>) -> StdioHost {
        StdioHost {
            common: Common::new(image),
            input: InputSource::Stdin,
            output: None,
            stdin: None,
            waker: None,
            splice: StreamTable::default(),
            inbound_waker: None,
            #[cfg(target_os = "macos")]
            reader_file: None,
        }
    }

    /// Where inbound connections (ingress) are handed over to this
    /// sandbox's kernel, from any thread.
    pub fn inbound_queue(&self) -> InboundQueue {
        self.splice.inbound_queue()
    }

    /// Sends every outbound flow to the egress proxy listening on `path`.
    /// On macOS this starts the thread that moves outbound bytes, which
    /// must exist before the kernel process confines itself.
    pub fn set_egress(&mut self, path: impl Into<std::path::PathBuf>) -> io::Result<()> {
        self.splice.set_endpoint(Endpoint::Egress(path.into()))
    }

    /// From now on the monotonic clock reads `now` and goes on from there
    /// (a warm clone in a new process continues its template's clock,
    /// which the kernel state it starts from counts in).
    pub fn set_monotonic_clock(&mut self, now: Duration) {
        self.common.start = Instant::now();
        self.common.origin = now;
    }

    /// Console input is at end of file from the start (a warm-clone
    /// template: its stdin belongs to no one, and no reader thread may
    /// exist when the template's process is forked).
    pub fn close_input(&mut self) {
        self.input = InputSource::Closed;
    }

    /// Connects the console to these files instead of the process's own
    /// stdio (a warm clone, in a fork of the template's process: the
    /// template had no reader thread, see [`StdioHost::close_input`]).
    pub fn set_console(&mut self, stdin: File, stdout: File, stderr: File) {
        #[cfg(target_os = "macos")]
        {
            self.reader_file = stdin.try_clone().ok();
        }
        self.input = InputSource::File(stdin);
        self.output = Some((stdout, stderr));
        self.stdin = None;
    }

    /// Test hook: splice every issued-fake-IP TCP connect to `addr`, with
    /// no egress policy. The guest's destination is not dialed.
    #[cfg(feature = "insecure-test-hooks")]
    pub fn set_splice_endpoint(&mut self, addr: std::net::SocketAddr) -> io::Result<()> {
        self.splice.set_endpoint(Endpoint::Splice(addr))
    }

    /// See [`StreamTable::drain`]: closes the remaining outbound streams and
    /// waits at most `limit` for their queued bytes to be delivered.
    pub fn drain_streams(&mut self, limit: Duration) -> bool {
        self.splice.drain(limit)
    }

    /// The stdin reader, started when the sandbox first asks for console
    /// input: a program that never reads its stdin leaves hellovm's stdin
    /// untouched for whoever comes next (the rest of a shell script, say).
    fn reader(&mut self) -> &Arc<StdinReader> {
        let waker = self.waker.clone();
        #[cfg(not(target_os = "macos"))]
        let file = match &self.input {
            InputSource::File(file) => file.try_clone().ok(),
            _ => None,
        };
        #[cfg(target_os = "macos")]
        let file = match &self.input {
            InputSource::File(_) if self.stdin.is_none() => self.reader_file.take(),
            _ => None,
        };
        self.stdin.get_or_insert_with(|| {
            let reader = Arc::new(StdinReader::default());
            reader.input.lock().unwrap_or_else(|e| e.into_inner()).waker = waker;
            let thread_reader = Arc::clone(&reader);
            // Detached: it may stay blocked in read() until the process
            // exits.
            std::thread::Builder::new()
                .name("hellovm-stdin".into())
                .spawn(move || thread_reader.run(file))
                .expect("starting the stdin thread");
            reader
        })
    }
}

impl Host for StdioHost {
    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize> {
        match (stream, &self.output) {
            (ConsoleStream::Stdout, Some((out, _))) => (&*out).write_all(data)?,
            (ConsoleStream::Stderr, Some((_, err))) => (&*err).write_all(data)?,
            (ConsoleStream::Stdout, None) => {
                let mut out = io::stdout().lock();
                out.write_all(data)?;
                out.flush()?;
            }
            (ConsoleStream::Stderr, None) => io::stderr().lock().write_all(data)?,
        }
        Ok(data.len())
    }

    fn console_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let InputSource::Closed = self.input {
            return Ok(0);
        }
        let reader = Arc::clone(self.reader());
        let mut input = reader.input.lock().unwrap_or_else(|e| e.into_inner());
        if input.buf.is_empty() {
            return if input.eof {
                Ok(0)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            };
        }
        let n = buf.len().min(input.buf.len());
        for (dst, src) in buf.iter_mut().zip(input.buf.drain(..n)) {
            *dst = src;
        }
        reader.room.notify_one();
        Ok(n)
    }

    fn set_console_waker(&mut self, waker: Waker) {
        // Does not start the reader.
        if let Some(reader) = &self.stdin {
            reader.input.lock().unwrap_or_else(|e| e.into_inner()).waker = Some(waker.clone());
        }
        self.waker = Some(waker);
    }

    common_host_methods!();
    splice_host_methods!();
}

/// Keeps sandbox console output in memory and serves console input from
/// memory.
#[derive(Debug)]
pub struct CaptureHost {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdin: VecDeque<u8>,
    common: Common,
    splice: StreamTable,
    inbound_waker: Option<Waker>,
}

impl CaptureHost {
    /// The image, to move it when the kernel process confines itself
    /// (see [`ImageDir::rebind`]).
    pub fn image_mut(&mut self) -> Option<&mut ImageDir> {
        self.common.image.as_mut()
    }

    pub fn new(image: Option<ImageDir>) -> CaptureHost {
        CaptureHost {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdin: VecDeque::new(),
            common: Common::new(image),
            splice: StreamTable::default(),
            inbound_waker: None,
        }
    }

    /// See [`StdioHost::inbound_queue`].
    pub fn inbound_queue(&self) -> InboundQueue {
        self.splice.inbound_queue()
    }

    /// Sends every outbound flow to the egress proxy listening on `path`.
    /// On macOS this starts the thread that moves outbound bytes, which
    /// must exist before the kernel process confines itself.
    pub fn set_egress(&mut self, path: impl Into<std::path::PathBuf>) -> io::Result<()> {
        self.splice.set_endpoint(Endpoint::Egress(path.into()))
    }

    /// Test hook: splice every issued-fake-IP TCP connect to `addr`.
    #[cfg(feature = "insecure-test-hooks")]
    pub fn set_splice_endpoint(&mut self, addr: std::net::SocketAddr) -> io::Result<()> {
        self.splice.set_endpoint(Endpoint::Splice(addr))
    }

    /// Outbound flows the kernel opened (the last 1024), in order.
    /// `dest_ip` is the guest address that was **not** dialed.
    pub fn outbound_flows(&self) -> &[hellovm_core::host::OutboundFlow] {
        self.splice.flows()
    }

    /// See [`StdioHost::drain_streams`].
    pub fn drain_streams(&mut self, limit: Duration) -> bool {
        self.splice.drain(limit)
    }
}

impl Default for CaptureHost {
    fn default() -> Self {
        CaptureHost::new(None)
    }
}

impl Host for CaptureHost {
    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize> {
        match stream {
            ConsoleStream::Stdout => self.stdout.extend_from_slice(data),
            ConsoleStream::Stderr => self.stderr.extend_from_slice(data),
        }
        Ok(data.len())
    }

    fn console_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.stdin.len());
        for (dst, src) in buf.iter_mut().zip(self.stdin.drain(..n)) {
            *dst = src;
        }
        Ok(n)
    }

    common_host_methods!();
    splice_host_methods!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_keeps_streams_apart() {
        let mut host = CaptureHost::default();
        host.console_write(ConsoleStream::Stdout, b"out").unwrap();
        host.console_write(ConsoleStream::Stderr, b"err").unwrap();
        assert_eq!(host.stdout, b"out");
        assert_eq!(host.stderr, b"err");
        host.stdin.extend(b"in");
        let mut buf = [0; 4];
        assert_eq!(host.console_read(&mut buf).unwrap(), 2);
        assert_eq!(host.console_read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn randomness_and_clocks() {
        let mut host = CaptureHost::default();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        host.random(&mut a).unwrap();
        host.random(&mut b).unwrap();
        assert_ne!(a, b);
        assert!(host.clock_realtime().as_secs() > 1_600_000_000);
        let t0 = host.clock_monotonic();
        assert!(host.clock_monotonic() >= t0);
        assert!(!host.has_image());
        assert!(host.image_stat(&ImagePath::root()).is_err());
    }
}
