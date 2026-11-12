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

#![forbid(unsafe_code)]

mod image;
mod stream;

use hellovm_core::host::{
    ConsoleStream, Host, HostStat, HostStreamId, ImagePath, OutboundFlow, StreamStatus,
};

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hellovm_core::platform::Waker;

use stream::SpliceTable;

pub use image::ImageDir;

/// The services every host implementation shares: the image, randomness and
/// clocks.
#[derive(Debug)]
struct Common {
    image: Option<ImageDir>,
    start: Instant,
}

impl Common {
    fn new(image: Option<ImageDir>) -> Common {
        Common {
            image,
            start: Instant::now(),
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
            random(buf)
        }

        fn clock_realtime(&mut self) -> Duration {
            realtime()
        }

        fn clock_monotonic(&mut self) -> Duration {
            self.common.start.elapsed()
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

/// stdin, read by a helper thread.
#[derive(Default)]
struct StdinReader {
    input: Mutex<Input>,
    /// Signalled when the kernel took input (room for more).
    room: Condvar,
}

impl StdinReader {
    fn run(&self) {
        let mut chunk = [0u8; 4096];
        loop {
            {
                let mut input = self.input.lock().unwrap_or_else(|e| e.into_inner());
                while input.buf.len() >= STDIN_AHEAD {
                    input = self.room.wait(input).unwrap_or_else(|e| e.into_inner());
                }
            }
            let result = io::stdin().lock().read(&mut chunk);
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

/// Connects the sandbox console to the kernel process's stdio.
pub struct StdioHost {
    common: Common,
    stdin: Option<Arc<StdinReader>>,
    /// Given to the stdin reader when it starts.
    waker: Option<Waker>,
    splice: SpliceTable,
}

impl std::fmt::Debug for StdioHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioHost").finish_non_exhaustive()
    }
}

impl StdioHost {
    pub fn new(image: Option<ImageDir>) -> StdioHost {
        StdioHost {
            common: Common::new(image),
            stdin: None,
            waker: None,
            splice: SpliceTable::default(),
        }
    }

    /// Splice every issued-fake-IP TCP connect to `addr`. The guest's
    /// destination is not dialed. Orthogonal to 002b's `--egress`.
    pub fn set_splice_endpoint(&mut self, addr: std::net::SocketAddr) {
        self.splice.set_endpoint(addr);
    }

    /// The stdin reader, started when the sandbox first asks for console
    /// input: a program that never reads its stdin leaves hellovm's stdin
    /// untouched for whoever comes next (the rest of a shell script, say).
    fn reader(&mut self) -> &Arc<StdinReader> {
        let waker = self.waker.clone();
        self.stdin.get_or_insert_with(|| {
            let reader = Arc::new(StdinReader::default());
            reader.input.lock().unwrap_or_else(|e| e.into_inner()).waker = waker;
            let thread_reader = Arc::clone(&reader);
            // Detached: it may stay blocked in read() until the process
            // exits.
            std::thread::Builder::new()
                .name("hellovm-stdin".into())
                .spawn(move || thread_reader.run())
                .expect("starting the stdin thread");
            reader
        })
    }
}

impl Host for StdioHost {
    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize> {
        match stream {
            ConsoleStream::Stdout => {
                let mut out = io::stdout().lock();
                out.write_all(data)?;
                out.flush()?;
            }
            ConsoleStream::Stderr => io::stderr().lock().write_all(data)?,
        }
        Ok(data.len())
    }

    fn console_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
    splice: SpliceTable,
}

impl CaptureHost {
    pub fn new(image: Option<ImageDir>) -> CaptureHost {
        CaptureHost {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdin: VecDeque::new(),
            common: Common::new(image),
            splice: SpliceTable::default(),
        }
    }

    /// Splice every issued-fake-IP TCP connect to `addr`.
    pub fn set_splice_endpoint(&mut self, addr: std::net::SocketAddr) {
        self.splice.set_endpoint(addr);
    }

    /// Flows the kernel asked to splice, in order. `dest_ip` is the guest
    /// address that was **not** dialed.
    pub fn splice_flows(&self) -> &[hellovm_core::host::OutboundFlow] {
        self.splice.flows()
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
