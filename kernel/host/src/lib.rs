//! Implementations of the cansol host interface ([`cansol_core::host::Host`]).
//!
//! Only portable `std` APIs (plus Unix file extensions) are used, so these
//! work on Linux and macOS hosts alike.
//!
//! * [`ImageDir`] serves a host directory as the sandbox's read-only image.
//! * [`StdioHost`] connects the sandbox console to the kernel process's own
//!   stdin, stdout and stderr.
//! * [`CaptureHost`] keeps console output in memory and feeds console input
//!   from memory (for tests and embedding).

#![forbid(unsafe_code)]

mod image;

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cansol_core::host::{ConsoleStream, Host, HostStat, ImagePath};

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

        fn image_read(&mut self, path: &ImagePath, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
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

        fn sleep(&mut self, duration: Duration) {
            std::thread::sleep(duration);
        }
    };
}

/// Connects the sandbox console to the kernel process's stdio.
#[derive(Debug)]
pub struct StdioHost {
    common: Common,
}

impl StdioHost {
    pub fn new(image: Option<ImageDir>) -> StdioHost {
        StdioHost {
            common: Common::new(image),
        }
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
        io::stdin().lock().read(buf)
    }

    common_host_methods!();
}

/// Keeps sandbox console output in memory and serves console input from
/// memory.
#[derive(Debug)]
pub struct CaptureHost {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdin: VecDeque<u8>,
    common: Common,
}

impl CaptureHost {
    pub fn new(image: Option<ImageDir>) -> CaptureHost {
        CaptureHost {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdin: VecDeque::new(),
            common: Common::new(image),
        }
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
