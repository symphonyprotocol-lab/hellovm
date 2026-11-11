//! Implementations of the cansol host interface ([`cansol_core::host::Host`]).
//!
//! Only portable `std` APIs are used so far, so these work on any host OS.
//! Linux- and macOS-specific implementations (files through the file proxy,
//! sockets to the egress proxy, ...) will live here as well.

#![forbid(unsafe_code)]

use std::io::{self, Write};

use cansol_core::host::{ConsoleStream, Host};

/// Sends sandbox console output to the kernel process's own stdout and
/// stderr.
#[derive(Debug, Default)]
pub struct StdioHost;

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
}

/// Keeps sandbox console output in memory.
#[derive(Debug, Default)]
pub struct CaptureHost {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Host for CaptureHost {
    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize> {
        match stream {
            ConsoleStream::Stdout => self.stdout.extend_from_slice(data),
            ConsoleStream::Stderr => self.stderr.extend_from_slice(data),
        }
        Ok(data.len())
    }
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
    }
}
