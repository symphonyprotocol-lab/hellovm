//! The host interface: what the kernel core needs from the OS it runs on.
//!
//! Everything the kernel does to the outside world goes through [`Host`], so
//! that the same core runs on a Linux or a macOS host. It only covers console
//! output for now; files, sockets, memory, time and threads are added as the
//! syscalls that need them are emulated.

use std::io;

/// The sandbox console stream a guest write goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleStream {
    Stdout,
    Stderr,
}

pub trait Host {
    /// Writes guest output to the sandbox console. Returns how many bytes of
    /// `data` were accepted, like a host `write`.
    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize>;
}

impl<H: Host + ?Sized> Host for &mut H {
    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize> {
        (**self).console_write(stream, data)
    }
}
