//! The sandbox console.
//!
//! The console connects the sandbox to the host's console streams
//! ([`crate::host::Host::console_read`] and `console_write`). Input is
//! pulled from the host without blocking and buffered here; a read with
//! nothing buffered parks the reading thread until the host's waker fires.

use std::collections::VecDeque;
use std::io;

use crate::host::Host;

/// Most console input buffered in the kernel.
const INPUT_MAX: usize = 4096;

/// What a console read can do now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputState {
    /// Bytes are buffered.
    Ready,
    /// End of input.
    Eof,
    /// Nothing yet: wait.
    Empty,
}

#[derive(Debug, Default)]
pub struct Console {
    input: VecDeque<u8>,
    eof: bool,
}

impl Console {
    pub fn new() -> Console {
        Console::default()
    }

    /// Pulls whatever input the host has, without blocking.
    pub fn fill<H: Host + ?Sized>(&mut self, host: &mut H) {
        let mut buf = [0u8; 1024];
        while !self.eof && self.input.len() < INPUT_MAX {
            let want = buf.len().min(INPUT_MAX - self.input.len());
            match host.console_read(&mut buf[..want]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.input.extend(&buf[..n]),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    log::warn!("console input failed on the host: {err}; treating it as closed");
                    self.eof = true;
                }
            }
        }
    }

    pub fn input_state<H: Host + ?Sized>(&mut self, host: &mut H) -> InputState {
        if self.input.is_empty() {
            self.fill(host);
        }
        if !self.input.is_empty() {
            InputState::Ready
        } else if self.eof {
            InputState::Eof
        } else {
            InputState::Empty
        }
    }

    /// Takes up to `max` buffered input bytes.
    pub fn take_input(&mut self, max: usize) -> Vec<u8> {
        let n = max.min(self.input.len());
        self.input.drain(..n).collect()
    }

    /// Puts back input that could not be delivered.
    pub fn unread(&mut self, data: &[u8]) {
        for &b in data.iter().rev() {
            self.input.push_front(b);
        }
    }

    pub fn buffered(&self) -> usize {
        self.input.len()
    }

    /// Process `sid` left its session (`setsid`): it no longer controls the
    /// terminal.
    pub fn session_left(&mut self, _sid: u32) {}
}
