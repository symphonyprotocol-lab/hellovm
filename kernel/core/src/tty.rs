//! The sandbox console: plain streams, or a terminal with a line
//! discipline.
//!
//! The console connects the sandbox to the host's console streams
//! ([`crate::host::Host::console_read`] and `console_write`). Input is
//! pulled from the host without blocking and buffered here; a read with
//! nothing buffered parks the reading thread until the host's waker fires.
//!
//! As a terminal ([`crate::ConsoleMode::Terminal`]) it behaves like the
//! slave side of a pty whose master is the host console: termios settings
//! (canonical line editing with erase, kill and word-erase; echo; CR/NL
//! translation; `ONLCR` output), a window size, a controlling session and a
//! foreground process group. The characters `VINTR`, `VQUIT` and `VSUSP`
//! become `SIGINT`, `SIGQUIT` and `SIGTSTP` for the foreground process
//! group as soon as they arrive from the host, whether or not anyone reads.
//! The host side is expected to be raw: hellovm, not the host terminal,
//! does the echoing and editing.

use std::collections::VecDeque;
use std::io;

use crate::host::{ConsoleStream, Host};
use crate::signal::{SIGINT, SIGQUIT, SIGTSTP};

/// Most console input buffered in the kernel.
const INPUT_MAX: usize = 4096;
/// Longest line canonical mode keeps (Linux's `N_TTY_BUF_SIZE`).
const LINE_MAX: usize = 4096;

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

// termios flags (the generic values, the same on x86_64 and aarch64).
pub const ISIG: u32 = 0x1;
pub const ICANON: u32 = 0x2;
pub const ECHO: u32 = 0x8;
pub const ECHOE: u32 = 0x10;
pub const ECHOK: u32 = 0x20;
pub const ECHONL: u32 = 0x40;
pub const NOFLSH: u32 = 0x80;
pub const TOSTOP: u32 = 0x100;
pub const ECHOCTL: u32 = 0x200;
pub const ECHOKE: u32 = 0x800;
pub const IEXTEN: u32 = 0x8000;
pub const INLCR: u32 = 0x40;
pub const IGNCR: u32 = 0x80;
pub const ICRNL: u32 = 0x100;
pub const IXON: u32 = 0x400;
pub const IUTF8: u32 = 0x4000;
pub const OPOST: u32 = 0x1;
pub const ONLCR: u32 = 0x4;

pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;
pub const VEOL2: usize = 16;
pub const NCCS: usize = 19;

/// The kernel's `struct termios` (`TCGETS`/`TCSETS`), 36 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; NCCS],
}

impl Default for Termios {
    /// The settings of a fresh Linux pty.
    fn default() -> Self {
        let mut cc = [0u8; NCCS];
        cc[VINTR] = 0x03;
        cc[VQUIT] = 0x1c;
        cc[VERASE] = 0x7f;
        cc[VKILL] = 0x15;
        cc[VEOF] = 0x04;
        cc[VTIME] = 0;
        cc[VMIN] = 1;
        cc[8] = 0x11; // VSTART
        cc[9] = 0x13; // VSTOP
        cc[VSUSP] = 0x1a;
        cc[12] = 0x12; // VREPRINT
        cc[13] = 0x0f; // VDISCARD
        cc[VWERASE] = 0x17;
        cc[VLNEXT] = 0x16;
        Termios {
            iflag: ICRNL | IXON | IUTF8,
            oflag: OPOST | ONLCR,
            // B38400 | CS8 | CREAD | HUPCL
            cflag: 0xf | 0x30 | 0x80 | 0x400,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
            line: 0,
            cc,
        }
    }
}

impl Termios {
    pub const SIZE: usize = 36;

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        for (i, v) in [self.iflag, self.oflag, self.cflag, self.lflag]
            .iter()
            .enumerate()
        {
            b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[16] = self.line;
        b[17..].copy_from_slice(&self.cc);
        b
    }

    pub fn decode(b: &[u8; Self::SIZE]) -> Termios {
        let f = |i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
        let mut cc = [0u8; NCCS];
        cc.copy_from_slice(&b[17..]);
        Termios {
            iflag: f(0),
            oflag: f(1),
            cflag: f(2),
            lflag: f(3),
            line: b[16],
            cc,
        }
    }

    pub fn canonical(&self) -> bool {
        self.lflag & ICANON != 0
    }
}

/// Input that a read can return.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Chunk {
    Data(Vec<u8>),
    /// `VEOF` at the start of a line: a read returns 0.
    Eof,
}

/// The terminal state.
#[derive(Debug)]
pub struct Tty {
    pub termios: Termios,
    pub rows: u16,
    pub cols: u16,
    /// The session the terminal controls.
    pub session: Option<u32>,
    /// The foreground process group.
    pub foreground: Option<u32>,
    /// The line being edited (canonical mode).
    line: Vec<u8>,
    /// The next byte is taken literally (`VLNEXT`).
    literal: bool,
    /// What reads return, in order.
    cooked: VecDeque<Chunk>,
    cooked_bytes: usize,
}

impl Tty {
    pub fn new(session: u32) -> Tty {
        Tty {
            termios: Termios::default(),
            rows: 24,
            cols: 80,
            session: Some(session),
            foreground: Some(session),
            line: Vec::new(),
            literal: false,
            cooked: VecDeque::new(),
            cooked_bytes: 0,
        }
    }

    fn push_cooked(&mut self, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        self.cooked_bytes += data.len();
        match self.cooked.back_mut() {
            Some(Chunk::Data(last)) if !self.termios.canonical() => last.extend(data),
            _ => self.cooked.push_back(Chunk::Data(data)),
        }
    }

    /// Bytes a read can return now.
    pub fn readable(&self) -> usize {
        self.cooked_bytes
    }

    /// Whether a read would return end of file now.
    pub fn has_eof(&self) -> bool {
        self.cooked.front() == Some(&Chunk::Eof)
    }

    /// Discards pending input (`TCFLSH`, signals).
    pub fn flush_input(&mut self) {
        self.line.clear();
        self.cooked.clear();
        self.cooked_bytes = 0;
    }

    /// New settings. Leaving canonical mode makes the line being edited
    /// readable.
    pub fn set_termios(&mut self, termios: Termios) {
        let was_canonical = self.termios.canonical();
        self.termios = termios;
        if was_canonical && !termios.canonical() {
            let line = std::mem::take(&mut self.line);
            self.push_cooked(line);
        }
    }

    /// Takes up to `max` bytes for a read: in canonical mode at most one
    /// line. `None` is end of file (`VEOF` on an empty line).
    pub fn take(&mut self, max: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < max {
            match self.cooked.pop_front() {
                None => break,
                Some(Chunk::Eof) => {
                    if out.is_empty() {
                        return None;
                    }
                    self.cooked.push_front(Chunk::Eof);
                    break;
                }
                Some(Chunk::Data(mut data)) => {
                    let n = (max - out.len()).min(data.len());
                    out.extend(data.drain(..n));
                    self.cooked_bytes -= n;
                    if !data.is_empty() {
                        self.cooked.push_front(Chunk::Data(data));
                        break;
                    }
                    if self.termios.canonical() {
                        break;
                    }
                }
            }
        }
        Some(out)
    }

    /// Puts back what a read took but could not deliver.
    pub fn unread(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.cooked_bytes += data.len();
        self.cooked.push_front(Chunk::Data(data.to_vec()));
    }

    /// Output processing (`OPOST`/`ONLCR`).
    pub fn output(&self, data: &[u8]) -> Vec<u8> {
        let t = &self.termios;
        if t.oflag & OPOST == 0 || t.oflag & ONLCR == 0 {
            return data.to_vec();
        }
        let mut out = Vec::with_capacity(data.len() + 8);
        for &b in data {
            if b == b'\n' {
                out.push(b'\r');
            }
            out.push(b);
        }
        out
    }

    fn echo_char(&self, b: u8, echo: &mut Vec<u8>) {
        if self.termios.lflag & ECHO == 0 {
            if b == b'\n' && self.termios.lflag & ECHONL != 0 {
                echo.extend_from_slice(b"\r\n");
            }
            return;
        }
        if b == b'\n' {
            echo.extend_from_slice(b"\r\n");
        } else if b < 0x20 && b != b'\t' && self.termios.lflag & ECHOCTL != 0 {
            echo.extend_from_slice(&[b'^', b + 0x40]);
        } else if b == 0x7f && self.termios.lflag & ECHOCTL != 0 {
            echo.extend_from_slice(b"^?");
        } else {
            echo.push(b);
        }
    }

    fn erase_one(&mut self, echo: &mut Vec<u8>) -> bool {
        let Some(b) = self.line.pop() else {
            return false;
        };
        // UTF-8: erase a whole character.
        if self.termios.iflag & IUTF8 != 0 && b & 0xc0 == 0x80 {
            while let Some(&c) = self.line.last() {
                self.line.pop();
                if c & 0xc0 != 0x80 {
                    break;
                }
            }
        }
        if self.termios.lflag & ECHO != 0 && self.termios.lflag & ECHOE != 0 {
            let width = if b < 0x20 && self.termios.lflag & ECHOCTL != 0 {
                2
            } else {
                1
            };
            for _ in 0..width {
                echo.extend_from_slice(b"\x08 \x08");
            }
        }
        true
    }

    /// Runs bytes from the host through the line discipline. Returns the
    /// echo to write and the signals to send to the foreground group.
    pub fn input(&mut self, data: &[u8]) -> (Vec<u8>, Vec<u32>) {
        let mut echo = Vec::new();
        let mut signals = Vec::new();
        for &raw in data {
            let t = self.termios;
            let mut b = raw;
            if std::mem::take(&mut self.literal) {
                self.line.push(b);
                self.echo_char(b, &mut echo);
                continue;
            }
            if b == b'\r' {
                if t.iflag & IGNCR != 0 {
                    continue;
                }
                if t.iflag & ICRNL != 0 {
                    b = b'\n';
                }
            } else if b == b'\n' && t.iflag & INLCR != 0 {
                b = b'\r';
            }
            if t.lflag & ISIG != 0 {
                let sig = match b {
                    _ if b == t.cc[VINTR] && b != 0 => Some(SIGINT),
                    _ if b == t.cc[VQUIT] && b != 0 => Some(SIGQUIT),
                    _ if b == t.cc[VSUSP] && b != 0 => Some(SIGTSTP),
                    _ => None,
                };
                if let Some(sig) = sig {
                    if t.lflag & NOFLSH == 0 {
                        self.flush_input();
                    }
                    self.echo_char(b, &mut echo);
                    signals.push(sig);
                    continue;
                }
            }
            if !t.canonical() {
                self.echo_char(b, &mut echo);
                self.push_cooked(vec![b]);
                continue;
            }
            if t.lflag & IEXTEN != 0 && b == t.cc[VLNEXT] && b != 0 {
                self.literal = true;
                continue;
            }
            if b == t.cc[VERASE] && b != 0 {
                self.erase_one(&mut echo);
            } else if t.lflag & IEXTEN != 0 && b == t.cc[VWERASE] && b != 0 {
                while self.line.last() == Some(&b' ') {
                    self.erase_one(&mut echo);
                }
                while self.line.last().is_some_and(|&c| c != b' ') {
                    self.erase_one(&mut echo);
                }
            } else if b == t.cc[VKILL] && b != 0 {
                while self.erase_one(&mut echo) {}
            } else if b == t.cc[VEOF] && b != 0 {
                let line = std::mem::take(&mut self.line);
                if line.is_empty() {
                    self.cooked.push_back(Chunk::Eof);
                } else {
                    self.push_cooked(line);
                }
            } else if b == b'\n' || (b != 0 && (b == t.cc[VEOL] || b == t.cc[VEOL2])) {
                self.echo_char(b, &mut echo);
                let mut line = std::mem::take(&mut self.line);
                line.push(b);
                self.push_cooked(line);
            } else if self.line.len() < LINE_MAX {
                self.line.push(b);
                self.echo_char(b, &mut echo);
            }
        }
        (echo, signals)
    }
}

#[derive(Debug, Default)]
pub struct Console {
    input: VecDeque<u8>,
    eof: bool,
    /// The terminal, when the console is one.
    pub tty: Option<Tty>,
}

impl Console {
    /// A console of plain streams.
    pub fn new() -> Console {
        Console::default()
    }

    /// A terminal controlled by session `sid` (whose process group is in
    /// the foreground).
    pub fn terminal(sid: u32) -> Console {
        Console {
            tty: Some(Tty::new(sid)),
            ..Console::default()
        }
    }

    /// Pulls whatever input the host has, without blocking. For a
    /// terminal, it goes through the line discipline: the echo is written
    /// to the host, and the signals for the foreground group are returned.
    pub fn fill<H: Host + ?Sized>(&mut self, host: &mut H) -> Vec<u32> {
        let mut buf = [0u8; 1024];
        let mut signals = Vec::new();
        loop {
            let room = match &self.tty {
                Some(tty) => INPUT_MAX.saturating_sub(tty.readable()),
                None => INPUT_MAX.saturating_sub(self.input.len()),
            };
            if self.eof || room == 0 {
                break;
            }
            let want = buf.len().min(room);
            let n = match host.console_read(&mut buf[..want]) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    log::warn!("console input failed on the host: {err}; treating it as closed");
                    self.eof = true;
                    break;
                }
            };
            match &mut self.tty {
                None => self.input.extend(&buf[..n]),
                Some(tty) => {
                    let (echo, sigs) = tty.input(&buf[..n]);
                    if !echo.is_empty() {
                        if let Err(err) = host.console_write(ConsoleStream::Stdout, &echo) {
                            log::warn!("terminal echo failed on the host: {err}");
                        }
                    }
                    signals.extend(sigs);
                }
            }
        }
        signals
    }

    /// The input state of a plain-stream console.
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

    /// Whether the host's input has ended.
    pub fn hung_up(&self) -> bool {
        self.eof
    }

    /// Takes up to `max` buffered input bytes.
    pub fn take_input(&mut self, max: usize) -> Vec<u8> {
        let n = max.min(self.input.len());
        self.input.drain(..n).collect()
    }

    /// Puts back input that could not be delivered.
    pub fn unread(&mut self, data: &[u8]) {
        match &mut self.tty {
            Some(tty) => tty.unread(data),
            None => {
                for &b in data.iter().rev() {
                    self.input.push_front(b);
                }
            }
        }
    }

    pub fn buffered(&self) -> usize {
        match &self.tty {
            Some(tty) => tty.readable(),
            None => self.input.len(),
        }
    }

    /// The session the terminal controls, if any.
    pub fn session(&self) -> Option<u32> {
        self.tty.as_ref().and_then(|t| t.session)
    }

    /// The terminal's foreground process group, if any.
    pub fn foreground(&self) -> Option<u32> {
        self.tty.as_ref().and_then(|t| t.foreground)
    }

    /// Session `sid` ended or its leader left it: the terminal is no longer
    /// its controlling terminal.
    pub fn session_left(&mut self, sid: u32) {
        if let Some(tty) = &mut self.tty {
            if tty.session == Some(sid) {
                tty.session = None;
                tty.foreground = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_editing_and_echo() {
        let mut tty = Tty::new(1);
        let (echo, sigs) = tty.input(b"helo\x7flo wrld\x17world\r");
        assert!(sigs.is_empty());
        assert_eq!(tty.take(100).unwrap(), b"hello world\n");
        // Echo: typed characters, erases as backspace-space-backspace,
        // CR echoed as CR NL.
        assert!(echo.starts_with(b"helo\x08 \x08lo wrld"), "{echo:?}");
        assert!(echo.ends_with(b"world\r\n"), "{echo:?}");
        // A partial line is not readable; ^D on it makes it readable, ^D
        // on an empty line is end of file.
        tty.input(b"abc");
        assert_eq!(tty.readable(), 0);
        tty.input(b"\x04\x04");
        assert_eq!(tty.take(100).unwrap(), b"abc");
        assert_eq!(tty.take(100), None);
        // ^U kills the line.
        tty.input(b"junk\x15ok\n");
        assert_eq!(tty.take(100).unwrap(), b"ok\n");
        // Reads return at most one line, and the rest of a long one later.
        tty.input(b"one\ntwo\n");
        assert_eq!(tty.take(2).unwrap(), b"on");
        assert_eq!(tty.take(100).unwrap(), b"e\n");
        assert_eq!(tty.take(100).unwrap(), b"two\n");
    }

    #[test]
    fn signals_flush_and_raw_mode() {
        let mut tty = Tty::new(1);
        let (echo, sigs) = tty.input(b"partial\x03");
        assert_eq!(sigs, vec![SIGINT]);
        assert!(echo.ends_with(b"^C"));
        assert_eq!(tty.readable(), 0, "flushed");
        let (_, sigs) = tty.input(b"\x1a\x1c");
        assert_eq!(sigs, vec![SIGTSTP, SIGQUIT]);
        // Raw mode: every byte at once, no echo, no signals.
        let mut raw = tty.termios;
        raw.lflag &= !(ICANON | ECHO | ISIG);
        raw.iflag &= !ICRNL;
        tty.set_termios(raw);
        let (echo, sigs) = tty.input(b"a\x03\r");
        assert!(echo.is_empty() && sigs.is_empty());
        assert_eq!(tty.take(100).unwrap(), b"a\x03\r");
        assert_eq!(tty.output(b"x\n"), b"x\r\n");
        let t = Termios::default();
        assert_eq!(Termios::decode(&t.encode()), t);
    }
}
