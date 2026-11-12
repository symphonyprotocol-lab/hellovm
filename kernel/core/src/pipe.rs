//! Pipes: bounded byte queues between open file descriptions.
//!
//! A pipe counts the open descriptions of each end; the descriptions
//! themselves are shared by every fd that refers to them (across `fork`
//! too). Reading an empty pipe whose write end is still open waits; writing
//! to a pipe whose read end is closed fails with `EPIPE` and raises
//! `SIGPIPE`. The waiting itself is done by the kernel loop: these methods
//! only say whether an operation can proceed.

use std::collections::VecDeque;

use crate::fd::PipeId;

/// Bytes a pipe holds (Linux's default of 16 pages).
pub const PIPE_CAPACITY: usize = 64 * 1024;
/// Writes up to this size are atomic: all or nothing.
pub const PIPE_BUF: usize = 4096;
/// Most pipes in one sandbox, which bounds the memory pipe buffers take
/// (64 MiB), like Linux's `pipe-user-pages-hard` per user.
pub const MAX_PIPES: usize = 1024;

#[derive(Debug, Default)]
pub struct Pipe {
    buf: VecDeque<u8>,
    /// Open descriptions of the read end.
    pub readers: u32,
    /// Open descriptions of the write end.
    pub writers: u32,
}

/// What a read of an empty pipe would do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadResult {
    Data(usize),
    /// End of file: no writer is left.
    Eof,
    /// Empty, writers still open: wait (or `EAGAIN`).
    Empty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteResult {
    Written(usize),
    /// No reader is left: `EPIPE` and `SIGPIPE`.
    Broken,
    /// Not enough room: wait (or `EAGAIN`).
    Full,
}

impl Pipe {
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn space(&self) -> usize {
        PIPE_CAPACITY - self.buf.len()
    }

    /// Moves up to `out.len()` bytes into `out`.
    pub fn read(&mut self, out: &mut [u8]) -> ReadResult {
        if self.buf.is_empty() {
            return if self.writers == 0 {
                ReadResult::Eof
            } else {
                ReadResult::Empty
            };
        }
        let n = out.len().min(self.buf.len());
        for (dst, src) in out.iter_mut().zip(self.buf.drain(..n)) {
            *dst = src;
        }
        ReadResult::Data(n)
    }

    /// Puts back bytes that were read but could not be delivered.
    pub fn unread(&mut self, data: &[u8]) {
        for &b in data.iter().rev() {
            self.buf.push_front(b);
        }
    }

    /// Appends as much of `data` as fits; writes of at most [`PIPE_BUF`]
    /// bytes go in whole or not at all.
    pub fn write(&mut self, data: &[u8]) -> WriteResult {
        if self.readers == 0 {
            return WriteResult::Broken;
        }
        let space = self.space();
        if space == 0 || (data.len() <= PIPE_BUF && data.len() > space) {
            return WriteResult::Full;
        }
        let n = data.len().min(space);
        self.buf.extend(&data[..n]);
        WriteResult::Written(n)
    }
}

/// The sandbox's pipes.
#[derive(Debug, Default)]
pub struct Pipes {
    slots: Vec<Option<Pipe>>,
    free: Vec<PipeId>,
}

impl Pipes {
    /// A new pipe with one reader and one writer description, unless the
    /// sandbox has [`MAX_PIPES`] already.
    pub fn create(&mut self) -> Option<PipeId> {
        if self.slots.len() - self.free.len() >= MAX_PIPES {
            return None;
        }
        let pipe = Pipe {
            readers: 1,
            writers: 1,
            ..Pipe::default()
        };
        if let Some(id) = self.free.pop() {
            self.slots[id] = Some(pipe);
            return Some(id);
        }
        self.slots.push(Some(pipe));
        Some(self.slots.len() - 1)
    }

    pub fn get(&self, id: PipeId) -> &Pipe {
        self.slots[id].as_ref().expect("live pipe")
    }

    pub fn get_mut(&mut self, id: PipeId) -> &mut Pipe {
        self.slots[id].as_mut().expect("live pipe")
    }

    /// One end's description is gone; frees the pipe with its last one.
    pub fn close_end(&mut self, id: PipeId, write_end: bool) {
        let pipe = self.get_mut(id);
        if write_end {
            pipe.writers -= 1;
        } else {
            pipe.readers -= 1;
        }
        if pipe.readers == 0 && pipe.writers == 0 {
            self.slots[id] = None;
            self.free.push(id);
        }
    }

    #[cfg(test)]
    pub fn live(&self) -> usize {
        self.slots.len() - self.free.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eof_only_without_writers() {
        let mut pipes = Pipes::default();
        let id = pipes.create().unwrap();
        let p = pipes.get_mut(id);
        let mut buf = [0; 4];
        assert_eq!(p.read(&mut buf), ReadResult::Empty);
        assert_eq!(p.write(b"abcdef"), WriteResult::Written(6));
        assert_eq!(p.read(&mut buf), ReadResult::Data(4));
        assert_eq!(&buf, b"abcd");
        p.unread(b"cd");
        assert_eq!(p.read(&mut buf), ReadResult::Data(4));
        assert_eq!(&buf, b"cdef");
        pipes.close_end(id, true);
        assert_eq!(pipes.get_mut(id).read(&mut buf), ReadResult::Eof);
        pipes.close_end(id, false);
        assert_eq!(pipes.live(), 0);
        for _ in 0..MAX_PIPES {
            pipes.create().unwrap();
        }
        assert_eq!(pipes.create(), None);
    }

    #[test]
    fn full_pipes_and_atomic_writes() {
        let mut pipes = Pipes::default();
        let id = pipes.create().unwrap();
        let p = pipes.get_mut(id);
        let big = vec![7u8; PIPE_CAPACITY + 10];
        assert_eq!(p.write(&big), WriteResult::Written(PIPE_CAPACITY));
        assert_eq!(p.write(b"x"), WriteResult::Full);
        let mut buf = vec![0; 100];
        p.read(&mut buf);
        // 100 bytes free: a 200-byte write is atomic and must wait, a
        // 5000-byte one goes in partly.
        assert_eq!(p.write(&[1; 200]), WriteResult::Full);
        assert_eq!(p.write(&[1; 5000]), WriteResult::Written(100));
        p.readers = 0;
        assert_eq!(p.write(b"x"), WriteResult::Broken);
    }
}
