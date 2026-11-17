//! An exec's output as `noded` holds it while the exec runs and after it
//! ended, whoever reads it and however slowly.
//!
//! - [`Capture`]: one stream, for the final result: its first and its last
//!   half of `limit` bytes, with a line saying how much was left out
//!   between them (the rule `exec` always had).
//! - [`StreamLog`]: both streams interleaved in the order they came, for
//!   readers that follow the output with a cursor (a byte position in the
//!   interleaved stream). It holds the same amount, `2 * limit`, by the
//!   same rule: the first `limit` bytes and the last `limit` bytes. A
//!   reader whose cursor fell into the part dropped between them is told
//!   how many bytes it missed.

use std::collections::VecDeque;

use hellovm_control::types::OutputEvent;

/// The line put where a capture's middle was cut.
pub fn omission(bytes: u64) -> String {
    format!("\n[... {bytes} bytes omitted ...]\n")
}

/// The first and the last half of `limit` bytes of a stream.
#[derive(Debug)]
pub struct Capture {
    head_cap: usize,
    tail_cap: usize,
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: u64,
}

impl Capture {
    pub fn new(limit: usize) -> Capture {
        let head_cap = limit / 2;
        Capture {
            head_cap,
            tail_cap: limit - head_cap,
            head: Vec::new(),
            tail: VecDeque::new(),
            total: 0,
        }
    }

    pub fn add(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        let room = self.head_cap - self.head.len();
        if room > 0 {
            let take = room.min(data.len());
            self.head.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        if data.len() >= self.tail_cap {
            self.tail.clear();
            self.tail.extend(&data[data.len() - self.tail_cap..]);
            return;
        }
        let over = (self.tail.len() + data.len()).saturating_sub(self.tail_cap);
        self.tail.drain(..over);
        self.tail.extend(data);
    }

    /// Bytes written to the stream in all.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The kept bytes (with the omission line between head and tail when
    /// something was dropped), and whether something was.
    pub fn result(&self) -> (Vec<u8>, bool) {
        let kept = (self.head.len() + self.tail.len()) as u64;
        let mut out = self.head.clone();
        let cut = kept < self.total;
        if cut {
            out.extend_from_slice(omission(self.total - kept).as_bytes());
        }
        out.extend(self.tail.iter());
        (out, cut)
    }
}

/// Which stream a piece of output came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
struct Chunk {
    /// Position of its first byte in the interleaved stream.
    start: u64,
    stream: Stream,
    data: Vec<u8>,
}

impl Chunk {
    fn end(&self) -> u64 {
        self.start + self.data.len() as u64
    }
}

/// Both streams interleaved, the first and last `limit` bytes of them.
#[derive(Debug)]
pub struct StreamLog {
    limit: usize,
    head: Vec<Chunk>,
    head_bytes: usize,
    tail: VecDeque<Chunk>,
    tail_bytes: usize,
    total: u64,
}

/// What a read found.
#[derive(Debug, PartialEq, Eq)]
pub struct Read {
    pub events: Vec<OutputEvent>,
    pub next_cursor: u64,
}

impl StreamLog {
    pub fn new(limit: usize) -> StreamLog {
        StreamLog {
            limit,
            head: Vec::new(),
            head_bytes: 0,
            tail: VecDeque::new(),
            tail_bytes: 0,
            total: 0,
        }
    }

    /// Bytes produced so far: the cursor after the last one.
    pub fn total(&self) -> u64 {
        self.total
    }

    fn append(chunks: &mut Vec<Chunk>, start: u64, stream: Stream, data: &[u8]) {
        match chunks.last_mut() {
            Some(last) if last.stream == stream && last.end() == start => {
                last.data.extend_from_slice(data)
            }
            _ => chunks.push(Chunk {
                start,
                stream,
                data: data.to_vec(),
            }),
        }
    }

    pub fn add(&mut self, stream: Stream, mut data: &[u8]) {
        let room = self.limit - self.head_bytes;
        if room > 0 && !data.is_empty() {
            let take = room.min(data.len());
            Self::append(&mut self.head, self.total, stream, &data[..take]);
            self.head_bytes += take;
            self.total += take as u64;
            data = &data[take..];
        }
        if data.is_empty() {
            return;
        }
        let start = self.total;
        self.total += data.len() as u64;
        // Only the last `limit` bytes of what comes now can stay.
        if data.len() > self.limit {
            let skip = data.len() - self.limit;
            data = &data[skip..];
            self.tail.clear();
            self.tail_bytes = 0;
            self.tail.push_back(Chunk {
                start: start + skip as u64,
                stream,
                data: data.to_vec(),
            });
            self.tail_bytes = data.len();
            return;
        }
        match self.tail.back_mut() {
            Some(last) if last.stream == stream && last.end() == start && last.data.len() < 1 << 16 => {
                last.data.extend_from_slice(data)
            }
            _ => self.tail.push_back(Chunk {
                start,
                stream,
                data: data.to_vec(),
            }),
        }
        self.tail_bytes += data.len();
        while self.tail_bytes > self.limit {
            let over = self.tail_bytes - self.limit;
            let Some(front) = self.tail.front_mut() else {
                break;
            };
            if front.data.len() <= over {
                self.tail_bytes -= front.data.len();
                self.tail.pop_front();
            } else {
                front.data.drain(..over);
                front.start += over as u64;
                self.tail_bytes -= over;
            }
        }
    }

    /// The output from `cursor` on, at most about `max_bytes` of it. While
    /// the exec runs (`ended` false), a character cut at the end of what
    /// is there is held back for the next read, so that the text of a
    /// multi-byte character is never split between reads; past that,
    /// output is decoded as UTF-8 with invalid bytes replaced. A cursor
    /// past the end reads nothing from the end.
    pub fn read(&self, cursor: u64, max_bytes: usize, ended: bool) -> Read {
        let mut cursor = cursor.min(self.total);
        let mut events: Vec<OutputEvent> = Vec::new();
        let mut budget = max_bytes;
        let chunks = self.head.iter().chain(self.tail.iter());
        let mut pieces: Vec<(Stream, &[u8])> = Vec::new();
        for chunk in chunks {
            if chunk.end() <= cursor || budget == 0 {
                continue;
            }
            if chunk.start > cursor {
                // The dropped middle.
                flush(&mut events, &mut pieces);
                events.push(OutputEvent::Omitted {
                    bytes: chunk.start - cursor,
                });
                cursor = chunk.start;
            }
            let from = (cursor - chunk.start) as usize;
            let take = (chunk.data.len() - from).min(budget);
            pieces.push((chunk.stream, &chunk.data[from..from + take]));
            cursor += take as u64;
            budget -= take;
        }
        // Hold back a character cut at the end, unless nothing more will
        // come. (`max_bytes` is far larger than a character, so a read cut
        // by it still makes progress.)
        if let Some((_, last)) = pieces.last_mut() {
            let cut = incomplete_tail(last);
            let at_end = cursor == self.total;
            if cut > 0 && !(ended && at_end) {
                *last = &last[..last.len() - cut];
                cursor -= cut as u64;
            }
        }
        flush(&mut events, &mut pieces);
        Read {
            events,
            next_cursor: cursor,
        }
    }
}

/// Turns consecutive pieces of the same stream into one event each.
fn flush(events: &mut Vec<OutputEvent>, pieces: &mut Vec<(Stream, &[u8])>) {
    let mut i = 0;
    while i < pieces.len() {
        let stream = pieces[i].0;
        let mut bytes = Vec::new();
        while i < pieces.len() && pieces[i].0 == stream {
            bytes.extend_from_slice(pieces[i].1);
            i += 1;
        }
        if bytes.is_empty() {
            continue;
        }
        let data = String::from_utf8_lossy(&bytes).into_owned();
        events.push(match stream {
            Stream::Stdout => OutputEvent::Stdout { data },
            Stream::Stderr => OutputEvent::Stderr { data },
        });
    }
    pieces.clear();
}

/// How many bytes at the end of `data` are the start of a UTF-8 character
/// whose rest is missing.
fn incomplete_tail(data: &[u8]) -> usize {
    for back in 1..=3.min(data.len()) {
        let b = data[data.len() - back];
        if b & 0xC0 == 0x80 {
            continue;
        }
        let need = match b {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => return 0,
        };
        return if need > back { back } else { 0 };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(events: &[OutputEvent]) -> String {
        events
            .iter()
            .map(|e| match e {
                OutputEvent::Stdout { data } => format!("o:{data}|"),
                OutputEvent::Stderr { data } => format!("e:{data}|"),
                OutputEvent::Omitted { bytes } => format!("[{bytes}]|"),
            })
            .collect()
    }

    #[test]
    fn a_capture_keeps_head_and_tail() {
        let mut c = Capture::new(10);
        c.add(b"0123");
        assert_eq!(c.result(), (b"0123".to_vec(), false));
        c.add(b"456789");
        assert_eq!(c.result(), (b"0123456789".to_vec(), false));
        c.add(b"abc");
        let (out, cut) = c.result();
        assert!(cut);
        assert_eq!(out, b"01234\n[... 3 bytes omitted ...]\n89abc");
        for _ in 0..1000 {
            c.add(b"xyz");
        }
        c.add(b"VWXYZ");
        assert_eq!(c.total(), 3018);
        assert_eq!(c.result().0, b"01234\n[... 3008 bytes omitted ...]\nVWXYZ");
        // One write larger than the whole limit.
        let mut big = Capture::new(4);
        big.add(&[b'a'; 100]);
        big.add(b"tail");
        assert_eq!(big.result().0, b"aa\n[... 100 bytes omitted ...]\nil");
    }

    #[test]
    fn the_log_interleaves_and_reads_from_a_cursor() {
        let mut log = StreamLog::new(100);
        log.add(Stream::Stdout, b"a1\n");
        log.add(Stream::Stderr, b"b1\n");
        log.add(Stream::Stdout, b"a2\n");
        log.add(Stream::Stdout, b"a3\n");
        let r = log.read(0, 1024, false);
        assert_eq!(text(&r.events), "o:a1\n|e:b1\n|o:a2\na3\n|");
        assert_eq!(r.next_cursor, 12);
        let r = log.read(6, 1024, false);
        assert_eq!(text(&r.events), "o:a2\na3\n|");
        // A small budget, then the rest.
        let r = log.read(0, 4, false);
        assert_eq!(text(&r.events), "o:a1\n|e:b|");
        let r = log.read(r.next_cursor, 1024, false);
        assert_eq!(text(&r.events), "e:1\n|o:a2\na3\n|");
        // Nothing new: nothing, at the same cursor; past the end too.
        let r = log.read(12, 1024, false);
        assert!(r.events.is_empty());
        assert_eq!(r.next_cursor, 12);
        assert_eq!(log.read(99, 1024, false).next_cursor, 12);
    }

    #[test]
    fn a_reader_left_behind_is_told_what_it_missed() {
        let mut log = StreamLog::new(10);
        log.add(Stream::Stdout, b"0123456789");
        log.add(Stream::Stdout, b"ABCDEFGHIJ");
        for _ in 0..10 {
            log.add(Stream::Stderr, b"zzzzzzzzzz");
        }
        log.add(Stream::Stdout, b"0123");
        log.add(Stream::Stderr, b"456789");
        assert_eq!(log.total(), 130);
        // Held: the first 10 and the last 10 bytes.
        let held: usize = log.head.iter().chain(log.tail.iter()).map(|c| c.data.len()).sum();
        assert_eq!(held, 20);
        let r = log.read(0, 1024, false);
        assert_eq!(text(&r.events), "o:0123456789|[110]|o:0123|e:456789|");
        assert_eq!(r.next_cursor, 130);
        let r = log.read(15, 1024, true);
        assert_eq!(text(&r.events), "[105]|o:0123|e:456789|");
        // One write far larger than what is held.
        let mut log = StreamLog::new(4);
        log.add(Stream::Stdout, &[b'x'; 1000]);
        let r = log.read(0, 1024, true);
        assert_eq!(text(&r.events), "o:xxxx|[992]|o:xxxx|");
    }

    #[test]
    fn characters_are_not_split_between_reads() {
        let mut log = StreamLog::new(100);
        let snow = "☃".as_bytes();
        log.add(Stream::Stdout, b"ab");
        log.add(Stream::Stdout, &snow[..2]);
        // Running: the cut character waits.
        let r = log.read(0, 1024, false);
        assert_eq!(text(&r.events), "o:ab|");
        assert_eq!(r.next_cursor, 2);
        log.add(Stream::Stdout, &snow[2..]);
        let r = log.read(2, 1024, false);
        assert_eq!(text(&r.events), "o:☃|");
        // Cut by the budget: the same.
        let r = log.read(0, 3, false);
        assert_eq!(text(&r.events), "o:ab|");
        // Ended with half a character: it is replaced, not held for ever.
        let mut log = StreamLog::new(100);
        log.add(Stream::Stdout, &snow[..2]);
        let r = log.read(0, 1024, true);
        assert_eq!(text(&r.events), "o:\u{fffd}|");
        assert_eq!(r.next_cursor, 2);
        // Only a cut character there, still running: wait for the rest.
        let r = log.read(0, 1024, false);
        assert!(r.events.is_empty());
        assert_eq!(r.next_cursor, 0);
        assert_eq!(incomplete_tail(b"a\xe2\x98"), 2);
        assert_eq!(incomplete_tail("a☃".as_bytes()), 0);
        assert_eq!(incomplete_tail(b"\xff"), 0);
    }
}
