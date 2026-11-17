//! The warm-clone control protocol, spoken on the Unix socket of
//! `hellovm --template SOCKET`, and a client for it (used by
//! `hellovm --clone SOCKET` and meant for the node daemon).
//!
//! One connection is one request. The client sends one request message:
//!
//! ```text
//! offset size
//!  0      4   magic "HVMC"
//!  4      1   version, 1
//!  5      1   kind: b'C' make a clone, b'P' wait until the template is ready
//!  6      2   flags (little endian): bit 0, the sandbox id below is set
//!  8      8   sandbox id (little endian; random when bit 0 is clear)
//! 16      4   length N of the clone's input (little endian), at most MAX_INPUT
//! 20      N   the clone's input
//! ```
//!
//! A clone request carries exactly three fds in an `SCM_RIGHTS` message with
//! its first bytes: the clone's stdin, stdout and stderr (any readable and
//! writable fds: pipes, files, sockets, a pty).
//!
//! The answers are frames, `[type: u8][length: u32 LE][payload]`:
//!
//! | Type | Payload | Meaning |
//! |---|---|---|
//! | `R` | stored bytes u64, areas u32 | the template is frozen and ready (answer to `P`) |
//! | `S` | sandbox id u64, kernel pid u32 | the clone exists and its first instruction runs now |
//! | `X` | kind u8 (0 exited, 1 killed by signal), code u32 | the clone ended |
//! | `E` | UTF-8 text | the request failed, or the clone's kernel process died |
//!
//! A clone request gets `S` and later `X`, or `E`. The connection then
//! closes. The clone lives only as long as the connection: closing it (or
//! shutting down its write side) kills the clone. Requests that arrive
//! before the template is frozen wait; if the template cannot be frozen,
//! they get `E` with the reason and the template exits.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

pub const MAGIC: &[u8; 4] = b"HVMC";
pub const VERSION: u8 = 1;
/// Length of a request without the input.
pub const HEADER_LEN: usize = 20;
/// Most bytes of input a clone request may carry. More goes to its stdin.
pub const MAX_INPUT: usize = 64 * 1024;
const FLAG_SANDBOX_ID: u16 = 1;
/// Longest frame payload a client accepts.
const MAX_FRAME: u32 = 64 * 1024;

/// What a request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Clone,
    Ping,
}

/// A parsed request (without its fds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub kind: Kind,
    pub sandbox_id: Option<u64>,
    pub input: Vec<u8>,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.input.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(match self.kind {
            Kind::Clone => b'C',
            Kind::Ping => b'P',
        });
        let flags = if self.sandbox_id.is_some() {
            FLAG_SANDBOX_ID
        } else {
            0
        };
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&self.sandbox_id.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&(self.input.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.input);
        out
    }

    /// Parses a request from the start of `buf`: `Ok(None)` while it is
    /// incomplete, the request and its length when complete.
    pub fn decode(buf: &[u8]) -> Result<Option<(Request, usize)>, String> {
        if buf.len() >= 4 && &buf[..4] != MAGIC {
            return Err("not a hellovm warm-clone request".into());
        }
        if buf.len() >= 5 && buf[4] != VERSION {
            return Err(format!("unsupported protocol version {}", buf[4]));
        }
        if buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let kind = match buf[5] {
            b'C' => Kind::Clone,
            b'P' => Kind::Ping,
            other => return Err(format!("unknown request kind {other:#x}")),
        };
        let flags = u16::from_le_bytes([buf[6], buf[7]]);
        if flags & !FLAG_SANDBOX_ID != 0 {
            return Err(format!("unknown request flags {flags:#x}"));
        }
        let id = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let len = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
        if len > MAX_INPUT {
            return Err(format!("input of {len} bytes, more than {MAX_INPUT}"));
        }
        if buf.len() < HEADER_LEN + len {
            return Ok(None);
        }
        let request = Request {
            kind,
            sandbox_id: (flags & FLAG_SANDBOX_ID != 0).then_some(id),
            input: buf[HEADER_LEN..HEADER_LEN + len].to_vec(),
        };
        Ok(Some((request, HEADER_LEN + len)))
    }
}

/// How a clone's first process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Exited(u32),
    Signaled(u32),
}

impl Status {
    /// The exit code `hellovm` uses for it: the code, or 128 + signal.
    pub fn code(self) -> u8 {
        match self {
            Status::Exited(code) => code as u8,
            Status::Signaled(sig) => (128 + sig).min(255) as u8,
        }
    }
}

/// One answer frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Ready { stored: u64, areas: u32 },
    Started { sandbox_id: u64, pid: u32 },
    Exit(Status),
    Error(String),
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let (kind, payload): (u8, Vec<u8>) = match self {
            Frame::Ready { stored, areas } => {
                let mut p = stored.to_le_bytes().to_vec();
                p.extend_from_slice(&areas.to_le_bytes());
                (b'R', p)
            }
            Frame::Started { sandbox_id, pid } => {
                let mut p = sandbox_id.to_le_bytes().to_vec();
                p.extend_from_slice(&pid.to_le_bytes());
                (b'S', p)
            }
            Frame::Exit(status) => {
                let (k, code) = match status {
                    Status::Exited(c) => (0u8, *c),
                    Status::Signaled(s) => (1u8, *s),
                };
                let mut p = vec![k];
                p.extend_from_slice(&code.to_le_bytes());
                (b'X', p)
            }
            Frame::Error(text) => {
                let mut text = text.as_bytes().to_vec();
                text.truncate(MAX_FRAME as usize);
                (b'E', text)
            }
        };
        let mut out = vec![kind];
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Reads one frame; `Ok(None)` at end of stream.
    pub fn read_from(stream: &mut impl Read) -> io::Result<Option<Frame>> {
        let mut head = [0u8; 5];
        match stream.read_exact(&mut head) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err),
        }
        let len = u32::from_le_bytes(head[1..5].try_into().unwrap());
        if len > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too long"));
        }
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload)?;
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed frame");
        let u32_at = |p: &[u8], at: usize| -> io::Result<u32> {
            Ok(u32::from_le_bytes(
                p.get(at..at + 4).ok_or_else(bad)?.try_into().unwrap(),
            ))
        };
        let u64_at = |p: &[u8], at: usize| -> io::Result<u64> {
            Ok(u64::from_le_bytes(
                p.get(at..at + 8).ok_or_else(bad)?.try_into().unwrap(),
            ))
        };
        Ok(Some(match head[0] {
            b'R' => Frame::Ready {
                stored: u64_at(&payload, 0)?,
                areas: u32_at(&payload, 8)?,
            },
            b'S' => Frame::Started {
                sandbox_id: u64_at(&payload, 0)?,
                pid: u32_at(&payload, 8)?,
            },
            b'X' => {
                let code = u32_at(&payload, 1)?;
                Frame::Exit(match payload.first() {
                    Some(0) => Status::Exited(code),
                    Some(1) => Status::Signaled(code),
                    _ => return Err(bad()),
                })
            }
            b'E' => Frame::Error(String::from_utf8_lossy(&payload).into_owned()),
            _ => return Err(bad()),
        }))
    }
}

/// Sends `data` with `fds` attached (`SCM_RIGHTS`), all of it.
pub fn send_with_fds(stream: &UnixStream, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut sent = 0;
    while sent < data.len() {
        let iov = libc::iovec {
            iov_base: data[sent..].as_ptr() as *mut libc::c_void,
            iov_len: data.len() - sent,
        };
        let attach = sent == 0 && !fds.is_empty();
        let fd_bytes = std::mem::size_of_val(fds);
        // SAFETY: CMSG_SPACE is a pure computation.
        let space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
        let mut control = vec![0u64; space.div_ceil(8)];
        // SAFETY: an all-zero msghdr is valid; the pointers set below
        // outlive the call.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
        msg.msg_iovlen = 1;
        if attach {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            // SAFETY: the control buffer has room for one header with
            // `fds.len()` fds.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr(),
                    libc::CMSG_DATA(cmsg) as *mut RawFd,
                    fds.len(),
                );
            }
        }
        // SAFETY: a valid message on a valid socket.
        let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        sent += n as usize;
    }
    Ok(())
}

/// Receives into `buf`, appending any fds that came with the bytes to
/// `fds` (close-on-exec). Returns the bytes read (0 at end of stream).
/// More than `max_fds` fds in total is an error (the extra ones are
/// closed).
pub fn recv_with_fds(
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
    fds: &mut Vec<OwnedFd>,
    max_fds: usize,
) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // Room for a few more fds than allowed, to see that there were more.
    let want = (max_fds + 4) * std::mem::size_of::<RawFd>();
    // SAFETY: CMSG_SPACE is a pure computation.
    let space = unsafe { libc::CMSG_SPACE(want as u32) } as usize;
    let mut control = vec![0u64; space.div_ceil(8)];
    // SAFETY: an all-zero msghdr is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: valid buffers for the call.
    let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut too_many = msg.msg_flags & libc::MSG_CTRUNC != 0;
    // SAFETY: walking the control messages the host wrote.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg) as *const RawFd;
                let count = ((*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    let fd = OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i)));
                    if fds.len() < max_fds {
                        fds.push(fd);
                    } else {
                        too_many = true;
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    if too_many {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("more than {max_fds} fds attached"),
        ));
    }
    Ok(n as usize)
}

/// A clone, as its requester sees it. Dropping it closes the connection,
/// which kills the clone.
#[derive(Debug)]
pub struct WarmClone {
    stream: UnixStream,
}

/// What [`WarmClone::start`] learns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Started {
    pub sandbox_id: u64,
    /// The clone's kernel process, as the host numbers it.
    pub pid: u32,
}

fn protocol_error(frame: Option<Frame>, waiting_for: &str) -> io::Error {
    match frame {
        Some(Frame::Error(text)) => io::Error::other(text),
        Some(other) => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected {other:?} while waiting for {waiting_for}"),
        ),
        None => io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("the template closed the connection before {waiting_for}"),
        ),
    }
}

impl WarmClone {
    /// Asks the template listening at `socket` for a clone whose console is
    /// `stdio` (stdin, stdout, stderr) and whose clone point returns
    /// `input`. Returns once the request is sent; [`WarmClone::start`] waits
    /// for the clone to run.
    pub fn request(
        socket: &Path,
        sandbox_id: Option<u64>,
        input: &[u8],
        stdio: [BorrowedFd<'_>; 3],
    ) -> io::Result<WarmClone> {
        if input.len() > MAX_INPUT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("clone input longer than {MAX_INPUT} bytes"),
            ));
        }
        let stream = UnixStream::connect(socket)?;
        let request = Request {
            kind: Kind::Clone,
            sandbox_id,
            input: input.to_vec(),
        };
        let fds = stdio.map(|fd| fd.as_raw_fd());
        send_with_fds(&stream, &request.encode(), &fds)?;
        Ok(WarmClone { stream })
    }

    /// Waits until the clone runs (frame `S`).
    pub fn start(&mut self) -> io::Result<Started> {
        match Frame::read_from(&mut self.stream)? {
            Some(Frame::Started { sandbox_id, pid }) => Ok(Started { sandbox_id, pid }),
            other => Err(protocol_error(other, "the clone to start")),
        }
    }

    /// Waits until the clone ends (frame `X`).
    pub fn wait(&mut self) -> io::Result<Status> {
        match Frame::read_from(&mut self.stream)? {
            Some(Frame::Exit(status)) => Ok(status),
            other => Err(protocol_error(other, "the clone to end")),
        }
    }

    /// The connection, e.g. to poll it.
    pub fn stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Kills the clone by closing the connection.
    pub fn kill(self) {}
}

/// Waits until the template listening at `socket` is frozen, and returns
/// how much of its memory the snapshot holds (bytes and areas).
pub fn wait_ready(socket: &Path) -> io::Result<(u64, u32)> {
    let mut stream = UnixStream::connect(socket)?;
    let request = Request {
        kind: Kind::Ping,
        sandbox_id: None,
        input: Vec::new(),
    };
    stream.write_all(&request.encode())?;
    match Frame::read_from(&mut stream)? {
        Some(Frame::Ready { stored, areas }) => Ok((stored, areas)),
        other => Err(protocol_error(other, "the template to be ready")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_and_reject_garbage() {
        let request = Request {
            kind: Kind::Clone,
            sandbox_id: Some(0x1234_5678_9abc_def0),
            input: b"print(1)".to_vec(),
        };
        let bytes = request.encode();
        for cut in 0..bytes.len() {
            assert_eq!(Request::decode(&bytes[..cut]).unwrap(), None, "{cut}");
        }
        let (back, len) = Request::decode(&bytes).unwrap().unwrap();
        assert_eq!((back, len), (request, bytes.len()));
        assert!(Request::decode(b"HTTP/1.1 ...").is_err());
        let mut long = Request {
            kind: Kind::Ping,
            sandbox_id: None,
            input: vec![0; MAX_INPUT + 1],
        }
        .encode();
        assert!(Request::decode(&long).is_err());
        long[5] = b'Z';
        assert!(Request::decode(&long).is_err());
    }

    #[test]
    fn frames_round_trip() {
        for frame in [
            Frame::Ready {
                stored: 1 << 33,
                areas: 7,
            },
            Frame::Started {
                sandbox_id: 42,
                pid: 4711,
            },
            Frame::Exit(Status::Exited(3)),
            Frame::Exit(Status::Signaled(9)),
            Frame::Error("no".into()),
        ] {
            let bytes = frame.encode();
            let back = Frame::read_from(&mut &bytes[..]).unwrap().unwrap();
            assert_eq!(back, frame);
        }
        assert_eq!(Frame::read_from(&mut &b""[..]).unwrap(), None);
        assert!(Frame::read_from(&mut &b"Q\x00\x00\x00\x00"[..]).is_err());
    }

    #[test]
    fn fds_travel_with_the_first_bytes() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, _w) = std::io::pipe().unwrap();
        use std::os::fd::AsFd;
        let raw = r.as_fd().as_raw_fd();
        send_with_fds(&a, b"hello", &[raw, raw, raw]).unwrap();
        let mut fds = Vec::new();
        let mut buf = [0u8; 16];
        let n = recv_with_fds(b.as_fd(), &mut buf, &mut fds, 3).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(fds.len(), 3);
        send_with_fds(&a, b"x", &[raw, raw, raw, raw]).unwrap();
        let mut more = Vec::new();
        assert!(recv_with_fds(b.as_fd(), &mut buf, &mut more, 3).is_err());
    }
}
