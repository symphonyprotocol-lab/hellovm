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
//!  6      2   flags (little endian): bit 0, the sandbox id below is set;
//!             bit 1, a fourth fd is attached (the ingress channel)
//!  8      8   sandbox id (little endian; random when bit 0 is clear)
//! 16      4   length N of the clone's input (little endian), at most MAX_INPUT
//! 20      N   the clone's input
//! ```
//!
//! A clone request carries exactly three fds in an `SCM_RIGHTS` message with
//! its first bytes: the clone's stdin, stdout and stderr (any readable and
//! writable fds: pipes, files, sockets, a pty); with flag bit 1, a fourth:
//! the clone's ingress channel.
//!
//! The ingress channel is a connected Unix stream socket the requester
//! keeps the other end of. Over it the requester hands the clone's kernel
//! process inbound connections to guest ports: each message is the port
//! (2 bytes, little endian) with one fd attached in `SCM_RIGHTS`, a
//! connected stream socket. The kernel process queues it on the guest's
//! listener for that port or refuses it, and the first byte the other end
//! of that connection reads is the verdict: `A` (accepted; the guest's
//! bytes follow) or `R` (refused; it closes). The channel carries nothing
//! the other way. A message that is not exactly that ends the channel.
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
//! they get `E` with the reason and the template exits. A request must be
//! complete within [`REQUEST_TIMEOUT`] of connecting, or it gets `E`.

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
/// How long after connecting a request may take to arrive completely. A
/// connection that sends nothing must not hold one of the template's
/// connection slots for ever.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const FLAG_SANDBOX_ID: u16 = 1;
const FLAG_INGRESS: u16 = 2;
/// Longest frame payload a client accepts.
const MAX_FRAME: u32 = 64 * 1024;

/// Flags of [`send_frame`]'s sends: no `SIGPIPE` when the requester is
/// gone. macOS has no such flag (a Rust program ignores `SIGPIPE` anyway,
/// and [`no_sigpipe`] sets the socket option); there the send never
/// blocks either: the template's process serves every connection, and
/// shares each with a clone's kernel process, which needs it blocking.
#[cfg(target_os = "linux")]
const FRAME_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const FRAME_FLAGS: libc::c_int = libc::MSG_DONTWAIT;

/// Flags of [`send_with_fds`].
#[cfg(target_os = "linux")]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: libc::c_int = 0;

/// Makes writes to a closed connection fail with `EPIPE` instead of
/// raising `SIGPIPE` (macOS: `SO_NOSIGPIPE`; Linux passes `MSG_NOSIGNAL`
/// with every send instead).
pub fn no_sigpipe(stream: &UnixStream) -> io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let on: libc::c_int = 1;
        // SAFETY: a valid socket and option value.
        let ret = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "linux")]
    let _ = stream;
    Ok(())
}

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
    /// A fourth fd, the ingress channel, comes with it.
    pub ingress: bool,
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
        let mut flags = if self.sandbox_id.is_some() {
            FLAG_SANDBOX_ID
        } else {
            0
        };
        if self.ingress {
            flags |= FLAG_INGRESS;
        }
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
        if flags & !(FLAG_SANDBOX_ID | FLAG_INGRESS) != 0 {
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
            ingress: flags & FLAG_INGRESS != 0,
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

/// Sends one frame, all of it, on a connection that may be non-blocking
/// (the template's are, and a clone's kernel process shares its
/// connection's open file with the template): when the socket's buffer is
/// full it waits for room until `patience` is over. An error means the
/// requester did not get the frame.
pub fn send_frame(
    stream: &UnixStream,
    frame: &Frame,
    patience: std::time::Duration,
) -> io::Result<()> {
    let bytes = frame.encode();
    let deadline = std::time::Instant::now() + patience;
    let mut sent = 0;
    while sent < bytes.len() {
        let rest = &bytes[sent..];
        // SAFETY: the buffer is valid for its length.
        let n = unsafe {
            libc::send(
                stream.as_raw_fd(),
                rest.as_ptr().cast(),
                rest.len(),
                FRAME_FLAGS,
            )
        };
        if n >= 0 {
            sent += n as usize;
            continue;
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::WouldBlock => {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the requester does not read its answers",
                    ));
                }
                let mut poll = libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let ms = left.as_millis().clamp(1, 1000) as libc::c_int;
                // SAFETY: one valid pollfd. A failure shows at the next send.
                unsafe { libc::poll(&mut poll, 1, ms) };
            }
            _ => return Err(err),
        }
    }
    Ok(())
}

/// Overwrites `bytes` with zeros in a way the compiler keeps even though
/// the buffer is freed next: request bytes of one tenant must not stay in
/// memory that a later clone (a fork of the template) starts with.
pub fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
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
        let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, SEND_FLAGS) };
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
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    // macOS has no such flag: close-on-exec is set below, before this
    // returns (nothing in a hellovm process spawns meanwhile).
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: valid buffers for the call.
    let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, flags) };
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
                    #[cfg(not(target_os = "linux"))]
                    libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
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
        Self::request_with(socket, sandbox_id, input, stdio, None)
    }

    /// [`WarmClone::request`], with the clone's ingress channel when
    /// `ingress` is given (see the module documentation).
    pub fn request_with(
        socket: &Path,
        sandbox_id: Option<u64>,
        input: &[u8],
        stdio: [BorrowedFd<'_>; 3],
        ingress: Option<BorrowedFd<'_>>,
    ) -> io::Result<WarmClone> {
        if input.len() > MAX_INPUT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("clone input longer than {MAX_INPUT} bytes"),
            ));
        }
        let stream = UnixStream::connect(socket)?;
        no_sigpipe(&stream)?;
        let request = Request {
            kind: Kind::Clone,
            sandbox_id,
            ingress: ingress.is_some(),
            input: input.to_vec(),
        };
        let mut fds = stdio.map(|fd| fd.as_raw_fd()).to_vec();
        fds.extend(ingress.map(|fd| fd.as_raw_fd()));
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
    no_sigpipe(&stream)?;
    let request = Request {
        kind: Kind::Ping,
        sandbox_id: None,
        ingress: false,
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
            ingress: true,
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
            ingress: false,
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
    fn a_frame_to_a_requester_that_does_not_read_fails_instead_of_vanishing() {
        let (a, mut b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let frame = Frame::Error("x".repeat(4096));
        let patience = std::time::Duration::from_millis(50);
        // Fill the socket: at some point a frame no longer fits.
        let mut sent = 0;
        let err = loop {
            match send_frame(&a, &frame, patience) {
                Ok(()) => sent += 1,
                Err(err) => break err,
            }
            assert!(sent < 100_000, "the socket never filled");
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // A reader that comes back gets whole frames again: with room, a
        // frame is sent completely even though the socket is non-blocking.
        let reader = std::thread::spawn(move || {
            let mut frames = 0;
            while let Ok(Some(_)) = Frame::read_from(&mut b) {
                frames += 1;
            }
            frames
        });
        // The frame cut short by the timeout makes the stream unusable for
        // the reader at that point; what counts is that every frame
        // reported as sent arrived whole.
        drop(a);
        assert!(reader.join().unwrap() >= sent);
    }

    #[test]
    fn wipe_zeroes() {
        let mut secret = b"tenant input".to_vec();
        wipe(&mut secret);
        assert!(secret.iter().all(|&b| b == 0));
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
