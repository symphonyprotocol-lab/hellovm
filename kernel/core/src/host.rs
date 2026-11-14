//! The host interface: what the kernel core needs from the OS it runs on.
//!
//! Everything the kernel does to the outside world goes through [`Host`], so
//! that the same core runs on a Linux or a macOS host. The operations are
//! deliberately narrow:
//!
//! * console output and input for the app's standard streams. Input never
//!   blocks the kernel: [`Host::console_read`] returns what has arrived and
//!   reports `WouldBlock` otherwise, and the host calls the [`Waker`] it was
//!   given when more arrives (the kernel serves every process of the
//!   sandbox from one thread and must not stall on one of them);
//! * read-only access to the image, the sandbox's lower filesystem layer,
//!   by [`ImagePath`]: a path the core has already resolved itself, made of
//!   plain names only (no `.`, `..`, empty components or `/`). The host
//!   never sees a path the guest supplied, never follows a symlink on the
//!   core's behalf (symlinks are reported, the core interprets them), and
//!   never writes to the image;
//! * random bytes and clocks. The kernel never sleeps itself: timeouts are
//!   deadlines on [`Host::clock_monotonic`] that bound its wait for app
//!   events;
//! * optional spliced byte streams ([`Host::open_stream`]). The kernel asks
//!   the host to connect to a configured endpoint and never passes a guest
//!   IP as a dial address. The connect, read, and write run off the kernel
//!   thread (`WouldBlock` plus a [`Waker`]), including a write-side
//!   half-close.
//!
//! Host errors are `std::io::Error`s; the core translates them by kind
//! ([`crate::errno::Errno::from_host`]), never by host errno number.

use std::fmt;
use std::io;
use std::time::Duration;

use crate::platform::Waker;

/// Identifies one host byte stream opened by [`Host::open_stream`].
///
/// The kernel treats the value as opaque. It never encodes a guest address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HostStreamId(pub u64);

/// Audit metadata for one outbound guest TCP flow.
///
/// The kernel passes this when it splices a connection onto the host. `dest_ip`
/// is the guest's destination and is **audit only**: an implementation must
/// not dial it. 002a dials the single configured endpoint (see
/// [`Host::egress_configured`]). 002b will dial the egress proxy's Unix
/// socket and send this metadata in the handshake, still without dialing
/// `dest_ip`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundFlow {
    /// Sandbox id. 002a passes 0; 002b will pass the real id.
    pub sandbox_id: u64,
    /// Guest pid that called `connect`.
    pub guest_pid: u32,
    /// Guest destination IPv4, network byte order. Never a dial address.
    pub dest_ip: [u8; 4],
    /// Guest destination port.
    pub dest_port: u16,
}

/// Non-blocking view of a host byte stream.
///
/// `readable` means a read returns data or EOF rather than `WouldBlock`.
/// `writable` means a short write can accept bytes. `broken` means the peer
/// is gone and further writes fail. `failed` means the connect itself failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamStatus {
    /// The connect attempt has finished, successfully or not.
    pub established: bool,
    /// The connect attempt failed. Implies `established`.
    pub failed: bool,
    pub readable: bool,
    pub writable: bool,
    pub broken: bool,
    /// The local write side has been shut down.
    pub shut_write: bool,
}

/// The sandbox console stream a guest write goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleStream {
    Stdout,
    Stderr,
}

/// A path inside the image, relative to its root. The empty path is the
/// root. Every component is a plain name: non-empty, without `/` or NUL,
/// and neither `.` nor `..`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ImagePath(Vec<u8>);

impl ImagePath {
    /// The image root.
    pub fn root() -> ImagePath {
        ImagePath(Vec::new())
    }

    /// Whether `name` may be a component of an image path.
    pub fn valid_name(name: &[u8]) -> bool {
        !name.is_empty()
            && name != b"."
            && name != b".."
            && !name.contains(&b'/')
            && !name.contains(&0)
    }

    /// This path with `name` appended, if `name` is a valid component.
    pub fn join(&self, name: &[u8]) -> Option<ImagePath> {
        if !Self::valid_name(name) {
            return None;
        }
        let mut path = self.0.clone();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(name);
        Some(ImagePath(path))
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The path as bytes (`a/b/c`; empty for the root).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The components, each a valid name.
    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.0.split(|&b| b == b'/').filter(|c| !c.is_empty())
    }
}

impl fmt::Display for ImagePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.0))
    }
}

/// The type of an image entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostFileKind {
    File,
    Directory,
    Symlink,
    /// Devices, sockets, FIFOs: present in the image but not usable.
    Other,
}

/// Metadata of an image entry (the entry itself, never a symlink target).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostStat {
    pub kind: HostFileKind,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    pub size: u64,
    pub nlink: u64,
    /// Modification time: seconds and nanoseconds since the Unix epoch.
    pub mtime: (i64, u32),
}

fn no_image() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no image")
}

pub trait Host {
    /// Writes guest output to the sandbox console. Returns how many bytes of
    /// `data` were accepted, like a host `write`.
    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize>;

    /// Reads console input (the app's standard input) that has already
    /// arrived. 0 is end of input; an error of kind `WouldBlock` means that
    /// nothing has arrived yet, and the waker set with
    /// [`Host::set_console_waker`] will be called when something does.
    fn console_read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }

    /// Sets the waker to call when console input arrives after
    /// [`Host::console_read`] reported `WouldBlock`.
    fn set_console_waker(&mut self, _waker: Waker) {}

    /// Whether there is an image at all. Without one, the sandbox
    /// filesystem starts empty.
    fn has_image(&self) -> bool {
        false
    }

    /// Metadata of an image entry, without following a final symlink.
    fn image_stat(&mut self, _path: &ImagePath) -> io::Result<HostStat> {
        Err(no_image())
    }

    /// The target of an image symlink, uninterpreted.
    fn image_read_link(&mut self, _path: &ImagePath) -> io::Result<Vec<u8>> {
        Err(no_image())
    }

    /// The names in an image directory, without `.` and `..`.
    fn image_read_dir(&mut self, _path: &ImagePath) -> io::Result<Vec<Vec<u8>>> {
        Err(no_image())
    }

    /// Reads from an image file at `offset`; 0 is end of file.
    fn image_read(
        &mut self,
        _path: &ImagePath,
        _offset: u64,
        _buf: &mut [u8],
    ) -> io::Result<usize> {
        Err(no_image())
    }

    /// Fills `buf` with cryptographically secure random bytes.
    fn random(&mut self, buf: &mut [u8]) -> io::Result<()>;

    /// Wall-clock time since the Unix epoch.
    fn clock_realtime(&mut self) -> Duration;

    /// A monotonic clock, starting at some arbitrary point.
    fn clock_monotonic(&mut self) -> Duration;

    /// Whether an outbound splice endpoint is configured.
    ///
    /// 002a: a local TCP server set by the host (the `--splice-to` flag).
    /// 002b: the egress Unix socket (`--egress`). When this is false, a
    /// guest `connect` to an issued fake IP fails with `ENETUNREACH` and
    /// the kernel does not call [`Host::open_stream`].
    fn egress_configured(&self) -> bool {
        false
    }

    /// Opens a byte stream to the **configured** endpoint for `flow`.
    ///
    /// Must not block the caller and must not dial `flow.dest_ip`. The
    /// connect itself runs off the kernel thread. [`Host::stream_connect_result`]
    /// reports `WouldBlock` until it finishes; the `waker` is called when
    /// the result, or later readability or room for a write, may have changed.
    ///
    /// The default refuses: no endpoint is configured.
    fn open_stream(&mut self, flow: OutboundFlow, waker: Waker) -> io::Result<HostStreamId> {
        let _ = (flow, waker);
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no splice endpoint configured",
        ))
    }

    /// Whether `id`'s connect has finished.
    ///
    /// `Ok(())` means the stream is connected. `WouldBlock` means the
    /// attempt is still running. Any other error is a failed connect (the
    /// guest observes it as `SO_ERROR`).
    fn stream_connect_result(&mut self, id: HostStreamId) -> io::Result<()> {
        let _ = id;
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no splice endpoint configured",
        ))
    }

    /// Current readiness. Does not consume bytes.
    fn stream_status(&mut self, id: HostStreamId) -> io::Result<StreamStatus> {
        let _ = id;
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no splice endpoint configured",
        ))
    }

    /// Reads bytes the peer has already sent. 0 is EOF (the peer half-closed
    /// or closed). `WouldBlock` means nothing is buffered yet.
    fn stream_read(&mut self, id: HostStreamId, buf: &mut [u8]) -> io::Result<usize> {
        let _ = (id, buf);
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no splice endpoint configured",
        ))
    }

    /// Writes bytes toward the peer. `WouldBlock` means the buffer is full.
    /// `BrokenPipe` or `ConnectionReset` means the peer is gone: the guest
    /// observes `EPIPE`.
    fn stream_write(&mut self, id: HostStreamId, data: &[u8]) -> io::Result<usize> {
        let _ = (id, data);
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no splice endpoint configured",
        ))
    }

    /// Half-closes the write side. The peer reads EOF; the guest can still
    /// receive. Further writes fail.
    fn stream_shutdown_write(&mut self, id: HostStreamId) -> io::Result<()> {
        let _ = id;
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no splice endpoint configured",
        ))
    }

    /// Drops the stream. Further use of `id` fails. Idempotent.
    fn stream_close(&mut self, id: HostStreamId) {
        let _ = id;
    }
}

impl<H: Host + ?Sized> Host for &mut H {
    fn console_write(&mut self, stream: ConsoleStream, data: &[u8]) -> io::Result<usize> {
        (**self).console_write(stream, data)
    }
    fn console_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).console_read(buf)
    }
    fn set_console_waker(&mut self, waker: Waker) {
        (**self).set_console_waker(waker)
    }
    fn has_image(&self) -> bool {
        (**self).has_image()
    }
    fn image_stat(&mut self, path: &ImagePath) -> io::Result<HostStat> {
        (**self).image_stat(path)
    }
    fn image_read_link(&mut self, path: &ImagePath) -> io::Result<Vec<u8>> {
        (**self).image_read_link(path)
    }
    fn image_read_dir(&mut self, path: &ImagePath) -> io::Result<Vec<Vec<u8>>> {
        (**self).image_read_dir(path)
    }
    fn image_read(&mut self, path: &ImagePath, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).image_read(path, offset, buf)
    }
    fn random(&mut self, buf: &mut [u8]) -> io::Result<()> {
        (**self).random(buf)
    }
    fn clock_realtime(&mut self) -> Duration {
        (**self).clock_realtime()
    }
    fn clock_monotonic(&mut self) -> Duration {
        (**self).clock_monotonic()
    }
    fn egress_configured(&self) -> bool {
        (**self).egress_configured()
    }
    fn open_stream(&mut self, flow: OutboundFlow, waker: Waker) -> io::Result<HostStreamId> {
        (**self).open_stream(flow, waker)
    }
    fn stream_connect_result(&mut self, id: HostStreamId) -> io::Result<()> {
        (**self).stream_connect_result(id)
    }
    fn stream_status(&mut self, id: HostStreamId) -> io::Result<StreamStatus> {
        (**self).stream_status(id)
    }
    fn stream_read(&mut self, id: HostStreamId, buf: &mut [u8]) -> io::Result<usize> {
        (**self).stream_read(id, buf)
    }
    fn stream_write(&mut self, id: HostStreamId, data: &[u8]) -> io::Result<usize> {
        (**self).stream_write(id, data)
    }
    fn stream_shutdown_write(&mut self, id: HostStreamId) -> io::Result<()> {
        (**self).stream_shutdown_write(id)
    }
    fn stream_close(&mut self, id: HostStreamId) {
        (**self).stream_close(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_paths_only_hold_plain_names() {
        let root = ImagePath::root();
        assert!(root.is_root());
        let p = root.join(b"etc").unwrap().join(b"passwd").unwrap();
        assert_eq!(p.as_bytes(), b"etc/passwd");
        assert_eq!(
            p.components().collect::<Vec<_>>(),
            vec![&b"etc"[..], b"passwd"]
        );
        for bad in [&b""[..], b".", b"..", b"a/b", b"a\0"] {
            assert!(root.join(bad).is_none(), "{bad:?}");
        }
        assert!(root.join(b"...").is_some());
    }
}
