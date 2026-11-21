//! `hellovm --template SOCKET` on macOS (the HVF platform): a warm-clone
//! template and its clones, with the protocol of `hellovm::warm`.
//!
//! A Hypervisor.framework VM does not survive `fork`, and a process has
//! one, so a clone cannot be a fork of the template's kernel process as on
//! Linux. Three kinds of process instead, each a `hellovm` started from
//! its own executable (see README, "Warm clones on macOS"):
//!
//! * The *supervisor* (`hellovm --template`) binds the socket, makes the
//!   snapshot (a POSIX shared memory object) and starts the template's
//!   kernel process. Once the template is frozen it serves the socket:
//!   for each clone request it starts a clone's kernel process. It runs no
//!   guest code, makes no VM and reads no byte any kernel process wrote:
//!   only the frozen message of the template's (fixed size) and the exit
//!   statuses of all of them.
//! * The *template's kernel process* (`--warm-role template`) runs the
//!   program like any sandbox, hardened the same way, until its clone
//!   point; then it writes the frozen state into the snapshot (the kernel
//!   state, the page tables, the app memory that is not zero), reports it
//!   and exits.
//! * A *clone's kernel process* (`--warm-role clone`) gets the request,
//!   the requester's fds and the snapshot (read only) from the
//!   supervisor, makes its VM, loads the page tables and the kernel state,
//!   hardens itself like any sandbox, and runs the clone: app memory comes
//!   from the snapshot page by page as the clone touches it. It sends `S`
//!   and `X` (or `E`) on the requester's connection itself.
//!
//! Each kernel process talks to the supervisor over a socket pair that is
//! its stdin. When the supervisor dies (the socket closes) or stops a
//! clone because its requester went away (it sends a byte), the kernel
//! process ends its apps with the platform's killer, as `--timeout` does,
//! and exits; only one that has not exited 10 s later is killed.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hellovm::warm::{self, Frame, Kind, Request, Status};
use hellovm_core::{Kernel, KernelError, TemplateEnd};
use hellovm_host::{ImageDir, StdioHost};
use hellovm_platform_hvf::{HvfConfig, HvfPlatform, SharedMap};

use crate::{egress_socket, harden, Ended, Options, EXIT_DRAIN};

/// Most connections served at once (clones and requests being read). Each
/// clone is a process with a VM of its own.
const MAX_CLIENTS: usize = 128;

/// The supervisor's soft fd limit: per connection the connection, the
/// clone's control socket and, while a request is read, its fds.
const SUPERVISOR_NOFILE: u64 = 1024;

/// Exit status of a clone's kernel process that has reported an error
/// itself (frame `E`).
const CLONE_FAILED: i32 = 3;

/// How long a clone's kernel process may block sending its `S`, `X` or
/// `E` when the requester does not read them (`SO_SNDTIMEO`).
const FRAME_PATIENCE: Duration = Duration::from_secs(5);

/// How long the template's kernel process may take to exit after it
/// reported the frozen template, and a kernel process to exit once told to
/// stop, before it is killed.
const EXIT_PATIENCE: Duration = Duration::from_secs(10);

/// How often the supervisor looks whether a kernel process that closed
/// its control socket has exited.
const REAP_EVERY: Duration = Duration::from_millis(2);

/// The roles of a kernel process (`--warm-role`).
pub const ROLE_TEMPLATE: &str = "template";
pub const ROLE_CLONE: &str = "clone";

/// The snapshot: one POSIX shared memory object, four regions.
///
/// ```text
/// offset                        size
/// 0                             HEADER      the header (below), written last
/// HEADER                        state       the kernel state, then the platform's state
/// HEADER + state                tables      the page tables
/// HEADER + state + tables       ram         app memory, each frame at its own offset
/// ```
#[derive(Clone, Copy, Debug)]
struct Layout {
    state: u64,
    tables: u64,
    ram: u64,
}

const HEADER: u64 = 16 * 1024;
/// Room for the kernel state beyond the writable layer's limit: pipes
/// (64 MiB at most), sockets, `/proc` contents, the platform's state.
const STATE_SLACK: u64 = 256 << 20;
const SNAPSHOT_MAGIC: &[u8; 8] = b"HVMSNAP1";

impl Layout {
    /// For a template with `options`: the VM's default size (clones are
    /// made with the same one), and the state region the writable layer's
    /// limit needs.
    fn of(options: &Options) -> Layout {
        let config = HvfConfig::default();
        let fs = options
            .fs_limit
            .unwrap_or(hellovm_core::vfs::DEFAULT_UPPER_LIMIT)
            .min(64 << 30);
        Layout {
            state: (fs + STATE_SLACK).next_multiple_of(HEADER),
            tables: config.table_memory,
            ram: config.memory,
        }
    }

    fn total(&self) -> u64 {
        HEADER + self.state + self.tables + self.ram
    }

    fn tables_at(&self) -> u64 {
        HEADER + self.state
    }

    fn ram_at(&self) -> u64 {
        HEADER + self.state + self.tables
    }
}

/// The header: where things are in the state region, and the clocks at
/// the freeze.
#[derive(Clone, Copy, Debug, Default)]
struct Header {
    kernel_len: u64,
    platform_len: u64,
    tables_len: u64,
    stored: u64,
    areas: u32,
    /// The template's monotonic clock, and the host's uptime clock
    /// (`CLOCK_UPTIME_RAW`, the one `Instant` uses), at the freeze.
    monotonic_ns: u64,
    uptime_ns: u64,
}

impl Header {
    const LEN: usize = 8 + 6 * 8 + 4;

    fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..8].copy_from_slice(SNAPSHOT_MAGIC);
        let words = [
            self.kernel_len,
            self.platform_len,
            self.tables_len,
            self.stored,
            self.monotonic_ns,
            self.uptime_ns,
        ];
        for (i, w) in words.iter().enumerate() {
            out[8 + i * 8..16 + i * 8].copy_from_slice(&w.to_le_bytes());
        }
        out[56..60].copy_from_slice(&self.areas.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8], layout: &Layout) -> Result<Header, String> {
        let bytes = bytes.get(..Self::LEN).ok_or("a short snapshot header")?;
        if &bytes[..8] != SNAPSHOT_MAGIC {
            return Err("not a hellovm snapshot".into());
        }
        let word = |i: usize| u64::from_le_bytes(bytes[8 + i * 8..16 + i * 8].try_into().unwrap());
        let header = Header {
            kernel_len: word(0),
            platform_len: word(1),
            tables_len: word(2),
            stored: word(3),
            monotonic_ns: word(4),
            uptime_ns: word(5),
            areas: u32::from_le_bytes(bytes[56..60].try_into().unwrap()),
        };
        let state = header.kernel_len.checked_add(header.platform_len);
        if state.is_none_or(|n| n > layout.state) || header.tables_len > layout.tables {
            return Err("the snapshot's header does not fit its layout".into());
        }
        Ok(header)
    }
}

fn uptime_ns() -> u64 {
    extern "C" {
        fn clock_gettime_nsec_np(clock: libc::clockid_t) -> u64;
    }
    // SAFETY: plain clock read (from the commpage: no system call).
    unsafe { clock_gettime_nsec_np(libc::CLOCK_UPTIME_RAW) }
}

/// The messages of the template's kernel process to the supervisor.
const MSG_FROZEN: u8 = b'F';
const MSG_EXITED: u8 = b'X';
const MSG_FAILED: u8 = b'E';
/// Longest message: the kind, and up to this many bytes of text.
const MAX_MESSAGE: usize = 1 + 4096;

// ---------------------------------------------------------------------
// The supervisor.

/// `hellovm --template SOCKET` on macOS.
pub fn run(options: &Options, socket: &Path) -> Result<Ended, Box<dyn std::error::Error>> {
    // The kernel processes check these themselves; checked here too so
    // that a bad option fails before the socket exists.
    if let Some(path) = &options.egress {
        egress_socket(path)?;
    }
    let exe = std::env::current_exe()?;
    let listener = UnixListener::bind(socket)
        .map_err(|err| format!("control socket {}: {err}", socket.display()))?;
    let layout = Layout::of(options);
    let (rw, ro) = shared_memory(layout.total())?;
    hellovm_sandbox::seal_supervisor(SUPERVISOR_NOFILE)
        .map_err(|why| format!("hardening the template's supervisor: {why}"))?;
    let (control, theirs) = UnixStream::pair()?;
    let mut kernel = Command::new(&exe)
        .args(kernel_args(options, ROLE_TEMPLATE))
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .spawn()
        .map_err(|err| format!("starting the template's kernel process: {err}"))?;
    let started = Instant::now();
    warm::send_with_fds(&control, b"HVMK", &[rw.as_raw_fd()])?;
    drop(rw);
    let message = read_message(&control);
    // It exits after its message; no snapshot is used before it has.
    let status = wait_exit(&mut kernel, EXIT_PATIENCE);
    let (stored, areas) = match message {
        Some(msg) if msg.first() == Some(&MSG_FROZEN) && msg.len() == 13 && status == Some(0) => {
            let stored = u64::from_le_bytes(msg[1..9].try_into().unwrap());
            let areas = u32::from_le_bytes(msg[9..13].try_into().unwrap());
            (stored, areas)
        }
        Some(msg) if msg.first() == Some(&MSG_EXITED) && msg.len() == 6 => {
            let code = i32::from_le_bytes(msg[2..6].try_into().unwrap());
            let status = match msg[1] {
                0 => hellovm_core::ExitStatus::Exited(code),
                _ => hellovm_core::ExitStatus::Signaled(code as u32),
            };
            refuse(
                &listener,
                &format!("the template ended before its clone point ({status:?})"),
            );
            return Ok(Ended::Status(status));
        }
        Some(msg) if msg.first() == Some(&MSG_FAILED) => {
            let why = String::from_utf8_lossy(&msg[1..]).into_owned();
            refuse(&listener, &why);
            return Err(why.into());
        }
        _ => {
            let why = format!(
                "the template's kernel process ended without a snapshot ({})",
                match status {
                    Some(code) => format!("exit status {code}"),
                    None => "killed".into(),
                }
            );
            refuse(&listener, &why);
            return Err(why.into());
        }
    };
    log::info!(
        "template frozen after {:?}: {stored} bytes of memory in {areas} areas",
        started.elapsed()
    );
    drop(control);
    serve(&listener, &exe, options, &ro, (stored, areas))?;
    Ok(Ended::Status(hellovm_core::ExitStatus::Exited(0)))
}

/// The snapshot object, sized, with no name left: a descriptor that may
/// write it (for the template's kernel process) and one that may only
/// read it (for the clones: a read-only descriptor cannot be mapped
/// writable).
fn shared_memory(len: u64) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut id = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut id)?;
    // At most 31 bytes (PSHMNAMLEN).
    let name = format!("/hvm.{}.{:08x}", std::process::id(), u32::from_le_bytes(id));
    let cname = std::ffi::CString::new(name).expect("no NUL");
    // SAFETY: plain calls with a valid name; the fds are owned below.
    unsafe {
        let rw = libc::shm_open(
            cname.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600 as libc::c_uint,
        );
        if rw < 0 {
            return Err(io::Error::last_os_error());
        }
        let rw = OwnedFd::from_raw_fd(rw);
        let ro = libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0 as libc::c_uint);
        let ro_err = io::Error::last_os_error();
        libc::shm_unlink(cname.as_ptr());
        if ro < 0 {
            return Err(ro_err);
        }
        let ro = OwnedFd::from_raw_fd(ro);
        for fd in [&rw, &ro] {
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
        }
        let len = libc::off_t::try_from(len).map_err(|_| io::ErrorKind::InvalidInput)?;
        if libc::ftruncate(rw.as_raw_fd(), len) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((rw, ro))
    }
}

/// The command line of a kernel process: the template's options (the
/// program too, which a clone ignores), and its role.
fn kernel_args(options: &Options, role: &str) -> Vec<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt;
    let mut args: Vec<std::ffi::OsString> = vec!["--warm-role".into(), role.into()];
    let mut flag = |name: &str, value: std::ffi::OsString| {
        args.push(name.into());
        args.push(value);
    };
    flag("--root", options.root.clone().into_os_string());
    if let Some(egress) = &options.egress {
        flag("--egress", egress.clone().into_os_string());
    }
    if let Some(id) = options.sandbox_id {
        flag("--sandbox-id", id.to_string().into());
    }
    if let Some(bytes) = options.fs_limit {
        flag("--fs-limit", bytes.to_string().into());
    }
    if let Some(n) = options.vcpus {
        flag("--vcpus", n.to_string().into());
    }
    flag(
        "--sandbox",
        match options.sandbox {
            hellovm_sandbox::Mode::Require => "require",
            hellovm_sandbox::Mode::BestEffort => "best-effort",
            hellovm_sandbox::Mode::Off => "off",
        }
        .into(),
    );
    for var in &options.env {
        flag("--env", std::ffi::OsString::from_vec(var.clone()));
    }
    if options.trace {
        args.push("--trace".into());
    }
    args.push("--no-tty".into());
    args.push("--".into());
    args.extend(
        options
            .argv
            .iter()
            .map(|a| std::ffi::OsString::from_vec(a.clone())),
    );
    args
}

/// One message of the template's kernel process: `None` if it closed
/// without one (or sent more than a message may be).
fn read_message(control: &UnixStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(MAX_MESSAGE);
    let mut chunk = [0u8; 512];
    loop {
        match (&*control).read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_MESSAGE {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (!buf.is_empty()).then_some(buf)
}

/// Waits for `child` to exit, at most `limit` (then kills it). Its exit
/// code, `None` if a signal ended it.
fn wait_exit(child: &mut Child, limit: Duration) -> Option<i32> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            _ => {
                let _ = child.kill();
                return child.wait().ok().and_then(|s| s.code());
            }
        }
    }
}

/// Answers every request waiting on `listener` with `why`.
fn refuse(listener: &UnixListener, why: &str) {
    eprintln!("hellovm: template: {why}");
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while let Ok((stream, _)) = listener.accept() {
        let _ = warm::no_sigpipe(&stream);
        let _ = warm::send_frame(&stream, &Frame::Error(why.to_string()), Duration::ZERO);
    }
}

/// One connection.
struct Client {
    stream: UnixStream,
    deadline: Instant,
    /// The request so far, in a buffer that never moves.
    buf: Vec<u8>,
    fds: Vec<OwnedFd>,
    /// The clone's kernel process and its control socket, once started.
    clone: Option<(Child, UnixStream)>,
    /// Told to stop: killed if it has not exited by then.
    kill_at: Option<Instant>,
    /// Its control socket closed (or said something, which a clone's
    /// kernel process never does) and it had not exited yet: looked at
    /// again every [`REAP_EVERY`], and killed at `kill_at`.
    exiting: bool,
    gone: bool,
    done: bool,
}

impl Client {
    fn send(&self, frame: &Frame) {
        if let Err(err) = warm::send_frame(&self.stream, frame, Duration::ZERO) {
            log::warn!("template: {frame:?} did not reach its requester: {err}");
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        warm::wipe(&mut self.buf);
        if let Some((child, _)) = &mut self.clone {
            // A clone outlives neither its connection nor the supervisor.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The supervisor's loop. Returns only when the listener fails.
fn serve(
    listener: &UnixListener,
    exe: &Path,
    options: &Options,
    snapshot: &OwnedFd,
    ready: (u64, u32),
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let mut clients: Vec<Client> = Vec::new();
    loop {
        let mut polls = vec![libc::pollfd {
            fd: if clients.len() < MAX_CLIENTS {
                listener.as_raw_fd()
            } else {
                -1
            },
            events: libc::POLLIN,
            revents: 0,
        }];
        for client in &clients {
            polls.push(libc::pollfd {
                fd: if client.gone {
                    -1
                } else {
                    client.stream.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            });
            polls.push(libc::pollfd {
                fd: match &client.clone {
                    Some((_, control)) if !client.exiting => control.as_raw_fd(),
                    _ => -1,
                },
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let now = Instant::now();
        let timeout = clients
            .iter()
            .filter_map(|c| match c.clone {
                None => Some(c.deadline),
                Some(_) if c.exiting => Some(now + REAP_EVERY),
                Some(_) => c.kill_at,
            })
            .map(|at| at.saturating_duration_since(now))
            .min()
            .map_or(-1, |left| left.as_millis().min(60_000) as libc::c_int + 1);
        // SAFETY: a valid array of pollfds.
        let n = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, timeout) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        for i in 0..clients.len() {
            let (conn, child) = (polls[1 + 2 * i].revents, polls[2 + 2 * i].revents);
            if conn != 0 {
                if clients[i].clone.is_none() {
                    read_request(&mut clients[i], exe, options, snapshot, ready);
                } else {
                    watch_requester(&mut clients[i]);
                }
            }
            if child != 0 || clients[i].exiting {
                reap(&mut clients[i]);
            }
        }
        let now = Instant::now();
        for client in &mut clients {
            if let (Some((child, _)), Some(at)) = (&mut client.clone, client.kill_at) {
                if now >= at {
                    log::warn!("template: a clone's kernel process did not stop; killing it");
                    let _ = child.kill();
                    client.kill_at = None;
                }
            }
            if client.clone.is_none() && !client.done && now >= client.deadline {
                client.send(&Frame::Error(format!(
                    "no complete request within {:?}",
                    warm::REQUEST_TIMEOUT
                )));
                client.done = true;
            }
        }
        clients.retain(|c| !c.done);
        if polls[0].revents != 0 {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Non-blocking while the request is read; a
                        // clone's kernel process gets it blocking.
                        stream.set_nonblocking(true)?;
                        let _ = warm::no_sigpipe(&stream);
                        clients.push(Client {
                            stream,
                            deadline: Instant::now() + warm::REQUEST_TIMEOUT,
                            buf: Vec::new(),
                            fds: Vec::new(),
                            clone: None,
                            kill_at: None,
                            exiting: false,
                            gone: false,
                            done: false,
                        });
                        if clients.len() >= MAX_CLIENTS {
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) if err.kind() == io::ErrorKind::ConnectionAborted => continue,
                    Err(err) => return Err(err),
                }
            }
        }
    }
}

/// Reads more of a request and acts on it once complete.
fn read_request(
    client: &mut Client,
    exe: &Path,
    options: &Options,
    snapshot: &OwnedFd,
    ready: (u64, u32),
) {
    let whole = warm::HEADER_LEN + warm::MAX_INPUT;
    if client.buf.capacity() < whole {
        client.buf.reserve_exact(whole);
    }
    let have = client.buf.len();
    if have >= whole {
        client.done = true;
        return;
    }
    client.buf.resize(whole, 0);
    let received = warm::recv_with_fds(
        client.stream.as_fd(),
        &mut client.buf[have..],
        &mut client.fds,
        4,
    );
    client
        .buf
        .truncate(have + received.as_ref().map_or(0, |&n| n));
    match received {
        Ok(0) => {
            client.done = true;
            return;
        }
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
        Err(err) if err.kind() == io::ErrorKind::Interrupted => return,
        Err(err) => {
            client.send(&Frame::Error(format!("reading the request: {err}")));
            client.done = true;
            return;
        }
    }
    let request = match Request::decode(&client.buf) {
        Ok(Some((request, _))) => request,
        Ok(None) => return,
        Err(why) => {
            client.send(&Frame::Error(why));
            client.done = true;
            return;
        }
    };
    match request.kind {
        Kind::Ping => {
            client.send(&Frame::Ready {
                stored: ready.0,
                areas: ready.1,
            });
            client.done = true;
        }
        Kind::Clone => {
            let want = if request.ingress { 4 } else { 3 };
            if client.fds.len() != want {
                client.send(&Frame::Error(format!(
                    "a clone request needs {want} fds (stdin, stdout, stderr{}), it came with {}",
                    if request.ingress { ", ingress" } else { "" },
                    client.fds.len()
                )));
                client.done = true;
                return;
            }
            if request.ingress {
                client.send(&Frame::Error(
                    "an ingress channel needs Linux: on macOS a sandbox has no inbound \
                     connections yet"
                        .into(),
                ));
                client.done = true;
                return;
            }
            start_clone(client, request, exe, options, snapshot);
        }
    }
}

/// Starts the clone's kernel process for `client` and hands it the
/// request, the snapshot and the requester's fds.
fn start_clone(
    client: &mut Client,
    mut request: Request,
    exe: &Path,
    options: &Options,
    snapshot: &OwnedFd,
) {
    let fds = std::mem::take(&mut client.fds);
    let started = (|| -> io::Result<(Child, UnixStream)> {
        // The clone's kernel process writes its frames itself, blocking
        // for at most FRAME_PATIENCE.
        client.stream.set_nonblocking(false)?;
        set_send_timeout(&client.stream, FRAME_PATIENCE)?;
        let (control, theirs) = UnixStream::pair()?;
        let mut child = Command::new(exe)
            .args(kernel_args(options, ROLE_CLONE))
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .spawn()?;
        let mut attach = vec![snapshot.as_raw_fd(), client.stream.as_raw_fd()];
        attach.extend(fds.iter().map(|fd| fd.as_raw_fd()));
        let mut bytes = request.encode();
        let sent = warm::send_with_fds(&control, &bytes, &attach);
        warm::wipe(&mut bytes);
        if let Err(err) = sent {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
        Ok((child, control))
    })();
    // The clone's kernel process has its copies now: nothing of the
    // request stays here.
    warm::wipe(&mut request.input);
    warm::wipe(&mut client.buf);
    client.buf.clear();
    drop(fds);
    match started {
        Ok(clone) => client.clone = Some(clone),
        Err(err) => {
            client.send(&Frame::Error(format!("starting the clone: {err}")));
            client.done = true;
        }
    }
}

fn set_send_timeout(stream: &UnixStream, limit: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: limit.as_secs() as libc::time_t,
        tv_usec: limit.subsec_micros() as libc::suseconds_t,
    };
    // SAFETY: a valid socket and option value.
    let ret = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The requester of a running clone sent something or closed: anything but
/// more bytes kills the clone.
fn watch_requester(client: &mut Client) {
    let mut sink = [0u8; 256];
    // SAFETY: a valid buffer; MSG_DONTWAIT, since the connection is
    // blocking now (the clone's kernel process shares it).
    let n = unsafe {
        libc::recv(
            client.stream.as_raw_fd(),
            sink.as_mut_ptr().cast(),
            sink.len(),
            libc::MSG_DONTWAIT,
        )
    };
    let err = io::Error::last_os_error();
    if n > 0
        || (n < 0
            && matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ))
    {
        return;
    }
    client.gone = true;
    if let Some((_, control)) = &client.clone {
        // Its supervisor thread stops it (see the module documentation).
        let _ = (&*control).write(b"K");
        client.kill_at = Some(Instant::now() + EXIT_PATIENCE);
    }
}

/// A clone's kernel process closed its control socket (it ends): reaps it
/// and reports a death it could not report itself. Never waits: one that
/// has not exited yet is looked at again soon, and killed if it is still
/// there after [`EXIT_PATIENCE`] (a kernel process that guest code took
/// over must not hold up the others).
fn reap(client: &mut Client) {
    let Some((child, _)) = &mut client.clone else {
        return;
    };
    let status = match child.try_wait() {
        Ok(Some(status)) => status,
        Ok(None) => {
            if !client.exiting {
                client.exiting = true;
                let at = Instant::now() + EXIT_PATIENCE;
                client.kill_at = Some(client.kill_at.map_or(at, |old| old.min(at)));
            }
            return;
        }
        Err(_) => return,
    };
    client.done = true;
    if client.gone {
        return;
    }
    let reported = matches!(status.code(), Some(0 | CLONE_FAILED));
    if !reported {
        use std::os::unix::process::ExitStatusExt;
        let how = match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit status {code}"),
            (None, Some(sig)) => format!("killed by signal {sig}"),
            _ => "unknown status".into(),
        };
        client.send(&Frame::Error(format!(
            "the clone's kernel process ended unexpectedly ({how})"
        )));
    }
}

// ---------------------------------------------------------------------
// The kernel processes.

/// The control socket a kernel process got from the supervisor as its
/// stdin.
fn control_socket() -> UnixStream {
    // SAFETY: fd 0 is the socket the supervisor made for this process;
    // nothing else in it uses fd 0 (a template's console input is closed,
    // a clone's comes with the request).
    unsafe { UnixStream::from_raw_fd(0) }
}

/// The supervisor stopped this kernel process: a clone that its template
/// or its requester left reports nothing (as on Linux, where it dies).
static STOPPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Stops the sandbox as soon as the supervisor closes `control` (it died)
/// or sends anything on it (stop): a thread, made before the hardening,
/// blocked in `read` until then, ends every app with `killer` (the run
/// then ends and the process exits as after `--timeout`), and exits the
/// process itself if that has not happened after [`EXIT_PATIENCE`].
fn stop_with_supervisor(
    control: &UnixStream,
    killer: hellovm_platform_hvf::AppKiller,
) -> io::Result<()> {
    let control = control.try_clone()?;
    STOPPED.store(false, std::sync::atomic::Ordering::SeqCst);
    std::thread::Builder::new()
        .name("hellovm-supervisor".into())
        .spawn(move || {
            let mut byte = [0u8; 1];
            // Anything, or end of file, or an error.
            let _ = read_some(&control, &mut byte);
            STOPPED.store(true, std::sync::atomic::Ordering::SeqCst);
            killer.kill();
            hellovm_host::sleep_confined(EXIT_PATIENCE);
            // SAFETY: ends the process at once.
            unsafe { libc::_exit(CLONE_FAILED) };
        })?;
    Ok(())
}

/// Writes all of `data` to the socket `fd` with `write`, which the
/// confined process may make (`std`'s socket writes are `sendto`, and its
/// reads `recvfrom`: not in the profile).
fn write_all(fd: &impl AsRawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        // SAFETY: a valid buffer of that length.
        let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        data = &data[n as usize..];
    }
    Ok(())
}

/// Reads with `read` (see [`write_all`]).
fn read_some(fd: &impl AsRawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: a valid buffer of that length.
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Sends one message to the supervisor, all of it (blocking).
fn tell(control: &UnixStream, message: &[u8]) {
    let mut message = message.to_vec();
    message.truncate(MAX_MESSAGE);
    let _ = write_all(control, &message);
}

/// `--warm-role template`: the template's kernel process.
pub fn run_template_kernel(options: &Options, fds: Result<usize, String>) -> ! {
    let control = control_socket();
    let code = match template_kernel(options, fds, &control) {
        Ok(code) => code,
        Err(why) => {
            eprintln!("hellovm: template: {why}");
            let mut message = vec![MSG_FAILED];
            message.extend_from_slice(why.to_string().as_bytes());
            tell(&control, &message);
            125
        }
    };
    // Not dropping the platform: see `run`.
    std::process::exit(code);
}

fn template_kernel(
    options: &Options,
    fds: Result<usize, String>,
    control: &UnixStream,
) -> Result<i32, Box<dyn std::error::Error>> {
    let mut buf = [0u8; 4];
    let mut got = Vec::new();
    let n = warm::recv_with_fds(control.as_fd(), &mut buf, &mut got, 1)?;
    let (Some(shm), true) = (got.pop(), &buf[..n] == b"HVMK") else {
        return Err("no snapshot from the supervisor".into());
    };
    let layout = Layout::of(options);
    let mut snapshot = SharedMap::map(shm.as_fd(), 0, layout.total() as usize, true)?;
    drop(shm);
    let egress = options.egress.as_deref().map(egress_socket).transpose()?;
    let image = ImageDir::open(&options.root)
        .map_err(|err| format!("image {}: {err}", options.root.display()))?;
    let image_path = image.root().to_path_buf();
    let mut app = std::mem::ManuallyDrop::new(HvfPlatform::new(HvfConfig {
        vcpus: options.vcpus.unwrap_or(0),
        ..HvfConfig::default()
    })?);
    let app: &mut HvfPlatform = &mut app;
    if app.pool_sizes() != (layout.ram, layout.tables) {
        return Err("the VM's size differs from the snapshot's".into());
    }
    stop_with_supervisor(control, app.killer())?;
    let mut host = StdioHost::new(Some(image));
    host.close_input();
    if let Some(path) = &egress {
        host.set_egress(path)?;
    }
    harden(options, &image_path, egress.as_deref(), fds)?;
    let sandbox_id = crate::sandbox_id(options, &mut host)?;
    let mut kernel = Kernel::new(host).with_sandbox_id(sandbox_id).template();
    if let Some(bytes) = options.fs_limit {
        kernel = kernel.with_fs_limit(bytes);
    }
    if options.trace {
        kernel = kernel.with_trace();
    }
    kernel.exec(app, &options.argv[0], &options.argv, &options.env)?;
    let end = kernel.run_template(app);
    for record in kernel.trace() {
        eprintln!("hellovm: trace: {record}");
    }
    match end? {
        TemplateEnd::Frozen => {}
        TemplateEnd::Exited(status) => {
            let (kind, code) = match status {
                hellovm_core::ExitStatus::Exited(code) => (0u8, code),
                hellovm_core::ExitStatus::Signaled(sig) => (1u8, sig as i32),
            };
            let mut message = vec![MSG_EXITED, kind];
            message.extend_from_slice(&code.to_le_bytes());
            tell(control, &message);
            return Ok(match status {
                hellovm_core::ExitStatus::Exited(code) => code,
                hellovm_core::ExitStatus::Signaled(sig) => 128 + sig as i32,
            });
        }
    }
    let saving = Instant::now();
    let areas = kernel.frozen_areas() as u32;
    let monotonic = hellovm_core::host::Host::clock_monotonic(kernel.host_mut());
    let uptime = uptime_ns();
    let bytes = snapshot.bytes_mut();
    let (head, rest) = bytes.split_at_mut(HEADER as usize);
    let (state_region, rest) = rest.split_at_mut(layout.state as usize);
    let (tables, ram) = rest.split_at_mut(layout.tables as usize);
    // Straight into the snapshot: nothing that grows is allocated here.
    let mut w = hellovm_core::snap::Writer::into_slice(state_region);
    kernel.save_frozen_to(&mut w)?;
    let kernel_len = w.len();
    let stats = app.save_frozen(tables, ram, &mut w)?;
    let total = w.written().map_err(|needed| {
        KernelError::NotClonable(format!(
            "the kernel state takes {needed} bytes, more than the snapshot's {} (see --fs-limit)",
            layout.state
        ))
    })?;
    let header = Header {
        kernel_len: kernel_len as u64,
        platform_len: (total - kernel_len) as u64,
        tables_len: stats.tables,
        stored: stats.stored * hellovm_core::platform::Platform::address_space(app).page_size,
        areas,
        monotonic_ns: monotonic.as_nanos() as u64,
        uptime_ns: uptime,
    };
    head[..Header::LEN].copy_from_slice(&header.encode());
    log::info!(
        "template saved in {:?}: kernel state {} bytes, platform {} bytes, page tables {} bytes, \
         {} of {} app frames stored",
        saving.elapsed(),
        header.kernel_len,
        header.platform_len,
        stats.tables,
        stats.stored,
        stats.frames
    );
    let mut message = vec![MSG_FROZEN];
    message.extend_from_slice(&header.stored.to_le_bytes());
    message.extend_from_slice(&areas.to_le_bytes());
    tell(control, &message);
    Ok(0)
}

/// `--warm-role clone`: a clone's kernel process.
pub fn run_clone_kernel(options: &Options, fds: Result<usize, String>) -> ! {
    let control = control_socket();
    let code = clone_kernel(options, fds, &control);
    std::process::exit(code);
}

/// What a clone's kernel process gets from the supervisor.
struct Setup {
    request: Request,
    snapshot: OwnedFd,
    conn: UnixStream,
    stdio: [File; 3],
}

fn receive_setup(control: &UnixStream) -> Result<Setup, String> {
    let mut buf = vec![0u8; warm::HEADER_LEN + warm::MAX_INPUT];
    let mut have = 0;
    let mut fds = Vec::new();
    let request = loop {
        let n = warm::recv_with_fds(control.as_fd(), &mut buf[have..], &mut fds, 6)
            .map_err(|err| format!("the request: {err}"))?;
        if n == 0 {
            return Err("the supervisor sent no request".into());
        }
        have += n;
        match Request::decode(&buf[..have]) {
            // Anything behind the request is the supervisor's stop, sent
            // before the thread that waits for it exists.
            Ok(Some((mut request, used))) if used < have => {
                warm::wipe(&mut request.input);
                warm::wipe(&mut buf);
                return Err("stopped before it started".into());
            }
            Ok(Some((request, _))) => break request,
            Ok(None) => continue,
            Err(why) => return Err(why),
        }
    };
    warm::wipe(&mut buf);
    let mut fds = fds.into_iter();
    let (Some(snapshot), Some(conn), Some(i), Some(o), Some(e), None) = (
        fds.next(),
        fds.next(),
        fds.next(),
        fds.next(),
        fds.next(),
        fds.next(),
    ) else {
        return Err("the request came without its fds".into());
    };
    Ok(Setup {
        request,
        snapshot,
        conn: UnixStream::from(conn),
        stdio: [File::from(i), File::from(o), File::from(e)],
    })
}

fn clone_kernel(options: &Options, fds: Result<usize, String>, control: &UnixStream) -> i32 {
    let forked = Instant::now();
    let setup = match receive_setup(control) {
        Ok(setup) => setup,
        Err(why) => {
            eprintln!("hellovm: clone: {why}");
            return CLONE_FAILED;
        }
    };
    let Setup {
        #[allow(unused_mut)]
        mut request,
        snapshot,
        conn,
        stdio,
    } = setup;
    let send = |frame: Frame| {
        let mut bytes = frame.encode();
        if let Err(err) = write_all(&conn, &bytes) {
            log::warn!("clone: {frame:?} did not reach the requester: {err}");
        }
        warm::wipe(&mut bytes);
    };
    let fail = |why: String| {
        send(Frame::Error(why));
        CLONE_FAILED
    };
    let mut app = match prepare_clone(options, fds, control, &snapshot, stdio) {
        Ok(prepared) => prepared,
        Err(why) => return fail(format!("rebuilding the clone: {why}")),
    };
    drop(snapshot);
    let (app, kernel): (&mut HvfPlatform, _) = (&mut app.0, &mut app.1);
    let sandbox_id = match request.sandbox_id {
        Some(id) => id,
        None => {
            let mut bytes = [0u8; 8];
            match hellovm_core::host::Host::random(kernel.host_mut(), &mut bytes) {
                Ok(()) => u64::from_be_bytes(bytes),
                Err(err) => return fail(format!("a sandbox id: {err}")),
            }
        }
    };
    kernel.set_sandbox_id(sandbox_id);
    let thawing = Instant::now();
    if let Err(err) = kernel.thaw(app, std::mem::take(&mut request.input)) {
        return fail(format!("rebuilding the clone: {err}"));
    }
    log::info!("clone sandbox id {sandbox_id:016x}");
    log::debug!(
        "clone: set up in {:?}, tasks rebuilt in {:?}",
        thawing - forked,
        thawing.elapsed()
    );
    send(Frame::Started {
        sandbox_id,
        pid: std::process::id(),
    });
    let status = kernel.run(app);
    for record in kernel.trace() {
        eprintln!("hellovm: trace: {record}");
    }
    log::debug!(
        "clone: {} app frames copied from the template",
        app.frames_loaded()
    );
    if STOPPED.load(std::sync::atomic::Ordering::SeqCst) {
        return CLONE_FAILED;
    }
    if !kernel.host_mut().drain_streams(EXIT_DRAIN) {
        log::warn!("outbound streams still had undelivered bytes after {EXIT_DRAIN:?}");
    }
    let status = match status {
        Ok(hellovm_core::ExitStatus::Exited(code)) => Status::Exited(code as u32),
        Ok(hellovm_core::ExitStatus::Signaled(sig)) => Status::Signaled(sig),
        Err(err) => return fail(format!("the clone failed: {err}")),
    };
    send(Frame::Exit(status));
    0
}

/// A clone's VM, with the template's tables, and its kernel, with the
/// template's state, hardened: everything but the thaw.
type Prepared = (std::mem::ManuallyDrop<Box<HvfPlatform>>, Kernel<StdioHost>);

fn prepare_clone(
    options: &Options,
    fds: Result<usize, String>,
    control: &UnixStream,
    snapshot: &OwnedFd,
    stdio: [File; 3],
) -> Result<Prepared, Box<dyn std::error::Error>> {
    let layout = Layout::of(options);
    let t0 = Instant::now();
    let head = SharedMap::map(snapshot.as_fd(), 0, HEADER as usize, false)?;
    let header = Header::decode(head.bytes(), &layout)?;
    drop(head);
    let state = SharedMap::map(snapshot.as_fd(), HEADER, layout.state as usize, false)?;
    let tables = SharedMap::map(
        snapshot.as_fd(),
        layout.tables_at(),
        layout.tables as usize,
        false,
    )?;
    let ram = SharedMap::map(
        snapshot.as_fd(),
        layout.ram_at(),
        layout.ram as usize,
        false,
    )?;
    let egress = options.egress.as_deref().map(egress_socket).transpose()?;
    let image = ImageDir::open(&options.root)
        .map_err(|err| format!("image {}: {err}", options.root.display()))?;
    let image_path = image.root().to_path_buf();
    let t1 = Instant::now();
    // Never dropped: see `run`.
    let mut app = std::mem::ManuallyDrop::new(Box::new(HvfPlatform::new(HvfConfig {
        vcpus: options.vcpus.unwrap_or(0),
        ..HvfConfig::default()
    })?));
    stop_with_supervisor(control, app.killer())?;
    let t2 = Instant::now();
    let mut host = StdioHost::new(Some(image));
    let [stdin, stdout, stderr] = stdio;
    host.set_console(stdin, stdout, stderr);
    // The template's clock goes on: deadlines in the state count in it.
    let waited = Duration::from_nanos(uptime_ns().saturating_sub(header.uptime_ns));
    host.set_monotonic_clock(Duration::from_nanos(header.monotonic_ns) + waited);
    if let Some(path) = &egress {
        host.set_egress(path)?;
    }
    // Confined before anything but the header is read: the snapshot was
    // written by the template's kernel process, which ran guest code.
    harden(options, &image_path, egress.as_deref(), fds)?;
    let t3 = Instant::now();
    let kernel_len = header.kernel_len as usize;
    let platform = &state.bytes()[kernel_len..kernel_len + header.platform_len as usize];
    app.load_frozen(
        platform,
        &tables.bytes()[..header.tables_len as usize],
        Box::new(ram),
    )?;
    drop(tables);
    let t4 = Instant::now();
    let kernel = Kernel::load_frozen(host, &state.bytes()[..kernel_len])?;
    drop(state);
    log::debug!(
        "clone: snapshot mapped in {:?}, VM made in {:?}, hardened in {:?}, \
         page tables loaded in {:?}, kernel state read in {:?}",
        t1 - t0,
        t2 - t1,
        t3 - t2,
        t4 - t3,
        t4.elapsed()
    );
    Ok((app, kernel))
}
