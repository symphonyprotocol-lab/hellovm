//! `hellovm --template SOCKET`: runs a program as a warm-clone template
//! and serves clones of it on `SOCKET` (protocol: `hellovm::warm`).
//!
//! The template starts like any sandbox (hardened the same way) but with no
//! console input, and runs until a thread reads `/dev/hellovm-clone`. The
//! kernel then freezes it (`Kernel::run_template`): the platform copies
//! the app processes' memory into a sealed memfd and ends them; the kernel
//! state stays in this process. From then on this process only serves the
//! socket, single-threaded: for each clone request it forks itself. The
//! child is the clone's kernel process: it enters a Landlock domain of its
//! own, takes the requester's stdio as console, rebuilds the app processes
//! from the snapshot (`Kernel::thaw`), reports `S`, runs the sandbox to its
//! end and reports `X`. This process watches each clone's connection and
//! kernel process: a closed connection kills the clone, a clone kernel
//! process that dies without reporting gets an `E` sent for it. Clones die
//! with the template (`PR_SET_PDEATHSIG`).
//!
//! A clone starts with a copy of everything in this process's memory, so
//! this process keeps nothing of one requester where another's clone could
//! find it: request bytes live in one buffer per connection that never
//! moves and is zeroed when the connection ends, and the child zeroes the
//! other connections' buffers before anything else.

use std::fs::File;
#[cfg(feature = "insecure-test-hooks")]
use std::io::Write;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use hellovm::warm::{self, Frame, Kind, Request, Status};
use hellovm_core::{Kernel, KernelError, TemplateEnd};
use hellovm_host::{ImageDir, StdioHost};
use hellovm_platform_seccomp::SeccompPlatform;

use crate::{harden, Ended, Options, EXIT_DRAIN};

/// Most connections served at once (clones and requests being read). Each
/// takes up to five fds (connection, pidfd, three stdio fds while the
/// request is read) under the kernel process's limit of 4096.
const MAX_CLIENTS: usize = 512;

/// Exit status of a clone's kernel process that has reported an error
/// itself (frame `E`).
const CLONE_FAILED: i32 = 3;

/// How long a clone's kernel process waits for room in its connection
/// when the requester does not read the clone's `S`, `X` or `E`.
const FRAME_PATIENCE: Duration = Duration::from_secs(5);

/// One connection.
struct Client {
    stream: UnixStream,
    /// When the request must be complete.
    deadline: Instant,
    /// The request so far. Its capacity is a whole request's from the first
    /// byte on, so the bytes are never moved (leaving a copy behind).
    buf: Vec<u8>,
    /// fds received with it.
    fds: Vec<OwnedFd>,
    /// The clone's kernel process, once forked.
    clone: Option<(libc::pid_t, OwnedFd)>,
    /// The requester closed its end (the clone is being killed).
    gone: bool,
    /// Served: drop the connection.
    done: bool,
}

impl Client {
    /// Sends a frame without waiting: this process serves every
    /// connection. Nothing was sent on the connection before, so only a
    /// requester that is gone cannot take it.
    fn send(&self, frame: &Frame) {
        if let Err(err) = warm::send_frame(&self.stream, frame, Duration::ZERO) {
            log::warn!("template: {frame:?} did not reach its requester: {err}");
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        warm::wipe(&mut self.buf);
    }
}

/// Binds the control socket. Before the hardening: afterwards there is no
/// filesystem to create it in.
fn bind(path: &Path) -> io::Result<UnixListener> {
    UnixListener::bind(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("control socket {}: {err}", path.display()),
        )
    })
}

pub fn run(
    options: &Options,
    socket: &Path,
    fds: Result<usize, String>,
) -> Result<Ended, Box<dyn std::error::Error>> {
    let image = ImageDir::open(&options.root)
        .map_err(|err| format!("image {}: {err}", options.root.display()))?;
    let egress = options
        .egress
        .as_deref()
        .map(std::path::absolute)
        .transpose()?;
    let listener = bind(socket)?;
    let mut app = SeccompPlatform::new()?;
    app.prepare_snapshots()?;
    let mut host = StdioHost::new(Some(image));
    host.close_input();
    #[cfg(feature = "insecure-test-hooks")]
    if let Some(addr) = options.splice_to {
        host.set_splice_endpoint(addr);
    }
    let image = host.image_mut().expect("the host has the image");
    let (egress, landlock) = harden(options, image, egress, fds, true)?;
    if !landlock {
        // Clones are forks of this process: they share its user namespace
        // and its Landlock domain (none), so nothing but a domain of their
        // own keeps one clone's kernel process from the others' processes.
        let why = "Landlock is not available here, so the clones of this template \
                   would not be fenced from each other: a clone's kernel process, if \
                   compromised, could read and write the memory of the other clones";
        if options.sandbox == hellovm_sandbox::Mode::Require {
            let why = format!("{why} (refused by --sandbox require)");
            refuse(&listener, &why);
            return Err(why.into());
        }
        log::warn!("{why}; use it for one tenant only");
    }
    if let Some(path) = egress {
        host.set_egress(path);
    }
    let sandbox_id = match options.sandbox_id {
        Some(id) => id,
        None => random_id(&mut host)?,
    };
    log::info!("template sandbox id {sandbox_id:016x}");
    let mut kernel = Kernel::new(host).with_sandbox_id(sandbox_id).template();
    // Kernel state: every clone keeps the template's limit.
    if let Some(bytes) = options.fs_limit {
        kernel = kernel.with_fs_limit(bytes);
    }
    if options.trace {
        kernel = kernel.with_trace();
    }
    let started = Instant::now();
    kernel.exec(&mut app, &options.argv[0], &options.argv, &options.env)?;
    let end = kernel.run_template(&mut app);
    print_trace(&kernel);
    match end {
        Ok(TemplateEnd::Frozen) => {}
        Ok(TemplateEnd::Exited(status)) => {
            refuse(
                &listener,
                &format!("the template ended before its clone point ({status:?})"),
            );
            return Ok(Ended::Status(status));
        }
        Err(err) => {
            refuse(&listener, &err.to_string());
            return Err(err.into());
        }
    }
    let (stored, areas) = app.snapshot_size().unwrap_or_default();
    log::info!(
        "template frozen after {:?}: {stored} bytes of memory in {areas} areas, {} extents",
        started.elapsed(),
        app.snapshot_extents()
    );
    serve(
        &listener,
        &mut kernel,
        &mut app,
        landlock,
        (stored, areas as u32),
    )?;
    Ok(Ended::Status(hellovm_core::ExitStatus::Exited(0)))
}

fn random_id(host: &mut StdioHost) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    hellovm_core::host::Host::random(host, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn print_trace(kernel: &Kernel<StdioHost>) {
    for record in kernel.trace() {
        eprintln!("hellovm: trace: {record}");
    }
}

/// Answers every request waiting on `listener` with `why`.
fn refuse(listener: &UnixListener, why: &str) {
    eprintln!("hellovm: template: {why}");
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while let Ok((stream, _)) = listener.accept() {
        let _ = warm::send_frame(&stream, &Frame::Error(why.to_string()), Duration::ZERO);
    }
}

/// The fork server. Returns only when the listener fails.
fn serve(
    listener: &UnixListener,
    kernel: &mut Kernel<StdioHost>,
    app: &mut SeccompPlatform,
    landlock: bool,
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
                fd: client.clone.as_ref().map_or(-1, |(_, fd)| fd.as_raw_fd()),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // Until the first request that is still incomplete runs out of time.
        let now = Instant::now();
        let timeout = clients
            .iter()
            .filter(|c| c.clone.is_none())
            .map(|c| c.deadline.saturating_duration_since(now))
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
                    read_request(&mut clients, i, kernel, app, listener, landlock, ready);
                } else {
                    watch_requester(&mut clients[i]);
                }
            }
            if child != 0 {
                reap(&mut clients[i]);
            }
        }
        let now = Instant::now();
        for client in &mut clients {
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
                        stream.set_nonblocking(true)?;
                        clients.push(Client {
                            stream,
                            deadline: Instant::now() + warm::REQUEST_TIMEOUT,
                            buf: Vec::new(),
                            fds: Vec::new(),
                            clone: None,
                            gone: false,
                            done: false,
                        });
                        if clients.len() >= MAX_CLIENTS {
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    // A connection that went away before it was accepted.
                    Err(err) if err.kind() == io::ErrorKind::ConnectionAborted => continue,
                    Err(err) => return Err(err),
                }
            }
        }
    }
}

/// Reads more of a request and acts on it once complete.
fn read_request(
    clients: &mut [Client],
    i: usize,
    kernel: &mut Kernel<StdioHost>,
    app: &mut SeccompPlatform,
    listener: &UnixListener,
    landlock: bool,
    ready: (u64, u32),
) {
    let client = &mut clients[i];
    // Straight into the connection's buffer, which is as large as a request
    // can be: no copy of the bytes is left anywhere else.
    let whole = warm::HEADER_LEN + warm::MAX_INPUT;
    if client.buf.capacity() < whole {
        client.buf.reserve_exact(whole);
    }
    let have = client.buf.len();
    if have >= whole {
        // Cannot happen: a request this long is complete or malformed.
        client.done = true;
        return;
    }
    client.buf.resize(whole, 0);
    let received = warm::recv_with_fds(
        client.stream.as_fd(),
        &mut client.buf[have..],
        &mut client.fds,
        3,
    );
    client
        .buf
        .truncate(have + received.as_ref().map_or(0, |&n| n));
    let _n = match received {
        Ok(0) => {
            client.done = true;
            return;
        }
        Ok(n) => n,
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
        Err(err) if err.kind() == io::ErrorKind::Interrupted => return,
        Err(err) => {
            client.send(&Frame::Error(format!("reading the request: {err}")));
            client.done = true;
            return;
        }
    };
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
            if client.fds.len() != 3 {
                client.send(&Frame::Error(format!(
                    "a clone request needs 3 fds (stdin, stdout, stderr), it came with {}",
                    client.fds.len()
                )));
                client.done = true;
                return;
            }
            fork_clone(clients, i, request, kernel, app, listener, landlock);
        }
    }
}

/// Forks the clone's kernel process for `clients[i]`.
fn fork_clone(
    clients: &mut [Client],
    i: usize,
    mut request: Request,
    kernel: &mut Kernel<StdioHost>,
    app: &mut SeccompPlatform,
    listener: &UnixListener,
    landlock: bool,
) {
    // Everything of the template's that the clone must not keep.
    let mut others: Vec<RawFd> = vec![listener.as_raw_fd()];
    for (j, client) in clients.iter().enumerate() {
        if j == i {
            continue;
        }
        others.push(client.stream.as_raw_fd());
        others.extend(client.clone.as_ref().map(|(_, fd)| fd.as_raw_fd()));
        others.extend(client.fds.iter().map(|fd| fd.as_raw_fd()));
    }
    // SAFETY: plain getpid.
    let template = unsafe { libc::getpid() };
    // SAFETY: the template is single-threaded here (it has no console
    // reader and no outbound streams: `Kernel::run_template` checked), so
    // the child may run any code.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        for fd in others {
            // SAFETY: closing the child's copies of the template's fds;
            // their owners are never dropped in the child, which exits
            // without returning.
            unsafe { libc::close(fd) };
        }
        // What other requesters have sent so far is not this clone's to
        // know (nor is the raw copy of its own request needed again).
        for client in clients.iter_mut() {
            warm::wipe(&mut client.buf);
        }
        let client = &mut clients[i];
        let stream = client.stream.try_clone();
        let fds = std::mem::take(&mut client.fds);
        let code = match stream {
            Ok(stream) => become_clone(template, stream, fds, request, kernel, app, landlock),
            Err(_) => CLONE_FAILED,
        };
        std::process::exit(code);
    }
    // The child has its own copies; the next clone must not get this one's
    // input.
    warm::wipe(&mut request.input);
    let client = &mut clients[i];
    warm::wipe(&mut client.buf);
    client.buf.clear();
    client.fds.clear();
    if pid < 0 {
        client.send(&Frame::Error(format!(
            "forking the clone: {}",
            io::Error::last_os_error()
        )));
        client.done = true;
        return;
    }
    // SAFETY: plain syscall; the pid is our unreaped child.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pidfd < 0 {
        // SAFETY: killing and reaping our own child.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        client.send(&Frame::Error(format!(
            "watching the clone: {}",
            io::Error::last_os_error()
        )));
        client.done = true;
        return;
    }
    // SAFETY: a new fd we own.
    client.clone = Some((pid, unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) }));
}

/// The requester of a running clone sent something or closed: anything but
/// more bytes kills the clone.
fn watch_requester(client: &mut Client) {
    let mut sink = [0u8; 256];
    match (&client.stream).read(&mut sink) {
        Ok(n) if n > 0 => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        _ => {
            client.gone = true;
            if let Some((_, pidfd)) = &client.clone {
                // SAFETY: plain syscall on our pidfd.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
            }
        }
    }
}

/// A clone's kernel process ended: reaps it and reports a death it could
/// not report itself.
fn reap(client: &mut Client) {
    let Some((pid, _)) = client.clone else {
        return;
    };
    let mut status = 0;
    // SAFETY: plain syscall on our child.
    let ret = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if ret == 0 {
        return;
    }
    client.done = true;
    if client.gone {
        return;
    }
    let reported = libc::WIFEXITED(status) && matches!(libc::WEXITSTATUS(status), 0 | CLONE_FAILED);
    if !reported {
        let how = if libc::WIFSIGNALED(status) {
            format!("killed by signal {}", libc::WTERMSIG(status))
        } else {
            format!("exit status {}", libc::WEXITSTATUS(status))
        };
        client.send(&Frame::Error(format!(
            "the clone's kernel process ended unexpectedly ({how})"
        )));
    }
}

/// The clone's kernel process, in the child of the fork. Returns its exit
/// status: 0 after `X`, [`CLONE_FAILED`] after `E`.
fn become_clone(
    template: libc::pid_t,
    stream: UnixStream,
    fds: Vec<OwnedFd>,
    #[allow(unused_mut)] mut request: Request,
    kernel: &mut Kernel<StdioHost>,
    app: &mut SeccompPlatform,
    landlock: bool,
) -> i32 {
    #[cfg(feature = "insecure-test-hooks")]
    let probe = probe::target(&mut request.input);
    let forked = Instant::now();
    let send = |frame: Frame| {
        if let Err(err) = warm::send_frame(&stream, &frame, FRAME_PATIENCE) {
            log::warn!("clone: {frame:?} did not reach the requester: {err}");
        }
    };
    let fail = |why: String| {
        send(Frame::Error(why));
        CLONE_FAILED
    };
    // SAFETY: plain prctl and getppid.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != template {
            return fail("the template is gone".into());
        }
    }
    let mut _abi = 0;
    if landlock {
        match hellovm_sandbox::nest_landlock_domain() {
            Ok(abi) => _abi = abi,
            Err(why) => return fail(format!("a Landlock domain for the clone: {why}")),
        }
    }
    let mut stdio = fds.into_iter().map(File::from);
    let (Some(stdin), Some(stdout), Some(stderr)) = (stdio.next(), stdio.next(), stdio.next())
    else {
        return fail("missing stdio fds".into());
    };
    #[cfg(feature = "insecure-test-hooks")]
    let probe_out = stderr.try_clone();
    kernel.host_mut().set_console(stdin, stdout, stderr);
    let sandbox_id = match request.sandbox_id {
        Some(id) => id,
        None => match random_id(kernel.host_mut()) {
            Ok(id) => id,
            Err(err) => return fail(format!("a sandbox id: {err}")),
        },
    };
    kernel.set_sandbox_id(sandbox_id);
    let thawing = Instant::now();
    if let Err(err) = kernel.thaw(app, request.input) {
        return fail(format!("rebuilding the clone: {err}"));
    }
    log::info!("clone sandbox id {sandbox_id:016x}");
    log::debug!(
        "clone: set up in {:?}, app processes rebuilt in {:?}",
        thawing - forked,
        thawing.elapsed()
    );
    #[cfg(feature = "insecure-test-hooks")]
    if let (Some(target), Ok(mut out)) = (probe, probe_out) {
        let _ = out.write_all(probe::run(_abi, app.host_pids()[0], target).as_bytes());
    }
    send(Frame::Started {
        sandbox_id,
        // SAFETY: plain getpid.
        pid: unsafe { libc::getpid() } as u32,
    });
    let status = kernel.run(app);
    print_trace(kernel);
    if !kernel.host_mut().drain_streams(EXIT_DRAIN) {
        log::warn!("outbound streams still had undelivered bytes after {EXIT_DRAIN:?}");
    }
    let status = match status {
        Ok(hellovm_core::ExitStatus::Exited(code)) => Status::Exited(code as u32),
        Ok(hellovm_core::ExitStatus::Signaled(sig)) => Status::Signaled(sig),
        Err(KernelError::Platform(err)) => return fail(format!("the clone failed: {err}")),
        Err(err) => return fail(format!("the clone failed: {err}")),
    };
    send(Frame::Exit(status));
    0
}

/// `hellovm --clone SOCKET`: asks the template for a clone with this
/// process's stdio as its console, waits for it and returns its exit code
/// (125 when it could not be made, 124 after `--timeout`).
pub fn client(
    socket: &Path,
    sandbox_id: Option<u64>,
    input: &[u8],
    ready: bool,
    timeout: Option<std::time::Duration>,
) -> u8 {
    if ready {
        return match warm::wait_ready(socket) {
            Ok((stored, areas)) => {
                eprintln!("hellovm: template ready: {stored} bytes in {areas} areas");
                0
            }
            Err(err) => {
                eprintln!("hellovm: {}: {err}", socket.display());
                125
            }
        };
    }
    let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
    let stdio = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
    let result = warm::WarmClone::request(socket, sandbox_id, input, stdio).and_then(|mut c| {
        c.stream().set_read_timeout(timeout)?;
        let started = c.start()?;
        log::info!("clone {:016x} runs", started.sandbox_id);
        c.wait()
    });
    match result {
        Ok(status) => {
            if let Status::Signaled(sig) = status {
                eprintln!("hellovm: program killed by signal {sig}");
            }
            status.code()
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            eprintln!("hellovm: clone timed out after {timeout:?}");
            crate::EXIT_TIMEOUT
        }
        Err(err) => {
            eprintln!("hellovm: {}: {err}", socket.display());
            125
        }
    }
}

/// Test hook (`insecure-test-hooks`): a clone whose input starts with
/// `\0probe:PID\n` has its kernel process, once its app processes exist,
/// try to read the memory of its own first app process and of process
/// `PID` (a sibling clone's app process, say) and to `SIGKILL` `PID`, and
/// write the outcome to the clone's stderr. The rest of the input is the
/// clone's input.
#[cfg(feature = "insecure-test-hooks")]
mod probe {
    pub fn target(input: &mut Vec<u8>) -> Option<libc::pid_t> {
        let rest = input.strip_prefix(b"\0probe:")?;
        let end = rest.iter().position(|&b| b == b'\n')?;
        let pid = std::str::from_utf8(&rest[..end]).ok()?.parse().ok()?;
        let skip = b"\0probe:".len() + end + 1;
        input.drain(..skip);
        Some(pid)
    }

    fn outcome(ret: isize, ok_errno: i32) -> String {
        let err = std::io::Error::last_os_error();
        if ret >= 0 || err.raw_os_error() == Some(ok_errno) {
            "ok".into()
        } else {
            format!("errno-{}", err.raw_os_error().unwrap_or(0))
        }
    }

    fn read(pid: libc::pid_t) -> String {
        let mut byte = 0u8;
        let local = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        // Nothing is mapped there: with access, EFAULT.
        let remote = libc::iovec {
            iov_base: 0x1000 as *mut libc::c_void,
            iov_len: 1,
        };
        // SAFETY: valid iovecs; reads at most one byte into `byte`.
        let ret = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        outcome(ret, libc::EFAULT)
    }

    pub fn run(abi: i64, own: libc::pid_t, target: libc::pid_t) -> String {
        let own_read = read(own);
        let sibling_read = read(target);
        // SAFETY: plain syscall.
        let ret = unsafe { libc::kill(target, libc::SIGKILL) } as isize;
        let sibling_kill = outcome(ret, 0);
        format!(
            "probe abi={abi} own-read={own_read} sibling-read={sibling_read} sibling-kill={sibling_kill}\n"
        )
    }
}
