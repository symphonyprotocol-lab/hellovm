//! What the Seatbelt profile lets the confined process reach, with and
//! without `--egress`, tried from inside a process that applied it with
//! `hellovm_sandbox::apply` (`--sandbox require`).
//!
//! The confined process here is this test binary itself, started again
//! with `HELLOVM_SEATBELT_PROBE` set: a process with no VM, so trying
//! what the profile refuses touches nothing but sockets (see README,
//! "Hardening", on why break-out attempts are not made against a
//! process that holds a VM). It has no test harness (`harness = false`)
//! so that the confined process runs no thread and makes no system call
//! of its own besides the attempts.
//!
//! With `--egress`: the egress socket can be connected to, also after a
//! proxy restart made a new socket at the same path; another Unix socket
//! and TCP to a listening loopback port are refused (`EPERM`); a Unix
//! datagram (to either path), a UDP datagram and name resolution kill the
//! process. Without `--egress` making any socket kills it.

#[cfg(not(target_os = "macos"))]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {
    if let Some(mode) = std::env::var_os("HELLOVM_SEATBELT_PROBE") {
        probe::child(&mode.to_string_lossy());
    } else {
        probe::parent();
    }
}

#[cfg(target_os = "macos")]
mod probe {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    const KILLED: i32 = libc::SIGKILL;

    fn sockaddr(path: &Path) -> (libc::sockaddr_un, libc::socklen_t) {
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: zeroed plain-old-data struct.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let bytes = path.as_os_str().as_bytes();
        assert!(bytes.len() < addr.sun_path.len());
        for (dst, &src) in addr.sun_path.iter_mut().zip(bytes) {
            *dst = src as libc::c_char;
        }
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        addr.sun_len = len as u8;
        (addr, len)
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// `Ok(fd)` or `Err(errno)`.
    fn socket(domain: i32, ty: i32) -> Result<i32, i32> {
        // SAFETY: plain socket call.
        let fd = unsafe { libc::socket(domain, ty, 0) };
        if fd < 0 {
            Err(errno())
        } else {
            Ok(fd)
        }
    }

    /// Connects a new Unix stream socket to `path`; the fd or the errno of
    /// the first call that failed.
    fn connect_unix(path: &Path) -> Result<i32, String> {
        let fd = socket(libc::AF_UNIX, libc::SOCK_STREAM).map_err(|e| format!("socket {e}"))?;
        let (addr, len) = sockaddr(path);
        // SAFETY: a valid sockaddr_un of `len` bytes.
        let ret = unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), len) };
        if ret != 0 {
            let e = errno();
            // SAFETY: closes the fd just made.
            unsafe { libc::close(fd) };
            return Err(format!("connect {e}"));
        }
        Ok(fd)
    }

    fn loopback(port: u16) -> libc::sockaddr_in {
        // SAFETY: zeroed plain-old-data struct.
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = port.to_be();
        sin.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        sin
    }

    fn say(line: &str) {
        let line = format!("{line}\n");
        // SAFETY: write from a valid buffer to stdout.
        unsafe { libc::write(1, line.as_ptr().cast(), line.len()) };
    }

    /// One line from stdin (a byte at a time: no buffering thread).
    fn wait_line() {
        let mut byte = 0u8;
        // SAFETY: reads one byte into `byte`.
        while unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) } == 1 && byte != b'\n' {}
    }

    /// The confined process. Arguments: the image directory, the egress
    /// socket (or `-`), the other Unix socket, the TCP port.
    pub fn child(mode: &str) {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let image = PathBuf::from(&args[0]);
        let egress = (args[1] != "-").then(|| PathBuf::from(&args[1]));
        let other = PathBuf::from(&args[2]);
        let port: u16 = args[3].parse().unwrap();
        let report = hellovm_sandbox::apply(hellovm_sandbox::Config {
            mode: hellovm_sandbox::Mode::Require,
            image_path: &image,
            egress: egress.as_deref(),
            learn: false,
            broken: false,
            fds: Ok(0),
        });
        if let Err(err) = report {
            say(&format!("not confined: {err}"));
            std::process::exit(3);
        }
        say("confined");
        match mode {
            "egress" => {
                let egress = egress.unwrap();
                say(&format!("egress {:?}", connect_unix(&egress).map(|_| ())));
                // The parent restarts the proxy now.
                wait_line();
                say(&format!(
                    "restarted {:?}",
                    connect_unix(&egress).map(|_| ())
                ));
                say(&format!("other {:?}", connect_unix(&other).map(|_| ())));
                // To a loopback port that listens.
                let tcp = socket(libc::AF_INET, libc::SOCK_STREAM).map(|fd| {
                    let sin = loopback(port);
                    // SAFETY: a valid sockaddr_in.
                    let ret = unsafe {
                        libc::connect(
                            fd,
                            (&sin as *const libc::sockaddr_in).cast(),
                            sin.sin_len as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        errno()
                    } else {
                        0
                    }
                });
                say(&format!("tcp {tcp:?}"));
                say("done");
            }
            // `sendto` is not allowed at all: these are killed.
            "unix-dgram" | "unix-dgram-egress" => {
                // Datagrams to the other path and to the egress path.
                let dgram = |path: &Path| {
                    socket(libc::AF_UNIX, libc::SOCK_DGRAM).map(|fd| {
                        let (addr, len) = sockaddr(path);
                        // SAFETY: one byte from a valid buffer to a valid address.
                        let ret = unsafe {
                            libc::sendto(
                                fd,
                                b"x".as_ptr().cast(),
                                1,
                                0,
                                (&addr as *const libc::sockaddr_un).cast(),
                                len,
                            )
                        };
                        if ret < 0 {
                            errno()
                        } else {
                            0
                        }
                    })
                };
                let to = if mode == "unix-dgram" {
                    other
                } else {
                    egress.unwrap()
                };
                say(&format!("{mode} {:?}", dgram(&to)));
            }
            "udp" => {
                let udp = socket(libc::AF_INET, libc::SOCK_DGRAM).map(|fd| {
                    let sin = loopback(port);
                    // SAFETY: one byte from a valid buffer to a valid address.
                    let ret = unsafe {
                        libc::sendto(
                            fd,
                            b"x".as_ptr().cast(),
                            1,
                            0,
                            (&sin as *const libc::sockaddr_in).cast(),
                            sin.sin_len as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        errno()
                    } else {
                        0
                    }
                });
                say(&format!("udp {udp:?}"));
            }
            "resolve" => {
                let mut res: *mut libc::addrinfo = std::ptr::null_mut();
                // SAFETY: valid C strings; `res` is an out pointer.
                let ret = unsafe {
                    libc::getaddrinfo(
                        c"localhost".as_ptr(),
                        c"80".as_ptr(),
                        std::ptr::null(),
                        &mut res,
                    )
                };
                say(&format!("resolve {ret}"));
            }
            "no-egress" => {
                say(&format!("egress {:?}", connect_unix(&other).map(|_| ())));
            }
            _ => unreachable!(),
        }
        std::process::exit(0);
    }

    struct Run {
        lines: Vec<String>,
        signal: Option<i32>,
    }

    fn run(
        mode: &str,
        image: &Path,
        egress: Option<&Path>,
        other: &Path,
        port: u16,
        restart: impl FnOnce(),
    ) -> Run {
        let egress_arg = egress.map_or("-".into(), |p| p.display().to_string());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .env("HELLOVM_SEATBELT_PROBE", mode)
            .arg(image)
            .arg(egress_arg)
            .arg(other)
            .arg(port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut lines = Vec::new();
        let mut restart = Some(restart);
        loop {
            let mut line = String::new();
            if out.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let line = line.trim_end().to_string();
            if line.starts_with("egress ") {
                if let Some(restart) = restart.take() {
                    restart();
                    let _ = stdin.write_all(b"\n");
                }
            }
            lines.push(line);
        }
        let status = child.wait().unwrap();
        Run {
            lines,
            signal: status.signal(),
        }
    }

    pub fn parent() {
        let dir = std::env::temp_dir().join(format!("hellovm-sb-net-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("image")).unwrap();
        // Canonical: Seatbelt sees the path a connect resolves to.
        let dir = dir.canonicalize().unwrap();
        let image = dir.join("image");
        let egress = dir.join("egress.sock");
        let other = dir.join("other.sock");
        let egress_listener = std::cell::RefCell::new(Some(UnixListener::bind(&egress).unwrap()));
        let _other = UnixListener::bind(&other).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let mut failures = Vec::new();
        let mut check = |what: &str, ok: bool, run: &Run| {
            if !ok {
                failures.push(format!("{what}: {:?} signal {:?}", run.lines, run.signal));
            }
        };

        let r = run("egress", &image, Some(&egress), &other, port, || {
            // A proxy restart: the old socket goes, a new one at the path.
            drop(egress_listener.borrow_mut().take());
            std::fs::remove_file(&egress).unwrap();
            *egress_listener.borrow_mut() = Some(UnixListener::bind(&egress).unwrap());
        });
        // Making a socket of any kind is not checked; connecting it to
        // anything but the egress socket is (EPERM), and sending a
        // datagram is not a system call the profile allows (killed).
        let eperm = format!("Ok({})", libc::EPERM);
        let expected = [
            "confined".to_string(),
            "egress Ok(())".into(),
            "restarted Ok(())".into(),
            format!("other Err(\"connect {}\")", libc::EPERM),
            format!("tcp {eperm}"),
            "done".into(),
        ];
        check(
            "with --egress",
            r.lines == expected && r.signal.is_none(),
            &r,
        );
        // Nothing reached the other listeners.
        tcp.set_nonblocking(true).unwrap();
        let tcp_accepted = tcp.accept().is_ok();
        check("tcp listener untouched", !tcp_accepted, &r);

        for mode in ["unix-dgram", "unix-dgram-egress", "udp", "resolve"] {
            let r = run(mode, &image, Some(&egress), &other, port, || {});
            check(
                &format!("{mode} killed"),
                r.lines == ["confined"] && r.signal == Some(KILLED),
                &r,
            );
        }

        let r = run("no-egress", &image, None, &other, port, || {});
        check(
            "without --egress, a socket kills",
            r.lines == ["confined"] && r.signal == Some(KILLED),
            &r,
        );

        let mut drain = Vec::new();
        if let Some(listener) = egress_listener.borrow_mut().take() {
            listener.set_nonblocking(true).unwrap();
            while let Ok((mut conn, _)) = listener.accept() {
                let _ = conn.read_to_end(&mut drain);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        if !failures.is_empty() {
            eprintln!("seatbelt_network: FAILED");
            for f in &failures {
                eprintln!("  {f}");
            }
            std::process::exit(1);
        }
        println!("seatbelt_network: ok (with --egress, resolution, without --egress)");
    }
}
