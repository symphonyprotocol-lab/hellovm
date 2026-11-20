//! `--insecure-fence-test` on macOS: from inside the hardened kernel
//! process (the VM and vCPU made, the image open, the sandbox entered),
//! tries one thing, reports and exits: 0 when it was refused, 1 when it
//! worked. A process the profile kills (a system call outside its
//! allowlist) never gets to report; the tests count that as refused too.
//!
//! Only ordinary system calls on files, sockets and signals are tried.
//! Attempts on the hypervisor (a second VM, replacing the VM), IOKit,
//! process creation, task ports and sysctls were removed: running them
//! (together, on macOS 27.2 on an M3 Max) coincided with two kernel
//! panics of the host, and which one caused it is not known (README,
//! "Hardening").
//!
//! `TEST` is `NAME` or `NAME:ARG`:
//!
//! | Test | What it tries |
//! |---|---|
//! | `read:PATH` | open and read `PATH` |
//! | `read-above-image:NAME` | `openat(fd, "../NAME")` from every fd the process holds |
//! | `list:PATH` | read the directory `PATH` |
//! | `write:PATH` | create `PATH` and write to it |
//! | `tcp:ADDR` | connect a TCP socket to `ADDR` |
//! | `udp:ADDR` | send a UDP datagram to `ADDR` |
//! | `unix:PATH` | connect to the Unix socket `PATH` |
//! | `resolve:NAME` | resolve a host name |
//! | `signal:PID` | send `SIGTERM` to `PID` |
//! | `env` | read the environment (expected: empty) |
//! | `state` | report the open fds and the number of environment variables (always "allowed") |
//! | `read-image:REL` | read `IMAGE/REL` by its host path (expected: allowed) |

use std::ffi::{c_int, CString};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::Path;

fn last() -> String {
    std::io::Error::last_os_error().to_string()
}

fn pid(arg: &str) -> c_int {
    arg.parse().unwrap_or_else(|_| {
        eprintln!("fence: not a pid: {arg}");
        std::process::exit(2)
    })
}

fn cstr(arg: &str) -> CString {
    CString::new(arg).expect("no NUL in a test argument")
}

fn attempt(name: &str, arg: &str, image: &Path) -> Result<String, String> {
    match name {
        "read" | "read-image" => {
            let path = if name == "read" {
                Path::new(arg).to_path_buf()
            } else {
                image.join(arg)
            };
            // read(), not read_to_end (which also calls lseek, a system
            // call the kernel process never makes).
            let mut buf = [0u8; 4096];
            std::fs::File::open(&path)
                .and_then(|mut f| f.read(&mut buf))
                .map(|n| format!("read {n} bytes of {}", path.display()))
                .map_err(|err| err.to_string())
        }
        "read-above-image" => {
            let rel = cstr(&format!("../{arg}"));
            let found = (3..256).find(|&fd| {
                // SAFETY: openat with a valid C string.
                let up = unsafe { libc::openat(fd, rel.as_ptr(), libc::O_RDONLY) };
                if up >= 0 {
                    // SAFETY: the fd just opened.
                    unsafe { libc::close(up) };
                }
                up >= 0
            });
            match found {
                Some(fd) => Ok(format!("opened ../{arg} from fd {fd}")),
                None => Err("no fd leads above the image".into()),
            }
        }
        "list" => std::fs::read_dir(arg)
            .map(|dir| format!("{} entries", dir.count()))
            .map_err(|err| err.to_string()),
        "write" => std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(arg)
            .and_then(|mut f| f.write_all(b"written from the kernel process\n"))
            .map(|()| format!("wrote {arg}"))
            .map_err(|err| err.to_string()),
        "tcp" => std::net::TcpStream::connect(arg)
            .map(|_| "connected".into())
            .map_err(|err| err.to_string()),
        "udp" => std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.send_to(b"x", arg))
            .map(|n| format!("sent {n} bytes"))
            .map_err(|err| err.to_string()),
        "unix" => std::os::unix::net::UnixStream::connect(arg)
            .map(|_| "connected".into())
            .map_err(|err| err.to_string()),
        "resolve" => std::net::ToSocketAddrs::to_socket_addrs(&(arg, 80))
            .map(|addrs| format!("{} addresses", addrs.count()))
            .map_err(|err| err.to_string()),
        "signal" => {
            // SAFETY: plain libc call.
            if unsafe { libc::kill(pid(arg), libc::SIGTERM) } == 0 {
                Ok("signalled".into())
            } else {
                Err(last())
            }
        }
        "state" => {
            // fcntl(F_GETFD) on each: proc_pidinfo, which the hardening
            // uses before the profile, is not allowed in it (nor is
            // getrlimit: `HELLOVM_LOG=debug` shows the limits).
            // SAFETY: F_GETFD on any number is harmless.
            let fds: Vec<i32> = (0..1024)
                .filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1)
                .collect();
            Ok(format!("fds={fds:?} env={}", std::env::vars_os().count()))
        }
        "env" => match std::env::vars_os().next() {
            Some((name, _)) => Ok(format!("{} is set", name.to_string_lossy())),
            None => Err("the environment is empty".into()),
        },
        _ => {
            eprintln!("fence: unknown test {name}");
            std::process::exit(2)
        }
    }
}

pub fn run(test: &str, image: &Path) -> ! {
    let (name, arg) = test.split_once(':').unwrap_or((test, ""));
    let outcome = attempt(name, arg, image);
    // Through fd 1 directly: the outcome must reach the test even if the
    // standard library's stdout cannot be used.
    // SAFETY: fd 1 stays open; ManuallyDrop keeps it from being closed.
    let mut out = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) });
    let (line, code) = match outcome {
        Ok(what) => (format!("fence: {test}: allowed: {what}\n"), 1),
        Err(why) => (format!("fence: {test}: refused: {why}\n"), 0),
    };
    let _ = out.write_all(line.as_bytes());
    std::process::exit(code)
}
