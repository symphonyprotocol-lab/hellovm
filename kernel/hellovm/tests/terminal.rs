//! The sandbox terminal, end to end: `hellovm` runs an interactive busybox
//! shell on a host pseudo-terminal, as a person at a terminal would.

#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::TempDir;

/// `hellovm` on the slave side of a host pty.
struct Session {
    master: std::fs::File,
    output: Arc<Mutex<Vec<u8>>>,
    child: Child,
    /// How much of `output` the expectations have consumed.
    seen: usize,
}

impl Session {
    fn start(root: &Path, argv: &[&str]) -> Session {
        let (mut master, mut slave) = (-1, -1);
        let ws = libc::winsize {
            ws_row: 30,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty with valid out pointers and a winsize.
        let ret = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &ws,
            )
        };
        assert_eq!(ret, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: openpty returned two fds we own.
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let mut command = Command::new(env!("CARGO_BIN_EXE_hellovm"));
        command
            .args(["--timeout", "60", "--env", "TERM=dumb", "--root"])
            .arg(root)
            .args(argv)
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY, 0);
                Ok(())
            });
        }
        let child = command.spawn().expect("start hellovm");
        let master = std::fs::File::from(master);
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut reader = master.try_clone().unwrap();
        let sink = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Session {
            master,
            output,
            child,
            seen: 0,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
    }

    /// Waits until the output after what was seen so far contains `text`;
    /// returns that output.
    fn expect(&mut self, text: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            {
                let out = self.output.lock().unwrap();
                let fresh = String::from_utf8_lossy(&out[self.seen..]).into_owned();
                if let Some(at) = fresh.find(text) {
                    self.seen += at + text.len();
                    return fresh;
                }
                assert!(
                    Instant::now() < deadline,
                    "waiting for {text:?}; got {fresh:?}"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait(mut self) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            assert!(Instant::now() < deadline, "hellovm did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn busybox_image() -> Option<TempDir> {
    let path = std::env::var("HELLOVM_BUSYBOX").unwrap_or_else(|_| "/bin/busybox".into());
    if !Path::new(&path).exists() {
        eprintln!("SKIPPING terminal test: {path} not found (install busybox-static)");
        return None;
    }
    let image = TempDir::new("terminal");
    image.install(&path, "bin/busybox");
    for applet in ["sh", "sleep", "tty", "stty", "echo", "cat"] {
        image.symlink("busybox", &format!("bin/{applet}"));
    }
    image.write("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n");
    image.mkdir("root");
    Some(image)
}

#[test]
fn an_interactive_shell_on_the_terminal() {
    let Some(image) = busybox_image() else { return };
    let mut s = Session::start(image.path(), &["/bin/sh", "-i"]);
    s.expect("# ");
    // The quotes vanish only if the shell ran the command; the echo of the
    // typed line comes first.
    s.send(b"echo hel''lo\r");
    s.expect("hello\r\n");
    s.send(b"tty; stty size\r");
    s.expect("/dev/console\r\n30 100\r\n");
    // Ctrl-C ends the foreground job, not the shell.
    s.send(b"sleep 30\r");
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    s.send(b"\x03");
    s.expect("# ");
    assert!(started.elapsed() < Duration::from_secs(10));
    s.send(b"echo after $?\r");
    s.expect("after 130\r\n");
    // Ctrl-Z stops it; fg brings it back, and Ctrl-C ends it.
    s.send(b"sleep 30\r");
    std::thread::sleep(Duration::from_millis(500));
    s.send(b"\x1a");
    s.expect("# ");
    s.send(b"fg\r");
    std::thread::sleep(Duration::from_millis(500));
    s.send(b"\x03");
    s.expect("# ");
    // A line editing typo, fixed with backspace.
    s.send(b"exit 6\x7f5\r");
    assert_eq!(s.wait(), 5);
}

#[test]
fn reading_a_line_from_the_terminal() {
    let Some(image) = busybox_image() else { return };
    let mut s = Session::start(
        image.path(),
        &[
            "/bin/sh",
            "-c",
            "read line; echo \"got <$line>\"; cat; echo done",
        ],
    );
    s.send(b"abc\x17xyz\r");
    s.expect("got <xyz>\r\n");
    // cat reads lines until ^D on an empty line.
    s.send(b"one\r");
    s.expect("one\r\n");
    s.send(b"\x04");
    s.expect("done\r\n");
    assert_eq!(s.wait(), 0);
}
