//! Egress on macOS (the HVF platform), through the `hellovm` command line
//! with `--sandbox require`: a guest resolves names and connects over TCP
//! through the `hellovm-egress` proxy, which this test runs in-process
//! with its test name table pointing allowed names at loopback servers of
//! the test. The same outcomes as on Linux (`egress.rs`): an allowed flow
//! carries bytes both ways and is audited with the kernel process as its
//! peer, a denied one is `ECONNREFUSED`, an address the kernel did not
//! hand out is `ENETUNREACH` and never reaches the proxy, and without
//! `--egress` names do not resolve. A stalled flow does not hold up
//! another, and a proxy that restarts at the same path is reached again.
//!
//! The guests are CPython from the guest image (`HELLOVM_HVF_GUESTS`).
//! What the confined process itself can reach (only the egress socket)
//! is `hellovm-sandbox`'s `tests/seatbelt_network.rs`.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod hvf_support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hellovm_egress::audit::{AuditSink, MemorySink};
use hellovm_egress::policy::Policy;
use hellovm_egress::resolve::Resolver;
use hellovm_egress::{Config, Limits, Proxy, ProxyHandle};
use hvf_support::{guest_image, hellovm, progress};

const SANDBOX_ID: &str = "0000000000e97e55";

const POLICY: &str = "allow allowed.test:80\nallow stall.test:80\n";

/// A loopback HTTP server: answers every request with one line, and
/// counts the connections it accepted.
struct Server {
    port: u16,
    accepted: Arc<AtomicUsize>,
}

const BODY: &str = "hello-through-egress\n";

impl Server {
    /// `answer`: false for a server that accepts and then neither reads
    /// nor writes.
    fn start(answer: bool) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        // Ends with the test process.
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { continue };
                count.fetch_add(1, Ordering::SeqCst);
                if !answer {
                    held.push(conn);
                    continue;
                }
                std::thread::spawn(move || {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match conn.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = conn.write_all(
                        format!(
                            "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{BODY}",
                            BODY.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        Server { port, accepted }
    }
}

/// A directory for the egress socket, with a short canonical path (a
/// Unix socket path holds at most 103 bytes).
struct SocketDir(PathBuf);

impl SocketDir {
    fn new(tag: &str) -> SocketDir {
        let dir = PathBuf::from("/tmp").join(format!("hv-egress-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        SocketDir(dir.canonicalize().unwrap())
    }

    fn socket(&self) -> PathBuf {
        self.0.join("egress.sock")
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn proxy(socket: &Path, table: &str) -> (ProxyHandle, MemorySink) {
    let mut policy = Policy::new();
    policy.add_file(POLICY).unwrap();
    let audit = MemorySink::default();
    let config = Config {
        policy,
        limits: Limits::default(),
        audit: AuditSink::new(Box::new(audit.clone())),
        resolver: Resolver::parse_test_table(table).unwrap(),
    };
    (Proxy::bind(socket, config).unwrap().spawn(), audit)
}

fn audit_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(' ')
        .find_map(|kv| kv.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
}

/// The audit line for `host` with `reason`, after waiting for it.
fn audit_line(audit: &MemorySink, host: &str, reason: &str) -> String {
    let start = Instant::now();
    loop {
        let lines = audit.lines();
        if let Some(line) = lines.iter().find(|l| {
            audit_field(l, "host") == Some(host) && audit_field(l, "reason") == Some(reason)
        }) {
            return line.clone();
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no audit line for {host} reason={reason}:\n{}",
            lines.join("\n")
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `hellovm --sandbox require` running `python3 -c script` from the guest
/// image, with these extra options.
fn python(exe: &Path, root: &Path, extra: &[&str], script: &str) -> Command {
    let mut cmd = Command::new(exe);
    cmd.args(["--sandbox", "require", "--no-tty", "--timeout", "60"])
        .args(extra)
        .arg("--root")
        .arg(root)
        .args(["/usr/bin/python3", "-c", script]);
    cmd
}

fn show(out: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// What every guest here can call.
const PRELUDE: &str = r#"
import socket, sys

def out(*a):
    print(*a, flush=True)

def errno_of(fn):
    try:
        fn()
        return "connected"
    except socket.gaierror:
        return "gaierror"
    except OSError as e:
        return e.errno

def fetch(host):
    with socket.create_connection((host, 80), timeout=20) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    return data.endswith(b"hello-through-egress\n")

def try_fetch(host):
    try:
        return fetch(host)
    except socket.gaierror:
        return "gaierror"
    except OSError as e:
        return e.errno

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return "gaierror"
"#;

/// The cases with a proxy, one guest run: each prints a line.
const CASES: &str = r#"
port = int(sys.argv[1])
out("addr", resolve("allowed.test"))

# A flow whose peer never reads, filled until it blocks: it must not
# hold up the next one.
stall = socket.create_connection(("stall.test", 80), timeout=20)
stall.sendall(b"GET / HTTP/1.1\r\nHost: stall.test\r\n\r\n")
stall.setblocking(False)
sent = 0
try:
    while sent < 64 << 20:
        sent += stall.send(b"x" * 65536)
except BlockingIOError:
    pass
out("stalled", sent > 0, sent < 64 << 20)

out("allowed", try_fetch("allowed.test"))
out("denied", errno_of(lambda: socket.create_connection(("denied.test", 80), timeout=20)))
out("raw-ip", errno_of(lambda: socket.create_connection(("151.101.0.223", 443), timeout=20)))
# The test's server listens on the host's loopback: the guest's own
# loopback is another one, where nothing listens.
out("loopback", errno_of(lambda: socket.create_connection(("127.0.0.1", port), timeout=20)))
stall.close()
"#;

fn table(allowed: &Server, stall: &Server) -> String {
    format!(
        "allowed.test 127.0.0.1:{a}\ndenied.test 127.0.0.1:{a}\nstall.test 127.0.0.1:{s}\n",
        a = allowed.port,
        s = stall.port
    )
}

#[test]
fn the_proxy_decides_every_outbound_flow() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let Some(root) = guest_image() else {
        return;
    };
    let server = Server::start(true);
    let stall = Server::start(false);
    let dir = SocketDir::new("cases");
    let (_proxy, audit) = proxy(&dir.socket(), &table(&server, &stall));
    progress("hvf_egress: cases");
    let socket = dir.socket();
    let started = Instant::now();
    let out = python(
        exe,
        &root,
        &[
            "--egress",
            socket.to_str().unwrap(),
            "--sandbox-id",
            SANDBOX_ID,
        ],
        &format!("{PRELUDE}{CASES}"),
    )
    .arg(server.port.to_string())
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", show(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "addr 198.51.100.1",
            "stalled True True",
            "allowed True",
            "denied 111",
            "raw-ip 101",
            "loopback 111",
        ],
        "{}",
        show(&out)
    );
    // Well before any of the 20 s timeouts: nothing waited on the stall.
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{}",
        show(&out)
    );
    // Only the proxy reached the servers.
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(stall.accepted.load(Ordering::SeqCst), 1);
    // Audited as on Linux, with the kernel process as the peer.
    let allowed = audit_line(&audit, "allowed.test", "ok");
    assert_eq!(audit_field(&allowed, "sandbox"), Some(SANDBOX_ID));
    assert_eq!(audit_field(&allowed, "verdict"), Some("allow"));
    assert_eq!(audit_field(&allowed, "port"), Some("80"));
    assert!(audit_field(&allowed, "up").unwrap().parse::<u64>().unwrap() > 0);
    assert!(
        audit_field(&allowed, "down")
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    let peer = audit_field(&allowed, "peer").unwrap();
    assert!(peer.parse::<u32>().is_ok_and(|pid| pid > 0), "{allowed}");
    let denied = audit_line(&audit, "denied.test", "policy");
    assert_eq!(audit_field(&denied, "verdict"), Some("deny"));
    assert_eq!(audit_field(&denied, "peer"), Some(peer));
    // The stalled flow is audited when it ends, which is when the proxy
    // gives up on a server that never reads: not waited for here.
    assert!(!audit.lines().iter().any(|l| l.contains("151.101")));
}

/// Without `--egress`, as on Linux: names do not resolve and no address
/// is reachable.
#[test]
fn without_egress_nothing_leaves() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let Some(root) = guest_image() else {
        return;
    };
    let server = Server::start(true);
    progress("hvf_egress: without --egress");
    let script = format!(
        "{PRELUDE}\nport = int(sys.argv[1])\n\
         out('addr', resolve('allowed.test'))\n\
         out('raw-ip', errno_of(lambda: socket.create_connection(('151.101.0.223', 443), timeout=20)))\n\
         out('loopback', errno_of(lambda: socket.create_connection(('127.0.0.1', port), timeout=20)))\n"
    );
    let out = python(exe, &root, &[], &script)
        .arg(server.port.to_string())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", show(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "addr gaierror\nraw-ip 101\nloopback 111\n",
        "{}",
        show(&out)
    );
    assert_eq!(server.accepted.load(Ordering::SeqCst), 0);
}

/// One run: no proxy yet (refused), a proxy started, then restarted at
/// the same path. The confined kernel process reaches each one, as on
/// Linux (`egress.rs`).
#[test]
fn a_proxy_that_comes_and_restarts_is_reached() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let Some(root) = guest_image() else {
        return;
    };
    let server = Server::start(true);
    let stall = Server::start(false);
    let table = table(&server, &stall);
    let dir = SocketDir::new("restart");
    let socket = dir.socket();
    let script = format!(
        "{PRELUDE}\n\
         for step in ['down', 'up', 'restarted']:\n    \
             out(step, try_fetch('allowed.test'))\n    \
             sys.stdin.readline()\n"
    );
    progress("hvf_egress: proxy down, up, restarted");
    let mut child = python(exe, &root, &["--egress", socket.to_str().unwrap()], &script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut lines = Vec::new();
    let mut proxies = Vec::new();
    for _ in 0..3 {
        let mut line = String::new();
        if stdout.read_line(&mut line).unwrap() == 0 {
            break;
        }
        lines.push(line.trim_end().to_string());
        // The next step's proxy: a first one, then a new one in its place.
        proxies.clear();
        proxies.push(proxy(&socket, &table));
        stdin.write_all(b"\n").unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        lines,
        ["down 111", "up True", "restarted True"],
        "{}",
        show(&out)
    );
    assert_eq!(out.status.code(), Some(0), "{}", show(&out));
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
}

/// The socket path is checked before the VM is made.
#[test]
fn an_egress_path_too_long_for_a_socket_is_refused() {
    let _serial = hvf_support::serial();
    let Some(exe) = hellovm() else {
        return;
    };
    let dir = SocketDir::new("long");
    let long = dir.0.join("x".repeat(120));
    let root = hvf_support::image("long", hellovm_test_guest::HELLO);
    progress("hvf_egress: long path");
    let out = Command::new(exe)
        .args(["--sandbox", "require", "--no-tty", "--egress"])
        .arg(&long)
        .arg("--root")
        .arg(&root)
        .arg("/long")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125), "{}", show(&out));
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("longer than a Unix socket path"),
        "{}",
        show(&out)
    );
}
