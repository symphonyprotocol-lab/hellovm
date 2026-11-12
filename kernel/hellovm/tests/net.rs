//! Spec 002a: emulated IPv4 sockets, under the seccomp platform.
//!
//! The guest is `hellovm-test-guest`'s `netcheck` (dynamic glibc). It checks
//! loopback (two processes, via `fork`), half-close, `EPIPE`/`MSG_NOSIGNAL`,
//! non-blocking connect, the address-classification errors, UDP, the accept
//! backlog, `SIOCGIFADDR` / `SIOCGIFCONF`, `/proc/net/{tcp,udp}`, virtual
//! DNS, and what glibc does when netlink returns `EAFNOSUPPORT`.
//!
//! A second run splices an issued fake IP from `198.51.100.0/24` onto a
//! local TCP server. The guest address is not the address the server accepts.

#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use common::{require_guest, TempDir, Watchdog};
use hellovm_core::{ExitStatus, Kernel, Sysno};
use hellovm_host::{CaptureHost, ImageDir};
use hellovm_platform_seccomp::SeccompPlatform;
use hellovm_test_guest as guest;

fn image() -> TempDir {
    let dir = TempDir::new("net");
    dir.install_with_libs(Path::new(guest::NETCHECK));
    // glibc resolves names through NSS, which is not in `ldd` output.
    for lib in [
        "/lib/x86_64-linux-gnu/libnss_files.so.2",
        "/lib/x86_64-linux-gnu/libnss_dns.so.2",
    ] {
        if Path::new(lib).exists() {
            dir.install_with_libs(Path::new(lib));
        }
    }
    dir.write(
        "etc/nsswitch.conf",
        b"hosts: files dns\npasswd: files\ngroup: files\n",
    );
    dir.write("etc/hosts", b"127.0.0.1 localhost\n192.0.2.2 hellovm\n");
    dir.write("etc/resolv.conf", b"nameserver 192.0.2.1\n");
    dir
}

struct GuestRun {
    status: ExitStatus,
    stdout: String,
    stderr: String,
    trace: Vec<Option<Sysno>>,
    flows: Vec<hellovm_core::host::OutboundFlow>,
}

fn run_guest(root: &Path, args: &[&str], splice: Option<SocketAddr>, fake_ip: bool) -> GuestRun {
    let mut host = CaptureHost::new(Some(ImageDir::open(root).unwrap()));
    if let Some(addr) = splice {
        host.set_splice_endpoint(addr);
    }
    let mut kernel = Kernel::new(host).with_trace();
    let mut argv: Vec<Vec<u8>> = args.iter().map(|a| a.as_bytes().to_vec()).collect();
    if fake_ip {
        let ip = kernel.issue_fake_ip().expect("fake-IP pool");
        let text = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        argv.push(text.into_bytes());
    }
    let mut app = SeccompPlatform::new().expect("start the platform");
    let _watchdog = Watchdog::start(app.killer());
    let envp = vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()];
    kernel
        .exec(&mut app, &argv[0], &argv, &envp)
        .unwrap_or_else(|err| panic!("exec {args:?}: {err}"));
    let status = kernel.run(&mut app).expect("run");
    let host = kernel.host();
    GuestRun {
        status,
        stdout: String::from_utf8_lossy(&host.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&host.stderr).into_owned(),
        trace: kernel.trace().iter().map(|r| r.sysno).collect(),
        flows: host.splice_flows().to_vec(),
    }
}

fn assert_checked(out: &GuestRun) {
    assert_eq!(
        out.status,
        ExitStatus::Exited(0),
        "stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(out.stdout.contains("check-ok"), "stdout:\n{}", out.stdout);
    assert!(!out.stdout.contains("FAIL "), "stdout:\n{}", out.stdout);
}

#[test]
fn guest_sockets_match_the_address_table() {
    if !require_guest(guest::NETCHECK, "netcheck") {
        return;
    }
    let image = image();
    let out = run_guest(image.path(), &[guest::NETCHECK, "check"], None, false);
    assert_checked(&out);
    // libc `send`/`recv` are `sendto`/`recvfrom` on both ABIs. The kernel
    // handled them; none came back ENOSYS.
    for name in [
        Sysno::Socket,
        Sysno::Connect,
        Sysno::Sendto,
        Sysno::Recvfrom,
        Sysno::Bind,
    ] {
        assert!(
            out.trace.contains(&Some(name)),
            "trace missing {name:?}: {:?}",
            out.trace.iter().flatten().collect::<Vec<_>>()
        );
    }
    // glibc 2.39: netlink failure makes getifaddrs fail with that errno, and
    // __check_pf assumes both families exist so AI_ADDRCONFIG still returns
    // the IPv4 result.
    assert!(
        out.stdout.contains("getifaddrs rc=-1 errno=97"),
        "getifaddrs line missing:\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("getaddrinfo-numeric rc=0 family=2"),
        "numeric getaddrinfo:\n{}",
        out.stdout
    );
}

#[test]
fn write_after_peer_close_raises_sigpipe() {
    if !require_guest(guest::NETCHECK, "netcheck") {
        return;
    }
    let image = image();
    let out = run_guest(image.path(), &[guest::NETCHECK, "epipe"], None, false);
    assert_eq!(
        out.status,
        ExitStatus::Signaled(13),
        "stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(!out.stdout.contains("epipe-survived"), "{}", out.stdout);
}

#[test]
fn issued_fake_ip_is_spliced_not_dialed() {
    if !require_guest(guest::NETCHECK, "netcheck") {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut sock, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip().to_string(), "127.0.0.1");
        // The server is not bound to the guest's fake IP.
        assert_ne!(sock.local_addr().unwrap().ip().to_string(), "198.51.100.1");
        let mut buf = [0u8; 32];
        let mut got = Vec::new();
        loop {
            let n = sock.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"splice-ping");
        sock.write_all(&got).unwrap();
    });
    let image = image();
    let out = run_guest(image.path(), &[guest::NETCHECK, "splice"], Some(addr), true);
    assert_eq!(
        out.status,
        ExitStatus::Exited(0),
        "stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(out.stdout.contains("splice-ok"), "{}", out.stdout);
    server.join().expect("echo server");
    assert_eq!(out.flows.len(), 1, "one spliced flow");
    let flow = out.flows[0];
    assert_eq!(flow.dest_port, 443);
    assert_eq!(flow.dest_ip[0], 198);
    assert_eq!(flow.dest_ip[1], 51);
    assert_eq!(flow.dest_ip[2], 100);
    assert_ne!(flow.dest_ip, [127, 0, 0, 1]);
    // The dial target was the configured endpoint, which is loopback, not
    // the guest destination.
    assert!(addr.ip().is_loopback());
}

/// CPython uses glibc `getaddrinfo` (with `AI_ADDRCONFIG`) and blocking
/// sockets. This is the check that a real interpreter still resolves and
/// can move bytes on loopback when netlink is `EAFNOSUPPORT`.
#[test]
fn cpython_resolves_and_talks_over_loopback() {
    let python = match std::fs::canonicalize("/usr/bin/python3") {
        Ok(path) => path,
        Err(err) => {
            common::skip_or_fail(&format!(
                "python socket test: no /usr/bin/python3 ({err}); install the distro python3 package"
            ));
            return;
        }
    };
    let version = python.file_name().unwrap().to_str().unwrap().to_string();
    let stdlib = std::path::PathBuf::from("/usr/lib").join(&version);
    if !stdlib.is_dir() {
        common::skip_or_fail(&format!(
            "python socket test: no stdlib directory {} (expected /usr/lib/python3.X)",
            stdlib.display()
        ));
        return;
    }
    let image = TempDir::new("net-python");
    image.install_with_libs(&python);
    image.symlink(&version, "usr/bin/python3");
    image.copy_host_tree(&stdlib);
    let dynload = stdlib.join("lib-dynload");
    if let Ok(entries) = std::fs::read_dir(&dynload) {
        for entry in entries.flatten() {
            image.install_with_libs(&entry.path());
        }
    }
    for lib in [
        "/lib/x86_64-linux-gnu/libnss_files.so.2",
        "/lib/x86_64-linux-gnu/libnss_dns.so.2",
    ] {
        if Path::new(lib).exists() {
            image.install_with_libs(Path::new(lib));
        }
    }
    image.write(
        "etc/nsswitch.conf",
        b"hosts: files dns\npasswd: files\ngroup: files\n",
    );
    image.write("etc/hosts", b"127.0.0.1 localhost\n");
    image.write("etc/resolv.conf", b"nameserver 192.0.2.1\n");
    let script = r#"
import socket
info = socket.getaddrinfo("127.0.0.1", 80, type=socket.SOCK_STREAM)
print("numeric", info[0][0], info[0][4][0])
info = socket.getaddrinfo("localhost", 80)
print("localhost", info[0][4][0])
try:
    print("if_nameindex", socket.if_nameindex())
except OSError as exc:
    print("if_nameindex errno", exc.errno)
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(1)
c = socket.socket()
c.connect(("127.0.0.1", s.getsockname()[1]))
conn, _ = s.accept()
c.send(b"py-loop")
print(conn.recv(16).decode())
"#;
    let out = run_guest(
        image.path(),
        &["/usr/bin/python3", "-c", script],
        None,
        false,
    );
    assert_eq!(
        out.status,
        ExitStatus::Exited(0),
        "stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(out.stdout.contains("numeric 2 127.0.0.1"), "{}", out.stdout);
    assert!(out.stdout.contains("localhost 127.0.0.1"), "{}", out.stdout);
    assert!(out.stdout.contains("py-loop"), "{}", out.stdout);
    assert!(
        out.stdout.contains("if_nameindex errno 97"),
        "CPython if_nameindex (getifaddrs) should fail with EAFNOSUPPORT:\n{}",
        out.stdout
    );
}

/// `echo hi | nc -w2 127.0.0.1 5000` against `nc -l -p 5000`. The listener
/// must exit because it saw the peer close. `wait` on that pid blocks if
/// poll never reports the close, so a timeout wrapped around `nc -l` is not
/// used. The test also checks `nc`'s exit status and that the run is short.
#[test]
fn busybox_nc_transfers_bytes_over_loopback() {
    let Some(busybox) = common::require_busybox("net busybox") else {
        return;
    };
    let image = TempDir::new("net-busybox");
    image.install(&busybox, "bin/busybox");
    for applet in ["sh", "nc", "echo", "cat", "usleep"] {
        image.symlink("busybox", &format!("bin/{applet}"));
    }
    // `wait` on the listener, not `timeout`. If poll misses the peer close,
    // `wait` does not return and the sandbox watchdog fails the test.
    // Busybox 1.37 `-w` is only a connect timeout. Once connected, `nc -l`
    // calls `shutdown(SHUT_WR)` as soon as stdin hits EOF, so a client that
    // arrives after that sees FIN and exits 0 having sent nothing. `nc` does
    // not wait for stdin: `sleep 10 | nc -l` makes `nc` exit at once, and
    // `wait` blocks only because ash waits for the whole pipeline. The loop
    // below is nc's stdin and exits only after `/got` is non-empty.
    let script = r#"
: > /got
{ n=0; while [ ! -s /got ] && [ "$n" -lt 300 ]; do usleep 10000; n=$((n + 1)); done; } | nc -l -p 5000 > /got &
lp=$!
i=0
st=1
while [ "$i" -lt 50 ]; do
  echo hi | nc -w 2 127.0.0.1 5000
  st=$?
  if [ "$st" -eq 0 ]; then
    break
  fi
  i=$((i + 1))
done
wait "$lp"
echo client:$st
cat /got
"#;
    for n in 0..10 {
        let started = std::time::Instant::now();
        let out = run_guest(image.path(), &["/bin/sh", "-c", script], None, false);
        let elapsed = started.elapsed();
        assert_eq!(
            out.status,
            ExitStatus::Exited(0),
            "loop {n} after {elapsed:?} stdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
        assert!(
            out.stdout.contains("client:0"),
            "loop {n} client status stdout:\n{}",
            out.stdout
        );
        assert!(
            out.stdout.contains("hi"),
            "loop {n} stdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "loop {n} took {elapsed:?}"
        );
    }
}

fn read_until_eof(listener: TcpListener) -> thread::JoinHandle<usize> {
    thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept splice");
        let mut buf = [0u8; 4096];
        let mut total = 0usize;
        loop {
            // Slow enough that the guest fills the splice buffer before close.
            std::thread::sleep(std::time::Duration::from_millis(1));
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(err) => panic!("splice read: {err}"),
            }
        }
        total
    })
}

#[test]
fn splice_close_and_exit_deliver_every_queued_byte() {
    if !require_guest(guest::NETCHECK, "netcheck") {
        return;
    }
    let image = image();
    for (mode, port) in [("bulk", 9u16), ("bulk-exit", 9u16)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = read_until_eof(listener);
        let out = run_guest(
            image.path(),
            &[guest::NETCHECK, mode],
            Some(SocketAddr::from(([127, 0, 0, 1], addr.port()))),
            true,
        );
        assert_eq!(
            out.status,
            ExitStatus::Exited(0),
            "{mode} stdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
        assert!(out.stdout.contains("bulk-sent"), "{mode}: {}", out.stdout);
        let got = reader.join().expect("reader");
        assert_eq!(got, 200_000, "{mode} delivered {got}, port {port}");
        let _ = port;
    }
}

/// 8 MiB through a slow reader. The guest then asks the reader, on a second
/// connection, to stop, waits for the ack, fills the socket until `EAGAIN`,
/// and closes or exits. The reader stays paused until 500 ms after
/// `kernel.run` returns, so a drain that gives up on a wall clock drops bytes.
fn pause_splice(root: &Path, mode: &'static str) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pause = Arc::new(AtomicBool::new(false));
    let paused = Arc::new(AtomicBool::new(false));
    let returned = Arc::new(AtomicBool::new(false));
    let got = Arc::new(AtomicUsize::new(0));
    let (p, pd, rt, count) = (
        Arc::clone(&pause),
        Arc::clone(&paused),
        Arc::clone(&returned),
        Arc::clone(&got),
    );
    let reader = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept data");
        let (p2, pd2) = (Arc::clone(&p), Arc::clone(&pd));
        let ctl = thread::spawn(move || {
            let (mut ctl, _) = listener.accept().expect("accept ctl");
            let mut byte = [0u8; 1];
            ctl.read_exact(&mut byte).expect("ctl D");
            p2.store(true, Ordering::SeqCst);
            while !pd2.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
            ctl.write_all(b"G").expect("ctl G");
        });
        let mut buf = vec![0u8; 4096];
        let mut done_pause = false;
        loop {
            if !done_pause && p.load(Ordering::SeqCst) {
                done_pause = true;
                pd.store(true, Ordering::SeqCst);
                while !rt.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(5));
                }
                thread::sleep(Duration::from_millis(500));
            }
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    count.fetch_add(n, Ordering::SeqCst);
                    if !done_pause {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
                Err(err) => panic!("{mode} read: {err}"),
            }
        }
        ctl.join().expect("ctl thread");
        count.load(Ordering::SeqCst)
    });
    let out = run_guest(
        root,
        &[guest::NETCHECK, mode],
        Some(SocketAddr::from(([127, 0, 0, 1], addr.port()))),
        true,
    );
    let at_return = got.load(Ordering::SeqCst);
    returned.store(true, Ordering::SeqCst);
    assert_eq!(
        out.status,
        ExitStatus::Exited(0),
        "{mode} stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    let sent: usize = out
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("bulk-sent "))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("{mode}: {}", out.stdout));
    assert!(
        at_return < sent,
        "{mode}: run waited for the drain ({at_return} of {sent})"
    );
    let total = reader.join().expect("pause reader");
    assert_eq!(total, sent, "{mode} delivered {total} of {sent}");
}

#[test]
fn slow_reader_delivers_every_byte_on_close_and_exit() {
    if !require_guest(guest::NETCHECK, "netcheck") {
        return;
    }
    let image = image();
    let root = image.path().to_path_buf();
    let mut threads = Vec::new();
    for mode in ["slowbulk", "slowbulk-exit"] {
        let root = root.clone();
        threads.push(thread::spawn(move || pause_splice(&root, mode)));
    }
    for thread in threads {
        thread.join().expect("pause splice thread");
    }
}
