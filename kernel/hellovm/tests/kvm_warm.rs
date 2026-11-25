//! Warm clones on the KVM platform (`--platform kvm`, arm64 Linux with
//! `/dev/kvm`), end to end: the tests of `hvf_warm.rs` (`vm_warm/tests.rs`)
//! with CPython and busybox from the guest image (`HELLOVM_KVM_GUESTS`),
//! under `--sandbox require`, and what only KVM clones have: an ingress
//! channel, and memory mapped from the snapshot file without growing it.
//! Without `/dev/kvm` the tests print `SKIPPING` and pass, unless
//! `HELLOVM_REQUIRE_E2E=1`. Built only with the `kvm-tests` feature
//! (`kernel/dev/run-kvm-lima.sh`), as `kvm_cli.rs`.

#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

#[path = "vm_memory/mod.rs"]
mod vm_memory;

mod support {
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    pub use super::vm_memory::FREE_AND_REUSE;

    pub const PLATFORM_ARGS: &[&str] = &["--platform", "kvm"];
    pub const INGRESS: bool = true;

    fn require() -> bool {
        std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1")
    }

    /// `hellovm` and the guest image, or `None` (skipped) without KVM or
    /// without the image.
    pub fn setup() -> Option<(&'static Path, PathBuf)> {
        if let Err(err) = hellovm_platform_kvm::check_access() {
            if require() {
                panic!("HELLOVM_REQUIRE_E2E=1 but KVM is unavailable: {err}");
            }
            eprintln!("SKIPPING: KVM is unavailable: {err}");
            return None;
        }
        let root = match std::env::var_os("HELLOVM_KVM_GUESTS") {
            Some(root) => PathBuf::from(root),
            None if require() => panic!("HELLOVM_REQUIRE_E2E=1 but HELLOVM_KVM_GUESTS is not set"),
            None => {
                eprintln!("SKIPPING: set HELLOVM_KVM_GUESTS (see platform-hvf/build-guests.sh)");
                return None;
            }
        };
        Some((Path::new(env!("CARGO_BIN_EXE_hellovm")), root))
    }

    /// One test at a time: the host may have few CPUs.
    pub fn serial() -> MutexGuard<'static, ()> {
        static SERIAL: Mutex<()> = Mutex::new(());
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn progress(what: &str) {
        eprintln!("kvm_warm: {what}");
    }

    /// The kernel processes inherit `HELLOVM_SECCOMP_LEARN` from the
    /// environment the tests run in: nothing to add.
    pub fn learn_env() -> Option<(&'static str, &'static str)> {
        None
    }

    /// A field of `/proc/PID/status`, in bytes (0 when it cannot be read).
    fn status(pid: u32, field: &str) -> u64 {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        status
            .lines()
            .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
            .and_then(|kib| {
                kib.trim()
                    .trim_end_matches(" kB")
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
            .map_or(0, |kib| kib << 10)
    }

    /// The resident size (`VmRSS`).
    pub fn footprint(pid: u32) -> u64 {
        status(pid, "VmRSS")
    }

    /// What of the resident size is the process's own (`RssAnon`) and
    /// what it shares with the snapshot (`RssShmem`: the template's pages
    /// it read, mapped from the file).
    pub fn memory_detail(pid: u32) -> String {
        let mib = |b: u64| b as f64 / (1 << 20) as f64;
        format!(
            "{:.1} MiB its own, {:.1} MiB shared with the snapshot",
            mib(status(pid, "RssAnon")),
            mib(status(pid, "RssShmem"))
        )
    }

    pub fn memory_goes_back(
        pid: u32,
        line: impl FnMut() -> String,
        send: impl FnMut(),
    ) -> [f64; 4] {
        super::vm_memory::memory_goes_back(|| footprint(pid), pid, line, send)
    }

    /// `kernels` kernel processes report every layer, and the KVM
    /// allowlist.
    pub fn assert_confined(output: &str, kernels: usize) {
        for layer in [
            "inherited fds closed: active",
            "resource limits: active",
            "no_new_privs: active",
            "not dumpable: active",
            "seccomp allowlist: active",
        ] {
            assert_eq!(output.matches(layer).count(), kernels, "{layer}: {output}");
        }
        assert_eq!(
            output
                .matches("Landlock: active")
                .count()
                .max(output.matches("namespaces: active").count()),
            kernels,
            "{output}"
        );
    }
}

include!("vm_warm/tests.rs");

/// Clones share the snapshot file read only. Memory that was zero in the
/// template (here a 32 MiB buffer nobody touched) must not come from the
/// file: the host would allocate each page of it in the file at a clone's
/// first touch, for all clones and for as long as the template lives. The
/// supervisor logs what the file holds once frozen and after each clone.
#[test]
fn clones_do_not_grow_the_snapshot() {
    let _serial = support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let program = r#"
import os, sys
big = bytearray(32 << 20)
print("template ready", flush=True)
code = open("/dev/hellovm-clone", "rb").read()
exec(compile(code, "<clone>", "exec"))
"#;
    let template = Template::start(
        exe,
        &root,
        &["/usr/bin/python3", "-c", program],
        &[],
        &[("HELLOVM_LOG", "debug")],
    );
    let (stored, _) = template.ready_ok();
    assert!(stored < 24 << 20, "the zero buffer was stored: {stored}");
    for _ in 0..3 {
        progress("snapshot: a clone writes the zero buffer");
        let run = template.run(
            b"print(sum(big[::4096]))\nbig[:] = b'x' * len(big)\nprint(big.count(b'x'))",
            b"",
        );
        assert_eq!(run.stdout, format!("0\n{}\n", 32 << 20), "{run:?}");
        assert_eq!(run.status, Status::Exited(0));
    }
    let output = template.output();
    let holds: Vec<u64> = output
        .lines()
        .filter_map(|l| {
            let rest = l.split("the snapshot holds ").nth(1)?;
            rest.split(' ').next()?.parse().ok()
        })
        .collect();
    assert_eq!(holds.len(), 4, "{output}");
    // Padded runs hold some zero pages too, but far less than the buffer.
    assert!(holds[0] < stored + (8 << 20), "{holds:?}, {stored} stored");
    assert!(
        holds.iter().all(|&h| h == holds[0]),
        "clones grew the snapshot: {holds:?}"
    );
}

const INGRESS_SERVER: &str = r#"
import socket, time
s = socket.socket()
s.bind(("0.0.0.0", 8080))
s.listen(32)
lo = socket.socket()
lo.bind(("127.0.0.1", 8081))
lo.listen(4)
print("listening", flush=True)
# 1: read to the opener's FIN, answer, half-close, then read what follows.
c, peer = s.accept()
print("peer", peer[0], peer[1], flush=True)
data = b""
while True:
    b = c.recv(65536)
    if not b:
        break
    data += b
c.sendall(b"got %d %s" % (len(data), data[:5]))
c.shutdown(socket.SHUT_WR)
c.close()
# 2: a large answer to a slow reader.
c, _ = s.accept()
c.sendall(b"x" * (1 << 20))
c.close()
# 3: twenty at once, an echo of one line each.
conns = [s.accept()[0] for _ in range(20)]
for c in conns:
    c.sendall(c.recv(100))
    c.close()
print("echoed", flush=True)
# 4: one more is queued, then the listener goes away.
time.sleep(0.5)
s.close()
print("closed", flush=True)
# 5: a new listener; its connection stays open until the sandbox ends.
s = socket.socket()
s.bind(("0.0.0.0", 8082))
s.listen(1)
print("again", flush=True)
c, _ = s.accept()
time.sleep(60)
"#;

/// Hands the clone a new inbound connection to `port` and reads its
/// verdict: the connection when it was accepted, `None` when refused.
fn inbound(
    channel: &std::os::unix::net::UnixStream,
    port: u16,
) -> Option<std::os::unix::net::UnixStream> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    hellovm::warm::send_with_fds(channel, &port.to_le_bytes(), &[theirs.as_raw_fd()]).unwrap();
    drop(theirs);
    ours.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut verdict = Vec::new();
    Read::by_ref(&mut ours)
        .take(1)
        .read_to_end(&mut verdict)
        .unwrap();
    match verdict.as_slice() {
        b"A" => Some(ours),
        b"R" => {
            let mut rest = Vec::new();
            ours.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty(), "bytes after R: {rest:?}");
            None
        }
        other => panic!("verdict {other:?}"),
    }
}

#[test]
fn inbound_connections_through_the_ingress_channel() {
    use std::io::{Read, Write};
    let _serial = support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    let template = python(exe, &root);
    template.ready_ok();
    let (mut clone, channel) = template
        .spawn_with_ingress(INGRESS_SERVER.as_bytes())
        .unwrap_or_else(|err| panic!("a clone: {err}\n{}", template.output()));
    assert_eq!(clone.line(), "listening\n");
    // Nobody listens there, or only on loopback.
    assert!(inbound(&channel, 9999).is_none());
    assert!(inbound(&channel, 8081).is_none());
    assert!(inbound(&channel, 0).is_none());
    // 1: both ways, the opener's FIN, the guest's half-close.
    let mut one = inbound(&channel, 8080).expect("accepted");
    let body = vec![b'b'; 200_000];
    one.write_all(&body).unwrap();
    one.shutdown(std::net::Shutdown::Write).unwrap();
    let mut answer = Vec::new();
    one.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, b"got 200000 bbbbb");
    assert_eq!(clone.line(), "peer 192.0.2.1 32768\n");
    // 2: a megabyte, taken slowly at first: the guest waits for room.
    let mut two = inbound(&channel, 8080).expect("accepted");
    std::thread::sleep(Duration::from_millis(300));
    let mut got = Vec::new();
    two.read_to_end(&mut got).unwrap();
    assert_eq!(got.len(), 1 << 20);
    assert!(got.iter().all(|&b| b == b'x'));
    // 3: twenty at once.
    let mut many: Vec<_> = (0..20)
        .map(|i| {
            let mut c = inbound(&channel, 8080).expect("accepted");
            c.write_all(format!("line {i}\n").as_bytes()).unwrap();
            c
        })
        .collect();
    for (i, c) in many.iter_mut().enumerate() {
        let mut got = String::new();
        c.read_to_string(&mut got).unwrap();
        assert_eq!(got, format!("line {i}\n"));
    }
    assert_eq!(clone.line(), "echoed\n");
    // 4: queued when the listener closes: it ends without a byte.
    let mut queued = inbound(&channel, 8080).expect("queued");
    assert_eq!(clone.line(), "closed\n");
    let mut got = Vec::new();
    let _ = queued.read_to_end(&mut got);
    assert!(got.is_empty(), "{got:?}");
    assert!(inbound(&channel, 8080).is_none(), "no listener any more");
    // 5: the sandbox ends while a connection is open: it ends too.
    assert_eq!(clone.line(), "again\n");
    let mut open = inbound(&channel, 8082).expect("accepted");
    std::thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    clone.conn.kill();
    let mut got = Vec::new();
    let _ = open.read_to_end(&mut got);
    assert!(got.is_empty());
    assert!(started.elapsed() < Duration::from_secs(15));
}

/// Each clone's outbound flows go through the egress proxy from its own
/// kernel process, named by its own sandbox id: the proxy audits each
/// flow with the clone's id and the clone's kernel process as the peer.
/// A name the template resolved keeps its fake address in every clone.
#[test]
fn each_clone_has_its_own_egress_flows() {
    use hellovm_egress::audit::{AuditSink, MemorySink};
    use hellovm_egress::policy::Policy;
    use hellovm_egress::resolve::Resolver;
    use hellovm_egress::{Config, Limits, Proxy};
    let _serial = support::serial();
    let Some((exe, root)) = setup() else {
        return;
    };
    // A loopback HTTP server that answers every request with one line.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            std::thread::spawn(move || {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\nfetched");
            });
        }
    });
    let dir = socket_dir();
    let socket = dir.join("egress.sock");
    let mut policy = Policy::new();
    policy.add_file("allow allowed.test:80\n").unwrap();
    let audit = MemorySink::default();
    let _proxy = Proxy::bind(
        &socket,
        Config {
            policy,
            limits: Limits::default(),
            audit: AuditSink::new(Box::new(audit.clone())),
            resolver: Resolver::parse_test_table(&format!("allowed.test 127.0.0.1:{port}\n"))
                .unwrap(),
        },
    )
    .unwrap()
    .spawn();
    let program = r#"
import socket, sys
addr = socket.gethostbyname("allowed.test")
print("template resolved", flush=True)
code = open("/dev/hellovm-clone", "rb").read()
exec(compile(code, "<clone>", "exec"))
"#;
    let template = Template::start(
        exe,
        &root,
        &["/usr/bin/python3", "-c", program],
        &["--egress", socket.to_str().unwrap()],
        &[],
    );
    template.ready_ok();
    let fetch = br#"
with socket.create_connection(("allowed.test", 80), timeout=20) as s:
    s.sendall(b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
    data = b""
    while chunk := s.recv(4096):
        data += chunk
print(data.endswith(b"fetched"), socket.gethostbyname("allowed.test") == addr)
"#;
    let mut peers = Vec::new();
    for id in [0xa1u64, 0xb2] {
        progress(&format!("egress: clone {id:x}"));
        let clone = template.spawn(Some(id), fetch).unwrap();
        let pid = clone.started.pid;
        let run = clone.finish();
        assert_eq!(run.stdout, "True True\n", "{run:?}\n{}", template.output());
        peers.push((format!("{id:016x}"), pid.to_string()));
    }
    let start = Instant::now();
    loop {
        let lines = audit.lines();
        let field = |line: &str, key: &str| -> Option<String> {
            line.split(' ')
                .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
                .map(str::to_string)
        };
        let seen: Vec<(String, String)> = lines
            .iter()
            .filter(|l| field(l, "host").as_deref() == Some("allowed.test"))
            .filter(|l| field(l, "verdict").as_deref() == Some("allow"))
            .filter_map(|l| Some((field(l, "sandbox")?, field(l, "peer")?)))
            .collect();
        if seen.len() >= 2 {
            assert_eq!(seen, peers, "{}", lines.join("\n"));
            let _ = std::fs::remove_dir_all(&dir);
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "audit:\n{}",
            lines.join("\n")
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
