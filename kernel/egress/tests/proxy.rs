//! The proxy against loopback upstreams. Loopback is reachable only through
//! the `insecure-test-hooks` name table, which this crate's tests enable.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use hellovm_egress::audit::{AuditSink, MemorySink};
use hellovm_egress::policy::Policy;
use hellovm_egress::resolve::Resolver;
use hellovm_egress::sniff::client_hello_for_test;
use hellovm_egress::wire::{Request, Status, REPLY};
use hellovm_egress::{Config, Limits, Proxy, ProxyHandle};

static N: AtomicUsize = AtomicUsize::new(0);

fn sock_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "hvegress-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ))
}

struct Fixture {
    proxy: ProxyHandle,
    audit: MemorySink,
}

impl Fixture {
    fn new(policy: &str, table: &str, limits: Limits) -> Fixture {
        let mut p = Policy::new();
        p.add_file(policy).unwrap();
        let audit = MemorySink::default();
        let config = Config {
            policy: p,
            limits,
            audit: AuditSink::new(Box::new(audit.clone())),
            resolver: Resolver::parse_test_table(table).unwrap(),
        };
        let proxy = Proxy::bind(sock_path(), config).unwrap().spawn();
        Fixture { proxy, audit }
    }

    fn open(&self, sandbox: u64, host: &str, port: u16) -> (UnixStream, Option<Status>) {
        let mut s = UnixStream::connect(self.proxy.path()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let req = Request {
            sandbox_id: sandbox,
            port,
            host: host.into(),
        };
        s.write_all(&req.encode().unwrap()).unwrap();
        let mut reply = [0u8; REPLY];
        let status = s
            .read_exact(&mut reply)
            .ok()
            .and_then(|()| Status::parse_reply(&reply));
        (s, status)
    }

    /// Waits for `n` audit lines.
    fn audit_lines(&self, n: usize) -> Vec<String> {
        let start = Instant::now();
        loop {
            let lines = self.audit.lines();
            if lines.len() >= n {
                return lines;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "audit lines: {lines:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// An upstream that records what it received and answers `reply`.
fn upstream(reply: &'static [u8]) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = thread::spawn(move || {
        listener.set_nonblocking(false).unwrap();
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    got.extend_from_slice(&buf[..n]);
                    if got.ends_with(b"END") {
                        let _ = s.write_all(reply);
                        let _ = s.shutdown(Shutdown::Write);
                    }
                }
            }
        }
        got
    });
    (port, h)
}

fn read_all(s: &mut UnixStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split(' ')
        .find_map(|kv| kv.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
        .unwrap_or_else(|| panic!("{key} in {line}"))
}

#[test]
fn allowed_tls_flow_relays_both_ways_and_is_audited() {
    let (port, server) = upstream(b"server-hello");
    let f = Fixture::new(
        "allow pypi.test:443",
        &format!("pypi.test 127.0.0.1:{port}"),
        Limits::default(),
    );
    let (mut s, status) = f.open(7, "pypi.test", 443);
    assert_eq!(status, Some(Status::Ok));
    let hello = client_hello_for_test(&["pypi.test"]);
    s.write_all(&hello).unwrap();
    s.write_all(b"END").unwrap();
    assert_eq!(read_all(&mut s), b"server-hello");
    s.shutdown(Shutdown::Write).unwrap();
    let got = server.join().unwrap();
    assert_eq!(&got[..hello.len()], &hello[..]);
    assert!(got.ends_with(b"END"));
    let line = &f.audit_lines(1)[0];
    assert_eq!(field(line, "sandbox"), "0000000000000007");
    assert_eq!(field(line, "host"), "pypi.test");
    assert_eq!(field(line, "port"), "443");
    assert_eq!(field(line, "verdict"), "allow");
    assert_eq!(field(line, "reason"), "ok");
    assert_eq!(field(line, "addr"), format!("127.0.0.1:{port}"));
    assert_eq!(field(line, "up"), (hello.len() + 3).to_string());
    assert_eq!(field(line, "down"), "12");
}

#[test]
fn allowed_http_flow() {
    let (port, server) = upstream(b"HTTP/1.0 200 OK\r\n\r\nhi");
    let f = Fixture::new(
        "allow web.test:80",
        &format!("web.test 127.0.0.1:{port}"),
        Limits::default(),
    );
    let (mut s, status) = f.open(1, "web.test", 80);
    assert_eq!(status, Some(Status::Ok));
    // One request with a body, then a second request for another host on
    // the same connection.
    s.write_all(
        b"POST / HTTP/1.1\r\nHost: web.test\r\nConnection: keep-alive\r\n\
          Content-Length: 3\r\n\r\nENDGET /leak HTTP/1.1\r\nHost: evil.test\r\n\r\n",
    )
    .unwrap();
    assert!(read_all(&mut s).ends_with(b"hi"));
    drop(s);
    let got = String::from_utf8(server.join().unwrap()).unwrap();
    // Only the checked request reached the server, marked as the last one.
    assert_eq!(
        got,
        "POST / HTTP/1.1\r\nHost: web.test\r\nContent-Length: 3\r\nConnection: close\r\n\r\nEND"
    );
    let line = &f.audit_lines(1)[0];
    assert_eq!(field(line, "verdict"), "allow");
    assert_eq!(field(line, "peer"), std::process::id().to_string());
}

#[test]
fn a_peer_cannot_dodge_its_flow_limit_with_other_sandbox_ids() {
    let limits = Limits {
        max_flows_per_sandbox: 2,
        ..Limits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let f = Fixture::new("allow a.test", &format!("a.test 127.0.0.1:{port}"), limits);
    // Two flows held open (the proxy waits for their first bytes), each
    // under its own claimed id.
    let (_one, status) = f.open(1, "a.test", 443);
    assert_eq!(status, Some(Status::Ok));
    let (_two, status) = f.open(2, "a.test", 443);
    assert_eq!(status, Some(Status::Ok));
    // A third id does not get this process a third flow.
    let (_three, status) = f.open(3, "a.test", 443);
    assert_eq!(status, Some(Status::Limit));
}

#[test]
fn deny_lines_are_rate_limited_per_peer() {
    let limits = Limits {
        deny_audit_burst: 3,
        deny_audit_per_sec: 20,
        ..Limits::default()
    };
    let f = Fixture::new("allow a.test", "a.test 127.0.0.1:9", limits);
    for _ in 0..10 {
        let (_s, status) = f.open(1, "evil.test", 443);
        assert_eq!(status, Some(Status::Denied));
    }
    thread::sleep(Duration::from_millis(300));
    let before = f.audit.lines().len();
    assert!((3..10).contains(&before), "{before} lines");
    // The next line that is written says how many were left out.
    let (_s, status) = f.open(1, "evil.test", 443);
    assert_eq!(status, Some(Status::Denied));
    let lines = f.audit_lines(before + 1);
    let last = lines.last().unwrap();
    assert_eq!(field(last, "suppressed"), (10 - before).to_string());
}

#[test]
fn names_off_the_list_are_denied() {
    let f = Fixture::new(
        "allow pypi.test:443\nallow *.ok.test",
        "pypi.test 127.0.0.1:9\nevil.test 127.0.0.1:9\na.ok.test 127.0.0.1:9",
        Limits::default(),
    );
    for (host, port) in [("evil.test", 443), ("pypi.test", 80), ("ok.test", 443)] {
        let (_s, status) = f.open(1, host, port);
        assert_eq!(status, Some(Status::Denied), "{host}:{port}");
    }
    let lines = f.audit_lines(3);
    for line in &lines {
        assert_eq!(field(line, "verdict"), "deny");
        assert_eq!(field(line, "reason"), "policy");
        assert_eq!(field(line, "addr"), "-");
    }
}

#[test]
fn sni_must_equal_the_flow_name() {
    let (port, server) = upstream(b"");
    let f = Fixture::new(
        "allow pypi.test:443",
        &format!("pypi.test 127.0.0.1:{port}"),
        Limits::default(),
    );
    let (mut s, status) = f.open(1, "pypi.test", 443);
    assert_eq!(status, Some(Status::Ok));
    s.write_all(&client_hello_for_test(&["evil.test"])).unwrap();
    assert_eq!(read_all(&mut s), b"", "the proxy closes the flow");
    // Nothing reached the upstream.
    assert_eq!(server.join().unwrap(), b"");
    let line = &f.audit_lines(1)[0];
    assert_eq!(field(line, "verdict"), "deny");
    assert_eq!(field(line, "reason"), "sni-mismatch");
    assert_eq!(field(line, "sni"), "evil.test");
}

#[test]
fn tls_without_sni_and_plain_http_on_443_are_refused() {
    for (first, reason) in [
        (client_hello_for_test(&[]), "unparsable"),
        (
            b"GET / HTTP/1.1\r\nHost: pypi.test\r\n\r\n".to_vec(),
            "not-tls",
        ),
        (b"SSH-2.0-x\r\n".to_vec(), "unparsable"),
    ] {
        let (port, server) = upstream(b"");
        let f = Fixture::new(
            "allow pypi.test:443",
            &format!("pypi.test 127.0.0.1:{port}"),
            Limits::default(),
        );
        let (mut s, status) = f.open(1, "pypi.test", 443);
        assert_eq!(status, Some(Status::Ok));
        s.write_all(&first).unwrap();
        assert_eq!(read_all(&mut s), b"");
        assert_eq!(server.join().unwrap(), b"");
        assert_eq!(field(&f.audit_lines(1)[0], "reason"), reason);
    }
}

#[test]
fn host_header_must_name_the_flow() {
    for (req, reason) in [
        (
            &b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n"[..],
            "host-mismatch",
        ),
        (
            b"GET / HTTP/1.1\r\nHost: web.test:8080\r\n\r\n",
            "host-mismatch",
        ),
        (b"GET / HTTP/1.1\r\n\r\n", "unparsable"),
    ] {
        let (port, server) = upstream(b"");
        let f = Fixture::new(
            "allow web.test:80",
            &format!("web.test 127.0.0.1:{port}"),
            Limits::default(),
        );
        let (mut s, status) = f.open(1, "web.test", 80);
        assert_eq!(status, Some(Status::Ok));
        s.write_all(req).unwrap();
        assert_eq!(read_all(&mut s), b"");
        assert_eq!(server.join().unwrap(), b"");
        let line = &f.audit_lines(1)[0];
        assert_eq!(field(line, "reason"), reason, "{line}");
    }
}

#[test]
fn private_and_metadata_addresses_are_never_dialed() {
    let f = Fixture::new(
        "allow private.test\nallow meta.test\nallow cgnat.test\nallow v6.test",
        "private.test 10.0.0.1 192.168.1.1\nmeta.test 169.254.169.254\ncgnat.test 100.64.0.1\nv6.test ::ffff:169.254.169.254 fe80::1",
        Limits::default(),
    );
    for host in ["private.test", "meta.test", "cgnat.test", "v6.test"] {
        let (_s, status) = f.open(1, host, 443);
        assert_eq!(status, Some(Status::BlockedAddress), "{host}");
    }
    let lines = f.audit_lines(4);
    assert!(lines
        .iter()
        .all(|l| field(l, "reason") == "blocked-address"));
    assert!(lines
        .iter()
        .any(|l| field(l, "addr") == "169.254.169.254:443"));
}

#[test]
fn a_mixed_name_is_dialed_only_where_it_passed() {
    let (port, server) = upstream(b"ok");
    let f = Fixture::new(
        "allow mixed.test",
        &format!("mixed.test 169.254.169.254 10.1.1.1 127.0.0.1:{port}"),
        Limits::default(),
    );
    let (mut s, status) = f.open(1, "mixed.test", 443);
    assert_eq!(status, Some(Status::Ok));
    s.write_all(&client_hello_for_test(&["mixed.test"]))
        .unwrap();
    s.write_all(b"END").unwrap();
    assert_eq!(read_all(&mut s), b"ok");
    drop(s);
    server.join().unwrap();
    let line = &f.audit_lines(1)[0];
    assert_eq!(field(line, "addr"), format!("127.0.0.1:{port}"));
}

#[test]
fn unresolvable_and_refusing_upstreams() {
    // A port nothing listens on.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let f = Fixture::new(
        "allow nowhere.test\nallow closed.test",
        &format!("closed.test 127.0.0.1:{port}"),
        Limits::default(),
    );
    assert_eq!(
        f.open(1, "nowhere.test", 443).1,
        Some(Status::ResolveFailed)
    );
    assert_eq!(
        f.open(1, "closed.test", 443).1,
        Some(Status::UpstreamRefused)
    );
    let lines = f.audit_lines(2);
    let reasons: Vec<_> = lines.iter().map(|l| field(l, "reason")).collect();
    assert!(reasons.contains(&"resolve"), "{lines:?}");
    assert!(reasons.contains(&"upstream-refused"), "{lines:?}");
}

#[test]
fn malformed_and_slow_headers_are_refused() {
    let limits = Limits {
        header_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let f = Fixture::new("allow a.test", "a.test 127.0.0.1:9", limits);
    let mut s = UnixStream::connect(f.proxy.path()).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let mut reply = [0u8; REPLY];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(Status::parse_reply(&reply), Some(Status::BadRequest));
    // Half a header, then silence.
    let mut s = UnixStream::connect(f.proxy.path()).unwrap();
    s.write_all(b"HVEG\x01").unwrap();
    let started = Instant::now();
    s.read_exact(&mut reply).unwrap();
    assert_eq!(Status::parse_reply(&reply), Some(Status::BadRequest));
    assert!(started.elapsed() < Duration::from_secs(3));
    let lines = f.audit_lines(2);
    assert!(lines.iter().all(|l| field(l, "sandbox") == "-"));
}

#[test]
fn a_silent_client_is_closed_at_the_sniff_timeout() {
    let (port, server) = upstream(b"");
    let limits = Limits {
        sniff_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let f = Fixture::new("allow a.test", &format!("a.test 127.0.0.1:{port}"), limits);
    let (mut s, status) = f.open(1, "a.test", 443);
    assert_eq!(status, Some(Status::Ok));
    let started = Instant::now();
    assert_eq!(read_all(&mut s), b"");
    assert!(started.elapsed() < Duration::from_secs(5));
    server.join().unwrap();
    assert_eq!(field(&f.audit_lines(1)[0], "reason"), "sniff-timeout");
}

#[test]
fn an_idle_flow_is_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        // Hold the connection silently until the proxy closes it.
        let mut s = s;
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
    });
    let limits = Limits {
        idle_timeout: Duration::from_millis(400),
        ..Limits::default()
    };
    let f = Fixture::new("allow a.test", &format!("a.test 127.0.0.1:{port}"), limits);
    let (mut s, status) = f.open(1, "a.test", 443);
    assert_eq!(status, Some(Status::Ok));
    s.write_all(&client_hello_for_test(&["a.test"])).unwrap();
    let started = Instant::now();
    assert_eq!(read_all(&mut s), b"");
    assert!(started.elapsed() < Duration::from_secs(5));
    server.join().unwrap();
    let line = &f.audit_lines(1)[0];
    assert_eq!(field(line, "verdict"), "allow");
    assert_eq!(field(line, "reason"), "idle-timeout");
}

#[test]
fn flows_per_sandbox_are_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || {
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(listener.accept().unwrap().0);
        }
        held
    });
    let limits = Limits {
        max_flows_per_sandbox: 1,
        ..Limits::default()
    };
    let f = Fixture::new("allow a.test", &format!("a.test 127.0.0.1:{port}"), limits);
    let (first, status) = f.open(1, "a.test", 443);
    assert_eq!(status, Some(Status::Ok));
    assert_eq!(f.open(1, "a.test", 443).1, Some(Status::Limit));
    // The limit also counts the connecting process, whatever id it claims
    // (see `a_peer_cannot_dodge_its_flow_limit_with_other_sandbox_ids`), so
    // from this one process another id is refused too...
    assert_eq!(f.open(2, "a.test", 443).1, Some(Status::Limit));
    // ...until the first flow ends and gives its slot back.
    drop(first);
    let start = Instant::now();
    let other = loop {
        let (other, status) = f.open(2, "a.test", 443);
        if status == Some(Status::Ok) {
            break other;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{status:?}");
        thread::sleep(Duration::from_millis(10));
    };
    drop(other);
    drop(accepted.join().unwrap());
    let lines = f.audit_lines(3);
    assert!(lines.iter().any(|l| field(l, "reason") == "limit"));
}

#[test]
fn the_binary_reads_a_policy_file_and_writes_an_audit_file() {
    let (port, server) = upstream(b"pong");
    let dir = std::env::temp_dir().join(format!("hvegress-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy");
    let hosts = dir.join("hosts");
    let audit = dir.join("audit.log");
    let sock = dir.join("egress.sock");
    let _ = std::fs::remove_file(&audit);
    std::fs::write(&policy, "# test\nallow bin.test:443\n").unwrap();
    std::fs::write(&hosts, format!("bin.test 127.0.0.1:{port}\n")).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_hellovm-egress"))
        .arg("--listen")
        .arg(&sock)
        .arg("--policy")
        .arg(&policy)
        .arg("--audit")
        .arg(&audit)
        .arg("--insecure-test-hosts")
        .arg(&hosts)
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut s = loop {
        if let Ok(s) = UnixStream::connect(&sock) {
            break s;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "proxy did not start"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let req = Request {
        sandbox_id: 0xabc,
        port: 443,
        host: "bin.test".into(),
    };
    s.write_all(&req.encode().unwrap()).unwrap();
    let mut reply = [0u8; REPLY];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(Status::parse_reply(&reply), Some(Status::Ok));
    s.write_all(&client_hello_for_test(&["bin.test"])).unwrap();
    s.write_all(b"END").unwrap();
    assert_eq!(read_all(&mut s), b"pong");
    drop(s);
    server.join().unwrap();
    let start = Instant::now();
    let text = loop {
        let text = std::fs::read_to_string(&audit).unwrap_or_default();
        if !text.is_empty() {
            break text;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "no audit line");
        thread::sleep(Duration::from_millis(20));
    };
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(field(&text, "sandbox"), "0000000000000abc");
    assert_eq!(field(&text, "verdict"), "allow");
    assert_eq!(field(&text, "down"), "4");
    let _ = std::fs::remove_dir_all(&dir);
}
