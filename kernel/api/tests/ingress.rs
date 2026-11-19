//! HTTP ingress end to end (README, "Ingress"): a Python HTTP server in a
//! sandbox reached through the API's ingress listener, with real `noded`
//! processes. The token (header, cookie, the one-time query parameter),
//! public ports, wrong and missing tokens, unexposed ports, another
//! tenant's sandbox, what is forwarded and what is not, an upgrade, large
//! streamed bodies both ways, hostile request heads that must not reach
//! the guest, metering, idle timeouts kept off by ingress use, the
//! deadlines against slow clients and guests, the connection limits, and
//! ingress across nodes with one unreachable.

#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::{IngressAnswer, Plane, PlaneOptions, ACME, ADMIN_TOKEN, BETA};
use serde_json::{json, Value};

/// The guest's server: `python3 /tmp/srv.py PORT`. Every request's path
/// goes to `/tmp/requests.log` as it is read.
const SERVER: &str = r#"
import http.server, socketserver, sys, json, hashlib, time
LOG = open('/tmp/requests.log', 'a', buffering=1)

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype='application/json'):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Set-Cookie', 'hellovm_ingress_token=forged; Domain=sb.test')
        self.send_header('Set-Cookie', 'app=1')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def body(self):
        h, n = hashlib.sha256(), 0
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            while True:
                size = int(self.rfile.readline(1024).strip().split(b';')[0], 16)
                if size == 0:
                    while self.rfile.readline(8192) not in (b'\r\n', b''):
                        pass
                    return n, h.hexdigest()
                left = size
                while left:
                    b = self.rfile.read(min(left, 65536))
                    h.update(b)
                    n += len(b)
                    left -= len(b)
                self.rfile.readline(8)
        left = int(self.headers.get('Content-Length', '0'))
        while left:
            b = self.rfile.read(min(left, 65536))
            if not b:
                break
            h.update(b)
            n += len(b)
            left -= len(b)
        return n, h.hexdigest()

    def do_GET(self):
        LOG.write(self.path + '\n')
        p = self.path.split('?')[0]
        if p == '/headers':
            seen = {k.lower(): v for k, v in self.headers.items()}
            seen['_path'] = self.path
            self.send(200, json.dumps(seen).encode())
        elif p == '/big':
            n = int(self.path.split('n=')[1])
            chunk = b'x' * 65536
            self.send_response(200)
            self.send_header('Content-Length', str(n))
            self.end_headers()
            while n:
                k = min(n, len(chunk))
                self.wfile.write(chunk[:k])
                n -= k
        elif p == '/slow':
            time.sleep(float(self.path.split('s=')[1]))
            self.send(200, b'slow')
        elif p == '/upgrade':
            self.send_response(101)
            self.send_header('Connection', 'Upgrade')
            self.send_header('Upgrade', 'shout')
            self.end_headers()
            self.wfile.flush()
            while True:
                b = self.connection.recv(65536)
                if not b:
                    break
                self.connection.sendall(b.upper())
            self.close_connection = True
        else:
            self.send(200, b'hello ' + p.encode(), 'text/plain')

    def do_POST(self):
        LOG.write(self.path + '\n')
        n, digest = self.body()
        self.send(200, json.dumps({'bytes': n, 'sha256': digest}).encode())

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

S(('0.0.0.0', int(sys.argv[1])), H).serve_forever()
"#;

fn id_of(sandbox: &Value) -> String {
    sandbox["id"].as_str().unwrap().to_string()
}

fn eventually(limit: Duration, what: &str, mut check: impl FnMut() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(start.elapsed() < limit, "{what} after {limit:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Starts the server in sandbox `id` on `port`.
fn serve(plane: &Plane, token: &str, id: &str, port: u16) {
    let r = plane.call(
        token,
        "PUT",
        &format!("/v1/sandboxes/{id}/files?path=/tmp/srv.py"),
        SERVER.as_bytes(),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = plane.sh(
        token,
        id,
        &format!("nohup python3 /tmp/srv.py {port} >/tmp/srv.log 2>&1 &"),
    );
    assert_eq!(r["exit_code"], 0, "{r}");
}

fn ingress(plane: &Plane, token: &str, id: &str) -> Value {
    let r = plane.call(token, "GET", &format!("/v1/sandboxes/{id}/ingress"), b"");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()
}

fn expose(plane: &Plane, token: &str, id: &str, port: u16, public: bool) -> Value {
    let r = plane.call_json(
        token,
        "PUT",
        &format!("/v1/sandboxes/{id}/ingress/ports/{port}"),
        json!({ "public": public }),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()
}

/// Waits until the server in `id` answers on `port` through ingress.
fn wait_serving(plane: &Plane, id: &str, port: u16, token: &str) {
    let header = format!("X-Hellovm-Ingress-Token: {token}");
    eventually(Duration::from_secs(20), "the guest's server", || {
        plane.ingress_get(port, id, "/", &[&header]).status == 200
    });
}

fn requests_log(plane: &Plane, id: &str) -> String {
    let r = plane.call(
        ACME,
        "GET",
        &format!("/v1/sandboxes/{id}/files?path=/tmp/requests.log"),
        b"",
    );
    String::from_utf8_lossy(&r.body).into_owned()
}

fn host(port: u16, id: &str) -> String {
    Plane::ingress_host(port, id)
}

/// A connection that sends `head` and then `body` in pieces.
fn send_in_pieces(plane: &Plane, head: &str, pieces: &[&[u8]], pause: Duration) -> IngressAnswer {
    let mut conn = TcpStream::connect(plane.ingress_addr()).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    conn.write_all(head.as_bytes()).unwrap();
    for piece in pieces {
        std::thread::sleep(pause);
        if conn.write_all(piece).is_err() {
            break;
        }
    }
    let mut got = Vec::new();
    let _ = conn.read_to_end(&mut got);
    common::parse_answer(got)
}

#[test]
fn ingress_reaches_a_server_in_a_sandbox() {
    let Some(plane) = Plane::start(PlaneOptions {
        api_extra: json!({"ingress": {"head_timeout": 3}}),
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let a = id_of(&plane.create(ACME, json!({})));
    let b = id_of(&plane.create(BETA, json!({})));
    serve(&plane, ACME, &a, 8000);
    serve(&plane, BETA, &b, 8000);

    // Nothing is exposed by default; the token is the tenant's to read.
    let info = ingress(&plane, ACME, &a);
    let token = info["token"].as_str().unwrap().to_string();
    assert!(token.len() >= 32, "{info}");
    assert_eq!(info["ports"], json!([]));
    let header = format!("X-Hellovm-Ingress-Token: {token}");
    assert_eq!(plane.ingress_get(8000, &a, "/", &[&header]).status, 404);
    // Another tenant cannot read it, nor expose a port.
    let r = plane.call(BETA, "GET", &format!("/v1/sandboxes/{a}/ingress"), b"");
    assert_eq!((r.status, r.code()), (404, "sandbox_not_found".into()));
    let r = plane.call_json(
        BETA,
        "PUT",
        &format!("/v1/sandboxes/{a}/ingress/ports/8000"),
        json!({}),
    );
    assert_eq!(r.status, 404);
    // Ports are checked; at most 16 at once.
    for bad in ["0", "65536", "x", "080"] {
        let r = plane.call(
            ACME,
            "PUT",
            &format!("/v1/sandboxes/{a}/ingress/ports/{bad}"),
            b"",
        );
        assert_eq!(r.status, 400, "{bad}");
    }
    for port in 9000..9016 {
        expose(&plane, ACME, &a, port, false);
    }
    let r = plane.call(
        ACME,
        "PUT",
        &format!("/v1/sandboxes/{a}/ingress/ports/9100"),
        b"",
    );
    assert_eq!((r.status, r.code()), (409, "too_many_ports".into()));
    for port in 9000..9016 {
        let r = plane.call(
            ACME,
            "DELETE",
            &format!("/v1/sandboxes/{a}/ingress/ports/{port}"),
            b"",
        );
        assert_eq!(r.status, 200);
    }

    let info = expose(&plane, ACME, &a, 8000, false);
    assert_eq!(
        info["ports"],
        json!([{"port": 8000, "public": false, "url": format!("http://{}/", host(8000, &a))}])
    );
    wait_serving(&plane, &a, 8000, &token);

    // The token is needed: missing, wrong, another sandbox's, all 404 like
    // an unknown sandbox, an unexposed port and a name that is not one.
    let b_token = ingress(&plane, BETA, &b)["token"]
        .as_str()
        .unwrap()
        .to_string();
    expose(&plane, BETA, &b, 8000, false);
    wait_serving(&plane, &b, 8000, &b_token);
    let wrong = format!("X-Hellovm-Ingress-Token: {b_token}");
    let unknown = "sb-00000000000000000000000000000000";
    let refused = [
        plane.ingress_get(8000, &a, "/", &[]),
        plane.ingress_get(8000, &a, "/", &[&wrong]),
        plane.ingress_get(
            8000,
            &a,
            "/",
            &[&format!("Cookie: hellovm_ingress_token={b_token}")],
        ),
        plane.ingress_get(8000, &a, &format!("/?hellovm_ingress_token={b_token}"), &[]),
        plane.ingress_get(8000, unknown, "/", &[&header]),
        plane.ingress_get(8001, &a, "/", &[&header]),
        plane.ingress_raw(
            format!("GET / HTTP/1.1\r\nHost: 8000-{a}.other.test\r\n{header}\r\n\r\n").as_bytes(),
            Duration::from_secs(10),
        ),
        plane.ingress_raw(
            format!("GET / HTTP/1.1\r\nHost: 8000-{}.sb.test\r\n\r\n", &a[..10]).as_bytes(),
            Duration::from_secs(10),
        ),
    ];
    let first = &refused[0];
    for (i, r) in refused.iter().enumerate() {
        assert_eq!(r.status, 404, "{i}: {}", r.head);
        assert_eq!(r.body, first.body, "{i}");
    }
    // Header, cookie, and the query parameter that sets the cookie.
    let ok = plane.ingress_get(8000, &a, "/x", &[&header]);
    assert_eq!((ok.status, ok.text()), (200, "hello /x".into()));
    assert!(common::header(&ok.head, "connection").is_some_and(|c| c == "close"));
    let cookie = format!("Cookie: a=1; hellovm_ingress_token={token}");
    assert_eq!(plane.ingress_get(8000, &a, "/", &[&cookie]).status, 200);
    let r = plane.ingress_get(
        8000,
        &a,
        &format!("/p?x=1&hellovm_ingress_token={token}"),
        &[],
    );
    assert_eq!(r.status, 303, "{}", r.head);
    assert_eq!(
        common::header(&r.head, "location").as_deref(),
        Some("/p?x=1")
    );
    let set = common::header(&r.head, "set-cookie").unwrap();
    assert!(
        set.starts_with(&format!("hellovm_ingress_token={token};")),
        "{set}"
    );
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Lax"),
        "{set}"
    );
    let r = plane.ingress_raw(
        format!("POST /?hellovm_ingress_token={token} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n", host(8000, &a)).as_bytes(),
        Duration::from_secs(10),
    );
    assert_eq!(r.status, 400, "the parameter is for GET only");
    // Another tenant's sandbox, with its own token, still works.
    assert_eq!(plane.ingress_get(8000, &b, "/", &[&wrong]).status, 200);

    // What reaches the guest: no hellovm credential, no hop-by-hop
    // header, forwarding headers set by the ingress.
    let seen = plane.ingress_get(
        8000,
        &a,
        "/headers?q=1",
        &[
            &header,
            &format!("Cookie: a=1; hellovm_ingress_token={token}; b=2"),
            &format!("Authorization: Bearer {ACME}"),
            "X-Hellovm-Tenant: beta",
            "X-Forwarded-For: 6.6.6.6",
            "Keep-Alive: 300",
            "Connection: keep-alive, X-Secret",
            "X-Secret: s",
            "X-App: kept",
        ],
    );
    assert_eq!(seen.status, 200, "{}", seen.head);
    let seen: Value = serde_json::from_slice(&seen.body).unwrap();
    assert_eq!(seen["_path"], "/headers?q=1");
    assert_eq!(seen["cookie"], "a=1; b=2", "{seen}");
    assert_eq!(seen["x-forwarded-for"], "127.0.0.1", "{seen}");
    assert_eq!(seen["x-forwarded-proto"], "http");
    assert_eq!(seen["x-forwarded-host"], host(8000, &a));
    assert_eq!(seen["connection"], "close");
    assert_eq!(seen["x-app"], "kept");
    for gone in [
        "x-hellovm-ingress-token",
        "authorization",
        "x-hellovm-tenant",
        "keep-alive",
        "x-secret",
    ] {
        assert!(seen.get(gone).is_none(), "{gone} reached the guest: {seen}");
    }
    let text = seen.to_string();
    assert!(!text.contains(&token) && !text.contains(ACME), "{text}");
    // A cookie of the token's name the guest sets never reaches a client.
    let r = plane.ingress_get(8000, &a, "/", &[&header]);
    assert!(
        !r.head.contains("forged") && r.head.contains("app=1"),
        "{}",
        r.head
    );

    // A public port needs no token.
    expose(&plane, ACME, &a, 8000, true);
    assert_eq!(plane.ingress_get(8000, &a, "/", &[]).status, 200);
    expose(&plane, ACME, &a, 8000, false);
    assert_eq!(plane.ingress_get(8000, &a, "/", &[]).status, 404);
    // An exposed port nothing listens on.
    expose(&plane, ACME, &a, 8002, true);
    let r = plane.ingress_get(8002, &a, "/", &[]);
    assert_eq!(r.status, 502, "{}", r.head);
    assert!(r.text().contains("listens"), "{}", r.text());

    // Large bodies, streamed both ways: 8 MiB up (chunked, then by
    // length) and 32 MiB down.
    let up: Vec<u8> = (0..8u32 << 20).map(|i| (i % 251) as u8).collect();
    let digest = {
        let out = std::process::Command::new("sha256sum")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.take().unwrap().write_all(&up)?;
                c.wait_with_output()
            })
            .unwrap();
        String::from_utf8_lossy(&out.stdout)[..64].to_string()
    };
    let mut chunked = Vec::new();
    for piece in up.chunks(100_000) {
        chunked.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        chunked.extend_from_slice(piece);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let head = format!(
        "POST /up HTTP/1.1\r\nHost: {}\r\n{header}\r\nTransfer-Encoding: chunked\r\n\r\n",
        host(8000, &a)
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(&chunked);
    let r = plane.ingress_raw(&request, Duration::from_secs(60));
    assert_eq!(r.status, 200, "{}", r.head);
    let got: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(
        (got["bytes"].as_u64(), got["sha256"].as_str()),
        (Some(8 << 20), Some(digest.as_str()))
    );
    let mut request = format!(
        "POST /up HTTP/1.1\r\nHost: {}\r\n{header}\r\nContent-Length: {}\r\n\r\n",
        host(8000, &a),
        up.len()
    )
    .into_bytes();
    request.extend_from_slice(&up);
    let r = plane.ingress_raw(&request, Duration::from_secs(60));
    assert_eq!(
        serde_json::from_slice::<Value>(&r.body).unwrap()["sha256"],
        digest
    );
    let started = Instant::now();
    let r = plane.ingress_get(8000, &a, &format!("/big?n={}", 32 << 20), &[&header]);
    assert_eq!((r.status, r.body.len()), (200, 32 << 20));
    assert!(r.body.iter().all(|&b| b == b'x'));
    eprintln!("32 MiB down through ingress in {:?}", started.elapsed());

    // An upgrade: after 101, bytes both ways, then the client's FIN ends
    // it.
    let mut conn = TcpStream::connect(plane.ingress_addr()).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        conn,
        "GET /upgrade HTTP/1.1\r\nHost: {}\r\n{header}\r\nConnection: Upgrade\r\nUpgrade: shout\r\n\r\n",
        host(8000, &a)
    )
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8];
    while !head.ends_with(b"\r\n\r\n") {
        conn.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    assert_eq!(common::header(&head, "upgrade").as_deref(), Some("shout"));
    for word in ["hello", "ingress"] {
        conn.write_all(word.as_bytes()).unwrap();
        let mut got = vec![0u8; word.len()];
        conn.read_exact(&mut got).unwrap();
        assert_eq!(got, word.to_uppercase().as_bytes());
    }
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    conn.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    // A 101 to a request that asked for no upgrade is not passed on.
    let r = plane.ingress_get(8000, &a, "/upgrade", &[&header]);
    assert_eq!(r.status, 502, "{}", r.head);

    // Hostile heads are refused before anything reaches the guest.
    let h = host(8000, &a);
    let hostile: Vec<(String, u16)> = vec![
        (format!("POST /evil-1 HTTP/1.1\r\nHost: {h}\r\n{header}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"), 400),
        (format!("POST /evil-2 HTTP/1.1\r\nHost: {h}\r\n{header}\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcd"), 400),
        (format!("POST /evil-3 HTTP/1.1\r\nHost: {h}\r\n{header}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n"), 400),
        (format!("POST /evil-4 HTTP/1.1\r\nHost: {h}\r\n{header}\r\nTransfer-Encoding: xchunked\r\n\r\n"), 400),
        (format!("GET /evil-5 HTTP/1.1\r\nHost: {h}\r\nHost: {h}\r\n{header}\r\n\r\n"), 400),
        (format!("GET /evil-6 HTTP/1.1\r\nHost: {h}\r\n{header}\r\nX: a\r\n b\r\n\r\n"), 400),
        (format!("GET /evil-7 HTTP/1.1\nHost: {h}\n{header}\n\n"), 0),
        (format!("GET http://{h}/evil-8 HTTP/1.1\r\nHost: {h}\r\n{header}\r\n\r\n"), 400),
        (format!("GET /evil-9 HTTP/1.1\r\nHost: {h}\r\n{header}\r\nX: {}\r\n\r\n", "a".repeat(40_000)), 431),
        (format!("GET /evil-10 HTTP/1.1\r\nHost: 8000-{a}.sb.test.evil\r\n{header}\r\n\r\n"), 404),
        (format!("GET /evil-11 HTTP/1.1\r\nHost: {h}:abc\r\n{header}\r\n\r\n"), 404),
        (format!("GET /evil-12 HTTP/2.0\r\nHost: {h}\r\n{header}\r\n\r\n"), 400),
    ];
    for (request, status) in &hostile {
        let r = plane.ingress_raw(request.as_bytes(), Duration::from_secs(15));
        if *status == 0 {
            // Bare LFs never complete a head: refused when it times out
            // (408) or as soon as the client stops.
            assert!(matches!(r.status, 0 | 400 | 408), "{request:?}: {}", r.head);
        } else {
            assert_eq!(r.status, *status, "{request:?}: {}", r.head);
        }
    }
    // A request smuggled after a chunked body's end, and pipelined
    // requests, go no further than the ingress.
    let mut smuggle = format!(
        "POST /fine HTTP/1.1\r\nHost: {h}\r\n{header}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    );
    smuggle.push_str(&format!(
        "GET /evil-smuggled HTTP/1.1\r\nHost: {h}\r\n{header}\r\n\r\n"
    ));
    let r = plane.ingress_raw(smuggle.as_bytes(), Duration::from_secs(15));
    assert_eq!(r.status, 200, "{}", r.head);
    assert!(!r.text().contains("evil"), "{}", r.text());
    let pipelined = format!(
        "POST /fine HTTP/1.1\r\nHost: {h}\r\n{header}\r\nContent-Length: 3\r\n\r\nabcGET /evil-pipelined HTTP/1.1\r\nHost: {h}\r\n{header}\r\n\r\n"
    );
    let r = plane.ingress_raw(pipelined.as_bytes(), Duration::from_secs(15));
    assert_eq!(r.status, 200);
    // A head split into pieces still arrives whole.
    let split = format!("GET /split HTTP/1.1\r\nHost: {h}\r\n{header}\r\n\r\n");
    let (one, two) = split.split_at(20);
    let r = send_in_pieces(&plane, one, &[two.as_bytes()], Duration::from_millis(300));
    assert_eq!((r.status, r.text()), (200, "hello /split".into()));
    let log = requests_log(&plane, &a);
    assert!(log.contains("/split") && log.contains("/fine"), "{log}");
    assert!(
        !log.contains("evil"),
        "a hostile request reached the guest: {log}"
    );

    // What one exchange costs: a new connection, a hand-over, a new
    // connection in the guest (debug build; printed, not checked).
    let mut times: Vec<f64> = (0..50)
        .map(|_| {
            let t = Instant::now();
            assert_eq!(plane.ingress_get(8000, &a, "/t", &[&header]).status, 200);
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    let (median, low, high) = common::stats(&mut times);
    eprintln!("ingress GET, request to the end of the answer: median {median:.2} ms ({low:.2} to {high:.2})");

    // Unexposing and rotating take effect at once.
    let r = plane.call(
        ACME,
        "POST",
        &format!("/v1/sandboxes/{a}/ingress/token"),
        b"",
    );
    assert_eq!(r.status, 200);
    let rotated = r.json()["token"].as_str().unwrap().to_string();
    assert_ne!(rotated, token);
    assert_eq!(plane.ingress_get(8000, &a, "/", &[&header]).status, 404);
    let new_header = format!("X-Hellovm-Ingress-Token: {rotated}");
    assert_eq!(plane.ingress_get(8000, &a, "/", &[&new_header]).status, 200);
    let r = plane.call(
        ACME,
        "DELETE",
        &format!("/v1/sandboxes/{a}/ingress/ports/8000"),
        b"",
    );
    assert_eq!(
        r.json()["ports"].as_array().unwrap().len(),
        1,
        "8002 is left"
    );
    assert_eq!(plane.ingress_get(8000, &a, "/", &[&new_header]).status, 404);

    // Metered: what went in and out, for the sandbox and the tenant.
    eventually(Duration::from_secs(10), "ingress counted", || {
        let s = plane
            .call(ACME, "GET", &format!("/v1/sandboxes/{a}"), b"")
            .json();
        s["usage"]["ingress_received_bytes"].as_u64().unwrap_or(0) > 16 << 20
            && s["usage"]["ingress_sent_bytes"].as_u64().unwrap_or(0) > 32 << 20
    });
    let usage = plane.call(ACME, "GET", "/v1/usage", b"").json();
    assert!(
        usage["usage"]["ingress_sent_bytes"].as_u64().unwrap() > 32 << 20,
        "{usage}"
    );
    let beta = plane.call(BETA, "GET", "/v1/usage", b"").json();
    assert!(
        beta["usage"]["ingress_sent_bytes"].as_u64().unwrap() < 1 << 20,
        "{beta}"
    );
    let list = plane.call(ACME, "GET", "/v1/sandboxes", b"").json();
    assert!(
        list["sandboxes"][0]["usage"]["ingress_sent_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
fn ingress_use_keeps_a_sandbox_from_its_idle_timeout() {
    let Some(plane) = Plane::start(PlaneOptions::default()) else {
        return;
    };
    let a = id_of(&plane.create(ACME, json!({"idle_timeout": 3})));
    serve(&plane, ACME, &a, 8000);
    expose(&plane, ACME, &a, 8000, true);
    wait_serving(&plane, &a, 8000, "");
    // Only bytes on one long connection, for twice the idle timeout.
    let mut conn = TcpStream::connect(plane.ingress_addr()).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        conn,
        "GET /upgrade HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: shout\r\n\r\n",
        host(8000, &a)
    )
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8];
    while !head.ends_with(b"\r\n\r\n") {
        conn.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    for _ in 0..7 {
        std::thread::sleep(Duration::from_secs(1));
        conn.write_all(b"x").unwrap();
        conn.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"X");
    }
    let r = plane.call(ACME, "GET", &format!("/v1/sandboxes/{a}"), b"");
    assert_eq!(r.status, 200, "removed while used through ingress");
    drop(conn);
    // Unused, it goes.
    eventually(Duration::from_secs(15), "idle sandbox removed", || {
        plane
            .call(ACME, "GET", &format!("/v1/sandboxes/{a}"), b"")
            .status
            == 410
    });
}

#[test]
fn ingress_deadlines_and_connection_limits() {
    let Some(plane) = Plane::start(PlaneOptions {
        acme_max: 3,
        api_extra: json!({"ingress": {
            "head_timeout": 2, "idle_timeout": 2, "max_duration": 6,
            "max_connections_per_sandbox": 2, "max_connections_per_tenant": 3,
        }}),
        ..PlaneOptions::default()
    }) else {
        return;
    };
    let a = id_of(&plane.create(ACME, json!({})));
    let a2 = id_of(&plane.create(ACME, json!({})));
    let b = id_of(&plane.create(BETA, json!({})));
    for (token, id) in [(ACME, &a), (ACME, &a2), (BETA, &b)] {
        serve(&plane, token, id, 8000);
        expose(&plane, token, id, 8000, true);
        wait_serving(&plane, id, 8000, "");
    }
    let h = host(8000, &a);

    // A slow head: 408 at the head timeout. A silent client: closed.
    let started = Instant::now();
    let r = send_in_pieces(&plane, "GET / HTTP/1.1\r\nHo", &[], Duration::ZERO);
    assert_eq!(r.status, 408, "{}", r.head);
    let silent = plane.ingress_raw(b"", Duration::from_secs(10));
    assert_eq!(silent.status, 0);
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
    // A guest that does not answer: 504 at the idle timeout.
    let started = Instant::now();
    let r = plane.ingress_get(8000, &a, "/slow?s=10", &[]);
    assert_eq!(r.status, 504, "{}", r.head);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // A client that stops sending its body: closed at the idle timeout,
    // the guest sees a short body.
    let started = Instant::now();
    let r = send_in_pieces(
        &plane,
        &format!("POST /short HTTP/1.1\r\nHost: {h}\r\nContent-Length: 100\r\n\r\n0123456789"),
        &[],
        Duration::ZERO,
    );
    assert!(r.status != 200, "{}", r.head);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // A connection that keeps moving bytes ends at max_duration.
    let started = Instant::now();
    let mut conn = upgrade(&plane, &a);
    let mut byte = [0u8];
    let mut ended = false;
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(300));
        if conn.write_all(b"x").is_err() || conn.read_exact(&mut byte).is_err() {
            ended = true;
            break;
        }
    }
    assert!(ended, "the connection outlived max_duration");
    let lasted = started.elapsed();
    assert!(
        lasted >= Duration::from_secs(5) && lasted < Duration::from_secs(9),
        "{lasted:?}"
    );

    // Per sandbox: two at once, the third waits its turn (503).
    let held: Vec<TcpStream> = (0..2).map(|_| upgrade(&plane, &a)).collect();
    let r = plane.ingress_get(8000, &a, "/", &[]);
    assert_eq!(r.status, 503, "{}", r.head);
    assert_eq!(common::header(&r.head, "retry-after").as_deref(), Some("1"));
    // Per tenant: one more for its other sandbox, then 503.
    let held2 = upgrade(&plane, &a2);
    assert_eq!(plane.ingress_get(8000, &a2, "/", &[]).status, 503);
    // Another tenant is not held up by any of it.
    for _ in 0..5 {
        let r = plane.ingress_get(8000, &b, "/", &[]);
        assert_eq!(r.status, 200, "{}", r.head);
    }
    drop(held);
    drop(held2);
    eventually(Duration::from_secs(10), "slots given back", || {
        plane.ingress_get(8000, &a, "/", &[]).status == 200
    });
    // None of this marked the node unreachable.
    let node = plane
        .admin_call(ADMIN_TOKEN, "GET", "/admin/v1/nodes/node-1")
        .json();
    assert_eq!(node["state"], "healthy", "{node}");
}

/// An upgraded connection to `/upgrade` of the public port 8000 of `id`.
fn upgrade(plane: &Plane, id: &str) -> TcpStream {
    let mut conn = TcpStream::connect(plane.ingress_addr()).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        conn,
        "GET /upgrade HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: shout\r\n\r\n",
        host(8000, id)
    )
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8];
    while !head.ends_with(b"\r\n\r\n") {
        conn.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    conn
}

#[test]
fn ingress_across_nodes_with_one_unreachable() {
    let Some(plane) = Plane::start(PlaneOptions {
        nodes: 2,
        ..PlaneOptions::default()
    }) else {
        return;
    };
    // Placement spreads them: one on each node.
    let s1 = plane.create(ACME, json!({}));
    let s2 = plane.create(ACME, json!({}));
    assert_ne!(s1["node"], s2["node"]);
    let ids = [id_of(&s1), id_of(&s2)];
    let mut tokens = Vec::new();
    for id in &ids {
        serve(&plane, ACME, id, 8000);
        tokens.push(
            ingress(&plane, ACME, id)["token"]
                .as_str()
                .unwrap()
                .to_string(),
        );
        expose(&plane, ACME, id, 8000, false);
        expose(&plane, ACME, id, 8001, true);
        wait_serving(&plane, id, 8000, &tokens[tokens.len() - 1]);
    }
    for (id, token) in ids.iter().zip(&tokens) {
        let r = plane.ingress_get(
            8000,
            id,
            "/n",
            &[&format!("X-Hellovm-Ingress-Token: {token}")],
        );
        assert_eq!((r.status, r.text()), (200, "hello /n".into()));
    }
    // The second sandbox's node stops answering.
    let i = if s2["node"] == "node-2" { 1 } else { 0 };
    plane.stop_node(i);
    let name = s2["node"].as_str().unwrap();
    eventually(Duration::from_secs(20), "node unreachable", || {
        plane
            .admin_call(ADMIN_TOKEN, "GET", &format!("/admin/v1/nodes/{name}"))
            .json()["state"]
            == "unreachable"
    });
    let right = format!("X-Hellovm-Ingress-Token: {}", tokens[1]);
    let wrong = format!("X-Hellovm-Ingress-Token: {}", tokens[0]);
    // With its token, or to its public port: told it does not answer.
    assert_eq!(plane.ingress_get(8000, &ids[1], "/", &[&right]).status, 502);
    assert_eq!(plane.ingress_get(8001, &ids[1], "/", &[]).status, 502);
    // Without it: the same 404 as for a sandbox that does not exist.
    let r = plane.ingress_get(8000, &ids[1], "/", &[&wrong]);
    let none = plane.ingress_get(8000, "sb-00000000000000000000000000000000", "/", &[&wrong]);
    assert_eq!((r.status, &r.body), (404, &none.body));
    assert_eq!(plane.ingress_get(8002, &ids[1], "/", &[&right]).status, 404);
    // The other node's sandbox is served as before.
    let r = plane.ingress_get(8000, &ids[0], "/", &[&wrong]);
    assert_eq!(r.status, 200);
    plane.cont_node(i);
    eventually(Duration::from_secs(20), "node back", || {
        plane.ingress_get(8000, &ids[1], "/", &[&right]).status == 200
    });
}
