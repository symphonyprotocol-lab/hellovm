//! Spec 002b end to end: guest programs reach the "outside" only through the
//! egress proxy, with no internet.
//!
//! The outside is two local servers started from `tests/egress/serve.py`:
//! one over TLS (a test CA and a leaf for `tls.test`, `pypi.test` and
//! `git.test`, made with `openssl`), one plain HTTP. They serve a pip index
//! with one pure-Python wheel and a bare git repository (dumb HTTP). The
//! proxy runs in this process with the `insecure-test-hooks` name table,
//! which is the only way an allowed name can point at loopback; every other
//! blocked range stays blocked. The sandbox's image is the host's `/`, so
//! the guest runs the host's CPython, pip and git; the kernel supplies its
//! own `/etc/resolv.conf`.
//!
//! `live_pip_and_git` is the opt-in internet check (`HELLOVM_NET_E2E=1`).

#![cfg(target_os = "linux")]

mod common;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::{Session, SessionOptions, TempDir};
use hellovm_core::ExitStatus;
use hellovm_egress::audit::{AuditSink, MemorySink};
use hellovm_egress::policy::Policy;
use hellovm_egress::resolve::Resolver;
use hellovm_egress::{Config, Limits, Proxy, ProxyHandle};

const SANDBOX_ID: u64 = 0x00e9_7e55;

/// A host tool the tests need, or a skip (a failure under
/// `HELLOVM_REQUIRE_E2E=1`) naming the package.
fn require_tool(path: &str, package: &str) -> bool {
    if Path::new(path).exists() {
        return true;
    }
    common::skip_or_fail(&format!("egress e2e: {path} not found (install {package})"));
    false
}

fn require_all() -> bool {
    require_tool("/usr/bin/python3", "python3")
        && require_tool("/usr/bin/openssl", "openssl")
        && require_tool("/usr/bin/git", "git")
        && require_tool("/usr/lib/git-core/git-remote-https", "git")
        && {
            let pip = Command::new("/usr/bin/python3")
                .args(["-c", "import pip"])
                .status()
                .is_ok_and(|s| s.success());
            if !pip {
                common::skip_or_fail("egress e2e: python3 cannot import pip (install python3-pip)");
            }
            pip
        }
}

fn sh(cmd: &mut Command) {
    let out = cmd.output().unwrap_or_else(|err| panic!("{cmd:?}: {err}"));
    assert!(
        out.status.success(),
        "{cmd:?}: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The servers, their files, and the CA the guest trusts.
struct Outside {
    dir: TempDir,
    tls_port: u16,
    http_port: u16,
    servers: Vec<Child>,
}

impl Drop for Outside {
    fn drop(&mut self) {
        for child in &mut self.servers {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn serve(root: &Path, tls: Option<(&Path, &Path)>) -> (Child, u16) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/egress/serve.py");
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.arg(&script).arg(root);
    if let Some((cert, key)) = tls {
        cmd.arg("--tls").arg(cert).arg(key);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start serve.py");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let port = line
        .strip_prefix("PORT ")
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or_else(|| panic!("serve.py said {line:?}"));
    (child, port)
}

impl Outside {
    fn start() -> Outside {
        let dir = TempDir::new("egress-outside");
        let d = dir.path().to_path_buf();
        let srv = d.join("srv");
        std::fs::create_dir_all(srv.join("simple/hvdemo")).unwrap();
        // A CA and a leaf it signed.
        sh(Command::new("openssl").current_dir(&d).args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "2",
            "-subj",
            "/CN=hellovm-test-ca",
            // Python 3.13 and later verify with VERIFY_X509_STRICT: a CA
            // must say it is one and what its key may sign.
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]));
        sh(Command::new("openssl").current_dir(&d).args([
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=tls.test",
        ]));
        std::fs::write(
            d.join("ext"),
            "subjectAltName=DNS:tls.test,DNS:pypi.test,DNS:git.test\n\
             basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n\
             extendedKeyUsage=serverAuth\n\
             subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
        )
        .unwrap();
        sh(Command::new("openssl").current_dir(&d).args([
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "leaf.pem",
            "-days",
            "2",
            "-extfile",
            "ext",
        ]));
        std::fs::write(srv.join("hello.txt"), "hello-outside\n").unwrap();
        // A pip index with one pure-Python wheel.
        sh(Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(WHEEL)
            .arg(&srv));
        // A bare repository served as static files (git's dumb HTTP).
        let work = d.join("work");
        sh(Command::new("git").args(["init", "-q"]).arg(&work));
        std::fs::write(work.join("README"), "hello-from-git\n").unwrap();
        sh(Command::new("git")
            .current_dir(&work)
            .args(["add", "README"]));
        sh(Command::new("git").current_dir(&work).args([
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "init",
        ]));
        sh(Command::new("git")
            .args(["clone", "-q", "--bare"])
            .arg(&work)
            .arg(srv.join("repo.git")));
        sh(Command::new("git")
            .current_dir(srv.join("repo.git"))
            .args(["update-server-info"]));
        let (tls, tls_port) = serve(&srv, Some((&d.join("leaf.pem"), &d.join("leaf.key"))));
        let (http, http_port) = serve(&srv, None);
        Outside {
            dir,
            tls_port,
            http_port,
            servers: vec![tls, http],
        }
    }

    fn ca(&self) -> PathBuf {
        self.dir.path().join("ca.pem")
    }

    /// The proxy's test name table.
    fn table(&self) -> String {
        format!(
            "tls.test 127.0.0.1:{t}\npypi.test 127.0.0.1:{t}\ngit.test 127.0.0.1:{t}\n\
             web.test 127.0.0.1:{h}\nevil.test 127.0.0.1:{t}\n\
             private.test 10.0.0.1 192.168.1.1\nmeta.test 169.254.169.254\n",
            t = self.tls_port,
            h = self.http_port
        )
    }
}

/// Writes `simple/hvdemo/` with `hvdemo-0.1-py3-none-any.whl`.
const WHEEL: &str = r#"
import base64, hashlib, os, sys, zipfile
root = sys.argv[1]
files = {
    "hvdemo/__init__.py": b"VALUE = 'hvdemo-ok'\n",
    "hvdemo-0.1.dist-info/METADATA": b"Metadata-Version: 2.1\nName: hvdemo\nVersion: 0.1\n",
    "hvdemo-0.1.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: hellovm-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
}
rec = []
for name, data in files.items():
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    rec.append(f"{name},sha256={digest},{len(data)}")
rec.append("hvdemo-0.1.dist-info/RECORD,,")
files["hvdemo-0.1.dist-info/RECORD"] = ("\n".join(rec) + "\n").encode()
whl = "hvdemo-0.1-py3-none-any.whl"
with zipfile.ZipFile(os.path.join(root, "simple/hvdemo", whl), "w") as z:
    for name, data in files.items():
        z.writestr(name, data)
with open(os.path.join(root, "simple/hvdemo/index.html"), "w") as f:
    f.write(f'<html><body><a href="{whl}">{whl}</a></body></html>\n')
with open(os.path.join(root, "simple/index.html"), "w") as f:
    f.write('<html><body><a href="hvdemo/">hvdemo</a></body></html>\n')
"#;

fn proxy(policy: &str, resolver: Resolver) -> (ProxyHandle, MemorySink, TempDir) {
    let dir = TempDir::new("egress-proxy");
    let (handle, audit) = proxy_at(&dir.path().join("egress.sock"), policy, resolver);
    (handle, audit, dir)
}

fn proxy_at(socket: &Path, policy: &str, resolver: Resolver) -> (ProxyHandle, MemorySink) {
    let mut p = Policy::new();
    p.add_file(policy).unwrap();
    let audit = MemorySink::default();
    let config = Config {
        policy: p,
        limits: Limits::default(),
        audit: AuditSink::new(Box::new(audit.clone())),
        resolver,
    };
    (Proxy::bind(socket, config).unwrap().spawn(), audit)
}

struct GuestRun {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl std::fmt::Display for GuestRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "status {:?}\nstdout:\n{}\nstderr:\n{}",
            self.status, self.stdout, self.stderr
        )
    }
}

/// Runs `argv` in a sandbox whose image is the host's `/`, with outbound
/// flows sent to the proxy at `egress`.
fn run_guest(egress: &Path, argv: &[&str], env: &[&str]) -> GuestRun {
    let mut session = Session::start(
        Path::new("/"),
        &SessionOptions {
            egress: Some(egress.to_path_buf()),
            sandbox_id: Some(SANDBOX_ID),
            ..SessionOptions::default()
        },
    );
    let mut envp = vec!["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/root"];
    envp.extend_from_slice(env);
    let out = session
        .run(argv, &envp, b"", Duration::from_secs(5))
        .unwrap_or_else(|err| panic!("exec {argv:?}: {err}"));
    GuestRun {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn audit_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(' ')
        .find_map(|kv| kv.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
}

/// The audit line for `host` with `reason`, after waiting for it.
fn audit_line(audit: &MemorySink, host: &str, reason: &str) -> String {
    let start = std::time::Instant::now();
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

const POLICY: &str = "allow tls.test:443\nallow pypi.test:443\nallow git.test:443\n\
                      allow web.test:80\nallow private.test\nallow meta.test:80\n";

/// One guest program checks every socket-level case; each prints a line.
const SOCKET_CASES: &str = r#"
import socket, ssl, sys
ca = sys.argv[1]

def out(*a):
    print(*a, flush=True)

def errno_of(fn):
    try:
        fn()
        return "connected"
    except OSError as e:
        return e.errno

def fetch(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk

out("addr", socket.gethostbyname("tls.test"))
try:
    socket.getaddrinfo("tls.test", 443, socket.AF_INET6)
    out("aaaa answered")
except socket.gaierror:
    out("aaaa none")

ctx = ssl.create_default_context(cafile=ca)
with socket.create_connection(("tls.test", 443), timeout=20) as s:
    with ctx.wrap_socket(s, server_hostname="tls.test") as t:
        t.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: tls.test\r\nConnection: close\r\n\r\n")
        data = fetch(t)
out("tls", data.split(b"\r\n")[0].decode(), data.endswith(b"hello-outside\n"))

with socket.create_connection(("web.test", 80), timeout=20) as s:
    s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: web.test\r\nConnection: close\r\n\r\n")
    data = fetch(s)
out("http", data.split(b"\r\n")[0].decode(), data.endswith(b"hello-outside\n"))

out("denied", errno_of(lambda: socket.create_connection(("evil.test", 443), timeout=20)))

# The SNI names another host. Certificate checks are off, so only the
# proxy can stop this handshake.
loose = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
loose.check_hostname = False
loose.verify_mode = ssl.CERT_NONE
s = socket.create_connection(("tls.test", 443), timeout=20)
try:
    loose.wrap_socket(s, server_hostname="evil.test")
    out("sni handshake-ok")
except (ssl.SSLError, OSError) as e:
    out("sni refused", type(e).__name__)
s.close()

with socket.create_connection(("web.test", 80), timeout=20) as s:
    s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n")
    try:
        out("host-mismatch", repr(fetch(s)[:12]))
    except OSError as e:
        out("host-mismatch", "error", e.errno)

out("private", errno_of(lambda: socket.create_connection(("private.test", 443), timeout=20)))
out("meta", errno_of(lambda: socket.create_connection(("meta.test", 80), timeout=20)))
out("raw-ip", errno_of(lambda: socket.create_connection(("151.101.0.223", 443), timeout=20)))
out("metadata-ip", errno_of(lambda: socket.create_connection(("169.254.169.254", 80), timeout=20)))
"#;

#[test]
fn the_proxy_decides_every_outbound_flow() {
    if !require_all() {
        return;
    }
    let outside = Outside::start();
    let (proxy, audit, _dir) = proxy(
        POLICY,
        Resolver::parse_test_table(&outside.table()).unwrap(),
    );
    let ca = outside.ca();
    let out = run_guest(
        proxy.path(),
        &["/usr/bin/python3", "-c", SOCKET_CASES, ca.to_str().unwrap()],
        &[],
    );
    assert_eq!(out.status, ExitStatus::Exited(0), "{out}");
    let lines: Vec<&str> = out.stdout.lines().collect();
    let want = [
        "addr 198.51.100.1",
        "aaaa none",
        "tls HTTP/1.0 200 OK True",
        "http HTTP/1.0 200 OK True",
        "denied 111",
        "host-mismatch b''",
        "private 111",
        "meta 111",
        "raw-ip 101",
        "metadata-ip 101",
    ];
    for w in want {
        assert!(lines.contains(&w), "missing {w:?}\n{out}");
    }
    assert!(
        out.stdout.contains("sni refused"),
        "the SNI check did not stop the handshake\n{out}"
    );
    // One audit line per decision, with the sandbox id and the reason.
    let tls = audit_line(&audit, "tls.test", "ok");
    assert_eq!(audit_field(&tls, "sandbox"), Some("0000000000e97e55"));
    assert_eq!(audit_field(&tls, "verdict"), Some("allow"));
    assert_eq!(audit_field(&tls, "port"), Some("443"));
    assert!(audit_field(&tls, "down").unwrap().parse::<u64>().unwrap() > 0);
    assert!(audit_field(&tls, "up").unwrap().parse::<u64>().unwrap() > 0);
    audit_line(&audit, "web.test", "ok");
    audit_line(&audit, "evil.test", "policy");
    let sni = audit_line(&audit, "tls.test", "sni-mismatch");
    assert_eq!(audit_field(&sni, "sni"), Some("evil.test"));
    let host = audit_line(&audit, "web.test", "host-mismatch");
    assert_eq!(audit_field(&host, "http_host"), Some("evil.test"));
    audit_line(&audit, "private.test", "blocked-address");
    let meta = audit_line(&audit, "meta.test", "blocked-address");
    assert_eq!(audit_field(&meta, "addr"), Some("169.254.169.254:80"));
    // The raw IPs never reached the proxy.
    assert!(!audit.lines().iter().any(|l| l.contains("151.101")));
}

#[test]
fn a_missing_proxy_refuses_connects() {
    if !require_tool("/usr/bin/python3", "python3") {
        return;
    }
    let dir = TempDir::new("egress-down");
    let script = r#"
import socket
print("addr", socket.gethostbyname("tls.test"))
try:
    socket.create_connection(("tls.test", 443), timeout=20)
    print("connected")
except OSError as e:
    print("errno", e.errno)
"#;
    let out = run_guest(
        &dir.path().join("nobody-listens.sock"),
        &["/usr/bin/python3", "-c", script],
        &[],
    );
    assert_eq!(out.status, ExitStatus::Exited(0), "{out}");
    assert!(out.stdout.contains("addr 198.51.100.1"), "{out}");
    assert!(out.stdout.contains("errno 111"), "{out}");
}

/// A proxy is restarted to change its policy, or after a crash. Sandboxes
/// that were already running must reach the new one: their kernel process
/// keeps the socket's directory, not the socket that was there at start-up.
#[test]
fn a_restarted_proxy_serves_sandboxes_that_were_already_running() {
    if !require_all() {
        return;
    }
    let outside = Outside::start();
    let dir = TempDir::new("egress-restart");
    let socket = dir.path().join("egress.sock");
    let start = || {
        proxy_at(
            &socket,
            POLICY,
            Resolver::parse_test_table(&outside.table()).unwrap(),
        )
    };
    let script = r#"
import socket
try:
    with socket.create_connection(("web.test", 80), timeout=20) as s:
        s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: web.test\r\nConnection: close\r\n\r\n")
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    print("fetched", data.endswith(b"hello-outside\n"))
except OSError as e:
    print("errno", e.errno)
"#;
    let (first, _audit) = start();
    let mut session = Session::start(
        Path::new("/"),
        &SessionOptions {
            egress: Some(socket.clone()),
            sandbox_id: Some(SANDBOX_ID),
            ..SessionOptions::default()
        },
    );
    let mut fetch = || {
        let out = session
            .run(
                &["/usr/bin/python3", "-c", script],
                &["PATH=/usr/bin:/bin"],
                b"",
                Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(out.status, ExitStatus::Exited(0));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(fetch(), "fetched True");
    first.stop();
    assert_eq!(fetch(), "errno 111");
    let (_second, audit) = start();
    assert_eq!(fetch(), "fetched True");
    audit_line(&audit, "web.test", "ok");
}

#[test]
fn pip_installs_from_a_local_index_through_the_proxy() {
    if !require_all() {
        return;
    }
    let outside = Outside::start();
    let (proxy, audit, _dir) = proxy(
        POLICY,
        Resolver::parse_test_table(&outside.table()).unwrap(),
    );
    let ca = outside.ca();
    let script = format!(
        "python3 -m pip install --no-cache-dir --disable-pip-version-check --cert {} \
         --index-url https://pypi.test/simple/ --target /tmp/hvdemo-target hvdemo \
         && python3 -c 'import sys; sys.path.insert(0, \"/tmp/hvdemo-target\"); \
         import hvdemo; print(\"imported\", hvdemo.VALUE)'",
        ca.display()
    );
    let out = run_guest(proxy.path(), &["/bin/sh", "-c", &script], &[]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{out}");
    assert!(
        out.stdout.contains("Successfully installed hvdemo-0.1"),
        "{out}"
    );
    assert!(out.stdout.contains("imported hvdemo-ok"), "{out}");
    let line = audit_line(&audit, "pypi.test", "ok");
    assert_eq!(audit_field(&line, "verdict"), Some("allow"));
}

#[test]
fn git_clones_from_a_local_server_through_the_proxy() {
    if !require_all() {
        return;
    }
    let outside = Outside::start();
    let (proxy, audit, _dir) = proxy(
        POLICY,
        Resolver::parse_test_table(&outside.table()).unwrap(),
    );
    let ca = format!("GIT_SSL_CAINFO={}", outside.ca().display());
    let out = run_guest(
        proxy.path(),
        &[
            "/bin/sh",
            "-c",
            "git clone -q https://git.test/repo.git /tmp/hv-clone && cat /tmp/hv-clone/README",
        ],
        &[&ca],
    );
    assert_eq!(out.status, ExitStatus::Exited(0), "{out}");
    assert!(out.stdout.contains("hello-from-git"), "{out}");
    audit_line(&audit, "git.test", "ok");
}

/// Opt-in: a real `pip install` and `git clone` over the internet, with an
/// allowlist of exactly the hosts they need and the host's resolver.
/// `HELLOVM_NET_E2E=1` enables it; run-e2e.sh and CI never set it.
#[test]
fn live_pip_and_git() {
    if std::env::var("HELLOVM_NET_E2E").as_deref() != Ok("1") {
        eprintln!("live_pip_and_git: not run (set HELLOVM_NET_E2E=1 to run it)");
        return;
    }
    assert!(
        require_all(),
        "live test needs python3, pip, git and openssl"
    );
    let (proxy, audit, _dir) = proxy(
        "allow pypi.org:443\nallow files.pythonhosted.org:443\nallow github.com:443\n",
        Resolver::System,
    );
    let out = run_guest(
        proxy.path(),
        &[
            "/bin/sh",
            "-c",
            "python3 -m pip install --no-cache-dir --disable-pip-version-check \
             --target /tmp/live-six six==1.16.0 \
             && python3 -c 'import sys; sys.path.insert(0, \"/tmp/live-six\"); import six; print(\"six\", six.__version__)' \
             && git clone -q --depth 1 https://github.com/octocat/Hello-World.git /tmp/hw \
             && cat /tmp/hw/README",
        ],
        &[],
    );
    eprintln!("{}", audit.lines().join("\n"));
    assert_eq!(out.status, ExitStatus::Exited(0), "{out}");
    assert!(out.stdout.contains("six 1.16.0"), "{out}");
    assert!(out.stdout.contains("Hello World"), "{out}");
    audit_line(&audit, "pypi.org", "ok");
    audit_line(&audit, "files.pythonhosted.org", "ok");
    audit_line(&audit, "github.com", "ok");
}
