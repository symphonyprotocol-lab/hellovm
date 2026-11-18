//! A whole control plane on this host for the tests: an egress proxy (in
//! this process, with a test name table pointing `web.test` at a local
//! HTTP server), one or more `hellovm-noded` keeping a CPython template of
//! the host's `/` warm, and `hellovm-api` with two tenants (and its admin
//! API), all as real processes talking HTTP on loopback.
//!
//! The binaries are found next to this test's own (`cargo test
//! --workspace` builds them all). `HELLOVM_REQUIRE_E2E=1` turns a missing
//! dependency into a failure.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use hellovm_control::http;
use hellovm_egress::audit::{AuditSink, MemorySink};
use hellovm_egress::policy::Policy;
use hellovm_egress::resolve::Resolver;
use hellovm_egress::{Config as ProxyConfig, Limits, Proxy, ProxyHandle};
use serde_json::{json, Value};

pub const ACME: &str = "acme-token-0123456789abcdef0123456789";
pub const BETA: &str = "beta-token-0123456789abcdef0123456789";
pub const NODE_TOKEN: &str = "node-token-0123456789abcdef0123456789";
pub const ADMIN_TOKEN: &str = "admin-token-0123456789abcdef0123456789";
pub const STATS_TOKEN: &str = "stats-token-0123456789abcdef0123456789";
pub const WEB_BODY: &str = "hello-egress";

pub fn e2e_required() -> bool {
    std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1")
}

pub fn skip_or_fail(reason: &str) {
    if e2e_required() {
        panic!("required e2e dependency missing: {reason}");
    }
    eprintln!("SKIPPING {reason}");
}

/// Whether the host kernel offers Landlock (what a shared template needs).
pub fn landlock() -> bool {
    // SAFETY: landlock_create_ruleset(NULL, 0, VERSION) only reports the ABI.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32,
        )
    };
    abi >= 1
}

fn binary(name: &str) -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_BIN_EXE_hellovm-api")).parent()?;
    let path = dir.join(name);
    path.is_file().then_some(path)
}

/// What the tests need on the host, or a skip.
pub fn require() -> Option<(PathBuf, PathBuf)> {
    if !Path::new("/usr/bin/python3").exists() {
        skip_or_fail("control plane e2e: /usr/bin/python3 not found (install python3)");
        return None;
    }
    match (binary("hellovm"), binary("hellovm-noded")) {
        (Some(hellovm), Some(noded)) => Some((hellovm, noded)),
        _ => {
            skip_or_fail(
                "control plane e2e: hellovm and hellovm-noded are not built next to the test \
                 (run cargo test --workspace)",
            );
            None
        }
    }
}

/// A child process whose stderr is kept and scanned for its address.
pub struct Service {
    pub child: Child,
    pub addr: String,
    pub log: Arc<Mutex<String>>,
}

impl Service {
    fn start(mut cmd: Command, what: &str) -> Service {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("start {what}: {e}"));
        let log = Arc::new(Mutex::new(String::new()));
        let (tx, rx) = mpsc::channel();
        let stderr = child.stderr.take().unwrap();
        let keep = Arc::clone(&log);
        let echo = std::env::var_os("HELLOVM_TEST_LOG").is_some();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if echo {
                    eprintln!("{line}");
                }
                if let Some(addr) = line.split("listening on ").nth(1) {
                    let _ = tx.send(addr.trim().to_string());
                }
                let mut log = keep.lock().unwrap();
                if log.len() < 4 << 20 {
                    log.push_str(&line);
                    log.push('\n');
                }
            }
        });
        let addr = rx
            .recv_timeout(Duration::from_secs(30))
            .unwrap_or_else(|_| panic!("{what} did not start:\n{}", log.lock().unwrap()));
        Service { child, addr, log }
    }

    pub fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// SIGKILL and reap.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// SIGTERM; the exit status.
    pub fn terminate(&mut self) -> std::process::ExitStatus {
        // SAFETY: plain kill of our own child.
        unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        self.child.wait().unwrap()
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.kill();
    }
}

/// An answer.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| {
            panic!(
                "not JSON ({}): {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    pub fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub struct PlaneOptions {
    pub memory_limit_mb: u64,
    pub max_processes: usize,
    pub acme_max: usize,
    /// How many `noded` (`node-1`, `node-2`, ...).
    pub nodes: usize,
    /// `max_sandboxes` per node, by index (32 for those not given).
    pub node_max_sandboxes: Vec<usize>,
    /// A node that also has a template `extra` (acme's own).
    pub extra_template_on: Option<usize>,
    /// More nodes in the API's configuration: `(name, addr)`, with the
    /// node token (fakes the test runs itself).
    pub extra_nodes: Vec<(String, String)>,
    /// Fields added to the API's configuration.
    pub api_extra: Value,
    /// Fields added to each node's configuration, by index.
    pub node_extra: Vec<Value>,
    /// Fields added to the tenants' configurations.
    pub acme_extra: Value,
    pub beta_extra: Value,
}

impl Default for PlaneOptions {
    fn default() -> PlaneOptions {
        PlaneOptions {
            memory_limit_mb: 512,
            max_processes: 4096,
            acme_max: 3,
            nodes: 1,
            node_max_sandboxes: Vec::new(),
            extra_template_on: None,
            extra_nodes: Vec::new(),
            api_extra: json!({}),
            node_extra: Vec::new(),
            acme_extra: json!({}),
            beta_extra: json!({}),
        }
    }
}

/// One `noded` of the plane.
pub struct NodeProc {
    pub name: String,
    /// A fixed port: the API finds a restarted noded again.
    pub port: u16,
    pub service: Option<Service>,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .unwrap()
        .port()
}

pub struct Plane {
    pub dir: PathBuf,
    pub hellovm: PathBuf,
    pub noded_bin: PathBuf,
    pub nodes: Vec<NodeProc>,
    pub api: Option<Service>,
    pub audit: MemorySink,
    _proxy: ProxyHandle,
    /// Whether one template serves both tenants (Landlock fences its
    /// clones), or each tenant has its own.
    pub shared: bool,
    pub options: PlaneOptions,
    /// The admin API's port (fixed, so a restarted API keeps it).
    pub admin_port: u16,
}

/// A local HTTP server: answers every request with [`WEB_BODY`].
fn web_server() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && head.len() < 16384 {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{WEB_BODY}",
                    WEB_BODY.len()
                );
            });
        }
    });
    port
}

impl Plane {
    pub fn start(options: PlaneOptions) -> Option<Plane> {
        let (hellovm, noded_bin) = require()?;
        let dir = std::env::temp_dir().join(format!(
            "hvplane-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("egress")).unwrap();
        std::fs::create_dir_all(dir.join("egress-stats")).unwrap();
        let web = web_server();
        let mut policy = Policy::new();
        policy.add_file("allow web.test:80\n").unwrap();
        let audit = MemorySink::default();
        let config = ProxyConfig {
            policy,
            limits: Limits::default(),
            audit: AuditSink::new(Box::new(audit.clone())),
            resolver: Resolver::parse_test_table(&format!("web.test 127.0.0.1:{web}\n")).unwrap(),
        };
        let proxy = Proxy::bind(dir.join("egress/egress.sock"), config)
            .unwrap()
            .spawn();
        proxy
            .serve_stats(&dir.join("egress-stats/stats.sock"), STATS_TOKEN.into())
            .unwrap();
        let shared = landlock();
        if !shared {
            eprintln!(
                "note: no Landlock on this host: each tenant gets a template of its own \
                 (a shared template needs Landlock to fence its clones)"
            );
        }
        let nodes = (0..options.nodes.max(1))
            .map(|i| NodeProc {
                name: format!("node-{}", i + 1),
                port: free_port(),
                service: None,
            })
            .collect();
        let mut plane = Plane {
            dir,
            hellovm,
            noded_bin,
            nodes,
            api: None,
            audit,
            _proxy: proxy,
            shared,
            options,
            admin_port: free_port(),
        };
        for i in 0..plane.nodes.len() {
            plane.write_node_config(i);
            plane.start_node(i);
        }
        for i in 0..plane.nodes.len() {
            plane.wait_templates_at(i, 1);
        }
        plane.start_api();
        Some(plane)
    }

    pub fn template(&self, tenant_token: &str) -> &'static str {
        if self.shared || tenant_token == ACME {
            "python"
        } else {
            "python-beta"
        }
    }

    fn write_node_config(&self, i: usize) {
        let template = |name: &str, tenant: Option<&str>| {
            let mut t = json!({
                "name": name, "root": "/", "python": "/usr/bin/python3",
                "preload": ["json", "decimal", "hashlib", "sqlite3", "urllib.request"],
                "memory_limit_mb": self.options.memory_limit_mb,
                "fs_limit_mb": 256,
                "max_processes": self.options.max_processes,
                // The image is the host's `/`, whose /root (the agent's
                // default home) only root can read; the tests also run
                // as another user.
                "env": {"HOME": "/home/sandbox"},
            });
            if let Some(tenant) = tenant {
                t["tenant"] = json!(tenant);
                t["sandbox"] = json!("best-effort");
            }
            t
        };
        let mut templates = if self.shared {
            vec![template("python", None)]
        } else {
            vec![
                template("python", Some("acme")),
                template("python-beta", Some("beta")),
            ]
        };
        if self.options.extra_template_on == Some(i) {
            templates.push(template("extra", Some("acme")));
        }
        let node = &self.nodes[i];
        let mut noded = json!({
            "node": node.name,
            "listen": format!("127.0.0.1:{}", node.port),
            "token": NODE_TOKEN,
            "hellovm": self.hellovm,
            "state_dir": self.state_dir(i),
            "egress": self.dir.join("egress/egress.sock"),
            "max_sandboxes": self.options.node_max_sandboxes.get(i).copied().unwrap_or(32),
            "templates": templates,
            "egress_stats": {
                "socket": self.dir.join("egress-stats/stats.sock"),
                "token": STATS_TOKEN,
            },
        });
        if let Some(Value::Object(extra)) = self.options.node_extra.get(i) {
            for (k, v) in extra {
                noded[k] = v.clone();
            }
        }
        std::fs::write(self.node_config(i), noded.to_string()).unwrap();
    }

    fn node_config(&self, i: usize) -> PathBuf {
        match i {
            0 => self.dir.join("noded.json"),
            i => self.dir.join(format!("noded-{}.json", i + 1)),
        }
    }

    /// Node `i`'s state directory (`state` for the first).
    pub fn state_dir(&self, i: usize) -> PathBuf {
        match i {
            0 => self.dir.join("state"),
            i => self.dir.join(format!("state-{}", i + 1)),
        }
    }

    /// Starts the first node.
    pub fn start_noded(&mut self) {
        self.start_node(0);
    }

    pub fn start_node(&mut self, i: usize) {
        let mut cmd = Command::new(&self.noded_bin);
        cmd.arg("--config").arg(self.node_config(i));
        self.nodes[i].service = Some(Service::start(cmd, "hellovm-noded"));
    }

    /// Stops node `i`'s process (`SIGSTOP`): it answers nothing, and its
    /// sandboxes live on.
    pub fn stop_node(&self, i: usize) {
        let pid = self.nodes[i]
            .service
            .as_ref()
            .expect("noded runs")
            .child
            .id();
        // SAFETY: plain kill of our own child.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
    }

    /// Lets node `i` run again (`SIGCONT`).
    pub fn cont_node(&self, i: usize) {
        let pid = self.nodes[i]
            .service
            .as_ref()
            .expect("noded runs")
            .child
            .id();
        // SAFETY: plain kill of our own child.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) };
    }

    /// Kills node `i` hard (its sandboxes die with it).
    pub fn kill_node(&mut self, i: usize) {
        if let Some(mut node) = self.nodes[i].service.take() {
            node.kill();
        }
    }

    /// Writes the API's configuration for the current node addresses.
    fn write_api_config(&self) {
        let mut nodes: Vec<Value> = self
            .nodes
            .iter()
            .map(|n| {
                json!({"name": n.name, "addr": format!("127.0.0.1:{}", n.port), "token": NODE_TOKEN})
            })
            .collect();
        for (name, addr) in &self.options.extra_nodes {
            nodes.push(json!({"name": name, "addr": addr, "token": NODE_TOKEN}));
        }
        let mut acme =
            json!({"name": "acme", "token": ACME, "max_sandboxes": self.options.acme_max});
        let mut beta = json!({"name": "beta", "token": BETA, "max_sandboxes": 2});
        for (tenant, extra) in [
            (&mut acme, &self.options.acme_extra),
            (&mut beta, &self.options.beta_extra),
        ] {
            if let Value::Object(extra) = extra {
                for (k, v) in extra {
                    tenant[k] = v.clone();
                }
            }
        }
        let mut api = json!({
            "listen": "127.0.0.1:0",
            "tenants": [acme, beta],
            "nodes": nodes,
            "reconcile_interval": 0.5,
            "node_timeout": 2,
            "admin": {"listen": format!("127.0.0.1:{}", self.admin_port), "token": ADMIN_TOKEN},
        });
        if let Value::Object(extra) = &self.options.api_extra {
            for (k, v) in extra {
                api[k] = v.clone();
            }
        }
        std::fs::write(self.dir.join("api.json"), api.to_string()).unwrap();
    }

    pub fn start_api(&mut self) {
        self.write_api_config();
        let api = Path::new(env!("CARGO_BIN_EXE_hellovm-api"));
        let mut cmd = Command::new(api);
        cmd.arg("--config").arg(self.dir.join("api.json"));
        self.api = Some(Service::start(cmd, "hellovm-api"));
    }

    pub fn restart_api(&mut self) {
        if let Some(mut api) = self.api.take() {
            api.kill();
        }
        self.start_api();
    }

    /// The first node.
    pub fn noded(&mut self) -> &mut Service {
        self.nodes[0].service.as_mut().expect("noded runs")
    }

    /// Everything the services logged, for failure messages.
    pub fn logs(&self) -> String {
        let mut out = String::new();
        for node in &self.nodes {
            out.push_str(&format!(
                "--- noded {} ---\n{}\n",
                node.name,
                node.service.as_ref().map(|s| s.log()).unwrap_or_default()
            ));
        }
        out.push_str(&format!(
            "--- api ---\n{}",
            self.api.as_ref().map(|s| s.log()).unwrap_or_default()
        ));
        out
    }

    /// Calls the first node's API directly.
    pub fn node_call(&self, method: &str, target: &str) -> Answer {
        self.node_call_at(0, method, target)
    }

    /// Calls node `i`'s API directly.
    pub fn node_call_at(&self, i: usize, method: &str, target: &str) -> Answer {
        let auth = format!("Bearer {NODE_TOKEN}");
        let r = http::call(
            &format!("127.0.0.1:{}", self.nodes[i].port),
            method,
            target,
            &[("Authorization", &auth)],
            b"",
            Duration::from_secs(30),
            32 << 20,
        )
        .unwrap();
        Answer {
            status: r.status,
            body: r.body,
        }
    }

    /// Calls the admin API with `token`.
    pub fn admin_call(&self, token: &str, method: &str, target: &str) -> Answer {
        api_call(
            &format!("127.0.0.1:{}", self.admin_port),
            token,
            method,
            target,
            b"",
        )
        .unwrap_or_else(|e| panic!("admin {method} {target}: {e}\n{}", self.logs()))
    }

    /// Waits until every template of the first node is ready and `python`
    /// was started at least `starts` times.
    pub fn wait_templates(&self, starts: u64) -> Value {
        self.wait_templates_at(0, starts)
    }

    pub fn wait_templates_at(&self, i: usize, starts: u64) -> Value {
        let start = Instant::now();
        loop {
            let status = self.node_call_at(i, "GET", "/v1/node").json();
            let templates = status["templates"].as_array().unwrap();
            if templates.iter().all(|t| {
                t["ready"] == json!(true)
                    && (t["name"] != "python" || t["starts"].as_u64() >= Some(starts))
            }) {
                return status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(180),
                "templates not ready: {status}\n{}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn api_addr(&self) -> String {
        self.api.as_ref().expect("api runs").addr.clone()
    }

    /// Calls the public API.
    pub fn call(&self, token: &str, method: &str, target: &str, body: &[u8]) -> Answer {
        api_call(&self.api_addr(), token, method, target, body)
            .unwrap_or_else(|e| panic!("{method} {target}: {e}\n{}", self.logs()))
    }

    pub fn call_json(&self, token: &str, method: &str, target: &str, body: Value) -> Answer {
        self.call(token, method, target, body.to_string().as_bytes())
    }

    /// Creates a sandbox and returns its description.
    pub fn create(&self, token: &str, extra: Value) -> Value {
        let mut body = json!({ "template": self.template(token) });
        if let Value::Object(extra) = extra {
            for (k, v) in extra {
                body[k] = v;
            }
        }
        let r = self.call_json(token, "POST", "/v1/sandboxes", body);
        assert_eq!(
            r.status,
            201,
            "{}\n{}",
            String::from_utf8_lossy(&r.body),
            self.logs()
        );
        r.json()
    }

    /// Runs an exec and returns its result (asserting `200`).
    pub fn exec(&self, token: &str, id: &str, request: Value) -> Value {
        let r = self.call_json(token, "POST", &format!("/v1/sandboxes/{id}/exec"), request);
        assert_eq!(
            r.status,
            200,
            "{}\n{}",
            String::from_utf8_lossy(&r.body),
            self.logs()
        );
        r.json()
    }

    pub fn sh(&self, token: &str, id: &str, command: &str) -> Value {
        self.exec(token, id, json!({ "command": command, "timeout": 30 }))
    }

    /// Starts an exec (`POST .../execs`) and returns its exec id.
    pub fn start_exec(&self, token: &str, id: &str, request: Value) -> String {
        let r = self.call_json(token, "POST", &format!("/v1/sandboxes/{id}/execs"), request);
        assert_eq!(
            r.status,
            201,
            "{}\n{}",
            String::from_utf8_lossy(&r.body),
            self.logs()
        );
        let status = r.json();
        assert_eq!(status["state"], "running", "{status}");
        status["exec_id"].as_str().unwrap().to_string()
    }

    /// One poll of an exec's output.
    pub fn poll(&self, token: &str, id: &str, exec: &str, cursor: u64, wait: f64) -> Answer {
        self.call(
            token,
            "GET",
            &format!("/v1/sandboxes/{id}/execs/{exec}?cursor={cursor}&wait={wait}"),
            b"",
        )
    }

    /// Reads an exec's output from `cursor` until `until` holds for the
    /// events so far (or its end): the events and the last poll.
    pub fn follow_until(
        &self,
        token: &str,
        id: &str,
        exec: &str,
        mut until: impl FnMut(&[Value]) -> bool,
    ) -> (Vec<Value>, Value) {
        let start = Instant::now();
        let mut cursor = 0;
        let mut events = Vec::new();
        loop {
            let r = self.poll(token, id, exec, cursor, 10.0);
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            let poll = r.json();
            events.extend(poll["events"].as_array().unwrap().iter().cloned());
            cursor = poll["next_cursor"].as_u64().unwrap();
            if poll["eof"] == json!(true) || until(&events) {
                return (events, poll);
            }
            assert!(
                start.elapsed() < Duration::from_secs(120),
                "the exec did not end: {poll}\n{}",
                self.logs()
            );
        }
    }

    /// Reads all of an exec's output: the events and its result.
    pub fn follow(&self, token: &str, id: &str, exec: &str) -> (Vec<Value>, Value) {
        let (events, poll) = self.follow_until(token, id, exec, |_| false);
        (events, poll["result"].clone())
    }

    pub fn cancel(&self, token: &str, id: &str, exec: &str) -> Answer {
        self.call(
            token,
            "POST",
            &format!("/v1/sandboxes/{id}/execs/{exec}/cancel"),
            b"",
        )
    }

    /// A stateful Python call run to its end.
    pub fn py(&self, token: &str, id: &str, code: &str) -> Value {
        self.exec(
            token,
            id,
            json!({"python": code, "stateful": true, "timeout": 30}),
        )
    }

    pub fn delete(&self, token: &str, id: &str) -> u16 {
        self.call(token, "DELETE", &format!("/v1/sandboxes/{id}"), b"")
            .status
    }
}

/// One request on a connection of its own, read raw: the status and the
/// response head (for headers the client does not keep).
pub fn raw_call(addr: &str, token: &str, method: &str, target: &str) -> (u16, String) {
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    let answer = String::from_utf8_lossy(&answer).to_string();
    let head = answer.split("\r\n\r\n").next().unwrap_or("").to_string();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, head)
}

/// A header's value in a response head.
pub fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// Calls the public API at `addr`.
pub fn api_call(
    addr: &str,
    token: &str,
    method: &str,
    target: &str,
    body: &[u8],
) -> std::io::Result<Answer> {
    let auth = format!("Bearer {token}");
    let headers: Vec<(&str, &str)> = if token.is_empty() {
        Vec::new()
    } else {
        vec![("Authorization", auth.as_str())]
    };
    let r = http::call(
        addr,
        method,
        target,
        &headers,
        body,
        Duration::from_secs(120),
        32 << 20,
    )?;
    Ok(Answer {
        status: r.status,
        body: r.body,
    })
}

impl Drop for Plane {
    fn drop(&mut self) {
        self.api = None;
        for node in &mut self.nodes {
            node.service = None;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The text of the events of one stream, joined.
pub fn stream_text(events: &[Value], stream: &str) -> String {
    events
        .iter()
        .filter(|e| e["type"] == stream)
        .map(|e| e["data"].as_str().unwrap())
        .collect()
}

/// The events as `(type, text)`, consecutive ones of a stream merged.
pub fn merged(events: &[Value]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for e in events {
        let kind = e["type"].as_str().unwrap().to_string();
        let text = match e.get("data") {
            Some(d) => d.as_str().unwrap().to_string(),
            None => e["bytes"].to_string(),
        };
        match out.last_mut() {
            Some((k, t)) if *k == kind && kind != "omitted" => t.push_str(&text),
            _ => out.push((kind, text)),
        }
    }
    out
}

/// Median, minimum and maximum of some durations, in ms.
pub fn stats(samples: &mut [f64]) -> (f64, f64, f64) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = samples.len();
    let median = if n % 2 == 1 {
        samples[n / 2]
    } else {
        (samples[n / 2 - 1] + samples[n / 2]) / 2.0
    };
    (median, samples[0], samples[n - 1])
}

pub fn ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}
