//! HTTP ingress: a client outside reaches a server listening in a
//! sandbox, at `PORT-SANDBOX.DOMAIN` (see the README, "Ingress").
//!
//! The listener (`ingress.listen`) is the API process's, apart from the
//! tenants' and the operators'. For each connection it reads one request
//! head (bounded in size and time, [`wire`]), finds the sandbox and port
//! its `Host` names, checks that the port is exposed and, unless it is
//! public, the sandbox's ingress token; then it asks the sandbox's node to
//! carry the connection (`POST /v1/sandboxes/{id}/ingress/connect` with
//! the node's token: `noded` hands that TCP connection itself to the
//! sandbox's kernel process, whose first byte back says whether a
//! listener took it), sends the rewritten head and relays the rest as
//! bytes: the request body by its framing (nothing after it), the
//! response with its head rewritten, both ways as raw bytes after a `101`.
//! One exchange per connection (`Connection: close` both ways).
//!
//! Bounds: connections at once in all, per client address, per tenant
//! and per sandbox (a slot is taken before anything else is done, the
//! last two only once the request is known to be allowed); two threads
//! per connection, so at most twice `max_connections` threads; every read
//! and write waits at most a second at a time, against the connection's
//! idle and total deadlines; no lock is held across I/O.

pub mod wire;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hellovm_control::ids::{token_eq, SandboxId};
use hellovm_control::types::{NodeIngress, MAX_EXPOSED_PORTS};

use crate::config::IngressConfig;
use crate::service::Api;
use wire::{Framing, RequestHead};

/// How long one read or write waits before the deadlines are looked at.
const SLICE: Duration = Duration::from_secs(1);
/// Connecting to a node.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The node's answer to the hand-over, and the kernel's verdict.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Asking a node for a sandbox's ingress state.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest answer of a node to the hand-over (a short error at most).
const MAX_HANDSHAKE: usize = 4096;
/// Bytes read from the client after its request (pipelined requests,
/// which are not served) before the connection is closed.
const MAX_AFTER: u64 = 64 * 1024;
/// Most 1xx answers before the final one.
const MAX_INTERIM: usize = 16;
/// Hand-overs in progress to one node at once: each holds one of the
/// node's HTTP connections (256) for its moment, and the node's probes
/// must always find one free, however many clients connect at once.
pub const MAX_HANDOVERS_PER_NODE: usize = 64;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What ingress keeps (in the [`Api`]).
pub struct IngressState {
    pub config: IngressConfig,
    /// Tokens of hellovm itself (tenants', nodes', the admin's): never
    /// forwarded to a guest in an `Authorization` header.
    secrets: Vec<String>,
    /// The ingress state of sandboxes, as their nodes last said: filled
    /// when asked for and on every change made through the API.
    cache: Mutex<HashMap<SandboxId, NodeIngress>>,
    /// The connections being relayed, and those that ended since the last
    /// [`IngressState::take_counts`].
    conns: Mutex<Vec<Arc<ConnMeter>>>,
    /// Sandboxes used through ingress since their node was last told, by
    /// node.
    touched: Mutex<HashMap<SandboxId, String>>,
    slots: Mutex<Slots>,
    /// Hand-overs in progress, by node.
    handovers: Mutex<HashMap<String, usize>>,
}

/// A hand-over in progress to a node, given back when dropped.
struct Handover<'a>(&'a IngressState, String);

impl Drop for Handover<'_> {
    fn drop(&mut self) {
        let mut h = lock(&self.0.handovers);
        if let Some(n) = h.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                h.remove(&self.1);
            }
        }
    }
}

#[derive(Default)]
struct Slots {
    total: usize,
    clients: HashMap<IpAddr, usize>,
    tenants: HashMap<String, usize>,
    sandboxes: HashMap<SandboxId, usize>,
}

/// A slot taken, given back when dropped.
struct Slot<'a> {
    state: &'a IngressState,
    client: Option<IpAddr>,
    tenant: Option<String>,
    sandbox: Option<SandboxId>,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut slots = lock(&self.state.slots);
        fn down<K: std::hash::Hash + Eq>(map: &mut HashMap<K, usize>, key: &K) {
            if let Some(n) = map.get_mut(key) {
                *n -= 1;
                if *n == 0 {
                    map.remove(key);
                }
            }
        }
        if let Some(ip) = &self.client {
            down(&mut slots.clients, ip);
        }
        if let Some(t) = &self.tenant {
            down(&mut slots.tenants, t);
        }
        if let Some(s) = &self.sandbox {
            down(&mut slots.sandboxes, s);
        }
        // A listener slot (not a sandbox's) also counts in the total.
        if self.tenant.is_none() && self.sandbox.is_none() {
            slots.total = slots.total.saturating_sub(1);
        }
    }
}

/// The bytes one connection relayed.
pub struct ConnMeter {
    sandbox: SandboxId,
    tenant: String,
    node: String,
    template: String,
    /// Delivered to the guest.
    received: AtomicU64,
    /// Delivered from the guest to the client.
    sent: AtomicU64,
    /// What [`IngressState::take_counts`] took so far.
    taken: Mutex<(u64, u64)>,
    done: AtomicBool,
    /// When the sandbox was last marked as used (ms since `opened`).
    marked: AtomicU64,
    opened: Instant,
}

/// Ingress bytes of one sandbox since the last count.
pub struct Count {
    pub sandbox: SandboxId,
    pub tenant: String,
    pub node: String,
    pub template: String,
    pub received: u64,
    pub sent: u64,
}

impl IngressState {
    pub fn new(config: IngressConfig, secrets: Vec<String>) -> IngressState {
        IngressState {
            config,
            secrets,
            cache: Mutex::new(HashMap::new()),
            conns: Mutex::new(Vec::new()),
            touched: Mutex::new(HashMap::new()),
            slots: Mutex::new(Slots::default()),
            handovers: Mutex::new(HashMap::new()),
        }
    }

    /// The URL of `port` of `sandbox`.
    pub fn url(&self, port: u16, sandbox: &SandboxId) -> String {
        let c = &self.config;
        match c.url_port {
            Some(p) => format!("{}://{port}-{sandbox}.{}:{p}/", c.scheme, c.domain),
            None => format!("{}://{port}-{sandbox}.{}/", c.scheme, c.domain),
        }
    }

    /// What the node said of a sandbox's ingress (it changed or was read
    /// through the API).
    pub fn remember(&self, sandbox: SandboxId, state: NodeIngress) {
        lock(&self.cache).insert(sandbox, state);
    }

    /// Forgets what is known of sandboxes `keep` says are gone.
    pub fn retain(&self, keep: impl Fn(&SandboxId) -> bool) {
        lock(&self.cache).retain(|id, _| keep(id));
        lock(&self.touched).retain(|id, _| keep(id));
    }

    /// The bytes relayed since the last call, per connection (those that
    /// ended are dropped once counted).
    pub fn take_counts(&self) -> Vec<Count> {
        let mut conns = lock(&self.conns);
        let mut out = Vec::new();
        conns.retain(|c| {
            let done = c.done.load(Ordering::Acquire);
            let received = c.received.load(Ordering::Acquire);
            let sent = c.sent.load(Ordering::Acquire);
            let mut taken = lock(&c.taken);
            if received > taken.0 || sent > taken.1 {
                out.push(Count {
                    sandbox: c.sandbox,
                    tenant: c.tenant.clone(),
                    node: c.node.clone(),
                    template: c.template.clone(),
                    received: received - taken.0,
                    sent: sent - taken.1,
                });
                *taken = (received, sent);
            }
            !done
        });
        out
    }

    /// The sandboxes of `node` used through ingress since the last call.
    pub fn take_touched(&self, node: &str) -> Vec<SandboxId> {
        let mut touched = lock(&self.touched);
        let ids: Vec<SandboxId> = touched
            .iter()
            .filter(|(_, n)| n.as_str() == node)
            .map(|(id, _)| *id)
            .collect();
        for id in &ids {
            touched.remove(id);
        }
        ids
    }

    /// Connections relayed now.
    pub fn open(&self) -> usize {
        lock(&self.slots).total
    }

    fn is_secret(&self, value: &[u8], ingress_token: &str) -> bool {
        let Ok(value) = std::str::from_utf8(value) else {
            return false;
        };
        let mut found = token_eq(value, ingress_token);
        for s in &self.secrets {
            found |= token_eq(value, s);
        }
        found
    }

    /// Takes a slot of the listener: in all and for `ip` (not behind a
    /// proxy, where every connection comes from it). The connection's
    /// thread gives it back ([`IngressState::client_slot`]).
    fn reserve_client(&self, ip: IpAddr) -> bool {
        let c = &self.config;
        let mut slots = lock(&self.slots);
        if slots.total >= c.max_connections {
            return false;
        }
        if !c.behind_proxy {
            let n = slots.clients.entry(ip).or_insert(0);
            if *n >= c.max_connections_per_client {
                return false;
            }
            *n += 1;
        }
        slots.total += 1;
        true
    }

    /// What gives back a slot [`IngressState::reserve_client`] took.
    fn client_slot(&self, ip: IpAddr) -> Slot<'_> {
        Slot {
            state: self,
            client: (!self.config.behind_proxy).then_some(ip),
            tenant: None,
            sandbox: None,
        }
    }

    fn take_handover(&self, node: &str) -> Option<Handover<'_>> {
        let mut h = lock(&self.handovers);
        let n = h.entry(node.to_string()).or_insert(0);
        if *n >= MAX_HANDOVERS_PER_NODE {
            return None;
        }
        *n += 1;
        Some(Handover(self, node.to_string()))
    }

    /// A slot for `tenant` and `sandbox`.
    fn take_sandbox(
        &self,
        tenant: &str,
        max_tenant: usize,
        sandbox: SandboxId,
    ) -> Option<Slot<'_>> {
        let mut slots = lock(&self.slots);
        let t = slots.tenants.get(tenant).copied().unwrap_or(0);
        let s = slots.sandboxes.get(&sandbox).copied().unwrap_or(0);
        if t >= max_tenant || s >= self.config.max_connections_per_sandbox {
            return None;
        }
        *slots.tenants.entry(tenant.to_string()).or_insert(0) += 1;
        *slots.sandboxes.entry(sandbox).or_insert(0) += 1;
        Some(Slot {
            state: self,
            client: None,
            tenant: Some(tenant.to_string()),
            sandbox: Some(sandbox),
        })
    }
}

/// Serves the ingress listener until accepting fails for good.
pub fn serve(listener: TcpListener, api: Arc<Api>) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(conn) => conn,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                ) =>
            {
                continue
            }
            Err(err) => {
                log::warn!("ingress: accept: {err}");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let Some(state) = api.ingress.as_ref() else {
            return;
        };
        let refuse = |stream: &TcpStream| {
            let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
            let _ = (&*stream).write_all(&wire::answer(
                503,
                "Service Unavailable",
                "too many connections",
                &[("Retry-After", "1".into())],
            ));
            let _ = stream.shutdown(Shutdown::Both);
        };
        // Taken here, given back by the connection's thread.
        if !state.reserve_client(peer.ip()) {
            refuse(&stream);
            continue;
        }
        let api2 = Arc::clone(&api);
        let spawned = std::thread::Builder::new()
            .name("ingress-conn".into())
            .spawn(move || {
                let state = api2.ingress.as_ref().expect("ingress is configured");
                let _slot = state.client_slot(peer.ip());
                connection(&api2, state, stream, peer);
            });
        if let Err(err) = spawned {
            log::warn!("ingress: no thread for a connection: {err}");
            drop(state.client_slot(peer.ip()));
        }
    }
}

/// Writes all of `data` before `deadline`.
fn write_until(stream: &TcpStream, data: &[u8], deadline: Instant) -> io::Result<()> {
    let mut rest = data;
    while !rest.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        stream.set_write_timeout(Some(left.min(SLICE)))?;
        match (&*stream).write(rest) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => rest = &rest[n..],
            Err(err) if is_timeout(&err) || err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// An answer of the ingress itself, then the end of the connection.
fn reply(stream: &TcpStream, status: u16, reason: &str, text: &str, extra: &[(&str, String)]) {
    let _ = write_until(
        stream,
        &wire::answer(status, reason, text, extra),
        Instant::now() + Duration::from_secs(5),
    );
    let _ = stream.shutdown(Shutdown::Both);
}

/// The same answer for every request that may not learn more: no such
/// name, sandbox, exposed port, or a missing or wrong token.
fn not_found(stream: &TcpStream) {
    reply(stream, 404, "Not Found", "not found", &[]);
}

/// Reads a request head (and what came after it) within `timeout`.
/// `None` when the connection is done (answered or gone).
fn read_head(stream: &TcpStream, timeout: Duration) -> Option<(Vec<u8>, Vec<u8>)> {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = wire::head_end(&buf) {
            let rest = buf.split_off(end);
            return Some((buf, rest));
        }
        if buf.len() >= wire::MAX_HEAD {
            reply(
                stream,
                431,
                "Request Header Fields Too Large",
                "request head too large",
                &[],
            );
            return None;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            if !buf.is_empty() {
                reply(
                    stream,
                    408,
                    "Request Timeout",
                    "request head not complete in time",
                    &[],
                );
            }
            return None;
        }
        let _ = stream.set_read_timeout(Some(left.min(SLICE)));
        let room = (wire::MAX_HEAD + 4 - buf.len()).min(chunk.len());
        match (&*stream).read(&mut chunk[..room]) {
            Ok(0) => {
                if !buf.is_empty() {
                    reply(stream, 400, "Bad Request", "incomplete request head", &[]);
                }
                return None;
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if is_timeout(&err) || err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
}

/// One ingress connection, from its first byte to its end.
fn connection(api: &Api, state: &IngressState, client: TcpStream, peer: SocketAddr) {
    let _ = client.set_nodelay(true);
    let config = &state.config;
    let Some((head_bytes, early)) =
        read_head(&client, Duration::from_secs_f64(config.head_timeout))
    else {
        return;
    };
    let head = match wire::parse_request(&head_bytes) {
        Ok(head) => head,
        Err(why) => {
            log::debug!("ingress: a bad request from {}: {why}", peer.ip());
            return reply(&client, 400, "Bad Request", "bad request", &[]);
        }
    };
    let Some((port, sandbox)) = wire::route(&head.host, &config.domain) else {
        return not_found(&client);
    };
    let Some(record) = api.store.get(&sandbox) else {
        return not_found(&client);
    };
    let Some(i) = api.nodes.index(&record.node) else {
        return not_found(&client);
    };
    let Some(tenant) = api.tenants.iter().find(|t| t.name == record.tenant) else {
        return not_found(&client);
    };
    let reachable = api.nodes.reachable(i);
    let known = lock(&state.cache).get(&sandbox).cloned();
    let ingress = match known {
        Some(known) => known,
        None if reachable => match fetch(api, i, &sandbox, &record.tenant) {
            Some(fetched) => {
                state.remember(sandbox, fetched.clone());
                fetched
            }
            None => return not_found(&client),
        },
        // Nothing is known of it, and its node cannot be asked: whether
        // the port is exposed or the token right cannot be told.
        None => return not_found(&client),
    };
    let Some(public) = ingress
        .ports
        .iter()
        .find(|p| p.port == port)
        .map(|p| p.public)
    else {
        return not_found(&client);
    };
    // A browser's first visit: the token in the query, answered with a
    // redirect that sets the cookie (the parameter goes no further).
    let target = match wire::query_token(&head.target) {
        Err(_) => return reply(&client, 400, "Bad Request", "bad request", &[]),
        Ok(Some((token, rest))) => {
            if !matches!(head.method.as_str(), "GET" | "HEAD") {
                return reply(&client, 400, "Bad Request", "bad request", &[]);
            }
            if !token_eq(&token, &ingress.token) {
                return not_found(&client);
            }
            let secure = config.scheme == "https";
            let name = if secure {
                wire::SECURE_COOKIE
            } else {
                wire::COOKIE
            };
            let cookie = format!(
                "{name}={}; Path=/; HttpOnly; SameSite=Lax{}",
                ingress.token,
                if secure { "; Secure" } else { "" }
            );
            return reply(
                &client,
                303,
                "See Other",
                "",
                &[("Location", rest), ("Set-Cookie", cookie)],
            );
        }
        Ok(None) => head.target.clone(),
    };
    if !public {
        let mut ok = false;
        for value in wire::presented(&head.headers) {
            ok |= std::str::from_utf8(&value).is_ok_and(|v| token_eq(v, &ingress.token));
        }
        if !ok {
            return not_found(&client);
        }
    }
    // Allowed: from here on the client may learn that the sandbox is
    // there.
    if !reachable {
        return reply(
            &client,
            502,
            "Bad Gateway",
            "the sandbox does not answer; try again later",
            &[],
        );
    }
    let max_tenant = tenant
        .max_ingress_connections
        .unwrap_or(config.max_connections_per_tenant);
    let Some(_slot) = state.take_sandbox(&record.tenant, max_tenant, sandbox) else {
        return reply(
            &client,
            503,
            "Service Unavailable",
            "too many connections to this sandbox",
            &[("Retry-After", "1".into())],
        );
    };
    let node = &api.nodes.configs()[i];
    let Some(handover) = state.take_handover(&node.name) else {
        return reply(
            &client,
            503,
            "Service Unavailable",
            "too many connections being made at once",
            &[("Retry-After", "1".into())],
        );
    };
    let handed = hand_over(node, &sandbox, &record.tenant, port);
    drop(handover);
    let (backend, verdict_rest) = match handed {
        Ok(Some(conn)) => conn,
        Ok(None) => {
            return reply(
                &client,
                502,
                "Bad Gateway",
                &format!("nothing in the sandbox listens on port {port}"),
                &[],
            )
        }
        Err(HandOver::Gone) => {
            lock(&state.cache).remove(&sandbox);
            return not_found(&client);
        }
        Err(HandOver::Failed(why)) => {
            // Not counted against the node: a request here may fail for
            // reasons of the sandbox's own, and the probes find a node that
            // stopped answering.
            log::debug!("ingress: sandbox {sandbox}: the hand-over failed: {why}");
            return reply(
                &client,
                502,
                "Bad Gateway",
                "the sandbox does not answer; try again later",
                &[],
            );
        }
    };
    let meter = Arc::new(ConnMeter {
        sandbox,
        tenant: record.tenant.clone(),
        node: record.node.clone(),
        template: record.template.clone(),
        received: AtomicU64::new(0),
        sent: AtomicU64::new(0),
        taken: Mutex::new((0, 0)),
        done: AtomicBool::new(false),
        marked: AtomicU64::new(u64::MAX),
        opened: Instant::now(),
    });
    lock(&state.conns).push(Arc::clone(&meter));
    let secret = |v: &[u8]| state.is_secret(v, &ingress.token);
    let forward = wire::Forward {
        peer: peer.ip(),
        behind_proxy: config.behind_proxy,
        scheme: &config.scheme,
        is_secret: &secret,
    };
    let out_head = wire::forward_request(&head, &target, &forward);
    let relay = Relay {
        state,
        meter: &meter,
        client,
        backend,
        start: Instant::now(),
        last: AtomicU64::new(0),
        idle: Duration::from_secs_f64(config.idle_timeout),
        total: Duration::from_secs_f64(config.max_duration),
        stop: AtomicBool::new(false),
        upgraded: Mutex::new(None),
        decided: Condvar::new(),
    };
    relay.run(&head, out_head, early, verdict_rest);
    meter.done.store(true, Ordering::Release);
}

/// Asks node `i` for a sandbox's ingress state.
fn fetch(api: &Api, i: usize, sandbox: &SandboxId, tenant: &str) -> Option<NodeIngress> {
    let node = &api.nodes.configs()[i];
    let auth = format!("Bearer {}", node.token);
    let answer = hellovm_control::http::call(
        &node.addr,
        "GET",
        &format!("/v1/sandboxes/{sandbox}/ingress"),
        &[("Authorization", &auth), ("X-Hellovm-Tenant", tenant)],
        b"",
        FETCH_TIMEOUT,
        64 * 1024,
    )
    .ok()?;
    if answer.status != 200 {
        return None;
    }
    let state: NodeIngress = serde_json::from_slice(&answer.body).ok()?;
    valid_state(&state).then_some(state)
}

/// What a node says of a sandbox's ingress is believed only within bounds.
pub fn valid_state(state: &NodeIngress) -> bool {
    (22..=128).contains(&state.token.len())
        && state.token.bytes().all(|b| b.is_ascii_graphic())
        && state.ports.len() <= MAX_EXPOSED_PORTS
        && state.ports.iter().all(|p| p.port > 0)
}

enum HandOver {
    /// The node no longer has the sandbox, or the port is not exposed.
    Gone,
    Failed(String),
}

/// Asks the sandbox's node to hand a new connection to guest `port`, and
/// reads the kernel's verdict: the connection (and bytes of the guest
/// that came with the verdict) when a listener took it, `None` when
/// refused.
fn hand_over(
    node: &crate::config::Node,
    sandbox: &SandboxId,
    tenant: &str,
    port: u16,
) -> Result<Option<(TcpStream, Vec<u8>)>, HandOver> {
    let failed =
        |what: &str, err: &dyn std::fmt::Display| HandOver::Failed(format!("{what}: {err}"));
    let addrs: Vec<SocketAddr> = node
        .addr
        .to_socket_addrs()
        .map_err(|e| failed("resolving the node", &e))?
        .collect();
    let mut stream = None;
    let mut last = String::from("no address");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(err) => last = err.to_string(),
        }
    }
    let stream = stream.ok_or_else(|| HandOver::Failed(format!("connecting: {last}")))?;
    let _ = stream.set_nodelay(true);
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let request = format!(
        "POST /v1/sandboxes/{sandbox}/ingress/connect?port={port} HTTP/1.1\r\nHost: {}\r\n\
         Authorization: Bearer {}\r\nX-Hellovm-Tenant: {tenant}\r\nContent-Length: 0\r\n\r\n",
        node.addr, node.token
    );
    write_until(&stream, request.as_bytes(), deadline).map_err(|e| failed("asking", &e))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(end) = wire::head_end(&buf) {
            break end;
        }
        if buf.len() > MAX_HANDSHAKE {
            return Err(HandOver::Failed("an answer too large".into()));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(HandOver::Failed("no answer in time".into()));
        }
        let _ = stream.set_read_timeout(Some(left.min(SLICE)));
        match (&stream).read(&mut chunk) {
            Ok(0) => return Err(HandOver::Failed("closed before answering".into())),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if is_timeout(&err) || err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(failed("reading", &err)),
        }
    };
    let status = buf
        .get(9..12)
        .and_then(|c| std::str::from_utf8(c).ok())
        .and_then(|c| c.parse::<u16>().ok());
    match status {
        Some(200) => {}
        Some(404) | Some(410) => return Err(HandOver::Gone),
        Some(other) => return Err(HandOver::Failed(format!("status {other}"))),
        None => return Err(HandOver::Failed("a malformed answer".into())),
    }
    let mut rest = buf.split_off(end);
    // The verdict, then (when accepted) the guest's bytes.
    while rest.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(HandOver::Failed("no verdict in time".into()));
        }
        let _ = stream.set_read_timeout(Some(left.min(SLICE)));
        match (&stream).read(&mut chunk) {
            Ok(0) => return Ok(None),
            Ok(n) => rest.extend_from_slice(&chunk[..n]),
            Err(err) if is_timeout(&err) || err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Ok(None),
        }
    }
    if rest[0] == ACCEPTED {
        Ok(Some((stream, rest.split_off(1))))
    } else {
        Ok(None)
    }
}

/// The kernel process's verdict when a listener took the connection
/// (`hellovm_host::INBOUND_ACCEPTED`; the API does not link that crate).
const ACCEPTED: u8 = b'A';

/// The two directions of one connection.
struct Relay<'a> {
    state: &'a IngressState,
    meter: &'a ConnMeter,
    client: TcpStream,
    backend: TcpStream,
    start: Instant,
    /// Milliseconds after `start` of the last byte moved either way.
    last: AtomicU64,
    idle: Duration,
    total: Duration,
    stop: AtomicBool,
    /// Whether the guest switched protocols (`101`), once its final answer
    /// is known.
    upgraded: Mutex<Option<bool>>,
    decided: Condvar,
}

/// Why a direction stopped.
#[derive(Debug)]
enum Stop {
    /// The end of what it carries (EOF, or the end of the framing).
    Done,
    /// The other side failed, or a read or write did.
    Broken,
    /// A deadline passed (or the connection is being ended).
    Expired,
}

impl Relay<'_> {
    fn moved(&self) {
        let ms = self.start.elapsed().as_millis() as u64;
        self.last.store(ms, Ordering::Release);
        // The sandbox is in use: its node is told at the next probe.
        let marked = self.meter.marked.load(Ordering::Acquire);
        let now = self.meter.opened.elapsed().as_millis() as u64;
        if marked == u64::MAX || now.saturating_sub(marked) >= 1000 {
            self.meter.marked.store(now, Ordering::Release);
            lock(&self.state.touched).insert(self.meter.sandbox, self.meter.node.clone());
        }
    }

    /// Whether the connection must end: stopped, or past a deadline.
    fn expired(&self) -> bool {
        if self.stop.load(Ordering::Acquire) {
            return true;
        }
        let now = self.start.elapsed();
        let last = Duration::from_millis(self.last.load(Ordering::Acquire));
        now >= self.total || now.saturating_sub(last) >= self.idle
    }

    /// Ends both directions at once.
    fn abort(&self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.backend.shutdown(Shutdown::Both);
        self.decide(false);
    }

    fn decide(&self, upgraded: bool) {
        let mut d = lock(&self.upgraded);
        if d.is_none() {
            *d = Some(upgraded);
        }
        self.decided.notify_all();
    }

    fn read(&self, from: &TcpStream, buf: &mut [u8]) -> Result<usize, Stop> {
        let _ = from.set_read_timeout(Some(SLICE));
        loop {
            if self.expired() {
                return Err(Stop::Expired);
            }
            match (&*from).read(buf) {
                Ok(n) => return Ok(n),
                Err(err) if is_timeout(&err) || err.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Stop::Broken),
            }
        }
    }

    /// Writes all of `data`, counting it to `count`.
    fn write(&self, to: &TcpStream, data: &[u8], count: &AtomicU64) -> Result<(), Stop> {
        let _ = to.set_write_timeout(Some(SLICE));
        let mut rest = data;
        while !rest.is_empty() {
            if self.expired() {
                return Err(Stop::Expired);
            }
            match (&*to).write(rest) {
                Ok(0) => return Err(Stop::Broken),
                Ok(n) => {
                    rest = &rest[n..];
                    count.fetch_add(n as u64, Ordering::AcqRel);
                    self.moved();
                }
                Err(err) if is_timeout(&err) || err.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Stop::Broken),
            }
        }
        Ok(())
    }

    fn to_guest(&self, data: &[u8]) -> Result<(), Stop> {
        self.write(&self.backend, data, &self.meter.received)
    }

    fn to_client(&self, data: &[u8]) -> Result<(), Stop> {
        self.write(&self.client, data, &self.meter.sent)
    }

    fn run(&self, head: &RequestHead, out_head: Vec<u8>, early: Vec<u8>, from_guest: Vec<u8>) {
        self.moved();
        let head_only = head.method == "HEAD";
        let wants_upgrade = head.upgrade.is_some();
        std::thread::scope(|scope| {
            let responses = std::thread::Builder::new()
                .name("ingress-back".into())
                .spawn_scoped(scope, || {
                    let end = self.responses(from_guest, head_only, wants_upgrade);
                    if !matches!(end, Ok(true)) {
                        // Answered (or failed): the connection is over.
                        self.abort();
                    }
                });
            if responses.is_err() {
                self.abort();
                return;
            }
            match self.requests(head, &out_head, early, wants_upgrade) {
                Ok(()) | Err(Stop::Done) => {}
                Err(Stop::Broken) => self.abort(),
                // The other direction sees the same deadline and answers
                // the client (504) if the guest has not.
                Err(Stop::Expired) => {}
            }
        });
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.backend.shutdown(Shutdown::Both);
    }

    /// Client to guest: the head, the body by its framing, then (after a
    /// `101`) raw bytes, or bytes read and dropped until the client is
    /// done.
    fn requests(
        &self,
        head: &RequestHead,
        out_head: &[u8],
        early: Vec<u8>,
        wants_upgrade: bool,
    ) -> Result<(), Stop> {
        self.to_guest(out_head)?;
        let mut pending = early;
        let mut buf = vec![0u8; 16 * 1024];
        match head.framing {
            Framing::None => {}
            Framing::Length(mut left) => loop {
                let take = (pending.len() as u64).min(left) as usize;
                if take > 0 {
                    self.to_guest(&pending[..take])?;
                    left -= take as u64;
                }
                pending.drain(..take);
                if left == 0 {
                    break;
                }
                let n = self.read(&self.client, &mut buf)?;
                if n == 0 {
                    // The client stopped inside its body.
                    let _ = self.backend.shutdown(Shutdown::Write);
                    return Err(Stop::Done);
                }
                pending.extend_from_slice(&buf[..n]);
            },
            Framing::Chunked => {
                let mut chunked = wire::Chunked::default();
                loop {
                    if !pending.is_empty() {
                        match chunked.feed(&pending) {
                            Ok(Some(end)) => {
                                self.to_guest(&pending[..end])?;
                                pending.drain(..end);
                                break;
                            }
                            Ok(None) => {
                                self.to_guest(&pending)?;
                                pending.clear();
                            }
                            Err(why) => {
                                // Nothing past the last good byte goes on.
                                log::debug!("ingress: a bad chunked body: {why}");
                                return Err(Stop::Broken);
                            }
                        }
                    }
                    let n = self.read(&self.client, &mut buf)?;
                    if n == 0 {
                        let _ = self.backend.shutdown(Shutdown::Write);
                        return Err(Stop::Done);
                    }
                    pending.extend_from_slice(&buf[..n]);
                }
            }
        }
        if wants_upgrade {
            let upgraded = {
                let mut d = lock(&self.upgraded);
                loop {
                    if let Some(up) = *d {
                        break up;
                    }
                    if self.expired() {
                        return Err(Stop::Broken);
                    }
                    d = self
                        .decided
                        .wait_timeout(d, SLICE)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            };
            if upgraded {
                // Bytes the client sent past its head belong to the new
                // protocol.
                if !pending.is_empty() {
                    self.to_guest(&pending)?;
                }
                loop {
                    let n = self.read(&self.client, &mut buf)?;
                    if n == 0 {
                        let _ = self.backend.shutdown(Shutdown::Write);
                        return Ok(());
                    }
                    self.to_guest(&buf[..n])?;
                }
            }
        }
        // Not served (one exchange per connection): read and dropped, so
        // that a client that resets is noticed, within a bound.
        let mut after = pending.len() as u64;
        loop {
            match self.read(&self.client, &mut buf) {
                Ok(0) => return Err(Stop::Done),
                Ok(n) => {
                    after += n as u64;
                    if after > MAX_AFTER {
                        return Err(Stop::Broken);
                    }
                }
                Err(Stop::Expired) => return Err(Stop::Done),
                Err(stop) => return Err(stop),
            }
        }
    }

    /// Guest to client: response heads (interim ones, then the final one)
    /// rewritten, then the body (by its framing, or to the guest's end),
    /// or raw bytes after a `101`. `Ok(true)` when the connection was
    /// upgraded and the guest's side ended (the client's side may still
    /// send).
    fn responses(
        &self,
        mut pending: Vec<u8>,
        head_only: bool,
        wants_upgrade: bool,
    ) -> Result<bool, Stop> {
        let mut buf = vec![0u8; 16 * 1024];
        let mut answered = false;
        let mut interim = 0;
        let response = loop {
            let end = loop {
                if let Some(end) = wire::head_end(&pending) {
                    break end;
                }
                if pending.len() > wire::MAX_HEAD {
                    break 0;
                }
                let n = match self.read(&self.backend, &mut buf) {
                    Ok(n) => n,
                    Err(stop) => {
                        if !answered && matches!(stop, Stop::Expired) {
                            let _ = self.client.set_write_timeout(Some(SLICE));
                            let _ = (&self.client).write_all(&wire::answer(
                                504,
                                "Gateway Timeout",
                                "the sandbox did not answer in time",
                                &[],
                            ));
                        }
                        return Err(stop);
                    }
                };
                if n == 0 {
                    break 0;
                }
                pending.extend_from_slice(&buf[..n]);
            };
            let parsed = if end == 0 {
                Err("no complete answer")
            } else {
                wire::parse_response(&pending[..end])
            };
            let response = match parsed {
                Ok(r) if r.status != 101 || wants_upgrade => r,
                Ok(_) | Err(_) => {
                    if !answered {
                        let _ = self.client.set_write_timeout(Some(SLICE));
                        let _ = (&self.client).write_all(&wire::answer(
                            502,
                            "Bad Gateway",
                            "the sandbox's answer is not valid HTTP",
                            &[],
                        ));
                    }
                    return Err(Stop::Broken);
                }
            };
            pending.drain(..end);
            self.to_client(&wire::forward_response(&response))?;
            answered = true;
            if response.status >= 200 || response.status == 101 {
                break response;
            }
            interim += 1;
            if interim > MAX_INTERIM {
                return Err(Stop::Broken);
            }
        };
        if response.status == 101 {
            self.decide(true);
            if !pending.is_empty() {
                self.to_client(&pending)?;
            }
            loop {
                let n = self.read(&self.backend, &mut buf)?;
                if n == 0 {
                    let _ = self.client.shutdown(Shutdown::Write);
                    return Ok(true);
                }
                self.to_client(&buf[..n])?;
            }
        }
        self.decide(false);
        // The body: by its framing where it has one, else to the end.
        let mut framing = match body_framing(&response, head_only) {
            Some(Framing::None) => return Err(Stop::Done),
            Some(Framing::Length(n)) => Some(Framing::Length(n)),
            Some(Framing::Chunked) => Some(Framing::Chunked),
            None => None,
        };
        let mut chunked = wire::Chunked::default();
        loop {
            if !pending.is_empty() {
                let take = match &mut framing {
                    Some(Framing::Length(left)) => {
                        let take = (pending.len() as u64).min(*left) as usize;
                        *left -= take as u64;
                        Some((take, *left == 0))
                    }
                    Some(Framing::Chunked) => match chunked.feed(&pending) {
                        Ok(Some(end)) => Some((end, true)),
                        Ok(None) => Some((pending.len(), false)),
                        // Not what it says it is: what passed is relayed,
                        // then the connection ends.
                        Err(_) => None,
                    },
                    _ => Some((pending.len(), false)),
                };
                let Some((take, end)) = take else {
                    return Err(Stop::Broken);
                };
                self.to_client(&pending[..take])?;
                pending.clear();
                if end {
                    return Err(Stop::Done);
                }
            }
            let n = self.read(&self.backend, &mut buf)?;
            if n == 0 {
                return Err(Stop::Done);
            }
            pending.extend_from_slice(&buf[..n]);
        }
    }
}

/// How a response's body ends: no body (`HEAD`, `204`, `304`), its
/// chunked or `Content-Length` framing, or `None`: when the guest closes.
fn body_framing(r: &wire::ResponseHead, head_only: bool) -> Option<Framing> {
    if head_only || r.status == 204 || r.status == 304 {
        return Some(Framing::None);
    }
    let te: Vec<&[u8]> = r
        .headers
        .iter()
        .filter(|h| h.lower == "transfer-encoding")
        .map(|h| h.value.as_slice())
        .collect();
    if !te.is_empty() {
        let last = te
            .last()
            .and_then(|v| v.rsplit(|&b| b == b',').next())
            .map(|v| String::from_utf8_lossy(v).trim().to_ascii_lowercase());
        return (last.as_deref() == Some("chunked")).then_some(Framing::Chunked);
    }
    let mut lengths = r.headers.iter().filter(|h| h.lower == "content-length");
    match (lengths.next(), lengths.next()) {
        (Some(h), None) => std::str::from_utf8(&h.value)
            .ok()
            .filter(|v| !v.is_empty() && v.len() <= 18 && v.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|v| v.parse().ok())
            .map(Framing::Length),
        _ => None,
    }
}
