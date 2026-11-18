//! A small, strict HTTP/1.1 server and client: what `api` and `noded`
//! need and nothing more.
//!
//! Every byte from the network is untrusted. A request head is at most
//! [`Limits::max_head`] bytes and must arrive within
//! [`Limits::head_timeout`]; a body needs `Content-Length` (no
//! `Transfer-Encoding`, no chunked bodies), is at most what the handler
//! allows for that method and path ([`Handler::body_limit`]), must arrive
//! within [`Limits::body_timeout`], and all bodies being read at once share
//! a byte budget ([`Limits::body_budget`]). At most
//! [`Limits::max_connections`] connections are served at once, one thread
//! each; the next one gets `503` and is closed. A connection takes its slot
//! before anyone has authenticated, so one address gets at most
//! [`Limits::max_connections_per_peer`] of them (the next gets `429`): a
//! client without a token cannot take every slot by opening connections
//! and saying nothing. A response must be taken at
//! [`Limits::min_write_rate`] or faster after [`Limits::write_timeout`]. Lines end with CRLF only,
//! header names are tokens, values have no control bytes, folded headers
//! and duplicate `Content-Length` are refused. Connections are kept alive
//! (HTTP/1.1) up to [`Limits::idle_timeout`] between requests.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

/// A parsed request.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// The path without the query, as sent (no percent-decoding).
    pub path: String,
    /// Query parameters, percent-decoded.
    pub query: Vec<(String, String)>,
    /// Header names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: SocketAddr,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn query(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The token of an `Authorization: Bearer TOKEN` header.
    pub fn bearer(&self) -> Option<&str> {
        let value = self.header("authorization")?;
        let (scheme, token) = value.split_once(' ')?;
        scheme
            .eq_ignore_ascii_case("bearer")
            .then(|| token.trim())
            .filter(|t| !t.is_empty())
    }

    /// The path's segments after the leading `/`.
    pub fn segments(&self) -> Vec<&str> {
        self.path.trim_start_matches('/').split('/').collect()
    }
}

/// A response to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

/// The JSON body of every error: `{"error": {"code": ..., "message": ...}}`.
#[derive(Debug, Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

impl Response {
    pub fn json<T: Serialize + ?Sized>(status: u16, value: &T) -> Response {
        match serde_json::to_vec(value) {
            Ok(body) => Response {
                status,
                content_type: "application/json",
                headers: Vec::new(),
                body,
            },
            Err(err) => Response::error(500, "internal", &format!("encoding the answer: {err}")),
        }
    }

    pub fn error(status: u16, code: &str, message: &str) -> Response {
        let body = ErrorBody {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        };
        Response {
            status,
            content_type: "application/json",
            headers: Vec::new(),
            body: serde_json::to_vec(&body).unwrap_or_default(),
        }
    }

    pub fn bytes(status: u16, body: Vec<u8>) -> Response {
        Response {
            status,
            content_type: "application/octet-stream",
            headers: Vec::new(),
            body,
        }
    }

    pub fn empty(status: u16) -> Response {
        Response {
            status,
            content_type: "application/json",
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &'static str, value: String) -> Response {
        self.headers.push((name, value));
        self
    }
}

/// What a server runs for each request.
pub trait Handler: Send + Sync + 'static {
    /// The largest body accepted for a request with this method and path;
    /// a longer `Content-Length` gets `413` before any of it is read.
    fn body_limit(&self, method: &str, path: &str) -> usize;
    fn handle(&self, request: Request) -> Response;
}

/// Server limits; see the module documentation.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_connections: usize,
    /// Connections served at once from one IP address. The default is
    /// `max_connections` (no separate limit): right for a service whose
    /// only client is another service (`noded`, called by `api`); a
    /// service open to tenants sets it lower.
    pub max_connections_per_peer: usize,
    pub max_head: usize,
    pub max_headers: usize,
    pub head_timeout: Duration,
    pub body_timeout: Duration,
    pub idle_timeout: Duration,
    /// A response must be written within this plus its length at
    /// `min_write_rate`.
    pub write_timeout: Duration,
    /// Bytes per second a client must take a response at.
    pub min_write_rate: usize,
    pub max_requests_per_connection: usize,
    /// Bytes of request bodies held at once, across all connections.
    pub body_budget: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_connections: 256,
            max_connections_per_peer: 256,
            max_head: 16 * 1024,
            max_headers: 64,
            head_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            min_write_rate: 64 * 1024,
            max_requests_per_connection: 1000,
            body_budget: 256 << 20,
        }
    }
}

/// Serves `listener` until accepting fails. Each connection gets a thread.
pub fn serve(listener: TcpListener, handler: Arc<dyn Handler>, limits: Limits) -> io::Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    let budget = Arc::new(Budget {
        used: AtomicUsize::new(0),
        limit: limits.body_budget,
    });
    let limits = Arc::new(limits);
    let peers: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::default();
    let refuse = |stream: &TcpStream, response: Response| {
        let _ = write_response(stream, &response, false, Duration::from_secs(1));
        let _ = stream.shutdown(Shutdown::Both);
    };
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
                // Out of fds, say: back off instead of spinning.
                log::warn!("http: accept: {err}");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        if active.fetch_add(1, Ordering::SeqCst) >= limits.max_connections {
            active.fetch_sub(1, Ordering::SeqCst);
            refuse(
                &stream,
                Response::error(503, "busy", "too many connections"),
            );
            continue;
        }
        let guard = Active(Arc::clone(&active));
        let Some(peer_guard) = PeerSlot::take(&peers, peer.ip(), limits.max_connections_per_peer)
        else {
            drop(guard);
            refuse(
                &stream,
                Response::error(
                    429,
                    "too_many_connections",
                    "too many connections from this address",
                ),
            );
            continue;
        };
        let handler = Arc::clone(&handler);
        let limits = Arc::clone(&limits);
        let budget = Arc::clone(&budget);
        let spawned = std::thread::Builder::new()
            .name("http-conn".into())
            .spawn(move || {
                let _guards = (guard, peer_guard);
                connection(stream, peer, &*handler, &limits, &budget);
            });
        if let Err(err) = spawned {
            log::warn!("http: no thread for a connection: {err}");
        }
    }
}

/// Counts a connection while it lives.
struct Active(Arc<AtomicUsize>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Counts a connection against its peer address while it lives.
struct PeerSlot {
    peers: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl PeerSlot {
    fn take(peers: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr, max: usize) -> Option<Self> {
        let mut map = peers.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(ip).or_insert(0);
        if *count >= max {
            if *count == 0 {
                map.remove(&ip);
            }
            return None;
        }
        *count += 1;
        Some(PeerSlot {
            peers: Arc::clone(peers),
            ip,
        })
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut map = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

struct Budget {
    used: AtomicUsize,
    limit: usize,
}

/// Bytes reserved from a [`Budget`] while a body is held.
struct Reserved<'a>(&'a Budget, usize);

impl Budget {
    fn reserve(&self, bytes: usize) -> Option<Reserved<'_>> {
        let mut used = self.used.load(Ordering::SeqCst);
        loop {
            let next = used.checked_add(bytes).filter(|&n| n <= self.limit)?;
            match self
                .used
                .compare_exchange(used, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Some(Reserved(self, bytes)),
                Err(now) => used = now,
            }
        }
    }
}

impl Drop for Reserved<'_> {
    fn drop(&mut self) {
        self.0.used.fetch_sub(self.1, Ordering::SeqCst);
    }
}

/// Why reading a request stopped.
enum ReadError {
    /// The peer closed or went quiet between requests: no answer.
    Closed,
    /// Answer with this and close.
    Reply(Response),
}

/// Reads from `stream` into `buf` before `deadline`; 0 at end of stream.
fn read_some(stream: &TcpStream, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        stream.set_read_timeout(Some(left))?;
        match (&*stream).read(buf) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::ErrorKind::TimedOut.into())
            }
            other => return other,
        }
    }
}

fn connection(
    stream: TcpStream,
    peer: SocketAddr,
    handler: &dyn Handler,
    limits: &Limits,
    budget: &Budget,
) {
    let _ = stream.set_nodelay(true);
    let write_time = |response: &Response| {
        limits.write_timeout
            + Duration::from_secs((response.body.len() / limits.min_write_rate.max(1)) as u64)
    };
    // Bytes read past the end of the previous request.
    let mut pending: Vec<u8> = Vec::new();
    for served in 0..limits.max_requests_per_connection {
        let first = served == 0;
        let (request, keep_alive, _reserved) =
            match read_request(&stream, peer, &mut pending, handler, limits, budget, first) {
                Ok(read) => read,
                Err(ReadError::Closed) => return,
                Err(ReadError::Reply(response)) => {
                    let _ = write_response(&stream, &response, false, write_time(&response));
                    let _ = stream.shutdown(Shutdown::Both);
                    return;
                }
            };
        let keep_alive = keep_alive && served + 1 < limits.max_requests_per_connection;
        let response = handler.handle(request);
        if write_response(&stream, &response, keep_alive, write_time(&response)).is_err()
            || !keep_alive
        {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    }
}

fn bad(message: &str) -> ReadError {
    ReadError::Reply(Response::error(400, "bad_request", message))
}

/// Reads one request. Returns it, whether the connection may be kept
/// alive, and the body's reservation (held until the answer is sent).
fn read_request<'b>(
    stream: &TcpStream,
    peer: SocketAddr,
    pending: &mut Vec<u8>,
    handler: &dyn Handler,
    limits: &Limits,
    budget: &'b Budget,
    first: bool,
) -> Result<(Request, bool, Option<Reserved<'b>>), ReadError> {
    // Between requests the connection may idle; once a byte of the head
    // is there, the whole head must follow in time.
    let mut deadline = Instant::now()
        + if first {
            limits.head_timeout
        } else {
            limits.idle_timeout
        };
    let mut started = !pending.is_empty();
    if started {
        deadline = Instant::now() + limits.head_timeout;
    }
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = find(pending, b"\r\n\r\n") {
            break at;
        }
        if pending.len() >= limits.max_head {
            return Err(ReadError::Reply(Response::error(
                431,
                "head_too_large",
                "request head too large",
            )));
        }
        let room = (limits.max_head - pending.len()).min(chunk.len());
        match read_some(stream, &mut chunk[..room], deadline) {
            Ok(0) => {
                return Err(if started {
                    bad("incomplete request")
                } else {
                    ReadError::Closed
                })
            }
            Ok(n) => {
                if !started {
                    started = true;
                    deadline = Instant::now() + limits.head_timeout;
                }
                pending.extend_from_slice(&chunk[..n]);
            }
            Err(err) if err.kind() == io::ErrorKind::TimedOut && started => {
                return Err(ReadError::Reply(Response::error(
                    408,
                    "timeout",
                    "request head not complete in time",
                )))
            }
            Err(_) => return Err(ReadError::Closed),
        }
    };
    let head = Head::parse(&pending[..head_end], limits.max_headers).map_err(|m| bad(&m))?;
    pending.drain(..head_end + 4);
    let limit = handler.body_limit(&head.method, &head.path);
    if head.content_length > limit {
        return Err(ReadError::Reply(Response::error(
            413,
            "too_large",
            &format!("request body larger than {limit} bytes"),
        )));
    }
    let reserved = if head.content_length > 0 {
        Some(budget.reserve(head.content_length).ok_or_else(|| {
            ReadError::Reply(Response::error(
                503,
                "busy",
                "too many large requests at once",
            ))
        })?)
    } else {
        None
    };
    let mut body = Vec::new();
    body.try_reserve_exact(head.content_length)
        .map_err(|_| ReadError::Reply(Response::error(503, "busy", "no memory for the body")))?;
    let take = pending.len().min(head.content_length);
    body.extend_from_slice(&pending[..take]);
    pending.drain(..take);
    let deadline = Instant::now() + limits.body_timeout;
    while body.len() < head.content_length {
        let want = (head.content_length - body.len()).min(chunk.len());
        match read_some(stream, &mut chunk[..want], deadline) {
            Ok(0) => return Err(bad("incomplete body")),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                return Err(ReadError::Reply(Response::error(
                    408,
                    "timeout",
                    "request body not complete in time",
                )))
            }
            Err(_) => return Err(ReadError::Closed),
        }
    }
    let request = Request {
        method: head.method,
        path: head.path,
        query: head.query,
        headers: head.headers,
        body,
        peer,
    };
    Ok((request, head.keep_alive, reserved))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A request head.
#[derive(Debug, PartialEq, Eq)]
struct Head {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    content_length: usize,
    keep_alive: bool,
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Parses header lines (after the start line) into lower-cased names and
/// trimmed values.
fn parse_headers<'a>(
    lines: impl Iterator<Item = &'a [u8]>,
    max: usize,
) -> Result<Vec<(String, String)>, String> {
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= max {
            return Err("too many headers".into());
        }
        if line.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            return Err("folded header lines are not accepted".into());
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or("header line without a colon")?;
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err("malformed header name".into());
        }
        if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err("control bytes in a header value".into());
        }
        let value = std::str::from_utf8(value).map_err(|_| "header value is not UTF-8")?;
        headers.push((
            String::from_utf8_lossy(name).to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_string(),
        ));
    }
    Ok(headers)
}

/// Splits on CRLF; a bare CR or LF anywhere is an error.
fn crlf_lines(bytes: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut lines = Vec::new();
    let mut rest = bytes;
    loop {
        match find(rest, b"\r\n") {
            Some(at) => {
                lines.push(&rest[..at]);
                rest = &rest[at + 2..];
            }
            None => {
                lines.push(rest);
                break;
            }
        }
    }
    if lines
        .iter()
        .any(|l| l.contains(&b'\r') || l.contains(&b'\n'))
    {
        return Err("lines must end with CRLF".into());
    }
    Ok(lines)
}

fn content_length(headers: &[(String, String)]) -> Result<Option<usize>, String> {
    let mut lengths = headers.iter().filter(|(n, _)| n == "content-length");
    let Some((_, value)) = lengths.next() else {
        return Ok(None);
    };
    if lengths.next().is_some() {
        return Err("more than one Content-Length".into());
    }
    if value.is_empty() || value.len() > 15 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("malformed Content-Length".into());
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| "malformed Content-Length".into())
}

impl Head {
    fn parse(bytes: &[u8], max_headers: usize) -> Result<Head, String> {
        let lines = crlf_lines(bytes)?;
        let (start, rest) = lines.split_first().ok_or("empty request")?;
        let start = std::str::from_utf8(start).map_err(|_| "request line is not ASCII")?;
        let mut parts = start.split(' ');
        let (Some(method), Some(target), Some(version), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("malformed request line".into());
        };
        if method.is_empty() || method.len() > 16 || !method.bytes().all(|b| b.is_ascii_uppercase())
        {
            return Err("malformed method".into());
        }
        let keep_alive_default = match version {
            "HTTP/1.1" => true,
            "HTTP/1.0" => false,
            _ => return Err("only HTTP/1.0 and HTTP/1.1 are spoken".into()),
        };
        if !target.starts_with('/') || !target.bytes().all(|b| (0x21..0x7f).contains(&b)) {
            return Err("malformed request target".into());
        }
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path, parse_query(query)?),
            None => (target, Vec::new()),
        };
        let headers = parse_headers(rest.iter().copied(), max_headers)?;
        if headers.iter().any(|(n, _)| n == "transfer-encoding") {
            return Err("Transfer-Encoding is not accepted; send Content-Length".into());
        }
        let content_length = content_length(&headers)?.unwrap_or(0);
        let connection = headers
            .iter()
            .filter(|(n, _)| n == "connection")
            .flat_map(|(_, v)| v.split(','))
            .map(|t| t.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        let keep_alive = if connection.iter().any(|t| t == "close") {
            false
        } else if connection.iter().any(|t| t == "keep-alive") {
            true
        } else {
            keep_alive_default
        };
        Ok(Head {
            method: method.to_string(),
            path: path.to_string(),
            query,
            headers,
            content_length,
            keep_alive,
        })
    }
}

/// Decodes `%XX` and `+` (a space).
pub fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or("malformed percent escape")?;
                out.push(hex);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "a query parameter is not UTF-8".into())
}

/// Encodes everything but unreserved characters as `%XX`.
pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn parse_query(query: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if out.len() >= 32 {
            return Err("too many query parameters".into());
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((percent_decode(name)?, percent_decode(value)?));
    }
    Ok(out)
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        507 => "Insufficient Storage",
        _ => "Status",
    }
}

/// Writes `response`, all of it within `within`: a client that takes it
/// too slowly loses the connection instead of keeping its thread.
fn write_response(
    stream: &TcpStream,
    response: &Response,
    keep_alive: bool,
    within: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + within;
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {}\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len(),
        if keep_alive { "keep-alive" } else { "close" },
    );
    for (name, value) in &response.headers {
        // Values come from this program, but never let one end the head.
        let value: String = value.chars().filter(|c| !c.is_control()).collect();
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&response.body);
    let mut rest = &out[..];
    while !rest.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        stream.set_write_timeout(Some(left))?;
        match (&*stream).write(rest) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => rest = &rest[n..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::ErrorKind::TimedOut.into())
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// A response the client read.
#[derive(Debug)]
pub struct ClientResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl ClientResponse {
    /// The error body's message, or the body as text.
    pub fn error_message(&self) -> String {
        match serde_json::from_slice::<ErrorBody>(&self.body) {
            Ok(body) => body.error.message,
            Err(_) => String::from_utf8_lossy(&self.body[..self.body.len().min(512)]).into_owned(),
        }
    }

    /// The error body's code, if it is one.
    pub fn error_code(&self) -> Option<String> {
        serde_json::from_slice::<ErrorBody>(&self.body)
            .ok()
            .map(|body| body.error.code)
    }

    /// Turns it back into a response to pass on.
    pub fn into_response(self) -> Response {
        let content_type = if self.content_type == "application/octet-stream" {
            "application/octet-stream"
        } else {
            "application/json"
        };
        Response {
            status: self.status,
            content_type,
            headers: Vec::new(),
            body: self.body,
        }
    }
}

/// Longest wait for a connection to be made by [`call`].
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Marks an error of [`call`] that came before anything was sent: no
/// connection could be made (refused, unreachable, timed out). Its kind is
/// the connect error's.
#[derive(Debug)]
pub struct ConnectFailed(pub io::Error);

impl std::fmt::Display for ConnectFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "connecting: {}", self.0)
    }
}

impl std::error::Error for ConnectFailed {}

/// Whether `err`, from [`call`], means the request was certainly not sent.
pub fn not_sent(err: &io::Error) -> bool {
    err.get_ref().is_some_and(|e| e.is::<ConnectFailed>())
}

/// One request on a new connection to `addr` (`HOST:PORT`), with
/// `Connection: close`. The connection must be made within
/// [`CONNECT_TIMEOUT`] (an error that [`not_sent`] recognises otherwise),
/// and the whole exchange must finish within `timeout`; a response body
/// longer than `max_body` is an error.
pub fn call(
    addr: &str,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    timeout: Duration,
    max_body: usize,
) -> io::Result<ClientResponse> {
    let deadline = Instant::now() + timeout;
    let connect_by = Instant::now() + timeout.min(CONNECT_TIMEOUT);
    let failed = |err: io::Error| io::Error::new(err.kind(), ConnectFailed(err));
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{addr}: no address"));
    let mut stream = None;
    for sock in addr.to_socket_addrs().map_err(failed)? {
        let left = connect_by.saturating_duration_since(Instant::now());
        match TcpStream::connect_timeout(&sock, left.max(Duration::from_millis(1))) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(err) => last = err,
        }
    }
    let stream = stream.ok_or(last).map_err(failed)?;
    let _ = stream.set_nodelay(true);
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        if value.chars().any(|c| c.is_control()) || name.chars().any(|c| c.is_control()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control characters in a header",
            ));
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.set_write_timeout(Some(
        deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1)),
    ))?;
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    (&stream).write_all(&out)?;
    read_response(&stream, deadline, max_body)
}

fn read_response(
    stream: &TcpStream,
    deadline: Instant,
    max_body: usize,
) -> io::Result<ClientResponse> {
    let invalid = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let max_head = 16 * 1024;
    let head_end = loop {
        if let Some(at) = find(&buf, b"\r\n\r\n") {
            break at;
        }
        if buf.len() > max_head {
            return Err(invalid("response head too large"));
        }
        match read_some(stream, &mut chunk, deadline)? {
            0 => return Err(invalid("connection closed before the response head")),
            n => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let lines = crlf_lines(&buf[..head_end]).map_err(|m| invalid(&m))?;
    let (start, rest) = lines
        .split_first()
        .ok_or_else(|| invalid("empty response"))?;
    let start = std::str::from_utf8(start).map_err(|_| invalid("malformed status line"))?;
    let mut parts = start.splitn(3, ' ');
    let (Some(version), Some(code)) = (parts.next(), parts.next()) else {
        return Err(invalid("malformed status line"));
    };
    if !version.starts_with("HTTP/1.") || code.len() != 3 {
        return Err(invalid("malformed status line"));
    }
    let status: u16 = code.parse().map_err(|_| invalid("malformed status code"))?;
    let headers = parse_headers(rest.iter().copied(), 64).map_err(|m| invalid(&m))?;
    if headers.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err(invalid("chunked responses are not accepted"));
    }
    let length = content_length(&headers).map_err(|m| invalid(&m))?;
    let content_type = headers
        .iter()
        .find(|(n, _)| n == "content-type")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let mut body = buf.split_off(head_end + 4);
    match length {
        Some(length) => {
            if length > max_body {
                return Err(invalid("response body too large"));
            }
            while body.len() < length {
                let want = (length - body.len()).min(chunk.len());
                match read_some(stream, &mut chunk[..want], deadline)? {
                    0 => return Err(invalid("connection closed inside the body")),
                    n => body.extend_from_slice(&chunk[..n]),
                }
            }
            body.truncate(length);
        }
        None => loop {
            if body.len() > max_body {
                return Err(invalid("response body too large"));
            }
            match read_some(stream, &mut chunk, deadline)? {
                0 => break,
                n => body.extend_from_slice(&chunk[..n]),
            }
        },
    }
    Ok(ClientResponse {
        status,
        content_type,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_parse_strictly() {
        let head = Head::parse(
            b"POST /v1/x?path=%2Fetc%2Fa+b&n=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nAuthorization: Bearer abc",
            64,
        )
        .unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(head.path, "/v1/x");
        assert_eq!(
            head.query,
            vec![
                ("path".to_string(), "/etc/a b".to_string()),
                ("n".to_string(), "1".to_string())
            ]
        );
        assert_eq!(head.content_length, 5);
        assert!(head.keep_alive);
        for bad in [
            &b"GET / HTTP/1.1\nHost: h"[..],
            b"GET / HTTP/1.1\r\nHost: h\r\n folded",
            b"GET / HTTP/2\r\nHost: h",
            b"get / HTTP/1.1",
            b"GET x HTTP/1.1",
            b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1",
            b"GET / HTTP/1.1\r\nContent-Length: -1",
            b"GET / HTTP/1.1\r\nContent-Length: 99999999999999999999",
            b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked",
            b"GET / HTTP/1.1\r\nBad Name: x",
            b"GET / HTTP/1.1\r\nX: a\x01b",
            b"GET /?a=%zz HTTP/1.1",
            b"GET /?a=%ff HTTP/1.1",
            b"GET  / HTTP/1.1",
        ] {
            assert!(
                Head::parse(bad, 64).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        let many: Vec<u8> = [&b"GET / HTTP/1.1"[..], &b"\r\nX: y".repeat(65)].concat();
        assert!(Head::parse(&many, 64).is_err());
        assert!(
            !Head::parse(b"GET / HTTP/1.1\r\nConnection: close", 64)
                .unwrap()
                .keep_alive
        );
        assert!(!Head::parse(b"GET / HTTP/1.0", 64).unwrap().keep_alive);
    }

    #[test]
    fn percent_round_trip() {
        let text = "/tmp/a b/ü?&=%";
        assert_eq!(percent_decode(&percent_encode(text)).unwrap(), text);
    }

    struct Echo;

    impl Handler for Echo {
        fn body_limit(&self, _method: &str, path: &str) -> usize {
            if path == "/small" {
                4
            } else {
                1 << 20
            }
        }

        fn handle(&self, request: Request) -> Response {
            let mut body = request.method.into_bytes();
            body.push(b' ');
            body.extend_from_slice(request.path.as_bytes());
            body.push(b' ');
            body.extend_from_slice(&request.body);
            Response::bytes(200, body)
        }
    }

    fn server(limits: Limits) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || serve(listener, Arc::new(Echo), limits));
        addr
    }

    #[test]
    fn serves_requests_and_refuses_what_is_too_large() {
        let addr = server(Limits::default());
        let t = Duration::from_secs(5);
        let ok = call(&addr, "PUT", "/x?y=1", &[], b"hello", t, 1 << 20).unwrap();
        assert_eq!(ok.status, 200);
        assert_eq!(ok.body, b"PUT /x hello");
        let big = call(&addr, "PUT", "/small", &[], b"hello", t, 1 << 20).unwrap();
        assert_eq!(big.status, 413);
        // The client refuses a body larger than it accepts.
        assert!(call(&addr, "PUT", "/x", &[], &[b'a'; 100], t, 10).is_err());
    }

    #[test]
    fn keeps_connections_alive_and_pipelines() {
        let addr = server(Limits::default());
        let mut stream = TcpStream::connect(&addr).unwrap();
        stream
            .write_all(
                b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nPOST /b HTTP/1.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
            )
            .unwrap();
        let mut all = String::new();
        stream.read_to_string(&mut all).unwrap();
        assert!(all.contains("GET /a "), "{all}");
        assert!(all.ends_with("POST /b hi"), "{all}");
        assert_eq!(all.matches("HTTP/1.1 200").count(), 2);
    }

    #[test]
    fn slow_or_huge_heads_are_cut_off() {
        let addr = server(Limits {
            head_timeout: Duration::from_millis(200),
            ..Limits::default()
        });
        let mut slow = TcpStream::connect(&addr).unwrap();
        slow.write_all(b"GET / HTTP/1.1\r\n").unwrap();
        let mut all = String::new();
        slow.read_to_string(&mut all).unwrap();
        assert!(all.starts_with("HTTP/1.1 408"), "{all}");
        let mut huge = TcpStream::connect(&addr).unwrap();
        let _ = huge.write_all(&[b'a'; 20 * 1024]);
        let mut all = String::new();
        let _ = huge.read_to_string(&mut all);
        assert!(all.starts_with("HTTP/1.1 4"), "{all}");
    }

    #[test]
    fn connections_past_the_limit_get_503() {
        let addr = server(Limits {
            max_connections: 1,
            ..Limits::default()
        });
        let _held = TcpStream::connect(&addr).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let refused = call(&addr, "GET", "/", &[], b"", Duration::from_secs(5), 1 << 20).unwrap();
        assert_eq!(refused.status, 503);
    }

    #[test]
    fn one_address_cannot_take_every_connection() {
        let addr = server(Limits {
            max_connections: 8,
            max_connections_per_peer: 2,
            ..Limits::default()
        });
        // Two silent connections from this address: the third is refused
        // although the server has room, and room comes back when one ends.
        let held = [
            TcpStream::connect(&addr).unwrap(),
            TcpStream::connect(&addr).unwrap(),
        ];
        std::thread::sleep(Duration::from_millis(100));
        let t = Duration::from_secs(5);
        let refused = call(&addr, "GET", "/", &[], b"", t, 1 << 20).unwrap();
        assert_eq!(refused.status, 429);
        drop(held);
        let start = Instant::now();
        loop {
            let again = call(&addr, "GET", "/", &[], b"", t, 1 << 20).unwrap();
            if again.status == 200 {
                break;
            }
            assert!(start.elapsed() < t, "no room after the others left");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_client_that_does_not_read_its_answer_is_dropped() {
        struct Big;
        impl Handler for Big {
            fn body_limit(&self, _: &str, _: &str) -> usize {
                0
            }
            fn handle(&self, _: Request) -> Response {
                Response::bytes(200, vec![b'x'; 64 << 20])
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let limits = Limits {
            max_connections: 1,
            write_timeout: Duration::from_millis(300),
            min_write_rate: usize::MAX,
            ..Limits::default()
        };
        std::thread::spawn(move || serve(listener, Arc::new(Big), limits));
        let mut stuck = TcpStream::connect(&addr).unwrap();
        stuck.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        // It never reads: the server gives up on it and its slot is free.
        let start = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(100));
            if let Ok(mut next) = TcpStream::connect(&addr) {
                next.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
                let mut head = [0u8; 12];
                if next.read_exact(&mut head).is_ok() && &head == b"HTTP/1.1 200" {
                    break;
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the stuck client kept its slot"
            );
        }
        drop(stuck);
    }

    #[test]
    fn the_body_budget_is_shared() {
        let budget = Budget {
            used: AtomicUsize::new(0),
            limit: 10,
        };
        let a = budget.reserve(6).unwrap();
        assert!(budget.reserve(6).is_none());
        drop(a);
        assert!(budget.reserve(10).is_some());
        assert!(budget.reserve(usize::MAX).is_none());
    }
}
