//! The bytes of ingress: host names, request and response heads (parsed
//! strictly and rewritten), the ingress token where a client presents it,
//! and chunked request bodies. Pure functions, no I/O.
//!
//! Every byte here comes from an ingress client or a guest: lengths are
//! bounded before anything is kept, and anything that is not plainly
//! HTTP/1.x is refused rather than guessed at.

use hellovm_control::ids::SandboxId;
use hellovm_control::types::check_port;

/// Largest request or response head.
pub const MAX_HEAD: usize = 32 * 1024;
/// Most header lines in one head.
pub const MAX_HEADERS: usize = 100;
/// Longest request target.
pub const MAX_TARGET: usize = 8192;
/// The header a client may present the ingress token in.
pub const TOKEN_HEADER: &str = "x-hellovm-ingress-token";
/// The query parameter a browser presents the token in once: answered
/// with a redirect that sets the cookie, never forwarded.
pub const TOKEN_PARAM: &str = "hellovm_ingress_token";
/// The cookie that carries the token (over `http`).
pub const COOKIE: &str = "hellovm_ingress_token";
/// The cookie over `https`: the `__Host-` prefix makes browsers refuse
/// it from a response that sets a `Domain` (another sandbox's guest
/// cannot set it for this host), and require `Secure` and `Path=/`.
pub const SECURE_COOKIE: &str = "__Host-hellovm_ingress_token";
/// Most values of the token cookie looked at in one request.
const MAX_COOKIES: usize = 16;

/// How a request's body ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    None,
    /// `Content-Length` bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`, up to its last chunk and trailers.
    Chunked,
}

/// One header line: its name as sent, in lower case, and its value
/// (without the whitespace around it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub lower: String,
    pub value: Vec<u8>,
}

/// A request head that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    /// Origin form (`/path?query`).
    pub target: String,
    pub http10: bool,
    pub headers: Vec<Header>,
    /// The one `Host`, in lower case.
    pub host: String,
    pub framing: Framing,
    /// The `Upgrade` value when `Connection` asks for an upgrade.
    pub upgrade: Option<Vec<u8>>,
}

/// A response head from a guest that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub http10: bool,
    pub reason: Vec<u8>,
    pub headers: Vec<Header>,
}

/// Where the head ends: the index just past its empty line.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    head_end_from(buf, &mut 0)
}

/// [`head_end`] for a buffer that grows: `scanned` (0 at first) is how
/// far earlier calls looked, so that each byte is looked at once however
/// the bytes arrive (a head sent a byte at a time would otherwise cost
/// the square of its length).
pub fn head_end_from(buf: &[u8], scanned: &mut usize) -> Option<usize> {
    // A mark past the buffer is not this buffer's (it shrank): from the
    // start.
    let from = if *scanned > buf.len() {
        0
    } else {
        scanned.saturating_sub(3)
    };
    let found = buf[from..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| from + i + 4);
    *scanned = buf.len();
    found
}

/// Where a redirect to `target` (a request target) leads on this host
/// only: a target that begins with more than one `/` (or a `\\`, which
/// browsers take for one) names another host to a browser, so the run is
/// made one `/`.
pub fn same_host(target: &str) -> String {
    let rest = target.trim_start_matches(['/', '\\']);
    format!("/{rest}")
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The lines of a head (without its final empty line): CRLF only, a bare
/// CR or LF anywhere is refused.
fn lines(head: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    let body = head
        .strip_suffix(b"\r\n\r\n")
        .ok_or("the head does not end with an empty line")?;
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let at = rest.windows(2).position(|w| w == b"\r\n");
        let (line, next) = match at {
            Some(at) => (&rest[..at], Some(&rest[at + 2..])),
            None => (rest, None),
        };
        if line.contains(&b'\r') || line.contains(&b'\n') {
            return Err("a line ends without CRLF");
        }
        out.push(line);
        match next {
            Some(next) => rest = next,
            None => return Ok(out),
        }
    }
}

/// Header lines: a token name directly followed by `:`, a value with no
/// control byte but tab, no folded lines, at most [`MAX_HEADERS`].
fn headers(lines: &[&[u8]]) -> Result<Vec<Header>, &'static str> {
    if lines.len() > MAX_HEADERS {
        return Err("too many header lines");
    }
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        if line.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            return Err("a folded header line");
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or("a header line without a colon")?;
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err("a malformed header name");
        }
        if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err("a control byte in a header value");
        }
        let start = value
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|&b| b != b' ' && b != b'\t')
            .map_or(start, |i| i + 1);
        let name = String::from_utf8_lossy(name).into_owned();
        out.push(Header {
            lower: name.to_ascii_lowercase(),
            name,
            value: value[start..end.max(start)].to_vec(),
        });
    }
    Ok(out)
}

fn values<'a>(headers: &'a [Header], lower: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
    headers
        .iter()
        .filter(move |h| h.lower == lower)
        .map(|h| h.value.as_slice())
}

/// The comma-separated tokens of every `Connection` header, lower case.
fn connection_tokens(headers: &[Header]) -> Vec<String> {
    values(headers, "connection")
        .flat_map(|v| v.split(|&b| b == b','))
        .map(|t| String::from_utf8_lossy(t).trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Parses and checks a request head (`head` ends with its empty line).
pub fn parse_request(head: &[u8]) -> Result<RequestHead, &'static str> {
    if head.len() > MAX_HEAD {
        return Err("the head is too large");
    }
    let lines = lines(head)?;
    let (start, rest) = lines.split_first().ok_or("an empty head")?;
    let mut parts = start.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("a malformed request line");
    };
    if method.is_empty() || method.len() > 32 || !method.iter().all(|&b| is_tchar(b)) {
        return Err("a malformed method");
    }
    let http10 = match version {
        b"HTTP/1.1" => false,
        b"HTTP/1.0" => true,
        _ => return Err("only HTTP/1.0 and HTTP/1.1 are spoken"),
    };
    if target.first() != Some(&b'/')
        || target.len() > MAX_TARGET
        || !target.iter().all(|&b| (0x21..0x7f).contains(&b))
    {
        return Err("a malformed request target (origin form only)");
    }
    let headers = headers(rest)?;
    let host = {
        let mut hosts = values(&headers, "host");
        match (hosts.next(), hosts.next()) {
            (Some(h), None) => std::str::from_utf8(h)
                .map_err(|_| "a malformed Host")?
                .to_ascii_lowercase(),
            (None, _) => return Err("no Host"),
            (Some(_), Some(_)) => return Err("more than one Host"),
        }
    };
    let lengths: Vec<&[u8]> = values(&headers, "content-length").collect();
    let encodings: Vec<&[u8]> = values(&headers, "transfer-encoding").collect();
    let framing = match (lengths.as_slice(), encodings.as_slice()) {
        ([], []) => Framing::None,
        ([len], []) => {
            if len.is_empty() || len.len() > 18 || !len.iter().all(u8::is_ascii_digit) {
                return Err("a malformed Content-Length");
            }
            let n = std::str::from_utf8(len)
                .ok()
                .and_then(|t| t.parse::<u64>().ok())
                .ok_or("a malformed Content-Length")?;
            Framing::Length(n)
        }
        ([], [te]) => {
            if http10 {
                return Err("Transfer-Encoding in an HTTP/1.0 request");
            }
            if !te.eq_ignore_ascii_case(b"chunked") {
                return Err("a Transfer-Encoding other than chunked");
            }
            Framing::Chunked
        }
        ([], _) => return Err("more than one Transfer-Encoding"),
        (_, []) => return Err("more than one Content-Length"),
        _ => return Err("both Content-Length and Transfer-Encoding"),
    };
    let connection = connection_tokens(&headers);
    for t in &connection {
        if matches!(
            t.as_str(),
            "host" | "content-length" | "transfer-encoding" | "x-forwarded-for"
        ) {
            return Err("Connection names a header that cannot be dropped");
        }
    }
    let upgrade = if connection.iter().any(|t| t == "upgrade") {
        let ups: Vec<&[u8]> = values(&headers, "upgrade").collect();
        match (ups.first(), ups.get(1)) {
            (Some(u), None) if !u.is_empty() => Some(u.to_vec()),
            (None, _) => None,
            _ => return Err("a malformed Upgrade"),
        }
    } else {
        None
    };
    Ok(RequestHead {
        method: String::from_utf8_lossy(method).into_owned(),
        target: String::from_utf8_lossy(target).into_owned(),
        http10,
        headers,
        host,
        framing,
        upgrade,
    })
}

/// The port and sandbox a `Host` names: `PORT-SANDBOX.DOMAIN`, with an
/// optional `:PORT` of the listener (`host` in lower case). `None` for
/// anything else.
pub fn route(host: &str, domain: &str) -> Option<(u16, SandboxId)> {
    let name = match host.rsplit_once(':') {
        Some((name, port)) => {
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            name
        }
        None => host,
    };
    let label = name.strip_suffix(domain)?.strip_suffix('.')?;
    let (port, sandbox) = label.split_once('-')?;
    Some((check_port(port)?, SandboxId::parse(sandbox)?))
}

/// The value of [`TOKEN_PARAM`] in `target`'s query and the target
/// without it; `Ok(None)` when it is not there. More than one is refused.
pub fn query_token(target: &str) -> Result<Option<(String, String)>, &'static str> {
    let Some((path, query)) = target.split_once('?') else {
        return Ok(None);
    };
    let mut token = None;
    let mut kept = Vec::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name == TOKEN_PARAM {
            if token.is_some() {
                return Err("the token parameter is given twice");
            }
            token = Some(value.to_string());
        } else {
            kept.push(pair);
        }
    }
    let Some(token) = token else {
        return Ok(None);
    };
    let rest = if kept.iter().all(|p| p.is_empty()) {
        path.to_string()
    } else {
        format!("{path}?{}", kept.join("&"))
    };
    Ok(Some((token, rest)))
}

/// The values the client presents the token in: the [`TOKEN_HEADER`]
/// header (at most one is taken) and the token cookies.
pub fn presented(headers: &[Header]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = values(headers, TOKEN_HEADER)
        .take(1)
        .map(<[u8]>::to_vec)
        .collect();
    for cookie in values(headers, "cookie") {
        for pair in cookie.split(|&b| b == b';') {
            if out.len() > MAX_COOKIES {
                return out;
            }
            if let Some((name, value)) = cookie_pair(pair) {
                if name == COOKIE.as_bytes() || name == SECURE_COOKIE.as_bytes() {
                    out.push(value.to_vec());
                }
            }
        }
    }
    out
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |i| i + 1);
    &bytes[start..end.max(start)]
}

fn cookie_pair(pair: &[u8]) -> Option<(&[u8], &[u8])> {
    let pair = trim(pair);
    let eq = pair.iter().position(|&b| b == b'=')?;
    Some((trim(&pair[..eq]), trim(&pair[eq + 1..])))
}

fn is_token_cookie(pair: &[u8]) -> bool {
    cookie_pair(pair).is_some_and(|(name, _)| {
        name.eq_ignore_ascii_case(COOKIE.as_bytes())
            || name.eq_ignore_ascii_case(SECURE_COOKIE.as_bytes())
    })
}

/// What the request is forwarded with.
pub struct Forward<'a> {
    /// The client's address (the reverse proxy's, behind one).
    pub peer: std::net::IpAddr,
    /// `X-Forwarded-For` and `X-Forwarded-Proto` from the client are kept
    /// (the peer is the trusted reverse proxy).
    pub behind_proxy: bool,
    /// The scheme clients use.
    pub scheme: &'a str,
    /// Whether a credential (an `Authorization` value, or its part after
    /// the scheme) is one of hellovm's own tokens.
    pub is_secret: &'a dyn Fn(&[u8]) -> bool,
}

/// Request headers never forwarded: hop-by-hop ones, hellovm's own,
/// and the forwarding headers this proxy sets itself.
const REQUEST_DROPPED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-real-ip",
];

fn push_header(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

/// The head to send to the guest for `head`: hop-by-hop headers and
/// those `Connection` names dropped, hellovm's credentials removed (the
/// token header and cookie, any `X-Hellovm-*`, an `Authorization` with a
/// hellovm token), `X-Forwarded-For`, `-Proto` and `-Host` set, and
/// `Connection: close` (or `Upgrade` for an upgrade).
pub fn forward_request(head: &RequestHead, target: &str, f: &Forward<'_>) -> Vec<u8> {
    let named = connection_tokens(&head.headers);
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(head.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(if head.http10 {
        b" HTTP/1.0\r\n"
    } else {
        b" HTTP/1.1\r\n"
    });
    let mut forwarded_for: Vec<u8> = Vec::new();
    let mut proto: Option<Vec<u8>> = None;
    for h in &head.headers {
        let lower = h.lower.as_str();
        if f.behind_proxy && lower == "x-forwarded-for" {
            if !forwarded_for.is_empty() {
                forwarded_for.extend_from_slice(b", ");
            }
            forwarded_for.extend_from_slice(&h.value);
            continue;
        }
        if f.behind_proxy
            && lower == "x-forwarded-proto"
            && (h.value == b"http" || h.value == b"https")
        {
            proto = Some(h.value.clone());
            continue;
        }
        if REQUEST_DROPPED.contains(&lower)
            || lower == TOKEN_HEADER
            || lower.starts_with("x-hellovm-")
            || named.iter().any(|n| n == lower)
        {
            continue;
        }
        if lower == "authorization" {
            let after = h
                .value
                .iter()
                .position(|&b| b == b' ')
                .map_or(&h.value[..], |i| trim(&h.value[i..]));
            if (f.is_secret)(&h.value) || (f.is_secret)(after) {
                continue;
            }
        }
        if lower == "cookie" {
            let kept: Vec<&[u8]> = h
                .value
                .split(|&b| b == b';')
                .filter(|p| !is_token_cookie(p) && !trim(p).is_empty())
                .map(trim)
                .collect();
            if !kept.is_empty() {
                push_header(&mut out, &h.name, &kept.join(&b"; "[..]));
            }
            continue;
        }
        push_header(&mut out, &h.name, &h.value);
    }
    match &head.upgrade {
        Some(upgrade) => {
            push_header(&mut out, "Connection", b"Upgrade");
            push_header(&mut out, "Upgrade", upgrade);
        }
        None => push_header(&mut out, "Connection", b"close"),
    }
    let peer = f.peer.to_string();
    if !forwarded_for.is_empty() {
        forwarded_for.extend_from_slice(b", ");
    }
    forwarded_for.extend_from_slice(peer.as_bytes());
    push_header(&mut out, "X-Forwarded-For", &forwarded_for);
    push_header(
        &mut out,
        "X-Forwarded-Proto",
        proto.as_deref().unwrap_or(f.scheme.as_bytes()),
    );
    push_header(&mut out, "X-Forwarded-Host", head.host.as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// Parses and checks a response head from a guest.
pub fn parse_response(head: &[u8]) -> Result<ResponseHead, &'static str> {
    if head.len() > MAX_HEAD {
        return Err("the response head is too large");
    }
    let lines = lines(head)?;
    let (start, rest) = lines.split_first().ok_or("an empty response head")?;
    let http10 = if start.starts_with(b"HTTP/1.1 ") {
        false
    } else if start.starts_with(b"HTTP/1.0 ") {
        true
    } else {
        return Err("a malformed status line");
    };
    let code = start.get(9..12).ok_or("a malformed status line")?;
    if !code.iter().all(u8::is_ascii_digit) || code[0] == b'0' {
        return Err("a malformed status code");
    }
    let reason = match start.get(12..) {
        None | Some([]) => Vec::new(),
        Some([b' ', reason @ ..]) => reason.to_vec(),
        Some(_) => return Err("a malformed status line"),
    };
    if reason
        .iter()
        .any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
    {
        return Err("a control byte in the reason");
    }
    let status = std::str::from_utf8(code)
        .ok()
        .and_then(|c| c.parse().ok())
        .ok_or("a malformed status code")?;
    Ok(ResponseHead {
        status,
        http10,
        reason,
        headers: headers(rest)?,
    })
}

/// Response headers never forwarded to the client.
const RESPONSE_DROPPED: &[&str] = &["connection", "keep-alive", "proxy-connection", "upgrade"];

/// The head to send to the client for a guest's `head`: hop-by-hop
/// headers and those `Connection` names dropped (but not the body's
/// framing), any cookie of the ingress token's name the guest sets
/// dropped, and `Connection: close` on a final answer (a `101`'s
/// `Connection: Upgrade` and `Upgrade` kept).
pub fn forward_response(head: &ResponseHead) -> Vec<u8> {
    let named = connection_tokens(&head.headers);
    let switching = head.status == 101;
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(if head.http10 {
        b"HTTP/1.0 "
    } else {
        b"HTTP/1.1 "
    });
    out.extend_from_slice(head.status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(&head.reason);
    out.extend_from_slice(b"\r\n");
    for h in &head.headers {
        let lower = h.lower.as_str();
        let framing = lower == "content-length" || lower == "transfer-encoding";
        if (switching && lower == "upgrade")
            || !(RESPONSE_DROPPED.contains(&lower)
                || (!framing && named.iter().any(|n| n == lower))
                || (lower == "set-cookie" && is_token_cookie(set_cookie_pair(&h.value))))
        {
            push_header(&mut out, &h.name, &h.value);
        }
    }
    if switching {
        push_header(&mut out, "Connection", b"Upgrade");
    } else if head.status >= 200 {
        push_header(&mut out, "Connection", b"close");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The `name=value` of a `Set-Cookie` value (before its attributes).
fn set_cookie_pair(value: &[u8]) -> &[u8] {
    value.split(|&b| b == b';').next().unwrap_or(value)
}

/// An answer of the ingress itself (never the guest's): a short text body
/// and `Connection: close`.
pub fn answer(status: u16, reason: &str, text: &str, extra: &[(&str, String)]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        text.len() + 1
    );
    for (name, value) in extra {
        let value: String = value.chars().filter(|c| !c.is_control()).collect();
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(text);
    out.push('\n');
    out.into_bytes()
}

/// Finds where a chunked body ends, as its bytes pass (they are relayed
/// unchanged): chunk sizes of at most 16 hex digits, extensions and
/// trailer lines bounded, CRLF only.
#[derive(Debug, Default)]
pub struct Chunked {
    state: ChunkState,
    /// Bytes of chunk data left, or of the current line so far.
    count: u64,
    /// Trailer bytes so far.
    trailers: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    /// In a chunk-size line: hex digits so far in `count`.
    #[default]
    Size,
    /// In a chunk extension (after `;`), `count` bytes of it.
    Extension,
    /// Read the CR of a size line.
    SizeLf,
    /// In chunk data.
    Data,
    DataCr,
    DataLf,
    /// At the start of a trailer line (or the final empty line).
    TrailerStart,
    /// In a trailer line.
    Trailer,
    TrailerLf,
    /// Read the CR of the final empty line.
    EndLf,
    Done,
}

/// Longest chunk extension.
const MAX_EXTENSION: u64 = 1024;
/// Most trailer bytes.
const MAX_TRAILERS: usize = 8192;

impl Chunked {
    /// Takes `data`, the next bytes of the body: `Ok(Some(n))` when the
    /// body ends after the first `n` of them, `Ok(None)` when all of them
    /// belong to it and more are needed.
    pub fn feed(&mut self, data: &[u8]) -> Result<Option<usize>, &'static str> {
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            match self.state {
                ChunkState::Size => match b {
                    b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                        if self.trailers >= 16 {
                            return Err("a chunk size of more than 16 digits");
                        }
                        let digit = (b as char).to_digit(16).unwrap_or(0) as u64;
                        self.count = (self.count << 4) | digit;
                        self.trailers += 1;
                    }
                    b';' if self.trailers > 0 => {
                        self.state = ChunkState::Extension;
                        self.trailers = 0;
                    }
                    b'\r' if self.trailers > 0 => self.state = ChunkState::SizeLf,
                    _ => return Err("a malformed chunk size"),
                },
                ChunkState::Extension => match b {
                    b'\r' => self.state = ChunkState::SizeLf,
                    b'\n' => return Err("a bare LF in a chunk size line"),
                    _ if b < 0x20 && b != b'\t' => return Err("a control byte in an extension"),
                    _ => {
                        self.trailers += 1;
                        if self.trailers as u64 > MAX_EXTENSION {
                            return Err("a chunk extension too long");
                        }
                    }
                },
                ChunkState::SizeLf => {
                    if b != b'\n' {
                        return Err("a chunk size line without CRLF");
                    }
                    self.trailers = 0;
                    self.state = if self.count == 0 {
                        ChunkState::TrailerStart
                    } else {
                        ChunkState::Data
                    };
                }
                ChunkState::Data => {
                    let take = ((data.len() - i) as u64).min(self.count);
                    self.count -= take;
                    i += take as usize;
                    if self.count == 0 {
                        self.state = ChunkState::DataCr;
                    }
                    continue;
                }
                ChunkState::DataCr => {
                    if b != b'\r' {
                        return Err("chunk data longer than its size");
                    }
                    self.state = ChunkState::DataLf;
                }
                ChunkState::DataLf => {
                    if b != b'\n' {
                        return Err("chunk data without CRLF");
                    }
                    self.state = ChunkState::Size;
                    self.count = 0;
                    self.trailers = 0;
                }
                ChunkState::TrailerStart => match b {
                    b'\r' => self.state = ChunkState::EndLf,
                    _ if is_tchar(b) => {
                        self.state = ChunkState::Trailer;
                        self.trailers += 1;
                    }
                    _ => return Err("a malformed trailer"),
                },
                ChunkState::Trailer => match b {
                    b'\r' => self.state = ChunkState::TrailerLf,
                    b'\n' => return Err("a bare LF in a trailer"),
                    _ if b < 0x20 && b != b'\t' => return Err("a control byte in a trailer"),
                    _ => {
                        self.trailers += 1;
                        if self.trailers > MAX_TRAILERS {
                            return Err("trailers too long");
                        }
                    }
                },
                ChunkState::TrailerLf => {
                    if b != b'\n' {
                        return Err("a trailer without CRLF");
                    }
                    self.state = ChunkState::TrailerStart;
                }
                ChunkState::EndLf => {
                    if b != b'\n' {
                        return Err("a chunked body without its final CRLF");
                    }
                    self.state = ChunkState::Done;
                    return Ok(Some(i + 1));
                }
                ChunkState::Done => return Ok(Some(i)),
            }
            i += 1;
        }
        if self.state == ChunkState::Done {
            return Ok(Some(0));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "sb-0123456789abcdef0123456789abcdef";

    fn req(text: &str) -> Result<RequestHead, &'static str> {
        parse_request(text.as_bytes())
    }

    #[test]
    fn host_names_route_strictly() {
        let domain = "sb.example.com";
        let id = SandboxId::parse(ID).unwrap();
        assert_eq!(
            route(&format!("8080-{ID}.sb.example.com"), domain),
            Some((8080, id))
        );
        assert_eq!(
            route(&format!("1-{ID}.sb.example.com:443"), domain),
            Some((1, id))
        );
        for bad in [
            format!("0-{ID}.sb.example.com"),
            format!("65536-{ID}.sb.example.com"),
            format!("080-{ID}.sb.example.com"),
            format!("8080-{ID}.sb.example.com."),
            format!("8080-{ID}.sb.example.com:"),
            format!("8080-{ID}.sb.example.com:x"),
            format!("8080-{ID}.sb.example.com:123456"),
            format!("8080-{ID}.other.example.com"),
            format!("8080-{ID}xsb.example.com"),
            format!("8080-{ID}.x.sb.example.com"),
            format!("8080-{}.sb.example.com", &ID[..ID.len() - 1]),
            format!("8080-{}.sb.example.com", ID.to_uppercase()),
            format!("8080.{ID}.sb.example.com"),
            format!("{ID}.sb.example.com"),
            format!("8080-8080-{ID}.sb.example.com"),
            "sb.example.com".to_string(),
            "".to_string(),
            format!("8080-{ID}.sb.example.com@evil"),
            "[::1]:80".to_string(),
        ] {
            assert_eq!(route(&bad, domain), None, "{bad}");
        }
    }

    #[test]
    fn request_heads_are_strict() {
        let ok = req("GET /a?b HTTP/1.1\r\nHost: X.example\r\nAccept: */*\r\n\r\n").unwrap();
        assert_eq!((ok.method.as_str(), ok.target.as_str()), ("GET", "/a?b"));
        assert_eq!((ok.host.as_str(), ok.framing), ("x.example", Framing::None));
        let post = req("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 12\r\n\r\n").unwrap();
        assert_eq!(post.framing, Framing::Length(12));
        let chunked = req("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: Chunked\r\n\r\n");
        assert_eq!(chunked.unwrap().framing, Framing::Chunked);
        let up = req("GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n");
        assert_eq!(up.unwrap().upgrade.as_deref(), Some(&b"websocket"[..]));
        let not_up = req("GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n");
        assert_eq!(not_up.unwrap().upgrade, None);
        for bad in [
            // Smuggling: conflicting or repeated framing.
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 5\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: \r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding : chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\n Transfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.0\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\r\nConnection: content-length\r\nContent-Length: 1\r\n\r\n",
            // Hosts.
            "GET / HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            // Lines, names, values.
            "GET / HTTP/1.1\nHost: h\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\nX: y\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\r\nX\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\r\nX: a\0b\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\r\nX: a\rb\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\r\nX:\x7f\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\r\n: v\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\r\nA\u{00e9}: v\r\n\r\n",
            // Request lines.
            "GET  / HTTP/1.1\r\nHost: h\r\n\r\n",
            "GET / HTTP/1.1 \r\nHost: h\r\n\r\n",
            "GET http://h/ HTTP/1.1\r\nHost: h\r\n\r\n",
            "OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n",
            "GET / HTTP/2.0\r\nHost: h\r\n\r\n",
            "GET /a b HTTP/1.1\r\nHost: h\r\n\r\n",
            "G(T / HTTP/1.1\r\nHost: h\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\r\n",
        ] {
            assert!(req(bad).is_err(), "{bad:?}");
        }
        let many: String = (0..=MAX_HEADERS).map(|i| format!("X{i}: v\r\n")).collect();
        assert!(req(&format!("GET / HTTP/1.1\r\nHost: h\r\n{many}\r\n")).is_err());
        let huge = format!(
            "GET / HTTP/1.1\r\nHost: h\r\nX: {}\r\n\r\n",
            "a".repeat(MAX_HEAD)
        );
        assert!(req(&huge).is_err());
        assert!(req(&format!(
            "GET /{} HTTP/1.1\r\nHost: h\r\n\r\n",
            "a".repeat(MAX_TARGET)
        ))
        .is_err());
    }

    #[test]
    fn tokens_are_found_where_presented() {
        assert_eq!(query_token("/a").unwrap(), None);
        assert_eq!(query_token("/a?x=1").unwrap(), None);
        assert_eq!(
            query_token("/a?hellovm_ingress_token=T").unwrap(),
            Some(("T".into(), "/a".into()))
        );
        assert_eq!(
            query_token("/a?x=1&hellovm_ingress_token=T&y=2").unwrap(),
            Some(("T".into(), "/a?x=1&y=2".into()))
        );
        assert!(query_token("/?hellovm_ingress_token=a&hellovm_ingress_token=b").is_err());
        let head = req(
            "GET / HTTP/1.1\r\nHost: h\r\nX-Hellovm-Ingress-Token: H\r\nX-Hellovm-Ingress-Token: H2\r\n\
             Cookie: a=1; hellovm_ingress_token=C1\r\nCookie: __Host-hellovm_ingress_token=C2\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            presented(&head.headers),
            vec![b"H".to_vec(), b"C1".to_vec(), b"C2".to_vec()]
        );
        // A flood of cookies is bounded.
        let flood: String = (0..100).map(|_| "hellovm_ingress_token=x; ").collect();
        let head = req(&format!(
            "GET / HTTP/1.1\r\nHost: h\r\nCookie: {flood}\r\n\r\n"
        ))
        .unwrap();
        assert!(presented(&head.headers).len() <= MAX_COOKIES + 1);
    }

    #[test]
    fn requests_are_rewritten_without_hellovm_credentials() {
        let head = req(
            "POST /x HTTP/1.1\r\nHost: 80-sb.example\r\nConnection: keep-alive, X-Drop\r\n\
             X-Drop: 1\r\nKeep-Alive: 5\r\nTE: trailers\r\nProxy-Authorization: Basic x\r\n\
             X-Hellovm-Ingress-Token: TOKEN\r\nX-Hellovm-Tenant: acme\r\n\
             Authorization: Bearer TENANT-TOKEN\r\nCookie: a=1; hellovm_ingress_token=TOKEN; b=2\r\n\
             X-Forwarded-For: 6.6.6.6\r\nForwarded: for=6.6.6.6\r\nX-Forwarded-Proto: http\r\n\
             Content-Length: 3\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        let secret = |v: &[u8]| v == b"TENANT-TOKEN";
        let f = Forward {
            peer: "10.1.2.3".parse().unwrap(),
            behind_proxy: false,
            scheme: "https",
            is_secret: &secret,
        };
        let out = String::from_utf8(forward_request(&head, "/x", &f)).unwrap();
        assert_eq!(
            out,
            "POST /x HTTP/1.1\r\nHost: 80-sb.example\r\nCookie: a=1; b=2\r\nContent-Length: 3\r\n\
             Accept: */*\r\nConnection: close\r\nX-Forwarded-For: 10.1.2.3\r\n\
             X-Forwarded-Proto: https\r\nX-Forwarded-Host: 80-sb.example\r\n\r\n"
        );
        // Behind a proxy its forwarding headers are kept and extended; an
        // Authorization that is not hellovm's goes through.
        let head = req(
            "GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 1.1.1.1\r\nX-Forwarded-Proto: http\r\n\
             Authorization: Bearer app-token\r\nCookie: hellovm_ingress_token=T\r\n\
             Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .unwrap();
        let f = Forward {
            behind_proxy: true,
            ..f
        };
        let out = String::from_utf8(forward_request(&head, "/", &f)).unwrap();
        assert_eq!(
            out,
            "GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer app-token\r\n\
             Connection: Upgrade\r\nUpgrade: websocket\r\nX-Forwarded-For: 1.1.1.1, 10.1.2.3\r\n\
             X-Forwarded-Proto: http\r\nX-Forwarded-Host: h\r\n\r\n"
        );
    }

    #[test]
    fn responses_are_checked_and_rewritten() {
        let r = parse_response(
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\nKeep-Alive: 5\r\n\
              Transfer-Encoding: chunked\r\nSet-Cookie: hellovm_ingress_token=evil; Domain=example\r\n\
              Set-Cookie: app=1\r\nUpgrade: h2c\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(forward_response(&r)).unwrap(),
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: app=1\r\n\
             Connection: close\r\n\r\n"
        );
        let r = parse_response(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(forward_response(&r)).unwrap(),
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        );
        let r = parse_response(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        assert_eq!(
            String::from_utf8(forward_response(&r)).unwrap(),
            "HTTP/1.1 100 Continue\r\n\r\n"
        );
        assert_eq!(parse_response(b"HTTP/1.0 204\r\n\r\n").unwrap().status, 204);
        for bad in [
            &b"HTTP/1.1 20 OK\r\n\r\n"[..],
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 099 x\r\n\r\n",
            b"HTTP/2 200 OK\r\n\r\n",
            b"http/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 200 O\rK\r\n\r\n",
            b"HTTP/1.1 200 OK\nX: y\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n folded\r\n\r\n",
            b"HTTP/1.1 200OK\r\n\r\n",
        ] {
            assert!(
                parse_response(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn chunked_bodies_end_where_they_end() {
        let body =
            b"5\r\nhello\r\n1A;ext=1\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\nTrailer: x\r\n\r\nNEXT";
        // In any pieces.
        for split in 0..body.len() {
            let mut c = Chunked::default();
            let first = c.feed(&body[..split]).unwrap();
            let end = match first {
                Some(n) => n,
                None => split + c.feed(&body[split..]).unwrap().unwrap(),
            };
            assert_eq!(end, body.len() - 4, "split {split}");
        }
        let mut c = Chunked::default();
        assert_eq!(c.feed(b"0\r\n\r\n").unwrap(), Some(5));
        for bad in [
            &b"x\r\n"[..],
            b"\r\n",
            b"5\nhello\r\n",
            b"5\r\nhelloX",
            b"5\r\nhello\n",
            b"11111111111111111\r\n",
            b"5 \r\n",
            b"-5\r\n",
            b"0\r\nbad trailer\n",
            b"0\r\n\rX",
        ] {
            let mut c = Chunked::default();
            assert!(c.feed(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let long = format!("1;{}\r\n", "e".repeat(2000));
        assert!(Chunked::default().feed(long.as_bytes()).is_err());
        let mut trailers = b"0\r\n".to_vec();
        for _ in 0..1000 {
            trailers.extend_from_slice(b"X-Trailer: aaaaaaaaaaaaaaa\r\n");
        }
        assert!(Chunked::default().feed(&trailers).is_err());
    }

    #[test]
    fn own_answers_are_plain() {
        let a = String::from_utf8(answer(404, "Not Found", "not found", &[])).unwrap();
        assert!(a.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(a.contains("Connection: close\r\n"));
        assert!(a.ends_with("\r\n\r\nnot found\n"));
        let a = answer(
            303,
            "See Other",
            "",
            &[("Location", "/x\r\nEvil: 1".into())],
        );
        assert!(!String::from_utf8(a).unwrap().contains("\r\nEvil"));
    }

    #[test]
    fn the_head_end_is_found_however_the_bytes_arrive() {
        let head = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nrest";
        assert_eq!(head_end(head), Some(head.len() - 4));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r"), None);
        // A byte at a time, or in pieces that split the empty line: found
        // at the same place, each byte looked at once.
        for step in 1..=5 {
            let mut buf = Vec::new();
            let mut scanned = 0;
            let mut found = None;
            for piece in head.chunks(step) {
                buf.extend_from_slice(piece);
                found = head_end_from(&buf, &mut scanned);
                assert_eq!(scanned, buf.len());
                if found.is_some() {
                    break;
                }
            }
            assert_eq!(found, Some(head.len() - 4), "step {step}");
        }
        // A scan mark past the buffer (it was drained) does no harm.
        assert_eq!(head_end_from(b"\r\n\r\n", &mut 100), Some(4));
    }

    #[test]
    fn a_redirect_stays_on_this_host() {
        assert_eq!(same_host("/a/b?x=1"), "/a/b?x=1");
        assert_eq!(same_host("/"), "/");
        assert_eq!(same_host("//evil.example/x"), "/evil.example/x");
        assert_eq!(same_host("///evil.example"), "/evil.example");
        assert_eq!(same_host("/\\evil.example"), "/evil.example");
        assert_eq!(same_host("/\\/evil.example"), "/evil.example");
        // Later slashes are the path's own.
        assert_eq!(same_host("/a//b"), "/a//b");
    }
}
