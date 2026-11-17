//! Reads the name a client asks for from the first bytes it sends, without
//! decrypting anything: the SNI of a TLS ClientHello, or the `Host` header
//! of an HTTP/1.x request.
//!
//! [`sniff`] is called with everything received so far and either needs
//! more, or decides. The caller bounds the bytes ([`crate::Limits`]) and the
//! time; this module bounds nothing itself but never reads past `buf`.

use crate::wire::normalize_hostname;

/// TLS record header size.
const RECORD_HEADER: usize = 5;
/// Largest TLS plaintext record.
const MAX_RECORD: usize = 16384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sniff {
    /// Not enough bytes yet to decide.
    NeedMore,
    /// A complete TLS ClientHello with this server name.
    Tls(String),
    /// A complete HTTP/1.x request head with this `Host` name and, if the
    /// header carried one, port.
    Http(String, Option<u16>),
    /// Neither, or ambiguous. Refuse.
    Invalid(&'static str),
}

/// Decides what `buf`, the client's first bytes, is.
pub fn sniff(buf: &[u8]) -> Sniff {
    match buf.first() {
        None => Sniff::NeedMore,
        Some(0x16) => tls(buf),
        Some(b) if b.is_ascii_uppercase() => http(buf),
        Some(_) => Sniff::Invalid("neither TLS nor HTTP"),
    }
}

/// Reassembles the first handshake message from TLS records and reads
/// its SNI.
fn tls(buf: &[u8]) -> Sniff {
    let mut hs = Vec::new();
    let mut at = 0;
    loop {
        if buf.len() < at + RECORD_HEADER {
            return Sniff::NeedMore;
        }
        let head = &buf[at..at + RECORD_HEADER];
        if head[0] != 0x16 {
            return Sniff::Invalid("TLS record is not a handshake");
        }
        if head[1] != 3 || head[2] > 4 {
            return Sniff::Invalid("unknown TLS record version");
        }
        let len = u16::from_be_bytes([head[3], head[4]]) as usize;
        if len == 0 || len > MAX_RECORD {
            return Sniff::Invalid("bad TLS record length");
        }
        let body = at + RECORD_HEADER;
        if buf.len() < body + len {
            return Sniff::NeedMore;
        }
        hs.extend_from_slice(&buf[body..body + len]);
        at = body + len;
        if hs.len() >= 4 {
            if hs[0] != 1 {
                return Sniff::Invalid("first handshake message is not a ClientHello");
            }
            let need = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
            if hs.len() >= 4 + need {
                return client_hello(&hs[4..4 + need]);
            }
        }
    }
}

/// A byte cursor that fails instead of panicking.
struct Cur<'a> {
    buf: &'a [u8],
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| b[0] as usize)
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(n)
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
}

fn client_hello(body: &[u8]) -> Sniff {
    parse_client_hello(body).unwrap_or(Sniff::Invalid("malformed ClientHello"))
}

fn parse_client_hello(body: &[u8]) -> Option<Sniff> {
    let mut c = Cur { buf: body };
    c.take(2)?; // legacy_version
    c.take(32)?; // random
    if c.vec8()?.len() > 32 {
        return Some(Sniff::Invalid("session id too long"));
    }
    let suites = c.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Some(Sniff::Invalid("bad cipher suites"));
    }
    c.vec8()?; // compression methods
    if c.buf.is_empty() {
        return Some(Sniff::Invalid("no server name"));
    }
    let mut exts = Cur { buf: c.vec16()? };
    let mut sni = None;
    while !exts.buf.is_empty() {
        let ty = exts.u16()?;
        let data = exts.vec16()?;
        if ty != 0 {
            continue;
        }
        if sni.is_some() {
            return Some(Sniff::Invalid("two server_name extensions"));
        }
        let mut list = Cur {
            buf: Cur { buf: data }.vec16()?,
        };
        let mut name = None;
        while !list.buf.is_empty() {
            let kind = list.u8()?;
            let value = list.vec16()?;
            if kind != 0 {
                continue;
            }
            if name.is_some() {
                return Some(Sniff::Invalid("two host names in server_name"));
            }
            name = Some(value);
        }
        sni = Some(name?);
    }
    let Some(sni) = sni else {
        return Some(Sniff::Invalid("no server name"));
    };
    let Some(name) = std::str::from_utf8(sni).ok().and_then(normalize_hostname) else {
        return Some(Sniff::Invalid("server name is not a hostname"));
    };
    Some(Sniff::Tls(name))
}

/// Methods a client may start a plain-HTTP flow with. `CONNECT` is not one:
/// the upstream is a web server, not a proxy.
const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"];

fn http(buf: &[u8]) -> Sniff {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        // Reject early what can never become a request line.
        let line_end = buf.iter().position(|&b| b == b'\r' || b == b'\n');
        let first = &buf[..line_end.unwrap_or(buf.len())];
        let method_len = first.iter().position(|&b| b == b' ').unwrap_or(first.len());
        if method_len > 7 || !first[..method_len].iter().all(u8::is_ascii_uppercase) {
            return Sniff::Invalid("not an HTTP request line");
        }
        return Sniff::NeedMore;
    };
    let Ok(head) = std::str::from_utf8(&buf[..end]) else {
        return Sniff::Invalid("HTTP head is not UTF-8");
    };
    let mut lines = head.split("\r\n");
    let request = lines.next().unwrap_or("");
    let mut parts = request.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Sniff::Invalid("bad HTTP request line");
    };
    if !METHODS.contains(&method) {
        return Sniff::Invalid("unsupported HTTP method");
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Sniff::Invalid("unsupported HTTP version");
    }
    let mut host = None;
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Sniff::Invalid("folded HTTP header");
        }
        let Some((name, value)) = line.split_once(':') else {
            return Sniff::Invalid("bad HTTP header");
        };
        if name.is_empty() || name.ends_with([' ', '\t']) {
            return Sniff::Invalid("bad HTTP header name");
        }
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Sniff::Invalid("two Host headers");
            }
            host = Some(value.trim_matches([' ', '\t']));
        }
    }
    let Some(host) = host else {
        return Sniff::Invalid("no Host header");
    };
    let Some(authority) = parse_authority(host) else {
        return Sniff::Invalid("Host header is not a hostname");
    };
    // An absolute-form target names its own authority, which a server
    // prefers over `Host`. It must agree.
    if !target.starts_with('/') && target != "*" {
        let rest = target
            .strip_prefix("http://")
            .or_else(|| target.strip_prefix("https://"));
        let Some(rest) = rest else {
            return Sniff::Invalid("bad HTTP request target");
        };
        let auth = rest.split(['/', '?']).next().unwrap_or("");
        if parse_authority(auth).as_ref() != Some(&authority) {
            return Sniff::Invalid("request target and Host disagree");
        }
    }
    Sniff::Http(authority.0, authority.1)
}

/// `name[:port]`, normalized.
fn parse_authority(text: &str) -> Option<(String, Option<u16>)> {
    if text.contains('@') {
        return None;
    }
    let (name, port) = match text.rsplit_once(':') {
        Some((name, port)) => (name, Some(port.parse::<u16>().ok().filter(|&p| p != 0)?)),
        None => (text, None),
    };
    Some((normalize_hostname(name)?, port))
}

/// A ClientHello carrying `names` as `host_name` entries, for tests here and
/// in the integration tests. `names` empty means no SNI extension at all.
#[doc(hidden)]
pub fn client_hello_for_test(names: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[3, 3]);
    body.extend_from_slice(&[0x42; 32]);
    body.push(0); // session id
    body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one suite
    body.extend_from_slice(&[1, 0]); // null compression
    let mut exts = Vec::new();
    // A non-SNI extension first (supported_versions).
    exts.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);
    if !names.is_empty() {
        let mut list = Vec::new();
        for name in names {
            list.push(0);
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name.as_bytes());
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        exts.extend_from_slice(&[0, 0]);
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(&data);
    }
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_sni() {
        let hello = client_hello_for_test(&["PyPI.org"]);
        assert_eq!(sniff(&hello), Sniff::Tls("pypi.org".into()));
        for cut in 0..hello.len() {
            assert_eq!(sniff(&hello[..cut]), Sniff::NeedMore, "cut {cut}");
        }
        // Trailing application bytes do not matter.
        let mut more = hello.clone();
        more.extend_from_slice(b"\x17\x03\x03");
        assert_eq!(sniff(&more), Sniff::Tls("pypi.org".into()));
    }

    #[test]
    fn tls_sni_split_across_records() {
        let hello = client_hello_for_test(&["a.example"]);
        let hs = &hello[5..];
        let mut split = Vec::new();
        for chunk in hs.chunks(7) {
            split.extend_from_slice(&[0x16, 3, 1]);
            split.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            split.extend_from_slice(chunk);
        }
        assert_eq!(sniff(&split), Sniff::Tls("a.example".into()));
    }

    #[test]
    fn tls_without_a_usable_name() {
        assert!(matches!(
            sniff(&client_hello_for_test(&[])),
            Sniff::Invalid(_)
        ));
        assert!(matches!(
            sniff(&client_hello_for_test(&["a.example", "b.example"])),
            Sniff::Invalid(_)
        ));
        assert!(matches!(
            sniff(&client_hello_for_test(&["10.0.0.1"])),
            Sniff::Invalid(_)
        ));
        // Not a handshake record, or a bogus length.
        assert!(matches!(sniff(&[0x16, 3, 1, 0, 0]), Sniff::Invalid(_)));
        assert!(matches!(sniff(&[0x16, 3, 1, 0x50, 0]), Sniff::Invalid(_)));
        assert!(matches!(sniff(&[0x16, 9, 1, 0, 4]), Sniff::Invalid(_)));
        let mut server_hello = client_hello_for_test(&["a.example"]);
        server_hello[5] = 2;
        assert!(matches!(sniff(&server_hello), Sniff::Invalid(_)));
    }

    #[test]
    fn tls_garbage_never_panics() {
        let hello = client_hello_for_test(&["a.example"]);
        for i in 5..hello.len() {
            for v in [0u8, 1, 0x7f, 0xff] {
                let mut bad = hello.clone();
                bad[i] = v;
                let _ = sniff(&bad);
            }
        }
    }

    #[test]
    fn http_host() {
        let req = b"GET /simple/ HTTP/1.1\r\nHost: Pypi.Test:8080\r\nAccept: */*\r\n\r\n";
        assert_eq!(sniff(req), Sniff::Http("pypi.test".into(), Some(8080)));
        let req = b"GET / HTTP/1.0\r\nhost:a.example\r\n\r\n";
        assert_eq!(sniff(req), Sniff::Http("a.example".into(), None));
        assert_eq!(sniff(b"GET / HT"), Sniff::NeedMore);
        let abs = b"GET http://a.example/x HTTP/1.1\r\nHost: a.example\r\n\r\n";
        assert_eq!(sniff(abs), Sniff::Http("a.example".into(), None));
    }

    #[test]
    fn http_refusals() {
        for bad in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: u@a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nX: y\r\n Host: a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : a.example\r\n\r\n",
            b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example\r\n\r\n",
            b"GET / HTTP/2.0\r\nHost: a.example\r\n\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"GET http://b.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
            b"SSH-2.0-OpenSSH\r\n",
            b"\x00\x01",
        ] {
            assert!(
                matches!(sniff(bad), Sniff::Invalid(_)),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
