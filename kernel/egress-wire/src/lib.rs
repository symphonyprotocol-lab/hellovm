//! The kernel-to-proxy flow header and the proxy's one-byte verdict.
//!
//! Request (kernel to proxy), sent right after the Unix stream connects:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 4 | magic `HVEG` |
//! | 4 | 1 | version, [`VERSION`] |
//! | 5 | 1 | hostname length `n`, 1..=253 |
//! | 6 | 2 | destination port, big endian, non-zero |
//! | 8 | 8 | sandbox id, big endian |
//! | 16 | n | hostname: lowercase LDH labels separated by `.`, no trailing dot |
//!
//! Reply (proxy to kernel): magic `HVEG`, version, one [`Status`] byte. After
//! [`Status::Ok`] the stream carries the flow's bytes both ways; after any
//! other status the proxy closes it.

use std::fmt;
use std::io::{self, Read};

pub const MAGIC: [u8; 4] = *b"HVEG";
pub const VERSION: u8 = 1;
/// Longest hostname (RFC 1035 presentation form without the trailing dot).
pub const MAX_HOST: usize = 253;
/// The fixed part of a request.
pub const FIXED: usize = 16;
/// The largest request on the wire.
pub const MAX_REQUEST: usize = FIXED + MAX_HOST;
/// The reply's size.
pub const REPLY: usize = 6;

/// What the kernel tells the proxy about one flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub sandbox_id: u64,
    pub port: u16,
    /// A valid hostname ([`valid_hostname`]).
    pub host: String,
}

/// The proxy's verdict on a flow, before any payload moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Allowed and connected upstream. Payload follows.
    Ok = 0,
    /// The name and port are not on the allowlist.
    Denied = 1,
    /// The name did not resolve (or resolution timed out).
    ResolveFailed = 2,
    /// Every address the name resolved to is blocked.
    BlockedAddress = 3,
    /// No allowed address accepted the connection.
    UpstreamRefused = 4,
    /// The upstream connect timed out.
    UpstreamTimeout = 5,
    /// Too many concurrent flows (in total, or for this sandbox).
    Limit = 6,
    /// The request header was malformed or arrived too slowly.
    BadRequest = 7,
}

impl Status {
    pub fn from_byte(b: u8) -> Option<Status> {
        Some(match b {
            0 => Status::Ok,
            1 => Status::Denied,
            2 => Status::ResolveFailed,
            3 => Status::BlockedAddress,
            4 => Status::UpstreamRefused,
            5 => Status::UpstreamTimeout,
            6 => Status::Limit,
            7 => Status::BadRequest,
            _ => return None,
        })
    }

    /// The reply bytes for this status.
    pub fn reply(self) -> [u8; REPLY] {
        [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION, self as u8]
    }

    /// Parses a reply.
    pub fn parse_reply(bytes: &[u8; REPLY]) -> Option<Status> {
        if bytes[..4] != MAGIC || bytes[4] != VERSION {
            return None;
        }
        Status::from_byte(bytes[5])
    }
}

/// Why a request could not be read.
#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    Malformed(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Io(err) => write!(f, "{err}"),
            WireError::Malformed(why) => f.write_str(why),
        }
    }
}

impl From<io::Error> for WireError {
    fn from(err: io::Error) -> Self {
        WireError::Io(err)
    }
}

impl Request {
    /// The request bytes. `None` if the hostname is not valid or the port
    /// is 0: the kernel never sends such a request.
    pub fn encode(&self) -> Option<Vec<u8>> {
        if !valid_hostname(self.host.as_bytes()) || self.port == 0 {
            return None;
        }
        let mut out = Vec::with_capacity(FIXED + self.host.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.host.len() as u8);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.sandbox_id.to_be_bytes());
        out.extend_from_slice(self.host.as_bytes());
        Some(out)
    }

    /// Reads one request. Reads at most [`MAX_REQUEST`] bytes; the caller
    /// sets the read deadline.
    pub fn read_from(r: &mut impl Read) -> Result<Request, WireError> {
        let mut fixed = [0u8; FIXED];
        r.read_exact(&mut fixed)?;
        if fixed[..4] != MAGIC {
            return Err(WireError::Malformed("bad magic"));
        }
        if fixed[4] != VERSION {
            return Err(WireError::Malformed("unsupported version"));
        }
        let len = fixed[5] as usize;
        if len == 0 || len > MAX_HOST {
            return Err(WireError::Malformed("bad hostname length"));
        }
        let port = u16::from_be_bytes([fixed[6], fixed[7]]);
        if port == 0 {
            return Err(WireError::Malformed("port 0"));
        }
        let sandbox_id = u64::from_be_bytes(fixed[8..16].try_into().expect("8 bytes"));
        let mut host = vec![0u8; len];
        r.read_exact(&mut host)?;
        if !valid_hostname(&host) {
            return Err(WireError::Malformed("invalid hostname"));
        }
        let host = String::from_utf8(host).map_err(|_| WireError::Malformed("invalid hostname"))?;
        Ok(Request {
            sandbox_id,
            port,
            host,
        })
    }
}

/// Whether `name` is a hostname the egress path accepts: at most 253
/// bytes, at least two labels, every label 1..=63 bytes of lowercase
/// letters, digits and `-`, not starting or ending with `-`, no trailing
/// dot, and the last label not all digits (so no IPv4 literal passes).
pub fn valid_hostname(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > MAX_HOST {
        return false;
    }
    let mut labels = 0;
    let mut last: &[u8] = &[];
    for label in name.split(|&b| b == b'.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label[0] == b'-' || label[label.len() - 1] == b'-' {
            return false;
        }
        if !label
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
        labels += 1;
        last = label;
    }
    labels >= 2 && !last.iter().all(u8::is_ascii_digit)
}

/// Lowercases `name` and strips one trailing dot; `None` unless the result
/// is a [`valid_hostname`].
pub fn normalize_hostname(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let lower = name.to_ascii_lowercase();
    valid_hostname(lower.as_bytes()).then_some(lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let req = Request {
            sandbox_id: 0x0102_0304_0506_0708,
            port: 443,
            host: "pypi.org".into(),
        };
        let bytes = req.encode().unwrap();
        assert_eq!(&bytes[..6], b"HVEG\x01\x08");
        assert_eq!(bytes.len(), FIXED + 8);
        let back = Request::read_from(&mut &bytes[..]).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn malformed_requests_are_refused() {
        let good = Request {
            sandbox_id: 1,
            port: 80,
            host: "a.example".into(),
        }
        .encode()
        .unwrap();
        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        let mut bad_version = good.clone();
        bad_version[4] = 2;
        let mut zero_len = good.clone();
        zero_len[5] = 0;
        let mut zero_port = good.clone();
        zero_port[6] = 0;
        zero_port[7] = 0;
        let mut upper = good.clone();
        upper[16] = b'A';
        for bytes in [bad_magic, bad_version, zero_len, zero_port, upper] {
            assert!(Request::read_from(&mut &bytes[..]).is_err(), "{bytes:?}");
        }
        // Truncated.
        assert!(Request::read_from(&mut &good[..good.len() - 1]).is_err());
        // A long length byte cannot make the reader take more than 253.
        let mut long = good.clone();
        long[5] = 254;
        assert!(Request::read_from(&mut &long[..]).is_err());
    }

    #[test]
    fn hostnames() {
        for ok in ["pypi.org", "a-b.c0.example", "x.y.z.w", "1.example"] {
            assert!(valid_hostname(ok.as_bytes()), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "Pypi.org",
            "pypi.org.",
            ".pypi.org",
            "a..b",
            "-a.b",
            "a-.b",
            "a_b.c",
            "1.2.3.4",
            "a.b:443",
            "a b.c",
            "*.a.b",
        ] {
            assert!(!valid_hostname(bad.as_bytes()), "{bad}");
        }
        assert!(!valid_hostname(
            format!("{}.com", "a".repeat(64)).as_bytes()
        ));
        let long = format!("{}.com", vec!["a".repeat(63); 4].join("."));
        assert!(long.len() > MAX_HOST);
        assert!(!valid_hostname(long.as_bytes()));
        assert_eq!(normalize_hostname("PyPI.org.").as_deref(), Some("pypi.org"));
        assert_eq!(normalize_hostname("pypi.org.."), None);
    }

    #[test]
    fn replies() {
        for b in 0..=7 {
            let status = Status::from_byte(b).unwrap();
            assert_eq!(Status::parse_reply(&status.reply()), Some(status));
        }
        assert_eq!(Status::from_byte(8), None);
        assert_eq!(Status::parse_reply(b"HVEG\x02\x00"), None);
    }
}
