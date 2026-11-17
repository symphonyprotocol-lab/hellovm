//! Name resolution on the proxy's side.
//!
//! The default resolver is the host's (`getaddrinfo` through
//! `std::net::ToSocketAddrs`), run on a helper thread so that a slow
//! resolver cannot hold a flow past [`crate::Limits::resolve_timeout`].
//!
//! With the `insecure-test-hooks` feature, a static table can stand in for
//! it. Entries may carry a port (the dial port then replaces the flow's
//! port) and may be loopback: a loopback address that comes from the table
//! is the one exception to [`crate::addr::blocked`], so tests can put local
//! servers behind allowed names. Every other blocked range stays blocked.
//! The default build has neither the table nor the exception.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::time::Duration;

/// Most resolutions in flight at once. A helper thread can stay inside
/// `getaddrinfo` long after its flow gave up waiting (the flow's slot is
/// free again by then), so the flow limit does not bound these threads;
/// this does. Past it, a resolution fails at once.
pub const MAX_RESOLVING: usize = 256;

static RESOLVING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct Resolving;

impl Resolving {
    fn begin() -> Option<Resolving> {
        use std::sync::atomic::Ordering;
        if RESOLVING.fetch_add(1, Ordering::SeqCst) >= MAX_RESOLVING {
            RESOLVING.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Resolving)
    }
}

impl Drop for Resolving {
    fn drop(&mut self) {
        RESOLVING.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Most addresses kept from one resolution.
pub const MAX_ADDRS: usize = 16;

/// One address a name resolved to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub addr: SocketAddr,
    /// A test-table loopback entry: dialable despite being loopback.
    pub test_loopback: bool,
}

#[derive(Clone, Debug, Default)]
pub enum Resolver {
    /// The host's resolver.
    #[default]
    System,
    /// A fixed table of names (tests only).
    #[cfg(feature = "insecure-test-hooks")]
    Static(std::collections::HashMap<String, Vec<(std::net::IpAddr, Option<u16>)>>),
}

impl Resolver {
    /// Parses a test table: one `NAME ADDR[:PORT] [ADDR[:PORT]...]` per line
    /// (IPv6 with a port as `[ADDR]:PORT`), `#` comments.
    #[cfg(feature = "insecure-test-hooks")]
    pub fn parse_test_table(text: &str) -> Result<Resolver, String> {
        use std::net::IpAddr;
        let mut table = std::collections::HashMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut words = line.split_whitespace();
            let name = words.next().unwrap_or("");
            let name = crate::wire::normalize_hostname(name)
                .ok_or_else(|| format!("line {}: {name}: not a hostname", n + 1))?;
            let mut addrs = Vec::new();
            for word in words {
                let entry = if let Ok(sa) = word.parse::<SocketAddr>() {
                    (sa.ip(), Some(sa.port()))
                } else if let Ok(ip) = word.parse::<IpAddr>() {
                    (ip, None)
                } else {
                    return Err(format!("line {}: {word}: not an address", n + 1));
                };
                addrs.push(entry);
            }
            if addrs.is_empty() {
                return Err(format!("line {}: {name} has no addresses", n + 1));
            }
            table.insert(name, addrs);
        }
        Ok(Resolver::Static(table))
    }

    /// The addresses of `host` for a flow to `port`, at most [`MAX_ADDRS`].
    pub fn resolve(&self, host: &str, port: u16, timeout: Duration) -> io::Result<Vec<Candidate>> {
        match self {
            Resolver::System => system(host, port, timeout),
            #[cfg(feature = "insecure-test-hooks")]
            Resolver::Static(table) => {
                let addrs = table.get(host).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "name not in the test table")
                })?;
                Ok(addrs
                    .iter()
                    .take(MAX_ADDRS)
                    .map(|&(ip, p)| Candidate {
                        addr: SocketAddr::new(ip, p.unwrap_or(port)),
                        test_loopback: ip.is_loopback(),
                    })
                    .collect())
            }
        }
    }
}

fn system(host: &str, port: u16, timeout: Duration) -> io::Result<Vec<Candidate>> {
    let (tx, rx) = mpsc::sync_channel(1);
    let name = host.to_string();
    // The thread may outlive the timeout inside getaddrinfo; it then exits
    // on its own. `MAX_RESOLVING` bounds how many can exist.
    let in_flight =
        Resolving::begin().ok_or_else(|| io::Error::other("too many resolutions in flight"))?;
    std::thread::Builder::new()
        .name("egress-resolve".into())
        .spawn(move || {
            let _in_flight = in_flight;
            let result = (name.as_str(), port)
                .to_socket_addrs()
                .map(|it| it.take(MAX_ADDRS).collect::<Vec<_>>());
            let _ = tx.send(result);
        })?;
    let addrs = rx
        .recv_timeout(timeout)
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "resolution timed out"))??;
    Ok(addrs
        .into_iter()
        .map(|addr| Candidate {
            addr,
            test_loopback: false,
        })
        .collect())
}
