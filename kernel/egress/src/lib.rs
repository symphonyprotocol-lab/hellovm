//! `hellovm-egress`: the egress proxy that every outbound guest TCP flow of
//! every sandbox on a host goes through (spec 002b).
//!
//! # Where it sits
//!
//! The guest never reaches the network. Its DNS queries go to the kernel's
//! virtual DNS (`192.0.2.1:53`), which answers an `A` query by binding the
//! name to a *fake IP* from `198.51.100.0/24`. A guest `connect` to an
//! issued fake IP makes the kernel process (not the guest) open a Unix
//! stream to this proxy and send a [`wire`] header naming the flow: the
//! sandbox id, the hostname the kernel bound to that fake IP, and the port.
//! The kernel derives the hostname from its own table; nothing it sends is
//! read from guest memory at connect time, and the guest's destination IP
//! is never used as a dial address.
//!
//! The proxy then decides, dials, and relays bytes without decrypting them:
//!
//! 1. **Name policy** ([`policy`]): default deny. An allowlist of exact
//!    names and `*.suffix` wildcards, each for a set of ports (80 and 443
//!    when none are given).
//! 2. **Resolution and address policy** ([`addr`]): the proxy resolves the
//!    name itself and drops every address that is private, loopback,
//!    link-local (including `169.254.169.254`), CGNAT, multicast,
//!    unspecified, reserved or documentation space. A name that resolves to
//!    a mix is dialed only at the addresses that passed; a name with none
//!    left is refused.
//! 3. **Verdict**: the proxy answers the header with one status. Only after
//!    an upstream connection is up does it answer `Ok`, so a refused or
//!    unreachable flow fails the guest's `connect` (`ECONNREFUSED`, or
//!    `ETIMEDOUT` when the upstream connect timed out).
//! 4. **Protocol check** ([`sniff`]): the first bytes the guest sends must be
//!    a TLS ClientHello whose SNI equals the flow's hostname, or an HTTP/1.x
//!    request whose `Host` header names it. Port 443 requires TLS and port
//!    80 requires HTTP; other allowed ports accept either. Nothing is sent
//!    upstream until the check passes; a failure closes both sides, so the
//!    guest sees its handshake end with EOF.
//! 5. **Relay** both ways until both sides have closed, an error, or the
//!    idle timeout. One audit line ([`audit`]) per flow, at its end.
//!
//! # Why this wire protocol
//!
//! The kernel-to-proxy header is a fixed 16-byte binary prefix plus the
//! hostname (at most 253 bytes), and the reply is 6 bytes ([`wire`]). It is
//! bounded before the proxy reads a byte of it, needs no parser beyond
//! length checks, carries nothing the kernel did not derive itself, and is
//! versioned. A text protocol (an HTTP `CONNECT` line, say) would invite
//! the ambiguities this proxy exists to rule out, and SOCKS5 would need
//! extensions for the sandbox id. Running over a Unix socket, the proxy's
//! listening path is its access control: only processes that may open it
//! (the kernel processes on this host) can send a header.
//!
//! # Why the flow names its hostname
//!
//! The proxy cannot learn the hostname from the destination IP: fake IPs
//! are per sandbox and mean nothing outside it. Reading it from the SNI or
//! `Host` header alone would let the guest choose the name it is checked
//! against. So the kernel, which issued the fake IP for a name, names the
//! flow, and the SNI or `Host` header must then *agree* with that name.
//!
//! # Limits
//!
//! Everything a guest can influence is bounded ([`Limits`]): header size
//! and time, concurrent flows in total and per sandbox, the bytes sniffed
//! and the time allowed for them, resolution and connect time, buffered
//! bytes per direction, and idle time.
//!
//! # Not covered
//!
//! The proxy checks the *first* HTTP request of a plain-HTTP connection;
//! later requests on a kept-alive connection go to the same upstream
//! address unchecked. Encrypted Client Hello hides the inner SNI, so a
//! ClientHello whose outer SNI is not the flow's hostname is refused.
//! Protocols where the server speaks first (SSH, SMTP) are refused at the
//! sniff timeout.

#![forbid(unsafe_code)]

pub mod addr;
pub mod audit;
pub mod policy;
pub mod proxy;
pub mod resolve;
pub mod sniff;
pub mod wire;

pub use proxy::{Config, Limits, Proxy, ProxyHandle};
