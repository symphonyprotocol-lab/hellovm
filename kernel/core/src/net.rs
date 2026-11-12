//! Emulated IPv4 sockets (spec 002a, decision D1).
//!
//! There is no packet-level TCP/IP stack and no smoltcp. The guest sees a
//! POSIX socket API and one virtual NIC; the kernel moves bytes itself.
//!
//! Address roles (they do not overlap):
//!
//! | Role | Address | Behaviour |
//! |---|---|---|
//! | Guest NIC | `192.0.2.2/24` (TEST-NET-1) | The guest's own address. In-kernel. |
//! | Gateway / virtual DNS | `192.0.2.1` port 53 | UDP and TCP DNS. Without egress, every query is NXDOMAIN. Any other port is `ECONNREFUSED`. |
//! | Rest of the NIC net | other `192.0.2.0/24` | `EHOSTUNREACH` |
//! | Loopback | `127.0.0.0/8`, and `0.0.0.0` as a wildcard | In-kernel. Connecting to `0.0.0.0` uses `127.0.0.1`. |
//! | Fake-IP pool | `198.51.100.0/24` (TEST-NET-2) | The only destinations that may be spliced to a [`crate::host::Host`] byte stream, and only after [`Net::issue_fake_ip`] handed that address out. |
//!
//! Anything else (`169.254.169.254`, RFC1918, off-list public addresses,
//! unissued fake IPs, outbound UDP that is not virtual DNS) is
//! `ENETUNREACH` at `connect` / `sendto`. The guest address is never a host
//! dial address.
//!
//! Ephemeral ports come from Linux's default `ip_local_port_range`,
//! **32768–60999**, unique per `(local address, protocol)` among sockets
//! that hold a port (explicit binds and kernel-assigned client ports).
//! Accepted sockets share the listener's local port and do not hold one of
//! their own. The range answers `EADDRINUSE` when it is exhausted.
//!
//! `listen` backlog is clamped to **[1, 128]**. A full accept queue makes
//! the next in-kernel `connect` fail with `ECONNREFUSED`.
//!
//! Half-close: `SHUT_WR` delivers EOF to the peer's reads; the caller can
//! still receive, and a bare FIN does **not** cause `EPIPE`. After a clean
//! full close, the first write is accepted and the next one fails with
//! `EPIPE` (and `SIGPIPE`, unless `MSG_NOSIGNAL`). A reset (the peer closed
//! with unread data, or the host stream fails a write) fails the write
//! immediately. That is what lets a server still reply after it has read
//! the client's FIN.

use std::collections::{BTreeSet, VecDeque};

use crate::errno::{
    Errno, EADDRINUSE, EADDRNOTAVAIL, ECONNREFUSED, EHOSTUNREACH, ENETUNREACH, ENOMEM,
};
use crate::host::HostStreamId;

/// Guest NIC address, `192.0.2.2`.
pub const GUEST_IP: u32 = 0xC000_0202;
/// Virtual gateway and DNS, `192.0.2.1`.
pub const GATEWAY_IP: u32 = 0xC000_0201;
/// `127.0.0.1`.
pub const LOOPBACK_IP: u32 = 0x7F00_0001;
/// First address of the fake-IP pool, `198.51.100.0`.
pub const FAKE_NET: u32 = 0xC633_6400;
/// First ephemeral port (Linux `ip_local_port_range` low).
pub const EPHEMERAL_LO: u16 = 32768;
/// Last ephemeral port (Linux `ip_local_port_range` high).
pub const EPHEMERAL_HI: u16 = 60999;
/// Virtual DNS port.
pub const DNS_PORT: u16 = 53;

/// Bytes one TCP direction buffers (one pipe's worth).
pub(crate) const STREAM_CAP: usize = 64 * 1024;
/// Datagrams one UDP socket queues.
pub(crate) const DGRAM_CAP: usize = 64;
/// Largest UDP payload (`65535 - 8 - 20`).
pub(crate) const DGRAM_MAX: usize = 65507;
/// Most sockets in one sandbox.
const MAX_SOCKETS: usize = 4096;
/// `listen` backlog limits.
const BACKLOG_MIN: usize = 1;
const BACKLOG_MAX: usize = 128;

/// An index into [`Net`]'s socket arena.
pub type SockId = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Domain {
    Inet,
    /// Unnamed `socketpair` only. Path-bound `AF_UNIX` is `EAFNOSUPPORT`.
    Unix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Proto {
    Tcp,
    Udp,
}

/// The other end of a TCP socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Link {
    /// In-kernel peer (loopback, the NIC address, or `socketpair`).
    Socket(SockId),
    /// Spliced to a host byte stream. The guest IP was not dialed.
    Host(HostStreamId),
    /// Virtual DNS on `192.0.2.1:53`.
    Dns,
}

#[derive(Clone, Debug)]
pub(crate) enum Phase {
    Open,
    Listening,
    Connecting(Link),
    Connected(Link),
}

#[derive(Clone, Debug)]
pub(crate) struct Dgram {
    pub src_ip: u32,
    pub src_port: u16,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct Socket {
    pub domain: Domain,
    pub proto: Proto,
    pub phase: Phase,
    pub local_ip: u32,
    pub local_port: u16,
    /// Set once `bind` or an implicit bind has chosen a local endpoint.
    pub bound: bool,
    /// This socket counts in the `(local ip, port, protocol)` uniqueness set.
    /// Accepted sockets do not: they share the listener's port.
    pub holds_port: bool,
    pub remote_ip: u32,
    pub remote_port: u16,
    /// UDP `connect` destination. TCP uses [`Phase::Connected`].
    pub udp_remote: Option<(u32, u16)>,
    pub rx: VecDeque<u8>,
    pub dgrams: VecDeque<Dgram>,
    /// TCP DNS request bytes, including the 2-byte length prefix.
    pub dns_in: Vec<u8>,
    pub shut_rd: bool,
    pub shut_wr: bool,
    /// Peer half-closed its write side (or fully closed). Reads return the
    /// bytes already queued, then 0.
    pub peer_fin: bool,
    /// Peer reset the connection (it closed with unread data, or the host
    /// stream failed). `recv` returns `ECONNRESET` once `rx` is empty.
    /// Writes fail with `EPIPE`.
    pub peer_reset: bool,
    /// The one write Linux accepts after a clean peer close has been done.
    /// The next write is `EPIPE`.
    pub post_fin_write: bool,
    /// A non-blocking connect already failed. A later `connect` returns the
    /// pending `SO_ERROR` once, then `ECONNABORTED`.
    pub connect_failed: bool,
    pub so_error: i64,
    pub reuseaddr: bool,
    pub keepalive: bool,
    pub nodelay: bool,
    pub sndbuf: u32,
    pub rcvbuf: u32,
    pub backlog: usize,
    pub queue: VecDeque<SockId>,
    /// Open-file descriptions plus accept-queue membership.
    owners: u32,
}

impl Socket {
    fn new(domain: Domain, proto: Proto) -> Socket {
        Socket {
            domain,
            proto,
            phase: Phase::Open,
            local_ip: 0,
            local_port: 0,
            bound: false,
            holds_port: false,
            remote_ip: 0,
            remote_port: 0,
            udp_remote: None,
            rx: VecDeque::new(),
            dgrams: VecDeque::new(),
            dns_in: Vec::new(),
            shut_rd: false,
            shut_wr: false,
            peer_fin: false,
            peer_reset: false,
            post_fin_write: false,
            connect_failed: false,
            so_error: 0,
            reuseaddr: false,
            keepalive: false,
            nodelay: false,
            sndbuf: STREAM_CAP as u32,
            rcvbuf: STREAM_CAP as u32,
            backlog: 0,
            queue: VecDeque::new(),
            owners: 1,
        }
    }

    pub(crate) fn link(&self) -> Option<Link> {
        match self.phase {
            Phase::Connecting(link) | Phase::Connected(link) => Some(link),
            Phase::Open | Phase::Listening => None,
        }
    }

    pub(crate) fn listening(&self) -> bool {
        matches!(self.phase, Phase::Listening)
    }

    pub(crate) fn tcp_connected(&self) -> bool {
        matches!(self.phase, Phase::Connected(_))
    }

    pub(crate) fn rx_space(&self) -> usize {
        STREAM_CAP.saturating_sub(self.rx.len())
    }
}

/// Where a destination sits in the address table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// In-kernel. The address is the normalized destination (`0.0.0.0`
    /// became `127.0.0.1`).
    Local(u32),
    /// `192.0.2.1:53`.
    Dns,
    /// `192.0.2.1` on a port other than 53.
    Refused,
    /// Another address in `192.0.2.0/24`.
    HostUnreach,
    /// An issued fake IP. TCP may be spliced; UDP is still unreachable.
    Splice(u32),
    /// Not local, not an issued fake IP.
    NetUnreach,
}

impl Class {
    pub(crate) fn errno(self) -> Option<i64> {
        match self {
            Class::Refused => Some(ECONNREFUSED),
            Class::HostUnreach => Some(EHOSTUNREACH),
            Class::NetUnreach => Some(ENETUNREACH),
            Class::Local(_) | Class::Dns | Class::Splice(_) => None,
        }
    }
}

#[derive(Debug, Default)]
struct Arena {
    slots: Vec<Option<Socket>>,
    free: Vec<SockId>,
}

impl Arena {
    fn insert(&mut self, sock: Socket) -> Result<SockId, Errno> {
        if self.slots.len() - self.free.len() >= MAX_SOCKETS {
            return Err(Errno(ENOMEM));
        }
        if let Some(id) = self.free.pop() {
            self.slots[id] = Some(sock);
            return Ok(id);
        }
        self.slots.push(Some(sock));
        Ok(self.slots.len() - 1)
    }

    fn get(&self, id: SockId) -> &Socket {
        self.slots[id].as_ref().expect("live socket")
    }

    fn get_mut(&mut self, id: SockId) -> &mut Socket {
        self.slots[id].as_mut().expect("live socket")
    }

    fn take(&mut self, id: SockId) -> Socket {
        let sock = self.slots[id].take().expect("live socket");
        self.free.push(id);
        sock
    }
}

/// The sandbox's sockets, issued fake IPs, and the ephemeral-port cursor.
#[derive(Debug)]
pub struct Net {
    sockets: Arena,
    /// Fake IPs handed out by [`Net::issue_fake_ip`], host order.
    issued: BTreeSet<u32>,
    /// Next host octet in `198.51.100.0/24` (1..=254).
    next_fake: u32,
    ephemeral: u16,
    /// `(local ip, port, protocol)` of sockets with `holds_port`.
    held: BTreeSet<(u32, u16, u8)>,
}

impl Default for Net {
    fn default() -> Self {
        Net {
            sockets: Arena::default(),
            issued: BTreeSet::new(),
            next_fake: 1,
            ephemeral: EPHEMERAL_LO,
            held: BTreeSet::new(),
        }
    }
}

fn proto_key(proto: Proto) -> u8 {
    match proto {
        Proto::Tcp => 0,
        Proto::Udp => 1,
    }
}

impl Net {
    pub(crate) fn contains(&self, id: SockId) -> bool {
        self.sockets.slots.get(id).is_some_and(|s| s.is_some())
    }

    pub(crate) fn get(&self, id: SockId) -> &Socket {
        self.sockets.get(id)
    }

    /// Removes `id` from every accept queue. `true` when it was queued.
    pub(crate) fn detach_queued(&mut self, id: SockId) -> bool {
        let mut found = false;
        for slot in &mut self.sockets.slots {
            let Some(sock) = slot else {
                continue;
            };
            let before = sock.queue.len();
            sock.queue.retain(|&q| q != id);
            if sock.queue.len() != before {
                found = true;
            }
        }
        found
    }

    pub(crate) fn get_mut(&mut self, id: SockId) -> &mut Socket {
        self.sockets.get_mut(id)
    }

    /// A new socket owned by one open-file description.
    pub(crate) fn create(&mut self, domain: Domain, proto: Proto) -> Result<SockId, Errno> {
        self.sockets.insert(Socket::new(domain, proto))
    }

    /// Hands out the next address from `198.51.100.1`–`198.51.100.254` and
    /// records it as issued. Never returns a NIC address, a loopback
    /// address, `0.0.0.0`, or anything in `198.18.0.0/15`. `None` when the
    /// pool is exhausted.
    pub fn issue_fake_ip(&mut self) -> Option<[u8; 4]> {
        if self.next_fake > 254 {
            return None;
        }
        let ip = FAKE_NET | self.next_fake;
        self.next_fake += 1;
        debug_assert!(is_issued_shape(ip));
        self.issued.insert(ip);
        Some(ip.to_be_bytes())
    }

    pub(crate) fn is_issued(&self, ip: u32) -> bool {
        self.issued.contains(&ip)
    }

    /// Classifies `ip`:`port`. `0.0.0.0` is normalized to `127.0.0.1`.
    /// Issued fake IPs are [`Class::Splice`] for TCP and
    /// [`Class::NetUnreach`] for UDP (outbound UDP is only virtual DNS).
    pub(crate) fn classify(&self, ip: u32, port: u16, tcp: bool) -> Class {
        let ip = if ip == 0 { LOOPBACK_IP } else { ip };
        if is_loopback(ip) || ip == GUEST_IP {
            return Class::Local(ip);
        }
        if ip == GATEWAY_IP {
            return if port == DNS_PORT {
                Class::Dns
            } else {
                Class::Refused
            };
        }
        if in_prefix(ip, 0xC000_0200, 24) {
            return Class::HostUnreach;
        }
        if in_prefix(ip, FAKE_NET, 24) && self.is_issued(ip) {
            return if tcp {
                Class::Splice(ip)
            } else {
                Class::NetUnreach
            };
        }
        Class::NetUnreach
    }

    /// `bind` is allowed on `0.0.0.0`, `127.0.0.0/8`, and `192.0.2.2` only.
    pub(crate) fn bind_ok(ip: u32) -> bool {
        ip == 0 || is_loopback(ip) || ip == GUEST_IP
    }

    pub(crate) fn bind_errno(ip: u32) -> Result<(), Errno> {
        if Self::bind_ok(ip) {
            Ok(())
        } else {
            Err(Errno(EADDRNOTAVAIL))
        }
    }

    pub(crate) fn port_busy(&self, ip: u32, port: u16, proto: Proto) -> bool {
        self.held.contains(&(ip, port, proto_key(proto)))
    }

    /// `bind` conflicts with the same address and with the other of
    /// `0.0.0.0:port` and a specific address on that port. Linux returns
    /// `EADDRINUSE` for both orders when `SO_REUSEADDR` is off; this stack
    /// does that even if the option was set.
    pub(crate) fn bind_conflicts(&self, ip: u32, port: u16, proto: Proto) -> bool {
        let key = proto_key(proto);
        if self.held.contains(&(ip, port, key)) {
            return true;
        }
        if ip == 0 {
            self.held
                .iter()
                .any(|&(other, oport, oproto)| oport == port && oproto == key && other != 0)
        } else {
            self.held.contains(&(0, port, key))
        }
    }

    /// Records that a socket now holds `(ip, port, proto)`.
    pub(crate) fn claim_port(&mut self, ip: u32, port: u16, proto: Proto) {
        self.held.insert((ip, port, proto_key(proto)));
    }

    /// Forgets a held port (bind replaced, or the last owner closed).
    pub(crate) fn release_port(&mut self, ip: u32, port: u16, proto: Proto) {
        self.held.remove(&(ip, port, proto_key(proto)));
    }

    /// Next free ephemeral port for `(ip, proto)`, or `EADDRINUSE`.
    pub(crate) fn alloc_ephemeral(&mut self, ip: u32, proto: Proto) -> Result<u16, Errno> {
        let start = self.ephemeral;
        loop {
            let port = self.ephemeral;
            self.ephemeral = if port == EPHEMERAL_HI {
                EPHEMERAL_LO
            } else {
                port + 1
            };
            if !self.port_busy(ip, port, proto) {
                return Ok(port);
            }
            if self.ephemeral == start {
                return Err(Errno(EADDRINUSE));
            }
        }
    }

    /// Clamps `listen`'s backlog to `[1, 128]`.
    pub(crate) fn clamp_backlog(backlog: i64) -> usize {
        if backlog < BACKLOG_MIN as i64 {
            BACKLOG_MIN
        } else if backlog > BACKLOG_MAX as i64 {
            BACKLOG_MAX
        } else {
            backlog as usize
        }
    }

    /// TCP listener for `ip`:`port`, preferring an exact address over
    /// `0.0.0.0`.
    pub(crate) fn find_listener(&self, ip: u32, port: u16) -> Option<SockId> {
        let mut wild = None;
        for (id, slot) in self.sockets.slots.iter().enumerate() {
            let Some(sock) = slot else {
                continue;
            };
            if sock.proto != Proto::Tcp || !sock.listening() || sock.local_port != port {
                continue;
            }
            if sock.local_ip == ip {
                return Some(id);
            }
            if sock.local_ip == 0 {
                wild = Some(id);
            }
        }
        wild
    }

    /// UDP socket bound to `ip`:`port`, preferring an exact address.
    pub(crate) fn find_udp(&self, ip: u32, port: u16) -> Option<SockId> {
        let mut wild = None;
        for (id, slot) in self.sockets.slots.iter().enumerate() {
            let Some(sock) = slot else {
                continue;
            };
            if sock.proto != Proto::Udp || !sock.bound || sock.local_port != port {
                continue;
            }
            if sock.local_ip == ip {
                return Some(id);
            }
            if sock.local_ip == 0 {
                wild = Some(id);
            }
        }
        wild
    }

    /// An accepted TCP socket that shares the listener's port (`holds_port`
    /// is false). Its owner is the listener's accept queue.
    pub(crate) fn spawn_accepted(
        &mut self,
        local_ip: u32,
        local_port: u16,
        remote_ip: u32,
        remote_port: u16,
    ) -> Result<SockId, Errno> {
        let mut sock = Socket::new(Domain::Inet, Proto::Tcp);
        sock.bound = true;
        sock.local_ip = local_ip;
        sock.local_port = local_port;
        sock.remote_ip = remote_ip;
        sock.remote_port = remote_port;
        self.sockets.insert(sock)
    }

    /// Drops one owner. Returns what the caller must do if this was the last
    /// owner: close a host stream, reset in-kernel peers, and drop queued
    /// children (each of those is returned so the caller can recurse — this
    /// method does not recurse, so the caller controls the order).
    pub(crate) fn drop_owner(&mut self, id: SockId) -> Dropped {
        let sock = self.sockets.get_mut(id);
        sock.owners = sock.owners.saturating_sub(1);
        if sock.owners > 0 {
            return Dropped::default();
        }
        let sock = self.sockets.take(id);
        if sock.holds_port {
            self.release_port(sock.local_ip, sock.local_port, sock.proto);
        }
        let mut dropped = Dropped {
            host: match sock.link() {
                Some(Link::Host(id)) => Some(id),
                _ => None,
            },
            reset: match sock.link() {
                Some(Link::Socket(peer)) => vec![peer],
                _ => Vec::new(),
            },
            children: sock.queue.into_iter().collect(),
        };
        // A queued child is only reachable from this listener. Its peer
        // (the connecting client) must see a reset when the child goes.
        dropped
            .reset
            .retain(|&peer| self.sockets.slots.get(peer).is_some_and(|s| s.is_some()));
        // A close with unread received data is a reset. A close that has
        // read everything is a clean FIN: the survivor stays connected so
        // `poll` still sees it, the first write is accepted, and the next
        // write is `EPIPE`.
        let reset = !sock.rx.is_empty();
        for &peer in &dropped.reset {
            let peer_sock = self.sockets.get_mut(peer);
            peer_sock.peer_fin = true;
            if reset {
                peer_sock.peer_reset = true;
            }
        }
        dropped
    }

    /// `/proc/net/tcp`, Linux's little-endian address columns.
    pub(crate) fn proc_tcp(&self) -> Vec<u8> {
        self.proc_table(Proto::Tcp)
    }

    /// `/proc/net/udp`.
    pub(crate) fn proc_udp(&self) -> Vec<u8> {
        self.proc_table(Proto::Udp)
    }

    fn proc_table(&self, proto: Proto) -> Vec<u8> {
        let mut out = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n".to_vec();
        let mut n = 0u32;
        for (id, slot) in self.sockets.slots.iter().enumerate() {
            let Some(sock) = slot else {
                continue;
            };
            if sock.proto != proto {
                continue;
            }
            let show = sock.bound
                || sock.listening()
                || sock.tcp_connected()
                || matches!(sock.phase, Phase::Connecting(_));
            if !show {
                continue;
            }
            let (rip, rport) = if sock.tcp_connected() || matches!(sock.phase, Phase::Connecting(_))
            {
                (sock.remote_ip, sock.remote_port)
            } else if let Some((ip, port)) = sock.udp_remote {
                (ip, port)
            } else {
                (0, 0)
            };
            let state = match (&sock.phase, proto) {
                (Phase::Listening, _) => 0x0Au8,
                (Phase::Connecting(_), _) => 0x02,
                (Phase::Connected(_), _) => 0x01,
                (_, Proto::Udp) if sock.udp_remote.is_some() => 0x01,
                _ => 0x07,
            };
            let rx = if proto == Proto::Tcp {
                sock.rx.len()
            } else {
                sock.dgrams.iter().map(|d| d.data.len()).sum()
            };
            out.extend(
                format!(
                    "{n:4}: {lip:08X}:{lp:04X} {rip:08X}:{rp:04X} {state:02X} {tx:08X}:{rx:08X} 00:00000000 00000000     0        0 {ino} 1 0000000000000000 100 0 0 10 0\n",
                    lip = sock.local_ip.swap_bytes(),
                    lp = sock.local_port,
                    rip = rip.swap_bytes(),
                    rp = rport,
                    tx = 0u32,
                    rx = rx as u32,
                    ino = 0x10_0000 + id,
                )
                .into_bytes(),
            );
            n += 1;
        }
        out
    }
}

/// Side effects of freeing the last owner of a socket.
#[derive(Default)]
pub(crate) struct Dropped {
    pub host: Option<HostStreamId>,
    /// Peers that pointed at the freed socket; already marked reset.
    pub reset: Vec<SockId>,
    /// Accepted sockets that were still queued.
    pub children: Vec<SockId>,
}

/// Source address the kernel picks for an unbound connect.
pub(crate) fn source_ip(dest: u32) -> u32 {
    if is_loopback(dest) {
        LOOPBACK_IP
    } else {
        GUEST_IP
    }
}

pub(crate) fn is_loopback(ip: u32) -> bool {
    ip & 0xFF00_0000 == 0x7F00_0000
}

fn in_prefix(ip: u32, base: u32, bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    ip & mask == base & mask
}

/// The pool address is in `198.51.100.0/24`, not the NIC, not loopback,
/// not `0.0.0.0`, and not `198.18.0.0/15`.
fn is_issued_shape(ip: u32) -> bool {
    in_prefix(ip, FAKE_NET, 24)
        && ip != FAKE_NET
        && ip != FAKE_NET | 0xFF
        && !is_loopback(ip)
        && ip != 0
        && ip != GUEST_IP
        && ip != GATEWAY_IP
        && !in_prefix(ip, 0xC000_0200, 24)
        && !in_prefix(ip, 0xC612_0000, 15)
}

/// Builds an NXDOMAIN response for a query. Returns `None` when `query` is
/// too short to be a DNS header. 002a has no egress, so every qtype,
/// including AAAA, is NXDOMAIN; 002b answers AAAA with an empty NOERROR
/// before this and only calls it for a deny.
pub(crate) fn dns_nxdomain(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qend = dns_question_end(query).unwrap_or(query.len());
    let mut resp = query[..qend.min(query.len())].to_vec();
    if resp.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let opcode = flags & 0x7800;
    let rd = flags & 0x0100;
    // QR, AA, copied opcode and RD, RCODE = NXDOMAIN.
    let out = 0x8000 | 0x0400 | opcode | rd | 0x0003;
    resp[2] = (out >> 8) as u8;
    resp[3] = out as u8;
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    Some(resp)
}

/// Byte offset just past the first question, or `None` if it is truncated.
fn dns_question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let mut i = 12;
    for _ in 0..qd.max(1) {
        loop {
            if i >= msg.len() {
                return None;
            }
            let len = msg[i] as usize;
            i += 1;
            if len == 0 {
                break;
            }
            if len > 63 || i + len > msg.len() {
                return None;
            }
            i += len;
        }
        // qtype + qclass
        if i + 4 > msg.len() {
            return None;
        }
        i += 4;
        if qd == 0 {
            break;
        }
    }
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_pool_stays_inside_test_net_2() {
        let mut net = Net::default();
        let mut seen = BTreeSet::new();
        for _ in 0..254 {
            let ip = net.issue_fake_ip().unwrap();
            let v = u32::from_be_bytes(ip);
            assert!(is_issued_shape(v), "{ip:?}");
            assert!(seen.insert(v));
            assert!(net.is_issued(v));
        }
        assert!(net.issue_fake_ip().is_none());
        // Unissued addresses in the same /24 are not spliceable.
        assert_eq!(net.classify(FAKE_NET, 443, true), Class::NetUnreach);
        let issued = u32::from_be_bytes(seen.iter().next().copied().unwrap().to_be_bytes());
        assert_eq!(net.classify(issued, 443, true), Class::Splice(issued));
        assert_eq!(net.classify(issued, 53, false), Class::NetUnreach);
    }

    #[test]
    fn classification_matches_the_table() {
        let mut net = Net::default();
        let fake = u32::from_be_bytes(net.issue_fake_ip().unwrap());
        let cases = [
            (0, 80, true, Class::Local(LOOPBACK_IP)),
            (LOOPBACK_IP, 80, true, Class::Local(LOOPBACK_IP)),
            (0x7F00_0005, 9, true, Class::Local(0x7F00_0005)),
            (GUEST_IP, 80, true, Class::Local(GUEST_IP)),
            (GATEWAY_IP, 53, false, Class::Dns),
            (GATEWAY_IP, 53, true, Class::Dns),
            (GATEWAY_IP, 80, true, Class::Refused),
            (0xC000_0263, 80, true, Class::HostUnreach), // 192.0.2.99
            (fake, 443, true, Class::Splice(fake)),
            (0xA9FE_A9FE, 80, true, Class::NetUnreach), // 169.254.169.254
            (0x0A01_0203, 80, true, Class::NetUnreach), // 10.1.2.3
            (0x9765_40DF, 443, true, Class::NetUnreach), // 151.101.64.223
            (0x0808_0808, 53, false, Class::NetUnreach),
        ];
        for (ip, port, tcp, want) in cases {
            assert_eq!(
                net.classify(ip, port, tcp),
                want,
                "{ip:#x}:{port} tcp={tcp}"
            );
        }
        assert!(Net::bind_ok(0));
        assert!(Net::bind_ok(LOOPBACK_IP));
        assert!(Net::bind_ok(GUEST_IP));
        assert!(!Net::bind_ok(GATEWAY_IP));
        assert!(!Net::bind_ok(0xC000_0263));
        assert!(!Net::bind_ok(fake));
        assert_eq!(Net::clamp_backlog(0), 1);
        assert_eq!(Net::clamp_backlog(-5), 1);
        assert_eq!(Net::clamp_backlog(16), 16);
        assert_eq!(Net::clamp_backlog(10_000), 128);
    }

    #[test]
    fn ephemeral_ports_are_unique_and_then_exhausted() {
        let mut net = Net::default();
        let mut ports = BTreeSet::new();
        for _ in EPHEMERAL_LO..=EPHEMERAL_HI {
            let port = net.alloc_ephemeral(LOOPBACK_IP, Proto::Tcp).unwrap();
            assert!((EPHEMERAL_LO..=EPHEMERAL_HI).contains(&port));
            assert!(ports.insert(port));
            net.claim_port(LOOPBACK_IP, port, Proto::Tcp);
        }
        assert_eq!(ports.len(), (EPHEMERAL_HI - EPHEMERAL_LO + 1) as usize);
        assert_eq!(
            net.alloc_ephemeral(LOOPBACK_IP, Proto::Tcp).unwrap_err(),
            Errno(EADDRINUSE)
        );
        // A different address, and UDP, are separate spaces.
        assert!(net.alloc_ephemeral(GUEST_IP, Proto::Tcp).is_ok());
        assert!(net.alloc_ephemeral(LOOPBACK_IP, Proto::Udp).is_ok());
        net.release_port(LOOPBACK_IP, EPHEMERAL_LO, Proto::Tcp);
        assert_eq!(
            net.alloc_ephemeral(LOOPBACK_IP, Proto::Tcp).unwrap(),
            EPHEMERAL_LO
        );
    }

    #[test]
    fn nxdomain_keeps_the_question_and_sets_rcode() {
        // Header + name "hi" + A/IN.
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x02hi\x00\x00\x01\x00\x01");
        let resp = dns_nxdomain(&q).unwrap();
        assert_eq!(&resp[..2], &q[..2]);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "QR");
        assert_eq!(flags & 0x000F, 3, "NXDOMAIN");
        assert_eq!(&resp[6..12], &[0; 6]);
        assert!(resp.windows(2).any(|w| w == b"hi"));
        assert!(dns_nxdomain(&[0; 4]).is_none());
    }
}
