//! Emulated IPv4 sockets and virtual DNS (spec 002, decision D1).
//!
//! There is no packet-level TCP/IP stack and no smoltcp. The guest sees a
//! POSIX socket API and one virtual NIC; the kernel moves bytes itself.
//!
//! Address roles (they do not overlap):
//!
//! | Role | Address | Behaviour |
//! |---|---|---|
//! | Guest NIC | `192.0.2.2/24` (TEST-NET-1) | The guest's own address. In-kernel. |
//! | Gateway / virtual DNS | `192.0.2.1` port 53 | UDP and TCP DNS ([`Net::dns_reply`]). Any other port is `ECONNREFUSED`. |
//! | Rest of the NIC net | other `192.0.2.0/24` | `EHOSTUNREACH` |
//! | Loopback | `127.0.0.0/8`, and `0.0.0.0` as a wildcard | In-kernel. Connecting to `0.0.0.0` uses `127.0.0.1`. |
//! | Fake-IP pool | `198.51.100.0/24` (TEST-NET-2) | The only destinations that may leave the sandbox (as a [`crate::host::Host`] byte stream to the egress proxy), and only after virtual DNS bound that address to a name. |
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
//!
//! Inbound connections (ingress, [`Net::queue_inbound`]): the host side
//! opens a connection to a guest port; it arrives at the guest NIC address,
//! `192.0.2.2:PORT`, so a listener on `0.0.0.0` or `192.0.2.2` gets it and
//! one on `127.0.0.1` only does not. Its peer is the gateway,
//! `192.0.2.1`, on a port from the ephemeral range: never a loopback
//! address, which servers often trust. Nothing a guest does can open one.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use hellovm_egress_wire::valid_hostname;

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
/// Payload bytes one datagram socket queues, so 4096 sockets cannot hold
/// gigabytes. One datagram of any size is still accepted into an empty
/// queue.
pub(crate) const DGRAM_BYTES_CAP: usize = STREAM_CAP;
/// TCP DNS request bytes buffered: one largest frame (2-byte length plus
/// 65535 bytes), so any well-formed frame can complete.
pub(crate) const DNS_IN_CAP: usize = 2 + 65535;
/// Largest UDP payload (`65535 - 8 - 20`).
pub(crate) const DGRAM_MAX: usize = 65507;
/// Most sockets in one sandbox.
const MAX_SOCKETS: usize = 4096;
/// `listen` backlog limits.
const BACKLOG_MIN: usize = 1;
const BACKLOG_MAX: usize = 128;
/// Inbound connections open in one sandbox at once (queued or accepted,
/// until the guest closes them). Past this one is refused.
pub const MAX_INBOUND: usize = 256;

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
    /// The peer's slot has been freed. This is not a [`SockId`]: the next
    /// socket may reuse that slot, and a survivor must not write into it.
    Gone,
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
    /// The last connect failed and that error was consumed by `SO_ERROR`
    /// (or returned directly by a blocking host connect). The next `connect`
    /// is `ECONNABORTED` once, then this flag clears and the call retries.
    pub connect_failed: bool,
    pub so_error: i64,
    pub reuseaddr: bool,
    pub keepalive: bool,
    pub nodelay: bool,
    pub sndbuf: u32,
    pub rcvbuf: u32,
    pub backlog: usize,
    pub queue: VecDeque<SockId>,
    /// An inbound connection (ingress): counted in `Net::inbound`.
    pub inbound: bool,
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
            inbound: false,
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

/// Names virtual DNS can have bound at once in one sandbox: the fake-IP
/// pool, `198.51.100.1`–`198.51.100.254`. When all are bound, a new name
/// takes over the address of the name that has gone unused longest, if that
/// is at least [`NAME_IDLE`]; otherwise it is answered with `SERVFAIL`.
pub const MAX_NAMES: usize = 254;
/// How long a name must have gone unused (no `A` query for it, no connect
/// to its address) before its fake IP may be bound to another name: twice
/// the TTL of the answers, so no resolver cache still holds it. A guest that
/// keeps an address longer and connects to it after it was rebound opens a
/// flow named for the new owner, which the egress proxy then refuses
/// because the TLS SNI or HTTP `Host` names the old one. Connections that
/// are already open are not affected.
pub const NAME_IDLE: Duration = Duration::from_secs(2 * DNS_TTL as u64);
/// TTL of a virtual DNS `A` answer, seconds.
pub const DNS_TTL: u32 = 300;

/// The sandbox's sockets, issued fake IPs and the names bound to them, and
/// the ephemeral-port cursor.
#[derive(Debug)]
pub struct Net {
    sockets: Arena,
    /// Fake IPs handed out, host order: by virtual DNS for a name, or by
    /// [`Net::issue_fake_ip`] without one.
    issued: BTreeSet<u32>,
    /// Name to fake IP, for stable answers.
    names: BTreeMap<String, u32>,
    /// Fake IP to name: what a `connect` to it is a flow to.
    by_ip: BTreeMap<u32, String>,
    /// When each named fake IP was last asked for or connected to
    /// (monotonic clock).
    last_used: BTreeMap<u32, Duration>,
    /// Next host octet in `198.51.100.0/24` (1..=254).
    next_fake: u32,
    ephemeral: u16,
    /// `(local ip, port, protocol)` of sockets with `holds_port`.
    held: BTreeSet<(u32, u16, u8)>,
    /// Names this sandbox to the egress proxy.
    pub(crate) sandbox_id: u64,
    /// Inbound connections open (sockets with `inbound`).
    inbound: usize,
    /// The next peer port of an inbound connection.
    inbound_port: u16,
}

impl Default for Net {
    fn default() -> Self {
        Net {
            sockets: Arena::default(),
            issued: BTreeSet::new(),
            names: BTreeMap::new(),
            by_ip: BTreeMap::new(),
            last_used: BTreeMap::new(),
            next_fake: 1,
            ephemeral: EPHEMERAL_LO,
            held: BTreeSet::new(),
            sandbox_id: 0,
            inbound: 0,
            inbound_port: EPHEMERAL_LO,
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
    /// Sockets connected (or connecting) to a host stream.
    pub(crate) fn host_links(&self) -> usize {
        self.sockets
            .slots
            .iter()
            .flatten()
            .filter(|s| matches!(s.link(), Some(Link::Host(_))))
            .count()
    }

    pub(crate) fn contains(&self, id: SockId) -> bool {
        self.sockets.slots.get(id).is_some_and(|s| s.is_some())
    }

    pub(crate) fn get(&self, id: SockId) -> &Socket {
        self.sockets.get(id)
    }

    /// `accept` is about to install `id` in an fd: the fd becomes a second
    /// owner while the accept queue still holds the first, so a failed
    /// install leaves the connection queued.
    pub(crate) fn add_owner(&mut self, id: SockId) {
        self.sockets.get_mut(id).owners += 1;
    }

    /// `accept` removed `id` from its queue after the fd was installed: the
    /// queue's ownership ends without freeing the socket.
    pub(crate) fn drop_queue_owner(&mut self, id: SockId) {
        let sock = self.sockets.get_mut(id);
        debug_assert!(sock.owners > 1);
        sock.owners = sock.owners.saturating_sub(1).max(1);
    }

    pub(crate) fn get_mut(&mut self, id: SockId) -> &mut Socket {
        self.sockets.get_mut(id)
    }

    /// A new socket owned by one open-file description.
    pub(crate) fn create(&mut self, domain: Domain, proto: Proto) -> Result<SockId, Errno> {
        self.sockets.insert(Socket::new(domain, proto))
    }

    /// Hands out the next address from `198.51.100.1`–`198.51.100.254`
    /// without a name (a test hook: with an egress proxy, a flow to it is
    /// refused because it names no host). Never returns a NIC address, a
    /// loopback address, `0.0.0.0`, or anything in `198.18.0.0/15`. `None`
    /// when the pool is exhausted.
    pub fn issue_fake_ip(&mut self) -> Option<[u8; 4]> {
        self.next_ip().map(u32::to_be_bytes)
    }

    fn next_ip(&mut self) -> Option<u32> {
        if self.next_fake > 254 {
            return None;
        }
        let ip = FAKE_NET | self.next_fake;
        self.next_fake += 1;
        debug_assert!(is_issued_shape(ip));
        self.issued.insert(ip);
        Some(ip)
    }

    /// The fake IP bound to `name` (a valid hostname) at time `now`,
    /// binding one on first use: the next free address, or the one of the
    /// name unused longest if that is at least [`NAME_IDLE`]. `None` when
    /// neither exists.
    pub(crate) fn bind_name(&mut self, name: &str, now: Duration) -> Option<u32> {
        if let Some(&ip) = self.names.get(name) {
            self.last_used.insert(ip, now);
            return Some(ip);
        }
        let ip = match self.next_ip() {
            Some(ip) => ip,
            None => self.recycle_name(now)?,
        };
        self.names.insert(name.to_string(), ip);
        self.by_ip.insert(ip, name.to_string());
        self.last_used.insert(ip, now);
        Some(ip)
    }

    /// Unbinds the name unused longest, if for at least [`NAME_IDLE`], and
    /// returns its fake IP (which stays issued).
    fn recycle_name(&mut self, now: Duration) -> Option<u32> {
        let (&ip, &last) = self.last_used.iter().min_by_key(|(_, &last)| last)?;
        if now.saturating_sub(last) < NAME_IDLE {
            return None;
        }
        self.last_used.remove(&ip);
        if let Some(old) = self.by_ip.remove(&ip) {
            self.names.remove(&old);
        }
        Some(ip)
    }

    /// Records a connect to `ip` at `now`, which keeps its name bound.
    pub(crate) fn touch_name(&mut self, ip: u32, now: Duration) {
        if let Some(last) = self.last_used.get_mut(&ip) {
            *last = now;
        }
    }

    /// The name virtual DNS bound to `ip`, if any.
    pub(crate) fn name_of(&self, ip: u32) -> Option<&str> {
        self.by_ip.get(&ip).map(String::as_str)
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

    /// Next free ephemeral port for `(ip, proto)`, or `EADDRINUSE`. "Free"
    /// uses the same rule as an explicit `bind`, so a wildcard socket never
    /// shares a port with a specific-address socket.
    pub(crate) fn alloc_ephemeral(&mut self, ip: u32, proto: Proto) -> Result<u16, Errno> {
        let start = self.ephemeral;
        loop {
            let port = self.ephemeral;
            self.ephemeral = if port == EPHEMERAL_HI {
                EPHEMERAL_LO
            } else {
                port + 1
            };
            if !self.bind_conflicts(ip, port, proto) {
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

    /// Queues an inbound connection (ingress) on the stream `stream` to
    /// guest port `port`: on the TCP listener of `192.0.2.2:port` or
    /// `0.0.0.0:port`, as an accepted socket connected to the stream, whose
    /// peer is `192.0.2.1` on the next port of the ephemeral range. Returns
    /// whether it was queued: not when no such listener exists (one bound
    /// to loopback only does not take it), its backlog is full, or
    /// [`MAX_INBOUND`] are open.
    pub fn queue_inbound(&mut self, port: u16, stream: HostStreamId) -> bool {
        if port == 0 || self.inbound >= MAX_INBOUND {
            return false;
        }
        let Some(listener) = self.find_listener(GUEST_IP, port) else {
            return false;
        };
        let l = self.sockets.get(listener);
        if l.queue.len() >= l.backlog.max(1) {
            return false;
        }
        let peer_port = self.inbound_port;
        self.inbound_port = if peer_port >= EPHEMERAL_HI {
            EPHEMERAL_LO
        } else {
            peer_port + 1
        };
        let Ok(accepted) = self.spawn_accepted(GUEST_IP, port, GATEWAY_IP, peer_port) else {
            return false;
        };
        let sock = self.sockets.get_mut(accepted);
        sock.phase = Phase::Connected(Link::Host(stream));
        sock.inbound = true;
        self.inbound += 1;
        self.sockets.get_mut(listener).queue.push_back(accepted);
        true
    }

    /// Inbound connections open now.
    pub fn inbound_open(&self) -> usize {
        self.inbound
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
        if sock.inbound {
            self.inbound = self.inbound.saturating_sub(1);
        }
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
            // Drop the raw slot id. The survivor stays connected (`Gone`)
            // so poll and the one accepted write still work, but a later
            // socket that reuses this slot is a different connection.
            if peer_sock.link() == Some(Link::Socket(id)) {
                peer_sock.phase = Phase::Connected(Link::Gone);
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

const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_NOTIMP: u16 = 4;
const RCODE_REFUSED: u16 = 5;
const QTYPE_A: u16 = 1;
const QCLASS_IN: u16 = 1;

/// The one question of a query.
struct Question {
    /// Lowercased, if it is a hostname the egress path accepts.
    name: Option<String>,
    qtype: u16,
    qclass: u16,
    /// Offset just past the question.
    end: usize,
}

impl Net {
    /// Virtual DNS: the reply to one query message, or `None` when `query`
    /// is not a query worth answering (shorter than a header, or a
    /// response).
    ///
    /// With `outbound` false (no egress proxy), every well-formed `IN`
    /// query is NXDOMAIN. With it:
    ///
    /// * `A` for a hostname binds (or reuses) a fake IP and answers it,
    ///   TTL [`DNS_TTL`]; `SERVFAIL` when [`MAX_NAMES`] are bound;
    /// * any other type for a hostname, `AAAA` included, is an empty
    ///   NOERROR answer (the name exists, without such records);
    /// * a name that is not a hostname (one label, `_` or other bytes
    ///   outside letters, digits and `-`, an all-digit last label) is
    ///   NXDOMAIN.
    ///
    /// Always: a class other than `IN` is REFUSED, an opcode other than
    /// QUERY is NOTIMP, and anything but exactly one parsable question is
    /// FORMERR. The reply echoes the question as sent (so case
    /// randomization survives) and carries no additional records.
    pub(crate) fn dns_reply(
        &mut self,
        query: &[u8],
        outbound: bool,
        now: Duration,
    ) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let flags = u16::from_be_bytes([query[2], query[3]]);
        if flags & 0x8000 != 0 {
            return None;
        }
        let opcode = flags & 0x7800;
        let qd = u16::from_be_bytes([query[4], query[5]]);
        let question = if qd == 1 && opcode == 0 {
            parse_question(query)
        } else {
            None
        };
        let mut answer = None;
        let rcode = match &question {
            _ if opcode != 0 => RCODE_NOTIMP,
            None => RCODE_FORMERR,
            Some(q) if q.qclass != QCLASS_IN => RCODE_REFUSED,
            Some(_) if !outbound => RCODE_NXDOMAIN,
            Some(Question { name: None, .. }) => RCODE_NXDOMAIN,
            Some(Question {
                name: Some(name),
                qtype,
                ..
            }) => {
                if *qtype == QTYPE_A {
                    match self.bind_name(name, now) {
                        Some(ip) => {
                            answer = Some(ip);
                            0
                        }
                        None => RCODE_SERVFAIL,
                    }
                } else {
                    0
                }
            }
        };
        let mut resp = Vec::with_capacity(64);
        resp.extend_from_slice(&query[..2]);
        // QR, AA, RA, the query's opcode and RD.
        let out = 0x8000 | opcode | 0x0400 | (flags & 0x0100) | 0x0080 | rcode;
        resp.extend_from_slice(&out.to_be_bytes());
        let qdcount = u16::from(question.is_some());
        resp.extend_from_slice(&qdcount.to_be_bytes());
        resp.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes());
        resp.extend_from_slice(&[0, 0, 0, 0]);
        if let Some(q) = &question {
            resp.extend_from_slice(&query[12..q.end]);
        }
        if let Some(ip) = answer {
            // Name: a pointer to the question's name at offset 12.
            resp.extend_from_slice(&[0xC0, 12]);
            resp.extend_from_slice(&QTYPE_A.to_be_bytes());
            resp.extend_from_slice(&QCLASS_IN.to_be_bytes());
            resp.extend_from_slice(&DNS_TTL.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&ip.to_be_bytes());
        }
        Some(resp)
    }
}

/// Parses the question at offset 12. Compression pointers are not valid in
/// a query's only question.
fn parse_question(msg: &[u8]) -> Option<Question> {
    let mut i = 12;
    let mut name = Vec::new();
    loop {
        let len = *msg.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = msg.get(i..i + len)?;
        i += len;
        if !name.is_empty() {
            name.push(b'.');
        }
        name.extend(label.iter().map(u8::to_ascii_lowercase));
        if name.len() > 255 {
            return None;
        }
    }
    let tail = msg.get(i..i + 4)?;
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    let qclass = u16::from_be_bytes([tail[2], tail[3]]);
    let name = if valid_hostname(&name) {
        String::from_utf8(name).ok()
    } else {
        None
    };
    Some(Question {
        name,
        qtype,
        qclass,
        end: i + 4,
    })
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

    /// A reply at time zero.
    fn reply(net: &mut Net, query: &[u8], outbound: bool) -> Option<Vec<u8>> {
        net.dns_reply(query, outbound, Duration::ZERO)
    }

    #[test]
    fn a_full_name_table_recycles_only_idle_names() {
        let mut net = Net::default();
        let t0 = Duration::from_secs(100);
        let answer = |net: &mut Net, name: &str, now| {
            let resp = net.dns_reply(&query(1, name, 1, 1), true, now).unwrap();
            (rcode(&resp) == 0)
                .then(|| u32::from_be_bytes(resp[resp.len() - 4..].try_into().unwrap()))
        };
        let mut ips = Vec::new();
        for i in 0..MAX_NAMES {
            ips.push(answer(&mut net, &format!("h{i}.example"), t0).unwrap());
        }
        // Nothing is idle long enough yet.
        assert_eq!(answer(&mut net, "new.example", t0 + NAME_IDLE / 2), None);
        // h0 is asked for again and h1 is connected to: both stay.
        let later = t0 + NAME_IDLE;
        assert_eq!(answer(&mut net, "h0.example", later), Some(ips[0]));
        net.touch_name(ips[1], later);
        // The longest-idle name, h2, gives up its address.
        assert_eq!(answer(&mut net, "new.example", later), Some(ips[2]));
        assert_eq!(net.name_of(ips[2]), Some("new.example"));
        assert_eq!(net.name_of(ips[0]), Some("h0.example"));
        assert_eq!(net.name_of(ips[1]), Some("h1.example"));
        // h2 comes back on another idle address, not its old one.
        let again = answer(&mut net, "h2.example", later).unwrap();
        assert_ne!(again, ips[2]);
        assert_eq!(net.names.len(), MAX_NAMES);
    }

    fn query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&qclass.to_be_bytes());
        q
    }

    fn rcode(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[2], resp[3]]) & 0x000F
    }

    fn ancount(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[6], resp[7]])
    }

    #[test]
    fn without_egress_every_name_is_nxdomain() {
        let mut net = Net::default();
        let q = query(0x1234, "hi.example", 1, 1);
        let resp = reply(&mut net, &q, false).unwrap();
        assert_eq!(&resp[..2], &q[..2]);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "QR");
        assert_eq!(rcode(&resp), 3, "NXDOMAIN");
        assert_eq!(&resp[4..6], &[0, 1]);
        assert_eq!(&resp[6..12], &[0; 6]);
        assert_eq!(&resp[12..], &q[12..]);
        assert!(reply(&mut net, &[0; 4], false).is_none());
        assert!(net.issued.is_empty());
    }

    #[test]
    fn a_queries_bind_stable_fake_ips() {
        let mut net = Net::default();
        let resp = reply(&mut net, &query(7, "PyPI.org", 1, 1), true).unwrap();
        assert_eq!(rcode(&resp), 0);
        assert_eq!(ancount(&resp), 1);
        // The question is echoed as sent.
        assert!(resp.windows(4).any(|w| w == b"PyPI"));
        let ip = u32::from_be_bytes(resp[resp.len() - 4..].try_into().unwrap());
        assert!(is_issued_shape(ip));
        assert_eq!(net.name_of(ip), Some("pypi.org"));
        assert_eq!(net.classify(ip, 443, true), Class::Splice(ip));
        let again = reply(&mut net, &query(8, "pypi.org", 1, 1), true).unwrap();
        assert_eq!(&again[again.len() - 4..], &ip.to_be_bytes());
        let other = reply(&mut net, &query(9, "files.pythonhosted.org", 1, 1), true).unwrap();
        let ip2 = u32::from_be_bytes(other[other.len() - 4..].try_into().unwrap());
        assert_ne!(ip, ip2);
        assert_eq!(net.name_of(ip2), Some("files.pythonhosted.org"));
        // TTL and the pointer to the question name.
        let rr = &resp[resp.len() - 16..];
        assert_eq!(&rr[..2], &[0xC0, 12]);
        assert_eq!(u32::from_be_bytes(rr[6..10].try_into().unwrap()), DNS_TTL);
    }

    #[test]
    fn other_types_and_bad_names() {
        let mut net = Net::default();
        for qtype in [28, 65, 15, 16, 255] {
            let resp = reply(&mut net, &query(1, "pypi.org", qtype, 1), true).unwrap();
            assert_eq!((rcode(&resp), ancount(&resp)), (0, 0), "type {qtype}");
        }
        assert!(net.names.is_empty(), "only A binds a name");
        for name in ["localhost", "a_b.example", "1.2.3.4", "-a.example"] {
            let resp = reply(&mut net, &query(1, name, 1, 1), true).unwrap();
            assert_eq!(rcode(&resp), 3, "{name}");
        }
        let resp = reply(&mut net, &query(1, "pypi.org", 1, 3), true).unwrap();
        assert_eq!(rcode(&resp), 5, "CHAOS is REFUSED");
        let mut iquery = query(1, "pypi.org", 1, 1);
        iquery[2] |= 0x08;
        assert_eq!(rcode(&reply(&mut net, &iquery, true).unwrap()), 4);
        let mut two = query(1, "pypi.org", 1, 1);
        two[5] = 2;
        assert_eq!(rcode(&reply(&mut net, &two, true).unwrap()), 1);
        let mut pointer = query(1, "pypi.org", 1, 1);
        pointer[12] = 0xC0;
        assert_eq!(rcode(&reply(&mut net, &pointer, true).unwrap()), 1);
        let mut response = query(1, "pypi.org", 1, 1);
        response[2] |= 0x80;
        assert!(reply(&mut net, &response, true).is_none());
        assert!(net.names.is_empty());
    }

    #[test]
    fn the_name_table_is_bounded() {
        let mut net = Net::default();
        for i in 0..MAX_NAMES {
            let resp = reply(&mut net, &query(1, &format!("h{i}.example"), 1, 1), true).unwrap();
            assert_eq!(rcode(&resp), 0);
        }
        let resp = reply(&mut net, &query(1, "one-more.example", 1, 1), true).unwrap();
        assert_eq!(rcode(&resp), 2, "SERVFAIL when full");
        // Names already bound still answer.
        let resp = reply(&mut net, &query(1, "h3.example", 1, 1), true).unwrap();
        assert_eq!(rcode(&resp), 0);
        assert_eq!(net.issue_fake_ip(), None);
    }

    #[test]
    fn dns_garbage_never_panics() {
        let mut net = Net::default();
        let q = query(1, "pypi.org", 1, 1);
        for cut in 0..q.len() {
            let _ = reply(&mut net, &q[..cut], true);
        }
        for i in 0..q.len() {
            for v in [0u8, 0x3f, 0x40, 0xc0, 0xff] {
                let mut bad = q.clone();
                bad[i] = v;
                let _ = reply(&mut net, &bad, true);
            }
        }
    }
}
