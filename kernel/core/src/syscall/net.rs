//! Socket syscalls. Semantics live in [`crate::net`]; this module copies
//! guest memory, parks the thread, and talks to [`crate::host::Host`].
//!
//! `send`/`recv` are not syscalls on x86_64 or aarch64: libc implements
//! them as `sendto`/`recvfrom` with a null address.
//!
//! `setsockopt` / `getsockopt` that are stored: `SO_ERROR`, `SO_REUSEADDR`,
//! `SO_TYPE`, `SO_KEEPALIVE`, `SO_SNDBUF`, `SO_RCVBUF`, `SO_ACCEPTCONN`,
//! `TCP_NODELAY`. The following are accepted and ignored so glibc and
//! CPython do not fail during socket setup: `SO_LINGER`, `SO_BROADCAST`,
//! `SO_RCVTIMEO`, `SO_SNDTIMEO`, `SO_OOBINLINE`, `SO_DONTROUTE`,
//! `SO_PRIORITY`, `SO_TIMESTAMP`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`,
//! `TCP_KEEPCNT`, `TCP_MAXSEG`, `TCP_QUICKACK`, `IP_TTL`, `IP_TOS`,
//! `IP_PKTINFO`, `IP_RECVERR`, `IP_MTU_DISCOVER`, `IP_RECVTOS`. Any other
//! option at `SOL_SOCKET`, `IPPROTO_IP` or `IPPROTO_TCP` is a silent
//! success on `setsockopt` and returns 0 from `getsockopt`. Any other level
//! is `ENOPROTOOPT`.
//!
//! Unnamed `AF_UNIX` `socketpair` (`SOCK_STREAM` and `SOCK_DGRAM`) is
//! implemented. `socket(AF_UNIX)`, and `bind`/`connect` of a path, are
//! `EAFNOSUPPORT`. Netlink is `EAFNOSUPPORT`.

use std::io;

use super::{Ctx, MAX_IO};
use crate::abi;
use crate::errno::{
    Errno, SysResult, EAFNOSUPPORT, EAGAIN, EALREADY, ECONNABORTED, ECONNREFUSED, ECONNRESET,
    EDESTADDRREQ, EFAULT, EINPROGRESS, EINVAL, EISCONN, EMSGSIZE, ENOTCONN, ENOTSOCK, ENXIO,
    EOPNOTSUPP, EPIPE, EPROTONOSUPPORT,
};
use crate::fd::{Access, FileObject, OpenFile};
use crate::host::{Host, OutboundFlow};
use crate::net::{
    dns_nxdomain, source_ip, Class, Domain, Link, Net, Phase, Proto, SockId, DGRAM_CAP, DGRAM_MAX,
    DNS_PORT, GATEWAY_IP, STREAM_CAP,
};
use crate::platform::{GuestAddr, Platform};
use crate::signal::{self, SigInfo};
use crate::task::Restart;

const AF_UNIX: i64 = 1;
const AF_INET: i64 = 2;
const AF_INET6: i64 = 10;
const AF_NETLINK: i64 = 16;

const SOCK_STREAM: i64 = 1;
const SOCK_DGRAM: i64 = 2;
const SOCK_TYPE_MASK: i64 = 0o777;

const IPPROTO_IP: i64 = 0;
const IPPROTO_TCP: i64 = 6;
const IPPROTO_UDP: i64 = 17;
const SOL_SOCKET: i64 = 1;

const SO_REUSEADDR: i64 = 2;
const SO_TYPE: i64 = 3;
const SO_ERROR: i64 = 4;
const SO_SNDBUF: i64 = 7;
const SO_RCVBUF: i64 = 8;
const SO_KEEPALIVE: i64 = 9;
const SO_ACCEPTCONN: i64 = 30;

const TCP_NODELAY: i64 = 1;

const MSG_OOB: u64 = 0x1;
const MSG_PEEK: u64 = 0x2;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_TRUNC: i32 = 0x20;

const SHUT_RD: i64 = 0;
const SHUT_WR: i64 = 1;
const SHUT_RDWR: i64 = 2;

const SIOCGIFCONF: u64 = 0x8912;
const SIOCGIFADDR: u64 = 0x8915;
/// `sizeof(struct ifreq)` on 64-bit glibc.
const IFREQ_SIZE: usize = 40;
const IFNAMSIZ: usize = 16;

/// One `recv`/`recvfrom`/`recvmsg` payload and, for UDP, its source.
type Recv = SysResult<(Vec<u8>, Option<(u32, u16)>)>;

/// Fields of a guest `msghdr` that `recvmsg` fills in.
struct MsgIn {
    iov: Vec<(GuestAddr, usize)>,
    name: GuestAddr,
    namelen: GuestAddr,
    controllen: u64,
}

/// Readiness a socket contributes to `poll` / `select`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SockPoll {
    pub readable: bool,
    pub writable: bool,
    pub err: bool,
    pub hup: bool,
    /// `POLLRDHUP`: the peer shut its write side. Reported only when the
    /// guest asked for it.
    pub rdhup: bool,
}

struct InetAddr {
    ip: u32,
    port: u16,
}

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    pub fn sys_socket(&mut self, domain: i64, ty: i64, protocol: i64) -> SysResult<u64> {
        let (domain, proto) = parse_socket(domain, ty, protocol)?;
        let id = self.st.net.create(domain, proto)?;
        let fd = self.install_sock(
            id,
            ty & abi::O_NONBLOCK as i64 != 0,
            ty & abi::O_CLOEXEC as i64 != 0,
        )?;
        Ok(fd as u64)
    }

    pub fn sys_socketpair(
        &mut self,
        domain: i64,
        ty: i64,
        protocol: i64,
        sv: GuestAddr,
    ) -> SysResult<u64> {
        // Only unnamed pairs. A later bind/connect on either end is rejected.
        if domain != AF_UNIX {
            return Err(Errno(EAFNOSUPPORT));
        }
        let (_domain, proto) = parse_socket(AF_INET, ty, protocol).map_err(|err| {
            if err == Errno(EAFNOSUPPORT) {
                Errno(EPROTONOSUPPORT)
            } else {
                err
            }
        })?;
        let probe: [u8; 8] = self.read_array(sv)?;
        self.write_mem(sv, &probe)?;
        let a = self.st.net.create(Domain::Unix, proto)?;
        let b = match self.st.net.create(Domain::Unix, proto) {
            Ok(id) => id,
            Err(err) => {
                self.finish_drop(a);
                return Err(err);
            }
        };
        self.st.net.get_mut(a).phase = Phase::Connected(Link::Socket(b));
        self.st.net.get_mut(b).phase = Phase::Connected(Link::Socket(a));
        let nonblock = ty & abi::O_NONBLOCK as i64 != 0;
        let cloexec = ty & abi::O_CLOEXEC as i64 != 0;
        let fa = match self.install_sock(a, nonblock, cloexec) {
            Ok(fd) => fd,
            Err(err) => {
                self.finish_drop(b);
                return Err(err);
            }
        };
        let fb = match self.install_sock(b, nonblock, cloexec) {
            Ok(fd) => fd,
            Err(err) => {
                self.sys_close(fa)?;
                return Err(err);
            }
        };
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&(fa as i32).to_le_bytes());
        out[4..].copy_from_slice(&(fb as i32).to_le_bytes());
        self.write_mem(sv, &out)?;
        Ok(0)
    }

    pub fn sys_bind(&mut self, fd: i64, addr: GuestAddr, addrlen: i64) -> SysResult<u64> {
        let id = self.sock_id(fd)?;
        if self.st.net.get(id).domain != Domain::Inet {
            return Err(Errno(EAFNOSUPPORT));
        }
        if self.st.net.get(id).bound {
            return Err(Errno(EINVAL));
        }
        let InetAddr { ip, port } = self.read_inet(addr, addrlen)?;
        Net::bind_errno(ip)?;
        let proto = self.st.net.get(id).proto;
        let port = if port == 0 {
            self.st.net.alloc_ephemeral(ip, proto)?
        } else if self.st.net.bind_conflicts(ip, port, proto) {
            return Err(Errno(crate::errno::EADDRINUSE));
        } else {
            port
        };
        let sock = self.st.net.get_mut(id);
        sock.local_ip = ip;
        sock.local_port = port;
        sock.bound = true;
        sock.holds_port = true;
        self.st.net.claim_port(ip, port, proto);
        Ok(0)
    }

    pub fn sys_connect(&mut self, fd: i64, addr: GuestAddr, addrlen: i64) -> SysResult<u64> {
        let id = self.sock_id(fd)?;
        let nonblock = self.sock_nonblock(fd);
        if self.st.net.get(id).domain != Domain::Inet {
            return Err(Errno(EAFNOSUPPORT));
        }
        // A failed non-blocking connect leaves `SO_ERROR`. Calling `connect`
        // again returns that error and then retries. If `SO_ERROR` was read
        // first (or a blocking host connect already returned the error), the
        // next call is `ECONNABORTED` once and the one after that retries.
        if !self.st.net.get(id).tcp_connected() {
            let pending = self.st.net.get(id).so_error;
            if pending != 0 {
                let sock = self.st.net.get_mut(id);
                sock.so_error = 0;
                sock.connect_failed = false;
                return Err(Errno(pending));
            }
            if self.st.net.get(id).connect_failed {
                self.st.net.get_mut(id).connect_failed = false;
                return Err(Errno(ECONNABORTED));
            }
        }
        if matches!(self.st.net.get(id).phase, Phase::Connecting(_)) {
            if self.parked.is_some() {
                return self.drive_host_connect(id, nonblock);
            }
            return Err(Errno(EALREADY));
        }
        if self.st.net.get(id).tcp_connected() || self.st.net.get(id).udp_remote.is_some() {
            return Err(Errno(EISCONN));
        }
        if self.st.net.get(id).listening() {
            return Err(Errno(EINVAL));
        }
        let InetAddr { mut ip, port } = self.read_inet(addr, addrlen)?;
        if port == 0 && self.st.net.get(id).proto == Proto::Tcp {
            return Err(Errno(ECONNREFUSED));
        }
        let tcp = self.st.net.get(id).proto == Proto::Tcp;
        let class = self.st.net.classify(ip, port, tcp);
        if let Class::Local(normalized) = class {
            ip = normalized;
        }
        // Classification failures are synchronous for blocking and
        // non-blocking sockets. `ECONNREFUSED` from a missing listener is
        // the exception and is handled in `connect_local`.
        if let Some(err) = class.errno() {
            return Err(Errno(err));
        }
        match class {
            Class::Dns => self.connect_dns(id, ip, port, nonblock),
            Class::Local(_) if tcp => self.connect_local(id, ip, port, nonblock),
            Class::Local(_) => self.connect_udp(id, ip, port),
            Class::Splice(_) => self.connect_splice(id, ip, port, nonblock),
            Class::Refused | Class::HostUnreach | Class::NetUnreach => unreachable!("errno set"),
        }
    }

    pub fn sys_listen(&mut self, fd: i64, backlog: i64) -> SysResult<u64> {
        let id = self.sock_id(fd)?;
        let sock = self.st.net.get(id);
        if sock.domain != Domain::Inet || sock.proto != Proto::Tcp {
            return Err(Errno(EOPNOTSUPP));
        }
        if sock.tcp_connected() || matches!(sock.phase, Phase::Connecting(_)) {
            return Err(Errno(EINVAL));
        }
        if !sock.bound {
            let port = self.st.net.alloc_ephemeral(0, Proto::Tcp)?;
            let sock = self.st.net.get_mut(id);
            sock.local_ip = 0;
            sock.local_port = port;
            sock.bound = true;
            sock.holds_port = true;
            self.st.net.claim_port(0, port, Proto::Tcp);
        }
        let sock = self.st.net.get_mut(id);
        sock.backlog = Net::clamp_backlog(backlog);
        sock.phase = Phase::Listening;
        Ok(0)
    }

    pub fn sys_accept4(
        &mut self,
        fd: i64,
        addr: GuestAddr,
        addrlen: GuestAddr,
        flags: i64,
    ) -> SysResult<u64> {
        if flags & !(abi::O_CLOEXEC as i64 | abi::O_NONBLOCK as i64) != 0 {
            return Err(Errno(EINVAL));
        }
        let id = self.sock_id(fd)?;
        if !self.st.net.get(id).listening() {
            return Err(Errno(EINVAL));
        }
        let nonblock = self.sock_nonblock(fd);
        if self.st.net.get(id).queue.is_empty() {
            if nonblock || self.timed_out() {
                return Err(Errno(EAGAIN));
            }
            return Err(self.park_retry(None, Restart::IfSaRestart));
        }
        let child = self.st.net.get_mut(id).queue.pop_front().expect("queued");
        let (ip, port) = {
            let child = self.st.net.get(child);
            (child.remote_ip, child.remote_port)
        };
        let newfd = self.install_sock(
            child,
            flags & abi::O_NONBLOCK as i64 != 0,
            flags & abi::O_CLOEXEC as i64 != 0,
        )?;
        self.write_inet_out(addr, addrlen, ip, port)?;
        self.st.changed = true;
        Ok(newfd as u64)
    }

    pub fn sys_shutdown(&mut self, fd: i64, how: i64) -> SysResult<u64> {
        let id = self.sock_id(fd)?;
        let sock = self.st.net.get(id);
        let connected = sock.tcp_connected()
            || matches!(sock.phase, Phase::Connecting(_))
            || sock.udp_remote.is_some()
            || sock.domain == Domain::Unix
            || sock.proto == Proto::Udp;
        if !connected && !sock.listening() {
            return Err(Errno(ENOTCONN));
        }
        match how {
            SHUT_RD | SHUT_WR | SHUT_RDWR => {}
            _ => return Err(Errno(EINVAL)),
        }
        if how == SHUT_RD || how == SHUT_RDWR {
            let sock = self.st.net.get_mut(id);
            sock.shut_rd = true;
            sock.rx.clear();
            sock.dgrams.clear();
        }
        if how == SHUT_WR || how == SHUT_RDWR {
            self.shut_write(id)?;
        }
        self.st.changed = true;
        Ok(0)
    }

    pub fn sys_getsockname(
        &mut self,
        fd: i64,
        addr: GuestAddr,
        addrlen: GuestAddr,
    ) -> SysResult<u64> {
        let id = self.sock_id(fd)?;
        let sock = self.st.net.get(id);
        if sock.domain == Domain::Unix {
            return self.write_unix_out(addr, addrlen);
        }
        let (ip, port) = if sock.bound {
            (sock.local_ip, sock.local_port)
        } else {
            (0, 0)
        };
        self.write_inet_out(addr, addrlen, ip, port)?;
        Ok(0)
    }

    pub fn sys_getpeername(
        &mut self,
        fd: i64,
        addr: GuestAddr,
        addrlen: GuestAddr,
    ) -> SysResult<u64> {
        let id = self.sock_id(fd)?;
        let sock = self.st.net.get(id);
        if sock.domain == Domain::Unix {
            if !sock.tcp_connected() {
                return Err(Errno(ENOTCONN));
            }
            return self.write_unix_out(addr, addrlen);
        }
        let remote = if let Some(remote) = sock.udp_remote {
            remote
        } else if sock.tcp_connected() || matches!(sock.phase, Phase::Connecting(_)) {
            (sock.remote_ip, sock.remote_port)
        } else {
            return Err(Errno(ENOTCONN));
        };
        self.write_inet_out(addr, addrlen, remote.0, remote.1)?;
        Ok(0)
    }

    pub fn sys_getsockopt(
        &mut self,
        fd: i64,
        level: i64,
        opt: i64,
        val: GuestAddr,
        len: GuestAddr,
    ) -> SysResult<u64> {
        let id = self.sock_id(fd)?;
        self.refresh_connect(id);
        if !known_level(level) {
            return Err(Errno(crate::errno::ENOPROTOOPT));
        }
        let sock = self.st.net.get(id);
        let value = match (level, opt) {
            (SOL_SOCKET, SO_ERROR) => {
                let err = sock.so_error;
                self.st.net.get_mut(id).so_error = 0;
                err as i32
            }
            (SOL_SOCKET, SO_TYPE) => match sock.proto {
                Proto::Tcp => SOCK_STREAM as i32,
                Proto::Udp => SOCK_DGRAM as i32,
            },
            (SOL_SOCKET, SO_REUSEADDR) => i32::from(sock.reuseaddr),
            (SOL_SOCKET, SO_KEEPALIVE) => i32::from(sock.keepalive),
            (SOL_SOCKET, SO_SNDBUF) => sock.sndbuf as i32,
            (SOL_SOCKET, SO_RCVBUF) => sock.rcvbuf as i32,
            (SOL_SOCKET, SO_ACCEPTCONN) => i32::from(sock.listening()),
            (IPPROTO_TCP, TCP_NODELAY) => i32::from(sock.nodelay),
            _ => 0,
        };
        self.write_opt_int(val, len, value)
    }

    pub fn sys_setsockopt(
        &mut self,
        fd: i64,
        level: i64,
        opt: i64,
        val: GuestAddr,
        len: i64,
    ) -> SysResult<u64> {
        let id = self.sock_id(fd)?;
        if !known_level(level) {
            return Err(Errno(crate::errno::ENOPROTOOPT));
        }
        // Stored when the option is one we honour; every other option at a
        // known level succeeds without changing behaviour (see the module
        // comment). A short buffer is still `EINVAL`, as on Linux.
        if matches!(
            (level, opt),
            (
                SOL_SOCKET,
                SO_REUSEADDR | SO_KEEPALIVE | SO_SNDBUF | SO_RCVBUF
            ) | (IPPROTO_TCP, TCP_NODELAY)
        ) {
            if len < 4 {
                return Err(Errno(EINVAL));
            }
            let raw = i32::from_le_bytes(self.read_array(val)?);
            let sock = self.st.net.get_mut(id);
            match (level, opt) {
                (SOL_SOCKET, SO_REUSEADDR) => sock.reuseaddr = raw != 0,
                (SOL_SOCKET, SO_KEEPALIVE) => sock.keepalive = raw != 0,
                (SOL_SOCKET, SO_SNDBUF) => sock.sndbuf = raw.unsigned_abs().max(2048),
                (SOL_SOCKET, SO_RCVBUF) => sock.rcvbuf = raw.unsigned_abs().max(2048),
                (IPPROTO_TCP, TCP_NODELAY) => sock.nodelay = raw != 0,
                _ => {}
            }
        }
        Ok(0)
    }

    pub fn sys_sendto(
        &mut self,
        fd: i64,
        buf: GuestAddr,
        len: u64,
        flags: u64,
        addr: GuestAddr,
        addrlen: i64,
    ) -> SysResult<u64> {
        if flags & MSG_OOB != 0 {
            return Err(Errno(EOPNOTSUPP));
        }
        let id = self.sock_id(fd)?;
        let len = (len as usize).min(MAX_IO);
        let data = if len == 0 {
            Vec::new()
        } else {
            self.read_mem(buf, len)?
        };
        let dest = if addr == 0 {
            None
        } else {
            Some(self.read_inet(addr, addrlen)?)
        };
        self.socket_send(id, &data, flags, dest).map(|n| n as u64)
    }

    pub fn sys_recvfrom(
        &mut self,
        fd: i64,
        buf: GuestAddr,
        len: u64,
        flags: u64,
        addr: GuestAddr,
        addrlen: GuestAddr,
    ) -> SysResult<u64> {
        if flags & MSG_OOB != 0 {
            return Err(Errno(EOPNOTSUPP));
        }
        let id = self.sock_id(fd)?;
        let len = (len as usize).min(MAX_IO);
        if len > 0 {
            self.probe_writable(buf)?;
        }
        let (data, src) = self.socket_recv(id, len, flags)?;
        let n = self.write_mem_prefix(buf, &data);
        if n < data.len() && flags & MSG_PEEK == 0 && self.st.net.get(id).proto == Proto::Tcp {
            // A stream short copy must not drop the tail.
            let rest = &data[n..];
            self.st
                .net
                .get_mut(id)
                .rx
                .extend(rest.iter().rev().copied());
            // extend at the back would reorder; put the tail back at the front.
            let sock = self.st.net.get_mut(id);
            for _ in 0..rest.len() {
                sock.rx.pop_back();
            }
            for &byte in rest.iter().rev() {
                sock.rx.push_front(byte);
            }
        }
        if n == 0 && !data.is_empty() {
            return Err(Errno(EFAULT));
        }
        if let Some((ip, port)) = src {
            self.write_inet_out(addr, addrlen, ip, port)?;
        }
        Ok(n as u64)
    }

    pub fn sys_sendmsg(&mut self, fd: i64, msg: GuestAddr, flags: u64) -> SysResult<u64> {
        let (dest, data) = self.read_msg_out(msg)?;
        let id = self.sock_id(fd)?;
        self.socket_send(id, &data, flags, dest).map(|n| n as u64)
    }

    pub fn sys_recvmsg(&mut self, fd: i64, msg: GuestAddr, flags: u64) -> SysResult<u64> {
        let MsgIn {
            iov,
            name,
            namelen,
            controllen,
        } = self.read_msg_in(msg)?;
        let total: usize = iov.iter().map(|(_, len)| *len).sum();
        let id = self.sock_id(fd)?;
        let (data, src) = self.socket_recv(id, total.min(MAX_IO), flags)?;
        let mut off = 0;
        for (base, len) in iov {
            if off >= data.len() {
                break;
            }
            let n = (data.len() - off).min(len);
            let wrote = self.write_mem_prefix(base, &data[off..off + n]);
            off += wrote;
            if wrote < n {
                break;
            }
        }
        if off < data.len() && flags & MSG_PEEK == 0 && self.st.net.get(id).proto == Proto::Tcp {
            let rest = data[off..].to_vec();
            for &byte in rest.iter().rev() {
                self.st.net.get_mut(id).rx.push_front(byte);
            }
        }
        if let Some((ip, port)) = src {
            self.write_inet_out(name, namelen, ip, port)?;
        }
        // No control messages in 002a.
        if controllen != 0 {
            self.write_u64(msg + 40, 0)?;
        }
        let mut out_flags = 0i32;
        if self.st.net.get(id).proto == Proto::Udp && data.len() > off {
            out_flags |= MSG_TRUNC;
        }
        self.write_mem(msg + 48, &out_flags.to_le_bytes())?;
        Ok(off as u64)
    }

    /// `read` on a socket.
    pub(crate) fn socket_read(&mut self, id: SockId, len: usize) -> SysResult<Vec<u8>> {
        let (data, _) = self.socket_recv(id, len, 0)?;
        Ok(data)
    }

    /// `write` on a socket. `SIGPIPE` is delivered on `EPIPE`.
    pub(crate) fn socket_write(&mut self, id: SockId, data: &[u8]) -> SysResult<usize> {
        self.socket_send(id, data, 0, None)
    }

    pub(crate) fn socket_readable_len(&mut self, id: SockId) -> usize {
        self.refresh_connect(id);
        let sock = self.st.net.get(id);
        if sock.proto == Proto::Udp {
            sock.dgrams.front().map(|d| d.data.len()).unwrap_or(0)
        } else {
            sock.rx.len()
        }
    }

    pub(crate) fn socket_poll(&mut self, id: SockId) -> SockPoll {
        self.refresh_connect(id);
        let sock = self.st.net.get(id);
        if sock.proto == Proto::Udp {
            return SockPoll {
                readable: !sock.dgrams.is_empty() || sock.shut_rd || sock.peer_fin,
                writable: !sock.shut_wr,
                err: sock.so_error != 0 || sock.peer_reset,
                // `POLLHUP` is a reset, not a bare FIN.
                hup: sock.peer_reset,
                rdhup: sock.peer_fin,
            };
        }
        if sock.listening() {
            return SockPoll {
                readable: !sock.queue.is_empty(),
                ..SockPoll::default()
            };
        }
        // Non-blocking connect that was refused: Linux reports
        // `POLLIN|POLLOUT|POLLERR|POLLHUP` (0x1d).
        if sock.so_error != 0 && !sock.tcp_connected() {
            return SockPoll {
                readable: true,
                writable: true,
                err: true,
                hup: true,
                rdhup: false,
            };
        }
        if matches!(sock.phase, Phase::Connecting(_)) {
            return SockPoll::default();
        }
        // A fresh TCP socket is `POLLOUT|POLLHUP`. A socket whose peer has
        // gone stays in `Connected` (see `Net::drop_owner`) so this is not
        // that case: `peer_fin` stays visible.
        if !sock.tcp_connected() && sock.domain == Domain::Inet && !sock.peer_fin {
            return SockPoll {
                writable: true,
                hup: true,
                ..SockPoll::default()
            };
        }
        let writable = !sock.shut_wr
            && match sock.link() {
                Some(Link::Socket(peer)) if self.st.net.contains(peer) => {
                    self.st.net.get(peer).rx_space() > 0
                }
                Some(Link::Socket(_)) => true,
                Some(Link::Host(stream)) => self
                    .host
                    .stream_status(stream)
                    .map(|status| status.writable && !status.broken)
                    .unwrap_or(true),
                Some(Link::Dns) => self.st.net.get(id).dns_in.len() < 16 * 1024,
                // Peer is already gone: Linux still reports `POLLOUT` until
                // `SHUT_WR`.
                Some(Link::Gone) | None => true,
            };
        let sock = self.st.net.get(id);
        SockPoll {
            // A drained FIN still reads as EOF, so `POLLIN` stays set.
            readable: !sock.rx.is_empty() || sock.peer_fin || sock.peer_reset || sock.shut_rd,
            writable,
            // `POLLERR` for a reset that was not produced by the one write
            // Linux accepts after a clean close.
            err: sock.so_error != 0 || (sock.peer_reset && !sock.post_fin_write),
            hup: sock.peer_reset || (sock.shut_wr && sock.peer_fin),
            rdhup: sock.peer_fin || sock.peer_reset,
        }
    }

    /// Interface ioctls on a socket. `None` if `request` is not one of them.
    pub(crate) fn socket_ioctl(&mut self, request: u64, arg: GuestAddr) -> Option<SysResult<u64>> {
        match request & 0xffff_ffff {
            SIOCGIFCONF => Some(self.ioctl_ifconf(arg)),
            SIOCGIFADDR => Some(self.ioctl_ifaddr(arg)),
            _ => None,
        }
    }

    pub(crate) fn finish_drop(&mut self, id: SockId) {
        if !self.st.net.contains(id) {
            return;
        }
        let dropped = self.st.net.drop_owner(id);
        if let Some(stream) = dropped.host {
            self.host.stream_close(stream);
        }
        let resets = dropped.reset;
        let children = dropped.children;
        for peer in resets {
            if self.st.net.detach_queued(peer) {
                self.finish_drop(peer);
            }
        }
        for child in children {
            self.finish_drop(child);
        }
        self.st.changed = true;
    }

    // ----- connect paths -----

    fn fail_connect(&mut self, id: SockId, err: i64, nonblock: bool) -> SysResult<u64> {
        // Classification failures are immediate on blocking and non-blocking
        // sockets. A refused in-kernel connect (no listener, full backlog)
        // matches Linux: blocking returns the error, non-blocking returns
        // `EINPROGRESS` and `SO_ERROR` carries it.
        let deferred = nonblock && (err == ECONNREFUSED);
        if deferred {
            let sock = self.st.net.get_mut(id);
            sock.so_error = err;
            sock.connect_failed = true;
            Err(Errno(EINPROGRESS))
        } else {
            Err(Errno(err))
        }
    }

    fn connect_udp(&mut self, id: SockId, ip: u32, port: u16) -> SysResult<u64> {
        self.ensure_local(id, source_ip(ip))?;
        let sock = self.st.net.get_mut(id);
        sock.udp_remote = Some((ip, port));
        sock.remote_ip = ip;
        sock.remote_port = port;
        Ok(0)
    }

    fn connect_dns(&mut self, id: SockId, ip: u32, port: u16, nonblock: bool) -> SysResult<u64> {
        if self.st.net.get(id).proto == Proto::Udp {
            return self.connect_udp(id, GATEWAY_IP, port);
        }
        self.ensure_local(id, source_ip(ip))?;
        let sock = self.st.net.get_mut(id);
        sock.remote_ip = GATEWAY_IP;
        sock.remote_port = DNS_PORT;
        sock.phase = Phase::Connected(Link::Dns);
        self.st.changed = true;
        if nonblock && self.parked.is_none() {
            Err(Errno(EINPROGRESS))
        } else {
            Ok(0)
        }
    }

    fn connect_local(&mut self, id: SockId, ip: u32, port: u16, nonblock: bool) -> SysResult<u64> {
        let Some(listener) = self.st.net.find_listener(ip, port) else {
            return self.fail_connect(id, ECONNREFUSED, nonblock);
        };
        if self.st.net.get(listener).queue.len() >= self.st.net.get(listener).backlog.max(1) {
            return self.fail_connect(id, ECONNREFUSED, nonblock);
        }
        self.ensure_local(id, source_ip(ip))?;
        let (lip, lport) = {
            let sock = self.st.net.get(id);
            (sock.local_ip, sock.local_port)
        };
        let accepted = self.st.net.spawn_accepted(ip, port, lip, lport)?;
        self.st.net.get_mut(accepted).phase = Phase::Connected(Link::Socket(id));
        self.st.net.get_mut(id).remote_ip = ip;
        self.st.net.get_mut(id).remote_port = port;
        self.st.net.get_mut(id).phase = Phase::Connected(Link::Socket(accepted));
        self.st.net.get_mut(listener).queue.push_back(accepted);
        self.st.changed = true;
        if nonblock && self.parked.is_none() {
            Err(Errno(EINPROGRESS))
        } else {
            Ok(0)
        }
    }

    fn connect_splice(&mut self, id: SockId, ip: u32, port: u16, nonblock: bool) -> SysResult<u64> {
        if !self.host.egress_configured() {
            return Err(Errno(crate::errno::ENETUNREACH));
        }
        self.ensure_local(id, source_ip(ip))?;
        let flow = OutboundFlow {
            sandbox_id: 0,
            guest_pid: self.pid,
            dest_ip: ip.to_be_bytes(),
            dest_port: port,
        };
        // `dest_ip` is audit metadata. The host dials only its configured
        // endpoint (002b: the egress Unix socket).
        let waker = self.plat.waker();
        let stream = match self.host.open_stream(flow, waker) {
            Ok(id) => id,
            Err(_) => return Err(Errno(crate::errno::ENETUNREACH)),
        };
        let sock = self.st.net.get_mut(id);
        sock.remote_ip = ip;
        sock.remote_port = port;
        sock.phase = Phase::Connecting(Link::Host(stream));
        self.drive_host_connect(id, nonblock)
    }

    fn drive_host_connect(&mut self, id: SockId, nonblock: bool) -> SysResult<u64> {
        let Some(Link::Host(stream)) = self.st.net.get(id).link() else {
            return Err(Errno(ENOTCONN));
        };
        match self.host.stream_connect_result(stream) {
            Ok(()) => {
                self.st.net.get_mut(id).phase = Phase::Connected(Link::Host(stream));
                self.st.changed = true;
                if nonblock && self.parked.is_none() {
                    Err(Errno(EINPROGRESS))
                } else {
                    Ok(0)
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if nonblock {
                    Err(Errno(EINPROGRESS))
                } else {
                    Err(self.park_retry(None, Restart::IfSaRestart))
                }
            }
            Err(err) => {
                self.host.stream_close(stream);
                let errno = io_errno(&err);
                let sock = self.st.net.get_mut(id);
                sock.phase = Phase::Open;
                sock.connect_failed = true;
                if nonblock && self.parked.is_none() {
                    sock.so_error = errno.0;
                    Err(Errno(EINPROGRESS))
                } else {
                    Err(errno)
                }
            }
        }
    }

    /// Observes a finished non-blocking connect so `poll` and `SO_ERROR` see it.
    fn refresh_connect(&mut self, id: SockId) {
        let Some(Link::Host(stream)) = self.st.net.get(id).link() else {
            return;
        };
        if !matches!(self.st.net.get(id).phase, Phase::Connecting(_)) {
            return;
        }
        match self.host.stream_connect_result(stream) {
            Ok(()) => {
                self.st.net.get_mut(id).phase = Phase::Connected(Link::Host(stream));
                self.st.changed = true;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => {
                self.host.stream_close(stream);
                let sock = self.st.net.get_mut(id);
                sock.phase = Phase::Open;
                sock.connect_failed = true;
                sock.so_error = io_errno(&err).0;
            }
        }
    }

    fn ensure_local(&mut self, id: SockId, ip: u32) -> SysResult<()> {
        let sock = self.st.net.get(id);
        let proto = sock.proto;
        if sock.bound && sock.local_port != 0 {
            if sock.local_ip == 0 {
                if self.st.net.port_busy(ip, sock.local_port, proto) {
                    return Err(Errno(crate::errno::EADDRINUSE));
                }
                let port = sock.local_port;
                self.st.net.release_port(0, port, proto);
                self.st.net.claim_port(ip, port, proto);
                let sock = self.st.net.get_mut(id);
                sock.local_ip = ip;
            }
            return Ok(());
        }
        let port = self.st.net.alloc_ephemeral(ip, proto)?;
        let sock = self.st.net.get_mut(id);
        sock.local_ip = ip;
        sock.local_port = port;
        sock.bound = true;
        sock.holds_port = true;
        self.st.net.claim_port(ip, port, proto);
        Ok(())
    }

    // ----- transfer -----

    fn socket_send(
        &mut self,
        id: SockId,
        data: &[u8],
        flags: u64,
        dest: Option<InetAddr>,
    ) -> SysResult<usize> {
        self.refresh_connect(id);
        let nonblock = self.sock_nonblock_id(id) || flags & MSG_DONTWAIT != 0;
        let nosignal = flags & MSG_NOSIGNAL != 0;
        let sock = self.st.net.get(id);
        if sock.listening() {
            return Err(Errno(EINVAL));
        }
        let broken = sock.peer_reset || sock.shut_wr;
        if broken {
            return self.epipe(nosignal);
        }
        if sock.domain == Domain::Unix {
            if sock.proto == Proto::Udp {
                let Some(Link::Socket(peer)) = sock.link() else {
                    return Err(Errno(ENOTCONN));
                };
                if data.len() > DGRAM_MAX {
                    return Err(Errno(EMSGSIZE));
                }
                self.enqueue_dgram(peer, 0, 0, data.to_vec(), nonblock)?;
                return Ok(data.len());
            }
            return self.send_stream(id, data, nonblock, nosignal);
        }
        if sock.proto == Proto::Udp {
            return self.send_udp(id, data, dest, nonblock, nosignal);
        }
        if dest.is_some() && sock.domain == Domain::Inet && !sock.tcp_connected() {
            return Err(Errno(ENOTCONN));
        }
        if !sock.tcp_connected() {
            if matches!(sock.phase, Phase::Connecting(_)) {
                return if nonblock {
                    Err(Errno(EAGAIN))
                } else {
                    Err(self.park_retry(None, Restart::IfSaRestart))
                };
            }
            return Err(Errno(ENOTCONN));
        }
        // A blocking stream send waits until every byte is queued, as Linux
        // `send` does. `MSG_DONTWAIT` and `O_NONBLOCK` may return a short count.
        if nonblock || data.is_empty() {
            let n = self.send_stream(id, data, nonblock, nosignal)?;
            if n > 0 {
                self.arm_reset_after_clean_close(id);
            }
            return Ok(n);
        }
        let tid = self.tid;
        let mut done = if self.parked.is_some() {
            self.st.thread(tid).io_done.min(data.len())
        } else {
            0
        };
        while done < data.len() {
            match self.send_stream(id, &data[done..], false, nosignal) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(err) if self.action.is_some() => {
                    self.st.thread_mut(tid).io_done = done;
                    return Err(err);
                }
                // Some bytes of this call were queued. The error (and
                // `SIGPIPE`, if it was posted) belongs to the next call.
                Err(_) if done > 0 => break,
                Err(err) => {
                    self.st.thread_mut(tid).io_done = 0;
                    return Err(err);
                }
            }
        }
        self.st.thread_mut(tid).io_done = 0;
        if done > 0 {
            self.arm_reset_after_clean_close(id);
        }
        Ok(done)
    }

    /// After the one write Linux accepts following a clean peer close, the
    /// next write is `EPIPE` and `poll` reports `POLLHUP`.
    fn arm_reset_after_clean_close(&mut self, id: SockId) {
        let sock = self.st.net.get(id);
        let dead = match sock.link() {
            Some(Link::Gone) => true,
            Some(Link::Socket(peer)) => !self.st.net.contains(peer),
            _ => false,
        };
        if dead && sock.peer_fin && !sock.peer_reset {
            let sock = self.st.net.get_mut(id);
            sock.post_fin_write = true;
            sock.peer_reset = true;
        }
    }

    fn send_udp(
        &mut self,
        id: SockId,
        data: &[u8],
        dest: Option<InetAddr>,
        nonblock: bool,
        nosignal: bool,
    ) -> SysResult<usize> {
        if data.len() > DGRAM_MAX {
            return Err(Errno(EMSGSIZE));
        }
        let sock = self.st.net.get(id);
        if sock.shut_wr || sock.peer_reset {
            return self.epipe(nosignal);
        }
        let (ip, port) = if let Some(InetAddr { ip, port }) = dest {
            if sock.udp_remote.is_some() {
                return Err(Errno(EISCONN));
            }
            (ip, port)
        } else if let Some(remote) = sock.udp_remote {
            remote
        } else {
            return Err(Errno(EDESTADDRREQ));
        };
        let mut ip = ip;
        let class = self.st.net.classify(ip, port, false);
        if let Class::Local(normalized) = class {
            ip = normalized;
        }
        if let Some(err) = class.errno() {
            return Err(Errno(err));
        }
        let source_ip = if self.st.net.get(id).bound && self.st.net.get(id).local_ip != 0 {
            self.st.net.get(id).local_ip
        } else {
            source_ip(ip)
        };
        self.ensure_local(id, source_ip)?;
        let (src_ip, src_port) = {
            let sock = self.st.net.get(id);
            (sock.local_ip, sock.local_port)
        };
        match class {
            Class::Dns => {
                if let Some(reply) = dns_nxdomain(data) {
                    self.enqueue_dgram(id, GATEWAY_IP, DNS_PORT, reply, nonblock)?;
                }
                Ok(data.len())
            }
            Class::Local(_) => {
                if let Some(dst) = self.st.net.find_udp(ip, port) {
                    if dst != id {
                        self.enqueue_dgram(dst, src_ip, src_port, data.to_vec(), nonblock)?;
                    }
                }
                Ok(data.len())
            }
            _ => unreachable!("classified"),
        }
    }

    fn enqueue_dgram(
        &mut self,
        id: SockId,
        src_ip: u32,
        src_port: u16,
        data: Vec<u8>,
        nonblock: bool,
    ) -> SysResult<()> {
        let sock = self.st.net.get(id);
        if sock.dgrams.len() >= DGRAM_CAP {
            return if nonblock || self.timed_out() {
                Err(Errno(EAGAIN))
            } else {
                Err(self.park_retry(None, Restart::IfSaRestart))
            };
        }
        self.st.net.get_mut(id).dgrams.push_back(crate::net::Dgram {
            src_ip,
            src_port,
            data,
        });
        self.st.changed = true;
        Ok(())
    }

    fn send_stream(
        &mut self,
        id: SockId,
        data: &[u8],
        nonblock: bool,
        nosignal: bool,
    ) -> SysResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let sock = self.st.net.get(id);
        if sock.shut_wr || sock.peer_reset {
            return self.epipe(nosignal);
        }
        match sock.link() {
            Some(Link::Gone) => {
                let sock = self.st.net.get(id);
                if sock.peer_fin && !sock.peer_reset && !sock.post_fin_write {
                    return Ok(data.len());
                }
                self.st.net.get_mut(id).peer_reset = true;
                self.epipe(nosignal)
            }
            Some(Link::Socket(peer)) => {
                if !self.st.net.contains(peer) {
                    let sock = self.st.net.get(id);
                    // Clean FIN: this write is accepted and discarded. The
                    // caller marks the socket so the next write is `EPIPE`.
                    if sock.peer_fin && !sock.peer_reset && !sock.post_fin_write {
                        return Ok(data.len());
                    }
                    self.st.net.get_mut(id).peer_reset = true;
                    return self.epipe(nosignal);
                }
                if self.st.net.get(peer).peer_reset {
                    self.st.net.get_mut(id).peer_reset = true;
                    return self.epipe(nosignal);
                }
                let space = self.st.net.get(peer).rx_space();
                if space == 0 {
                    return if nonblock || self.timed_out() {
                        Err(Errno(EAGAIN))
                    } else {
                        Err(self.park_retry(None, Restart::IfSaRestart))
                    };
                }
                let n = data.len().min(space);
                self.st.net.get_mut(peer).rx.extend(&data[..n]);
                self.st.changed = true;
                Ok(n)
            }
            Some(Link::Host(stream)) => match self.host.stream_write(stream, data) {
                Ok(0) if !data.is_empty() => {
                    self.st.net.get_mut(id).peer_reset = true;
                    self.epipe(nosignal)
                }
                Ok(n) => Ok(n),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if nonblock || self.timed_out() {
                        Err(Errno(EAGAIN))
                    } else {
                        Err(self.park_retry(None, Restart::IfSaRestart))
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    self.st.net.get_mut(id).peer_reset = true;
                    self.st.net.get_mut(id).peer_fin = true;
                    self.epipe(nosignal)
                }
                Err(err) => Err(io_errno(&err)),
            },
            Some(Link::Dns) => {
                if self.st.net.get(id).dns_in.len() + data.len() > 16 * 1024 {
                    return Err(Errno(EMSGSIZE));
                }
                self.st.net.get_mut(id).dns_in.extend(data);
                self.drain_dns(id);
                Ok(data.len())
            }
            None => Err(Errno(ENOTCONN)),
        }
    }

    fn drain_dns(&mut self, id: SockId) {
        loop {
            let buf = &self.st.net.get(id).dns_in;
            if buf.len() < 2 {
                return;
            }
            let need = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() < 2 + need {
                return;
            }
            let query = buf[2..2 + need].to_vec();
            let sock = self.st.net.get_mut(id);
            sock.dns_in.drain(..2 + need);
            if let Some(reply) = dns_nxdomain(&query) {
                let len = (reply.len() as u16).to_be_bytes();
                sock.rx.extend(len);
                sock.rx.extend(reply);
            }
            self.st.changed = true;
        }
    }

    fn socket_recv(&mut self, id: SockId, len: usize, flags: u64) -> Recv {
        self.refresh_connect(id);
        let nonblock = self.sock_nonblock_id(id) || flags & MSG_DONTWAIT != 0;
        let peek = flags & MSG_PEEK != 0;
        let sock = self.st.net.get(id);
        if sock.listening() {
            return Err(Errno(EINVAL));
        }
        if sock.proto == Proto::Udp {
            return self.recv_udp(id, len, peek, nonblock);
        }
        if sock.shut_rd {
            return Ok((Vec::new(), None));
        }
        if !sock.rx.is_empty() {
            let n = len.min(sock.rx.len());
            let data: Vec<u8> = if peek {
                sock.rx.iter().take(n).copied().collect()
            } else {
                self.st.net.get_mut(id).rx.drain(..n).collect()
            };
            if !peek {
                self.st.changed = true;
            }
            return Ok((data, None));
        }
        let sock = self.st.net.get(id);
        if sock.peer_reset {
            return Err(Errno(ECONNRESET));
        }
        if sock.peer_fin {
            return Ok((Vec::new(), None));
        }
        if !sock.tcp_connected() {
            if matches!(sock.phase, Phase::Connecting(_)) {
                return if nonblock || self.timed_out() {
                    Err(Errno(EAGAIN))
                } else {
                    Err(self.park_retry(None, Restart::IfSaRestart))
                };
            }
            return Err(Errno(ENOTCONN));
        }
        // Host streams: pull anything the reader thread has buffered.
        if let Some(Link::Host(stream)) = sock.link() {
            let mut buf = vec![0u8; len.min(STREAM_CAP)];
            match self.host.stream_read(stream, &mut buf) {
                Ok(0) => {
                    self.st.net.get_mut(id).peer_fin = true;
                    return Ok((Vec::new(), None));
                }
                Ok(n) => {
                    buf.truncate(n);
                    if peek {
                        // Put it back into the guest-side buffer and also
                        // return it. A later non-peek read consumes `rx`.
                        for &byte in buf.iter().rev() {
                            self.st.net.get_mut(id).rx.push_front(byte);
                        }
                    }
                    return Ok((buf, None));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    let sock = self.st.net.get_mut(id);
                    sock.peer_fin = true;
                    sock.peer_reset = true;
                    return Err(Errno(ECONNRESET));
                }
                Err(err) => return Err(io_errno(&err)),
            }
        }
        if nonblock || self.timed_out() {
            Err(Errno(EAGAIN))
        } else {
            Err(self.park_retry(None, Restart::IfSaRestart))
        }
    }

    fn recv_udp(&mut self, id: SockId, len: usize, peek: bool, nonblock: bool) -> Recv {
        let sock = self.st.net.get(id);
        if sock.shut_rd {
            return Ok((Vec::new(), None));
        }
        if sock.dgrams.is_empty() {
            if sock.peer_reset {
                return Err(Errno(ECONNRESET));
            }
            if sock.peer_fin {
                return Ok((Vec::new(), None));
            }
            return if nonblock || self.timed_out() {
                Err(Errno(EAGAIN))
            } else {
                Err(self.park_retry(None, Restart::IfSaRestart))
            };
        }
        let dgram = if peek {
            self.st.net.get(id).dgrams.front().unwrap().clone()
        } else {
            let dgram = self.st.net.get_mut(id).dgrams.pop_front().unwrap();
            self.st.changed = true;
            dgram
        };
        let n = len.min(dgram.data.len());
        Ok((
            dgram.data[..n].to_vec(),
            Some((dgram.src_ip, dgram.src_port)),
        ))
    }

    fn shut_write(&mut self, id: SockId) -> SysResult<()> {
        let sock = self.st.net.get_mut(id);
        if sock.shut_wr {
            return Ok(());
        }
        sock.shut_wr = true;
        match sock.link() {
            Some(Link::Socket(peer)) => {
                if self.st.net.contains(peer) {
                    self.st.net.get_mut(peer).peer_fin = true;
                }
            }
            Some(Link::Host(stream)) => {
                self.host.stream_shutdown_write(stream).map_err(|err| {
                    if err.kind() == io::ErrorKind::NotConnected {
                        Errno(ENOTCONN)
                    } else {
                        io_errno(&err)
                    }
                })?;
            }
            Some(Link::Dns) | Some(Link::Gone) | None => {}
        }
        Ok(())
    }

    fn epipe(&mut self, nosignal: bool) -> SysResult<usize> {
        if !nosignal {
            let info = SigInfo::kernel(signal::SIGPIPE);
            self.st.post_signal(self.pid, Some(self.tid), info);
        }
        Err(Errno(EPIPE))
    }

    // ----- guest memory -----

    fn install_sock(&mut self, id: SockId, nonblock: bool, cloexec: bool) -> SysResult<i64> {
        let mut file = OpenFile::new(FileObject::Socket(id), Access::ReadWrite);
        file.nonblock = nonblock;
        let ino = 0x10_0000 + id;
        file.path = Some(format!("socket:[{ino}]").into_bytes());
        self.install(file, 0, cloexec)
    }

    fn sock_id(&self, fd: i64) -> SysResult<SockId> {
        let (_, file) = self.file(fd)?;
        match file.object {
            FileObject::Socket(id) => Ok(id),
            _ => Err(Errno(ENOTSOCK)),
        }
    }

    fn sock_nonblock(&self, fd: i64) -> bool {
        self.file(fd).map(|(_, f)| f.nonblock).unwrap_or(false)
    }

    fn sock_nonblock_id(&self, id: SockId) -> bool {
        self.st
            .files
            .iter()
            .any(|(_, f)| matches!(f.object, FileObject::Socket(sock) if sock == id) && f.nonblock)
    }

    fn read_inet(&mut self, addr: GuestAddr, addrlen: i64) -> SysResult<InetAddr> {
        if addrlen < 2 {
            return Err(Errno(EINVAL));
        }
        let n = (addrlen as usize).min(128);
        let buf = self.read_mem(addr, n)?;
        let family = u16::from_le_bytes([buf[0], buf[1]]);
        match family as i64 {
            AF_INET => {
                if buf.len() < 8 {
                    return Err(Errno(EINVAL));
                }
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                let ip = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                Ok(InetAddr { ip, port })
            }
            AF_UNIX | AF_INET6 | AF_NETLINK => Err(Errno(EAFNOSUPPORT)),
            _ => Err(Errno(EAFNOSUPPORT)),
        }
    }

    fn write_inet_out(
        &mut self,
        addr: GuestAddr,
        addrlen: GuestAddr,
        ip: u32,
        port: u16,
    ) -> SysResult<()> {
        if addr == 0 {
            return Ok(());
        }
        let mut raw = [0u8; 16];
        raw[0..2].copy_from_slice(&u16::try_from(AF_INET).unwrap_or(2).to_le_bytes());
        raw[2..4].copy_from_slice(&port.to_be_bytes());
        raw[4..8].copy_from_slice(&ip.to_be_bytes());
        self.write_sa(addr, addrlen, &raw)
    }

    fn write_unix_out(&mut self, addr: GuestAddr, addrlen: GuestAddr) -> SysResult<u64> {
        if addr == 0 {
            return Ok(0);
        }
        let mut raw = [0u8; 2];
        raw.copy_from_slice(&1u16.to_le_bytes());
        self.write_sa(addr, addrlen, &raw)?;
        Ok(0)
    }

    fn write_sa(&mut self, addr: GuestAddr, addrlen: GuestAddr, raw: &[u8]) -> SysResult<()> {
        let room = if addrlen == 0 {
            raw.len()
        } else {
            self.read_u32(addrlen)? as usize
        };
        let n = room.min(raw.len());
        if n > 0 {
            self.write_mem(addr, &raw[..n])?;
        }
        if addrlen != 0 {
            self.write_u32(addrlen, raw.len() as u32)?;
        }
        Ok(())
    }

    fn write_opt_int(&mut self, val: GuestAddr, len_ptr: GuestAddr, value: i32) -> SysResult<u64> {
        if val == 0 || len_ptr == 0 {
            return Err(Errno(EFAULT));
        }
        let len = self.read_u32(len_ptr)? as usize;
        if len == 0 {
            return Err(Errno(EINVAL));
        }
        let bytes = value.to_le_bytes();
        self.write_mem(val, &bytes[..len.min(4)])?;
        self.write_u32(len_ptr, 4)?;
        Ok(0)
    }

    fn read_msg_out(&mut self, msg: GuestAddr) -> SysResult<(Option<InetAddr>, Vec<u8>)> {
        let hdr = self.read_mem(msg, 56)?;
        let name = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
        let namelen = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as i64;
        let iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        let iovlen = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
        let dest = if name == 0 {
            None
        } else {
            Some(self.read_inet(name, namelen)?)
        };
        let data = self.gather(iov, iovlen)?;
        Ok((dest, data))
    }

    fn read_msg_in(&mut self, msg: GuestAddr) -> SysResult<MsgIn> {
        let hdr = self.read_mem(msg, 56)?;
        let name = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
        let namelen_val = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        let iovlen = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
        let controllen = u64::from_le_bytes(hdr[40..48].try_into().unwrap());
        // `msg_namelen` is a value on the way in. Stash the pointer-sized
        // slot by writing the original length back through a fake pointer:
        // recvmsg's address length lives in the msghdr itself, at offset 8.
        // `write_inet_out` expects a pointer to a socklen_t. Point it at
        // `msg + 8` after seeding that word.
        if name != 0 {
            self.write_u32(msg + 8, namelen_val)?;
        }
        let iov = self.read_iov(iov, iovlen)?;
        let namelen = if name == 0 { 0 } else { msg + 8 };
        Ok(MsgIn {
            iov,
            name,
            namelen,
            controllen,
        })
    }

    fn gather(&mut self, iov: GuestAddr, iovlen: u64) -> SysResult<Vec<u8>> {
        let vecs = self.read_iov(iov, iovlen)?;
        let mut out = Vec::new();
        for (base, len) in vecs {
            if out.len() >= MAX_IO {
                break;
            }
            let n = len.min(MAX_IO - out.len());
            if n > 0 {
                out.extend(self.read_mem(base, n)?);
            }
        }
        Ok(out)
    }

    fn read_iov(&mut self, iov: GuestAddr, iovlen: u64) -> SysResult<Vec<(GuestAddr, usize)>> {
        const IOV_MAX: u64 = 1024;
        if iovlen > IOV_MAX {
            return Err(Errno(EINVAL));
        }
        if iovlen == 0 {
            return Ok(Vec::new());
        }
        let raw = self.read_mem(iov, iovlen as usize * 16)?;
        let mut out = Vec::with_capacity(iovlen as usize);
        for chunk in raw.chunks(16) {
            let base = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let len = u64::from_le_bytes(chunk[8..16].try_into().unwrap()) as usize;
            out.push((base, len));
        }
        Ok(out)
    }

    fn ioctl_ifconf(&mut self, arg: GuestAddr) -> SysResult<u64> {
        if arg == 0 {
            return Err(Errno(EFAULT));
        }
        let len = self.read_u32(arg)? as usize;
        let buf = self.read_u64(arg + 8)?;
        if len < IFREQ_SIZE {
            self.write_u32(arg, 0)?;
            return Ok(0);
        }
        self.write_ifreq(buf, b"eth0")?;
        self.write_u32(arg, IFREQ_SIZE as u32)?;
        Ok(0)
    }

    fn ioctl_ifaddr(&mut self, arg: GuestAddr) -> SysResult<u64> {
        if arg == 0 {
            return Err(Errno(EFAULT));
        }
        let name = self.read_mem(arg, IFNAMSIZ)?;
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        if &name[..end] != b"eth0" {
            return Err(Errno(ENXIO));
        }
        self.write_ifreq(arg, b"eth0")?;
        Ok(0)
    }

    fn write_ifreq(&mut self, addr: GuestAddr, name: &[u8]) -> SysResult<()> {
        let mut raw = vec![0u8; IFREQ_SIZE];
        raw[..name.len()].copy_from_slice(name);
        // sockaddr_in at offset 16: AF_INET, port 0, 192.0.2.2.
        raw[16..18].copy_from_slice(&2u16.to_le_bytes());
        raw[20..24].copy_from_slice(&crate::net::GUEST_IP.to_be_bytes());
        self.write_mem(addr, &raw)
    }
}

fn parse_socket(domain: i64, ty: i64, protocol: i64) -> SysResult<(Domain, Proto)> {
    let sock_type = ty & SOCK_TYPE_MASK;
    match domain {
        AF_INET6 | AF_NETLINK | AF_UNIX => return Err(Errno(EAFNOSUPPORT)),
        AF_INET => {}
        _ => return Err(Errno(EAFNOSUPPORT)),
    }
    let proto = match sock_type {
        SOCK_STREAM => Proto::Tcp,
        SOCK_DGRAM => Proto::Udp,
        _ => return Err(Errno(EPROTONOSUPPORT)),
    };
    let ok = matches!(
        (proto, protocol),
        (Proto::Tcp, 0 | IPPROTO_TCP) | (Proto::Udp, 0 | IPPROTO_UDP)
    );
    if !ok {
        return Err(Errno(EPROTONOSUPPORT));
    }
    Ok((Domain::Inet, proto))
}

fn known_level(level: i64) -> bool {
    matches!(level, SOL_SOCKET | IPPROTO_IP | IPPROTO_TCP | IPPROTO_UDP)
}

fn io_errno(err: &io::Error) -> Errno {
    use io::ErrorKind::{
        AddrNotAvailable, BrokenPipe, ConnectionRefused, ConnectionReset, NotConnected, TimedOut,
        WouldBlock,
    };
    Errno(match err.kind() {
        WouldBlock => EAGAIN,
        ConnectionRefused => ECONNREFUSED,
        ConnectionReset | BrokenPipe => crate::errno::ECONNRESET,
        TimedOut => crate::errno::ETIMEDOUT,
        AddrNotAvailable => crate::errno::EADDRNOTAVAIL,
        NotConnected => ENOTCONN,
        _ => crate::errno::EIO,
    })
}
