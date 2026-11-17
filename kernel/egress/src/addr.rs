//! Addresses the proxy never dials, whatever a name resolves to.
//!
//! IPv4: `0.0.0.0/8`, `10/8`, `100.64/10` (CGNAT), `127/8`, `169.254/16`
//! (link-local, including the cloud metadata address `169.254.169.254`),
//! `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.168/16`, `198.18/15`,
//! `198.51.100/24` (also the sandbox fake-IP pool), `203.0.113/24`,
//! `224/4` (multicast) and `240/4` (reserved and broadcast).
//!
//! IPv6: only global unicast `2000::/3` passes, minus `2001::/23` (Teredo
//! and other IETF special use), `2001:db8::/32` (documentation) and
//! `2002::/16` (6to4, which embeds an IPv4 address). That excludes `::`,
//! `::1`, link-local, unique-local, multicast, and IPv4-mapped addresses.
//! A mapped `::ffff:a.b.c.d` is not dialed even when `a.b.c.d` would pass.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const V4_BLOCKS: [(u32, u32, &str); 15] = [
    (0x0000_0000, 8, "this-network"),
    (0x0A00_0000, 8, "private"),
    (0x6440_0000, 10, "cgnat"),
    (0x7F00_0000, 8, "loopback"),
    (0xA9FE_A9FE, 32, "metadata"),
    (0xA9FE_0000, 16, "link-local"),
    (0xAC10_0000, 12, "private"),
    (0xC000_0000, 24, "special"),
    (0xC000_0200, 24, "documentation"),
    (0xC0A8_0000, 16, "private"),
    (0xC612_0000, 15, "benchmarking"),
    (0xC633_6400, 24, "documentation"),
    (0xCB00_7100, 24, "documentation"),
    (0xE000_0000, 4, "multicast"),
    (0xF000_0000, 4, "reserved"),
];

/// Why `ip` must not be dialed, or `None` when it may be.
pub fn blocked(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => blocked_v6(v6),
    }
}

fn blocked_v4(ip: Ipv4Addr) -> Option<&'static str> {
    let ip = u32::from(ip);
    V4_BLOCKS.iter().find_map(|&(base, bits, why)| {
        let mask = u32::MAX << (32 - bits);
        (ip & mask == base & mask).then_some(why)
    })
}

fn blocked_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let s = ip.segments();
    if ip.to_ipv4_mapped().is_some() {
        return Some("ipv4-mapped");
    }
    if s[0] & 0xE000 != 0x2000 {
        return Some(if ip.is_loopback() {
            "loopback"
        } else if ip.is_unspecified() {
            "this-network"
        } else if s[0] & 0xFF00 == 0xFF00 {
            "multicast"
        } else if s[0] & 0xFFC0 == 0xFE80 {
            "link-local"
        } else if s[0] & 0xFE00 == 0xFC00 {
            "private"
        } else {
            "reserved"
        });
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return Some("documentation");
    }
    if s[0] == 0x2001 && s[1] < 0x0200 {
        return Some("special");
    }
    if s[0] == 0x2002 {
        return Some("6to4");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Option<&'static str> {
        blocked(s.parse().unwrap())
    }

    #[test]
    fn blocked_v4_ranges() {
        for (ip, why) in [
            ("0.0.0.0", "this-network"),
            ("10.1.2.3", "private"),
            ("100.64.0.1", "cgnat"),
            ("100.127.255.255", "cgnat"),
            ("127.0.0.1", "loopback"),
            ("169.254.169.254", "metadata"),
            ("169.254.1.1", "link-local"),
            ("172.16.0.1", "private"),
            ("172.31.255.255", "private"),
            ("192.168.65.7", "private"),
            ("192.0.2.1", "documentation"),
            ("198.51.100.7", "documentation"),
            ("198.18.0.1", "benchmarking"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "reserved"),
        ] {
            assert_eq!(b(ip), Some(why), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "151.101.0.223",
            "140.82.112.3",
            "100.128.0.1",
            "172.32.0.1",
            "169.253.0.1",
        ] {
            assert_eq!(b(ip), None, "{ip}");
        }
    }

    #[test]
    fn blocked_v6_ranges() {
        for ip in [
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "ff02::1",
            "::ffff:1.1.1.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2001:db8::1",
            "2001::1",
            "2002:a9fe:a9fe::1",
        ] {
            assert!(b(ip).is_some(), "{ip}");
        }
        for ip in ["2606:4700::1111", "2a04:4e42::223", "2001:4860::8888"] {
            assert_eq!(b(ip), None, "{ip}");
        }
    }
}
