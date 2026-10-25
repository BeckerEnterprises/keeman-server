//! Addresses the favicon proxy must never connect to: an own
//! list, not just `is_private()`. IPv6 outside 2000::/3 is blocked, except
//! the prefixes with an embedded IPv4 address, which decides for them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Decides which resolved or literal addresses may be fetched from.
/// Production uses [`Blocklist`]; tests may allow their local server.
pub trait Policy: Send + Sync + 'static {
    fn allows(&self, ip: IpAddr) -> bool;
}

/// The fixed list of blocked ranges.
pub struct Blocklist;

impl Policy for Blocklist {
    fn allows(&self, ip: IpAddr) -> bool {
        !is_blocked(ip)
    }
}

const BLOCKED_V4: &[([u8; 4], u32)] = &[
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 88, 99, 0], 24),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
];

/// Blocked ranges inside 2000::/3.
const BLOCKED_V6: &[([u16; 8], u32)] = &[
    // Teredo
    ([0x2001, 0, 0, 0, 0, 0, 0, 0], 32),
    // Benchmarking
    ([0x2001, 0x2, 0, 0, 0, 0, 0, 0], 48),
    // ORCHID and ORCHIDv2
    ([0x2001, 0x10, 0, 0, 0, 0, 0, 0], 28),
    ([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
    // Documentation
    ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
    ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
];

pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => blocked_v6(v6),
    }
}

fn blocked_v4(ip: Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    BLOCKED_V4.iter().any(|&(net, prefix)| {
        let mask = u32::MAX << (32 - prefix);
        bits & mask == u32::from_be_bytes(net) & mask
    })
}

fn blocked_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return blocked_v4(v4);
    }
    let bits = u128::from(ip);
    if bits >> 125 != 0b001 {
        return true;
    }
    BLOCKED_V6.iter().any(|&(net, prefix)| {
        let mask = u128::MAX << (128 - prefix);
        bits & mask == u128::from(Ipv6Addr::from(net)) & mask
    })
}

/// The IPv4 address in `::ffff:0:0/96`, `64:ff9b::/96` or `2002::/16`.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let bits = u128::from(ip);
    match bits >> 32 {
        0xffff | 0x0064_ff9b_0000_0000_0000_0000 => Some(Ipv4Addr::from(bits as u32)),
        _ if bits >> 112 == 0x2002 => Some(Ipv4Addr::from((bits >> 80) as u32)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(text: &str) -> bool {
        is_blocked(text.parse().unwrap())
    }

    #[test]
    fn every_ipv4_range_with_its_neighbours() {
        let cases = [
            ("0.0.0.0", true),
            ("0.255.255.255", true),
            ("1.0.0.0", false),
            ("9.255.255.255", false),
            ("10.0.0.0", true),
            ("10.255.255.255", true),
            ("11.0.0.0", false),
            ("100.63.255.255", false),
            ("100.64.0.0", true),
            ("100.127.255.255", true),
            ("100.128.0.0", false),
            ("126.255.255.255", false),
            ("127.0.0.0", true),
            ("127.255.255.255", true),
            ("128.0.0.0", false),
            ("169.253.255.255", false),
            ("169.254.0.0", true),
            ("169.254.255.255", true),
            ("169.255.0.0", false),
            ("172.15.255.255", false),
            ("172.16.0.0", true),
            ("172.31.255.255", true),
            ("172.32.0.0", false),
            ("191.255.255.255", false),
            ("192.0.0.0", true),
            ("192.0.0.255", true),
            ("192.0.1.0", false),
            ("192.0.1.255", false),
            ("192.0.2.0", true),
            ("192.0.2.255", true),
            ("192.0.3.0", false),
            ("192.88.98.255", false),
            ("192.88.99.0", true),
            ("192.88.99.255", true),
            ("192.88.100.0", false),
            ("192.167.255.255", false),
            ("192.168.0.0", true),
            ("192.168.255.255", true),
            ("192.169.0.0", false),
            ("198.17.255.255", false),
            ("198.18.0.0", true),
            ("198.19.255.255", true),
            ("198.20.0.0", false),
            ("198.51.99.255", false),
            ("198.51.100.0", true),
            ("198.51.100.255", true),
            ("198.51.101.0", false),
            ("203.0.112.255", false),
            ("203.0.113.0", true),
            ("203.0.113.255", true),
            ("203.0.114.0", false),
            ("223.255.255.255", false),
            ("224.0.0.0", true),
            ("239.255.255.255", true),
            ("240.0.0.0", true),
            ("255.255.255.255", true),
            ("8.8.8.8", false),
            ("1.1.1.1", false),
            ("93.184.215.14", false),
        ];
        for (ip, expected) in cases {
            assert_eq!(blocked(ip), expected, "{ip}");
        }
    }

    #[test]
    fn ipv6_outside_global_unicast_is_blocked() {
        for ip in [
            "::",
            "::1",
            "::7f00:1",
            "::808:808",
            "100::1",
            "100::ffff:ffff:ffff:ffff",
            "64:ff9b:1::1",
            "fc00::1",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe80::1",
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "ff02::1",
            "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "4000::",
            "5f00::1",
        ] {
            assert!(blocked(ip), "{ip}");
        }
    }

    #[test]
    fn every_ipv6_range_inside_global_unicast_with_its_neighbours() {
        let cases = [
            ("2000::", false),
            ("2001::", true),
            ("2001:0:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:1::", false),
            ("2001:1::1", false),
            ("2001:2::", true),
            ("2001:2:0:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:2:1::", false),
            ("2001:f:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:10::", true),
            ("2001:1f:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:20::", true),
            ("2001:2f:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:30::", false),
            ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:db8::", true),
            ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:db9::", false),
            ("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("3fff::", true),
            ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("3fff:1000::", false),
            ("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2606:4700:4700::1111", false),
            ("2001:4860:4860::8888", false),
            ("2a00:1450:4001:80b::200e", false),
        ];
        for (ip, expected) in cases {
            assert_eq!(blocked(ip), expected, "{ip}");
        }
    }

    #[test]
    fn embedded_ipv4_decides() {
        let cases = [
            ("::ffff:127.0.0.1", true),
            ("::ffff:10.1.2.3", true),
            ("::ffff:8.8.8.8", false),
            ("64:ff9b::10.0.0.1", true),
            ("64:ff9b::169.254.169.254", true),
            ("64:ff9b::8.8.8.8", false),
            ("2002:7f00:1::", true),
            ("2002:c0a8:101::1", true),
            ("2002:a9fe:a9fe::", true),
            ("2002:808:808::", false),
        ];
        for (ip, expected) in cases {
            assert_eq!(blocked(ip), expected, "{ip}");
        }
    }

    #[test]
    fn the_blocklist_policy_follows_the_list() {
        assert!(!Blocklist.allows("127.0.0.1".parse().unwrap()));
        assert!(Blocklist.allows("8.8.8.8".parse().unwrap()));
    }
}
