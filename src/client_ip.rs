//! Client IP behind trusted proxies, truncated hints and rate-limit keys.

use std::net::{IpAddr, Ipv6Addr};

use ipnet::IpNet;

fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// The client IP: the proxy header counts only if the peer is a trusted
/// proxy; entries are read from the right, trusted ones skipped.
pub fn resolve(peer: IpAddr, forwarded: &[&str], trusted: &[IpNet]) -> IpAddr {
    let peer = canonical(peer);
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(&ip));
    if forwarded.is_empty() || !is_trusted(peer) {
        return peer;
    }
    let entries: Vec<&str> = forwarded
        .iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    let mut leftmost = peer;
    for entry in entries.iter().rev() {
        let Ok(ip) = entry.parse::<IpAddr>().map(canonical) else {
            return peer;
        };
        if !is_trusted(ip) {
            return ip;
        }
        leftmost = ip;
    }
    leftmost
}

/// `203.0.113.x` for IPv4, the /48 prefix for IPv6.
pub fn ip_hint(ip: IpAddr) -> String {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.x")
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!(
                "{}::/48",
                Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0)
                    .to_string()
                    .trim_end_matches("::")
            )
        }
    }
}

/// Rate-limit key: the full IPv4 address, or the /64 prefix for IPv6.
pub fn limit_key(ip: IpAddr) -> String {
    match canonical(ip) {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{}/64", Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|n| n.parse().unwrap()).collect()
    }

    #[test]
    fn walks_forwarded_for_from_the_right() {
        let trusted = nets(&["127.0.0.1/32", "10.0.0.0/8"]);
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolve(peer, &["198.51.100.7, 10.0.0.2"], &trusted).to_string(),
            "198.51.100.7"
        );
        assert_eq!(
            resolve(peer, &["203.0.113.1, 198.51.100.7"], &trusted).to_string(),
            "198.51.100.7"
        );
        assert_eq!(
            resolve(peer, &["10.0.0.3", "10.0.0.2"], &trusted).to_string(),
            "10.0.0.3"
        );
        assert_eq!(resolve(peer, &["garbage"], &trusted), peer);
        assert_eq!(resolve(peer, &[], &trusted), peer);
        let untrusted_peer: IpAddr = "198.51.100.9".parse().unwrap();
        assert_eq!(
            resolve(untrusted_peer, &["1.2.3.4"], &trusted),
            untrusted_peer
        );
        assert_eq!(
            resolve(
                "::ffff:127.0.0.1".parse().unwrap(),
                &["::ffff:198.51.100.7"],
                &trusted
            )
            .to_string(),
            "198.51.100.7"
        );
    }

    #[test]
    fn truncates() {
        assert_eq!(ip_hint("203.0.113.77".parse().unwrap()), "203.0.113.x");
        assert_eq!(
            ip_hint("2001:db8:85a3:1:2:3:4:5".parse().unwrap()),
            "2001:db8:85a3::/48"
        );
        assert_eq!(
            limit_key("2001:db8:85a3:1:2:3:4:5".parse().unwrap()),
            "2001:db8:85a3:1::/64"
        );
        assert_eq!(
            limit_key("::ffff:203.0.113.77".parse().unwrap()),
            "203.0.113.77"
        );
    }
}
