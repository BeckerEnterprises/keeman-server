//! URLs the favicon proxy may fetch: `http` or
//! `https`, no user info, port none, 80 or 443, and an IP host that the
//! policy allows. Parsing follows WHATWG, so `0x7f.1` is an IPv4 address.

use std::net::IpAddr;

use url::{Host, Url};

use super::policy::Policy;

/// Whether `url` may be fetched; names are checked later by the resolver.
pub fn allowed(url: &Url, policy: &dyn Policy) -> bool {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.port(), None | Some(80) | Some(443))
    {
        return false;
    }
    match url.host() {
        Some(Host::Domain(_)) => true,
        Some(Host::Ipv4(ip)) => policy.allows(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => policy.allows(IpAddr::V6(ip)),
        None => false,
    }
}

/// The page to fetch for a requested URL and its origin, or `None` for
/// `400 url_not_allowed`.
pub fn input(text: &str, policy: &dyn Policy) -> Option<(Url, String)> {
    let url = Url::parse(text).ok()?;
    if !allowed(&url, policy) {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    let page = Url::parse(&format!("{origin}/")).ok()?;
    Some((page, origin))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::favicon::policy::Blocklist;

    fn input_of(text: &str) -> Option<(String, String)> {
        input(text, &Blocklist).map(|(page, origin)| (page.to_string(), origin))
    }

    #[test]
    fn reduces_to_the_origin() {
        assert_eq!(
            input_of("https://www.example.com/login?next=/x#top"),
            Some((
                "https://www.example.com/".into(),
                "https://www.example.com".into()
            ))
        );
        assert_eq!(
            input_of("http://Example.COM:443/a"),
            Some((
                "http://example.com:443/".into(),
                "http://example.com:443".into()
            ))
        );
        assert_eq!(
            input_of("https://example.com:443"),
            Some(("https://example.com/".into(), "https://example.com".into()))
        );
        assert_eq!(
            input_of("https://bücher.example/"),
            Some((
                "https://xn--bcher-kva.example/".into(),
                "https://xn--bcher-kva.example".into()
            ))
        );
    }

    #[test]
    fn rejects_what_the_url_itself_forbids() {
        for text in [
            "",
            "example.com",
            "/favicon.ico",
            "ftp://example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:image/png;base64,AAAA",
            "https://user@example.com/",
            "https://user:pw@example.com/",
            "https://:pw@example.com/",
            "https://example.com:8080/",
            "http://example.com:22/",
            "http://127.0.0.1/",
            "http://127.1/",
            "http://0x7f.0.0.1/",
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://0/",
            "http://10.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:7f00:1]/",
            "http://[64:ff9b::a00:1]/",
            "http://[2002:7f00:1::]/",
            "http://[fe80::1]/",
            "http://[fd00::1]/",
        ] {
            assert_eq!(input_of(text), None, "{text}");
        }
    }

    #[test]
    fn public_literals_and_names_pass() {
        assert!(input_of("http://8.8.8.8/").is_some());
        assert!(input_of("https://[2606:4700:4700::1111]/").is_some());
        assert!(input_of("https://localhost/").is_some());
    }

    #[test]
    fn targets_keep_their_path() {
        let url = Url::parse("https://cdn.example.com/static/icon.png").unwrap();
        assert!(allowed(&url, &Blocklist));
        let url = Url::parse("http://192.168.1.1/favicon.ico").unwrap();
        assert!(!allowed(&url, &Blocklist));
    }
}
