//! The refresh cookie of web clients.

use axum::http::{HeaderMap, header};

pub fn name(dev_mode: bool) -> &'static str {
    if dev_mode {
        "keeman_rt"
    } else {
        "__Host-keeman_rt"
    }
}

pub fn set(name: &str, token: &str, max_age_seconds: u64) -> String {
    format!("{name}={token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age_seconds}")
}

pub fn clear(name: &str) -> String {
    format!("{name}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// The value of the first cookie with this name, if any.
pub fn read(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn reads_the_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("a=1; __Host-keeman_rt=abc"),
        );
        headers.append(header::COOKIE, HeaderValue::from_static("keeman_rt=dev"));
        assert_eq!(read(&headers, "__Host-keeman_rt").as_deref(), Some("abc"));
        assert_eq!(read(&headers, "keeman_rt").as_deref(), Some("dev"));
        assert_eq!(read(&headers, "missing"), None);
        assert_eq!(
            set("n", "t", 60),
            "n=t; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=60"
        );
    }
}
