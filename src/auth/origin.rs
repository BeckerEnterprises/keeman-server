//! `Origin` check of `refresh` and `logout`.

use axum::http::{HeaderMap, header};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// No `Origin` header (native clients).
    Absent,
    Allowed,
    /// Not in the allowlist, `null`, or more than one header.
    Forbidden,
}

pub fn check(headers: &HeaderMap, allowed: &[String]) -> Origin {
    let mut values = headers.get_all(header::ORIGIN).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return if headers.contains_key(header::ORIGIN) {
            Origin::Forbidden
        } else {
            Origin::Absent
        };
    };
    match value.to_str() {
        Ok(origin) if allowed.iter().any(|a| a == origin) => Origin::Allowed,
        _ => Origin::Forbidden,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn checks_against_the_allowlist() {
        let allowed = vec!["https://app.example.org".to_string()];
        let mut headers = HeaderMap::new();
        assert_eq!(check(&headers, &allowed), Origin::Absent);
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://app.example.org"),
        );
        assert_eq!(check(&headers, &allowed), Origin::Allowed);
        headers.append(
            header::ORIGIN,
            HeaderValue::from_static("https://app.example.org"),
        );
        assert_eq!(check(&headers, &allowed), Origin::Forbidden);
        headers.insert(header::ORIGIN, HeaderValue::from_static("null"));
        assert_eq!(check(&headers, &allowed), Origin::Forbidden);
    }
}
