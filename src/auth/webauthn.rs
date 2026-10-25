//! The WebAuthn relying party for passkeys as second factor, built once from
//! `[webauthn]`.

use webauthn_rs::prelude::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::config::WebauthnSection;

/// The relying party for passkeys as second factor: exact origins from
/// `rp_origins`, no subdomains, no other ports.
pub fn relying_party(config: &WebauthnSection) -> Result<Webauthn, String> {
    let parse = |origin: &str| {
        Url::parse(origin).map_err(|_| format!("webauthn.rp_origins: {origin} is not a URL"))
    };
    let (first, rest) = config
        .rp_origins
        .split_first()
        .ok_or("webauthn.rp_origins must not be empty")?;
    let first = parse(first)?;
    let mut builder = WebauthnBuilder::new(&config.rp_id, &first)
        .map_err(|e| format!("webauthn: {e}"))?
        .rp_name(&config.rp_name);
    for origin in rest {
        builder = builder.append_allowed_origin(&parse(origin)?);
    }
    builder.build().map_err(|e| format!("webauthn: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(rp_id: &str, origins: &[&str]) -> WebauthnSection {
        WebauthnSection {
            rp_id: rp_id.into(),
            rp_name: "KeeMan".into(),
            rp_origins: origins.iter().map(|o| o.to_string()).collect(),
        }
    }

    #[test]
    fn builds_for_production_and_local_development() {
        let production = section("app.example.org", &["https://app.example.org"]);
        assert!(relying_party(&production).is_ok());
        let local = section(
            "localhost",
            &["http://localhost:5173", "http://localhost:4173"],
        );
        assert!(relying_party(&local).is_ok());
    }

    #[test]
    fn rejects_mismatched_or_missing_origins() {
        assert!(relying_party(&section("app.example.org", &["https://example.net"])).is_err());
        assert!(relying_party(&section("app.example.org", &[])).is_err());
    }
}
