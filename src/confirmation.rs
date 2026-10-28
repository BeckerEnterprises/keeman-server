//! Answers to a confirmation request: another device of the account signs
//! its marks together with the nonce of the requesting device. The server
//! reads the canonical bytes strictly and checks the signature against the
//! account's registered signing key; the content only the requesting device
//! judges.

use serde_json::Value;

use crate::roles::{is_timestamp, key32, uuid, verify_in};
use crate::types::{decode_base64url, encode_base64url};

/// Prefix of the signed bytes; a signature never counts for another context.
pub const SIGNATURE_CONTEXT: &str = "keeman:v1:device-confirmation";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub user_id: String,
    pub nonce: [u8; 32],
    pub time: String,
    /// The JSON content as signed; never empty.
    pub content: Vec<u8>,
}

/// Reads answer bytes. Every field must be valid and the bytes must be
/// exactly the canonical form, which rules out duplicate keys, other field
/// orders, unknown fields, escapes and whitespace.
pub fn parse(bytes: &[u8]) -> Option<Statement> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    if value.get("v")?.as_i64()? != 1 || value.get("type")?.as_str()? != "device_confirmation" {
        return None;
    }
    let time = value.get("time")?.as_str()?;
    if !is_timestamp(time) {
        return None;
    }
    let content = decode_base64url(value.get("content")?.as_str()?)?;
    if content.is_empty() {
        return None;
    }
    let statement = Statement {
        user_id: uuid(value.get("user_id")?)?,
        nonce: key32(value.get("nonce")?)?,
        time: time.to_string(),
        content,
    };
    (encode(&statement) == bytes).then_some(statement)
}

/// The canonical bytes: ASCII JSON without whitespace in the fixed field
/// order. Every value is a UUID, Base64url or a timestamp, so nothing needs
/// escaping.
pub fn encode(s: &Statement) -> Vec<u8> {
    format!(
        r#"{{"v":1,"type":"device_confirmation","user_id":"{}","nonce":"{}","time":"{}","content":"{}"}}"#,
        s.user_id,
        encode_base64url(&s.nonce),
        s.time,
        encode_base64url(&s.content)
    )
    .into_bytes()
}

/// The Ed25519 signature of `signing_key` over the confirmation context and
/// the bytes.
pub fn verify(signing_key: &[u8; 32], bytes: &[u8], signature: &[u8; 64]) -> bool {
    verify_in(SIGNATURE_CONTEXT, signing_key, bytes, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a01";

    fn sample() -> Statement {
        Statement {
            user_id: USER.into(),
            nonce: [7; 32],
            time: "2026-10-28T08:42:00.000Z".into(),
            content: br#"{"schema":1,"user_data":null,"vaults":{}}"#.to_vec(),
        }
    }

    #[test]
    fn round_trip() {
        assert_eq!(parse(&encode(&sample())), Some(sample()));
        let text = String::from_utf8(encode(&sample())).unwrap();
        assert!(text.starts_with(r#"{"v":1,"type":"device_confirmation","user_id":""#));
        assert!(text.contains(&format!(r#""nonce":"{}""#, encode_base64url(&[7; 32]))));
    }

    #[test]
    fn only_the_canonical_form() {
        let t = String::from_utf8(encode(&sample())).unwrap();
        let nonce = encode_base64url(&[7; 32]);
        let content = encode_base64url(&sample().content);
        let variants = [
            t.replace(r#"{"v":1,"#, r#"{ "v":1,"#),
            format!("{t}\n"),
            t.replace(r#""v":1,"#, r#""v":1,"v":1,"#),
            t.replace(r#""v":1,"#, r#""v":1,"note":"x","#),
            t.replace(r#""v":1,"#, r#""v":2,"#),
            t.replace("device_confirmation", "vault_freshness"),
            t.replace(USER, &USER.to_uppercase()),
            t.replace(&nonce, &encode_base64url(&[7; 31])),
            t.replace(&nonce, &format!("{nonce}=")),
            t.replace(&content, ""),
            t.replace(&content, &format!("{content}=")),
            t.replace("08:42:00.000Z", "08:42:00Z"),
            t.replace(
                r#","time":"2026-10-28T08:42:00.000Z""#,
                r#","time":"2026-10-28T08:42:00.000Z","time":"2026-10-28T08:42:00.000Z""#,
            ),
            format!("\u{feff}{t}"),
            "[]".into(),
        ];
        for variant in variants {
            assert_ne!(variant, t);
            assert!(parse(variant.as_bytes()).is_none(), "{variant}");
        }
    }
}
