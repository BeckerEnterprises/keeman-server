//! Statements of the owner-signed roles chain: strict reading of the
//! canonical bytes, their hash and the Ed25519 signature. The server checks
//! each new statement against its stored head and the active owners; the
//! commitment to the vault key only clients can check.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value;

use crate::types::{MAX_SAFE_INTEGER, decode_base64url, encode_base64url, is_canonical_uuid};

/// Prefix of the signed bytes; a signature never counts for another context.
pub const SIGNATURE_CONTEXT: &str = "keeman:v1:roles";
const HASH_CONTEXT: &str = "keeman:v1:roles-hash";

/// One owner of a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub user_id: String,
    pub public_key: [u8; 32],
    pub signing_key: [u8; 32],
}

/// A statement as read from its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub vault_id: String,
    pub version: i64,
    /// Hash of the previous statement; `None` exactly for version 1.
    pub previous: Option<[u8; 32]>,
    pub key_version: i64,
    pub key_commitment: [u8; 32],
    /// Ascending by `user_id`, without duplicates, never empty.
    pub owners: Vec<Owner>,
    pub signer: String,
    pub created: String,
}

impl Statement {
    pub fn owner(&self, user_id: &str) -> Option<&Owner> {
        self.owners.iter().find(|o| o.user_id == user_id)
    }
}

fn count(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .filter(|v| (1..=MAX_SAFE_INTEGER).contains(v))
}

fn key32(value: &Value) -> Option<[u8; 32]> {
    decode_base64url(value.as_str()?)?.try_into().ok()
}

fn uuid(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|s| is_canonical_uuid(s))
        .map(str::to_string)
}

/// ISO 8601 UTC with milliseconds, e.g. `2026-10-23T08:42:00.000Z`.
fn is_timestamp(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 24
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'.',
            23 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

fn owner(value: &Value) -> Option<Owner> {
    Some(Owner {
        user_id: uuid(value.get("user_id")?)?,
        public_key: key32(value.get("public_key")?)?,
        signing_key: key32(value.get("signing_key")?)?,
    })
}

/// Reads statement bytes. Every field must be valid and the bytes must be
/// exactly the canonical form, which rules out duplicate keys, other field
/// orders, unknown fields, escapes and whitespace.
pub fn parse(bytes: &[u8]) -> Option<Statement> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    if value.get("v")?.as_i64()? != 1 || value.get("type")?.as_str()? != "vault_roles" {
        return None;
    }
    let version = count(value.get("version")?)?;
    let previous = match (version, value.get("previous")?) {
        (1, Value::Null) => None,
        (1, _) => return None,
        (_, previous) => Some(key32(previous)?),
    };
    let owners: Vec<Owner> = value
        .get("owners")?
        .as_array()?
        .iter()
        .map(owner)
        .collect::<Option<_>>()?;
    if owners.is_empty() || owners.windows(2).any(|w| w[0].user_id >= w[1].user_id) {
        return None;
    }
    let created = value.get("created")?.as_str()?;
    if !is_timestamp(created) {
        return None;
    }
    let statement = Statement {
        vault_id: uuid(value.get("vault_id")?)?,
        version,
        previous,
        key_version: count(value.get("key_version")?)?,
        key_commitment: key32(value.get("key_commitment")?)?,
        owners,
        signer: uuid(value.get("signer")?)?,
        created: created.to_string(),
    };
    (encode(&statement) == bytes).then_some(statement)
}

/// The canonical bytes: ASCII JSON without whitespace in the fixed field
/// order. Every value is a UUID, Base64url, a timestamp or an integer, so
/// nothing needs escaping.
pub fn encode(s: &Statement) -> Vec<u8> {
    let previous = s.previous.map_or_else(
        || "null".to_string(),
        |h| format!("\"{}\"", encode_base64url(&h)),
    );
    let owners: Vec<String> = s
        .owners
        .iter()
        .map(|o| {
            format!(
                r#"{{"user_id":"{}","public_key":"{}","signing_key":"{}"}}"#,
                o.user_id,
                encode_base64url(&o.public_key),
                encode_base64url(&o.signing_key)
            )
        })
        .collect();
    format!(
        r#"{{"v":1,"type":"vault_roles","vault_id":"{}","version":{},"previous":{},"key_version":{},"key_commitment":"{}","owners":[{}],"signer":"{}","created":"{}"}}"#,
        s.vault_id,
        s.version,
        previous,
        s.key_version,
        encode_base64url(&s.key_commitment),
        owners.join(","),
        s.signer,
        s.created
    )
    .into_bytes()
}

fn with_context(context: &str, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(context.len() + 1 + bytes.len());
    out.extend_from_slice(context.as_bytes());
    out.push(0x00);
    out.extend_from_slice(bytes);
    out
}

/// h(S) = BLAKE2b-256("keeman:v1:roles-hash" ‖ 0x00 ‖ bytes).
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(with_context(HASH_CONTEXT, bytes)).into()
}

/// The Ed25519 signature of `signing_key` over the context and the bytes.
pub fn verify(signing_key: &[u8; 32], bytes: &[u8], signature: &[u8; 64]) -> bool {
    UnparsedPublicKey::new(&ED25519, signing_key)
        .verify(&with_context(SIGNATURE_CONTEXT, bytes), signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Statement {
        Statement {
            vault_id: "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5b01".into(),
            version: 2,
            previous: Some([1; 32]),
            key_version: 1,
            key_commitment: [2; 32],
            owners: vec![
                Owner {
                    user_id: "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a01".into(),
                    public_key: [3; 32],
                    signing_key: [4; 32],
                },
                Owner {
                    user_id: "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a02".into(),
                    public_key: [5; 32],
                    signing_key: [6; 32],
                },
            ],
            signer: "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a01".into(),
            created: "2026-10-23T08:42:00.000Z".into(),
        }
    }

    fn text() -> String {
        String::from_utf8(encode(&sample())).unwrap()
    }

    #[test]
    fn round_trip() {
        assert_eq!(parse(&encode(&sample())), Some(sample()));
        let first = Statement {
            version: 1,
            previous: None,
            ..sample()
        };
        assert!(text().contains(r#""previous":"AQEB"#));
        assert!(
            String::from_utf8(encode(&first))
                .unwrap()
                .contains(r#""version":1,"previous":null,"#)
        );
        assert_eq!(parse(&encode(&first)), Some(first));
    }

    #[test]
    fn only_the_canonical_form() {
        let t = text();
        let owners_start = t.find(r#""owners":["#).unwrap() + 10;
        let owners_end = t.find(r#"],"signer""#).unwrap();
        let owners = &t[owners_start..owners_end];
        let (first, second) = owners.split_once("},{").unwrap();
        let variants = [
            t.replace(r#"{"v":1,"#, r#"{ "v":1,"#),
            format!("{t}\n"),
            t.replace(
                r#""v":1,"type":"vault_roles""#,
                r#""type":"vault_roles","v":1"#,
            ),
            t.replace(r#""v":1,"#, r#""v":1,"v":1,"#),
            t.replace(r#""v":1,"#, r#""v":1,"note":"x","#),
            t.replace(r#""version":2"#, r#""version":2.0"#),
            t.replace(r#""vault_roles""#, r#""vault\u005froles""#),
            t.replace(r#""v":1"#, r#""v":2"#),
            t.replace(r#""version":2"#, r#""version":0"#),
            t.replace(r#""version":2"#, r#""version":1"#),
            t.replace(r#""key_version":1"#, r#""key_version":9007199254740992"#),
            t.replace(owners, &format!("{{{second},{first}}}")),
            t.replace(owners, &format!("{first}}},{first}}}")),
            t.replace(owners, ""),
            t.replace("2026-10-23T08:42:00.000Z", "2026-10-23T08:42:00Z"),
            t.replace(
                "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5b01",
                "0192B3A4-5C6D-7E8F-9A0B-1C2D3E4F5B01",
            ),
            format!("\u{feff}{t}"),
            "[]".into(),
        ];
        for variant in variants {
            assert_ne!(variant, t);
            assert!(parse(variant.as_bytes()).is_none(), "{variant}");
        }
        let previous_null = t.replace(&format!("\"{}\"", encode_base64url(&[1; 32])), "null");
        assert!(parse(previous_null.as_bytes()).is_none());
        assert!(parse(&[0xff]).is_none());
    }

    #[test]
    fn timestamps() {
        assert!(is_timestamp("2026-10-23T08:42:00.000Z"));
        assert!(!is_timestamp("2026-10-23T08:42:00.000+"));
        assert!(!is_timestamp("2026-10-23 08:42:00.000Z"));
    }
}
