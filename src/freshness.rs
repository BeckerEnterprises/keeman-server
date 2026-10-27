//! Freshness attestations: by these, the devices of an account confirm the
//! state of a vault or of the user data they saw. The server reads the
//! canonical bytes strictly and checks the signature against the account's
//! registered signing key; the content only the account's clients can judge.

use serde_json::Value;

use crate::roles::{count, is_timestamp, key32, uuid, verify_in};
use crate::types::encode_base64url;

/// Prefix of the signed bytes; a signature never counts for another context.
pub const SIGNATURE_CONTEXT: &str = "keeman:v1:freshness";

/// A number and a hash: `seq` of a manifest root, or version of a roles head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub n: i64,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    Vault {
        vault_id: String,
        user_id: String,
        time: String,
        key_version: i64,
        manifest: Option<Point>,
        roles: Option<Point>,
    },
    UserData {
        user_id: String,
        time: String,
        seq: i64,
    },
}

impl Statement {
    pub fn user_id(&self) -> &str {
        match self {
            Statement::Vault { user_id, .. } | Statement::UserData { user_id, .. } => user_id,
        }
    }
}

fn point(value: &Value) -> Option<Option<Point>> {
    match value {
        Value::Null => Some(None),
        Value::Array(items) if items.len() == 2 => Some(Some(Point {
            n: count(&items[0])?,
            hash: key32(&items[1])?,
        })),
        _ => None,
    }
}

fn time(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|t| is_timestamp(t))
        .map(str::to_string)
}

/// Reads statement bytes of either type. Every field must be valid and the
/// bytes must be exactly the canonical form, which rules out duplicate keys,
/// other field orders, unknown fields, escapes and whitespace.
pub fn parse(bytes: &[u8]) -> Option<Statement> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    if value.get("v")?.as_i64()? != 1 {
        return None;
    }
    let statement = match value.get("type")?.as_str()? {
        "vault_freshness" => Statement::Vault {
            vault_id: uuid(value.get("vault_id")?)?,
            user_id: uuid(value.get("user_id")?)?,
            time: time(value.get("time")?)?,
            key_version: count(value.get("key_version")?)?,
            manifest: point(value.get("manifest")?)?,
            roles: point(value.get("roles")?)?,
        },
        "user_data_freshness" => Statement::UserData {
            user_id: uuid(value.get("user_id")?)?,
            time: time(value.get("time")?)?,
            seq: count(value.get("seq")?)?,
        },
        _ => return None,
    };
    (encode(&statement) == bytes).then_some(statement)
}

fn encode_point(point: Option<Point>) -> String {
    point.map_or_else(
        || "null".to_string(),
        |p| format!("[{},\"{}\"]", p.n, encode_base64url(&p.hash)),
    )
}

/// The canonical bytes: ASCII JSON without whitespace in the fixed field
/// order. Every value is a UUID, Base64url, a timestamp or an integer, so
/// nothing needs escaping.
pub fn encode(statement: &Statement) -> Vec<u8> {
    match statement {
        Statement::Vault {
            vault_id,
            user_id,
            time,
            key_version,
            manifest,
            roles,
        } => format!(
            r#"{{"v":1,"type":"vault_freshness","vault_id":"{vault_id}","user_id":"{user_id}","time":"{time}","key_version":{key_version},"manifest":{},"roles":{}}}"#,
            encode_point(*manifest),
            encode_point(*roles),
        ),
        Statement::UserData { user_id, time, seq } => format!(
            r#"{{"v":1,"type":"user_data_freshness","user_id":"{user_id}","time":"{time}","seq":{seq}}}"#
        ),
    }
    .into_bytes()
}

/// The Ed25519 signature of `signing_key` over the freshness context and
/// the bytes.
pub fn verify(signing_key: &[u8; 32], bytes: &[u8], signature: &[u8; 64]) -> bool {
    verify_in(SIGNATURE_CONTEXT, signing_key, bytes, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5b01";
    const USER: &str = "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a01";

    fn vault() -> Statement {
        Statement::Vault {
            vault_id: VAULT.into(),
            user_id: USER.into(),
            time: "2026-10-27T08:42:00.000Z".into(),
            key_version: 3,
            manifest: Some(Point {
                n: 57,
                hash: [1; 32],
            }),
            roles: None,
        }
    }

    #[test]
    fn round_trip() {
        assert_eq!(parse(&encode(&vault())), Some(vault()));
        let user_data = Statement::UserData {
            user_id: USER.into(),
            time: "2026-10-27T08:42:00.000Z".into(),
            seq: 9,
        };
        assert_eq!(parse(&encode(&user_data)), Some(user_data));
        let text = String::from_utf8(encode(&vault())).unwrap();
        assert!(text.contains(r#""manifest":[57,"AQEB"#));
        assert!(text.ends_with(r#""roles":null}"#));
    }

    #[test]
    fn only_the_canonical_form() {
        let t = String::from_utf8(encode(&vault())).unwrap();
        let variants = [
            t.replace(r#"{"v":1,"#, r#"{ "v":1,"#),
            format!("{t}\n"),
            t.replace(r#""v":1,"#, r#""v":1,"v":1,"#),
            t.replace(r#""v":1,"#, r#""v":1,"note":"x","#),
            t.replace(r#""key_version":3"#, r#""key_version":3.0"#),
            t.replace(r#""key_version":3"#, r#""key_version":0"#),
            t.replace(r#""manifest":[57,"#, r#""manifest":[0,"#),
            t.replace(r#""roles":null"#, r#""roles":[]"#),
            t.replace("vault_freshness", "vault_roles"),
            t.replace(VAULT, &VAULT.to_uppercase()),
            t.replace("08:42:00.000Z", "08:42:00Z"),
            format!("\u{feff}{t}"),
            "[]".into(),
        ];
        for variant in variants {
            assert_ne!(variant, t);
            assert!(parse(variant.as_bytes()).is_none(), "{variant}");
        }
    }
}
