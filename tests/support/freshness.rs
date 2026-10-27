//! Freshness attestations for tests: built with the server's own encoding
//! and signed with the test accounts' Ed25519 keys.

use keeman_server::freshness::{Point, Statement, encode};
use keeman_server::types::encode_base64url;
use ring::signature::Ed25519KeyPair;
use serde_json::{Value, json};

use super::Account;
use super::roles::rand32;

pub const TIME: &str = "2026-10-27T08:42:00.000Z";

/// An attestation of `account` for a vault at key version 1.
pub fn vault(account: &Account, vault_id: &str) -> Statement {
    Statement::Vault {
        vault_id: vault_id.to_string(),
        user_id: account.user_id.clone(),
        time: TIME.to_string(),
        key_version: 1,
        manifest: Some(Point {
            n: 1,
            hash: rand32(),
        }),
        roles: None,
    }
}

/// An attestation of `account` for its user data.
pub fn user_data(account: &Account, seq: i64) -> Statement {
    Statement::UserData {
        user_id: account.user_id.clone(),
        time: TIME.to_string(),
        seq,
    }
}

/// `{statement, signature}` of exactly these bytes, signed by `account` in
/// the given context.
pub fn sign_in(account: &Account, context: &str, bytes: &[u8]) -> Value {
    let pair = Ed25519KeyPair::from_seed_unchecked(&account.signing_seed).unwrap();
    let mut message = context.as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(bytes);
    json!({
        "statement": encode_base64url(bytes),
        "signature": encode_base64url(pair.sign(&message).as_ref()),
    })
}

pub fn sign_bytes(account: &Account, bytes: &[u8]) -> Value {
    sign_in(account, "keeman:v1:freshness", bytes)
}

pub fn signed(account: &Account, statement: &Statement) -> Value {
    sign_bytes(account, &encode(statement))
}
