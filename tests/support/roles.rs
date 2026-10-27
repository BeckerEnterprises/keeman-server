//! Statements of the roles chain for tests: built with the server's own
//! encoding and signed with the test accounts' Ed25519 keys.

use keeman_server::roles::{Owner, Statement, encode, hash};
use keeman_server::types::{decode_base64url, encode_base64url};
use ring::signature::Ed25519KeyPair;
use serde_json::{Value, json};

use super::Account;

pub const CREATED: &str = "2026-10-23T08:42:00.000Z";

fn key32(text: &str) -> [u8; 32] {
    decode_base64url(text).unwrap().try_into().unwrap()
}

/// An owner entry with the keys the account registered.
pub fn owner(account: &Account) -> Owner {
    owner_with(
        &account.user_id,
        &account.public_key,
        &account.signing_public_key,
    )
}

pub fn owner_with(user_id: &str, public_key: &str, signing_key: &str) -> Owner {
    Owner {
        user_id: user_id.to_string(),
        public_key: key32(public_key),
        signing_key: key32(signing_key),
    }
}

pub fn sorted(mut owners: Vec<Owner>) -> Vec<Owner> {
    owners.sort_by(|a, b| a.user_id.cmp(&b.user_id));
    owners
}

/// The first statement of a vault with these owners.
pub fn genesis(vault_id: &str, owners: Vec<Owner>, signer: &str, key_version: i64) -> Statement {
    Statement {
        vault_id: vault_id.to_string(),
        version: 1,
        previous: None,
        key_version,
        key_commitment: rand32(),
        owners: sorted(owners),
        signer: signer.to_string(),
        created: CREATED.to_string(),
    }
}

/// The statement after `head`, without a key change.
pub fn successor(head: &Statement, owners: Vec<Owner>, signer: &str) -> Statement {
    Statement {
        version: head.version + 1,
        previous: Some(hash(&encode(head))),
        owners: sorted(owners),
        signer: signer.to_string(),
        ..head.clone()
    }
}

/// The statement of a rotation after `head`: next key version, new commitment.
pub fn rotated(head: &Statement, owners: Vec<Owner>, signer: &str) -> Statement {
    Statement {
        key_version: head.key_version + 1,
        key_commitment: rand32(),
        ..successor(head, owners, signer)
    }
}

pub fn rand32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}

/// `{statement, signature}` of exactly these bytes, signed by `account`.
pub fn sign_bytes(account: &Account, bytes: &[u8]) -> Value {
    let pair = Ed25519KeyPair::from_seed_unchecked(&account.signing_seed).unwrap();
    let mut message = b"keeman:v1:roles\x00".to_vec();
    message.extend_from_slice(bytes);
    json!({
        "statement": encode_base64url(bytes),
        "signature": encode_base64url(pair.sign(&message).as_ref()),
    })
}

pub fn signed(account: &Account, statement: &Statement) -> Value {
    sign_bytes(account, &encode(statement))
}

/// The statement in a delivered `{version, statement, signature}`.
pub fn read(delivered: &Value) -> Statement {
    let bytes = decode_base64url(delivered["statement"].as_str().unwrap()).unwrap();
    keeman_server::roles::parse(&bytes).unwrap()
}
