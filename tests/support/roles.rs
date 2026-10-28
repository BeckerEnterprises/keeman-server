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

/// Group order L of Ed25519, little-endian 64-bit limbs.
const ORDER: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

fn at_least_order(x: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if x[i] != ORDER[i] {
            return x[i] > ORDER[i];
        }
    }
    true
}

fn minus_order(x: &mut [u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = x[i].overflowing_sub(ORDER[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        x[i] = d;
        borrow = u64::from(b1 || b2);
    }
}

/// `x + y mod L` for `x, y < L` (both below 2^253, so nothing overflows).
fn add_mod(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s, c1) = x[i].overflowing_add(y[i]);
        let (s, c2) = s.overflowing_add(carry);
        out[i] = s;
        carry = u64::from(c1 || c2);
    }
    if at_least_order(&out) {
        minus_order(&mut out);
    }
    out
}

/// A little-endian number of any length, reduced mod L bit by bit.
fn reduce(bytes: &[u8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for byte in bytes.iter().rev() {
        for bit in (0..8).rev() {
            r = add_mod(&r, &r);
            if byte >> bit & 1 == 1 {
                r = add_mod(&r, &[1, 0, 0, 0]);
            }
        }
    }
    r
}

fn mul_mod(x: &[u64; 4], scalar: &[u8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for byte in scalar.iter().rev() {
        for bit in (0..8).rev() {
            r = add_mod(&r, &r);
            if byte >> bit & 1 == 1 {
                r = add_mod(&r, x);
            }
        }
    }
    r
}

/// A signature of `account` over the roles context and `bytes` whose R is
/// the identity: S = k·a, so [S]B = R + [k]A holds exactly. A check without
/// the small-order test (ring) accepts it, libsodium does not.
pub fn sign_small_r(account: &Account, bytes: &[u8]) -> Value {
    use ring::digest::{SHA512, digest};
    use ring::signature::KeyPair;
    let pair = Ed25519KeyPair::from_seed_unchecked(&account.signing_seed).unwrap();
    let mut scalar: [u8; 32] = digest(&SHA512, &account.signing_seed).as_ref()[..32]
        .try_into()
        .unwrap();
    scalar[0] &= 248;
    scalar[31] = (scalar[31] & 127) | 64;
    let mut r = [0u8; 32];
    r[0] = 1;
    let mut message = b"keeman:v1:roles\x00".to_vec();
    message.extend_from_slice(bytes);
    let mut hashed = r.to_vec();
    hashed.extend_from_slice(pair.public_key().as_ref());
    hashed.extend_from_slice(&message);
    let k = reduce(digest(&SHA512, &hashed).as_ref());
    let s = mul_mod(&k, &scalar);
    let mut signature = r.to_vec();
    for limb in s {
        signature.extend_from_slice(&limb.to_le_bytes());
    }
    // ring alone takes it; the server must not.
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pair.public_key().as_ref())
        .verify(&message, &signature)
        .unwrap();
    json!({
        "statement": encode_base64url(bytes),
        "signature": encode_base64url(&signature),
    })
}
