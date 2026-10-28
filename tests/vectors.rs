//! The shared test vectors that apply to the server: strict Base64url, UUID
//! format, the KDF parameter range, TOTP, the fixed manifest IDs, signatures,
//! the statements of the roles chain, freshness attestations and answers to
//! a confirmation request. Clients pass the same vectors.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use blake2::digest::consts::U32;
use blake2::digest::{Digest, Mac};
use blake2::{Blake2b, Blake2bMac};
use keeman_server::confirmation;
use keeman_server::extract::parse_json;
use keeman_server::freshness;
use keeman_server::manifest_ids::{SHARDS, root_id, shard_id};
use keeman_server::roles;
use keeman_server::types::{B64, KdfParamsInput, decode_base64url, is_canonical_uuid};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde_json::Value;

fn cases(file: &str) -> Vec<Value> {
    let path = format!("{}/tests/vectors/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path).unwrap();
    // kdf.json has a lone surrogate on purpose (a client-side password case);
    // Rust strings cannot hold it, and the server only needs the other cases.
    let text = text.replace("\\ud800", "\\ufffd");
    let doc: Value = serde_json::from_str(&text).unwrap();
    doc["cases"].as_array().unwrap().clone()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// A case with its `base` merged in (`override` replaces top-level fields).
fn resolved(case: &Value, all: &[Value]) -> Value {
    let Some(base) = case["base"].as_str() else {
        return case.clone();
    };
    let mut merged = all.iter().find(|c| c["id"] == base).unwrap().clone();
    if let Some(fields) = case["override"].as_object() {
        for (key, value) in fields {
            merged[key] = value.clone();
        }
    }
    merged
}

/// The mutations of the vector format that the signing cases use.
fn mutate(mut bytes: Vec<u8>, mutations: &Value) -> Vec<u8> {
    for m in mutations.as_array().into_iter().flatten() {
        let offset = m["offset"].as_u64().map(|o| usize::try_from(o).unwrap());
        match m["op"].as_str().unwrap() {
            "xor" => bytes[offset.unwrap()] ^= u8::try_from(m["value"].as_u64().unwrap()).unwrap(),
            "replace" => {
                let with = unhex(m["hex"].as_str().unwrap());
                let start = offset.unwrap();
                bytes[start..start + with.len()].copy_from_slice(&with);
            }
            "truncate" => bytes.truncate(usize::try_from(m["length"].as_u64().unwrap()).unwrap()),
            other => panic!("unknown mutation {other}"),
        }
    }
    bytes
}

/// `crypto_kdf_derive_from_key(32, id, ctx, key)`: keyed BLAKE2b-256 with
/// salt LE64(id) ‖ 0⁸ and personal ctx ‖ 0⁸.
fn kdf(key: &[u8], id: u64, context: &str) -> [u8; 32] {
    let mut salt = id.to_le_bytes().to_vec();
    salt.extend([0; 8]);
    let mut personal = context.as_bytes().to_vec();
    personal.extend([0; 8]);
    let mac = Blake2bMac::<U32>::new_with_salt_and_personal(Some(key), &salt, &personal).unwrap();
    mac.finalize().into_bytes().into()
}

fn signing_seed(user_key_hex: &str) -> [u8; 32] {
    kdf(&unhex(user_key_hex), 1, "keemanSG")
}

#[test]
fn encoding_vectors() {
    let mut checked = 0;
    for case in cases("encoding.json") {
        let id = case["id"].as_str().unwrap();
        match case["kind"].as_str().unwrap() {
            "base64url_decode" => {
                let text = case["text"].as_str().unwrap();
                let decoded = match case["length"].as_u64() {
                    Some(32) => B64::<32>::parse(text).map(|b| b.0.to_vec()),
                    Some(other) => panic!("{id}: length {other}"),
                    None => decode_base64url(text),
                };
                match case["expected"]["bytes_hex"].as_str() {
                    Some(expected) => {
                        assert_eq!(decoded.map(|b| hex(&b)).as_deref(), Some(expected), "{id}")
                    }
                    None => assert_eq!(decoded, None, "{id}"),
                }
            }
            "uuid_check" => {
                let valid = case["expected"]["valid"].as_bool().unwrap();
                assert_eq!(
                    is_canonical_uuid(case["value"].as_str().unwrap()),
                    valid,
                    "{id}"
                );
            }
            "uuidv7" => continue,
            other => panic!("{id}: unknown kind {other}"),
        }
        checked += 1;
    }
    assert!(checked >= 20);
}

#[test]
fn kdf_parameter_vectors() {
    let mut checked = 0;
    for case in cases("kdf.json")
        .into_iter()
        .filter(|c| c["kind"] == "params")
    {
        let id = case["id"].as_str().unwrap();
        let bytes = serde_json::to_vec(&case["kdf"]).unwrap();
        let accepted = parse_json::<KdfParamsInput>(&bytes)
            .ok()
            .and_then(|input| input.validate().ok())
            .is_some();
        assert_eq!(accepted, case["expected"]["valid"] == true, "{id}");
        checked += 1;
    }
    assert!(checked >= 10);
}

#[test]
fn totp_vectors() {
    use keeman_server::crypto::base32;
    use keeman_server::crypto::totp::{Algorithm, hotp};

    let mut checked = 0;
    for case in cases("totp.json") {
        let id = case["id"].as_str().unwrap();
        let secret = base32::decode(case["secret_base32"].as_str().unwrap()).expect(id);
        let algorithm = match case["algorithm"].as_str().unwrap() {
            "SHA1" => Algorithm::Sha1,
            "SHA256" => Algorithm::Sha256,
            "SHA512" => Algorithm::Sha512,
            other => panic!("{id}: algorithm {other}"),
        };
        let digits = u32::try_from(case["digits"].as_u64().unwrap()).unwrap();
        let period = case["period"].as_u64().unwrap();
        let unix_time = case["unix_time"].as_u64().unwrap();
        let expected = &case["expected"];
        let counter = unix_time / period;
        assert_eq!(counter, expected["counter"].as_u64().unwrap(), "{id}");
        assert_eq!(
            (counter + 1) * period,
            expected["valid_until"].as_u64().unwrap(),
            "{id}"
        );
        let code = |counter| {
            let value = hotp(algorithm, &secret, counter, digits).unwrap();
            format!("{value:0width$}", width = digits as usize)
        };
        assert_eq!(code(counter), expected["code"].as_str().unwrap(), "{id}");
        assert_eq!(
            code(counter + 1),
            expected["next"].as_str().unwrap(),
            "{id}"
        );
        checked += 1;
    }
    assert_eq!(checked, 25);
}

#[test]
fn manifest_id_vectors() {
    let cases = cases("manifest.json");
    let case = cases.iter().find(|c| c["kind"] == "ids").unwrap();
    let vault = case["vault_id"].as_str().unwrap();
    assert_eq!(case["expected"]["root"], root_id(vault));
    let shards = case["expected"]["shards"].as_array().unwrap();
    assert_eq!(shards.len(), SHARDS);
    for (k, expected) in shards.iter().enumerate() {
        assert_eq!(expected, &shard_id(vault, k), "shard {k}");
    }
}

#[test]
fn signing_vectors() {
    let all = cases("signing.json");
    let mut verified = 0;
    for case in &all {
        let id = case["id"].as_str().unwrap();
        if case["kind"] == "derive" {
            let seed = signing_seed(case["user_key_hex"].as_str().unwrap());
            assert_eq!(hex(&seed), case["expected"]["seed_hex"], "{id}");
            let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            assert_eq!(
                hex(pair.public_key().as_ref()),
                case["expected"]["public_key_hex"],
                "{id}"
            );
            continue;
        }
        let effective = resolved(case, &all);
        let context = effective["context"].as_str().unwrap();
        let message = unhex(effective["message_hex"].as_str().unwrap());
        let mut signed = context.as_bytes().to_vec();
        signed.push(0);
        signed.extend_from_slice(&message);
        let signature = if case.get("base").is_none() {
            assert_eq!(hex(&signed), case["expected"]["signed_hex"], "{id}");
            let seed = unhex(case["seed_hex"].as_str().unwrap());
            let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            let signature = pair.sign(&signed).as_ref().to_vec();
            assert_eq!(hex(&signature), case["expected"]["signature_hex"], "{id}");
            signature
        } else if let Some(built) = effective["signature_hex"].as_str() {
            // A signature built for the case, with R or the key of small order.
            unhex(built)
        } else {
            let base = all.iter().find(|c| c["id"] == case["base"]).unwrap();
            mutate(
                unhex(base["expected"]["signature_hex"].as_str().unwrap()),
                &case["mutations"],
            )
        };
        let public_key = unhex(effective["public_key_hex"].as_str().unwrap());
        let expected = case["expected"].get("error").is_none();
        let sized = <[u8; 32]>::try_from(public_key.as_slice())
            .ok()
            .zip(<[u8; 64]>::try_from(signature.as_slice()).ok());
        // The server's check must agree with the clients' (libsodium).
        let accepted =
            sized.is_some_and(|(key, sig)| roles::verify_in(context, &key, &message, &sig));
        assert_eq!(accepted, expected, "{id}");
        // ring alone checks less strictly: it takes R or a key of small order,
        // which is why the server refuses those before asking ring.
        let ring_accepts = sized.is_some()
            && UnparsedPublicKey::new(&ED25519, &public_key)
                .verify(&signed, &signature)
                .is_ok();
        if ["r-small-order", "pk-small-order"].contains(&id) {
            assert!(ring_accepts, "{id}");
        } else {
            assert_eq!(ring_accepts, expected, "{id}");
        }
        verified += 1;
    }
    assert_eq!(verified, 13);
}

fn key32(value: &Value) -> [u8; 32] {
    decode_base64url(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// A statement in the field names of the API.
fn statement_of(wire: &Value) -> roles::Statement {
    roles::Statement {
        vault_id: wire["vault_id"].as_str().unwrap().into(),
        version: wire["version"].as_i64().unwrap(),
        previous: wire["previous"].as_str().map(|_| key32(&wire["previous"])),
        key_version: wire["key_version"].as_i64().unwrap(),
        key_commitment: key32(&wire["key_commitment"]),
        owners: wire["owners"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| roles::Owner {
                user_id: o["user_id"].as_str().unwrap().into(),
                public_key: key32(&o["public_key"]),
                signing_key: key32(&o["signing_key"]),
            })
            .collect(),
        signer: wire["signer"].as_str().unwrap().into(),
        created: wire["created"].as_str().unwrap().into(),
    }
}

#[test]
fn roles_vectors() {
    let mut checked = 0;
    for case in cases("roles.json") {
        let id = case["id"].as_str().unwrap();
        let expected = &case["expected"];
        match case["kind"].as_str().unwrap() {
            "commitment" => {
                let prefix = format!(
                    "keeman:v1:key-commitment:{}:{}\0",
                    case["vault_id"].as_str().unwrap(),
                    case["key_version"]
                );
                let mut input = prefix.into_bytes();
                input.extend(unhex(case["vault_key_hex"].as_str().unwrap()));
                let digest: [u8; 32] = Blake2b::<U32>::digest(&input).into();
                assert_eq!(
                    keeman_server::types::encode_base64url(&digest),
                    expected["commitment"],
                    "{id}"
                );
            }
            "statement" => {
                let statement = statement_of(&case["statement"]);
                let bytes = roles::encode(&statement);
                assert_eq!(
                    keeman_server::types::encode_base64url(&bytes),
                    expected["statement"],
                    "{id}"
                );
                assert_eq!(
                    keeman_server::types::encode_base64url(&roles::hash(&bytes)),
                    expected["hash"],
                    "{id}"
                );
                assert_eq!(roles::parse(&bytes), Some(statement.clone()), "{id}");
                let seed = signing_seed(case["signer_user_key_hex"].as_str().unwrap());
                let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
                let mut signed = roles::SIGNATURE_CONTEXT.as_bytes().to_vec();
                signed.push(0);
                signed.extend_from_slice(&bytes);
                assert_eq!(
                    keeman_server::types::encode_base64url(pair.sign(&signed).as_ref()),
                    expected["signature"],
                    "{id}"
                );
                let signature: [u8; 64] = decode_base64url(expected["signature"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
                assert!(roles::verify(&key, &bytes, &signature), "{id}");
            }
            "decode" => {
                let bytes = decode_base64url(case["statement_b64"].as_str().unwrap()).unwrap();
                let parsed = roles::parse(&bytes);
                match expected.get("statement") {
                    Some(wire) => assert_eq!(parsed, Some(statement_of(wire)), "{id}"),
                    None => assert_eq!(parsed, None, "{id}"),
                }
            }
            // Chain and grant checks are the clients' part.
            "chain" | "grant" => continue,
            other => panic!("{id}: unknown kind {other}"),
        }
        checked += 1;
    }
    assert_eq!(checked, 28);
}

/// A freshness statement in the field names of the API.
fn freshness_of(wire: &Value) -> freshness::Statement {
    let point = |value: &Value| {
        value.as_array().map(|items| freshness::Point {
            n: items[0].as_i64().unwrap(),
            hash: key32(&items[1]),
        })
    };
    match wire["type"].as_str().unwrap() {
        "vault_freshness" => freshness::Statement::Vault {
            vault_id: wire["vault_id"].as_str().unwrap().into(),
            user_id: wire["user_id"].as_str().unwrap().into(),
            time: wire["time"].as_str().unwrap().into(),
            key_version: wire["key_version"].as_i64().unwrap(),
            manifest: point(&wire["manifest"]),
            roles: point(&wire["roles"]),
        },
        "user_data_freshness" => freshness::Statement::UserData {
            user_id: wire["user_id"].as_str().unwrap().into(),
            time: wire["time"].as_str().unwrap().into(),
            seq: wire["seq"].as_i64().unwrap(),
        },
        other => panic!("unknown type {other}"),
    }
}

/// What the server makes of an attestation: `None` when it would refuse it.
fn read_attestation(attestation: &Value, public_key: &[u8]) -> Option<freshness::Statement> {
    let bytes = decode_base64url(attestation["statement"].as_str()?)?;
    let signature: [u8; 64] = decode_base64url(attestation["signature"].as_str()?)?
        .try_into()
        .ok()?;
    let key: [u8; 32] = public_key.try_into().ok()?;
    let statement = freshness::parse(&bytes)?;
    freshness::verify(&key, &bytes, &signature).then_some(statement)
}

#[test]
fn freshness_vectors() {
    let mut checked = 0;
    for case in cases("freshness.json") {
        let id = case["id"].as_str().unwrap();
        let expected = &case["expected"];
        match case["kind"].as_str().unwrap() {
            "statement" => {
                let statement = freshness_of(&case["statement"]);
                let bytes = freshness::encode(&statement);
                assert_eq!(
                    keeman_server::types::encode_base64url(&bytes),
                    expected["statement"],
                    "{id}"
                );
                assert_eq!(freshness::parse(&bytes), Some(statement), "{id}");
                let seed = signing_seed(case["signer_user_key_hex"].as_str().unwrap());
                let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
                let mut signed = freshness::SIGNATURE_CONTEXT.as_bytes().to_vec();
                signed.push(0);
                signed.extend_from_slice(&bytes);
                assert_eq!(
                    keeman_server::types::encode_base64url(pair.sign(&signed).as_ref()),
                    expected["signature"],
                    "{id}"
                );
                let signature: [u8; 64] = decode_base64url(expected["signature"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
                assert!(freshness::verify(&key, &bytes, &signature), "{id}");
                assert!(!roles::verify(&key, &bytes, &signature), "{id}");
            }
            "decode" => {
                let bytes = decode_base64url(case["statement_b64"].as_str().unwrap()).unwrap();
                let parsed = freshness::parse(&bytes);
                match expected.get("statement") {
                    Some(wire) => assert_eq!(parsed, Some(freshness_of(wire)), "{id}"),
                    None => assert_eq!(parsed, None, "{id}"),
                }
            }
            "verify" => {
                let read = read_attestation(
                    &case["attestation"],
                    &unhex(case["public_key_hex"].as_str().unwrap()),
                );
                match expected.get("statement") {
                    Some(wire) => assert_eq!(read, Some(freshness_of(wire)), "{id}"),
                    None => assert_eq!(read, None, "{id}"),
                }
            }
            other => panic!("{id}: unknown kind {other}"),
        }
        checked += 1;
    }
    assert_eq!(checked, 36);
}

/// An answer statement in the field names of the API.
fn confirmation_of(wire: &Value) -> confirmation::Statement {
    confirmation::Statement {
        user_id: wire["user_id"].as_str().unwrap().into(),
        nonce: key32(&wire["nonce"]),
        time: wire["time"].as_str().unwrap().into(),
        content: decode_base64url(wire["content"].as_str().unwrap()).unwrap(),
    }
}

/// What the server makes of an answer up to account and nonce: `None` when
/// it would refuse it. The content only clients read.
fn read_answer(
    answer: &Value,
    public_key: &[u8],
    user_id: &str,
    nonce: &str,
) -> Option<confirmation::Statement> {
    let bytes = decode_base64url(answer["statement"].as_str()?)?;
    let signature: [u8; 64] = decode_base64url(answer["signature"].as_str()?)?
        .try_into()
        .ok()?;
    let key: [u8; 32] = public_key.try_into().ok()?;
    let statement = confirmation::parse(&bytes)?;
    let fits = statement.user_id == user_id && decode_base64url(nonce)? == statement.nonce;
    (fits && confirmation::verify(&key, &bytes, &signature)).then_some(statement)
}

#[test]
fn confirmation_vectors() {
    let mut checked = 0;
    for case in cases("confirmation.json") {
        let id = case["id"].as_str().unwrap();
        let expected = &case["expected"];
        match case["kind"].as_str().unwrap() {
            "statement" => {
                let statement = confirmation::Statement {
                    user_id: case["user_id"].as_str().unwrap().into(),
                    nonce: key32(&case["nonce"]),
                    time: case["time"].as_str().unwrap().into(),
                    content: unhex(case["content_utf8_hex"].as_str().unwrap()),
                };
                let bytes = confirmation::encode(&statement);
                assert_eq!(
                    keeman_server::types::encode_base64url(&bytes),
                    expected["statement"],
                    "{id}"
                );
                assert_eq!(confirmation::parse(&bytes), Some(statement.clone()), "{id}");
                assert_eq!(confirmation_of(&expected["decoded"]), statement, "{id}");
                let seed = signing_seed(case["signer_user_key_hex"].as_str().unwrap());
                let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
                let mut signed = confirmation::SIGNATURE_CONTEXT.as_bytes().to_vec();
                signed.push(0);
                signed.extend_from_slice(&bytes);
                assert_eq!(
                    keeman_server::types::encode_base64url(pair.sign(&signed).as_ref()),
                    expected["signature"],
                    "{id}"
                );
                let signature: [u8; 64] = decode_base64url(expected["signature"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
                assert!(confirmation::verify(&key, &bytes, &signature), "{id}");
                assert!(!freshness::verify(&key, &bytes, &signature), "{id}");
                assert!(!roles::verify(&key, &bytes, &signature), "{id}");
            }
            "decode" => {
                let bytes = decode_base64url(case["statement_b64"].as_str().unwrap()).unwrap();
                let parsed = confirmation::parse(&bytes);
                match expected.get("statement") {
                    Some(wire) => assert_eq!(parsed, Some(confirmation_of(wire)), "{id}"),
                    None => assert_eq!(parsed, None, "{id}"),
                }
            }
            "verify" => {
                let read = read_answer(
                    &case["answer"],
                    &unhex(case["public_key_hex"].as_str().unwrap()),
                    case["expected_user_id"].as_str().unwrap(),
                    case["expected_nonce"].as_str().unwrap(),
                );
                match expected.get("time") {
                    Some(time) => assert_eq!(
                        read.map(|s| s.time),
                        time.as_str().map(str::to_string),
                        "{id}"
                    ),
                    None => assert_eq!(read, None, "{id}"),
                }
            }
            // The content only clients read.
            "content" => continue,
            other => panic!("{id}: unknown kind {other}"),
        }
        checked += 1;
    }
    assert_eq!(checked, 31);
}
