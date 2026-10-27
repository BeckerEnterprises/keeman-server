//! The shared test vectors that apply to the server: strict Base64url, UUID
//! format, the KDF parameter range, TOTP and the fixed manifest IDs. Clients
//! pass the same vectors.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use keeman_server::extract::parse_json;
use keeman_server::manifest_ids::{SHARDS, root_id, shard_id};
use keeman_server::types::{B64, KdfParamsInput, decode_base64url, is_canonical_uuid};
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
