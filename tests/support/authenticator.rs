//! A software authenticator with a P-256 key that answers WebAuthn options
//! exactly like `PublicKeyCredential.toJSON()` in a browser.

use keeman_server::types::{decode_base64url, encode_base64url};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::sign::Signer;
use serde_json::{Value, json};

pub use super::{ORIGIN, RP_ID};

/// Minimal CBOR for attestation objects and COSE keys.
pub enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    Text(&'static str),
    Map(Vec<(Cbor, Cbor)>),
}

fn head(major: u8, value: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => out.extend([major | 24, value as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend((value as u16).to_be_bytes());
        }
        _ => {
            out.push(major | 26);
            out.extend((value as u32).to_be_bytes());
        }
    }
}

pub fn cbor(value: &Cbor, out: &mut Vec<u8>) {
    match value {
        Cbor::Int(n) if *n >= 0 => head(0, *n as u64, out),
        Cbor::Int(n) => head(1, (-1 - n) as u64, out),
        Cbor::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend(b);
        }
        Cbor::Text(t) => {
            head(3, t.len() as u64, out);
            out.extend(t.as_bytes());
        }
        Cbor::Map(entries) => {
            head(5, entries.len() as u64, out);
            for (key, value) in entries {
                cbor(key, out);
                cbor(value, out);
            }
        }
    }
}

pub struct Authenticator {
    key: PKey<Private>,
    ec: EcKey<Private>,
    pub credential_id: Vec<u8>,
    pub counter: u32,
    /// Synchronised passkeys always report 0.
    pub counting: bool,
    pub user_handle: Vec<u8>,
    pub origin: String,
    pub rp_id: String,
    pub user_verified: bool,
}

impl Authenticator {
    pub fn new() -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(ec.clone()).unwrap();
        let mut credential_id = vec![0u8; 32];
        openssl::rand::rand_bytes(&mut credential_id).unwrap();
        Self {
            key,
            ec,
            credential_id,
            counter: 0,
            counting: true,
            user_handle: Vec::new(),
            origin: ORIGIN.into(),
            rp_id: RP_ID.into(),
            user_verified: true,
        }
    }

    /// An authenticator with a known private scalar (fixtures).
    pub fn from_scalar(hex: &str, credential_id: Vec<u8>, counter: u32) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let scalar = BigNum::from_hex_str(hex).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut point = EcPoint::new(&group).unwrap();
        point.mul_generator2(&group, &scalar, &mut ctx).unwrap();
        let ec = EcKey::from_private_components(&group, &scalar, &point).unwrap();
        let key = PKey::from_ec_key(ec.clone()).unwrap();
        Self {
            key,
            ec,
            credential_id,
            counter,
            ..Self::new()
        }
    }

    fn cose_key(&self) -> Vec<u8> {
        let mut ctx = BigNumContext::new().unwrap();
        let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
        self.ec
            .public_key()
            .affine_coordinates_gfp(self.ec.group(), &mut x, &mut y, &mut ctx)
            .unwrap();
        let mut out = Vec::new();
        cbor(
            &Cbor::Map(vec![
                (Cbor::Int(1), Cbor::Int(2)),
                (Cbor::Int(3), Cbor::Int(-7)),
                (Cbor::Int(-1), Cbor::Int(1)),
                (Cbor::Int(-2), Cbor::Bytes(x.to_vec_padded(32).unwrap())),
                (Cbor::Int(-3), Cbor::Bytes(y.to_vec_padded(32).unwrap())),
            ]),
            &mut out,
        );
        out
    }

    fn flags(&self, attested: bool) -> u8 {
        let uv = if self.user_verified { 0x04 } else { 0 };
        0x01 | uv | if attested { 0x40 } else { 0 }
    }

    fn next_counter(&mut self) -> u32 {
        if self.counting {
            self.counter += 1;
        }
        self.counter
    }

    fn client_data(&self, kind: &str, challenge: &str) -> Vec<u8> {
        json!({ "type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": false })
            .to_string()
            .into_bytes()
    }

    /// Answers `PublicKeyCredentialCreationOptionsJSON`.
    pub fn register(&mut self, options: &Value) -> Value {
        let challenge = options["challenge"].as_str().unwrap();
        self.user_handle = decode_base64url(options["user"]["id"].as_str().unwrap()).unwrap();
        let client_data = self.client_data("webauthn.create", challenge);
        let counter = self.next_counter();
        let mut auth_data = sha256(self.rp_id.as_bytes()).to_vec();
        auth_data.push(self.flags(true));
        auth_data.extend(counter.to_be_bytes());
        auth_data.extend([0u8; 16]);
        auth_data.extend((self.credential_id.len() as u16).to_be_bytes());
        auth_data.extend(&self.credential_id);
        auth_data.extend(self.cose_key());
        let mut attestation = Vec::new();
        cbor(
            &Cbor::Map(vec![
                (Cbor::Text("fmt"), Cbor::Text("none")),
                (Cbor::Text("attStmt"), Cbor::Map(Vec::new())),
                (Cbor::Text("authData"), Cbor::Bytes(auth_data.clone())),
            ]),
            &mut attestation,
        );
        let id = encode_base64url(&self.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "clientDataJSON": encode_base64url(&client_data),
                "attestationObject": encode_base64url(&attestation),
                "transports": ["internal"],
                "publicKeyAlgorithm": -7,
                "publicKey": encode_base64url(&self.key.public_key_to_der().unwrap()),
                "authenticatorData": encode_base64url(&auth_data),
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        })
    }

    /// Answers `PublicKeyCredentialRequestOptionsJSON`.
    pub fn assert(&mut self, options: &Value) -> Value {
        let challenge = options["challenge"].as_str().unwrap();
        let client_data = self.client_data("webauthn.get", challenge);
        let counter = self.next_counter();
        let mut auth_data = sha256(self.rp_id.as_bytes()).to_vec();
        auth_data.push(self.flags(false));
        auth_data.extend(counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend(sha256(&client_data));
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
        let signature = signer.sign_oneshot_to_vec(&signed).unwrap();
        let id = encode_base64url(&self.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "clientDataJSON": encode_base64url(&client_data),
                "authenticatorData": encode_base64url(&auth_data),
                "signature": encode_base64url(&signature),
                "userHandle": encode_base64url(&self.user_handle),
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        })
    }
}
