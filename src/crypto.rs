//! Server-side cryptography only: the server secret and its
//! derivations, the account TOTP secret, token hashing and randomness. The server never sees keys
//! that protect vault data.

pub mod base32;
pub mod totp;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// The 32-byte server secret; never printed.
pub struct ServerSecret([u8; 32]);

impl ServerSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for ServerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerSecret(..)")
    }
}

/// HKDF-SHA256 without salt, 32 bytes of output.
fn hkdf(secret: &ServerSecret, info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    // A 32-byte output is always within HKDF's limit of 255 * 32 bytes.
    let _ = Hkdf::<Sha256>::new(None, &secret.0).expand(info.as_bytes(), &mut out);
    out
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(message);
            mac.finalize().into_bytes().into()
        }
        // HMAC accepts keys of any length; this branch is unreachable.
        Err(_) => [0u8; 32],
    }
}

/// Format byte of a stored account TOTP secret.
const TOTP_SECRET_FORMAT: u8 = 0x01;
const TOTP_NONCE_BYTES: usize = 24;
/// `0x01 ‖ nonce (24) ‖ ciphertext (20) ‖ tag (16)`.
pub const SEALED_TOTP_SECRET_BYTES: usize = 1 + TOTP_NONCE_BYTES + totp::SECRET_BYTES + 16;

/// Keys derived from the server secret once at startup.
pub struct DerivedKeys {
    prelogin: [u8; 32],
    throttle: [u8; 32],
    totp: [u8; 32],
}

impl DerivedKeys {
    pub fn derive(secret: &ServerSecret) -> Self {
        Self {
            prelogin: hkdf(secret, "keeman-server:prelogin:v1"),
            throttle: hkdf(secret, "keeman-server:throttle:v1"),
            totp: hkdf(secret, "keeman-server:totp-secret:v1"),
        }
    }

    /// Deterministic dummy salt for an unknown, normalised e-mail address.
    pub fn dummy_salt(&self, email: &str) -> [u8; 16] {
        let mac = hmac_sha256(&self.prelogin, email.as_bytes());
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&mac[..16]);
        salt
    }

    /// Key of the failed-attempt counter of a normalised e-mail address.
    pub fn throttle_key(&self, email: &str) -> [u8; 32] {
        hmac_sha256(&self.throttle, email.as_bytes())
    }

    /// Encrypts an account TOTP secret for storage, bound to the account by
    /// the AAD.
    pub fn seal_totp_secret(
        &self,
        user_id: &str,
        secret: &[u8; totp::SECRET_BYTES],
    ) -> Result<Vec<u8>, &'static str> {
        let nonce = random_bytes::<TOTP_NONCE_BYTES>().map_err(|_| "no randomness")?;
        self.seal_totp_secret_with_nonce(user_id, secret, nonce)
    }

    fn seal_totp_secret_with_nonce(
        &self,
        user_id: &str,
        secret: &[u8; totp::SECRET_BYTES],
        nonce: [u8; TOTP_NONCE_BYTES],
    ) -> Result<Vec<u8>, &'static str> {
        let cipher = XChaCha20Poly1305::new(&self.totp.into());
        let payload = Payload {
            msg: secret,
            aad: user_id.as_bytes(),
        };
        let sealed = cipher
            .encrypt(&XNonce::from(nonce), payload)
            .map_err(|_| "cannot seal TOTP secret")?;
        let mut out = Vec::with_capacity(SEALED_TOTP_SECRET_BYTES);
        out.push(TOTP_SECRET_FORMAT);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Opens a stored account TOTP secret. Any failure is a server error
    /// (another secret, damaged data), never a wrong code.
    pub fn open_totp_secret(
        &self,
        user_id: &str,
        sealed: &[u8],
    ) -> Result<[u8; totp::SECRET_BYTES], &'static str> {
        const ERROR: &str = "cannot open TOTP secret";
        if sealed.len() != SEALED_TOTP_SECRET_BYTES || sealed[0] != TOTP_SECRET_FORMAT {
            return Err(ERROR);
        }
        let (nonce, ciphertext) = sealed[1..].split_at(TOTP_NONCE_BYTES);
        let nonce: [u8; TOTP_NONCE_BYTES] = nonce.try_into().map_err(|_| ERROR)?;
        let cipher = XChaCha20Poly1305::new(&self.totp.into());
        let payload = Payload {
            msg: ciphertext,
            aad: user_id.as_bytes(),
        };
        let secret = cipher
            .decrypt(&XNonce::from(nonce), payload)
            .map_err(|_| ERROR)?;
        secret.try_into().map_err(|_| ERROR)
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out)?;
    Ok(out)
}

/// A new token as sent to the client and its stored SHA-256 hash.
pub struct NewToken {
    pub text: String,
    pub hash: [u8; 32],
}

pub fn new_token() -> Result<NewToken, getrandom::Error> {
    let bytes = random_bytes::<32>()?;
    Ok(NewToken {
        text: URL_SAFE_NO_PAD.encode(bytes),
        hash: sha256(&bytes),
    })
}

/// Hash of a token from the client, or `None` if it is not a canonical
/// 32-byte Base64url value (then it is simply invalid).
pub fn hash_token(text: &str) -> Option<[u8; 32]> {
    if text.len() != 43 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (bytes.len() == 32).then(|| sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivations_match_rfc_constructions() {
        let secret = ServerSecret::from_bytes([7u8; 32]);
        let keys = DerivedKeys::derive(&secret);
        // Same email → same salt; another email or secret → another salt.
        assert_eq!(
            keys.dummy_salt("a@example.com"),
            keys.dummy_salt("a@example.com")
        );
        assert_ne!(
            keys.dummy_salt("a@example.com"),
            keys.dummy_salt("b@example.com")
        );
        let other = DerivedKeys::derive(&ServerSecret::from_bytes([8u8; 32]));
        assert_ne!(
            keys.dummy_salt("a@example.com"),
            other.dummy_salt("a@example.com")
        );
        assert_ne!(
            keys.throttle_key("a@example.com")[..16],
            keys.dummy_salt("a@example.com")
        );
    }

    #[test]
    fn known_answer_hkdf_hmac() {
        // Computed independently with Python's hmac/hashlib (RFC 5869 HKDF, empty salt).
        let keys = DerivedKeys::derive(&ServerSecret::from_bytes([0u8; 32]));
        let salt = keys.dummy_salt("alice@example.com");
        assert_eq!(hex(&salt), KAT_DUMMY_SALT);
        assert_eq!(
            hex(&keys.throttle_key("alice@example.com")),
            KAT_THROTTLE_KEY
        );
    }

    #[test]
    fn known_answer_totp_secret() {
        // Computed independently with Python (hmac, hashlib, pycryptodome).
        let keys = DerivedKeys::derive(&ServerSecret::from_bytes([0u8; 32]));
        let secret: [u8; 20] = std::array::from_fn(|i| i as u8);
        let sealed = keys
            .seal_totp_secret_with_nonce(KAT_USER_ID, &secret, [0x24; 24])
            .unwrap();
        assert_eq!(hex(&sealed), KAT_SEALED_TOTP_SECRET);
        assert_eq!(keys.open_totp_secret(KAT_USER_ID, &sealed).unwrap(), secret);
    }

    #[test]
    fn totp_secret_is_bound_to_account_and_format() {
        let keys = DerivedKeys::derive(&ServerSecret::from_bytes([3u8; 32]));
        let secret = [9u8; 20];
        let sealed = keys.seal_totp_secret(KAT_USER_ID, &secret).unwrap();
        assert_eq!(sealed.len(), SEALED_TOTP_SECRET_BYTES);
        assert_ne!(sealed, keys.seal_totp_secret(KAT_USER_ID, &secret).unwrap());
        assert_eq!(keys.open_totp_secret(KAT_USER_ID, &sealed).unwrap(), secret);
        let other_user = "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6c";
        assert!(keys.open_totp_secret(other_user, &sealed).is_err());
        let other = DerivedKeys::derive(&ServerSecret::from_bytes([4u8; 32]));
        assert!(other.open_totp_secret(KAT_USER_ID, &sealed).is_err());
        let mut format = sealed.clone();
        format[0] = 0x02;
        assert!(keys.open_totp_secret(KAT_USER_ID, &format).is_err());
        let mut tampered = sealed.clone();
        tampered[30] ^= 1;
        assert!(keys.open_totp_secret(KAT_USER_ID, &tampered).is_err());
        assert!(keys.open_totp_secret(KAT_USER_ID, &sealed[..60]).is_err());
    }

    const KAT_USER_ID: &str = "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b";
    const KAT_SEALED_TOTP_SECRET: &str = "012424242424242424242424242424242424242424242424248bafbe766593fea47762d204343b378f83c2a14013366b6d66025f01cebe57c6c5616cad";

    const KAT_DUMMY_SALT: &str = "6daaebc394cfc158d463142c3638f559";
    const KAT_THROTTLE_KEY: &str =
        "d139376b5e8e2476c8dea8719b0177b9938266dc09674cd4d34c2058e436b2ad";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn tokens_hash_only_canonical_values() {
        let token = new_token().unwrap();
        assert_eq!(hash_token(&token.text), Some(token.hash));
        assert_eq!(hash_token("short"), None);
        assert_eq!(hash_token(&format!("{}=", &token.text[..42])), None);
    }
}
