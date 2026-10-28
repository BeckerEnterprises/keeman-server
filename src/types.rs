//! Validated request values: strict Base64url, fixed lengths and
//! limits, normalised e-mail addresses. Errors carry fixed
//! messages only, never parts of the input.

use std::fmt;
use std::marker::PhantomData;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::error::{ApiError, ErrorCode};

/// Prefix of our own validation messages; the rest is one of [`MESSAGES`].
pub const MESSAGE_PREFIX: &str = "keeman:";
/// Message of values over a byte limit; mapped to `413` instead of `400`.
pub const TOO_LARGE: &str = "keeman:too-large";

pub const MSG_BASE64: &str = "not a canonical Base64url value of the expected length";
pub const MSG_ENVELOPE: &str = "not an AEAD envelope";
pub const MSG_EMAIL: &str = "invalid e-mail address";
pub const MSG_DEVICE_NAME: &str = "invalid device name";
pub const MSG_UUID: &str = "not a canonical UUID";
pub const MSG_POSITIVE: &str = "not a positive safe integer";
pub const MSG_BOX: &str = "not a box envelope";
pub const MSG_TOTP_CODE: &str = "not a 6-digit code";
pub const MSG_BACKUP_CODE: &str = "not a backup code";
pub const MSG_PASSKEY_NAME: &str = "invalid passkey name";
pub const MSG_FAVICON_URL: &str = "URL longer than 2048 characters";
pub const MESSAGES: &[&str] = &[
    MSG_BASE64,
    MSG_ENVELOPE,
    MSG_BOX,
    MSG_EMAIL,
    MSG_DEVICE_NAME,
    MSG_UUID,
    MSG_POSITIVE,
    MSG_TOTP_CODE,
    MSG_BACKUP_CODE,
    MSG_PASSKEY_NAME,
    MSG_FAVICON_URL,
];

fn invalid<E: de::Error>(message: &str) -> E {
    E::custom(format!("{MESSAGE_PREFIX}{message}"))
}

/// Strict Base64url: canonical unpadded form only.
pub fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == text).then_some(bytes)
}

pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

struct StrVisitor<F>(F, PhantomData<()>);

impl<'de, T, F: FnOnce(&str) -> Result<T, &'static str>> Visitor<'de> for StrVisitor<F> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<T, E> {
        (self.0)(value).map_err(|message| {
            if message == TOO_LARGE {
                E::custom(TOO_LARGE)
            } else {
                invalid(message)
            }
        })
    }
}

fn deserialize_str<'de, D: Deserializer<'de>, T>(
    deserializer: D,
    parse: impl FnOnce(&str) -> Result<T, &'static str>,
) -> Result<T, D::Error> {
    deserializer.deserialize_str(StrVisitor(parse, PhantomData))
}

/// Exactly `N` bytes as canonical Base64url.
#[derive(Clone, PartialEq, Eq)]
pub struct B64<const N: usize>(pub [u8; N]);

impl<const N: usize> fmt::Debug for B64<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B64<{N}>(..)")
    }
}

impl<const N: usize> B64<N> {
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != (N * 4).div_ceil(3) {
            return None;
        }
        decode_base64url(text)?.try_into().ok().map(Self)
    }
}

impl<'de, const N: usize> Deserialize<'de> for B64<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| Self::parse(s).ok_or(MSG_BASE64))
    }
}

/// 32-byte keys and public keys.
pub type Key32 = B64<32>;
/// 16-byte KDF salt.
pub type Salt = B64<16>;
/// 32-byte tokens and invite codes.
pub type Token = B64<32>;

/// AEAD envelope of a 32-byte key: 73 bytes, format byte `0x01`.
#[derive(Debug, Clone)]
pub struct WrappedKey(pub Vec<u8>);

impl<'de> Deserialize<'de> for WrappedKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| match B64::<73>::parse(s) {
            Some(B64(bytes)) if bytes[0] == 0x01 => Ok(Self(bytes.to_vec())),
            Some(_) => Err(MSG_ENVELOPE),
            None => Err(MSG_BASE64),
        })
    }
}

/// `user_data`: AEAD envelope, at most 349922 characters.
#[derive(Debug, Clone)]
pub struct UserDataEnvelope(pub Vec<u8>);

pub const USER_DATA_MAX_CHARS: usize = 349_922;

impl<'de> Deserialize<'de> for UserDataEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            if s.len() > USER_DATA_MAX_CHARS {
                return Err(TOO_LARGE);
            }
            match decode_base64url(s) {
                Some(bytes) if bytes.len() >= 41 && bytes[0] == 0x01 => Ok(Self(bytes)),
                Some(_) => Err(MSG_ENVELOPE),
                None => Err(MSG_BASE64),
            }
        })
    }
}

/// Encrypted object or tombstone: canonical Base64url of at most
/// 1572864 characters (`413` above), format byte `0x01`, at least 41 bytes.
#[derive(Debug, Clone)]
pub struct ObjectData(pub Vec<u8>);

pub const OBJECT_DATA_MAX_CHARS: usize = 1_572_864;

impl<'de> Deserialize<'de> for ObjectData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            if s.len() > OBJECT_DATA_MAX_CHARS {
                return Err(TOO_LARGE);
            }
            match decode_base64url(s) {
                Some(bytes) if bytes.len() >= 41 && bytes[0] == 0x01 => Ok(Self(bytes)),
                Some(_) => Err(MSG_ENVELOPE),
                None => Err(MSG_BASE64),
            }
        })
    }
}

/// Box envelope with a vault key: canonical Base64url of
/// at most 65536 characters (`413` above), format byte `0x02`, at least 41
/// bytes.
#[derive(Debug, Clone)]
pub struct KeyBox(pub Vec<u8>);

pub const KEY_BOX_MAX_CHARS: usize = 65_536;

impl<'de> Deserialize<'de> for KeyBox {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            if s.len() > KEY_BOX_MAX_CHARS {
                return Err(TOO_LARGE);
            }
            match decode_base64url(s) {
                Some(bytes) if bytes.len() >= 41 && bytes[0] == 0x02 => Ok(Self(bytes)),
                Some(_) => Err(MSG_BOX),
                None => Err(MSG_BASE64),
            }
        })
    }
}

/// Statement bytes of the roles chain as canonical Base64url of at most
/// 65536 characters; the content is read by `roles`.
#[derive(Debug, Clone)]
pub struct StatementBytes(pub Vec<u8>);

pub const STATEMENT_MAX_CHARS: usize = 65_536;

impl<'de> Deserialize<'de> for StatementBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            if s.is_empty() || s.len() > STATEMENT_MAX_CHARS {
                return Err(MSG_BASE64);
            }
            decode_base64url(s).map(Self).ok_or(MSG_BASE64)
        })
    }
}

/// Ed25519 signature.
pub type Signature = B64<64>;

/// Statement bytes of a freshness attestation as canonical Base64url of at
/// most 4096 characters; the content is read by `freshness`.
#[derive(Debug, Clone)]
pub struct FreshnessBytes(pub Vec<u8>);

pub const FRESHNESS_MAX_CHARS: usize = 4096;

impl<'de> Deserialize<'de> for FreshnessBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            if s.is_empty() || s.len() > FRESHNESS_MAX_CHARS {
                return Err(MSG_BASE64);
            }
            decode_base64url(s).map(Self).ok_or(MSG_BASE64)
        })
    }
}

/// Statement bytes of a confirmation answer as canonical Base64url of at
/// most 1 MiB decoded (`413` above); the content is read by `confirmation`.
#[derive(Debug, Clone)]
pub struct ConfirmationBytes(pub Vec<u8>);

/// 1 MiB as Base64url without padding.
pub const CONFIRMATION_MAX_CHARS: usize = 1_398_102;

impl<'de> Deserialize<'de> for ConfirmationBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            if s.len() > CONFIRMATION_MAX_CHARS {
                return Err(TOO_LARGE);
            }
            if s.is_empty() {
                return Err(MSG_BASE64);
            }
            decode_base64url(s).map(Self).ok_or(MSG_BASE64)
        })
    }
}

/// Nonce of a confirmation request: 32 random bytes of the requesting device.
pub type Nonce = B64<32>;

/// Role of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }
}

/// Largest integer clients can represent exactly (2^53 - 1).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// A revision or key version: integer from 1 to 2^53 - 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Positive(pub i64);

impl<'de> Deserialize<'de> for Positive {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = i64::deserialize(deserializer)?;
        if (1..=MAX_SAFE_INTEGER).contains(&value) {
            Ok(Self(value))
        } else {
            Err(invalid(MSG_POSITIVE))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    VaultMeta,
    Group,
    Entry,
    Icon,
    Manifest,
}

impl ObjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectType::VaultMeta => "vault_meta",
            ObjectType::Group => "group",
            ObjectType::Entry => "entry",
            ObjectType::Icon => "icon",
            ObjectType::Manifest => "manifest",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [
            ObjectType::VaultMeta,
            ObjectType::Group,
            ObjectType::Entry,
            ObjectType::Icon,
            ObjectType::Manifest,
        ]
        .into_iter()
        .find(|t| t.as_str() == text)
    }
}

/// Lowercase canonical UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uuid(pub String);

pub fn is_canonical_uuid(text: &str) -> bool {
    text.len() == 36
        && text.char_indices().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_digit() || ('a'..='f').contains(&c)
            }
        })
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            if is_canonical_uuid(s) {
                Ok(Self(s.to_string()))
            } else {
                Err(MSG_UUID)
            }
        })
    }
}

/// E-mail normalisation: trim White_Space, NFC, lowercase.
pub fn normalize_email(text: &str) -> String {
    text.trim_matches(char::is_whitespace)
        .nfc()
        .collect::<String>()
        .to_lowercase()
}

/// Normalised e-mail address: 3–254 characters, contains `@`, no control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(pub String);

impl Email {
    pub fn parse(text: &str) -> Option<Self> {
        let email = normalize_email(text);
        let length = email.chars().count();
        ((3..=254).contains(&length) && email.contains('@') && !email.chars().any(char::is_control))
            .then_some(Self(email))
    }
}

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| Self::parse(s).ok_or(MSG_EMAIL))
    }
}

/// Device name: 1–64 characters, no control characters.
#[derive(Debug, Clone)]
pub struct DeviceName(pub String);

impl<'de> Deserialize<'de> for DeviceName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            let length = s.chars().count();
            if (1..=64).contains(&length) && !s.chars().any(char::is_control) {
                Ok(Self(s.to_string()))
            } else {
                Err(MSG_DEVICE_NAME)
            }
        })
    }
}

/// Passkey name: 1–64 characters, no control characters.
#[derive(Debug, Clone)]
pub struct PasskeyName(pub String);

impl<'de> Deserialize<'de> for PasskeyName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            let length = s.chars().count();
            if (1..=64).contains(&length) && !s.chars().any(char::is_control) {
                Ok(Self(s.to_string()))
            } else {
                Err(MSG_PASSKEY_NAME)
            }
        })
    }
}

/// Favicon URL: at most 2048 characters; the proxy checks the rest.
#[derive(Debug, Clone)]
pub struct FaviconUrl(pub String);

impl<'de> Deserialize<'de> for FaviconUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            if s.chars().count() <= 2048 {
                Ok(Self(s.to_string()))
            } else {
                Err(MSG_FAVICON_URL)
            }
        })
    }
}

/// A TOTP code: exactly six ASCII digits.
#[derive(Clone)]
pub struct TotpCode(pub String);

impl fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpCode(..)")
    }
}

impl<'de> Deserialize<'de> for TotpCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            if s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit()) {
                Ok(Self(s.to_string()))
            } else {
                Err(MSG_TOTP_CODE)
            }
        })
    }
}

/// A backup code as typed (10–32 characters of `A–Z a–z 2–7`, space and
/// `-`), kept in its normalised form.
#[derive(Clone)]
pub struct BackupCode(pub String);

impl fmt::Debug for BackupCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BackupCode(..)")
    }
}

impl<'de> Deserialize<'de> for BackupCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_str(deserializer, |s| {
            let allowed = s
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || matches!(b, b'2'..=b'7' | b' ' | b'-'));
            (allowed && (10..=32).contains(&s.len()))
                .then(|| crate::auth::backup_codes::normalize(s))
                .flatten()
                .map(Self)
                .ok_or(MSG_BACKUP_CODE)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    Web,
    Desktop,
    Mobile,
    Cli,
}

impl ClientType {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientType::Web => "web",
            ClientType::Desktop => "desktop",
            ClientType::Mobile => "mobile",
            ClientType::Cli => "cli",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [
            ClientType::Web,
            ClientType::Desktop,
            ClientType::Mobile,
            ClientType::Cli,
        ]
        .into_iter()
        .find(|t| t.as_str() == text)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub name: DeviceName,
    pub client_type: ClientType,
}

/// KDF parameters as sent; structure is checked by serde (`400`), values by
/// [`KdfParamsInput::validate`] (`422`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParamsInput {
    pub alg: String,
    pub ops: i64,
    pub mem: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub alg: KdfAlg,
    pub ops: i64,
    pub mem: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlg {
    #[serde(rename = "argon2id13")]
    Argon2id13,
}

pub const DEFAULT_KDF: KdfParams = KdfParams {
    alg: KdfAlg::Argon2id13,
    ops: 3,
    mem: 67_108_864,
};

impl KdfParamsInput {
    pub fn validate(&self) -> Result<KdfParams, ApiError> {
        let valid = self.alg == "argon2id13"
            && (2..=10).contains(&self.ops)
            && (19_922_944..=1_073_741_824).contains(&self.mem)
            && self.mem % 1024 == 0;
        if valid {
            Ok(KdfParams {
                alg: KdfAlg::Argon2id13,
                ops: self.ops,
                mem: self.mem,
            })
        } else {
            Err(ApiError::new(ErrorCode::KdfParamsInvalid))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_is_strict() {
        assert!(B64::<1>::parse("AA").is_some());
        for bad in ["AA==", "AB", "A+", "A A", "AAA"] {
            assert!(B64::<1>::parse(bad).is_none(), "{bad}");
        }
        assert!(B64::<32>::parse(&encode_base64url(&[0u8; 31])).is_none());
    }

    #[test]
    fn emails_are_normalised() {
        assert_eq!(
            Email::parse("\u{a0} Ali\u{308}ce@Example.COM\n").map(|e| e.0),
            Some("al\u{ef}ce@example.com".into())
        );
        assert!(Email::parse("no-at").is_none());
        assert!(Email::parse("a@\u{7}b").is_none());
    }

    #[test]
    fn second_factor_codes_are_checked() {
        let totp = |s: &str| serde_json::from_value::<TotpCode>(serde_json::json!(s)).ok();
        assert_eq!(totp("012345").map(|c| c.0).as_deref(), Some("012345"));
        for bad in ["12345", "1234567", "12345a", "１２３４５６"] {
            assert!(totp(bad).is_none(), "{bad}");
        }
        let backup = |s: &str| serde_json::from_value::<BackupCode>(serde_json::json!(s)).ok();
        assert_eq!(
            backup("abcde-fghij").map(|c| c.0).as_deref(),
            Some("ABCDEFGHIJ")
        );
        assert_eq!(
            backup("AB CD EF GH IJ").map(|c| c.0).as_deref(),
            Some("ABCDEFGHIJ")
        );
        let long = format!("ABCDE{}FGHIJ", " ".repeat(23));
        assert!(backup(&long).is_none());
        for bad in ["ABCDEFGHI", "ABCDEFGHI1", "ABCDE_FGHIJ", "----------"] {
            assert!(backup(bad).is_none(), "{bad}");
        }
        assert_eq!(
            format!("{:?}", backup("ABCDEFGHIJ").unwrap()),
            "BackupCode(..)"
        );
    }

    #[test]
    fn uuids_are_canonical() {
        assert!(is_canonical_uuid("0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b"));
        assert!(!is_canonical_uuid("0192B3A4-5C6D-7E8F-9A0B-1C2D3E4F5A6B"));
        assert!(!is_canonical_uuid("0192b3a45c6d7e8f9a0b1c2d3e4f5a6b"));
    }

    #[test]
    fn kdf_values_are_checked() {
        let input = |alg: &str, ops, mem| KdfParamsInput {
            alg: alg.into(),
            ops,
            mem,
        };
        assert!(input("argon2id13", 3, 67_108_864).validate().is_ok());
        assert!(input("argon2id13", 1, 67_108_864).validate().is_err());
        assert!(input("argon2id13", 3, 67_108_865).validate().is_err());
        assert!(input("argon2i13", 3, 67_108_864).validate().is_err());
    }
}
