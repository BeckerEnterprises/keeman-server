//! Request handlers per area. They never contain SQL.

pub mod attachments;
pub mod auth;
pub mod favicon;
pub mod freshness;
pub mod me;
pub mod members;
pub mod meta;
pub mod objects;
pub mod pairing;
pub mod passkeys;
pub mod recovery;
pub mod roles;
pub mod rotations;
pub mod second_factor;
pub mod sessions;
pub mod two_factor;
pub mod users;
pub mod vaults;

use crate::error::{ApiError, ApiResult};
use crate::types::{KdfParams, Key32, WrappedKey};
use serde::Deserialize;

/// KDF parameters as stored in `users.kdf_params`.
pub(crate) fn parse_kdf(text: &str) -> ApiResult<KdfParams> {
    serde_json::from_str(text).map_err(ApiError::internal)
}

pub(crate) fn kdf_json(kdf: &KdfParams) -> ApiResult<String> {
    serde_json::to_string(kdf).map_err(ApiError::internal)
}

/// Lowercase hex, used as rate-limit key of an e-mail HMAC.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Recovery material: auth key and recovery-wrapped user key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryMaterial {
    pub auth_key: Key32,
    pub user_key_wrapped: WrappedKey,
}
