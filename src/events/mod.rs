//! Change notifications over WebSocket.

pub mod hub;
pub mod socket;

pub use hub::Hub;

use serde_json::{Value, json};

pub fn vault_changed(vault_id: &str, revision: i64) -> Value {
    json!({ "type": "vault_changed", "vault_id": vault_id, "revision": revision })
}

pub fn vaults_changed() -> Value {
    json!({ "type": "vaults_changed" })
}

pub fn user_data_changed(revision: i64) -> Value {
    json!({ "type": "user_data_changed", "revision": revision })
}
