//! The fixed IDs of a vault's manifest: one root and 64 shards, derived from
//! the vault ID so that two devices creating a manifest at the same time hit
//! the same IDs and one of them gets a conflict. The server only uses them to
//! keep the `manifest` type to these IDs; it never reads a manifest.

use std::collections::HashSet;

use blake2::{Blake2b128, Digest};

/// Shards per manifest.
pub const SHARDS: usize = 64;

/// UUIDv8 (RFC 9562) from the first 16 bytes of BLAKE2b-128 of `label`.
fn uuid8(label: &str) -> String {
    let mut b: [u8; 16] = Blake2b128::digest(label.as_bytes()).into();
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

pub fn root_id(vault_id: &str) -> String {
    uuid8(&format!("keeman:v1:manifest:{vault_id}:root"))
}

pub fn shard_id(vault_id: &str, shard: usize) -> String {
    uuid8(&format!("keeman:v1:manifest:{vault_id}:shard:{shard}"))
}

/// All 65 manifest IDs of one vault.
pub struct ManifestIds {
    pub root: String,
    all: HashSet<String>,
}

impl ManifestIds {
    pub fn of(vault_id: &str) -> Self {
        let root = root_id(vault_id);
        let mut all: HashSet<String> = (0..SHARDS).map(|k| shard_id(vault_id, k)).collect();
        all.insert(root.clone());
        Self { root, all }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.all.contains(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Computed independently with Python's hashlib.blake2b(digest_size=16).
    const VAULT: &str = "0192f0a1-0000-7000-8000-000000000001";

    #[test]
    fn ids_match_an_independent_implementation() {
        assert_eq!(root_id(VAULT), "90c59180-834e-8b34-aad8-8dfa1ff9f2b6");
        assert_eq!(shard_id(VAULT, 0), "79be765c-42de-82a0-90ff-6d2e2fb7219d");
        assert_eq!(shard_id(VAULT, 63), "33746697-f1e6-80dc-8218-3a41e5656250");
    }

    #[test]
    fn a_vault_has_65_distinct_manifest_ids() {
        let ids = ManifestIds::of(VAULT);
        assert!(ids.contains(&ids.root));
        assert!((0..SHARDS).all(|k| ids.contains(&shard_id(VAULT, k))));
        assert_eq!(ids.all.len(), SHARDS + 1);
        assert!(!ids.contains(VAULT));
        assert!(!ids.contains(&shard_id(VAULT, SHARDS)));
        assert!(!ids.contains(&root_id("0192f0a1-0000-7000-8000-000000000002")));
    }
}
