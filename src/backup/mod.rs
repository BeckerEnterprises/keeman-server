//! Backups: a consistent snapshot of the database and every complete
//! attachment file in one tar archive with zstd, described by a manifest
//! with the size and SHA-256 of every file. A restore checks every file
//! against the manifest before anything is put in place.
//!
//! Archive entries are exactly `manifest.json` (last), `keeman.sqlite` and
//! `attachments/<xx>/<id>.bin`. The server secret and the configuration are
//! never part of a backup.

pub mod create;
pub mod restore;
pub mod retention;

use std::io::{self, Read};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::db::maintenance::Counts;
use crate::types::is_canonical_uuid;

pub const FORMAT: &str = "keeman-backup";
pub const VERSION: u32 = 1;
pub const MANIFEST: &str = "manifest.json";
pub const DATABASE: &str = "keeman.sqlite";
/// zstd level of the archive.
pub const LEVEL: i32 = 10;
/// Upper bound for the manifest when reading an archive.
const MANIFEST_MAX: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub version: u32,
    pub created: String,
    pub server_version: String,
    pub counts: Counts,
    pub files: Vec<FileEntry>,
    /// Complete attachments whose file was missing when the backup ran.
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// What an archive entry may be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Manifest,
    Database,
    Attachment(String),
}

/// The archive path of an attachment's blob.
pub fn attachment_path(id: &str) -> String {
    format!("attachments/{}/{id}.bin", id.get(..2).unwrap_or("00"))
}

/// Classifies an archive path; anything else is refused. Attachment paths
/// need a canonical UUID and its first two characters as folder, so no
/// entry can leave the data directory.
pub fn item(path: &str) -> Option<Item> {
    match path {
        MANIFEST => Some(Item::Manifest),
        DATABASE => Some(Item::Database),
        _ => {
            let (prefix, file) = path.strip_prefix("attachments/")?.split_once('/')?;
            let id = file.strip_suffix(".bin")?;
            (is_canonical_uuid(id) && id.get(..2) == Some(prefix))
                .then(|| Item::Attachment(id.to_string()))
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A reader that hashes and counts what passes through.
pub struct Hashing<R> {
    inner: R,
    hasher: Sha256,
    len: u64,
}

impl<R> Hashing<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            len: 0,
        }
    }

    /// Size and SHA-256 (hex) of everything read.
    pub fn finish(self) -> (u64, String) {
        (self.len, hex(&self.hasher.finalize()))
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(read) = buf.get(..n) {
            self.hasher.update(read);
        }
        self.len += n as u64;
        Ok(n)
    }
}

/// Parses and checks a manifest read from an archive.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, String> {
    let manifest: Manifest =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid manifest: {e}"))?;
    if manifest.format != FORMAT || manifest.version != VERSION {
        return Err(format!(
            "unsupported backup format {} version {}",
            manifest.format, manifest.version
        ));
    }
    for file in &manifest.files {
        if !matches!(item(&file.path), Some(Item::Database | Item::Attachment(_))) {
            return Err(format!("manifest names an invalid path {}", file.path));
        }
    }
    Ok(manifest)
}

/// Reads at most the manifest size limit.
fn read_manifest(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MANIFEST_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read the manifest: {e}"))?;
    if bytes.len() as u64 > MANIFEST_MAX {
        return Err("manifest too large".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b";

    #[test]
    fn only_known_paths_are_items() {
        assert_eq!(item("manifest.json"), Some(Item::Manifest));
        assert_eq!(item("keeman.sqlite"), Some(Item::Database));
        assert_eq!(
            item(&attachment_path(ID)),
            Some(Item::Attachment(ID.to_string()))
        );
        for bad in [
            "",
            "/keeman.sqlite",
            "./keeman.sqlite",
            "../keeman.sqlite",
            "keeman.sqlite-wal",
            "attachments/02/0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b.bin",
            "attachments/01/../../etc/passwd",
            "attachments/01/0192B3A4-5C6D-7E8F-9A0B-1C2D3E4F5A6B.bin",
            "attachments/01/0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b",
            "attachments/01/0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b.bin/x",
            "uploads/0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b/0.part",
            "server_secret",
            "config.toml",
        ] {
            assert_eq!(item(bad), None, "{bad}");
        }
    }

    #[test]
    fn hashes_what_passes_through() {
        let mut reader = Hashing::new(&b"abc"[..]);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(
            reader.finish(),
            (
                3,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into()
            )
        );
    }

    #[test]
    fn manifests_are_checked() {
        let good = Manifest {
            format: FORMAT.into(),
            version: VERSION,
            created: "2026-10-25T00:00:00.000Z".into(),
            server_version: "0.1.0".into(),
            counts: Counts {
                users: 1,
                vaults: 1,
                objects: 3,
                attachments: 1,
            },
            files: vec![
                FileEntry {
                    path: DATABASE.into(),
                    size: 1,
                    sha256: "00".into(),
                },
                FileEntry {
                    path: attachment_path(ID),
                    size: 1,
                    sha256: "00".into(),
                },
            ],
            missing: vec![],
        };
        let bytes = serde_json::to_vec(&good).unwrap();
        assert_eq!(parse_manifest(&bytes).unwrap(), good);
        for change in [
            |m: &mut Manifest| m.version = 2,
            |m: &mut Manifest| m.format = "other".into(),
            |m: &mut Manifest| m.files[0].path = "../x".into(),
            |m: &mut Manifest| m.files[0].path = MANIFEST.into(),
        ] {
            let mut bad = good.clone();
            change(&mut bad);
            assert!(parse_manifest(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        assert!(parse_manifest(br#"{"format":"keeman-backup"}"#).is_err());
        assert!(read_manifest(std::io::repeat(b' ')).is_err());
    }
}
