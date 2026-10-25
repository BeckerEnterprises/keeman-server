//! Restoring a backup into an empty data directory. Everything is unpacked
//! into a staging folder and checked against the manifest first; only then
//! are database and attachments moved into place.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use super::{DATABASE, Hashing, Item, Manifest, item, parse_manifest, read_manifest};

/// Removes the staging folder when dropped, also after an error.
struct Staging<'a>(&'a Path);

impl Drop for Staging<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.0);
    }
}

fn private_dir(path: &Path, recursive: bool) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(recursive)
        .mode(0o700)
        .create(path)
}

/// The target must not exist or hold at most empty `attachments/` and
/// `uploads/`, as `init` leaves them; a missing target is created (0700).
fn check_target(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == ErrorKind::NotFound => {
            private_dir(dir, false).map_err(|e| format!("cannot create {}: {e}", dir.display()))
        }
        Err(e) => Err(format!("{}: {e}", dir.display())),
        Ok(metadata) if !metadata.is_dir() => Err(format!("{} is not a directory", dir.display())),
        Ok(_) => {
            let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name();
                let allowed = (name == "attachments" || name == "uploads")
                    && entry.file_type().is_ok_and(|t| t.is_dir())
                    && fs::read_dir(entry.path()).is_ok_and(|mut d| d.next().is_none());
                if !allowed {
                    return Err(format!(
                        "data directory {} is not empty ({}); restore needs an empty one",
                        dir.display(),
                        name.to_string_lossy()
                    ));
                }
            }
            Ok(())
        }
    }
}

/// Restores `from` into `data_dir` and returns the manifest.
pub fn restore(from: &Path, data_dir: &Path) -> Result<Manifest, String> {
    let file = File::open(from).map_err(|e| format!("cannot open {}: {e}", from.display()))?;
    check_target(data_dir)?;
    let staging = data_dir.join(format!(".restore-{}", uuid::Uuid::now_v7()));
    private_dir(&staging, false)
        .map_err(|e| format!("cannot create {}: {e}", staging.display()))?;
    let _staging = Staging(&staging);

    let decoder = zstd::Decoder::new(file).map_err(|e| format!("zstd: {e}"))?;
    let mut archive = tar::Archive::new(decoder);
    let mut found: BTreeMap<String, (u64, String)> = BTreeMap::new();
    let mut manifest = None;
    let entries = archive
        .entries()
        .map_err(|e| format!("cannot read the archive: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("cannot read the archive: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("archive entry: {e}"))?
            .to_str()
            .ok_or("archive entry with a non-UTF-8 name")?
            .to_string();
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(format!("archive entry {path} is not a regular file"));
        }
        match item(&path) {
            None => return Err(format!("unexpected archive entry {path}")),
            Some(Item::Manifest) => {
                if manifest.is_some() {
                    return Err("archive with two manifests".into());
                }
                manifest = Some(read_manifest(&mut entry)?);
            }
            Some(Item::Database | Item::Attachment(_)) => {
                if found.contains_key(&path) {
                    return Err(format!("archive entry {path} appears twice"));
                }
                let target = staging.join(&path);
                if let Some(parent) = target.parent() {
                    private_dir(parent, true).map_err(|e| format!("{path}: {e}"))?;
                }
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&target)
                    .map_err(|e| format!("{path}: {e}"))?;
                let mut reader = Hashing::new(&mut entry);
                io::copy(&mut reader, &mut out).map_err(|e| format!("{path}: {e}"))?;
                out.sync_all().map_err(|e| format!("{path}: {e}"))?;
                found.insert(path, reader.finish());
            }
        }
    }
    let manifest = parse_manifest(&manifest.ok_or("archive without manifest")?)?;
    compare(&manifest, &found)?;

    let attachments = data_dir.join("attachments");
    if attachments.exists() {
        fs::remove_dir(&attachments).map_err(|e| format!("{}: {e}", attachments.display()))?;
    }
    let staged = staging.join("attachments");
    if staged.exists() {
        fs::rename(&staged, &attachments).map_err(|e| format!("attachments: {e}"))?;
    } else {
        private_dir(&attachments, false).map_err(|e| format!("attachments: {e}"))?;
    }
    fs::rename(staging.join(DATABASE), data_dir.join(DATABASE))
        .map_err(|e| format!("database: {e}"))?;
    let uploads = data_dir.join("uploads");
    if !uploads.exists() {
        private_dir(&uploads, false).map_err(|e| format!("uploads: {e}"))?;
    }
    File::open(data_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| format!("{}: {e}", data_dir.display()))?;
    Ok(manifest)
}

/// Every file of the manifest must be in the archive with its size and
/// hash, and no other.
fn compare(manifest: &Manifest, found: &BTreeMap<String, (u64, String)>) -> Result<(), String> {
    if !manifest.files.iter().any(|f| f.path == DATABASE) {
        return Err("the backup holds no database".into());
    }
    for file in &manifest.files {
        match found.get(&file.path) {
            None => return Err(format!("{} is missing from the archive", file.path)),
            Some((size, sha256)) if *size != file.size || *sha256 != file.sha256 => {
                return Err(format!("{} does not match the manifest", file.path));
            }
            Some(_) => {}
        }
    }
    if let Some(extra) = found
        .keys()
        .find(|path| !manifest.files.iter().any(|f| &&f.path == path))
    {
        return Err(format!("{extra} is in the archive but not in the manifest"));
    }
    Ok(())
}
