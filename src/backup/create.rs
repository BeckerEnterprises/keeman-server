//! Writing a backup, also while the server runs: `VACUUM INTO` takes a
//! consistent snapshot, and the attachment IDs come from that snapshot.

use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use super::{
    DATABASE, FORMAT, FileEntry, Hashing, LEVEL, MANIFEST, Manifest, VERSION, attachment_path,
};
use crate::clock::format_timestamp;
use crate::config::Config;
use crate::db::{Db, attachments, maintenance};
use crate::storage::attachments::Storage;

pub struct Report {
    pub manifest: Manifest,
}

/// Removes a path when dropped, unless disarmed: temporary folders and
/// unfinished archives never stay behind.
struct Cleanup {
    path: Option<PathBuf>,
    dir: bool,
}

impl Cleanup {
    fn file(path: &Path) -> Self {
        Self {
            path: Some(path.to_path_buf()),
            dir: false,
        }
    }

    fn dir(path: &Path) -> Self {
        Self {
            path: Some(path.to_path_buf()),
            dir: true,
        }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = if self.dir {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            };
        }
    }
}

fn partial(out: &Path) -> PathBuf {
    let mut name = out.as_os_str().to_owned();
    name.push(".partial");
    PathBuf::from(name)
}

/// Writes a backup to `out`, which must not exist yet.
pub async fn create(config: &Config, out: &Path, now: OffsetDateTime) -> Result<Report, String> {
    if out.exists() || partial(out).exists() {
        return Err(format!("{} already exists", out.display()));
    }
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err(format!("folder {} does not exist", parent.display()));
    }
    let db = Db::open_existing(&config.database_path())
        .await
        .map_err(|e| format!("cannot open database: {e}"))?;
    let result = snapshot_and_write(&db, config, parent, out, now).await;
    db.close().await;
    result
}

async fn snapshot_and_write(
    db: &Db,
    config: &Config,
    parent: &Path,
    out: &Path,
    now: OffsetDateTime,
) -> Result<Report, String> {
    let error = |e: sqlx::Error| format!("database: {e}");
    {
        let mut conn = db.read.acquire().await.map_err(error)?;
        if !maintenance::migrations_current(&mut conn)
            .await
            .map_err(error)?
        {
            return Err(
                "the database has pending or unknown migrations; run `migrate` with this binary"
                    .into(),
            );
        }
    }

    let temp = parent.join(format!(".keeman-backup-{}", uuid::Uuid::now_v7()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&temp)
        .map_err(|e| format!("cannot create {}: {e}", temp.display()))?;
    let _temp = Cleanup::dir(&temp);
    let snapshot = temp.join(DATABASE);
    maintenance::vacuum_into(db, &snapshot)
        .await
        .map_err(error)?;

    let mut conn = maintenance::open_file(&snapshot).await.map_err(error)?;
    let counts = maintenance::counts(&mut conn).await.map_err(error)?;
    let ids = attachments::ids_in_state(&mut conn, "complete")
        .await
        .map_err(error)?;
    drop(conn);

    let storage = Storage::new(&config.storage.data_dir);
    let head = Manifest {
        format: FORMAT.into(),
        version: VERSION,
        created: format_timestamp(now),
        server_version: env!("CARGO_PKG_VERSION").into(),
        counts,
        files: Vec::new(),
        missing: Vec::new(),
    };
    let out = out.to_path_buf();
    let mtime = u64::try_from(now.unix_timestamp()).unwrap_or(0);
    let manifest = tokio::task::spawn_blocking(move || {
        write_archive(&out, &snapshot, &storage, &ids, head, mtime)
    })
    .await
    .map_err(|e| e.to_string())??;
    Ok(Report { manifest })
}

fn write_archive(
    out: &Path,
    snapshot: &Path,
    storage: &Storage,
    ids: &[String],
    mut manifest: Manifest,
    mtime: u64,
) -> Result<Manifest, String> {
    let io = |what: &str, e: std::io::Error| format!("{what}: {e}");
    let partial = partial(out);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&partial)
        .map_err(|e| io(&format!("cannot create {}", partial.display()), e))?;
    let mut cleanup = Cleanup::file(&partial);
    let encoder = zstd::Encoder::new(file, LEVEL).map_err(|e| io("zstd", e))?;
    let mut tar = tar::Builder::new(encoder);

    let database = File::open(snapshot).map_err(|e| io("snapshot", e))?;
    manifest
        .files
        .push(append(&mut tar, DATABASE, database, mtime)?);
    for id in ids {
        match File::open(storage.blob_path(id)) {
            Ok(blob) => manifest
                .files
                .push(append(&mut tar, &attachment_path(id), blob, mtime)?),
            Err(e) if e.kind() == ErrorKind::NotFound => manifest.missing.push(id.clone()),
            Err(e) => return Err(io(&format!("attachment {id}"), e)),
        }
    }
    let json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    let mut header = header(json.len() as u64, mtime);
    tar.append_data(&mut header, MANIFEST, json.as_slice())
        .map_err(|e| io("archive", e))?;

    let encoder = tar.into_inner().map_err(|e| io("archive", e))?;
    let file = encoder.finish().map_err(|e| io("zstd", e))?;
    file.sync_all().map_err(|e| io("archive", e))?;
    fs::rename(&partial, out).map_err(|e| io("cannot rename the archive", e))?;
    cleanup.disarm();
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| io("folder", e))?;
    }
    Ok(manifest)
}

fn header(size: u64, mtime: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(size);
    header.set_mode(0o600);
    header.set_mtime(mtime);
    header.set_uid(0);
    header.set_gid(0);
    header
}

/// Appends a file under `path` and returns its manifest entry.
fn append<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    file: File,
    mtime: u64,
) -> Result<FileEntry, String> {
    let size = file.metadata().map_err(|e| format!("{path}: {e}"))?.len();
    let mut header = header(size, mtime);
    let mut reader = Hashing::new(file);
    tar.append_data(&mut header, path, &mut reader)
        .map_err(|e| format!("{path}: {e}"))?;
    let (len, sha256) = reader.finish();
    if len != size {
        return Err(format!("{path} changed while it was read"));
    }
    Ok(FileEntry {
        path: path.to_string(),
        size,
        sha256,
    })
}
