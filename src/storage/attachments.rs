//! Attachment files: complete blobs under `attachments/`, uploads in
//! progress under `uploads/`. Paths depend only on the attachment ID, a
//! canonical UUID checked by the handlers, so they stay inside the data
//! directory. Files are 0600, directories 0700.

use std::collections::BTreeSet;
use std::io::{self, ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};

use axum::body::{Body, Bytes};
use tokio::fs::{self, DirBuilder, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// Bytes per chunk of a streamed download.
const CHUNK: u64 = 64 * 1024;

pub struct Storage {
    attachments: PathBuf,
    uploads: PathBuf,
}

fn not_found_ok(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// A unique name for a temporary file next to its target.
fn temporary(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!(".{name}.{}.tmp", uuid::Uuid::now_v7()))
}

async fn private_dir(path: &Path) -> io::Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .await
}

async fn private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await
}

/// Directory names from a listing, e.g. upload IDs.
async fn names(dir: &Path) -> io::Result<Vec<String>> {
    let mut found = Vec::new();
    let mut entries = match fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(found),
        Err(error) => return Err(error),
    };
    while let Some(entry) = entries.next_entry().await? {
        if let Some(name) = entry.file_name().to_str() {
            found.push(name.to_string());
        }
    }
    Ok(found)
}

impl Storage {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            attachments: data_dir.join("attachments"),
            uploads: data_dir.join("uploads"),
        }
    }

    /// The directories of a data directory, for the permission check.
    pub fn dirs(data_dir: &Path) -> [PathBuf; 2] {
        [data_dir.join("attachments"), data_dir.join("uploads")]
    }

    /// Creates missing directories with mode 0700.
    pub fn create_dirs(&self) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        for dir in [&self.attachments, &self.uploads] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        Ok(())
    }

    fn blob_dir(&self, id: &str) -> PathBuf {
        self.attachments.join(id.get(..2).unwrap_or("00"))
    }

    /// Where the complete blob of an attachment lives.
    pub fn blob_path(&self, id: &str) -> PathBuf {
        self.blob_dir(id).join(format!("{id}.bin"))
    }

    /// The folder of uploads in progress.
    pub fn uploads_dir(&self) -> &Path {
        &self.uploads
    }

    fn upload_dir(&self, id: &str) -> PathBuf {
        self.uploads.join(id)
    }

    fn part_path(&self, id: &str, part: u64) -> PathBuf {
        self.upload_dir(id).join(format!("{part}.part"))
    }

    /// Stores a part; a part uploaded again replaces the old one atomically.
    /// Writes a part into a temporary file beside its place; `place_part`
    /// moves it there once the upload may still take it.
    pub async fn stage_part(&self, id: &str, part: u64, bytes: &[u8]) -> io::Result<PathBuf> {
        let dir = self.upload_dir(id);
        private_dir(&dir).await?;
        let temp = temporary(&dir, &format!("{part}.part"));
        let mut file = private_file(&temp).await?;
        let written = async {
            file.write_all(bytes).await?;
            file.flush().await
        }
        .await;
        drop(file);
        if let Err(error) = written {
            let _ = fs::remove_file(&temp).await;
            return Err(error);
        }
        Ok(temp)
    }

    /// Moves a staged part to its place; an earlier upload of the part is
    /// replaced atomically.
    pub async fn place_part(&self, temp: &Path, id: &str, part: u64) -> io::Result<()> {
        fs::rename(temp, self.part_path(id, part)).await
    }

    /// The size of a stored part, `None` if it is missing.
    pub async fn part_len(&self, id: &str, part: u64) -> io::Result<Option<u64>> {
        match fs::metadata(self.part_path(id, part)).await {
            Ok(metadata) => Ok(Some(metadata.len())),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Joins the parts into a temporary file in the upload directory and
    /// syncs it; [`Storage::publish`] moves it into place.
    pub async fn assemble(&self, id: &str, parts: u64) -> io::Result<PathBuf> {
        let temp = temporary(&self.upload_dir(id), "blob");
        let mut out = private_file(&temp).await?;
        let joined = async {
            for part in 0..parts {
                let mut input = File::open(self.part_path(id, part)).await?;
                tokio::io::copy(&mut input, &mut out).await?;
            }
            out.sync_all().await
        }
        .await;
        drop(out);
        if let Err(error) = joined {
            let _ = fs::remove_file(&temp).await;
            return Err(error);
        }
        Ok(temp)
    }

    /// Moves an assembled blob to its final path and syncs the directory.
    pub async fn publish(&self, temp: &Path, id: &str) -> io::Result<()> {
        let dir = self.blob_dir(id);
        private_dir(&dir).await?;
        fs::rename(temp, self.blob_path(id)).await?;
        File::open(&dir).await?.sync_all().await
    }

    pub async fn discard(&self, temp: &Path) {
        let _ = fs::remove_file(temp).await;
    }

    /// The blob and its length.
    pub async fn open(&self, id: &str) -> io::Result<(File, u64)> {
        let file = File::open(self.blob_path(id)).await?;
        let len = file.metadata().await?.len();
        Ok((file, len))
    }

    /// The parts of an upload, also leftovers of an interrupted `complete`.
    pub async fn remove_upload(&self, id: &str) -> io::Result<()> {
        not_found_ok(fs::remove_dir_all(self.upload_dir(id)).await)
    }

    /// Everything stored for this attachment; missing files are fine.
    pub async fn remove(&self, id: &str) -> io::Result<()> {
        not_found_ok(fs::remove_file(self.blob_path(id)).await)?;
        self.remove_upload(id).await
    }

    /// Like [`Storage::remove`], but only logs a failure.
    pub async fn remove_logged(&self, ids: &[String]) {
        for id in ids {
            if let Err(error) = self.remove(id).await {
                tracing::warn!(error = %error, "cannot delete attachment files");
            }
        }
    }

    /// IDs of the complete blobs on disk.
    pub async fn blob_ids(&self) -> io::Result<BTreeSet<String>> {
        let mut ids = BTreeSet::new();
        for prefix in names(&self.attachments).await? {
            for name in names(&self.attachments.join(&prefix)).await? {
                if let Some(id) = name.strip_suffix(".bin") {
                    ids.insert(id.to_string());
                }
            }
        }
        Ok(ids)
    }

    /// IDs with an upload directory.
    pub async fn upload_ids(&self) -> io::Result<BTreeSet<String>> {
        Ok(names(&self.uploads).await?.into_iter().collect())
    }
}

/// `len` bytes of `file` from `start`, as a streamed body.
pub async fn body(mut file: File, start: u64, len: u64) -> io::Result<Body> {
    file.seek(SeekFrom::Start(start)).await?;
    let stream = futures_util::stream::try_unfold((file, len), |(mut file, left)| async move {
        if left == 0 {
            return Ok::<_, io::Error>(None);
        }
        let size = usize::try_from(left.min(CHUNK)).unwrap_or(64 * 1024);
        let mut chunk = vec![0u8; size];
        file.read_exact(&mut chunk).await?;
        let rest = left - chunk.len() as u64;
        Ok(Some((Bytes::from(chunk), (file, rest))))
    });
    Ok(Body::from_stream(stream))
}
