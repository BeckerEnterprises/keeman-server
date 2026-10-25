//! `keeman-server check`: reports every problem it finds and changes
//! nothing, so it can run next to the server.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use time::{Duration, OffsetDateTime};

use super::{CliResult, environment};
use crate::clock::format_timestamp;
use crate::config::Config;
use crate::db::{Db, attachments, maintenance};
use crate::storage::attachments::Storage;

pub async fn check(config_path: &Path, now: OffsetDateTime) -> CliResult<()> {
    let env = environment();
    let config = Config::load(config_path, &env).map_err(|e| e.to_string())?;
    let mut problems = config.permission_problems(config_path);
    if let Err(error) = config.load_secret(&env) {
        problems.push(error.to_string());
    }
    if config.storage.data_dir.is_dir() {
        private_tree(&config.storage.data_dir, &mut problems);
    }
    match Db::open_existing(&config.database_path()).await {
        Err(error) => problems.push(format!("cannot open database: {error}")),
        Ok(db) => {
            if let Err(error) = database(&db, &config, now, &mut problems).await {
                problems.push(format!("database: {error}"));
            }
            db.close().await;
        }
    }
    for problem in &problems {
        println!("problem: {problem}");
    }
    if problems.is_empty() {
        println!("ok: no problems found");
        Ok(())
    } else {
        Err(format!("{} problem(s) found", problems.len()))
    }
}

/// Every path below the data directory must be private and no link.
fn private_tree(dir: &Path, problems: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            problems.push(format!("cannot read {}: {error}", dir.display()));
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            problems.push(format!("{} is a symbolic link", path.display()));
            continue;
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            problems.push(format!(
                "{} must not be accessible by group or others (chmod go-rwx)",
                path.display()
            ));
        }
        if metadata.is_dir() {
            private_tree(&path, problems);
        }
    }
}

async fn database(
    db: &Db,
    config: &Config,
    now: OffsetDateTime,
    problems: &mut Vec<String>,
) -> Result<(), sqlx::Error> {
    let mut conn = db.read.acquire().await?;
    if !maintenance::migrations_current(&mut conn).await? {
        problems.push("the database has pending or unknown migrations".into());
    }
    let integrity = maintenance::integrity_check(&mut conn).await?;
    if integrity != ["ok"] {
        problems.extend(
            integrity
                .into_iter()
                .map(|line| format!("integrity: {line}")),
        );
    }
    problems.extend(
        maintenance::foreign_key_check(&mut conn)
            .await?
            .into_iter()
            .map(|line| format!("foreign key: {line}")),
    );

    let storage = Storage::new(&config.storage.data_dir);
    let complete: BTreeSet<String> = attachments::ids_in_state(&mut conn, "complete")
        .await?
        .into_iter()
        .collect();
    let uploading: BTreeSet<String> = attachments::ids_in_state(&mut conn, "uploading")
        .await?
        .into_iter()
        .collect();
    let files = storage.blob_ids().await.map_err(sqlx::Error::Io)?;
    for id in complete.difference(&files) {
        problems.push(format!("attachment {id} is complete but has no file"));
    }
    for id in files.difference(&complete) {
        problems.push(format!(
            "file {} belongs to no complete attachment",
            storage.blob_path(id).display()
        ));
    }
    for id in storage.upload_ids().await.map_err(sqlx::Error::Io)? {
        if !uploading.contains(&id) {
            problems.push(format!(
                "upload folder {} belongs to no upload in progress",
                storage.uploads_dir().join(&id).display()
            ));
        }
    }
    let day_ago = format_timestamp(now - Duration::hours(24));
    for id in maintenance::uploads_started_before(&mut conn, &day_ago).await? {
        problems.push(format!("upload {id} started more than 24 h ago"));
    }
    Ok(())
}
