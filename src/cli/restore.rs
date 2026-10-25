//! `keeman-server restore`: needs neither configuration nor secret, only
//! the archive and an empty data directory. The server must be stopped.

use std::path::Path;

use super::CliResult;
use crate::backup::{DATABASE, restore};
use crate::db::maintenance;

pub async fn restore(from: &Path, data_dir: &Path) -> CliResult<()> {
    let manifest = {
        let from = from.to_path_buf();
        let data_dir = data_dir.to_path_buf();
        tokio::task::spawn_blocking(move || restore::restore(&from, &data_dir))
            .await
            .map_err(|e| e.to_string())??
    };
    let mut conn = maintenance::open_file(&data_dir.join(DATABASE))
        .await
        .map_err(|e| format!("restored database: {e}"))?;
    let integrity = maintenance::integrity_check(&mut conn)
        .await
        .map_err(|e| format!("restored database: {e}"))?;
    if integrity != ["ok"] {
        return Err(format!(
            "the restored database fails the integrity check: {}",
            integrity.join("; ")
        ));
    }
    let current = maintenance::migrations_current(&mut conn)
        .await
        .map_err(|e| format!("restored database: {e}"))?;
    drop(conn);
    for id in &manifest.missing {
        eprintln!("warning: attachment {id} had no file when the backup was made");
    }
    if !current {
        eprintln!("note: the backup is from another version; `serve` applies pending migrations");
    }
    let counts = manifest.counts;
    println!(
        "restored backup of {}: {} accounts, {} vaults, {} objects, {} attachments",
        manifest.created, counts.users, counts.vaults, counts.objects, counts.attachments
    );
    Ok(())
}
