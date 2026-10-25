//! `keeman-server backup`: one archive with `--out`, or a timestamped one
//! in a folder with retention (`--dir`). Runs next to the running server.
//! An archive without some attachment files is still written, but ends
//! with exit code 3 and prunes nothing, so it never pushes out a complete
//! backup.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use time::OffsetDateTime;

use super::CliResult;
use crate::backup::{create, retention};
use crate::config::Config;

pub struct Target {
    pub out: Option<PathBuf>,
    pub dir: Option<PathBuf>,
    pub keep_daily: usize,
    pub keep_weekly: usize,
}

/// Exit code of a backup written without some attachment files.
pub const INCOMPLETE: u8 = 3;

pub async fn backup(config: &Config, target: Target, now: OffsetDateTime) -> CliResult<ExitCode> {
    let path = match (&target.out, &target.dir) {
        (Some(out), None) => out.clone(),
        (None, Some(dir)) => {
            warn_if_shared(dir);
            dir.join(retention::file_name(now))
        }
        _ => return Err("give either --out or --dir".into()),
    };
    let report = create::create(config, &path, now).await?;
    let missing = &report.manifest.missing;
    for id in missing {
        eprintln!("warning: attachment {id} has no file; it is listed as missing in the manifest");
    }
    if let Some(dir) = &target.dir
        && missing.is_empty()
    {
        prune(dir, &path, target.keep_daily, target.keep_weekly)?;
    }
    let counts = report.manifest.counts;
    eprintln!(
        "backup: {} accounts, {} vaults, {} objects, {} attachments",
        counts.users, counts.vaults, counts.objects, counts.attachments
    );
    println!("{}", path.display());
    if missing.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!(
        "error: backup incomplete, {} attachment file(s) missing; older backups were kept",
        missing.len()
    );
    Ok(ExitCode::from(INCOMPLETE))
}

/// Backups hold auth hashes and wrapped keys: say so if others can read them.
fn warn_if_shared(dir: &Path) {
    if let Ok(metadata) = std::fs::metadata(dir)
        && metadata.permissions().mode() & 0o077 != 0
    {
        eprintln!(
            "warning: {} is accessible by group or others (chmod go-rwx)",
            dir.display()
        );
    }
}

fn prune(dir: &Path, written: &Path, keep_daily: usize, keep_weekly: usize) -> CliResult<()> {
    let names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .collect();
    let keep = written
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    for name in retention::to_delete(&names, keep_daily, keep_weekly, keep) {
        std::fs::remove_file(dir.join(&name)).map_err(|e| format!("cannot remove {name}: {e}"))?;
        eprintln!("removed {name}");
    }
    Ok(())
}
