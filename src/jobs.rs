//! Background cleanup: every 10 minutes and once at startup.

use std::collections::BTreeSet;
use std::sync::Arc;

use time::Duration;
use tokio::task::JoinHandle;

use crate::app::App;
use crate::clock::format_timestamp;
use crate::db::attachments;
use crate::db::cleanup::{self, Cutoffs, Removed};

pub const INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
/// Tombstones removed per transaction, so writers never wait long.
const TOMBSTONE_BLOCK: i64 = 1000;

pub async fn cleanup(app: &App) -> Result<Removed, sqlx::Error> {
    let now = app.now();
    let before = |age: Duration| format_timestamp(now - age);
    let cutoffs = Cutoffs {
        now: &format_timestamp(now),
        refresh_history: &before(app.refresh_ttl()),
        throttle_idle: &before(Duration::hours(24)),
        invite_expired: &before(Duration::days(30)),
        security_log: &before(Duration::days(i64::from(
            app.config.logging.security_log_retention_days,
        ))),
        idempotency: &before(Duration::hours(24)),
    };
    let mut tx = app.db.begin().await?;
    let mut removed = cleanup::run(&mut tx, &cutoffs).await?;
    tx.commit().await?;
    let tombstones = before(Duration::days(i64::from(
        app.config.limits.tombstone_retention_days,
    )));
    loop {
        let mut tx = app.db.begin().await?;
        let purged = cleanup::purge_tombstones(&mut tx, &tombstones, TOMBSTONE_BLOCK).await?;
        tx.commit().await?;
        removed.tombstones += purged;
        if purged < u64::try_from(TOMBSTONE_BLOCK).unwrap_or(0) {
            break;
        }
    }
    let mut tx = app.db.begin().await?;
    let stale = attachments::delete_stale_uploads(&mut tx, &before(Duration::hours(24))).await?;
    tx.commit().await?;
    app.storage.remove_logged(&stale).await;
    removed.attachments = stale.len() as u64;
    check_attachments(app).await?;
    app.limiter.prune();
    Ok(removed)
}

/// How attachment files and rows differ.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AttachmentReport {
    /// Upload directories without a running upload; removed.
    pub leftover_uploads: usize,
    /// Blobs without a row; only reported.
    pub orphaned_files: usize,
    /// Complete attachments without a blob; only reported.
    pub missing_files: usize,
}

/// Removes leftover upload directories and reports blobs without rows and
/// rows without blobs, never deleting a blob automatically.
pub async fn check_attachments(app: &App) -> Result<AttachmentReport, sqlx::Error> {
    // Files first: a file seen here belongs to a row that already exists.
    let files = async {
        Ok::<_, std::io::Error>((
            app.storage.upload_ids().await?,
            app.storage.blob_ids().await?,
        ))
    }
    .await;
    let (uploads, blobs) = match files {
        Ok(files) => files,
        Err(error) => {
            tracing::error!(error = %error, "cannot list attachment files");
            return Ok(AttachmentReport::default());
        }
    };
    let mut conn = app.db.read.acquire().await?;
    let uploading: BTreeSet<String> = attachments::ids_in_state(&mut conn, "uploading")
        .await?
        .into_iter()
        .collect();
    let complete: BTreeSet<String> = attachments::ids_in_state(&mut conn, "complete")
        .await?
        .into_iter()
        .collect();
    drop(conn);
    let leftover: Vec<String> = uploads.difference(&uploading).cloned().collect();
    for id in &leftover {
        if let Err(error) = app.storage.remove_upload(id).await {
            tracing::warn!(error = %error, "cannot delete upload parts");
        }
    }
    let report = AttachmentReport {
        leftover_uploads: leftover.len(),
        orphaned_files: blobs
            .iter()
            .filter(|id| !complete.contains(*id) && !uploading.contains(*id))
            .count(),
        missing_files: complete.difference(&blobs).count(),
    };
    if report.orphaned_files > 0 || report.missing_files > 0 {
        tracing::warn!(
            orphaned_files = report.orphaned_files,
            missing_files = report.missing_files,
            "attachment files and database differ"
        );
    }
    Ok(report)
}

pub fn spawn(app: Arc<App>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(INTERVAL);
        loop {
            // The first tick fires immediately.
            interval.tick().await;
            if let Err(error) = cleanup(&app).await {
                tracing::error!(error = %error, "cleanup failed");
            }
        }
    })
}
