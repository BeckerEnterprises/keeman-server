//! Attachments: upload in parts, complete, download with a
//! single range, delete, transfer, and the quota of the account a vault
//! counts against. The server only ever sees encrypted blobs.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::vaults::{Need, require, vault_id};
use crate::app::App;
use crate::auth::{AuthSession, NoQuery};
use crate::clock::format_timestamp;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::{StrictJson, octet_stream};
use crate::quota;
use crate::storage::attachments::body;
use crate::types::{Uuid, is_canonical_uuid};

/// Size of every part but the last (fixed in API v1).
pub const PART_SIZE: u64 = 8 * 1024 * 1024;
/// Body limit of a part.
const PART_BODY_LIMIT: usize = 8 * 1024 * 1024 + 64 * 1024;
/// The smallest blob: an empty file.
const MIN_BLOB: u64 = 42;

/// The largest encrypted blob for this limit on original files.
pub fn blob_limit(attachment_max_bytes: u64) -> u64 {
    attachment_max_bytes + 17 * (attachment_max_bytes / 65536 + 1) + 25
}

fn attachment_id(path: &str) -> ApiResult<&str> {
    if is_canonical_uuid(path) {
        Ok(path)
    } else {
        Err(ApiError::parameter("attachment_id", "not a canonical UUID"))
    }
}

/// Decimal digits without sign or leading zeros.
fn part_index(path: &str) -> ApiResult<u64> {
    let digits = !path.is_empty() && path.bytes().all(|b| b.is_ascii_digit());
    if !digits || (path.len() > 1 && path.starts_with('0')) {
        return Err(ApiError::parameter("part", "not a part index"));
    }
    path.parse()
        .map_err(|_| ApiError::parameter("part", "not a part index"))
}

/// Expected size of a part of an upload.
fn part_len(size: u64, parts: u64, part: u64) -> u64 {
    if part + 1 < parts {
        PART_SIZE
    } else {
        size - PART_SIZE * (parts - 1)
    }
}

fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// The attachment, if it belongs to this vault; otherwise `404`.
async fn in_vault(
    conn: &mut Conn,
    id: &str,
    vault_id: &str,
) -> ApiResult<db::attachments::Attachment> {
    db::attachments::get(conn, id)
        .await?
        .filter(|a| a.vault_id == vault_id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))
}

/// `507` if `size` more bytes would exceed the quota of the account the
/// vault counts against; without an owner it is the caller's.
async fn check_quota(
    app: &App,
    conn: &mut Conn,
    vault_id: &str,
    caller: &str,
    size: u64,
) -> ApiResult<()> {
    let account = quota::account_for(conn, vault_id, caller).await?;
    let growth = i64::try_from(size).unwrap_or(i64::MAX);
    let now = format_timestamp(app.now());
    quota::require_room(
        conn,
        &account,
        growth,
        app.config.limits.user_quota_bytes,
        &now,
    )
    .await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBody {
    attachment_id: Uuid,
    entry_id: Uuid,
    size: u64,
}

pub async fn create(
    State(app): State<Arc<App>>,
    session: AuthSession,
    Path(path): Path<String>,
    _: NoQuery,
    StrictJson(body): StrictJson<CreateBody>,
) -> ApiResult<Response> {
    let vault_id = vault_id(&path)?;
    if body.size < MIN_BLOB {
        return Err(ApiError::pointer("/size", "smaller than an empty blob"));
    }
    if body.size > blob_limit(app.config.limits.attachment_max_bytes) {
        return Err(ApiError::new(ErrorCode::AttachmentTooLarge));
    }
    let parts = body.size.div_ceil(PART_SIZE);
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    require(&mut tx, vault_id, user_id, Need::Member).await?;
    if db::attachments::get(&mut tx, &body.attachment_id.0)
        .await?
        .is_some()
    {
        return Err(ApiError::new(ErrorCode::Conflict));
    }
    check_quota(&app, &mut tx, vault_id, user_id, body.size).await?;
    db::attachments::insert(
        &mut tx,
        &db::attachments::NewAttachment {
            id: &body.attachment_id.0,
            vault_id,
            entry_id: &body.entry_id.0,
            size: signed(body.size),
            parts: signed(parts),
            created_by: user_id,
            now: &now,
        },
    )
    .await?;
    tx.commit().await?;
    let answer: Value = json!({ "part_size": PART_SIZE, "parts": parts });
    Ok((StatusCode::CREATED, Json(answer)).into_response())
}

pub async fn put_part(
    State(app): State<Arc<App>>,
    session: AuthSession,
    Path((vault, attachment, part)): Path<(String, String, String)>,
    _: NoQuery,
    request: Request,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&vault)?;
    let id = attachment_id(&attachment)?;
    let part = part_index(&part)?;
    let bytes = octet_stream(request, PART_BODY_LIMIT).await?;
    let mut conn = app.db.read.acquire().await?;
    require(&mut conn, vault_id, &session.user_id, Need::Member).await?;
    let attachment = in_vault(&mut conn, id, vault_id).await?;
    drop(conn);
    if attachment.complete() {
        return Err(ApiError::new(ErrorCode::Conflict));
    }
    let (size, parts) = (unsigned(attachment.size), unsigned(attachment.parts));
    if part >= parts {
        return Err(ApiError::parameter("part", "no such part"));
    }
    if bytes.len() as u64 != part_len(size, parts, part) {
        return Err(ApiError::pointer("", "wrong part size"));
    }
    app.storage
        .write_part(id, part, &bytes)
        .await
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn complete(
    State(app): State<Arc<App>>,
    session: AuthSession,
    Path((vault, attachment)): Path<(String, String)>,
    _: NoQuery,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&vault)?;
    let id = attachment_id(&attachment)?;
    let mut conn = app.db.read.acquire().await?;
    require(&mut conn, vault_id, &session.user_id, Need::Member).await?;
    let attachment = in_vault(&mut conn, id, vault_id).await?;
    drop(conn);
    if attachment.complete() {
        return Ok(StatusCode::NO_CONTENT);
    }
    let (size, parts) = (unsigned(attachment.size), unsigned(attachment.parts));
    for part in 0..parts {
        let stored = app
            .storage
            .part_len(id, part)
            .await
            .map_err(ApiError::internal)?;
        if stored != Some(part_len(size, parts, part)) {
            return Err(ApiError::new(ErrorCode::AttachmentIncomplete));
        }
    }
    // Assembled without holding the write lock; published inside it.
    let temp = app
        .storage
        .assemble(id, parts)
        .await
        .map_err(ApiError::internal)?;
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    let current = db::attachments::get(&mut tx, id)
        .await?
        .filter(|a| a.vault_id == vault_id);
    let Some(current) = current else {
        app.storage.discard(&temp).await;
        return Err(ApiError::new(ErrorCode::NotFound));
    };
    if current.complete() {
        app.storage.discard(&temp).await;
        return Ok(StatusCode::NO_CONTENT);
    }
    if let Err(error) = app.storage.publish(&temp, id).await {
        app.storage.discard(&temp).await;
        return Err(ApiError::internal(error));
    }
    db::attachments::complete(&mut tx, id, &now).await?;
    tx.commit().await?;
    if let Err(error) = app.storage.remove_upload(id).await {
        tracing::warn!(error = %error, "cannot delete upload parts");
    }
    Ok(StatusCode::NO_CONTENT)
}

/// What a `Range` header asks for.
#[derive(Debug, PartialEq, Eq)]
enum Wanted {
    All,
    /// First and last byte, inclusive.
    Part(u64, u64),
    Unsatisfiable,
}

fn number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// A single range `a-b`, `a-` or `-n`; several or unreadable ranges are
/// ignored, as RFC 9110 allows.
fn wanted(value: Option<&HeaderValue>, total: u64) -> Wanted {
    let Some(spec) = value
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().strip_prefix("bytes="))
    else {
        return Wanted::All;
    };
    if spec.contains(',') {
        return Wanted::All;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return Wanted::All;
    };
    match (first, last) {
        ("", suffix) => match number(suffix) {
            None => Wanted::All,
            Some(0) => Wanted::Unsatisfiable,
            Some(_) if total == 0 => Wanted::Unsatisfiable,
            Some(n) => Wanted::Part(total.saturating_sub(n), total - 1),
        },
        (start, "") => match number(start) {
            None => Wanted::All,
            Some(start) if start >= total => Wanted::Unsatisfiable,
            Some(start) => Wanted::Part(start, total - 1),
        },
        (start, end) => match (number(start), number(end)) {
            (Some(start), Some(end)) if start <= end => {
                if start >= total {
                    Wanted::Unsatisfiable
                } else {
                    Wanted::Part(start, end.min(total - 1))
                }
            }
            _ => Wanted::All,
        },
    }
}

pub async fn download(
    State(app): State<Arc<App>>,
    session: AuthSession,
    Path((vault, attachment)): Path<(String, String)>,
    _: NoQuery,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let vault_id = vault_id(&vault)?;
    let id = attachment_id(&attachment)?;
    let mut conn = app.db.read.acquire().await?;
    require(&mut conn, vault_id, &session.user_id, Need::Member).await?;
    let attachment = in_vault(&mut conn, id, vault_id).await?;
    drop(conn);
    if !attachment.complete() {
        return Err(ApiError::new(ErrorCode::NotFound));
    }
    let (file, total) = app.storage.open(id).await.map_err(ApiError::internal)?;
    let (status, start, end) = match wanted(headers.get(header::RANGE), total) {
        Wanted::All => (StatusCode::OK, 0, total),
        Wanted::Part(first, last) => (StatusCode::PARTIAL_CONTENT, first, last + 1),
        Wanted::Unsatisfiable => {
            return Err(ApiError::new(ErrorCode::RangeNotSatisfiable).header(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{total}")).map_err(ApiError::internal)?,
            ));
        }
    };
    let content = body(file, start, end - start)
        .await
        .map_err(ApiError::internal)?;
    let mut response = (status, content).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(end - start));
    if status == StatusCode::PARTIAL_CONTENT {
        let range = format!("bytes {start}-{}/{total}", end - 1);
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&range).map_err(ApiError::internal)?,
        );
    }
    Ok(response)
}

pub async fn delete(
    State(app): State<Arc<App>>,
    session: AuthSession,
    Path((vault, attachment)): Path<(String, String)>,
    _: NoQuery,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&vault)?;
    let id = attachment_id(&attachment)?;
    let mut tx = app.db.begin().await?;
    require(&mut tx, vault_id, &session.user_id, Need::Member).await?;
    in_vault(&mut tx, id, vault_id).await?;
    db::attachments::delete(&mut tx, id).await?;
    tx.commit().await?;
    app.storage.remove_logged(&[id.to_string()]).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferBody {
    target_vault_id: Uuid,
    target_entry_id: Uuid,
}

pub async fn transfer(
    State(app): State<Arc<App>>,
    session: AuthSession,
    Path((vault, attachment)): Path<(String, String)>,
    _: NoQuery,
    StrictJson(body): StrictJson<TransferBody>,
) -> ApiResult<StatusCode> {
    let source = vault_id(&vault)?;
    let id = attachment_id(&attachment)?;
    let target = body.target_vault_id.0.as_str();
    let entry = body.target_entry_id.0.as_str();
    let user_id = session.user_id.as_str();
    let mut tx = app.db.begin().await?;
    require(&mut tx, source, user_id, Need::Member).await?;
    let attachment = db::attachments::get(&mut tx, id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if attachment.vault_id != source {
        // A repeated transfer that already happened.
        if attachment.vault_id == target && attachment.entry_id == entry {
            require(&mut tx, target, user_id, Need::Member).await?;
            return Ok(StatusCode::NO_CONTENT);
        }
        return Err(ApiError::new(ErrorCode::NotFound));
    }
    if target != source {
        require(&mut tx, target, user_id, Need::Member).await?;
    }
    if !attachment.complete() {
        return Err(ApiError::new(ErrorCode::Conflict));
    }
    if target != source {
        let from = db::quota::account(&mut tx, source).await?;
        let to = db::quota::account(&mut tx, target).await?;
        if from != to {
            check_quota(&app, &mut tx, target, user_id, unsigned(attachment.size)).await?;
        }
    }
    db::attachments::transfer(&mut tx, id, target, entry).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(text: &str, total: u64) -> Wanted {
        wanted(Some(&HeaderValue::from_str(text).unwrap()), total)
    }

    #[test]
    fn reads_single_ranges() {
        assert_eq!(wanted(None, 100), Wanted::All);
        assert_eq!(range("bytes=0-9", 100), Wanted::Part(0, 9));
        assert_eq!(range("bytes=90-200", 100), Wanted::Part(90, 99));
        assert_eq!(range("bytes=10-", 100), Wanted::Part(10, 99));
        assert_eq!(range("bytes=-5", 100), Wanted::Part(95, 99));
        assert_eq!(range("bytes=-500", 100), Wanted::Part(0, 99));
        assert_eq!(range(" bytes=99-99", 100), Wanted::Part(99, 99));
    }

    #[test]
    fn refuses_ranges_beyond_the_end() {
        assert_eq!(range("bytes=100-", 100), Wanted::Unsatisfiable);
        assert_eq!(range("bytes=100-120", 100), Wanted::Unsatisfiable);
        assert_eq!(range("bytes=-0", 100), Wanted::Unsatisfiable);
    }

    #[test]
    fn ignores_several_or_unreadable_ranges() {
        for text in [
            "bytes=0-1,5-6",
            "items=0-1",
            "bytes=5-1",
            "bytes=a-b",
            "bytes=-",
            "bytes=1",
            "bytes=+1-2",
            "bytes=99999999999999999999-",
        ] {
            assert_eq!(range(text, 100), Wanted::All, "{text}");
        }
    }

    #[test]
    fn computes_part_sizes_and_limits() {
        assert_eq!(part_len(42, 1, 0), 42);
        assert_eq!(part_len(PART_SIZE * 2 + 5, 3, 1), PART_SIZE);
        assert_eq!(part_len(PART_SIZE * 2 + 5, 3, 2), 5);
        assert_eq!(blob_limit(52_428_800), 52_442_442);
        assert_eq!(part_index("0").unwrap(), 0);
        assert!(part_index("01").is_err());
        assert!(part_index("-1").is_err());
        assert!(part_index("").is_err());
    }
}
