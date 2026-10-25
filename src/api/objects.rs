//! Objects and synchronisation: `changes` and `batch`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

use super::vaults::{MAX_OBJECTS, Need, precheck, require, vault_id};
use crate::app::App;
use crate::auth::AuthSession;
use crate::clock::format_timestamp;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, Conflict, ErrorCode};
use crate::events;
use crate::extract::{LARGE_BODY_LIMIT, parse_query};
use crate::idempotency;
use crate::quota;
use crate::types::{
    MAX_SAFE_INTEGER, ObjectData, ObjectType, Positive, Uuid, decode_base64url, encode_base64url,
    is_canonical_uuid,
};

/// Default and maximum page size of `changes`.
const DEFAULT_LIMIT: i64 = 500;
const MAX_LIMIT: i64 = 1000;
/// A page ends once its `data` fields would exceed this many characters.
pub const PAGE_BUDGET: i64 = 4 * 1024 * 1024;
const MAX_CURSOR: usize = 256;

/// A counter in a query string: decimal digits without sign or leading
/// zeros (except `0`), at most 2^53 - 1, never percent-decoded.
fn counter(text: &str) -> Option<i64> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if !digits || (text.len() > 1 && text.starts_with('0')) || text.len() > 16 {
        return None;
    }
    text.parse().ok().filter(|v| *v <= MAX_SAFE_INTEGER)
}

/// Opaque position of a page: vault, `since`, and `(revision, id)` of the
/// last delivered object.
struct Cursor {
    revision: i64,
    id: String,
}

impl Cursor {
    fn encode(vault_id: &str, since: i64, revision: i64, id: &str) -> String {
        encode_base64url(format!("1:{vault_id}:{since}:{revision}:{id}").as_bytes())
    }

    fn decode(text: &str, vault_id: &str, since: i64) -> ApiResult<Cursor> {
        let invalid = || ApiError::parameter("cursor", "invalid cursor");
        if text.len() > MAX_CURSOR {
            return Err(invalid());
        }
        let bytes = decode_base64url(text).ok_or_else(invalid)?;
        let plain = String::from_utf8(bytes).map_err(|_| invalid())?;
        let parts: Vec<&str> = plain.split(':').collect();
        let [version, vault, cursor_since, revision, id] = parts.as_slice() else {
            return Err(invalid());
        };
        let since_text = since.to_string();
        if *version != "1" || *vault != vault_id || *cursor_since != since_text {
            return Err(invalid());
        }
        let revision = counter(revision).ok_or_else(invalid)?;
        if !is_canonical_uuid(id) {
            return Err(invalid());
        }
        Ok(Cursor {
            revision,
            id: (*id).to_string(),
        })
    }
}

/// Length of the Base64url text of `size` bytes.
fn base64_len(size: i64) -> i64 {
    (size.max(0) * 4 + 2) / 3
}

pub async fn changes(
    State(app): State<Arc<App>>,
    session: AuthSession,
    Path(path): Path<String>,
    uri: Uri,
) -> ApiResult<Json<Value>> {
    let vault_id = vault_id(&path)?;
    let query = parse_query(uri.query(), &["since", "cursor", "limit"])?;
    let since = query
        .get("since")
        .ok_or_else(|| ApiError::parameter("since", "missing parameter"))
        .and_then(|s| counter(s).ok_or_else(|| ApiError::parameter("since", "invalid value")))?;
    let limit = match query.get("limit") {
        None => DEFAULT_LIMIT,
        Some(text) => counter(text)
            .filter(|l| (1..=MAX_LIMIT).contains(l))
            .ok_or_else(|| ApiError::parameter("limit", "must be 1-1000"))?,
    };
    let cursor = query
        .get("cursor")
        .map(|text| Cursor::decode(text, vault_id, since))
        .transpose()?;

    // One read transaction per page.
    let mut tx = app.db.read.begin().await?;
    require(&mut tx, vault_id, &session.user_id, Need::Member).await?;
    let vault = db::vaults::vault(&mut tx, vault_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if since > 0 && since < vault.tombstone_horizon {
        return Err(ApiError::new(ErrorCode::ResyncRequired));
    }
    let start = db::objects::PageStart {
        since,
        after_revision: cursor.as_ref().map_or(since, |c| c.revision),
        after_id: cursor.as_ref().map_or("", |c| c.id.as_str()),
        with_tombstones: since > 0,
    };
    let candidates = db::objects::page_meta(&mut tx, vault_id, &start, limit + 1).await?;
    let mut total = 0;
    let mut take = 0;
    for meta in candidates.iter().take(usize::try_from(limit).unwrap_or(0)) {
        let length = base64_len(meta.size);
        if take > 0 && total + length > PAGE_BUDGET {
            break;
        }
        total += length;
        take += 1;
    }
    let rows = if take > 0 {
        db::objects::page(&mut tx, vault_id, &start, i64::try_from(take).unwrap_or(0)).await?
    } else {
        Vec::new()
    };
    tx.commit().await?;
    let next_cursor = match rows.last() {
        Some(last) if candidates.len() > take => {
            Some(Cursor::encode(vault_id, since, last.revision, &last.id))
        }
        _ => None,
    };
    let objects: Vec<Value> = rows
        .into_iter()
        .map(|o| {
            json!({
                "id": o.id,
                "type": o.kind,
                "revision": o.revision,
                "key_version": o.key_version,
                "deleted": o.deleted,
                "data": o.data.map(|d| encode_base64url(&d)),
                "updated_at": o.updated_at,
                "updated_by": o.updated_by,
            })
        })
        .collect();
    Ok(Json(json!({
        "vault_revision": vault.revision,
        "key_version": vault.key_version,
        "objects": objects,
        "next_cursor": next_cursor,
    })))
}

/// `put` must send `expected_revision`, `null` creates.
fn present_revision<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Positive>, D::Error> {
    Option::<Positive>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutOp {
    id: Uuid,
    #[serde(rename = "type")]
    kind: ObjectType,
    key_version: Positive,
    #[serde(deserialize_with = "present_revision")]
    expected_revision: Option<Positive>,
    data: ObjectData,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteOp {
    id: Uuid,
    key_version: Positive,
    expected_revision: Positive,
    data: ObjectData,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Op {
    Put(PutOp),
    Delete(DeleteOp),
}

impl Op {
    fn id(&self) -> &str {
        match self {
            Op::Put(op) => &op.id.0,
            Op::Delete(op) => &op.id.0,
        }
    }

    fn key_version(&self) -> i64 {
        match self {
            Op::Put(op) => op.key_version.0,
            Op::Delete(op) => op.key_version.0,
        }
    }

    fn expected(&self) -> Option<i64> {
        match self {
            Op::Put(op) => op.expected_revision.map(|r| r.0),
            Op::Delete(op) => Some(op.expected_revision.0),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchBody {
    ops: Vec<Op>,
}

/// Structural checks before the transaction.
fn check_batch(vault_id: &str, ops: &[Op]) -> ApiResult<()> {
    if ops.is_empty() || ops.len() > MAX_OBJECTS {
        return Err(ApiError::pointer("/ops", "between 1 and 500 ops"));
    }
    let mut seen = HashSet::new();
    for (i, op) in ops.iter().enumerate() {
        let pointer = || format!("/ops/{i}/id");
        if !seen.insert(op.id()) {
            return Err(ApiError::pointer(pointer(), "duplicate ID"));
        }
        let is_vault_id = op.id() == vault_id;
        match op {
            Op::Delete(_) if is_vault_id => {
                return Err(ApiError::pointer(pointer(), "vault_meta cannot be deleted"));
            }
            Op::Put(put) if (put.kind == ObjectType::VaultMeta) != is_vault_id => {
                return Err(ApiError::pointer(
                    pointer(),
                    "only vault_meta has the vault ID",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// What a conflict entry looks like for this op, if any.
fn conflict(op: &Op, stored: Option<&db::objects::Existing>) -> Option<Conflict> {
    let entry = |current_revision, deleted| {
        Some(Conflict {
            id: op.id().to_string(),
            current_revision,
            deleted,
        })
    };
    match (op.expected(), stored) {
        (None, None) => None,
        (None, Some(s)) => entry(Some(s.revision), s.deleted),
        (Some(_), None) => entry(None, false),
        (Some(_), Some(s)) if s.deleted => entry(Some(s.revision), true),
        (Some(expected), Some(s)) if s.revision != expected => entry(Some(s.revision), false),
        (Some(_), Some(_)) => None,
    }
}

struct Applied {
    body: Value,
    revision: i64,
    members: Vec<String>,
    /// Attachments of deleted entries; their files go after the commit.
    attachments: Vec<String>,
}

async fn batch_in(
    conn: &mut Conn,
    user_id: &str,
    vault_id: &str,
    ops: &[Op],
    quota: u64,
    now: &str,
) -> ApiResult<Applied> {
    require(conn, vault_id, user_id, Need::Member).await?;
    let vault = db::vaults::vault(conn, vault_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let ids: Vec<&str> = ops.iter().map(Op::id).collect();
    let ids = serde_json::to_string(&ids).map_err(ApiError::internal)?;
    let stored: HashMap<String, db::objects::Existing> =
        db::objects::existing(conn, vault_id, &ids)
            .await?
            .into_iter()
            .map(|o| (o.id.clone(), o))
            .collect();
    for (i, op) in ops.iter().enumerate() {
        if let (Op::Put(put), Some(existing)) = (op, stored.get(op.id()))
            && existing.kind != put.kind.as_str()
        {
            return Err(ApiError::pointer(
                format!("/ops/{i}/type"),
                "the type of an object cannot change",
            ));
        }
    }
    if ops.iter().any(|op| op.key_version() != vault.key_version) {
        return Err(
            ApiError::new(ErrorCode::StaleKeyVersion).current_key_version(vault.key_version)
        );
    }
    let conflicts: Vec<Conflict> = ops
        .iter()
        .filter_map(|op| conflict(op, stored.get(op.id())))
        .collect();
    if !conflicts.is_empty() {
        return Err(ApiError::conflicts(conflicts));
    }
    // New minus replaced sizes; a tombstone replaces its object too.
    let growth: i64 = ops
        .iter()
        .map(|op| {
            let data = match op {
                Op::Put(put) => &put.data,
                Op::Delete(delete) => &delete.data,
            };
            quota::bytes(data.0.len()) - stored.get(op.id()).map_or(0, |o| o.size)
        })
        .sum();
    if growth > 0 {
        let account = quota::account_for(conn, vault_id, user_id).await?;
        quota::require_room(conn, &account, growth, quota, now).await?;
    }

    let revision = vault.revision + 1;
    db::vaults::set_revision(conn, vault_id, revision).await?;
    for op in ops {
        let (kind, deleted, data) = match op {
            Op::Put(put) => (put.kind.as_str(), false, &put.data),
            Op::Delete(delete) => (
                stored.get(op.id()).map_or("entry", |s| s.kind.as_str()),
                true,
                &delete.data,
            ),
        };
        let object = db::objects::NewObject {
            id: op.id(),
            kind,
            revision,
            key_version: vault.key_version,
            deleted,
            data: Some(&data.0),
            user_id,
            now,
        };
        db::objects::upsert(conn, vault_id, &object).await?;
    }
    // Deleting an entry deletes its attachments.
    let entries: Vec<&str> = ops
        .iter()
        .filter(|op| {
            matches!(op, Op::Delete(_)) && stored.get(op.id()).is_some_and(|s| s.kind == "entry")
        })
        .map(Op::id)
        .collect();
    let attachments = if entries.is_empty() {
        Vec::new()
    } else {
        let entries = serde_json::to_string(&entries).map_err(ApiError::internal)?;
        db::attachments::delete_for_entries(conn, vault_id, &entries).await?
    };
    let results: Vec<Value> = ops
        .iter()
        .map(|op| json!({ "id": op.id(), "revision": revision }))
        .collect();
    Ok(Applied {
        body: json!({ "vault_revision": revision, "results": results }),
        revision,
        members: db::vaults::active_members(conn, vault_id).await?,
        attachments,
    })
}

pub async fn batch(
    State(app): State<Arc<App>>,
    session: AuthSession,
    Path(path): Path<String>,
    uri: Uri,
    request: Request,
) -> ApiResult<Response> {
    let vault_id = vault_id(&path)?.to_string();
    parse_query(uri.query(), &[])?;
    let user = session.user_id.as_str();
    precheck(&app, &request, &vault_id, user, Need::Member, true).await?;
    let _admitted = app
        .large_bodies
        .admit(user, request.headers(), LARGE_BODY_LIMIT)
        .await?;
    let (request, body): (_, BatchBody) = idempotency::read(request, LARGE_BODY_LIMIT).await?;
    check_batch(&vault_id, &body.ops)?;
    let now = format_timestamp(app.now());
    let user_id = session.user_id.as_str();
    let mut tx = app.db.begin().await?;
    if let Some(replay) = idempotency::lookup(&mut tx, user_id, &request).await? {
        return Ok(replay);
    }
    let mut savepoint = db::savepoint(&mut tx).await?;
    let quota = app.config.limits.user_quota_bytes;
    let result = batch_in(&mut savepoint, user_id, &vault_id, &body.ops, quota, &now).await;
    let answer = idempotency::settle(savepoint, result).await?;
    let event = answer
        .as_ref()
        .ok()
        .map(|applied| (applied.revision, applied.members.clone()));
    let attachments = answer
        .as_ref()
        .map(|applied| applied.attachments.clone())
        .unwrap_or_default();
    let answer = answer.map(|applied| (StatusCode::OK, applied.body));
    let response =
        idempotency::store(&mut tx, &app.config.limits, user_id, &request, &now, answer).await?;
    tx.commit().await?;
    app.storage.remove_logged(&attachments).await;
    if let Some((revision, members)) = event {
        app.hub.publish(
            members.iter().map(String::as_str),
            &events::vault_changed(&vault_id, revision),
        );
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_strict() {
        assert_eq!(counter("0"), Some(0));
        assert_eq!(counter("412"), Some(412));
        assert_eq!(counter("9007199254740991"), Some(MAX_SAFE_INTEGER));
        for bad in [
            "",
            "-1",
            "+1",
            "01",
            "1.0",
            "9007199254740992",
            "1%30",
            " 1",
            "1e3",
        ] {
            assert_eq!(counter(bad), None, "{bad}");
        }
    }

    #[test]
    fn cursors_are_bound_to_vault_and_since() {
        let vault = "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b";
        let id = "0192b3a4-5c6d-7e8f-9a0b-000000000001";
        let text = Cursor::encode(vault, 7, 9, id);
        let cursor = Cursor::decode(&text, vault, 7).unwrap();
        assert_eq!((cursor.revision, cursor.id.as_str()), (9, id));
        assert!(Cursor::decode(&text, vault, 8).is_err());
        assert!(Cursor::decode(&text, "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6c", 7).is_err());
        assert!(Cursor::decode("not base64!", vault, 7).is_err());
        assert!(Cursor::decode(&encode_base64url(b"2:x"), vault, 7).is_err());
        assert!(Cursor::decode(&"A".repeat(257), vault, 7).is_err());
    }

    #[test]
    fn base64_lengths() {
        assert_eq!(base64_len(0), 0);
        assert_eq!(base64_len(1), 2);
        assert_eq!(base64_len(3), 4);
        assert_eq!(base64_len(41), 55);
    }
}
