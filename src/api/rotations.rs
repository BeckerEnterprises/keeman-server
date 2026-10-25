//! Staged key rotation: open, upload re-encrypted
//! objects in parts, commit atomically. All three are idempotent requests.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;

use super::vaults::{MAX_OBJECTS, Need, path_uuid, require, vault_id};
use crate::app::App;
use crate::audit;
use crate::auth::{AuthSession, ClientIp, NoQuery};
use crate::clock::format_timestamp;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::events;
use crate::extract::{BODY_LIMIT, LARGE_BODY_LIMIT};
use crate::idempotency;
use crate::types::{KeyBox, ObjectData, ObjectType, Positive, Uuid, WrappedKey};

/// A rotation expires after one hour.
const LIFETIME: Duration = Duration::hours(1);
/// At most this many dropped objects per commit.
const MAX_DROPS: usize = 10_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenBody {
    base_revision: Positive,
    new_key_version: Positive,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationObject {
    id: Uuid,
    #[serde(rename = "type")]
    kind: ObjectType,
    key_version: Positive,
    data: ObjectData,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectsBody {
    objects: Vec<RotationObject>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberKey {
    user_id: Uuid,
    key_box: KeyBox,
}

/// A dropped object with its encrypted drop tombstone.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DroppedObject {
    id: Uuid,
    data: ObjectData,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitBody {
    key_wrapped: WrappedKey,
    member_keys: Vec<MemberKey>,
    invite_keys: Vec<MemberKey>,
    remove_user_ids: Vec<Uuid>,
    drop_objects: Vec<DroppedObject>,
}

fn ids_json(ids: &[&str]) -> ApiResult<String> {
    serde_json::to_string(ids).map_err(ApiError::internal)
}

/// Runs the work of an idempotent request in a savepoint and stores its
/// answer; `discard` runs in the outer transaction before a stored error.
async fn idempotent<T, W, D>(
    app: &App,
    user_id: &str,
    request: &idempotency::Idempotent,
    now: &str,
    work: W,
    discard: D,
) -> ApiResult<(Response, Option<T>)>
where
    W: AsyncFnOnce(&mut Conn) -> ApiResult<(T, StatusCode, Value)>,
    D: AsyncFnOnce(&mut Conn, &ApiError) -> ApiResult<()>,
{
    let mut tx = app.db.begin().await?;
    if let Some(replay) = idempotency::lookup(&mut tx, user_id, request).await? {
        return Ok((replay, None));
    }
    let mut savepoint = db::savepoint(&mut tx).await?;
    let result = work(&mut savepoint).await;
    let answer = idempotency::settle(savepoint, result).await?;
    if let Err(error) = &answer {
        discard(&mut tx, error).await?;
    }
    let (done, answer) = match answer {
        Ok((done, status, body)) => (Some(done), Ok((status, body))),
        Err(error) => (None, Err(error)),
    };
    let response = idempotency::store(&mut tx, user_id, request, now, answer).await?;
    tx.commit().await?;
    Ok((response, done))
}

async fn nothing(_: &mut Conn, _: &ApiError) -> ApiResult<()> {
    Ok(())
}

/// Unknown, expired, replaced, or of another vault or account → `409`.
async fn rotation(
    conn: &mut Conn,
    rotation_id: &str,
    vault_id: &str,
    user_id: &str,
    now: &str,
) -> ApiResult<db::rotations::Rotation> {
    db::rotations::get(conn, rotation_id)
        .await?
        .filter(|r| {
            r.vault_id == vault_id && r.created_by == user_id && r.expires_at.as_str() > now
        })
        .ok_or_else(|| ApiError::new(ErrorCode::RotationInvalid))
}

async fn open_in(
    conn: &mut Conn,
    user_id: &str,
    vault_id: &str,
    body: &OpenBody,
    expires_at: &str,
) -> ApiResult<((), StatusCode, Value)> {
    require(conn, vault_id, user_id, Need::Owner).await?;
    let vault = db::vaults::vault(conn, vault_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if body.base_revision.0 != vault.revision {
        return Err(ApiError::new(ErrorCode::Conflict).current_revision(vault.revision));
    }
    if body.new_key_version.0 != vault.key_version + 1 {
        return Err(
            ApiError::new(ErrorCode::KeyVersionMismatch).current_key_version(vault.key_version)
        );
    }
    let id = uuid::Uuid::now_v7().to_string();
    let rotation = db::rotations::Rotation {
        id: id.clone(),
        vault_id: vault_id.to_string(),
        base_revision: vault.revision,
        new_key_version: body.new_key_version.0,
        created_by: user_id.to_string(),
        expires_at: expires_at.to_string(),
    };
    db::rotations::replace(conn, &rotation).await?;
    let expires_in = LIFETIME.whole_seconds();
    Ok((
        (),
        StatusCode::CREATED,
        json!({ "rotation_id": id, "expires_in": expires_in }),
    ))
}

/// `POST /v1/vaults/{id}/rotations`: owners only; `409 conflict` for an old
/// `base_revision`, `409 key_version_mismatch` for a version other than + 1.
pub async fn open(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    Path(path): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    let vault_id = vault_id(&path)?.to_string();
    let (request, body): (_, OpenBody) = idempotency::read(request, BODY_LIMIT).await?;
    let now = format_timestamp(app.now());
    let expires_at = format_timestamp(app.now() + LIFETIME);
    let user_id = session.user_id.as_str();
    let work = async |conn: &mut Conn| open_in(conn, user_id, &vault_id, &body, &expires_at).await;
    let (response, _) = idempotent(&app, user_id, &request, &now, work, nothing).await?;
    Ok(response)
}

fn check_objects(objects: &[RotationObject]) -> ApiResult<()> {
    if objects.is_empty() || objects.len() > MAX_OBJECTS {
        return Err(ApiError::pointer("/objects", "between 1 and 500 objects"));
    }
    let mut seen = HashSet::new();
    for (i, object) in objects.iter().enumerate() {
        if !seen.insert(object.id.0.as_str()) {
            return Err(ApiError::pointer(
                format!("/objects/{i}/id"),
                "duplicate ID",
            ));
        }
    }
    Ok(())
}

async fn upload_in(
    conn: &mut Conn,
    user_id: &str,
    vault_id: &str,
    rotation_id: &str,
    objects: &[RotationObject],
    now: &str,
) -> ApiResult<((), StatusCode, Value)> {
    require(conn, vault_id, user_id, Need::Owner).await?;
    let rotation = rotation(conn, rotation_id, vault_id, user_id, now).await?;
    let ids: Vec<&str> = objects.iter().map(|o| o.id.0.as_str()).collect();
    let stored: HashMap<String, db::objects::Existing> =
        db::objects::existing(conn, vault_id, &ids_json(&ids)?)
            .await?
            .into_iter()
            .map(|o| (o.id.clone(), o))
            .collect();
    for (i, object) in objects.iter().enumerate() {
        if object.key_version.0 != rotation.new_key_version {
            return Err(ApiError::pointer(
                format!("/objects/{i}/key_version"),
                "must be the new key version",
            ));
        }
        match stored.get(&object.id.0) {
            Some(existing) if !existing.deleted => {
                if existing.kind != object.kind.as_str() {
                    return Err(ApiError::pointer(
                        format!("/objects/{i}/type"),
                        "the type of an object cannot change",
                    ));
                }
            }
            _ => {
                return Err(ApiError::pointer(
                    format!("/objects/{i}/id"),
                    "unknown or deleted object",
                ));
            }
        }
    }
    for object in objects {
        db::rotations::upsert_object(
            conn,
            rotation_id,
            &object.id.0,
            object.kind.as_str(),
            &object.data.0,
        )
        .await?;
    }
    Ok(((), StatusCode::NO_CONTENT, Value::Null))
}

/// `PUT …/rotations/{rotation_id}/objects`: 1–500 objects, `204`.
pub async fn upload(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    Path((vault, rotation)): Path<(String, String)>,
    request: Request,
) -> ApiResult<Response> {
    let vault_id = vault_id(&vault)?.to_string();
    let rotation_id = path_uuid("rotation_id", &rotation)?.to_string();
    let (request, body): (_, ObjectsBody) = idempotency::read(request, LARGE_BODY_LIMIT).await?;
    check_objects(&body.objects)?;
    let now = format_timestamp(app.now());
    let user_id = session.user_id.as_str();
    let work = async |conn: &mut Conn| {
        upload_in(conn, user_id, &vault_id, &rotation_id, &body.objects, &now).await
    };
    let (response, _) = idempotent(&app, user_id, &request, &now, work, nothing).await?;
    Ok(response)
}

/// Structural checks before the transaction.
fn check_commit(vault_id: &str, user_id: &str, body: &CommitBody) -> ApiResult<()> {
    let mut accounts = HashSet::new();
    let lists = [
        (
            "member_keys",
            body.member_keys
                .iter()
                .map(|k| &k.user_id)
                .collect::<Vec<_>>(),
        ),
        (
            "invite_keys",
            body.invite_keys.iter().map(|k| &k.user_id).collect(),
        ),
        ("remove_user_ids", body.remove_user_ids.iter().collect()),
    ];
    for (name, ids) in lists {
        for (i, id) in ids.into_iter().enumerate() {
            if id.0 == user_id {
                return Err(ApiError::pointer(
                    format!("/{name}/{i}"),
                    "the caller cannot be listed",
                ));
            }
            if !accounts.insert(id.0.as_str()) {
                return Err(ApiError::pointer(
                    format!("/{name}/{i}"),
                    "an account may appear only once",
                ));
            }
        }
    }
    if body.drop_objects.len() > MAX_DROPS {
        return Err(ApiError::pointer(
            "/drop_objects",
            "at most 10000 dropped objects",
        ));
    }
    let mut dropped = HashSet::new();
    for (i, object) in body.drop_objects.iter().enumerate() {
        if object.id.0 == vault_id {
            return Err(ApiError::pointer(
                format!("/drop_objects/{i}/id"),
                "vault_meta is never dropped",
            ));
        }
        if !dropped.insert(object.id.0.as_str()) {
            return Err(ApiError::pointer(
                format!("/drop_objects/{i}/id"),
                "duplicate ID",
            ));
        }
    }
    Ok(())
}

/// What happens after a commit: events and attachment files.
struct Committed {
    revision: i64,
    /// Active members afterwards, the caller included.
    members: Vec<String>,
    /// Everyone whose vault list changed.
    affected: Vec<String>,
    attachments: Vec<String>,
}

async fn commit_in(
    conn: &mut Conn,
    user_id: &str,
    vault_id: &str,
    rotation_id: &str,
    body: &CommitBody,
    now: &str,
    ip_hint: &str,
) -> ApiResult<(Committed, StatusCode, Value)> {
    require(conn, vault_id, user_id, Need::Owner).await?;
    let rotation = rotation(conn, rotation_id, vault_id, user_id, now).await?;
    let vault = db::vaults::vault(conn, vault_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if vault.revision != rotation.base_revision {
        return Err(ApiError::new(ErrorCode::Conflict).current_revision(vault.revision));
    }
    let dropped: Vec<&str> = body.drop_objects.iter().map(|o| o.id.0.as_str()).collect();
    let dropped_json = ids_json(&dropped)?;
    let stored: HashMap<String, db::objects::Existing> =
        db::objects::existing(conn, vault_id, &dropped_json)
            .await?
            .into_iter()
            .map(|o| (o.id.clone(), o))
            .collect();
    for (i, id) in dropped.iter().enumerate() {
        if !stored.get(*id).is_some_and(|o| !o.deleted) {
            return Err(ApiError::pointer(
                format!("/drop_objects/{i}/id"),
                "unknown or deleted object",
            ));
        }
    }
    let incomplete = || ApiError::new(ErrorCode::RotationIncomplete);
    if db::rotations::missing_count(conn, rotation_id, vault_id, &dropped_json).await? > 0 {
        return Err(incomplete());
    }
    let states: HashMap<String, String> = db::vaults::member_states(conn, vault_id)
        .await?
        .into_iter()
        .map(|m| (m.user_id, m.state))
        .collect();
    let removed: HashSet<&str> = body.remove_user_ids.iter().map(|u| u.0.as_str()).collect();
    if removed.iter().any(|id| !states.contains_key(*id)) {
        return Err(incomplete());
    }
    let remaining: HashSet<&str> = states
        .iter()
        .filter(|(id, state)| {
            *state == "active" && *id != user_id && !removed.contains(id.as_str())
        })
        .map(|(id, _)| id.as_str())
        .collect();
    let keyed: HashSet<&str> = body
        .member_keys
        .iter()
        .map(|k| k.user_id.0.as_str())
        .collect();
    if keyed != remaining {
        return Err(incomplete());
    }
    if body
        .invite_keys
        .iter()
        .any(|k| states.get(&k.user_id.0).is_none_or(|s| s != "pending"))
    {
        return Err(incomplete());
    }

    let revision = rotation.base_revision + 1;
    let key_version = rotation.new_key_version;
    let applied = db::rotations::Applied {
        rotation_id,
        vault_id,
        revision,
        key_version,
        user_id,
        now,
    };
    db::rotations::apply_objects(conn, &applied).await?;
    for object in &body.drop_objects {
        let kind = stored
            .get(&object.id.0)
            .map_or("entry", |o| o.kind.as_str());
        let tombstone = db::objects::NewObject {
            id: &object.id.0,
            kind,
            revision,
            key_version,
            deleted: true,
            data: Some(&object.data.0),
            user_id,
            now,
        };
        db::objects::upsert(conn, vault_id, &tombstone).await?;
    }
    let entries: Vec<&str> = dropped
        .iter()
        .copied()
        .filter(|id| stored.get(*id).is_some_and(|o| o.kind == "entry"))
        .collect();
    let attachments = if entries.is_empty() {
        Vec::new()
    } else {
        db::attachments::delete_for_entries(conn, vault_id, &ids_json(&entries)?).await?
    };
    db::rotations::purge_tombstones_upto(conn, vault_id, rotation.base_revision).await?;
    db::rotations::set_rotated(conn, vault_id, revision, key_version).await?;
    db::vaults::set_own_key(conn, vault_id, user_id, &body.key_wrapped.0, key_version).await?;
    for member in &body.member_keys {
        db::vaults::set_pending_key(
            conn,
            vault_id,
            &member.user_id.0,
            &member.key_box.0,
            key_version,
            user_id,
        )
        .await?;
    }
    for id in &removed {
        db::vaults::delete_membership(conn, vault_id, id).await?;
    }
    for invite in &body.invite_keys {
        db::vaults::replace_invitation(
            conn,
            vault_id,
            &invite.user_id.0,
            &invite.key_box.0,
            key_version,
            user_id,
        )
        .await?;
    }
    let kept: Vec<&str> = body
        .invite_keys
        .iter()
        .map(|k| k.user_id.0.as_str())
        .collect();
    let uninvited =
        db::vaults::delete_invitations_except(conn, vault_id, &ids_json(&kept)?).await?;
    db::rotations::delete(conn, rotation_id).await?;
    let mut removed_ids: Vec<&str> = removed.iter().copied().collect();
    removed_ids.sort_unstable();
    audit::vault_log(
        conn,
        now,
        "vault_rotated",
        user_id,
        vault_id,
        Some(ip_hint),
        json!({ "key_version": key_version, "removed": removed_ids, "dropped": dropped.len() }),
    )
    .await?;

    let members = db::vaults::active_members(conn, vault_id).await?;
    let mut affected: Vec<String> = members.clone();
    affected.extend(removed.iter().map(|id| (*id).to_string()));
    affected.extend(kept.iter().map(|id| (*id).to_string()));
    affected.extend(uninvited);
    Ok((
        Committed {
            revision,
            members,
            affected,
            attachments,
        },
        StatusCode::OK,
        json!({ "revision": revision }),
    ))
}

/// `POST …/rotations/{rotation_id}/commit`: swaps objects, keys and
/// memberships in one transaction; a `409 conflict` discards the rotation.
pub async fn commit(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    Path((vault, rotation)): Path<(String, String)>,
    request: Request,
) -> ApiResult<Response> {
    let vault_id = vault_id(&vault)?.to_string();
    let rotation_id = path_uuid("rotation_id", &rotation)?.to_string();
    let (request, body): (_, CommitBody) = idempotency::read(request, LARGE_BODY_LIMIT).await?;
    let user_id = session.user_id.as_str();
    check_commit(&vault_id, user_id, &body)?;
    let now = format_timestamp(app.now());
    let ip_hint = ip.hint();
    let work = async |conn: &mut Conn| {
        commit_in(
            conn,
            user_id,
            &vault_id,
            &rotation_id,
            &body,
            &now,
            &ip_hint,
        )
        .await
    };
    let discard = async |conn: &mut Conn, error: &ApiError| {
        if error.code() == ErrorCode::Conflict {
            db::rotations::delete(conn, &rotation_id).await?;
        }
        Ok(())
    };
    let (response, done) = idempotent(&app, user_id, &request, &now, work, discard).await?;
    if let Some(done) = done {
        app.storage.remove_logged(&done.attachments).await;
        app.hub.publish(
            done.members.iter().map(String::as_str),
            &events::vault_changed(&vault_id, done.revision),
        );
        app.hub.publish(
            done.affected.iter().map(String::as_str),
            &events::vaults_changed(),
        );
    }
    Ok(response)
}
