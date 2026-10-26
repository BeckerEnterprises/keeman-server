//! Vaults: list, create, delete and the central membership check
//! of all vault endpoints.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::App;
use crate::audit::Audit;
use crate::auth::{AuthSession, ClientIp, NoQuery, Reauthed};
use crate::clock::format_timestamp;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::events;
use crate::extract::BODY_LIMIT;
use crate::idempotency;
use crate::quota;
use crate::types::{
    ObjectData, ObjectType, Positive, Uuid, WrappedKey, encode_base64url, is_canonical_uuid,
};

/// Objects per request.
pub const MAX_OBJECTS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Any active member.
    Member,
    Owner,
}

/// Unknown vault or not a member → `404`; pending → `403`; owner-only
/// action as a member → `403`.
pub async fn require(conn: &mut Conn, vault_id: &str, user_id: &str, need: Need) -> ApiResult<()> {
    let membership = db::vaults::membership(conn, vault_id, user_id).await?;
    refusal(membership.as_ref(), need).map_or(Ok(()), Err)
}

fn refusal(membership: Option<&db::vaults::Membership>, need: Need) -> Option<ApiError> {
    match membership {
        None => Some(ApiError::new(ErrorCode::NotFound)),
        Some(m) if m.state != "active" || (need == Need::Owner && m.role != "owner") => {
            Some(ApiError::new(ErrorCode::Forbidden))
        }
        Some(_) => None,
    }
}

/// [`require`] before a large body is read, outside the transaction: callers
/// without the membership are refused before their body is accepted. A key
/// with an answer already stored for the same endpoint skips it, so the
/// repetition still gets that answer; the check in the transaction stays.
pub fn precheck<'a>(
    app: &'a App,
    request: &Request,
    vault_id: &'a str,
    user_id: &'a str,
    need: Need,
    idempotent: bool,
) -> impl Future<Output = ApiResult<()>> + Send + 'a {
    // Taken from the request now: its body must not be held across `await`.
    let stored_answer = if idempotent {
        idempotency::key(request.headers()).map(|key| (key, idempotency::endpoint(request)))
    } else {
        None
    };
    precheck_with(app, vault_id, user_id, need, stored_answer)
}

async fn precheck_with(
    app: &App,
    vault_id: &str,
    user_id: &str,
    need: Need,
    stored_answer: Option<(String, String)>,
) -> ApiResult<()> {
    let mut conn = app.db.read.acquire().await?;
    let membership = db::vaults::membership(&mut conn, vault_id, user_id).await?;
    let Some(refused) = refusal(membership.as_ref(), need) else {
        return Ok(());
    };
    if let Some((key, endpoint)) = stored_answer {
        let stored = db::idempotency::stored_endpoint(&mut conn, user_id, &key).await?;
        if stored.is_some_and(|stored| stored == endpoint) {
            return Ok(());
        }
    }
    Err(refused)
}

/// A UUID path segment in canonical form, else `400` naming the parameter.
pub fn path_uuid<'a>(name: &'static str, path: &'a str) -> ApiResult<&'a str> {
    if is_canonical_uuid(path) {
        Ok(path)
    } else {
        Err(ApiError::parameter(name, "not a canonical UUID"))
    }
}

/// The `{vault_id}` path segment in canonical form.
pub fn vault_id(path: &str) -> ApiResult<&str> {
    path_uuid("vault_id", path)
}

fn key_grant(key_box: Option<&[u8]>, version: Option<i64>, sender: Option<&str>) -> Value {
    match (key_box, version, sender) {
        (Some(key_box), Some(version), Some(sender)) => json!({
            "key_box": encode_base64url(key_box),
            "key_version": version,
            "sender_id": sender,
        }),
        _ => Value::Null,
    }
}

pub async fn list(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
) -> ApiResult<Json<Value>> {
    let rows = db::vaults::list_for_user(&app.db.read, &session.user_id).await?;
    let vaults: Vec<Value> = rows
        .into_iter()
        .map(|v| {
            let pending = v.state == "pending";
            let invitation = if pending {
                key_grant(
                    v.key_box.as_deref(),
                    Some(v.member_key_version),
                    v.sender_id.as_deref(),
                )
            } else {
                Value::Null
            };
            json!({
                "vault_id": v.vault_id,
                "role": v.role,
                "state": v.state,
                "vault_key_version": v.vault_key_version,
                "member_key_version": v.member_key_version,
                "key_wrapped": v.key_wrapped.filter(|_| !pending).map(|k| encode_base64url(&k)),
                "pending_key": key_grant(
                    v.pending_key_box.as_deref(),
                    v.pending_key_version,
                    v.pending_key_sender_id.as_deref(),
                ),
                "invitation": invitation,
                "revision": v.revision,
                "rotation_required": v.rotation_required,
                "member_count": v.member_count,
                "created": v.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "vaults": vaults })))
}

/// One object of `POST /v1/vaults` (`ObjectUpload`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectUpload {
    id: Uuid,
    #[serde(rename = "type")]
    kind: ObjectType,
    key_version: Positive,
    data: ObjectData,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBody {
    vault_id: Uuid,
    key_wrapped: WrappedKey,
    objects: Vec<ObjectUpload>,
}

/// Structural checks before the transaction.
fn check_create(body: &CreateBody) -> ApiResult<()> {
    if body.objects.is_empty() || body.objects.len() > MAX_OBJECTS {
        return Err(ApiError::pointer("/objects", "between 1 and 500 objects"));
    }
    let mut seen = HashSet::new();
    let mut meta = false;
    for (i, object) in body.objects.iter().enumerate() {
        if object.key_version.0 != 1 {
            return Err(ApiError::pointer(
                format!("/objects/{i}/key_version"),
                "key version must be 1",
            ));
        }
        if !seen.insert(object.id.0.as_str()) {
            return Err(ApiError::pointer(
                format!("/objects/{i}/id"),
                "duplicate ID",
            ));
        }
        let is_meta = object.kind == ObjectType::VaultMeta;
        match (is_meta, object.id == body.vault_id) {
            (true, true) => meta = true,
            (true, false) => {
                return Err(ApiError::pointer(
                    format!("/objects/{i}/id"),
                    "vault_meta must have the vault ID",
                ));
            }
            (false, true) => {
                return Err(ApiError::pointer(
                    format!("/objects/{i}/id"),
                    "only vault_meta has the vault ID",
                ));
            }
            (false, false) => {}
        }
    }
    if !meta {
        return Err(ApiError::pointer(
            "/objects",
            "exactly one vault_meta required",
        ));
    }
    Ok(())
}

async fn create_in(
    conn: &mut Conn,
    audit: &Audit,
    user_id: &str,
    body: &CreateBody,
    quota: u64,
    now: &str,
    ip_hint: &str,
) -> ApiResult<(StatusCode, Value)> {
    let vault_id = body.vault_id.0.as_str();
    if db::vaults::exists(conn, vault_id).await? {
        return Err(ApiError::new(ErrorCode::Conflict));
    }
    // The new vault counts against its creator.
    let growth = body
        .objects
        .iter()
        .map(|o| quota::bytes(o.data.0.len()))
        .sum();
    quota::require_room(conn, user_id, growth, quota, now).await?;
    let vault = db::vaults::NewVault {
        id: vault_id,
        owner: user_id,
        key_wrapped: &body.key_wrapped.0,
        now,
    };
    db::vaults::insert(conn, &vault).await?;
    for object in &body.objects {
        let new = db::objects::NewObject {
            id: &object.id.0,
            kind: object.kind.as_str(),
            revision: 1,
            key_version: 1,
            deleted: false,
            data: Some(&object.data.0),
            user_id,
            now,
        };
        db::objects::upsert(conn, vault_id, &new).await?;
    }
    audit
        .vault_event(conn, now, "vault_created", user_id, vault_id, Some(ip_hint))
        .await?;
    Ok((StatusCode::CREATED, json!({ "revision": 1 })))
}

pub async fn create(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Response> {
    let (request, body): (_, CreateBody) = idempotency::read(request, BODY_LIMIT).await?;
    check_create(&body)?;
    let now = format_timestamp(app.now());
    let user_id = session.user_id.as_str();
    let mut tx = app.db.begin().await?;
    if let Some(replay) = idempotency::lookup(&mut tx, user_id, &request).await? {
        return Ok(replay);
    }
    let mut savepoint = db::savepoint(&mut tx).await?;
    let quota = app.config.limits.user_quota_bytes;
    let result = create_in(
        &mut savepoint,
        &app.audit,
        user_id,
        &body,
        quota,
        &now,
        &ip.hint(),
    )
    .await;
    let answer = idempotency::settle(savepoint, result).await?;
    let created = answer.is_ok();
    let response =
        idempotency::store(&mut tx, &app.config.limits, user_id, &request, &now, answer).await?;
    tx.commit().await?;
    if created {
        app.hub.publish([user_id], &events::vaults_changed());
    }
    Ok(response)
}

/// Owners only; deletes objects, memberships and rotations.
pub async fn delete(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    reauthed: Reauthed,
    Path(path): Path<String>,
    _: NoQuery,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&path)?;
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = reauthed.begin(&app).await?;
    require(&mut tx, vault_id, user_id, Need::Owner).await?;
    let members = db::vaults::members(&mut tx, vault_id).await?;
    let attachments = db::attachments::ids_of_vault(&mut tx, vault_id).await?;
    db::vaults::delete(&mut tx, vault_id).await?;
    app.audit
        .vault_event(
            &mut tx,
            &now,
            "vault_deleted",
            user_id,
            vault_id,
            Some(&ip.hint()),
        )
        .await?;
    tx.commit().await?;
    app.remove_attachment_files(&attachments).await;
    app.hub.publish(
        members.iter().map(String::as_str),
        &events::vaults_changed(),
    );
    Ok(StatusCode::NO_CONTENT)
}
