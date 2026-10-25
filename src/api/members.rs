//! Members of a vault: list, invite, accept, decline, pending key,
//! role, withdraw and leave. Every change runs in one transaction with its
//! security-log entry; events follow after the commit.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use super::vaults::{Need, path_uuid, require, vault_id};
use crate::app::App;
use crate::auth::{AuthSession, ClientIp, NoQuery};
use crate::clock::format_timestamp;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::events;
use crate::extract::StrictJson;
use crate::ratelimit::{Bucket, Quota};
use crate::types::{KeyBox, Positive, Role, Uuid, WrappedKey, encode_base64url};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteBody {
    user_id: Uuid,
    key_version: Positive,
    key_box: KeyBox,
}

/// `VaultKeyAcceptance` of `accept` and `key`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptBody {
    key_version: Positive,
    key_wrapped: WrappedKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBody {
    role: Role,
}

async fn current_key_version(conn: &mut Conn, vault_id: &str) -> ApiResult<i64> {
    Ok(db::vaults::vault(conn, vault_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?
        .key_version)
}

fn mismatch(current: i64) -> ApiError {
    ApiError::new(ErrorCode::KeyVersionMismatch).current_key_version(current)
}

fn notify(app: &App, recipients: &[String]) {
    app.hub.publish(
        recipients.iter().map(String::as_str),
        &events::vaults_changed(),
    );
}

/// Members and pending invitations, for every active member.
pub async fn list(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    Path(path): Path<String>,
) -> ApiResult<Json<Value>> {
    let vault_id = vault_id(&path)?;
    let mut tx = app.db.read.begin().await?;
    require(&mut tx, vault_id, &session.user_id, Need::Member).await?;
    let members: Vec<Value> = db::vaults::member_list(&mut tx, vault_id)
        .await?
        .into_iter()
        .map(|m| {
            json!({
                "user_id": m.user_id,
                "email": m.email,
                "role": m.role,
                "state": m.state,
                "public_key": encode_base64url(&m.public_key),
                "invited_by": m.invited_by,
                "created": m.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "members": members })))
}

/// Owner → invitation limits → `user_not_found` → `already_member` →
/// `key_version_mismatch`.
pub async fn invite(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    Path(path): Path<String>,
    StrictJson(body): StrictJson<InviteBody>,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&path)?;
    let user_id = session.user_id.as_str();
    let invitee = body.user_id.0.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    require(&mut tx, vault_id, user_id, Need::Owner).await?;
    // Before the lookup, so the limits also bound probing for accounts.
    let limits = &app.config.rate_limits;
    app.limit_all(&[
        (
            Bucket::InvitesByAccount,
            user_id,
            Quota::per_hour(limits.invites_per_account_per_hour),
        ),
        (
            Bucket::InvitesByInvitee,
            invitee,
            Quota::per_hour(limits.invites_per_invitee_per_hour),
        ),
    ])?;
    if db::users::email_by_id(&mut *tx, invitee).await?.is_none() {
        return Err(ApiError::new(ErrorCode::UserNotFound));
    }
    if db::vaults::membership(&mut tx, vault_id, invitee)
        .await?
        .is_some()
    {
        return Err(ApiError::new(ErrorCode::AlreadyMember));
    }
    let current = current_key_version(&mut tx, vault_id).await?;
    if body.key_version.0 != current {
        return Err(mismatch(current));
    }
    let invitation = db::vaults::NewInvitation {
        vault_id,
        user_id: invitee,
        key_version: current,
        key_box: &body.key_box.0,
        sender_id: user_id,
        now: &now,
    };
    db::vaults::insert_invitation(&mut tx, &invitation).await?;
    app.audit
        .vault_log(
            &mut tx,
            &now,
            "member_invited",
            user_id,
            vault_id,
            Some(&ip.hint()),
            json!({ "user_id": invitee }),
        )
        .await?;
    let mut recipients = db::vaults::active_members(&mut tx, vault_id).await?;
    recipients.push(invitee.to_string());
    tx.commit().await?;
    notify(&app, &recipients);
    Ok(StatusCode::CREATED)
}

/// The own pending invitation, else `404`; its version, else `409`.
pub async fn accept(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    Path(path): Path<String>,
    StrictJson(body): StrictJson<AcceptBody>,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&path)?;
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    let membership = db::vaults::membership_full(&mut tx, vault_id, user_id)
        .await?
        .filter(|m| m.state == "pending")
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if body.key_version.0 != membership.key_version {
        let current = current_key_version(&mut tx, vault_id).await?;
        return Err(mismatch(current));
    }
    db::vaults::activate(&mut tx, vault_id, user_id, &body.key_wrapped.0).await?;
    app.audit
        .vault_event(
            &mut tx,
            &now,
            "invitation_accepted",
            user_id,
            vault_id,
            Some(&ip.hint()),
        )
        .await?;
    let recipients = db::vaults::active_members(&mut tx, vault_id).await?;
    tx.commit().await?;
    notify(&app, &recipients);
    Ok(StatusCode::NO_CONTENT)
}

/// The own pending invitation, else `404`.
pub async fn decline(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    Path(path): Path<String>,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&path)?;
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    db::vaults::membership(&mut tx, vault_id, user_id)
        .await?
        .filter(|m| m.state == "pending")
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    db::vaults::delete_membership(&mut tx, vault_id, user_id).await?;
    app.audit
        .vault_event(
            &mut tx,
            &now,
            "invitation_declined",
            user_id,
            vault_id,
            Some(&ip.hint()),
        )
        .await?;
    let mut recipients = db::vaults::active_members(&mut tx, vault_id).await?;
    recipients.push(user_id.to_string());
    tx.commit().await?;
    notify(&app, &recipients);
    Ok(StatusCode::NO_CONTENT)
}

/// The pending key after a rotation, else `404`; its version, else `409`.
pub async fn accept_key(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    Path(path): Path<String>,
    StrictJson(body): StrictJson<AcceptBody>,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&path)?;
    let user_id = session.user_id.as_str();
    let mut tx = app.db.begin().await?;
    require(&mut tx, vault_id, user_id, Need::Member).await?;
    let pending = db::vaults::membership_full(&mut tx, vault_id, user_id)
        .await?
        .and_then(|m| m.pending_key_version)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if body.key_version.0 != pending {
        let current = current_key_version(&mut tx, vault_id).await?;
        return Err(mismatch(current));
    }
    db::vaults::accept_pending_key(&mut tx, vault_id, user_id, &body.key_wrapped.0).await?;
    tx.commit().await?;
    notify(&app, &[user_id.to_string()]);
    Ok(StatusCode::NO_CONTENT)
}

/// Owner → target active, else `404` → at least one owner stays.
pub async fn update(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    Path((vault, target)): Path<(String, String)>,
    StrictJson(body): StrictJson<RoleBody>,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&vault)?;
    let target = path_uuid("user_id", &target)?;
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    require(&mut tx, vault_id, user_id, Need::Owner).await?;
    let membership = db::vaults::membership(&mut tx, vault_id, target)
        .await?
        .filter(|m| m.state == "active")
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let role = body.role.as_str();
    if membership.role == role {
        return Ok(StatusCode::NO_CONTENT);
    }
    if membership.role == "owner" && db::vaults::owner_count(&mut tx, vault_id).await? <= 1 {
        return Err(ApiError::new(ErrorCode::LastOwner));
    }
    db::vaults::set_role(&mut tx, vault_id, target, role).await?;
    app.audit
        .vault_log(
            &mut tx,
            &now,
            "member_role_changed",
            user_id,
            vault_id,
            Some(&ip.hint()),
            json!({ "user_id": target, "role": role }),
        )
        .await?;
    let recipients = db::vaults::active_members(&mut tx, vault_id).await?;
    tx.commit().await?;
    notify(&app, &recipients);
    Ok(StatusCode::NO_CONTENT)
}

/// Owner → withdraws a pending invitation; active members need a rotation.
pub async fn withdraw(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    Path((vault, target)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&vault)?;
    let target = path_uuid("user_id", &target)?;
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    require(&mut tx, vault_id, user_id, Need::Owner).await?;
    let membership = db::vaults::membership(&mut tx, vault_id, target)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if membership.state == "active" {
        return Err(ApiError::new(ErrorCode::UseRotate));
    }
    db::vaults::delete_membership(&mut tx, vault_id, target).await?;
    app.audit
        .vault_log(
            &mut tx,
            &now,
            "invitation_withdrawn",
            user_id,
            vault_id,
            Some(&ip.hint()),
            json!({ "user_id": target }),
        )
        .await?;
    let mut recipients = db::vaults::active_members(&mut tx, vault_id).await?;
    recipients.push(target.to_string());
    tx.commit().await?;
    notify(&app, &recipients);
    Ok(StatusCode::NO_CONTENT)
}

/// Leaving flags the vault for a rotation and drops the invitations and
/// pending keys the leaver sent in it.
pub async fn leave(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    Path(path): Path<String>,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&path)?;
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    let membership = db::vaults::membership(&mut tx, vault_id, user_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if membership.state != "active" {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    if membership.role == "owner" && db::vaults::owner_count(&mut tx, vault_id).await? <= 1 {
        return Err(ApiError::new(ErrorCode::LastOwner));
    }
    db::vaults::delete_membership(&mut tx, vault_id, user_id).await?;
    db::vaults::flag_rotation(&mut tx, vault_id).await?;
    let invitees = db::vaults::drop_vault_invitations_from(&mut tx, vault_id, user_id).await?;
    db::vaults::drop_vault_pending_keys_from(&mut tx, vault_id, user_id).await?;
    app.audit
        .vault_event(
            &mut tx,
            &now,
            "member_left",
            user_id,
            vault_id,
            Some(&ip.hint()),
        )
        .await?;
    let mut recipients = db::vaults::active_members(&mut tx, vault_id).await?;
    recipients.extend(invitees);
    recipients.push(user_id.to_string());
    tx.commit().await?;
    notify(&app, &recipients);
    Ok(StatusCode::NO_CONTENT)
}
