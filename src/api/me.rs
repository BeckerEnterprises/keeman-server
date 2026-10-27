//! The own account: `GET /v1/me`, reauth, `user_data`, password and
//! recovery material.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;

use super::{RecoveryMaterial, hex, kdf_json, parse_kdf};
use crate::app::App;
use crate::auth::session::with_cookie;
use crate::auth::{AuthSession, ClientIp, NoQuery, Reauthed, throttle};
use crate::clock::format_timestamp;
use crate::crypto::new_token;
use crate::db;
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::events;
use crate::extract::{StrictJson, json};
use crate::ratelimit::{Bucket, Quota};
use crate::types::{KdfParamsInput, Key32, Salt, UserDataEnvelope, WrappedKey, encode_base64url};

/// Lifetime of a reauth token.
const REAUTH_TTL: Duration = Duration::minutes(5);

pub async fn get(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
) -> ApiResult<Json<Value>> {
    let me = db::users::me(&app.db.read, &session.user_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::SessionInvalid))?;
    Ok(Json(json!({
        "user_id": me.id,
        "email": me.email,
        "kdf": parse_kdf(&me.kdf_params)?,
        "salt": encode_base64url(&me.kdf_salt),
        "user_key_wrapped": encode_base64url(&me.user_key_wrapped),
        "public_key": encode_base64url(&me.public_key),
        "private_key_wrapped": encode_base64url(&me.private_key_wrapped),
        "signing_public_key": me.signing_public_key.as_deref().map(encode_base64url),
        "user_data": { "revision": me.user_data_revision, "data": encode_base64url(&me.user_data) },
        "two_factor": {
            "totp": me.totp_enabled,
            "webauthn_credentials": me.webauthn_credentials,
            "backup_codes_remaining": me.backup_codes_remaining,
        },
        "freshness": match (me.freshness_statement, me.freshness_signature) {
            (Some(statement), Some(signature)) => json!({
                "statement": encode_base64url(&statement),
                "signature": encode_base64url(&signature),
            }),
            _ => Value::Null,
        },
        "created": me.created_at,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthBody {
    auth_key: Key32,
}

/// Rate-limited like login and counted for the lockout.
pub async fn reauth(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Json<Value>> {
    let limits = &app.config.rate_limits;
    app.limit(
        Bucket::CredentialIp,
        &ip.limit_key(),
        Quota::per_minute(limits.credential_per_ip_per_min),
    )?;
    let body: ReauthBody = json(request).await?;
    let user = db::users::login_by_id(&app.db.read, &session.user_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::SessionInvalid))?;
    let key = app.keys.throttle_key(&user.email);
    app.limit(
        Bucket::CredentialEmail,
        &hex(&key),
        Quota::per_minute(limits.credential_per_email_per_min),
    )?;
    throttle::check(&app, &key).await?;

    let valid = app
        .passwords
        .verify(&body.auth_key.0, Some(&user.auth_hash))
        .await?;
    let now = app.now();
    let now_text = format_timestamp(now);
    let hint = ip.hint();
    let mut tx = app.db.begin().await?;
    throttle::ensure_unlocked(&mut tx, &app, &key).await?;
    // The session may have been revoked and the password changed while the
    // key was checked; only the state in this transaction counts.
    session.confirm(&mut tx, &app).await?;
    let valid = valid
        && db::users::login_by_id(&mut *tx, &user.id)
            .await?
            .is_some_and(|current| current.auth_hash == user.auth_hash);
    if !valid {
        throttle::failure(&mut tx, &app, &key, Some(&user.id), &hint).await?;
        app.audit
            .log(
                &mut tx,
                &now_text,
                "reauth_failed",
                Some(&user.id),
                Some(&hint),
                json!({ "session_id": session.session_id }),
            )
            .await?;
        tx.commit().await?;
        // The session stays valid; clients tell this apart by `code`.
        return Err(ApiError::new(ErrorCode::InvalidCredentials));
    }
    throttle::success(&mut tx, &app, &key).await?;
    let token = new_token().map_err(ApiError::internal)?;
    let challenge = db::challenges::NewChallenge {
        hash: &token.hash,
        purpose: "reauth",
        user_id: &user.id,
        session_id: Some(&session.session_id),
        state: None,
        expires_at: &format_timestamp(now + REAUTH_TTL),
    };
    db::challenges::insert(&mut *tx, &challenge).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "reauth_token": token.text, "expires_in": REAUTH_TTL.whole_seconds() }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDataBody {
    expected_revision: i64,
    data: UserDataEnvelope,
}

pub async fn put_user_data(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    StrictJson(body): StrictJson<UserDataBody>,
) -> ApiResult<Json<Value>> {
    let now_text = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    let updated = db::users::update_user_data(
        &mut *tx,
        &session.user_id,
        body.expected_revision,
        &body.data.0,
        &now_text,
    )
    .await?;
    if updated == 0 {
        let current = db::users::user_data_revision(&mut *tx, &session.user_id)
            .await?
            .unwrap_or(0);
        return Err(ApiError::new(ErrorCode::Conflict).current_revision(current));
    }
    tx.commit().await?;
    let revision = body.expected_revision + 1;
    app.hub.publish(
        [session.user_id.as_str()],
        &events::user_data_changed(revision),
    );
    Ok(Json(json!({ "revision": revision })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordBody {
    kdf: KdfParamsInput,
    salt: Salt,
    auth_key: Key32,
    user_key_wrapped: WrappedKey,
    revoke_other_sessions: bool,
}

pub async fn put_password(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    reauthed: Reauthed,
    _: NoQuery,
    StrictJson(body): StrictJson<PasswordBody>,
) -> ApiResult<StatusCode> {
    let kdf = body.kdf.validate()?;
    let auth_hash = app.passwords.hash(&body.auth_key.0).await?;
    let now_text = format_timestamp(app.now());
    let hint = ip.hint();
    let user_id = session.user_id.as_str();
    let mut tx = reauthed.begin(&app).await?;
    db::users::update_password(
        &mut *tx,
        user_id,
        &kdf_json(&kdf)?,
        &body.salt.0,
        &auth_hash,
        &body.user_key_wrapped.0,
        &now_text,
    )
    .await?;
    // All reauth tokens of the account, including the one just used, and
    // sign-in and recovery steps begun with the old password.
    db::challenges::delete_password_steps(&mut *tx, user_id).await?;
    let revoked = if body.revoke_other_sessions {
        db::sessions::revoke_others(&mut tx, user_id, &session.session_id, &now_text).await?
    } else {
        Vec::new()
    };
    app.audit
        .sessions_revoked(
            &mut tx,
            &now_text,
            user_id,
            Some(&hint),
            &revoked,
            "password",
        )
        .await?;
    let detail = json!({ "revoke_other_sessions": body.revoke_other_sessions, "revoked_sessions": revoked.len() });
    app.audit
        .log(
            &mut tx,
            &now_text,
            "password_changed",
            Some(user_id),
            Some(&hint),
            detail,
        )
        .await?;
    tx.commit().await?;
    app.hub.revoke_sessions(&revoked);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn put_recovery(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    reauthed: Reauthed,
    _: NoQuery,
    StrictJson(body): StrictJson<RecoveryMaterial>,
) -> ApiResult<StatusCode> {
    let recovery_hash = app.passwords.hash(&body.auth_key.0).await?;
    let now_text = format_timestamp(app.now());
    let mut tx = reauthed.begin(&app).await?;
    db::users::update_recovery(
        &mut *tx,
        &session.user_id,
        &recovery_hash,
        &body.user_key_wrapped.0,
        &now_text,
    )
    .await?;
    // A recovery begun with the old key must not finish after the change.
    db::challenges::delete_recovery_steps(&mut *tx, &session.user_id).await?;
    app.audit
        .log(
            &mut tx,
            &now_text,
            "recovery_changed",
            Some(&session.user_id),
            Some(&ip.hint()),
            json!({}),
        )
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyBody {
    signing_public_key: Key32,
}

/// Sets the public signing key once: the same value again is `204`, another
/// one `409 conflict`.
pub async fn put_signing_key(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    reauthed: Reauthed,
    _: NoQuery,
    StrictJson(body): StrictJson<SigningKeyBody>,
) -> ApiResult<StatusCode> {
    let user_id = session.user_id.as_str();
    let key = &body.signing_public_key.0;
    let now_text = format_timestamp(app.now());
    let mut tx = reauthed.begin(&app).await?;
    match db::users::signing_key(&mut *tx, user_id).await? {
        Some(Some(current)) if current == key => return Ok(StatusCode::NO_CONTENT),
        Some(Some(_)) => return Err(ApiError::new(ErrorCode::Conflict)),
        Some(None) => {}
        None => return Err(ApiError::new(ErrorCode::SessionInvalid)),
    }
    if db::users::set_signing_key(&mut *tx, user_id, key, &now_text).await? == 0 {
        return Err(ApiError::new(ErrorCode::Conflict));
    }
    app.audit
        .log(
            &mut tx,
            &now_text,
            "signing_key_set",
            Some(user_id),
            Some(&ip.hint()),
            json!({}),
        )
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes the account: solo vaults go, shared ones are left and
/// flagged for rotation; one transaction, then events and the cookie.
pub async fn delete(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    reauthed: Reauthed,
    _: NoQuery,
) -> ApiResult<Response> {
    let user_id = session.user_id.as_str();
    let now_text = format_timestamp(app.now());
    let mut tx = reauthed.begin(&app).await?;
    if db::vaults::sole_owner_of_shared(&mut tx, user_id).await? {
        return Err(ApiError::new(ErrorCode::SoleOwnerOfSharedVault));
    }
    // A signed owner list must not keep naming an account that is gone.
    if db::roles::owner_in_chain_with_others(&mut tx, user_id).await? {
        return Err(ApiError::new(ErrorCode::OwnerMustDemote));
    }
    let mut notify = BTreeSet::new();
    let mut attachments = Vec::new();
    for vault_id in db::vaults::solo_vaults(&mut tx, user_id).await? {
        notify.extend(db::vaults::members(&mut tx, &vault_id).await?);
        attachments.extend(db::attachments::ids_of_vault(&mut tx, &vault_id).await?);
        db::vaults::delete(&mut tx, &vault_id).await?;
        app.audit
            .vault_event(
                &mut tx,
                &now_text,
                "vault_deleted",
                user_id,
                &vault_id,
                Some(&ip.hint()),
            )
            .await?;
    }
    for vault_id in db::vaults::active_vaults(&mut tx, user_id).await? {
        notify.extend(db::vaults::active_members(&mut tx, &vault_id).await?);
        db::vaults::flag_rotation(&mut tx, &vault_id).await?;
    }
    let mut dropped = db::vaults::drop_invitations_from(&mut tx, user_id).await?;
    dropped.extend(db::vaults::drop_pending_keys_from(&mut tx, user_id).await?);
    for grant in dropped {
        db::vaults::flag_rotation(&mut tx, &grant.vault_id).await?;
        notify.insert(grant.user_id);
    }
    db::users::delete(&mut *tx, user_id).await?;
    app.audit
        .log(
            &mut tx,
            &now_text,
            "account_deleted",
            Some(user_id),
            Some(&ip.hint()),
            json!({}),
        )
        .await?;
    tx.commit().await?;
    app.remove_attachment_files(&attachments).await;
    notify.remove(user_id);
    app.hub.revoke_user(user_id);
    app.hub
        .publish(notify.iter().map(String::as_str), &events::vaults_changed());
    let mut response = StatusCode::NO_CONTENT.into_response();
    with_cookie(&mut response, &app.clear_cookie());
    Ok(response)
}
