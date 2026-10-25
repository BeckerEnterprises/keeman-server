//! Account recovery with the recovery key:
//! `recover/start` and `recover/finish`.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use super::{RecoveryMaterial, hex, kdf_json};
use crate::app::App;
use crate::auth::second_factor::{self, Factors};
use crate::auth::{ClientIp, NoQuery, session, throttle};
use crate::clock::format_timestamp;
use crate::crypto::sha256;
use crate::db;
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::{json, present};
use crate::ratelimit::{Bucket, Quota};
use crate::types::{Device, Email, KdfParamsInput, Key32, Salt, Token, WrappedKey};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverStartBody {
    email: Email,
    recovery_auth_key: Key32,
}

/// Same buckets, failure counter and lockout as login.
pub async fn start(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Response> {
    let limits = &app.config.rate_limits;
    app.limit(
        Bucket::CredentialIp,
        &ip.limit_key(),
        Quota::per_minute(limits.credential_per_ip_per_min),
    )?;
    let body: RecoverStartBody = json(request).await?;
    let key = app.keys.throttle_key(&body.email.0);
    app.limit(
        Bucket::CredentialEmail,
        &hex(&key),
        Quota::per_minute(limits.credential_per_email_per_min),
    )?;
    throttle::check(&app, &key).await?;

    let user = db::users::recovery_by_email(&app.db.read, &body.email.0).await?;
    // Unknown addresses are checked against the dummy hash.
    let valid = app
        .passwords
        .verify(
            &body.recovery_auth_key.0,
            user.as_ref().map(|u| u.recovery_auth_hash.as_str()),
        )
        .await?;
    let now = app.now();
    let now_text = format_timestamp(now);
    let hint = ip.hint();
    let mut tx = app.db.begin().await?;
    throttle::ensure_unlocked(&mut tx, &app, &key).await?;
    // As at login: the check counts only while the checked hash is still
    // stored (a new recovery key may have committed meanwhile).
    let current = match &user {
        Some(checked) if valid => db::users::recovery_by_id(&mut *tx, &checked.id)
            .await?
            .filter(|current| current.recovery_auth_hash == checked.recovery_auth_hash),
        _ => None,
    };
    let user = match current {
        Some(current) => current,
        None => {
            let user_id = user.as_ref().map(|u| u.id.as_str());
            throttle::failure(&mut tx, &app, &key, user_id, &hint).await?;
            app.audit
                .log(
                    &mut tx,
                    &now_text,
                    "recovery_failed",
                    user_id,
                    Some(&hint),
                    json!({}),
                )
                .await?;
            tx.commit().await?;
            return Err(ApiError::new(ErrorCode::InvalidCredentials));
        }
    };
    if user.disabled {
        app.audit
            .log(
                &mut tx,
                &now_text,
                "login_disabled",
                Some(&user.id),
                Some(&hint),
                json!({ "recovery": true }),
            )
            .await?;
        tx.commit().await?;
        return Err(ApiError::new(ErrorCode::AccountDisabled));
    }
    let factors = Factors {
        totp: user.totp,
        webauthn: user.webauthn,
        backup_codes: user.backup_codes,
    };
    let response = if factors.any() {
        // The counter stays until the second factor succeeds.
        second_factor::issue(&mut tx, "recovery", &user.id, factors, None, now).await?
    } else {
        throttle::success(&mut tx, &app, &key).await?;
        second_factor::recovery_payload(&mut tx, &app, &user.id, "recovery_key", &hint, now, None)
            .await?
    };
    tx.commit().await?;
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverFinishBody {
    recovery_token: Token,
    kdf: KdfParamsInput,
    salt: Salt,
    auth_key: Key32,
    user_key_wrapped: WrappedKey,
    #[serde(default, deserialize_with = "present")]
    recovery: Option<RecoveryMaterial>,
    device: Device,
}

/// New password material, all sessions revoked, one new session.
pub async fn finish(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Response> {
    let limits = &app.config.rate_limits;
    app.limit(
        Bucket::RecoverIp,
        &ip.limit_key(),
        Quota::per_minute(limits.credential_per_ip_per_min),
    )?;
    let body: RecoverFinishBody = json(request).await?;
    let hash = sha256(&body.recovery_token.0);
    let now = app.now();
    let now_text = format_timestamp(now);
    let invalid = || ApiError::new(ErrorCode::ChallengeInvalid);
    let challenge = db::challenges::get(&app.db.read, &hash, &now_text)
        .await?
        .filter(|c| c.purpose == "recovery_finish")
        .ok_or_else(invalid)?;
    let user_id = challenge.user_id;
    app.limit(
        Bucket::RecoverAccount,
        &user_id,
        Quota::per_minute(limits.credential_per_email_per_min),
    )?;
    // `400` and `422` keep the token.
    let kdf = body.kdf.validate()?;
    let user = db::users::login_by_id(&app.db.read, &user_id)
        .await?
        .ok_or_else(invalid)?;
    let hint = ip.hint();
    if user.disabled {
        let mut tx = app.db.begin().await?;
        db::challenges::delete(&mut *tx, &hash).await?;
        tx.commit().await?;
        return Err(ApiError::new(ErrorCode::AccountDisabled));
    }
    let auth_hash = app.passwords.hash(&body.auth_key.0).await?;
    let recovery_hash = match &body.recovery {
        Some(recovery) => Some(app.passwords.hash(&recovery.auth_key.0).await?),
        None => None,
    };

    let mut tx = app.db.begin().await?;
    if !db::challenges::delete(&mut *tx, &hash).await? {
        return Err(invalid());
    }
    db::users::update_password(
        &mut *tx,
        &user_id,
        &kdf_json(&kdf)?,
        &body.salt.0,
        &auth_hash,
        &body.user_key_wrapped.0,
        &now_text,
    )
    .await?;
    if let (Some(recovery), Some(recovery_hash)) = (&body.recovery, &recovery_hash) {
        db::users::update_recovery(
            &mut *tx,
            &user_id,
            recovery_hash,
            &recovery.user_key_wrapped.0,
            &now_text,
        )
        .await?;
    }
    // Reauth tokens, open second-factor steps and other recovery tokens.
    db::challenges::delete_all_for_user(&mut *tx, &user_id).await?;
    let revoked = db::sessions::revoke_all(&mut tx, &user_id, &now_text).await?;
    let issued = session::create(&mut tx, &app, &user_id, &body.device, &hint, now).await?;
    db::users::set_last_login(&mut *tx, &user_id, &now_text).await?;
    app.audit
        .sessions_revoked(
            &mut tx,
            &now_text,
            &user_id,
            Some(&hint),
            &revoked,
            "recovery",
        )
        .await?;
    app.audit
        .log(
            &mut tx,
            &now_text,
            "recovery_completed",
            Some(&user_id),
            Some(&hint),
            json!({
                "revoked_sessions": revoked.len(),
                "recovery_key_replaced": body.recovery.is_some(),
                "session_id": issued.session_id,
            }),
        )
        .await?;
    tx.commit().await?;
    app.hub.revoke_sessions(&revoked);
    Ok(session::response(
        &app,
        StatusCode::OK,
        &user_id,
        &issued,
        body.device.client_type,
    ))
}
