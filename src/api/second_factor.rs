//! Completing a login or recovery challenge with a second factor:
//! `2fa/totp`, `2fa/backup-code` and `2fa/webauthn/*`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PublicKeyCredential};

use crate::app::App;
use crate::auth::second_factor::{self, Pending};
use crate::auth::{ClientIp, NoQuery};
use crate::clock::format_timestamp;
use crate::crypto::totp;
use crate::db;
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::json;
use crate::ratelimit::{Bucket, Quota};
use crate::types::{BackupCode, Token, TotpCode};

fn limit_ip(app: &App, ip: ClientIp) -> ApiResult<()> {
    app.limit(
        Bucket::CredentialIp,
        &ip.limit_key(),
        Quota::per_minute(app.config.rate_limits.credential_per_ip_per_min),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpBody {
    challenge_token: Token,
    code: TotpCode,
}

pub async fn totp(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Response> {
    limit_ip(&app, ip)?;
    let body: TotpBody = json(request).await?;
    let pending = second_factor::open(&app, &body.challenge_token, true).await?;
    let hint = ip.hint();
    let Some(step) = check_totp(&app, &pending, &body.code.0).await? else {
        return Err(second_factor::fail(&app, &pending, "totp", &hint).await);
    };
    if pending.disabled {
        return Err(second_factor::disabled(&app, &pending, &hint).await);
    }
    let mut tx = app.db.begin().await?;
    // Stored conditionally: of two requests with the same code only one wins.
    if !db::users::advance_totp_step(&mut *tx, &pending.user_id, step).await? {
        drop(tx);
        return Err(second_factor::fail(&app, &pending, "totp", &hint).await);
    }
    let response = second_factor::complete(&mut tx, &app, &pending, "totp", &hint, None).await?;
    tx.commit().await?;
    Ok(response)
}

/// The accepted time step of a code, or `None`; an account
/// without active TOTP never matches.
async fn check_totp(app: &App, pending: &Pending, code: &str) -> ApiResult<Option<i64>> {
    let Some(state) = db::users::totp_state(&app.db.read, &pending.user_id).await? else {
        return Ok(None);
    };
    let (true, Some(sealed)) = (state.enabled, state.secret_enc) else {
        return Ok(None);
    };
    let secret = app
        .keys
        .open_totp_secret(&pending.user_id, &sealed)
        .map_err(ApiError::internal)?;
    Ok(totp::verify(
        &secret,
        code,
        app.now().unix_timestamp(),
        state.last_step,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCodeBody {
    challenge_token: Token,
    code: BackupCode,
}

pub async fn backup_code(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Response> {
    limit_ip(&app, ip)?;
    let body: BackupCodeBody = json(request).await?;
    let pending = second_factor::open(&app, &body.challenge_token, true).await?;
    let hint = ip.hint();
    let unused = db::backup_codes::unused(&app.db.read, &pending.user_id).await?;
    let ids: Vec<i64> = unused.iter().map(|c| c.id).collect();
    let hashes = unused.into_iter().map(|c| c.code_hash).collect();
    let found = app.passwords.find(body.code.0.as_bytes(), hashes).await?;
    let Some(id) = found.and_then(|index| ids.get(index).copied()) else {
        return Err(second_factor::fail(&app, &pending, "backup_code", &hint).await);
    };
    if pending.disabled {
        return Err(second_factor::disabled(&app, &pending, &hint).await);
    }
    let now_text = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    if !db::backup_codes::mark_used(&mut *tx, id, &now_text).await? {
        drop(tx);
        return Err(second_factor::fail(&app, &pending, "backup_code", &hint).await);
    }
    let remaining = db::backup_codes::remaining(&mut *tx, &pending.user_id).await?;
    let response = second_factor::complete(
        &mut tx,
        &app,
        &pending,
        "backup_code",
        &hint,
        Some(remaining),
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnOptionsBody {
    challenge_token: Token,
}

/// Assertion options for the account's passkeys; the ceremony state is
/// kept at the challenge and replaces an earlier one.
pub async fn webauthn_options(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Json<Value>> {
    limit_ip(&app, ip)?;
    let body: WebauthnOptionsBody = json(request).await?;
    // Nothing is checked here, so neither the address bucket nor the lockout.
    let pending = second_factor::open(&app, &body.challenge_token, false).await?;
    let passkeys = db::passkeys::for_user(&app.db.read, &pending.user_id)
        .await?
        .iter()
        .map(|p| serde_json::from_str::<Passkey>(&p.passkey))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;
    // webauthn-rs would accept an empty list and fail only later.
    if passkeys.is_empty() {
        return Err(ApiError::new(ErrorCode::TwoFactorStateInvalid));
    }
    let (options, authentication) = app
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(ApiError::internal)?;
    let mut state = pending.state.clone();
    state["webauthn"] = serde_json::to_value(&authentication).map_err(ApiError::internal)?;
    let public_key = serde_json::to_value(&options)
        .map_err(ApiError::internal)?
        .get("publicKey")
        .cloned()
        .ok_or_else(|| ApiError::internal("request options without publicKey"))?;
    let mut tx = app.db.begin().await?;
    db::challenges::set_state(&mut *tx, &pending.hash, Some(&state.to_string())).await?;
    tx.commit().await?;
    Ok(Json(json!({ "public_key": public_key })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnVerifyBody {
    challenge_token: Token,
    credential: PublicKeyCredential,
}

pub async fn webauthn_verify(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Response> {
    limit_ip(&app, ip)?;
    let body: WebauthnVerifyBody = json(request).await?;
    let pending = second_factor::open(&app, &body.challenge_token, true).await?;
    let hint = ip.hint();
    let fail = || second_factor::fail(&app, &pending, "webauthn", &hint);
    // Every verification uses the state of the last options call up.
    let Some(authentication) = pending.state.get("webauthn").cloned() else {
        return Err(fail().await);
    };
    let mut state = pending.state.clone();
    if let Some(map) = state.as_object_mut() {
        map.remove("webauthn");
    }
    let state = state.to_string();
    let fail = || second_factor::fail_with_state(&app, &pending, "webauthn", &hint, &state);
    let authentication: PasskeyAuthentication =
        serde_json::from_value(authentication).map_err(ApiError::internal)?;
    let Ok(result) = app
        .webauthn
        .finish_passkey_authentication(&body.credential, &authentication)
    else {
        return Err(fail().await);
    };
    if pending.disabled {
        return Err(second_factor::disabled(&app, &pending, &hint).await);
    }
    let now_text = format_timestamp(app.now());
    // The signature is checked; everything else happens in one transaction,
    // so a concurrent login, a removed passkey or a second verification of
    // the same challenge cannot slip in between check and write.
    let mut tx = app.db.begin().await?;
    let used_up = db::challenges::replace_state(
        &mut *tx,
        &pending.hash,
        pending.stored_state.as_deref(),
        &state,
    )
    .await?;
    let stored = if used_up {
        db::passkeys::by_credential(&mut *tx, &pending.user_id, result.cred_id()).await?
    } else {
        // Another verification of this challenge, or a newer options call.
        None
    };
    let Some(stored) = stored else {
        drop(tx);
        return Err(fail().await);
    };
    // The counter must grow over the stored value, read here. The library
    // exposes it only in the serialised state (`cred.counter`).
    let current = serde_json::from_str::<Value>(&stored.passkey)
        .ok()
        .and_then(|v| v["cred"]["counter"].as_u64())
        .ok_or_else(|| ApiError::internal("stored passkey without counter"))?;
    let counter = u64::from(result.counter());
    if (counter > 0 || current > 0) && counter <= current {
        drop(tx);
        return Err(fail().await);
    }
    let mut passkey: Passkey = serde_json::from_str(&stored.passkey).map_err(ApiError::internal)?;
    passkey.update_credential(&result);
    let updated = serde_json::to_string(&passkey).map_err(ApiError::internal)?;
    if !db::passkeys::record_use(&mut *tx, &stored.id, &stored.passkey, &updated, &now_text).await?
    {
        return Err(ApiError::internal("passkey changed inside the transaction"));
    }
    let response =
        second_factor::complete(&mut tx, &app, &pending, "webauthn", &hint, None).await?;
    tx.commit().await?;
    Ok(response)
}
