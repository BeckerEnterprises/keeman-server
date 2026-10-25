//! Managing the own second factors: account TOTP and backup codes.
//! Changes leave sessions and open challenges alone.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;

use crate::app::App;
use crate::audit;
use crate::auth::second_factor::{Factors, MAX_ATTEMPTS};
use crate::auth::{AuthSession, ClientIp, NoQuery, Reauthed, backup_codes};
use crate::clock::format_timestamp;
use crate::crypto::{base32, new_token, random_bytes, totp};
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::StrictJson;
use crate::types::{TotpCode, decode_base64url, encode_base64url};

/// Lifetime of an open TOTP setup.
const TOTP_SETUP_TTL: Duration = Duration::minutes(10);

fn state_invalid() -> ApiError {
    ApiError::new(ErrorCode::TwoFactorStateInvalid)
}

/// The second factors of an account as seen inside a transaction.
async fn factors(conn: &mut Conn, user_id: &str) -> ApiResult<Factors> {
    let user = db::users::login_by_id(conn, user_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::SessionInvalid))?;
    Ok(Factors {
        totp: user.totp,
        webauthn: user.webauthn,
        backup_codes: user.backup_codes,
    })
}

/// Ten new backup codes and their hashes, computed outside transactions.
pub(crate) async fn new_backup_codes(app: &App) -> ApiResult<(Vec<String>, Vec<String>)> {
    let codes = backup_codes::generate().map_err(ApiError::internal)?;
    let inputs = codes.iter().map(|c| c.as_bytes().to_vec()).collect();
    let hashes = app.passwords.hash_all(inputs).await?;
    Ok((codes, hashes))
}

/// Stores the backup codes if the factor just added is the first one;
/// returns the codes to show.
pub(crate) async fn codes_for_first_factor(
    tx: &mut Conn,
    user_id: &str,
    was_first: bool,
    codes: Option<(Vec<String>, Vec<String>)>,
) -> ApiResult<Option<Vec<String>>> {
    let Some((codes, hashes)) = codes.filter(|_| was_first) else {
        return Ok(None);
    };
    db::backup_codes::replace(tx, user_id, &hashes).await?;
    Ok(Some(codes))
}

pub async fn totp_setup(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: Reauthed,
    _: NoQuery,
) -> ApiResult<Json<Value>> {
    let user_id = session.user_id.as_str();
    let state = db::users::totp_state(&app.db.read, user_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::SessionInvalid))?;
    if state.enabled {
        return Err(state_invalid());
    }
    let secret = random_bytes::<{ totp::SECRET_BYTES }>().map_err(ApiError::internal)?;
    let sealed = app
        .keys
        .seal_totp_secret(user_id, &secret)
        .map_err(ApiError::internal)?;
    let token = new_token().map_err(ApiError::internal)?;
    let setup = json!({ "secret": encode_base64url(&sealed) }).to_string();
    let now = app.now();
    let mut tx = app.db.begin().await?;
    db::challenges::delete_for_user(&mut *tx, user_id, "totp_setup").await?;
    let challenge = db::challenges::NewChallenge {
        hash: &token.hash,
        purpose: "totp_setup",
        user_id,
        session_id: Some(&session.session_id),
        state: Some(&setup),
        expires_at: &format_timestamp(now + TOTP_SETUP_TTL),
    };
    db::challenges::insert(&mut *tx, &challenge).await?;
    tx.commit().await?;
    Ok(Json(json!({
        "secret": base32::encode(&secret),
        "otpauth_uri": totp::otpauth_uri(&state.email, &secret),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpEnableBody {
    code: TotpCode,
}

pub async fn totp_enable(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    StrictJson(body): StrictJson<TotpEnableBody>,
) -> ApiResult<Json<Value>> {
    let user_id = session.user_id.as_str();
    let now = app.now();
    let now_text = format_timestamp(now);
    let setup =
        db::challenges::get_for_session(&app.db.read, &session.session_id, "totp_setup", &now_text)
            .await?
            .ok_or_else(|| ApiError::new(ErrorCode::ChallengeInvalid))?;
    let before = factors(&mut *app.db.read.acquire().await?, user_id).await?;
    if before.totp {
        return Err(state_invalid());
    }
    let sealed = setup
        .state
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v["secret"].as_str().and_then(decode_base64url))
        .ok_or_else(|| ApiError::internal("TOTP setup without secret"))?;
    let secret = app
        .keys
        .open_totp_secret(user_id, &sealed)
        .map_err(ApiError::internal)?;
    let Some(step) = totp::verify(&secret, &body.code.0, now.unix_timestamp(), None) else {
        let mut tx = app.db.begin().await?;
        if db::challenges::count_failure(&mut *tx, &setup.hash).await? >= MAX_ATTEMPTS {
            db::challenges::delete(&mut *tx, &setup.hash).await?;
        }
        tx.commit().await?;
        return Err(ApiError::new(ErrorCode::InvalidSecondFactor));
    };
    let codes = if before.any() {
        None
    } else {
        Some(new_backup_codes(&app).await?)
    };
    let mut tx = app.db.begin().await?;
    if !db::challenges::delete(&mut *tx, &setup.hash).await? {
        return Err(ApiError::new(ErrorCode::ChallengeInvalid));
    }
    let current = factors(&mut tx, user_id).await?;
    if current.totp {
        return Err(state_invalid());
    }
    db::users::enable_totp(&mut *tx, user_id, &sealed, step, &now_text).await?;
    let shown = codes_for_first_factor(&mut tx, user_id, !current.any(), codes).await?;
    audit::log(
        &mut tx,
        &now_text,
        "totp_enabled",
        Some(user_id),
        Some(&ip.hint()),
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(match shown {
        Some(codes) => json!({ "backup_codes": codes }),
        None => json!({}),
    }))
}

pub async fn totp_disable(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: Reauthed,
    _: NoQuery,
) -> ApiResult<StatusCode> {
    let user_id = session.user_id.as_str();
    let now_text = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    if !db::users::disable_totp(&mut *tx, user_id, &now_text).await? {
        return Err(state_invalid());
    }
    // Backup codes go with the last second factor.
    if !factors(&mut tx, user_id).await?.any() {
        db::backup_codes::delete_all(&mut *tx, user_id).await?;
    }
    audit::log(
        &mut tx,
        &now_text,
        "totp_disabled",
        Some(user_id),
        Some(&ip.hint()),
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn regenerate_backup_codes(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: Reauthed,
    _: NoQuery,
) -> ApiResult<Json<Value>> {
    let user_id = session.user_id.as_str();
    if !factors(&mut *app.db.read.acquire().await?, user_id)
        .await?
        .any()
    {
        return Err(state_invalid());
    }
    let (codes, hashes) = new_backup_codes(&app).await?;
    let now_text = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    if !factors(&mut tx, user_id).await?.any() {
        return Err(state_invalid());
    }
    db::backup_codes::replace(&mut tx, user_id, &hashes).await?;
    audit::log(
        &mut tx,
        &now_text,
        "backup_codes_regenerated",
        Some(user_id),
        Some(&ip.hint()),
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "backup_codes": codes })))
}
