//! Passkeys of the own account as second factor:
//! registration, list and removal.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;
use webauthn_rs::prelude::{CredentialID, PasskeyRegistration, RegisterPublicKeyCredential, Uuid};

use super::two_factor::{codes_for_first_factor, new_backup_codes};
use crate::app::App;
use crate::audit;
use crate::auth::{AuthSession, ClientIp, NoQuery, Reauthed};
use crate::clock::format_timestamp;
use crate::crypto::{new_token, sha256};
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::StrictJson;
use crate::types::{PasskeyName, Token, is_canonical_uuid};

/// Passkeys per account.
pub const MAX_PASSKEYS: i64 = 10;
/// Lifetime of a registration.
const REGISTRATION_TTL: Duration = Duration::minutes(5);
/// Longest credential ID of WebAuthn Level 3.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

fn state_invalid() -> ApiError {
    ApiError::new(ErrorCode::TwoFactorStateInvalid)
}

/// The account has TOTP or a passkey (backup codes do not count).
async fn has_factor(conn: &mut Conn, user_id: &str) -> ApiResult<bool> {
    let user = db::users::login_by_id(conn, user_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::SessionInvalid))?;
    Ok(user.totp || user.webauthn)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterOptionsBody {
    name: PasskeyName,
}

pub async fn register_options(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: Reauthed,
    _: NoQuery,
    StrictJson(body): StrictJson<RegisterOptionsBody>,
) -> ApiResult<Json<Value>> {
    let user_id = session.user_id.as_str();
    let existing = db::passkeys::for_user(&app.db.read, user_id).await?;
    if existing.len() >= MAX_PASSKEYS as usize {
        return Err(state_invalid());
    }
    let email = db::users::email_by_id(&app.db.read, user_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::SessionInvalid))?;
    let user_uuid = Uuid::parse_str(user_id).map_err(ApiError::internal)?;
    let exclude: Vec<CredentialID> = existing
        .into_iter()
        .map(|p| CredentialID::from(p.credential_id))
        .collect();
    let (options, registration) = app
        .webauthn
        .start_passkey_registration(user_uuid, &email, &email, Some(exclude))
        .map_err(ApiError::internal)?;
    let state = json!({
        "name": body.name.0,
        "registration": serde_json::to_value(&registration).map_err(ApiError::internal)?,
    })
    .to_string();
    let public_key = serde_json::to_value(&options)
        .map_err(ApiError::internal)?
        .get("publicKey")
        .cloned()
        .ok_or_else(|| ApiError::internal("creation options without publicKey"))?;
    let token = new_token().map_err(ApiError::internal)?;
    let mut tx = app.db.begin().await?;
    db::challenges::delete_for_session(&mut *tx, &session.session_id, "webauthn_register").await?;
    let challenge = db::challenges::NewChallenge {
        hash: &token.hash,
        purpose: "webauthn_register",
        user_id,
        session_id: Some(&session.session_id),
        state: Some(&state),
        expires_at: &format_timestamp(app.now() + REGISTRATION_TTL),
    };
    db::challenges::insert(&mut *tx, &challenge).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "registration_token": token.text, "public_key": public_key }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterVerifyBody {
    registration_token: Token,
    credential: RegisterPublicKeyCredential,
}

/// `400` for a credential that cannot be registered.
fn rejected() -> ApiError {
    ApiError::pointer("/credential", "credential rejected")
}

pub async fn register_verify(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    StrictJson(body): StrictJson<RegisterVerifyBody>,
) -> ApiResult<Response> {
    let user_id = session.user_id.as_str();
    let hash = sha256(&body.registration_token.0);
    let now = app.now();
    let now_text = format_timestamp(now);
    let invalid = || ApiError::new(ErrorCode::ChallengeInvalid);
    let challenge = db::challenges::get(&app.db.read, &hash, &now_text)
        .await?
        .filter(|c| {
            c.purpose == "webauthn_register"
                && c.session_id.as_deref() == Some(session.session_id.as_str())
        })
        .ok_or_else(invalid)?;
    // From here on the token is used up, even if the check fails.
    let mut tx = app.db.begin().await?;
    if !db::challenges::delete(&mut *tx, &hash).await? {
        return Err(invalid());
    }
    tx.commit().await?;
    let state: Value = challenge
        .state
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .ok_or_else(|| ApiError::internal("registration without state"))?;
    let name = state["name"]
        .as_str()
        .ok_or_else(|| ApiError::internal("registration without name"))?
        .to_string();
    let registration: PasskeyRegistration =
        serde_json::from_value(state["registration"].clone()).map_err(ApiError::internal)?;
    let passkey = app
        .webauthn
        .finish_passkey_registration(&body.credential, &registration)
        .map_err(|_| rejected())?;
    let credential_id: Vec<u8> = passkey.cred_id().to_vec();
    if credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(rejected());
    }
    let stored = serde_json::to_string(&passkey).map_err(ApiError::internal)?;
    let was_first = !has_factor(&mut *app.db.read.acquire().await?, user_id).await?;
    let codes = if was_first {
        Some(new_backup_codes(&app).await?)
    } else {
        None
    };

    let id = Uuid::now_v7().to_string();
    let mut tx = app.db.begin().await?;
    if db::passkeys::credential_exists(&mut *tx, &credential_id).await? {
        return Err(rejected());
    }
    if db::passkeys::count(&mut *tx, user_id).await? >= MAX_PASSKEYS {
        return Err(state_invalid());
    }
    let first = !has_factor(&mut tx, user_id).await?;
    let new = db::passkeys::NewPasskey {
        id: &id,
        user_id,
        credential_id: &credential_id,
        passkey: &stored,
        name: &name,
        now: &now_text,
    };
    db::passkeys::insert(&mut *tx, &new).await?;
    let shown = codes_for_first_factor(&mut tx, user_id, first, codes).await?;
    audit::log(
        &mut tx,
        &now_text,
        "passkey_added",
        Some(user_id),
        Some(&ip.hint()),
        json!({ "id": id }),
    )
    .await?;
    tx.commit().await?;
    let body = match shown {
        Some(codes) => json!({ "id": id, "backup_codes": codes }),
        None => json!({ "id": id }),
    };
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

pub async fn list(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
) -> ApiResult<Json<Value>> {
    let rows = db::passkeys::list(&app.db.read, &session.user_id).await?;
    let credentials: Vec<Value> = rows
        .into_iter()
        .map(|p| {
            json!({
                "id": p.id,
                "name": p.name,
                "created": p.created_at,
                "last_used": p.last_used_at,
                "prf_enabled": p.prf_enabled,
            })
        })
        .collect();
    Ok(Json(json!({ "credentials": credentials })))
}

pub async fn delete(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: Reauthed,
    Path(credential_id): Path<String>,
    _: NoQuery,
) -> ApiResult<StatusCode> {
    if !is_canonical_uuid(&credential_id) {
        return Err(ApiError::parameter("credential_id", "not a canonical UUID"));
    }
    let user_id = session.user_id.as_str();
    let now_text = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    if !db::passkeys::delete(&mut *tx, user_id, &credential_id).await? {
        return Err(ApiError::new(ErrorCode::NotFound));
    }
    // Backup codes go with the last second factor.
    if !has_factor(&mut tx, user_id).await? {
        db::backup_codes::delete_all(&mut *tx, user_id).await?;
    }
    audit::log(
        &mut tx,
        &now_text,
        "passkey_removed",
        Some(user_id),
        Some(&ip.hint()),
        json!({ "id": credential_id }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
