//! `prelogin`, `register`, `login`, `refresh` and `logout`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::Duration;

use super::{RecoveryMaterial, hex, kdf_json, parse_kdf};
use crate::app::App;
use crate::audit;
use crate::auth::origin::{self, Origin};
use crate::auth::second_factor::{self, Factors};
use crate::auth::session::{self, issue_access, issue_refresh, with_cookie};
use crate::auth::{AuthSession, ClientIp, NoQuery, cookie, throttle};
use crate::clock::{format_timestamp, parse_timestamp};
use crate::config::Registration;
use crate::crypto::{hash_token, sha256};
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::{json, optional_json, present};
use crate::ratelimit::{Bucket, Quota};
use crate::types::{
    ClientType, DEFAULT_KDF, Device, Email, KdfParamsInput, Key32, Salt, Token, UserDataEnvelope,
    Uuid, WrappedKey, encode_base64url,
};

/// A parallel refresh may present the directly preceding token this long.
const REFRESH_GRACE: Duration = Duration::seconds(30);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreloginBody {
    email: Email,
}

pub async fn prelogin(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Response> {
    app.limit(
        Bucket::Prelogin,
        &ip.limit_key(),
        Quota::per_minute(app.config.rate_limits.prelogin_per_ip_per_min),
    )?;
    let body: PreloginBody = json(request).await?;
    let email = &body.email.0;
    // Unknown addresses get deterministic dummy values.
    let (kdf, salt) = match db::users::kdf_by_email(&app.db.read, email).await? {
        Some(row) => (parse_kdf(&row.kdf_params)?, row.kdf_salt),
        None => (DEFAULT_KDF, app.keys.dummy_salt(email).to_vec()),
    };
    Ok(Json(json!({ "kdf": kdf, "salt": encode_base64url(&salt) })).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterBody {
    #[serde(default, deserialize_with = "present")]
    invite_code: Option<Token>,
    user_id: Uuid,
    email: Email,
    kdf: KdfParamsInput,
    salt: Salt,
    auth_key: Key32,
    user_key_wrapped: WrappedKey,
    public_key: Key32,
    private_key_wrapped: WrappedKey,
    recovery: RecoveryMaterial,
    user_data: UserDataEnvelope,
    device: Device,
}

pub async fn register(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Response> {
    let mode = app.config.security.registration;
    if mode == Registration::Closed {
        return Err(ApiError::new(ErrorCode::RegistrationClosed));
    }
    let body: RegisterBody = json(request).await?;
    // Only well-formed requests count.
    app.limit(
        Bucket::Register,
        &ip.limit_key(),
        Quota::per_hour(app.config.rate_limits.register_per_ip_per_hour),
    )?;
    {
        // Cheap checks first, so invalid requests cost no Argon2id.
        let mut conn = app.db.read.acquire().await?;
        register_checks(&mut conn, &app, mode, &body).await?;
    }
    let kdf = body.kdf.validate()?;
    let auth_hash = app.passwords.hash(&body.auth_key.0).await?;
    let recovery_hash = app.passwords.hash(&body.recovery.auth_key.0).await?;

    let now = app.now();
    let now_text = format_timestamp(now);
    let hint = ip.hint();
    let mut tx = app.db.begin().await?;
    let invite_id = register_checks(&mut tx, &app, mode, &body).await?;
    let user_id = body.user_id.0.as_str();
    let user = db::users::NewUser {
        id: user_id,
        email: &body.email.0,
        kdf_params: &kdf_json(&kdf)?,
        kdf_salt: &body.salt.0,
        auth_hash: &auth_hash,
        user_key_wrapped: &body.user_key_wrapped.0,
        public_key: &body.public_key.0,
        private_key_wrapped: &body.private_key_wrapped.0,
        user_data: &body.user_data.0,
        recovery_auth_hash: &recovery_hash,
        user_key_recovery_wrapped: &body.recovery.user_key_wrapped.0,
        now: &now_text,
    };
    db::users::insert(&mut *tx, &user).await?;
    // After the account exists: `invites.used_by` references it.
    if let Some(invite_id) = invite_id
        && db::invites::consume(&mut *tx, &invite_id, user_id, &now_text).await? == 0
    {
        return Err(ApiError::new(ErrorCode::InviteInvalid));
    }
    let issued = session::create(&mut tx, &app, user_id, &body.device, &hint, now).await?;
    audit::log(
        &mut tx,
        &now_text,
        "register",
        Some(user_id),
        Some(&hint),
        json!({ "session_id": issued.session_id }),
    )
    .await?;
    tx.commit().await?;
    Ok(session::response(
        &app,
        StatusCode::CREATED,
        user_id,
        &issued,
        body.device.client_type,
    ))
}

/// Registration checks after the structure (invite, existing account, KDF
/// parameters, taken e-mail); returns the invite to consume. Runs before
/// hashing and again inside the write transaction.
async fn register_checks(
    conn: &mut Conn,
    app: &App,
    mode: Registration,
    body: &RegisterBody,
) -> ApiResult<Option<String>> {
    let user_id = body.user_id.0.as_str();
    let email = body.email.0.as_str();
    let existing_email = db::users::email_by_id(&mut *conn, user_id).await?;
    let same_account = existing_email.as_deref() == Some(email);
    let mut invite_id = None;
    match mode {
        Registration::Closed => return Err(ApiError::new(ErrorCode::RegistrationClosed)),
        Registration::Invite => {
            let invalid = || ApiError::new(ErrorCode::InviteInvalid);
            let code = body.invite_code.as_ref().ok_or_else(invalid)?;
            let invite = db::invites::by_hash(&mut *conn, &sha256(&code.0))
                .await?
                .ok_or_else(invalid)?;
            if invite.used_at.is_some() {
                // A byte-identical retry after a network error.
                let retry = invite.used_by.as_deref() == Some(user_id) && same_account;
                return Err(if retry {
                    ApiError::new(ErrorCode::AlreadyRegistered)
                } else {
                    invalid()
                });
            }
            if invite.expires_at <= format_timestamp(app.now()) {
                return Err(invalid());
            }
            invite_id = Some(invite.id);
        }
        Registration::Open => {
            if same_account {
                return Err(ApiError::new(ErrorCode::AlreadyRegistered));
            }
        }
    }
    body.kdf.validate()?;
    if db::users::id_by_email(&mut *conn, email)
        .await?
        .is_some_and(|owner| owner != user_id)
    {
        return Err(ApiError::new(ErrorCode::EmailTaken));
    }
    match existing_email {
        Some(_) if same_account => Err(ApiError::new(ErrorCode::AlreadyRegistered)),
        Some(_) => Err(ApiError::new(ErrorCode::Conflict)),
        None => Ok(invite_id),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginBody {
    email: Email,
    auth_key: Key32,
    device: Device,
}

pub async fn login(
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
    let body: LoginBody = json(request).await?;
    let key = app.keys.throttle_key(&body.email.0);
    app.limit(
        Bucket::CredentialEmail,
        &hex(&key),
        Quota::per_minute(limits.credential_per_email_per_min),
    )?;
    throttle::check(&app, &key).await?;

    let user = db::users::login_by_email(&app.db.read, &body.email.0).await?;
    let valid = app
        .passwords
        .verify(
            &body.auth_key.0,
            user.as_ref().map(|u| u.auth_hash.as_str()),
        )
        .await?;
    let now = app.now();
    let now_text = format_timestamp(now);
    let hint = ip.hint();
    let mut tx = app.db.begin().await?;
    let user = match user {
        Some(user) if valid => user,
        user => {
            let user_id = user.as_ref().map(|u| u.id.as_str());
            throttle::failure(&mut tx, &app, &key, user_id, &hint).await?;
            audit::log(
                &mut tx,
                &now_text,
                "login_failed",
                user_id,
                Some(&hint),
                json!({}),
            )
            .await?;
            tx.commit().await?;
            return Err(ApiError::new(ErrorCode::InvalidCredentials));
        }
    };
    // Neither a failure nor a reset: only a complete login resets.
    if user.disabled {
        audit::log(
            &mut tx,
            &now_text,
            "login_disabled",
            Some(&user.id),
            Some(&hint),
            json!({}),
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
    if factors.any() {
        // Never a session while a second factor is set up; the counter stays
        // until the second factor succeeds.
        let response =
            second_factor::issue(&mut tx, "login", &user.id, factors, Some(&body.device), now)
                .await?;
        tx.commit().await?;
        return Ok(response);
    }
    throttle::success(&mut tx, &key).await?;
    let issued = session::create(&mut tx, &app, &user.id, &body.device, &hint, now).await?;
    db::users::set_last_login(&mut *tx, &user.id, &now_text).await?;
    audit::log(
        &mut tx,
        &now_text,
        "login_ok",
        Some(&user.id),
        Some(&hint),
        json!({ "session_id": issued.session_id, "method": "password" }),
    )
    .await?;
    tx.commit().await?;
    Ok(session::response(
        &app,
        StatusCode::OK,
        &user.id,
        &issued,
        body.device.client_type,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshBody {
    #[serde(default, deserialize_with = "present")]
    refresh_token: Option<Token>,
}

#[derive(Serialize)]
struct TokenRefresh<'a> {
    access_token: &'a str,
    access_expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
}

pub async fn refresh(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    request: Request,
) -> ApiResult<Response> {
    // The origin check comes before any token lookup.
    let origin = origin::check(request.headers(), &app.config.server.allowed_origins);
    if origin == Origin::Forbidden {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    app.limit(
        Bucket::Refresh,
        &ip.limit_key(),
        Quota::per_minute(app.config.rate_limits.refresh_per_ip_per_min),
    )?;
    let cookie = cookie::read(request.headers(), app.cookie_name());
    let body: Option<RefreshBody> = optional_json(request).await?;
    let (hash, from_cookie) = match (body.and_then(|b| b.refresh_token), cookie) {
        (Some(token), _) => (Some(sha256(&token.0)), false),
        (None, Some(_)) if origin != Origin::Allowed => {
            return Err(ApiError::new(ErrorCode::Forbidden));
        }
        (None, Some(value)) => (hash_token(&value), true),
        (None, None) => return Err(ApiError::new(ErrorCode::SessionInvalid)),
    };
    let unauthorized = || {
        let error = ApiError::new(ErrorCode::SessionInvalid);
        if from_cookie {
            error.set_cookie(app.clear_cookie())
        } else {
            error
        }
    };
    let Some(hash) = hash else {
        return Err(unauthorized());
    };

    let now = app.now();
    let now_text = format_timestamp(now);
    let mut tx = app.db.begin().await?;
    let Some(row) = db::sessions::refresh_lookup(&mut *tx, &hash).await? else {
        return Err(unauthorized());
    };
    if row.revoked_at.is_some() || row.refresh_expires_at <= now_text || row.disabled {
        return Err(unauthorized());
    }
    let client_type = ClientType::parse(&row.client_type)
        .ok_or_else(|| ApiError::internal("unknown client type"))?;
    if let Some(superseded) = row.superseded_at.as_deref() {
        let recent = parse_timestamp(superseded).is_some_and(|t| now - t <= REFRESH_GRACE);
        if recent && row.is_previous {
            return Err(ApiError::new(ErrorCode::RefreshSuperseded));
        }
        // Reuse of an old token: the session is considered stolen.
        let hint = ip.hint();
        db::sessions::revoke(&mut tx, &row.session_id, &now_text).await?;
        audit::log(
            &mut tx,
            &now_text,
            "refresh_reuse",
            Some(&row.user_id),
            Some(&hint),
            json!({ "session_id": row.session_id }),
        )
        .await?;
        audit::sessions_revoked(
            &mut tx,
            &now_text,
            &row.user_id,
            Some(&hint),
            std::slice::from_ref(&row.session_id),
            "reuse",
        )
        .await?;
        tx.commit().await?;
        app.hub
            .revoke_sessions(std::slice::from_ref(&row.session_id));
        return Err(unauthorized());
    }
    db::sessions::supersede_refresh(&mut *tx, &hash, &now_text).await?;
    let refresh_token = issue_refresh(&mut tx, &row.session_id, now).await?;
    let access_token = issue_access(&mut tx, &app, &row.session_id, now).await?;
    let expires = format_timestamp(now + app.refresh_ttl());
    db::sessions::extend(
        &mut *tx,
        &row.session_id,
        &expires,
        &now_text,
        Some(&ip.hint()),
    )
    .await?;
    tx.commit().await?;

    let web = client_type == ClientType::Web;
    let body = TokenRefresh {
        access_token: &access_token,
        access_expires_in: app.access_ttl().whole_seconds(),
        refresh_token: (!web).then_some(refresh_token.as_str()),
    };
    let mut response = Json(body).into_response();
    if web {
        with_cookie(&mut response, &app.refresh_cookie(&refresh_token));
    }
    Ok(response)
}

pub async fn logout(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if origin::check(&headers, &app.config.server.allowed_origins) == Origin::Forbidden {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    let now_text = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    db::sessions::revoke(&mut tx, &session.session_id, &now_text).await?;
    let ids = std::slice::from_ref(&session.session_id);
    audit::sessions_revoked(
        &mut tx,
        &now_text,
        &session.user_id,
        Some(&ip.hint()),
        ids,
        "logout",
    )
    .await?;
    tx.commit().await?;
    app.hub.revoke_sessions(ids);
    let mut response = StatusCode::NO_CONTENT.into_response();
    with_cookie(&mut response, &app.clear_cookie());
    Ok(response)
}
