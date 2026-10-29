//! Shared steps of the second factor: issuing challenges,
//! opening them in `2fa/*`, failures and completion. The lockout counter
//! is reset only by a complete login.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use crate::api::hex;
use crate::app::App;
use crate::auth::{session, throttle};
use crate::clock::format_timestamp;
use crate::crypto::{new_token, sha256};
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::ratelimit::{Bucket, Quota};
use crate::types::{Device, Token, encode_base64url};

/// Lifetime of a login or recovery challenge.
pub const CHALLENGE_TTL: Duration = Duration::minutes(5);
/// Lifetime of a recovery token.
pub const RECOVERY_TTL: Duration = Duration::minutes(10);
/// Failed attempts after which a challenge is used up.
pub const MAX_ATTEMPTS: i64 = 5;

/// Which second factors an account has (`methods`).
#[derive(Debug, Clone, Copy)]
pub struct Factors {
    pub totp: bool,
    pub webauthn: bool,
    pub backup_codes: bool,
}

impl Factors {
    /// Backup codes alone are no second factor.
    pub fn any(self) -> bool {
        self.totp || self.webauthn
    }

    fn methods(self) -> Vec<&'static str> {
        [
            (self.totp, "totp"),
            (self.webauthn, "webauthn"),
            (self.backup_codes, "backup_code"),
        ]
        .into_iter()
        .filter_map(|(on, method)| on.then_some(method))
        .collect()
    }
}

#[derive(Serialize)]
struct SecondFactorRequired {
    status: &'static str,
    challenge_token: String,
    methods: Vec<&'static str>,
    expires_in: i64,
}

/// Creates a `login` or `recovery` challenge and its `SecondFactorRequired`
/// body. A login challenge carries the device of the later session.
pub async fn issue(
    conn: &mut Conn,
    purpose: &'static str,
    user_id: &str,
    factors: Factors,
    device: Option<&Device>,
    now: OffsetDateTime,
) -> ApiResult<Response> {
    let token = new_token().map_err(ApiError::internal)?;
    let state = device.map(|d| {
        json!({ "device": { "name": d.name.0, "client_type": d.client_type } }).to_string()
    });
    let challenge = db::challenges::NewChallenge {
        hash: &token.hash,
        purpose,
        user_id,
        session_id: None,
        state: state.as_deref(),
        expires_at: &format_timestamp(now + CHALLENGE_TTL),
    };
    db::challenges::insert(conn, &challenge).await?;
    let body = SecondFactorRequired {
        status: "second_factor_required",
        challenge_token: token.text,
        methods: factors.methods(),
        expires_in: CHALLENGE_TTL.whole_seconds(),
    };
    Ok(Json(body).into_response())
}

/// An open `login` or `recovery` challenge with its account.
pub struct Pending {
    pub hash: Vec<u8>,
    pub purpose: String,
    pub user_id: String,
    pub state: Value,
    /// The state as stored, to replace it only if nobody else did.
    pub stored_state: Option<String>,
    pub disabled: bool,
    pub factors: Factors,
    throttle_key: [u8; 32],
}

/// Challenge → rate limit per e-mail address of the account → lockout.
/// The rate limit per IP and the body come first, in the handler.
pub async fn open(app: &App, token: &Token, check_lockout: bool) -> ApiResult<Pending> {
    let hash = sha256(&token.0);
    let now = format_timestamp(app.now());
    let invalid = || ApiError::new(ErrorCode::ChallengeInvalid);
    let challenge = db::challenges::get(&app.db.read, &hash, &now)
        .await?
        .filter(|c| c.purpose == "login" || c.purpose == "recovery")
        .ok_or_else(invalid)?;
    let user = db::users::login_by_id(&app.db.read, &challenge.user_id)
        .await?
        .ok_or_else(invalid)?;
    let throttle_key = app.keys.throttle_key(&user.email);
    if check_lockout {
        app.limit(
            Bucket::CredentialEmail,
            &hex(&throttle_key),
            Quota::per_minute(app.config.rate_limits.credential_per_email_per_min),
        )?;
        throttle::check(app, &throttle_key).await?;
    }
    let state = match challenge.state.as_deref() {
        Some(text) => serde_json::from_str(text).map_err(ApiError::internal)?,
        None => Value::Object(Default::default()),
    };
    Ok(Pending {
        hash: challenge.hash,
        purpose: challenge.purpose,
        user_id: challenge.user_id,
        state,
        stored_state: challenge.state,
        disabled: user.disabled,
        factors: Factors {
            totp: user.totp,
            webauthn: user.webauthn,
            backup_codes: user.backup_codes,
        },
        throttle_key,
    })
}

/// A wrong second factor: counts at the challenge (5 end it) and towards
/// the lockout, and is logged. Returns the error to answer.
pub async fn fail(app: &App, pending: &Pending, method: &str, ip_hint: &str) -> ApiError {
    match record_failure(app, pending, method, ip_hint, None).await {
        Ok(()) => ApiError::new(ErrorCode::InvalidSecondFactor),
        Err(error) => error,
    }
}

/// Like [`fail`], and replaces the challenge state in the same transaction
/// (used-up WebAuthn ceremony) unless it changed since it was read.
pub async fn fail_with_state(
    app: &App,
    pending: &Pending,
    method: &str,
    ip_hint: &str,
    state: &str,
) -> ApiError {
    match record_failure(app, pending, method, ip_hint, Some(state)).await {
        Ok(()) => ApiError::new(ErrorCode::InvalidSecondFactor),
        Err(error) => error,
    }
}

async fn record_failure(
    app: &App,
    pending: &Pending,
    method: &str,
    ip_hint: &str,
    state: Option<&str>,
) -> ApiResult<()> {
    let now_text = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    if let Some(state) = state {
        db::challenges::replace_state(
            &mut *tx,
            &pending.hash,
            pending.stored_state.as_deref(),
            state,
        )
        .await?;
    }
    let attempts = db::challenges::count_failure(&mut *tx, &pending.hash).await?;
    if attempts >= MAX_ATTEMPTS {
        db::challenges::delete(&mut *tx, &pending.hash).await?;
    }
    throttle::failure(
        &mut tx,
        app,
        &pending.throttle_key,
        Some(&pending.user_id),
        ip_hint,
    )
    .await?;
    app.audit
        .log(
            &mut tx,
            &now_text,
            "2fa_failed",
            Some(&pending.user_id),
            Some(ip_hint),
            json!({ "method": method }),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

/// A disabled account after a correct second factor: the challenge is
/// used up and the answer is `403 account_disabled`.
pub async fn disabled(app: &App, pending: &Pending, ip_hint: &str) -> ApiError {
    let result: ApiResult<()> = async {
        let now_text = format_timestamp(app.now());
        let mut tx = app.db.begin().await?;
        // A lock that began meanwhile hides the disabled account as well.
        throttle::ensure_unlocked(&mut tx, app, &pending.throttle_key).await?;
        db::challenges::delete(&mut *tx, &pending.hash).await?;
        app.audit
            .log(
                &mut tx,
                &now_text,
                "login_disabled",
                Some(&pending.user_id),
                Some(ip_hint),
                json!({}),
            )
            .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => ApiError::new(ErrorCode::AccountDisabled),
        Err(error) => error,
    }
}

/// Completes the challenge inside the caller's transaction, after the
/// factor was accepted there: consumes it, resets the lockout and answers
/// with `Session` (login) or `RecoveryPayload` (recovery). Also returns the
/// sessions a new one revoked for room, for the hub after the commit.
pub async fn complete(
    tx: &mut Conn,
    app: &App,
    pending: &Pending,
    method: &str,
    ip_hint: &str,
    backup_codes_remaining: Option<i64>,
) -> ApiResult<(Response, Vec<String>)> {
    // Gone if a concurrent request used it up, if a password change,
    // recovery or disabling the account deleted it after it was opened, or
    // if it expired while the factor was checked.
    let now = app.now();
    if !db::challenges::consume(&mut *tx, &pending.hash, &format_timestamp(now)).await? {
        return Err(ApiError::new(ErrorCode::ChallengeInvalid));
    }
    throttle::success(tx, app, &pending.throttle_key).await?;
    if pending.purpose == "recovery" {
        let response = recovery_payload(
            tx,
            app,
            &pending.user_id,
            method,
            ip_hint,
            now,
            backup_codes_remaining,
        )
        .await?;
        return Ok((response, Vec::new()));
    }
    let device: Device =
        serde_json::from_value(pending.state["device"].clone()).map_err(ApiError::internal)?;
    let now_text = format_timestamp(now);
    let issued = session::create(tx, app, &pending.user_id, &device, ip_hint, now).await?;
    db::users::set_last_login(&mut *tx, &pending.user_id, &now_text).await?;
    app.audit
        .log(
            tx,
            &now_text,
            "login_ok",
            Some(&pending.user_id),
            Some(ip_hint),
            json!({ "session_id": issued.session_id, "method": method }),
        )
        .await?;
    let response = session::response_with_remaining(
        app,
        StatusCode::OK,
        &pending.user_id,
        &issued,
        device.client_type,
        backup_codes_remaining,
    );
    Ok((response, issued.revoked))
}

#[derive(Serialize)]
struct RecoveryPayload {
    status: &'static str,
    recovery_token: String,
    user_id: String,
    user_key_recovery_wrapped: String,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_codes_remaining: Option<i64>,
}

/// Issues a recovery token (replacing earlier ones of the account) and the
/// `RecoveryPayload`.
pub async fn recovery_payload(
    tx: &mut Conn,
    app: &App,
    user_id: &str,
    method: &str,
    ip_hint: &str,
    now: OffsetDateTime,
    backup_codes_remaining: Option<i64>,
) -> ApiResult<Response> {
    let wrapped = db::users::user_key_recovery_wrapped(&mut *tx, user_id)
        .await?
        .ok_or_else(|| ApiError::internal("account vanished"))?;
    let token = new_token().map_err(ApiError::internal)?;
    db::challenges::delete_for_user(&mut *tx, user_id, "recovery_finish").await?;
    let challenge = db::challenges::NewChallenge {
        hash: &token.hash,
        purpose: "recovery_finish",
        user_id,
        session_id: None,
        state: None,
        expires_at: &format_timestamp(now + RECOVERY_TTL),
    };
    db::challenges::insert(&mut *tx, &challenge).await?;
    let now_text = format_timestamp(now);
    app.audit
        .log(
            tx,
            &now_text,
            "recovery_started",
            Some(user_id),
            Some(ip_hint),
            json!({ "method": method }),
        )
        .await?;
    let body = RecoveryPayload {
        status: "recovery_ok",
        recovery_token: token.text,
        user_id: user_id.to_string(),
        user_key_recovery_wrapped: encode_base64url(&wrapped),
        expires_in: RECOVERY_TTL.whole_seconds(),
        backup_codes_remaining,
    };
    Ok(Json(body).into_response())
}
