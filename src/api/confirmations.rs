//! Confirmation by another device: a session asks the other sessions of its
//! account with a nonce, one of them answers with a signed statement. The
//! server checks the canonical bytes, that the caller made the answer for
//! this nonce, and the signature against the caller's registered signing
//! key; the content only the requesting device judges.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use super::vaults::path_uuid;
use crate::app::App;
use crate::auth::{AuthSession, NoQuery};
use crate::clock::{format_timestamp, parse_timestamp};
use crate::confirmation;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::events;
use crate::extract::json;
use crate::ratelimit::{Bucket, Quota};
use crate::types::{ConfirmationBytes, Nonce, Signature, encode_base64url};

/// Lifetime of a request.
pub const CONFIRMATION_TTL: Duration = Duration::minutes(5);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBody {
    nonce: Nonce,
}

/// An answer as it travels through the API.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConfirmation {
    statement: ConfirmationBytes,
    signature: Signature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerBody {
    answer: SignedConfirmation,
}

fn invalid(detail: &'static str) -> ApiError {
    ApiError::pointer("/answer", detail)
}

/// Whole seconds until `expires_at`, never negative.
fn remaining(now: OffsetDateTime, expires_at: &str) -> i64 {
    parse_timestamp(expires_at).map_or(0, |at| (at - now).whole_seconds().max(0))
}

/// The registered signing key of the caller (`409 signing_key_missing`).
async fn signing_key(conn: &mut Conn, user_id: &str) -> ApiResult<[u8; 32]> {
    let key = match db::users::signing_key(&mut *conn, user_id).await? {
        Some(Some(key)) => key,
        Some(None) => return Err(ApiError::new(ErrorCode::SigningKeyMissing)),
        None => return Err(ApiError::new(ErrorCode::SessionInvalid)),
    };
    key.try_into()
        .map_err(|_| ApiError::internal("stored signing key has a wrong length"))
}

/// `POST /v1/me/confirmations`: rate-limited per account before the body is
/// read; replaces an open request of the same session with its answer.
pub async fn create(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    request: Request,
) -> ApiResult<(StatusCode, Json<Value>)> {
    app.limit(
        Bucket::Confirmation,
        &session.user_id,
        Quota::per_hour(app.config.rate_limits.confirmations_per_account_per_hour),
    )?;
    let body: CreateBody = json(request).await?;
    let now = app.now();
    let id = uuid::Uuid::now_v7().to_string();
    let expires_at = format_timestamp(now + CONFIRMATION_TTL);
    let mut tx = app.db.begin().await?;
    session.confirm(&mut tx, &app).await?;
    signing_key(&mut tx, &session.user_id).await?;
    let row = db::confirmations::NewRequest {
        id: &id,
        user_id: &session.user_id,
        session_id: &session.session_id,
        nonce: &body.nonce.0,
        now: &format_timestamp(now),
        expires_at: &expires_at,
    };
    db::confirmations::replace(&mut tx, &row).await?;
    tx.commit().await?;
    app.hub
        .publish([session.user_id.as_str()], &events::confirmations_changed());
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "request_id": id,
            "expires_at": expires_at,
            "expires_in": CONFIRMATION_TTL.whole_seconds(),
        })),
    ))
}

/// `GET /v1/me/confirmations`: the open requests of the account, without
/// answers.
pub async fn list(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
) -> ApiResult<Json<Value>> {
    let now = app.now();
    let rows =
        db::confirmations::list(&app.db.read, &session.user_id, &format_timestamp(now)).await?;
    let requests: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "request_id": r.id,
                "own": r.session_id == session.session_id,
                "session_id": r.session_id,
                "device_name": r.device_name,
                "client_type": r.client_type,
                "created": r.created_at,
                "expires_in": remaining(now, &r.expires_at),
                "expires_at": r.expires_at,
                "nonce": encode_base64url(&r.nonce),
                "answered": r.answered,
            })
        })
        .collect();
    Ok(Json(json!({ "requests": requests })))
}

/// `GET /v1/me/confirmations/{request_id}`: only for the session that made
/// the request, else `404`.
pub async fn get(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    Path(path): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = path_uuid("request_id", &path)?;
    let now = app.now();
    let open = db::confirmations::open(&app.db.read, id, &session.user_id, &format_timestamp(now))
        .await?
        .filter(|o| o.session_id == session.session_id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let answer = match (&open.answer_statement, &open.answer_signature) {
        (Some(statement), Some(signature)) => json!({
            "statement": encode_base64url(statement),
            "signature": encode_base64url(signature),
        }),
        _ => Value::Null,
    };
    Ok(Json(json!({
        "request_id": id,
        "expires_at": open.expires_at,
        "expires_in": remaining(now, &open.expires_at),
        "answer": answer,
    })))
}

/// `PUT /v1/me/confirmations/{request_id}`: the answer of another session
/// of the account. Checked and stored in one write transaction; the same
/// bytes again are `204`, other ones `409 conflict`.
pub async fn answer(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    Path(path): Path<String>,
    request: Request,
) -> ApiResult<StatusCode> {
    let id = path_uuid("request_id", &path)?;
    let body: AnswerBody = json(request).await?;
    let signed = &body.answer;
    let user_id = session.user_id.as_str();
    let mut tx = app.db.begin().await?;
    session.confirm(&mut tx, &app).await?;
    let open = db::confirmations::open(&mut *tx, id, user_id, &format_timestamp(app.now()))
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    if open.session_id == session.session_id {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    let key = signing_key(&mut tx, user_id).await?;
    let bytes = &signed.statement.0;
    let statement =
        confirmation::parse(bytes).ok_or_else(|| invalid("invalid confirmation statement"))?;
    if statement.user_id != user_id {
        return Err(invalid("the caller must make the statement"));
    }
    if statement.nonce.as_slice() != open.nonce.as_slice() {
        return Err(invalid("the statement answers another request"));
    }
    if !confirmation::verify(&key, bytes, &signed.signature.0) {
        return Err(invalid("the signature does not verify"));
    }
    match (&open.answer_statement, &open.answer_signature) {
        (Some(stored), Some(signature)) => {
            if stored == bytes && signature.as_slice() == signed.signature.0.as_slice() {
                Ok(StatusCode::NO_CONTENT)
            } else {
                Err(ApiError::new(ErrorCode::Conflict))
            }
        }
        _ => {
            db::confirmations::answer(&mut tx, id, bytes, &signed.signature.0).await?;
            tx.commit().await?;
            app.hub.publish([user_id], &events::confirmations_changed());
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

/// `DELETE /v1/me/confirmations/{request_id}`: any session of the account;
/// `204` also when there is none.
pub async fn delete(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    Path(path): Path<String>,
) -> ApiResult<StatusCode> {
    let id = path_uuid("request_id", &path)?;
    let mut tx = app.db.begin().await?;
    session.confirm(&mut tx, &app).await?;
    let deleted = db::confirmations::delete(&mut tx, id, &session.user_id).await?;
    tx.commit().await?;
    if deleted > 0 {
        app.hub
            .publish([session.user_id.as_str()], &events::confirmations_changed());
    }
    Ok(StatusCode::NO_CONTENT)
}
