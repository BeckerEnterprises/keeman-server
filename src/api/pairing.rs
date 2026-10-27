//! Pairing of two devices of an account: one envelope per account, which the
//! server can neither read nor forge, valid for a few minutes.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;

use crate::app::App;
use crate::auth::{AuthSession, NoQuery};
use crate::clock::format_timestamp;
use crate::db;
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::json;
use crate::ratelimit::{Bucket, Quota};
use crate::types::{PairingEnvelope, encode_base64url};

/// Lifetime of a pairing.
pub const PAIRING_TTL: Duration = Duration::minutes(10);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingBody {
    payload: PairingEnvelope,
}

/// `PUT /v1/me/pairing`: replaces the account's pairing. Rate-limited per
/// account before the body is read.
pub async fn put(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    request: Request,
) -> ApiResult<Json<Value>> {
    app.limit(
        Bucket::Pairing,
        &session.user_id,
        Quota::per_hour(app.config.rate_limits.pairings_per_account_per_hour),
    )?;
    let body: PairingBody = json(request).await?;
    let now = app.now();
    let expires_at = format_timestamp(now + PAIRING_TTL);
    let mut tx = app.db.begin().await?;
    db::pairings::put(
        &mut tx,
        &session.user_id,
        &body.payload.0,
        &format_timestamp(now),
        &expires_at,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "expires_at": expires_at })))
}

/// `GET /v1/me/pairing`: `404` when there is none or it has expired.
pub async fn get(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
) -> ApiResult<Json<Value>> {
    let now = format_timestamp(app.now());
    let pairing = db::pairings::get(&app.db.read, &session.user_id, &now)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    Ok(Json(json!({
        "payload": encode_base64url(&pairing.payload),
        "expires_at": pairing.expires_at,
    })))
}

/// `DELETE /v1/me/pairing`: `204`, also without a pairing.
pub async fn delete(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
) -> ApiResult<StatusCode> {
    let mut tx = app.db.begin().await?;
    db::pairings::delete(&mut tx, &session.user_id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
