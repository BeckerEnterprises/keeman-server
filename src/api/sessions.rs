//! Sessions (devices) of the own account.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri};
use serde_json::{Value, json};

use crate::app::App;
use crate::audit;
use crate::auth::{AuthSession, ClientIp, NoQuery};
use crate::clock::format_timestamp;
use crate::db;
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::parse_query;
use crate::types::is_canonical_uuid;

pub async fn list(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
) -> ApiResult<Json<Value>> {
    let now_text = format_timestamp(app.now());
    let rows = db::sessions::list_active(&app.db.read, &session.user_id, &now_text).await?;
    let sessions: Vec<Value> = rows
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "device_name": s.device_name,
                "client_type": s.client_type,
                "created": s.created_at,
                "last_seen": s.last_seen_at,
                "ip_hint": s.ip_hint,
                "current": s.id == session.session_id,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": sessions })))
}

/// `DELETE /v1/me/sessions?scope=others`; without a valid `scope` → `400`,
/// never "revoke all".
pub async fn revoke_others(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    uri: Uri,
) -> ApiResult<StatusCode> {
    let query = parse_query(uri.query(), &["scope"])?;
    match query.get("scope").map(String::as_str) {
        Some("others") => {}
        Some(_) => return Err(ApiError::parameter("scope", "invalid value")),
        None => return Err(ApiError::parameter("scope", "missing parameter")),
    }
    let now_text = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    let revoked =
        db::sessions::revoke_others(&mut tx, &session.user_id, &session.session_id, &now_text)
            .await?;
    audit::sessions_revoked(
        &mut tx,
        &now_text,
        &session.user_id,
        Some(&ip.hint()),
        &revoked,
        "others",
    )
    .await?;
    tx.commit().await?;
    app.hub.revoke_sessions(&revoked);
    Ok(StatusCode::NO_CONTENT)
}

/// Revoking the own session works like logout, but keeps the cookie.
pub async fn revoke(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    Path(session_id): Path<String>,
    _: NoQuery,
) -> ApiResult<StatusCode> {
    if !is_canonical_uuid(&session_id) {
        return Err(ApiError::parameter("session_id", "not a canonical UUID"));
    }
    let now_text = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    if !db::sessions::is_active_of(&mut *tx, &session.user_id, &session_id, &now_text).await? {
        return Err(ApiError::new(ErrorCode::NotFound));
    }
    db::sessions::revoke(&mut tx, &session_id, &now_text).await?;
    audit::sessions_revoked(
        &mut tx,
        &now_text,
        &session.user_id,
        Some(&ip.hint()),
        std::slice::from_ref(&session_id),
        "user",
    )
    .await?;
    tx.commit().await?;
    app.hub.revoke_sessions(std::slice::from_ref(&session_id));
    Ok(StatusCode::NO_CONTENT)
}
