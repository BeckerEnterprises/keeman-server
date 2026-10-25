//! Creating sessions and issuing tokens.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use time::{Duration, OffsetDateTime};

use crate::app::App;
use crate::auth::cookie;
use crate::clock::format_timestamp;
use crate::crypto::new_token;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult};
use crate::types::{ClientType, Device};

pub struct Issued {
    pub session_id: String,
    pub access_token: String,
    pub refresh_token: String,
}

impl App {
    pub fn access_ttl(&self) -> Duration {
        Duration::minutes(i64::from(self.config.security.access_token_ttl_minutes))
    }

    pub fn refresh_ttl(&self) -> Duration {
        Duration::days(i64::from(self.config.security.refresh_token_ttl_days))
    }

    pub fn cookie_name(&self) -> &'static str {
        cookie::name(self.config.security.dev_mode)
    }

    pub fn refresh_cookie(&self, token: &str) -> String {
        let max_age = u64::try_from(self.refresh_ttl().whole_seconds()).unwrap_or(0);
        cookie::set(self.cookie_name(), token, max_age)
    }

    pub fn clear_cookie(&self) -> String {
        cookie::clear(self.cookie_name())
    }
}

/// Inserts a new access token for the session and returns its text.
pub async fn issue_access(
    conn: &mut Conn,
    app: &App,
    session_id: &str,
    now: OffsetDateTime,
) -> ApiResult<String> {
    let token = new_token().map_err(ApiError::internal)?;
    db::sessions::insert_access(
        conn,
        &token.hash,
        session_id,
        &format_timestamp(now + app.access_ttl()),
    )
    .await?;
    Ok(token.text)
}

/// Inserts a new current refresh token for the session and returns its text.
pub async fn issue_refresh(
    conn: &mut Conn,
    session_id: &str,
    now: OffsetDateTime,
) -> ApiResult<String> {
    let token = new_token().map_err(ApiError::internal)?;
    db::sessions::insert_refresh(conn, &token.hash, session_id, &format_timestamp(now)).await?;
    Ok(token.text)
}

pub async fn create(
    conn: &mut Conn,
    app: &App,
    user_id: &str,
    device: &Device,
    ip_hint: &str,
    now: OffsetDateTime,
) -> ApiResult<Issued> {
    let session_id = uuid::Uuid::now_v7().to_string();
    let now_text = format_timestamp(now);
    let session = db::sessions::NewSession {
        id: &session_id,
        user_id,
        device_name: &device.name.0,
        client_type: device.client_type.as_str(),
        refresh_expires_at: &format_timestamp(now + app.refresh_ttl()),
        ip_hint: Some(ip_hint),
        now: &now_text,
    };
    db::sessions::insert(&mut *conn, &session).await?;
    let refresh_token = issue_refresh(conn, &session_id, now).await?;
    let access_token = issue_access(conn, app, &session_id, now).await?;
    Ok(Issued {
        session_id,
        access_token,
        refresh_token,
    })
}

#[derive(Serialize)]
struct SessionBody<'a> {
    status: &'static str,
    session_id: &'a str,
    user_id: &'a str,
    access_token: &'a str,
    access_expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_codes_remaining: Option<i64>,
}

/// The `Session` response: web clients get the refresh token as a cookie,
/// native clients in the body.
pub fn response(
    app: &App,
    status: StatusCode,
    user_id: &str,
    issued: &Issued,
    client_type: ClientType,
) -> Response {
    response_with_remaining(app, status, user_id, issued, client_type, None)
}

/// Like [`response`], with `backup_codes_remaining` after a backup code.
pub fn response_with_remaining(
    app: &App,
    status: StatusCode,
    user_id: &str,
    issued: &Issued,
    client_type: ClientType,
    backup_codes_remaining: Option<i64>,
) -> Response {
    let web = client_type == ClientType::Web;
    let body = SessionBody {
        status: "ok",
        session_id: &issued.session_id,
        user_id,
        access_token: &issued.access_token,
        access_expires_in: app.access_ttl().whole_seconds(),
        refresh_token: (!web).then_some(issued.refresh_token.as_str()),
        backup_codes_remaining,
    };
    let mut response = (status, Json(body)).into_response();
    if web {
        with_cookie(&mut response, &app.refresh_cookie(&issued.refresh_token));
    }
    response
}

pub fn with_cookie(response: &mut Response, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}
