//! Authentication: access tokens, sessions, reauth and the lockout.

pub mod backup_codes;
pub mod cookie;
pub mod middleware;
pub mod origin;
pub mod password;
pub mod second_factor;
pub mod session;
pub mod throttle;
pub mod webauthn;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::app::App;
use crate::client_ip;
use crate::clock::format_timestamp;
use crate::crypto::hash_token;
use crate::db;
use crate::error::{ApiError, ErrorCode};
use crate::types::ClientType;

pub const REAUTH_HEADER: &str = "x-keeman-reauth";

/// Paths that need no access token: exactly the public operations of the
/// API (`tests/fixtures/operations.json`). Everything else under `/v1/`,
/// including unknown paths, answers `401` without a valid token.
pub const PUBLIC_PATHS: &[&str] = &[
    "/v1/config",
    "/v1/time",
    "/v1/health",
    "/v1/events",
    "/v1/auth/prelogin",
    "/v1/auth/register",
    "/v1/auth/login",
    "/v1/auth/refresh",
    "/v1/auth/2fa/totp",
    "/v1/auth/2fa/backup-code",
    "/v1/auth/2fa/webauthn/options",
    "/v1/auth/2fa/webauthn/verify",
    "/v1/auth/recover/start",
    "/v1/auth/recover/finish",
];

/// The authenticated session of a request, set by the middleware.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub session_id: String,
    pub user_id: String,
    pub client_type: ClientType,
}

impl<S: Send + Sync> FromRequestParts<S> for AuthSession {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        parts
            .extensions
            .get::<AuthSession>()
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::SessionInvalid))
    }
}

/// The client IP after the trusted-proxy rules. Only its truncated
/// hint is stored, only its limit key used for rate limits.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    pub fn hint(self) -> String {
        client_ip::ip_hint(self.0)
    }

    pub fn limit_key(self) -> String {
        client_ip::limit_key(self.0)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        Ok(parts
            .extensions
            .get::<ClientIp>()
            .copied()
            .unwrap_or(ClientIp(IpAddr::V4(Ipv4Addr::UNSPECIFIED))))
    }
}

/// A valid `X-Keeman-Reauth` token of the current session;
/// checked before the body is read.
pub struct Reauthed;

impl FromRequestParts<Arc<App>> for Reauthed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, ApiError> {
        let session = AuthSession::from_request_parts(parts, app).await?;
        let mut values = parts.headers.get_all(REAUTH_HEADER).iter();
        let hash = match (values.next(), values.next()) {
            (Some(value), None) => value.to_str().ok().and_then(hash_token),
            _ => None,
        };
        let Some(hash) = hash else {
            return Err(ApiError::new(ErrorCode::ReauthRequired));
        };
        let now = format_timestamp(app.now());
        if db::challenges::reauth_valid(&app.db.read, &hash, &session.session_id, &now).await? {
            Ok(Reauthed)
        } else {
            Err(ApiError::new(ErrorCode::ReauthRequired))
        }
    }
}

/// Rejects any query string on endpoints without query parameters.
pub struct NoQuery;

impl<S: Send + Sync> FromRequestParts<S> for NoQuery {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        crate::extract::parse_query(parts.uri.query(), &[])?;
        Ok(NoQuery)
    }
}
