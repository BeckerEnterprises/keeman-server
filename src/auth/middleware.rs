//! The request gate: client IP, `X-Keeman-Client`, and
//! authentication by default for everything outside [`PUBLIC_PATHS`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use time::Duration;

use super::{AuthSession, ClientIp, PUBLIC_PATHS};
use crate::app::App;
use crate::client_ip;
use crate::clock::{format_timestamp, parse_timestamp};
use crate::crypto::hash_token;
use crate::db;
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::ratelimit::{Bucket, Quota};
use crate::types::ClientType;

pub const CLIENT_HEADER: &str = "x-keeman-client";

/// `<name>/<version>`: `^[a-z][a-z0-9-]{0,31}/[0-9A-Za-z.+-]{1,32}$`.
pub fn valid_client_id(value: &str) -> bool {
    let Some((name, version)) = value.split_once('/') else {
        return false;
    };
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && (1..=32).contains(&version.len())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
}

/// The single valid `X-Keeman-Client` value, if any.
pub fn client_id(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(CLIENT_HEADER).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().filter(|v| valid_client_id(v)),
        _ => None,
    }
}

pub async fn gate(State(app): State<Arc<App>>, mut request: Request, next: Next) -> Response {
    match prepare(&app, &mut request).await {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}

async fn prepare(app: &App, request: &mut Request) -> ApiResult<()> {
    let ip = resolve_ip(app, request);
    request.extensions_mut().insert(ClientIp(ip));

    let path = request.uri().path().to_string();
    // HEAD is GET without a body, a common monitoring probe.
    let exempt = matches!(*request.method(), Method::GET | Method::HEAD)
        && matches!(path.as_str(), "/v1/health" | "/v1/events");
    if !exempt && client_id(request.headers()).is_none() {
        return Err(ApiError::parameter(
            "X-Keeman-Client",
            "missing or invalid client identifier",
        ));
    }
    if PUBLIC_PATHS.contains(&path.as_str()) {
        return Ok(());
    }
    let session = authenticate(app, request.headers(), ClientIp(ip)).await?;
    // Endpoints with their own limit do not count against the session limit.
    if !matches!(
        path.as_str(),
        "/v1/me/reauth" | "/v1/users/lookup" | "/v1/favicon"
    ) {
        let quota = Quota::per_minute(app.config.rate_limits.session_per_min);
        app.limiter
            .check(Bucket::Session, &session.session_id, quota)
            .map_err(|seconds| ApiError::new(ErrorCode::RateLimited).retry_after(seconds))?;
    }
    request.extensions_mut().insert(session);
    Ok(())
}

fn resolve_ip(app: &App, request: &Request) -> IpAddr {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |info| info.0.ip());
    let forwarded: Option<Vec<&str>> = request
        .headers()
        .get_all(&app.client_ip_header)
        .iter()
        .map(|v| v.to_str().ok())
        .collect();
    // An unreadable header counts like an unreadable entry: the peer is the client.
    forwarded.map_or(peer, |values| {
        client_ip::resolve(peer, &values, &app.trusted_proxies)
    })
}

/// Exactly one `Authorization: Bearer <43 characters>` with a valid access
/// token; everything else is `401 session_invalid`.
async fn authenticate(app: &App, headers: &HeaderMap, ip: ClientIp) -> ApiResult<AuthSession> {
    let invalid = || ApiError::new(ErrorCode::SessionInvalid);
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(invalid());
    };
    let (scheme, token) = value
        .to_str()
        .ok()
        .and_then(|v| v.split_once(' '))
        .ok_or_else(invalid)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(invalid());
    }
    let (session, last_seen) = access_session(app, token).await?;
    // `last_seen` changes at most once per minute.
    let now = app.now();
    if parse_timestamp(&last_seen).is_none_or(|seen| now - seen >= Duration::minutes(1)) {
        let mut tx = app.db.begin().await?;
        db::sessions::touch(
            &mut *tx,
            &session.session_id,
            &format_timestamp(now),
            Some(&ip.hint()),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(session)
}

/// The session of a valid access token and its `last_seen`; also used for
/// the `auth` message of the WebSocket.
pub async fn access_session(app: &App, token: &str) -> ApiResult<(AuthSession, String)> {
    let invalid = || ApiError::new(ErrorCode::SessionInvalid);
    let hash = hash_token(token).ok_or_else(invalid)?;
    let row = db::sessions::access_lookup(&app.db.read, &hash, &format_timestamp(app.now()))
        .await?
        .ok_or_else(invalid)?;
    let client_type = ClientType::parse(&row.client_type)
        .ok_or_else(|| ApiError::internal("unknown client type"))?;
    Ok((
        AuthSession {
            session_id: row.session_id,
            user_id: row.user_id,
            client_type,
        },
        row.last_seen_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::valid_client_id;

    #[test]
    fn client_ids() {
        for ok in [
            "web/0.1.0",
            "cli/1.0.0-rc.1+build",
            "a/1",
            "keeman-desktop/2",
        ] {
            assert!(valid_client_id(ok), "{ok}");
        }
        for bad in [
            "",
            "web",
            "Web/1",
            "1web/1",
            "web/",
            "web/1 2",
            "web/1/2",
            "w_b/1",
            &format!("w/{}", "1".repeat(33)),
        ] {
            assert!(!valid_client_id(bad), "{bad}");
        }
    }
}
