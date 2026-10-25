//! `GET /v1/events`: origin and rate limit before the upgrade, the
//! `auth` message within 5 seconds, then events until the session ends.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use tokio::time::{Instant, interval_at, timeout_at};

use super::hub::{CloseReason, Registration};
use crate::app::App;
use crate::auth::middleware::access_session;
use crate::auth::origin::{self, Origin};
use crate::auth::{AuthSession, ClientIp, NoQuery};
use crate::clock::format_timestamp;
use crate::db;
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::ratelimit::{Bucket, Quota};

/// Largest text message a client may send.
pub const MAX_TEXT: usize = 4096;
/// Frames above this size end the connection inside tungstenite already.
const MAX_FRAME: usize = 64 * 1024;

/// Timings of the WebSocket protocol; shorter in tests.
#[derive(Debug, Clone, Copy)]
pub struct Timings {
    pub auth_timeout: Duration,
    pub ping_interval: Duration,
    pub revalidate_interval: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            auth_timeout: Duration::from_secs(5),
            ping_interval: Duration::from_secs(30),
            revalidate_interval: Duration::from_secs(30),
        }
    }
}

pub mod close {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    pub const UNSUPPORTED: u16 = 1003;
    pub const TOO_BIG: u16 = 1009;
    pub const INTERNAL: u16 = 1011;
    pub const TRY_AGAIN: u16 = 1013;
    pub const UNAUTHORIZED: u16 = 4401;
    pub const AUTH_TIMEOUT: u16 = 4408;
    pub const TOO_MANY: u16 = 4429;
}

pub async fn connect(
    State(app): State<Arc<App>>,
    ip: ClientIp,
    _: NoQuery,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> ApiResult<Response> {
    if origin::check(&headers, &app.config.server.allowed_origins) == Origin::Forbidden {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    app.limit(
        Bucket::Events,
        &ip.limit_key(),
        Quota::per_minute(app.config.rate_limits.events_per_ip_per_min),
    )?;
    let upgrade =
        upgrade.map_err(|_| ApiError::parameter("Upgrade", "not a WebSocket upgrade request"))?;
    Ok(upgrade
        .max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| run(app, socket)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthMessage {
    #[serde(rename = "type")]
    kind: String,
    access_token: String,
}

/// How a connection ends.
enum End {
    /// Send a close frame with this code.
    Close(u16),
    /// `session_revoked`, then `4401`.
    Revoked,
    /// The peer is gone; nothing to send.
    Gone,
}

async fn run(app: Arc<App>, mut socket: WebSocket) {
    let end = match authenticate(&app, &mut socket).await {
        Ok(session) => attach(&app, &mut socket, &session).await,
        Err(end) => end,
    };
    match end {
        End::Close(code) => send_close(&mut socket, code).await,
        End::Revoked => {
            let revoked = Message::Text(Utf8Bytes::from_static(r#"{"type":"session_revoked"}"#));
            if socket.send(revoked).await.is_ok() {
                send_close(&mut socket, close::UNAUTHORIZED).await;
            }
        }
        End::Gone => {}
    }
}

async fn send_close(socket: &mut WebSocket, code: u16) {
    let frame = CloseFrame {
        code,
        reason: Utf8Bytes::default(),
    };
    // The peer may already be gone; there is nothing left to do then.
    let _ = socket.send(Message::Close(Some(frame))).await;
}

/// The first message must be `auth` with a valid access token.
async fn authenticate(app: &App, socket: &mut WebSocket) -> Result<AuthSession, End> {
    let deadline = Instant::now() + app.event_timings.auth_timeout;
    loop {
        let message = match timeout_at(deadline, socket.recv()).await {
            Err(_) => return Err(End::Close(close::AUTH_TIMEOUT)),
            Ok(None | Some(Err(_))) => return Err(End::Gone),
            Ok(Some(Ok(message))) => message,
        };
        match message {
            Message::Text(text) if text.len() > MAX_TEXT => {
                return Err(End::Close(close::TOO_BIG));
            }
            Message::Text(text) => {
                let auth: AuthMessage = serde_json::from_str(text.as_str())
                    .map_err(|_| End::Close(close::UNAUTHORIZED))?;
                if auth.kind != "auth" {
                    return Err(End::Close(close::UNAUTHORIZED));
                }
                return match access_session(app, &auth.access_token).await {
                    Ok((session, _)) => Ok(session),
                    Err(error) if error.code() == ErrorCode::SessionInvalid => {
                        Err(End::Close(close::UNAUTHORIZED))
                    }
                    Err(_) => Err(End::Close(close::INTERNAL)),
                };
            }
            Message::Binary(_) => return Err(End::Close(close::UNSUPPORTED)),
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => return Err(End::Gone),
        }
    }
}

async fn attach(app: &App, socket: &mut WebSocket, session: &AuthSession) -> End {
    let Some(mut registration) = app.hub.register(&session.user_id, &session.session_id) else {
        return End::Close(close::TOO_MANY);
    };
    // A revocation between the token check and the registration would be missed.
    let end = match still_valid(app, &session.session_id).await {
        Ok(true) => match socket
            .send(Message::Text(Utf8Bytes::from_static(r#"{"type":"ready"}"#)))
            .await
        {
            Ok(()) => serve(app, socket, &mut registration).await,
            Err(_) => End::Gone,
        },
        Ok(false) => End::Revoked,
        Err(_) => End::Close(close::INTERNAL),
    };
    app.hub.unregister(&session.user_id, registration.id);
    end
}

async fn still_valid(app: &App, session_id: &str) -> Result<bool, sqlx::Error> {
    let ids = serde_json::json!([session_id]).to_string();
    let now = format_timestamp(app.now());
    Ok(!db::sessions::valid_ids(&app.db.read, &ids, &now)
        .await?
        .is_empty())
}

async fn serve(app: &App, socket: &mut WebSocket, registration: &mut Registration) -> End {
    let every = app.event_timings.ping_interval;
    let mut ticker = interval_at(Instant::now() + every, every);
    let close_signal = registration.close.clone();
    let mut awaiting_pong = false;
    loop {
        tokio::select! {
            reason = close_signal.wait() => {
                return match reason {
                    CloseReason::Revoked => End::Revoked,
                    CloseReason::QueueFull => End::Close(close::TRY_AGAIN),
                    CloseReason::Shutdown => End::Close(close::GOING_AWAY),
                };
            }
            message = registration.messages.recv() => {
                let Some(text) = message else {
                    return End::Close(close::INTERNAL);
                };
                if socket.send(Message::Text(text.into())).await.is_err() {
                    return End::Gone;
                }
            }
            _ = ticker.tick() => {
                // No pong since the last ping: the peer is gone.
                if awaiting_pong {
                    return End::Gone;
                }
                awaiting_pong = true;
                if socket.send(Message::Ping(Default::default())).await.is_err() {
                    return End::Gone;
                }
            }
            incoming = socket.recv() => match incoming {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return End::Gone,
                Some(Ok(Message::Pong(_))) => awaiting_pong = false,
                Some(Ok(Message::Ping(_))) => {}
                Some(Ok(Message::Text(text))) if text.len() > MAX_TEXT => {
                    return End::Close(close::TOO_BIG);
                }
                // After `ready` the client sends nothing; extra messages are ignored.
                Some(Ok(Message::Text(_))) => {}
                Some(Ok(Message::Binary(_))) => return End::Close(close::UNSUPPORTED),
            },
        }
    }
}

/// Closes connections whose session became invalid without a hook, e.g.
/// after `user disable` in the separate CLI process.
pub async fn revalidate(app: &App) -> Result<usize, sqlx::Error> {
    let sessions = app.hub.sessions();
    if sessions.is_empty() {
        return Ok(0);
    }
    let ids = serde_json::to_string(&sessions).unwrap_or_else(|_| "[]".into());
    let now = format_timestamp(app.now());
    let valid = db::sessions::valid_ids(&app.db.read, &ids, &now).await?;
    let invalid: Vec<String> = sessions
        .into_iter()
        .filter(|s| !valid.contains(s))
        .collect();
    app.hub.revoke_sessions(&invalid);
    Ok(invalid.len())
}

pub fn spawn_revalidation(app: Arc<App>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let every = app.event_timings.revalidate_interval;
        let mut ticker = interval_at(Instant::now() + every, every);
        loop {
            ticker.tick().await;
            if let Err(error) = revalidate(&app).await {
                tracing::error!(error = %error, "revalidation of event connections failed");
            }
        }
    })
}
