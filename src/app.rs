//! Application state, router and middleware stack.
//!
//! Outer to inner: request ID, access log, security headers and problem
//! finaliser → CORS → panic catcher → gate (client IP, `X-Keeman-Client`,
//! authentication) → routing → timeout of the route group → handler.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use ipnet::IpNet;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use webauthn_rs::Webauthn;

use crate::api;
use crate::audit::Audit;
use crate::auth::middleware::{client_id, gate};
use crate::auth::password::Passwords;
use crate::auth::webauthn::relying_party;
use crate::auth::{PUBLIC_PATHS, REAUTH_HEADER};
use crate::clock::SharedClock;
use crate::config::Config;
use crate::crypto::{DerivedKeys, ServerSecret};
use crate::db::Db;
use crate::error::{ApiError, ApiResult, ErrorCode, ProblemData, StoredProblem};
use crate::events::Hub;
use crate::events::socket::{self, Timings};
use crate::favicon::Favicons;
use crate::inflight::LargeBodies;
use crate::ratelimit::{Bucket, Quota, RateLimiter};
use crate::storage::attachments::Storage;

pub struct App {
    pub config: Config,
    pub db: Db,
    /// The security log with its caps.
    pub audit: Audit,
    pub clock: SharedClock,
    pub keys: DerivedKeys,
    pub passwords: Passwords,
    pub limiter: RateLimiter,
    /// Budget and per-account cap for large request bodies.
    pub large_bodies: LargeBodies,
    pub trusted_proxies: Vec<IpNet>,
    pub client_ip_header: HeaderName,
    pub hub: Hub,
    pub event_timings: Timings,
    pub storage: Storage,
    pub webauthn: Webauthn,
    /// `None` while `features.favicon` is off.
    pub favicon: Option<Favicons>,
}

impl App {
    pub fn new(
        config: Config,
        secret: &ServerSecret,
        db: Db,
        clock: SharedClock,
    ) -> Result<Arc<App>, String> {
        Self::with_timings(config, secret, db, clock, Timings::default())
    }

    /// Like [`App::new`] with other WebSocket timings (tests).
    pub fn with_timings(
        config: Config,
        secret: &ServerSecret,
        db: Db,
        clock: SharedClock,
        event_timings: Timings,
    ) -> Result<Arc<App>, String> {
        let favicon = match config.features.favicon {
            true => Some(Favicons::new()?),
            false => None,
        };
        Self::with_parts(config, secret, db, clock, event_timings, favicon)
    }

    /// Like [`App::with_timings`] with another favicon proxy (tests).
    pub fn with_parts(
        config: Config,
        secret: &ServerSecret,
        db: Db,
        clock: SharedClock,
        event_timings: Timings,
        favicon: Option<Favicons>,
    ) -> Result<Arc<App>, String> {
        let trusted_proxies = config.trusted_proxies().map_err(|e| e.0)?;
        let client_ip_header = HeaderName::from_bytes(config.server.client_ip_header.as_bytes())
            .map_err(|e| e.to_string())?;
        let storage = Storage::new(&config.storage.data_dir);
        storage
            .create_dirs()
            .map_err(|e| format!("cannot create attachment directories: {e}"))?;
        let webauthn = relying_party(&config.webauthn)?;
        Ok(Arc::new(App {
            audit: Audit::new(&config.logging),
            keys: DerivedKeys::derive(secret),
            passwords: Passwords::new()?,
            limiter: RateLimiter::new(clock.clone()),
            large_bodies: LargeBodies::new(
                config.limits.large_body_budget_bytes,
                config.limits.large_requests_per_account,
            ),
            config,
            db,
            clock,
            trusted_proxies,
            client_ip_header,
            hub: Hub::default(),
            event_timings,
            storage,
            webauthn,
            favicon,
        }))
    }

    pub fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// Takes a token from a rate-limit bucket or fails with `429`.
    pub fn limit(&self, bucket: Bucket, key: &str, quota: Quota) -> ApiResult<()> {
        self.limit_all(&[(bucket, key, quota)])
    }

    /// Takes a token from every bucket, or from none if one is empty.
    pub fn limit_all(&self, buckets: &[(Bucket, &str, Quota)]) -> ApiResult<()> {
        self.limiter
            .check_all(buckets)
            .map_err(|seconds| ApiError::new(ErrorCode::RateLimited).retry_after(seconds))
    }
}

/// Marks an error response whose body is not a problem (`503` of `health`).
#[derive(Debug, Clone, Copy)]
pub struct KeepBody;

/// Request timeout.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout of `batch`, attachment parts and rotation uploads.
pub const LONG_TIMEOUT: Duration = Duration::from_secs(120);

pub fn router(app: Arc<App>) -> Router {
    let standard = Router::new()
        .route("/v1/config", get(api::meta::config))
        .route("/v1/time", get(api::meta::time))
        .route("/v1/health", get(api::meta::health))
        .route("/v1/auth/prelogin", post(api::auth::prelogin))
        .route("/v1/auth/register", post(api::auth::register))
        .route("/v1/auth/login", post(api::auth::login))
        .route("/v1/auth/2fa/totp", post(api::second_factor::totp))
        .route(
            "/v1/auth/2fa/backup-code",
            post(api::second_factor::backup_code),
        )
        .route(
            "/v1/auth/2fa/webauthn/options",
            post(api::second_factor::webauthn_options),
        )
        .route(
            "/v1/auth/2fa/webauthn/verify",
            post(api::second_factor::webauthn_verify),
        )
        .route("/v1/auth/refresh", post(api::auth::refresh))
        .route("/v1/auth/logout", post(api::auth::logout))
        .route("/v1/auth/recover/start", post(api::recovery::start))
        .route("/v1/auth/recover/finish", post(api::recovery::finish))
        .route("/v1/me", get(api::me::get).delete(api::me::delete))
        .route("/v1/me/reauth", post(api::me::reauth))
        .route("/v1/me/user-data", put(api::me::put_user_data))
        .route("/v1/me/password", put(api::me::put_password))
        .route("/v1/me/recovery", put(api::me::put_recovery))
        .route("/v1/me/totp/setup", post(api::two_factor::totp_setup))
        .route("/v1/me/totp/enable", post(api::two_factor::totp_enable))
        .route("/v1/me/totp", delete(api::two_factor::totp_disable))
        .route(
            "/v1/me/backup-codes",
            post(api::two_factor::regenerate_backup_codes),
        )
        .route(
            "/v1/me/webauthn/register/options",
            post(api::passkeys::register_options),
        )
        .route(
            "/v1/me/webauthn/register/verify",
            post(api::passkeys::register_verify),
        )
        .route("/v1/me/webauthn", get(api::passkeys::list))
        .route(
            "/v1/me/webauthn/{credential_id}",
            delete(api::passkeys::delete),
        )
        .route(
            "/v1/me/sessions",
            get(api::sessions::list).delete(api::sessions::revoke_others),
        )
        .route(
            "/v1/me/sessions/{session_id}",
            delete(api::sessions::revoke),
        )
        .route("/v1/users/lookup", post(api::users::lookup))
        .route("/v1/favicon", post(api::favicon::fetch))
        .route(
            "/v1/users/{user_id}/public-key",
            get(api::users::public_key),
        )
        .route(
            "/v1/vaults",
            get(api::vaults::list).post(api::vaults::create),
        )
        .route("/v1/vaults/{vault_id}", delete(api::vaults::delete))
        .route("/v1/vaults/{vault_id}/changes", get(api::objects::changes))
        .route(
            "/v1/vaults/{vault_id}/members",
            get(api::members::list).post(api::members::invite),
        )
        .route(
            "/v1/vaults/{vault_id}/members/me",
            delete(api::members::leave),
        )
        .route(
            "/v1/vaults/{vault_id}/members/{user_id}",
            patch(api::members::update).delete(api::members::withdraw),
        )
        .route("/v1/vaults/{vault_id}/accept", post(api::members::accept))
        .route("/v1/vaults/{vault_id}/decline", post(api::members::decline))
        .route("/v1/vaults/{vault_id}/key", post(api::members::accept_key))
        .route(
            "/v1/vaults/{vault_id}/rotations",
            post(api::rotations::open),
        )
        .route(
            "/v1/vaults/{vault_id}/attachments",
            post(api::attachments::create),
        )
        .route(
            "/v1/vaults/{vault_id}/attachments/{attachment_id}",
            get(api::attachments::download).delete(api::attachments::delete),
        )
        .route(
            "/v1/vaults/{vault_id}/attachments/{attachment_id}/complete",
            post(api::attachments::complete),
        )
        .route(
            "/v1/vaults/{vault_id}/attachments/{attachment_id}/transfer",
            post(api::attachments::transfer),
        )
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            TIMEOUT,
        ));
    let long = Router::new()
        .route("/v1/vaults/{vault_id}/batch", post(api::objects::batch))
        .route(
            "/v1/vaults/{vault_id}/rotations/{rotation_id}/objects",
            put(api::rotations::upload),
        )
        .route(
            "/v1/vaults/{vault_id}/rotations/{rotation_id}/commit",
            post(api::rotations::commit),
        )
        .route(
            "/v1/vaults/{vault_id}/attachments/{attachment_id}/parts/{part}",
            put(api::attachments::put_part),
        )
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            LONG_TIMEOUT,
        ));
    // The upgrade answers at once; an open connection has no request timeout.
    let events = Router::new().route("/v1/events", get(socket::connect));
    let routes = standard
        .merge(long)
        .merge(events)
        .fallback(|| async { ApiError::new(ErrorCode::NotFound) })
        .method_not_allowed_fallback(|| async { ApiError::new(ErrorCode::MethodNotAllowed) })
        .with_state(app.clone());
    debug_assert!(PUBLIC_PATHS.iter().all(|p| p.starts_with("/v1/")));
    routes
        .layer(middleware::from_fn_with_state(app.clone(), gate))
        .layer(CatchPanicLayer::custom(panic_response))
        .layer(cors(&app.config))
        .layer(middleware::from_fn(outer))
}

fn cors(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .server
        .allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static("x-keeman-client"),
            HeaderName::from_static(REAUTH_HEADER),
        ])
        .expose_headers([
            header::RETRY_AFTER,
            header::CONTENT_RANGE,
            header::CONTENT_LENGTH,
        ])
        .max_age(Duration::from_secs(600))
}

fn panic_response(_payload: Box<dyn Any + Send + 'static>) -> Response {
    // The payload is not logged: it could contain request data.
    tracing::error!("request handler panicked");
    ApiError::new(ErrorCode::InternalError).into_response()
}

async fn outer(request: Request, next: Next) -> Response {
    let started = Instant::now();
    let request_id = uuid::Uuid::now_v7();
    let method = request.method().clone();
    let pattern = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_string();
    let client = client_id(request.headers()).unwrap_or("-").to_string();
    let mut response = if request.uri().path().starts_with("/v1/") {
        next.run(request).await
    } else {
        ApiError::new(ErrorCode::NotFound).into_response()
    };
    finalise(&mut response, request_id);
    let headers = response.headers_mut();
    // tower-http adds some CORS headers to every response; without an allowed
    // origin there must be none.
    if !headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN) {
        let cors: Vec<HeaderName> = headers
            .keys()
            .filter(|name| name.as_str().starts_with("access-control-"))
            .cloned()
            .collect();
        for name in cors {
            headers.remove(name);
        }
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %pattern,
        status = response.status().as_u16(),
        duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        client = %client,
        "request"
    );
    response
}

/// Renders every error response as `application/problem+json`,
/// including the bodyless ones from routing, timeouts and limits.
fn finalise(response: &mut Response, request_id: uuid::Uuid) {
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error())
        || response.extensions().get::<KeepBody>().is_some()
    {
        return;
    }
    let mut body = if let Some(stored) = response.extensions().get::<StoredProblem>() {
        stored.0.clone()
    } else {
        response
            .extensions()
            .get::<ProblemData>()
            .cloned()
            .unwrap_or_else(|| ProblemData {
                code: ErrorCode::for_status(status),
                ..ProblemData::default()
            })
            .body(status)
    };
    body.insert("instance".into(), json!(format!("urn:uuid:{request_id}")));
    *response.body_mut() = Body::from(Value::Object(body).to_string());
    let headers = response.headers_mut();
    headers.remove(header::CONTENT_LENGTH);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
}
