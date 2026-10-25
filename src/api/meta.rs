//! `config`, `time` and `health`.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::app::{App, KeepBody};
use crate::auth::NoQuery;
use crate::clock::unix_ms;

/// `batch` accepts at most this many operations.
pub const BATCH_MAX_OPS: u32 = 500;

pub async fn config(State(app): State<Arc<App>>, _: NoQuery) -> Json<Value> {
    let c = &app.config;
    Json(json!({
        "server_version": env!("CARGO_PKG_VERSION"),
        "api_version": 1,
        "registration": c.security.registration.as_str(),
        "webauthn": { "rp_id": c.webauthn.rp_id },
        "features": { "favicon": c.features.favicon },
        "limits": { "attachment_max_bytes": c.limits.attachment_max_bytes, "batch_max_ops": BATCH_MAX_OPS },
    }))
}

pub async fn time(State(app): State<Arc<App>>, _: NoQuery) -> Json<Value> {
    Json(json!({ "now_ms": unix_ms(app.now()) }))
}

pub async fn health(State(app): State<Arc<App>>, _: NoQuery) -> Response {
    if app.db.ping().await {
        Json(json!({ "status": "ok" })).into_response()
    } else {
        let mut response = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "error" })),
        )
            .into_response();
        response.extensions_mut().insert(KeepBody);
        response
    }
}
