//! Limits against resource exhaustion by authenticated users: the rate
//! limit per account across sessions, and the cap on large requests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{Req, TestApp};

#[tokio::test]
async fn the_account_limit_spans_all_sessions() {
    let t = TestApp::with_config("[rate_limits]\naccount_per_min = 3").await;
    let alice = t.register("alice@example.com").await;
    let sessions = [alice.clone(), t.login(&alice).await, t.login(&alice).await];
    for session in &sessions {
        let response = t
            .call(Req::get("/v1/me").token(&session.access_token))
            .await;
        assert_eq!(response.status, StatusCode::OK);
    }
    // A fresh session does not raise the limit.
    let fourth = t.login(&alice).await;
    let response = t.call(Req::get("/v1/me").token(&fourth.access_token)).await;
    assert_eq!(response.code(), "rate_limited");
    assert!(response.header("retry-after").is_some());
    // Endpoints with their own limit do not count against it.
    let response = t
        .call(
            Req::post("/v1/users/lookup")
                .token(&fourth.access_token)
                .json(&json!({ "email": "alice@example.com" })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    // Other accounts are not affected.
    let bob = t.register("bob@example.com").await;
    let response = t.call(Req::get("/v1/me").token(&bob.access_token)).await;
    assert_eq!(response.status, StatusCode::OK);
}
