//! Limits against resource exhaustion by authenticated users: the rate
//! limit per account across sessions, and the cap on large requests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::Duration as StdDuration;

use axum::http::StatusCode;
use serde_json::json;
use support::{Account, Req, TestApp, new_uuid, put_op};

fn batch(account: &Account, vault: &str) -> Req {
    Req::post(&format!("/v1/vaults/{vault}/batch"))
        .token(&account.access_token)
        .idem(&new_uuid())
        .json(&json!({ "ops": [put_op(&new_uuid(), "entry", None)] }))
}

/// A batch whose body has not arrived yet; dropping the sender ends it.
fn stalled(
    account: &Account,
    vault: &str,
    length: usize,
) -> (
    axum::http::Request<axum::body::Body>,
    tokio::sync::mpsc::Sender<axum::body::Bytes>,
) {
    batch(account, vault)
        .header("content-length", &length.to_string())
        .build_streaming()
}

async fn eventually(what: &str, condition: impl Fn() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(StdDuration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

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

#[tokio::test]
async fn large_requests_are_capped_per_account() {
    let t = TestApp::with_config("[limits]\nlarge_requests_per_account = 1").await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault = t.create_vault(&alice).await;
    let bobs = t.create_vault(&bob).await;
    let (request, body) = stalled(&alice, &vault, 1000);
    let first = t.spawn(request);
    eventually("the first request", || {
        t.app.large_bodies.in_flight(&alice.user_id) == 1
    })
    .await;

    let response = t.call(batch(&alice, &vault)).await;
    assert_eq!(response.code(), "rate_limited");
    assert_eq!(response.header("retry-after").as_deref(), Some("1"));
    // Other accounts are not affected.
    assert_eq!(t.call(batch(&bob, &bobs)).await.status, StatusCode::OK);

    // The slot is free again once the request ends, also without a body.
    drop(body);
    assert_eq!(first.await.unwrap().status, StatusCode::BAD_REQUEST);
    assert_eq!(t.app.large_bodies.in_flight(&alice.user_id), 0);
    assert_eq!(t.call(batch(&alice, &vault)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn bodies_wait_for_room_in_the_shared_budget() {
    let t = TestApp::with_config("[limits]\nlarge_body_budget_bytes = 16777216").await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let dave = t.register("dave@example.com").await;
    let vault = t.create_vault(&alice).await;
    let bobs = t.create_vault(&bob).await;
    // Alice announces 16 MiB and takes the whole budget.
    let (request, body) = stalled(&alice, &vault, 16 * 1024 * 1024);
    let first = t.spawn(request);
    eventually("the budget to be taken", || {
        t.app.large_bodies.available_kib() == 0
    })
    .await;

    // Outsiders are refused at once: the pre-check comes before the budget.
    let response = t.call(batch(&dave, &vault)).await;
    assert_eq!(response.code(), "not_found");

    // Bob waits without being refused ...
    let second = t.spawn(batch(&bob, &bobs).build());
    tokio::time::sleep(StdDuration::from_millis(200)).await;
    assert!(!second.is_finished());
    // ... and goes ahead once Alice's request ends.
    drop(body);
    assert_eq!(first.await.unwrap().status, StatusCode::BAD_REQUEST);
    let response = second.await.unwrap();
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(t.app.large_bodies.available_kib(), 16 * 1024);
}
