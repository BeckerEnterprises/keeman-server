//! Pairing: one envelope per account, replaced by a new one, read until it
//! expires, deleted by the receiving device or the cleanup job, and limited
//! per account.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use keeman_server::clock::format_timestamp;
use serde_json::{Value, json};
use support::{Account, Req, TestApp, envelope};
use time::Duration;

fn put(account: &Account, payload: &Value) -> Req {
    Req::put("/v1/me/pairing")
        .token(&account.access_token)
        .json(&json!({ "payload": payload }))
}

fn get(account: &Account) -> Req {
    Req::get("/v1/me/pairing").token(&account.access_token)
}

fn delete(account: &Account) -> Req {
    Req::delete("/v1/me/pairing").token(&account.access_token)
}

#[tokio::test]
async fn a_pairing_is_stored_replaced_read_and_deleted() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    assert_eq!(t.call(get(&alice)).await.code(), "not_found");

    let first = envelope(300);
    let response = t.call(put(&alice, &json!(first))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let expires_at = format_timestamp(t.now() + Duration::minutes(10));
    assert_eq!(response.json(), json!({ "expires_at": expires_at }));
    let read = t.call(get(&alice)).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(
        read.json(),
        json!({ "payload": first, "expires_at": expires_at })
    );
    // Another account sees nothing of it.
    assert_eq!(t.call(get(&bob)).await.code(), "not_found");

    t.advance(Duration::minutes(3));
    let second = envelope(500);
    let replaced = t.call(put(&alice, &json!(second))).await;
    assert_eq!(replaced.status, StatusCode::OK);
    let read = t.call(get(&alice)).await.json();
    assert_eq!(read["payload"], json!(second));
    assert_eq!(
        read["expires_at"],
        json!(format_timestamp(t.now() + Duration::minutes(10)))
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM pairings").await, 1);

    assert_eq!(t.call(delete(&alice)).await.status, StatusCode::NO_CONTENT);
    assert_eq!(t.call(get(&alice)).await.code(), "not_found");
    assert_eq!(t.call(delete(&alice)).await.status, StatusCode::NO_CONTENT);
    assert_eq!(t.count("SELECT COUNT(*) FROM pairings").await, 0);
}

#[tokio::test]
async fn a_pairing_expires_after_ten_minutes() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    t.call(put(&alice, &json!(envelope(300)))).await;
    t.advance(Duration::minutes(5));
    t.call(put(&bob, &json!(envelope(300)))).await;
    t.advance(Duration::minutes(5) - Duration::milliseconds(1));
    assert_eq!(t.call(get(&alice)).await.status, StatusCode::OK);
    t.advance(Duration::milliseconds(1));
    assert_eq!(t.call(get(&alice)).await.code(), "not_found");
    assert_eq!(t.call(get(&bob)).await.status, StatusCode::OK);

    let removed = keeman_server::jobs::cleanup(&t.app).await.unwrap();
    assert_eq!(removed.pairings, 1);
    assert_eq!(t.count("SELECT COUNT(*) FROM pairings").await, 1);
    assert_eq!(t.call(get(&bob)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_payload_is_an_envelope_of_at_most_one_mebibyte() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    for payload in [
        json!(support::key_box(300)),
        json!(envelope(40)),
        json!(format!("{}=", envelope(300))),
        json!("not base64!"),
        json!(42),
        Value::Null,
    ] {
        let response = t.call(put(&alice, &payload)).await;
        assert_eq!(response.code(), "validation_failed", "{payload}");
        assert_eq!(response.field_error().0, "/payload", "{payload}");
    }
    let response = t
        .call(
            Req::put("/v1/me/pairing")
                .token(&alice.access_token)
                .json(&json!({ "payload": envelope(300), "note": 1 })),
        )
        .await;
    assert_eq!(response.code(), "validation_failed");
    // 1 MiB of text fits, one character more does not.
    let largest = envelope(786_432);
    assert_eq!(largest.len(), 1_048_576);
    assert_eq!(
        t.call(put(&alice, &json!(largest))).await.status,
        StatusCode::OK
    );
    let too_large = envelope(786_433);
    assert!(too_large.len() > 1_048_576);
    assert_eq!(
        t.call(put(&alice, &json!(too_large))).await.code(),
        "payload_too_large"
    );
}

#[tokio::test]
async fn storing_pairings_has_its_own_limit_per_account() {
    let t = TestApp::with_config(
        "[rate_limits]\npairings_per_account_per_hour = 3\nsession_per_min = 4\naccount_per_min = 4\n",
    )
    .await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    for _ in 0..3 {
        assert_eq!(
            t.call(put(&alice, &json!(envelope(300)))).await.status,
            StatusCode::OK
        );
    }
    let limited = t.call(put(&alice, &json!(envelope(300)))).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.header("retry-after").is_some());
    // Other accounts have their own bucket.
    assert_eq!(
        t.call(put(&bob, &json!(envelope(300)))).await.status,
        StatusCode::OK
    );
    // Storing did not count against the session limit; reading does.
    for _ in 0..4 {
        assert_eq!(t.call(get(&alice)).await.status, StatusCode::OK);
    }
    assert_eq!(
        t.call(get(&alice)).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // One token comes back every 20 minutes, also for a new session.
    t.advance(Duration::minutes(20));
    let alice = t.login(&alice).await;
    assert_eq!(
        t.call(put(&alice, &json!(envelope(300)))).await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.call(put(&alice, &json!(envelope(300)))).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}
