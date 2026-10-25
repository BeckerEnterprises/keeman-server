//! `POST /v1/users/lookup` and `GET /v1/users/{id}/public-key`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{Req, TestApp, new_uuid};

fn lookup(token: &str, email: &str) -> Req {
    Req::post("/v1/users/lookup")
        .token(token)
        .json(&json!({ "email": email }))
}

#[tokio::test]
async fn lookup_finds_accounts_by_normalized_email() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;

    let response = t
        .call(lookup(&bob.access_token, " Alice@Example.COM "))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        response.json(),
        json!({ "user_id": alice.user_id, "email": "alice@example.com", "public_key": alice.public_key })
    );
    // The own account is found as well; the client refuses to invite itself.
    let own = t.call(lookup(&bob.access_token, "bob@example.com")).await;
    assert_eq!(own.json()["user_id"], json!(bob.user_id));

    let unknown = t
        .call(lookup(&bob.access_token, "nobody@example.com"))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.code(), "user_not_found");

    let extra = t
        .call(
            Req::post("/v1/users/lookup")
                .token(&bob.access_token)
                .json(&json!({ "email": "alice@example.com", "x": 1 })),
        )
        .await;
    assert_eq!(extra.status, StatusCode::BAD_REQUEST);
    let invalid = t.call(lookup(&bob.access_token, "no-at-sign")).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    let media = t
        .call(
            Req::post("/v1/users/lookup")
                .token(&bob.access_token)
                .raw(Some("text/plain"), b"alice@example.com"),
        )
        .await;
    assert_eq!(media.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn lookup_has_its_own_limit_per_account() {
    let t = TestApp::with_config(
        "[rate_limits]\nlookup_per_account_per_hour = 3\nsession_per_min = 2\n",
    )
    .await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    for _ in 0..3 {
        let response = t.call(lookup(&alice.access_token, "bob@example.com")).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    }
    let limited = t.call(lookup(&alice.access_token, "bob@example.com")).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.code(), "rate_limited");
    assert_eq!(limited.header("retry-after").as_deref(), Some("1200"));
    // Other accounts have their own bucket.
    let other = t.call(lookup(&bob.access_token, "alice@example.com")).await;
    assert_eq!(other.status, StatusCode::OK);
    // Lookups do not count against the session limit.
    for _ in 0..2 {
        let list = t
            .call(Req::get("/v1/vaults").token(&alice.access_token))
            .await;
        assert_eq!(list.status, StatusCode::OK);
    }
}

#[tokio::test]
async fn public_key_requires_a_shared_membership() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let key = |caller: &support::Account, target: &str| {
        Req::get(&format!("/v1/users/{target}/public-key")).token(&caller.access_token)
    };

    let unshared = t.call(key(&alice, &bob.user_id)).await;
    assert_eq!(unshared.status, StatusCode::NOT_FOUND);
    assert_eq!(unshared.code(), "user_not_found");
    let unknown = t.call(key(&alice, &new_uuid())).await;
    assert_eq!(unknown.code(), "user_not_found");
    let own = t.call(key(&alice, &alice.user_id)).await;
    assert_eq!(own.json()["public_key"], json!(alice.public_key));

    // A pending invitation counts as a shared membership, in both directions.
    let vault_id = t.create_vault(&alice).await;
    t.add_member(&vault_id, &bob, "member", "pending").await;
    let response = t.call(key(&alice, &bob.user_id)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        response.json(),
        json!({ "user_id": bob.user_id, "email": "bob@example.com", "public_key": bob.public_key })
    );
    let back = t.call(key(&bob, &alice.user_id)).await;
    assert_eq!(back.json()["public_key"], json!(alice.public_key));
    assert_eq!(
        t.call(key(&carol, &alice.user_id)).await.code(),
        "user_not_found"
    );

    let invalid = t.call(key(&alice, "ALICE")).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid.field_error().0, "user_id");
}
