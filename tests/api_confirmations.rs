//! Confirmation by another device: a session asks with a nonce, another
//! session of the same account answers with a signed statement; requests
//! are replaced, listed while open, read back only by the asking session,
//! deleted, expire and are limited per account.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use keeman_server::clock::format_timestamp;
use keeman_server::confirmation::{Statement, encode};
use serde_json::{Value, json};
use support::freshness::sign_in;
use support::{Account, Req, TestApp, b64, envelope, new_uuid};
use time::Duration;

const CONTEXT: &str = "keeman:v1:device-confirmation";
const TIME: &str = "2026-10-28T08:42:00.000Z";

fn create(account: &Account, nonce: &str) -> Req {
    Req::post("/v1/me/confirmations")
        .token(&account.access_token)
        .json(&json!({ "nonce": nonce }))
}

fn list(account: &Account) -> Req {
    Req::get("/v1/me/confirmations").token(&account.access_token)
}

fn get(account: &Account, id: &str) -> Req {
    Req::get(&format!("/v1/me/confirmations/{id}")).token(&account.access_token)
}

fn answer(account: &Account, id: &str, signed: &Value) -> Req {
    Req::put(&format!("/v1/me/confirmations/{id}"))
        .token(&account.access_token)
        .json(&json!({ "answer": signed }))
}

fn delete(account: &Account, id: &str) -> Req {
    Req::delete(&format!("/v1/me/confirmations/{id}")).token(&account.access_token)
}

fn statement(account: &Account, nonce: [u8; 32]) -> Statement {
    Statement {
        user_id: account.user_id.clone(),
        nonce,
        time: TIME.to_string(),
        content: br#"{"schema":1,"user_data":null,"vaults":{}}"#.to_vec(),
    }
}

fn signed(account: &Account, statement: &Statement) -> Value {
    sign_in(account, CONTEXT, &encode(statement))
}

/// Opens a request of `asking` with the nonce `[n; 32]`; returns its id.
async fn open(t: &TestApp, asking: &Account, n: u8) -> String {
    let response = t.call(create(asking, &b64([n; 32]))).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    response.json()["request_id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_request_is_answered_by_another_session_and_read_back() {
    let t = TestApp::new().await;
    let asking = t.register("alice@example.com").await;
    let other = t.login(&asking).await;
    let stranger = t.register("bob@example.com").await;

    let response = t.call(create(&asking, &b64([1; 32]))).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    let body = response.json();
    let id = body["request_id"].as_str().unwrap().to_string();
    let expires_at = format_timestamp(t.now() + Duration::minutes(5));
    assert_eq!(
        body,
        json!({ "request_id": id, "expires_at": expires_at, "expires_in": 300 })
    );

    t.advance(Duration::seconds(10));
    let listed = t.call(list(&other)).await;
    assert_eq!(listed.status, StatusCode::OK);
    let created = format_timestamp(t.now() - Duration::seconds(10));
    assert_eq!(
        listed.json(),
        json!({ "requests": [{
            "request_id": id,
            "session_id": asking.session_id,
            "device_name": "Test device",
            "client_type": "cli",
            "created": created,
            "expires_at": expires_at,
            "expires_in": 290,
            "nonce": b64([1; 32]),
            "own": false,
            "answered": false,
        }] })
    );
    assert_eq!(
        t.call(list(&asking)).await.json()["requests"][0]["own"],
        true
    );
    // Another account sees nothing of it.
    assert_eq!(
        t.call(list(&stranger)).await.json(),
        json!({ "requests": [] })
    );
    assert_eq!(
        t.call(get(&asking, &id)).await.json(),
        json!({ "request_id": id, "expires_at": expires_at, "expires_in": 290, "answer": null })
    );

    let answer_body = signed(&other, &statement(&other, [1; 32]));
    let stored = t.call(answer(&other, &id, &answer_body)).await;
    assert_eq!(stored.status, StatusCode::NO_CONTENT, "{}", stored.text());
    assert_eq!(
        t.call(get(&asking, &id)).await.json()["answer"],
        answer_body
    );
    assert_eq!(
        t.call(list(&other)).await.json()["requests"][0]["answered"],
        true
    );
    // The answer is for the asking session only.
    assert_eq!(t.call(get(&other, &id)).await.code(), "not_found");
    assert_eq!(t.call(get(&stranger, &id)).await.code(), "not_found");

    // The same bytes again are fine, other ones conflict.
    let again = t.call(answer(&other, &id, &answer_body)).await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);
    let mut later = statement(&other, [1; 32]);
    later.time = "2026-10-28T08:43:00.000Z".into();
    let third = t.login(&asking).await;
    assert_eq!(
        t.call(answer(&third, &id, &signed(&third, &later)))
            .await
            .code(),
        "conflict"
    );

    assert_eq!(
        t.call(delete(&asking, &id)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(t.call(get(&asking, &id)).await.code(), "not_found");
    assert_eq!(
        t.call(delete(&asking, &id)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM confirmations").await, 0);
}

#[tokio::test]
async fn a_new_request_replaces_the_old_one_with_its_answer() {
    let t = TestApp::new().await;
    let asking = t.register("alice@example.com").await;
    let other = t.login(&asking).await;
    let first = open(&t, &asking, 1).await;
    let response = t
        .call(answer(
            &other,
            &first,
            &signed(&other, &statement(&other, [1; 32])),
        ))
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    // Another session of the account may have its own request.
    let others = open(&t, &other, 3).await;

    let second = open(&t, &asking, 2).await;
    assert_ne!(first, second);
    assert_eq!(t.call(get(&asking, &first)).await.code(), "not_found");
    assert_eq!(
        t.call(get(&asking, &second)).await.json()["answer"],
        Value::Null
    );
    let listed = t.call(list(&asking)).await.json();
    let ids: Vec<&str> = listed["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["request_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [others.as_str(), second.as_str()]);
    assert_eq!(t.count("SELECT COUNT(*) FROM confirmations").await, 2);
    // The answer to the old request does not fit the new one.
    let stale = t
        .call(answer(
            &other,
            &second,
            &signed(&other, &statement(&other, [1; 32])),
        ))
        .await;
    assert_eq!(stale.code(), "validation_failed");
    assert_eq!(stale.field_error().0, "/answer");
}

#[tokio::test]
async fn only_a_valid_answer_of_the_own_account_for_this_nonce_is_stored() {
    let t = TestApp::new().await;
    let asking = t.register("alice@example.com").await;
    let other = t.login(&asking).await;
    let stranger = t.register("bob@example.com").await;
    let id = open(&t, &asking, 1).await;
    let good = statement(&other, [1; 32]);
    let text = String::from_utf8(encode(&good)).unwrap();

    let mut foreign = statement(&stranger, [1; 32]);
    foreign.user_id = stranger.user_id.clone();
    let cases: Vec<(&str, Value)> = vec![
        ("another nonce", signed(&other, &statement(&other, [2; 32]))),
        ("signed by another account", signed(&stranger, &good)),
        ("made by another account", signed(&stranger, &foreign)),
        // Signed with the caller's key, so only the user_id rule rejects it.
        ("naming another account", signed(&other, &foreign)),
        (
            "the freshness context",
            sign_in(&other, "keeman:v1:freshness", &encode(&good)),
        ),
        (
            "the roles context",
            sign_in(&other, "keeman:v1:roles", &encode(&good)),
        ),
        (
            "not canonical",
            sign_in(
                &other,
                CONTEXT,
                text.replace(r#"{"v":1,"#, r#"{ "v":1,"#).as_bytes(),
            ),
        ),
        (
            "an unknown field",
            sign_in(
                &other,
                CONTEXT,
                text.replace(r#""v":1,"#, r#""v":1,"x":1,"#).as_bytes(),
            ),
        ),
        (
            "empty content",
            sign_in(
                &other,
                CONTEXT,
                text.replace(&b64_of(&good.content), "").as_bytes(),
            ),
        ),
        (
            "a freshness statement",
            sign_in(
                &other,
                CONTEXT,
                &keeman_server::freshness::encode(&support::freshness::user_data(&other, 1)),
            ),
        ),
    ];
    for (name, body) in cases {
        let response = t.call(answer(&other, &id, &body)).await;
        assert_eq!(response.code(), "validation_failed", "{name}");
        assert_eq!(response.field_error().0, "/answer", "{name}");
    }
    // Structure: Base64url, signature length, unknown fields.
    for body in [
        json!({ "statement": "not base64!", "signature": b64([0; 64]) }),
        json!({ "statement": "", "signature": b64([0; 64]) }),
        json!({ "statement": b64_of(&encode(&good)), "signature": b64([0; 32]) }),
        json!({ "statement": b64_of(&encode(&good)), "signature": b64([0; 64]), "x": 1 }),
    ] {
        let response = t.call(answer(&other, &id, &body)).await;
        assert_eq!(response.code(), "validation_failed", "{body}");
    }
    assert_eq!(
        t.count("SELECT COUNT(*) FROM confirmations WHERE answer_statement IS NOT NULL")
            .await,
        0
    );
    let response = t.call(answer(&other, &id, &signed(&other, &good))).await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
}

fn b64_of(bytes: &[u8]) -> String {
    keeman_server::types::encode_base64url(bytes)
}

#[tokio::test]
async fn the_statement_may_have_one_mebibyte() {
    let t = TestApp::new().await;
    let asking = t.register("alice@example.com").await;
    let other = t.login(&asking).await;
    let id = open(&t, &asking, 1).await;
    let mut large = statement(&other, [1; 32]);
    let frame = encode(&large).len() - b64_of(&large.content).len();
    // Content whose Base64url makes the statement exactly 1 MiB.
    let content_chars = 1_048_576 - frame;
    large.content = vec![b' '; content_chars / 4 * 3];
    let size = encode(&large).len();
    assert!(size <= 1_048_576 && size > 1_048_570, "{size}");
    let response = t.call(answer(&other, &id, &signed(&other, &large))).await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );

    let second = open(&t, &asking, 2).await;
    let mut too_large = statement(&other, [2; 32]);
    too_large.content = vec![b' '; 1_048_576];
    let response = t
        .call(answer(&other, &second, &signed(&other, &too_large)))
        .await;
    assert_eq!(response.code(), "payload_too_large");
}

#[tokio::test]
async fn the_asking_session_cannot_answer_and_ended_sessions_count_as_gone() {
    let t = TestApp::new().await;
    let asking = t.register("alice@example.com").await;
    let other = t.login(&asking).await;
    let id = open(&t, &asking, 1).await;
    let own = t
        .call(answer(
            &asking,
            &id,
            &signed(&asking, &statement(&asking, [1; 32])),
        ))
        .await;
    assert_eq!(own.code(), "forbidden");
    assert_eq!(
        t.call(answer(
            &other,
            &new_uuid(),
            &signed(&other, &statement(&other, [1; 32]))
        ))
        .await
        .code(),
        "not_found"
    );
    let bad = t.call(get(&asking, "not-a-uuid")).await;
    assert_eq!(bad.field_error().0, "request_id");

    // The asking session ends: its request is gone for everyone.
    let revoked = t
        .call(
            Req::delete(&format!("/v1/me/sessions/{}", asking.session_id))
                .token(&other.access_token),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    assert_eq!(t.call(list(&other)).await.json(), json!({ "requests": [] }));
    let late = t
        .call(answer(
            &other,
            &id,
            &signed(&other, &statement(&other, [1; 32])),
        ))
        .await;
    assert_eq!(late.code(), "not_found");
    // The cleanup job removes the session and with it the request.
    keeman_server::jobs::cleanup(&t.app).await.unwrap();
    assert_eq!(t.count("SELECT COUNT(*) FROM confirmations").await, 0);
}

#[tokio::test]
async fn without_a_signing_key_nothing_is_asked_or_answered() {
    let t = TestApp::new().await;
    let asking = t.register("alice@example.com").await;
    let other = t.login(&asking).await;
    let id = open(&t, &asking, 1).await;
    t.sql(&format!(
        "UPDATE users SET signing_public_key = NULL WHERE id = '{}'",
        asking.user_id
    ))
    .await;
    assert_eq!(
        t.call(create(&asking, &b64([2; 32]))).await.code(),
        "signing_key_missing"
    );
    let response = t
        .call(answer(
            &other,
            &id,
            &signed(&other, &statement(&other, [1; 32])),
        ))
        .await;
    assert_eq!(response.code(), "signing_key_missing");
}

#[tokio::test]
async fn the_nonce_has_exactly_32_bytes() {
    let t = TestApp::new().await;
    let asking = t.register("alice@example.com").await;
    for nonce in [
        json!(b64([1; 31])),
        json!(b64([1; 33])),
        json!(format!("{}=", b64([1; 32]))),
        json!(42),
        Value::Null,
    ] {
        let response = t
            .call(
                Req::post("/v1/me/confirmations")
                    .token(&asking.access_token)
                    .json(&json!({ "nonce": nonce })),
            )
            .await;
        assert_eq!(response.code(), "validation_failed", "{nonce}");
        assert_eq!(response.field_error().0, "/nonce", "{nonce}");
    }
    let extra = t
        .call(
            Req::post("/v1/me/confirmations")
                .token(&asking.access_token)
                .json(&json!({ "nonce": b64([1; 32]), "x": 1 })),
        )
        .await;
    assert_eq!(extra.code(), "validation_failed");
    assert_eq!(t.count("SELECT COUNT(*) FROM confirmations").await, 0);
}

#[tokio::test]
async fn a_request_expires_after_five_minutes() {
    let t = TestApp::new().await;
    let asking = t.register("alice@example.com").await;
    let other = t.login(&asking).await;
    let id = open(&t, &asking, 1).await;
    t.advance(Duration::minutes(5) - Duration::milliseconds(1));
    assert_eq!(t.call(get(&asking, &id)).await.json()["expires_in"], 0);
    assert_eq!(
        t.call(list(&other)).await.json()["requests"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    t.advance(Duration::milliseconds(1));
    assert_eq!(t.call(get(&asking, &id)).await.code(), "not_found");
    assert_eq!(t.call(list(&other)).await.json(), json!({ "requests": [] }));
    let late = t
        .call(answer(
            &other,
            &id,
            &signed(&other, &statement(&other, [1; 32])),
        ))
        .await;
    assert_eq!(late.code(), "not_found");
    assert_eq!(t.count("SELECT COUNT(*) FROM confirmations").await, 1);
    let removed = keeman_server::jobs::cleanup(&t.app).await.unwrap();
    assert_eq!(removed.confirmations, 1);
    assert_eq!(t.count("SELECT COUNT(*) FROM confirmations").await, 0);
}

#[tokio::test]
async fn requests_go_with_their_account() {
    let t = TestApp::new().await;
    let asking = t.register("alice@example.com").await;
    let stranger = t.register("bob@example.com").await;
    let id = open(&t, &asking, 1).await;
    // Another account can neither delete nor answer it.
    assert_eq!(
        t.call(delete(&stranger, &id)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM confirmations").await, 1);
    let response = t
        .call(answer(
            &stranger,
            &id,
            &signed(&stranger, &statement(&stranger, [1; 32])),
        ))
        .await;
    assert_eq!(response.code(), "not_found");

    let reauth = t.reauth(&asking).await;
    let deleted = t
        .call(
            Req::delete("/v1/me")
                .token(&asking.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.text());
    assert_eq!(t.count("SELECT COUNT(*) FROM confirmations").await, 0);
}

#[tokio::test]
async fn asking_has_its_own_limit_per_account() {
    let t = TestApp::with_config(
        "[rate_limits]\nconfirmations_per_account_per_hour = 3\nsession_per_min = 4\naccount_per_min = 4\n",
    )
    .await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    for n in 0..3 {
        assert_eq!(
            t.call(create(&alice, &b64([n; 32]))).await.status,
            StatusCode::CREATED
        );
    }
    let limited = t.call(create(&alice, &b64([9; 32]))).await;
    assert_eq!(limited.code(), "rate_limited");
    assert!(limited.header("retry-after").is_some());
    // Other requests of the account still pass the session limit.
    for _ in 0..3 {
        assert_eq!(t.call(list(&alice)).await.status, StatusCode::OK);
    }
    assert_eq!(
        t.call(create(&bob, &b64([1; 32]))).await.status,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn the_pairing_by_code_is_gone() {
    let t = TestApp::with_config("[rate_limits]\npairings_per_account_per_hour = 20\n").await;
    let alice = t.register("alice@example.com").await;
    for request in [
        Req::put("/v1/me/pairing").json(&json!({ "payload": envelope(300) })),
        Req::get("/v1/me/pairing"),
        Req::delete("/v1/me/pairing"),
    ] {
        let response = t.call(request.token(&alice.access_token)).await;
        assert!(
            matches!(
                response.status,
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{}",
            response.status
        );
    }
    let config = t.call(Req::get("/v1/config")).await.json();
    assert_eq!(config["features"]["confirmation"], true);
    assert_eq!(config["features"]["freshness"], true);
}
