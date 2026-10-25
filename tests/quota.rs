//! The storage quota counts objects with tombstones as well as attachments:
//! growth beyond it is refused with `507`, which is never stored, while
//! deleting and shrinking always works.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{Account, Req, TestApp, envelope, new_uuid, vault_body};

fn put(id: &str, expected: Option<i64>, len: usize) -> Value {
    json!({ "op": "put", "id": id, "type": "entry", "key_version": 1, "expected_revision": expected, "data": envelope(len) })
}

fn delete(id: &str, expected: i64, len: usize) -> Value {
    json!({ "op": "delete", "id": id, "key_version": 1, "expected_revision": expected, "data": envelope(len) })
}

fn batch(account: &Account, vault: &str, key: &str, ops: &Value) -> Req {
    Req::post(&format!("/v1/vaults/{vault}/batch"))
        .token(&account.access_token)
        .idem(key)
        .json(&json!({ "ops": ops }))
}

#[tokio::test]
async fn objects_and_tombstones_count_and_shrinking_always_works() {
    // The vault's own three objects take 900 bytes.
    let t = TestApp::with_config("[limits]\nuser_quota_bytes = 2000\n").await;
    let alice = t.register("alice@example.com").await;
    let vault = t.create_vault(&alice).await;
    let a = new_uuid();
    let response = t
        .call(batch(
            &alice,
            &vault,
            &new_uuid(),
            &json!([put(&a, None, 1000)]),
        ))
        .await;
    assert_eq!(response.status, StatusCode::OK);

    // 900 + 1000 + 200 > 2000.
    let b = new_uuid();
    let key = new_uuid();
    let grow = json!([put(&b, None, 200)]);
    let response = t.call(batch(&alice, &vault, &key, &grow)).await;
    assert_eq!(response.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(response.code(), "quota_exceeded");
    // Nothing applied, nothing stored for the key.
    assert_eq!(t.count("SELECT COUNT(*) FROM objects").await, 4);
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM idempotency WHERE key = '{key}'"
        ))
        .await,
        0
    );

    // A same-size update and a delete pass even when full.
    let response = t
        .call(batch(
            &alice,
            &vault,
            &new_uuid(),
            &json!([put(&a, Some(2), 1000)]),
        ))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let response = t
        .call(batch(
            &alice,
            &vault,
            &new_uuid(),
            &json!([delete(&a, 3, 256)]),
        ))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());

    // Room again: the same key with the same body now succeeds.
    let response = t.call(batch(&alice, &vault, &key, &grow)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
}

#[tokio::test]
async fn an_oversized_tombstone_counts_like_any_other_data() {
    let t = TestApp::with_config("[limits]\nuser_quota_bytes = 1500\n").await;
    let alice = t.register("alice@example.com").await;
    let vault = t.create_vault(&alice).await;
    let a = new_uuid();
    let response = t
        .call(batch(
            &alice,
            &vault,
            &new_uuid(),
            &json!([put(&a, None, 100)]),
        ))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    // 900 + 100 used; a 700-byte tombstone for a 100-byte object grows by 600.
    let response = t
        .call(batch(
            &alice,
            &vault,
            &new_uuid(),
            &json!([delete(&a, 2, 700)]),
        ))
        .await;
    assert_eq!(response.code(), "quota_exceeded");
}

#[tokio::test]
async fn creating_a_vault_counts_against_the_creator() {
    let t = TestApp::with_config("[limits]\nuser_quota_bytes = 1000\n").await;
    let alice = t.register("alice@example.com").await;
    let first = t.create_vault(&alice).await;
    let second = new_uuid();
    let key = new_uuid();
    let create = || {
        Req::post("/v1/vaults")
            .token(&alice.access_token)
            .idem(&key)
            .json(&vault_body(&second))
    };
    let response = t.call(create()).await;
    assert_eq!(response.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(response.code(), "quota_exceeded");

    // After deleting the first vault the same request succeeds.
    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete(&format!("/v1/vaults/{first}"))
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    let response = t.call(create()).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
}

#[tokio::test]
async fn members_write_into_the_owners_quota() {
    let t = TestApp::with_config("[limits]\nuser_quota_bytes = 2000\n").await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault = t.create_vault(&alice).await;
    t.share(&alice, &vault, &bob).await;
    // Bob owns nothing, but the vault counts against Alice.
    let response = t
        .call(batch(
            &bob,
            &vault,
            &new_uuid(),
            &json!([put(&new_uuid(), None, 1200)]),
        ))
        .await;
    assert_eq!(response.code(), "quota_exceeded");
    let response = t
        .call(batch(
            &bob,
            &vault,
            &new_uuid(),
            &json!([put(&new_uuid(), None, 1000)]),
        ))
        .await;
    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn attachments_and_objects_share_one_quota() {
    let t = TestApp::with_config("[limits]\nuser_quota_bytes = 1300\n").await;
    let alice = t.register("alice@example.com").await;
    let vault = t.create_vault(&alice).await;
    let create = |size: usize| {
        Req::post(&format!("/v1/vaults/{vault}/attachments"))
            .token(&alice.access_token)
            .json(&json!({ "attachment_id": new_uuid(), "entry_id": new_uuid(), "size": size }))
    };
    // 900 bytes of objects: 401 more do not fit, 400 do.
    assert_eq!(t.call(create(401)).await.code(), "quota_exceeded");
    assert_eq!(t.call(create(400)).await.status, StatusCode::CREATED);
    // Now the objects cannot grow either.
    let response = t
        .call(batch(
            &alice,
            &vault,
            &new_uuid(),
            &json!([put(&new_uuid(), None, 100)]),
        ))
        .await;
    assert_eq!(response.code(), "quota_exceeded");
}
