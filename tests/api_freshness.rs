//! Freshness attestations: storing the caller's own per vault and for the
//! user data, the checks of the statement and its signature, that only the
//! caller ever gets it back, and that it goes with the membership.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use keeman_server::freshness::{Statement, encode};
use serde_json::{Value, json};
use support::freshness::{sign_bytes, sign_in, signed, user_data, vault};
use support::{Account, Req, TestApp, envelope, key_box, new_uuid};

fn put_vault(account: &Account, vault_id: &str, freshness: &Value) -> Req {
    Req::put(&format!("/v1/vaults/{vault_id}/freshness"))
        .token(&account.access_token)
        .json(&json!({ "freshness": freshness }))
}

fn put_user(account: &Account, freshness: &Value) -> Req {
    Req::put("/v1/me/freshness")
        .token(&account.access_token)
        .json(&json!({ "freshness": freshness }))
}

async fn listed_freshness(t: &TestApp, account: &Account, vault_id: &str) -> Value {
    t.listed(account, vault_id).await.unwrap()["freshness"].clone()
}

async fn me_freshness(t: &TestApp, account: &Account) -> Value {
    t.call(Req::get("/v1/me").token(&account.access_token))
        .await
        .json()["freshness"]
        .clone()
}

async fn rows(t: &TestApp, account: &Account) -> i64 {
    t.count(&format!(
        "SELECT COUNT(*) FROM vault_freshness WHERE user_id = '{}'",
        account.user_id
    ))
    .await
}

/// A vault of Alice shared with Bob (member).
async fn shared(t: &TestApp, alice: &Account, bob: &Account) -> String {
    let vault_id = t.create_vault(alice).await;
    t.share(alice, &vault_id, bob).await;
    vault_id
}

#[tokio::test]
async fn each_account_gets_back_only_its_own_attestation() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = shared(&t, &alice, &bob).await;
    assert_eq!(listed_freshness(&t, &alice, &vault_id).await, Value::Null);

    let first = signed(&alice, &vault(&alice, &vault_id));
    let response = t.call(put_vault(&alice, &vault_id, &first)).await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
    assert_eq!(listed_freshness(&t, &alice, &vault_id).await, first);
    assert_eq!(listed_freshness(&t, &bob, &vault_id).await, Value::Null);

    let bobs = signed(&bob, &vault(&bob, &vault_id));
    assert_eq!(
        t.call(put_vault(&bob, &vault_id, &bobs)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(listed_freshness(&t, &bob, &vault_id).await, bobs);
    assert_eq!(listed_freshness(&t, &alice, &vault_id).await, first);

    // A new attestation replaces the last one.
    let second = signed(&alice, &vault(&alice, &vault_id));
    assert_ne!(second, first);
    assert_eq!(
        t.call(put_vault(&alice, &vault_id, &second)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(listed_freshness(&t, &alice, &vault_id).await, second);
    assert_eq!(rows(&t, &alice).await, 1);

    // The member list never shows attestations.
    let members = t
        .call(Req::get(&format!("/v1/vaults/{vault_id}/members")).token(&bob.access_token))
        .await
        .text();
    assert!(!members.contains(first["signature"].as_str().unwrap()));
    assert!(!members.contains(second["signature"].as_str().unwrap()));
    // Nothing of it reaches the security log or the other member's events.
    assert!(
        !t.security_events()
            .await
            .iter()
            .any(|e| e.contains("fresh"))
    );
}

#[tokio::test]
async fn the_user_data_attestation_is_stored_and_replaced() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    assert_eq!(me_freshness(&t, &alice).await, Value::Null);
    let first = signed(&alice, &user_data(&alice, 2));
    let response = t.call(put_user(&alice, &first)).await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
    assert_eq!(me_freshness(&t, &alice).await, first);
    assert_eq!(me_freshness(&t, &bob).await, Value::Null);
    let second = signed(&alice, &user_data(&alice, 3));
    assert_eq!(
        t.call(put_user(&alice, &second)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(me_freshness(&t, &alice).await, second);
    assert_eq!(t.count("SELECT COUNT(*) FROM user_freshness").await, 1);
}

#[tokio::test]
async fn statements_and_signatures_are_checked() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = shared(&t, &alice, &bob).await;
    let other_vault = t.create_vault(&alice).await;
    let own = vault(&alice, &vault_id);
    let bytes = encode(&own);
    let text = String::from_utf8(bytes.clone()).unwrap();
    let mut flipped = signed(&alice, &own);
    let signature = flipped["signature"].as_str().unwrap().to_string();
    let replaced = if signature.starts_with('A') { "B" } else { "A" };
    flipped["signature"] = json!(format!("{replaced}{}", &signature[1..]));

    let cases: Vec<(&str, Value)> = vec![
        (
            "signed with another account's key",
            sign_bytes(&bob, &bytes),
        ),
        (
            "made by another account",
            signed(&bob, &vault(&bob, &vault_id)),
        ),
        (
            "for another vault",
            signed(&alice, &vault(&alice, &other_vault)),
        ),
        ("of the user data", signed(&alice, &user_data(&alice, 1))),
        (
            "not canonical",
            sign_bytes(&alice, text.replace(r#""v":1,"#, r#""v": 1,"#).as_bytes()),
        ),
        (
            "signed for the roles chain",
            sign_in(&alice, "keeman:v1:roles", &bytes),
        ),
        ("with a changed signature", flipped),
    ];
    for (what, freshness) in cases {
        let response = t.call(put_vault(&alice, &vault_id, &freshness)).await;
        assert_eq!(response.code(), "validation_failed", "{what}");
        assert_eq!(response.field_error().0, "/freshness", "{what}");
    }
    let vault_statement = signed(&alice, &own);
    let response = t.call(put_user(&alice, &vault_statement)).await;
    assert_eq!(response.code(), "validation_failed");
    assert_eq!(response.field_error().0, "/freshness");
    let other_user = signed(&bob, &user_data(&bob, 1));
    assert_eq!(
        t.call(put_user(&alice, &other_user)).await.code(),
        "validation_failed"
    );

    // Structure, before anything else.
    let good = signed(&alice, &own);
    let long = "A".repeat(4100);
    let structural = [
        json!({ "statement": good["statement"], "signature": good["signature"], "note": 1 }),
        json!({ "statement": good["statement"] }),
        json!({ "statement": good["statement"], "signature": "AAAA" }),
        json!({ "statement": format!("{}=", good["statement"].as_str().unwrap()), "signature": good["signature"] }),
        json!({ "statement": long, "signature": good["signature"] }),
    ];
    for freshness in structural {
        let response = t.call(put_vault(&alice, &vault_id, &freshness)).await;
        assert_eq!(response.code(), "validation_failed", "{freshness}");
    }
    let response = t
        .call(
            Req::put(&format!("/v1/vaults/{vault_id}/freshness"))
                .token(&alice.access_token)
                .json(&json!({ "freshness": good, "extra": true })),
        )
        .await;
    assert_eq!(response.code(), "validation_failed");
    assert_eq!(rows(&t, &alice).await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM user_freshness").await, 0);
}

#[tokio::test]
async fn only_active_members_with_a_signing_key_store_one() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;

    let outsider = signed(&bob, &vault(&bob, &vault_id));
    assert_eq!(
        t.call(put_vault(&bob, &vault_id, &outsider)).await.code(),
        "not_found"
    );
    assert_eq!(
        t.call(put_vault(&bob, &new_uuid(), &outsider)).await.code(),
        "not_found"
    );
    t.invite_member(&alice, &vault_id, &carol).await;
    let invitee = signed(&carol, &vault(&carol, &vault_id));
    assert_eq!(
        t.call(put_vault(&carol, &vault_id, &invitee)).await.code(),
        "forbidden"
    );
    assert_eq!(
        t.call(put_vault(&alice, "not-a-uuid", &outsider))
            .await
            .code(),
        "validation_failed"
    );

    // An account from before signing keys cannot store one.
    t.sql(&format!(
        "UPDATE users SET signing_public_key = NULL WHERE id = '{}'",
        alice.user_id
    ))
    .await;
    let own = signed(&alice, &vault(&alice, &vault_id));
    assert_eq!(
        t.call(put_vault(&alice, &vault_id, &own)).await.code(),
        "signing_key_missing"
    );
    assert_eq!(
        t.call(put_user(&alice, &signed(&alice, &user_data(&alice, 1))))
            .await
            .code(),
        "signing_key_missing"
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM vault_freshness").await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM user_freshness").await, 0);
}

async fn store(t: &TestApp, account: &Account, vault_id: &str) {
    let freshness = signed(account, &vault(account, vault_id));
    let response = t.call(put_vault(account, vault_id, &freshness)).await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
}

#[tokio::test]
async fn the_attestation_goes_when_the_member_leaves() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = shared(&t, &alice, &bob).await;
    store(&t, &alice, &vault_id).await;
    store(&t, &bob, &vault_id).await;
    let left = t
        .call(Req::delete(&format!("/v1/vaults/{vault_id}/members/me")).token(&bob.access_token))
        .await;
    assert_eq!(left.status, StatusCode::NO_CONTENT, "{}", left.text());
    assert_eq!(rows(&t, &bob).await, 0);
    assert_eq!(rows(&t, &alice).await, 1);
}

#[tokio::test]
async fn the_attestation_goes_when_a_rotation_removes_the_member() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = shared(&t, &alice, &bob).await;
    t.share(&alice, &vault_id, &carol).await;
    store(&t, &bob, &vault_id).await;
    store(&t, &carol, &vault_id).await;

    let revision = t.listed(&alice, &vault_id).await.unwrap()["revision"]
        .as_i64()
        .unwrap();
    let opened = t
        .call(
            Req::post(&format!("/v1/vaults/{vault_id}/rotations"))
                .token(&alice.access_token)
                .idem(&new_uuid())
                .json(&json!({ "base_revision": revision, "new_key_version": 2 })),
        )
        .await;
    assert_eq!(opened.status, StatusCode::CREATED, "{}", opened.text());
    let rotation_id = opened.json()["rotation_id"].as_str().unwrap().to_string();
    let objects: Vec<Value> = t.changes(&alice, &vault_id, "since=0").await.json()["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| json!({ "id": o["id"], "type": o["type"], "key_version": 2, "data": envelope(300) }))
        .collect();
    let uploaded = t
        .call(
            Req::put(&format!(
                "/v1/vaults/{vault_id}/rotations/{rotation_id}/objects"
            ))
            .token(&alice.access_token)
            .idem(&new_uuid())
            .json(&json!({ "objects": objects })),
        )
        .await;
    assert_eq!(
        uploaded.status,
        StatusCode::NO_CONTENT,
        "{}",
        uploaded.text()
    );
    let roles = t
        .rotation_roles(&alice, &vault_id, &[&bob.user_id])
        .await
        .unwrap();
    let committed = t
        .call(
            Req::post(&format!(
                "/v1/vaults/{vault_id}/rotations/{rotation_id}/commit"
            ))
            .token(&alice.access_token)
            .idem(&new_uuid())
            .json(&json!({
                "key_wrapped": envelope(73),
                "member_keys": [{ "user_id": carol.user_id, "key_box": key_box(200) }],
                "invite_keys": [],
                "remove_user_ids": [bob.user_id],
                "drop_objects": [],
                "roles": roles,
            })),
        )
        .await;
    assert_eq!(committed.status, StatusCode::OK, "{}", committed.text());
    assert_eq!(rows(&t, &bob).await, 0);
    assert_eq!(rows(&t, &carol).await, 1);
}

#[tokio::test]
async fn attestations_go_with_the_vault_and_the_account() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = shared(&t, &alice, &bob).await;
    let other = t.create_vault(&bob).await;
    store(&t, &alice, &vault_id).await;
    store(&t, &bob, &vault_id).await;
    store(&t, &bob, &other).await;
    let bobs_user_data = signed(&bob, &user_data(&bob, 1));
    assert_eq!(
        t.call(put_user(&bob, &bobs_user_data)).await.status,
        StatusCode::NO_CONTENT
    );

    let reauth = t.reauth(&bob).await;
    let deleted = t
        .call(
            Req::delete("/v1/me")
                .token(&bob.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.text());
    assert_eq!(rows(&t, &bob).await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM user_freshness").await, 0);
    assert_eq!(rows(&t, &alice).await, 1);

    let reauth = t.reauth(&alice).await;
    let deleted = t
        .call(
            Req::delete(&format!("/v1/vaults/{vault_id}"))
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.text());
    assert_eq!(t.count("SELECT COUNT(*) FROM vault_freshness").await, 0);
}

#[tokio::test]
async fn the_feature_is_announced() {
    let t = TestApp::new().await;
    let config = t.call(Req::get("/v1/config")).await.json();
    assert_eq!(config["features"]["freshness"], json!(true));
    // A statement type the server does not know is refused like any other.
    let alice = t.register("alice@example.com").await;
    let unknown = Statement::UserData {
        user_id: alice.user_id.clone(),
        time: "2026-10-27T08:42:00.000Z".into(),
        seq: 1,
    };
    let text = String::from_utf8(encode(&unknown))
        .unwrap()
        .replace("user_data_freshness", "account_freshness");
    assert_eq!(
        t.call(put_user(&alice, &sign_bytes(&alice, text.as_bytes())))
            .await
            .code(),
        "validation_failed"
    );
}
