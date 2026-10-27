//! `GET/POST /v1/vaults`, `DELETE /v1/vaults/{id}` and idempotency.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{Req, TestApp, envelope, new_uuid, object, vault_body};
use time::Duration;

fn create(token: &str, key: &str, body: &Value) -> Req {
    Req::post("/v1/vaults").token(token).idem(key).json(body)
}

#[tokio::test]
async fn create_and_list() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = new_uuid();
    let body = vault_body(&alice, &vault_id);
    let response = t
        .call(create(&alice.access_token, &new_uuid(), &body))
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    assert_eq!(response.json(), json!({ "revision": 1 }));

    let list = t
        .call(Req::get("/v1/vaults").token(&alice.access_token))
        .await
        .json();
    assert_eq!(
        list,
        json!({ "vaults": [{
            "vault_id": vault_id,
            "role": "owner",
            "state": "active",
            "vault_key_version": 1,
            "member_key_version": 1,
            "key_wrapped": body["key_wrapped"],
            "pending_key": null,
            "invitation": null,
            "revision": 1,
            "rotation_required": false,
            "roles_version": 1,
            "freshness": null,
            "member_count": 1,
            "created": "2026-10-23T08:00:00.000Z",
        }] })
    );
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM objects WHERE vault_id = '{vault_id}' AND revision = 1 AND key_version = 1"
        ))
        .await,
        3
    );
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM security_log WHERE event = 'vault_created' AND vault_id = '{vault_id}' AND user_id = '{}'",
            alice.user_id
        ))
        .await,
        1
    );
    // Other accounts do not see it.
    let bob = t.register("bob@example.com").await;
    let list = t
        .call(Req::get("/v1/vaults").token(&bob.access_token))
        .await
        .json();
    assert_eq!(list, json!({ "vaults": [] }));
}

#[tokio::test]
async fn list_is_sorted_by_creation() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(t.create_vault(&alice).await);
        t.advance(Duration::seconds(1));
    }
    let list = t
        .call(Req::get("/v1/vaults").token(&alice.access_token))
        .await
        .json();
    let listed: Vec<&str> = list["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["vault_id"].as_str().unwrap())
        .collect();
    assert_eq!(listed, ids);
    let response = t
        .call(Req::get("/v1/vaults?x=1").token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn idempotent_create_replays_the_first_answer() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = new_uuid();
    let body = vault_body(&alice, &vault_id);
    let key = new_uuid();
    let first = t.call(create(&alice.access_token, &key, &body)).await;
    let second = t.call(create(&alice.access_token, &key, &body)).await;
    assert_eq!(first.status, StatusCode::CREATED);
    assert_eq!(second.status, StatusCode::CREATED);
    assert_eq!(first.body, second.body);
    assert_eq!(
        second.header("content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM vaults").await, 1);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = 'vault_created'")
            .await,
        1
    );

    // The same key with another body: 422, never stored.
    let other = t
        .call(create(
            &alice.access_token,
            &key,
            &vault_body(&alice, &new_uuid()),
        ))
        .await;
    assert_eq!(other.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(other.code(), "idempotency_key_reused");
    assert_eq!(t.count("SELECT COUNT(*) FROM idempotency").await, 1);

    // A new key for an existing vault: 409, and its repetition is the stored 409.
    let key = new_uuid();
    let conflict = t.call(create(&alice.access_token, &key, &body)).await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    assert_eq!(conflict.code(), "conflict");
    let again = t.call(create(&alice.access_token, &key, &body)).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "conflict");
    assert_ne!(again.json()["instance"], conflict.json()["instance"]);

    // Keys are scoped per account.
    let bob = t.register("bob@example.com").await;
    let response = t
        .call(create(
            &bob.access_token,
            &key,
            &vault_body(&bob, &new_uuid()),
        ))
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
}

#[tokio::test]
async fn stored_answers_never_contain_tokens() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    t.create_vault(&alice).await;
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT response FROM idempotency")
        .fetch_all(&t.app.db.read)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let text = String::from_utf8(rows[0].clone()).unwrap();
    assert_eq!(text, r#"{"revision":1}"#);
    assert!(!text.contains(&alice.access_token));
}

#[tokio::test]
async fn concurrent_repetitions_have_one_effect() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let body = vault_body(&alice, &new_uuid());
    let key = new_uuid();
    let (a, b) = tokio::join!(
        t.call(create(&alice.access_token, &key, &body)),
        t.call(create(&alice.access_token, &key, &body)),
    );
    assert_eq!(a.status, StatusCode::CREATED);
    assert_eq!(b.status, StatusCode::CREATED);
    assert_eq!(t.count("SELECT COUNT(*) FROM vaults").await, 1);
}

#[tokio::test]
async fn idempotency_key_is_required_and_canonical() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let body = vault_body(&alice, &new_uuid());
    let without = Req::post("/v1/vaults")
        .token(&alice.access_token)
        .json(&body);
    let upper = create(&alice.access_token, &new_uuid().to_uppercase(), &body);
    let twice = create(&alice.access_token, &new_uuid(), &body).idem(&new_uuid());
    for request in [without, upper, twice] {
        let response = t.call(request).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response.field_error().0,
            "Idempotency-Key",
            "{}",
            response.text()
        );
    }
    // 415 and 413 come first.
    let response = t
        .call(
            Req::post("/v1/vaults")
                .token(&alice.access_token)
                .raw(Some("text/plain"), b"{}"),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let big = vec![b' '; 2 * 1024 * 1024 + 1];
    let response = t
        .call(
            Req::post("/v1/vaults")
                .token(&alice.access_token)
                .raw(Some("application/json"), &big),
        )
        .await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(t.count("SELECT COUNT(*) FROM vaults").await, 0);
}

#[tokio::test]
async fn create_rejects_invalid_objects() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = new_uuid();
    let meta = object(&vault_id, "vault_meta", 300);
    let group = object(&new_uuid(), "group", 300);
    let roles = vault_body(&alice, &vault_id)["roles"].clone();
    let with = |objects: Vec<Value>| json!({ "vault_id": vault_id, "key_wrapped": envelope(73), "objects": objects, "roles": roles });
    let mut version_two = group.clone();
    version_two["key_version"] = json!(2);
    let mut short = group.clone();
    short["data"] = json!(envelope(40));
    let mut no_format_byte = group.clone();
    no_format_byte["data"] = json!(support::b64([2u8; 64]));
    let mut unknown = group.clone();
    unknown["extra"] = json!(1);
    let cases: Vec<(Value, &str)> = vec![
        (with(vec![]), "/objects"),
        (with(vec![group.clone()]), "/objects"),
        (
            with(vec![meta.clone(), version_two]),
            "/objects/1/key_version",
        ),
        (
            with(vec![meta.clone(), group.clone(), group.clone()]),
            "/objects/2/id",
        ),
        (
            with(vec![object(&new_uuid(), "vault_meta", 300)]),
            "/objects/0/id",
        ),
        (
            with(vec![meta.clone(), object(&vault_id, "group", 300)]),
            "/objects/1/id",
        ),
        (with(vec![meta.clone(), short]), "/objects/1/data"),
        (with(vec![meta.clone(), no_format_byte]), "/objects/1/data"),
        (with(vec![meta.clone(), unknown]), "/objects/1/extra"),
        (
            with(vec![meta.clone(), object(&new_uuid(), "note", 300)]),
            "/objects/1/type",
        ),
        (
            json!({ "vault_id": vault_id, "key_wrapped": envelope(72), "objects": [meta], "roles": roles }),
            "/key_wrapped",
        ),
    ];
    for (body, pointer) in cases {
        let response = t
            .call(create(&alice.access_token, &new_uuid(), &body))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{pointer}");
        assert_eq!(response.field_error().0, pointer, "{}", response.text());
    }
    let too_many: Vec<Value> = std::iter::once(object(&vault_id, "vault_meta", 41))
        .chain((0..500).map(|_| object(&new_uuid(), "group", 41)))
        .collect();
    let response = t
        .call(create(&alice.access_token, &new_uuid(), &with(too_many)))
        .await;
    assert_eq!(response.field_error().0, "/objects");
    let mut huge = object(&new_uuid(), "group", 41);
    huge["data"] = json!("A".repeat(1_572_865));
    let response = t
        .call(create(
            &alice.access_token,
            &new_uuid(),
            &with(vec![object(&vault_id, "vault_meta", 300), huge]),
        ))
        .await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(t.count("SELECT COUNT(*) FROM vaults").await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM idempotency").await, 0);
}

#[tokio::test]
async fn delete_needs_reauth_and_ownership() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let path = format!("/v1/vaults/{vault_id}");

    let response = t.call(Req::delete(&path).token(&alice.access_token)).await;
    assert_eq!(response.code(), "reauth_required");

    // Not a member: 404; pending: 403; member: 403.
    t.add_member(&vault_id, &bob, "member", "active").await;
    t.add_member(&vault_id, &carol, "member", "pending").await;
    let dave = t.register("dave@example.com").await;
    for (account, status) in [
        (&dave, StatusCode::NOT_FOUND),
        (&carol, StatusCode::FORBIDDEN),
        (&bob, StatusCode::FORBIDDEN),
    ] {
        let reauth = t.reauth(account).await;
        let response = t
            .call(
                Req::delete(&path)
                    .token(&account.access_token)
                    .reauth(&reauth),
            )
            .await;
        assert_eq!(response.status, status, "{}", account.email);
    }

    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete(&path)
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM vaults").await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM objects").await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM memberships").await, 0);
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM security_log WHERE event = 'vault_deleted' AND vault_id = '{vault_id}'"
        ))
        .await,
        1
    );
    // A repetition is 404; the client that deleted treats it as success.
    let response = t
        .call(
            Req::delete(&path)
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.code(), "not_found");

    let response = t
        .call(
            Req::delete("/v1/vaults/NOT-A-UUID")
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.field_error().0, "vault_id");
}

#[tokio::test]
async fn shared_vaults_list_invitations_and_pending_keys() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.invite_member(&alice, &vault_id, &carol).await;

    let own = t.listed(&alice, &vault_id).await.unwrap();
    assert_eq!(own["member_count"], 2);
    assert_eq!(own["invitation"], json!(null));
    assert_eq!(own["pending_key"], json!(null));
    let pending = t.listed(&carol, &vault_id).await.unwrap();
    assert_eq!(pending["state"], "pending");
    assert_eq!(pending["key_wrapped"], json!(null));
    assert_eq!(pending["invitation"]["sender_id"], json!(alice.user_id));
    assert_eq!(pending["member_count"], 2);
    let member = t.listed(&bob, &vault_id).await.unwrap();
    assert_eq!(member["role"], "member");
    assert_eq!(member["vault_key_version"], 1);
    assert_eq!(member["member_key_version"], 1);
}
