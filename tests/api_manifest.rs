//! The vault manifest: the type only under the derived IDs, never deleted or
//! dropped, and once the root exists every batch must write it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use keeman_server::manifest_ids::{root_id, shard_id};
use serde_json::{Value, json};
use support::{Req, TestApp, delete_op, envelope, new_uuid, object, put_op, vault_body};

fn batch_request(token: &str, vault_id: &str, key: &str, ops: &[Value]) -> Req {
    Req::post(&format!("/v1/vaults/{vault_id}/batch"))
        .token(token)
        .idem(key)
        .json(&json!({ "ops": ops }))
}

#[tokio::test]
async fn manifest_objects_live_under_the_derived_ids() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let root = root_id(&vault_id);
    let shard = shard_id(&vault_id, 7);

    let created = t
        .batch(
            &alice,
            &vault_id,
            vec![
                put_op(&root, "manifest", None),
                put_op(&shard, "manifest", None),
            ],
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());
    let updated = t
        .batch(
            &alice,
            &vault_id,
            vec![
                put_op(&root, "manifest", Some(2)),
                put_op(&new_uuid(), "entry", None),
            ],
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text());

    let page = t.changes(&alice, &vault_id, "since=0").await.json();
    let kinds: Vec<(&str, i64)> = page["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["type"] == "manifest")
        .map(|o| (o["id"].as_str().unwrap(), o["revision"].as_i64().unwrap()))
        .collect();
    assert_eq!(kinds, vec![(shard.as_str(), 2), (root.as_str(), 3)]);
}

#[tokio::test]
async fn the_type_and_the_derived_ids_belong_together() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let root = root_id(&vault_id);
    let other_vault_root = root_id(&new_uuid());
    t.batch(&alice, &vault_id, vec![put_op(&root, "manifest", None)])
        .await;

    for ops in [
        vec![put_op(&new_uuid(), "manifest", None)],
        vec![put_op(&other_vault_root, "manifest", None)],
        vec![put_op(&shard_id(&vault_id, 3), "group", None)],
        vec![put_op(&root, "manifest", Some(2)), delete_op(&root, 2)],
        vec![
            put_op(&root, "manifest", Some(2)),
            delete_op(&shard_id(&vault_id, 63), 1),
        ],
    ] {
        let key = new_uuid();
        let response = t
            .call(batch_request(&alice.access_token, &vault_id, &key, &ops))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{ops:?}");
        // Structural: nothing is stored for the key.
        let stored = t
            .count(&format!(
                "SELECT COUNT(*) FROM idempotency WHERE key = '{key}'"
            ))
            .await;
        assert_eq!(stored, 0);
    }

    for objects in [
        vec![object(&new_uuid(), "manifest", 300)],
        vec![object(&root_id(&new_uuid()), "manifest", 300)],
    ] {
        let mut body = vault_body(&alice, &new_uuid());
        body["objects"].as_array_mut().unwrap().extend(objects);
        let response = t
            .call(
                Req::post("/v1/vaults")
                    .token(&alice.access_token)
                    .idem(&new_uuid())
                    .json(&body),
            )
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(response.field_error().0, "/objects/3/id");
    }
    let new_vault = new_uuid();
    let mut body = vault_body(&alice, &new_vault);
    body["objects"].as_array_mut().unwrap().extend([
        object(&root_id(&new_vault), "manifest", 300),
        object(&shard_id(&new_vault, 0), "manifest", 300),
    ]);
    let response = t
        .call(
            Req::post("/v1/vaults")
                .token(&alice.access_token)
                .idem(&new_uuid())
                .json(&body),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
}

#[tokio::test]
async fn a_vault_with_a_root_requires_it_in_every_batch() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let root = root_id(&vault_id);
    let shard = shard_id(&vault_id, 1);

    // Without a root nothing changes for old clients.
    let entry = new_uuid();
    let plain = t
        .batch(&alice, &vault_id, vec![put_op(&entry, "entry", None)])
        .await;
    assert_eq!(plain.status, StatusCode::OK);
    let created = t
        .batch(
            &alice,
            &vault_id,
            vec![
                put_op(&root, "manifest", None),
                put_op(&shard, "manifest", None),
            ],
        )
        .await;
    assert_eq!(created.status, StatusCode::OK);

    for ops in [
        vec![put_op(&new_uuid(), "entry", None)],
        vec![put_op(&shard, "manifest", Some(3))],
        vec![delete_op(&entry, 2)],
    ] {
        let key = new_uuid();
        let first = t
            .call(batch_request(&alice.access_token, &vault_id, &key, &ops))
            .await;
        assert_eq!(first.status, StatusCode::UNPROCESSABLE_ENTITY, "{ops:?}");
        assert_eq!(first.code(), "manifest_required");
        let again = t
            .call(batch_request(&alice.access_token, &vault_id, &key, &ops))
            .await;
        assert_eq!(again.status, StatusCode::UNPROCESSABLE_ENTITY);
        let stored = t
            .count(&format!(
                "SELECT COUNT(*) FROM idempotency WHERE key = '{key}'"
            ))
            .await;
        assert_eq!(stored, 1, "a business error is stored");
    }

    let with_root = t
        .batch(
            &alice,
            &vault_id,
            vec![put_op(&root, "manifest", Some(3)), delete_op(&entry, 2)],
        )
        .await;
    assert_eq!(with_root.status, StatusCode::OK, "{}", with_root.text());
}

#[tokio::test]
async fn manifest_required_comes_after_the_key_version_and_before_conflicts() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let root = root_id(&vault_id);
    t.batch(&alice, &vault_id, vec![put_op(&root, "manifest", None)])
        .await;

    let mut stale = put_op(&new_uuid(), "entry", None);
    stale["key_version"] = json!(2);
    let response = t.batch(&alice, &vault_id, vec![stale]).await;
    assert_eq!(response.code(), "stale_key_version");

    let conflicting = put_op(&new_uuid(), "entry", Some(5));
    let response = t.batch(&alice, &vault_id, vec![conflicting]).await;
    assert_eq!(response.code(), "manifest_required");

    // A client that missed the root creates it and gets the normal conflict.
    let response = t
        .batch(
            &alice,
            &vault_id,
            vec![
                put_op(&root, "manifest", None),
                put_op(&new_uuid(), "entry", None),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["conflicts"][0]["id"], json!(root));
}

#[tokio::test]
async fn a_manifest_is_never_dropped_and_counts_for_completeness() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let root = root_id(&vault_id);
    t.batch(&alice, &vault_id, vec![put_op(&root, "manifest", None)])
        .await;
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
    let rotation_id = opened.json()["rotation_id"].as_str().unwrap().to_string();
    let roles = t.rotation_roles(&alice, &vault_id, &[]).await.unwrap();
    let commit = |drop: Value| {
        Req::post(&format!(
            "/v1/vaults/{vault_id}/rotations/{rotation_id}/commit"
        ))
        .token(&alice.access_token)
        .idem(&new_uuid())
        .json(&json!({
            "key_wrapped": envelope(73),
            "member_keys": [],
            "invite_keys": [],
            "remove_user_ids": [],
            "drop_objects": drop,
            "roles": roles,
        }))
    };

    let dropped = t
        .call(commit(json!([{ "id": root, "data": envelope(256) }])))
        .await;
    assert_eq!(dropped.status, StatusCode::BAD_REQUEST);
    assert_eq!(dropped.field_error().0, "/drop_objects/0/id");

    // Everything but the manifest re-encrypted: incomplete.
    let page = t.changes(&alice, &vault_id, "since=0").await.json();
    let others: Vec<Value> = page["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["type"] != "manifest")
        .map(|o| json!({ "id": o["id"], "type": o["type"], "key_version": 2, "data": envelope(300) }))
        .collect();
    let upload = |objects: Vec<Value>| {
        Req::put(&format!(
            "/v1/vaults/{vault_id}/rotations/{rotation_id}/objects"
        ))
        .token(&alice.access_token)
        .idem(&new_uuid())
        .json(&json!({ "objects": objects }))
    };
    assert_eq!(t.call(upload(others)).await.status, StatusCode::NO_CONTENT);
    let incomplete = t.call(commit(json!([]))).await;
    assert_eq!(incomplete.code(), "rotation_incomplete");
    let manifest =
        vec![json!({ "id": root, "type": "manifest", "key_version": 2, "data": envelope(300) })];
    assert_eq!(
        t.call(upload(manifest)).await.status,
        StatusCode::NO_CONTENT
    );
    let done = t.call(commit(json!([]))).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
}
