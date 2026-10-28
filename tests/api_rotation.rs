//! Staged key rotation: open, upload, commit with drop
//! tombstones, tombstone purge, membership swap and a vault over 20 MiB.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{Account, Req, TestApp, delete_op, envelope, key_box, new_uuid, put_op};
use time::Duration;

fn open(account: &Account, vault_id: &str, base: i64, key_version: i64) -> Req {
    Req::post(&format!("/v1/vaults/{vault_id}/rotations"))
        .token(&account.access_token)
        .idem(&new_uuid())
        .json(&json!({ "base_revision": base, "new_key_version": key_version }))
}

fn upload(account: &Account, vault_id: &str, rotation_id: &str, objects: &[Value]) -> Req {
    Req::put(&format!(
        "/v1/vaults/{vault_id}/rotations/{rotation_id}/objects"
    ))
    .token(&account.access_token)
    .idem(&new_uuid())
    .json(&json!({ "objects": objects }))
}

/// The commit request; a body without `roles` gets the next statement of
/// the vault's roles chain (owners afterwards, next key version).
async fn commit(
    t: &TestApp,
    account: &Account,
    vault_id: &str,
    rotation_id: &str,
    body: &Value,
) -> Req {
    let mut body = body.clone();
    if body.get("roles").is_none() && body.is_object() {
        let removed: Vec<&str> = body["remove_user_ids"]
            .as_array()
            .map(|ids| ids.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if let Some(roles) = t.rotation_roles(account, vault_id, &removed).await {
            body["roles"] = roles;
        }
    }
    Req::post(&format!(
        "/v1/vaults/{vault_id}/rotations/{rotation_id}/commit"
    ))
    .token(&account.access_token)
    .idem(&new_uuid())
    .json(&body)
}

fn commit_body(members: &[&Account], invites: &[&Account], remove: &[&Account]) -> Value {
    let keys = |accounts: &[&Account]| -> Vec<Value> {
        accounts
            .iter()
            .map(|a| json!({ "user_id": a.user_id, "key_box": key_box(200) }))
            .collect()
    };
    json!({
        "key_wrapped": envelope(73),
        "member_keys": keys(members),
        "invite_keys": keys(invites),
        "remove_user_ids": remove.iter().map(|a| a.user_id.clone()).collect::<Vec<_>>(),
        "drop_objects": [],
    })
}

/// Live objects as `changes?since=0` lists them: `(id, type, revision)`.
async fn live(t: &TestApp, account: &Account, vault_id: &str) -> Vec<Value> {
    let mut objects = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let query = match &cursor {
            Some(c) => format!("since=0&cursor={c}"),
            None => "since=0".to_string(),
        };
        let page = t.changes(account, vault_id, &query).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.text());
        let page = page.json();
        objects.extend(page["objects"].as_array().unwrap().iter().cloned());
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => return objects,
        }
    }
}

/// Re-encrypted uploads of all live objects with key version 2.
fn reencrypted(objects: &[Value], data_len: usize) -> Vec<Value> {
    objects
        .iter()
        .map(|o| json!({ "id": o["id"], "type": o["type"], "key_version": 2, "data": envelope(data_len) }))
        .collect()
}

async fn revision(t: &TestApp, account: &Account, vault_id: &str) -> i64 {
    t.listed(account, vault_id).await.unwrap()["revision"]
        .as_i64()
        .unwrap()
}

async fn opened(t: &TestApp, account: &Account, vault_id: &str) -> String {
    opened_removing(t, account, vault_id, &[]).await
}

/// Opens a rotation that is to remove these accounts.
async fn opened_removing(
    t: &TestApp,
    account: &Account,
    vault_id: &str,
    remove: &[&Account],
) -> String {
    let base = revision(t, account, vault_id).await;
    let response = t.call(open_removing(account, vault_id, base, remove)).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    response.json()["rotation_id"].as_str().unwrap().to_string()
}

fn open_removing(account: &Account, vault_id: &str, base: i64, remove: &[&Account]) -> Req {
    let remove: Vec<&str> = remove.iter().map(|a| a.user_id.as_str()).collect();
    Req::post(&format!("/v1/vaults/{vault_id}/rotations"))
        .token(&account.access_token)
        .idem(&new_uuid())
        .json(&json!({ "base_revision": base, "new_key_version": 2, "remove_user_ids": remove }))
}

#[tokio::test]
async fn opening_checks_revision_and_next_key_version() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;

    let old = t.call(open(&alice, &vault_id, 7, 2)).await;
    assert_eq!(old.code(), "conflict");
    assert_eq!(old.json()["current_revision"], 1);
    let skipped = t.call(open(&alice, &vault_id, 1, 3)).await;
    assert_eq!(skipped.code(), "key_version_mismatch");
    assert_eq!(skipped.json()["current_key_version"], 1);
    assert_eq!(
        t.call(open(&bob, &vault_id, 1, 2)).await.code(),
        "forbidden"
    );

    let key = new_uuid();
    let request = |key: &str| {
        Req::post(&format!("/v1/vaults/{vault_id}/rotations"))
            .token(&alice.access_token)
            .idem(key)
            .json(&json!({ "base_revision": 1, "new_key_version": 2 }))
    };
    let first = t.call(request(&key)).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.text());
    assert_eq!(first.json()["expires_in"], 3600);
    let replay = t.call(request(&key)).await;
    assert_eq!(replay.json()["rotation_id"], first.json()["rotation_id"]);

    // A new rotation replaces the older one.
    let older = first.json()["rotation_id"].as_str().unwrap().to_string();
    let newer = t.call(open(&alice, &vault_id, 1, 2)).await;
    assert_eq!(newer.status, StatusCode::CREATED);
    let objects = reencrypted(&live(&t, &alice, &vault_id).await, 300);
    let stale = t.call(upload(&alice, &vault_id, &older, &objects)).await;
    assert_eq!(stale.code(), "rotation_invalid");
}

#[tokio::test]
async fn uploads_are_checked_and_replayed_without_body() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    let objects = live(&t, &alice, &vault_id).await;
    let entry = new_uuid();
    t.batch(&alice, &vault_id, vec![put_op(&entry, "entry", None)])
        .await;
    t.batch(&alice, &vault_id, vec![delete_op(&entry, 2)]).await;
    let rotation_id = opened(&t, &alice, &vault_id).await;
    let mut uploads = reencrypted(&objects, 300);

    let mut wrong_version = uploads.clone();
    wrong_version[0]["key_version"] = json!(1);
    let response = t
        .call(upload(&alice, &vault_id, &rotation_id, &wrong_version))
        .await;
    assert_eq!(response.field_error().0, "/objects/0/key_version");
    let mut wrong_type = uploads.clone();
    wrong_type[1]["type"] = json!("entry");
    let response = t
        .call(upload(&alice, &vault_id, &rotation_id, &wrong_type))
        .await;
    assert_eq!(response.field_error().0, "/objects/1/type");
    for id in [new_uuid(), entry.clone()] {
        let unknown =
            vec![json!({ "id": id, "type": "entry", "key_version": 2, "data": envelope(300) })];
        let response = t
            .call(upload(&alice, &vault_id, &rotation_id, &unknown))
            .await;
        assert_eq!(response.field_error().0, "/objects/0/id");
    }
    let twice = vec![uploads[0].clone(), uploads[0].clone()];
    let response = t
        .call(upload(&alice, &vault_id, &rotation_id, &twice))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let response = t.call(upload(&alice, &vault_id, &rotation_id, &[])).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    let key = new_uuid();
    let request = |key: &str, objects: &[Value]| {
        Req::put(&format!(
            "/v1/vaults/{vault_id}/rotations/{rotation_id}/objects"
        ))
        .token(&alice.access_token)
        .idem(key)
        .json(&json!({ "objects": objects }))
    };
    let stored = t.call(request(&key, &uploads)).await;
    assert_eq!(stored.status, StatusCode::NO_CONTENT, "{}", stored.text());
    assert!(stored.body.is_empty());
    let replay = t.call(request(&key, &uploads)).await;
    assert_eq!(replay.status, StatusCode::NO_CONTENT);
    assert!(replay.body.is_empty());
    assert_eq!(replay.header("content-type"), None);
    uploads[0]["data"] = json!(envelope(300));
    let reused = t.call(request(&key, &uploads)).await;
    assert_eq!(reused.code(), "idempotency_key_reused");

    // Another owner cannot use Alice's rotation, and it expires after an hour.
    let promoted = t
        .call(
            t.role_change(&alice, &vault_id, &bob.user_id, "owner")
                .await,
        )
        .await;
    assert_eq!(
        promoted.status,
        StatusCode::NO_CONTENT,
        "{}",
        promoted.text()
    );
    let foreign = t
        .call(upload(&bob, &vault_id, &rotation_id, &uploads))
        .await;
    assert_eq!(foreign.code(), "rotation_invalid");
    t.advance(Duration::minutes(61));
    let alice = t.login(&alice).await;
    let expired = t
        .call(upload(&alice, &vault_id, &rotation_id, &uploads))
        .await;
    assert_eq!(expired.code(), "rotation_invalid");
}

#[tokio::test]
async fn a_commit_swaps_objects_keys_and_memberships() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let dave = t.register("dave@example.com").await;
    let erin = t.register("erin@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.share(&alice, &vault_id, &dave).await;
    t.invite_member(&alice, &vault_id, &carol).await;
    t.invite_member(&alice, &vault_id, &erin).await;
    let objects = live(&t, &alice, &vault_id).await;
    let rotation_id = opened_removing(&t, &alice, &vault_id, &[&dave]).await;
    let uploads = reencrypted(&objects, 400);
    assert_eq!(
        t.call(upload(&alice, &vault_id, &rotation_id, &uploads))
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    // Erin's invitation is left out and therefore deleted; Dave is removed.
    let body = commit_body(&[&bob], &[&carol], &[&dave]);
    let response = t
        .call(commit(&t, &alice, &vault_id, &rotation_id, &body).await)
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json(), json!({ "revision": 2 }));

    let after = live(&t, &alice, &vault_id).await;
    assert_eq!(after.len(), uploads.len());
    for object in &after {
        let uploaded = uploads.iter().find(|u| u["id"] == object["id"]).unwrap();
        assert_eq!(object["data"], uploaded["data"]);
        assert_eq!(object["key_version"], 2);
        assert_eq!(object["revision"], 2);
        assert_eq!(object["updated_by"], json!(alice.user_id));
    }
    let own = t.listed(&alice, &vault_id).await.unwrap();
    assert_eq!(own["vault_key_version"], 2);
    assert_eq!(own["member_key_version"], 2);
    assert_eq!(own["key_wrapped"], body["key_wrapped"]);
    assert_eq!(own["rotation_required"], false);
    let member = t.listed(&bob, &vault_id).await.unwrap();
    assert_eq!(member["member_key_version"], 1);
    assert_eq!(member["pending_key"]["key_version"], 2);
    assert_eq!(member["pending_key"]["sender_id"], json!(alice.user_id));
    assert_eq!(
        member["pending_key"]["key_box"],
        body["member_keys"][0]["key_box"]
    );
    let invited = t.listed(&carol, &vault_id).await.unwrap();
    assert_eq!(invited["invitation"]["key_version"], 2);
    assert_eq!(
        invited["invitation"]["key_box"],
        body["invite_keys"][0]["key_box"]
    );
    assert!(t.listed(&dave, &vault_id).await.is_none());
    assert!(t.listed(&erin, &vault_id).await.is_none());
    assert_eq!(t.count("SELECT COUNT(*) FROM rotations").await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM rotation_objects").await, 0);
    assert!(
        t.security_events()
            .await
            .contains(&"vault_rotated".to_string())
    );
    // The removed member gets nothing new.
    assert_eq!(
        t.changes(&dave, &vault_id, "since=0").await.code(),
        "not_found"
    );
}

#[tokio::test]
async fn incomplete_commits_are_refused() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let mallory = t.register("mallory@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.invite_member(&alice, &vault_id, &carol).await;
    let objects = live(&t, &alice, &vault_id).await;
    // Mallory is announced, so the commit reaches the membership check.
    let rotation_id = opened_removing(&t, &alice, &vault_id, &[&mallory]).await;
    let uploads = reencrypted(&objects, 300);

    let missing = t
        .call(upload(&alice, &vault_id, &rotation_id, &uploads[1..]))
        .await;
    assert_eq!(missing.status, StatusCode::NO_CONTENT);
    let body = commit_body(&[&bob], &[&carol], &[]);
    let incomplete = t
        .call(commit(&t, &alice, &vault_id, &rotation_id, &body).await)
        .await;
    assert_eq!(incomplete.code(), "rotation_incomplete");
    t.call(upload(&alice, &vault_id, &rotation_id, &uploads[..1]))
        .await;

    for body in [
        commit_body(&[], &[&carol], &[]),
        commit_body(&[&bob, &carol], &[], &[]),
        commit_body(&[], &[&bob], &[]),
        commit_body(&[&bob], &[&carol], &[&mallory]),
        commit_body(&[&bob, &mallory], &[], &[]),
    ] {
        let response = t
            .call(commit(&t, &alice, &vault_id, &rotation_id, &body).await)
            .await;
        assert_eq!(response.code(), "rotation_incomplete", "{body}");
    }
    let done = t
        .call(
            commit(
                &t,
                &alice,
                &vault_id,
                &rotation_id,
                &commit_body(&[&bob], &[&carol], &[]),
            )
            .await,
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
}

#[tokio::test]
async fn structural_errors_of_a_commit() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    let rotation_id = opened(&t, &alice, &vault_id).await;
    let base = commit_body(&[&bob], &[], &[]);

    let mut caller = base.clone();
    caller["remove_user_ids"] = json!([alice.user_id]);
    let mut twice = base.clone();
    twice["remove_user_ids"] = json!([bob.user_id]);
    let mut meta = base.clone();
    meta["drop_objects"] = json!([{ "id": vault_id, "data": envelope(256) }]);
    let id = new_uuid();
    let mut duplicate = base.clone();
    duplicate["drop_objects"] =
        json!([{ "id": id, "data": envelope(256) }, { "id": id, "data": envelope(256) }]);
    let mut aead = base.clone();
    aead["member_keys"][0]["key_box"] = json!(envelope(200));
    for (body, pointer) in [
        (caller, "/remove_user_ids/0"),
        (twice, "/remove_user_ids/0"),
        (meta, "/drop_objects/0/id"),
        (duplicate, "/drop_objects/1/id"),
    ] {
        let response = t
            .call(commit(&t, &alice, &vault_id, &rotation_id, &body).await)
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(response.field_error().0, pointer);
    }
    let response = t
        .call(commit(&t, &alice, &vault_id, &rotation_id, &aead).await)
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    // An unknown dropped object is a stored 400.
    let mut unknown = base.clone();
    unknown["drop_objects"] = json!([{ "id": new_uuid(), "data": envelope(256) }]);
    let response = t
        .call(commit(&t, &alice, &vault_id, &rotation_id, &unknown).await)
        .await;
    assert_eq!(response.field_error().0, "/drop_objects/0/id");
}

#[tokio::test]
async fn a_conflict_discards_the_rotation() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let objects = live(&t, &alice, &vault_id).await;
    let rotation_id = opened(&t, &alice, &vault_id).await;
    let uploads = reencrypted(&objects, 300);
    t.call(upload(&alice, &vault_id, &rotation_id, &uploads))
        .await;
    t.batch(&alice, &vault_id, vec![put_op(&new_uuid(), "entry", None)])
        .await;

    let key = new_uuid();
    let body = commit_body(&[], &[], &[]);
    let request = |key: &str| {
        Req::post(&format!(
            "/v1/vaults/{vault_id}/rotations/{rotation_id}/commit"
        ))
        .token(&alice.access_token)
        .idem(key)
        .json(&body)
    };
    let response = t.call(request(&key)).await;
    assert_eq!(response.code(), "conflict");
    assert_eq!(response.json()["current_revision"], 2);
    assert_eq!(t.count("SELECT COUNT(*) FROM rotations").await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM rotation_objects").await, 0);
    let replay = t.call(request(&key)).await;
    assert_eq!(replay.code(), "conflict");
    let late = t
        .call(upload(&alice, &vault_id, &rotation_id, &uploads))
        .await;
    assert_eq!(late.code(), "rotation_invalid");
}

#[tokio::test]
async fn tombstones_up_to_the_base_are_purged() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let gone = new_uuid();
    let corrupt = new_uuid();
    t.batch(
        &alice,
        &vault_id,
        vec![
            put_op(&gone, "entry", None),
            put_op(&corrupt, "group", None),
        ],
    )
    .await;
    t.batch(&alice, &vault_id, vec![delete_op(&gone, 2)]).await;
    let objects: Vec<Value> = live(&t, &alice, &vault_id)
        .await
        .into_iter()
        .filter(|o| o["id"] != corrupt.as_str())
        .collect();
    let rotation_id = opened(&t, &alice, &vault_id).await;
    t.call(upload(
        &alice,
        &vault_id,
        &rotation_id,
        &reencrypted(&objects, 300),
    ))
    .await;
    let mut body = commit_body(&[], &[], &[]);
    let tombstone = envelope(256);
    body["drop_objects"] = json!([{ "id": corrupt, "data": tombstone }]);
    let response = t
        .call(commit(&t, &alice, &vault_id, &rotation_id, &body).await)
        .await;
    assert_eq!(response.json(), json!({ "revision": 4 }));

    let old = t.changes(&alice, &vault_id, "since=1").await;
    assert_eq!(old.code(), "resync_required");
    let delta = t.changes(&alice, &vault_id, "since=3").await.json();
    let delta = delta["objects"].as_array().unwrap();
    assert_eq!(delta.len(), objects.len() + 1);
    let dropped = delta.iter().find(|o| o["id"] == corrupt.as_str()).unwrap();
    assert_eq!(dropped["deleted"], true);
    assert_eq!(dropped["data"], json!(tombstone));
    assert_eq!(dropped["key_version"], 2);
    assert!(delta.iter().all(|o| o["id"] != gone.as_str()));
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM objects WHERE vault_id = '{vault_id}' AND deleted = 1"
        ))
        .await,
        1
    );
}

#[tokio::test]
async fn dropping_an_entry_deletes_its_attachments() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let entry = new_uuid();
    t.batch(&alice, &vault_id, vec![put_op(&entry, "entry", None)])
        .await;
    let attachment = new_uuid();
    let created = t
        .call(
            Req::post(&format!("/v1/vaults/{vault_id}/attachments"))
                .token(&alice.access_token)
                .json(&json!({ "attachment_id": attachment, "entry_id": entry, "size": 42 })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text());
    let base = format!("/v1/vaults/{vault_id}/attachments/{attachment}");
    t.call(
        Req::put(&format!("{base}/parts/0"))
            .token(&alice.access_token)
            .raw(Some("application/octet-stream"), &[3u8; 42]),
    )
    .await;
    t.call(Req::post(&format!("{base}/complete")).token(&alice.access_token))
        .await;

    let objects: Vec<Value> = live(&t, &alice, &vault_id)
        .await
        .into_iter()
        .filter(|o| o["id"] != entry.as_str())
        .collect();
    let rotation_id = opened(&t, &alice, &vault_id).await;
    t.call(upload(
        &alice,
        &vault_id,
        &rotation_id,
        &reencrypted(&objects, 300),
    ))
    .await;
    let mut body = commit_body(&[], &[], &[]);
    body["drop_objects"] = json!([{ "id": entry, "data": envelope(256) }]);
    let response = t
        .call(commit(&t, &alice, &vault_id, &rotation_id, &body).await)
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(t.count("SELECT COUNT(*) FROM attachments").await, 0);
    let download = t.call(Req::get(&base).token(&alice.access_token)).await;
    assert_eq!(download.code(), "not_found");
}

#[tokio::test]
async fn a_vault_of_more_than_20_mib_is_rotated() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    // 24 entries of 1 MB each, written in batches below 16 MiB.
    let entries: Vec<String> = (0..24).map(|_| new_uuid()).collect();
    for chunk in entries.chunks(8) {
        let ops: Vec<Value> = chunk
            .iter()
            .map(|id| json!({ "op": "put", "id": id, "type": "entry", "key_version": 1, "expected_revision": null, "data": envelope(1_000_000) }))
            .collect();
        let response = t.batch(&alice, &vault_id, ops).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    }
    let objects = live(&t, &alice, &vault_id).await;
    assert_eq!(objects.len(), 27);
    let rotation_id = opened(&t, &alice, &vault_id).await;
    let uploads = reencrypted(&objects, 1_000_000);
    for chunk in uploads.chunks(10) {
        let response = t.call(upload(&alice, &vault_id, &rotation_id, chunk)).await;
        assert_eq!(
            response.status,
            StatusCode::NO_CONTENT,
            "{}",
            response.text()
        );
    }
    let response = t
        .call(
            commit(
                &t,
                &alice,
                &vault_id,
                &rotation_id,
                &commit_body(&[&bob], &[], &[]),
            )
            .await,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());

    let size = t
        .count(&format!(
            "SELECT SUM(size) FROM objects WHERE vault_id = '{vault_id}' AND key_version = 2"
        ))
        .await;
    assert!(size > 20 * 1024 * 1024, "{size}");
    let after = live(&t, &alice, &vault_id).await;
    assert_eq!(after.len(), 27);
    assert!(
        after
            .iter()
            .all(|o| o["key_version"] == 2 && o["revision"] == 5)
    );
    for object in &after {
        let uploaded = uploads.iter().find(|u| u["id"] == object["id"]).unwrap();
        assert_eq!(object["data"], uploaded["data"]);
    }
}

#[tokio::test]
async fn staged_objects_count_only_their_excess() {
    // The vault's three objects take 900 bytes.
    let t = TestApp::with_config("[limits]\nuser_quota_bytes = 1000\n").await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let objects = live(&t, &alice, &vault_id).await;
    let rotation_id = opened(&t, &alice, &vault_id).await;
    // A re-encryption has the same size and costs nothing.
    let response = t
        .call(upload(
            &alice,
            &vault_id,
            &rotation_id,
            &reencrypted(&objects, 300),
        ))
        .await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
    let one = |i: usize, len: usize| reencrypted(&objects[i..=i], len);
    // 80 bytes of excess fit, 50 more do not.
    assert_eq!(
        t.call(upload(&alice, &vault_id, &rotation_id, &one(0, 380)))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let response = t
        .call(upload(&alice, &vault_id, &rotation_id, &one(1, 350)))
        .await;
    assert_eq!(response.code(), "quota_exceeded");
    // Replacing the larger upload frees its excess.
    assert_eq!(
        t.call(upload(&alice, &vault_id, &rotation_id, &one(0, 300)))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        t.call(upload(&alice, &vault_id, &rotation_id, &one(1, 350)))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    // The open rotation's excess blocks this batch until it expires.
    let response = t
        .batch(&alice, &vault_id, vec![put_op(&new_uuid(), "entry", None)])
        .await;
    assert_eq!(response.code(), "quota_exceeded");
    t.advance(Duration::minutes(61));
    let alice = t.login(&alice).await;
    let response = t
        .batch(&alice, &vault_id, vec![put_op(&new_uuid(), "entry", None)])
        .await;
    assert_eq!(
        response.code(),
        "quota_exceeded",
        "900 + 300 is still too much"
    );
    let mut small = put_op(&new_uuid(), "entry", None);
    small["data"] = json!(envelope(100));
    let response = t.batch(&alice, &vault_id, vec![small]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
}

#[tokio::test]
async fn oversized_drop_tombstones_count_at_commit() {
    let t = TestApp::with_config("[limits]\nuser_quota_bytes = 1000\n").await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let objects = live(&t, &alice, &vault_id).await;
    let dropped = objects
        .iter()
        .find(|o| o["type"] == "group")
        .unwrap()
        .clone();
    let kept: Vec<Value> = objects
        .iter()
        .filter(|o| o["id"] != dropped["id"])
        .cloned()
        .collect();
    let rotation_id = opened(&t, &alice, &vault_id).await;
    let response = t
        .call(upload(
            &alice,
            &vault_id,
            &rotation_id,
            &reencrypted(&kept, 300),
        ))
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    let mut body = commit_body(&[], &[], &[]);
    // A 450-byte tombstone for a 300-byte object grows the usage by 150.
    body["drop_objects"] = json!([{ "id": dropped["id"], "data": envelope(450) }]);
    let response = t
        .call(commit(&t, &alice, &vault_id, &rotation_id, &body).await)
        .await;
    assert_eq!(response.code(), "quota_exceeded");
    body["drop_objects"] = json!([{ "id": dropped["id"], "data": envelope(256) }]);
    let response = t
        .call(commit(&t, &alice, &vault_id, &rotation_id, &body).await)
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
}

#[tokio::test]
async fn an_account_being_removed_writes_nothing_meanwhile() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.share(&alice, &vault_id, &carol).await;
    let base = revision(&t, &alice, &vault_id).await;
    let opening = t
        .call(open_removing(&alice, &vault_id, base, &[&bob]))
        .await;
    assert_eq!(opening.status, StatusCode::CREATED, "{}", opening.text());

    // Bob's batches would keep moving the revision and so block the commit.
    let key = new_uuid();
    let batch = || {
        Req::post(&format!("/v1/vaults/{vault_id}/batch"))
            .token(&bob.access_token)
            .idem(&key)
            .json(
                &json!({ "ops": [put_op("0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5c01", "entry", None)] }),
            )
    };
    let refused = t.call(batch()).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.code(), "rotation_in_progress");
    assert_eq!(revision(&t, &alice, &vault_id).await, base);
    // Attachments do not move the revision and stay allowed; others write.
    let other = t
        .batch(&carol, &vault_id, vec![put_op(&new_uuid(), "entry", None)])
        .await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.text());
    // The answer was not stored: once the rotation is over (here: expired),
    // the same request with the same key goes through.
    t.sql("UPDATE rotations SET expires_at = '2000-01-01T00:00:00.000Z'")
        .await;
    let later = t.call(batch()).await;
    assert_eq!(later.status, StatusCode::OK, "{}", later.text());
}

#[tokio::test]
async fn the_commit_removes_at_most_the_announced_accounts() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let dave = t.register("dave@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.share(&alice, &vault_id, &carol).await;
    t.share(&alice, &vault_id, &dave).await;
    let objects = live(&t, &alice, &vault_id).await;
    let uploads = reencrypted(&objects, 300);
    let rotation_id = opened_removing(&t, &alice, &vault_id, &[&bob, &dave]).await;
    t.call(upload(&alice, &vault_id, &rotation_id, &uploads))
        .await;
    // Carol was not announced.
    let foreign = t
        .call(
            commit(
                &t,
                &alice,
                &vault_id,
                &rotation_id,
                &commit_body(&[&dave], &[], &[&bob, &carol]),
            )
            .await,
        )
        .await;
    assert_eq!(foreign.status, StatusCode::BAD_REQUEST);
    assert_eq!(foreign.field_error().0, "/remove_user_ids/1");
    // Dave left in the meantime; a subset is enough.
    let left = t
        .call(Req::delete(&format!("/v1/vaults/{vault_id}/members/me")).token(&dave.access_token))
        .await;
    assert_eq!(left.status, StatusCode::NO_CONTENT, "{}", left.text());
    let done = t
        .call(
            commit(
                &t,
                &alice,
                &vault_id,
                &rotation_id,
                &commit_body(&[&carol], &[], &[&bob]),
            )
            .await,
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert!(t.listed(&bob, &vault_id).await.is_none());
}

#[tokio::test]
async fn opening_names_valid_accounts_to_remove() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    let base = revision(&t, &alice, &vault_id).await;
    let stored = t.count("SELECT COUNT(*) FROM idempotency").await;
    let open_with = |remove: Value| {
        Req::post(&format!("/v1/vaults/{vault_id}/rotations"))
            .token(&alice.access_token)
            .idem(&new_uuid())
            .json(
                &json!({ "base_revision": base, "new_key_version": 2, "remove_user_ids": remove }),
            )
    };
    for (remove, pointer) in [
        (json!([alice.user_id]), "/remove_user_ids/0"),
        (json!([bob.user_id, bob.user_id]), "/remove_user_ids/1"),
        (json!(vec![new_uuid(); 1001]), "/remove_user_ids"),
    ] {
        let response = t.call(open_with(remove)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{pointer}");
        assert_eq!(response.field_error().0, pointer);
    }
    assert_eq!(t.count("SELECT COUNT(*) FROM rotations").await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM idempotency").await, stored);
}

#[tokio::test]
async fn a_co_owner_being_removed_cannot_interfere() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.share(&alice, &vault_id, &carol).await;
    let promoted = t
        .call(
            t.role_change(&alice, &vault_id, &bob.user_id, "owner")
                .await,
        )
        .await;
    assert_eq!(
        promoted.status,
        StatusCode::NO_CONTENT,
        "{}",
        promoted.text()
    );
    let objects = live(&t, &alice, &vault_id).await;
    let rotation_id = opened_removing(&t, &alice, &vault_id, &[&bob]).await;

    // Bob can neither replace the rotation nor change roles meanwhile.
    let base = revision(&t, &bob, &vault_id).await;
    let replace = t.call(open(&bob, &vault_id, base, 2)).await;
    assert_eq!(replace.code(), "rotation_in_progress");
    let demote = t
        .call(
            t.role_change(&bob, &vault_id, &alice.user_id, "member")
                .await,
        )
        .await;
    assert_eq!(demote.code(), "rotation_in_progress");
    let appended = t
        .call(
            Req::post(&format!("/v1/vaults/{vault_id}/roles"))
                .token(&bob.access_token)
                .json(&json!({ "roles": support::roles::sign_bytes(&bob, b"x") })),
        )
        .await;
    assert_eq!(appended.code(), "rotation_in_progress");

    let uploads = reencrypted(&objects, 300);
    t.call(upload(&alice, &vault_id, &rotation_id, &uploads))
        .await;
    let done = t
        .call(
            commit(
                &t,
                &alice,
                &vault_id,
                &rotation_id,
                &commit_body(&[&carol], &[], &[&bob]),
            )
            .await,
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
}
