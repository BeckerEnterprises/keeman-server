//! `GET /v1/vaults/{id}/changes` and `POST /v1/vaults/{id}/batch`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::HashSet;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{Account, Req, TestApp, delete_op, envelope, new_uuid, put_op};

/// All pages of one sync; returns the objects and the last `vault_revision`.
async fn sync_all(
    t: &TestApp,
    account: &Account,
    vault_id: &str,
    since: i64,
    limit: usize,
) -> (Vec<Value>, i64, usize) {
    let mut objects = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let mut query = format!("since={since}&limit={limit}");
        if let Some(c) = &cursor {
            query.push_str(&format!("&cursor={c}"));
        }
        let response = t.changes(account, vault_id, &query).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        let page = response.json();
        pages += 1;
        objects.extend(page["objects"].as_array().unwrap().iter().cloned());
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => return (objects, page["vault_revision"].as_i64().unwrap(), pages),
        }
    }
}

fn ids(objects: &[Value]) -> Vec<String> {
    objects
        .iter()
        .map(|o| o["id"].as_str().unwrap().to_string())
        .collect()
}

async fn revision(t: &TestApp, vault_id: &str) -> i64 {
    t.count(&format!(
        "SELECT revision FROM vaults WHERE id = '{vault_id}'"
    ))
    .await
}

#[tokio::test]
async fn put_update_delete_and_changes() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let group = new_uuid();

    let response = t
        .batch(&alice, &vault_id, vec![put_op(&group, "group", None)])
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        response.json(),
        json!({ "vault_revision": 2, "results": [{ "id": group, "revision": 2 }] })
    );

    let page = t.changes(&alice, &vault_id, "since=1").await.json();
    assert_eq!(page["vault_revision"], 2);
    assert_eq!(page["key_version"], 1);
    assert_eq!(page["next_cursor"], Value::Null);
    let objects = page["objects"].as_array().unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0]["id"], group);
    assert_eq!(objects[0]["type"], "group");
    assert_eq!(objects[0]["revision"], 2);
    assert_eq!(objects[0]["deleted"], false);
    assert_eq!(objects[0]["updated_by"], alice.user_id);
    assert_eq!(objects[0]["updated_at"], "2026-10-23T08:00:00.000Z");
    assert_eq!(
        t.count(&format!("SELECT size FROM objects WHERE id = '{group}'"))
            .await,
        300
    );

    let update = put_op(&group, "group", Some(2));
    let response = t.batch(&alice, &vault_id, vec![update.clone()]).await;
    assert_eq!(response.json()["vault_revision"], 3);
    let tombstone = delete_op(&group, 3);
    let response = t.batch(&alice, &vault_id, vec![tombstone.clone()]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["vault_revision"], 4);

    let page = t.changes(&alice, &vault_id, "since=3").await.json();
    let objects = page["objects"].as_array().unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0]["deleted"], true);
    assert_eq!(objects[0]["data"], tombstone["data"]);
    assert_eq!(objects[0]["type"], "group");
    // The full state has no tombstones.
    let (full, revision, _) = sync_all(&t, &alice, &vault_id, 0, 500).await;
    assert_eq!(revision, 4);
    assert_eq!(full.len(), 3);
    assert!(!ids(&full).contains(&group));
    // `since` beyond the vault revision: empty page (the client's rollback
    // detection decides).
    let page = t.changes(&alice, &vault_id, "since=99").await.json();
    assert_eq!(page["objects"], json!([]));
    assert_eq!(page["vault_revision"], 4);
}

#[tokio::test]
async fn conflicts_are_complete_and_never_revive_tombstones() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let live = new_uuid();
    let gone = new_uuid();
    t.batch(
        &alice,
        &vault_id,
        vec![put_op(&live, "entry", None), put_op(&gone, "entry", None)],
    )
    .await;
    t.batch(&alice, &vault_id, vec![delete_op(&gone, 2)]).await;
    assert_eq!(revision(&t, &vault_id).await, 3);

    let missing = new_uuid();
    let fresh = new_uuid();
    let response = t
        .batch(
            &alice,
            &vault_id,
            vec![
                put_op(&fresh, "entry", None),
                put_op(&live, "entry", None),
                put_op(&gone, "entry", None),
                put_op(&missing, "entry", Some(1)),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "conflict");
    assert_eq!(
        response.json()["conflicts"],
        json!([
            { "id": live, "current_revision": 2, "deleted": false },
            { "id": gone, "current_revision": 3, "deleted": true },
            { "id": missing, "current_revision": null, "deleted": false },
        ])
    );
    // All or nothing.
    assert_eq!(revision(&t, &vault_id).await, 3);
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM objects WHERE id = '{fresh}'"
        ))
        .await,
        0
    );

    for op in [
        put_op(&gone, "entry", Some(3)),
        delete_op(&gone, 3),
        put_op(&live, "entry", Some(1)),
        delete_op(&live, 5),
        delete_op(&missing, 1),
    ] {
        let response = t.batch(&alice, &vault_id, vec![op.clone()]).await;
        assert_eq!(response.status, StatusCode::CONFLICT, "{op}");
        assert_eq!(response.code(), "conflict");
        assert_eq!(response.json()["conflicts"].as_array().unwrap().len(), 1);
    }
    assert_eq!(revision(&t, &vault_id).await, 3);
}

#[tokio::test]
async fn type_change_and_key_version_come_before_conflicts() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let entry = new_uuid();
    let gone = new_uuid();
    t.batch(
        &alice,
        &vault_id,
        vec![put_op(&entry, "entry", None), put_op(&gone, "group", None)],
    )
    .await;
    t.batch(&alice, &vault_id, vec![delete_op(&gone, 2)]).await;

    for (op, pointer) in [
        (put_op(&entry, "group", Some(2)), "/ops/1/type"),
        (put_op(&gone, "entry", None), "/ops/1/type"),
    ] {
        let response = t
            .batch(
                &alice,
                &vault_id,
                vec![put_op(&new_uuid(), "entry", Some(9)), op],
            )
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(response.field_error().0, pointer);
    }

    let mut stale = put_op(&entry, "entry", Some(1));
    stale["key_version"] = json!(2);
    let mut stale_delete = delete_op(&entry, 2);
    stale_delete["key_version"] = json!(2);
    for op in [stale, stale_delete] {
        let response = t.batch(&alice, &vault_id, vec![op]).await;
        assert_eq!(response.status, StatusCode::CONFLICT);
        assert_eq!(response.code(), "stale_key_version");
        assert_eq!(response.json()["current_key_version"], 1);
    }
}

#[tokio::test]
async fn batch_structure_is_checked_before_the_transaction() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let id = new_uuid();
    let mut no_expected = put_op(&id, "entry", None);
    no_expected
        .as_object_mut()
        .unwrap()
        .remove("expected_revision");
    let mut delete_with_type = delete_op(&id, 1);
    delete_with_type["type"] = json!("entry");
    let mut zero = delete_op(&id, 1);
    zero["expected_revision"] = json!(0);
    let mut delete_null = delete_op(&id, 1);
    delete_null["expected_revision"] = Value::Null;
    let mut unknown_op = put_op(&id, "entry", None);
    unknown_op["op"] = json!("move");
    let mut short = put_op(&id, "entry", None);
    short["data"] = json!(envelope(40));
    let cases = vec![
        vec![],
        vec![put_op(&id, "entry", None), put_op(&id, "entry", None)],
        vec![delete_op(&vault_id, 1)],
        vec![put_op(&new_uuid(), "vault_meta", Some(1))],
        vec![put_op(&vault_id, "group", Some(1))],
        vec![no_expected],
        vec![delete_with_type],
        vec![zero],
        vec![delete_null],
        vec![unknown_op],
        vec![short],
        (0..501)
            .map(|_| put_op(&new_uuid(), "entry", None))
            .collect(),
    ];
    for ops in cases {
        let response = t.batch(&alice, &vault_id, ops).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{}",
            response.text()
        );
        assert_eq!(response.code(), "validation_failed");
    }
    let mut huge = put_op(&id, "entry", None);
    huge["data"] = json!("A".repeat(1_572_865));
    let response = t.batch(&alice, &vault_id, vec![huge]).await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    let big = vec![b' '; 16 * 1024 * 1024 + 1];
    let response = t
        .call(
            Req::post(&format!("/v1/vaults/{vault_id}/batch"))
                .token(&alice.access_token)
                .idem(&new_uuid())
                .raw(Some("application/json"), &big),
        )
        .await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    // Bodies up to 16 MiB are accepted (above the default of 2 MiB).
    let ops: Vec<Value> = (0..3)
        .map(|_| {
            let mut op = put_op(&new_uuid(), "entry", None);
            op["data"] = json!(envelope(1_000_000));
            op
        })
        .collect();
    let response = t.batch(&alice, &vault_id, ops).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(t.count("SELECT COUNT(*) FROM idempotency").await, 2);
}

#[tokio::test]
async fn membership_is_checked_centrally() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let dave = t.register("dave@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.add_member(&vault_id, &bob, "member", "active").await;
    t.add_member(&vault_id, &carol, "member", "pending").await;

    for (account, status) in [
        (&dave, StatusCode::NOT_FOUND),
        (&carol, StatusCode::FORBIDDEN),
        (&bob, StatusCode::OK),
    ] {
        let response = t.changes(account, &vault_id, "since=0").await;
        assert_eq!(response.status, status, "changes {}", account.email);
        let response = t
            .batch(account, &vault_id, vec![put_op(&new_uuid(), "entry", None)])
            .await;
        assert_eq!(response.status, status, "batch {}", account.email);
    }
    let unknown = new_uuid();
    let response = t.changes(&alice, &unknown, "since=0").await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    let response = t
        .batch(&alice, &unknown, vec![put_op(&new_uuid(), "entry", None)])
        .await;
    assert_eq!(response.code(), "not_found");
}

#[tokio::test]
async fn idempotent_batches() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let path = format!("/v1/vaults/{vault_id}/batch");
    let key = new_uuid();
    let body = json!({ "ops": [put_op(&new_uuid(), "entry", None)] });
    let send = |key: &str, body: &Value| {
        Req::post(&path)
            .token(&alice.access_token)
            .idem(key)
            .json(body)
    };
    let first = t.call(send(&key, &body)).await;
    let second = t.call(send(&key, &body)).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body, second.body);
    assert_eq!(revision(&t, &vault_id).await, 2);

    let other = json!({ "ops": [put_op(&new_uuid(), "entry", None)] });
    let response = t.call(send(&key, &other)).await;
    assert_eq!(response.code(), "idempotency_key_reused");

    // A key used for another endpoint.
    let create_key = new_uuid();
    t.call(
        Req::post("/v1/vaults")
            .token(&alice.access_token)
            .idem(&create_key)
            .json(&support::vault_body(&alice, &new_uuid())),
    )
    .await;
    let response = t.call(send(&create_key, &body)).await;
    assert_eq!(response.code(), "idempotency_key_reused");

    // A stored conflict is replayed with a new instance.
    let key = new_uuid();
    let conflicting = json!({ "ops": [put_op(&new_uuid(), "entry", Some(7))] });
    let a = t.call(send(&key, &conflicting)).await;
    t.batch(&alice, &vault_id, vec![put_op(&new_uuid(), "entry", None)])
        .await;
    let b = t.call(send(&key, &conflicting)).await;
    assert_eq!(a.status, StatusCode::CONFLICT);
    assert_eq!(b.status, StatusCode::CONFLICT);
    assert_eq!(a.json()["conflicts"], b.json()["conflicts"]);
    assert_ne!(a.json()["instance"], b.json()["instance"]);
    assert_eq!(b.code(), "conflict");
}

#[tokio::test]
async fn full_sync_of_three_batches_with_small_pages() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let mut expected: HashSet<String> = ids(&sync_all(&t, &alice, &vault_id, 0, 500).await.0)
        .into_iter()
        .collect();
    for _ in 0..3 {
        let ops: Vec<Value> = (0..500)
            .map(|_| put_op(&new_uuid(), "entry", None))
            .collect();
        for op in &ops {
            expected.insert(op["id"].as_str().unwrap().to_string());
        }
        let response = t.batch(&alice, &vault_id, ops).await;
        assert_eq!(response.status, StatusCode::OK);
    }
    let (objects, revision, pages) = sync_all(&t, &alice, &vault_id, 0, 100).await;
    assert_eq!(revision, 4);
    assert_eq!(pages, 16);
    let got = ids(&objects);
    assert_eq!(got.len(), 1503, "no duplicates");
    assert_eq!(got.iter().cloned().collect::<HashSet<_>>(), expected);
    // Ordered by (revision, id).
    let keys: Vec<(i64, String)> = objects
        .iter()
        .map(|o| {
            (
                o["revision"].as_i64().unwrap(),
                o["id"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[tokio::test]
async fn changes_while_paging_arrive_later_or_by_delta() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let ops: Vec<Value> = (0..10)
        .map(|_| put_op(&new_uuid(), "entry", None))
        .collect();
    t.batch(&alice, &vault_id, ops).await;

    let first = t.changes(&alice, &vault_id, "since=0&limit=5").await.json();
    let first_revision = first["vault_revision"].as_i64().unwrap();
    let delivered: Vec<String> = ids(first["objects"].as_array().unwrap());
    let cursor = first["next_cursor"].as_str().unwrap().to_string();
    // Between the pages: one delivered object changes, another is deleted.
    let changed = delivered[3].clone();
    let deleted = delivered[4].clone();
    let rev = |id: &str| {
        first["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == id)
            .unwrap()["revision"]
            .as_i64()
            .unwrap()
    };
    let response = t
        .batch(
            &alice,
            &vault_id,
            vec![
                put_op(&changed, "entry", Some(rev(&changed))),
                delete_op(&deleted, rev(&deleted)),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let mut rest = Vec::new();
    let mut cursor = Some(cursor);
    while let Some(c) = cursor {
        let page = t
            .changes(&alice, &vault_id, &format!("since=0&limit=5&cursor={c}"))
            .await
            .json();
        rest.extend(page["objects"].as_array().unwrap().iter().cloned());
        cursor = page["next_cursor"].as_str().map(str::to_string);
    }
    let rest_ids = ids(&rest);
    assert!(rest_ids.contains(&changed), "the change arrives again");
    assert!(!rest_ids.contains(&deleted), "since=0 has no tombstones");
    // The follow-up delta from the first page's revision brings the deletion.
    let (delta, _, _) = sync_all(&t, &alice, &vault_id, first_revision, 500).await;
    assert!(
        delta
            .iter()
            .any(|o| o["id"] == deleted.as_str() && o["deleted"] == true)
    );
}

#[tokio::test]
async fn pages_end_at_the_size_budget() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let before = sync_all(&t, &alice, &vault_id, 1, 1000).await.0.len();
    assert_eq!(before, 0);
    // 1,000,000 bytes are 1,333,334 characters: three fit into 4 MiB.
    let ops: Vec<Value> = (0..7)
        .map(|_| {
            let mut op = put_op(&new_uuid(), "entry", None);
            op["data"] = json!(envelope(1_000_000));
            op
        })
        .collect();
    let response = t.batch(&alice, &vault_id, ops).await;
    assert_eq!(response.status, StatusCode::OK);
    let mut sizes = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let query = match &cursor {
            Some(c) => format!("since=1&limit=1000&cursor={c}"),
            None => "since=1&limit=1000".to_string(),
        };
        let page = t.changes(&alice, &vault_id, &query).await.json();
        sizes.push(page["objects"].as_array().unwrap().len());
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(sizes, vec![3, 3, 1]);
}

#[tokio::test]
async fn query_parameters_are_strict() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let other = t.create_vault(&alice).await;
    let ops: Vec<Value> = (0..3).map(|_| put_op(&new_uuid(), "entry", None)).collect();
    t.batch(&alice, &vault_id, ops).await;
    let page = t.changes(&alice, &vault_id, "since=1&limit=1").await.json();
    let cursor = page["next_cursor"].as_str().unwrap().to_string();
    let other_cursor = t.changes(&alice, &other, "since=0&limit=1").await.json()["next_cursor"]
        .as_str()
        .unwrap()
        .to_string();

    for (query, parameter) in [
        ("", "since"),
        ("since=01", "since"),
        ("since=-1", "since"),
        ("since=%31", "since"),
        ("since=9007199254740992", "since"),
        ("since=0&limit=0", "limit"),
        ("since=0&limit=1001", "limit"),
        ("since=0&limit=ten", "limit"),
        ("since=0&cursor=abc!", "cursor"),
        (&format!("since=0&cursor={cursor}"), "cursor"),
        (&format!("since=1&cursor={other_cursor}"), "cursor"),
        ("since=0&since=1", "since"),
        ("since=0&other=1", "query"),
    ] {
        let response = t.changes(&alice, &vault_id, query).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(response.field_error().0, parameter, "{query}");
    }
    let response = t
        .changes(
            &alice,
            &vault_id,
            &format!("since=1&limit=1&cursor={cursor}"),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let response = t.changes(&alice, "NOT-A-UUID", "since=0").await;
    assert_eq!(response.field_error().0, "vault_id");
}

#[tokio::test]
async fn purged_tombstones_require_a_resync_on_every_page() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    for _ in 0..6 {
        t.batch(&alice, &vault_id, vec![put_op(&new_uuid(), "entry", None)])
            .await;
    }
    t.sql(&format!(
        "UPDATE vaults SET tombstone_horizon = 5 WHERE id = '{vault_id}'"
    ))
    .await;
    for (since, status) in [
        (3, StatusCode::GONE),
        (4, StatusCode::GONE),
        (5, StatusCode::OK),
        (0, StatusCode::OK),
    ] {
        let response = t
            .changes(&alice, &vault_id, &format!("since={since}"))
            .await;
        assert_eq!(response.status, status, "since={since}");
        if status == StatusCode::GONE {
            assert_eq!(response.code(), "resync_required");
        }
    }
    // The horizon rises while paging.
    let page = t.changes(&alice, &vault_id, "since=5&limit=1").await.json();
    let cursor = page["next_cursor"].as_str().unwrap().to_string();
    t.sql(&format!(
        "UPDATE vaults SET tombstone_horizon = 6 WHERE id = '{vault_id}'"
    ))
    .await;
    let response = t
        .changes(
            &alice,
            &vault_id,
            &format!("since=5&limit=1&cursor={cursor}"),
        )
        .await;
    assert_eq!(response.status, StatusCode::GONE);
}

#[tokio::test]
async fn cleanup_purges_old_tombstones_and_raises_the_horizon() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let (a, b) = (new_uuid(), new_uuid());
    t.batch(
        &alice,
        &vault_id,
        vec![put_op(&a, "entry", None), put_op(&b, "entry", None)],
    )
    .await;
    t.batch(&alice, &vault_id, vec![delete_op(&a, 2)]).await;
    t.advance(time::Duration::days(100));
    let alice = t.login(&alice).await;
    t.batch(&alice, &vault_id, vec![delete_op(&b, 2)]).await;
    t.advance(time::Duration::days(81));
    let alice = t.login(&alice).await;
    let removed = keeman_server::jobs::cleanup(&t.app).await.unwrap();
    assert_eq!(removed.tombstones, 1, "only the one older than 180 days");
    assert_eq!(
        t.count(&format!(
            "SELECT tombstone_horizon FROM vaults WHERE id = '{vault_id}'"
        ))
        .await,
        3
    );
    assert_eq!(
        t.changes(&alice, &vault_id, "since=2").await.status,
        StatusCode::GONE
    );
    let page = t.changes(&alice, &vault_id, "since=3").await.json();
    assert_eq!(page["objects"][0]["id"], b.as_str());
    // The purged ID no longer exists and can be created again.
    let response = t
        .batch(&alice, &vault_id, vec![put_op(&a, "entry", None)])
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
}

#[tokio::test]
async fn cleanup_works_in_blocks() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.sql(&format!(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2500)
         INSERT INTO objects (vault_id, id, type, revision, key_version, deleted, size, updated_at, updated_by, data)
         SELECT '{vault_id}', printf('00000000-0000-7000-8000-%012d', i), 'entry', 1 + i, 1, 1, 41,
                '2020-01-01T00:00:00.000Z', '{}', X'01' FROM n",
        alice.user_id
    ))
    .await;
    let removed = keeman_server::jobs::cleanup(&t.app).await.unwrap();
    assert_eq!(removed.tombstones, 2500);
    assert_eq!(
        t.count(&format!(
            "SELECT tombstone_horizon FROM vaults WHERE id = '{vault_id}'"
        ))
        .await,
        2501
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM objects WHERE deleted = 1")
            .await,
        0
    );
}

#[tokio::test]
async fn idempotency_records_expire_after_a_day() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let body = support::vault_body(&alice, &new_uuid());
    let key = new_uuid();
    let send = || {
        Req::post("/v1/vaults")
            .token(&alice.access_token)
            .idem(&key)
            .json(&body)
    };
    assert_eq!(t.call(send()).await.status, StatusCode::CREATED);
    t.advance(time::Duration::hours(23));
    assert_eq!(
        keeman_server::jobs::cleanup(&t.app)
            .await
            .unwrap()
            .idempotency,
        0
    );
    let alice = t.login(&alice).await;
    let send = || {
        Req::post("/v1/vaults")
            .token(&alice.access_token)
            .idem(&key)
            .json(&body)
    };
    assert_eq!(t.call(send()).await.status, StatusCode::CREATED);
    t.advance(time::Duration::hours(2));
    assert_eq!(
        keeman_server::jobs::cleanup(&t.app)
            .await
            .unwrap()
            .idempotency,
        1
    );
    // Now the repetition acts again and meets the existing vault.
    let alice = t.login(&alice).await;
    let response = t
        .call(
            Req::post("/v1/vaults")
                .token(&alice.access_token)
                .idem(&key)
                .json(&body),
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "conflict");
}

#[tokio::test]
async fn a_replay_survives_a_lost_membership() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let dave = t.register("dave@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let other = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    let send = |account: &Account, vault: &str, key: &str, body: &Value| {
        Req::post(&format!("/v1/vaults/{vault}/batch"))
            .token(&account.access_token)
            .idem(key)
            .json(body)
    };
    let key = new_uuid();
    let body = json!({ "ops": [put_op(&new_uuid(), "entry", None)] });
    let first = t.call(send(&bob, &vault_id, &key, &body)).await;
    assert_eq!(first.status, StatusCode::OK);
    t.sql(&format!(
        "DELETE FROM memberships WHERE user_id = '{}'",
        bob.user_id
    ))
    .await;

    // The stored answer is still returned to the former member.
    let again = t.call(send(&bob, &vault_id, &key, &body)).await;
    assert_eq!((again.status, again.json()), (first.status, first.json()));
    let changed = json!({ "ops": [put_op(&new_uuid(), "entry", None)] });
    let response = t.call(send(&bob, &vault_id, &key, &changed)).await;
    assert_eq!(response.code(), "idempotency_key_reused");
    // A new key, or the key on another endpoint, gets the pre-check's 404.
    let response = t.call(send(&bob, &vault_id, &new_uuid(), &body)).await;
    assert_eq!(response.code(), "not_found");
    let response = t.call(send(&bob, &other, &key, &body)).await;
    assert_eq!(response.code(), "not_found");

    // Answers of the pre-check are not stored under the key.
    let late = new_uuid();
    let fresh = json!({ "ops": [put_op(&new_uuid(), "entry", None)] });
    let response = t.call(send(&dave, &vault_id, &late, &fresh)).await;
    assert_eq!(response.code(), "not_found");
    t.add_member(&vault_id, &dave, "member", "active").await;
    let response = t.call(send(&dave, &vault_id, &late, &fresh)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
}

#[tokio::test]
async fn stored_answers_stay_within_the_budget_of_the_account() {
    let t = TestApp::with_config(
        "[limits]\nidempotency_entries_per_account = 10\nidempotency_bytes_per_account = 1048576\n",
    )
    .await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let bobs_vault = t.create_vault(&bob).await;
    let send = |account: &support::Account, vault: &str, key: &str, body: &Value| {
        Req::post(&format!("/v1/vaults/{vault}/batch"))
            .token(&account.access_token)
            .idem(key)
            .json(body)
    };
    let rows = |user: &str| format!("SELECT COUNT(*) FROM idempotency WHERE user_id = '{user}'");

    // Rows: the oldest give way, the newest replays.
    let keys: Vec<String> = (0..12).map(|_| new_uuid()).collect();
    let bodies: Vec<Value> = keys
        .iter()
        .map(|_| json!({ "ops": [put_op(&new_uuid(), "entry", None)] }))
        .collect();
    for (key, body) in keys.iter().zip(&bodies) {
        assert_eq!(
            t.call(send(&alice, &vault_id, key, body)).await.status,
            StatusCode::OK
        );
    }
    assert_eq!(t.count(&rows(&alice.user_id)).await, 10);
    let newest = t
        .call(send(&alice, &vault_id, &keys[11], &bodies[11]))
        .await;
    assert_eq!(newest.status, StatusCode::OK);
    assert_eq!(
        revision(&t, &vault_id).await,
        13,
        "a replay changes nothing"
    );
    // An answer that gave way: the batch acts again and conflicts.
    let evicted = t.call(send(&alice, &vault_id, &keys[0], &bodies[0])).await;
    assert_eq!(evicted.code(), "conflict");

    // Each account has its own budget.
    let key = new_uuid();
    let body = json!({ "ops": [put_op(&new_uuid(), "entry", None)] });
    t.call(send(&bob, &bobs_vault, &key, &body)).await;
    assert_eq!(
        t.count(&rows(&bob.user_id)).await,
        2,
        "vault creation and batch"
    );
}

#[tokio::test]
async fn large_stored_answers_give_way_by_size() {
    let t = TestApp::with_config("[limits]\nidempotency_bytes_per_account = 1048576\n").await;
    let alice = t.register("alice@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let send = |key: &str, body: &Value| {
        Req::post(&format!("/v1/vaults/{vault_id}/batch"))
            .token(&alice.access_token)
            .idem(key)
            .json(body)
    };
    // 500 conflicts make an answer of about 43 KB, without any data growing.
    let conflicts = json!({
        "ops": (0..500).map(|_| put_op(&new_uuid(), "entry", Some(7))).collect::<Vec<_>>()
    });
    let mut last = String::new();
    for _ in 0..30 {
        last = new_uuid();
        assert_eq!(t.call(send(&last, &conflicts)).await.code(), "conflict");
    }
    let stored = t
        .count(&format!(
            "SELECT SUM(length(response)) FROM idempotency WHERE user_id = '{}'",
            alice.user_id
        ))
        .await;
    assert!(stored <= 1_048_576, "{stored} bytes stored");
    assert!(stored > 900_000, "{stored} bytes stored");
    let rows = t
        .count(&format!(
            "SELECT COUNT(*) FROM idempotency WHERE user_id = '{}'",
            alice.user_id
        ))
        .await;
    assert!(rows < 30, "{rows} rows");
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM idempotency WHERE user_id = '{}' AND key = '{last}'",
            alice.user_id
        ))
        .await,
        1,
        "the newest answer stays"
    );
}
