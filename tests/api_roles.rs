//! The owner-signed roles chain: reading it, appending statements, the
//! checks of every new statement (head, signer, signature, owners, keys,
//! key version), the rules for leaving and the stored answers.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use keeman_server::roles::{Statement, encode, hash};
use serde_json::{Value, json};
use support::roles::{genesis, owner, rotated, sign_bytes, sign_small_r, signed, successor};
use support::{Account, Req, TestApp, envelope, key_box, new_uuid, vault_body};

fn chain(account: &Account, vault_id: &str, query: &str) -> Req {
    Req::get(&format!("/v1/vaults/{vault_id}/roles{query}")).token(&account.access_token)
}

fn append(account: &Account, vault_id: &str, roles: &Value) -> Req {
    Req::post(&format!("/v1/vaults/{vault_id}/roles"))
        .token(&account.access_token)
        .json(&json!({ "roles": roles }))
}

fn patch(account: &Account, vault_id: &str, user_id: &str, role: &str, roles: &Value) -> Req {
    Req::new("PATCH", &format!("/v1/vaults/{vault_id}/members/{user_id}"))
        .token(&account.access_token)
        .json(&json!({ "role": role, "roles": roles }))
}

fn leave(account: &Account, vault_id: &str) -> Req {
    Req::delete(&format!("/v1/vaults/{vault_id}/members/me")).token(&account.access_token)
}

/// A vault of Alice shared with Bob (member) and the chain head.
async fn shared(t: &TestApp, alice: &Account, bob: &Account) -> (String, Statement) {
    let vault_id = t.create_vault(alice).await;
    t.share(alice, &vault_id, bob).await;
    let head = t.roles_head(alice, &vault_id).await.unwrap();
    (vault_id, head)
}

async fn head_version(t: &TestApp, account: &Account, vault_id: &str) -> i64 {
    t.listed(account, vault_id).await.unwrap()["roles_version"]
        .as_i64()
        .unwrap_or(0)
}

/// Makes the vault one from before the roles chain.
async fn without_chain(t: &TestApp, vault_id: &str) {
    t.sql(&format!(
        "DELETE FROM vault_roles WHERE vault_id = '{vault_id}'"
    ))
    .await;
}

#[tokio::test]
async fn the_chain_starts_with_the_vault_and_is_read_from_a_version() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let mallory = t.register("mallory@example.com").await;
    let (vault_id, first) = shared(&t, &alice, &bob).await;
    assert_eq!(first.version, 1);
    assert_eq!(first.previous, None);
    assert_eq!(first.key_version, 1);
    assert_eq!(first.owners, vec![owner(&alice)]);
    assert_eq!(first.signer, alice.user_id);
    assert_eq!(head_version(&t, &alice, &vault_id).await, 1);

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
    let all = t.call(chain(&bob, &vault_id, "")).await.json();
    let statements = all["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 2);
    assert_eq!(statements[0]["version"], 1);
    assert_eq!(statements[1]["version"], 2);
    let second = support::roles::read(&statements[1]);
    assert_eq!(second.previous, Some(hash(&encode(&first))));
    assert_eq!(second.key_commitment, first.key_commitment);
    assert_eq!(head_version(&t, &bob, &vault_id).await, 2);

    let tail = t.call(chain(&alice, &vault_id, "?since=1")).await.json();
    assert_eq!(tail["statements"].as_array().unwrap().len(), 1);
    let none = t.call(chain(&alice, &vault_id, "?since=2")).await.json();
    assert_eq!(none, json!({ "statements": [] }));
    for query in [
        "?since=-1",
        "?since=01",
        "?since=x",
        "?since=1&since=1",
        "?other=1",
    ] {
        let response = t.call(chain(&alice, &vault_id, query)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{query}");
    }

    // Invitees read it before they accept; outsiders do not.
    t.invite_member(&alice, &vault_id, &carol).await;
    let pending = t.call(chain(&carol, &vault_id, "")).await;
    assert_eq!(pending.status, StatusCode::OK);
    assert_eq!(pending.json()["statements"].as_array().unwrap().len(), 2);
    assert_eq!(
        t.call(chain(&mallory, &vault_id, "")).await.code(),
        "not_found"
    );
    let changed = t
        .count("SELECT COUNT(*) FROM security_log WHERE event = 'roles_changed'")
        .await;
    assert_eq!(changed, 2);
    let detail = t
        .text(&format!(
            "SELECT detail FROM security_log WHERE event = 'roles_changed' AND vault_id = '{vault_id}' ORDER BY id DESC LIMIT 1"
        ))
        .await;
    assert_eq!(
        serde_json::from_str::<Value>(&detail).unwrap(),
        json!({ "version": 2, "signer": alice.user_id })
    );
}

#[tokio::test]
async fn vault_creation_needs_the_creator_as_only_signed_owner() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let create = |key: &str, body: &Value| {
        Req::post("/v1/vaults")
            .token(&alice.access_token)
            .idem(key)
            .json(body)
    };
    let vault_id = new_uuid();
    let mut body = vault_body(&alice, &vault_id);
    let cases: Vec<(&str, Statement, &Account, &str)> = vec![
        (
            "another vault",
            genesis(&new_uuid(), vec![owner(&alice)], &alice.user_id, 1),
            &alice,
            "roles_conflict",
        ),
        (
            "a second statement",
            Statement {
                version: 2,
                previous: Some([1; 32]),
                ..genesis(&vault_id, vec![owner(&alice)], &alice.user_id, 1)
            },
            &alice,
            "roles_conflict",
        ),
        (
            "another owner",
            genesis(
                &vault_id,
                vec![owner(&alice), owner(&bob)],
                &alice.user_id,
                1,
            ),
            &alice,
            "validation_failed",
        ),
        (
            "another signer",
            genesis(&vault_id, vec![owner(&bob)], &bob.user_id, 1),
            &bob,
            "validation_failed",
        ),
        (
            "key version 2",
            genesis(&vault_id, vec![owner(&alice)], &alice.user_id, 2),
            &alice,
            "validation_failed",
        ),
    ];
    for (what, statement, signer, code) in cases {
        body["roles"] = signed(signer, &statement);
        let key = new_uuid();
        let response = t.call(create(&key, &body)).await;
        assert_eq!(response.code(), code, "{what}: {}", response.text());
        // Final answers of the statement check are stored.
        let again = t.call(create(&key, &body)).await;
        assert_eq!(again.code(), code, "{what}");
    }
    // Signed with a key other than the one the statement names.
    let first = genesis(&vault_id, vec![owner(&alice)], &alice.user_id, 1);
    body["roles"] = sign_bytes(&bob, &encode(&first));
    assert_eq!(
        t.call(create(&new_uuid(), &body)).await.code(),
        "validation_failed"
    );
    // Not canonical: stored as well.
    let spaced = String::from_utf8(encode(&first))
        .unwrap()
        .replacen(',', ", ", 1);
    body["roles"] = sign_bytes(&alice, spaced.as_bytes());
    let key = new_uuid();
    let response = t.call(create(&key, &body)).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.field_error().0, "/roles");
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM idempotency WHERE key = '{key}'"
        ))
        .await,
        1
    );
    // A signature of the wrong length is structural and not stored.
    body["roles"] = json!({ "statement": signed(&alice, &first)["statement"], "signature": support::random_b64::<63>() });
    let key = new_uuid();
    let response = t.call(create(&key, &body)).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM idempotency WHERE key = '{key}'"
        ))
        .await,
        0
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM vaults").await, 0);

    // An account without a signing key cannot create a vault.
    t.sql(&format!(
        "UPDATE users SET signing_public_key = NULL WHERE id = '{}'",
        alice.user_id
    ))
    .await;
    body["roles"] = signed(&alice, &first);
    let key = new_uuid();
    assert_eq!(
        t.call(create(&key, &body)).await.code(),
        "signing_key_missing"
    );
    assert_eq!(
        t.call(create(&key, &body)).await.code(),
        "signing_key_missing"
    );
    let missing = vault_body(&alice, &vault_id);
    let mut without = missing.clone();
    without.as_object_mut().unwrap().remove("roles");
    let response = t.call(create(&new_uuid(), &without)).await;
    assert_eq!(response.field_error().0, "/roles");
}

#[tokio::test]
async fn role_changes_follow_the_head_once() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let (vault_id, head) = shared(&t, &alice, &bob).await;
    t.share(&alice, &vault_id, &carol).await;

    // Two owners' changes built on the same head: exactly one wins.
    let with_bob = signed(
        &alice,
        &successor(&head, vec![owner(&alice), owner(&bob)], &alice.user_id),
    );
    let with_carol = signed(
        &alice,
        &successor(&head, vec![owner(&alice), owner(&carol)], &alice.user_id),
    );
    let first = t.spawn(patch(&alice, &vault_id, &bob.user_id, "owner", &with_bob).build());
    let second = t.spawn(patch(&alice, &vault_id, &carol.user_id, "owner", &with_carol).build());
    let (first, second) = (first.await.unwrap(), second.await.unwrap());
    let (won, lost) = if first.status == StatusCode::NO_CONTENT {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(won.status, StatusCode::NO_CONTENT, "{}", won.text());
    assert_eq!(lost.status, StatusCode::CONFLICT, "{}", lost.text());
    assert_eq!(lost.code(), "roles_conflict");
    assert_eq!(lost.json()["current_roles_version"], 2);
    assert_eq!(head_version(&t, &alice, &vault_id).await, 2);
    // The loser left the roles unchanged.
    let owners = t.owners_after(&alice, &vault_id, &[]).await;
    assert_eq!(owners.len(), 2);

    // The loser's statement stays stale; sent again it conflicts again.
    let bob_won = t
        .owners_after(&alice, &vault_id, &[])
        .await
        .contains(&owner(&bob));
    let stale = if bob_won {
        patch(&alice, &vault_id, &carol.user_id, "owner", &with_carol)
    } else {
        patch(&alice, &vault_id, &bob.user_id, "owner", &with_bob)
    };
    let again = t.call(stale).await;
    assert_eq!(again.code(), "roles_conflict");
}

#[tokio::test]
async fn statements_name_the_owners_with_their_registered_keys() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let (vault_id, head) = shared(&t, &alice, &bob).await;
    t.share(&alice, &vault_id, &carol).await;
    let promote = |roles: Value| patch(&alice, &vault_id, &bob.user_id, "owner", &roles);
    let mut forged = owner(&bob);
    forged.public_key = [9; 32];
    let mut other_signing = owner(&bob);
    other_signing.signing_key = owner(&carol).signing_key;
    for (what, owners) in [
        ("missing the new owner", vec![owner(&alice)]),
        (
            "an extra owner",
            vec![owner(&alice), owner(&bob), owner(&carol)],
        ),
        ("another public key", vec![owner(&alice), forged]),
        ("another signing key", vec![owner(&alice), other_signing]),
    ] {
        let roles = signed(&alice, &successor(&head, owners, &alice.user_id));
        let response = t.call(promote(roles)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{what}");
        assert_eq!(response.field_error().0, "/roles", "{what}");
    }
    // Signed by Bob, who is not an owner of the head; by Alice for Bob.
    let as_bob = signed(
        &bob,
        &successor(&head, vec![owner(&alice), owner(&bob)], &bob.user_id),
    );
    assert_eq!(t.call(promote(as_bob)).await.code(), "validation_failed");
    let alice_key_bob_signer = sign_bytes(
        &alice,
        &encode(&successor(
            &head,
            vec![owner(&alice), owner(&bob)],
            &bob.user_id,
        )),
    );
    assert_eq!(
        t.call(promote(alice_key_bob_signer)).await.code(),
        "validation_failed"
    );
    // A tampered signature, a changed commitment, a key change.
    let good = successor(&head, vec![owner(&alice), owner(&bob)], &alice.user_id);
    let mut tampered = signed(&alice, &good);
    let other = signed(
        &alice,
        &Statement {
            created: "2026-10-24T00:00:00.000Z".into(),
            ..good.clone()
        },
    );
    tampered["signature"] = other["signature"].clone();
    assert_eq!(t.call(promote(tampered)).await.code(), "validation_failed");
    // A signature with R of small order: ring alone would take it, every
    // client refuses it, and the vault would be stuck with that head.
    let small_r = sign_small_r(&alice, &encode(&good));
    let response = t.call(promote(small_r)).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.field_error().0, "/roles");
    let recommitted = Statement {
        key_commitment: [3; 32],
        ..good.clone()
    };
    assert_eq!(
        t.call(promote(signed(&alice, &recommitted))).await.code(),
        "validation_failed"
    );
    let rekeyed = rotated(&head, vec![owner(&alice), owner(&bob)], &alice.user_id);
    assert_eq!(
        t.call(promote(signed(&alice, &rekeyed))).await.code(),
        "validation_failed"
    );
    assert_eq!(head_version(&t, &alice, &vault_id).await, 1);
    // An owner the server added outside the chain cannot sign.
    t.sql(&format!(
        "UPDATE memberships SET role = 'owner' WHERE vault_id = '{vault_id}' AND user_id = '{}'",
        carol.user_id
    ))
    .await;
    let by_carol = signed(
        &carol,
        &successor(
            &head,
            vec![owner(&alice), owner(&bob), owner(&carol)],
            &carol.user_id,
        ),
    );
    assert_eq!(
        t.call(patch(&carol, &vault_id, &bob.user_id, "owner", &by_carol))
            .await
            .code(),
        "validation_failed"
    );
    t.sql(&format!(
        "UPDATE memberships SET role = 'member' WHERE vault_id = '{vault_id}' AND user_id = '{}'",
        carol.user_id
    ))
    .await;
    let response = t.call(promote(signed(&alice, &good))).await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
}

#[tokio::test]
async fn role_changes_need_a_statement_once_there_is_a_chain() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let (vault_id, head) = shared(&t, &alice, &bob).await;
    let plain = |user_id: &str, role: &str| {
        Req::new("PATCH", &format!("/v1/vaults/{vault_id}/members/{user_id}"))
            .token(&alice.access_token)
            .json(&json!({ "role": role }))
    };
    assert_eq!(
        t.call(plain(&bob.user_id, "owner")).await.code(),
        "roles_required"
    );
    // The same role again needs nothing.
    assert_eq!(
        t.call(plain(&alice.user_id, "owner")).await.status,
        StatusCode::NO_CONTENT
    );
    // `null` is not a missing statement.
    let null = t
        .call(
            Req::new(
                "PATCH",
                &format!("/v1/vaults/{vault_id}/members/{}", bob.user_id),
            )
            .token(&alice.access_token)
            .json(&json!({ "role": "owner", "roles": null })),
        )
        .await;
    assert_eq!(null.status, StatusCode::BAD_REQUEST);

    // Promoting an account without a signing key.
    t.share(&alice, &vault_id, &carol).await;
    t.sql(&format!(
        "UPDATE users SET signing_public_key = NULL WHERE id = '{}'",
        carol.user_id
    ))
    .await;
    assert_eq!(
        t.call(plain(&carol.user_id, "owner")).await.code(),
        "signing_key_missing"
    );

    // A vault from before the chain: no statement, and none accepted.
    without_chain(&t, &vault_id).await;
    let roles = signed(
        &alice,
        &successor(&head, vec![owner(&alice), owner(&bob)], &alice.user_id),
    );
    let refused = t
        .call(patch(&alice, &vault_id, &bob.user_id, "owner", &roles))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.field_error().0, "/roles");
    assert_eq!(
        t.call(plain(&carol.user_id, "owner")).await.code(),
        "signing_key_missing"
    );
    assert_eq!(
        t.call(plain(&bob.user_id, "owner")).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(head_version(&t, &alice, &vault_id).await, 0);
}

#[tokio::test]
async fn older_vaults_get_their_first_statement_and_departed_owners_are_dropped() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let (vault_id, _) = shared(&t, &alice, &bob).await;
    t.share(&alice, &vault_id, &carol).await;
    without_chain(&t, &vault_id).await;
    t.call(
        t.role_change(&alice, &vault_id, &bob.user_id, "owner")
            .await,
    )
    .await;

    // The first statement names every active owner, with the current key.
    let both = genesis(
        &vault_id,
        vec![owner(&alice), owner(&bob)],
        &alice.user_id,
        1,
    );
    let alone = genesis(&vault_id, vec![owner(&alice)], &alice.user_id, 1);
    let response = t
        .call(append(&alice, &vault_id, &signed(&alice, &alone)))
        .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    let by_member = t
        .call(append(&carol, &vault_id, &signed(&carol, &alone)))
        .await;
    assert_eq!(by_member.code(), "forbidden");
    let response = t
        .call(append(&alice, &vault_id, &signed(&alice, &both)))
        .await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
    assert_eq!(head_version(&t, &carol, &vault_id).await, 1);
    let again = t
        .call(append(&alice, &vault_id, &signed(&alice, &both)))
        .await;
    assert_eq!(again.code(), "roles_conflict");
    assert_eq!(again.json()["current_roles_version"], 1);

    // Bob is gone without demoting himself (an older client): Alice drops him.
    t.sql(&format!(
        "DELETE FROM memberships WHERE vault_id = '{vault_id}' AND user_id = '{}'",
        bob.user_id
    ))
    .await;
    let head = t.roles_head(&alice, &vault_id).await.unwrap();
    let rekeyed = rotated(&head, vec![owner(&alice)], &alice.user_id);
    assert_eq!(
        t.call(append(&alice, &vault_id, &signed(&alice, &rekeyed)))
            .await
            .code(),
        "validation_failed"
    );
    let kept = successor(&head, vec![owner(&alice), owner(&bob)], &alice.user_id);
    assert_eq!(
        t.call(append(&alice, &vault_id, &signed(&alice, &kept)))
            .await
            .code(),
        "validation_failed"
    );
    let dropped = successor(&head, vec![owner(&alice)], &alice.user_id);
    let response = t
        .call(append(&alice, &vault_id, &signed(&alice, &dropped)))
        .await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
    assert_eq!(head_version(&t, &alice, &vault_id).await, 2);
    // A first statement while some owner has no signing key yet.
    let other = t.create_vault(&alice).await;
    t.share(&alice, &other, &carol).await;
    without_chain(&t, &other).await;
    t.sql(&format!(
        "UPDATE memberships SET role = 'owner' WHERE vault_id = '{other}' AND user_id = '{}'",
        carol.user_id
    ))
    .await;
    t.sql(&format!(
        "UPDATE users SET signing_public_key = NULL WHERE id = '{}'",
        carol.user_id
    ))
    .await;
    let first = genesis(
        &other,
        vec![owner(&alice), owner(&carol)],
        &alice.user_id,
        1,
    );
    assert_eq!(
        t.call(append(&alice, &other, &signed(&alice, &first)))
            .await
            .code(),
        "signing_key_missing"
    );
}

#[tokio::test]
async fn owners_of_a_signed_list_demote_themselves_before_they_go() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let (vault_id, _) = shared(&t, &alice, &bob).await;
    t.call(
        t.role_change(&alice, &vault_id, &bob.user_id, "owner")
            .await,
    )
    .await;
    assert_eq!(
        t.call(leave(&bob, &vault_id)).await.code(),
        "owner_must_demote"
    );
    let reauth = t.reauth(&bob).await;
    let delete = || {
        Req::delete("/v1/me")
            .token(&bob.access_token)
            .reauth(&reauth)
    };
    assert_eq!(t.call(delete()).await.code(), "owner_must_demote");
    let demoted = t
        .call(t.role_change(&bob, &vault_id, &bob.user_id, "member").await)
        .await;
    assert_eq!(demoted.status, StatusCode::NO_CONTENT, "{}", demoted.text());
    let head = t.roles_head(&alice, &vault_id).await.unwrap();
    assert_eq!(head.owners, vec![owner(&alice)]);
    assert_eq!(head.signer, bob.user_id);
    assert_eq!(t.call(delete()).await.status, StatusCode::NO_CONTENT);

    // Without a chain the earlier rules apply.
    let carol = t.register("carol@example.com").await;
    let other = t.create_vault(&alice).await;
    t.share(&alice, &other, &carol).await;
    without_chain(&t, &other).await;
    t.call(t.role_change(&alice, &other, &carol.user_id, "owner").await)
        .await;
    assert_eq!(
        t.call(leave(&carol, &other)).await.status,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn rotations_commit_the_next_statement() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let (vault_id, _) = shared(&t, &alice, &bob).await;
    t.share(&alice, &vault_id, &carol).await;
    t.call(
        t.role_change(&alice, &vault_id, &carol.user_id, "owner")
            .await,
    )
    .await;
    let head = t.roles_head(&alice, &vault_id).await.unwrap();

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
    assert_eq!(uploaded.status, StatusCode::NO_CONTENT);
    // Carol, an owner, is removed with the rotation.
    let body = |roles: Option<Value>| {
        let mut body = json!({
            "key_wrapped": envelope(73),
            "member_keys": [{ "user_id": bob.user_id, "key_box": key_box(200) }],
            "invite_keys": [],
            "remove_user_ids": [carol.user_id],
            "drop_objects": [],
        });
        if let Some(roles) = roles {
            body["roles"] = roles;
        }
        body
    };
    let commit = |key: &str, body: &Value| {
        Req::post(&format!(
            "/v1/vaults/{vault_id}/rotations/{rotation_id}/commit"
        ))
        .token(&alice.access_token)
        .idem(key)
        .json(body)
    };
    let key = new_uuid();
    let without = body(None);
    let missing = t.call(commit(&key, &without)).await;
    assert_eq!(missing.code(), "roles_required");
    assert_eq!(
        t.call(commit(&key, &without)).await.code(),
        "roles_required"
    );
    let same_key = successor(&head, vec![owner(&alice)], &alice.user_id);
    let still_carol = rotated(&head, vec![owner(&alice), owner(&carol)], &alice.user_id);
    let skipped = Statement {
        key_version: 3,
        ..rotated(&head, vec![owner(&alice)], &alice.user_id)
    };
    for (what, statement) in [
        ("without a key change", same_key),
        ("keeping the removed owner", still_carol),
        ("skipping a key version", skipped),
    ] {
        let key = new_uuid();
        let body = body(Some(signed(&alice, &statement)));
        let response = t.call(commit(&key, &body)).await;
        assert_eq!(response.code(), "validation_failed", "{what}");
        assert_eq!(
            t.call(commit(&key, &body)).await.code(),
            "validation_failed",
            "{what}: stored"
        );
    }
    let next = rotated(&head, vec![owner(&alice)], &alice.user_id);
    let done = t
        .call(commit(&new_uuid(), &body(Some(signed(&alice, &next)))))
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    let stored = t.roles_head(&alice, &vault_id).await.unwrap();
    assert_eq!(stored, next);
    assert_eq!(stored.key_version, 2);
    assert_eq!(head_version(&t, &bob, &vault_id).await, head.version + 1);

    // Without a chain, a statement is refused.
    let other = t.create_vault(&alice).await;
    without_chain(&t, &other).await;
    let opened = t
        .call(
            Req::post(&format!("/v1/vaults/{other}/rotations"))
                .token(&alice.access_token)
                .idem(&new_uuid())
                .json(&json!({ "base_revision": 1, "new_key_version": 2 })),
        )
        .await;
    let rotation = opened.json()["rotation_id"].as_str().unwrap().to_string();
    let objects: Vec<Value> = t.changes(&alice, &other, "since=0").await.json()["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| json!({ "id": o["id"], "type": o["type"], "key_version": 2, "data": envelope(300) }))
        .collect();
    t.call(
        Req::put(&format!("/v1/vaults/{other}/rotations/{rotation}/objects"))
            .token(&alice.access_token)
            .idem(&new_uuid())
            .json(&json!({ "objects": objects })),
    )
    .await;
    let roles = signed(
        &alice,
        &rotated(
            &genesis(&other, vec![owner(&alice)], &alice.user_id, 1),
            vec![owner(&alice)],
            &alice.user_id,
        ),
    );
    let refused = t
        .call(
            Req::post(&format!("/v1/vaults/{other}/rotations/{rotation}/commit"))
                .token(&alice.access_token)
                .idem(&new_uuid())
                .json(&json!({
                    "key_wrapped": envelope(73),
                    "member_keys": [],
                    "invite_keys": [],
                    "remove_user_ids": [],
                    "drop_objects": [],
                    "roles": roles,
                })),
        )
        .await;
    assert_eq!(refused.field_error().0, "/roles");
}
