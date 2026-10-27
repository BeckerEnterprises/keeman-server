//! Every vault operation of the API contract (tests/fixtures/operations.json)
//! as an outsider (`404`), as a pending member (`403`, except accepting and
//! declining) and owner-only operations as a member (`403`). All requests are
//! otherwise valid and name existing objects, so only the membership check
//! can refuse them; none of them changes anything. Large-body operations
//! check membership before they read the body.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use support::{Account, Req, TestApp, envelope, key_box, new_uuid, put_op};

#[derive(Deserialize)]
struct Operation {
    method: String,
    path: String,
}

const VAULT_PREFIX: &str = "/v1/vaults/{vault_id}";

fn vault_operations() -> BTreeSet<(String, String)> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/operations.json"
    ))
    .unwrap();
    let operations: Vec<Operation> = serde_json::from_str(&text).unwrap();
    operations
        .into_iter()
        .filter(|o| o.path.starts_with(VAULT_PREFIX))
        .map(|o| (o.method, o.path))
        .collect()
}

struct Fixture {
    vault: String,
    attachment: String,
    rotation: String,
    member: String,
    other_vault: String,
}

/// The operation template, whether only owners may call it, and the request.
fn requests(f: &Fixture, caller: &Account, reauth: &str) -> Vec<(&'static str, bool, Req)> {
    let v = &f.vault;
    let a = format!("/v1/vaults/{v}/attachments/{}", f.attachment);
    let r = format!("/v1/vaults/{v}/rotations/{}", f.rotation);
    let token = &caller.access_token;
    vec![
        (
            "DELETE /v1/vaults/{vault_id}",
            true,
            Req::delete(&format!("/v1/vaults/{v}")).reauth(reauth),
        ),
        (
            "POST /v1/vaults/{vault_id}/accept",
            false,
            Req::post(&format!("/v1/vaults/{v}/accept"))
                .json(&json!({ "key_version": 1, "key_wrapped": envelope(73) })),
        ),
        (
            "POST /v1/vaults/{vault_id}/decline",
            false,
            Req::post(&format!("/v1/vaults/{v}/decline")),
        ),
        (
            "POST /v1/vaults/{vault_id}/key",
            false,
            Req::post(&format!("/v1/vaults/{v}/key"))
                .json(&json!({ "key_version": 2, "key_wrapped": envelope(73) })),
        ),
        (
            "GET /v1/vaults/{vault_id}/members",
            false,
            Req::get(&format!("/v1/vaults/{v}/members")),
        ),
        (
            "POST /v1/vaults/{vault_id}/members",
            true,
            Req::post(&format!("/v1/vaults/{v}/members")).json(
                &json!({ "user_id": caller.user_id, "key_version": 1, "key_box": key_box(200) }),
            ),
        ),
        (
            "DELETE /v1/vaults/{vault_id}/members/me",
            false,
            Req::delete(&format!("/v1/vaults/{v}/members/me")),
        ),
        (
            "PATCH /v1/vaults/{vault_id}/members/{user_id}",
            true,
            Req::new("PATCH", &format!("/v1/vaults/{v}/members/{}", f.member))
                .json(&json!({ "role": "owner" })),
        ),
        (
            "DELETE /v1/vaults/{vault_id}/members/{user_id}",
            true,
            Req::delete(&format!("/v1/vaults/{v}/members/{}", f.member)),
        ),
        (
            "GET /v1/vaults/{vault_id}/roles",
            false,
            Req::get(&format!("/v1/vaults/{v}/roles")),
        ),
        (
            "POST /v1/vaults/{vault_id}/roles",
            true,
            Req::post(&format!("/v1/vaults/{v}/roles")).json(&json!({
                "roles": support::roles::signed(
                    caller,
                    &support::roles::genesis(v, vec![support::roles::owner(caller)], &caller.user_id, 1),
                ),
            })),
        ),
        (
            "PUT /v1/vaults/{vault_id}/freshness",
            false,
            Req::put(&format!("/v1/vaults/{v}/freshness")).json(&json!({
                "freshness": support::freshness::signed(
                    caller,
                    &support::freshness::vault(caller, v),
                ),
            })),
        ),
        (
            "POST /v1/vaults/{vault_id}/rotations",
            true,
            Req::post(&format!("/v1/vaults/{v}/rotations"))
                .idem(&new_uuid())
                .json(&json!({ "base_revision": 1, "new_key_version": 2 })),
        ),
        (
            "PUT /v1/vaults/{vault_id}/rotations/{rotation_id}/objects",
            true,
            Req::put(&format!("{r}/objects")).idem(&new_uuid()).json(&json!({
                "objects": [{ "id": v, "type": "vault_meta", "key_version": 2, "data": envelope(64) }]
            })),
        ),
        (
            "POST /v1/vaults/{vault_id}/rotations/{rotation_id}/commit",
            true,
            Req::post(&format!("{r}/commit")).idem(&new_uuid()).json(&json!({
                "key_wrapped": envelope(73),
                "member_keys": [],
                "invite_keys": [],
                "remove_user_ids": [],
                "drop_objects": [],
            })),
        ),
        (
            "GET /v1/vaults/{vault_id}/changes",
            false,
            Req::get(&format!("/v1/vaults/{v}/changes?since=0")),
        ),
        (
            "POST /v1/vaults/{vault_id}/batch",
            false,
            Req::post(&format!("/v1/vaults/{v}/batch"))
                .idem(&new_uuid())
                .json(&json!({ "ops": [put_op(&new_uuid(), "entry", None)] })),
        ),
        (
            "POST /v1/vaults/{vault_id}/attachments",
            false,
            Req::post(&format!("/v1/vaults/{v}/attachments"))
                .json(&json!({ "attachment_id": new_uuid(), "entry_id": new_uuid(), "size": 100 })),
        ),
        (
            "GET /v1/vaults/{vault_id}/attachments/{attachment_id}",
            false,
            Req::get(&a),
        ),
        (
            "DELETE /v1/vaults/{vault_id}/attachments/{attachment_id}",
            false,
            Req::delete(&a),
        ),
        (
            "PUT /v1/vaults/{vault_id}/attachments/{attachment_id}/parts/{part}",
            false,
            Req::put(&format!("{a}/parts/0")).raw(Some("application/octet-stream"), &[7; 100]),
        ),
        (
            "POST /v1/vaults/{vault_id}/attachments/{attachment_id}/complete",
            false,
            Req::post(&format!("{a}/complete")),
        ),
        (
            "POST /v1/vaults/{vault_id}/attachments/{attachment_id}/transfer",
            false,
            Req::post(&format!("{a}/transfer"))
                .json(&json!({ "target_vault_id": f.other_vault, "target_entry_id": new_uuid() })),
        ),
    ]
    .into_iter()
    .map(|(op, owner_only, request)| (op, owner_only, request.token(token)))
    .collect()
}

#[tokio::test]
async fn every_vault_operation_checks_membership_and_role() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let dave = t.register("dave@example.com").await;
    let vault = t.create_vault(&alice).await;
    t.share(&alice, &vault, &bob).await;
    t.invite_member(&alice, &vault, &carol).await;

    // A complete attachment and an open rotation of the owner.
    let attachment = new_uuid();
    let base = format!("/v1/vaults/{vault}/attachments/{attachment}");
    for request in [
        Req::post(&format!("/v1/vaults/{vault}/attachments"))
            .json(&json!({ "attachment_id": attachment, "entry_id": new_uuid(), "size": 100 })),
        Req::put(&format!("{base}/parts/0")).raw(Some("application/octet-stream"), &[1; 100]),
        Req::post(&format!("{base}/complete")),
    ] {
        let response = t.call(request.token(&alice.access_token)).await;
        assert!(response.status.is_success(), "{}", response.text());
    }
    let revision = t.listed(&alice, &vault).await.unwrap()["revision"]
        .as_i64()
        .unwrap();
    let response = t
        .call(
            Req::post(&format!("/v1/vaults/{vault}/rotations"))
                .token(&alice.access_token)
                .idem(&new_uuid())
                .json(&json!({ "base_revision": revision, "new_key_version": 2 })),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    let fixture = Fixture {
        vault: vault.clone(),
        attachment: attachment.clone(),
        rotation: response.json()["rotation_id"].as_str().unwrap().to_string(),
        member: bob.user_id.clone(),
        other_vault: t.create_vault(&dave).await,
    };

    // The table covers every vault operation of the contract.
    let covered: BTreeSet<(String, String)> = requests(&fixture, &dave, "")
        .iter()
        .map(|(op, _, _)| {
            let (method, path) = op.split_once(' ').unwrap();
            (method.to_string(), path.to_string())
        })
        .collect();
    assert_eq!(covered, vault_operations());

    let reauth = t.reauth(&dave).await;
    for (op, _, request) in requests(&fixture, &dave, &reauth) {
        assert_eq!(t.call(request).await.code(), "not_found", "outsider: {op}");
    }
    let reauth = t.reauth(&carol).await;
    for (op, _, request) in requests(&fixture, &carol, &reauth) {
        if op.ends_with("/accept") || op.ends_with("/decline") {
            continue;
        }
        // Invitees read the roles chain before they accept.
        if op == "GET /v1/vaults/{vault_id}/roles" {
            assert_eq!(
                t.call(request).await.status,
                StatusCode::OK,
                "pending: {op}"
            );
            continue;
        }
        assert_eq!(t.call(request).await.code(), "forbidden", "pending: {op}");
    }
    let reauth = t.reauth(&bob).await;
    for (op, owner_only, request) in requests(&fixture, &bob, &reauth) {
        if owner_only {
            assert_eq!(t.call(request).await.code(), "forbidden", "member: {op}");
        }
    }

    // Nothing changed: same revision, members, attachment and rotation.
    assert_eq!(
        t.listed(&alice, &vault).await.unwrap()["revision"].as_i64(),
        Some(revision)
    );
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM memberships WHERE vault_id = '{vault}'"
        ))
        .await,
        3
    );
    let download = t.call(Req::get(&base).token(&alice.access_token)).await;
    assert_eq!(download.status, StatusCode::OK);
    assert_eq!(t.count("SELECT COUNT(*) FROM rotations").await, 1);
    assert_eq!(t.count("SELECT COUNT(*) FROM attachments").await, 1);
    assert_eq!(t.count("SELECT COUNT(*) FROM vault_freshness").await, 0);
}

/// Large-body operations check membership before reading the body: a
/// non-member's malformed request gets `404`/`403`, not `415`/`400`/`413`.
#[tokio::test]
async fn large_bodies_are_not_read_for_non_members() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let dave = t.register("dave@example.com").await;
    let vault = t.create_vault(&alice).await;
    t.share(&alice, &vault, &bob).await;
    t.invite_member(&alice, &vault, &carol).await;
    let upload = new_uuid();
    let response = t
        .call(
            Req::post(&format!("/v1/vaults/{vault}/attachments"))
                .token(&alice.access_token)
                .json(&json!({ "attachment_id": upload, "entry_id": new_uuid(), "size": 100 })),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    let revision = t.listed(&alice, &vault).await.unwrap()["revision"]
        .as_i64()
        .unwrap();
    let response = t
        .call(
            Req::post(&format!("/v1/vaults/{vault}/rotations"))
                .token(&alice.access_token)
                .idem(&new_uuid())
                .json(&json!({ "base_revision": revision, "new_key_version": 2 })),
        )
        .await;
    let rotation = response.json()["rotation_id"].as_str().unwrap().to_string();
    let too_large = vec![b' '; 16 * 1024 * 1024 + 1];
    let part_too_large = vec![0u8; 8 * 1024 * 1024 + 64 * 1024 + 1];

    // (owner only, request, the owner's answer)
    let requests = |caller: &Account| {
        let token = caller.access_token.as_str();
        let json_ops = [
            ("POST", format!("/v1/vaults/{vault}/batch"), false),
            (
                "PUT",
                format!("/v1/vaults/{vault}/rotations/{rotation}/objects"),
                true,
            ),
            (
                "POST",
                format!("/v1/vaults/{vault}/rotations/{rotation}/commit"),
                true,
            ),
        ];
        let mut all = Vec::new();
        for (method, path, owner_only) in json_ops {
            all.push((
                owner_only,
                Req::new(method, &path)
                    .token(token)
                    .idem(&new_uuid())
                    .raw(Some("text/plain"), b"{}"),
                "unsupported_media_type",
            ));
            all.push((
                owner_only,
                Req::new(method, &path).token(token).json(&json!({})),
                "validation_failed",
            ));
            all.push((
                owner_only,
                Req::new(method, &path)
                    .token(token)
                    .idem(&new_uuid())
                    .raw(Some("application/json"), &too_large),
                "payload_too_large",
            ));
        }
        let part = format!("/v1/vaults/{vault}/attachments/{upload}/parts/0");
        all.push((
            false,
            Req::put(&part)
                .token(token)
                .raw(Some("application/json"), &[0; 100]),
            "unsupported_media_type",
        ));
        all.push((
            false,
            Req::put(&part)
                .token(token)
                .raw(Some("application/octet-stream"), &part_too_large),
            "payload_too_large",
        ));
        all
    };
    for (_, request, _) in requests(&dave) {
        assert_eq!(t.call(request).await.code(), "not_found");
    }
    for (_, request, _) in requests(&carol) {
        assert_eq!(t.call(request).await.code(), "forbidden");
    }
    for (owner_only, request, expected) in requests(&bob) {
        let code = t.call(request).await.code();
        assert_eq!(code, if owner_only { "forbidden" } else { expected });
    }
    for (_, request, expected) in requests(&alice) {
        assert_eq!(t.call(request).await.code(), expected);
    }
    // Small-body operations are unchanged: the body checks come first.
    let response = t
        .call(
            Req::post(&format!("/v1/vaults/{vault}/members"))
                .token(&dave.access_token)
                .raw(Some("text/plain"), b"{}"),
        )
        .await;
    assert_eq!(response.code(), "unsupported_media_type");
}
