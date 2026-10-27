//! Members of a vault: list, invite, accept, decline, pending key,
//! role, withdraw and leave, including the central membership check.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{Account, Req, TestApp, envelope, key_box, new_uuid};

fn members(account: &Account, vault_id: &str) -> Req {
    Req::get(&format!("/v1/vaults/{vault_id}/members")).token(&account.access_token)
}

/// A role change without a statement; refused before any statement check.
fn role(account: &Account, vault_id: &str, user_id: &str, role: &str) -> Req {
    Req::new("PATCH", &format!("/v1/vaults/{vault_id}/members/{user_id}"))
        .token(&account.access_token)
        .json(&json!({ "role": role }))
}

fn withdraw(account: &Account, vault_id: &str, user_id: &str) -> Req {
    Req::delete(&format!("/v1/vaults/{vault_id}/members/{user_id}")).token(&account.access_token)
}

fn leave(account: &Account, vault_id: &str) -> Req {
    Req::delete(&format!("/v1/vaults/{vault_id}/members/me")).token(&account.access_token)
}

fn accept_key(account: &Account, vault_id: &str, key_version: i64) -> Req {
    Req::post(&format!("/v1/vaults/{vault_id}/key"))
        .token(&account.access_token)
        .json(&json!({ "key_version": key_version, "key_wrapped": envelope(73) }))
}

#[tokio::test]
async fn invitations_appear_in_the_vault_and_member_lists() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&alice).await;

    let invited = t.invite_member(&alice, &vault_id, &bob).await;
    assert_eq!(invited.status, StatusCode::CREATED, "{}", invited.text());
    let listed = t.listed(&bob, &vault_id).await.unwrap();
    assert_eq!(listed["state"], "pending");
    assert_eq!(listed["role"], "member");
    assert_eq!(listed["key_wrapped"], json!(null));
    assert_eq!(listed["member_count"], 1);
    assert_eq!(listed["invitation"]["key_version"], 1);
    assert_eq!(listed["invitation"]["sender_id"], json!(alice.user_id));
    assert!(listed["invitation"]["key_box"].as_str().unwrap().len() > 200);

    let list = t.call(members(&alice, &vault_id)).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.text());
    let rows = list.json()["members"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["user_id"], json!(alice.user_id));
    assert_eq!(rows[0]["role"], "owner");
    assert_eq!(rows[0]["state"], "active");
    assert_eq!(rows[0]["invited_by"], json!(null));
    assert_eq!(rows[0]["public_key"], json!(alice.public_key));
    assert_eq!(
        rows[0]["signing_public_key"],
        json!(alice.signing_public_key)
    );
    assert_eq!(rows[1]["user_id"], json!(bob.user_id));
    assert_eq!(rows[1]["email"], "bob@example.com");
    assert_eq!(rows[1]["state"], "pending");
    assert_eq!(rows[1]["invited_by"], json!(alice.user_id));
    assert!(
        t.security_events()
            .await
            .contains(&"member_invited".to_string())
    );
    // Pending invitees do not see the member list yet.
    assert_eq!(t.call(members(&bob, &vault_id)).await.code(), "forbidden");
}

#[tokio::test]
async fn invitations_are_checked_in_order() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let invite = |owner: &Account, user_id: &str, key_version: i64, key_box: String| {
        Req::post(&format!("/v1/vaults/{vault_id}/members"))
            .token(&owner.access_token)
            .json(&json!({ "user_id": user_id, "key_version": key_version, "key_box": key_box }))
    };

    let unknown = t.call(invite(&alice, &new_uuid(), 1, key_box(200))).await;
    assert_eq!(unknown.code(), "user_not_found");
    let own = t
        .call(invite(&alice, &alice.user_id, 1, key_box(200)))
        .await;
    assert_eq!(own.code(), "already_member");
    let stale = t.call(invite(&alice, &bob.user_id, 2, key_box(200))).await;
    assert_eq!(stale.code(), "key_version_mismatch");
    assert_eq!(stale.json()["current_key_version"], 1);
    let aead = t.call(invite(&alice, &bob.user_id, 1, envelope(200))).await;
    assert_eq!(aead.status, StatusCode::BAD_REQUEST);
    let short = t.call(invite(&alice, &bob.user_id, 1, key_box(40))).await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    let huge = t
        .call(invite(&alice, &bob.user_id, 1, key_box(49_153)))
        .await;
    assert_eq!(huge.status, StatusCode::PAYLOAD_TOO_LARGE);

    assert_eq!(
        t.invite_member(&alice, &vault_id, &bob).await.status,
        StatusCode::CREATED
    );
    let twice = t.invite_member(&alice, &vault_id, &bob).await;
    assert_eq!(twice.code(), "already_member");
    // A pending invitee and a non-member cannot invite.
    let pending = t.invite_member(&bob, &vault_id, &carol).await;
    assert_eq!(pending.code(), "forbidden");
    let stranger = t.invite_member(&carol, &vault_id, &bob).await;
    assert_eq!(stranger.code(), "not_found");
    // A member who is not an owner cannot either.
    t.accept_invitation(&bob, &vault_id, 1).await;
    let member = t.invite_member(&bob, &vault_id, &carol).await;
    assert_eq!(member.code(), "forbidden");
}

#[tokio::test]
async fn accepting_activates_the_membership() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.invite_member(&alice, &vault_id, &bob).await;

    let stale = t.accept_invitation(&bob, &vault_id, 2).await;
    assert_eq!(stale.code(), "key_version_mismatch");
    assert_eq!(stale.json()["current_key_version"], 1);
    let none = t.accept_invitation(&carol, &vault_id, 1).await;
    assert_eq!(none.code(), "not_found");

    let accepted = t.accept_invitation(&bob, &vault_id, 1).await;
    assert_eq!(
        accepted.status,
        StatusCode::NO_CONTENT,
        "{}",
        accepted.text()
    );
    let listed = t.listed(&bob, &vault_id).await.unwrap();
    assert_eq!(listed["state"], "active");
    assert_eq!(listed["invitation"], json!(null));
    assert!(listed["key_wrapped"].is_string());
    assert_eq!(listed["member_count"], 2);
    let rows = t.call(members(&bob, &vault_id)).await.json();
    assert_eq!(rows["members"][1]["state"], "active");
    assert_eq!(rows["members"][1]["invited_by"], json!(alice.user_id));
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM memberships WHERE vault_id = '{vault_id}' AND key_box IS NOT NULL"
        ))
        .await,
        0
    );
    // A repetition after a lost answer finds nothing pending.
    let again = t.accept_invitation(&bob, &vault_id, 1).await;
    assert_eq!(again.code(), "not_found");
    assert!(
        t.security_events()
            .await
            .contains(&"invitation_accepted".to_string())
    );
}

#[tokio::test]
async fn declining_removes_the_invitation() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.invite_member(&alice, &vault_id, &bob).await;
    let decline = || Req::post(&format!("/v1/vaults/{vault_id}/decline")).token(&bob.access_token);

    assert_eq!(t.call(decline()).await.status, StatusCode::NO_CONTENT);
    assert!(t.listed(&bob, &vault_id).await.is_none());
    assert_eq!(t.call(decline()).await.code(), "not_found");
    let rows = t.call(members(&alice, &vault_id)).await.json();
    assert_eq!(rows["members"].as_array().unwrap().len(), 1);
    // An active member cannot decline.
    t.share(&alice, &vault_id, &bob).await;
    assert_eq!(t.call(decline()).await.code(), "not_found");
    assert!(
        t.security_events()
            .await
            .contains(&"invitation_declined".to_string())
    );
}

#[tokio::test]
async fn only_pending_invitations_can_be_withdrawn() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.invite_member(&alice, &vault_id, &carol).await;

    let member = t.call(withdraw(&bob, &vault_id, &carol.user_id)).await;
    assert_eq!(member.code(), "forbidden");
    let active = t.call(withdraw(&alice, &vault_id, &bob.user_id)).await;
    assert_eq!(active.code(), "use_rotate");
    let unknown = t.call(withdraw(&alice, &vault_id, &new_uuid())).await;
    assert_eq!(unknown.code(), "not_found");
    let invalid = t.call(withdraw(&alice, &vault_id, "carol")).await;
    assert_eq!(invalid.field_error().0, "user_id");

    let done = t.call(withdraw(&alice, &vault_id, &carol.user_id)).await;
    assert_eq!(done.status, StatusCode::NO_CONTENT);
    assert!(t.listed(&carol, &vault_id).await.is_none());
    assert!(
        t.security_events()
            .await
            .contains(&"invitation_withdrawn".to_string())
    );
}

#[tokio::test]
async fn roles_change_while_one_owner_remains() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.invite_member(&alice, &vault_id, &carol).await;

    let last = t
        .call(
            t.role_change(&alice, &vault_id, &alice.user_id, "member")
                .await,
        )
        .await;
    assert_eq!(last.code(), "last_owner");
    let by_member = t
        .call(t.role_change(&bob, &vault_id, &bob.user_id, "owner").await)
        .await;
    assert_eq!(by_member.code(), "forbidden");
    let pending = t
        .call(
            t.role_change(&alice, &vault_id, &carol.user_id, "owner")
                .await,
        )
        .await;
    assert_eq!(pending.code(), "not_found");
    let invalid = t
        .call(
            t.role_change(&alice, &vault_id, &bob.user_id, "admin")
                .await,
        )
        .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);

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
    assert_eq!(t.listed(&bob, &vault_id).await.unwrap()["role"], "owner");
    let same = t
        .call(
            t.role_change(&alice, &vault_id, &bob.user_id, "owner")
                .await,
        )
        .await;
    assert_eq!(same.status, StatusCode::NO_CONTENT);
    // Owners may demote other owners, also themselves, while one remains.
    let demoted = t
        .call(
            t.role_change(&bob, &vault_id, &alice.user_id, "member")
                .await,
        )
        .await;
    assert_eq!(demoted.status, StatusCode::NO_CONTENT);
    let alone = t
        .call(t.role_change(&bob, &vault_id, &bob.user_id, "member").await)
        .await;
    assert_eq!(alone.code(), "last_owner");
    let events = t.security_events().await;
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == "member_role_changed")
            .count(),
        2
    );
}

#[tokio::test]
async fn leaving_flags_the_vault_and_drops_the_leavers_grants() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let dave = t.register("dave@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.share(&alice, &vault_id, &dave).await;
    t.call(
        t.role_change(&alice, &vault_id, &bob.user_id, "owner")
            .await,
    )
    .await;
    // Bob invites Carol and left a pending key for Dave after a rotation.
    assert_eq!(
        t.invite_member(&bob, &vault_id, &carol).await.status,
        StatusCode::CREATED
    );
    t.sql(&format!(
        "UPDATE memberships SET pending_key_box = X'02', pending_key_version = 2, pending_key_sender_id = '{}'
         WHERE vault_id = '{vault_id}' AND user_id = '{}'",
        bob.user_id, dave.user_id
    ))
    .await;

    // An owner in a signed owner list demotes itself first.
    assert_eq!(
        t.call(leave(&bob, &vault_id)).await.code(),
        "owner_must_demote"
    );
    let demoted = t
        .call(t.role_change(&bob, &vault_id, &bob.user_id, "member").await)
        .await;
    assert_eq!(demoted.status, StatusCode::NO_CONTENT, "{}", demoted.text());
    let left = t.call(leave(&bob, &vault_id)).await;
    assert_eq!(left.status, StatusCode::NO_CONTENT, "{}", left.text());
    assert!(t.listed(&bob, &vault_id).await.is_none());
    let listed = t.listed(&alice, &vault_id).await.unwrap();
    assert_eq!(listed["rotation_required"], true);
    assert_eq!(listed["member_count"], 2);
    assert!(t.listed(&carol, &vault_id).await.is_none());
    assert_eq!(
        t.listed(&dave, &vault_id).await.unwrap()["pending_key"],
        json!(null)
    );
    assert!(
        t.security_events()
            .await
            .contains(&"member_left".to_string())
    );
    assert_eq!(t.call(leave(&bob, &vault_id)).await.code(), "not_found");
}

#[tokio::test]
async fn the_last_owner_cannot_leave() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    assert_eq!(t.call(leave(&alice, &vault_id)).await.code(), "last_owner");
    t.share(&alice, &vault_id, &bob).await;
    assert_eq!(t.call(leave(&alice, &vault_id)).await.code(), "last_owner");
    t.invite_member(&alice, &vault_id, &carol).await;
    // A pending invitation is declined, not left.
    assert_eq!(t.call(leave(&carol, &vault_id)).await.code(), "forbidden");
    // A member may leave.
    assert_eq!(
        t.call(leave(&bob, &vault_id)).await.status,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn a_pending_key_is_accepted_once() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.invite_member(&alice, &vault_id, &carol).await;

    assert_eq!(
        t.call(accept_key(&bob, &vault_id, 2)).await.code(),
        "not_found"
    );
    t.sql(&format!(
        "UPDATE vaults SET key_version = 2 WHERE id = '{vault_id}';
         UPDATE memberships SET pending_key_box = X'0201', pending_key_version = 2, pending_key_sender_id = '{}'
         WHERE vault_id = '{vault_id}' AND user_id = '{}'",
        alice.user_id, bob.user_id
    ))
    .await;
    let listed = t.listed(&bob, &vault_id).await.unwrap();
    assert_eq!(listed["pending_key"]["key_version"], 2);
    assert_eq!(listed["pending_key"]["sender_id"], json!(alice.user_id));

    let stale = t.call(accept_key(&bob, &vault_id, 1)).await;
    assert_eq!(stale.code(), "key_version_mismatch");
    assert_eq!(stale.json()["current_key_version"], 2);
    let accepted = t.call(accept_key(&bob, &vault_id, 2)).await;
    assert_eq!(
        accepted.status,
        StatusCode::NO_CONTENT,
        "{}",
        accepted.text()
    );
    let listed = t.listed(&bob, &vault_id).await.unwrap();
    assert_eq!(listed["member_key_version"], 2);
    assert_eq!(listed["pending_key"], json!(null));
    assert_eq!(
        t.call(accept_key(&bob, &vault_id, 2)).await.code(),
        "not_found"
    );
    assert_eq!(
        t.call(accept_key(&carol, &vault_id, 2)).await.code(),
        "forbidden"
    );
}

#[tokio::test]
async fn foreign_and_pending_callers_are_rejected() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let mallory = t.register("mallory@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    t.share(&alice, &vault_id, &bob).await;
    t.invite_member(&alice, &vault_id, &carol).await;
    let target = bob.user_id.clone();
    let requests = |caller: &Account| {
        vec![
            members(caller, &vault_id),
            Req::post(&format!("/v1/vaults/{vault_id}/members"))
                .token(&caller.access_token)
                .json(&json!({ "user_id": mallory.user_id, "key_version": 1, "key_box": key_box(200) })),
            role(caller, &vault_id, &target, "owner"),
            withdraw(caller, &vault_id, &target),
            accept_key(caller, &vault_id, 2),
        ]
    };
    for request in requests(&mallory) {
        assert_eq!(t.call(request).await.code(), "not_found");
    }
    for request in requests(&carol) {
        assert_eq!(t.call(request).await.code(), "forbidden");
    }
    // Owner-only actions as a member.
    for request in requests(&bob).into_iter().skip(1).take(3) {
        assert_eq!(t.call(request).await.code(), "forbidden");
    }
    for path in ["accept", "decline"] {
        let response = t
            .call(
                Req::post(&format!("/v1/vaults/{vault_id}/{path}"))
                    .token(&mallory.access_token)
                    .json(&json!({ "key_version": 1, "key_wrapped": envelope(73) })),
            )
            .await;
        assert_eq!(response.code(), "not_found", "{path}");
    }
}

#[tokio::test]
async fn invitations_are_limited_per_inviter_and_per_invitee() {
    let t = TestApp::with_config(
        "[rate_limits]\ninvites_per_account_per_hour = 3\ninvites_per_invitee_per_hour = 2\n",
    )
    .await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let dave = t.register("dave@example.com").await;
    let erin = t.register("erin@example.com").await;
    let vaults = [
        t.create_vault(&alice).await,
        t.create_vault(&alice).await,
        t.create_vault(&alice).await,
    ];
    // Bob may receive two invitations an hour, from anyone.
    for vault in &vaults[..2] {
        let response = t.invite_member(&alice, vault, &bob).await;
        assert_eq!(response.status, StatusCode::CREATED);
    }
    let response = t.invite_member(&alice, &vaults[2], &bob).await;
    assert_eq!(response.code(), "rate_limited");
    assert!(response.header("retry-after").is_some());
    let erins = t.create_vault(&erin).await;
    assert_eq!(
        t.invite_member(&erin, &erins, &bob).await.code(),
        "rate_limited"
    );
    // The refused attempts took nothing from Alice: her third invitation
    // goes through, the fourth does not, not even to an unknown account.
    let response = t.invite_member(&alice, &vaults[2], &carol).await;
    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(
        t.invite_member(&alice, &vaults[0], &dave).await.code(),
        "rate_limited"
    );
    let unknown = t
        .call(
            Req::post(&format!("/v1/vaults/{}/members", vaults[0]))
                .token(&alice.access_token)
                .json(&json!({ "user_id": new_uuid(), "key_version": 1, "key_box": key_box(200) })),
        )
        .await;
    assert_eq!(unknown.code(), "rate_limited");
    // One invitation per 20 minutes comes back.
    t.advance(time::Duration::minutes(20));
    let alice = t.login(&alice).await;
    let response = t.invite_member(&alice, &vaults[0], &dave).await;
    assert_eq!(response.status, StatusCode::CREATED);
}
