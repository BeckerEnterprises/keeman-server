//! `/v1/me`: account data, reauth, `user_data`, password, recovery and
//! sessions.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{Req, TestApp, envelope, random_b64, unique_ip};
use time::Duration;

#[tokio::test]
async fn me_returns_the_account_material() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let response = t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    assert_eq!(response.status, StatusCode::OK);
    let me = response.json();
    assert_eq!(me["user_id"].as_str(), Some(alice.user_id.as_str()));
    assert_eq!(me["email"], "alice@example.com");
    assert_eq!(
        me["kdf"],
        json!({ "alg": "argon2id13", "ops": 3, "mem": 67108864 })
    );
    assert_eq!(me["salt"].as_str(), Some(alice.salt.as_str()));
    for field in ["user_key_wrapped", "private_key_wrapped"] {
        assert_eq!(me[field].as_str().unwrap().len(), 98, "{field}");
    }
    assert_eq!(me["public_key"].as_str().unwrap().len(), 43);
    assert_eq!(me["user_data"]["revision"], 1);
    assert_eq!(
        me["two_factor"],
        json!({ "totp": false, "webauthn_credentials": 0, "backup_codes_remaining": 0 })
    );
    assert_eq!(me["created"], "2026-10-23T08:00:00.000Z");
}

#[tokio::test]
async fn reauth_issues_a_session_bound_token() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let response = t
        .call(
            Req::post("/v1/me/reauth")
                .token(&alice.access_token)
                .json(&json!({ "auth_key": alice.auth_key })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["expires_in"], 300);
    let token = response.json()["reauth_token"]
        .as_str()
        .unwrap()
        .to_string();
    // Usable several times within 5 minutes.
    let body = json!({ "auth_key": random_b64::<32>(), "user_key_wrapped": envelope(73) });
    for _ in 0..2 {
        let response = t
            .call(
                Req::put("/v1/me/recovery")
                    .token(&alice.access_token)
                    .reauth(&token)
                    .json(&body),
            )
            .await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
    }
}

#[tokio::test]
async fn wrong_reauth_key_keeps_the_session_and_counts_for_the_lockout() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let wrong = json!({ "auth_key": random_b64::<32>() });
    for attempt in 1..=10 {
        let response = t
            .call(
                Req::post("/v1/me/reauth")
                    .token(&alice.access_token)
                    .json(&wrong)
                    .peer(&unique_ip()),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt}"
        );
        assert_eq!(response.code(), "invalid_credentials");
        t.advance(Duration::seconds(12));
    }
    assert_eq!(
        t.call(Req::get("/v1/me").token(&alice.access_token))
            .await
            .status,
        StatusCode::OK,
        "session stays valid"
    );
    // The lockout applies to reauth and login alike.
    let right = json!({ "auth_key": alice.auth_key });
    let response = t
        .call(
            Req::post("/v1/me/reauth")
                .token(&alice.access_token)
                .json(&right)
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = 'reauth_failed'")
            .await,
        10
    );
}

#[tokio::test]
async fn reauth_does_not_count_against_the_session_limit() {
    let t = TestApp::with_config("[rate_limits]\nsession_per_min = 3\n").await;
    let alice = t.register("alice@example.com").await;
    for _ in 0..3 {
        assert_eq!(
            t.call(Req::get("/v1/me").token(&alice.access_token))
                .await
                .status,
            StatusCode::OK
        );
    }
    let response = t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.header("retry-after").as_deref(), Some("20"));
    let response = t
        .call(
            Req::post("/v1/me/reauth")
                .token(&alice.access_token)
                .json(&json!({ "auth_key": alice.auth_key })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn user_data_updates_conditionally() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let data = envelope(553);
    let put = |expected: i64, data: &str| {
        Req::put("/v1/me/user-data")
            .token(&alice.access_token)
            .json(&json!({ "expected_revision": expected, "data": data }))
    };
    let response = t.call(put(1, &data)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({ "revision": 2 }));
    let me = t
        .call(Req::get("/v1/me").token(&alice.access_token))
        .await
        .json();
    assert_eq!(me["user_data"], json!({ "revision": 2, "data": data }));

    for stale in [1, 3, 0] {
        let response = t.call(put(stale, &envelope(100))).await;
        assert_eq!(response.status, StatusCode::CONFLICT, "{stale}");
        assert_eq!(response.code(), "conflict");
        assert_eq!(response.json()["current_revision"], 2);
    }
    let response = t.call(put(2, &"A".repeat(349_923))).await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    let response = t.call(put(2, "AAAA")).await;
    assert_eq!(
        response.field_error(),
        ("/data".into(), "not an AEAD envelope".into())
    );
}

async fn password_change(
    t: &TestApp,
    account: &support::Account,
    reauth: &str,
    revoke: bool,
) -> (support::TestResponse, String) {
    let new_key = random_b64::<32>();
    let body = json!({
        "kdf": { "alg": "argon2id13", "ops": 4, "mem": 134217728 },
        "salt": random_b64::<16>(),
        "auth_key": new_key,
        "user_key_wrapped": envelope(73),
        "revoke_other_sessions": revoke,
    });
    let response = t
        .call(
            Req::put("/v1/me/password")
                .token(&account.access_token)
                .reauth(reauth)
                .json(&body),
        )
        .await;
    (response, new_key)
}

#[tokio::test]
async fn password_change_replaces_the_material_and_revokes_others() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let other_reauth = t.reauth(&other).await;
    let reauth = t.reauth(&alice).await;
    let (response, new_key) = password_change(&t, &alice, &reauth, true).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);

    // The current session stays; the other one is gone; all reauth tokens are deleted.
    assert_eq!(
        t.call(Req::get("/v1/me").token(&alice.access_token))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        t.call(Req::get("/v1/me").token(&other.access_token))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM challenges WHERE purpose = 'reauth'")
            .await,
        0
    );
    let _ = other_reauth;
    let (response, _) = password_change(&t, &alice, &reauth, false).await;
    assert_eq!(
        response.code(),
        "reauth_required",
        "the used reauth token is gone too"
    );

    let prelogin = t
        .call(Req::post("/v1/auth/prelogin").json(&json!({ "email": "alice@example.com" })))
        .await
        .json();
    assert_eq!(
        prelogin["kdf"],
        json!({ "alg": "argon2id13", "ops": 4, "mem": 134217728 })
    );
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.code(), "invalid_credentials", "old key");
    let mut login = alice.login_body();
    login["auth_key"] = json!(new_key);
    let response = t
        .call(Req::post("/v1/auth/login").json(&login).peer(&unique_ip()))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let detail: String =
        sqlx::query_scalar("SELECT detail FROM security_log WHERE event = 'password_changed'")
            .fetch_one(&t.app.db.read)
            .await
            .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&detail).unwrap(),
        json!({ "revoke_other_sessions": true, "revoked_sessions": 1 })
    );
}

#[tokio::test]
async fn kdf_upgrade_keeps_other_sessions() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let reauth = t.reauth(&alice).await;
    let (response, _) = password_change(&t, &alice, &reauth, false).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(
        t.call(Req::get("/v1/me").token(&other.access_token))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn password_change_validates_the_kdf() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let reauth = t.reauth(&alice).await;
    let body = json!({
        "kdf": { "alg": "argon2id13", "ops": 3, "mem": 1024 },
        "salt": random_b64::<16>(),
        "auth_key": random_b64::<32>(),
        "user_key_wrapped": envelope(73),
        "revoke_other_sessions": true,
    });
    let response = t
        .call(
            Req::put("/v1/me/password")
                .token(&alice.access_token)
                .reauth(&reauth)
                .json(&body),
        )
        .await;
    assert_eq!(response.code(), "kdf_params_invalid");
    let mut body = body;
    body.as_object_mut()
        .unwrap()
        .remove("revoke_other_sessions");
    let response = t
        .call(
            Req::put("/v1/me/password")
                .token(&alice.access_token)
                .reauth(&reauth)
                .json(&body),
        )
        .await;
    assert_eq!(
        response.field_error(),
        ("/revoke_other_sessions".into(), "missing field".into())
    );
    // Reauth comes before the body checks.
    let response = t
        .call(
            Req::put("/v1/me/password")
                .token(&alice.access_token)
                .raw(Some("text/plain"), b"x"),
        )
        .await;
    assert_eq!(response.code(), "reauth_required");
}

#[tokio::test]
async fn recovery_change_replaces_only_the_recovery_material() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let before: String = sqlx::query_scalar("SELECT recovery_auth_hash FROM users")
        .fetch_one(&t.app.db.read)
        .await
        .unwrap();
    let reauth = t.reauth(&alice).await;
    let body = json!({ "auth_key": random_b64::<32>(), "user_key_wrapped": envelope(73) });
    let response = t
        .call(
            Req::put("/v1/me/recovery")
                .token(&alice.access_token)
                .reauth(&reauth)
                .json(&body),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    let after: String = sqlx::query_scalar("SELECT recovery_auth_hash FROM users")
        .fetch_one(&t.app.db.read)
        .await
        .unwrap();
    assert_ne!(before, after);
    assert_eq!(
        t.call(Req::get("/v1/me").token(&other.access_token))
            .await
            .status,
        StatusCode::OK
    );
    assert!(
        t.security_events()
            .await
            .contains(&"recovery_changed".to_string())
    );
}

#[tokio::test]
async fn sessions_are_listed_newest_first() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    t.advance(Duration::minutes(2));
    let second = t.login(&alice).await;
    let response = t
        .call(Req::get("/v1/me/sessions").token(&second.access_token))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let sessions = response.json()["sessions"].as_array().unwrap().clone();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0]["id"].as_str(), Some(second.session_id.as_str()));
    assert_eq!(sessions[0]["current"], true);
    assert_eq!(sessions[1]["current"], false);
    assert_eq!(sessions[0]["device_name"], "Test device");
    assert_eq!(sessions[0]["client_type"], "cli");
    let hint = sessions[0]["ip_hint"].as_str().unwrap();
    assert!(
        hint.starts_with("198.51.") && hint.ends_with(".x"),
        "{hint}"
    );
    assert_eq!(sessions[1]["created"], "2026-10-23T08:00:00.000Z");

    // last_seen moves at most once per minute.
    t.advance(Duration::seconds(30));
    t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    let sessions = t
        .call(Req::get("/v1/me/sessions").token(&second.access_token))
        .await
        .json()["sessions"]
        .clone();
    assert_eq!(
        sessions[0]["id"].as_str(),
        Some(alice.session_id.as_str()),
        "now the most recently used"
    );
    assert_eq!(
        sessions[0]["last_seen"], "2026-10-23T08:02:30.000Z",
        "first use after more than a minute"
    );
    t.advance(Duration::seconds(30));
    t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    let sessions = t
        .call(Req::get("/v1/me/sessions").token(&second.access_token))
        .await
        .json()["sessions"]
        .clone();
    let alice_session = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"].as_str() == Some(alice.session_id.as_str()))
        .unwrap();
    assert_eq!(
        alice_session["last_seen"], "2026-10-23T08:02:30.000Z",
        "not again within a minute"
    );
}

#[tokio::test]
async fn revoking_single_sessions() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let second = t.login(&alice).await;
    let bob = t.register("bob@example.com").await;

    let path = |id: &str| format!("/v1/me/sessions/{id}");
    let response = t
        .call(Req::delete(&path(&bob.session_id)).token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "foreign session");
    assert_eq!(response.code(), "not_found");
    let response = t
        .call(Req::delete(&path(&support::new_uuid())).token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "unknown session");
    let response = t
        .call(Req::delete(&path("NOT-A-UUID")).token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    let response = t
        .call(Req::delete(&path(&second.session_id)).token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(
        t.call(Req::get("/v1/me").token(&second.access_token))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let response = t
        .call(Req::delete(&path(&second.session_id)).token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "already revoked");

    // The own session works like logout, without clearing the cookie.
    let response = t
        .call(Req::delete(&path(&alice.session_id)).token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(response.set_cookies().is_empty());
    assert_eq!(
        t.call(Req::get("/v1/me").token(&alice.access_token))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.call(Req::get("/v1/me").token(&bob.access_token))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn revoking_other_sessions_needs_the_scope() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let second = t.login(&alice).await;
    let third = t.login(&alice).await;
    for query in [
        "",
        "?scope=all",
        "?scope=others&scope=others",
        "?scope=others&x=1",
    ] {
        let response = t
            .call(Req::delete(&format!("/v1/me/sessions{query}")).token(&alice.access_token))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(response.code(), "validation_failed");
    }
    assert_eq!(
        t.call(Req::get("/v1/me").token(&second.access_token))
            .await
            .status,
        StatusCode::OK
    );
    let response = t
        .call(Req::delete("/v1/me/sessions?scope=others").token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    for revoked in [&second, &third] {
        assert_eq!(
            t.call(Req::get("/v1/me").token(&revoked.access_token))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        t.call(Req::get("/v1/me").token(&alice.access_token))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM security_log WHERE event = 'session_revoked' AND detail LIKE '%others%'").await, 2);
}

#[tokio::test]
async fn delete_account_removes_solo_vaults_and_leaves_shared_ones() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let dave = t.register("dave@example.com").await;
    let erin = t.register("erin@example.com").await;
    let solo = t.create_vault(&alice).await;
    let bobs = t.create_vault(&bob).await;
    t.add_member(&bobs, &alice, "member", "active").await;
    let shared = t.create_vault(&alice).await;
    t.add_member(&shared, &dave, "owner", "active").await;
    t.add_member(&shared, &erin, "member", "pending").await;
    t.sql(&format!(
        "UPDATE memberships SET sender_id = '{}' WHERE vault_id = '{shared}' AND user_id = '{}'",
        alice.user_id, erin.user_id
    ))
    .await;
    let invited = t.create_vault(&bob).await;
    t.add_member(&invited, &alice, "member", "pending").await;

    let response = t
        .call(Req::delete("/v1/me").token(&alice.access_token))
        .await;
    assert_eq!(response.code(), "reauth_required");

    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete("/v1/me")
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
    assert!(
        response
            .set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-keeman_rt=;") && c.contains("Max-Age=0"))
    );

    let id = &alice.user_id;
    for (table, column) in [
        ("users", "id"),
        ("sessions", "user_id"),
        ("memberships", "user_id"),
        ("idempotency", "user_id"),
        ("challenges", "user_id"),
    ] {
        assert_eq!(
            t.count(&format!(
                "SELECT COUNT(*) FROM {table} WHERE {column} = '{id}'"
            ))
            .await,
            0,
            "{table}"
        );
    }
    let vault_exists = |v: &str| format!("SELECT COUNT(*) FROM vaults WHERE id = '{v}'");
    assert_eq!(t.count(&vault_exists(&solo)).await, 0);
    for vault in [&bobs, &shared] {
        assert_eq!(
            t.count(&format!(
                "SELECT rotation_required FROM vaults WHERE id = '{vault}'"
            ))
            .await,
            1
        );
    }
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM memberships WHERE vault_id = '{shared}' AND user_id = '{}'",
            erin.user_id
        ))
        .await,
        0,
        "the invitation sent by the deleted account is dropped"
    );
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM security_log WHERE event = 'account_deleted' AND user_id = '{id}'"
        ))
        .await,
        1
    );

    let response = t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&support::unique_ip()),
        )
        .await;
    assert_eq!(response.code(), "invalid_credentials");
}

#[tokio::test]
async fn delete_account_refuses_the_sole_owner_of_a_shared_vault() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault = t.create_vault(&alice).await;
    t.add_member(&vault, &bob, "member", "pending").await;
    let reauth = t.reauth(&alice).await;
    // A pending invitation does not count.
    t.add_member(&t.create_vault(&alice).await, &bob, "member", "active")
        .await;
    let response = t
        .call(
            Req::delete("/v1/me")
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "sole_owner_of_shared_vault");
    assert_eq!(t.count("SELECT COUNT(*) FROM users").await, 2);

    t.sql(&format!(
        "DELETE FROM memberships WHERE user_id = '{}' AND state = 'active'",
        bob.user_id
    ))
    .await;
    let response = t
        .call(
            Req::delete("/v1/me")
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(t.count("SELECT COUNT(*) FROM vaults").await, 0);
}
