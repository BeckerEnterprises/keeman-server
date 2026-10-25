//! Requests overtaken by a commit between their checks and their write
//! transaction. The test holds the write lock, waits until the request
//! reaches its own transaction, changes what the request checked before
//! and lets go. Only the state in the request's transaction may count.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use support::{Account, Req, TestApp, envelope, random_b64, sql_in, unique_ip};

async fn test_app() -> TestApp {
    TestApp::with_config("[rate_limits]\ncredential_per_email_per_min = 1000\n").await
}

fn login(account: &Account) -> Request<Body> {
    Req::post("/v1/auth/login")
        .json(&account.login_body())
        .peer(&unique_ip())
        .build()
}

fn password_change(account: &Account, reauth: &str) -> Request<Body> {
    let body = json!({
        "kdf": { "alg": "argon2id13", "ops": 3, "mem": 67108864 },
        "salt": random_b64::<16>(),
        "auth_key": random_b64::<32>(),
        "user_key_wrapped": envelope(73),
        "revoke_other_sessions": true,
    });
    Req::put("/v1/me/password")
        .token(&account.access_token)
        .reauth(reauth)
        .json(&body)
        .build()
}

async fn sessions(t: &TestApp, account: &Account) -> i64 {
    t.count(&format!(
        "SELECT COUNT(*) FROM sessions WHERE user_id = '{}' AND revoked_at IS NULL",
        account.user_id
    ))
    .await
}

/// What revoking a session commits (as `DELETE /v1/me/sessions/{id}` does).
fn revoke(session_id: &str) -> String {
    format!(
        "UPDATE sessions SET revoked_at = '2026-10-23T08:00:00.000Z' WHERE id = '{session_id}';
         DELETE FROM access_tokens WHERE session_id = '{session_id}';
         DELETE FROM challenges WHERE session_id = '{session_id}';"
    )
}

#[tokio::test]
async fn a_login_overtaken_by_a_password_change_gets_no_session() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let before = sessions(&t, &alice).await;
    let mut tx = t.app.db.begin().await.unwrap();
    let pending = t.spawn(login(&alice));
    t.writers_waiting(1).await;
    sql_in(
        &mut tx,
        &format!(
            "UPDATE users SET auth_hash = 'changed' WHERE id = '{}'",
            alice.user_id
        ),
    )
    .await;
    tx.commit().await.unwrap();
    let response = pending.await.unwrap();
    assert_eq!(response.code(), "invalid_credentials");
    assert_eq!(sessions(&t, &alice).await, before);
    assert_eq!(t.security_events().await.last().unwrap(), "login_failed");
}

#[tokio::test]
async fn a_login_overtaken_by_a_new_second_factor_asks_for_it() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let before = sessions(&t, &alice).await;
    let mut tx = t.app.db.begin().await.unwrap();
    let pending = t.spawn(login(&alice));
    t.writers_waiting(1).await;
    t.enable_totp_in(&mut tx, &alice).await;
    tx.commit().await.unwrap();
    let response = pending.await.unwrap();
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["status"], "second_factor_required");
    assert_eq!(sessions(&t, &alice).await, before);
}

#[tokio::test]
async fn a_login_overtaken_by_disabling_the_account_is_refused() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let mut tx = t.app.db.begin().await.unwrap();
    let pending = t.spawn(login(&alice));
    t.writers_waiting(1).await;
    sql_in(
        &mut tx,
        &format!(
            "UPDATE users SET disabled = 1 WHERE id = '{}'",
            alice.user_id
        ),
    )
    .await;
    tx.commit().await.unwrap();
    let response = pending.await.unwrap();
    assert_eq!(response.code(), "account_disabled");
}

#[tokio::test]
async fn a_recovery_overtaken_by_a_new_recovery_key_fails() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let body = json!({ "email": alice.email, "recovery_auth_key": alice.recovery_auth_key });
    let mut tx = t.app.db.begin().await.unwrap();
    let pending = t.spawn(
        Req::post("/v1/auth/recover/start")
            .json(&body)
            .peer(&unique_ip())
            .build(),
    );
    t.writers_waiting(1).await;
    sql_in(
        &mut tx,
        &format!(
            "UPDATE users SET recovery_auth_hash = 'changed' WHERE id = '{}'",
            alice.user_id
        ),
    )
    .await;
    tx.commit().await.unwrap();
    let response = pending.await.unwrap();
    assert_eq!(response.code(), "invalid_credentials");
    assert_eq!(
        t.count("SELECT COUNT(*) FROM challenges WHERE purpose = 'recovery_finish'")
            .await,
        0
    );
}

#[tokio::test]
async fn a_reauth_overtaken_by_a_revocation_issues_no_token() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let mut tx = t.app.db.begin().await.unwrap();
    let pending = t.spawn(
        Req::post("/v1/me/reauth")
            .token(&alice.access_token)
            .json(&json!({ "auth_key": alice.auth_key }))
            .peer(&unique_ip())
            .build(),
    );
    t.writers_waiting(1).await;
    sql_in(&mut tx, &revoke(&alice.session_id)).await;
    tx.commit().await.unwrap();
    let response = pending.await.unwrap();
    assert_eq!(response.code(), "session_invalid");
    assert_eq!(
        t.count("SELECT COUNT(*) FROM challenges WHERE purpose = 'reauth'")
            .await,
        0
    );
}

#[tokio::test]
async fn a_reauth_overtaken_by_a_password_change_fails() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let mut tx = t.app.db.begin().await.unwrap();
    let pending = t.spawn(
        Req::post("/v1/me/reauth")
            .token(&alice.access_token)
            .json(&json!({ "auth_key": alice.auth_key }))
            .peer(&unique_ip())
            .build(),
    );
    t.writers_waiting(1).await;
    sql_in(
        &mut tx,
        &format!(
            "UPDATE users SET auth_hash = 'changed' WHERE id = '{}'",
            alice.user_id
        ),
    )
    .await;
    tx.commit().await.unwrap();
    let response = pending.await.unwrap();
    assert_eq!(response.code(), "invalid_credentials");
    assert_eq!(
        t.count("SELECT COUNT(*) FROM challenges WHERE purpose = 'reauth'")
            .await,
        0
    );
}

#[tokio::test]
async fn a_password_change_overtaken_by_a_revocation_changes_nothing() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let reauth = t.reauth(&alice).await;
    let hash = format!("SELECT auth_hash FROM users WHERE id = '{}'", alice.user_id);
    let before = t.text(&hash).await;
    let mut tx = t.app.db.begin().await.unwrap();
    let pending = t.spawn(password_change(&alice, &reauth));
    t.writers_waiting(1).await;
    sql_in(&mut tx, &revoke(&alice.session_id)).await;
    tx.commit().await.unwrap();
    let response = pending.await.unwrap();
    assert_eq!(response.code(), "reauth_required");
    assert_eq!(t.text(&hash).await, before);
}

#[tokio::test]
async fn of_two_password_changes_with_one_token_only_the_first_works() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let reauth = t.reauth(&alice).await;
    let tx = t.app.db.begin().await.unwrap();
    let first = t.spawn(password_change(&alice, &reauth));
    t.writers_waiting(1).await;
    let second = t.spawn(password_change(&alice, &reauth));
    t.writers_waiting(2).await;
    tx.commit().await.unwrap();
    let mut outcomes = [first.await.unwrap(), second.await.unwrap()]
        .into_iter()
        .map(|response| match response.status {
            StatusCode::NO_CONTENT => "changed".to_string(),
            _ => response.code(),
        })
        .collect::<Vec<_>>();
    outcomes.sort();
    assert_eq!(outcomes, ["changed", "reauth_required"]);
}

#[tokio::test]
async fn a_revoked_session_cannot_sign_out_the_others() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let mut tx = t.app.db.begin().await.unwrap();
    let pending = t.spawn(
        Req::delete("/v1/me/sessions?scope=others")
            .token(&alice.access_token)
            .build(),
    );
    t.writers_waiting(1).await;
    sql_in(&mut tx, &revoke(&alice.session_id)).await;
    tx.commit().await.unwrap();
    let response = pending.await.unwrap();
    assert_eq!(response.code(), "session_invalid");
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM sessions WHERE id = '{}' AND revoked_at IS NULL",
            other.session_id
        ))
        .await,
        1
    );
}
