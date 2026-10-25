//! The security log stays within its caps per account (or without one),
//! event and day; more entries are only counted.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use serde_json::json;
use support::{Account, Req, TestApp, unique_ip};
use time::Duration;

async fn test_app() -> TestApp {
    TestApp::with_config(
        "[logging]\nsecurity_log_per_account_per_day = 3\nsecurity_log_anonymous_per_day = 2\n\
         [rate_limits]\ncredential_per_email_per_min = 1000\ncredential_per_ip_per_min = 1000\n",
    )
    .await
}

async fn wrong_reauth(t: &TestApp, account: &Account) {
    let response = t
        .call(
            Req::post("/v1/me/reauth")
                .token(&account.access_token)
                .json(&json!({ "auth_key": support::random_b64::<32>() }))
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.code(), "invalid_credentials");
}

async fn unknown_login(t: &TestApp) {
    let stranger = Account::new("nobody@example.com");
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&stranger.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.code(), "invalid_credentials");
}

async fn entries(t: &TestApp, user: Option<&str>, event: &str) -> i64 {
    let user = user.map_or("IS NULL".to_string(), |id| format!("= '{id}'"));
    t.count(&format!(
        "SELECT COUNT(*) FROM security_log WHERE user_id {user} AND event = '{event}'"
    ))
    .await
}

async fn suppressed(t: &TestApp, user: Option<&str>, event: &str) -> i64 {
    let user = user.map_or("IS NULL".to_string(), |id| format!("= '{id}'"));
    t.count(&format!(
        "SELECT COALESCE(SUM(json_extract(detail, '$.suppressed')), 0) FROM security_log
         WHERE user_id {user} AND event = 'log_capped' AND json_extract(detail, '$.event') = '{event}'"
    ))
    .await
}

#[tokio::test]
async fn a_flood_of_one_event_is_counted_not_logged() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    for _ in 0..7 {
        wrong_reauth(&t, &alice).await;
    }
    let id = Some(alice.user_id.as_str());
    assert_eq!(entries(&t, id, "reauth_failed").await, 3);
    assert_eq!(suppressed(&t, id, "reauth_failed").await, 4);
    assert_eq!(
        entries(&t, id, "log_capped").await,
        1,
        "one summary per day"
    );
    // Another event of the same account is still logged.
    t.login(&alice).await;
    assert_eq!(entries(&t, id, "login_ok").await, 1);
    // The next day starts a new count.
    t.advance(Duration::days(1));
    let alice = t.login(&alice).await;
    wrong_reauth(&t, &alice).await;
    assert_eq!(entries(&t, id, "reauth_failed").await, 4);
    assert_eq!(entries(&t, id, "log_capped").await, 1);
}

#[tokio::test]
async fn events_without_an_account_have_their_own_cap() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    for _ in 0..5 {
        unknown_login(&t).await;
    }
    assert_eq!(entries(&t, None, "login_failed").await, 2);
    assert_eq!(suppressed(&t, None, "login_failed").await, 3);
    // Accounts are not affected by the flood without one.
    let mut wrong = alice.clone();
    wrong.auth_key = support::random_b64::<32>();
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&wrong.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.code(), "invalid_credentials");
    assert_eq!(entries(&t, Some(&alice.user_id), "login_failed").await, 1);
}
