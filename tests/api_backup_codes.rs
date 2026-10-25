//! Backup codes at login and their management.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{Req, TestApp, unique_ip};

async fn test_app() -> TestApp {
    TestApp::with_config("[rate_limits]\ncredential_per_email_per_min = 1000\n").await
}

async fn backup_raw(t: &TestApp, challenge: &str, code: &str) -> support::TestResponse {
    let body = json!({ "challenge_token": challenge, "code": code });
    t.call(
        Req::post("/v1/auth/2fa/backup-code")
            .json(&body)
            .peer(&unique_ip()),
    )
    .await
}

#[tokio::test]
async fn backup_codes_log_in_once_each() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    t.enable_totp_direct(&alice).await;
    t.set_backup_codes(&alice, &["AAAAAAAAAA", "BBBBBBBBBB", "CCCCCCCCCC"])
        .await;

    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.json()["methods"], json!(["totp", "backup_code"]));
    let challenge = response.json()["challenge_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Normalised: lower case, spaces and hyphens.
    let response = backup_raw(&t, &challenge, "bbbbb-bbbbb").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["status"], "ok");
    assert_eq!(response.json()["backup_codes_remaining"], 2);
    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM security_log WHERE event = 'login_ok'
               AND json_extract(detail, '$.method') = 'backup_code'"
        )
        .await,
        1
    );

    // The same code a second time fails; another one works.
    let challenge = t.login_challenge(&alice).await;
    let response = backup_raw(&t, &challenge, "BBBBB BBBBB").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.code(), "invalid_second_factor");
    let response = backup_raw(&t, &challenge, "CCCCCCCCCC").await;
    assert_eq!(response.json()["backup_codes_remaining"], 1);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM backup_codes WHERE used_at IS NOT NULL")
            .await,
        2
    );
}

#[tokio::test]
async fn malformed_backup_codes_are_400_and_do_not_count() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    t.enable_totp_direct(&alice).await;
    t.set_backup_codes(&alice, &["AAAAAAAAAA"]).await;
    let challenge = t.login_challenge(&alice).await;
    for bad in [
        "AAAAAAAAA",
        "AAAAAAAAAAA",
        "AAAAAAAAA1",
        "AAAAA_AAAAA",
        "AAAAAAAAAA ",
    ] {
        let response = backup_raw(&t, &challenge, bad).await;
        if bad == "AAAAAAAAAA " {
            assert_eq!(response.status, StatusCode::OK, "trailing space is fine");
            continue;
        }
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(response.field_error().0, "/code");
    }
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = '2fa_failed'")
            .await,
        0
    );
}

#[tokio::test]
async fn backup_codes_also_complete_a_challenge_with_wrong_attempts_before() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;
    t.set_backup_codes(&alice, &["AAAAAAAAAA"]).await;
    let challenge = t.login_challenge(&alice).await;
    let window = [t.totp(&secret, -1), t.totp(&secret, 0), t.totp(&secret, 1)];
    let wrong = (0..)
        .map(|n| format!("{n:06}"))
        .find(|c| !window.contains(c))
        .unwrap();
    let body = json!({ "challenge_token": challenge, "code": wrong });
    let response = t
        .call(
            Req::post("/v1/auth/2fa/totp")
                .json(&body)
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.code(), "invalid_second_factor");
    let response = backup_raw(&t, &challenge, "AAAAAAAAAA").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["backup_codes_remaining"], 0);
    // Without unused codes the method is no longer offered.
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.json()["methods"], json!(["totp"]));
}

#[tokio::test]
async fn regenerating_replaces_all_codes() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let reauth = t.reauth(&alice).await;
    let regenerate = |reauth: Option<String>| {
        let t = &t;
        let token = alice.access_token.clone();
        async move {
            let mut request = Req::post("/v1/me/backup-codes").token(&token);
            if let Some(reauth) = reauth {
                request = request.reauth(&reauth);
            }
            t.call(request).await
        }
    };
    let response = regenerate(Some(reauth.clone())).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "no second factor");
    assert_eq!(response.code(), "two_factor_state_invalid");

    let (_, body) = t.enable_totp(&alice).await;
    let old = body["backup_codes"][0].as_str().unwrap().to_string();
    let response = regenerate(None).await;
    assert_eq!(response.code(), "reauth_required");
    let reauth = t.reauth(&alice).await;
    let response = regenerate(Some(reauth)).await;
    assert_eq!(response.status, StatusCode::OK);
    let codes = response.json()["backup_codes"].as_array().unwrap().clone();
    assert_eq!(codes.len(), 10);
    assert!(!codes.contains(&json!(old)));
    assert_eq!(t.count("SELECT COUNT(*) FROM backup_codes").await, 10);
    assert!(
        t.security_events()
            .await
            .contains(&"backup_codes_regenerated".to_string())
    );

    let challenge = t.login_challenge(&alice).await;
    let response = backup_raw(&t, &challenge, &old).await;
    assert_eq!(
        response.code(),
        "invalid_second_factor",
        "old codes are gone"
    );
    let response = backup_raw(&t, &challenge, codes[9].as_str().unwrap()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["backup_codes_remaining"], 9);
}
