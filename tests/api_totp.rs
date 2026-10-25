//! Second factor at login: TOTP, challenges and the lockout
//! across password and second factor.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{Req, TestApp, unique_ip};
use time::Duration;

async fn totp_raw(t: &TestApp, challenge: &str, code: &str) -> support::TestResponse {
    let body = json!({ "challenge_token": challenge, "code": code });
    t.call(
        Req::post("/v1/auth/2fa/totp")
            .json(&body)
            .peer(&unique_ip()),
    )
    .await
}

/// Without the per-address rate limit, so time stays in one TOTP step; the
/// lockout tests advance the clock themselves.
async fn test_app() -> TestApp {
    TestApp::with_config("[rate_limits]\ncredential_per_email_per_min = 1000\n").await
}

async fn login_raw(t: &TestApp, body: &Value) -> support::TestResponse {
    t.call(Req::post("/v1/auth/login").json(body).peer(&unique_ip()))
        .await
}

#[tokio::test]
async fn login_with_totp_creates_the_session_of_the_challenge() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;
    let challenge = t.login_challenge(&alice).await;
    assert_eq!(
        t.count("SELECT COUNT(*) FROM sessions").await,
        1,
        "no session yet"
    );

    let response = totp_raw(&t, &challenge, &t.totp(&secret, 0)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["user_id"], alice.user_id.as_str());
    assert_eq!(body["refresh_token"].as_str().unwrap().len(), 43, "native");
    assert!(body.get("backup_codes_remaining").is_none());
    let session = alice.clone().with_session(&response);
    let me = t
        .call(Req::get("/v1/me").token(&session.access_token))
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM sessions WHERE device_name = 'Test device'")
            .await,
        2
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM challenges").await,
        0,
        "consumed"
    );
    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM security_log WHERE event = 'login_ok'
               AND json_extract(detail, '$.method') = 'totp'"
        )
        .await,
        1
    );
    // The challenge is used up.
    let again = totp_raw(&t, &challenge, &t.totp(&secret, 1)).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert_eq!(again.code(), "challenge_invalid");
}

#[tokio::test]
async fn web_login_with_totp_sets_the_cookie() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;
    let mut body = alice.login_body();
    body["device"] = json!({ "name": "Firefox · Linux", "client_type": "web" });
    let challenge = login_raw(&t, &body).await.json()["challenge_token"]
        .as_str()
        .unwrap()
        .to_string();
    let response = totp_raw(&t, &challenge, &t.totp(&secret, 0)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.json().get("refresh_token").is_none());
    assert!(response.cookie_value("__Host-keeman_rt").is_some());
    assert_eq!(
        t.count("SELECT COUNT(*) FROM sessions WHERE client_type = 'web' AND device_name = 'Firefox · Linux'")
            .await,
        1
    );
}

#[tokio::test]
async fn codes_are_single_use_within_one_step_either_way() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;

    let challenge = t.login_challenge(&alice).await;
    assert_eq!(
        totp_raw(&t, &challenge, &t.totp(&secret, 0)).await.status,
        StatusCode::OK
    );
    // Replay of the same code and an older one with a fresh challenge.
    let challenge = t.login_challenge(&alice).await;
    for offset in [0, -1] {
        let response = totp_raw(&t, &challenge, &t.totp(&secret, offset)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "offset {offset}");
        assert_eq!(response.code(), "invalid_second_factor");
    }
    // ±2 steps are outside the window.
    for offset in [2, -2] {
        let response = totp_raw(&t, &challenge, &t.totp(&secret, offset)).await;
        assert_eq!(response.code(), "invalid_second_factor", "offset {offset}");
    }
    // The next step works once.
    assert_eq!(
        totp_raw(&t, &challenge, &t.totp(&secret, 1)).await.status,
        StatusCode::OK
    );
    t.advance(Duration::seconds(90));
    let challenge = t.login_challenge(&alice).await;
    assert_eq!(
        totp_raw(&t, &challenge, &t.totp(&secret, -1)).await.status,
        StatusCode::OK,
        "one step back is fine once it is newer than the last"
    );
}

#[tokio::test]
async fn five_failures_use_up_the_challenge() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;
    let wrong = wrong_code(&t, &secret);
    let challenge = t.login_challenge(&alice).await;
    for attempt in 1..=5 {
        let response = totp_raw(&t, &challenge, &wrong).await;
        assert_eq!(
            response.code(),
            "invalid_second_factor",
            "attempt {attempt}"
        );
    }
    let response = totp_raw(&t, &challenge, &t.totp(&secret, 0)).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.code(), "challenge_invalid");
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = '2fa_failed'")
            .await,
        5
    );
}

/// A code that is none of the three accepted ones right now.
fn wrong_code(t: &TestApp, secret: &[u8; 20]) -> String {
    let window = [t.totp(secret, -1), t.totp(secret, 0), t.totp(secret, 1)];
    (0..)
        .map(|n| format!("{n:06}"))
        .find(|c| !window.contains(c))
        .unwrap()
}

#[tokio::test]
async fn lockout_counts_second_factors_and_the_password_alone_does_not_reset() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;
    let mut failures = 0;
    while failures < 9 {
        let challenge = t.login_challenge(&alice).await;
        for _ in 0..3 {
            if failures == 9 {
                break;
            }
            t.advance(Duration::seconds(12));
            let wrong = wrong_code(&t, &secret);
            assert_eq!(
                totp_raw(&t, &challenge, &wrong).await.code(),
                "invalid_second_factor"
            );
            failures += 1;
        }
        t.advance(Duration::seconds(12));
    }
    // The correct auth key gives a challenge but does not reset the counter.
    let challenge = t.login_challenge(&alice).await;
    t.advance(Duration::seconds(12));
    let wrong = wrong_code(&t, &secret);
    assert_eq!(
        totp_raw(&t, &challenge, &wrong).await.code(),
        "invalid_second_factor",
        "the tenth failure still answers 401"
    );
    t.advance(Duration::seconds(12));
    let response = totp_raw(&t, &challenge, &t.totp(&secret, 0)).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS, "locked");
    let response = login_raw(&t, &alice.login_body()).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = 'login_locked'")
            .await,
        1
    );

    // After the lock, a complete login resets the counter.
    t.advance(Duration::minutes(15));
    let challenge = t.login_challenge(&alice).await;
    t.advance(Duration::seconds(12));
    assert_eq!(
        totp_raw(&t, &challenge, &t.totp(&secret, 0)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM login_throttle WHERE failures > 0 OR locked_until IS NOT NULL"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn challenge_tokens_are_checked() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;
    let code = t.totp(&secret, 0);

    let unknown = totp_raw(&t, &support::random_b64::<32>(), &code).await;
    assert_eq!(unknown.code(), "challenge_invalid");

    // A reauth token is a challenge of another purpose.
    let reauth = t.reauth(&alice).await;
    let response = totp_raw(&t, &reauth, &code).await;
    assert_eq!(response.code(), "challenge_invalid");

    let challenge = t.login_challenge(&alice).await;
    t.advance(Duration::minutes(5));
    let response = totp_raw(&t, &challenge, &code).await;
    assert_eq!(response.code(), "challenge_invalid", "expired");
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = '2fa_failed'")
            .await,
        0,
        "invalid challenges are no failures"
    );

    // Structure before the challenge.
    let challenge = t.login_challenge(&alice).await;
    for bad in ["12345", "1234567", "abcdef"] {
        let response = totp_raw(&t, &challenge, bad).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(response.field_error().0, "/code");
    }
    let response = t
        .call(
            Req::post("/v1/auth/2fa/totp")
                .json(&json!({ "challenge_token": challenge, "code": code, "extra": 1 }))
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn totp_turned_off_meanwhile_is_a_failure() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;
    t.set_backup_codes(&alice, &["AAAAAAAAAA"]).await;
    let challenge = t.login_challenge(&alice).await;
    t.sql("UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL")
        .await;
    let response = totp_raw(&t, &challenge, &t.totp(&secret, 0)).await;
    assert_eq!(response.code(), "invalid_second_factor");
}

#[tokio::test]
async fn disabled_account_after_the_second_factor() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;
    let challenge = t.login_challenge(&alice).await;
    t.sql("UPDATE users SET disabled = 1").await;
    let wrong = wrong_code(&t, &secret);
    assert_eq!(
        totp_raw(&t, &challenge, &wrong).await.code(),
        "invalid_second_factor",
        "disabled only after a correct factor"
    );
    let response = totp_raw(&t, &challenge, &t.totp(&secret, 0)).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.code(), "account_disabled");
    assert_eq!(t.count("SELECT COUNT(*) FROM challenges").await, 0);
    assert_eq!(t.count("SELECT COUNT(*) FROM sessions").await, 1);
}

#[tokio::test]
async fn second_factor_endpoints_share_the_ip_bucket() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    t.enable_totp_direct(&alice).await;
    let ip = unique_ip();
    for _ in 0..10 {
        let body = json!({ "challenge_token": support::random_b64::<32>(), "code": "123456" });
        let response = t
            .call(Req::post("/v1/auth/2fa/totp").json(&body).peer(&ip))
            .await;
        assert_eq!(response.code(), "challenge_invalid");
    }
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&ip),
        )
        .await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn account_disabled_at_login_does_not_reset_the_counter() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let mut wrong = alice.login_body();
    wrong["auth_key"] = json!(support::random_b64::<32>());
    for _ in 0..9 {
        assert_eq!(login_raw(&t, &wrong).await.code(), "invalid_credentials");
        t.advance(Duration::seconds(12));
    }
    t.sql("UPDATE users SET disabled = 1").await;
    assert_eq!(
        login_raw(&t, &alice.login_body()).await.code(),
        "account_disabled"
    );
    t.advance(Duration::seconds(12));
    t.sql("UPDATE users SET disabled = 0").await;
    login_raw(&t, &wrong).await;
    t.advance(Duration::seconds(12));
    assert_eq!(
        login_raw(&t, &alice.login_body()).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn second_factor_counts_against_the_address_bucket() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let secret = t.enable_totp_direct(&alice).await;
    let challenge = t.login_challenge(&alice).await;
    let wrong = wrong_code(&t, &secret);
    // The login took one token of 5 per minute.
    for _ in 0..4 {
        assert_eq!(
            totp_raw(&t, &challenge, &wrong).await.code(),
            "invalid_second_factor"
        );
    }
    let response = totp_raw(&t, &challenge, &t.totp(&secret, 0)).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.header("retry-after").as_deref(), Some("12"));
}

// ---------------------------------------------------------------- management

async fn setup_raw(t: &TestApp, token: &str, reauth: Option<&str>) -> support::TestResponse {
    let mut request = Req::post("/v1/me/totp/setup").token(token);
    if let Some(reauth) = reauth {
        request = request.reauth(reauth);
    }
    t.call(request).await
}

async fn enable_raw(t: &TestApp, token: &str, code: &str) -> support::TestResponse {
    t.call(
        Req::post("/v1/me/totp/enable")
            .token(token)
            .json(&json!({ "code": code })),
    )
    .await
}

fn secret_of(response: &support::TestResponse) -> [u8; 20] {
    let text = response.json()["secret"].as_str().unwrap().to_string();
    keeman_server::crypto::base32::decode(&text)
        .unwrap()
        .try_into()
        .unwrap()
}

#[tokio::test]
async fn setup_needs_reauth_and_returns_secret_and_key_uri() {
    let t = test_app().await;
    let alice = t.register("alice+x@example.com").await;
    let response = setup_raw(&t, &alice.access_token, None).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.code(), "reauth_required");

    let reauth = t.reauth(&alice).await;
    let response = setup_raw(&t, &alice.access_token, Some(&reauth)).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    let secret = body["secret"].as_str().unwrap();
    assert_eq!(secret.len(), 32);
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
    );
    assert_eq!(
        body["otpauth_uri"],
        format!("otpauth://totp/KeeMan:alice%2Bx%40example.com?secret={secret}&issuer=KeeMan")
    );
    // Not active yet; the secret lives encrypted at the setup.
    let me = t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    assert_eq!(me.json()["two_factor"]["totp"], false);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM users WHERE totp_secret_enc IS NOT NULL")
            .await,
        0
    );
    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM challenges WHERE purpose = 'totp_setup'
               AND length(json_extract(state, '$.secret')) = 82"
        )
        .await,
        1,
        "61 sealed bytes as Base64url"
    );
}

#[tokio::test]
async fn enable_activates_totp_with_backup_codes_for_the_first_factor() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let (secret, body) = t.enable_totp(&alice).await;
    let codes = body["backup_codes"].as_array().unwrap();
    assert_eq!(codes.len(), 10);
    for code in codes {
        let code = code.as_str().unwrap();
        assert_eq!(code.len(), 10);
        assert!(
            code.bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
        );
    }
    let me = t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    assert_eq!(
        me.json()["two_factor"],
        json!({ "totp": true, "webauthn_credentials": 0, "backup_codes_remaining": 10 })
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM challenges WHERE purpose = 'totp_setup'")
            .await,
        0
    );
    assert!(
        t.security_events()
            .await
            .contains(&"totp_enabled".to_string())
    );
    // The enabling code cannot log in again (it set the last step).
    let challenge = t.login_challenge(&alice).await;
    let response = totp_raw(&t, &challenge, &t.totp(&secret, 0)).await;
    assert_eq!(response.code(), "invalid_second_factor");
    let response = totp_raw(&t, &challenge, &t.totp(&secret, 1)).await;
    assert_eq!(response.status, StatusCode::OK);
    // A backup code from the list works.
    let challenge = t.login_challenge(&alice).await;
    let body = json!({ "challenge_token": challenge, "code": codes[3] });
    let response = t
        .call(
            Req::post("/v1/auth/2fa/backup-code")
                .json(&body)
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.json()["backup_codes_remaining"], 9);
    // The existing session stays.
    let me = t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    assert_eq!(me.status, StatusCode::OK);
}

#[tokio::test]
async fn enable_rules() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    // Without a setup.
    let response = enable_raw(&t, &alice.access_token, "123456").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.code(), "challenge_invalid");

    let reauth = t.reauth(&alice).await;
    let first = setup_raw(&t, &alice.access_token, Some(&reauth)).await;
    let second = setup_raw(&t, &alice.access_token, Some(&reauth)).await;
    let (old, new) = (secret_of(&first), secret_of(&second));
    assert_ne!(old, new);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM challenges WHERE purpose = 'totp_setup'")
            .await,
        1,
        "a new setup replaces the open one"
    );
    // Another session of the account has no setup.
    let other = t.login(&alice).await;
    let response = enable_raw(&t, &other.access_token, &t.totp(&new, 0)).await;
    assert_eq!(response.code(), "challenge_invalid");
    // Five wrong codes use up the setup; they do not count for the lockout.
    let window = [t.totp(&new, -1), t.totp(&new, 0), t.totp(&new, 1)];
    let wrong = if window.contains(&t.totp(&old, 0)) {
        "000000".to_string()
    } else {
        t.totp(&old, 0)
    };
    for attempt in 1..=5 {
        let response = enable_raw(&t, &alice.access_token, &wrong).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{attempt}");
        assert_eq!(response.code(), "invalid_second_factor");
    }
    let response = enable_raw(&t, &alice.access_token, &t.totp(&new, 0)).await;
    assert_eq!(response.code(), "challenge_invalid");
    assert_eq!(
        t.count("SELECT COUNT(*) FROM login_throttle").await,
        0,
        "no lockout failures"
    );
    // Structure.
    let response = enable_raw(&t, &alice.access_token, "12345").await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn setup_expires_after_ten_minutes() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let reauth = t.reauth(&alice).await;
    let setup = setup_raw(&t, &alice.access_token, Some(&reauth)).await;
    let secret = secret_of(&setup);
    t.advance(Duration::minutes(10));
    let response = enable_raw(&t, &alice.access_token, &t.totp(&secret, 0)).await;
    assert_eq!(response.code(), "challenge_invalid");
}

#[tokio::test]
async fn setup_and_enable_while_active_are_conflicts() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let reauth = t.reauth(&alice).await;
    let setup = setup_raw(&t, &alice.access_token, Some(&reauth)).await;
    let secret = secret_of(&setup);
    t.enable_totp_direct(&alice).await;
    let response = enable_raw(&t, &alice.access_token, &t.totp(&secret, 0)).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "two_factor_state_invalid");
    let reauth = t.reauth(&alice).await;
    let response = setup_raw(&t, &alice.access_token, Some(&reauth)).await;
    assert_eq!(response.code(), "two_factor_state_invalid");
}

#[tokio::test]
async fn totp_as_second_factor_brings_no_backup_codes() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    t.sql(&format!(
        "INSERT INTO webauthn_credentials (id, user_id, credential_id, passkey, name, created_at)
         VALUES ('{}', '{}', X'01', '{{}}', 'Key', '2026-10-23T08:00:00.000Z')",
        support::new_uuid(),
        alice.user_id
    ))
    .await;
    t.set_backup_codes(&alice, &["AAAAAAAAAA"]).await;
    let (_, body) = t.enable_totp(&alice).await;
    assert!(body.get("backup_codes").is_none(), "{body}");
    assert_eq!(
        t.count("SELECT COUNT(*) FROM backup_codes").await,
        1,
        "existing codes stay"
    );
}

#[tokio::test]
async fn disable_removes_totp_and_the_last_backup_codes() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    t.enable_totp(&alice).await;
    let response = t
        .call(Req::delete("/v1/me/totp").token(&alice.access_token))
        .await;
    assert_eq!(response.code(), "reauth_required");
    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete("/v1/me/totp")
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    let me = t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    assert_eq!(
        me.json()["two_factor"],
        json!({ "totp": false, "webauthn_credentials": 0, "backup_codes_remaining": 0 })
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM users WHERE totp_secret_enc IS NOT NULL OR totp_last_step IS NOT NULL")
            .await,
        0
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM backup_codes").await, 0);
    assert!(
        t.security_events()
            .await
            .contains(&"totp_disabled".to_string())
    );
    let response = t
        .call(
            Req::delete("/v1/me/totp")
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "two_factor_state_invalid");
    // Login without second factor again.
    assert_eq!(t.login(&alice).await.access_token.len(), 43);
}
