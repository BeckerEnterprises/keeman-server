//! Account recovery with the recovery key.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::authenticator::Authenticator;
use support::{Account, Req, TestApp, envelope, random_b64, unique_ip};
use time::Duration;

async fn test_app() -> TestApp {
    TestApp::with_config("[rate_limits]\ncredential_per_email_per_min = 1000\n").await
}

async fn start_raw(t: &TestApp, email: &str, key: &str) -> support::TestResponse {
    let body = json!({ "email": email, "recovery_auth_key": key });
    t.call(
        Req::post("/v1/auth/recover/start")
            .json(&body)
            .peer(&unique_ip()),
    )
    .await
}

/// A `recover/finish` body with new password material and a new recovery key.
fn finish_body(token: &str, auth_key: &str, recovery_key: Option<&str>) -> Value {
    let mut body = json!({
        "recovery_token": token,
        "kdf": { "alg": "argon2id13", "ops": 3, "mem": 67108864 },
        "salt": random_b64::<16>(),
        "auth_key": auth_key,
        "user_key_wrapped": envelope(73),
        "device": { "name": "Recovered", "client_type": "cli" },
    });
    if let Some(key) = recovery_key {
        body["recovery"] = json!({ "auth_key": key, "user_key_wrapped": envelope(73) });
    }
    body
}

async fn finish_raw(t: &TestApp, body: &Value) -> support::TestResponse {
    t.call(
        Req::post("/v1/auth/recover/finish")
            .json(body)
            .peer(&unique_ip()),
    )
    .await
}

async fn recovery_token(t: &TestApp, account: &Account) -> String {
    let response = start_raw(t, &account.email, &account.recovery_auth_key).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["status"], "recovery_ok");
    response.json()["recovery_token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn start_without_second_factor_returns_the_wrapped_user_key() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let response = start_raw(&t, " ALICE@example.com", &alice.recovery_auth_key).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    assert_eq!(body["status"], "recovery_ok");
    assert_eq!(body["user_id"], alice.user_id.as_str());
    assert_eq!(body["recovery_token"].as_str().unwrap().len(), 43);
    assert_eq!(body["expires_in"], 600);
    assert_eq!(
        body["user_key_recovery_wrapped"].as_str().unwrap().len(),
        98
    );
    assert!(body.get("backup_codes_remaining").is_none());
    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM security_log WHERE event = 'recovery_started'
               AND json_extract(detail, '$.method') = 'recovery_key'"
        )
        .await,
        1
    );
    // A new start replaces the token.
    let first = body["recovery_token"].as_str().unwrap().to_string();
    let second = recovery_token(&t, &alice).await;
    let response = finish_raw(&t, &finish_body(&first, &random_b64::<32>(), None)).await;
    assert_eq!(response.code(), "challenge_invalid");
    assert_eq!(
        finish_raw(&t, &finish_body(&second, &random_b64::<32>(), None))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn wrong_keys_count_like_login_failures() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let wrong = start_raw(&t, &alice.email, &random_b64::<32>()).await;
    let unknown = start_raw(&t, "nobody@example.com", &random_b64::<32>()).await;
    for response in [&wrong, &unknown] {
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.code(), "invalid_credentials");
    }
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = 'recovery_failed'")
            .await,
        2
    );
    for _ in 0..9 {
        t.advance(Duration::seconds(12));
        start_raw(&t, &alice.email, &random_b64::<32>()).await;
    }
    t.advance(Duration::seconds(12));
    let login = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(login.status, StatusCode::TOO_MANY_REQUESTS, "same lockout");
    let response = start_raw(&t, &alice.email, &alice.recovery_auth_key).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn finish_replaces_the_password_and_revokes_all_sessions() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let reauth = t.reauth(&other).await;
    let token = recovery_token(&t, &alice).await;
    let new_key = random_b64::<32>();
    let new_recovery = random_b64::<32>();
    let response = finish_raw(&t, &finish_body(&token, &new_key, Some(&new_recovery))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["user_id"], alice.user_id.as_str());
    let recovered = alice.clone().with_session(&response);

    for session in [&alice, &other] {
        let me = t
            .call(Req::get("/v1/me").token(&session.access_token))
            .await;
        assert_eq!(
            me.status,
            StatusCode::UNAUTHORIZED,
            "old sessions are revoked"
        );
    }
    let me = t
        .call(Req::get("/v1/me").token(&recovered.access_token))
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL")
            .await,
        1
    );
    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND device_name = 'Recovered'"
        )
        .await,
        1
    );
    // All challenges are gone, also the reauth token of the other session.
    assert_eq!(t.count("SELECT COUNT(*) FROM challenges").await, 0);
    drop(reauth);

    // Old password and old recovery key fail; the new ones work.
    let old = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(old.code(), "invalid_credentials");
    let mut renewed = alice.clone();
    renewed.auth_key = new_key;
    t.login(&renewed).await;
    let response = start_raw(&t, &alice.email, &alice.recovery_auth_key).await;
    assert_eq!(response.code(), "invalid_credentials");
    let response = start_raw(&t, &alice.email, &new_recovery).await;
    assert_eq!(response.status, StatusCode::OK);

    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM security_log WHERE event = 'session_revoked'
               AND json_extract(detail, '$.reason') = 'recovery'"
        )
        .await,
        2
    );
    let detail = t
        .text("SELECT detail FROM security_log WHERE event = 'recovery_completed'")
        .await;
    let detail: Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(detail["revoked_sessions"], 2);
    assert_eq!(detail["recovery_key_replaced"], true);
}

#[tokio::test]
async fn without_new_material_the_recovery_key_stays() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let token = recovery_token(&t, &alice).await;
    let response = finish_raw(&t, &finish_body(&token, &random_b64::<32>(), None)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        start_raw(&t, &alice.email, &alice.recovery_auth_key)
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn recovery_tokens_are_single_use_and_expire() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let token = recovery_token(&t, &alice).await;
    // 400 and 422 keep the token.
    let mut bad = finish_body(&token, &random_b64::<32>(), None);
    bad["salt"] = json!("short");
    let response = finish_raw(&t, &bad).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let mut bad = finish_body(&token, &random_b64::<32>(), None);
    bad["kdf"]["ops"] = json!(1);
    let response = finish_raw(&t, &bad).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.code(), "kdf_params_invalid");
    let body = finish_body(&token, &random_b64::<32>(), None);
    assert_eq!(finish_raw(&t, &body).await.status, StatusCode::OK);
    // Used up.
    let response = finish_raw(&t, &body).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.code(), "challenge_invalid");

    let token = recovery_token(&t, &alice).await;
    t.advance(Duration::minutes(10));
    let response = finish_raw(&t, &finish_body(&token, &random_b64::<32>(), None)).await;
    assert_eq!(response.code(), "challenge_invalid", "expired");
    let response = finish_raw(
        &t,
        &finish_body(&random_b64::<32>(), &random_b64::<32>(), None),
    )
    .await;
    assert_eq!(response.code(), "challenge_invalid");
}

#[tokio::test]
async fn a_reauth_token_is_no_recovery_token() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let reauth = t.reauth(&alice).await;
    let response = finish_raw(&t, &finish_body(&reauth, &random_b64::<32>(), None)).await;
    assert_eq!(response.code(), "challenge_invalid");
}

#[tokio::test]
async fn finish_has_its_own_limits_per_ip_and_account() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let token = recovery_token(&t, &alice).await;
    let mut bad = finish_body(&token, &random_b64::<32>(), None);
    bad["kdf"]["ops"] = json!(1);
    // 5 per minute and account (the default of the address bucket).
    for _ in 0..5 {
        assert_eq!(finish_raw(&t, &bad).await.code(), "kdf_params_invalid");
    }
    let response = finish_raw(&t, &bad).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    // 10 per minute and IP, independent of the login bucket.
    let ip = unique_ip();
    for _ in 0..10 {
        let body = finish_body(&random_b64::<32>(), &random_b64::<32>(), None);
        let response = t
            .call(Req::post("/v1/auth/recover/finish").json(&body).peer(&ip))
            .await;
        assert_eq!(response.code(), "challenge_invalid");
    }
    let body = finish_body(&random_b64::<32>(), &random_b64::<32>(), None);
    let response = t
        .call(Req::post("/v1/auth/recover/finish").json(&body).peer(&ip))
        .await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    let login = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&ip),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "the login bucket is separate");
}

#[tokio::test]
async fn disabled_accounts() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let token = recovery_token(&t, &alice).await;
    t.sql("UPDATE users SET disabled = 1").await;
    let response = start_raw(&t, &alice.email, &alice.recovery_auth_key).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.code(), "account_disabled");
    let response = finish_raw(&t, &finish_body(&token, &random_b64::<32>(), None)).await;
    assert_eq!(response.code(), "account_disabled");
    t.sql("UPDATE users SET disabled = 0").await;
    let response = finish_raw(&t, &finish_body(&token, &random_b64::<32>(), None)).await;
    assert_eq!(
        response.code(),
        "challenge_invalid",
        "the token was used up"
    );
}

// ---------------------------------------------------------------- with 2FA

#[tokio::test]
async fn recovery_with_totp_needs_the_second_factor() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let (secret, enabled) = t.enable_totp(&alice).await;
    let response = start_raw(&t, &alice.email, &alice.recovery_auth_key).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    assert_eq!(body["status"], "second_factor_required");
    assert_eq!(body["methods"], json!(["totp", "backup_code"]));
    let challenge = body["challenge_token"].as_str().unwrap().to_string();
    // A recovery challenge is no recovery token.
    let response = finish_raw(&t, &finish_body(&challenge, &random_b64::<32>(), None)).await;
    assert_eq!(response.code(), "challenge_invalid");

    let sessions = t.count("SELECT COUNT(*) FROM sessions").await;
    let response = t
        .call(
            Req::post("/v1/auth/2fa/totp")
                .json(&json!({ "challenge_token": challenge, "code": t.totp(&secret, 1) }))
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["status"], "recovery_ok");
    assert!(response.set_cookies().is_empty());
    assert_eq!(
        t.count("SELECT COUNT(*) FROM sessions").await,
        sessions,
        "no session"
    );
    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM security_log WHERE event = 'recovery_started'
               AND json_extract(detail, '$.method') = 'totp'"
        )
        .await,
        1
    );
    let token = response.json()["recovery_token"]
        .as_str()
        .unwrap()
        .to_string();
    let response = finish_raw(&t, &finish_body(&token, &random_b64::<32>(), None)).await;
    assert_eq!(response.status, StatusCode::OK);
    // TOTP and backup codes stay.
    assert_eq!(
        t.count("SELECT COUNT(*) FROM users WHERE totp_enabled = 1")
            .await,
        1
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM backup_codes").await, 10);

    // A backup code works too and reports what is left.
    let response = start_raw(&t, &alice.email, &alice.recovery_auth_key).await;
    let challenge = response.json()["challenge_token"]
        .as_str()
        .unwrap()
        .to_string();
    let code = enabled["backup_codes"][0].as_str().unwrap();
    let response = t
        .call(
            Req::post("/v1/auth/2fa/backup-code")
                .json(&json!({ "challenge_token": challenge, "code": code }))
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.json()["status"], "recovery_ok");
    assert_eq!(response.json()["backup_codes_remaining"], 9);
}

#[tokio::test]
async fn recovery_with_a_passkey() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let reauth = t.reauth(&alice).await;
    let options = t
        .call(
            Req::post("/v1/me/webauthn/register/options")
                .token(&alice.access_token)
                .reauth(&reauth)
                .json(&json!({ "name": "Key" })),
        )
        .await
        .json();
    let mut key = Authenticator::new();
    let credential = key.register(&options["public_key"]);
    let response = t
        .call(
            Req::post("/v1/me/webauthn/register/verify")
                .token(&alice.access_token)
                .json(&json!({ "registration_token": options["registration_token"], "credential": credential })),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let response = start_raw(&t, &alice.email, &alice.recovery_auth_key).await;
    let challenge = response.json()["challenge_token"]
        .as_str()
        .unwrap()
        .to_string();
    let options = t
        .call(
            Req::post("/v1/auth/2fa/webauthn/options")
                .json(&json!({ "challenge_token": challenge }))
                .peer(&unique_ip()),
        )
        .await
        .json();
    let assertion = key.assert(&options["public_key"]);
    let response = t
        .call(
            Req::post("/v1/auth/2fa/webauthn/verify")
                .json(&json!({ "challenge_token": challenge, "credential": assertion }))
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["status"], "recovery_ok");
}

#[tokio::test]
async fn the_recovery_payload_resets_the_lockout_counter() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let mut wrong = alice.login_body();
    wrong["auth_key"] = json!(random_b64::<32>());
    for _ in 0..9 {
        t.call(Req::post("/v1/auth/login").json(&wrong).peer(&unique_ip()))
            .await;
        t.advance(Duration::seconds(12));
    }
    recovery_token(&t, &alice).await;
    t.advance(Duration::seconds(12));
    t.call(Req::post("/v1/auth/login").json(&wrong).peer(&unique_ip()))
        .await;
    t.advance(Duration::seconds(12));
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "only one failure since");
}
