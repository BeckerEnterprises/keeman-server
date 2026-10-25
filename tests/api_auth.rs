//! `prelogin`, `register`, `login`, `refresh` and `logout`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use keeman_server::crypto::{DerivedKeys, ServerSecret};
use keeman_server::types::encode_base64url;
use serde_json::{Value, json};
use support::{Account, ORIGIN, Req, SECRET, TestApp, envelope, unique_ip};
use time::Duration;

fn dummy_salt(secret: [u8; 32], email: &str) -> String {
    encode_base64url(&DerivedKeys::derive(&ServerSecret::from_bytes(secret)).dummy_salt(email))
}

// ---------------------------------------------------------------- prelogin

#[tokio::test]
async fn prelogin_returns_the_real_salt_or_a_deterministic_dummy() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let response = t
        .call(Req::post("/v1/auth/prelogin").json(&json!({ "email": " Alice@Example.COM " })))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.json(),
        json!({ "kdf": { "alg": "argon2id13", "ops": 3, "mem": 67108864 }, "salt": alice.salt })
    );

    let unknown = t
        .call(Req::post("/v1/auth/prelogin").json(&json!({ "email": "nobody@example.com" })))
        .await;
    assert_eq!(unknown.status, StatusCode::OK);
    let body = unknown.json();
    assert_eq!(
        body["kdf"],
        json!({ "alg": "argon2id13", "ops": 3, "mem": 67108864 })
    );
    assert_eq!(
        body["salt"].as_str(),
        Some(dummy_salt(SECRET, "nobody@example.com").as_str())
    );
    // Spellings that normalise to the same address get the same salt.
    let again = t
        .call(Req::post("/v1/auth/prelogin").json(&json!({ "email": "\tNOBODY@example.com\n" })))
        .await;
    assert_eq!(again.json()["salt"], body["salt"]);
    // A restart with the same secret keeps it; another secret changes it.
    let restarted = TestApp::new().await;
    let response = restarted
        .call(Req::post("/v1/auth/prelogin").json(&json!({ "email": "nobody@example.com" })))
        .await;
    assert_eq!(response.json()["salt"], body["salt"]);
    assert_ne!(
        dummy_salt([8u8; 32], "nobody@example.com"),
        dummy_salt(SECRET, "nobody@example.com")
    );
}

#[tokio::test]
async fn prelogin_validates_and_limits() {
    let t = TestApp::new().await;
    let response = t
        .call(Req::post("/v1/auth/prelogin").json(&json!({ "email": "no-at-sign" })))
        .await;
    assert_eq!(response.code(), "validation_failed");
    assert_eq!(
        response.field_error(),
        ("/email".into(), "invalid e-mail address".into())
    );
    let response = t
        .call(Req::post("/v1/auth/prelogin").json(&json!({ "email": "a@b.c", "extra": 1 })))
        .await;
    assert_eq!(
        response.field_error(),
        ("/extra".into(), "unknown field".into())
    );

    let ip = unique_ip();
    for _ in 0..20 {
        let response = t
            .call(
                Req::post("/v1/auth/prelogin")
                    .json(&json!({ "email": "a@b.c" }))
                    .peer(&ip),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK);
    }
    let response = t
        .call(
            Req::post("/v1/auth/prelogin")
                .json(&json!({ "email": "a@b.c" }))
                .peer(&ip),
        )
        .await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.code(), "rate_limited");
    assert_eq!(response.header("retry-after").as_deref(), Some("3"));
    t.advance(Duration::seconds(3));
    let response = t
        .call(
            Req::post("/v1/auth/prelogin")
                .json(&json!({ "email": "a@b.c" }))
                .peer(&ip),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
}

// ---------------------------------------------------------------- register

async fn register_raw(t: &TestApp, body: &Value) -> support::TestResponse {
    t.call(Req::post("/v1/auth/register").json(body).peer(&unique_ip()))
        .await
}

#[tokio::test]
async fn register_creates_account_and_web_session() {
    let t = TestApp::new().await;
    let invite = t.invite().await;
    let account = Account::new("Carol@Example.com");
    let mut body = account.register_body(Some(&invite));
    body["device"] = json!({ "name": "Firefox on Linux", "client_type": "web" });
    let response = register_raw(&t, &body).await;
    assert_eq!(response.status, StatusCode::CREATED);
    let session = response.json();
    assert_eq!(session["status"], "ok");
    assert_eq!(session["user_id"].as_str(), Some(account.user_id.as_str()));
    assert_eq!(session["access_expires_in"], 900);
    assert!(
        session.get("refresh_token").is_none(),
        "web clients get the cookie only"
    );
    let cookies = response.set_cookies();
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].starts_with("__Host-keeman_rt="));
    assert!(cookies[0].ends_with("; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000"));

    let me = t
        .call(Req::get("/v1/me").token(session["access_token"].as_str().unwrap()))
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["email"], "carol@example.com");
    assert_eq!(me.json()["user_data"]["revision"], 1);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM invites WHERE used_at IS NOT NULL")
            .await,
        1
    );
    assert_eq!(t.security_events().await, ["invite_created", "register"]);
}

#[tokio::test]
async fn register_native_session_carries_the_refresh_token() {
    let t = TestApp::new().await;
    let account = t.register("dave@example.com").await;
    assert_eq!(account.refresh_token.len(), 43);
}

#[tokio::test]
async fn register_with_closed_registration() {
    let t = TestApp::with_config("[security]\nregistration = \"closed\"\n").await;
    // Closed is checked before the body is read.
    let response = t
        .call(Req::post("/v1/auth/register").raw(Some("text/plain"), b"garbage"))
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.code(), "registration_closed");
}

#[tokio::test]
async fn register_invite_rules() {
    let t = TestApp::new().await;
    let account = Account::new("erin@example.com");
    let response = register_raw(&t, &account.register_body(None)).await;
    assert_eq!(response.code(), "invite_invalid", "missing code");
    let response = register_raw(
        &t,
        &account.register_body(Some(&support::random_b64::<32>())),
    )
    .await;
    assert_eq!(response.code(), "invite_invalid", "unknown code");
    let mut body = account.register_body(None);
    body["invite_code"] = Value::Null;
    assert_eq!(
        register_raw(&t, &body).await.field_error(),
        ("/invite_code".into(), "invalid type".into())
    );
    body["invite_code"] = json!("short");
    assert_eq!(
        register_raw(&t, &body).await.status,
        StatusCode::BAD_REQUEST
    );

    let expired =
        keeman_server::cli::invite::create(&t.app.db, t.now(), Duration::minutes(1), None)
            .await
            .unwrap();
    t.advance(Duration::minutes(1));
    let response = register_raw(&t, &account.register_body(Some(&expired))).await;
    assert_eq!(response.code(), "invite_invalid", "expired code");

    let invite = t.invite().await;
    let body = account.register_body(Some(&invite));
    assert_eq!(register_raw(&t, &body).await.status, StatusCode::CREATED);
    // A byte-identical retry after a network error.
    let response = register_raw(&t, &body).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "already_registered");
    // Someone else with the used code.
    let response = register_raw(
        &t,
        &Account::new("frank@example.com").register_body(Some(&invite)),
    )
    .await;
    assert_eq!(response.code(), "invite_invalid", "used code");
}

#[tokio::test]
async fn register_conflicts() {
    let t = TestApp::new().await;
    let erin = t.register("erin@example.com").await;
    // Same e-mail, another user_id.
    let response = register_raw(
        &t,
        &Account::new("ERIN@example.com").register_body(Some(&t.invite().await)),
    )
    .await;
    assert_eq!(response.code(), "email_taken");
    // Same user_id, another e-mail.
    let mut other = Account::new("grace@example.com");
    other.user_id = erin.user_id.clone();
    let response = register_raw(&t, &other.register_body(Some(&t.invite().await))).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "conflict");
    // Same account with a fresh code: already registered.
    let mut same = Account::new("erin@example.com");
    same.user_id = erin.user_id.clone();
    let response = register_raw(&t, &same.register_body(Some(&t.invite().await))).await;
    assert_eq!(response.code(), "already_registered");
    assert_eq!(
        t.count("SELECT COUNT(*) FROM invites WHERE used_at IS NULL")
            .await,
        3,
        "failed attempts keep their codes"
    );
}

#[tokio::test]
async fn register_in_open_mode() {
    let t = TestApp::with_config("[security]\nregistration = \"open\"\n").await;
    let account = Account::new("open@example.com");
    let body = account.register_body(None);
    assert_eq!(register_raw(&t, &body).await.status, StatusCode::CREATED);
    assert_eq!(register_raw(&t, &body).await.code(), "already_registered");
    // An invite code is checked for its format only, then ignored.
    let response = register_raw(
        &t,
        &Account::new("x@example.com").register_body(Some(&support::random_b64::<32>())),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);
}

#[tokio::test]
async fn register_validation() {
    let t = TestApp::new().await;
    let invite = t.invite().await;
    let base = Account::new("val@example.com").register_body(Some(&invite));
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "/user_id",
            json!("0192B3A4-5C6D-7E8F-9A0B-1C2D3E4F5A6B"),
            "not a canonical UUID",
        ),
        (
            "/salt",
            json!("AAAA"),
            "not a canonical Base64url value of the expected length",
        ),
        (
            "/auth_key",
            json!(format!("{}=", "A".repeat(42))),
            "not a canonical Base64url value of the expected length",
        ),
        (
            "/user_key_wrapped",
            json!(envelope(72)),
            "not a canonical Base64url value of the expected length",
        ),
        (
            "/private_key_wrapped",
            json!(encode_base64url(&[2u8; 73])),
            "not an AEAD envelope",
        ),
        (
            "/user_data",
            json!(encode_base64url(&[1u8; 40])),
            "not an AEAD envelope",
        ),
        (
            "/device/name",
            json!({ "name": "", "client_type": "web" }),
            "invalid device name",
        ),
        (
            "/device/client_type",
            json!({ "name": "x", "client_type": "tv" }),
            "invalid value",
        ),
        (
            "/kdf/ops",
            json!({ "alg": "argon2id13", "ops": 3.5, "mem": 67108864 }),
            "invalid type",
        ),
        (
            "/kdf/mem",
            json!({ "alg": "argon2id13", "ops": 3 }),
            "missing field",
        ),
    ];
    for (pointer, value, detail) in cases {
        let mut body = base.clone();
        let field = pointer.trim_start_matches('/').split('/').next().unwrap();
        body[field] = value;
        let response = register_raw(&t, &body).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{pointer}");
        assert_eq!(
            response.field_error(),
            (pointer.to_string(), detail.to_string()),
            "{pointer}"
        );
    }
    let mut body = base.clone();
    body.as_object_mut().unwrap().remove("recovery");
    assert_eq!(
        register_raw(&t, &body).await.field_error(),
        ("/recovery".into(), "missing field".into())
    );

    // Envelope fields over their byte limit → 413.
    let mut body = base.clone();
    body["user_data"] = json!("A".repeat(349_923));
    assert_eq!(register_raw(&t, &body).await.code(), "payload_too_large");

    // Value errors of the KDF parameters → 422 without errors[].
    for kdf in [
        json!({ "alg": "argon2id13", "ops": 1, "mem": 67108864 }),
        json!({ "alg": "argon2id13", "ops": 3, "mem": 67108865 }),
        json!({ "alg": "argon2i13", "ops": 3, "mem": 67108864 }),
        json!({ "alg": "argon2id13", "ops": 11, "mem": 67108864 }),
        json!({ "alg": "argon2id13", "ops": 3, "mem": 2147483648_i64 }),
    ] {
        let mut body = base.clone();
        body["kdf"] = kdf.clone();
        let response = register_raw(&t, &body).await;
        assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY, "{kdf}");
        assert_eq!(response.code(), "kdf_params_invalid");
        assert!(response.json().get("errors").is_none());
    }
    assert_eq!(t.count("SELECT COUNT(*) FROM users").await, 0);
}

#[tokio::test]
async fn register_rate_limit_counts_well_formed_requests() {
    let t = TestApp::new().await;
    let ip = unique_ip();
    for _ in 0..10 {
        let response = t
            .call(Req::post("/v1/auth/register").json(&json!({})).peer(&ip))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }
    for i in 0..5 {
        let body = Account::new(&format!("u{i}@example.com")).register_body(None);
        let response = t
            .call(Req::post("/v1/auth/register").json(&body).peer(&ip))
            .await;
        assert_eq!(response.code(), "invite_invalid");
    }
    let body = Account::new("u9@example.com").register_body(Some(&t.invite().await));
    let response = t
        .call(Req::post("/v1/auth/register").json(&body).peer(&ip))
        .await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.header("retry-after").as_deref(), Some("720"));
}

// ---------------------------------------------------------------- login

async fn login_raw(t: &TestApp, body: &Value, ip: &str) -> support::TestResponse {
    t.call(Req::post("/v1/auth/login").json(body).peer(ip))
        .await
}

#[tokio::test]
async fn login_creates_a_session() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let mut body = alice.login_body();
    body["email"] = json!("ALICE@example.com ");
    body["device"] = json!({ "name": "Laptop", "client_type": "web" });
    let response = login_raw(&t, &body, &unique_ip()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["status"], "ok");
    assert!(response.cookie_value("__Host-keeman_rt").is_some());
    assert_eq!(
        t.count("SELECT COUNT(*) FROM users WHERE last_login_at IS NOT NULL")
            .await,
        1
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM sessions").await, 2);
    assert!(t.security_events().await.contains(&"login_ok".to_string()));
}

#[tokio::test]
async fn login_failures_look_the_same_for_unknown_accounts() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let mut wrong = alice.login_body();
    wrong["auth_key"] = json!(support::random_b64::<32>());
    let a = login_raw(&t, &wrong, &unique_ip()).await;
    let mut unknown = alice.login_body();
    unknown["email"] = json!("nobody@example.com");
    let b = login_raw(&t, &unknown, &unique_ip()).await;
    for response in [&a, &b] {
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.code(), "invalid_credentials");
    }
    let strip = |r: &support::TestResponse| {
        let mut body = r.json();
        body.as_object_mut().unwrap().remove("instance");
        body
    };
    assert_eq!(strip(&a), strip(&b));
    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM security_log WHERE event = 'login_failed' AND user_id IS NULL"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn lockout_is_identical_for_existing_and_unknown_emails() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    for email in ["alice@example.com", "nobody@example.com"] {
        let mut body = alice.login_body();
        body["email"] = json!(email);
        body["auth_key"] = json!(support::random_b64::<32>());
        for attempt in 1..=10 {
            let response = login_raw(&t, &body, &unique_ip()).await;
            assert_eq!(
                response.status,
                StatusCode::UNAUTHORIZED,
                "{email} attempt {attempt}"
            );
            // Stay within 5/min per e-mail.
            t.advance(Duration::seconds(12));
        }
        // Locked, even with the right key; not counted.
        let mut right = alice.login_body();
        right["email"] = json!(email);
        let response = login_raw(&t, &right, &unique_ip()).await;
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS, "{email}");
        assert_eq!(response.code(), "rate_limited");
        let retry: i64 = response.header("retry-after").unwrap().parse().unwrap();
        assert_eq!(retry, 15 * 60 - 12, "{email}");
        t.advance(Duration::seconds(retry - 1));
        assert_eq!(
            login_raw(&t, &right, &unique_ip()).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
        t.advance(Duration::seconds(1));
        let response = login_raw(&t, &right, &unique_ip()).await;
        let expected = if email == "alice@example.com" {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        };
        assert_eq!(response.status, expected, "{email} after the lock");
        t.advance(Duration::seconds(12));
    }
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = 'login_locked'")
            .await,
        2
    );
}

#[tokio::test]
async fn lockout_counter_resets_on_success_and_decays() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let mut wrong = alice.login_body();
    wrong["auth_key"] = json!(support::random_b64::<32>());
    let fail = |n: usize| {
        let t = &t;
        let wrong = wrong.clone();
        async move {
            for _ in 0..n {
                assert_eq!(
                    login_raw(t, &wrong, &unique_ip()).await.status,
                    StatusCode::UNAUTHORIZED
                );
                t.advance(Duration::seconds(12));
            }
        }
    };
    fail(9).await;
    assert_eq!(
        login_raw(&t, &alice.login_body(), &unique_ip())
            .await
            .status,
        StatusCode::OK
    );
    t.advance(Duration::seconds(12));
    fail(9).await;
    t.advance(Duration::hours(24));
    fail(9).await;
    // Neither reset nor decay left 10 failures in a row.
    assert_eq!(
        login_raw(&t, &alice.login_body(), &unique_ip())
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn login_rate_limits_per_ip_and_per_email() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let ip = unique_ip();
    for i in 0..10 {
        let mut body = alice.login_body();
        body["email"] = json!(format!("u{i}@example.com"));
        assert_eq!(
            login_raw(&t, &body, &ip).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    let response = login_raw(&t, &alice.login_body(), &ip).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.header("retry-after").as_deref(), Some("6"));

    for _ in 0..5 {
        assert_eq!(
            login_raw(&t, &alice.login_body(), &unique_ip())
                .await
                .status,
            StatusCode::OK
        );
    }
    let response = login_raw(&t, &alice.login_body(), &unique_ip()).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS, "per e-mail");
    assert_eq!(response.header("retry-after").as_deref(), Some("12"));
}

#[tokio::test]
async fn disabled_accounts_and_second_factor() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    t.sql("UPDATE users SET disabled = 1").await;
    let response = login_raw(&t, &alice.login_body(), &unique_ip()).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.code(), "account_disabled");
    let mut wrong = alice.login_body();
    wrong["auth_key"] = json!(support::random_b64::<32>());
    assert_eq!(
        login_raw(&t, &wrong, &unique_ip()).await.code(),
        "invalid_credentials",
        "disabled only after valid credentials"
    );

    t.sql("UPDATE users SET disabled = 0, totp_enabled = 1")
        .await;
    let response = login_raw(&t, &alice.login_body(), &unique_ip()).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    assert_eq!(body["status"], "second_factor_required");
    assert_eq!(body["methods"], json!(["totp"]));
    assert_eq!(body["expires_in"], 300);
    assert_eq!(body["challenge_token"].as_str().unwrap().len(), 43);
    assert!(body.get("access_token").is_none());
    assert!(response.set_cookies().is_empty());
    assert_eq!(
        t.count("SELECT COUNT(*) FROM sessions").await,
        1,
        "no new session"
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM challenges WHERE purpose = 'login'")
            .await,
        1
    );
}

// ---------------------------------------------------------------- refresh

async fn refresh_native(t: &TestApp, token: &str) -> support::TestResponse {
    t.call(
        Req::post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": token }))
            .peer(&unique_ip()),
    )
    .await
}

#[tokio::test]
async fn native_refresh_rotates_and_slides() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    t.advance(Duration::days(29));
    let response = refresh_native(&t, &alice.refresh_token).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    assert_eq!(body["access_expires_in"], 900);
    let next = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(next, alice.refresh_token);
    assert!(response.set_cookies().is_empty());
    // The new access token works.
    let me = t
        .call(Req::get("/v1/me").token(body["access_token"].as_str().unwrap()))
        .await;
    assert_eq!(me.status, StatusCode::OK);
    // Sliding: 29 more days are fine, the original 30 would have expired.
    t.advance(Duration::days(29));
    assert_eq!(refresh_native(&t, &next).await.status, StatusCode::OK);
}

#[tokio::test]
async fn refresh_superseded_within_grace_then_reuse_revokes() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let rotated = refresh_native(&t, &alice.refresh_token).await.json();
    t.advance(Duration::seconds(30));
    let response = refresh_native(&t, &alice.refresh_token).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "refresh_superseded");
    let new_access = rotated["access_token"].as_str().unwrap();
    assert_eq!(
        t.call(Req::get("/v1/me").token(new_access)).await.status,
        StatusCode::OK,
        "no revocation"
    );

    t.advance(Duration::seconds(1));
    let response = refresh_native(&t, &alice.refresh_token).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.code(), "session_invalid");
    // The whole session is gone, other sessions stay.
    assert_eq!(
        t.call(Req::get("/v1/me").token(new_access)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh_native(&t, rotated["refresh_token"].as_str().unwrap())
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.call(Req::get("/v1/me").token(&other.access_token))
            .await
            .status,
        StatusCode::OK
    );
    let events = t.security_events().await;
    assert!(events.contains(&"refresh_reuse".to_string()));
    assert_eq!(t.count("SELECT COUNT(*) FROM security_log WHERE event = 'session_revoked' AND detail LIKE '%reuse%'").await, 1);
}

#[tokio::test]
async fn reuse_after_two_rotations_revokes() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    // An attacker rotates twice with a stolen token …
    let first = refresh_native(&t, &alice.refresh_token).await.json();
    let second = refresh_native(&t, first["refresh_token"].as_str().unwrap())
        .await
        .json();
    // … the original token is not the direct predecessor any more, even within 30 s.
    let response = refresh_native(&t, &alice.refresh_token).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        refresh_native(&t, second["refresh_token"].as_str().unwrap())
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn web_refresh_uses_the_cookie_and_checks_the_origin() {
    let t = TestApp::new().await;
    let alice = t.register_as("alice@example.com", "web").await;
    let cookie = alice.refresh_token.clone();

    let response = t.call(Req::post("/v1/auth/refresh").cookie(&cookie)).await;
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "cookie without Origin"
    );
    assert_eq!(response.code(), "forbidden");
    let response = t
        .call(
            Req::post("/v1/auth/refresh")
                .cookie(&cookie)
                .origin("https://evil.example"),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    let response = t
        .call(Req::post("/v1/auth/refresh").cookie(&cookie).origin("null"))
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);

    let response = t
        .call(Req::post("/v1/auth/refresh").cookie(&cookie).origin(ORIGIN))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.json().get("refresh_token").is_none());
    let next = response.cookie_value("__Host-keeman_rt").unwrap();
    assert_ne!(next, cookie);

    // A body token wins over the cookie; the format follows the session (web).
    let response = t
        .call(
            Req::post("/v1/auth/refresh")
                .cookie("garbage")
                .json(&json!({ "refresh_token": next })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.json().get("refresh_token").is_none());
    assert!(response.cookie_value("__Host-keeman_rt").is_some());

    // 401 on a cookie token clears the cookie.
    let response = t
        .call(
            Req::post("/v1/auth/refresh")
                .cookie("garbage")
                .origin(ORIGIN),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(
        response
            .set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-keeman_rt=;") && c.ends_with("Max-Age=0"))
    );
}

#[tokio::test]
async fn refresh_errors() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let response = t.call(Req::post("/v1/auth/refresh")).await;
    assert_eq!(response.code(), "session_invalid", "no token at all");
    let response = t
        .call(Req::post("/v1/auth/refresh").json(&json!({ "refresh_token": "short" })))
        .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "malformed body token"
    );
    let response = refresh_native(&t, &support::random_b64::<32>()).await;
    assert_eq!(response.code(), "session_invalid");
    assert!(
        response.set_cookies().is_empty(),
        "body tokens never clear the cookie"
    );

    t.advance(Duration::days(30));
    assert_eq!(
        refresh_native(&t, &alice.refresh_token).await.code(),
        "session_invalid",
        "expired"
    );

    let bob = t.register("bob@example.com").await;
    t.sql("UPDATE users SET disabled = 1").await;
    assert_eq!(
        refresh_native(&t, &bob.refresh_token).await.code(),
        "session_invalid",
        "disabled"
    );

    let ip = unique_ip();
    for _ in 0..60 {
        t.call(Req::post("/v1/auth/refresh").peer(&ip)).await;
    }
    let response = t.call(Req::post("/v1/auth/refresh").peer(&ip)).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.header("retry-after").as_deref(), Some("1"));
}

// ---------------------------------------------------------------- logout

#[tokio::test]
async fn logout_revokes_the_session_and_clears_the_cookie() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let response = t
        .call(
            Req::post("/v1/auth/logout")
                .token(&alice.access_token)
                .origin("https://evil.example"),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    let response = t
        .call(Req::post("/v1/auth/logout").token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(
        response
            .set_cookies()
            .iter()
            .any(|c| c.ends_with("Max-Age=0"))
    );
    assert_eq!(
        t.call(Req::get("/v1/me").token(&alice.access_token))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh_native(&t, &alice.refresh_token).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.call(Req::get("/v1/me").token(&other.access_token))
            .await
            .status,
        StatusCode::OK
    );
    let response = t
        .call(
            Req::post("/v1/auth/logout")
                .token(&other.access_token)
                .origin(ORIGIN),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn dev_mode_uses_the_fallback_cookie_name() {
    let extra = "[server]\nallowed_origins = [\"http://localhost:5173\"]\n[security]\ndev_mode = true\n\
                 [webauthn]\nrp_id = \"localhost\"\nrp_origins = [\"http://localhost:5173\"]\n";
    let t = TestApp::with_config(extra).await;
    let invite = t.invite().await;
    let mut body = Account::new("dev@example.com").register_body(Some(&invite));
    body["device"]["client_type"] = json!("web");
    let response = t.call(Req::post("/v1/auth/register").json(&body)).await;
    assert!(response.set_cookies()[0].starts_with("keeman_rt="));
    let token = response.cookie_value("keeman_rt").unwrap();
    let response = t
        .call(
            Req::post("/v1/auth/refresh")
                .header("cookie", &format!("keeman_rt={token}"))
                .origin("http://localhost:5173"),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
}
