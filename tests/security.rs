//! Security checks: no secrets in the database
//! or the logs, client IP handling, timing, and the cleanup job.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::StatusCode;
use keeman_server::types::decode_base64url;
use serde_json::json;
use support::{ORIGIN, Req, TestApp, random_b64, unique_ip};
use time::Duration;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn database_holds_no_tokens_or_auth_keys() {
    let t = TestApp::new().await;
    let invite = t.invite().await;
    let account = support::Account::new("alice@example.com");
    let response = t
        .call(Req::post("/v1/auth/register").json(&account.register_body(Some(&invite))))
        .await;
    let alice = account.with_session(&response);
    let refreshed = t
        .call(Req::post("/v1/auth/refresh").json(&json!({ "refresh_token": alice.refresh_token })))
        .await
        .json();
    let reauth = t.reauth(&alice).await;
    let login = t.login(&alice).await;

    let secrets = [
        invite,
        alice.auth_key.clone(),
        alice.access_token.clone(),
        alice.refresh_token.clone(),
        refreshed["access_token"].as_str().unwrap().to_string(),
        refreshed["refresh_token"].as_str().unwrap().to_string(),
        reauth,
        login.access_token.clone(),
        login.refresh_token.clone(),
    ];
    let data = t.dir.path().join("data");
    let mut files = Vec::new();
    for name in ["keeman.sqlite", "keeman.sqlite-wal", "keeman.sqlite-shm"] {
        if let Ok(bytes) = std::fs::read(data.join(name)) {
            files.push((name, bytes));
        }
    }
    assert!(files.iter().map(|(_, b)| b.len()).sum::<usize>() > 0);
    for secret in &secrets {
        let raw = decode_base64url(secret).unwrap();
        assert_eq!(raw.len(), 32);
        for (name, bytes) in &files {
            assert!(
                !contains(bytes, secret.as_bytes()),
                "{name} contains a token as text"
            );
            assert!(!contains(bytes, &raw), "{name} contains a token as bytes");
        }
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn logs_hold_no_secrets_emails_ips_or_device_names() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let t = TestApp::new().await;
    let invite = t.invite().await;
    let account = support::Account::new("alice@example.com");
    let mut body = account.register_body(Some(&invite));
    body["device"] = json!({ "name": "Secret Laptop Name", "client_type": "web" });
    let response = t
        .call(
            Req::post("/v1/auth/register")
                .json(&body)
                .peer("127.0.0.1")
                .header("x-forwarded-for", "192.0.2.77")
                .origin(ORIGIN),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    let alice = account.with_session(&response);
    let response = t
        .call(
            Req::post("/v1/auth/refresh")
                .cookie(&alice.refresh_token)
                .origin(ORIGIN),
        )
        .await;
    let cookie = response.cookie_value("__Host-keeman_rt").unwrap();
    let reauth = t.reauth(&alice).await;
    t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    t.call(
        Req::put("/v1/me/recovery")
            .token(&alice.access_token)
            .reauth(&reauth)
            .json(&json!({})),
    )
    .await;
    let mut wrong = alice.login_body();
    wrong["email"] = json!("unknown-person@example.com");
    t.call(Req::post("/v1/auth/login").json(&wrong)).await;
    t.call(Req::post("/v1/auth/prelogin").json(&json!({ "email": "prelogin-person@example.com" })))
        .await;
    t.call(Req::get("/v1/nope/with-id-0192b3a4")).await;
    let vault_id = t.create_vault(&alice).await;
    let op = support::put_op(&support::new_uuid(), "entry", None);
    let response = t.batch(&alice, &vault_id, vec![op.clone()]).await;
    assert_eq!(response.status, StatusCode::OK);
    t.changes(&alice, &vault_id, "since=0").await;
    let attachment = support::new_uuid();
    let path = format!("/v1/vaults/{vault_id}/attachments");
    let blob = vec![0x5a_u8; 64];
    t.call(Req::post(&path).token(&alice.access_token).json(
        &json!({ "attachment_id": attachment, "entry_id": support::new_uuid(), "size": 64 }),
    ))
    .await;
    let part = t
        .call(
            Req::put(&format!("{path}/{attachment}/parts/0"))
                .token(&alice.access_token)
                .raw(Some("application/octet-stream"), &blob),
        )
        .await;
    assert_eq!(part.status, StatusCode::NO_CONTENT);
    t.call(Req::post(&format!("{path}/{attachment}/complete")).token(&alice.access_token))
        .await;
    t.call(Req::get(&format!("{path}/{attachment}")).token(&alice.access_token))
        .await;
    let bob = t.register("bob-shared@example.com").await;
    t.call(
        Req::post("/v1/users/lookup")
            .token(&alice.access_token)
            .json(&json!({ "email": "bob-shared@example.com" })),
    )
    .await;
    assert_eq!(
        t.invite_member(&alice, &vault_id, &bob).await.status,
        StatusCode::CREATED
    );
    t.accept_invitation(&bob, &vault_id, 1).await;
    t.call(Req::get(&format!("/v1/vaults/{vault_id}/members")).token(&alice.access_token))
        .await;
    t.call(Req::get(&format!("/v1/users/{}/public-key", bob.user_id)).token(&alice.access_token))
        .await;
    let rotation = t
        .call(
            Req::post(&format!("/v1/vaults/{vault_id}/rotations"))
                .token(&alice.access_token)
                .idem(&support::new_uuid())
                .json(&json!({ "base_revision": 2, "new_key_version": 2 })),
        )
        .await;
    assert_eq!(rotation.status, StatusCode::CREATED, "{}", rotation.text());
    let rotation_id = rotation.json()["rotation_id"].as_str().unwrap().to_string();

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("\"path\":\"/v1/vaults/{vault_id}/members\""));
    assert!(
        logs.contains(
            "\"path\":\"/v1/vaults/{vault_id}/attachments/{attachment_id}/parts/{part}\""
        )
    );
    assert!(logs.contains("\"path\":\"/v1/vaults/{vault_id}/batch\""));
    assert!(
        logs.contains("\"path\":\"/v1/auth/register\""),
        "access log present: {logs}"
    );
    assert!(logs.contains("\"client\":\"test/1.0.0\""));
    let forbidden = [
        "alice@example.com",
        "unknown-person@example.com",
        "prelogin-person@example.com",
        "Secret Laptop Name",
        "192.0.2.77",
        "192.0.2",
        "203.0.113.10",
        "127.0.0.1",
        "with-id-0192b3a4",
        &invite,
        &alice.auth_key,
        &alice.access_token,
        &alice.refresh_token,
        &cookie,
        &reauth,
        &vault_id,
        op["data"].as_str().unwrap(),
        op["id"].as_str().unwrap(),
        &attachment,
        "bob-shared@example.com",
        &bob.user_id,
        &bob.public_key,
        &rotation_id,
        "ZZZZZZZZ",
    ];
    for needle in forbidden {
        assert!(!logs.contains(needle), "log contains {needle}");
    }
}

#[tokio::test]
async fn client_ip_comes_from_trusted_proxies_only() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer("127.0.0.1")
                .header("x-forwarded-for", "192.0.2.77"),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    t.advance(Duration::seconds(12));
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer("203.0.113.99")
                .header("x-forwarded-for", "192.0.2.77"),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    t.advance(Duration::seconds(12));
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer("2001:db8:85a3:1:2:3:4:5"),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let sessions = t
        .call(Req::get("/v1/me/sessions").token(&alice.access_token))
        .await
        .json()["sessions"]
        .clone();
    let found: Vec<String> = sessions
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["ip_hint"].as_str().unwrap().to_string())
        .collect();
    assert!(found.contains(&"192.0.2.x".to_string()), "{found:?}");
    assert!(found.contains(&"203.0.113.x".to_string()), "{found:?}");
    assert!(
        found.contains(&"2001:db8:85a3::/48".to_string()),
        "{found:?}"
    );
}

#[tokio::test]
async fn ipv6_clients_share_limits_per_64() {
    let t = TestApp::new().await;
    for i in 1..=20 {
        let response = t
            .call(
                Req::post("/v1/auth/prelogin")
                    .json(&json!({ "email": "a@b.c" }))
                    .peer(&format!("2001:db8:1:2::{i:x}")),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK);
    }
    let response = t
        .call(
            Req::post("/v1/auth/prelogin")
                .json(&json!({ "email": "a@b.c" }))
                .peer("2001:db8:1:2:ffff::1"),
        )
        .await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    let response = t
        .call(
            Req::post("/v1/auth/prelogin")
                .json(&json!({ "email": "a@b.c" }))
                .peer("2001:db8:1:3::1"),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_emails_take_about_as_long_as_wrong_keys() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let mut known = std::time::Duration::ZERO;
    let mut unknown = std::time::Duration::ZERO;
    for i in 0..5 {
        let mut wrong = alice.login_body();
        wrong["auth_key"] = json!(random_b64::<32>());
        let started = Instant::now();
        assert_eq!(
            t.call(Req::post("/v1/auth/login").json(&wrong).peer(&unique_ip()))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
        known += started.elapsed();

        let mut missing = alice.login_body();
        missing["email"] = json!(format!("nobody{i}@example.com"));
        let started = Instant::now();
        assert_eq!(
            t.call(
                Req::post("/v1/auth/login")
                    .json(&missing)
                    .peer(&unique_ip())
            )
            .await
            .status,
            StatusCode::UNAUTHORIZED
        );
        unknown += started.elapsed();
    }
    let ratio = unknown.as_secs_f64() / known.as_secs_f64();
    assert!(
        (0.5..2.0).contains(&ratio),
        "known {known:?}, unknown {unknown:?}"
    );
}

#[tokio::test]
async fn unknown_emails_take_about_as_long_at_recovery() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let mut known = std::time::Duration::ZERO;
    let mut unknown = std::time::Duration::ZERO;
    for i in 0..5 {
        for (email, total) in [
            (alice.email.clone(), &mut known),
            (format!("nobody{i}@example.com"), &mut unknown),
        ] {
            let body = json!({ "email": email, "recovery_auth_key": random_b64::<32>() });
            let started = Instant::now();
            let response = t
                .call(
                    Req::post("/v1/auth/recover/start")
                        .json(&body)
                        .peer(&unique_ip()),
                )
                .await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED);
            *total += started.elapsed();
        }
    }
    let ratio = unknown.as_secs_f64() / known.as_secs_f64();
    assert!(
        (0.5..2.0).contains(&ratio),
        "known {known:?}, unknown {unknown:?}"
    );
}

#[tokio::test]
async fn cleanup_job_removes_expired_rows() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    t.call(Req::post("/v1/auth/logout").token(&other.access_token))
        .await;
    let first = t
        .call(Req::post("/v1/auth/refresh").json(&json!({ "refresh_token": alice.refresh_token })))
        .await
        .json();
    let second = t
        .call(
            Req::post("/v1/auth/refresh").json(&json!({ "refresh_token": first["refresh_token"] })),
        )
        .await
        .json();
    t.reauth(&alice).await;
    let mut wrong = alice.login_body();
    wrong["email"] = json!("nobody@example.com");
    t.call(Req::post("/v1/auth/login").json(&wrong).peer(&unique_ip()))
        .await;
    keeman_server::cli::invite::create(
        &t.app.db,
        &t.app.audit,
        t.now(),
        Duration::minutes(1),
        None,
    )
    .await
    .unwrap();
    let job = || keeman_server::jobs::cleanup(&t.app);

    t.advance(Duration::minutes(20));
    let removed = job().await.unwrap();
    assert_eq!(removed.sessions, 1, "the logged-out session");
    assert_eq!(removed.challenges, 1, "the expired reauth token");
    assert!(removed.access_tokens >= 3);
    assert_eq!(
        (removed.refresh_tokens, removed.throttle, removed.invites),
        (0, 0, 0)
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM access_tokens").await, 0);

    t.advance(Duration::hours(24));
    assert_eq!(job().await.unwrap().throttle, 1, "idle counter after 24 h");

    // Keep the session alive; only history older than refresh_token_ttl_days goes.
    t.advance(Duration::days(28));
    let third = t
        .call(
            Req::post("/v1/auth/refresh")
                .json(&json!({ "refresh_token": second["refresh_token"] })),
        )
        .await;
    assert_eq!(third.status, StatusCode::OK);
    t.advance(Duration::days(2));
    let removed = job().await.unwrap();
    assert_eq!(removed.refresh_tokens, 2);
    assert_eq!(
        removed.invites, 1,
        "expired for more than 30 days; the 7-day invite of registration was used"
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM refresh_tokens").await, 2);

    t.advance(Duration::days(61));
    let removed = job().await.unwrap();
    assert!(removed.security_log > 0);
    let cutoff = keeman_server::clock::format_timestamp(t.now() - Duration::days(90));
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM security_log WHERE ts <= '{cutoff}'"
        ))
        .await,
        0
    );
}

#[tokio::test]
async fn cleanup_runs_once_at_startup() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    t.call(Req::post("/v1/auth/logout").token(&alice.access_token))
        .await;
    let handle = keeman_server::jobs::spawn(t.app.clone());
    for _ in 0..100 {
        if t.count("SELECT COUNT(*) FROM sessions").await == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    handle.abort();
    assert_eq!(t.count("SELECT COUNT(*) FROM sessions").await, 0);
}

#[tokio::test]
async fn database_holds_no_second_factor_secrets() {
    let t = TestApp::with_config("[rate_limits]\ncredential_per_email_per_min = 1000\n").await;
    let alice = t.register("alice@example.com").await;
    // TOTP with backup codes, a passkey, a login challenge and a recovery.
    let reauth = t.reauth(&alice).await;
    let setup = t
        .call(
            Req::post("/v1/me/totp/setup")
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await
        .json();
    let secret_text = setup["secret"].as_str().unwrap().to_string();
    let secret = keeman_server::crypto::base32::decode(&secret_text).unwrap();
    let secret_array: [u8; 20] = secret.clone().try_into().unwrap();
    let enable = t
        .call(
            Req::post("/v1/me/totp/enable")
                .token(&alice.access_token)
                .json(&json!({ "code": t.totp(&secret_array, 0) })),
        )
        .await
        .json();
    let codes: Vec<String> = enable["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
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
    let registration_token = options["registration_token"].as_str().unwrap().to_string();
    let credential = support::authenticator::Authenticator::new().register(&options["public_key"]);
    let response = t
        .call(
            Req::post("/v1/me/webauthn/register/verify")
                .token(&alice.access_token)
                .json(
                    &json!({ "registration_token": registration_token, "credential": credential }),
                ),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    let challenge = t.login_challenge(&alice).await;
    let start = t
        .call(
            Req::post("/v1/auth/recover/start")
                .json(
                    &json!({ "email": alice.email, "recovery_auth_key": alice.recovery_auth_key }),
                )
                .peer(&unique_ip()),
        )
        .await
        .json();
    let recovery_challenge = start["challenge_token"].as_str().unwrap().to_string();
    let payload = t
        .call(
            Req::post("/v1/auth/2fa/backup-code")
                .json(&json!({ "challenge_token": recovery_challenge, "code": codes[0] }))
                .peer(&unique_ip()),
        )
        .await
        .json();
    let recovery_token = payload["recovery_token"].as_str().unwrap().to_string();

    let data = t.dir.path().join("data");
    let mut files = Vec::new();
    for name in ["keeman.sqlite", "keeman.sqlite-wal", "keeman.sqlite-shm"] {
        if let Ok(bytes) = std::fs::read(data.join(name)) {
            files.push((name, bytes));
        }
    }
    let mut needles: Vec<(String, Vec<u8>)> = vec![
        ("TOTP secret".into(), secret.clone()),
        ("TOTP secret as text".into(), secret_text.into_bytes()),
    ];
    for code in &codes {
        needles.push((format!("backup code {code}"), code.clone().into_bytes()));
    }
    for (name, token) in [
        ("registration token", &registration_token),
        ("challenge token", &challenge),
        ("recovery challenge", &recovery_challenge),
        ("recovery token", &recovery_token),
        ("recovery auth key", &alice.recovery_auth_key),
    ] {
        needles.push((format!("{name} as text"), token.clone().into_bytes()));
        needles.push((name.into(), decode_base64url(token).unwrap()));
    }
    for (what, needle) in &needles {
        for (name, bytes) in &files {
            assert!(!contains(bytes, needle), "{name} contains the {what}");
        }
    }
}

#[tokio::test]
async fn second_factor_logs_hold_no_codes_names_or_credential_ids() {
    use keeman_server::config::LogLevel;
    use tracing_subscriber::layer::SubscriberExt;

    let captured = Captured::default();
    let writer = captured.clone();
    // The same filter as the server, with everything at its most verbose.
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish()
        .with(keeman_server::logging::targets(LogLevel::Trace));
    let _guard = tracing::subscriber::set_default(subscriber);

    let t = TestApp::with_config("[rate_limits]\ncredential_per_email_per_min = 1000\n").await;
    let carol = t.register("carol-2fa@example.com").await;
    let (secret, enabled) = t.enable_totp(&carol).await;
    let codes: Vec<String> = enabled["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    let reauth = t.reauth(&carol).await;
    let options = t
        .call(
            Req::post("/v1/me/webauthn/register/options")
                .token(&carol.access_token)
                .reauth(&reauth)
                .json(&json!({ "name": "Secret Passkey Name" })),
        )
        .await
        .json();
    let mut key = support::authenticator::Authenticator::new();
    let credential = key.register(&options["public_key"]);
    t.call(
        Req::post("/v1/me/webauthn/register/verify")
            .token(&carol.access_token)
            .json(&json!({ "registration_token": options["registration_token"], "credential": credential })),
    )
    .await;
    // Logins with a wrong and a right code, a backup code and the passkey.
    let challenge = t.login_challenge(&carol).await;
    let next = t.totp(&secret, 1);
    for code in ["000000", next.as_str()] {
        t.call(
            Req::post("/v1/auth/2fa/totp")
                .json(&json!({ "challenge_token": challenge, "code": code }))
                .peer(&unique_ip()),
        )
        .await;
    }
    let challenge = t.login_challenge(&carol).await;
    t.call(
        Req::post("/v1/auth/2fa/backup-code")
            .json(&json!({ "challenge_token": challenge, "code": codes[1] }))
            .peer(&unique_ip()),
    )
    .await;
    let challenge = t.login_challenge(&carol).await;
    let assertion_options = t
        .call(
            Req::post("/v1/auth/2fa/webauthn/options")
                .json(&json!({ "challenge_token": challenge }))
                .peer(&unique_ip()),
        )
        .await
        .json();
    let assertion = key.assert(&assertion_options["public_key"]);
    let response = t
        .call(
            Req::post("/v1/auth/2fa/webauthn/verify")
                .json(&json!({ "challenge_token": challenge, "credential": assertion }))
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    // A recovery with the passkey and a new recovery key.
    let start = t
        .call(
            Req::post("/v1/auth/recover/start")
                .json(
                    &json!({ "email": carol.email, "recovery_auth_key": carol.recovery_auth_key }),
                )
                .peer(&unique_ip()),
        )
        .await
        .json();
    let recovery_challenge = start["challenge_token"].as_str().unwrap().to_string();
    let payload = t
        .call(
            Req::post("/v1/auth/2fa/backup-code")
                .json(&json!({ "challenge_token": recovery_challenge, "code": codes[2] }))
                .peer(&unique_ip()),
        )
        .await
        .json();
    let recovery_token = payload["recovery_token"].as_str().unwrap().to_string();
    let new_recovery_key = random_b64::<32>();
    let finish = t
        .call(
            Req::post("/v1/auth/recover/finish")
                .json(&json!({
                    "recovery_token": recovery_token,
                    "kdf": { "alg": "argon2id13", "ops": 3, "mem": 67108864 },
                    "salt": random_b64::<16>(),
                    "auth_key": random_b64::<32>(),
                    "user_key_wrapped": support::envelope(73),
                    "recovery": { "auth_key": new_recovery_key, "user_key_wrapped": support::envelope(73) },
                    "device": { "name": "Secret Recovery Device", "client_type": "cli" },
                }))
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.text());

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("\"path\":\"/v1/auth/2fa/webauthn/verify\""),
        "{logs}"
    );
    let mut forbidden = vec![
        "carol-2fa@example.com".to_string(),
        "Secret Passkey Name".into(),
        "Secret Recovery Device".into(),
        keeman_server::crypto::base32::encode(&secret),
        keeman_server::types::encode_base64url(&key.credential_id),
        format!("\"{next}\""),
        challenge,
        recovery_challenge,
        recovery_token,
        carol.recovery_auth_key.clone(),
        new_recovery_key,
        options["registration_token"].as_str().unwrap().to_string(),
    ];
    forbidden.extend(codes);
    for value in &forbidden {
        assert!(!logs.contains(value.as_str()), "logs contain {value}");
    }
    for line in logs.lines().filter(|l| l.contains("\"target\":\"webauthn")) {
        assert!(
            line.contains("\"level\":\"INFO\"")
                || line.contains("\"level\":\"WARN\"")
                || line.contains("\"level\":\"ERROR\""),
            "library debug output: {line}"
        );
    }
}
