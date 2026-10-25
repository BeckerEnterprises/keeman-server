//! Passkeys as second factor with a software
//! authenticator that answers like a browser's `toJSON()`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::authenticator::Authenticator;
use support::{Account, Req, TestApp, unique_ip};
use time::Duration;

async fn test_app() -> TestApp {
    TestApp::with_config("[rate_limits]\ncredential_per_email_per_min = 1000\n").await
}

async fn options_raw(t: &TestApp, account: &Account, name: &str) -> support::TestResponse {
    let reauth = t.reauth(account).await;
    t.call(
        Req::post("/v1/me/webauthn/register/options")
            .token(&account.access_token)
            .reauth(&reauth)
            .json(&json!({ "name": name })),
    )
    .await
}

async fn verify_raw(
    t: &TestApp,
    account: &Account,
    token: &str,
    credential: &Value,
) -> support::TestResponse {
    t.call(
        Req::post("/v1/me/webauthn/register/verify")
            .token(&account.access_token)
            .json(&json!({ "registration_token": token, "credential": credential })),
    )
    .await
}

/// Registers the authenticator's passkey and returns the verify response.
async fn register(
    t: &TestApp,
    account: &Account,
    authenticator: &mut Authenticator,
) -> support::TestResponse {
    let options = options_raw(t, account, "Laptop").await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.text());
    let body = options.json();
    let credential = authenticator.register(&body["public_key"]);
    verify_raw(
        t,
        account,
        body["registration_token"].as_str().unwrap(),
        &credential,
    )
    .await
}

fn has_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.iter().any(has_null),
        Value::Object(map) => map.values().any(has_null),
        _ => false,
    }
}

#[tokio::test]
async fn registration_options_follow_the_spec() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let response = t
        .call(
            Req::post("/v1/me/webauthn/register/options")
                .token(&alice.access_token)
                .json(&json!({ "name": "Laptop" })),
        )
        .await;
    assert_eq!(response.code(), "reauth_required");

    let response = options_raw(&t, &alice, "Laptop").await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    assert_eq!(body["registration_token"].as_str().unwrap().len(), 43);
    let options = &body["public_key"];
    assert!(!has_null(options), "{options}");
    assert_eq!(
        options["rp"],
        json!({ "id": "app.example.org", "name": "KeeMan" })
    );
    assert_eq!(options["user"]["name"], "alice@example.com");
    assert_eq!(options["user"]["displayName"], "alice@example.com");
    let user_id = keeman_server::types::decode_base64url(options["user"]["id"].as_str().unwrap());
    assert_eq!(
        user_id.unwrap(),
        uuid_bytes(&alice.user_id),
        "user.id is the 16 bytes of the user ID"
    );
    let algorithms: Vec<i64> = options["pubKeyCredParams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["alg"].as_i64().unwrap())
        .collect();
    assert_eq!(algorithms, vec![-7, -257]);
    assert_eq!(options["attestation"], "none");
    assert_eq!(options["timeout"], 300_000);
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(
        options["authenticatorSelection"]["residentKey"],
        "discouraged"
    );
    assert!(options["challenge"].as_str().unwrap().len() >= 43);
    // A name is 1-64 characters without control characters.
    for name in [String::new(), "x".repeat(65), "a\nb".into()] {
        let response = options_raw(&t, &alice, &name).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{name:?}");
        assert_eq!(response.field_error().0, "/name");
    }
}

fn uuid_bytes(id: &str) -> Vec<u8> {
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    (0..16)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn registering_the_first_passkey_brings_backup_codes() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let mut key = Authenticator::new();
    let response = register(&t, &alice, &mut key).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    let body = response.json();
    let id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["backup_codes"].as_array().unwrap().len(), 10);

    let list = t
        .call(Req::get("/v1/me/webauthn").token(&alice.access_token))
        .await;
    let credentials = list.json()["credentials"].clone();
    assert_eq!(credentials.as_array().unwrap().len(), 1);
    assert_eq!(credentials[0]["id"], id.as_str());
    assert_eq!(credentials[0]["name"], "Laptop");
    assert_eq!(credentials[0]["last_used"], Value::Null);
    assert_eq!(credentials[0]["prf_enabled"], false);
    let me = t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    assert_eq!(
        me.json()["two_factor"],
        json!({ "totp": false, "webauthn_credentials": 1, "backup_codes_remaining": 10 })
    );
    assert!(
        t.security_events()
            .await
            .contains(&"passkey_added".to_string())
    );

    // A second passkey: the first one is excluded, no new backup codes.
    let options = options_raw(&t, &alice, "Phone").await.json();
    let excluded = options["public_key"]["excludeCredentials"][0]["id"].clone();
    assert_eq!(
        excluded,
        keeman_server::types::encode_base64url(&key.credential_id)
    );
    let mut phone = Authenticator::new();
    let credential = phone.register(&options["public_key"]);
    let response = verify_raw(
        &t,
        &alice,
        options["registration_token"].as_str().unwrap(),
        &credential,
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);
    assert!(response.json().get("backup_codes").is_none());
    assert_eq!(t.count("SELECT COUNT(*) FROM backup_codes").await, 10);
    // Login now needs the second factor.
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&unique_ip()),
        )
        .await;
    assert_eq!(
        response.json()["methods"],
        json!(["webauthn", "backup_code"])
    );
}

#[tokio::test]
async fn a_credential_is_registered_only_once() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let mut key = Authenticator::new();
    assert_eq!(
        register(&t, &alice, &mut key).await.status,
        StatusCode::CREATED
    );
    for account in [&alice, &bob] {
        let response = register(&t, account, &mut key).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{}",
            account.email
        );
        assert_eq!(response.field_error().0, "/credential");
    }
    assert_eq!(
        t.count("SELECT COUNT(*) FROM webauthn_credentials").await,
        1
    );
}

/// Turns a working authenticator into one whose answer must be rejected.
type Breaker = Box<dyn Fn(&mut Authenticator)>;

#[tokio::test]
async fn failed_checks_are_400_and_use_up_the_token() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let cases: Vec<(&str, Breaker)> = vec![
        (
            "wrong origin",
            Box::new(|a| a.origin = "https://evil.example".into()),
        ),
        ("wrong rp", Box::new(|a| a.rp_id = "example.org".into())),
        (
            "no user verification",
            Box::new(|a| a.user_verified = false),
        ),
    ];
    for (name, break_it) in cases {
        let options = options_raw(&t, &alice, "Laptop").await.json();
        let token = options["registration_token"].as_str().unwrap();
        let mut key = Authenticator::new();
        break_it(&mut key);
        let credential = key.register(&options["public_key"]);
        let response = verify_raw(&t, &alice, token, &credential).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{name}");
        // The token is used up.
        let mut good = Authenticator::new();
        let credential = good.register(&options["public_key"]);
        let response = verify_raw(&t, &alice, token, &credential).await;
        assert_eq!(response.code(), "challenge_invalid", "{name}");
    }
    // Another challenge than the one of the options.
    let options = options_raw(&t, &alice, "Laptop").await.json();
    let mut other = options["public_key"].clone();
    other["challenge"] = json!(support::random_b64::<32>());
    let credential = Authenticator::new().register(&other);
    let response = verify_raw(
        &t,
        &alice,
        options["registration_token"].as_str().unwrap(),
        &credential,
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    // A credential that cannot be read is 400 and keeps the token.
    let options = options_raw(&t, &alice, "Laptop").await.json();
    let token = options["registration_token"].as_str().unwrap();
    let response = verify_raw(&t, &alice, token, &json!({ "id": "x" })).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let credential = Authenticator::new().register(&options["public_key"]);
    assert_eq!(
        verify_raw(&t, &alice, token, &credential).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM webauthn_credentials").await,
        1
    );
}

#[tokio::test]
async fn registration_tokens_are_bound_and_expire() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let options = options_raw(&t, &alice, "Laptop").await.json();
    let token = options["registration_token"].as_str().unwrap().to_string();
    let credential = Authenticator::new().register(&options["public_key"]);
    let response = verify_raw(&t, &other, &token, &credential).await;
    assert_eq!(response.code(), "challenge_invalid", "another session");
    // A new options call of the session replaces the open registration.
    let newer = options_raw(&t, &alice, "Laptop").await.json();
    let response = verify_raw(&t, &alice, &token, &credential).await;
    assert_eq!(response.code(), "challenge_invalid", "replaced");
    t.advance(Duration::minutes(5));
    let credential = Authenticator::new().register(&newer["public_key"]);
    let response = verify_raw(
        &t,
        &alice,
        newer["registration_token"].as_str().unwrap(),
        &credential,
    )
    .await;
    assert_eq!(response.code(), "challenge_invalid", "expired");
    let response = verify_raw(&t, &alice, &support::random_b64::<32>(), &credential).await;
    assert_eq!(response.code(), "challenge_invalid");
}

#[tokio::test]
async fn at_most_ten_passkeys() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    for _ in 0..10 {
        let mut key = Authenticator::new();
        assert_eq!(
            register(&t, &alice, &mut key).await.status,
            StatusCode::CREATED
        );
    }
    let response = options_raw(&t, &alice, "Eleventh").await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.code(), "two_factor_state_invalid");
}

#[tokio::test]
async fn removing_the_last_passkey_removes_the_backup_codes() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let mut key = Authenticator::new();
    let id = register(&t, &alice, &mut key).await.json()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/v1/me/webauthn/{id}");
    let response = t.call(Req::delete(&path).token(&alice.access_token)).await;
    assert_eq!(response.code(), "reauth_required");
    let reauth = t.reauth(&bob).await;
    let response = t
        .call(Req::delete(&path).token(&bob.access_token).reauth(&reauth))
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "another account");
    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete("/v1/me/webauthn/not-a-uuid")
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let response = t
        .call(
            Req::delete(&path)
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM webauthn_credentials").await,
        0
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM backup_codes").await, 0);
    assert!(
        t.security_events()
            .await
            .contains(&"passkey_removed".to_string())
    );
    let response = t
        .call(
            Req::delete(&path)
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    // Login without second factor again.
    assert_eq!(t.login(&alice).await.access_token.len(), 43);
}

#[tokio::test]
async fn removing_one_of_two_factors_keeps_the_backup_codes() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let mut key = Authenticator::new();
    let id = register(&t, &alice, &mut key).await.json()["id"]
        .as_str()
        .unwrap()
        .to_string();
    t.enable_totp(&alice).await;
    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete(&format!("/v1/me/webauthn/{id}"))
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(t.count("SELECT COUNT(*) FROM backup_codes").await, 10);
}

// ---------------------------------------------------------------- login

async fn webauthn_options(t: &TestApp, challenge: &str) -> support::TestResponse {
    t.call(
        Req::post("/v1/auth/2fa/webauthn/options")
            .json(&json!({ "challenge_token": challenge }))
            .peer(&unique_ip()),
    )
    .await
}

async fn webauthn_verify(
    t: &TestApp,
    challenge: &str,
    credential: &Value,
) -> support::TestResponse {
    t.call(
        Req::post("/v1/auth/2fa/webauthn/verify")
            .json(&json!({ "challenge_token": challenge, "credential": credential }))
            .peer(&unique_ip()),
    )
    .await
}

/// Options and assertion of one login attempt.
async fn assert_login(
    t: &TestApp,
    challenge: &str,
    key: &mut Authenticator,
) -> support::TestResponse {
    let options = webauthn_options(t, challenge).await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.text());
    let credential = key.assert(&options.json()["public_key"]);
    webauthn_verify(t, challenge, &credential).await
}

async fn with_passkey(t: &TestApp, email: &str) -> (Account, Authenticator) {
    let account = t.register(email).await;
    let mut key = Authenticator::new();
    assert_eq!(
        register(t, &account, &mut key).await.status,
        StatusCode::CREATED
    );
    (account, key)
}

fn stored_counter(passkey: &str) -> u64 {
    serde_json::from_str::<Value>(passkey).unwrap()["cred"]["counter"]
        .as_u64()
        .unwrap()
}

#[tokio::test]
async fn login_with_a_passkey() {
    let t = test_app().await;
    let (alice, mut key) = with_passkey(&t, "alice@example.com").await;
    let challenge = t.login_challenge(&alice).await;
    let options = webauthn_options(&t, &challenge).await;
    assert_eq!(options.status, StatusCode::OK);
    let public_key = options.json()["public_key"].clone();
    assert!(!has_null(&public_key), "{public_key}");
    assert_eq!(public_key["rpId"], "app.example.org");
    assert_eq!(public_key["userVerification"], "required");
    assert_eq!(
        public_key["allowCredentials"][0]["id"],
        keeman_server::types::encode_base64url(&key.credential_id)
    );
    let credential = key.assert(&public_key);
    let response = webauthn_verify(&t, &challenge, &credential).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["status"], "ok");
    let session = alice.clone().with_session(&response);
    let list = t
        .call(Req::get("/v1/me/webauthn").token(&session.access_token))
        .await;
    assert_eq!(
        list.json()["credentials"][0]["last_used"],
        "2026-10-23T08:00:00.000Z"
    );
    let passkey = t.text("SELECT passkey FROM webauthn_credentials").await;
    assert_eq!(stored_counter(&passkey), 2, "registration 1, login 2");
    assert_eq!(
        t.count(
            "SELECT COUNT(*) FROM security_log WHERE event = 'login_ok'
               AND json_extract(detail, '$.method') = 'webauthn'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn options_rules() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    t.enable_totp(&alice).await;
    let challenge = t.login_challenge(&alice).await;
    let response = webauthn_options(&t, &challenge).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "no passkey");
    assert_eq!(response.code(), "two_factor_state_invalid");
    let response = webauthn_options(&t, &support::random_b64::<32>()).await;
    assert_eq!(response.code(), "challenge_invalid");

    // Options neither count nor use up the challenge; a new call replaces
    // the state, so an answer to the old options fails.
    let (bob, mut key) = with_passkey(&t, "bob@example.com").await;
    let challenge = t.login_challenge(&bob).await;
    let first = webauthn_options(&t, &challenge).await.json();
    let second = webauthn_options(&t, &challenge).await.json();
    let old = key.assert(&first["public_key"]);
    let response = webauthn_verify(&t, &challenge, &old).await;
    assert_eq!(response.code(), "invalid_second_factor");
    // The verification used the state up, even the newer one.
    let new = key.assert(&second["public_key"]);
    let response = webauthn_verify(&t, &challenge, &new).await;
    assert_eq!(response.code(), "invalid_second_factor");
    let response = assert_login(&t, &challenge, &mut key).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = '2fa_failed'")
            .await,
        2
    );
}

#[tokio::test]
async fn failed_assertions_count() {
    let t = test_app().await;
    let (alice, mut key) = with_passkey(&t, "alice@example.com").await;
    let challenge = t.login_challenge(&alice).await;
    // Without options.
    let credential = key.assert(&json!({ "challenge": support::random_b64::<32>() }));
    let response = webauthn_verify(&t, &challenge, &credential).await;
    assert_eq!(response.code(), "invalid_second_factor");
    // Tampered signature.
    let options = webauthn_options(&t, &challenge).await.json();
    let mut credential = key.assert(&options["public_key"]);
    let signature = credential["response"]["signature"].as_str().unwrap();
    let mut bytes = keeman_server::types::decode_base64url(signature).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    credential["response"]["signature"] = json!(keeman_server::types::encode_base64url(&bytes));
    let response = webauthn_verify(&t, &challenge, &credential).await;
    assert_eq!(response.code(), "invalid_second_factor");
    // Another authenticator.
    let options = webauthn_options(&t, &challenge).await.json();
    let mut stranger = Authenticator::new();
    let credential = stranger.assert(&options["public_key"]);
    let response = webauthn_verify(&t, &challenge, &credential).await;
    assert_eq!(response.code(), "invalid_second_factor");
    // Without user verification.
    let options = webauthn_options(&t, &challenge).await.json();
    key.user_verified = false;
    let credential = key.assert(&options["public_key"]);
    let response = webauthn_verify(&t, &challenge, &credential).await;
    assert_eq!(response.code(), "invalid_second_factor");
    // A fifth failure (another origin) uses the challenge up.
    key.user_verified = true;
    key.origin = "https://evil.example".into();
    let options = webauthn_options(&t, &challenge).await.json();
    let credential = key.assert(&options["public_key"]);
    let response = webauthn_verify(&t, &challenge, &credential).await;
    assert_eq!(response.code(), "invalid_second_factor");
    let response = webauthn_options(&t, &challenge).await;
    assert_eq!(response.code(), "challenge_invalid");
    // A credential that cannot be read is 400 and does not count.
    let challenge = t.login_challenge(&alice).await;
    webauthn_options(&t, &challenge).await;
    let response = webauthn_verify(&t, &challenge, &json!({ "id": 1 })).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = '2fa_failed'")
            .await,
        5
    );
}

#[tokio::test]
async fn replayed_assertions_and_counters_that_do_not_increase_fail() {
    let t = test_app().await;
    let (alice, mut key) = with_passkey(&t, "alice@example.com").await;
    let challenge = t.login_challenge(&alice).await;
    let options = webauthn_options(&t, &challenge).await.json();
    let credential = key.assert(&options["public_key"]);
    assert_eq!(
        webauthn_verify(&t, &challenge, &credential).await.status,
        StatusCode::OK
    );
    // The same assertion with a new challenge fails (other challenge).
    let challenge = t.login_challenge(&alice).await;
    webauthn_options(&t, &challenge).await;
    let response = webauthn_verify(&t, &challenge, &credential).await;
    assert_eq!(response.code(), "invalid_second_factor");
    // A cloned authenticator whose counter went back.
    key.counter = 1;
    let response = assert_login(&t, &challenge, &mut key).await;
    assert_eq!(response.code(), "invalid_second_factor", "counter 2 again");
    key.counter = 10;
    let response = assert_login(&t, &challenge, &mut key).await;
    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn concurrent_logins_cannot_reuse_a_counter() {
    let t = test_app().await;
    let (alice, mut key) = with_passkey(&t, "alice@example.com").await;
    // Both options are taken while the stored counter is 1.
    let first = t.login_challenge(&alice).await;
    let second = t.login_challenge(&alice).await;
    let first_options = webauthn_options(&t, &first).await.json();
    let second_options = webauthn_options(&t, &second).await.json();
    key.counter = 4;
    let a = key.assert(&first_options["public_key"]);
    assert_eq!(webauthn_verify(&t, &first, &a).await.status, StatusCode::OK);
    key.counter = 3;
    let b = key.assert(&second_options["public_key"]);
    let response = webauthn_verify(&t, &second, &b).await;
    assert_eq!(response.code(), "invalid_second_factor", "4 is stored now");
}

#[tokio::test]
async fn synchronised_passkeys_report_zero() {
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    let mut key = Authenticator::new();
    key.counting = false;
    assert_eq!(
        register(&t, &alice, &mut key).await.status,
        StatusCode::CREATED
    );
    for _ in 0..2 {
        let challenge = t.login_challenge(&alice).await;
        assert_eq!(
            assert_login(&t, &challenge, &mut key).await.status,
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn a_passkey_removed_after_the_options_fails() {
    let t = test_app().await;
    let (alice, mut key) = with_passkey(&t, "alice@example.com").await;
    t.enable_totp(&alice).await;
    let challenge = t.login_challenge(&alice).await;
    let options = webauthn_options(&t, &challenge).await.json();
    t.sql("DELETE FROM webauthn_credentials").await;
    let credential = key.assert(&options["public_key"]);
    let response = webauthn_verify(&t, &challenge, &credential).await;
    assert_eq!(response.code(), "invalid_second_factor");
}

#[tokio::test]
async fn a_passkey_stored_by_this_version_still_works() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/passkey-webauthn-rs-0.5.json")).unwrap();
    let credential_id =
        keeman_server::types::decode_base64url(fixture["credential_id"].as_str().unwrap()).unwrap();
    let mut key = Authenticator::from_scalar(
        fixture["private_key_hex"].as_str().unwrap(),
        credential_id.clone(),
        u32::try_from(fixture["counter"].as_u64().unwrap()).unwrap(),
    );
    let t = test_app().await;
    let alice = t.register("alice@example.com").await;
    t.insert_passkey(&alice, &credential_id, &fixture["passkey"].to_string())
        .await;
    let challenge = t.login_challenge(&alice).await;
    let response = assert_login(&t, &challenge, &mut key).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
}
