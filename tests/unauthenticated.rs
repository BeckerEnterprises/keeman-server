//! Every operation of the API without a valid access token → `401`, except
//! the public ones, which must equal `PUBLIC_PATHS`. The operations and the
//! authentication each requires come from the API contract
//! (tests/fixtures/operations.json).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use keeman_server::auth::PUBLIC_PATHS;
use serde::Deserialize;
use support::{Req, TestApp};
use time::Duration;

#[derive(Deserialize)]
struct Operation {
    method: String,
    path: String,
    /// `public`, `token` or `reauth`.
    access: String,
}

impl Operation {
    fn public(&self) -> bool {
        self.access == "public"
    }

    fn reauth(&self) -> bool {
        self.access == "reauth"
    }
}

fn operations() -> Vec<Operation> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/operations.json"
    ))
    .unwrap();
    let operations: Vec<Operation> = serde_json::from_str(&text).unwrap();
    assert!(operations.len() >= 57, "operations.json read");
    operations
}

/// Fills path parameters with syntactically valid values.
fn concrete(path: &str) -> String {
    path.split('/')
        .map(|segment| match segment {
            "{part}" => "0",
            s if s.starts_with('{') => "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b",
            s => s,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn public_paths_match_openapi() {
    let from_contract: BTreeSet<String> = operations()
        .into_iter()
        .filter(|o| o.public())
        .map(|o| o.path)
        .collect();
    let from_code: BTreeSet<String> = PUBLIC_PATHS.iter().map(|p| p.to_string()).collect();
    assert_eq!(from_contract, from_code);
}

#[tokio::test]
async fn every_protected_operation_requires_a_token() {
    let t = TestApp::new().await;
    let account = t.register("alice@example.com").await;
    let expired = account.access_token.clone();
    t.advance(Duration::minutes(16));
    let fresh = t.login(&account).await;

    for operation in operations().iter().filter(|o| !o.public()) {
        let path = concrete(&operation.path);
        let bad_tokens = [
            None,
            Some("A".repeat(43)),
            Some(expired.clone()),
            Some(format!("{}=", &expired[..42])),
            Some(format!("{expired} ")),
        ];
        for token in bad_tokens {
            let mut request = Req::new(&operation.method, &path);
            if let Some(token) = &token {
                request = request.token(token);
            }
            let response = t.call(request).await;
            assert_eq!(
                response.status,
                StatusCode::UNAUTHORIZED,
                "{} {} with {token:?}",
                operation.method,
                path
            );
            assert_eq!(response.code(), "session_invalid");
        }
        // Wrong scheme and a duplicated header count as missing.
        let response = t
            .call(
                Req::new(&operation.method, &path)
                    .header("authorization", &format!("Basic {}", fresh.access_token)),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{} {path} Basic",
            operation.method
        );
        let response = t
            .call(
                Req::new(&operation.method, &path)
                    .token(&fresh.access_token)
                    .token(&fresh.access_token),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{} {path} twice",
            operation.method
        );

        // Logout would end the shared session; it gets its own.
        let valid = if operation.path == "/v1/auth/logout" {
            t.login(&account).await.access_token
        } else {
            fresh.access_token.clone()
        };
        let response = t
            .call(Req::new(&operation.method, &path).token(&valid))
            .await;
        if operation.reauth() {
            // [Reauth] operations without the header.
            assert_eq!(
                response.status,
                StatusCode::UNAUTHORIZED,
                "{} {path}",
                operation.method
            );
            assert_eq!(
                response.code(),
                "reauth_required",
                "{} {path}",
                operation.method
            );
        } else {
            assert_ne!(
                response.status,
                StatusCode::UNAUTHORIZED,
                "{} {path} with a valid token",
                operation.method
            );
        }
    }
}

#[tokio::test]
async fn unknown_paths_require_a_token() {
    let t = TestApp::new().await;
    for path in [
        "/v1/nope",
        "/v1/auth/2fa/nope",
        "/v1/admin",
        "/v1/me/../config",
    ] {
        let response = t.call(Req::get(path)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(response.code(), "session_invalid");
    }
    let account = t.register("bob@example.com").await;
    let response = t
        .call(Req::get("/v1/nope").token(&account.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.code(), "not_found");
}

#[tokio::test]
async fn reauth_operations_reject_missing_foreign_and_expired_tokens() {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let other_session = t.login(&alice).await;
    let foreign = t.reauth(&other_session).await;
    let vault = format!("/v1/vaults/{}", t.create_vault(&alice).await);
    let passkey = format!("/v1/me/webauthn/{}", support::new_uuid());
    for (method, path) in [
        ("PUT", "/v1/me/password"),
        ("PUT", "/v1/me/recovery"),
        ("DELETE", "/v1/me"),
        ("DELETE", vault.as_str()),
        ("POST", "/v1/me/totp/setup"),
        ("DELETE", "/v1/me/totp"),
        ("POST", "/v1/me/backup-codes"),
        ("POST", "/v1/me/webauthn/register/options"),
        ("DELETE", passkey.as_str()),
    ] {
        let response = t
            .call(Req::new(method, path).token(&alice.access_token))
            .await;
        assert_eq!(response.code(), "reauth_required", "{path} without header");
        let response = t
            .call(
                Req::new(method, path)
                    .token(&alice.access_token)
                    .reauth(&foreign),
            )
            .await;
        assert_eq!(
            response.code(),
            "reauth_required",
            "{path} with a token of another session"
        );
        let response = t
            .call(
                Req::new(method, path)
                    .token(&alice.access_token)
                    .reauth("not-a-token"),
            )
            .await;
        assert_eq!(response.code(), "reauth_required", "{path} malformed");
    }
    let own = t.reauth(&alice).await;
    t.advance(Duration::minutes(5));
    let response = t
        .call(
            Req::put("/v1/me/recovery")
                .token(&alice.access_token)
                .reauth(&own),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.code(),
        "reauth_required",
        "expired after 5 minutes"
    );
}
