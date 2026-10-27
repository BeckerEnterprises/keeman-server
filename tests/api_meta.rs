//! `config`, `time`, `health` and the request pipeline: problem format,
//! security headers, CORS, client identifier, routing errors.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{ORIGIN, Req, TestApp};

#[tokio::test]
async fn config_reports_public_settings() {
    let t = TestApp::new().await;
    let response = t.call(Req::get("/v1/config")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.json(),
        json!({
            "server_version": env!("CARGO_PKG_VERSION"),
            "api_version": 1,
            "registration": "invite",
            "webauthn": { "rp_id": "app.example.org" },
            "features": { "favicon": true, "manifest": true },
            "limits": { "attachment_max_bytes": 52428800, "batch_max_ops": 500 },
        })
    );
}

#[tokio::test]
async fn time_uses_the_server_clock() {
    let t = TestApp::new().await;
    let response = t.call(Req::get("/v1/time")).await;
    assert_eq!(
        response.json()["now_ms"].as_i64(),
        Some(t.now().unix_timestamp() * 1000)
    );
}

#[tokio::test]
async fn health_needs_no_client_header_and_reports_the_database() {
    let t = TestApp::new().await;
    let response = t.call(Req::get("/v1/health").without_client()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({ "status": "ok" }));
    let response = t
        .call(Req::new("HEAD", "/v1/health").without_client())
        .await;
    assert_eq!(response.status, StatusCode::OK);

    t.app.db.close().await;
    let response = t.call(Req::get("/v1/health").without_client()).await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.json(), json!({ "status": "error" }));
    assert_eq!(
        response.header("cache-control").as_deref(),
        Some("no-store")
    );
}

#[tokio::test]
async fn client_header_is_required_and_validated() {
    let t = TestApp::new().await;
    let response = t.call(Req::get("/v1/config").without_client()).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.code(), "validation_failed");
    assert_eq!(response.field_error().0, "X-Keeman-Client");

    for bad in ["Test/1", "test", "test/", "test/1 2"] {
        let response = t
            .call(
                Req::get("/v1/config")
                    .without_client()
                    .header("x-keeman-client", bad),
            )
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let response = t
        .call(Req::get("/v1/config").header("x-keeman-client", "web/0.1.0"))
        .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "two client headers"
    );
    // Only GET /v1/health is exempt.
    let response = t.call(Req::post("/v1/health").without_client()).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn security_headers_on_every_response() {
    let t = TestApp::new().await;
    let responses = [
        t.call(Req::get("/v1/config")).await,
        t.call(Req::get("/v1/me")).await,
        t.call(Req::get("/nope")).await,
        t.call(Req::new("PATCH", "/v1/config")).await,
        t.call(Req::post("/v1/auth/prelogin").raw(Some("text/plain"), b"x"))
            .await,
        t.call(
            Req::new("OPTIONS", "/v1/config")
                .origin(ORIGIN)
                .header("access-control-request-method", "GET"),
        )
        .await,
    ];
    for response in responses {
        assert_eq!(
            response.header("x-content-type-options").as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            response.header("referrer-policy").as_deref(),
            Some("no-referrer")
        );
        assert_eq!(
            response.header("content-security-policy").as_deref(),
            Some("default-src 'none'; frame-ancestors 'none'")
        );
        assert_eq!(
            response.header("cache-control").as_deref(),
            Some("no-store")
        );
        assert!(
            !response
                .header("content-type")
                .unwrap_or_default()
                .contains("html")
        );
    }
}

#[tokio::test]
async fn routing_errors_are_problems() {
    let t = TestApp::new().await;
    // Outside /v1/ → 404 before anything else.
    for path in ["/", "/v1", "/index.html", "/v2/config"] {
        let response = t.call(Req::get(path).without_client()).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(response.code(), "not_found");
    }
    let response = t.call(Req::new("PATCH", "/v1/config")).await;
    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.code(), "method_not_allowed");
}

#[tokio::test]
async fn request_ids_are_fresh_uuidv7() {
    let t = TestApp::new().await;
    let a = t
        .call(Req::get("/v1/me").header("x-request-id", "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b"))
        .await;
    let b = t.call(Req::get("/v1/me")).await;
    let id = |r: &support::TestResponse| {
        r.json()["instance"]
            .as_str()
            .unwrap()
            .trim_start_matches("urn:uuid:")
            .to_string()
    };
    assert_ne!(id(&a), id(&b));
    assert_ne!(id(&a), "0192b3a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b");
    assert_eq!(uuid::Uuid::parse_str(&id(&a)).unwrap().get_version_num(), 7);
}

#[tokio::test]
async fn cors_allows_only_configured_origins() {
    let t = TestApp::new().await;
    let preflight = t
        .call(
            Req::new("OPTIONS", "/v1/me/password")
                .without_client()
                .origin(ORIGIN)
                .header("access-control-request-method", "PUT")
                .header(
                    "access-control-request-headers",
                    "authorization,content-type,x-keeman-client,x-keeman-reauth",
                ),
        )
        .await;
    assert_eq!(preflight.status, StatusCode::OK);
    assert_eq!(
        preflight.header("access-control-allow-origin").as_deref(),
        Some(ORIGIN)
    );
    assert_eq!(
        preflight
            .header("access-control-allow-credentials")
            .as_deref(),
        Some("true")
    );
    assert_eq!(
        preflight.header("access-control-max-age").as_deref(),
        Some("600")
    );
    let allowed_headers = preflight
        .header("access-control-allow-headers")
        .unwrap()
        .to_lowercase();
    for name in [
        "authorization",
        "content-type",
        "idempotency-key",
        "x-keeman-client",
        "x-keeman-reauth",
    ] {
        assert!(allowed_headers.contains(name), "{name}");
    }

    let response = t.call(Req::get("/v1/config").origin(ORIGIN)).await;
    assert_eq!(
        response.header("access-control-allow-origin").as_deref(),
        Some(ORIGIN)
    );
    let exposed = response
        .header("access-control-expose-headers")
        .unwrap()
        .to_lowercase();
    assert!(exposed.contains("retry-after"));

    // A foreign or missing origin gets no CORS headers at all, but the request is processed.
    for request in [
        Req::get("/v1/config").origin("https://evil.example"),
        Req::get("/v1/config"),
    ] {
        let response = t.call(request).await;
        assert_eq!(response.status, StatusCode::OK);
        let cors: Vec<_> = response
            .headers
            .keys()
            .filter(|n| n.as_str().starts_with("access-control-"))
            .collect();
        assert!(cors.is_empty(), "{cors:?}");
    }
    let preflight = t
        .call(
            Req::new("OPTIONS", "/v1/config")
                .without_client()
                .origin("https://evil.example")
                .header("access-control-request-method", "GET"),
        )
        .await;
    assert_eq!(preflight.header("access-control-allow-origin"), None);
    assert_eq!(preflight.header("access-control-allow-methods"), None);
}

#[tokio::test]
async fn unknown_query_parameters_are_rejected() {
    let t = TestApp::new().await;
    let response = t.call(Req::get("/v1/config?x=1")).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.code(), "validation_failed");
}

#[tokio::test]
async fn body_content_type_and_size() {
    let t = TestApp::new().await;
    let response = t
        .call(Req::post("/v1/auth/prelogin").raw(Some("text/plain"), b"{}"))
        .await;
    assert_eq!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(response.code(), "unsupported_media_type");
    let response = t
        .call(Req::post("/v1/auth/prelogin").raw(None, br#"{"email":"a@b.c"}"#))
        .await;
    assert_eq!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let response = t
        .call(Req::post("/v1/auth/prelogin").raw(
            Some("application/json; charset=utf-8"),
            br#"{"email":"a@b.c"}"#,
        ))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let response = t
        .call(Req::post("/v1/auth/prelogin").raw(Some("application/json"), b""))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        response.field_error(),
        (String::new(), "request body required".into())
    );
    let big = vec![b' '; 2 * 1024 * 1024 + 1];
    let response = t
        .call(Req::post("/v1/auth/prelogin").raw(Some("application/json"), &big))
        .await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.code(), "payload_too_large");
}
