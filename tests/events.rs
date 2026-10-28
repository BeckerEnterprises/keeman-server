//! `GET /v1/events` over a real TCP listener.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::{HeaderValue, StatusCode};
use futures_util::{SinkExt, StreamExt};
use keeman_server::app::router;
use keeman_server::events::socket::Timings;
use serde_json::{Value, json};
use support::{Account, ORIGIN, Req, TestApp, config_in, new_uuid, put_op};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const FAST: Timings = Timings {
    auth_timeout: Duration::from_millis(300),
    ping_interval: Duration::from_millis(150),
    revalidate_interval: Duration::from_secs(3600),
    send_timeout: Duration::from_millis(300),
};

/// The test app plus the address of a real listener serving its router.
async fn serve(extra: &str) -> (TestApp, SocketAddr) {
    serve_with(extra, FAST).await
}

async fn serve_with(extra: &str, timings: Timings) -> (TestApp, SocketAddr) {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path(), extra);
    let t = TestApp::with_timings(config, dir, timings).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(t.app.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (t, addr)
}

async fn open(addr: SocketAddr, origin: Option<&str>) -> Result<Ws, WsError> {
    let mut request = format!("ws://{addr}/v1/events")
        .into_client_request()
        .unwrap();
    if let Some(origin) = origin {
        request
            .headers_mut()
            .insert("origin", HeaderValue::from_str(origin).unwrap());
    }
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(ws, _)| ws)
}

async fn next_text(ws: &mut Ws) -> Value {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("a message in time")
            .expect("open stream")
            .expect("no error");
        match message {
            Message::Text(text) => return serde_json::from_str(text.as_str()).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// The close code the server sends next, skipping other messages.
async fn close_code(ws: &mut Ws) -> u16 {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("a close in time");
        match message {
            Some(Ok(Message::Close(Some(frame)))) => return u16::from(frame.code),
            Some(Ok(Message::Close(None))) | None => return 1005,
            Some(Ok(_)) => {}
            Some(Err(error)) => panic!("{error}"),
        }
    }
}

async fn ready(addr: SocketAddr, account: &Account) -> Ws {
    let mut ws = open(addr, Some(ORIGIN)).await.unwrap();
    let auth = json!({ "type": "auth", "access_token": account.access_token });
    ws.send(Message::text(auth.to_string())).await.unwrap();
    assert_eq!(next_text(&mut ws).await, json!({ "type": "ready" }));
    ws
}

#[tokio::test]
async fn events_follow_the_changes() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let mut a = ready(addr, &alice).await;
    let mut b = ready(addr, &bob).await;

    let vault_id = t.create_vault(&alice).await;
    assert_eq!(next_text(&mut a).await, json!({ "type": "vaults_changed" }));

    t.add_member(&vault_id, &bob, "member", "active").await;
    let response = t
        .batch(&alice, &vault_id, vec![put_op(&new_uuid(), "entry", None)])
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let event = json!({ "type": "vault_changed", "vault_id": vault_id, "revision": 2 });
    assert_eq!(next_text(&mut a).await, event);
    assert_eq!(next_text(&mut b).await, event);

    let body = json!({ "expected_revision": 1, "data": support::envelope(297) });
    let response = t
        .call(
            Req::put("/v1/me/user-data")
                .token(&alice.access_token)
                .json(&body),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        next_text(&mut a).await,
        json!({ "type": "user_data_changed", "revision": 2 })
    );

    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete(&format!("/v1/vaults/{vault_id}"))
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(next_text(&mut a).await, json!({ "type": "vaults_changed" }));
    assert_eq!(next_text(&mut b).await, json!({ "type": "vaults_changed" }));
}

#[tokio::test]
async fn origin_is_checked_before_the_upgrade() {
    let (t, addr) = serve("").await;
    for origin in ["https://evil.example", "null"] {
        match open(addr, Some(origin)).await {
            Err(WsError::Http(response)) => assert_eq!(response.status(), 403, "{origin}"),
            other => panic!("{origin}: {other:?}"),
        }
    }
    // Native clients send no Origin.
    let alice = t.register("alice@example.com").await;
    let mut ws = open(addr, None).await.unwrap();
    let auth = json!({ "type": "auth", "access_token": alice.access_token });
    ws.send(Message::text(auth.to_string())).await.unwrap();
    assert_eq!(next_text(&mut ws).await["type"], "ready");
}

#[tokio::test]
async fn upgrades_have_their_own_rate_limit() {
    let (_t, addr) = serve("[rate_limits]\nevents_per_ip_per_min = 2\n").await;
    open(addr, Some(ORIGIN)).await.unwrap();
    open(addr, Some(ORIGIN)).await.unwrap();
    match open(addr, Some(ORIGIN)).await {
        Err(WsError::Http(response)) => {
            assert_eq!(response.status(), 429);
            assert!(response.headers().contains_key("retry-after"));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_plain_request_is_not_an_upgrade() {
    let t = TestApp::new().await;
    let response = t.call(Req::get("/v1/events").without_client()).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.field_error().0, "Upgrade");
    let response = t
        .call(
            Req::get("/v1/events")
                .without_client()
                .origin("https://evil.example"),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn authentication_rules() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;

    // No message within the time limit.
    let mut ws = open(addr, Some(ORIGIN)).await.unwrap();
    assert_eq!(close_code(&mut ws).await, 4408);

    let expired = alice.access_token.clone();
    t.advance(time::Duration::minutes(16));
    let first_messages = [
        Message::text(json!({ "type": "auth", "access_token": "A".repeat(43) }).to_string()),
        Message::text(json!({ "type": "auth", "access_token": expired }).to_string()),
        Message::text(json!({ "type": "hello", "access_token": expired }).to_string()),
        Message::text("not json"),
        Message::text(json!({ "type": "auth", "access_token": expired, "x": 1 }).to_string()),
    ];
    for message in first_messages {
        let mut ws = open(addr, Some(ORIGIN)).await.unwrap();
        ws.send(message).await.unwrap();
        assert_eq!(close_code(&mut ws).await, 4401);
    }
    let mut ws = open(addr, Some(ORIGIN)).await.unwrap();
    ws.send(Message::binary(vec![1, 2, 3])).await.unwrap();
    assert_eq!(close_code(&mut ws).await, 1003);
    let mut ws = open(addr, Some(ORIGIN)).await.unwrap();
    ws.send(Message::text("x".repeat(5000))).await.unwrap();
    assert_eq!(close_code(&mut ws).await, 1009);
}

#[tokio::test]
async fn revocations_close_the_connections_of_the_session() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let mut mine = ready(addr, &alice).await;
    let mut theirs = ready(addr, &other).await;

    let response = t
        .call(Req::post("/v1/auth/logout").token(&other.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(
        next_text(&mut theirs).await,
        json!({ "type": "session_revoked" })
    );
    assert_eq!(close_code(&mut theirs).await, 4401);

    // The other session stays connected and still gets events.
    t.create_vault(&alice).await;
    assert_eq!(next_text(&mut mine).await["type"], "vaults_changed");

    // Revoking other sessions and the password change close them as well.
    let third = t.login(&alice).await;
    let mut ws = ready(addr, &third).await;
    let response = t
        .call(Req::delete("/v1/me/sessions?scope=others").token(&alice.access_token))
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(next_text(&mut ws).await["type"], "session_revoked");
    assert_eq!(close_code(&mut ws).await, 4401);

    let fourth = t.login(&alice).await;
    let mut ws = ready(addr, &fourth).await;
    let reauth = t.reauth(&alice).await;
    let body = json!({
        "kdf": { "alg": "argon2id13", "ops": 3, "mem": 67108864 },
        "salt": support::random_b64::<16>(),
        "auth_key": alice.auth_key,
        "user_key_wrapped": support::envelope(73),
        "revoke_other_sessions": true,
    });
    let response = t
        .call(
            Req::put("/v1/me/password")
                .token(&alice.access_token)
                .reauth(&reauth)
                .json(&body),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{}",
        response.text()
    );
    assert_eq!(next_text(&mut ws).await["type"], "session_revoked");
    assert_eq!(close_code(&mut ws).await, 4401);

    // Reuse of an old refresh token revokes the session.
    let fifth = t.login(&alice).await;
    let mut ws = ready(addr, &fifth).await;
    let refresh =
        |token: &str| Req::post("/v1/auth/refresh").json(&json!({ "refresh_token": token }));
    let rotated = t.call(refresh(&fifth.refresh_token)).await;
    assert_eq!(rotated.status, StatusCode::OK);
    t.advance(time::Duration::seconds(31));
    let reused = t.call(refresh(&fifth.refresh_token)).await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(next_text(&mut ws).await["type"], "session_revoked");
    assert_eq!(close_code(&mut ws).await, 4401);
}

#[tokio::test]
async fn revalidation_catches_revocations_outside_the_process() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let mut a = ready(addr, &alice).await;
    let mut b = ready(addr, &bob).await;
    // Like `keeman-server user disable` in the CLI process.
    t.sql(&format!(
        "UPDATE users SET disabled = 1 WHERE id = '{}'",
        alice.user_id
    ))
    .await;
    let closed = keeman_server::events::socket::revalidate(&t.app)
        .await
        .unwrap();
    assert_eq!(closed, 1);
    assert_eq!(next_text(&mut a).await["type"], "session_revoked");
    assert_eq!(close_code(&mut a).await, 4401);
    // Bob's connection lives on.
    t.create_vault(&bob).await;
    assert_eq!(next_text(&mut b).await["type"], "vaults_changed");
}

#[tokio::test]
async fn limits_frames_and_connections() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;

    let mut ws = ready(addr, &alice).await;
    ws.send(Message::text("ignored")).await.unwrap();
    ws.send(Message::text("x".repeat(5000))).await.unwrap();
    assert_eq!(close_code(&mut ws).await, 1009);
    let mut ws = ready(addr, &alice).await;
    ws.send(Message::binary(vec![0])).await.unwrap();
    assert_eq!(close_code(&mut ws).await, 1003);

    let mut open_connections = Vec::new();
    for _ in 0..20 {
        open_connections.push(ready(addr, &alice).await);
    }
    let mut ws = open(addr, Some(ORIGIN)).await.unwrap();
    let auth = json!({ "type": "auth", "access_token": alice.access_token });
    ws.send(Message::text(auth.to_string())).await.unwrap();
    assert_eq!(close_code(&mut ws).await, 4429);
}

#[tokio::test]
async fn pings_keep_readers_and_drop_silent_peers() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let mut reader = ready(addr, &alice).await;
    let silent = ready(addr, &alice).await;
    // The reader answers pings while it waits for an event.
    let later = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        t.create_vault(&alice).await
    };
    let (event, _) = tokio::join!(next_text(&mut reader), later);
    assert_eq!(event["type"], "vaults_changed");
    // The silent peer never read, so it never answered a ping.
    assert_eq!(t.app.hub.connections(&alice.user_id), 1);
    drop(silent);
}

#[tokio::test]
async fn shutdown_closes_with_going_away() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let mut ws = ready(addr, &alice).await;
    t.app.hub.shutdown();
    assert_eq!(close_code(&mut ws).await, u16::from(CloseCode::Away));
}

#[tokio::test]
async fn account_deletion_revokes_and_notifies() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&bob).await;
    t.add_member(&vault_id, &alice, "member", "active").await;
    let mut a = ready(addr, &alice).await;
    let mut b = ready(addr, &bob).await;
    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete("/v1/me")
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(next_text(&mut a).await["type"], "session_revoked");
    assert_eq!(close_code(&mut a).await, 4401);
    assert_eq!(next_text(&mut b).await, json!({ "type": "vaults_changed" }));
}

#[tokio::test]
async fn sharing_notifies_the_affected_accounts() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault_id = t.create_vault(&alice).await;
    let mut a = ready(addr, &alice).await;
    let mut b = ready(addr, &bob).await;
    let changed = json!({ "type": "vaults_changed" });

    t.invite_member(&alice, &vault_id, &bob).await;
    assert_eq!(next_text(&mut b).await, changed);
    assert_eq!(next_text(&mut a).await, changed);
    t.accept_invitation(&bob, &vault_id, 1).await;
    assert_eq!(next_text(&mut a).await, changed);
    assert_eq!(next_text(&mut b).await, changed);

    // A rotation removing Bob: Alice syncs the new revision, Bob loses the vault.
    let page = t.changes(&alice, &vault_id, "since=0").await.json();
    let objects: Vec<Value> = page["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| json!({ "id": o["id"], "type": o["type"], "key_version": 2, "data": support::envelope(300) }))
        .collect();
    let opened = t
        .call(
            Req::post(&format!("/v1/vaults/{vault_id}/rotations"))
                .token(&alice.access_token)
                .idem(&new_uuid())
                .json(&json!({ "base_revision": 1, "new_key_version": 2, "remove_user_ids": [bob.user_id] })),
        )
        .await
        .json();
    let rotation_id = opened["rotation_id"].as_str().unwrap();
    let base = format!("/v1/vaults/{vault_id}/rotations/{rotation_id}");
    let roles = t
        .rotation_roles(&alice, &vault_id, &[&bob.user_id])
        .await
        .unwrap();
    t.call(
        Req::put(&format!("{base}/objects"))
            .token(&alice.access_token)
            .idem(&new_uuid())
            .json(&json!({ "objects": objects })),
    )
    .await;
    let committed = t
        .call(
            Req::post(&format!("{base}/commit"))
                .token(&alice.access_token)
                .idem(&new_uuid())
                .json(&json!({
                    "key_wrapped": support::envelope(73),
                    "member_keys": [],
                    "invite_keys": [],
                    "remove_user_ids": [bob.user_id],
                    "drop_objects": [],
                    "roles": roles,
                })),
        )
        .await;
    assert_eq!(committed.status, StatusCode::OK, "{}", committed.text());
    assert_eq!(
        next_text(&mut a).await,
        json!({ "type": "vault_changed", "vault_id": vault_id, "revision": 2 })
    );
    assert_eq!(next_text(&mut a).await, changed);
    assert_eq!(next_text(&mut b).await, changed);
}

#[tokio::test]
async fn confirmations_notify_every_session_of_the_account_only() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let bob = t.register("bob@example.com").await;
    let mut mine = ready(addr, &alice).await;
    let mut theirs = ready(addr, &other).await;
    let mut b = ready(addr, &bob).await;
    let changed = json!({ "type": "confirmations_changed" });

    let nonce = support::b64([1u8; 32]);
    let created = t
        .call(
            Req::post("/v1/me/confirmations")
                .token(&alice.access_token)
                .json(&json!({ "nonce": nonce })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let id = created.json()["request_id"].as_str().unwrap().to_string();
    assert_eq!(next_text(&mut mine).await, changed);
    assert_eq!(next_text(&mut theirs).await, changed);

    let statement = keeman_server::confirmation::Statement {
        user_id: alice.user_id.clone(),
        nonce: [1; 32],
        time: "2026-10-28T08:42:00.000Z".into(),
        content: b"{}".to_vec(),
    };
    let answer = support::freshness::sign_in(
        &other,
        "keeman:v1:device-confirmation",
        &keeman_server::confirmation::encode(&statement),
    );
    let answered = t
        .call(
            Req::put(&format!("/v1/me/confirmations/{id}"))
                .token(&other.access_token)
                .json(&json!({ "answer": answer })),
        )
        .await;
    assert_eq!(
        answered.status,
        StatusCode::NO_CONTENT,
        "{}",
        answered.text()
    );
    assert_eq!(next_text(&mut mine).await, changed);
    assert_eq!(next_text(&mut theirs).await, changed);

    let deleted = t
        .call(Req::delete(&format!("/v1/me/confirmations/{id}")).token(&alice.access_token))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(next_text(&mut mine).await, changed);

    // Bob's connection heard none of it: his next message is his own.
    let body = json!({ "expected_revision": 1, "data": support::envelope(297) });
    t.call(
        Req::put("/v1/me/user-data")
            .token(&bob.access_token)
            .json(&body),
    )
    .await;
    assert_eq!(
        next_text(&mut b).await,
        json!({ "type": "user_data_changed", "revision": 2 })
    );
}

#[tokio::test]
async fn recovery_closes_the_connections_of_all_sessions() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let other = t.login(&alice).await;
    let mut mine = ready(addr, &alice).await;
    let mut theirs = ready(addr, &other).await;
    let body = json!({ "email": alice.email, "recovery_auth_key": alice.recovery_auth_key });
    let start = t
        .call(Req::post("/v1/auth/recover/start").json(&body))
        .await;
    assert_eq!(start.status, StatusCode::OK);
    let body = json!({
        "recovery_token": start.json()["recovery_token"],
        "kdf": { "alg": "argon2id13", "ops": 3, "mem": 67108864 },
        "salt": support::random_b64::<16>(),
        "auth_key": support::random_b64::<32>(),
        "user_key_wrapped": support::envelope(73),
        "device": { "name": "Recovered", "client_type": "cli" },
    });
    let finish = t
        .call(Req::post("/v1/auth/recover/finish").json(&body))
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.text());
    for ws in [&mut mine, &mut theirs] {
        assert_eq!(next_text(ws).await["type"], "session_revoked");
        assert_eq!(close_code(ws).await, 4401);
    }
}

#[tokio::test]
async fn expired_invitations_are_deleted_and_announced() {
    let (t, addr) = serve("").await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let carol = t.register("carol@example.com").await;
    let old = t.create_vault(&alice).await;
    t.invite_member(&alice, &old, &bob).await;
    t.advance(time::Duration::days(29));
    let alice = t.login(&alice).await;
    let young = t.create_vault(&alice).await;
    t.invite_member(&alice, &young, &carol).await;
    t.advance(time::Duration::days(1) + time::Duration::minutes(1));
    let alice = t.login(&alice).await;
    let bob = t.login(&bob).await;
    let mut a = ready(addr, &alice).await;
    let mut b = ready(addr, &bob).await;

    let removed = keeman_server::jobs::cleanup(&t.app).await.unwrap();
    assert_eq!(removed.invitations, 1);
    let changed = json!({ "type": "vaults_changed" });
    assert_eq!(next_text(&mut b).await, changed);
    assert_eq!(next_text(&mut a).await, changed);
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM memberships WHERE state = 'pending' AND vault_id = '{young}'"
        ))
        .await,
        1
    );
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM memberships WHERE state = 'pending' AND vault_id = '{old}'"
        ))
        .await,
        0
    );
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM security_log WHERE event = 'invitation_expired' AND vault_id = '{old}' AND user_id = '{}'",
            bob.user_id
        ))
        .await,
        1
    );
}

#[tokio::test]
async fn a_peer_that_stops_reading_is_dropped_after_the_send_timeout() {
    // Pings so rare that only the send timeout can end the connection.
    let timings = Timings {
        ping_interval: Duration::from_secs(3600),
        ..FAST
    };
    let (t, addr) = serve_with("", timings).await;
    let alice = t.register("alice@example.com").await;
    let ws = ready(addr, &alice).await;
    assert_eq!(t.app.hub.connections(&alice.user_id), 1);
    // The client never reads: large events fill the socket buffers until a
    // send hangs.
    let filler = json!({ "type": "filler", "data": "x".repeat(64 * 1024) });
    for _ in 0..600 {
        if t.app.hub.connections(&alice.user_id) == 0 {
            break;
        }
        t.app.hub.publish([alice.user_id.as_str()], &filler);
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    for _ in 0..300 {
        if t.app.hub.connections(&alice.user_id) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(t.app.hub.connections(&alice.user_id), 0);
    drop(ws);
}
