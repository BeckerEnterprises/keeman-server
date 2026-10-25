//! Test harness: the real router on a temporary SQLite database with a
//! mock clock and a fixed server secret. Raw SQL is allowed only here.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

pub mod authenticator;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use keeman_server::app::{App, router};
use keeman_server::clock::{Clock, MockClock};
use keeman_server::config::Config;
use keeman_server::crypto::{ServerSecret, random_bytes};
use keeman_server::db::{Db, Tx};
use keeman_server::events::socket::Timings;
use keeman_server::favicon::Favicons;
use keeman_server::types::encode_base64url;
use serde_json::{Value, json};
use tempfile::TempDir;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

pub const SECRET: [u8; 32] = [7u8; 32];
pub const START: OffsetDateTime = datetime!(2026-10-23 08:00 UTC);
pub const PEER: &str = "203.0.113.10";
pub const RP_ID: &str = "app.example.org";
pub const ORIGIN: &str = "https://app.example.org";

pub struct TestApp {
    pub app: Arc<App>,
    pub clock: Arc<MockClock>,
    pub router: Router,
    pub dir: TempDir,
}

/// Writes a minimal config file (the required keys, `data_dir` and `extra`,
/// whose sections are merged into these) and loads it.
pub fn config_in(dir: &Path, extra: &str) -> Config {
    let path = dir.join("config.toml");
    let mut table: toml::Table = toml::from_str(&format!(
        "[server]\npublic_api_url = \"https://api.example.org\"\nallowed_origins = [\"{ORIGIN}\"]\n\
         [storage]\ndata_dir = \"{}\"\n\
         [webauthn]\nrp_id = \"{RP_ID}\"\nrp_origins = [\"{ORIGIN}\"]\n",
        dir.join("data").display()
    ))
    .unwrap();
    for (section, values) in toml::from_str::<toml::Table>(extra).unwrap() {
        match (table.get_mut(&section), values) {
            (Some(toml::Value::Table(base)), toml::Value::Table(values)) => base.extend(values),
            (_, values) => {
                table.insert(section, values);
            }
        }
    }
    std::fs::write(&path, toml::to_string(&table).unwrap()).unwrap();
    std::fs::create_dir_all(dir.join("data")).unwrap();
    Config::load(&path, &[]).unwrap()
}

impl TestApp {
    pub async fn new() -> Self {
        Self::with_config("").await
    }

    /// `extra` is appended to the config file, e.g. `[security]\nregistration = "open"`.
    pub async fn with_config(extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path(), extra);
        Self::with(config, dir).await
    }

    pub async fn with(config: Config, dir: TempDir) -> Self {
        Self::with_timings(config, dir, Timings::default()).await
    }

    pub async fn with_timings(config: Config, dir: TempDir, timings: Timings) -> Self {
        let favicon = config.features.favicon.then(|| Favicons::new().unwrap());
        Self::with_parts(config, dir, timings, favicon).await
    }

    /// With another favicon proxy (`None`: none at all).
    pub async fn with_favicons(config: Config, dir: TempDir, favicon: Option<Favicons>) -> Self {
        Self::with_parts(config, dir, Timings::default(), favicon).await
    }

    async fn with_parts(
        config: Config,
        dir: TempDir,
        timings: Timings,
        favicon: Option<Favicons>,
    ) -> Self {
        // Errors (never secrets) show up in the output of failing tests.
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::WARN)
            .try_init();
        let db = Db::open(&config.database_path()).await.unwrap();
        db.migrate().await.unwrap();
        let clock = Arc::new(MockClock::new(START));
        let app = App::with_parts(
            config,
            &ServerSecret::from_bytes(SECRET),
            db,
            clock.clone(),
            timings,
            favicon,
        )
        .unwrap();
        let router = router(app.clone());
        Self {
            app,
            clock,
            router,
            dir,
        }
    }

    pub fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    pub fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    pub async fn send(&self, request: Request<Body>) -> TestResponse {
        send_to(self.router.clone(), request).await
    }

    /// Runs a request in the background, e.g. one with a stalled body.
    pub fn spawn(&self, request: Request<Body>) -> tokio::task::JoinHandle<TestResponse> {
        tokio::spawn(send_to(self.router.clone(), request))
    }

    pub async fn call(&self, request: Req) -> TestResponse {
        self.send(request.build()).await
    }

    /// Creates an invite code like `keeman-server invite create`.
    pub async fn invite(&self) -> String {
        keeman_server::cli::invite::create(
            &self.app.db,
            &self.app.audit,
            self.now(),
            Duration::days(7),
            None,
        )
        .await
        .unwrap()
    }

    /// Registers a native (`cli`) account with a fresh invite from its own IP.
    pub async fn register(&self, email: &str) -> Account {
        self.register_as(email, "cli").await
    }

    pub async fn register_as(&self, email: &str, client_type: &str) -> Account {
        let invite = self.invite().await;
        let account = Account::new(email);
        let mut body = account.register_body(Some(&invite));
        body["device"]["client_type"] = json!(client_type);
        let response = self
            .call(
                Req::post("/v1/auth/register")
                    .json(&body)
                    .peer(&unique_ip()),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
        account.with_session(&response)
    }

    /// Logs in as a native client from a fresh IP.
    pub async fn login(&self, account: &Account) -> Account {
        let response = self
            .call(
                Req::post("/v1/auth/login")
                    .json(&account.login_body())
                    .peer(&unique_ip()),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        account.clone().with_session(&response)
    }

    pub async fn reauth(&self, account: &Account) -> String {
        let body = json!({ "auth_key": account.auth_key });
        let response = self
            .call(
                Req::post("/v1/me/reauth")
                    .token(&account.access_token)
                    .json(&body)
                    .peer(&unique_ip()),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        response.json()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Raw SQL against the test database (support code only).
    pub async fn sql(&self, statement: &str) {
        sqlx::query(sqlx::AssertSqlSafe(statement.to_string()))
            .execute(&self.app.db.read)
            .await
            .unwrap();
    }

    pub async fn count(&self, statement: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(statement.to_string()))
            .fetch_one(&self.app.db.read)
            .await
            .unwrap()
    }

    /// Turns on TOTP directly in the repository (as after a finished setup)
    /// and returns the secret.
    pub async fn enable_totp_direct(&self, account: &Account) -> [u8; 20] {
        let secret = random_bytes::<20>().unwrap();
        let sealed = self
            .app
            .keys
            .seal_totp_secret(&account.user_id, &secret)
            .unwrap();
        keeman_server::db::users::enable_totp(
            &self.app.db.read,
            &account.user_id,
            &sealed,
            0,
            "2026-10-23T08:00:00.000Z",
        )
        .await
        .unwrap();
        secret
    }

    /// Sets up and enables TOTP through the API; returns the secret and the
    /// body of `enable` (with `backup_codes` for a first factor).
    pub async fn enable_totp(&self, account: &Account) -> ([u8; 20], Value) {
        let reauth = self.reauth(account).await;
        let setup = self
            .call(
                Req::post("/v1/me/totp/setup")
                    .token(&account.access_token)
                    .reauth(&reauth),
            )
            .await;
        assert_eq!(setup.status, StatusCode::OK, "{}", setup.text());
        let text = setup.json()["secret"].as_str().unwrap().to_string();
        let secret: [u8; 20] = keeman_server::crypto::base32::decode(&text)
            .unwrap()
            .try_into()
            .unwrap();
        let code = self.totp(&secret, 0);
        let enable = self
            .call(
                Req::post("/v1/me/totp/enable")
                    .token(&account.access_token)
                    .json(&json!({ "code": code })),
            )
            .await;
        assert_eq!(enable.status, StatusCode::OK, "{}", enable.text());
        (secret, enable.json())
    }

    /// Replaces the backup codes of an account directly in the repository.
    pub async fn set_backup_codes(&self, account: &Account, codes: &[&str]) {
        let inputs = codes.iter().map(|c| c.as_bytes().to_vec()).collect();
        let hashes = self.app.passwords.hash_all(inputs).await.unwrap();
        let mut tx = self.app.db.begin().await.unwrap();
        keeman_server::db::backup_codes::replace(&mut tx, &account.user_id, &hashes)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// The account TOTP code `offset` steps from now.
    pub fn totp(&self, secret: &[u8; 20], offset: i64) -> String {
        use keeman_server::crypto::totp;
        totp::code(secret, totp::step(self.now().unix_timestamp()) + offset).unwrap()
    }

    /// Logs in with the auth key and returns the challenge token of
    /// `SecondFactorRequired`.
    pub async fn login_challenge(&self, account: &Account) -> String {
        let response = self
            .call(
                Req::post("/v1/auth/login")
                    .json(&account.login_body())
                    .peer(&unique_ip()),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        let body = response.json();
        assert_eq!(body["status"], "second_factor_required", "{body}");
        body["challenge_token"].as_str().unwrap().to_string()
    }

    pub async fn text(&self, statement: &str) -> String {
        sqlx::query_scalar(sqlx::AssertSqlSafe(statement.to_string()))
            .fetch_one(&self.app.db.read)
            .await
            .unwrap()
    }

    /// Stores a passkey row as the server would (fixtures).
    pub async fn insert_passkey(&self, account: &Account, credential_id: &[u8], passkey: &str) {
        sqlx::query(
            "INSERT INTO webauthn_credentials (id, user_id, credential_id, passkey, name, created_at)
             VALUES (?, ?, ?, ?, 'Fixture', '2026-10-23T08:00:00.000Z')",
        )
        .bind(new_uuid())
        .bind(&account.user_id)
        .bind(credential_id)
        .bind(passkey)
        .execute(&self.app.db.read)
        .await
        .unwrap();
    }

    /// Waits until `n` tasks wait for the write connection: a request
    /// started while the test holds a transaction has reached its own, after
    /// everything it checks beforehand.
    pub async fn writers_waiting(&self, n: usize) {
        for _ in 0..500 {
            if self.app.db.writers_waiting() >= n {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!(
            "{} writers waiting, expected {n}",
            self.app.db.writers_waiting()
        );
    }

    /// Turns on TOTP inside a held transaction.
    pub async fn enable_totp_in(&self, tx: &mut Tx, account: &Account) {
        let secret = random_bytes::<20>().unwrap();
        let sealed = self
            .app
            .keys
            .seal_totp_secret(&account.user_id, &secret)
            .unwrap();
        keeman_server::db::users::enable_totp(
            &mut **tx,
            &account.user_id,
            &sealed,
            0,
            "2026-10-23T08:00:00.000Z",
        )
        .await
        .unwrap();
    }

    pub async fn security_events(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT event FROM security_log ORDER BY id")
            .fetch_all(&self.app.db.read)
            .await
            .unwrap()
    }
}

/// An object of a create or rotation request (`ObjectUpload`).
/// Raw SQL inside a held transaction (support code only).
pub async fn sql_in(tx: &mut Tx, statement: &str) {
    sqlx::query(sqlx::AssertSqlSafe(statement.to_string()))
        .execute(&mut **tx)
        .await
        .unwrap();
}

pub fn object(id: &str, kind: &str, data_len: usize) -> Value {
    json!({ "id": id, "type": kind, "key_version": 1, "data": envelope(data_len) })
}

/// `POST /v1/vaults` body: vault_meta, root group and recycle bin.
pub fn vault_body(vault_id: &str) -> Value {
    json!({
        "vault_id": vault_id,
        "key_wrapped": envelope(73),
        "objects": [
            object(vault_id, "vault_meta", 300),
            object(&new_uuid(), "group", 300),
            object(&new_uuid(), "group", 300),
        ],
    })
}

pub fn put_op(id: &str, kind: &str, expected: Option<i64>) -> Value {
    json!({ "op": "put", "id": id, "type": kind, "key_version": 1, "expected_revision": expected, "data": envelope(300) })
}

pub fn delete_op(id: &str, expected: i64) -> Value {
    json!({ "op": "delete", "id": id, "key_version": 1, "expected_revision": expected, "data": envelope(256) })
}

impl TestApp {
    /// Creates a vault with three objects; returns its ID.
    pub async fn create_vault(&self, account: &Account) -> String {
        let vault_id = new_uuid();
        let response = self
            .call(
                Req::post("/v1/vaults")
                    .token(&account.access_token)
                    .idem(&new_uuid())
                    .json(&vault_body(&vault_id)),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
        vault_id
    }

    pub async fn batch(&self, account: &Account, vault_id: &str, ops: Vec<Value>) -> TestResponse {
        self.call(
            Req::post(&format!("/v1/vaults/{vault_id}/batch"))
                .token(&account.access_token)
                .idem(&new_uuid())
                .json(&json!({ "ops": ops })),
        )
        .await
    }

    pub async fn changes(&self, account: &Account, vault_id: &str, query: &str) -> TestResponse {
        self.call(
            Req::get(&format!("/v1/vaults/{vault_id}/changes?{query}"))
                .token(&account.access_token),
        )
        .await
    }

    /// Adds a membership directly, without a sender (tests of other areas).
    pub async fn add_member(&self, vault_id: &str, account: &Account, role: &str, state: &str) {
        let key = if state == "active" { "X'01'" } else { "NULL" };
        let key_box = if state == "pending" { "X'02'" } else { "NULL" };
        self.sql(&format!(
            "INSERT INTO memberships (vault_id, user_id, role, state, key_version, key_wrapped, key_box, created_at)
             VALUES ('{vault_id}', '{}', '{role}', '{state}', 1, {key}, {key_box}, '2026-10-23T08:00:00.000Z')",
            account.user_id
        ))
        .await;
    }

    /// `POST /v1/vaults/{id}/members` with a box for key version 1.
    pub async fn invite_member(
        &self,
        owner: &Account,
        vault_id: &str,
        invitee: &Account,
    ) -> TestResponse {
        self.call(
            Req::post(&format!("/v1/vaults/{vault_id}/members"))
                .token(&owner.access_token)
                .json(&json!({ "user_id": invitee.user_id, "key_version": 1, "key_box": key_box(200) })),
        )
        .await
    }

    /// `POST /v1/vaults/{id}/accept`.
    pub async fn accept_invitation(
        &self,
        account: &Account,
        vault_id: &str,
        key_version: i64,
    ) -> TestResponse {
        self.call(
            Req::post(&format!("/v1/vaults/{vault_id}/accept"))
                .token(&account.access_token)
                .json(&json!({ "key_version": key_version, "key_wrapped": envelope(73) })),
        )
        .await
    }

    /// Invites and accepts: `member` becomes an active member.
    pub async fn share(&self, owner: &Account, vault_id: &str, member: &Account) {
        let invited = self.invite_member(owner, vault_id, member).await;
        assert_eq!(invited.status, StatusCode::CREATED, "{}", invited.text());
        let accepted = self.accept_invitation(member, vault_id, 1).await;
        assert_eq!(
            accepted.status,
            StatusCode::NO_CONTENT,
            "{}",
            accepted.text()
        );
    }

    /// The vault as `GET /v1/vaults` shows it to the account.
    pub async fn listed(&self, account: &Account, vault_id: &str) -> Option<Value> {
        let list = self
            .call(Req::get("/v1/vaults").token(&account.access_token))
            .await
            .json();
        list["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["vault_id"] == vault_id)
            .cloned()
    }
}

static NEXT_IP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// A fresh client IP, so helpers do not share rate-limit buckets.
pub fn unique_ip() -> String {
    let n = NEXT_IP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("198.51.{}.{}", 100 + n / 250, 1 + n % 250)
}

pub fn b64<const N: usize>(bytes: [u8; N]) -> String {
    encode_base64url(&bytes)
}

pub fn random_b64<const N: usize>() -> String {
    b64(random_bytes::<N>().unwrap())
}

/// An AEAD-envelope-shaped value (format byte `0x01`); the server never
/// decrypts it, so random bytes suffice. No real password data.
pub fn envelope(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).unwrap();
    bytes[0] = 0x01;
    encode_base64url(&bytes)
}

/// A box-envelope-shaped value (format byte `0x02`).
pub fn key_box(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).unwrap();
    bytes[0] = 0x02;
    encode_base64url(&bytes)
}

pub fn new_uuid() -> String {
    uuid::Uuid::now_v7().to_string()
}

#[derive(Debug, Clone)]
pub struct Account {
    pub user_id: String,
    pub email: String,
    pub auth_key: String,
    pub recovery_auth_key: String,
    pub salt: String,
    pub public_key: String,
    pub session_id: String,
    pub access_token: String,
    pub refresh_token: String,
}

impl Account {
    pub fn new(email: &str) -> Self {
        Self {
            user_id: new_uuid(),
            email: email.to_string(),
            auth_key: random_b64::<32>(),
            recovery_auth_key: random_b64::<32>(),
            salt: random_b64::<16>(),
            public_key: random_b64::<32>(),
            session_id: String::new(),
            access_token: String::new(),
            refresh_token: String::new(),
        }
    }

    pub fn register_body(&self, invite: Option<&str>) -> Value {
        let mut body = json!({
            "user_id": self.user_id,
            "email": self.email,
            "kdf": { "alg": "argon2id13", "ops": 3, "mem": 67108864 },
            "salt": self.salt,
            "auth_key": self.auth_key,
            "user_key_wrapped": envelope(73),
            "public_key": self.public_key,
            "private_key_wrapped": envelope(73),
            "recovery": { "auth_key": self.recovery_auth_key, "user_key_wrapped": envelope(73) },
            "user_data": envelope(297),
            "device": { "name": "Test device", "client_type": "cli" },
        });
        if let Some(invite) = invite {
            body["invite_code"] = json!(invite);
        }
        body
    }

    pub fn login_body(&self) -> Value {
        json!({ "email": self.email, "auth_key": self.auth_key, "device": { "name": "Test device", "client_type": "cli" } })
    }

    pub fn with_session(mut self, response: &TestResponse) -> Self {
        let body = response.json();
        self.session_id = body["session_id"].as_str().unwrap_or_default().to_string();
        self.access_token = body["access_token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        self.refresh_token = body["refresh_token"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| {
                response
                    .cookie_value("__Host-keeman_rt")
                    .unwrap_or_default()
            });
        self
    }
}

/// Request builder with the defaults every client sends.
pub struct Req {
    method: Method,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    peer: Option<String>,
    client: bool,
}

impl Req {
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.parse().unwrap(),
            path: path.to_string(),
            headers: Vec::new(),
            body: None,
            peer: None,
            client: true,
        }
    }

    pub fn get(path: &str) -> Self {
        Self::new("GET", path)
    }

    pub fn post(path: &str) -> Self {
        Self::new("POST", path)
    }

    pub fn put(path: &str) -> Self {
        Self::new("PUT", path)
    }

    pub fn delete(path: &str) -> Self {
        Self::new("DELETE", path)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn token(self, token: &str) -> Self {
        self.header("authorization", &format!("Bearer {token}"))
    }

    pub fn reauth(self, token: &str) -> Self {
        self.header("x-keeman-reauth", token)
    }

    pub fn idem(self, key: &str) -> Self {
        self.header("idempotency-key", key)
    }

    pub fn origin(self, origin: &str) -> Self {
        self.header("origin", origin)
    }

    pub fn cookie(self, token: &str) -> Self {
        self.header("cookie", &format!("__Host-keeman_rt={token}"))
    }

    pub fn json(mut self, body: &Value) -> Self {
        self.body = Some(body.to_string().into_bytes());
        self.header("content-type", "application/json")
    }

    pub fn raw(mut self, content_type: Option<&str>, body: &[u8]) -> Self {
        self.body = Some(body.to_vec());
        match content_type {
            Some(value) => self.header("content-type", value),
            None => self,
        }
    }

    pub fn peer(mut self, ip: &str) -> Self {
        self.peer = Some(ip.to_string());
        self
    }

    pub fn without_client(mut self) -> Self {
        self.client = false;
        self
    }

    /// The request with a body that arrives only through the returned
    /// sender; dropping the sender ends it.
    pub fn build_streaming(mut self) -> (Request<Body>, tokio::sync::mpsc::Sender<Bytes>) {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Bytes>(4);
        let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
            let chunk = receiver.recv().await?;
            Some((Ok::<Bytes, std::io::Error>(chunk), receiver))
        });
        self.body = None;
        let mut request = self.build();
        *request.body_mut() = Body::from_stream(stream);
        (request, sender)
    }

    pub fn build(self) -> Request<Body> {
        let mut builder = Request::builder().method(self.method).uri(self.path);
        if self.client {
            builder = builder.header("x-keeman-client", "test/1.0.0");
        }
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        let mut request = builder
            .body(self.body.map(Body::from).unwrap_or_else(Body::empty))
            .unwrap();
        if let Some(ip) = self.peer {
            let peer = SocketAddr::new(ip.parse().unwrap(), 40000);
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        request
    }
}

async fn send_to(router: axum::Router, mut request: Request<Body>) -> TestResponse {
    if request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_none()
    {
        let peer: SocketAddr = format!("{PEER}:40000").parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    TestResponse {
        status,
        headers,
        body,
    }
}

pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl TestResponse {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// The problem `code`; also checks the problem shape.
    pub fn code(&self) -> String {
        assert_eq!(
            self.header("content-type").as_deref(),
            Some("application/problem+json"),
            "{}",
            self.text()
        );
        let body = self.json();
        assert_eq!(
            body["status"].as_u64(),
            Some(u64::from(self.status.as_u16()))
        );
        assert!(body["title"].is_string());
        assert!(
            body["instance"]
                .as_str()
                .is_some_and(|i| i.starts_with("urn:uuid:"))
        );
        body["code"].as_str().unwrap_or_default().to_string()
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_string)
            .collect()
    }

    pub fn cookie_value(&self, name: &str) -> Option<String> {
        self.set_cookies().iter().find_map(|c| {
            c.strip_prefix(&format!("{name}="))?
                .split(';')
                .next()
                .map(str::to_string)
        })
    }

    /// The first `errors[]` entry as (`pointer` or `parameter`, `detail`).
    pub fn field_error(&self) -> (String, String) {
        let error = &self.json()["errors"][0];
        let location = error["pointer"]
            .as_str()
            .or(error["parameter"].as_str())
            .unwrap_or("<none>")
            .to_string();
        (
            location,
            error["detail"].as_str().unwrap_or_default().to_string(),
        )
    }
}
