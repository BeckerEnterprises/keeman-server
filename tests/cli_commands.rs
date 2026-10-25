//! The `keeman-server` binary: `init`, `invite`, `user`, `migrate` and the
//! startup refusals of the configuration.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use axum::http::StatusCode;
use keeman_server::config::Config;
use support::{Req, TestApp};

fn binary(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_keeman-server"));
    command.env_clear().current_dir(dir).args(args);
    command
}

fn run(dir: &Path, args: &[&str]) -> Output {
    binary(dir, args).output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A directory with `init --dev` already run.
fn initialised() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let output = run(dir.path(), &["init", "--dev"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let config = dir.path().join("config.toml");
    (dir, config)
}

#[test]
fn prints_version() {
    let output = run(Path::new("."), &["--version"]);
    assert!(output.status.success());
    assert_eq!(
        stdout(&output).trim(),
        concat!("keeman-server ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn init_creates_private_files_and_never_overwrites() {
    let (dir, config) = initialised();
    let secret = dir.path().join("server_secret");
    let data = dir.path().join("data");
    assert_eq!(mode(&config), 0o600);
    assert_eq!(mode(&secret), 0o600);
    assert_eq!(mode(&data), 0o700);
    assert_eq!(mode(&data.join("attachments")), 0o700);
    assert_eq!(mode(&data.join("uploads")), 0o700);
    assert_eq!(std::fs::read(&secret).unwrap().len(), 32);
    assert!(
        !data.join("keeman.sqlite").exists(),
        "init creates no database"
    );

    let loaded = Config::load(&config, &[]).unwrap();
    assert_eq!(loaded.server.allowed_origins, ["http://localhost:5173"]);
    assert_eq!(loaded.webauthn.rp_id, "localhost");
    assert!(!loaded.security.dev_mode);
    loaded.check_permissions(&config).unwrap();

    let before = std::fs::read(&secret).unwrap();
    let output = run(dir.path(), &["init"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("never overwrites"));
    assert_eq!(std::fs::read(&secret).unwrap(), before);
}

#[test]
fn init_for_production() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("api/config.toml");
    std::fs::create_dir(dir.path().join("api")).unwrap();
    let data = dir.path().join("data");
    let output = run(
        dir.path(),
        &[
            "init",
            "--config",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let loaded = Config::load(&config, &[]).unwrap();
    assert_eq!(loaded.server.allowed_origins, ["https://app.example.org"]);
    assert_eq!(loaded.webauthn.rp_id, "app.example.org");
    assert_eq!(loaded.storage.data_dir, data);
    assert_eq!(
        loaded.security.server_secret_file,
        Some(dir.path().join("api/server_secret"))
    );
    assert_eq!(mode(&data), 0o700);
}

#[test]
fn migrate_creates_a_private_database() {
    let (dir, _) = initialised();
    let output = run(dir.path(), &["migrate"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(mode(&dir.path().join("data/keeman.sqlite")), 0o600);
    // Idempotent.
    assert!(run(dir.path(), &["migrate"]).status.success());
}

#[test]
fn refuses_to_start_with_unsafe_configuration() {
    type Breaker = Box<dyn Fn(&Path)>;
    let cases: Vec<(&str, Breaker, &str)> = vec![
        (
            "config readable by others",
            Box::new(|d: &Path| chmod(&d.join("config.toml"), 0o644)),
            "config file",
        ),
        (
            "data_dir open for the group",
            Box::new(|d: &Path| chmod(&d.join("data"), 0o750)),
            "data_dir",
        ),
        (
            "attachment directory open for others",
            Box::new(|d: &Path| chmod(&d.join("data/uploads"), 0o705)),
            "attachment directory",
        ),
        (
            "secret readable",
            Box::new(|d: &Path| chmod(&d.join("server_secret"), 0o640)),
            "server_secret_file",
        ),
        (
            "short secret",
            Box::new(|d: &Path| std::fs::write(d.join("server_secret"), [1u8; 31]).unwrap()),
            "32 bytes",
        ),
        (
            "unknown key",
            Box::new(|d: &Path| append(d, "[extra]\nkey = 1\n")),
            "invalid configuration",
        ),
        (
            "unknown key in a section",
            Box::new(|d: &Path| {
                replace(
                    d,
                    "client_ip_header = \"X-Forwarded-For\"",
                    "client_ip_header = \"X-Forwarded-For\"\nport = 1",
                )
            }),
            "unknown field",
        ),
        (
            "origin with path",
            Box::new(|d: &Path| {
                replace(
                    d,
                    "\"http://localhost:5173\"]",
                    "\"http://localhost:5173/app\"]",
                )
            }),
            "not an origin",
        ),
        (
            "plain http",
            Box::new(|d: &Path| {
                replace(
                    d,
                    "allowed_origins = [\"http://localhost:5173\"]",
                    "allowed_origins = [\"http://my.example\"]",
                )
            }),
            "https",
        ),
        (
            "dev_mode with a public origin",
            Box::new(|d: &Path| {
                replace(d, "dev_mode = false", "dev_mode = true");
                replace(
                    d,
                    "allowed_origins = [\"http://localhost:5173\"]",
                    "allowed_origins = [\"https://app.example.org\"]",
                );
            }),
            "dev_mode",
        ),
        (
            "rp_id is an IP address",
            Box::new(|d: &Path| {
                replace(d, "rp_id = \"localhost\"", "rp_id = \"127.0.0.1\"");
                replace(
                    d,
                    "rp_origins = [\"http://localhost:5173\"]",
                    "rp_origins = [\"http://127.0.0.1:5173\"]",
                );
            }),
            "domain name",
        ),
        (
            "rp_id mismatch",
            Box::new(|d: &Path| replace(d, "rp_id = \"localhost\"", "rp_id = \"example.org\"")),
            "rp_id",
        ),
        (
            "account limit zero",
            Box::new(|d: &Path| replace(d, "account_per_min = 1200", "account_per_min = 0")),
            "rate_limits must all be positive",
        ),
        (
            "large-body budget below the largest body",
            Box::new(|d: &Path| {
                replace(
                    d,
                    "large_body_budget_bytes = 134217728",
                    "large_body_budget_bytes = 1048576",
                )
            }),
            "large_body_budget_bytes",
        ),
        (
            "no large requests per account",
            Box::new(|d: &Path| {
                replace(
                    d,
                    "large_requests_per_account = 4",
                    "large_requests_per_account = 0",
                )
            }),
            "large_requests_per_account",
        ),
        (
            "token lifetime",
            Box::new(|d: &Path| {
                replace(
                    d,
                    "access_token_ttl_minutes = 15",
                    "access_token_ttl_minutes = 61",
                )
            }),
            "1-60",
        ),
    ];
    for (name, break_it, message) in cases {
        let (dir, _) = initialised();
        break_it(dir.path());
        let output = run(dir.path(), &["migrate"]);
        assert!(!output.status.success(), "{name}");
        assert!(
            stderr(&output).contains(message),
            "{name}: {}",
            stderr(&output)
        );
        assert!(!dir.path().join("data/keeman.sqlite").exists(), "{name}");
    }

    // An existing database readable by others.
    let (dir, _) = initialised();
    assert!(run(dir.path(), &["migrate"]).status.success());
    chmod(&dir.path().join("data/keeman.sqlite"), 0o644);
    let output = run(dir.path(), &["migrate"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("database"), "{}", stderr(&output));

    // Secret as file and environment variable at once.
    let (dir, _) = initialised();
    let output = binary(dir.path(), &["migrate"])
        .env("KEEMAN_SERVER_SECRET", "A".repeat(43))
        .output()
        .unwrap();
    assert!(stderr(&output).contains("both"), "{}", stderr(&output));
    // Unknown and invalid overrides.
    let output = binary(dir.path(), &["migrate"])
        .env("KEEMAN__SERVER__NOPE", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let output = binary(dir.path(), &["migrate"])
        .env("KEEMAN__SERVER__LISTEN", "nowhere")
        .output()
        .unwrap();
    assert!(
        stderr(&output).contains("server.listen"),
        "{}",
        stderr(&output)
    );
}

fn append(dir: &Path, text: &str) {
    let path = dir.join("config.toml");
    let content = std::fs::read_to_string(&path).unwrap() + text;
    std::fs::write(&path, content).unwrap();
}

fn replace(dir: &Path, from: &str, to: &str) {
    let path = dir.join("config.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains(from), "{from}");
    std::fs::write(&path, content.replace(from, to)).unwrap();
}

#[tokio::test]
async fn invite_commands() {
    let (dir, config) = initialised();
    let output = run(
        dir.path(),
        &["invite", "create", "--expires", "2d", "--note", "for Alice"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let code = stdout(&output);
    assert_eq!(code.trim().len(), 43, "stdout contains only the code");
    assert_eq!(code.lines().count(), 1);

    assert!(
        !run(dir.path(), &["invite", "create", "--expires", "400d"])
            .status
            .success()
    );
    assert!(
        !run(
            dir.path(),
            &["invite", "create", "--note", &"x".repeat(201)]
        )
        .status
        .success()
    );

    let list = stdout(&run(dir.path(), &["invite", "list"]));
    assert!(
        list.contains("\tunused\t") && list.contains("for Alice"),
        "{list}"
    );
    assert!(!list.contains(code.trim()), "the list never shows codes");

    // The code works for registration against the same database.
    let t = TestApp::with(
        Config::load(&config, &[]).unwrap(),
        tempfile::tempdir().unwrap(),
    )
    .await;
    let account = support::Account::new("alice@example.com");
    let response = t
        .call(Req::post("/v1/auth/register").json(&account.register_body(Some(code.trim()))))
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    let list = stdout(&run(dir.path(), &["invite", "list"]));
    assert!(list.contains("\tused\t"), "{list}");

    let id = list
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .next()
        .unwrap()
        .to_string();
    let output = run(dir.path(), &["invite", "revoke", &id]);
    assert!(!output.status.success(), "used invites stay");
    let fresh = run(dir.path(), &["invite", "create"]);
    assert!(fresh.status.success());
    let list = stdout(&run(dir.path(), &["invite", "list"]));
    let unused = list
        .lines()
        .find(|l| l.contains("\tunused\t"))
        .unwrap()
        .split('\t')
        .next()
        .unwrap()
        .to_string();
    assert!(
        run(dir.path(), &["invite", "revoke", &unused])
            .status
            .success()
    );
    assert!(!stdout(&run(dir.path(), &["invite", "list"])).contains("\tunused\t"));
    let events = t.security_events().await;
    assert_eq!(events.iter().filter(|e| *e == "invite_created").count(), 2);
    assert_eq!(events.iter().filter(|e| *e == "invite_revoked").count(), 1);
}

#[tokio::test]
async fn user_commands() {
    let (dir, config) = initialised();
    let t = TestApp::with(
        Config::load(&config, &[]).unwrap(),
        tempfile::tempdir().unwrap(),
    )
    .await;
    let alice = t.register("alice@example.com").await;

    let list = stdout(&run(dir.path(), &["user", "list"]));
    assert!(
        list.contains("alice@example.com\t2026-10-23T08:00:00.000Z\tnone\t-\tactive"),
        "{list}"
    );

    for _ in 0..2 {
        let output = run(dir.path(), &["user", "disable", " Alice@Example.com"]);
        assert!(output.status.success(), "{}", stderr(&output));
    }
    assert_eq!(
        t.call(Req::get("/v1/me").token(&alice.access_token))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&support::unique_ip()),
        )
        .await;
    assert_eq!(response.code(), "account_disabled");
    assert!(stdout(&run(dir.path(), &["user", "list"])).contains("\tdisabled"));

    assert!(
        run(dir.path(), &["user", "enable", "alice@example.com"])
            .status
            .success()
    );
    let response = t
        .call(
            Req::post("/v1/auth/login")
                .json(&alice.login_body())
                .peer(&support::unique_ip()),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(
        !run(dir.path(), &["user", "disable", "nobody@example.com"])
            .status
            .success()
    );
    let events = t.security_events().await;
    assert!(
        events.contains(&"user_disabled".to_string())
            && events.contains(&"user_enabled".to_string())
    );
    assert_eq!(t.count("SELECT COUNT(*) FROM security_log WHERE event = 'session_revoked' AND detail LIKE '%admin%'").await, 1);
}

#[tokio::test]
async fn reset_two_factor_removes_all_factors_and_keeps_sessions() {
    let (dir, config) = initialised();
    let t = TestApp::with(
        Config::load(&config, &[]).unwrap(),
        tempfile::tempdir().unwrap(),
    )
    .await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    t.enable_totp(&alice).await;
    t.enable_totp(&bob).await;
    t.sql(&format!(
        "INSERT INTO webauthn_credentials (id, user_id, credential_id, passkey, name, created_at)
         VALUES ('{}', '{}', X'01', '{{}}', 'Key', '2026-10-23T08:00:00.000Z')",
        support::new_uuid(),
        alice.user_id
    ))
    .await;
    let challenge = t.login_challenge(&alice).await;
    let list = stdout(&run(dir.path(), &["user", "list"]));
    assert!(
        list.contains("alice@example.com\t2026-10-23T08:00:00.000Z\ttotp,passkeys:1"),
        "{list}"
    );

    for _ in 0..2 {
        let output = run(dir.path(), &["user", "reset-2fa", " Alice@Example.com "]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).contains("alice@example.com"));
    }
    let me = t.call(Req::get("/v1/me").token(&alice.access_token)).await;
    assert_eq!(me.status, StatusCode::OK, "sessions stay");
    assert_eq!(
        me.json()["two_factor"],
        serde_json::json!({ "totp": false, "webauthn_credentials": 0, "backup_codes_remaining": 0 })
    );
    assert_eq!(
        t.count(&format!(
            "SELECT COUNT(*) FROM challenges WHERE user_id = '{}'
               AND purpose IN ('login', 'recovery', 'totp_setup', 'webauthn_register')",
            alice.user_id
        ))
        .await,
        0,
        "open second-factor steps are gone"
    );
    let response = t
        .call(
            Req::post("/v1/auth/2fa/totp")
                .json(&serde_json::json!({ "challenge_token": challenge, "code": "123456" }))
                .peer(&support::unique_ip()),
        )
        .await;
    assert_eq!(response.code(), "challenge_invalid");
    // Login works without second factor; the other account is untouched.
    assert_eq!(t.login(&alice).await.access_token.len(), 43);
    let me = t.call(Req::get("/v1/me").token(&bob.access_token)).await;
    assert_eq!(me.json()["two_factor"]["totp"], true);
    assert_eq!(me.json()["two_factor"]["backup_codes_remaining"], 10);

    let output = run(dir.path(), &["user", "reset-2fa", "nobody@example.com"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("no account"));
    assert_eq!(
        t.count("SELECT COUNT(*) FROM security_log WHERE event = 'two_factor_reset'")
            .await,
        2
    );
}
