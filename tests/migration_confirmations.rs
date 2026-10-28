//! Migration 0008 replaces the pairings by confirmation requests: the old
//! table goes away with its rows, and a request goes with its account and
//! its session, one per session.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use keeman_server::db::MIGRATOR;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

async fn pool(dir: &tempfile::TempDir) -> SqlitePool {
    let options = SqliteConnectOptions::new()
        .filename(dir.path().join("keeman.db"))
        .create_if_missing(true)
        .foreign_keys(true);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap()
}

async fn exec(pool: &SqlitePool, statement: &str) -> Result<(), sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(statement.to_string()))
        .execute(pool)
        .await
        .map(|_| ())
}

async fn count(pool: &SqlitePool, table: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn table_exists(pool: &SqlitePool, name: &str) -> bool {
    let found: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(name)
            .fetch_one(pool)
            .await
            .unwrap();
    found == 1
}

const NOW: &str = "2026-10-28T00:00:00.000Z";

async fn user(pool: &SqlitePool, id: &str) {
    exec(
        pool,
        &format!(
            "INSERT INTO users (id, email, kdf_params, kdf_salt, auth_hash, user_key_wrapped, public_key,
                private_key_wrapped, user_data, recovery_auth_hash, user_key_recovery_wrapped, created_at, updated_at)
             VALUES ('{id}', '{id}@example.org', '{{}}', x'00', 'h', x'01', x'02', x'03', x'04', 'r', x'05', '{NOW}', '{NOW}')"
        ),
    )
    .await
    .unwrap();
}

async fn session(pool: &SqlitePool, id: &str, user_id: &str) {
    exec(
        pool,
        &format!(
            "INSERT INTO sessions (id, user_id, device_name, client_type, refresh_expires_at, created_at, last_seen_at)
             VALUES ('{id}', '{user_id}', 'Test device', 'cli', '{NOW}', '{NOW}', '{NOW}')"
        ),
    )
    .await
    .unwrap();
}

fn request(id: &str, user_id: &str, session_id: &str) -> String {
    format!(
        "INSERT INTO confirmations (id, user_id, session_id, nonce, created_at, expires_at)
         VALUES ('{id}', '{user_id}', '{session_id}', x'00', '{NOW}', '{NOW}')"
    )
}

#[tokio::test]
async fn pairings_give_way_to_confirmation_requests() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    MIGRATOR.run_to(7, &pool).await.unwrap();
    user(&pool, "u").await;
    user(&pool, "w").await;
    exec(
        &pool,
        &format!("INSERT INTO pairings VALUES ('u', x'01', '{NOW}', '{NOW}')"),
    )
    .await
    .unwrap();

    MIGRATOR.run(&pool).await.unwrap();
    assert!(!table_exists(&pool, "pairings").await);
    assert_eq!(count(&pool, "users").await, 2);
    assert_eq!(count(&pool, "confirmations").await, 0);

    session(&pool, "s1", "u").await;
    session(&pool, "s2", "u").await;
    session(&pool, "s3", "w").await;
    exec(&pool, &request("r1", "u", "s1")).await.unwrap();
    exec(&pool, &request("r2", "u", "s2")).await.unwrap();
    exec(&pool, &request("r3", "w", "s3")).await.unwrap();
    // One request per session, and only for an existing one.
    assert!(exec(&pool, &request("r4", "u", "s1")).await.is_err());
    assert!(exec(&pool, &request("r5", "u", "nobody")).await.is_err());

    exec(&pool, "DELETE FROM sessions WHERE id = 's1'")
        .await
        .unwrap();
    assert_eq!(count(&pool, "confirmations").await, 2);
    exec(&pool, "DELETE FROM users WHERE id = 'u'")
        .await
        .unwrap();
    assert_eq!(count(&pool, "confirmations").await, 1);
}
