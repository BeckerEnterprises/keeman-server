//! Migration 0007 adds freshness attestations and pairings: existing rows
//! stay as they are, and the new rows go with their account and vault.
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

const NOW: &str = "2026-10-27T00:00:00.000Z";

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

#[tokio::test]
async fn new_rows_go_with_their_account_and_vault() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    MIGRATOR.run_to(6, &pool).await.unwrap();
    user(&pool, "u").await;
    user(&pool, "w").await;
    exec(
        &pool,
        &format!(
            "INSERT INTO vaults (id, revision, key_version, created_by, created_at)
             VALUES ('v', 1, 1, 'u', '{NOW}')"
        ),
    )
    .await
    .unwrap();

    MIGRATOR.run_to(7, &pool).await.unwrap();
    assert_eq!(count(&pool, "users").await, 2);
    assert_eq!(count(&pool, "vault_freshness").await, 0);
    for statement in [
        format!("INSERT INTO vault_freshness VALUES ('u', 'v', x'01', x'02', '{NOW}')"),
        format!("INSERT INTO vault_freshness VALUES ('w', 'v', x'01', x'02', '{NOW}')"),
        format!("INSERT INTO user_freshness VALUES ('u', x'01', x'02', '{NOW}')"),
        format!("INSERT INTO pairings VALUES ('u', x'01', '{NOW}', '{NOW}')"),
    ] {
        exec(&pool, &statement).await.unwrap();
    }
    // One row per account and vault, one per account.
    assert!(
        exec(
            &pool,
            &format!("INSERT INTO vault_freshness VALUES ('u', 'v', x'01', x'02', '{NOW}')")
        )
        .await
        .is_err()
    );
    assert!(
        exec(
            &pool,
            &format!("INSERT INTO pairings VALUES ('u', x'01', '{NOW}', '{NOW}')")
        )
        .await
        .is_err()
    );
    assert!(
        exec(
            &pool,
            &format!("INSERT INTO user_freshness VALUES ('nobody', x'01', x'02', '{NOW}')")
        )
        .await
        .is_err()
    );

    exec(&pool, "DELETE FROM vaults WHERE id = 'v'")
        .await
        .unwrap();
    assert_eq!(count(&pool, "vault_freshness").await, 0);
    exec(&pool, "DELETE FROM users WHERE id = 'u'")
        .await
        .unwrap();
    assert_eq!(count(&pool, "user_freshness").await, 0);
    assert_eq!(count(&pool, "pairings").await, 0);
    assert_eq!(count(&pool, "users").await, 1);
}
