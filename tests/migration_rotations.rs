//! Migration 0009 gives each rotation the accounts it is to remove; a
//! rotation that was open before the update removes nobody.
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

#[tokio::test]
async fn open_rotations_remove_nobody_after_the_update() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    MIGRATOR.run_to(8, &pool).await.unwrap();
    user(&pool, "u").await;
    exec(
        &pool,
        &format!(
            "INSERT INTO vaults (id, revision, key_version, created_by, created_at)
             VALUES ('v', 1, 1, 'u', '{NOW}')"
        ),
    )
    .await
    .unwrap();
    exec(
        &pool,
        &format!(
            "INSERT INTO rotations (id, vault_id, base_revision, new_key_version, created_by, expires_at)
             VALUES ('r', 'v', 1, 2, 'u', '{NOW}')"
        ),
    )
    .await
    .unwrap();

    MIGRATOR.run(&pool).await.unwrap();
    let removed: String =
        sqlx::query_scalar("SELECT remove_user_ids FROM rotations WHERE id = 'r'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(removed, "[]");
    exec(
        &pool,
        &format!(
            "INSERT INTO rotations (id, vault_id, base_revision, new_key_version, created_by, expires_at, remove_user_ids)
             VALUES ('r2', 'v', 1, 2, 'u', '{NOW}', '[\"w\"]')"
        ),
    )
    .await
    .unwrap();
    // Not null: every rotation has a list, possibly empty.
    assert!(
        exec(
            &pool,
            "UPDATE rotations SET remove_user_ids = NULL WHERE id = 'r2'"
        )
        .await
        .is_err()
    );
}
