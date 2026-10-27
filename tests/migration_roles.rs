//! Migration 0006 adds the signing key of accounts and the roles chain:
//! existing accounts keep their rows without a key, statements go with
//! their vault.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use keeman_server::db::MIGRATOR;
use sqlx::Row;
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

const NOW: &str = "2026-10-27T00:00:00.000Z";

#[tokio::test]
async fn accounts_keep_their_rows_and_chains_go_with_their_vault() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    MIGRATOR.run_to(5, &pool).await.unwrap();
    exec(
        &pool,
        &format!(
            "INSERT INTO users (id, email, kdf_params, kdf_salt, auth_hash, user_key_wrapped, public_key,
                private_key_wrapped, user_data, recovery_auth_hash, user_key_recovery_wrapped, created_at, updated_at)
             VALUES ('u', 'u@example.org', '{{}}', x'00', 'h', x'01', x'02', x'03', x'04', 'r', x'05', '{NOW}', '{NOW}')"
        ),
    )
    .await
    .unwrap();
    exec(
        &pool,
        &format!(
            "INSERT INTO vaults (id, revision, key_version, created_by, created_at)
             VALUES ('v', 1, 1, 'u', '{NOW}')"
        ),
    )
    .await
    .unwrap();

    MIGRATOR.run(&pool).await.unwrap();
    let row = sqlx::query("SELECT signing_public_key, public_key FROM users WHERE id = 'u'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<Option<Vec<u8>>, _>("signing_public_key"), None);
    assert_eq!(row.get::<Vec<u8>, _>("public_key"), vec![2]);

    let statement = |version: i64| {
        format!(
            "INSERT INTO vault_roles (vault_id, version, statement, signature, hash, created_at)
             VALUES ('v', {version}, x'7b7d', x'00', x'01', '{NOW}')"
        )
    };
    exec(&pool, &statement(1)).await.unwrap();
    assert!(
        exec(&pool, &statement(1)).await.is_err(),
        "one row per version"
    );
    assert!(
        exec(
            &pool,
            &format!(
                "INSERT INTO vault_roles (vault_id, version, statement, signature, hash, created_at)
                 VALUES ('w', 1, x'00', x'00', x'00', '{NOW}')"
            ),
        )
        .await
        .is_err(),
        "only for existing vaults"
    );
    assert!(
        exec(
            &pool,
            &format!(
                "INSERT INTO vault_roles (vault_id, version, statement, signature, hash, created_at)
                 VALUES ('v', 'two', x'00', x'00', x'00', '{NOW}')"
            ),
        )
        .await
        .is_err(),
        "strict types"
    );
    exec(&pool, "DELETE FROM vaults WHERE id = 'v'")
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_roles")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}
