//! Migration 0005 rebuilds `objects` for the type `manifest`: existing rows,
//! indexes and the strict schema survive, and unknown types stay refused.
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

async fn indexes(pool: &SqlitePool) -> Vec<String> {
    let mut names: Vec<String> = sqlx::query("SELECT name FROM pragma_index_list('objects')")
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String, _>("name"))
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn objects_keep_their_rows_and_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool(&dir).await;
    MIGRATOR.run_to(4, &pool).await.unwrap();
    let before = indexes(&pool).await;
    exec(
        &pool,
        "INSERT INTO vaults (id, revision, key_version, created_by, created_at)
         VALUES ('v', 3, 1, 'u', '2026-10-27T00:00:00.000Z')",
    )
    .await
    .unwrap();
    for (id, kind, deleted) in [
        ("m", "vault_meta", 0),
        ("g", "group", 0),
        ("e", "entry", 1),
        ("i", "icon", 0),
    ] {
        exec(
            &pool,
            &format!(
                "INSERT INTO objects (vault_id, id, type, revision, key_version, deleted, size, updated_at, updated_by, data)
                 VALUES ('v', '{id}', '{kind}', 2, 1, {deleted}, 3, '2026-10-27T00:00:00.000Z', 'u', x'010203')"
            ),
        )
        .await
        .unwrap();
    }
    assert!(
        exec(
            &pool,
            "INSERT INTO objects (vault_id, id, type, revision, key_version, updated_at, updated_by)
             VALUES ('v', 'x', 'manifest', 2, 1, 'now', 'u')",
        )
        .await
        .is_err()
    );

    MIGRATOR.run(&pool).await.unwrap();

    let rows = sqlx::query(
        "SELECT id, type, revision, key_version, deleted, size, updated_by, data
         FROM objects ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 4);
    let first = &rows[0];
    assert_eq!(first.get::<String, _>("id"), "e");
    assert_eq!(first.get::<String, _>("type"), "entry");
    for (column, value) in [
        ("revision", 2),
        ("key_version", 1),
        ("deleted", 1),
        ("size", 3),
    ] {
        assert_eq!(first.get::<i64, _>(column), value, "{column}");
    }
    assert_eq!(first.get::<String, _>("updated_by"), "u");
    assert_eq!(first.get::<Vec<u8>, _>("data"), vec![1, 2, 3]);
    let kinds: Vec<String> = rows.iter().map(|r| r.get::<String, _>("type")).collect();
    assert_eq!(kinds, ["entry", "group", "icon", "vault_meta"]);
    assert_eq!(indexes(&pool).await, before);
    let columns: Vec<String> = sqlx::query("SELECT name FROM pragma_table_info('objects')")
        .fetch_all(&pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String, _>("name"))
        .collect();
    assert_eq!(columns.last().map(String::as_str), Some("data"));
    let strict: i64 = sqlx::query("SELECT strict FROM pragma_table_list WHERE name = 'objects'")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("strict");
    assert_eq!(strict, 1);

    exec(
        &pool,
        "INSERT INTO objects (vault_id, id, type, revision, key_version, updated_at, updated_by)
         VALUES ('v', 'x', 'manifest', 4, 1, 'now', 'u')",
    )
    .await
    .unwrap();
    assert!(
        exec(
            &pool,
            "INSERT INTO objects (vault_id, id, type, revision, key_version, updated_at, updated_by)
             VALUES ('v', 'y', 'note', 4, 1, 'now', 'u')",
        )
        .await
        .is_err()
    );
    // The foreign key to the vault still cascades.
    exec(&pool, "DELETE FROM vaults WHERE id = 'v'")
        .await
        .unwrap();
    let left: i64 = sqlx::query("SELECT COUNT(*) AS n FROM objects")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(left, 0);
}
