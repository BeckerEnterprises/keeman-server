//! Queries for `backup`, `restore` and `check`: migration state, snapshot,
//! integrity, counts and the attachment rows the maintenance commands
//! compare with the files.

use std::collections::BTreeSet;
use std::path::Path;
use std::str::FromStr;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, Row};

use super::{Conn, Db, MIGRATOR};

/// Accounts, vaults, objects (tombstones included) and complete attachments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub users: i64,
    pub vaults: i64,
    pub objects: i64,
    pub attachments: i64,
}

/// Opens a database file read-only on one plain connection, without WAL and
/// without creating it: for snapshots and restored files.
pub async fn open_file(path: &Path) -> Result<Conn, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?
        .read_only(true)
        .create_if_missing(false);
    Conn::connect_with(&options).await
}

/// Whether every migration of this binary is applied and no unknown one is.
pub async fn migrations_current(conn: &mut Conn) -> Result<bool, sqlx::Error> {
    let applied: BTreeSet<i64> = match sqlx::query_scalar!(
        r#"SELECT version AS "version!: i64" FROM _sqlx_migrations WHERE success = 1"#
    )
    .fetch_all(&mut *conn)
    .await
    {
        Ok(versions) => versions.into_iter().collect(),
        // A database without the table has never been migrated.
        Err(sqlx::Error::Database(error)) if error.message().contains("no such table") => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let expected: BTreeSet<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    Ok(applied == expected)
}

/// A consistent copy of the database at `target`, while the server runs.
/// `VACUUM INTO` has no form the query macros can describe.
pub async fn vacuum_into(db: &Db, target: &Path) -> Result<(), sqlx::Error> {
    sqlx::query("VACUUM INTO ?")
        .bind(target.to_string_lossy().into_owned())
        .execute(&db.read)
        .await?;
    Ok(())
}

/// The rows of `PRAGMA integrity_check`; a sound database answers `ok`.
pub async fn integrity_check(conn: &mut Conn) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_all(&mut *conn)
        .await
}

/// Violations of foreign keys, one line each.
pub async fn foreign_key_check(conn: &mut Conn) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let table: String = row.try_get(0).unwrap_or_default();
            let rowid: Option<i64> = row.try_get(1).unwrap_or_default();
            let parent: String = row.try_get(2).unwrap_or_default();
            format!(
                "{table} row {} refers to a missing {parent}",
                rowid.map_or_else(|| "?".to_string(), |r| r.to_string())
            )
        })
        .collect())
}

pub async fn counts(conn: &mut Conn) -> Result<Counts, sqlx::Error> {
    Ok(Counts {
        users: sqlx::query_scalar!(r#"SELECT COUNT(*) AS "n!: i64" FROM users"#)
            .fetch_one(&mut *conn)
            .await?,
        vaults: sqlx::query_scalar!(r#"SELECT COUNT(*) AS "n!: i64" FROM vaults"#)
            .fetch_one(&mut *conn)
            .await?,
        objects: sqlx::query_scalar!(r#"SELECT COUNT(*) AS "n!: i64" FROM objects"#)
            .fetch_one(&mut *conn)
            .await?,
        attachments: sqlx::query_scalar!(
            r#"SELECT COUNT(*) AS "n!: i64" FROM attachments WHERE state = 'complete'"#
        )
        .fetch_one(&mut *conn)
        .await?,
    })
}

/// Uploads still in progress that started before `before`.
pub async fn uploads_started_before(
    conn: &mut Conn,
    before: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM attachments WHERE state = 'uploading' AND created_at < ?"#,
        before
    )
    .fetch_all(&mut *conn)
    .await
}
