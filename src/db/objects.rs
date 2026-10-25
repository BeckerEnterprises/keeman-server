use super::Conn;

pub struct NewObject<'a> {
    pub id: &'a str,
    pub kind: &'a str,
    pub revision: i64,
    pub key_version: i64,
    pub deleted: bool,
    pub data: Option<&'a [u8]>,
    pub user_id: &'a str,
    pub now: &'a str,
}

/// Inserts an object or replaces its content; the type never changes.
pub async fn upsert(conn: &mut Conn, vault_id: &str, o: &NewObject<'_>) -> Result<(), sqlx::Error> {
    let size = o
        .data
        .map_or(0, |d| i64::try_from(d.len()).unwrap_or(i64::MAX));
    sqlx::query!(
        "INSERT INTO objects (vault_id, id, type, revision, key_version, deleted, size, updated_at, updated_by, data)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (vault_id, id) DO UPDATE SET
           revision = excluded.revision, key_version = excluded.key_version,
           deleted = excluded.deleted, size = excluded.size, updated_at = excluded.updated_at,
           updated_by = excluded.updated_by, data = excluded.data",
        vault_id,
        o.id,
        o.kind,
        o.revision,
        o.key_version,
        o.deleted,
        size,
        o.now,
        o.user_id,
        o.data
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub struct Existing {
    pub id: String,
    pub kind: String,
    pub revision: i64,
    pub deleted: bool,
    /// Decoded size of the stored data, for the quota.
    pub size: i64,
}

/// The stored state of these objects; `ids` is a JSON array of IDs.
pub async fn existing(
    conn: &mut Conn,
    vault_id: &str,
    ids: &str,
) -> Result<Vec<Existing>, sqlx::Error> {
    sqlx::query_as!(
        Existing,
        r#"SELECT id AS "id!", type AS kind, revision, deleted AS "deleted: bool", size FROM objects
           WHERE vault_id = ? AND id IN (SELECT value FROM json_each(?))"#,
        vault_id,
        ids
    )
    .fetch_all(&mut *conn)
    .await
}

/// Where a page of `changes` starts.
pub struct PageStart<'a> {
    pub since: i64,
    /// Position of the last delivered object: `(revision, id)`.
    pub after_revision: i64,
    pub after_id: &'a str,
    /// `since = 0` delivers the full state without tombstones.
    pub with_tombstones: bool,
}

pub struct Meta {
    pub id: String,
    pub revision: i64,
    pub size: i64,
}

/// Position and size of the next objects, without their data.
pub async fn page_meta(
    conn: &mut Conn,
    vault_id: &str,
    start: &PageStart<'_>,
    limit: i64,
) -> Result<Vec<Meta>, sqlx::Error> {
    sqlx::query_as!(
        Meta,
        r#"SELECT id AS "id!", revision, size FROM objects
           WHERE vault_id = ? AND revision > ? AND (? OR deleted = 0) AND (revision, id) > (?, ?)
           ORDER BY revision, id LIMIT ?"#,
        vault_id,
        start.since,
        start.with_tombstones,
        start.after_revision,
        start.after_id,
        limit
    )
    .fetch_all(&mut *conn)
    .await
}

pub struct Changed {
    pub id: String,
    pub kind: String,
    pub revision: i64,
    pub key_version: i64,
    pub deleted: bool,
    pub data: Option<Vec<u8>>,
    pub updated_at: String,
    pub updated_by: String,
}

pub async fn page(
    conn: &mut Conn,
    vault_id: &str,
    start: &PageStart<'_>,
    limit: i64,
) -> Result<Vec<Changed>, sqlx::Error> {
    sqlx::query_as!(
        Changed,
        r#"SELECT id AS "id!", type AS kind, revision, key_version, deleted AS "deleted: bool",
             data, updated_at, updated_by FROM objects
           WHERE vault_id = ? AND revision > ? AND (? OR deleted = 0) AND (revision, id) > (?, ?)
           ORDER BY revision, id LIMIT ?"#,
        vault_id,
        start.since,
        start.with_tombstones,
        start.after_revision,
        start.after_id,
        limit
    )
    .fetch_all(&mut *conn)
    .await
}
