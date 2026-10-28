//! Staged key rotations: objects are collected in
//! `rotation_objects` and swapped in at the commit with one statement.

use super::Conn;

pub struct Rotation {
    pub id: String,
    pub vault_id: String,
    pub base_revision: i64,
    pub new_key_version: i64,
    pub created_by: String,
    pub expires_at: String,
    /// JSON list of the accounts the rotation is to remove.
    pub remove_user_ids: String,
}

/// Opens a rotation; an older open rotation of the vault is discarded.
pub async fn replace(conn: &mut Conn, r: &Rotation) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM rotations WHERE vault_id = ?", r.vault_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query!(
        "INSERT INTO rotations (id, vault_id, base_revision, new_key_version, created_by, expires_at,
                                remove_user_ids)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        r.id,
        r.vault_id,
        r.base_revision,
        r.new_key_version,
        r.created_by,
        r.expires_at,
        r.remove_user_ids
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Whether an open rotation of the vault is to remove the account.
pub async fn removes(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!: i64" FROM rotations r
           WHERE r.vault_id = ? AND r.expires_at > ?
             AND EXISTS (SELECT 1 FROM json_each(r.remove_user_ids) WHERE value = ?)"#,
        vault_id,
        now,
        user_id
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(found.is_some())
}

pub async fn get(conn: &mut Conn, id: &str) -> Result<Option<Rotation>, sqlx::Error> {
    sqlx::query_as!(
        Rotation,
        r#"SELECT id AS "id!", vault_id, base_revision, new_key_version, created_by, expires_at,
                  remove_user_ids
           FROM rotations WHERE id = ?"#,
        id
    )
    .fetch_optional(&mut *conn)
    .await
}

/// Stores a re-encrypted object; uploading it again replaces it.
pub async fn upsert_object(
    conn: &mut Conn,
    rotation_id: &str,
    id: &str,
    kind: &str,
    data: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO rotation_objects (rotation_id, id, type, data) VALUES (?, ?, ?, ?)
         ON CONFLICT (rotation_id, id) DO UPDATE SET type = excluded.type, data = excluded.data",
        rotation_id,
        id,
        kind,
        data
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Lengths of objects already staged in this rotation (`ids`: JSON array);
/// `length()` of a BLOB does not read its content.
pub async fn staged_lengths(
    conn: &mut Conn,
    rotation_id: &str,
    ids: &str,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", length(data) AS "len!: i64" FROM rotation_objects
           WHERE rotation_id = ? AND id IN (SELECT value FROM json_each(?))"#,
        rotation_id,
        ids
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(|r| (r.id, r.len)).collect())
}

/// Changes the excess of staged objects over the objects they replace.
pub async fn add_excess(conn: &mut Conn, rotation_id: &str, delta: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE rotations SET staged_excess = MAX(0, staged_excess + ?) WHERE id = ?",
        delta,
        rotation_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Live objects that are neither dropped (`dropped`, a JSON array of IDs)
/// nor uploaded with their type.
pub async fn missing_count(
    conn: &mut Conn,
    rotation_id: &str,
    vault_id: &str,
    dropped: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!: i64" FROM objects o
           WHERE o.vault_id = ? AND o.deleted = 0
             AND o.id NOT IN (SELECT value FROM json_each(?))
             AND NOT EXISTS (SELECT 1 FROM rotation_objects r
                             WHERE r.rotation_id = ? AND r.id = o.id AND r.type = o.type)"#,
        vault_id,
        dropped,
        rotation_id
    )
    .fetch_one(&mut *conn)
    .await
}

pub struct Applied<'a> {
    pub rotation_id: &'a str,
    pub vault_id: &'a str,
    pub revision: i64,
    pub key_version: i64,
    pub user_id: &'a str,
    pub now: &'a str,
}

/// Swaps in the uploaded objects in one statement, so large vaults never
/// pass through the memory of the server.
pub async fn apply_objects(conn: &mut Conn, a: &Applied<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE objects SET
           data = (SELECT r.data FROM rotation_objects r WHERE r.rotation_id = ? AND r.id = objects.id),
           size = (SELECT length(r.data) FROM rotation_objects r WHERE r.rotation_id = ? AND r.id = objects.id),
           key_version = ?, revision = ?, updated_at = ?, updated_by = ?
         WHERE vault_id = ? AND deleted = 0
           AND id IN (SELECT id FROM rotation_objects WHERE rotation_id = ?)",
        a.rotation_id,
        a.rotation_id,
        a.key_version,
        a.revision,
        a.now,
        a.user_id,
        a.vault_id,
        a.rotation_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Removes tombstones up to the base revision and raises the horizon:
/// they carry the old key version.
pub async fn purge_tombstones_upto(
    conn: &mut Conn,
    vault_id: &str,
    base_revision: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM objects WHERE vault_id = ? AND deleted = 1 AND revision <= ?",
        vault_id,
        base_revision
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query!(
        "UPDATE vaults SET tombstone_horizon = MAX(tombstone_horizon, ?) WHERE id = ?",
        base_revision,
        vault_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// New revision and key version; the rotation is no longer required.
pub async fn set_rotated(
    conn: &mut Conn,
    vault_id: &str,
    revision: i64,
    key_version: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE vaults SET revision = ?, key_version = ?, rotation_required = 0 WHERE id = ?",
        revision,
        key_version,
        vault_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn delete(conn: &mut Conn, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM rotations WHERE id = ?", id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
