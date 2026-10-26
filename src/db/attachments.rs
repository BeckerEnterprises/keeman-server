use super::Conn;

pub struct Attachment {
    pub id: String,
    pub vault_id: String,
    pub entry_id: String,
    pub size: i64,
    pub parts: i64,
    pub state: String,
    /// Random per created row: tells an attachment recreated with the same
    /// ID from the one a request saw before.
    pub generation: String,
}

impl Attachment {
    pub fn complete(&self) -> bool {
        self.state == "complete"
    }
}

pub async fn get(conn: &mut Conn, id: &str) -> Result<Option<Attachment>, sqlx::Error> {
    sqlx::query_as!(
        Attachment,
        r#"SELECT id AS "id!", vault_id, entry_id, size, parts, state, generation FROM attachments WHERE id = ?"#,
        id
    )
    .fetch_optional(&mut *conn)
    .await
}

pub struct NewAttachment<'a> {
    pub id: &'a str,
    pub vault_id: &'a str,
    pub entry_id: &'a str,
    pub size: i64,
    pub parts: i64,
    pub created_by: &'a str,
    pub now: &'a str,
    pub generation: &'a str,
}

pub async fn insert(conn: &mut Conn, a: &NewAttachment<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO attachments (id, vault_id, entry_id, size, parts, state, created_by, created_at, generation)
         VALUES (?, ?, ?, ?, ?, 'uploading', ?, ?, ?)",
        a.id,
        a.vault_id,
        a.entry_id,
        a.size,
        a.parts,
        a.created_by,
        a.now,
        a.generation
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Marks an upload complete; false if it was not uploading any more.
pub async fn complete(conn: &mut Conn, id: &str, now: &str) -> Result<bool, sqlx::Error> {
    let done = sqlx::query!(
        "UPDATE attachments SET state = 'complete', completed_at = ? WHERE id = ? AND state = 'uploading'",
        now,
        id
    )
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn delete(conn: &mut Conn, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM attachments WHERE id = ?", id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Assigns the attachment to another vault and entry (`transfer`).
pub async fn transfer(
    conn: &mut Conn,
    id: &str,
    vault_id: &str,
    entry_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE attachments SET vault_id = ?, entry_id = ? WHERE id = ?",
        vault_id,
        entry_id,
        id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Deletes the attachments of these entries (`ids` is a JSON array) and
/// returns their IDs, so their files can go after the commit.
pub async fn delete_for_entries(
    conn: &mut Conn,
    vault_id: &str,
    entry_ids: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"DELETE FROM attachments
           WHERE vault_id = ? AND entry_id IN (SELECT value FROM json_each(?))
           RETURNING id AS "id!""#,
        vault_id,
        entry_ids
    )
    .fetch_all(&mut *conn)
    .await
}

/// IDs of all attachments of a vault; the rows go with the vault (cascade).
pub async fn ids_of_vault(conn: &mut Conn, vault_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM attachments WHERE vault_id = ?"#,
        vault_id
    )
    .fetch_all(&mut *conn)
    .await
}

/// Deletes uploads started before `cutoff` that never completed.
pub async fn delete_stale_uploads(
    conn: &mut Conn,
    cutoff: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"DELETE FROM attachments WHERE state = 'uploading' AND created_at < ?
           RETURNING id AS "id!""#,
        cutoff
    )
    .fetch_all(&mut *conn)
    .await
}

/// IDs by state, for the report on orphaned files.
pub async fn ids_in_state(conn: &mut Conn, state: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM attachments WHERE state = ?"#,
        state
    )
    .fetch_all(&mut *conn)
    .await
}
