use sqlx::SqliteExecutor;

pub async fn insert<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    code_hash: &[u8],
    note: Option<&str>,
    now: &str,
    expires_at: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO invites (id, code_hash, note, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        id,
        code_hash,
        note,
        now,
        expires_at
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub struct InviteRow {
    pub id: String,
    pub expires_at: String,
    pub used_by: Option<String>,
    pub used_at: Option<String>,
}

pub async fn by_hash<'e>(
    ex: impl SqliteExecutor<'e>,
    code_hash: &[u8],
) -> Result<Option<InviteRow>, sqlx::Error> {
    sqlx::query_as!(
        InviteRow,
        r#"SELECT id AS "id!", expires_at, used_by, used_at FROM invites WHERE code_hash = ?"#,
        code_hash
    )
    .fetch_optional(ex)
    .await
}

/// Marks an unused, unexpired invite as used; returns the number of rows.
pub async fn consume<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    user_id: &str,
    now: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE invites SET used_by = ?, used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?",
        user_id,
        now,
        id,
        now
    )
    .execute(ex)
    .await?;
    Ok(result.rows_affected())
}

pub struct InviteListRow {
    pub id: String,
    pub note: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub used_at: Option<String>,
}

pub async fn list<'e>(ex: impl SqliteExecutor<'e>) -> Result<Vec<InviteListRow>, sqlx::Error> {
    sqlx::query_as!(InviteListRow, r#"SELECT id AS "id!", note, created_at, expires_at, used_at FROM invites ORDER BY created_at"#)
        .fetch_all(ex)
        .await
}

/// Deletes an unused invite; used ones stay for auditing.
pub async fn revoke_unused<'e>(ex: impl SqliteExecutor<'e>, id: &str) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query!("DELETE FROM invites WHERE id = ? AND used_at IS NULL", id)
            .execute(ex)
            .await?
            .rows_affected(),
    )
}
