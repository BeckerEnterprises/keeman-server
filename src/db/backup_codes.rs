use sqlx::SqliteExecutor;

use super::Conn;

/// Replaces all backup codes of an account with new hashes.
pub async fn replace(conn: &mut Conn, user_id: &str, hashes: &[String]) -> Result<(), sqlx::Error> {
    delete_all(&mut *conn, user_id).await?;
    for hash in hashes {
        sqlx::query!(
            "INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)",
            user_id,
            hash
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

pub struct UnusedCode {
    pub id: i64,
    pub code_hash: String,
}

pub async fn unused<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
) -> Result<Vec<UnusedCode>, sqlx::Error> {
    sqlx::query_as!(
        UnusedCode,
        r#"SELECT id AS "id!", code_hash FROM backup_codes WHERE user_id = ? AND used_at IS NULL ORDER BY id"#,
        user_id
    )
    .fetch_all(ex)
    .await
}

/// Marks a code as used; returns whether it was still unused, so of two
/// concurrent requests with the same code only one succeeds.
pub async fn mark_used<'e>(
    ex: impl SqliteExecutor<'e>,
    id: i64,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE backup_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
        now,
        id
    )
    .execute(ex)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn remaining<'e>(ex: impl SqliteExecutor<'e>, user_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!: i64" FROM backup_codes WHERE user_id = ? AND used_at IS NULL"#,
        user_id
    )
    .fetch_one(ex)
    .await
}

pub async fn delete_all<'e>(ex: impl SqliteExecutor<'e>, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM backup_codes WHERE user_id = ?", user_id)
        .execute(ex)
        .await?;
    Ok(())
}
