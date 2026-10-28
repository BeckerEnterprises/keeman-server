//! Confirmation requests: one per session, valid until `expires_at`, with at
//! most one answer. Requests of sessions that are no longer active count as
//! gone.

use sqlx::SqliteExecutor;

use super::Conn;

pub struct NewRequest<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub session_id: &'a str,
    pub nonce: &'a [u8],
    pub now: &'a str,
    pub expires_at: &'a str,
}

/// Stores a request, replacing the one of the same session with its answer.
pub async fn replace(conn: &mut Conn, r: &NewRequest<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM confirmations WHERE session_id = ?",
        r.session_id
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query!(
        "INSERT INTO confirmations (id, user_id, session_id, nonce, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        r.id,
        r.user_id,
        r.session_id,
        r.nonce,
        r.now,
        r.expires_at
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// An open request as the account's sessions see it, without the answer.
pub struct Listed {
    pub id: String,
    pub session_id: String,
    pub device_name: String,
    pub client_type: String,
    pub created_at: String,
    pub expires_at: String,
    pub nonce: Vec<u8>,
    pub answered: bool,
}

/// The open requests of an account from active sessions, oldest first.
pub async fn list<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
    now: &str,
) -> Result<Vec<Listed>, sqlx::Error> {
    sqlx::query_as!(
        Listed,
        r#"SELECT c.id AS "id!", c.session_id, s.device_name, s.client_type, c.created_at,
                  c.expires_at, c.nonce, c.answer_statement IS NOT NULL AS "answered!: bool"
           FROM confirmations c JOIN sessions s ON s.id = c.session_id
           WHERE c.user_id = ? AND c.expires_at > ?
             AND s.revoked_at IS NULL AND s.refresh_expires_at > ?
           ORDER BY c.created_at, c.id"#,
        user_id,
        now,
        now
    )
    .fetch_all(ex)
    .await
}

/// A request with what an answer needs to be checked against.
pub struct Open {
    pub session_id: String,
    pub expires_at: String,
    pub nonce: Vec<u8>,
    pub answer_statement: Option<Vec<u8>>,
    pub answer_signature: Option<Vec<u8>>,
}

/// An open request of this account from an active session.
pub async fn open<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    user_id: &str,
    now: &str,
) -> Result<Option<Open>, sqlx::Error> {
    sqlx::query_as!(
        Open,
        r#"SELECT c.session_id, c.expires_at, c.nonce, c.answer_statement, c.answer_signature
           FROM confirmations c JOIN sessions s ON s.id = c.session_id
           WHERE c.id = ? AND c.user_id = ? AND c.expires_at > ?
             AND s.revoked_at IS NULL AND s.refresh_expires_at > ?"#,
        id,
        user_id,
        now,
        now
    )
    .fetch_optional(ex)
    .await
}

/// Stores the answer of a request that has none yet.
pub async fn answer(
    conn: &mut Conn,
    id: &str,
    statement: &[u8],
    signature: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE confirmations SET answer_statement = ?, answer_signature = ?
         WHERE id = ? AND answer_statement IS NULL",
        statement,
        signature,
        id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Deletes a request of this account; the number of rows deleted.
pub async fn delete(conn: &mut Conn, id: &str, user_id: &str) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query!(
        "DELETE FROM confirmations WHERE id = ? AND user_id = ?",
        id,
        user_id
    )
    .execute(&mut *conn)
    .await?
    .rows_affected())
}
