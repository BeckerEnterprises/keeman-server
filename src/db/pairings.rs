//! Pairings: one envelope per account, valid until `expires_at`.

use sqlx::SqliteExecutor;

use super::Conn;

pub struct Pairing {
    pub payload: Vec<u8>,
    pub expires_at: String,
}

/// Stores the pairing of an account, replacing an existing one.
pub async fn put(
    conn: &mut Conn,
    user_id: &str,
    payload: &[u8],
    now: &str,
    expires_at: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO pairings (user_id, payload, created_at, expires_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (user_id) DO UPDATE SET
           payload = excluded.payload, created_at = excluded.created_at,
           expires_at = excluded.expires_at",
        user_id,
        payload,
        now,
        expires_at
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The pairing of an account, unless it has expired.
pub async fn get<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
    now: &str,
) -> Result<Option<Pairing>, sqlx::Error> {
    sqlx::query_as!(
        Pairing,
        "SELECT payload, expires_at FROM pairings WHERE user_id = ? AND expires_at > ?",
        user_id,
        now
    )
    .fetch_optional(ex)
    .await
}

pub async fn delete(conn: &mut Conn, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM pairings WHERE user_id = ?", user_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
