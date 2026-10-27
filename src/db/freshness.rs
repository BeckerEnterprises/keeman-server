//! Freshness attestations: the latest one of each account per vault and the
//! one for its user data. Only the account itself ever reads them back.

use sqlx::SqliteExecutor;

use super::Conn;

/// A stored attestation.
pub struct Stored {
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct NewAttestation<'a> {
    pub user_id: &'a str,
    pub statement: &'a [u8],
    pub signature: &'a [u8],
    pub now: &'a str,
}

/// Stores the attestation of an account for a vault, replacing its last one.
pub async fn put_vault(
    conn: &mut Conn,
    vault_id: &str,
    a: &NewAttestation<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO vault_freshness (user_id, vault_id, statement, signature, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (user_id, vault_id) DO UPDATE SET
           statement = excluded.statement, signature = excluded.signature,
           updated_at = excluded.updated_at",
        a.user_id,
        vault_id,
        a.statement,
        a.signature,
        a.now
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Stores the attestation of an account for its user data.
pub async fn put_user(conn: &mut Conn, a: &NewAttestation<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO user_freshness (user_id, statement, signature, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (user_id) DO UPDATE SET
           statement = excluded.statement, signature = excluded.signature,
           updated_at = excluded.updated_at",
        a.user_id,
        a.statement,
        a.signature,
        a.now
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn user<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
) -> Result<Option<Stored>, sqlx::Error> {
    sqlx::query_as!(
        Stored,
        "SELECT statement, signature FROM user_freshness WHERE user_id = ?",
        user_id
    )
    .fetch_optional(ex)
    .await
}
