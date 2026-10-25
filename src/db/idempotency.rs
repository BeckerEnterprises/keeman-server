use super::Conn;

/// A stored idempotent answer.
pub struct Stored {
    pub endpoint: String,
    pub request_hash: Vec<u8>,
    pub status: i64,
    pub response: Vec<u8>,
}

pub async fn find(
    conn: &mut Conn,
    user_id: &str,
    key: &str,
) -> Result<Option<Stored>, sqlx::Error> {
    sqlx::query_as!(
        Stored,
        "SELECT endpoint, request_hash, status, response FROM idempotency WHERE user_id = ? AND key = ?",
        user_id,
        key
    )
    .fetch_optional(&mut *conn)
    .await
}

/// The endpoint of an answer stored under this key, if any.
pub async fn stored_endpoint(
    conn: &mut Conn,
    user_id: &str,
    key: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT endpoint FROM idempotency WHERE user_id = ? AND key = ?",
        user_id,
        key
    )
    .fetch_optional(&mut *conn)
    .await
}

pub struct NewEntry<'a> {
    pub user_id: &'a str,
    pub key: &'a str,
    pub endpoint: &'a str,
    pub request_hash: &'a [u8],
    pub status: i64,
    pub response: &'a [u8],
    pub now: &'a str,
}

pub async fn insert(conn: &mut Conn, e: &NewEntry<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO idempotency (user_id, key, endpoint, request_hash, status, response, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        e.user_id,
        e.key,
        e.endpoint,
        e.request_hash,
        e.status,
        e.response,
        e.now
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}
