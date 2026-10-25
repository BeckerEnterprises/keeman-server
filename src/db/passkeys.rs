use sqlx::SqliteExecutor;

pub struct NewPasskey<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub credential_id: &'a [u8],
    pub passkey: &'a str,
    pub name: &'a str,
    pub now: &'a str,
}

pub async fn insert<'e>(
    ex: impl SqliteExecutor<'e>,
    p: &NewPasskey<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO webauthn_credentials (id, user_id, credential_id, passkey, name, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        p.id,
        p.user_id,
        p.credential_id,
        p.passkey,
        p.name,
        p.now
    )
    .execute(ex)
    .await?;
    Ok(())
}

/// A passkey as listed for its owner.
pub struct PasskeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub prf_enabled: bool,
}

pub async fn list<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
) -> Result<Vec<PasskeyInfo>, sqlx::Error> {
    sqlx::query_as!(
        PasskeyInfo,
        r#"SELECT id AS "id!", name, created_at, last_used_at,
             prf_wrapped_user_key IS NOT NULL AS "prf_enabled!: bool"
           FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at, id"#,
        user_id
    )
    .fetch_all(ex)
    .await
}

/// The stored library state of a passkey.
pub struct StoredPasskey {
    pub id: String,
    pub credential_id: Vec<u8>,
    pub passkey: String,
}

pub async fn for_user<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
) -> Result<Vec<StoredPasskey>, sqlx::Error> {
    sqlx::query_as!(
        StoredPasskey,
        r#"SELECT id AS "id!", credential_id, passkey FROM webauthn_credentials
           WHERE user_id = ? ORDER BY created_at, id"#,
        user_id
    )
    .fetch_all(ex)
    .await
}

pub async fn by_credential<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
    credential_id: &[u8],
) -> Result<Option<StoredPasskey>, sqlx::Error> {
    sqlx::query_as!(
        StoredPasskey,
        r#"SELECT id AS "id!", credential_id, passkey FROM webauthn_credentials
           WHERE user_id = ? AND credential_id = ?"#,
        user_id,
        credential_id
    )
    .fetch_optional(ex)
    .await
}

pub async fn count<'e>(ex: impl SqliteExecutor<'e>, user_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!: i64" FROM webauthn_credentials WHERE user_id = ?"#,
        user_id
    )
    .fetch_one(ex)
    .await
}

/// Whether any account has registered this credential ID.
pub async fn credential_exists<'e>(
    ex: impl SqliteExecutor<'e>,
    credential_id: &[u8],
) -> Result<bool, sqlx::Error> {
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!: i64" FROM webauthn_credentials WHERE credential_id = ?"#,
        credential_id
    )
    .fetch_optional(ex)
    .await?;
    Ok(found.is_some())
}

/// Stores the state after a login and the time of use, only over the
/// state `read` (compare and swap); returns whether it did.
pub async fn record_use<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    read: &str,
    passkey: &str,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query!(
        "UPDATE webauthn_credentials SET passkey = ?, last_used_at = ? WHERE id = ? AND passkey = ?",
        passkey,
        now,
        id,
        read
    )
    .execute(ex)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Deletes a passkey of the account; returns whether it existed.
pub async fn delete<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM webauthn_credentials WHERE user_id = ? AND id = ?",
        user_id,
        id
    )
    .execute(ex)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_all<'e>(ex: impl SqliteExecutor<'e>, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM webauthn_credentials WHERE user_id = ?",
        user_id
    )
    .execute(ex)
    .await?;
    Ok(())
}
