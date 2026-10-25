use sqlx::SqliteExecutor;

pub struct ThrottleRow {
    pub failures: i64,
    pub locked_until: Option<String>,
    pub updated_at: String,
}

pub async fn get<'e>(
    ex: impl SqliteExecutor<'e>,
    key: &[u8],
) -> Result<Option<ThrottleRow>, sqlx::Error> {
    sqlx::query_as!(
        ThrottleRow,
        "SELECT failures, locked_until, updated_at FROM login_throttle WHERE email_hmac = ?",
        key
    )
    .fetch_optional(ex)
    .await
}

pub async fn upsert<'e>(
    ex: impl SqliteExecutor<'e>,
    key: &[u8],
    failures: i64,
    locked_until: Option<&str>,
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO login_throttle (email_hmac, failures, locked_until, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (email_hmac) DO UPDATE SET failures = excluded.failures,
           locked_until = excluded.locked_until, updated_at = excluded.updated_at",
        key,
        failures,
        locked_until,
        now
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub async fn clear<'e>(ex: impl SqliteExecutor<'e>, key: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM login_throttle WHERE email_hmac = ?", key)
        .execute(ex)
        .await?;
    Ok(())
}
