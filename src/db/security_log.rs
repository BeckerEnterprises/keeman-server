use sqlx::SqliteExecutor;

/// One security log entry; `detail` is JSON without secrets.
pub struct Event<'a> {
    pub event: &'a str,
    pub user_id: Option<&'a str>,
    pub vault_id: Option<&'a str>,
    pub ip_hint: Option<&'a str>,
    pub detail: &'a str,
}

pub async fn insert<'e>(
    ex: impl SqliteExecutor<'e>,
    now: &str,
    e: &Event<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO security_log (ts, user_id, vault_id, event, ip_hint, detail) VALUES (?, ?, ?, ?, ?, ?)",
        now,
        e.user_id,
        e.vault_id,
        e.event,
        e.ip_hint,
        e.detail
    )
    .execute(ex)
    .await?;
    Ok(())
}
