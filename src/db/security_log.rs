use sqlx::SqliteExecutor;

use super::Conn;

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

/// Inserts the entry unless its account (or no account) already has `cap`
/// entries of this event today (UTC); then the day's `log_capped` entry for
/// this event counts it instead.
pub async fn insert_capped(
    conn: &mut Conn,
    now: &str,
    e: &Event<'_>,
    cap: u32,
) -> Result<(), sqlx::Error> {
    // Timestamps have a fixed width, so the day starts at its first ten
    // characters.
    let day = format!("{}T00:00:00.000Z", now.get(..10).unwrap_or(now));
    let today = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!: i64" FROM security_log
           WHERE user_id IS ? AND event = ? AND ts >= ?"#,
        e.user_id,
        e.event,
        day
    )
    .fetch_one(&mut *conn)
    .await?;
    if today < i64::from(cap) {
        return insert(&mut *conn, now, e).await;
    }
    let counted = sqlx::query!(
        r#"UPDATE security_log
           SET detail = json_set(detail, '$.suppressed', json_extract(detail, '$.suppressed') + 1)
           WHERE id = (SELECT id FROM security_log
                       WHERE user_id IS ? AND event = 'log_capped' AND ts >= ?
                         AND json_extract(detail, '$.event') = ?
                       LIMIT 1)"#,
        e.user_id,
        day,
        e.event
    )
    .execute(&mut *conn)
    .await?;
    if counted.rows_affected() > 0 {
        return Ok(());
    }
    let detail = serde_json::json!({ "event": e.event, "suppressed": 1 }).to_string();
    let summary = Event {
        event: "log_capped",
        user_id: e.user_id,
        vault_id: None,
        ip_hint: None,
        detail: &detail,
    };
    insert(&mut *conn, now, &summary).await
}
