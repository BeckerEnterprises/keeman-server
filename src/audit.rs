//! Security log, written in the same transaction as the action.
//! `detail` never contains tokens, keys, e-mail addresses or device names.

use serde_json::Value;

use crate::db::{self, Conn};

pub async fn log(
    conn: &mut Conn,
    now: &str,
    event: &str,
    user_id: Option<&str>,
    ip_hint: Option<&str>,
    detail: Value,
) -> Result<(), sqlx::Error> {
    let detail = detail.to_string();
    let entry = db::security_log::Event {
        event,
        user_id,
        vault_id: None,
        ip_hint,
        detail: &detail,
    };
    db::security_log::insert(conn, now, &entry).await
}

/// A vault event (`vault_created`, `vault_deleted`) with its `vault_id`.
pub async fn vault_event(
    conn: &mut Conn,
    now: &str,
    event: &str,
    user_id: &str,
    vault_id: &str,
    ip_hint: Option<&str>,
) -> Result<(), sqlx::Error> {
    vault_log(
        conn,
        now,
        event,
        user_id,
        vault_id,
        ip_hint,
        Value::Object(Default::default()),
    )
    .await
}

/// A vault event with details, e.g. the member it concerns.
pub async fn vault_log(
    conn: &mut Conn,
    now: &str,
    event: &str,
    user_id: &str,
    vault_id: &str,
    ip_hint: Option<&str>,
    detail: Value,
) -> Result<(), sqlx::Error> {
    let detail = detail.to_string();
    let entry = db::security_log::Event {
        event,
        user_id: Some(user_id),
        vault_id: Some(vault_id),
        ip_hint,
        detail: &detail,
    };
    db::security_log::insert(conn, now, &entry).await
}

/// Logs `session_revoked` for each session with the given reason.
pub async fn sessions_revoked(
    conn: &mut Conn,
    now: &str,
    user_id: &str,
    ip_hint: Option<&str>,
    session_ids: &[String],
    reason: &str,
) -> Result<(), sqlx::Error> {
    for id in session_ids {
        log(
            conn,
            now,
            "session_revoked",
            Some(user_id),
            ip_hint,
            serde_json::json!({ "reason": reason, "session_id": id }),
        )
        .await?;
    }
    Ok(())
}
