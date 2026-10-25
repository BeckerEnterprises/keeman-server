//! Security log, written in the same transaction as the action.
//! `detail` never contains tokens, keys, e-mail addresses or device names.

use serde_json::Value;

use crate::config::LoggingSection;
use crate::db::{self, Conn};

/// Writes the security log within its caps: per account (or without one),
/// event and day only so many entries, more are counted in one summary
/// entry. A flood of one event never pushes out another.
#[derive(Debug, Clone, Copy)]
pub struct Audit {
    per_account: u32,
    anonymous: u32,
}

impl Audit {
    pub fn new(logging: &LoggingSection) -> Self {
        Self {
            per_account: logging.security_log_per_account_per_day,
            anonymous: logging.security_log_anonymous_per_day,
        }
    }

    pub async fn log(
        &self,
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
        self.insert(conn, now, &entry).await
    }

    /// A vault event (`vault_created`, `vault_deleted`) with its `vault_id`.
    pub async fn vault_event(
        &self,
        conn: &mut Conn,
        now: &str,
        event: &str,
        user_id: &str,
        vault_id: &str,
        ip_hint: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        self.vault_log(
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
    #[allow(clippy::too_many_arguments)]
    pub async fn vault_log(
        &self,
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
        self.insert(conn, now, &entry).await
    }

    /// Logs `session_revoked` for each session with the given reason.
    pub async fn sessions_revoked(
        &self,
        conn: &mut Conn,
        now: &str,
        user_id: &str,
        ip_hint: Option<&str>,
        session_ids: &[String],
        reason: &str,
    ) -> Result<(), sqlx::Error> {
        for id in session_ids {
            self.log(
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

    async fn insert(
        &self,
        conn: &mut Conn,
        now: &str,
        entry: &db::security_log::Event<'_>,
    ) -> Result<(), sqlx::Error> {
        let cap = if entry.user_id.is_some() {
            self.per_account
        } else {
            self.anonymous
        };
        db::security_log::insert_capped(conn, now, entry, cap).await
    }
}
