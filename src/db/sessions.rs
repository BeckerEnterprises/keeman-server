use sqlx::SqliteExecutor;

use super::Conn;

pub struct NewSession<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub device_name: &'a str,
    pub client_type: &'a str,
    pub refresh_expires_at: &'a str,
    pub ip_hint: Option<&'a str>,
    pub now: &'a str,
}

pub async fn insert<'e>(
    ex: impl SqliteExecutor<'e>,
    s: &NewSession<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO sessions (id, user_id, device_name, client_type, refresh_expires_at, ip_hint, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        s.id,
        s.user_id,
        s.device_name,
        s.client_type,
        s.refresh_expires_at,
        s.ip_hint,
        s.now,
        s.now
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub async fn insert_refresh<'e>(
    ex: impl SqliteExecutor<'e>,
    hash: &[u8],
    session_id: &str,
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO refresh_tokens (token_hash, session_id, created_at) VALUES (?, ?, ?)",
        hash,
        session_id,
        now
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub async fn insert_access<'e>(
    ex: impl SqliteExecutor<'e>,
    hash: &[u8],
    session_id: &str,
    expires_at: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO access_tokens (token_hash, session_id, expires_at) VALUES (?, ?, ?)",
        hash,
        session_id,
        expires_at
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub struct AccessRow {
    pub session_id: String,
    pub user_id: String,
    pub client_type: String,
    pub last_seen_at: String,
}

/// A valid access token: unexpired, session active, account enabled.
pub async fn access_lookup<'e>(
    ex: impl SqliteExecutor<'e>,
    hash: &[u8],
    now: &str,
) -> Result<Option<AccessRow>, sqlx::Error> {
    sqlx::query_as!(
        AccessRow,
        r#"SELECT s.id AS "session_id!", s.user_id, s.client_type, s.last_seen_at
           FROM access_tokens a
           JOIN sessions s ON s.id = a.session_id
           JOIN users u ON u.id = s.user_id
           WHERE a.token_hash = ? AND a.expires_at > ? AND s.revoked_at IS NULL
             AND s.refresh_expires_at > ? AND u.disabled = 0"#,
        hash,
        now,
        now
    )
    .fetch_optional(ex)
    .await
}

pub async fn touch<'e>(
    ex: impl SqliteExecutor<'e>,
    session_id: &str,
    now: &str,
    ip_hint: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE sessions SET last_seen_at = ?, ip_hint = ? WHERE id = ?",
        now,
        ip_hint,
        session_id
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub struct RefreshRow {
    pub session_id: String,
    pub user_id: String,
    pub client_type: String,
    pub superseded_at: Option<String>,
    pub revoked_at: Option<String>,
    pub refresh_expires_at: String,
    pub disabled: bool,
    /// The token superseded last, i.e. directly before the current one.
    pub is_previous: bool,
}

pub async fn refresh_lookup<'e>(
    ex: impl SqliteExecutor<'e>,
    hash: &[u8],
) -> Result<Option<RefreshRow>, sqlx::Error> {
    sqlx::query_as!(
        RefreshRow,
        r#"SELECT s.id AS "session_id!", s.user_id, s.client_type, r.superseded_at, s.revoked_at,
             s.refresh_expires_at, u.disabled AS "disabled: bool",
             (r.rowid = (SELECT MAX(p.rowid) FROM refresh_tokens p
                         WHERE p.session_id = r.session_id AND p.superseded_at IS NOT NULL)) AS "is_previous!: bool"
           FROM refresh_tokens r
           JOIN sessions s ON s.id = r.session_id
           JOIN users u ON u.id = s.user_id
           WHERE r.token_hash = ?"#,
        hash
    )
    .fetch_optional(ex)
    .await
}

pub async fn supersede_refresh<'e>(
    ex: impl SqliteExecutor<'e>,
    hash: &[u8],
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE refresh_tokens SET superseded_at = ? WHERE token_hash = ?",
        now,
        hash
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub async fn extend<'e>(
    ex: impl SqliteExecutor<'e>,
    session_id: &str,
    refresh_expires_at: &str,
    now: &str,
    ip_hint: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE sessions SET refresh_expires_at = ?, last_seen_at = ?, ip_hint = ? WHERE id = ?",
        refresh_expires_at,
        now,
        ip_hint,
        session_id
    )
    .execute(ex)
    .await?;
    Ok(())
}

/// Revokes a session and deletes its access tokens and challenges.
pub async fn revoke(conn: &mut Conn, session_id: &str, now: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        now,
        session_id
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query!("DELETE FROM access_tokens WHERE session_id = ?", session_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query!("DELETE FROM challenges WHERE session_id = ?", session_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// IDs of the active sessions of a user (optionally except one).
async fn active_ids(
    conn: &mut Conn,
    user_id: &str,
    except: &str,
    now: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM sessions WHERE user_id = ? AND id != ? AND revoked_at IS NULL AND refresh_expires_at > ?"#,
        user_id,
        except,
        now
    )
    .fetch_all(&mut *conn)
    .await
}

/// Revokes every active session of the user except `keep`; returns their IDs.
pub async fn revoke_others(
    conn: &mut Conn,
    user_id: &str,
    keep: &str,
    now: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let ids = active_ids(conn, user_id, keep, now).await?;
    for id in &ids {
        revoke(conn, id, now).await?;
    }
    Ok(ids)
}

pub async fn revoke_all(
    conn: &mut Conn,
    user_id: &str,
    now: &str,
) -> Result<Vec<String>, sqlx::Error> {
    revoke_others(conn, user_id, "", now).await
}

/// Whether the session is an active session of this user.
pub async fn is_active_of<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
    session_id: &str,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!: i64" FROM sessions WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND refresh_expires_at > ?"#,
        session_id,
        user_id,
        now
    )
    .fetch_optional(ex)
    .await?;
    Ok(found.is_some())
}

pub struct SessionRow {
    pub id: String,
    pub device_name: String,
    pub client_type: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub ip_hint: Option<String>,
}

pub async fn list_active<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
    now: &str,
) -> Result<Vec<SessionRow>, sqlx::Error> {
    sqlx::query_as!(
        SessionRow,
        r#"SELECT id AS "id!", device_name, client_type, created_at, last_seen_at, ip_hint
           FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND refresh_expires_at > ?
           ORDER BY last_seen_at DESC, created_at DESC"#,
        user_id,
        now
    )
    .fetch_all(ex)
    .await
}

/// Which of these sessions are still valid: not revoked, not expired, the
/// account enabled. `ids` is a JSON array (30-s check).
pub async fn valid_ids<'e>(
    ex: impl SqliteExecutor<'e>,
    ids: &str,
    now: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT s.id AS "id!" FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.id IN (SELECT value FROM json_each(?))
             AND s.revoked_at IS NULL AND s.refresh_expires_at > ? AND u.disabled = 0"#,
        ids,
        now
    )
    .fetch_all(ex)
    .await
}
