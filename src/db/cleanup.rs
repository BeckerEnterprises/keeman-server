use super::Conn;

/// Cut-off times for the cleanup job, all as ISO 8601 UTC timestamps.
pub struct Cutoffs<'a> {
    pub now: &'a str,
    /// Superseded refresh tokens older than this are forgotten.
    pub refresh_history: &'a str,
    /// Unlocked throttle rows idle since before this are deleted.
    pub throttle_idle: &'a str,
    /// Expired unused invites older than this are deleted.
    pub invite_expired: &'a str,
    /// Security log entries older than this are deleted.
    pub security_log: &'a str,
    /// Idempotency records older than this are deleted (24 h).
    pub idempotency: &'a str,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Removed {
    pub access_tokens: u64,
    pub sessions: u64,
    pub refresh_tokens: u64,
    pub challenges: u64,
    pub throttle: u64,
    pub invites: u64,
    pub security_log: u64,
    pub idempotency: u64,
    pub rotations: u64,
    /// Confirmation requests whose time ran out or whose session ended.
    pub confirmations: u64,
    /// Pending invitations whose time ran out.
    pub invitations: u64,
    pub tombstones: u64,
    /// Uploads that never completed.
    pub attachments: u64,
}

pub async fn run(conn: &mut Conn, c: &Cutoffs<'_>) -> Result<Removed, sqlx::Error> {
    let access_tokens = sqlx::query!("DELETE FROM access_tokens WHERE expires_at <= ?", c.now)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    let sessions = sqlx::query!(
        "DELETE FROM sessions WHERE revoked_at IS NOT NULL OR refresh_expires_at <= ?",
        c.now
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let refresh_tokens = sqlx::query!(
        "DELETE FROM refresh_tokens WHERE superseded_at IS NOT NULL AND superseded_at <= ?",
        c.refresh_history
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let challenges = sqlx::query!("DELETE FROM challenges WHERE expires_at <= ?", c.now)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    let throttle = sqlx::query!(
        "DELETE FROM login_throttle WHERE (locked_until IS NULL OR locked_until <= ?) AND updated_at <= ?",
        c.now,
        c.throttle_idle
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let invites = sqlx::query!(
        "DELETE FROM invites WHERE used_at IS NULL AND expires_at <= ?",
        c.invite_expired
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let security_log = sqlx::query!("DELETE FROM security_log WHERE ts <= ?", c.security_log)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    let idempotency = sqlx::query!(
        "DELETE FROM idempotency WHERE created_at <= ?",
        c.idempotency
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let rotations = sqlx::query!("DELETE FROM rotations WHERE expires_at <= ?", c.now)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    // Requests of ended sessions went with them above (cascade).
    let confirmations = sqlx::query!("DELETE FROM confirmations WHERE expires_at <= ?", c.now)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(Removed {
        access_tokens,
        sessions,
        refresh_tokens,
        challenges,
        throttle,
        invites,
        security_log,
        idempotency,
        rotations,
        confirmations,
        invitations: 0,
        tombstones: 0,
        attachments: 0,
    })
}

struct Tombstone {
    vault_id: String,
    id: String,
    revision: i64,
}

/// Removes up to `block` tombstones last changed before `before` and raises
/// the horizon of their vaults in the same transaction.
pub async fn purge_tombstones(
    conn: &mut Conn,
    before: &str,
    block: i64,
) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query_as!(
        Tombstone,
        r#"SELECT vault_id, id AS "id!", revision FROM objects
           WHERE deleted = 1 AND updated_at <= ? ORDER BY vault_id, revision LIMIT ?"#,
        before,
        block
    )
    .fetch_all(&mut *conn)
    .await?;
    for row in &rows {
        sqlx::query!(
            "UPDATE vaults SET tombstone_horizon = MAX(tombstone_horizon, ?) WHERE id = ?",
            row.revision,
            row.vault_id
        )
        .execute(&mut *conn)
        .await?;
        sqlx::query!(
            "DELETE FROM objects WHERE vault_id = ? AND id = ?",
            row.vault_id,
            row.id
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(u64::try_from(rows.len()).unwrap_or(u64::MAX))
}
