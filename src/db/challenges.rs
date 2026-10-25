use sqlx::SqliteExecutor;

pub struct NewChallenge<'a> {
    pub hash: &'a [u8],
    pub purpose: &'a str,
    pub user_id: &'a str,
    pub session_id: Option<&'a str>,
    pub state: Option<&'a str>,
    pub expires_at: &'a str,
}

pub async fn insert<'e>(
    ex: impl SqliteExecutor<'e>,
    c: &NewChallenge<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO challenges (token_hash, purpose, user_id, session_id, state, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        c.hash,
        c.purpose,
        c.user_id,
        c.session_id,
        c.state,
        c.expires_at
    )
    .execute(ex)
    .await?;
    Ok(())
}

/// A reauth token bound to this session and not yet expired.
pub async fn reauth_valid<'e>(
    ex: impl SqliteExecutor<'e>,
    hash: &[u8],
    session_id: &str,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!: i64" FROM challenges WHERE token_hash = ? AND purpose = 'reauth' AND session_id = ? AND expires_at > ?"#,
        hash,
        session_id,
        now
    )
    .fetch_optional(ex)
    .await?;
    Ok(found.is_some())
}

pub async fn delete_for_user<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
    purpose: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM challenges WHERE user_id = ? AND purpose = ?",
        user_id,
        purpose
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub async fn delete_all_for_user<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM challenges WHERE user_id = ?", user_id)
        .execute(ex)
        .await?;
    Ok(())
}

/// An open challenge.
pub struct ChallengeRow {
    pub hash: Vec<u8>,
    pub purpose: String,
    pub user_id: String,
    pub session_id: Option<String>,
    pub state: Option<String>,
    pub attempts: i64,
}

/// The challenge of a token if it has not expired; the caller checks the purpose.
pub async fn get<'e>(
    ex: impl SqliteExecutor<'e>,
    hash: &[u8],
    now: &str,
) -> Result<Option<ChallengeRow>, sqlx::Error> {
    sqlx::query_as!(
        ChallengeRow,
        r#"SELECT token_hash AS hash, purpose, user_id, session_id, state, attempts
           FROM challenges WHERE token_hash = ? AND expires_at > ?"#,
        hash,
        now
    )
    .fetch_optional(ex)
    .await
}

/// The open challenge of a purpose that belongs to a session (TOTP setup).
pub async fn get_for_session<'e>(
    ex: impl SqliteExecutor<'e>,
    session_id: &str,
    purpose: &str,
    now: &str,
) -> Result<Option<ChallengeRow>, sqlx::Error> {
    sqlx::query_as!(
        ChallengeRow,
        r#"SELECT token_hash AS hash, purpose, user_id, session_id, state, attempts
           FROM challenges WHERE session_id = ? AND purpose = ? AND expires_at > ?"#,
        session_id,
        purpose,
        now
    )
    .fetch_optional(ex)
    .await
}

/// Counts a failed attempt; returns the attempts so far.
pub async fn count_failure<'e>(
    ex: impl SqliteExecutor<'e>,
    hash: &[u8],
) -> Result<i64, sqlx::Error> {
    let attempts = sqlx::query_scalar!(
        "UPDATE challenges SET attempts = attempts + 1 WHERE token_hash = ? RETURNING attempts",
        hash
    )
    .fetch_optional(ex)
    .await?;
    Ok(attempts.unwrap_or(0))
}

pub async fn set_state<'e>(
    ex: impl SqliteExecutor<'e>,
    hash: &[u8],
    state: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE challenges SET state = ? WHERE token_hash = ?",
        state,
        hash
    )
    .execute(ex)
    .await?;
    Ok(())
}

/// Consumes a challenge; returns whether it still existed.
pub async fn delete<'e>(ex: impl SqliteExecutor<'e>, hash: &[u8]) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!("DELETE FROM challenges WHERE token_hash = ?", hash)
        .execute(ex)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_for_session<'e>(
    ex: impl SqliteExecutor<'e>,
    session_id: &str,
    purpose: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM challenges WHERE session_id = ? AND purpose = ?",
        session_id,
        purpose
    )
    .execute(ex)
    .await?;
    Ok(())
}

/// Open second-factor steps of an account (`user reset-2fa`).
pub async fn delete_two_factor_steps<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM challenges WHERE user_id = ?
           AND purpose IN ('login', 'recovery', 'totp_setup', 'webauthn_register')",
        user_id
    )
    .execute(ex)
    .await?;
    Ok(())
}
