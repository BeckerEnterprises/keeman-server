use sqlx::SqliteExecutor;

pub struct NewUser<'a> {
    pub id: &'a str,
    pub email: &'a str,
    pub kdf_params: &'a str,
    pub kdf_salt: &'a [u8],
    pub auth_hash: &'a str,
    pub user_key_wrapped: &'a [u8],
    pub public_key: &'a [u8],
    pub private_key_wrapped: &'a [u8],
    pub user_data: &'a [u8],
    pub recovery_auth_hash: &'a str,
    pub user_key_recovery_wrapped: &'a [u8],
    pub now: &'a str,
}

pub async fn insert<'e>(ex: impl SqliteExecutor<'e>, u: &NewUser<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO users (id, email, kdf_params, kdf_salt, auth_hash, user_key_wrapped, public_key,
            private_key_wrapped, user_data, user_data_revision, recovery_auth_hash, user_key_recovery_wrapped,
            created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
        u.id,
        u.email,
        u.kdf_params,
        u.kdf_salt,
        u.auth_hash,
        u.user_key_wrapped,
        u.public_key,
        u.private_key_wrapped,
        u.user_data,
        u.recovery_auth_hash,
        u.user_key_recovery_wrapped,
        u.now,
        u.now
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub struct KdfRow {
    pub kdf_params: String,
    pub kdf_salt: Vec<u8>,
}

pub async fn kdf_by_email<'e>(
    ex: impl SqliteExecutor<'e>,
    email: &str,
) -> Result<Option<KdfRow>, sqlx::Error> {
    sqlx::query_as!(
        KdfRow,
        "SELECT kdf_params, kdf_salt FROM users WHERE email = ?",
        email
    )
    .fetch_optional(ex)
    .await
}

pub async fn email_by_id<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar!("SELECT email FROM users WHERE id = ?", id)
        .fetch_optional(ex)
        .await
}

/// An account as other accounts see it (`PublicUser`).
pub struct PublicUser {
    pub id: String,
    pub email: String,
    pub public_key: Vec<u8>,
}

pub async fn public_by_email<'e>(
    ex: impl SqliteExecutor<'e>,
    email: &str,
) -> Result<Option<PublicUser>, sqlx::Error> {
    sqlx::query_as!(
        PublicUser,
        r#"SELECT id AS "id!", email, public_key FROM users WHERE email = ?"#,
        email
    )
    .fetch_optional(ex)
    .await
}

pub async fn public_by_id<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
) -> Result<Option<PublicUser>, sqlx::Error> {
    sqlx::query_as!(
        PublicUser,
        r#"SELECT id AS "id!", email, public_key FROM users WHERE id = ?"#,
        id
    )
    .fetch_optional(ex)
    .await
}

pub async fn id_by_email<'e>(
    ex: impl SqliteExecutor<'e>,
    email: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar!("SELECT id FROM users WHERE email = ?", email)
        .fetch_optional(ex)
        .await
}

pub struct LoginUser {
    pub id: String,
    pub email: String,
    pub auth_hash: String,
    pub disabled: bool,
    pub totp: bool,
    pub webauthn: bool,
    pub backup_codes: bool,
}

pub async fn login_by_email<'e>(
    ex: impl SqliteExecutor<'e>,
    email: &str,
) -> Result<Option<LoginUser>, sqlx::Error> {
    sqlx::query_as!(
        LoginUser,
        r#"SELECT id AS "id!", email, auth_hash, disabled AS "disabled: bool", totp_enabled AS "totp: bool",
             EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = users.id) AS "webauthn!: bool",
             EXISTS (SELECT 1 FROM backup_codes b WHERE b.user_id = users.id AND b.used_at IS NULL) AS "backup_codes!: bool"
           FROM users WHERE email = ?"#,
        email
    )
    .fetch_optional(ex)
    .await
}

pub async fn login_by_id<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
) -> Result<Option<LoginUser>, sqlx::Error> {
    sqlx::query_as!(
        LoginUser,
        r#"SELECT id AS "id!", email, auth_hash, disabled AS "disabled: bool", totp_enabled AS "totp: bool",
             EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = users.id) AS "webauthn!: bool",
             EXISTS (SELECT 1 FROM backup_codes b WHERE b.user_id = users.id AND b.used_at IS NULL) AS "backup_codes!: bool"
           FROM users WHERE id = ?"#,
        id
    )
    .fetch_optional(ex)
    .await
}

/// What `recover/start` needs.
pub struct RecoveryUser {
    pub id: String,
    pub recovery_auth_hash: String,
    pub user_key_recovery_wrapped: Vec<u8>,
    pub disabled: bool,
    pub totp: bool,
    pub webauthn: bool,
    pub backup_codes: bool,
}

pub async fn recovery_by_email<'e>(
    ex: impl SqliteExecutor<'e>,
    email: &str,
) -> Result<Option<RecoveryUser>, sqlx::Error> {
    sqlx::query_as!(
        RecoveryUser,
        r#"SELECT id AS "id!", recovery_auth_hash, user_key_recovery_wrapped, disabled AS "disabled: bool",
             totp_enabled AS "totp: bool",
             EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = users.id) AS "webauthn!: bool",
             EXISTS (SELECT 1 FROM backup_codes b WHERE b.user_id = users.id AND b.used_at IS NULL) AS "backup_codes!: bool"
           FROM users WHERE email = ?"#,
        email
    )
    .fetch_optional(ex)
    .await
}

pub async fn recovery_by_id<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
) -> Result<Option<RecoveryUser>, sqlx::Error> {
    sqlx::query_as!(
        RecoveryUser,
        r#"SELECT id AS "id!", recovery_auth_hash, user_key_recovery_wrapped, disabled AS "disabled: bool",
             totp_enabled AS "totp: bool",
             EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = users.id) AS "webauthn!: bool",
             EXISTS (SELECT 1 FROM backup_codes b WHERE b.user_id = users.id AND b.used_at IS NULL) AS "backup_codes!: bool"
           FROM users WHERE id = ?"#,
        id
    )
    .fetch_optional(ex)
    .await
}

pub async fn user_key_recovery_wrapped<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT user_key_recovery_wrapped FROM users WHERE id = ?",
        id
    )
    .fetch_optional(ex)
    .await
}

/// The account TOTP (second factor).
pub struct TotpState {
    pub email: String,
    pub enabled: bool,
    pub secret_enc: Option<Vec<u8>>,
    pub last_step: Option<i64>,
}

pub async fn totp_state<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
) -> Result<Option<TotpState>, sqlx::Error> {
    sqlx::query_as!(
        TotpState,
        r#"SELECT email, totp_enabled AS "enabled: bool", totp_secret_enc AS secret_enc,
             totp_last_step AS last_step
           FROM users WHERE id = ?"#,
        id
    )
    .fetch_optional(ex)
    .await
}

pub async fn enable_totp<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    secret_enc: &[u8],
    step: i64,
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET totp_secret_enc = ?, totp_enabled = 1, totp_last_step = ?, updated_at = ? WHERE id = ?",
        secret_enc,
        step,
        now,
        id
    )
    .execute(ex)
    .await?;
    Ok(())
}

/// Turns TOTP off; returns whether it was on.
pub async fn disable_totp<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE users SET totp_secret_enc = NULL, totp_enabled = 0, totp_last_step = NULL, updated_at = ?
         WHERE id = ? AND totp_enabled = 1",
        now,
        id
    )
    .execute(ex)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Stores the step of an accepted code only if it is newer than the last
/// one, so each code works once; returns whether it was stored.
pub async fn advance_totp_step<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    step: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE users SET totp_last_step = ?
         WHERE id = ? AND totp_enabled = 1 AND (totp_last_step IS NULL OR totp_last_step < ?)",
        step,
        id,
        step
    )
    .execute(ex)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub struct MeRow {
    pub id: String,
    pub email: String,
    pub kdf_params: String,
    pub kdf_salt: Vec<u8>,
    pub user_key_wrapped: Vec<u8>,
    pub public_key: Vec<u8>,
    pub private_key_wrapped: Vec<u8>,
    pub user_data: Vec<u8>,
    pub user_data_revision: i64,
    pub totp_enabled: bool,
    pub webauthn_credentials: i64,
    pub backup_codes_remaining: i64,
    pub created_at: String,
}

pub async fn me<'e>(ex: impl SqliteExecutor<'e>, id: &str) -> Result<Option<MeRow>, sqlx::Error> {
    sqlx::query_as!(
        MeRow,
        r#"SELECT id AS "id!", email, kdf_params, kdf_salt, user_key_wrapped, public_key, private_key_wrapped,
             user_data, user_data_revision, totp_enabled AS "totp_enabled: bool",
             (SELECT COUNT(*) FROM webauthn_credentials w WHERE w.user_id = users.id) AS "webauthn_credentials!: i64",
             (SELECT COUNT(*) FROM backup_codes b WHERE b.user_id = users.id AND b.used_at IS NULL) AS "backup_codes_remaining!: i64",
             created_at
           FROM users WHERE id = ?"#,
        id
    )
    .fetch_optional(ex)
    .await
}

/// Conditional update; returns the number of updated rows.
pub async fn update_user_data<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    expected: i64,
    data: &[u8],
    now: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE users SET user_data = ?, user_data_revision = user_data_revision + 1, updated_at = ?
         WHERE id = ? AND user_data_revision = ?",
        data,
        now,
        id,
        expected
    )
    .execute(ex)
    .await?;
    Ok(result.rows_affected())
}

pub async fn user_data_revision<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar!("SELECT user_data_revision FROM users WHERE id = ?", id)
        .fetch_optional(ex)
        .await
}

pub async fn update_password<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    kdf_params: &str,
    kdf_salt: &[u8],
    auth_hash: &str,
    user_key_wrapped: &[u8],
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET kdf_params = ?, kdf_salt = ?, auth_hash = ?, user_key_wrapped = ?, updated_at = ? WHERE id = ?",
        kdf_params,
        kdf_salt,
        auth_hash,
        user_key_wrapped,
        now,
        id
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub async fn update_recovery<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    recovery_auth_hash: &str,
    user_key_recovery_wrapped: &[u8],
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET recovery_auth_hash = ?, user_key_recovery_wrapped = ?, updated_at = ? WHERE id = ?",
        recovery_auth_hash,
        user_key_recovery_wrapped,
        now,
        id
    )
    .execute(ex)
    .await?;
    Ok(())
}

pub async fn set_last_login<'e>(
    ex: impl SqliteExecutor<'e>,
    id: &str,
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!("UPDATE users SET last_login_at = ? WHERE id = ?", now, id)
        .execute(ex)
        .await?;
    Ok(())
}

/// Sets the `disabled` flag; returns the user ID if the e-mail exists.
pub async fn set_disabled<'e>(
    ex: impl SqliteExecutor<'e>,
    email: &str,
    disabled: bool,
    now: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"UPDATE users SET disabled = ?, updated_at = ? WHERE email = ? RETURNING id AS "id!""#,
        disabled,
        now,
        email
    )
    .fetch_optional(ex)
    .await
}

/// Removes TOTP, passkeys, backup codes and open second-factor steps of an
/// account (`user reset-2fa`); returns the user ID if the e-mail exists.
pub async fn reset_two_factor(
    conn: &mut super::Conn,
    email: &str,
    now: &str,
) -> Result<Option<String>, sqlx::Error> {
    let id = sqlx::query_scalar!(
        r#"UPDATE users SET totp_secret_enc = NULL, totp_enabled = 0, totp_last_step = NULL, updated_at = ?
           WHERE email = ? RETURNING id AS "id!""#,
        now,
        email
    )
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(id) = &id {
        super::passkeys::delete_all(&mut *conn, id).await?;
        super::backup_codes::delete_all(&mut *conn, id).await?;
        super::challenges::delete_two_factor_steps(&mut *conn, id).await?;
    }
    Ok(id)
}

pub struct UserListRow {
    pub email: String,
    pub created_at: String,
    pub totp_enabled: bool,
    pub webauthn_credentials: i64,
    pub last_login_at: Option<String>,
    pub disabled: bool,
}

pub async fn list<'e>(ex: impl SqliteExecutor<'e>) -> Result<Vec<UserListRow>, sqlx::Error> {
    sqlx::query_as!(
        UserListRow,
        r#"SELECT email, created_at, totp_enabled AS "totp_enabled: bool",
             (SELECT COUNT(*) FROM webauthn_credentials w WHERE w.user_id = users.id) AS "webauthn_credentials!: i64",
             last_login_at, disabled AS "disabled: bool"
           FROM users ORDER BY created_at"#
    )
    .fetch_all(ex)
    .await
}

/// Deletes the account; sessions, tokens, challenges, passkeys, backup codes,
/// memberships and idempotency records go with it (foreign keys).
pub async fn delete<'e>(ex: impl SqliteExecutor<'e>, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM users WHERE id = ?", id)
        .execute(ex)
        .await?;
    Ok(())
}
