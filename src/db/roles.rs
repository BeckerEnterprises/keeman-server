//! The roles chain of each vault: stored statements, the head and the keys
//! of the active owners the server checks a new statement against.

use sqlx::SqliteExecutor;

use super::Conn;

/// The newest stored statement.
pub struct Head {
    pub version: i64,
    pub statement: Vec<u8>,
    pub hash: Vec<u8>,
}

pub async fn head(conn: &mut Conn, vault_id: &str) -> Result<Option<Head>, sqlx::Error> {
    sqlx::query_as!(
        Head,
        "SELECT version, statement, hash FROM vault_roles WHERE vault_id = ?
         ORDER BY version DESC LIMIT 1",
        vault_id
    )
    .fetch_optional(&mut *conn)
    .await
}

pub struct NewStatement<'a> {
    pub vault_id: &'a str,
    pub version: i64,
    pub statement: &'a [u8],
    pub signature: &'a [u8],
    pub hash: &'a [u8],
    pub now: &'a str,
}

pub async fn insert(conn: &mut Conn, s: &NewStatement<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO vault_roles (vault_id, version, statement, signature, hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        s.vault_id,
        s.version,
        s.statement,
        s.signature,
        s.hash,
        s.now
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// One statement of `GET /v1/vaults/{id}/roles`.
pub struct Stored {
    pub version: i64,
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The statements after `since`, ascending.
pub async fn since(
    conn: &mut Conn,
    vault_id: &str,
    since: i64,
) -> Result<Vec<Stored>, sqlx::Error> {
    sqlx::query_as!(
        Stored,
        "SELECT version, statement, signature FROM vault_roles
         WHERE vault_id = ? AND version > ? ORDER BY version",
        vault_id,
        since
    )
    .fetch_all(&mut *conn)
    .await
}

/// An account's keys as registered: X25519 public key and signing key.
pub struct AccountKeys {
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub signing_public_key: Option<Vec<u8>>,
}

/// The active owners of a vault with their registered keys.
pub async fn owner_keys(conn: &mut Conn, vault_id: &str) -> Result<Vec<AccountKeys>, sqlx::Error> {
    sqlx::query_as!(
        AccountKeys,
        r#"SELECT m.user_id AS "user_id!", u.public_key, u.signing_public_key
           FROM memberships m JOIN users u ON u.id = m.user_id
           WHERE m.vault_id = ? AND m.role = 'owner' AND m.state = 'active'
           ORDER BY m.user_id"#,
        vault_id
    )
    .fetch_all(&mut *conn)
    .await
}

pub async fn account_keys<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
) -> Result<Option<AccountKeys>, sqlx::Error> {
    sqlx::query_as!(
        AccountKeys,
        r#"SELECT id AS "user_id!", public_key, signing_public_key FROM users WHERE id = ?"#,
        user_id
    )
    .fetch_optional(ex)
    .await
}

/// Whether the account is an active owner of a vault that has a roles chain
/// and further active owners: it must demote itself before it goes.
pub async fn owner_in_chain_with_others(
    conn: &mut Conn,
    user_id: &str,
) -> Result<bool, sqlx::Error> {
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!: i64" FROM memberships m
           WHERE m.user_id = ? AND m.role = 'owner' AND m.state = 'active'
             AND EXISTS (SELECT 1 FROM vault_roles r WHERE r.vault_id = m.vault_id)
             AND EXISTS (SELECT 1 FROM memberships o WHERE o.vault_id = m.vault_id
                         AND o.user_id != m.user_id AND o.role = 'owner' AND o.state = 'active')
           LIMIT 1"#,
        user_id
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(found.is_some())
}

/// Every stored statement of every vault, for `check`.
pub struct Link {
    pub vault_id: String,
    pub version: i64,
    pub statement: Vec<u8>,
    pub hash: Vec<u8>,
}

pub async fn all_links(conn: &mut Conn) -> Result<Vec<Link>, sqlx::Error> {
    sqlx::query_as!(
        Link,
        r#"SELECT vault_id AS "vault_id!", version, statement, hash FROM vault_roles
           ORDER BY vault_id, version"#
    )
    .fetch_all(&mut *conn)
    .await
}
