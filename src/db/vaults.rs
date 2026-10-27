use sqlx::SqliteExecutor;

use super::Conn;

pub struct Membership {
    pub role: String,
    pub state: String,
}

pub async fn membership(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
) -> Result<Option<Membership>, sqlx::Error> {
    sqlx::query_as!(
        Membership,
        "SELECT role, state FROM memberships WHERE vault_id = ? AND user_id = ?",
        vault_id,
        user_id
    )
    .fetch_optional(&mut *conn)
    .await
}

pub struct Vault {
    pub revision: i64,
    pub key_version: i64,
    pub tombstone_horizon: i64,
}

pub async fn vault(conn: &mut Conn, vault_id: &str) -> Result<Option<Vault>, sqlx::Error> {
    sqlx::query_as!(
        Vault,
        "SELECT revision, key_version, tombstone_horizon FROM vaults WHERE id = ?",
        vault_id
    )
    .fetch_optional(&mut *conn)
    .await
}

pub async fn exists(conn: &mut Conn, vault_id: &str) -> Result<bool, sqlx::Error> {
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!: i64" FROM vaults WHERE id = ?"#,
        vault_id
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(found.is_some())
}

pub struct NewVault<'a> {
    pub id: &'a str,
    pub owner: &'a str,
    pub key_wrapped: &'a [u8],
    pub now: &'a str,
}

/// A vault with revision 1 and key version 1; the creator is its active owner.
pub async fn insert(conn: &mut Conn, v: &NewVault<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO vaults (id, revision, key_version, created_by, created_at) VALUES (?, 1, 1, ?, ?)",
        v.id,
        v.owner,
        v.now
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query!(
        "INSERT INTO memberships (vault_id, user_id, role, state, key_version, key_wrapped, created_at)
         VALUES (?, ?, 'owner', 'active', 1, ?, ?)",
        v.id,
        v.owner,
        v.key_wrapped,
        v.now
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn set_revision(
    conn: &mut Conn,
    vault_id: &str,
    revision: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE vaults SET revision = ? WHERE id = ?",
        revision,
        vault_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// One row of `GET /v1/vaults`.
pub struct Listed {
    pub vault_id: String,
    pub role: String,
    pub state: String,
    pub vault_key_version: i64,
    pub member_key_version: i64,
    pub key_wrapped: Option<Vec<u8>>,
    pub key_box: Option<Vec<u8>>,
    pub sender_id: Option<String>,
    pub pending_key_box: Option<Vec<u8>>,
    pub pending_key_version: Option<i64>,
    pub pending_key_sender_id: Option<String>,
    pub revision: i64,
    pub rotation_required: bool,
    pub roles_version: Option<i64>,
    /// The caller's own freshness attestation for the vault.
    pub freshness_statement: Option<Vec<u8>>,
    pub freshness_signature: Option<Vec<u8>>,
    pub member_count: i64,
    pub created_at: String,
}

pub async fn list_for_user<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
) -> Result<Vec<Listed>, sqlx::Error> {
    sqlx::query_as!(
        Listed,
        r#"SELECT v.id AS "vault_id!", m.role, m.state, v.key_version AS vault_key_version,
             m.key_version AS member_key_version, m.key_wrapped, m.key_box, m.sender_id,
             m.pending_key_box, m.pending_key_version, m.pending_key_sender_id, v.revision,
             v.rotation_required AS "rotation_required: bool",
             (SELECT MAX(r.version) FROM vault_roles r WHERE r.vault_id = v.id) AS "roles_version: i64",
             f.statement AS "freshness_statement?", f.signature AS "freshness_signature?",
             (SELECT COUNT(*) FROM memberships c WHERE c.vault_id = v.id AND c.state = 'active') AS "member_count!: i64",
             v.created_at
           FROM memberships m JOIN vaults v ON v.id = m.vault_id
             LEFT JOIN vault_freshness f ON f.vault_id = v.id AND f.user_id = m.user_id
           WHERE m.user_id = ?
           ORDER BY v.created_at, v.id"#,
        user_id
    )
    .fetch_all(ex)
    .await
}

/// Whether two accounts share a membership, pending ones included.
pub async fn shares_membership<'e>(
    ex: impl SqliteExecutor<'e>,
    user_id: &str,
    other_id: &str,
) -> Result<bool, sqlx::Error> {
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!: i64" FROM memberships a JOIN memberships b ON a.vault_id = b.vault_id
           WHERE a.user_id = ? AND b.user_id = ? LIMIT 1"#,
        user_id,
        other_id
    )
    .fetch_optional(ex)
    .await?;
    Ok(found.is_some())
}

pub async fn active_members(conn: &mut Conn, vault_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT user_id FROM memberships WHERE vault_id = ? AND state = 'active'",
        vault_id
    )
    .fetch_all(&mut *conn)
    .await
}

/// All members including pending invitations.
pub async fn members(conn: &mut Conn, vault_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT user_id FROM memberships WHERE vault_id = ?",
        vault_id
    )
    .fetch_all(&mut *conn)
    .await
}

/// Deletes the vault with its objects, memberships and rotations.
pub async fn delete(conn: &mut Conn, vault_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM vaults WHERE id = ?", vault_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Whether the account is the only owner of a vault with further active
/// members (`409 sole_owner_of_shared_vault`).
pub async fn sole_owner_of_shared(conn: &mut Conn, user_id: &str) -> Result<bool, sqlx::Error> {
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!: i64" FROM memberships m
           WHERE m.user_id = ? AND m.role = 'owner' AND m.state = 'active'
             AND NOT EXISTS (SELECT 1 FROM memberships o WHERE o.vault_id = m.vault_id
                             AND o.user_id != m.user_id AND o.role = 'owner' AND o.state = 'active')
             AND EXISTS (SELECT 1 FROM memberships x WHERE x.vault_id = m.vault_id
                         AND x.user_id != m.user_id AND x.state = 'active')
           LIMIT 1"#,
        user_id
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(found.is_some())
}

/// Vaults in which the account is the only active member.
pub async fn solo_vaults(conn: &mut Conn, user_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT m.vault_id AS "vault_id!" FROM memberships m
           WHERE m.user_id = ? AND m.state = 'active'
             AND NOT EXISTS (SELECT 1 FROM memberships o WHERE o.vault_id = m.vault_id
                             AND o.user_id != m.user_id AND o.state = 'active')"#,
        user_id
    )
    .fetch_all(&mut *conn)
    .await
}

/// Vaults in which the account is an active member.
pub async fn active_vaults(conn: &mut Conn, user_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT vault_id AS "vault_id!" FROM memberships WHERE user_id = ? AND state = 'active'"#,
        user_id
    )
    .fetch_all(&mut *conn)
    .await
}

pub async fn flag_rotation(conn: &mut Conn, vault_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE vaults SET rotation_required = 1 WHERE id = ?",
        vault_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub struct Grant {
    pub vault_id: String,
    pub user_id: String,
}

/// A membership with its key versions.
pub struct MembershipFull {
    pub role: String,
    pub state: String,
    pub key_version: i64,
    pub pending_key_version: Option<i64>,
}

pub async fn membership_full(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
) -> Result<Option<MembershipFull>, sqlx::Error> {
    sqlx::query_as!(
        MembershipFull,
        "SELECT role, state, key_version, pending_key_version FROM memberships
         WHERE vault_id = ? AND user_id = ?",
        vault_id,
        user_id
    )
    .fetch_optional(&mut *conn)
    .await
}

/// One row of `GET /v1/vaults/{id}/members`.
pub struct Member {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub state: String,
    pub public_key: Vec<u8>,
    pub signing_public_key: Option<Vec<u8>>,
    pub invited_by: Option<String>,
    pub created_at: String,
}

pub async fn member_list(conn: &mut Conn, vault_id: &str) -> Result<Vec<Member>, sqlx::Error> {
    sqlx::query_as!(
        Member,
        r#"SELECT m.user_id AS "user_id!", u.email, m.role, m.state, u.public_key,
             u.signing_public_key, m.sender_id AS invited_by, m.created_at
           FROM memberships m JOIN users u ON u.id = m.user_id
           WHERE m.vault_id = ?
           ORDER BY m.created_at, m.user_id"#,
        vault_id
    )
    .fetch_all(&mut *conn)
    .await
}

pub struct NewInvitation<'a> {
    pub vault_id: &'a str,
    pub user_id: &'a str,
    pub key_version: i64,
    pub key_box: &'a [u8],
    pub sender_id: &'a str,
    pub now: &'a str,
}

/// A pending invitation that was deleted after its time ran out.
pub struct ExpiredInvitation {
    pub vault_id: String,
    pub user_id: String,
}

/// Deletes the pending invitations created at or before `before`.
pub async fn expire_invitations(
    conn: &mut Conn,
    before: &str,
) -> Result<Vec<ExpiredInvitation>, sqlx::Error> {
    sqlx::query_as!(
        ExpiredInvitation,
        "DELETE FROM memberships WHERE state = 'pending' AND created_at <= ?
         RETURNING vault_id, user_id",
        before
    )
    .fetch_all(&mut *conn)
    .await
}

pub async fn insert_invitation(conn: &mut Conn, i: &NewInvitation<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO memberships (vault_id, user_id, role, state, key_version, key_box, sender_id, created_at)
         VALUES (?, ?, 'member', 'pending', ?, ?, ?, ?)",
        i.vault_id,
        i.user_id,
        i.key_version,
        i.key_box,
        i.sender_id,
        i.now
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Pending → active with the own `key_wrapped`; the sender stays as `invited_by`.
pub async fn activate(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
    key_wrapped: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE memberships SET state = 'active', key_wrapped = ?, key_box = NULL
         WHERE vault_id = ? AND user_id = ? AND state = 'pending'",
        key_wrapped,
        vault_id,
        user_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Takes over the pending key: `key_wrapped` and `key_version` are replaced.
pub async fn accept_pending_key(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
    key_wrapped: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE memberships SET key_wrapped = ?, key_version = pending_key_version,
           pending_key_box = NULL, pending_key_version = NULL, pending_key_sender_id = NULL
         WHERE vault_id = ? AND user_id = ? AND pending_key_version IS NOT NULL",
        key_wrapped,
        vault_id,
        user_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Ends a membership; the member's freshness attestation for the vault goes
/// with it.
pub async fn delete_membership(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM memberships WHERE vault_id = ? AND user_id = ?",
        vault_id,
        user_id
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query!(
        "DELETE FROM vault_freshness WHERE vault_id = ? AND user_id = ?",
        vault_id,
        user_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn set_role(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
    role: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE memberships SET role = ? WHERE vault_id = ? AND user_id = ?",
        role,
        vault_id,
        user_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Active owners of the vault.
pub async fn owner_count(conn: &mut Conn, vault_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!: i64" FROM memberships
           WHERE vault_id = ? AND role = 'owner' AND state = 'active'"#,
        vault_id
    )
    .fetch_one(&mut *conn)
    .await
}

pub struct MemberState {
    pub user_id: String,
    pub state: String,
}

/// User IDs and states of all memberships, pending ones included.
pub async fn member_states(
    conn: &mut Conn,
    vault_id: &str,
) -> Result<Vec<MemberState>, sqlx::Error> {
    sqlx::query_as!(
        MemberState,
        r#"SELECT user_id AS "user_id!", state FROM memberships WHERE vault_id = ?"#,
        vault_id
    )
    .fetch_all(&mut *conn)
    .await
}

/// The rotating owner's new `key_wrapped`; an older pending key is dropped.
pub async fn set_own_key(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
    key_wrapped: &[u8],
    key_version: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE memberships SET key_wrapped = ?, key_version = ?,
           pending_key_box = NULL, pending_key_version = NULL, pending_key_sender_id = NULL
         WHERE vault_id = ? AND user_id = ?",
        key_wrapped,
        key_version,
        vault_id,
        user_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// A pending key after a rotation; an older one is replaced.
pub async fn set_pending_key(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
    key_box: &[u8],
    key_version: i64,
    sender_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE memberships SET pending_key_box = ?, pending_key_version = ?, pending_key_sender_id = ?
         WHERE vault_id = ? AND user_id = ?",
        key_box,
        key_version,
        sender_id,
        vault_id,
        user_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// A new box for a pending invitation; the rotating owner becomes its sender.
pub async fn replace_invitation(
    conn: &mut Conn,
    vault_id: &str,
    user_id: &str,
    key_box: &[u8],
    key_version: i64,
    sender_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE memberships SET key_box = ?, key_version = ?, sender_id = ?
         WHERE vault_id = ? AND user_id = ? AND state = 'pending'",
        key_box,
        key_version,
        sender_id,
        vault_id,
        user_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Deletes the pending invitations not in `keep` (a JSON array of user IDs).
pub async fn delete_invitations_except(
    conn: &mut Conn,
    vault_id: &str,
    keep: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        "DELETE FROM memberships WHERE vault_id = ? AND state = 'pending'
           AND user_id NOT IN (SELECT value FROM json_each(?))
         RETURNING user_id",
        vault_id,
        keep
    )
    .fetch_all(&mut *conn)
    .await
}

/// Drops the invitations of one vault sent by the account; returns the invitees.
pub async fn drop_vault_invitations_from(
    conn: &mut Conn,
    vault_id: &str,
    sender_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        "DELETE FROM memberships WHERE vault_id = ? AND sender_id = ? AND state = 'pending'
         RETURNING user_id",
        vault_id,
        sender_id
    )
    .fetch_all(&mut *conn)
    .await
}

/// Drops the pending keys of one vault sent by the account; returns their holders.
pub async fn drop_vault_pending_keys_from(
    conn: &mut Conn,
    vault_id: &str,
    sender_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        "UPDATE memberships SET pending_key_box = NULL, pending_key_version = NULL, pending_key_sender_id = NULL
         WHERE vault_id = ? AND pending_key_sender_id = ?
         RETURNING user_id",
        vault_id,
        sender_id
    )
    .fetch_all(&mut *conn)
    .await
}

/// Drops pending invitations sent by the account; returns who had them.
pub async fn drop_invitations_from(
    conn: &mut Conn,
    sender_id: &str,
) -> Result<Vec<Grant>, sqlx::Error> {
    let grants = sqlx::query_as!(
        Grant,
        "SELECT vault_id, user_id FROM memberships WHERE sender_id = ? AND state = 'pending'",
        sender_id
    )
    .fetch_all(&mut *conn)
    .await?;
    sqlx::query!(
        "DELETE FROM memberships WHERE sender_id = ? AND state = 'pending'",
        sender_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(grants)
}

/// Drops pending keys sent by the account after a rotation.
pub async fn drop_pending_keys_from(
    conn: &mut Conn,
    sender_id: &str,
) -> Result<Vec<Grant>, sqlx::Error> {
    let grants = sqlx::query_as!(
        Grant,
        "SELECT vault_id, user_id FROM memberships WHERE pending_key_sender_id = ?",
        sender_id
    )
    .fetch_all(&mut *conn)
    .await?;
    sqlx::query!(
        "UPDATE memberships SET pending_key_box = NULL, pending_key_version = NULL, pending_key_sender_id = NULL
         WHERE pending_key_sender_id = ?",
        sender_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(grants)
}
