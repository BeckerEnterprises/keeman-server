//! The storage quota: which account a vault counts against and how much
//! that account uses.

use super::Conn;

/// The account a vault counts against: its creator while an active owner,
/// otherwise the active owner with the oldest membership.
pub async fn account(conn: &mut Conn, vault_id: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT COALESCE(
             (SELECT v.created_by FROM vaults v
              JOIN memberships c ON c.vault_id = v.id AND c.user_id = v.created_by
              WHERE v.id = ? AND c.role = 'owner' AND c.state = 'active'),
             (SELECT o.user_id FROM memberships o
              WHERE o.vault_id = ? AND o.role = 'owner' AND o.state = 'active'
              ORDER BY o.created_at, o.user_id LIMIT 1)) AS "account?: String""#,
        vault_id,
        vault_id
    )
    .fetch_one(&mut *conn)
    .await
}

/// Bytes used by the vaults that count against this account: objects and
/// tombstones (decoded size), attachments (encrypted, uploading or
/// complete) and the excess of rotations that are still open.
pub async fn usage(conn: &mut Conn, account: &str, now: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"WITH charged(vault_id) AS (
             SELECT m.vault_id FROM memberships m
             WHERE m.user_id = ? AND m.role = 'owner' AND m.state = 'active'
               AND m.user_id = COALESCE(
                 (SELECT v.created_by FROM vaults v
                  JOIN memberships c ON c.vault_id = v.id AND c.user_id = v.created_by
                  WHERE v.id = m.vault_id AND c.role = 'owner' AND c.state = 'active'),
                 (SELECT o.user_id FROM memberships o
                  WHERE o.vault_id = m.vault_id AND o.role = 'owner' AND o.state = 'active'
                  ORDER BY o.created_at, o.user_id LIMIT 1)))
           SELECT
             (SELECT COALESCE(SUM(a.size), 0) FROM attachments a
              WHERE a.vault_id IN (SELECT vault_id FROM charged))
           + (SELECT COALESCE(SUM(o.size), 0) FROM objects o
              WHERE o.vault_id IN (SELECT vault_id FROM charged))
           + (SELECT COALESCE(SUM(r.staged_excess), 0) FROM rotations r
              WHERE r.vault_id IN (SELECT vault_id FROM charged) AND r.expires_at > ?)
           AS "bytes!: i64""#,
        account,
        now
    )
    .fetch_one(&mut *conn)
    .await
}
