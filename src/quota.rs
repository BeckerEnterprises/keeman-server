//! The storage quota of the account a vault counts against. Checked inside
//! the write transaction and only when a request increases the usage, so an
//! account over its quota can still delete and shrink. `507` is never
//! stored for an idempotency key.

use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};

/// The account a vault counts against; without an active owner the caller's.
pub async fn account_for(conn: &mut Conn, vault_id: &str, caller: &str) -> ApiResult<String> {
    Ok(db::quota::account(conn, vault_id)
        .await?
        .unwrap_or_else(|| caller.to_string()))
}

/// `507 quota_exceeded` if `growth` more bytes would exceed `quota`.
pub async fn require_room(
    conn: &mut Conn,
    account: &str,
    growth: i64,
    quota: u64,
    now: &str,
) -> ApiResult<()> {
    if growth <= 0 {
        return Ok(());
    }
    let used = db::quota::usage(conn, account, now).await?;
    let quota = i64::try_from(quota).unwrap_or(i64::MAX);
    if used.saturating_add(growth) > quota {
        return Err(ApiError::new(ErrorCode::QuotaExceeded));
    }
    Ok(())
}

/// A byte count as a signed number for growth arithmetic.
pub fn bytes(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}
