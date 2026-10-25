//! Login lockout per e-mail HMAC: stored in the database, also for
//! addresses without an account, so it never reveals whether one exists.

use time::{Duration, OffsetDateTime};

use crate::app::App;
use crate::clock::{format_timestamp, parse_timestamp};
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};

/// Counters without new failures are forgotten after this time.
const DECAY: Duration = Duration::hours(24);

/// `429` with `Retry-After` if the row holds a lock that is still active.
fn locked(row: Option<&db::throttle::ThrottleRow>, now: OffsetDateTime) -> Option<ApiError> {
    let until = row?.locked_until.as_deref().and_then(parse_timestamp)?;
    if until <= now {
        return None;
    }
    let seconds = ((until - now).whole_milliseconds() + 999) / 1000;
    Some(ApiError::new(ErrorCode::RateLimited).retry_after(u64::try_from(seconds).unwrap_or(1)))
}

/// `429` with `Retry-After` while the address is locked; checked before
/// anything else and not counted.
pub async fn check(app: &App, key: &[u8; 32]) -> ApiResult<()> {
    let row = db::throttle::get(&app.db.read, key).await?;
    locked(row.as_ref(), app.now()).map_or(Ok(()), Err)
}

/// The same test as the first statement of the write transaction: a lock
/// that began while this request was being checked applies to it too, so
/// its result (failure, success, disabled account) is never revealed.
pub async fn ensure_unlocked(conn: &mut Conn, app: &App, key: &[u8; 32]) -> ApiResult<()> {
    let row = db::throttle::get(&mut *conn, key).await?;
    locked(row.as_ref(), app.now()).map_or(Ok(()), Err)
}

/// Counts a failed credential check; the last allowed failure locks the
/// address and starts the counter again. While a lock is active nothing is
/// counted and the lock stays as it is (`429`).
pub async fn failure(
    conn: &mut Conn,
    app: &App,
    key: &[u8; 32],
    user_id: Option<&str>,
    ip_hint: &str,
) -> ApiResult<()> {
    let now = app.now();
    let now_text = format_timestamp(now);
    let row = db::throttle::get(&mut *conn, key).await?;
    if let Some(error) = locked(row.as_ref(), now) {
        return Err(error);
    }
    let previous = row
        .as_ref()
        .filter(|r| parse_timestamp(&r.updated_at).is_some_and(|t| now - t < DECAY))
        .map_or(0, |r| r.failures);
    let failures = previous + 1;
    if failures >= i64::from(app.config.rate_limits.lockout_failures) {
        let until = format_timestamp(
            now + Duration::minutes(i64::from(app.config.rate_limits.lockout_minutes)),
        );
        db::throttle::upsert(&mut *conn, key, 0, Some(&until), &now_text).await?;
        app.audit
            .log(
                conn,
                &now_text,
                "login_locked",
                user_id,
                Some(ip_hint),
                serde_json::json!({}),
            )
            .await?;
    } else {
        db::throttle::upsert(&mut *conn, key, failures, None, &now_text).await?;
    }
    Ok(())
}

/// A complete login resets the counter, but never lifts an active lock.
pub async fn success(conn: &mut Conn, app: &App, key: &[u8; 32]) -> ApiResult<()> {
    ensure_unlocked(conn, app, key).await?;
    db::throttle::clear(conn, key).await?;
    Ok(())
}
