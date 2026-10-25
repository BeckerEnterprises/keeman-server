//! Login lockout per e-mail HMAC: stored in the database, also for
//! addresses without an account, so it never reveals whether one exists.

use time::Duration;

use crate::app::App;
use crate::audit;
use crate::clock::{format_timestamp, parse_timestamp};
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};

/// Counters without new failures are forgotten after this time.
const DECAY: Duration = Duration::hours(24);

/// `429` with `Retry-After` while the address is locked; checked before
/// anything else and not counted.
pub async fn check(app: &App, key: &[u8; 32]) -> ApiResult<()> {
    let Some(row) = db::throttle::get(&app.db.read, key).await? else {
        return Ok(());
    };
    let now = app.now();
    match row.locked_until.as_deref().and_then(parse_timestamp) {
        Some(until) if until > now => {
            let seconds = ((until - now).whole_milliseconds() + 999) / 1000;
            Err(ApiError::new(ErrorCode::RateLimited)
                .retry_after(u64::try_from(seconds).unwrap_or(1)))
        }
        _ => Ok(()),
    }
}

/// Counts a failed credential check; the last allowed failure locks the
/// address and starts the counter again.
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
        audit::log(
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

/// A successful credential check resets the counter.
pub async fn success(conn: &mut Conn, key: &[u8; 32]) -> ApiResult<()> {
    db::throttle::clear(conn, key).await?;
    Ok(())
}
