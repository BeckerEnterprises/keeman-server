//! Time source. Injectable, so tests can drive expiry, rate limits and lockout.

use std::sync::{Arc, Mutex};

use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> OffsetDateTime;
}

pub type SharedClock = Arc<dyn Clock>;

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A clock that only moves when told to.
pub struct MockClock(Mutex<OffsetDateTime>);

impl MockClock {
    pub fn new(start: OffsetDateTime) -> Self {
        Self(Mutex::new(start))
    }

    pub fn advance(&self, by: Duration) {
        let mut now = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *now += by;
    }
}

impl Clock for MockClock {
    fn now(&self) -> OffsetDateTime {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// ISO 8601 UTC timestamp with milliseconds, e.g. `2026-10-23T08:42:00.000Z`. Sorts
/// lexicographically, so the database stores it as TEXT.
pub fn format_timestamp(time: OffsetDateTime) -> String {
    let t = time.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

pub fn parse_timestamp(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

pub fn unix_ms(time: OffsetDateTime) -> i64 {
    i64::try_from(time.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn formats_with_milliseconds() {
        let t = datetime!(2026-10-23 08:42:00.123456 UTC);
        assert_eq!(format_timestamp(t), "2026-10-23T08:42:00.123Z");
        assert_eq!(
            parse_timestamp("2026-10-23T08:42:00.123Z")
                .map(format_timestamp)
                .as_deref(),
            Some("2026-10-23T08:42:00.123Z")
        );
        assert_eq!(unix_ms(datetime!(1970-01-01 00:00:01 UTC)), 1000);
    }

    #[test]
    fn mock_clock_advances() {
        let clock = MockClock::new(datetime!(2026-01-01 00:00 UTC));
        clock.advance(Duration::minutes(15));
        assert_eq!(clock.now(), datetime!(2026-01-01 00:15 UTC));
    }
}
