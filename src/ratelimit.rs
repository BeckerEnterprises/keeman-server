//! In-memory rate limits: GCRA, an exact token bucket. "N per
//! period" means a burst of N, refilled evenly over the period.

use std::collections::HashMap;
use std::sync::Mutex;

use time::Duration;

use crate::clock::{SharedClock, unix_ms};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    Prelogin,
    CredentialIp,
    CredentialEmail,
    /// `recover/finish` per IP and per account.
    RecoverIp,
    RecoverAccount,
    Register,
    Refresh,
    Events,
    Session,
    Lookup,
    Favicon,
}

#[derive(Debug, Clone, Copy)]
pub struct Quota {
    pub burst: u32,
    pub period: Duration,
}

impl Quota {
    pub fn per_minute(burst: u32) -> Self {
        Self {
            burst,
            period: Duration::minutes(1),
        }
    }

    pub fn per_hour(burst: u32) -> Self {
        Self {
            burst,
            period: Duration::hours(1),
        }
    }
}

pub struct RateLimiter {
    clock: SharedClock,
    /// Theoretical arrival time per bucket and key, in microseconds.
    state: Mutex<HashMap<(Bucket, String), i64>>,
}

impl RateLimiter {
    pub fn new(clock: SharedClock) -> Self {
        Self {
            clock,
            state: Mutex::new(HashMap::new()),
        }
    }

    fn now_us(&self) -> i64 {
        unix_ms(self.clock.now()).saturating_mul(1000)
    }

    /// Takes one token, or returns the seconds until the next one (`Retry-After`).
    pub fn check(&self, bucket: Bucket, key: &str, quota: Quota) -> Result<(), u64> {
        let period = i64::try_from(quota.period.whole_microseconds()).unwrap_or(i64::MAX);
        let interval = period / i64::from(quota.burst.max(1));
        let tolerance = period - interval;
        let now = self.now_us();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tat = state
            .get(&(bucket, key.to_string()))
            .copied()
            .unwrap_or(now)
            .max(now);
        if tat - now > tolerance {
            let wait_us = tat - now - tolerance;
            return Err(u64::try_from(wait_us)
                .unwrap_or(0)
                .div_ceil(1_000_000)
                .max(1));
        }
        state.insert((bucket, key.to_string()), tat + interval);
        Ok(())
    }

    /// Drops buckets that are full again.
    pub fn prune(&self) {
        let now = self.now_us();
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|_, tat| *tat > now);
    }

    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use std::sync::Arc;
    use time::macros::datetime;

    #[test]
    fn allows_a_burst_then_refills_evenly() {
        let clock = Arc::new(MockClock::new(datetime!(2026-01-01 00:00 UTC)));
        let limiter = RateLimiter::new(clock.clone());
        let quota = Quota::per_minute(10);
        for _ in 0..10 {
            assert!(limiter.check(Bucket::CredentialIp, "ip", quota).is_ok());
        }
        assert_eq!(limiter.check(Bucket::CredentialIp, "ip", quota), Err(6));
        assert!(limiter.check(Bucket::CredentialIp, "other", quota).is_ok());
        assert!(limiter.check(Bucket::CredentialEmail, "ip", quota).is_ok());
        clock.advance(Duration::seconds(6));
        assert!(limiter.check(Bucket::CredentialIp, "ip", quota).is_ok());
        assert!(limiter.check(Bucket::CredentialIp, "ip", quota).is_err());
        clock.advance(Duration::minutes(2));
        limiter.prune();
        assert!(limiter.is_empty());
    }
}
