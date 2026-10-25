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
    /// All sessions of an account together.
    Account,
    Lookup,
    Favicon,
    /// Invitations sent by an account and received by an account.
    InvitesByAccount,
    InvitesByInvitee,
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
        self.check_all(&[(bucket, key, quota)])
    }

    /// Takes one token from every bucket, or none at all if any of them is
    /// empty; the error is the longest wait.
    pub fn check_all(&self, buckets: &[(Bucket, &str, Quota)]) -> Result<(), u64> {
        let now = self.now_us();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut next = Vec::with_capacity(buckets.len());
        let mut wait_us = 0;
        for &(bucket, key, quota) in buckets {
            let period = i64::try_from(quota.period.whole_microseconds()).unwrap_or(i64::MAX);
            let interval = period / i64::from(quota.burst.max(1));
            let tolerance = period - interval;
            let tat = state
                .get(&(bucket, key.to_string()))
                .copied()
                .unwrap_or(now)
                .max(now);
            if tat - now > tolerance {
                wait_us = wait_us.max(tat - now - tolerance);
            }
            next.push(((bucket, key.to_string()), tat + interval));
        }
        if wait_us > 0 {
            return Err(u64::try_from(wait_us)
                .unwrap_or(0)
                .div_ceil(1_000_000)
                .max(1));
        }
        state.extend(next);
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
    fn check_all_takes_tokens_only_if_every_bucket_allows() {
        let clock = Arc::new(MockClock::new(datetime!(2026-10-23 08:00 UTC)));
        let limiter = RateLimiter::new(clock);
        let session = Quota::per_minute(10);
        let account = Quota::per_minute(1);
        let first = [
            (Bucket::Session, "s1", session),
            (Bucket::Account, "alice", account),
        ];
        assert_eq!(limiter.check_all(&first), Ok(()));
        // The account is empty: the second session's bucket stays untouched.
        let second = [
            (Bucket::Session, "s2", session),
            (Bucket::Account, "alice", account),
        ];
        assert!(limiter.check_all(&second).is_err());
        for _ in 0..10 {
            assert_eq!(limiter.check(Bucket::Session, "s2", session), Ok(()));
        }
        assert!(limiter.check(Bucket::Session, "s2", session).is_err());
    }

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
