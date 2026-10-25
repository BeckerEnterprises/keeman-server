//! Large request bodies (`batch`, rotation upload and commit, attachment
//! parts): a shared budget for the bodies in memory and a cap on such
//! requests per account. Both are taken before the body is read and freed
//! when the request ends, also when the client goes away.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, header};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::{ApiError, ApiResult, ErrorCode};

/// The smallest reservation, so that many tiny bodies cannot pass a budget
/// counted in large units unnoticed.
const MIN_RESERVATION: u64 = 64 * 1024;

pub struct LargeBodies {
    /// Free budget in KiB; waiting requests are served in arrival order.
    budget: Arc<Semaphore>,
    per_account: Arc<Mutex<HashMap<String, u32>>>,
    max_per_account: u32,
}

/// Held for the whole request.
pub struct Admission {
    _permit: OwnedSemaphorePermit,
    _slot: Slot,
}

struct Slot {
    counts: Arc<Mutex<HashMap<String, u32>>>,
    account: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(&self.account) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.account);
            }
        }
    }
}

impl LargeBodies {
    pub fn new(budget_bytes: u64, max_per_account: u32) -> Self {
        let kib = usize::try_from(budget_bytes / 1024).unwrap_or(usize::MAX);
        Self {
            budget: Arc::new(Semaphore::new(kib.min(Semaphore::MAX_PERMITS))),
            per_account: Arc::new(Mutex::new(HashMap::new())),
            max_per_account,
        }
    }

    /// A slot of the account (else `429` with `Retry-After: 1` at once),
    /// then room in the budget for `Content-Length`, at least 64 KiB and at
    /// most `limit`, or `limit` without the header. Waiting for room is
    /// bounded by the request timeout.
    pub async fn admit(
        &self,
        account: &str,
        headers: &HeaderMap,
        limit: usize,
    ) -> ApiResult<Admission> {
        let slot = {
            let mut counts = self
                .per_account
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let count = counts.entry(account.to_string()).or_insert(0);
            if *count >= self.max_per_account {
                return Err(ApiError::new(ErrorCode::RateLimited).retry_after(1));
            }
            *count += 1;
            Slot {
                counts: self.per_account.clone(),
                account: account.to_string(),
            }
        };
        let limit = limit as u64;
        let bytes = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map_or(limit, |length| length.clamp(MIN_RESERVATION, limit));
        let kib = u32::try_from(bytes.div_ceil(1024)).unwrap_or(u32::MAX);
        let permit = self
            .budget
            .clone()
            .acquire_many_owned(kib)
            .await
            .map_err(ApiError::internal)?;
        Ok(Admission {
            _permit: permit,
            _slot: slot,
        })
    }

    /// Large requests of this account in progress (tests).
    pub fn in_flight(&self, account: &str) -> u32 {
        self.per_account
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(account)
            .copied()
            .unwrap_or(0)
    }

    /// Free budget in KiB (tests).
    pub fn available_kib(&self) -> usize {
        self.budget.available_permits()
    }
}
