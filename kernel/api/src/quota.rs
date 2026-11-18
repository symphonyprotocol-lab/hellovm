//! The request rate limit: a token bucket per tenant.
//!
//! Each tenant's bucket holds up to `burst` tokens and refills at
//! `requests_per_second`; an authenticated request takes one, and a
//! request that finds none is answered `429 rate_limited` at once, with
//! `Retry-After` (whole seconds until a token is back). A request without
//! a valid token takes nothing from anyone's bucket. The check is a few
//! arithmetic operations under one lock and never waits, so a tenant that
//! is refused costs the others nothing.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    refilled: Instant,
}

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// Takes a token of `tenant`'s bucket (`rate` per second, `burst` at
    /// most) at `now`: `Ok`, or the seconds until one is back.
    pub fn take(&self, tenant: &str, rate: f64, burst: u32, now: Instant) -> Result<(), u64> {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let burst = f64::from(burst.max(1));
        let bucket = buckets.entry(tenant.to_string()).or_insert(Bucket {
            tokens: burst,
            refilled: now,
        });
        let gained = now.saturating_duration_since(bucket.refilled).as_secs_f64() * rate;
        bucket.tokens = (bucket.tokens + gained).min(burst);
        bucket.refilled = now.max(bucket.refilled);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        let wait = (1.0 - bucket.tokens) / rate;
        Err((wait.ceil() as u64).max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_burst_then_the_rate() {
        let limiter = RateLimiter::default();
        let t0 = Instant::now();
        for _ in 0..5 {
            assert_eq!(limiter.take("a", 2.0, 5, t0), Ok(()));
        }
        assert_eq!(limiter.take("a", 2.0, 5, t0), Err(1));
        // Another tenant has a bucket of its own.
        assert_eq!(limiter.take("b", 2.0, 5, t0), Ok(()));
        // Half a second brings one token back, not more.
        let t1 = t0 + Duration::from_millis(500);
        assert_eq!(limiter.take("a", 2.0, 5, t1), Ok(()));
        assert!(limiter.take("a", 2.0, 5, t1).is_err());
        // Idle time refills up to the burst only.
        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..5 {
            assert_eq!(limiter.take("a", 2.0, 5, t2), Ok(()));
        }
        assert!(limiter.take("a", 2.0, 5, t2).is_err());
        // A slow rate: the wait is whole seconds, rounded up.
        assert_eq!(limiter.take("c", 0.1, 1, t0), Ok(()));
        assert_eq!(limiter.take("c", 0.1, 1, t0), Err(10));
    }
}
