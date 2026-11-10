//! Per-client rate limiting.
//!
//! Each key owns a token bucket. All buckets live in one map behind a single
//! mutex: the critical section is a hash lookup and a couple of float
//! operations, so a contended check costs less than the connection handling it
//! guards. Time is always supplied by the caller rather than read here, which
//! keeps the refill arithmetic testable.
//!
//! Keys are hashed with a per-process random state before they reach the map.
//! Header, cookie and authorization values are therefore not retained in
//! memory, and a client cannot grow the table by sending crafted keys that
//! collide with the map's own hashing.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Hard cap on tracked keys. Without it a client that rotates keys could grow
/// the map for as long as it keeps connecting.
const MAX_ENTRIES: usize = 10_000;

/// Keys idle for longer than this are dropped when the map is over its cap.
const IDLE_TTL: Duration = Duration::from_secs(60);

struct Bucket {
    tokens: f64,
    /// Last time this key was seen. Refreshed on rejected checks too: the
    /// client is active even when it is being throttled.
    last_seen: Instant,
}

/// Token-bucket rate limiter keyed by the caller.
///
/// `rate` is sustained tokens per second and `burst` is the bucket capacity. A
/// rate of zero disables limiting entirely.
pub struct RateLimiter {
    // Kept as f64 so the refill loop does no conversions; a fractional rate is
    // meaningful because tokens accumulate over sub-second intervals.
    rate: f64,
    burst: f64,
    hasher: RandomState,
    buckets: Mutex<HashMap<u64, Bucket>>,
}

/// Result of a delayed token-bucket check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    Delay(Duration),
    Reject,
}

impl RateLimiter {
    /// Creates a limiter allowing `rate` tokens per second with a maximum
    /// stored balance of `burst`.
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate: f64::from(rate),
            burst: f64::from(burst),
            hasher: RandomState::new(),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` when the request is allowed, spending one token.
    ///
    /// `key` identifies the bucket: a peer address, a header value, a cookie,
    /// or anything else the caller considers one client. `now` is supplied by
    /// the caller so tests can move time forward without sleeping.
    pub fn check<K: Hash + ?Sized>(&self, key: &K, now: Instant) -> bool {
        if self.rate == 0.0 {
            // Limiting is off; skip the lock so the disabled path stays as
            // cheap as the map never being allocated.
            return true;
        }

        let key = self.hasher.hash_one(key);
        let mut buckets = self.lock();

        if let Some(bucket) = buckets.get_mut(&key) {
            return refill_and_take(bucket, self.rate, self.burst, now);
        }

        if buckets.len() >= MAX_ENTRIES {
            prune(&mut buckets, now);
            if buckets.len() >= MAX_ENTRIES {
                // Every tracked key is still active. Refusing the newcomer is
                // preferable to evicting a live entry, and it costs nothing.
                return false;
            }
        }

        // A new client starts with a full bucket, so a first request is never
        // rejected because of a history it does not have.
        let mut bucket = Bucket {
            tokens: self.burst,
            last_seen: now,
        };
        let allowed = refill_and_take(&mut bucket, self.rate, self.burst, now);
        if allowed {
            buckets.insert(key, bucket);
        }
        // A first request that fails (only possible with a burst below one)
        // leaves a bucket no future request could ever use, so it is not worth
        // a table slot.
        allowed
    }

    /// Delayed variant of [`check`](Self::check).
    ///
    /// When the bucket is empty, a request may borrow against future refills
    /// until the queue reaches the burst size. The caller is expected to wait
    /// for the returned duration before serving the request.
    pub fn check_delay<K: Hash + ?Sized>(&self, key: &K, now: Instant) -> RateDecision {
        if self.rate == 0.0 {
            return RateDecision::Allow;
        }

        let key = self.hasher.hash_one(key);
        let mut buckets = self.lock();
        let bucket = buckets.entry(key).or_insert_with(|| Bucket {
            tokens: self.burst,
            last_seen: now,
        });
        refill(bucket, self.rate, self.burst, now);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return RateDecision::Allow;
        }

        // The queue may grow until it is one full burst deep. Tokens below
        // zero represent requests already promised a future slot.
        if bucket.tokens > -(self.burst - 1.0) {
            let wait = Duration::from_secs_f64((1.0 - bucket.tokens) / self.rate);
            bucket.tokens -= 1.0;
            RateDecision::Delay(wait)
        } else {
            RateDecision::Reject
        }
    }

    /// Number of keys currently tracked. Intended for tests and metrics.
    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Bucket>> {
        // A panic while holding the lock leaves at most one bucket in a
        // half-updated state; recovering keeps the limiter serving traffic
        // instead of turning the poison flag into an outage.
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for RateLimiter {
    /// Disabled limiter, matching `new(0, 0)`.
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("rate", &self.rate)
            .field("burst", &self.burst)
            .field("tracked", &self.tracked())
            .finish()
    }
}

/// Adds the tokens earned since the last check, then spends one if available.
fn refill_and_take(bucket: &mut Bucket, rate: f64, burst: f64, now: Instant) -> bool {
    refill(bucket, rate, burst, now);
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        // Nothing is deducted on rejection, so a client that backs off regains
        // its allowance exactly when the refill says it should.
        false
    }
}

fn refill(bucket: &mut Bucket, rate: f64, burst: f64, now: Instant) {
    // saturating_duration_since tolerates a caller passing a time earlier than
    // the previous check instead of panicking on a non-monotonic argument.
    let elapsed = now
        .saturating_duration_since(bucket.last_seen)
        .as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
    bucket.last_seen = now;
}

fn prune(buckets: &mut HashMap<u64, Bucket>, now: Instant) {
    buckets.retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) <= IDLE_TTL);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer(index: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(index))
    }

    #[test]
    fn burst_is_spent_then_refills_with_time() {
        let limiter = RateLimiter::new(4, 4);
        let client = peer(1);
        let t0 = Instant::now();

        for _ in 0..4 {
            assert!(limiter.check(&client, t0));
        }
        assert!(!limiter.check(&client, t0));

        // 250 ms at 4 tokens/s is exactly one token.
        let t1 = t0 + Duration::from_millis(250);
        assert!(limiter.check(&client, t1));
        assert!(!limiter.check(&client, t1));

        // A long idle period refills, but never beyond the burst.
        let t2 = t0 + Duration::from_secs(10);
        for _ in 0..4 {
            assert!(limiter.check(&client, t2));
        }
        assert!(!limiter.check(&client, t2));
    }

    #[test]
    fn delayed_checks_queue_up_to_the_burst() {
        let limiter = RateLimiter::new(1, 3);
        let client = peer(1);
        let t0 = Instant::now();

        for _ in 0..3 {
            assert_eq!(limiter.check_delay(&client, t0), RateDecision::Allow);
        }
        assert_eq!(
            limiter.check_delay(&client, t0),
            RateDecision::Delay(Duration::from_secs(1))
        );
        assert_eq!(
            limiter.check_delay(&client, t0),
            RateDecision::Delay(Duration::from_secs(2))
        );
        assert_eq!(limiter.check_delay(&client, t0), RateDecision::Reject);

        // After the promised time the queue drains.
        let later = t0 + Duration::from_secs(3);
        assert_eq!(limiter.check_delay(&client, later), RateDecision::Allow);
    }

    #[test]
    fn rejection_does_not_spend_a_token() {
        let limiter = RateLimiter::new(1, 1);
        let client = peer(1);
        let t0 = Instant::now();

        assert!(limiter.check(&client, t0));
        assert!(!limiter.check(&client, t0));

        // Half a token is not enough, and the failed attempt must not take it.
        let t1 = t0 + Duration::from_millis(500);
        assert!(!limiter.check(&client, t1));

        // Exactly one token has accrued since the successful check.
        let t2 = t0 + Duration::from_secs(1);
        assert!(limiter.check(&client, t2));
        assert!(!limiter.check(&client, t2));
    }

    #[test]
    fn zero_rate_allows_everything_and_tracks_nothing() {
        let limiter = RateLimiter::new(0, 10);
        let t0 = Instant::now();

        for i in 0..1_000 {
            assert!(limiter.check(&peer(i), t0));
        }
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn default_is_disabled() {
        let limiter = RateLimiter::default();
        let t0 = Instant::now();

        assert!(limiter.check(&peer(1), t0));
        assert!(limiter.check(&peer(1), t0));
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn stale_entries_are_evicted_when_full() {
        let limiter = RateLimiter::new(1, 1);
        let t0 = Instant::now();

        for i in 0..MAX_ENTRIES as u32 {
            assert!(limiter.check(&peer(i), t0));
        }
        assert_eq!(limiter.tracked(), MAX_ENTRIES);

        // One second past the idle TTL the whole table is stale, so the
        // newcomer displaces it.
        let t1 = t0 + IDLE_TTL + Duration::from_secs(1);
        assert!(limiter.check(&peer(MAX_ENTRIES as u32), t1));
        assert_eq!(limiter.tracked(), 1);
    }

    #[test]
    fn full_table_of_live_entries_rejects_newcomers() {
        let limiter = RateLimiter::new(1, 1);
        let t0 = Instant::now();

        for i in 0..MAX_ENTRIES as u32 {
            assert!(limiter.check(&peer(i), t0));
        }

        assert!(!limiter.check(&peer(MAX_ENTRIES as u32), t0));
        assert_eq!(limiter.tracked(), MAX_ENTRIES);
    }

    #[test]
    fn tracked_counts_distinct_clients() {
        let limiter = RateLimiter::new(10, 10);
        let t0 = Instant::now();

        assert!(limiter.check(&peer(1), t0));
        assert!(limiter.check(&peer(2), t0));
        assert!(limiter.check(&peer(1), t0));
        assert_eq!(limiter.tracked(), 2);
    }

    #[test]
    fn string_keys_are_independent() {
        let limiter = RateLimiter::new(1, 1);
        let t0 = Instant::now();

        assert!(limiter.check("api-key-a", t0));
        assert!(!limiter.check("api-key-a", t0));
        assert!(limiter.check("api-key-b", t0));
        assert_eq!(limiter.tracked(), 2);
    }
}
