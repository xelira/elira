use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 10_000;

const IDLE_TTL: Duration = Duration::from_secs(60);

const MAX_DELAY: Duration = Duration::from_secs(5);

struct Bucket {
    tokens: f64,

    last_seen: Instant,
}

pub struct RateLimiter {
    rate: f64,
    burst: f64,
    hasher: RandomState,
    buckets: Mutex<HashMap<u64, Bucket>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    Delay(Duration),
    Reject,
}

impl RateLimiter {
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate: f64::from(rate),
            burst: f64::from(burst),
            hasher: RandomState::new(),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check<K: Hash + ?Sized>(&self, key: &K, now: Instant) -> bool {
        if self.rate == 0.0 {
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
                return false;
            }
        }

        let mut bucket = Bucket {
            tokens: self.burst,
            last_seen: now,
        };
        let allowed = refill_and_take(&mut bucket, self.rate, self.burst, now);
        if allowed {
            buckets.insert(key, bucket);
        }

        allowed
    }

    pub fn check_delay<K: Hash + ?Sized>(&self, key: &K, now: Instant) -> RateDecision {
        if self.rate == 0.0 {
            return RateDecision::Allow;
        }

        let key = self.hasher.hash_one(key);
        let mut buckets = self.lock();
        if !buckets.contains_key(&key) && buckets.len() >= MAX_ENTRIES {
            prune(&mut buckets, now);
            if buckets.len() >= MAX_ENTRIES {
                return RateDecision::Reject;
            }
        }
        let bucket = buckets.entry(key).or_insert_with(|| Bucket {
            tokens: self.burst,
            last_seen: now,
        });
        refill(bucket, self.rate, self.burst, now);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return RateDecision::Allow;
        }

        if bucket.tokens > -(self.burst - 1.0) {
            let wait = Duration::from_secs_f64((1.0 - bucket.tokens) / self.rate);
            if wait > MAX_DELAY {
                return RateDecision::Reject;
            }
            bucket.tokens -= 1.0;
            RateDecision::Delay(wait)
        } else {
            RateDecision::Reject
        }
    }

    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Bucket>> {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for RateLimiter {
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

fn refill_and_take(bucket: &mut Bucket, rate: f64, burst: f64, now: Instant) -> bool {
    refill(bucket, rate, burst, now);
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

fn refill(bucket: &mut Bucket, rate: f64, burst: f64, now: Instant) {
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

        let t1 = t0 + Duration::from_millis(250);
        assert!(limiter.check(&client, t1));
        assert!(!limiter.check(&client, t1));

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

        let t1 = t0 + Duration::from_millis(500);
        assert!(!limiter.check(&client, t1));

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

#[cfg(test)]
mod delay_tests {
    use super::*;

    #[test]
    fn delays_are_capped_instead_of_sleeping_for_hours() {
        let limiter = RateLimiter::new(1, 7);
        let client = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let now = Instant::now();
        for _ in 0..7 {
            assert_eq!(limiter.check_delay(&client, now), RateDecision::Allow);
        }
        for expected in 1..=5 {
            assert_eq!(
                limiter.check_delay(&client, now),
                RateDecision::Delay(Duration::from_secs(expected))
            );
        }
        assert_eq!(limiter.check_delay(&client, now), RateDecision::Reject);
    }
}
