//! In-memory response cache.
//!
//! Responses are keyed by a caller-supplied string and bounded by the total
//! size of their bodies, not by the number of entries: response bodies vary by
//! orders of magnitude, so a byte budget is the only limit that maps to actual
//! memory use. Time is supplied by the caller for the same reason it is in the
//! rate limiter — expiry becomes testable without sleeping.
//!
//! The cache holds one mutex and never awaits while holding it. Reads clone the
//! entry so the lock is released before the caller touches the body.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Default body budget: large enough to absorb a working set of small API
/// responses without threatening a container memory limit.
const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Default lifetime. One minute keeps a hot upstream from being hit on every
/// request while still tracking content that changes on human timescales.
const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// A cached response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

struct Record {
    entry: Entry,
    /// Insertion time, used for both expiry and eviction order.
    stored: Instant,
    /// Tie-breaker for entries inserted at the same `Instant`. Without it,
    /// eviction between equal timestamps would follow hash order and make
    /// behaviour depend on the hasher seed.
    seq: u64,
}

struct Store {
    entries: HashMap<String, Record>,
    total_bytes: usize,
    next_seq: u64,
}

impl Store {
    /// Drops entries whose lifetime is over. Called on insert so space held by
    /// dead responses is reclaimed even if those keys are never requested
    /// again.
    fn purge_expired(&mut self, now: Instant, ttl: Duration) {
        let mut freed = 0;
        self.entries.retain(|_, record| {
            let expired = now.saturating_duration_since(record.stored) >= ttl;
            if expired {
                freed += record.entry.body.len();
            }
            !expired
        });
        self.total_bytes -= freed;
    }

    /// Key of the entry inserted longest ago. A linear scan is acceptable here:
    /// eviction only runs when the byte budget is already exhausted, and the
    /// map is bounded by that budget rather than by request count.
    fn oldest_key(&self) -> Option<String> {
        self.entries
            .iter()
            .min_by_key(|(_, record)| (record.stored, record.seq))
            .map(|(key, _)| key.clone())
    }
}

/// Response cache with a byte budget and a fixed TTL.
///
/// A `max_bytes` of zero disables the cache entirely: reads always miss and
/// writes are ignored, so the disabled path allocates nothing.
pub struct Cache {
    max_bytes: usize,
    ttl: Duration,
    store: Mutex<Store>,
}

impl Cache {
    /// Creates a cache holding at most `max_bytes` of response bodies, where
    /// each entry lives for `ttl`.
    pub fn new(max_bytes: usize, ttl: Duration) -> Self {
        Self {
            max_bytes,
            ttl,
            store: Mutex::new(Store {
                entries: HashMap::new(),
                total_bytes: 0,
                next_seq: 0,
            }),
        }
    }

    /// Returns a copy of the cached entry, or `None` when it is absent or
    /// older than the TTL. An expired entry is removed on the way out so a key
    /// requested once after expiry does not keep occupying budget.
    pub fn get(&self, key: &str, now: Instant) -> Option<Entry> {
        if self.max_bytes == 0 {
            return None;
        }

        let mut store = self.lock();
        let expired = {
            let record = store.entries.get(key)?;
            now.saturating_duration_since(record.stored) >= self.ttl
        };

        if expired {
            if let Some(record) = store.entries.remove(key) {
                store.total_bytes -= record.entry.body.len();
            }
            return None;
        }

        store.entries.get(key).map(|record| record.entry.clone())
    }

    /// Stores `entry` under `key`, replacing any previous value.
    ///
    /// A body larger than the whole budget is rejected: admitting it would
    /// either exceed the limit or evict everything else and still not fit.
    /// Expired entries go first, then the oldest live ones until the body fits.
    pub fn insert(&self, key: String, entry: Entry, now: Instant) {
        if self.max_bytes == 0 || entry.body.len() > self.max_bytes {
            return;
        }

        let body_len = entry.body.len();
        let mut store = self.lock();

        store.purge_expired(now, self.ttl);

        // Replacing a key must not double-count the old body.
        if let Some(previous) = store.entries.remove(&key) {
            store.total_bytes -= previous.entry.body.len();
        }

        // Strict comparison, so a body that exactly fills the budget is kept.
        while store.total_bytes + body_len > self.max_bytes {
            let Some(victim) = store.oldest_key() else {
                // Unreachable while the check above accepts the body, but
                // returning beats panicking on an accounting bug.
                break;
            };
            if let Some(record) = store.entries.remove(&victim) {
                store.total_bytes -= record.entry.body.len();
            }
        }

        let seq = store.next_seq;
        store.next_seq = store.next_seq.wrapping_add(1);
        store.total_bytes += body_len;
        store.entries.insert(
            key,
            Record {
                entry,
                stored: now,
                seq,
            },
        );
    }

    /// Total body bytes and entry count currently held. Both are zero when the
    /// cache is disabled.
    pub fn stats(&self) -> (usize, usize) {
        let store = self.lock();
        (store.total_bytes, store.entries.len())
    }

    fn lock(&self) -> MutexGuard<'_, Store> {
        // A panic in a previous holder leaves the map structurally intact; the
        // poison flag would otherwise turn one panic into a permanent outage.
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_BYTES, DEFAULT_TTL)
    }
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (bytes, entries) = self.stats();
        f.debug_struct("Cache")
            .field("max_bytes", &self.max_bytes)
            .field("ttl", &self.ttl)
            .field("bytes", &bytes)
            .field("entries", &entries)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(body: &[u8]) -> Entry {
        Entry {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: body.to_vec(),
        }
    }

    #[test]
    fn get_returns_an_inserted_entry() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();

        assert_eq!(cache.get("missing", t0), None);

        cache.insert("key".to_string(), entry(b"hello"), t0);
        let hit = cache.get("key", t0).expect("entry should be cached");
        assert_eq!(hit, entry(b"hello"));
    }

    #[test]
    fn entry_expires_exactly_at_the_ttl() {
        let ttl = Duration::from_secs(10);
        let cache = Cache::new(1024, ttl);
        let t0 = Instant::now();
        cache.insert("key".to_string(), entry(b"body"), t0);

        let just_before = t0 + ttl - Duration::from_millis(1);
        assert!(cache.get("key", just_before).is_some());

        // Expiry is inclusive: a record at the TTL boundary is already stale.
        assert!(cache.get("key", t0 + ttl).is_none());
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn insert_replaces_a_key_without_double_counting() {
        let cache = Cache::new(100, Duration::from_secs(60));
        let t0 = Instant::now();

        cache.insert("key".to_string(), entry(b"first"), t0);
        assert_eq!(cache.stats(), (5, 1));

        cache.insert("key".to_string(), entry(b"second"), t0);
        assert_eq!(cache.stats(), (6, 1));
        assert_eq!(cache.get("key", t0), Some(entry(b"second")));

        cache.insert("key".to_string(), entry(b"x"), t0);
        assert_eq!(cache.stats(), (1, 1));
    }

    #[test]
    fn oldest_entries_are_evicted_when_over_budget() {
        let cache = Cache::new(10, Duration::from_secs(60));
        let t0 = Instant::now();

        cache.insert("a".to_string(), entry(b"aaaa"), t0);
        cache.insert(
            "b".to_string(),
            entry(b"bbbb"),
            t0 + Duration::from_millis(1),
        );
        cache.insert(
            "c".to_string(),
            entry(b"cccc"),
            t0 + Duration::from_millis(2),
        );
        // 12 bytes do not fit in 10, so "a" is evicted on this insert.
        assert_eq!(cache.stats(), (8, 2));
        assert!(cache.get("a", t0 + Duration::from_millis(2)).is_none());

        cache.insert(
            "d".to_string(),
            entry(b"dddd"),
            t0 + Duration::from_millis(3),
        );

        assert_eq!(cache.stats(), (8, 2));
        assert!(cache.get("b", t0 + Duration::from_millis(3)).is_none());
        assert!(cache.get("c", t0 + Duration::from_millis(3)).is_some());
        assert!(cache.get("d", t0 + Duration::from_millis(3)).is_some());
    }

    #[test]
    fn equal_timestamps_fall_back_to_insertion_order() {
        let cache = Cache::new(4, Duration::from_secs(60));
        let t0 = Instant::now();

        // All three share one timestamp; the sequence number keeps eviction
        // deterministic instead of following hash order.
        cache.insert("a".to_string(), entry(b"aa"), t0);
        cache.insert("b".to_string(), entry(b"bb"), t0);
        cache.insert("c".to_string(), entry(b"cc"), t0);

        assert_eq!(cache.stats(), (4, 2));
        assert!(cache.get("a", t0).is_none());
        assert!(cache.get("b", t0).is_some());
        assert!(cache.get("c", t0).is_some());
    }

    #[test]
    fn insert_purges_expired_entries_even_with_free_space() {
        let ttl = Duration::from_secs(10);
        let cache = Cache::new(100, ttl);
        let t0 = Instant::now();

        cache.insert("old".to_string(), entry(b"12345678"), t0);

        // The new body fits easily, so only the explicit purge can remove the
        // expired record. It must not linger until its key is requested again.
        let later = t0 + ttl;
        cache.insert("new".to_string(), entry(b"abcd"), later);

        assert_eq!(cache.stats(), (4, 1));
        assert!(cache.get("old", later).is_none());
        assert!(cache.get("new", later).is_some());
    }

    #[test]
    fn bodies_larger_than_the_budget_are_rejected() {
        let cache = Cache::new(8, Duration::from_secs(60));
        let t0 = Instant::now();

        cache.insert("big".to_string(), entry(b"123456789"), t0);
        assert_eq!(cache.stats(), (0, 0));
        assert!(cache.get("big", t0).is_none());

        // Exactly the budget is allowed, and nothing is evicted for it.
        cache.insert("exact".to_string(), entry(b"12345678"), t0);
        assert_eq!(cache.stats(), (8, 1));
        assert!(cache.get("exact", t0).is_some());
    }

    #[test]
    fn oversized_insert_keeps_existing_entries() {
        let cache = Cache::new(8, Duration::from_secs(60));
        let t0 = Instant::now();

        cache.insert("small".to_string(), entry(b"1234"), t0);
        cache.insert("big".to_string(), entry(b"123456789"), t0);

        assert_eq!(cache.stats(), (4, 1));
        assert!(cache.get("small", t0).is_some());
    }

    #[test]
    fn zero_budget_disables_the_cache() {
        let cache = Cache::new(0, Duration::from_secs(60));
        let t0 = Instant::now();

        // Even an empty body, whose size fits any budget, must not be stored.
        cache.insert("key".to_string(), entry(b""), t0);
        cache.insert("key".to_string(), entry(b"body"), t0);
        assert_eq!(cache.stats(), (0, 0));
        assert!(cache.get("key", t0).is_none());
    }

    #[test]
    fn stats_track_bytes_and_entries() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();

        assert_eq!(cache.stats(), (0, 0));
        cache.insert("a".to_string(), entry(b"123"), t0);
        cache.insert("b".to_string(), entry(b"45678"), t0);
        assert_eq!(cache.stats(), (8, 2));

        cache.insert("a".to_string(), entry(b""), t0);
        assert_eq!(cache.stats(), (5, 2));
    }

    #[test]
    fn default_uses_a_large_budget_and_one_minute_ttl() {
        let cache = Cache::default();
        let t0 = Instant::now();
        cache.insert("key".to_string(), entry(b"body"), t0);

        assert_eq!(cache.stats(), (4, 1));
        assert!(cache
            .get("key", t0 + DEFAULT_TTL - Duration::from_millis(1))
            .is_some());
        assert!(cache.get("key", t0 + DEFAULT_TTL).is_none());
    }
}
