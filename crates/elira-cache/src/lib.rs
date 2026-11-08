//! In-memory response cache shared by every client of the proxy.
//!
//! The cache is keyed by host and path. Because several users can read the
//! same stored response, anything user-specific must be kept out: requests
//! carrying credentials are never stored or served, and responses marked
//! private are rejected. `Vary` is honoured so a response negotiated for one
//! request representation is not replayed for another.
//!
//! Bodies are bounded by a byte budget rather than an entry count, since
//! response sizes vary by orders of magnitude. Time is supplied by the caller
//! so expiry is testable without sleeping.
//!
//! One mutex guards the store and no lock is held across an await. `get`
//! clones the entry so the caller can work with the body after the lock is
//! released.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, COOKIE, SET_COOKIE, VARY,
};
use http::{HeaderMap, HeaderName};

/// Default body budget: enough to hold a working set of small API responses
/// without threatening a container's memory limit.
const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Default lifetime. One minute keeps a hot upstream from seeing every request
/// while still tracking content that changes on human timescales.
const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// A cached response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// When the response entered the cache. Used for expiry and `Age`.
    stored_at: Instant,
    /// Lifetime derived from the response's `Cache-Control`, capped by the
    /// cache-wide default.
    ttl: Duration,
    /// Request header values selected by the response's `Vary` header. A
    /// missing request header is recorded as `None`, which must only match
    /// another missing header.
    vary: Vec<(HeaderName, Option<Vec<u8>>)>,
}

impl Entry {
    /// Whole seconds since insertion, suitable for the `Age` header.
    pub fn age(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.stored_at).as_secs()
    }

    fn is_fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.stored_at) < self.ttl
    }

    fn matches(&self, request: &HeaderMap) -> bool {
        self.vary
            .iter()
            .all(|(name, stored)| combined_value(request, name) == *stored)
    }
}

struct Record {
    entry: Entry,
    /// Tie-breaker for entries inserted at the same `Instant`. Without it,
    /// eviction between equal timestamps would follow hash order and depend
    /// on the hasher seed.
    seq: u64,
}

struct Store {
    /// One key holds one entry per distinct `Vary` signature. Without this,
    /// the second language or encoding would evict the first.
    entries: HashMap<String, Vec<Record>>,
    total_bytes: usize,
    next_seq: u64,
}

impl Store {
    /// Reclaims space held by responses whose lifetime is over, even when
    /// their keys are never looked up again.
    fn purge_expired(&mut self, now: Instant) {
        let mut freed = 0;
        self.entries.retain(|_, records| {
            let before = records.len();
            records.retain(|record| {
                if record.entry.is_fresh(now) {
                    true
                } else {
                    freed += record.entry.body.len();
                    false
                }
            });
            let _ = before;
            !records.is_empty()
        });
        self.total_bytes -= freed;
    }

    fn len(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    /// Entry inserted longest ago, with the index of its variant.
    fn oldest(&self) -> Option<(String, usize)> {
        self.entries
            .iter()
            .flat_map(|(key, records)| {
                records
                    .iter()
                    .enumerate()
                    .map(move |(index, record)| (key, index, record))
            })
            .min_by_key(|(_, _, record)| (record.entry.stored_at, record.seq))
            .map(|(key, index, _)| (key.clone(), index))
    }
}

/// Response cache with a byte budget and a default lifetime.
///
/// A `max_bytes` of zero disables the cache: reads miss and writes are
/// rejected without allocating.
pub struct Cache {
    max_bytes: usize,
    default_ttl: Duration,
    store: Mutex<Store>,
}

impl Cache {
    /// Creates a cache holding at most `max_bytes` of response bodies. A
    /// response may live up to `default_ttl`; its own `Cache-Control` can
    /// only shorten that.
    pub fn new(max_bytes: usize, default_ttl: Duration) -> Self {
        Self {
            max_bytes,
            default_ttl,
            store: Mutex::new(Store {
                entries: HashMap::new(),
                total_bytes: 0,
                next_seq: 0,
            }),
        }
    }

    /// Looks up a stored response. `key` is host plus path; `request` supplies
    /// the header values that the stored `Vary` fields are checked against.
    ///
    /// Returns `None` for a stale entry, a `Vary` mismatch, or a request that
    /// must not share a cache at all.
    pub fn get(&self, key: &str, request: &HeaderMap, now: Instant) -> Option<Entry> {
        if self.max_bytes == 0 || is_sensitive(request) {
            return None;
        }

        let mut store = self.lock();

        // Take the variants out so the borrow ends before the accounting
        // update and before the entry may be put back.
        let mut records = store.entries.remove(key)?;
        let mut stale_bytes = 0;
        records.retain(|record| {
            if record.entry.is_fresh(now) {
                true
            } else {
                stale_bytes += record.entry.body.len();
                false
            }
        });
        store.total_bytes = store.total_bytes.saturating_sub(stale_bytes);

        let found = records
            .iter()
            .find(|record| record.entry.matches(request))
            .map(|record| record.entry.clone());

        if !records.is_empty() {
            store.entries.insert(key.to_owned(), records);
        }
        found
    }

    /// Stores a response when its headers allow sharing.
    ///
    /// `key` is host plus path. Returns `true` when the response was stored.
    /// A response that is already stale, cannot be shared, or is larger than
    /// the whole budget is rejected.
    pub fn insert(
        &self,
        key: &str,
        request: &HeaderMap,
        response: &HeaderMap,
        status: u16,
        body: Vec<u8>,
        now: Instant,
    ) -> bool {
        if self.max_bytes == 0
            || is_sensitive(request)
            || stores_cookies(response)
            || body.len() > self.max_bytes
        {
            return false;
        }

        let Some(ttl) = response_ttl(response, self.default_ttl) else {
            return false;
        };
        let Some(vary_fields) = vary_fields(response) else {
            return false;
        };

        let vary = vary_fields
            .into_iter()
            .map(|name| {
                let value = combined_value(request, &name);
                (name, value)
            })
            .collect();
        let entry = Entry {
            status,
            headers: stored_headers(response),
            body,
            stored_at: now,
            ttl,
            vary,
        };
        let body_len = entry.body.len();

        let mut store = self.lock();
        store.purge_expired(now);

        // Replace only the variant with the same Vary signature. Other
        // languages or encodings stay valid.
        if let Some(records) = store.entries.get_mut(key) {
            if let Some(index) = records
                .iter()
                .position(|record| record.entry.vary == entry.vary)
            {
                let previous = records.remove(index);
                store.total_bytes -= previous.entry.body.len();
            }
        }

        // Evict oldest first until the new body fits. The strict comparison
        // keeps a body that exactly fills the budget.
        while store.total_bytes.saturating_add(body_len) > self.max_bytes {
            let Some((key, index)) = store.oldest() else {
                // Unreachable while the size check above accepts the body, but
                // returning beats panicking on an accounting bug.
                return false;
            };
            let victim = match store.entries.get_mut(&key) {
                Some(records) if index < records.len() => records.remove(index),
                _ => continue,
            };
            store.total_bytes -= victim.entry.body.len();
            if store
                .entries
                .get(&key)
                .map(|records| records.is_empty())
                .unwrap_or(false)
            {
                store.entries.remove(&key);
            }
        }

        let seq = store.next_seq;
        store.next_seq = store.next_seq.wrapping_add(1);
        store.total_bytes += body_len;
        store
            .entries
            .entry(key.to_owned())
            .or_default()
            .push(Record { entry, seq });
        true
    }

    /// Drops every stored response.
    pub fn purge(&self) {
        let mut store = self.lock();
        store.entries.clear();
        store.total_bytes = 0;
    }

    /// Total body bytes and entry count currently held. Both are zero when the
    /// cache is disabled.
    pub fn stats(&self) -> (usize, usize) {
        let store = self.lock();
        (store.total_bytes, store.len())
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
            .field("default_ttl", &self.default_ttl)
            .field("bytes", &bytes)
            .field("entries", &entries)
            .finish()
    }
}

/// Requests carrying credentials cannot share a cache entry with anyone. The
/// cache does not know whether two requests share an identity, so the only
/// safe answer is to bypass it entirely.
fn is_sensitive(request: &HeaderMap) -> bool {
    request.contains_key(AUTHORIZATION) || request.contains_key(COOKIE)
}

/// Lifetime for a response, or `None` when it must not be stored.
///
/// `s-maxage` takes precedence over `max-age` because this is a shared cache.
/// Both are capped by the cache-wide default so a misconfigured upstream
/// cannot pin content in memory indefinitely.
fn response_ttl(response: &HeaderMap, default_ttl: Duration) -> Option<Duration> {
    let control = CacheControl::parse(response);
    if control.no_store || control.private || control.no_cache || control.unparsable {
        return None;
    }

    let ttl = control
        .s_maxage
        .or(control.max_age)
        .map(Duration::from_secs)
        .unwrap_or(default_ttl)
        .min(default_ttl);

    // A zero lifetime means the response is stale on arrival; storing it only
    // wastes budget.
    if ttl.is_zero() {
        None
    } else {
        Some(ttl)
    }
}

#[derive(Default)]
struct CacheControl {
    no_store: bool,
    private: bool,
    no_cache: bool,
    s_maxage: Option<u64>,
    max_age: Option<u64>,
    /// A header value that is not valid UTF-8 cannot be inspected reliably.
    /// Treat it as unstoreable rather than risk missing `no-store`.
    unparsable: bool,
}

impl CacheControl {
    /// Parses all `Cache-Control` header lines. Directive names are
    /// case-insensitive; values are trimmed of quotes so `"60"` works like
    /// `60`.
    fn parse(response: &HeaderMap) -> Self {
        let mut control = Self::default();

        for value in response.get_all(CACHE_CONTROL) {
            let Ok(text) = value.to_str() else {
                control.unparsable = true;
                continue;
            };
            for directive in text.split(',') {
                let directive = directive.trim();
                if directive.is_empty() {
                    continue;
                }

                let (name, value) = match directive.split_once('=') {
                    Some((name, value)) => (name.trim(), Some(value.trim().trim_matches('"'))),
                    None => (directive, None),
                };

                if name.eq_ignore_ascii_case("no-store") {
                    control.no_store = true;
                } else if name.eq_ignore_ascii_case("private") {
                    control.private = true;
                } else if name.eq_ignore_ascii_case("no-cache") {
                    control.no_cache = true;
                } else if name.eq_ignore_ascii_case("s-maxage") {
                    control.s_maxage = value.and_then(|value| value.parse().ok());
                } else if name.eq_ignore_ascii_case("max-age") {
                    control.max_age = value.and_then(|value| value.parse().ok());
                }
            }
        }

        control
    }
}

/// Header names listed by every `Vary` line, or `None` when the response
/// cannot be stored.
///
/// `Vary: *` makes the response unmatchable and therefore unstoreable. A
/// non-UTF-8 or syntactically invalid field name is treated the same way
/// rather than guessed at.
fn vary_fields(response: &HeaderMap) -> Option<Vec<HeaderName>> {
    let mut fields: Vec<HeaderName> = Vec::new();

    for value in response.get_all(VARY) {
        let text = value.to_str().ok()?;
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if token == "*" {
                return None;
            }
            let name = HeaderName::from_bytes(token.as_bytes()).ok()?;
            if !fields.contains(&name) {
                fields.push(name);
            }
        }
    }

    Some(fields)
}

/// All values of `name` joined with `, `, or `None` when the header is absent.
///
/// Joining makes a single `Accept-Encoding: gzip, br` header compare equal to
/// two separate header lines, as HTTP field combination requires.
fn combined_value(headers: &HeaderMap, name: &HeaderName) -> Option<Vec<u8>> {
    let mut combined: Option<Vec<u8>> = None;

    for value in headers.get_all(name) {
        match &mut combined {
            Some(existing) => {
                existing.extend_from_slice(b", ");
                existing.extend_from_slice(value.as_bytes());
            }
            None => combined = Some(value.as_bytes().to_vec()),
        }
    }

    combined
}

/// Copies the response headers into the representation the proxy rebuilds
/// from.
///
/// Framing and connection metadata describe the upstream exchange, not the
/// cached body, so replaying them would corrupt the next response. `Age` is
/// dropped because the cache computes its own from `stored_at`.
fn stored_headers(response: &HeaderMap) -> Vec<(String, String)> {
    let mut connection_names: Vec<String> = Vec::new();
    for value in response.get_all(CONNECTION) {
        if let Ok(text) = value.to_str() {
            connection_names.extend(
                text.split(',')
                    .map(|token| token.trim().to_ascii_lowercase())
                    .filter(|token| !token.is_empty()),
            );
        }
    }

    response
        .iter()
        .filter(|(name, _)| {
            !is_hop_by_hop(name)
                && **name != CONTENT_LENGTH
                && name.as_str() != "age"
                && !connection_names
                    .iter()
                    .any(|listed| listed == name.as_str())
        })
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// A response carrying `Set-Cookie` is tied to one client and must never be
/// replayed from a shared cache.
fn stores_cookies(response: &HeaderMap) -> bool {
    response.contains_key(SET_COOKIE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn response(cache_control: Option<&str>) -> HeaderMap {
        match cache_control {
            Some(value) => headers(&[("cache-control", value)]),
            None => HeaderMap::new(),
        }
    }

    fn store(
        cache: &Cache,
        key: &str,
        request: &HeaderMap,
        response: &HeaderMap,
        body: &[u8],
        now: Instant,
    ) -> bool {
        cache.insert(key, request, response, 200, body.to_vec(), now)
    }

    #[test]
    fn get_returns_an_inserted_entry() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=30"));

        assert!(store(&cache, "key", &request, &response, b"hello", t0));
        let hit = cache
            .get("key", &request, t0)
            .expect("entry should be cached");
        assert_eq!(hit.status, 200);
        assert_eq!(hit.body, b"hello");
        assert_eq!(
            hit.headers,
            vec![("cache-control".to_owned(), "max-age=30".to_owned())]
        );
    }

    #[test]
    fn no_store_is_not_cached() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();

        assert!(!store(
            &cache,
            "key",
            &request,
            &response(Some("no-store, max-age=60")),
            b"secret",
            t0
        ));
        assert!(cache.get("key", &request, t0).is_none());
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn private_is_not_cached() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();

        assert!(!store(
            &cache,
            "key",
            &request,
            &response(Some("Private")),
            b"secret",
            t0
        ));
        assert!(cache.get("key", &request, t0).is_none());
    }

    #[test]
    fn no_cache_is_not_cached() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();

        assert!(!store(
            &cache,
            "key",
            &request,
            &response(Some("no-cache")),
            b"body",
            t0
        ));
        assert!(cache.get("key", &request, t0).is_none());
    }

    #[test]
    fn non_utf8_cache_control_is_not_cached() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let mut response = HeaderMap::new();
        // A value that cannot be decoded could still hide `no-store`, so the
        // response must not be admitted.
        response.insert(
            CACHE_CONTROL,
            HeaderValue::from_bytes(b"max-age=60\xff").unwrap(),
        );

        assert!(!store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache.get("key", &request, t0).is_none());
    }

    #[test]
    fn authorization_bypasses_the_cache() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let anonymous = HeaderMap::new();
        let authorized = headers(&[("authorization", "Bearer token")]);

        assert!(store(
            &cache,
            "key",
            &anonymous,
            &response(Some("max-age=60")),
            b"body",
            t0
        ));
        // Reads carrying credentials must never see a stored response, even
        // one inserted anonymously.
        assert!(cache.get("key", &authorized, t0).is_none());

        // And a credentialed request must not create an entry for others.
        assert!(!store(
            &cache,
            "other",
            &authorized,
            &response(Some("max-age=60")),
            b"body",
            t0
        ));
        assert!(cache.get("other", &anonymous, t0).is_none());
    }

    #[test]
    fn cookie_bypasses_the_cache() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let anonymous = HeaderMap::new();
        let with_cookie = headers(&[("cookie", "session=abc")]);

        assert!(store(
            &cache,
            "key",
            &anonymous,
            &response(Some("max-age=60")),
            b"body",
            t0
        ));
        assert!(cache.get("key", &with_cookie, t0).is_none());
        assert!(!store(
            &cache,
            "other",
            &with_cookie,
            &response(Some("max-age=60")),
            b"body",
            t0
        ));
    }

    #[test]
    fn set_cookie_responses_are_not_cached() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = headers(&[
            ("cache-control", "max-age=60"),
            ("set-cookie", "session=abc"),
        ]);

        assert!(!store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache.get("key", &request, t0).is_none());
    }

    #[test]
    fn max_age_shorter_than_default_expires_early() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=5"));

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache
            .get("key", &request, t0 + Duration::from_secs(4))
            .is_some());
        // Expiry is inclusive at the TTL boundary.
        assert!(cache
            .get("key", &request, t0 + Duration::from_secs(5))
            .is_none());
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn max_age_longer_than_default_is_capped() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=3600"));

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache
            .get("key", &request, t0 + Duration::from_secs(59))
            .is_some());
        assert!(cache
            .get("key", &request, t0 + Duration::from_secs(60))
            .is_none());
    }

    #[test]
    fn s_maxage_wins_over_max_age() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=100, s-maxage=5"));

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache
            .get("key", &request, t0 + Duration::from_secs(4))
            .is_some());
        assert!(cache
            .get("key", &request, t0 + Duration::from_secs(5))
            .is_none());
    }

    #[test]
    fn cache_control_names_and_values_are_case_insensitive() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("S-MAXAGE=\"5\", Max-Age=100"));

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache
            .get("key", &request, t0 + Duration::from_secs(4))
            .is_some());
        assert!(cache
            .get("key", &request, t0 + Duration::from_secs(5))
            .is_none());
    }

    #[test]
    fn vary_match_is_required() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let gzip = headers(&[("accept-encoding", "gzip")]);
        let br = headers(&[("accept-encoding", "br")]);
        let response = headers(&[("cache-control", "max-age=60"), ("vary", "accept-encoding")]);

        assert!(store(&cache, "key", &gzip, &response, b"gzipped", t0));
        let hit = cache.get("key", &gzip, t0).expect("matching variant");
        assert_eq!(hit.body, b"gzipped");

        // A different representation must not receive the stored body.
        assert!(cache.get("key", &br, t0).is_none());
    }

    #[test]
    fn vary_missing_matches_only_missing() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let absent = HeaderMap::new();
        let present = headers(&[("accept-encoding", "gzip")]);
        let response = headers(&[("cache-control", "max-age=60"), ("vary", "accept-encoding")]);

        assert!(store(&cache, "key", &absent, &response, b"plain", t0));
        assert!(cache.get("key", &absent, t0).is_some());
        assert!(cache.get("key", &present, t0).is_none());
    }

    #[test]
    fn vary_star_is_not_cached() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = headers(&[
            ("cache-control", "max-age=60"),
            ("vary", "accept-encoding, *"),
        ]);

        assert!(!store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache.get("key", &request, t0).is_none());
    }

    #[test]
    fn multiple_vary_fields_must_all_match() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = headers(&[("accept-encoding", "gzip"), ("accept-language", "en")]);
        let wrong_language = headers(&[("accept-encoding", "gzip"), ("accept-language", "fr")]);
        let response = headers(&[
            ("cache-control", "max-age=60"),
            ("vary", "accept-encoding, accept-language"),
        ]);

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache.get("key", &request, t0).is_some());
        assert!(cache.get("key", &wrong_language, t0).is_none());
    }

    #[test]
    fn vary_combined_header_lines_are_equivalent_to_one_line() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = headers(&[("accept-encoding", "gzip, br")]);
        let split = headers(&[("accept-encoding", "gzip"), ("accept-encoding", "br")]);
        let response = headers(&[("cache-control", "max-age=60"), ("vary", "accept-encoding")]);

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache.get("key", &split, t0).is_some());
    }

    #[test]
    fn oldest_entries_are_evicted_to_make_room() {
        let cache = Cache::new(10, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=60"));

        assert!(store(&cache, "a", &request, &response, b"aaaa", t0));
        assert!(store(
            &cache,
            "b",
            &request,
            &response,
            b"bbbb",
            t0 + Duration::from_millis(1)
        ));
        // 12 bytes cannot fit in 10, so "a" is evicted by this insert.
        assert!(store(
            &cache,
            "c",
            &request,
            &response,
            b"cccc",
            t0 + Duration::from_millis(2)
        ));

        assert_eq!(cache.stats(), (8, 2));
        assert!(cache
            .get("a", &request, t0 + Duration::from_millis(2))
            .is_none());
        assert!(cache
            .get("b", &request, t0 + Duration::from_millis(2))
            .is_some());
        assert!(cache
            .get("c", &request, t0 + Duration::from_millis(2))
            .is_some());
    }

    #[test]
    fn equal_timestamps_fall_back_to_insertion_order() {
        let cache = Cache::new(4, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=60"));

        // All three share one timestamp; the sequence number keeps eviction
        // deterministic instead of following hash order.
        assert!(store(&cache, "a", &request, &response, b"aa", t0));
        assert!(store(&cache, "b", &request, &response, b"bb", t0));
        assert!(store(&cache, "c", &request, &response, b"cc", t0));

        assert_eq!(cache.stats(), (4, 2));
        assert!(cache.get("a", &request, t0).is_none());
        assert!(cache.get("b", &request, t0).is_some());
        assert!(cache.get("c", &request, t0).is_some());
    }

    #[test]
    fn bodies_larger_than_the_budget_are_rejected() {
        let cache = Cache::new(8, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=60"));

        assert!(!store(&cache, "big", &request, &response, b"123456789", t0));
        assert_eq!(cache.stats(), (0, 0));

        // Exactly the budget is allowed.
        assert!(store(&cache, "exact", &request, &response, b"12345678", t0));
        assert_eq!(cache.stats(), (8, 1));
    }

    #[test]
    fn replacing_a_key_does_not_double_count() {
        let cache = Cache::new(100, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=60"));

        assert!(store(&cache, "key", &request, &response, b"first", t0));
        assert_eq!(cache.stats(), (5, 1));
        assert!(store(&cache, "key", &request, &response, b"second", t0));
        assert_eq!(cache.stats(), (6, 1));
        assert_eq!(
            cache.get("key", &request, t0).map(|entry| entry.body),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn zero_budget_disables_the_cache() {
        let cache = Cache::new(0, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=60"));

        assert!(!store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache.get("key", &request, t0).is_none());
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn stale_entry_is_dropped_on_read() {
        let ttl = Duration::from_secs(10);
        let cache = Cache::new(1024, ttl);
        let t0 = Instant::now();
        let request = HeaderMap::new();
        // No Cache-Control means the cache-wide default applies.
        let response = HeaderMap::new();

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache
            .get("key", &request, t0 + ttl - Duration::from_millis(1))
            .is_some());
        assert!(cache.get("key", &request, t0 + ttl).is_none());
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn insert_purges_expired_entries() {
        let ttl = Duration::from_secs(10);
        let cache = Cache::new(100, ttl);
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = HeaderMap::new();

        assert!(store(&cache, "old", &request, &response, b"12345678", t0));
        // The new body fits easily, so only the explicit purge can remove the
        // expired record.
        let later = t0 + ttl;
        assert!(store(&cache, "new", &request, &response, b"abcd", later));

        assert_eq!(cache.stats(), (4, 1));
        assert!(cache.get("old", &request, later).is_none());
        assert!(cache.get("new", &request, later).is_some());
    }

    #[test]
    fn purge_drops_everything() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=60"));

        assert!(store(&cache, "a", &request, &response, b"one", t0));
        assert!(store(&cache, "b", &request, &response, b"two", t0));
        assert_eq!(cache.stats(), (6, 2));

        cache.purge();
        assert_eq!(cache.stats(), (0, 0));
        assert!(cache.get("a", &request, t0).is_none());
        assert!(cache.get("b", &request, t0).is_none());
    }

    #[test]
    fn age_counts_seconds_since_insertion() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = response(Some("max-age=60"));

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        let entry = cache.get("key", &request, t0).unwrap();
        assert_eq!(entry.age(t0), 0);
        assert_eq!(entry.age(t0 + Duration::from_millis(1500)), 1);
        assert_eq!(entry.age(t0 + Duration::from_secs(30)), 30);
    }

    #[test]
    fn default_uses_the_configured_budget_and_ttl() {
        let cache = Cache::default();
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = HeaderMap::new();

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        assert!(cache
            .get("key", &request, t0 + DEFAULT_TTL - Duration::from_millis(1))
            .is_some());
        assert!(cache.get("key", &request, t0 + DEFAULT_TTL).is_none());
    }

    #[test]
    fn zero_max_age_is_not_stored() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();

        assert!(!store(
            &cache,
            "key",
            &request,
            &response(Some("max-age=0")),
            b"body",
            t0
        ));
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn framing_and_connection_headers_are_not_stored() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let t0 = Instant::now();
        let request = HeaderMap::new();
        let response = headers(&[
            ("cache-control", "max-age=60"),
            ("content-type", "text/plain"),
            ("content-length", "4"),
            ("age", "12"),
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("x-keep", "yes"),
        ]);

        assert!(store(&cache, "key", &request, &response, b"body", t0));
        let entry = cache.get("key", &request, t0).unwrap();
        assert_eq!(
            entry.headers,
            vec![
                ("cache-control".to_owned(), "max-age=60".to_owned()),
                ("content-type".to_owned(), "text/plain".to_owned()),
                ("x-keep".to_owned(), "yes".to_owned()),
            ]
        );
    }

    #[test]
    fn keeps_each_vary_variant_under_one_key() {
        let cache = Cache::new(1024, Duration::from_secs(60));
        let now = Instant::now();

        let request = |language: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("accept-language", language.parse().unwrap());
            headers
        };
        let response = {
            let mut headers = HeaderMap::new();
            headers.insert("vary", "Accept-Language".parse().unwrap());
            headers
        };

        assert!(cache.insert(
            "example.com/",
            &request("en"),
            &response,
            200,
            b"hello".to_vec(),
            now,
        ));
        assert!(cache.insert(
            "example.com/",
            &request("de"),
            &response,
            200,
            b"hallo".to_vec(),
            now,
        ));

        assert_eq!(
            cache
                .get("example.com/", &request("en"), now)
                .map(|entry| entry.body),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            cache
                .get("example.com/", &request("de"), now)
                .map(|entry| entry.body),
            Some(b"hallo".to_vec())
        );
        assert_eq!(cache.stats(), (10, 2));
    }
}
