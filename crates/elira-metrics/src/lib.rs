//! Request metrics in the Prometheus text exposition format.
//!
//! Global values live in atomics so the request path records an outcome
//! without taking a lock or waiting for a scrape. Per-route and per-upstream
//! series need a short critical section around a [`BTreeMap`]; the number of
//! distinct labels is capped so untrusted names cannot grow it without bound.
//! [`Metrics::render`] snapshots everything into text; no state is reset by
//! rendering.
//!
//! Worker processes can move their counters with [`Metrics::take_delta`] and
//! merge them into an aggregate registry with [`Metrics::apply_delta`]. A
//! [`Delta`] is plain serde data, so it can be sent over an IPC channel or
//! serialised to JSON without exposing the atomics or the label maps.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

const STATUS_CLASSES: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];

/// Requests by status class for one label.
type LabeledRequests = Vec<(String, [u64; STATUS_CLASSES.len()])>;
/// Duration sums and counts for one label, as `(label, sum_nanos, count)`.
type LabeledDuration = Vec<(String, u64, u64)>;

/// Maximum number of distinct route or upstream labels kept in memory.
pub const MAX_LABELS: usize = 200;

struct Bucket {
    /// Upper bound in nanoseconds; comparing integers avoids float rounding.
    upper_nanos: u64,
    label: &'static str,
}

const BUCKETS: [Bucket; 12] = [
    Bucket {
        upper_nanos: 1_000_000,
        label: "0.001",
    },
    Bucket {
        upper_nanos: 5_000_000,
        label: "0.005",
    },
    Bucket {
        upper_nanos: 10_000_000,
        label: "0.01",
    },
    Bucket {
        upper_nanos: 25_000_000,
        label: "0.025",
    },
    Bucket {
        upper_nanos: 50_000_000,
        label: "0.05",
    },
    Bucket {
        upper_nanos: 100_000_000,
        label: "0.1",
    },
    Bucket {
        upper_nanos: 250_000_000,
        label: "0.25",
    },
    Bucket {
        upper_nanos: 500_000_000,
        label: "0.5",
    },
    Bucket {
        upper_nanos: 1_000_000_000,
        label: "1",
    },
    Bucket {
        upper_nanos: 2_500_000_000,
        label: "2.5",
    },
    Bucket {
        upper_nanos: 5_000_000_000,
        label: "5",
    },
    Bucket {
        upper_nanos: 10_000_000_000,
        label: "10",
    },
];

/// Counters for one route or upstream label.
#[derive(Debug, Default)]
struct Labeled {
    requests: [u64; STATUS_CLASSES.len()],
    duration_sum_nanos: u64,
    duration_count: u64,
}

impl Labeled {
    fn record(&mut self, status: u16, nanos: u64) {
        let class = status_class(status);
        self.requests[class] = self.requests[class].saturating_add(1);
        self.duration_sum_nanos = self.duration_sum_nanos.saturating_add(nanos);
        self.duration_count = self.duration_count.saturating_add(1);
    }

    fn merge(&mut self, other: &Labeled) {
        for (target, value) in self.requests.iter_mut().zip(&other.requests) {
            *target = target.saturating_add(*value);
        }
        self.duration_sum_nanos = self
            .duration_sum_nanos
            .saturating_add(other.duration_sum_nanos);
        self.duration_count = self.duration_count.saturating_add(other.duration_count);
    }

    fn is_empty(&self) -> bool {
        self.requests.iter().all(|&value| value == 0)
            && self.duration_sum_nanos == 0
            && self.duration_count == 0
    }
}

/// Counters and gauges moved between a worker and an aggregate registry.
///
/// A worker calls [`Metrics::take_delta`] to drain its counters into a
/// `Delta`, serialises it, and sends it to an aggregator. The aggregator calls
/// [`Metrics::apply_delta`] (or the split [`Metrics::apply_counters`] and
/// [`Metrics::apply_gauges`] methods) to merge it into its own registry.
///
/// Every counter field is a monotonic amount since the previous
/// `take_delta`, so applying two deltas in either order produces the same
/// counters. The three gauge fields describe the current state at the time of
/// the take and are never reset by it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Delta {
    /// Global requests by status class, indexed like `STATUS_CLASSES`.
    pub requests: [u64; STATUS_CLASSES.len()],
    /// Cumulative histogram bucket counts, in [`BUCKETS`] order.
    pub duration_buckets: Vec<u64>,
    /// Total observed request duration in nanoseconds.
    pub duration_sum_nanos: u64,
    /// Number of observed requests.
    pub duration_count: u64,
    /// Per-route requests by status class, sorted by route name.
    pub route_requests: Vec<(String, [u64; STATUS_CLASSES.len()])>,
    /// Per-route duration sums and counts, sorted by route name.
    ///
    /// Each entry is `(route, sum_nanos, count)`.
    pub route_duration: Vec<(String, u64, u64)>,
    /// Per-upstream requests by status class, sorted by upstream name.
    pub upstream_requests: Vec<(String, [u64; STATUS_CLASSES.len()])>,
    /// Per-upstream duration sums and counts, sorted by upstream name.
    ///
    /// Each entry is `(upstream, sum_nanos, count)`.
    pub upstream_duration: Vec<(String, u64, u64)>,
    /// Cache lookups that were hits.
    pub cache_hits: u64,
    /// Cache lookups that were misses.
    pub cache_misses: u64,
    pub cache_stale: u64,
    pub health_checks_ok: u64,
    pub health_checks_failed: u64,
    /// Request body bytes read from clients.
    pub request_bytes: u64,
    /// Response body bytes written to clients.
    pub response_bytes: u64,
    /// Successful configuration reloads.
    pub reloads_ok: u64,
    /// Failed configuration reloads.
    pub reloads_failed: u64,
    pub tls_handshakes_ok: u64,
    pub tls_handshakes_failed: u64,
    pub quic_connections: u64,
    /// Active upstream requests per pool, a snapshot.
    pub upstream_load: Vec<(String, u64)>,
    /// Certificate path -> Unix expiry seconds, a snapshot.
    pub certificate_expiry: Vec<(String, i64)>,
    /// Custom HTTP/2 pool: upstream -> (connections, active, total, queued).
    pub h2_pools: Vec<(String, u64, u64, u64, u64)>,
    /// Custom HTTP/3 pool: upstream -> (connections, active, total).
    pub h3_pools: Vec<(String, u64, u64, u64)>,
    /// Current connections in flight, not a delta.
    pub connections_in_flight: u64,
    /// Current upstreams considered healthy, not a delta.
    pub upstreams_up: u64,
    /// Current upstreams considered unhealthy, not a delta.
    pub upstreams_down: u64,
}

impl Delta {
    /// Return `true` when this delta carries no counters and all gauges are
    /// zero.
    ///
    /// Useful for skipping an empty inter-process message. A delta produced by
    /// [`Metrics::take_delta`] always has a full-length
    /// `duration_buckets` vector, so an empty one still contains zeros.
    pub fn is_empty(&self) -> bool {
        self.requests.iter().all(|&value| value == 0)
            && self.duration_buckets.iter().all(|&value| value == 0)
            && self.duration_sum_nanos == 0
            && self.duration_count == 0
            && self
                .route_requests
                .iter()
                .all(|(_, counts)| counts.iter().all(|&value| value == 0))
            && self
                .route_duration
                .iter()
                .all(|(_, sum, count)| *sum == 0 && *count == 0)
            && self
                .upstream_requests
                .iter()
                .all(|(_, counts)| counts.iter().all(|&value| value == 0))
            && self
                .upstream_duration
                .iter()
                .all(|(_, sum, count)| *sum == 0 && *count == 0)
            && self.cache_hits == 0
            && self.cache_misses == 0
            && self.cache_stale == 0
            && self.health_checks_ok == 0
            && self.health_checks_failed == 0
            && self.request_bytes == 0
            && self.response_bytes == 0
            && self.reloads_ok == 0
            && self.reloads_failed == 0
            && self.tls_handshakes_ok == 0
            && self.tls_handshakes_failed == 0
            && self.quic_connections == 0
            && self.connections_in_flight == 0
            && self.upstreams_up == 0
            && self.upstreams_down == 0
    }
}

/// Counters and gauges for a running proxy.
#[derive(Debug)]
pub struct Metrics {
    requests: [AtomicU64; STATUS_CLASSES.len()],
    duration_buckets: [AtomicU64; BUCKETS.len()],
    duration_sum_nanos: AtomicU64,
    duration_count: AtomicU64,
    connections_in_flight: AtomicU64,
    upstreams_up: AtomicUsize,
    upstreams_down: AtomicUsize,
    routes: Mutex<BTreeMap<String, Labeled>>,
    upstreams: Mutex<BTreeMap<String, Labeled>>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    cache_stale: AtomicU64,
    health_checks_ok: AtomicU64,
    health_checks_failed: AtomicU64,
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    reloads_ok: AtomicU64,
    reloads_failed: AtomicU64,
    tls_handshakes_ok: AtomicU64,
    tls_handshakes_failed: AtomicU64,
    quic_connections: AtomicU64,
    upstream_load: Mutex<BTreeMap<String, u64>>,
    certificate_expiry: Mutex<BTreeMap<String, i64>>,
    h2_pools: Mutex<BTreeMap<String, (u64, u64, u64, u64)>>,
    h3_pools: Mutex<BTreeMap<String, (u64, u64, u64)>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests: std::array::from_fn(|_| AtomicU64::new(0)),
            duration_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            duration_sum_nanos: AtomicU64::new(0),
            duration_count: AtomicU64::new(0),
            connections_in_flight: AtomicU64::new(0),
            upstreams_up: AtomicUsize::new(0),
            upstreams_down: AtomicUsize::new(0),
            routes: Mutex::new(BTreeMap::new()),
            upstreams: Mutex::new(BTreeMap::new()),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_stale: AtomicU64::new(0),
            health_checks_ok: AtomicU64::new(0),
            health_checks_failed: AtomicU64::new(0),
            request_bytes: AtomicU64::new(0),
            response_bytes: AtomicU64::new(0),
            reloads_ok: AtomicU64::new(0),
            reloads_failed: AtomicU64::new(0),
            tls_handshakes_ok: AtomicU64::new(0),
            tls_handshakes_failed: AtomicU64::new(0),
            quic_connections: AtomicU64::new(0),
            upstream_load: Mutex::new(BTreeMap::new()),
            certificate_expiry: Mutex::new(BTreeMap::new()),
            h2_pools: Mutex::new(BTreeMap::new()),
            h3_pools: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record one finished request.
    pub fn observe(&self, status: u16, duration: Duration) {
        self.requests[status_class(status)].fetch_add(1, Ordering::Relaxed);

        let nanos = nanos_of(duration);
        add_saturating(&self.duration_sum_nanos, nanos);

        // The count is bumped before the buckets so a scrape that reads the
        // buckets first and the count afterwards cannot report a bucket
        // larger than the total.
        self.duration_count.fetch_add(1, Ordering::Relaxed);
        for (bucket, counter) in BUCKETS.iter().zip(&self.duration_buckets) {
            if nanos <= bucket.upper_nanos {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record one finished request for the global status-class series.
    ///
    /// This is an alias for [`Metrics::observe`], kept for callers that prefer
    /// the explicit name now that labelled counters also exist.
    pub fn record_request(&self, status: u16, duration: Duration) {
        self.observe(status, duration);
    }

    /// Record one finished request for a configured route.
    ///
    /// `route` should be a bounded route name, not a raw `Host` header. At most
    /// [`MAX_LABELS`] distinct routes are tracked; further labels are dropped.
    pub fn record_route(&self, route: &str, status: u16, duration: Duration) {
        let nanos = nanos_of(duration);
        let mut routes = lock(&self.routes);
        record_labeled(&mut routes, route, status, nanos);
    }

    /// Record one finished request for an upstream.
    ///
    /// At most [`MAX_LABELS`] distinct upstreams are tracked; new labels are
    /// dropped once the cap is reached.
    pub fn record_upstream(&self, upstream: &str, status: u16, duration: Duration) {
        let nanos = nanos_of(duration);
        let mut upstreams = lock(&self.upstreams);
        record_labeled(&mut upstreams, upstream, status, nanos);
    }

    /// Record one cache hit.
    pub fn cache_hit(&self) {
        add_saturating(&self.cache_hits, 1);
    }

    /// Record one cache miss.
    pub fn cache_miss(&self) {
        add_saturating(&self.cache_misses, 1);
    }

    /// Record one stale cache hit.
    pub fn cache_stale(&self) {
        add_saturating(&self.cache_stale, 1);
    }

    /// Record one upstream health probe.
    pub fn health_check(&self, ok: bool) {
        if ok {
            add_saturating(&self.health_checks_ok, 1);
        } else {
            add_saturating(&self.health_checks_failed, 1);
        }
    }

    /// Record request body bytes read from clients.
    pub fn request_bytes(&self, bytes: u64) {
        add_saturating(&self.request_bytes, bytes);
    }

    /// Record response body bytes written to clients.
    pub fn response_bytes(&self, bytes: u64) {
        add_saturating(&self.response_bytes, bytes);
    }

    /// Record a successful configuration reload.
    pub fn reload_ok(&self) {
        add_saturating(&self.reloads_ok, 1);
    }

    /// Record a failed configuration reload.
    /// Record a TLS handshake outcome.
    pub fn tls_handshake(&self, ok: bool) {
        let counter = if ok {
            &self.tls_handshakes_ok
        } else {
            &self.tls_handshakes_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an accepted QUIC connection.
    pub fn quic_connection(&self) {
        self.quic_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Replace the active-request gauge for one upstream pool.
    /// Record the Unix expiry timestamp of a certificate file.
    pub fn set_certificate_expiry(&self, path: &str, expires: i64) {
        self.certificate_expiry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(path.to_owned(), expires);
    }

    /// Replace the custom HTTP/2 pool gauges for one upstream.
    pub fn set_h2_pool(
        &self,
        upstream: &str,
        connections: u64,
        active: u64,
        total: u64,
        queued: u64,
    ) {
        self.h2_pools
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(upstream.to_owned(), (connections, active, total, queued));
    }

    /// Replace the custom HTTP/3 pool gauges for one upstream.
    pub fn set_h3_pool(&self, upstream: &str, connections: u64, active: u64, total: u64) {
        self.h3_pools
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(upstream.to_owned(), (connections, active, total));
    }

    pub fn set_upstream_load(&self, upstream: &str, active: u64) {
        self.upstream_load
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(upstream.to_owned(), active);
    }

    pub fn reload_failed(&self) {
        add_saturating(&self.reloads_failed, 1);
    }

    /// Mark one client connection as open.
    pub fn connection_started(&self) {
        self.connections_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Mark one client connection as closed.
    pub fn connection_finished(&self) {
        // A mismatched finish must not wrap the gauge around to a huge value.
        let _ = self.connections_in_flight.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(1)),
        );
    }

    /// Replace the upstream health gauges.
    pub fn set_upstreams(&self, up: usize, down: usize) {
        self.upstreams_up.store(up, Ordering::Relaxed);
        self.upstreams_down.store(down, Ordering::Relaxed);
    }

    /// Replace the in-flight connection gauge.
    ///
    /// This is the gauge counterpart of [`Metrics::connection_started`] and
    /// [`Metrics::connection_finished`]. It is mainly used by aggregators when
    /// applying a [`Delta`], where the value is a snapshot from another
    /// process rather than a local increment.
    pub fn connection_set(&self, in_flight: u64) {
        self.connections_in_flight
            .store(in_flight, Ordering::Relaxed);
    }

    /// Drain every counter into a [`Delta`] and reset it to zero.
    ///
    /// Each counter is cleared with an atomic swap, so every individual
    /// counter increment lands in exactly one delta, never in both and never
    /// lost. A single request updates several counters and the label maps
    /// separately, so a take racing with an observation can split that
    /// observation's contributions across two deltas; the running totals stay
    /// correct. Per-label maps are swapped out under their mutex and copied in
    /// name order, which makes the result deterministic.
    ///
    /// Gauges are copied but deliberately not reset: they describe current
    /// state rather than an amount since the last take.
    pub fn take_delta(&self) -> Delta {
        let requests = std::array::from_fn(|index| self.requests[index].swap(0, Ordering::Relaxed));
        let duration_buckets = self
            .duration_buckets
            .iter()
            .map(|counter| counter.swap(0, Ordering::Relaxed))
            .collect();
        let duration_sum_nanos = self.duration_sum_nanos.swap(0, Ordering::Relaxed);
        let duration_count = self.duration_count.swap(0, Ordering::Relaxed);
        let (route_requests, route_duration) = take_labeled(&self.routes);
        let (upstream_requests, upstream_duration) = take_labeled(&self.upstreams);

        Delta {
            requests,
            duration_buckets,
            duration_sum_nanos,
            duration_count,
            route_requests,
            route_duration,
            upstream_requests,
            upstream_duration,
            cache_hits: self.cache_hits.swap(0, Ordering::Relaxed),
            cache_misses: self.cache_misses.swap(0, Ordering::Relaxed),
            cache_stale: self.cache_stale.swap(0, Ordering::Relaxed),
            health_checks_ok: self.health_checks_ok.swap(0, Ordering::Relaxed),
            health_checks_failed: self.health_checks_failed.swap(0, Ordering::Relaxed),
            request_bytes: self.request_bytes.swap(0, Ordering::Relaxed),
            response_bytes: self.response_bytes.swap(0, Ordering::Relaxed),
            reloads_ok: self.reloads_ok.swap(0, Ordering::Relaxed),
            reloads_failed: self.reloads_failed.swap(0, Ordering::Relaxed),
            tls_handshakes_ok: self.tls_handshakes_ok.swap(0, Ordering::Relaxed),
            tls_handshakes_failed: self.tls_handshakes_failed.swap(0, Ordering::Relaxed),
            quic_connections: self.quic_connections.swap(0, Ordering::Relaxed),
            upstream_load: self
                .upstream_load
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .map(|(name, active)| (name.clone(), *active))
                .collect(),
            certificate_expiry: self
                .certificate_expiry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .map(|(path, expires)| (path.clone(), *expires))
                .collect(),
            h2_pools: self
                .h2_pools
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .map(|(name, (a, b, c, d))| (name.clone(), *a, *b, *c, *d))
                .collect(),
            h3_pools: self
                .h3_pools
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .map(|(name, (a, b, c))| (name.clone(), *a, *b, *c))
                .collect(),
            connections_in_flight: self.connections_in_flight.load(Ordering::Relaxed),
            upstreams_up: self.upstreams_up.load(Ordering::Relaxed) as u64,
            upstreams_down: self.upstreams_down.load(Ordering::Relaxed) as u64,
        }
    }

    /// Add every counter in `delta` to this registry.
    ///
    /// Global counters and gauges are independent; this method never touches
    /// the gauges. Per-label series are merged in sorted name order so the
    /// [`MAX_LABELS`] cap keeps a deterministic subset even when the input
    /// vectors are not sorted. Labels that already exist keep accumulating
    /// after the cap is reached; new labels are dropped.
    ///
    /// Extra or missing entries in `delta.duration_buckets` are ignored
    /// because every registry uses the same bucket layout; matching indexes
    /// are added together.
    pub fn apply_counters(&self, delta: &Delta) {
        for (target, value) in self.requests.iter().zip(&delta.requests) {
            add_saturating(target, *value);
        }
        for (target, value) in self.duration_buckets.iter().zip(&delta.duration_buckets) {
            add_saturating(target, *value);
        }
        add_saturating(&self.duration_sum_nanos, delta.duration_sum_nanos);
        add_saturating(&self.duration_count, delta.duration_count);

        {
            let mut routes = lock(&self.routes);
            apply_labeled(&mut routes, &delta.route_requests, &delta.route_duration);
        }
        {
            let mut upstreams = lock(&self.upstreams);
            apply_labeled(
                &mut upstreams,
                &delta.upstream_requests,
                &delta.upstream_duration,
            );
        }

        add_saturating(&self.cache_hits, delta.cache_hits);
        add_saturating(&self.cache_misses, delta.cache_misses);
        add_saturating(&self.cache_stale, delta.cache_stale);
        add_saturating(&self.health_checks_ok, delta.health_checks_ok);
        add_saturating(&self.health_checks_failed, delta.health_checks_failed);
        add_saturating(&self.request_bytes, delta.request_bytes);
        add_saturating(&self.response_bytes, delta.response_bytes);
        add_saturating(&self.reloads_ok, delta.reloads_ok);
        add_saturating(&self.reloads_failed, delta.reloads_failed);
        add_saturating(&self.tls_handshakes_ok, delta.tls_handshakes_ok);
        add_saturating(&self.tls_handshakes_failed, delta.tls_handshakes_failed);
        add_saturating(&self.quic_connections, delta.quic_connections);
    }

    /// Overwrite this registry's gauges with the values in `delta`.
    ///
    /// This uses [`Metrics::connection_set`] and [`Metrics::set_upstreams`]
    /// semantics: a gauge is a current value, not something that can simply be
    /// summed across workers. Callers that want different aggregation (for
    /// example summing connections over workers) should call
    /// [`Metrics::apply_counters`] and set the gauges themselves.
    pub fn apply_gauges(&self, delta: &Delta) {
        self.connection_set(delta.connections_in_flight);
        if !delta.upstream_load.is_empty() {
            let mut load = self
                .upstream_load
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (name, active) in &delta.upstream_load {
                load.insert(name.clone(), *active);
            }
        }
        if !delta.certificate_expiry.is_empty() {
            let mut expiry = self
                .certificate_expiry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (path, expires) in &delta.certificate_expiry {
                expiry.insert(path.clone(), *expires);
            }
        }
        self.set_upstreams(usize_of(delta.upstreams_up), usize_of(delta.upstreams_down));
    }

    /// Apply a [`Delta`] by adding its counters and overwriting the gauges.
    ///
    /// This is exactly [`Metrics::apply_counters`] followed by
    /// [`Metrics::apply_gauges`]. It is the convenient entry point when the
    /// aggregate should mirror the latest worker snapshot.
    pub fn apply_delta(&self, delta: &Delta) {
        self.apply_counters(delta);
        self.apply_gauges(delta);
    }

    /// Render every metric in the Prometheus text exposition format.
    ///
    /// Output order is fixed: global status classes in order, histogram
    /// buckets by ascending bound with `+Inf` last, the gauges, then the
    /// labelled route and upstream sections (labels sorted by name), and
    /// finally the cache, byte and reload counters.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(2048);

        out.push_str("# HELP elira_requests_total Completed requests by status class.\n");
        out.push_str("# TYPE elira_requests_total counter\n");
        for (class, counter) in STATUS_CLASSES.iter().zip(&self.requests) {
            let _ = writeln!(
                out,
                "elira_requests_total{{class=\"{class}\"}} {}",
                counter.load(Ordering::Relaxed)
            );
        }

        out.push_str("# HELP elira_request_duration_seconds Time spent handling a request.\n");
        out.push_str("# TYPE elira_request_duration_seconds histogram\n");
        let count = self.duration_count.load(Ordering::Relaxed);
        for (bucket, counter) in BUCKETS.iter().zip(&self.duration_buckets) {
            let _ = writeln!(
                out,
                "elira_request_duration_seconds_bucket{{le=\"{}\"}} {}",
                bucket.label,
                counter.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            out,
            "elira_request_duration_seconds_bucket{{le=\"+Inf\"}} {count}"
        );
        let _ = writeln!(
            out,
            "elira_request_duration_seconds_sum {}",
            format_seconds(self.duration_sum_nanos.load(Ordering::Relaxed))
        );
        let _ = writeln!(out, "elira_request_duration_seconds_count {count}");

        out.push_str("# HELP elira_connections_in_flight Client connections currently open.\n");
        out.push_str("# TYPE elira_connections_in_flight gauge\n");
        let _ = writeln!(
            out,
            "elira_connections_in_flight {}",
            self.connections_in_flight.load(Ordering::Relaxed)
        );

        out.push_str("# HELP elira_upstreams Upstreams by health state as last checked.\n");
        out.push_str("# TYPE elira_upstreams gauge\n");
        let _ = writeln!(
            out,
            "elira_upstreams{{state=\"up\"}} {}",
            self.upstreams_up.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "elira_upstreams{{state=\"down\"}} {}",
            self.upstreams_down.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP elira_route_requests_total Completed requests by configured route and status class.\n",
        );
        out.push_str("# TYPE elira_route_requests_total counter\n");
        out.push_str("# HELP elira_route_duration_seconds Time spent handling requests per configured route.\n");
        out.push_str("# TYPE elira_route_duration_seconds summary\n");
        render_labeled(
            &mut out,
            &lock(&self.routes),
            "elira_route_requests_total",
            "elira_route_duration_seconds",
            "route",
        );

        out.push_str(
            "# HELP elira_upstream_requests_total Proxied requests by upstream and status class.\n",
        );
        out.push_str("# TYPE elira_upstream_requests_total counter\n");
        out.push_str(
            "# HELP elira_upstream_duration_seconds Time spent waiting for an upstream.\n",
        );
        out.push_str("# TYPE elira_upstream_duration_seconds summary\n");
        render_labeled(
            &mut out,
            &lock(&self.upstreams),
            "elira_upstream_requests_total",
            "elira_upstream_duration_seconds",
            "upstream",
        );

        out.push_str("# HELP elira_cache_requests_total Cache lookups by result.\n");
        out.push_str("# TYPE elira_cache_requests_total counter\n");
        let _ = writeln!(
            out,
            "elira_cache_requests_total{{result=\"hit\"}} {}",
            self.cache_hits.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "elira_cache_requests_total{{result=\"miss\"}} {}",
            self.cache_misses.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "elira_cache_requests_total{{result=\"stale\"}} {}",
            self.cache_stale.load(Ordering::Relaxed)
        );

        out.push_str("# HELP elira_health_checks_total Upstream health probes by result.\n");
        out.push_str("# TYPE elira_health_checks_total counter\n");
        let _ = writeln!(
            out,
            "elira_health_checks_total{{result=\"ok\"}} {}",
            self.health_checks_ok.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "elira_health_checks_total{{result=\"failed\"}} {}",
            self.health_checks_failed.load(Ordering::Relaxed)
        );

        out.push_str("# HELP elira_request_bytes_total Request body bytes read from clients.\n");
        out.push_str("# TYPE elira_request_bytes_total counter\n");
        let _ = writeln!(
            out,
            "elira_request_bytes_total {}",
            self.request_bytes.load(Ordering::Relaxed)
        );

        out.push_str("# HELP elira_response_bytes_total Response body bytes written to clients.\n");
        out.push_str("# TYPE elira_response_bytes_total counter\n");
        let _ = writeln!(
            out,
            "elira_response_bytes_total {}",
            self.response_bytes.load(Ordering::Relaxed)
        );

        out.push_str("# HELP elira_tls_handshakes_total TLS handshakes by result.\n");
        out.push_str("# TYPE elira_tls_handshakes_total counter\n");
        let _ = writeln!(
            out,
            "elira_tls_handshakes_total{{result=\"ok\"}} {}",
            self.tls_handshakes_ok.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "elira_tls_handshakes_total{{result=\"failed\"}} {}",
            self.tls_handshakes_failed.load(Ordering::Relaxed)
        );
        out.push_str("# HELP elira_quic_connections_total Accepted QUIC connections.\n");
        out.push_str("# TYPE elira_quic_connections_total counter\n");
        let _ = writeln!(
            out,
            "elira_quic_connections_total {}",
            self.quic_connections.load(Ordering::Relaxed)
        );
        out.push_str("# HELP elira_tls_certificate_expires_seconds Certificate expiry as a Unix timestamp.\n");
        out.push_str("# TYPE elira_tls_certificate_expires_seconds gauge\n");
        {
            let expiry = self
                .certificate_expiry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (path, expires) in expiry.iter() {
                let _ = writeln!(
                    out,
                    "elira_tls_certificate_expires_seconds{{path=\"{}\"}} {}",
                    escape_label(path),
                    expires
                );
            }
        }
        out.push_str("# HELP elira_upstream_active_requests Active requests per upstream pool.\n");
        out.push_str("# TYPE elira_upstream_active_requests gauge\n");
        {
            let load = self
                .upstream_load
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (name, active) in load.iter() {
                let _ = writeln!(
                    out,
                    "elira_upstream_active_requests{{upstream=\"{}\"}} {}",
                    escape_label(name),
                    active
                );
            }
        }
        out.push_str("# HELP elira_h2_pool_connections Live custom HTTP/2 pool connections.\n");
        out.push_str("# TYPE elira_h2_pool_connections gauge\n");
        {
            let pools = self
                .h2_pools
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (name, (connections, active, total, queued)) in pools.iter() {
                let _ = writeln!(
                    out,
                    "elira_h2_pool_connections{{upstream=\"{}\"}} {connections}",
                    escape_label(name)
                );
                let _ = writeln!(
                    out,
                    "elira_h2_pool_active_streams{{upstream=\"{}\"}} {active}",
                    escape_label(name)
                );
                let _ = writeln!(
                    out,
                    "elira_h2_pool_total_connections{{upstream=\"{}\"}} {total}",
                    escape_label(name)
                );
                let _ = writeln!(
                    out,
                    "elira_h2_pool_queued_streams{{upstream=\"{}\"}} {queued}",
                    escape_label(name)
                );
            }
        }
        out.push_str("# HELP elira_h3_pool_connections Live custom HTTP/3 pool connections.\n");
        out.push_str("# TYPE elira_h3_pool_connections gauge\n");
        {
            let pools = self
                .h3_pools
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (name, (connections, active, total)) in pools.iter() {
                let _ = writeln!(
                    out,
                    "elira_h3_pool_connections{{upstream=\"{}\"}} {connections}",
                    escape_label(name)
                );
                let _ = writeln!(
                    out,
                    "elira_h3_pool_active_requests{{upstream=\"{}\"}} {active}",
                    escape_label(name)
                );
                let _ = writeln!(
                    out,
                    "elira_h3_pool_total_connections{{upstream=\"{}\"}} {total}",
                    escape_label(name)
                );
            }
        }
        out.push_str("# HELP elira_reloads_total Configuration reload attempts by result.\n");
        out.push_str("# TYPE elira_reloads_total counter\n");
        let _ = writeln!(
            out,
            "elira_reloads_total{{result=\"ok\"}} {}",
            self.reloads_ok.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "elira_reloads_total{{result=\"failed\"}} {}",
            self.reloads_failed.load(Ordering::Relaxed)
        );

        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

fn status_class(status: u16) -> usize {
    match status {
        100..=199 => 0,
        200..=299 => 1,
        300..=399 => 2,
        400..=499 => 3,
        500..=599 => 4,
        _ => 5,
    }
}

fn nanos_of(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

/// Lock a map, recovering the contents if a previous holder panicked while
/// updating metrics. Metrics are not allowed to take the process down.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Remove all labelled series, returning requests and durations in name order.
fn take_labeled(mutex: &Mutex<BTreeMap<String, Labeled>>) -> (LabeledRequests, LabeledDuration) {
    let map = std::mem::take(&mut *lock(mutex));
    let mut requests = Vec::with_capacity(map.len());
    let mut duration = Vec::with_capacity(map.len());
    for (label, stats) in map {
        duration.push((
            label.clone(),
            stats.duration_sum_nanos,
            stats.duration_count,
        ));
        requests.push((label, stats.requests));
    }
    (requests, duration)
}

/// Merge the request and duration halves of a delta into one label map.
///
/// The incoming entries are first combined per label in a sorted map. That
/// makes cap enforcement independent of the order of the input vectors and
/// guarantees that a label present in both halves is only counted once.
fn apply_labeled(
    map: &mut BTreeMap<String, Labeled>,
    requests: &[(String, [u64; STATUS_CLASSES.len()])],
    duration: &[(String, u64, u64)],
) {
    let mut incoming: BTreeMap<&str, Labeled> = BTreeMap::new();
    for (label, counters) in requests {
        let stats = incoming.entry(label.as_str()).or_default();
        for (target, value) in stats.requests.iter_mut().zip(counters) {
            *target = target.saturating_add(*value);
        }
    }
    for (label, sum, count) in duration {
        let stats = incoming.entry(label.as_str()).or_default();
        stats.duration_sum_nanos = stats.duration_sum_nanos.saturating_add(*sum);
        stats.duration_count = stats.duration_count.saturating_add(*count);
    }

    for (label, stats) in incoming {
        if stats.is_empty() {
            continue;
        }
        if let Some(existing) = map.get_mut(label) {
            existing.merge(&stats);
            continue;
        }
        if map.len() >= MAX_LABELS {
            continue;
        }
        map.insert(label.to_owned(), stats);
    }
}

fn usize_of(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn record_labeled(map: &mut BTreeMap<String, Labeled>, label: &str, status: u16, nanos: u64) {
    if let Some(stats) = map.get_mut(label) {
        stats.record(status, nanos);
        return;
    }
    if map.len() >= MAX_LABELS {
        return;
    }
    let mut stats = Labeled::default();
    stats.record(status, nanos);
    map.insert(label.to_owned(), stats);
}

fn render_labeled(
    out: &mut String,
    map: &BTreeMap<String, Labeled>,
    requests_name: &str,
    duration_name: &str,
    label_key: &str,
) {
    for (label, stats) in map {
        let label = escape_label(label);
        for (class, count) in STATUS_CLASSES.iter().zip(&stats.requests) {
            let _ = writeln!(
                out,
                "{requests_name}{{{label_key}=\"{label}\",class=\"{class}\"}} {count}"
            );
        }
    }

    for (label, stats) in map {
        let label = escape_label(label);
        let _ = writeln!(
            out,
            "{duration_name}_sum{{{label_key}=\"{label}\"}} {}",
            format_seconds(stats.duration_sum_nanos)
        );
        let _ = writeln!(
            out,
            "{duration_name}_count{{{label_key}=\"{label}\"}} {}",
            stats.duration_count
        );
    }
}

/// Escape a Prometheus label value: backslash, double quote and newline.
fn escape_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn add_saturating(counter: &AtomicU64, value: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(value);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

/// Format nanoseconds as seconds without an exponent, which keeps successive
/// scrapes byte-for-byte comparable.
fn format_seconds(nanos: u64) -> String {
    let whole = nanos / 1_000_000_000;
    let frac = nanos % 1_000_000_000;
    if frac == 0 {
        return format!("{whole}.0");
    }

    let mut text = format!("{whole}.{frac:09}");
    while text.ends_with('0') {
        text.pop();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn line(text: &str, expected: &str) -> bool {
        text.lines().any(|candidate| candidate == expected)
    }

    fn series_value<'a>(text: &'a str, prefix: &str) -> &'a str {
        text.lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("missing metric line starting with {prefix:?}"))
            .rsplit_once(' ')
            .expect("metric line has a value")
            .1
    }

    #[test]
    fn requests_are_counted_by_status_class() {
        let metrics = Metrics::new();
        metrics.observe(101, Duration::from_millis(1));
        metrics.observe(200, Duration::from_millis(1));
        metrics.observe(204, Duration::from_millis(1));
        metrics.observe(301, Duration::from_millis(1));
        metrics.observe(404, Duration::from_millis(1));
        metrics.observe(503, Duration::from_millis(1));
        metrics.observe(99, Duration::from_millis(1));
        metrics.observe(600, Duration::from_millis(1));

        let text = metrics.render();
        assert!(line(&text, "elira_requests_total{class=\"1xx\"} 1"));
        assert!(line(&text, "elira_requests_total{class=\"2xx\"} 2"));
        assert!(line(&text, "elira_requests_total{class=\"3xx\"} 1"));
        assert!(line(&text, "elira_requests_total{class=\"4xx\"} 1"));
        assert!(line(&text, "elira_requests_total{class=\"5xx\"} 1"));
        assert!(line(&text, "elira_requests_total{class=\"other\"} 2"));
    }

    #[test]
    fn histogram_accumulates_sum_count_and_buckets() {
        let metrics = Metrics::new();
        metrics.observe(200, Duration::from_millis(1));
        metrics.observe(200, Duration::from_millis(3));
        metrics.observe(500, Duration::from_secs(2));

        let text = metrics.render();
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_bucket{le=\"0.001\"}"),
            "1"
        );
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_bucket{le=\"0.005\"}"),
            "2"
        );
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_sum"),
            "2.004"
        );
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_count"),
            "3"
        );
    }

    #[test]
    fn infinity_bucket_equals_count() {
        let metrics = Metrics::new();
        for i in 0..100 {
            metrics.observe(200, Duration::from_micros(i * 100_000));
        }

        let text = metrics.render();
        let count = series_value(&text, "elira_request_duration_seconds_count");
        let infinity = series_value(&text, "elira_request_duration_seconds_bucket{le=\"+Inf\"}");
        assert_eq!(count, "100");
        assert_eq!(infinity, count);
    }

    #[test]
    fn buckets_are_ordered_cumulative_and_terminate_with_infinity() {
        let metrics = Metrics::new();
        metrics.observe(200, Duration::from_nanos(1));
        metrics.observe(200, Duration::from_millis(30));
        metrics.observe(200, Duration::from_secs(30));

        let text = metrics.render();
        let buckets: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("elira_request_duration_seconds_bucket{"))
            .collect();

        assert_eq!(buckets.len(), BUCKETS.len() + 1);
        assert!(buckets.last().unwrap().contains("le=\"+Inf\""));

        let mut previous = 0_u64;
        for (line, bucket) in buckets[..BUCKETS.len()].iter().zip(&BUCKETS) {
            assert!(line.contains(bucket.label));
            let value: u64 = line.rsplit_once(' ').unwrap().1.parse().unwrap();
            assert!(value >= previous, "bucket values must be cumulative");
            previous = value;
        }
    }

    #[test]
    fn render_contains_help_and_type_for_every_metric() {
        let text = Metrics::new().render();

        for name in [
            "elira_requests_total",
            "elira_request_duration_seconds",
            "elira_connections_in_flight",
            "elira_upstreams",
        ] {
            assert!(
                text.lines()
                    .any(|line| line.starts_with(&format!("# HELP {name} "))),
                "missing HELP for {name}"
            );
            assert!(
                text.lines()
                    .any(|line| line.starts_with(&format!("# TYPE {name} "))),
                "missing TYPE for {name}"
            );
        }

        assert!(line(&text, "# TYPE elira_requests_total counter"));
        assert!(line(
            &text,
            "# TYPE elira_request_duration_seconds histogram"
        ));
        assert!(line(&text, "# TYPE elira_connections_in_flight gauge"));
        assert!(line(&text, "# TYPE elira_upstreams gauge"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn connections_in_flight_follow_start_and_finish() {
        let metrics = Metrics::new();
        metrics.connection_started();
        metrics.connection_started();
        metrics.connection_finished();

        let text = metrics.render();
        assert_eq!(series_value(&text, "elira_connections_in_flight"), "1");

        metrics.connection_finished();
        metrics.connection_finished();
        let text = metrics.render();
        assert_eq!(series_value(&text, "elira_connections_in_flight"), "0");
    }

    #[test]
    fn upstream_gauges_reflect_the_last_update() {
        let metrics = Metrics::new();
        metrics.set_upstreams(3, 1);

        let text = metrics.render();
        assert_eq!(series_value(&text, "elira_upstreams{state=\"up\"}"), "3");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"down\"}"), "1");

        metrics.set_upstreams(0, 4);
        let text = metrics.render();
        assert_eq!(series_value(&text, "elira_upstreams{state=\"up\"}"), "0");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"down\"}"), "4");
    }

    #[test]
    fn zero_duration_lands_in_every_bucket() {
        let metrics = Metrics::new();
        metrics.observe(200, Duration::ZERO);

        let text = metrics.render();
        for bucket in &BUCKETS {
            assert_eq!(
                series_value(
                    &text,
                    &format!(
                        "elira_request_duration_seconds_bucket{{le=\"{}\"}}",
                        bucket.label
                    )
                ),
                "1"
            );
        }
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_sum"),
            "0.0"
        );
    }

    #[test]
    fn default_renders_the_same_as_new() {
        let fresh = Metrics::new().render();
        let default = Metrics::default().render();
        assert_eq!(fresh, default);
    }

    #[test]
    fn sum_uses_plain_decimal_seconds() {
        assert_eq!(format_seconds(0), "0.0");
        assert_eq!(format_seconds(1), "0.000000001");
        assert_eq!(format_seconds(1_500_000_000), "1.5");
        assert_eq!(format_seconds(3_000_000_000), "3.0");
        assert!(!format_seconds(u64::MAX).contains('e'));
    }

    #[test]
    fn record_request_still_updates_global_series() {
        let metrics = Metrics::new();
        metrics.record_request(201, Duration::from_millis(2));

        let text = metrics.render();
        assert!(line(&text, "elira_requests_total{class=\"2xx\"} 1"));
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_count"),
            "1"
        );
    }

    #[test]
    fn route_and_upstream_series_are_recorded() {
        let metrics = Metrics::new();
        metrics.record_route("api", 200, Duration::from_millis(10));
        metrics.record_route("api", 500, Duration::from_millis(20));
        metrics.record_route("static", 404, Duration::ZERO);
        metrics.record_upstream("backend-a", 200, Duration::from_millis(15));
        metrics.record_upstream("backend-a", 502, Duration::from_millis(5));

        let text = metrics.render();
        assert!(line(
            &text,
            "elira_route_requests_total{route=\"api\",class=\"2xx\"} 1"
        ));
        assert!(line(
            &text,
            "elira_route_requests_total{route=\"api\",class=\"5xx\"} 1"
        ));
        assert!(line(
            &text,
            "elira_route_requests_total{route=\"static\",class=\"4xx\"} 1"
        ));
        assert_eq!(
            series_value(&text, "elira_route_duration_seconds_sum{route=\"api\"}"),
            "0.03"
        );
        assert_eq!(
            series_value(&text, "elira_route_duration_seconds_count{route=\"api\"}"),
            "2"
        );
        assert_eq!(
            series_value(
                &text,
                "elira_route_duration_seconds_count{route=\"static\"}"
            ),
            "1"
        );

        assert!(line(
            &text,
            "elira_upstream_requests_total{upstream=\"backend-a\",class=\"5xx\"} 1"
        ));
        assert_eq!(
            series_value(
                &text,
                "elira_upstream_duration_seconds_sum{upstream=\"backend-a\"}"
            ),
            "0.02"
        );
        assert_eq!(
            series_value(
                &text,
                "elira_upstream_duration_seconds_count{upstream=\"backend-a\"}"
            ),
            "2"
        );
        assert_valid_exposition(&text);
    }

    #[test]
    fn label_values_are_escaped() {
        let metrics = Metrics::new();
        metrics.record_route("a\"b\\c\nd", 200, Duration::ZERO);
        metrics.record_upstream("up\\stream", 200, Duration::ZERO);

        let text = metrics.render();
        assert!(line(
            &text,
            "elira_route_requests_total{route=\"a\\\"b\\\\c\\nd\",class=\"2xx\"} 1"
        ));
        assert!(line(
            &text,
            "elira_upstream_requests_total{upstream=\"up\\\\stream\",class=\"2xx\"} 1"
        ));
        assert_valid_exposition(&text);
    }

    #[test]
    fn label_cardinality_is_capped() {
        let metrics = Metrics::new();
        for i in 0..MAX_LABELS + 50 {
            metrics.record_route(&format!("route-{i}"), 200, Duration::ZERO);
            metrics.record_upstream(&format!("upstream-{i}"), 200, Duration::ZERO);
        }

        let text = metrics.render();
        let routes = text
            .lines()
            .filter(|line| line.starts_with("elira_route_duration_seconds_count{"))
            .count();
        let upstreams = text
            .lines()
            .filter(|line| line.starts_with("elira_upstream_duration_seconds_count{"))
            .count();
        assert_eq!(routes, MAX_LABELS);
        assert_eq!(upstreams, MAX_LABELS);

        assert!(text.contains("route=\"route-0\""));
        assert!(!text.contains(&format!("route=\"route-{MAX_LABELS}\"")));
        assert!(!text.contains(&format!("upstream=\"upstream-{MAX_LABELS}\"")));

        // Existing labels keep accumulating after the cap is reached.
        metrics.record_route("route-0", 500, Duration::ZERO);
        let text = metrics.render();
        assert!(line(
            &text,
            "elira_route_requests_total{route=\"route-0\",class=\"5xx\"} 1"
        ));
        assert_valid_exposition(&text);
    }

    #[test]
    fn cache_counters_are_split_by_result() {
        let metrics = Metrics::new();
        metrics.cache_hit();
        metrics.cache_hit();
        metrics.cache_miss();

        let text = metrics.render();
        assert!(line(&text, "elira_cache_requests_total{result=\"hit\"} 2"));
        assert!(line(&text, "elira_cache_requests_total{result=\"miss\"} 1"));
    }

    #[test]
    fn byte_counters_accumulate() {
        let metrics = Metrics::new();
        metrics.request_bytes(100);
        metrics.request_bytes(50);
        metrics.response_bytes(2048);

        let text = metrics.render();
        assert_eq!(series_value(&text, "elira_request_bytes_total"), "150");
        assert_eq!(series_value(&text, "elira_response_bytes_total"), "2048");
    }

    #[test]
    fn reload_counters_are_split_by_result() {
        let metrics = Metrics::new();
        metrics.reload_ok();
        metrics.reload_ok();
        metrics.reload_failed();

        let text = metrics.render();
        assert!(line(&text, "elira_reloads_total{result=\"ok\"} 2"));
        assert!(line(&text, "elira_reloads_total{result=\"failed\"} 1"));
    }

    #[test]
    fn render_is_valid_prometheus_text() {
        let metrics = Metrics::new();
        metrics.observe(200, Duration::from_millis(3));
        metrics.connection_started();
        metrics.set_upstreams(2, 1);
        metrics.record_route("weird \"route\"\\\nwith newline", 418, Duration::ZERO);
        metrics.record_upstream("backend\\one", 503, Duration::from_millis(1));
        metrics.cache_hit();
        metrics.cache_miss();
        metrics.request_bytes(17);
        metrics.response_bytes(42);
        metrics.reload_ok();
        metrics.reload_failed();

        let text = metrics.render();
        assert_valid_exposition(&text);
        assert!(text.ends_with('\n'));
    }

    fn class(status: u16) -> usize {
        status_class(status)
    }

    #[test]
    fn take_delta_resets_counters() {
        let metrics = Metrics::new();
        metrics.observe(200, Duration::from_millis(2));
        metrics.record_route("api", 404, Duration::from_millis(1));
        metrics.record_upstream("backend", 503, Duration::from_millis(3));
        metrics.cache_hit();
        metrics.cache_miss();
        metrics.request_bytes(10);
        metrics.response_bytes(20);
        metrics.reload_ok();
        metrics.reload_failed();

        let delta = metrics.take_delta();
        assert_eq!(delta.requests[class(200)], 1);
        assert_eq!(delta.duration_count, 1);
        assert_eq!(delta.duration_sum_nanos, 2_000_000);
        assert_eq!(delta.route_requests.len(), 1);
        assert_eq!(delta.upstream_requests.len(), 1);
        assert_eq!(delta.cache_hits, 1);
        assert_eq!(delta.cache_misses, 1);
        assert_eq!(delta.request_bytes, 10);
        assert_eq!(delta.response_bytes, 20);
        assert_eq!(delta.reloads_ok, 1);
        assert_eq!(delta.reloads_failed, 1);
        assert!(!delta.is_empty());

        let again = metrics.take_delta();
        assert_eq!(again.requests, [0; STATUS_CLASSES.len()]);
        assert!(again.duration_buckets.iter().all(|&value| value == 0));
        assert_eq!(again.duration_sum_nanos, 0);
        assert_eq!(again.duration_count, 0);
        assert!(again.route_requests.is_empty());
        assert!(again.route_duration.is_empty());
        assert!(again.upstream_requests.is_empty());
        assert!(again.upstream_duration.is_empty());
        assert_eq!(again.cache_hits, 0);
        assert_eq!(again.cache_misses, 0);
        assert_eq!(again.request_bytes, 0);
        assert_eq!(again.response_bytes, 0);
        assert_eq!(again.reloads_ok, 0);
        assert_eq!(again.reloads_failed, 0);
    }

    #[test]
    fn take_delta_copies_labels_in_sorted_order() {
        let metrics = Metrics::new();
        metrics.record_route("zeta", 500, Duration::from_millis(3));
        metrics.record_route("alpha", 200, Duration::from_millis(1));
        metrics.record_upstream("up-b", 200, Duration::from_millis(4));
        metrics.record_upstream("up-a", 503, Duration::from_millis(2));

        let delta = metrics.take_delta();
        let labels = |entries: &[(String, [u64; STATUS_CLASSES.len()])]| {
            entries
                .iter()
                .map(|(label, _)| label.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(labels(&delta.route_requests), ["alpha", "zeta"]);
        assert_eq!(labels(&delta.upstream_requests), ["up-a", "up-b"]);

        assert_eq!(delta.route_duration[0].0, "alpha");
        assert_eq!(delta.route_duration[0].1, 1_000_000);
        assert_eq!(delta.route_duration[0].2, 1);
        assert_eq!(delta.route_requests[1].1[class(500)], 1);
        assert_eq!(delta.upstream_requests[0].1[class(503)], 1);
        assert_eq!(delta.upstream_duration[0].0, "up-a");
    }

    #[test]
    fn two_deltas_sum_when_applied() {
        let worker = Metrics::new();
        let aggregate = Metrics::new();

        worker.observe(200, Duration::from_millis(1));
        worker.record_route("api", 200, Duration::from_millis(1));
        worker.cache_hit();
        aggregate.apply_delta(&worker.take_delta());

        worker.observe(500, Duration::from_millis(2));
        worker.record_route("api", 500, Duration::from_millis(2));
        worker.cache_miss();
        aggregate.apply_delta(&worker.take_delta());

        let delta = aggregate.take_delta();
        assert_eq!(delta.requests[class(200)], 1);
        assert_eq!(delta.requests[class(500)], 1);
        assert_eq!(delta.duration_count, 2);
        assert_eq!(delta.duration_sum_nanos, 3_000_000);
        assert_eq!(delta.route_requests.len(), 1);
        assert_eq!(delta.route_requests[0].1[class(200)], 1);
        assert_eq!(delta.route_requests[0].1[class(500)], 1);
        assert_eq!(delta.route_duration[0].1, 3_000_000);
        assert_eq!(delta.route_duration[0].2, 2);
        assert_eq!(delta.cache_hits, 1);
        assert_eq!(delta.cache_misses, 1);
    }

    #[test]
    fn gauges_are_copied_not_reset() {
        let metrics = Metrics::new();
        metrics.connection_started();
        metrics.connection_started();
        metrics.set_upstreams(4, 2);

        let delta = metrics.take_delta();
        assert_eq!(delta.connections_in_flight, 2);
        assert_eq!(delta.upstreams_up, 4);
        assert_eq!(delta.upstreams_down, 2);

        // Taking a delta must leave the live gauges in place.
        let text = metrics.render();
        assert_eq!(series_value(&text, "elira_connections_in_flight"), "2");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"up\"}"), "4");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"down\"}"), "2");

        let again = metrics.take_delta();
        assert_eq!(again.connections_in_flight, 2);
        assert_eq!(again.upstreams_up, 4);
        assert_eq!(again.upstreams_down, 2);
    }

    #[test]
    fn delta_json_round_trips() {
        let metrics = Metrics::new();
        metrics.observe(201, Duration::from_millis(7));
        metrics.observe(404, Duration::from_millis(1));
        metrics.record_route("api", 201, Duration::from_millis(7));
        metrics.record_upstream("backend", 404, Duration::from_millis(1));
        metrics.cache_hit();
        metrics.cache_miss();
        metrics.request_bytes(1234);
        metrics.response_bytes(5678);
        metrics.reload_ok();
        metrics.reload_failed();
        metrics.connection_started();
        metrics.set_upstreams(2, 1);

        let delta = metrics.take_delta();
        let json = serde_json::to_string(&delta).expect("serialise delta");
        let restored: Delta = serde_json::from_str(&json).expect("deserialise delta");
        assert_eq!(restored, delta);
        assert!(json.contains("\"route_requests\""));
        assert!(json.contains("\"duration_buckets\""));
    }

    #[test]
    fn applying_delta_reproduces_the_original_render() {
        let worker = Metrics::new();
        worker.observe(200, Duration::from_millis(1));
        worker.observe(500, Duration::from_millis(30));
        worker.record_route("api", 200, Duration::from_millis(1));
        worker.record_route("api", 500, Duration::from_millis(30));
        worker.record_route("static", 404, Duration::ZERO);
        worker.record_upstream("backend", 200, Duration::from_millis(2));
        worker.record_upstream("backend", 502, Duration::from_millis(20));
        worker.cache_hit();
        worker.cache_miss();
        worker.request_bytes(11);
        worker.response_bytes(22);
        worker.reload_ok();
        worker.reload_failed();
        worker.connection_started();
        worker.set_upstreams(3, 1);

        let original = worker.render();
        let delta = worker.take_delta();
        let aggregate = Metrics::new();
        aggregate.apply_delta(&delta);
        assert_eq!(aggregate.render(), original);
    }

    #[test]
    fn apply_counters_leaves_gauges_alone() {
        let metrics = Metrics::new();
        metrics.connection_set(7);
        metrics.set_upstreams(1, 2);

        let delta = Delta {
            cache_hits: 3,
            connections_in_flight: 99,
            upstreams_up: 8,
            upstreams_down: 9,
            ..Delta::default()
        };

        metrics.apply_counters(&delta);
        let text = metrics.render();
        assert!(line(&text, "elira_cache_requests_total{result=\"hit\"} 3"));
        assert_eq!(series_value(&text, "elira_connections_in_flight"), "7");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"up\"}"), "1");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"down\"}"), "2");

        metrics.apply_gauges(&delta);
        let text = metrics.render();
        assert_eq!(series_value(&text, "elira_connections_in_flight"), "99");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"up\"}"), "8");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"down\"}"), "9");
    }

    #[test]
    fn applying_deltas_preserves_label_cap() {
        let aggregate = Metrics::new();
        let mut delta = Delta::default();
        for index in 0..MAX_LABELS + 50 {
            let mut requests = [0; STATUS_CLASSES.len()];
            requests[class(200)] = 1;
            delta
                .route_requests
                .push((format!("route-{index:04}"), requests));
            delta
                .route_duration
                .push((format!("route-{index:04}"), 1_000_000, 1));
        }

        // Deliberately unsorted input: the cap must pick the same sorted
        // subset a fresh registry would, not whichever entries come first.
        delta.route_requests.reverse();
        delta.route_duration.reverse();

        aggregate.apply_delta(&delta);
        let text = aggregate.render();
        let routes = text
            .lines()
            .filter(|line| line.starts_with("elira_route_duration_seconds_count{"))
            .count();
        assert_eq!(routes, MAX_LABELS);
        assert!(text.contains("route=\"route-0000\""));
        assert!(text.contains(&format!("route=\"route-{:04}\"", MAX_LABELS - 1)));
        assert!(!text.contains(&format!("route=\"route-{:04}\"", MAX_LABELS)));

        // Labels already present keep accumulating even when the cap is full.
        let mut extra = Delta::default();
        let mut requests = [0; STATUS_CLASSES.len()];
        requests[class(500)] = 1;
        extra
            .route_requests
            .push(("route-0000".to_owned(), requests));
        extra
            .route_duration
            .push(("route-0000".to_owned(), 2_000_000, 1));
        extra
            .route_requests
            .push(("route-new".to_owned(), requests));
        aggregate.apply_delta(&extra);

        let text = aggregate.render();
        assert!(line(
            &text,
            "elira_route_requests_total{route=\"route-0000\",class=\"5xx\"} 1"
        ));
        assert_eq!(
            series_value(
                &text,
                "elira_route_duration_seconds_count{route=\"route-0000\"}"
            ),
            "2"
        );
        assert!(!text.contains("route=\"route-new\""));
        assert_valid_exposition(&text);
    }

    #[test]
    fn apply_delta_overwrites_gauges_with_the_latest_snapshot() {
        let aggregate = Metrics::new();

        let first = Delta {
            connections_in_flight: 2,
            upstreams_up: 5,
            upstreams_down: 1,
            ..Delta::default()
        };
        aggregate.apply_delta(&first);
        assert_eq!(
            series_value(&aggregate.render(), "elira_connections_in_flight"),
            "2"
        );

        let second = Delta {
            connections_in_flight: 4,
            upstreams_up: 3,
            upstreams_down: 2,
            ..Delta::default()
        };
        aggregate.apply_delta(&second);
        let text = aggregate.render();
        assert_eq!(series_value(&text, "elira_connections_in_flight"), "4");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"up\"}"), "3");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"down\"}"), "2");
    }

    #[test]
    fn default_delta_only_overwrites_gauges_when_applied_fully() {
        let metrics = Metrics::new();
        metrics.observe(200, Duration::from_millis(1));
        metrics.connection_set(5);
        let before = metrics.render();

        // Counters are additive, so an empty delta changes nothing.
        metrics.apply_counters(&Delta::default());
        assert_eq!(metrics.render(), before);

        // Gauges are snapshots, so an empty delta resets them to zero.
        metrics.apply_gauges(&Delta::default());
        let text = metrics.render();
        assert_eq!(series_value(&text, "elira_connections_in_flight"), "0");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"up\"}"), "0");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"down\"}"), "0");
    }

    #[test]
    fn applying_short_bucket_vectors_only_updates_matching_indexes() {
        let metrics = Metrics::new();
        let delta = Delta {
            duration_buckets: vec![3, 4],
            duration_sum_nanos: 10,
            duration_count: 2,
            ..Delta::default()
        };
        metrics.apply_counters(&delta);

        let text = metrics.render();
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_bucket{le=\"0.001\"}"),
            "3"
        );
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_bucket{le=\"0.005\"}"),
            "4"
        );
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_bucket{le=\"0.01\"}"),
            "0"
        );
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_count"),
            "2"
        );
    }

    #[test]
    fn take_and_apply_round_trip_through_json_between_registries() {
        let worker = Metrics::new();
        for _ in 0..3 {
            worker.observe(200, Duration::from_millis(4));
            worker.record_route("api", 200, Duration::from_millis(4));
            worker.record_upstream("backend", 200, Duration::from_millis(4));
            worker.cache_hit();
            worker.request_bytes(8);
            worker.response_bytes(16);
            worker.reload_ok();
        }
        worker.set_upstreams(2, 0);

        let json = serde_json::to_string(&worker.take_delta()).expect("serialise delta");
        let aggregate = Metrics::new();
        for _ in 0..2 {
            let delta: Delta = serde_json::from_str(&json).expect("deserialise delta");
            aggregate.apply_counters(&delta);
        }
        aggregate.apply_gauges(&serde_json::from_str(&json).expect("deserialise delta"));

        let text = aggregate.render();
        assert!(line(&text, "elira_requests_total{class=\"2xx\"} 6"));
        assert_eq!(
            series_value(&text, "elira_request_duration_seconds_count"),
            "6"
        );
        assert_eq!(
            series_value(&text, "elira_route_duration_seconds_count{route=\"api\"}"),
            "6"
        );
        assert_eq!(
            series_value(
                &text,
                "elira_upstream_duration_seconds_count{upstream=\"backend\"}"
            ),
            "6"
        );
        assert!(line(&text, "elira_cache_requests_total{result=\"hit\"} 6"));
        assert_eq!(series_value(&text, "elira_request_bytes_total"), "48");
        assert_eq!(series_value(&text, "elira_response_bytes_total"), "96");
        assert!(line(&text, "elira_reloads_total{result=\"ok\"} 6"));
        assert_eq!(series_value(&text, "elira_connections_in_flight"), "0");
        assert_eq!(series_value(&text, "elira_upstreams{state=\"up\"}"), "2");
        assert_valid_exposition(&text);
    }

    fn assert_valid_exposition(text: &str) {
        assert!(text.ends_with('\n'), "exposition must end with a newline");
        for line in text.lines() {
            if line.starts_with('#') {
                assert!(
                    line.starts_with("# HELP ") || line.starts_with("# TYPE "),
                    "invalid comment line: {line:?}"
                );
                continue;
            }
            assert!(!line.is_empty(), "empty exposition line");

            let (series, value) = line
                .rsplit_once(' ')
                .unwrap_or_else(|| panic!("missing value: {line:?}"));
            value
                .parse::<f64>()
                .unwrap_or_else(|_| panic!("invalid value in: {line:?}"));
            validate_series(series);
        }
    }

    fn validate_series(series: &str) {
        let (name, labels) = match series.split_once('{') {
            Some((name, rest)) => {
                let labels = rest
                    .strip_suffix('}')
                    .unwrap_or_else(|| panic!("unterminated labels in: {series:?}"));
                (name, Some(labels))
            }
            None => (series, None),
        };
        assert!(valid_metric_name(name), "invalid metric name: {series:?}");

        let Some(mut rest) = labels else {
            return;
        };
        if rest.is_empty() {
            return;
        }

        loop {
            let (key, after_key) = rest
                .split_once('=')
                .unwrap_or_else(|| panic!("missing '=' in: {series:?}"));
            assert!(valid_label_name(key), "invalid label name: {series:?}");
            let after_quote = after_key
                .strip_prefix('"')
                .unwrap_or_else(|| panic!("unquoted label value: {series:?}"));

            let mut escaped = false;
            let mut closing = None;
            for (index, ch) in after_quote.char_indices() {
                if escaped {
                    match ch {
                        '\\' | '"' | 'n' => escaped = false,
                        _ => panic!("invalid escape in label value: {series:?}"),
                    }
                    continue;
                }
                match ch {
                    '\\' => escaped = true,
                    '"' => {
                        closing = Some(index);
                        break;
                    }
                    _ => {}
                }
            }
            assert!(!escaped, "trailing escape in: {series:?}");
            let closing = closing.unwrap_or_else(|| panic!("unterminated value: {series:?}"));

            let remainder = &after_quote[closing + 1..];
            if remainder.is_empty() {
                break;
            }
            rest = remainder
                .strip_prefix(',')
                .unwrap_or_else(|| panic!("missing ',' in: {series:?}"));
        }
    }

    fn valid_metric_name(name: &str) -> bool {
        let mut chars = name.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !(first.is_ascii_alphabetic() || first == '_' || first == ':') {
            return false;
        }
        chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':')
    }

    fn valid_label_name(name: &str) -> bool {
        let mut chars = name.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !(first.is_ascii_alphabetic() || first == '_') {
            return false;
        }
        chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    }

    #[test]
    fn upstream_load_is_a_gauge() {
        let metrics = Metrics::new();
        metrics.set_upstream_load("app", 3);
        assert!(metrics
            .render()
            .contains("elira_upstream_active_requests{upstream=\"app\"} 3"));
        let delta = metrics.take_delta();
        assert_eq!(delta.upstream_load, vec![("app".to_owned(), 3)]);
    }

    #[test]
    fn stale_and_health_counters_render() {
        let metrics = Metrics::new();
        metrics.cache_stale();
        metrics.health_check(true);
        metrics.health_check(false);
        let text = metrics.render();
        assert!(line(
            &text,
            "elira_cache_requests_total{result=\"stale\"} 1"
        ));
        assert!(line(&text, "elira_health_checks_total{result=\"ok\"} 1"));
        assert!(line(
            &text,
            "elira_health_checks_total{result=\"failed\"} 1"
        ));
    }

    #[test]
    fn certificate_expiry_is_a_gauge() {
        let metrics = Metrics::new();
        metrics.set_certificate_expiry("/tmp/cert.pem", 1_900_000_000);
        assert!(metrics
            .render()
            .contains("elira_tls_certificate_expires_seconds{path=\"/tmp/cert.pem\"} 1900000000"));
    }

    #[test]
    fn h2_pool_gauges_render() {
        let metrics = Metrics::new();
        metrics.set_h2_pool("app", 2, 3, 10, 1);
        let text = metrics.render();
        assert!(line(&text, "elira_h2_pool_connections{upstream=\"app\"} 2"));
        assert!(line(
            &text,
            "elira_h2_pool_active_streams{upstream=\"app\"} 3"
        ));
        assert!(line(
            &text,
            "elira_h2_pool_total_connections{upstream=\"app\"} 10"
        ));
        assert!(line(
            &text,
            "elira_h2_pool_queued_streams{upstream=\"app\"} 1"
        ));
    }

    #[test]
    fn h3_pool_gauges_render() {
        let metrics = Metrics::new();
        metrics.set_h3_pool("app", 2, 3, 10);
        let text = metrics.render();
        assert!(line(&text, "elira_h3_pool_connections{upstream=\"app\"} 2"));
        assert!(line(
            &text,
            "elira_h3_pool_active_requests{upstream=\"app\"} 3"
        ));
        assert!(line(
            &text,
            "elira_h3_pool_total_connections{upstream=\"app\"} 10"
        ));
    }
}
