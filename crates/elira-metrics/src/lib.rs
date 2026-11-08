//! Request metrics in the Prometheus text exposition format.
//!
//! Global values live in atomics so the request path records an outcome
//! without taking a lock or waiting for a scrape. Per-route and per-upstream
//! series need a short critical section around a [`BTreeMap`]; the number of
//! distinct labels is capped so untrusted names cannot grow it without bound.
//! [`Metrics::render`] snapshots everything into text; no state is reset by
//! rendering.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

const STATUS_CLASSES: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];

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
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    reloads_ok: AtomicU64,
    reloads_failed: AtomicU64,
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
            request_bytes: AtomicU64::new(0),
            response_bytes: AtomicU64::new(0),
            reloads_ok: AtomicU64::new(0),
            reloads_failed: AtomicU64::new(0),
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
}
