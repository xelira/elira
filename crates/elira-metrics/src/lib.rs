//! Request metrics in the Prometheus text exposition format.
//!
//! All values live in atomics so the request path records an outcome without
//! taking a lock or waiting for a scrape. [`Metrics::render`] snapshots them
//! into text; no state is reset by rendering.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

const STATUS_CLASSES: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];

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
        }
    }

    /// Record one finished request.
    pub fn observe(&self, status: u16, duration: Duration) {
        self.requests[status_class(status)].fetch_add(1, Ordering::Relaxed);

        let nanos = duration.as_nanos().min(u64::MAX as u128) as u64;
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
    /// Output order is fixed: status classes in order, histogram buckets by
    /// ascending bound with `+Inf` last, then the gauges.
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
}
