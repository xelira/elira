use super::*;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use http::header::{CONNECTION, TRANSFER_ENCODING, UPGRADE};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};

use elira_config::Balance;

use elira_upstream::{https_connector, TlsOptions};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

#[tokio::test]
async fn capped_body_errors_after_the_limit() {
    let frames = futures_util::stream::iter(vec![
        Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"0123456789"))),
        Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"abc"))),
    ]);
    let body = capped_body(BodyExt::boxed(StreamBody::new(frames)), 10);
    let err = BodyExt::collect(body).await.expect_err("over the cap");
    assert!(err.to_string().contains("upstream response too large"));
}

#[test]
fn canonical_host_ignores_port_and_case() {
    assert_eq!(
        canonical_host("Example.COM:8080").map(|h| h.0).as_deref(),
        Some("example.com")
    );
    assert_eq!(
        canonical_host("example.com.").map(|h| h.0).as_deref(),
        Some("example.com")
    );
}

#[test]
fn canonical_host_rejects_userinfo_and_bad_port() {
    assert!(canonical_host("admin:80@example.com").is_none());
    assert!(canonical_host("example.com:abc").is_none());
    assert!(canonical_host("::1").is_none());
}

#[test]
fn canonical_host_keeps_bracketed_ipv6() {
    assert_eq!(
        canonical_host("[::1]:8080").map(|h| h.1),
        Some("[::1]:8080".to_owned())
    );
}

#[test]
fn header_limits_count_names_values_and_overhead() {
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("a"), HeaderValue::from_static("1"));
    assert!(headers_within_limits(&headers, 1, 6));
    assert!(!headers_within_limits(&headers, 1, 5));
    assert!(!headers_within_limits(&headers, 0, 100));

    headers.insert(HeaderName::from_static("b"), HeaderValue::from_static("2"));
    assert!(!headers_within_limits(&headers, 1, 100));
    assert!(headers_within_limits(&headers, 2, 100));
}

#[test]
fn spool_budget_reserves_and_releases_bytes() {
    let budget = Arc::new(SpoolBudget::new(100));
    let first = budget.reserve(60).expect("first reservation");
    assert_eq!(budget.used(), 60);
    assert!(budget.reserve(50).is_none(), "over budget");

    let second = budget.reserve(40).expect("fits exactly");
    assert_eq!(budget.used(), 100);
    drop(first);
    assert_eq!(budget.used(), 40);
    drop(second);
    assert_eq!(budget.used(), 0);

    let unlimited = Arc::new(SpoolBudget::new(0));
    let permit = unlimited.reserve(u64::MAX).expect("unlimited");
    drop(permit);
    assert_eq!(unlimited.used(), 0);
}

#[test]
fn hop_by_hop_headers_are_recognised() {
    assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
    assert!(is_hop_by_hop(&HeaderName::from_static("connection")));
    assert!(is_hop_by_hop(&HeaderName::from_static("proxy-connection")));
    assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
}

#[test]
fn forwarding_headers_are_recognised() {
    assert!(is_client_forwarding(&HeaderName::from_static(
        "x-forwarded-for"
    )));
    assert!(is_client_forwarding(&HeaderName::from_static(
        "x-forwarded-ssl"
    )));
    assert!(is_client_forwarding(&HeaderName::from_static("x-real-ip")));
    assert!(is_client_forwarding(&HeaderName::from_static(
        "x_forwarded_for"
    )));
    assert!(!is_client_forwarding(&HeaderName::from_static("host")));
}

#[test]
fn only_plain_chunked_is_accepted() {
    let mut headers = HeaderMap::new();
    assert!(transfer_encoding_is_plain_chunked(&headers));

    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    assert!(transfer_encoding_is_plain_chunked(&headers));

    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));
    assert!(!transfer_encoding_is_plain_chunked(&headers));
}

#[test]
fn least_conn_prefers_the_idle_server() {
    let tls = TlsOptions::default();
    let client = Client::builder(TokioExecutor::new())
        .build(https_connector(&tls, elira_upstream::Resolver::default()).expect("connector"));
    let pool = Pool {
        name: "test".to_owned(),
        servers: vec![
            ServerAddr::Tcp("127.0.0.1:1".parse().unwrap()),
            ServerAddr::Tcp("127.0.0.1:2".parse().unwrap()),
        ],
        health: vec![AtomicBool::new(true), AtomicBool::new(true)],
        active: vec![AtomicUsize::new(0), AtomicUsize::new(5)],
        backup: vec![false, false],
        down: vec![false, false],
        max_conns: vec![0, 0],
        slow_start: vec![Duration::ZERO, Duration::ZERO],
        recover_at: vec![AtomicU64::new(0), AtomicU64::new(0)],
        passive: vec![
            Passive {
                failures: AtomicU32::new(0),
                ejected_until_ms: AtomicU64::new(0),
            },
            Passive {
                failures: AtomicU32::new(0),
                ejected_until_ms: AtomicU64::new(0),
            },
        ],
        failures_before_eject: 0,
        eject_for: Duration::from_secs(30),
        started: Instant::now(),
        hash_key: RequestKey::Ip,
        server_labels: vec!["127.0.0.1:1".to_owned(), "127.0.0.1:2".to_owned()],
        weights: vec![1, 1],
        retry_on: RetryOn::parse(&[]),
        next: AtomicUsize::new(0),
        balance: Balance::LeastConn,
        retries: 0,
        scheme: "http",
        client: std::sync::RwLock::new(client),
        served: AtomicU64::new(0),
        keepalive_requests: 0,
        idle_timeout: Duration::from_secs(30),
        max_idle: None,
        tls,
        tls_config: std::sync::Arc::new(
            elira_upstream::client_config(&TlsOptions::default()).expect("tls config"),
        ),
        resolver: elira_upstream::Resolver::default(),
        proxy_protocol: false,
        health_path: None,
        health_method: None,
        health_status: None,
        health_host: None,
        h2: None,
        h1: None,
        h3: None,
    };

    assert_eq!(pool.pick().expect("server"), 0);
    pool.active[0].store(10, Ordering::Relaxed);
    assert_eq!(pool.pick().expect("server"), 1);
}

#[test]
fn weighted_least_conn_compares_active_over_weight() {
    let tls = TlsOptions::default();
    let client = Client::builder(TokioExecutor::new())
        .build(https_connector(&tls, elira_upstream::Resolver::default()).expect("connector"));
    let pool = Pool {
        name: "test".to_owned(),
        servers: vec![
            ServerAddr::Tcp("127.0.0.1:1".parse().unwrap()),
            ServerAddr::Tcp("127.0.0.1:2".parse().unwrap()),
        ],
        health: vec![AtomicBool::new(true), AtomicBool::new(true)],
        active: vec![AtomicUsize::new(3), AtomicUsize::new(3)],
        backup: vec![false, false],
        down: vec![false, false],
        max_conns: vec![0, 0],
        slow_start: vec![Duration::ZERO, Duration::ZERO],
        recover_at: vec![AtomicU64::new(0), AtomicU64::new(0)],
        passive: vec![
            Passive {
                failures: AtomicU32::new(0),
                ejected_until_ms: AtomicU64::new(0),
            },
            Passive {
                failures: AtomicU32::new(0),
                ejected_until_ms: AtomicU64::new(0),
            },
        ],
        failures_before_eject: 0,
        eject_for: Duration::from_secs(30),
        started: Instant::now(),
        hash_key: RequestKey::Ip,
        server_labels: vec!["127.0.0.1:1".to_owned(), "127.0.0.1:2".to_owned()],
        weights: vec![1, 3],
        retry_on: RetryOn::parse(&[]),
        next: AtomicUsize::new(0),
        balance: Balance::LeastConn,
        retries: 0,
        scheme: "http",
        client: std::sync::RwLock::new(client),
        served: AtomicU64::new(0),
        keepalive_requests: 0,
        idle_timeout: Duration::from_secs(30),
        max_idle: None,
        tls,
        tls_config: std::sync::Arc::new(
            elira_upstream::client_config(&TlsOptions::default()).expect("tls config"),
        ),
        resolver: elira_upstream::Resolver::default(),
        proxy_protocol: false,
        health_path: None,
        health_method: None,
        health_status: None,
        health_host: None,
        h2: None,
        h1: None,
        h3: None,
    };

    assert_eq!(pool.pick().expect("server"), 1, "3/3 beats 3/1");
    pool.active[0].store(0, Ordering::Relaxed);
    pool.active[1].store(0, Ordering::Relaxed);
    pool.next.store(0, Ordering::Relaxed);
    assert_eq!(pool.pick().expect("server"), 0);
}

#[tokio::test]
async fn health_probe_honours_method_host_and_expected_status() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let addr = listener.local_addr().expect("probe addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..read]);
                let status = if head.starts_with("HEAD /ready ")
                    && head.to_ascii_lowercase().contains("host: health.local")
                {
                    "204 No Content"
                } else {
                    "503 Service Unavailable"
                };
                let _ = stream
                    .write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n").as_bytes())
                    .await;
            });
        }
    });

    let server = ServerAddr::Tcp(format!("{addr}").parse().expect("authority"));
    let tls = TlsOptions::default();
    let resolver = elira_upstream::Resolver::default();
    let probe = |path: &'static str, expect: &'static [u16]| Probe {
        path,
        method: "HEAD",
        host: Some("health.local"),
        expect,
        timeout: Duration::from_secs(2),
        tls: false,
        options: &tls,
        resolver: &resolver,
    };

    assert!(probe_server(&server, &probe("/ready", &[204])).await);
    assert!(probe_server(&server, &probe("/ready", &[])).await);
    assert!(!probe_server(&server, &probe("/broken", &[204])).await);
    assert!(probe_server(&server, &probe("/broken", &[503])).await);
}

#[test]
fn passive_ejection_skips_a_failing_server_until_the_cooldown() {
    let tls = TlsOptions::default();
    let client = Client::builder(TokioExecutor::new())
        .build(https_connector(&tls, elira_upstream::Resolver::default()).expect("connector"));
    let pool = Pool {
        name: "test".to_owned(),
        servers: vec![
            ServerAddr::Tcp("127.0.0.1:1".parse().unwrap()),
            ServerAddr::Tcp("127.0.0.1:2".parse().unwrap()),
        ],
        health: vec![AtomicBool::new(true), AtomicBool::new(true)],
        active: vec![AtomicUsize::new(0), AtomicUsize::new(0)],
        backup: vec![false, false],
        down: vec![false, false],
        max_conns: vec![0, 0],
        slow_start: vec![Duration::ZERO, Duration::ZERO],
        recover_at: vec![AtomicU64::new(0), AtomicU64::new(0)],
        passive: vec![
            Passive {
                failures: AtomicU32::new(0),
                ejected_until_ms: AtomicU64::new(0),
            },
            Passive {
                failures: AtomicU32::new(0),
                ejected_until_ms: AtomicU64::new(0),
            },
        ],
        failures_before_eject: 2,
        eject_for: Duration::from_secs(30),
        started: Instant::now(),
        hash_key: RequestKey::Ip,
        server_labels: vec!["127.0.0.1:1".to_owned(), "127.0.0.1:2".to_owned()],
        weights: vec![1, 1],
        retry_on: RetryOn::parse(&[]),
        next: AtomicUsize::new(0),
        balance: Balance::RoundRobin,
        retries: 0,
        scheme: "http",
        client: std::sync::RwLock::new(client),
        served: AtomicU64::new(0),
        keepalive_requests: 0,
        idle_timeout: Duration::from_secs(30),
        max_idle: None,
        tls,
        tls_config: std::sync::Arc::new(
            elira_upstream::client_config(&TlsOptions::default()).expect("tls config"),
        ),
        resolver: elira_upstream::Resolver::default(),
        proxy_protocol: false,
        health_path: None,
        health_method: None,
        health_status: None,
        health_host: None,
        h2: None,
        h1: None,
        h3: None,
    };

    pool.record_failure(0);
    pool.next.store(0, Ordering::Relaxed);
    assert_eq!(
        pool.pick().expect("server"),
        0,
        "one failure must not eject the server"
    );

    pool.record_failure(0);
    pool.next.store(0, Ordering::Relaxed);
    assert_eq!(
        pool.pick().expect("server"),
        1,
        "the ejected server is skipped"
    );

    pool.record_success(0);
    pool.next.store(0, Ordering::Relaxed);
    assert_eq!(pool.pick().expect("server"), 0);
}

#[test]
fn rendezvous_only_moves_keys_owned_by_a_removed_server() {
    let labels = ["a", "b", "c"];
    for index in 0..500 {
        let key = format!("client-{index}");
        let full = labels
            .iter()
            .copied()
            .max_by_key(|label| rendezvous(&key, label))
            .expect("winner");

        for removed in labels {
            if removed == full {
                continue;
            }
            let reduced: Vec<_> = labels
                .iter()
                .copied()
                .filter(|label| *label != removed)
                .collect();
            let winner = reduced
                .iter()
                .copied()
                .max_by_key(|label| rendezvous(&key, label))
                .expect("winner");
            assert_eq!(winner, full, "key {key} moved when {removed} was removed");
        }
    }
}

#[test]
fn module_owner_must_be_root_or_the_server_user() {
    assert!(super::module_owner_allowed(0, 1000));
    assert!(super::module_owner_allowed(1000, 1000));
    assert!(!super::module_owner_allowed(1001, 1000));
}

#[test]
fn upgrade_needs_both_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    assert!(wants_upgrade(&headers).is_none());

    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
    assert_eq!(
        wants_upgrade(&headers),
        Some(HeaderValue::from_static("websocket"))
    );
}

#[tokio::test(start_paused = true)]
async fn rate_limit_body_spaces_chunks() {
    let payload = Bytes::from(vec![0u8; 32 * 1024]);
    let body = http_body_util::Full::new(payload)
        .map_err(|never| -> BoxError { match never {} })
        .boxed();
    let mut body = rate_limit_body(body, 1024, 0);
    let started = tokio::time::Instant::now();
    let mut total = 0;
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("frame");
        if let Ok(data) = frame.into_data() {
            total += data.len();
        }
    }
    let elapsed = started.elapsed();
    assert_eq!(total, 32 * 1024);
    assert!(
        elapsed >= Duration::from_secs(30),
        "32 KiB at 1 KiB/s took {elapsed:?}"
    );
}
