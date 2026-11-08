//! End-to-end tests: a real listener, a real upstream, real sockets.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use elira::config::Config;
use elira::server::{self, Options, Runtime};
use elira_metrics::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// An HTTP upstream that echoes the request head in the response body.
/// Websocket handshakes get a 101 and an echo loop instead.
async fn upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };

            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0u8; 4096];

                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&chunk[..read]);
                    if head.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }

                let text = String::from_utf8_lossy(&head).to_string();

                if text.to_ascii_lowercase().contains("upgrade: websocket") {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\n\
                              Upgrade: websocket\r\n\
                              Connection: Upgrade\r\n\r\n",
                        )
                        .await;

                    loop {
                        let Ok(read) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        if stream.write_all(&chunk[..read]).await.is_err() {
                            return;
                        }
                    }
                }

                let body = if text.starts_with("GET /big ") {
                    "x".repeat(4096)
                } else {
                    text.clone()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    addr
}

/// A TCP server that echoes bytes back. Used by the CONNECT tests.
async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };

            tokio::spawn(async move {
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    if stream.write_all(&chunk[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    addr
}

/// Start the real server on an ephemeral port. Keep the returned sender alive
/// for the duration of the test: dropping it stops the server.
async fn start(config: &str) -> (SocketAddr, watch::Sender<bool>, Arc<Metrics>) {
    let cfg = Config::parse(config).expect("parse config");
    let runtime = Arc::new(ArcSwap::from_pointee(
        Runtime::build(&cfg).expect("build runtime"),
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");

    let (stop_tx, stop_rx) = watch::channel(false);
    let metrics = Arc::new(Metrics::new());
    tokio::spawn(server::serve(
        listener,
        runtime,
        Options::from_config(&cfg),
        metrics.clone(),
        stop_rx,
    ));

    (addr, stop_tx, metrics)
}

/// Send a request with `Connection: close` and read until the server hangs up.
async fn roundtrip(addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => response.extend_from_slice(&chunk[..read]),
            Ok(Err(_)) => break,
        }
    }

    String::from_utf8_lossy(&response).to_string()
}

fn status(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

const NO_DEFAULT: &str = r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
"#;

#[tokio::test]
async fn routes_by_host_and_drops_spoofed_headers() {
    let upstream = upstream().await;
    let config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /hello?x=1 HTTP/1.1\r\n\
         Host: Example.COM:8080\r\n\
         X-Forwarded-For: 1.2.3.4\r\n\
         X-Real-IP: 5.6.7.8\r\n\
         X-Forwarded-Ssl: on\r\n\
         Connection: close, X-Secret\r\n\
         X-Secret: leak\r\n\
         Proxy-Authorization: Basic zzz\r\n\r\n",
    )
    .await;

    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    // The echoed head is the body.
    assert!(response.contains("host: example.com:8080"), "{response}");
    assert!(
        response.contains("x-forwarded-for: 127.0.0.1"),
        "{response}"
    );
    assert!(response.contains("x-forwarded-proto: http"), "{response}");
    assert!(response.contains("via: 1.1 elira"), "{response}");
    assert!(
        !response.to_ascii_lowercase().contains("x-real-ip"),
        "{response}"
    );
    assert!(
        !response.to_ascii_lowercase().contains("x-forwarded-ssl"),
        "{response}"
    );
    assert!(
        !response.to_ascii_lowercase().contains("x-secret"),
        "{response}"
    );
    assert!(
        !response
            .to_ascii_lowercase()
            .contains("proxy-authorization"),
        "{response}"
    );
}

#[tokio::test]
async fn unknown_host_is_404_and_missing_host_is_400() {
    let upstream = upstream().await;
    let config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    let (addr, _stop, _metrics) = start(&config).await;

    let missing = roundtrip(addr, "GET / HTTP/1.1\r\nConnection: close\r\n\r\n").await;
    assert_eq!(status(&missing), "HTTP/1.1 400 Bad Request");

    let unknown = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: nope.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&unknown), "HTTP/1.1 404 Not Found");
}

#[tokio::test]
async fn idle_connection_is_closed() {
    let upstream = upstream().await;
    let mut config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    config.push_str("\n[limits]\nidle_timeout_secs = 1\n");
    let (addr, _stop, _metrics) = start(&config).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write");

    // Consume the response, then wait past the idle timeout.
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
        }
    }

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "connection should be closed, got {closed:?}"
    );
}

#[tokio::test]
async fn websocket_upgrade_is_tunnelled() {
    let upstream = upstream().await;
    let config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    let (addr, _stop, _metrics) = start(&config).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\n\r\n",
        )
        .await
        .expect("write");

    let mut head = [0u8; 1024];
    let read = stream.read(&mut head).await.expect("read 101");
    let head = String::from_utf8_lossy(&head[..read]).to_string();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    stream.write_all(b"ping").await.expect("write frame");
    let mut echo = [0u8; 16];
    let read = stream.read(&mut echo).await.expect("read echo");
    assert_eq!(&echo[..read], b"ping");

    stream.write_all(b"second").await.expect("write frame");
    let read = stream.read(&mut echo).await.expect("read echo");
    assert_eq!(&echo[..read], b"second");
}

#[tokio::test]
async fn connect_reaches_allowed_targets_only() {
    let echo = tcp_echo().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[connect]
enabled = true
allow = ["{echo}"]

[[upstreams]]
name = "app"
servers = ["{echo}"]

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .await
        .expect("write");

    let mut head = [0u8; 1024];
    let read = stream.read(&mut head).await.expect("read 200");
    let head = String::from_utf8_lossy(&head[..read]).to_string();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    stream.write_all(b"ping").await.expect("write");
    let mut echo_buf = [0u8; 16];
    let read = stream.read(&mut echo_buf).await.expect("read echo");
    assert_eq!(&echo_buf[..read], b"ping");

    let denied = roundtrip(
        addr,
        "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&denied), "HTTP/1.1 403 Forbidden");
}

fn temp_root(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    let path = std::env::temp_dir().join(format!(
        "elira-static-{}-{}-{}",
        std::process::id(),
        label,
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).expect("create root");
    path
}

#[tokio::test]
async fn serves_files_with_ranges_and_conditionals() {
    let root = temp_root("files");
    std::fs::write(root.join("index.html"), "<h1>index</h1>").unwrap();
    std::fs::write(root.join("file.txt"), "hello world").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{}"
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let index = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&index), "HTTP/1.1 200 OK");
    assert!(index.contains("content-type: text/html"), "{index}");
    assert!(index.ends_with("<h1>index</h1>"));

    let file = roundtrip(
        addr,
        "GET /file.txt HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&file), "HTTP/1.1 200 OK");
    assert!(file.ends_with("hello world"));

    let etag = file
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("etag:"))
        .map(|line| line["etag:".len()..].trim().to_owned())
        .expect("etag header");

    let range = roundtrip(
        addr,
        "GET /file.txt HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-4\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&range), "HTTP/1.1 206 Partial Content");
    assert!(range.contains("content-range: bytes 0-4/11"), "{range}");
    assert!(range.ends_with("hello"));

    let cached = roundtrip(
        addr,
        &format!(
            "GET /file.txt HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: {etag}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status(&cached), "HTTP/1.1 304 Not Modified");

    let missing = roundtrip(
        addr,
        "GET /missing HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&missing), "HTTP/1.1 404 Not Found");
}

#[tokio::test]
async fn static_root_blocks_traversal_and_supports_spa() {
    let root = temp_root("spa");
    std::fs::write(root.join("index.html"), "<h1>app</h1>").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{}"
spa = true
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let traversal = roundtrip(
        addr,
        "GET /../Cargo.toml HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&traversal), "HTTP/1.1 403 Forbidden");

    let encoded = roundtrip(
        addr,
        "GET /%2e%2e%2fCargo.toml HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&encoded), "HTTP/1.1 403 Forbidden");

    let spa = roundtrip(
        addr,
        "GET /some/client/route HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&spa), "HTTP/1.1 200 OK");
    assert!(spa.ends_with("<h1>app</h1>"));
}

#[tokio::test]
async fn metrics_listener_reports_requests() {
    let upstream = upstream().await;
    let config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    let (addr, _stop, metrics) = start(&config).await;

    let metrics_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind metrics");
    let metrics_addr = metrics_listener.local_addr().expect("metrics addr");
    let (_metrics_stop, metrics_stop_rx) = watch::channel(false);
    let status_runtime = Arc::new(ArcSwap::from_pointee(
        Runtime::build(&Config::parse(&config).expect("parse")).expect("runtime"),
    ));
    let (reload_tx, _reload_rx) = watch::channel(0u64);
    let (drain_tx, _drain_rx) = watch::channel(false);
    server::spawn_metrics(
        metrics_listener,
        status_runtime,
        metrics.clone(),
        None,
        reload_tx,
        drain_tx,
        metrics_stop_rx,
    );

    roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let body = roundtrip(
        metrics_addr,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        body.contains("elira_requests_total{class=\"2xx\"}"),
        "{body}"
    );
    assert!(
        body.contains("elira_request_duration_seconds_count"),
        "{body}"
    );
    assert!(body.contains("elira_connections_in_flight"), "{body}");

    let status = roundtrip(
        metrics_addr,
        "GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(status.contains("application/json"), "{status}");
    assert!(status.contains("\"upstreams\""), "{status}");
}

#[tokio::test]
async fn compresses_large_text_for_clients_that_ask() {
    let upstream = upstream().await;
    let config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    let (addr, _stop, _metrics) = start(&config).await;

    let plain = roundtrip(
        addr,
        "GET /big HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(!plain.to_ascii_lowercase().contains("content-encoding"));
    assert!(plain.ends_with(&"x".repeat(4096)));

    let gz = roundtrip(
        addr,
        "GET /big HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        gz.to_ascii_lowercase().contains("content-encoding: gzip"),
        "{gz}"
    );
    assert!(
        gz.to_ascii_lowercase().contains("vary: accept-encoding"),
        "{gz}"
    );
    assert!(!gz.contains(&"x".repeat(4096)));
}

#[tokio::test]
async fn rejects_bodies_over_the_limit() {
    let upstream = upstream().await;
    let mut config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    config.push_str("\n[limits]\nmax_body_bytes = 10\n");
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 413 Payload Too Large");
}

#[tokio::test]
async fn rate_limits_per_client() {
    let upstream = upstream().await;
    let mut config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    config.push_str("\n[limits]\nrequests_per_second = 1\nburst = 1\n");
    let (addr, _stop, _metrics) = start(&config).await;

    let first = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&first), "HTTP/1.1 200 OK");

    let second = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&second), "HTTP/1.1 429 Too Many Requests");
}

#[tokio::test]
async fn trusted_proxies_extend_the_forwarded_chain() {
    let upstream = upstream().await;
    let mut config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    config.push_str("\n[limits]\ntrusted_proxies = [\"127.0.0.1/32\"]\n");
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 9.9.9.9\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response.contains("x-forwarded-for: 9.9.9.9, 127.0.0.1"),
        "{response}"
    );
}

#[tokio::test]
async fn retries_a_dead_upstream_for_get() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:1", "{upstream}"]
retries = 1

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK");
}

#[tokio::test]
async fn does_not_retry_when_disabled() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:1", "{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 502 Bad Gateway");
}

async fn read_all(mut stream: TcpStream) -> String {
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => response.extend_from_slice(&chunk[..read]),
            Ok(Err(_)) => break,
        }
    }

    String::from_utf8_lossy(&response).to_string()
}

fn proxy_config(upstream: SocketAddr) -> String {
    format!(
        r#"
listen = "127.0.0.1:0"
proxy_protocol = true

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#
    )
}

#[tokio::test]
async fn proxy_protocol_v1_sets_the_client_address() {
    let upstream = upstream().await;
    let (addr, _stop, _metrics) = start(&proxy_config(upstream)).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"PROXY TCP4 203.0.113.7 127.0.0.1 5555 8080\r\n")
        .await
        .expect("write header");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let response = read_all(stream).await;
    assert!(
        response.contains("x-forwarded-for: 203.0.113.7"),
        "{response}"
    );
}

#[tokio::test]
async fn proxy_protocol_v2_sets_the_client_address() {
    let upstream = upstream().await;
    let (addr, _stop, _metrics) = start(&proxy_config(upstream)).await;

    let mut header = Vec::new();
    header.extend_from_slice(&[
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    ]);
    header.push(0x21);
    header.push(0x11);
    header.extend_from_slice(&12u16.to_be_bytes());
    header.extend_from_slice(&[203, 0, 113, 7]);
    header.extend_from_slice(&[127, 0, 0, 1]);
    header.extend_from_slice(&5555u16.to_be_bytes());
    header.extend_from_slice(&8080u16.to_be_bytes());

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(&header).await.expect("write header");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let response = read_all(stream).await;
    assert!(
        response.contains("x-forwarded-for: 203.0.113.7"),
        "{response}"
    );
}

#[tokio::test]
async fn proxy_protocol_closes_connections_without_the_header() {
    let upstream = upstream().await;
    let (addr, _stop, _metrics) = start(&proxy_config(upstream)).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let response = read_all(stream).await;
    assert!(response.is_empty(), "{response}");
}

#[tokio::test]
async fn path_prefix_routes_and_strips() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
path = "/api"
upstream = "app"
strip_prefix = true

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let api = roundtrip(
        addr,
        "GET /api/users HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(api.contains("GET /users HTTP/1.1"), "{api}");

    let other = roundtrip(
        addr,
        "GET /other HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(other.contains("GET /other HTTP/1.1"), "{other}");
}

#[tokio::test]
async fn wildcard_host_matches_subdomains() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*.example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let matched = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&matched), "HTTP/1.1 200 OK");

    let missed = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&missed), "HTTP/1.1 404 Not Found");
}

#[tokio::test]
async fn redirect_routes_answer_without_an_upstream() {
    let config = r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
redirect = { to = "https://new.example.com/", status = 301 }
"#;
    let (addr, _stop, _metrics) = start(config).await;

    let response = roundtrip(
        addr,
        "GET /old HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 301 Moved Permanently");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("location: https://new.example.com/"),
        "{response}"
    );
}

#[tokio::test]
async fn route_headers_are_applied_and_server_header_can_hide() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"
server_header = false

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
add_headers = ["X-Frame-Options: DENY"]
remove_headers = ["Server"]
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let lower = response.to_ascii_lowercase();
    assert!(lower.contains("x-frame-options: deny"), "{response}");
    assert!(
        !lower.lines().any(|line| line.starts_with("server:")),
        "{response}"
    );
}

#[tokio::test]
async fn request_id_is_echoed_and_forwarded() {
    let upstream = upstream().await;
    let config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Request-Id: test-123\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-request-id: test-123"),
        "{response}"
    );
}

#[tokio::test]
async fn cache_reports_miss_then_hit() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[cache]
enabled = true
max_bytes = 1048576
max_item_bytes = 8192
ttl_secs = 60

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let first = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        first.to_ascii_lowercase().contains("x-cache: miss"),
        "{first}"
    );

    let second = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        second.to_ascii_lowercase().contains("x-cache: hit"),
        "{second}"
    );
}

#[tokio::test]
async fn brotli_is_preferred_when_offered() {
    let upstream = upstream().await;
    let config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /big HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip, br\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-encoding: br"),
        "{response}"
    );
    assert!(response
        .to_ascii_lowercase()
        .contains("vary: accept-encoding"));
}

#[tokio::test]
async fn precompressed_static_files_are_served() {
    let root = temp_root("precompressed");
    std::fs::write(root.join("app.js"), "console.log(1)").unwrap();
    std::fs::write(root.join("app.js.br"), "fake-brotli").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{}"
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let plain = roundtrip(
        addr,
        "GET /app.js HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(plain.ends_with("console.log(1)"), "{plain}");

    let compressed = roundtrip(
        addr,
        "GET /app.js HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: br\r\nConnection: close\r\n\r\n",
    )
    .await;
    let lower = compressed.to_ascii_lowercase();
    assert!(lower.contains("content-encoding: br"), "{compressed}");
    assert!(compressed.ends_with("fake-brotli"), "{compressed}");
}

#[tokio::test]
async fn try_files_rewrites_a_missing_path() {
    let root = temp_root("tryfiles");
    std::fs::write(root.join("about.html"), "<h1>about</h1>").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{}"
try_files = ["$uri", "$uri.html"]
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let about = roundtrip(
        addr,
        "GET /about HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&about), "HTTP/1.1 200 OK");
    assert!(about.ends_with("<h1>about</h1>"), "{about}");

    let missing = roundtrip(
        addr,
        "GET /nope HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&missing), "HTTP/1.1 404 Not Found");
}

#[tokio::test]
async fn autoindex_lists_a_directory() {
    let root = temp_root("autoindex");
    std::fs::create_dir_all(root.join("docs")).unwrap();
    std::fs::write(root.join("docs").join("a.txt"), "a").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{}"
autoindex = true
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let listing = roundtrip(
        addr,
        "GET /docs/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&listing), "HTTP/1.1 200 OK");
    assert!(listing
        .to_ascii_lowercase()
        .contains("content-type: text/html"));
    assert!(listing.contains("<a href=\"a.txt\">a.txt</a>"), "{listing}");

    let redirect = roundtrip(
        addr,
        "GET /docs HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&redirect), "HTTP/1.1 301 Moved Permanently");
}

async fn tls_upstream() -> SocketAddr {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../elira-tls/tests/fixtures");
    let config = elira_tls::server_config(&fixtures.join("cert.pem"), &fixtures.join("key.pem"))
        .expect("tls config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tls");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\
                          Connection: close\r\n\r\ntls",
                    )
                    .await;
            });
        }
    });

    addr
}

fn tls_proxy_config(upstream: SocketAddr, insecure: bool) -> String {
    let block = if insecure {
        "[upstream_tls]\ninsecure = true\n"
    } else {
        ""
    };

    format!(
        r#"
listen = "127.0.0.1:0"

{block}

[[upstreams]]
name = "secure"
servers = ["{upstream}"]
tls = true

[[routes]]
host = "*"
upstream = "secure"
"#
    )
}

#[tokio::test]
async fn proxies_to_a_tls_upstream() {
    let upstream = tls_upstream().await;
    let (addr, _stop, _metrics) = start(&tls_proxy_config(upstream, true)).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert!(response.ends_with("tls"), "{response}");
}

#[tokio::test]
async fn self_signed_tls_upstream_is_rejected_by_default() {
    let upstream = tls_upstream().await;
    let (addr, _stop, _metrics) = start(&tls_proxy_config(upstream, false)).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 502 Bad Gateway");
}

#[tokio::test]
async fn sendfile_serves_a_plain_static_get() {
    let root = temp_root("sendfile");
    std::fs::write(root.join("app.bin"), vec![b'x'; 256 * 1024]).unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"
server_header = false

[[routes]]
host = "*"
root = "{}"
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /app.bin HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK");

    // The zero-copy path writes its own headers, so the hyper `Server` header
    // is absent. Its presence would mean the request took the slow path.
    assert!(
        !response
            .to_ascii_lowercase()
            .lines()
            .any(|line| line.starts_with("server:")),
        "expected the sendfile path"
    );

    let body = response.split("\r\n\r\n").nth(1).expect("body");
    assert_eq!(body.len(), 256 * 1024);
}

#[tokio::test]
async fn sendfile_falls_back_for_ranges_and_compression() {
    let root = temp_root("sendfile-fallback");
    std::fs::write(root.join("app.bin"), vec![b'y'; 4096]).unwrap();
    std::fs::write(root.join("app.txt"), "hello ".repeat(4096)).unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{}"
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let ranged = roundtrip(
        addr,
        "GET /app.bin HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-9\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&ranged), "HTTP/1.1 206 Partial Content");

    // Conditional requests carry an ETag from the fast path but must be
    // answered by hyper, which owns the 304 logic.
    let first = roundtrip(
        addr,
        "GET /app.txt HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let etag = first
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("etag:"))
        .map(|line| line["etag:".len()..].trim().to_owned())
        .expect("etag");

    let cached = roundtrip(
        addr,
        &format!(
            "GET /app.txt HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: {etag}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status(&cached), "HTTP/1.1 304 Not Modified");
}

#[tokio::test]
async fn static_files_are_compressed_on_the_fly() {
    let root = temp_root("static-gzip");
    std::fs::write(root.join("app.css"), "body { color: red }\n".repeat(200)).unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[compression]
enabled = true
min_bytes = 64

[[routes]]
host = "*"
root = "{}"
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let plain = roundtrip(
        addr,
        "GET /app.css HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(plain.ends_with("body { color: red }\n"), "{plain}");

    let compressed = roundtrip(
        addr,
        "GET /app.css HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    let lower = compressed.to_ascii_lowercase();
    assert!(lower.contains("content-encoding: gzip"), "{compressed}");
    assert!(lower.contains("vary: accept-encoding"), "{compressed}");
    assert!(!compressed.contains("body { color: red }"), "{compressed}");
}

#[tokio::test]
async fn access_log_is_written_to_a_file() {
    let root = temp_root("logfile");
    std::fs::write(root.join("index.html"), "ok").unwrap();
    let log_path = root.join("access.log");

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[log]
format = "text"
file = "{log}"
max_bytes = 1048576

[[routes]]
host = "*"
root = "{root}"
"#,
        log = log_path.display(),
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let _ = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let logged = std::fs::read_to_string(&log_path).expect("log file");
    assert!(logged.contains("GET /"), "{logged}");
}

#[tokio::test]
async fn basic_auth_guards_a_route() {
    let upstream = upstream().await;
    let root = temp_root("auth");
    let htpasswd = root.join("htpasswd");
    let hash = bcrypt::hash("secret", 4).expect("bcrypt");
    std::fs::write(&htpasswd, format!("user:{hash}\n")).unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
auth_file = "{htpasswd}"
"#,
        htpasswd = htpasswd.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let anonymous = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&anonymous), "HTTP/1.1 401 Unauthorized");
    assert!(
        anonymous
            .to_ascii_lowercase()
            .contains("www-authenticate: basic"),
        "{anonymous}"
    );

    let wrong = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjp3cm9uZw==\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&wrong), "HTTP/1.1 401 Unauthorized");

    let good = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpzZWNyZXQ=\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&good), "HTTP/1.1 200 OK");
}

#[tokio::test]
async fn ip_acl_denies_and_allows() {
    let upstream = upstream().await;

    let denied = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
ip_deny = ["127.0.0.1/32"]
"#
    );
    let (addr, _stop, _metrics) = start(&denied).await;
    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 403 Forbidden");

    let allowed = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
ip_allow = ["127.0.0.1/32"]
"#
    );
    let (addr, _stop, _metrics) = start(&allowed).await;
    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK");
}

#[tokio::test]
async fn route_timeout_overrides_the_global_one() {
    // Accept the connection, read the request, then answer too late.
    let slow = TcpListener::bind("127.0.0.1:0").await.expect("bind slow");
    let slow_addr = slow.local_addr().expect("slow addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = slow.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            });
        }
    });

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "slow"
servers = ["{slow_addr}"]

[[routes]]
host = "*"
upstream = "slow"
timeout_secs = 1
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 504 Gateway Timeout");
}

/// An upstream that varies its answer by Accept-Language and says so.
async fn vary_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind vary upstream");
    let addr = listener.local_addr().expect("vary addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0u8; 2048];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    head.extend_from_slice(&chunk[..read]);
                    if read == 0 || head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let body = if text.contains("accept-language: de") {
                    "hallo"
                } else {
                    "hello"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nVary: Accept-Language\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn cache_honours_vary() {
    let upstream = vary_upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[cache]
enabled = true
ttl_secs = 60
max_item_bytes = 65536

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let english = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(english.ends_with("hello"), "{english}");

    let german = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Language: de\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(german.ends_with("hallo"), "{german}");

    let english_again = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(english_again.contains("x-cache: HIT"), "{english_again}");
    assert!(english_again.ends_with("hello"), "{english_again}");
}

#[tokio::test]
async fn cache_never_stores_authorized_requests() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[cache]
enabled = true
ttl_secs = 60
max_item_bytes = 65536

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let first = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer one\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(first.contains("Bearer one"), "{first}");

    let second = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer two\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(second.contains("Bearer two"), "{second}");
    assert!(!second.contains("x-cache: HIT"), "{second}");
}

#[tokio::test]
async fn error_page_replaces_a_missing_file() {
    let root = temp_root("error-page");
    std::fs::write(root.join("index.html"), "home").unwrap();
    std::fs::write(root.join("404.html"), "custom not found").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{root}"
error_pages = ["404 /404.html"]
"#,
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /missing HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 404 Not Found");
    assert!(response.ends_with("custom not found"), "{response}");
}

#[tokio::test]
async fn route_rate_limit_and_body_cap_apply() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
requests_per_second = 1
burst = 1
max_body_bytes = 10
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let first = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&first), "HTTP/1.1 200 OK");

    let limited = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&limited), "HTTP/1.1 429 Too Many Requests");

    // The limiter is per route, so a different host still has to pay the same
    // bucket after the wait, but the body cap is checked before forwarding.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let too_large = roundtrip(
        addr,
        "POST / HTTP/1.1\r\nHost: other.example\r\nContent-Length: 20\r\nConnection: close\r\n\r\n01234567890123456789",
    )
    .await;
    assert_eq!(status(&too_large), "HTTP/1.1 413 Payload Too Large");
}

#[tokio::test]
async fn mutual_tls_requires_a_client_certificate() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("ca");

    let server_key = KeyPair::generate().expect("server key");
    let server_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("server params");
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("server cert");

    let client_key = KeyPair::generate().expect("client key");
    let client_params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    let client = client_params
        .signed_by(&client_key, &ca, &ca_key)
        .expect("client cert");

    let root = temp_root("mtls");
    std::fs::write(root.join("server.pem"), server.pem()).unwrap();
    std::fs::write(root.join("server.key"), server_key.serialize_pem()).unwrap();
    std::fs::write(root.join("ca.pem"), ca.pem()).unwrap();

    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[tls]
cert = "{cert}"
key = "{key}"
client_ca = "{ca}"
client_auth = "required"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#,
        cert = root.join("server.pem").display(),
        key = root.join("server.key").display(),
        ca = root.join("ca.pem").display(),
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).expect("add ca");
    let base = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots);

    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");

    // No certificate: the handshake must fail, not fall through to the route.
    let anonymous = base.clone().with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(anonymous));
    let tcp = TcpStream::connect(addr).await.expect("connect");
    // With TLS 1.3 the client can finish its side before the server checks
    // the certificate, so the rejection may arrive on the first read.
    let rejected = match connector.connect(name.clone(), tcp).await {
        Err(_) => true,
        Ok(mut tls) => {
            let _ = tls
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await;
            let mut buf = [0u8; 128];
            matches!(
                tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await,
                Ok(Ok(0)) | Ok(Err(_)) | Err(_)
            )
        }
    };
    assert!(rejected, "a client without a certificate must be rejected");

    let with_cert = base
        .with_client_auth_cert(
            vec![rustls::pki_types::CertificateDer::from(
                client.der().to_vec(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(client_key.serialize_der().into()),
        )
        .expect("client auth config");
    let connector = tokio_rustls::TlsConnector::from(Arc::new(with_cert));
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let mut tls = connector
        .connect(name, tcp)
        .await
        .expect("mutual handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), tls.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => response.extend_from_slice(&chunk[..read]),
            Ok(Err(_)) => break,
        }
    }
    let response = String::from_utf8_lossy(&response).to_string();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got {response}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn proxies_to_a_unix_socket_upstream() {
    use tokio::net::UnixListener;

    let dir = temp_root("unix-upstream");
    let socket = dir.join("app.sock");
    let listener = UnixListener::bind(&socket).expect("bind unix upstream");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0u8; 2048];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    head.extend_from_slice(&chunk[..read]);
                    if read == 0 || head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\
                          Connection: close\r\n\r\nunix!",
                    )
                    .await;
            });
        }
    });

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["unix:{socket}"]

[[routes]]
host = "*"
upstream = "app"
"#,
        socket = socket.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /hello HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert!(response.ends_with("unix!"), "{response}");
}

#[cfg(unix)]
#[tokio::test]
async fn unix_listener_serves_http() {
    use tokio::net::{UnixListener, UnixStream};

    let dir = temp_root("unix-listen");
    let path = dir.join("elira.sock");
    let listener = UnixListener::bind(&path).expect("bind unix listener");

    let cfg = Config::parse(&format!(
        r#"
listen = "127.0.0.1:0"
listen_unix = "{}"

[[routes]]
host = "*"
root = "{}"
"#,
        path.display(),
        dir.display()
    ))
    .expect("config");
    std::fs::write(dir.join("index.html"), "via unix").unwrap();

    let runtime = Arc::new(ArcSwap::from_pointee(
        Runtime::build(&cfg).expect("runtime"),
    ));
    let metrics = Arc::new(Metrics::new());
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(server::serve_unix(
        listener,
        runtime,
        Options::from_config(&cfg),
        metrics,
        stop_rx,
    ));

    let mut stream = UnixStream::connect(&path).await.expect("connect unix");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => response.extend_from_slice(&chunk[..read]),
            Ok(Err(_)) => break,
        }
    }
    let response = String::from_utf8_lossy(&response).to_string();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("via unix"), "{response}");
    let _ = stop_tx.send(true);
}

#[tokio::test]
async fn stale_cache_entry_is_served_while_it_refreshes() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind varying upstream");
    let upstream = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2048];
                let _ = stream.read(&mut head).await;
                let body = format!("v{}", counter.fetch_add(1, Ordering::SeqCst) + 1);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: max-age=1\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[cache]
enabled = true
ttl_secs = 1
stale_secs = 5
max_item_bytes = 65536

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let first = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(first.ends_with("v1"), "{first}");

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let stale = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(stale.contains("x-cache: STALE"), "{stale}");
    assert!(stale.ends_with("v1"), "{stale}");

    tokio::time::sleep(Duration::from_millis(800)).await;

    let fresh = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(fresh.ends_with("v2"), "{fresh}");
}
