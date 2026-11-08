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
    server::spawn_metrics(metrics_listener, metrics.clone(), metrics_stop_rx);

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
