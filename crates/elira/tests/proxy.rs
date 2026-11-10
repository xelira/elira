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

                if text.starts_with("GET /chunked ") {
                    let mut response = String::from(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    );
                    for _ in 0..8 {
                        response.push_str("200\r\n");
                        response.push_str(&"y".repeat(512));
                        response.push_str("\r\n");
                    }
                    response.push_str("0\r\n\r\n");
                    let _ = stream.write_all(response.as_bytes()).await;
                    return;
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

/// An HTTP upstream whose response body is a fixed label, so a test can tell
/// which pool member served the request.
async fn labeled_upstream(label: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind labeled upstream");
    let addr = listener.local_addr().expect("labeled addr");

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
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    label.len(),
                    label
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    addr
}

/// An upstream that accepts a request and never answers, so a test can
/// exercise what the proxy does while a body is still being sent.
async fn silent_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent upstream");
    let addr = listener.local_addr().expect("silent addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut chunk = [0u8; 4096];
                while matches!(stream.read(&mut chunk).await, Ok(read) if read > 0) {}
            });
        }
    });

    addr
}

/// An HTTP upstream that answers after a delay, used by concurrency tests.
async fn slow_upstream(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind slow upstream");
    let addr = listener.local_addr().expect("slow addr");

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
                tokio::time::sleep(delay).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow",
                    )
                    .await;
            });
        }
    });

    addr
}

/// An HTTP upstream that reads the declared request body and echoes it.
async fn body_echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind body echo");
    let addr = listener.local_addr().expect("body echo addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    if let Some(index) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
                let length: usize = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = buffer[head_end..].to_vec();
                while body.len() < length {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    body.extend_from_slice(&chunk[..read]);
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });

    addr
}

/// An upstream that returns 502 on its first connection and 200 afterwards.
async fn flaky_upstream() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind flaky upstream");
    let addr = listener.local_addr().expect("flaky addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let counter = counter.clone();
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
                let attempt = counter.fetch_add(1, Ordering::SeqCst);
                let response = if attempt == 0 {
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned()
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nrecovered"
                        .to_owned()
                };
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    (addr, hits)
}

/// A hyper HTTP/1.1 upstream that collects the request body and echoes it,
/// including chunked input.
async fn hyper_echo_upstream() -> SocketAddr {
    use http_body_util::{BodyExt, Full};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hyper echo");
    let addr = listener.local_addr().expect("hyper echo addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async move {
                        let body = request
                            .into_body()
                            .collect()
                            .await
                            .expect("request body")
                            .to_bytes();
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("content-length", body.len())
                                .body(Full::new(body))
                                .expect("response"),
                        )
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
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
    let (addr, stop, metrics, _) = start_full(config).await;
    (addr, stop, metrics)
}

async fn start_full(
    config: &str,
) -> (
    SocketAddr,
    watch::Sender<bool>,
    Arc<Metrics>,
    Arc<ArcSwap<Runtime>>,
) {
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
        runtime.clone(),
        Options::from_config(&cfg),
        metrics.clone(),
        stop_rx,
    ));

    (addr, stop_tx, metrics, runtime)
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

#[tokio::test]
async fn websocket_over_http2_extended_connect() {
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"
h2c = true

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut request = hyper::Request::builder()
        .method(http::Method::CONNECT)
        .uri("http://example.com/ws")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .body(Empty::<Bytes>::new())
        .expect("extended CONNECT");
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));

    let response = sender
        .send_request(request)
        .await
        .expect("extended CONNECT");
    assert_eq!(response.status(), http::StatusCode::OK);

    let upgraded = hyper::upgrade::on(response).await.expect("upgrade");
    let mut upgraded = TokioIo::new(upgraded);
    upgraded.write_all(b"ping").await.expect("write");
    let mut echoed = [0u8; 4];
    upgraded.read_exact(&mut echoed).await.expect("read");
    assert_eq!(&echoed, b"ping");
}

#[tokio::test]
async fn connect_tunnels_over_http2() {
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let echo = tcp_echo().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"
h2c = true

[connect]
enabled = true
allow = ["{echo}"]

[[routes]]
host = "*"
return = {{ status = 404, body = "no route" }}
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = hyper::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("{echo}"))
        .body(Empty::<Bytes>::new())
        .expect("CONNECT request");
    let response = sender.send_request(request).await.expect("h2 CONNECT");
    assert_eq!(response.status(), http::StatusCode::OK);

    let upgraded = hyper::upgrade::on(response).await.expect("upgrade");
    let mut upgraded = TokioIo::new(upgraded);
    upgraded.write_all(b"ping").await.expect("write");
    let mut echoed = [0u8; 4];
    upgraded.read_exact(&mut echoed).await.expect("read");
    assert_eq!(&echoed, b"ping");
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
async fn try_files_reaches_a_named_location_and_internal_stays_hidden() {
    let root = temp_root("named");
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "example.com"
path = "/app"
root = "{}"
try_files = ["$uri", "@fallback"]

[[routes]]
host = "example.com"
name = "@fallback"
return = {{ status = 200, body = "fallback" }}

[[routes]]
host = "example.com"
path = "/internal"
internal = true
return = {{ status = 200, body = "secret" }}
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let fallback = roundtrip(
        addr,
        "GET /app/missing HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&fallback), "HTTP/1.1 200 OK", "{fallback}");
    assert!(fallback.ends_with("fallback"), "{fallback}");

    let hidden = roundtrip(
        addr,
        "GET /internal HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&hidden), "HTTP/1.1 404 Not Found", "{hidden}");

    let by_name = roundtrip(
        addr,
        "GET /@fallback HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&by_name), "HTTP/1.1 404 Not Found", "{by_name}");
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

    let if_range = roundtrip(
        addr,
        &format!(
            "GET /file.txt HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-4\r\n\
             If-Range: {etag}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(
        status(&if_range),
        "HTTP/1.1 206 Partial Content",
        "{if_range}"
    );
    assert!(if_range.ends_with("hello"), "{if_range}");

    let stale_range = roundtrip(
        addr,
        "GET /file.txt HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-4\r\n\
         If-Range: \"stale\"\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&stale_range), "HTTP/1.1 200 OK", "{stale_range}");
    assert!(stale_range.ends_with("hello world"), "{stale_range}");

    let multi = roundtrip(
        addr,
        "GET /file.txt HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-4,6-10\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&multi), "HTTP/1.1 206 Partial Content", "{multi}");
    let boundary = multi
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-type:"))
        .and_then(|line| line.split("boundary=").nth(1))
        .map(str::trim)
        .expect("multipart boundary");
    let lower = multi.to_ascii_lowercase();
    assert!(
        lower.contains("content-type: multipart/byteranges"),
        "{multi}"
    );
    assert!(lower.contains("content-range: bytes 0-4/11"), "{multi}");
    assert!(lower.contains("content-range: bytes 6-10/11"), "{multi}");
    assert!(lower.contains(&format!("--{boundary}--")), "{multi}");
    assert!(
        multi.contains("hello") && multi.contains("world"),
        "{multi}"
    );

    let merged = roundtrip(
        addr,
        "GET /file.txt HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-4,3-6\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&merged), "HTTP/1.1 206 Partial Content");
    assert!(merged.contains("content-range: bytes 0-6/11"), "{merged}");
    assert!(merged.ends_with("hello w"));

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
    let (addr, _stop, metrics, status_runtime) = start_full(&config).await;

    let metrics_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind metrics");
    let metrics_addr = metrics_listener.local_addr().expect("metrics addr");
    let (_metrics_stop, metrics_stop_rx) = watch::channel(false);
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

    let config = roundtrip(
        metrics_addr,
        "GET /config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(config.contains("application/json"), "{config}");
    assert!(config.contains("\"listen\""), "{config}");
    assert!(config.contains("\"upstreams\""), "{config}");
    assert!(config.contains("\"routes\""), "{config}");
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
async fn caps_an_upstream_response_with_a_known_length() {
    let upstream = upstream().await;
    let mut config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    config.push_str("\n[limits]\nmax_upstream_response_bytes = 1024\n");
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /big HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 502 Bad Gateway", "{response}");
    assert!(
        response.contains("upstream response too large"),
        "{response}"
    );
}

#[tokio::test]
async fn caps_a_chunked_upstream_response_while_streaming() {
    let upstream = upstream().await;
    let mut config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    config.push_str("\n[limits]\nmax_upstream_response_bytes = 1024\n");
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /chunked HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    let count = body.matches('y').count();
    assert!(
        count <= 1024,
        "streamed past the cap: {count} bytes\n{response}"
    );
}

#[tokio::test]
async fn per_route_upstream_cap_overrides_the_global_one() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[limits]
max_upstream_response_bytes = 1024

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
max_upstream_response_bytes = 8192
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /big HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    assert!(response.ends_with(&"x".repeat(4096)), "{response}");
}

#[tokio::test]
async fn spools_a_large_upstream_response_to_disk() {
    let upstream = upstream().await;
    let mut config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    config.push_str("\n[limits]\nresponse_buffer_bytes = 4\nresponse_spool_bytes = 8192\n");
    let (addr, _stop, _metrics, runtime) = start_full(&config).await;

    let response = roundtrip(
        addr,
        "GET /big HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    assert!(response.ends_with(&"x".repeat(4096)));

    let status = runtime.load().proxy().status();
    assert_eq!(status["spooled"], 1, "{status}");
    assert_eq!(status["spool_used"], 0, "{status}");
}

#[tokio::test]
async fn a_full_spool_budget_falls_back_to_streaming() {
    let upstream = upstream().await;
    let mut config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    config.push_str(
        "\n[limits]\nresponse_buffer_bytes = 4\nresponse_spool_bytes = 8192\nspool_budget_bytes = 1024\n",
    );
    let (addr, _stop, _metrics, runtime) = start_full(&config).await;

    let response = roundtrip(
        addr,
        "GET /big HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    assert!(response.ends_with(&"x".repeat(4096)));

    let status = runtime.load().proxy().status();
    assert_eq!(status["spooled"], 0, "{status}");
    assert_eq!(status["spool_used"], 0, "{status}");
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
async fn rejects_a_chunked_body_over_the_limit() {
    let upstream = silent_upstream().await;
    let mut config = NO_DEFAULT.replace("{upstream}", &upstream.to_string());
    config.push_str("\n[limits]\nmax_body_bytes = 10\n");
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n\
         5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&response),
        "HTTP/1.1 413 Payload Too Large",
        "{response}"
    );
    assert!(response.contains("request body too large"), "{response}");
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
    assert!(
        response.contains("forwarded: for=127.0.0.1;proto=http;host=\"example.com\""),
        "{response}"
    );
    assert!(response.contains("x-forwarded-port: 80"), "{response}");
}

#[tokio::test]
async fn route_templates_expand_request_variables() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
request_headers = ["X-Remote: $remote_addr", "X-Original: $request_uri"]
add_headers = ["X-Reply-Host: $host", "X-Reply-Method: $request_method"]

[[routes]]
host = "redir.example"
redirect = {{ to = "https://$host/new", status = 302 }}
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    assert!(response.contains("x-remote: 127.0.0.1"), "{response}");
    assert!(response.contains("x-original: /path?q=1"), "{response}");
    assert!(response.contains("x-reply-host: example.com"), "{response}");
    assert!(response.contains("x-reply-method: GET"), "{response}");

    let redirect = roundtrip(
        addr,
        "GET /old HTTP/1.1\r\nHost: redir.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&redirect), "HTTP/1.1 302 Found", "{redirect}");
    assert!(
        redirect.contains("location: https://redir.example/new"),
        "{redirect}"
    );
}

#[tokio::test]
async fn alias_serves_files_with_expires_and_no_etag() {
    let root = temp_root("alias");
    std::fs::write(root.join("app.js"), "console.log(1)").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
path = "/static"
alias = "{}"
expires_secs = 60
etag = false
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /static/app.js HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    assert!(response.ends_with("console.log(1)"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("cache-control: public, max-age=60"),
        "{response}"
    );
    assert!(
        response.to_ascii_lowercase().contains("expires:"),
        "{response}"
    );
    assert!(
        !response.to_ascii_lowercase().contains("etag:"),
        "{response}"
    );

    let outside = roundtrip(
        addr,
        "GET /other/app.js HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&outside), "HTTP/1.1 404 Not Found", "{outside}");
}

#[tokio::test]
async fn return_route_expands_variables() {
    let config = r#"
listen = "127.0.0.1:0"

[[routes]]
host = "down.example"
return = { status = 503, body = "down for $host and $request_method", content_type = "text/plain" }

[[routes]]
host = "empty.example"
return = { status = 204 }
"#;
    let (addr, _stop, _metrics) = start(config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: down.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&response),
        "HTTP/1.1 503 Service Unavailable",
        "{response}"
    );
    assert!(
        response.ends_with("down for down.example and GET"),
        "{response}"
    );
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-type: text/plain"),
        "{response}"
    );

    let empty = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: empty.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&empty), "HTTP/1.1 204 No Content", "{empty}");
}

#[tokio::test]
async fn rewrite_rules_change_the_path_and_redirect() {
    let root = temp_root("rewrite");
    std::fs::create_dir_all(root.join("new")).unwrap();
    std::fs::write(root.join("new").join("hello.txt"), "rewritten").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[rewrites]]
pattern = "^/old/(.*)$"
replacement = "/new/$1"
flag = "last"

[[rewrites]]
pattern = "^/go$"
replacement = "/target"
flag = "redirect"

[[routes]]
host = "*"
root = "{}"
"#,
        root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let rewritten = roundtrip(
        addr,
        "GET /old/hello.txt HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&rewritten), "HTTP/1.1 200 OK", "{rewritten}");
    assert!(rewritten.ends_with("rewritten"), "{rewritten}");

    let redirected = roundtrip(
        addr,
        "GET /go HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&redirected), "HTTP/1.1 302 Found", "{redirected}");
    assert!(
        redirected
            .to_ascii_lowercase()
            .contains("location: /target"),
        "{redirected}"
    );
}

#[tokio::test]
async fn map_variables_resolve_in_headers() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[maps]]
name = "tenant"
source = "$http_x_tenant"
default = "guest"
values = {{ acme = "gold", beta = "silver" }}

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
add_headers = ["X-Tenant: $tenant"]
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let gold = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Tenant: acme\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(gold.contains("x-tenant: gold"), "{gold}");

    let guest = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(guest.contains("x-tenant: guest"), "{guest}");
}

#[tokio::test]
async fn geo_and_split_variables_resolve() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[geos]]
name = "zone"
default = "other"
values = {{ "127.0.0.0/8" = "loopback" }}

[[splits]]
name = "variant"
source = "$http_x_user"
buckets = [{{ percent = 100, value = "only" }}]

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
add_headers = ["X-Zone: $zone", "X-Variant: $variant"]
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.contains("x-zone: loopback"), "{response}");
    assert!(response.contains("x-variant: only"), "{response}");
}

#[tokio::test]
async fn route_if_returns_on_a_matching_variable() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
if = [{{ variable = "$http_x_debug", equals = "1", return = {{ status = 503, body = "blocked" }} }}]
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let blocked = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Debug: 1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&blocked),
        "HTTP/1.1 503 Service Unavailable",
        "{blocked}"
    );
    assert!(blocked.ends_with("blocked"), "{blocked}");

    let allowed = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&allowed), "HTTP/1.1 200 OK", "{allowed}");
}

#[tokio::test]
async fn nested_locations_match_under_the_parent_prefix() {
    let config = r#"
listen = "127.0.0.1:0"

[[routes]]
host = "example.com"
path = "/app"
return = { status = 200, body = "parent" }

[[routes.locations]]
path = "/admin"
return = { status = 200, body = "admin" }

[[routes.locations]]
path_regex = "\\.php$"
return = { status = 200, body = "php" }
"#;
    let (addr, _stop, _metrics) = start(config).await;

    let parent = roundtrip(
        addr,
        "GET /app/other HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(parent.ends_with("parent"), "{parent}");

    let child = roundtrip(
        addr,
        "GET /app/admin HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(child.ends_with("admin"), "{child}");

    let regex = roundtrip(
        addr,
        "GET /app/index.php HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(regex.ends_with("php"), "{regex}");

    let outside = roundtrip(
        addr,
        "GET /other.php HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&outside), "HTTP/1.1 404 Not Found", "{outside}");
}

#[tokio::test]
async fn exact_and_no_regex_locations_pick_the_right_route() {
    let config = r#"
listen = "127.0.0.1:0"

[[routes]]
host = "example.com"
path = "/app"
match = "exact"
return = { status = 200, body = "exact" }

[[routes]]
host = "example.com"
path = "/app"
return = { status = 200, body = "prefix" }

[[routes]]
host = "example.com"
path_regex = "^/app/.*"
return = { status = 200, body = "regex" }

[[routes]]
host = "noregex.example"
path = "/app"
no_regex = true
return = { status = 200, body = "prefix" }

[[routes]]
host = "noregex.example"
path_regex = "^/app/.*"
return = { status = 200, body = "regex" }
"#;
    let (addr, _stop, _metrics) = start(config).await;

    let exact = roundtrip(
        addr,
        "GET /app HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&exact), "HTTP/1.1 200 OK", "{exact}");
    assert!(exact.ends_with("exact"), "{exact}");

    let regex = roundtrip(
        addr,
        "GET /app/x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(regex.ends_with("regex"), "{regex}");

    let no_regex = roundtrip(
        addr,
        "GET /app/x HTTP/1.1\r\nHost: noregex.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(no_regex.ends_with("prefix"), "{no_regex}");
}

#[tokio::test]
async fn route_request_headers_are_set_and_removed() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
request_headers = ["X-Service-Token: secret"]
request_remove_headers = ["X-Client-Secret"]
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Client-Secret: leak\r\n\
         X-Service-Token: client-value\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-service-token: secret"),
        "{response}"
    );
    assert!(
        !response
            .to_ascii_lowercase()
            .contains("x-service-token: client-value"),
        "{response}"
    );
    assert!(
        !response.to_ascii_lowercase().contains("x-client-secret"),
        "{response}"
    );
    // The canonical Host and forwarding headers still win unless the
    // operator overrides them explicitly.
    assert!(response.contains("host: example.com"), "{response}");
    assert!(
        response.contains("x-forwarded-for: 127.0.0.1"),
        "{response}"
    );
}

#[tokio::test]
async fn passive_ejection_skips_a_dead_upstream() {
    let healthy = upstream().await;
    // Bind and drop a listener to get a port that refuses connections.
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind dead")
        .local_addr()
        .expect("dead addr");
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{dead}", "{healthy}"]
failures_before_eject = 1
eject_secs = 30

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let first = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&first), "HTTP/1.1 502 Bad Gateway", "{first}");

    // The dead server is now ejected; the round robin position that would
    // have selected it must fall through to the healthy one.
    for _ in 0..3 {
        let response = roundtrip(
            addr,
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    }
}

#[tokio::test]
async fn hash_balance_keeps_a_key_on_one_server() {
    let first = labeled_upstream("one").await;
    let second = labeled_upstream("two").await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{first}", "{second}"]
balance = "hash"
hash_key = "header:x-user"

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    async fn body_for(addr: SocketAddr, user: &str) -> String {
        let response = roundtrip(
            addr,
            &format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nX-User: {user}\r\n\
                 Connection: close\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
        response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_default()
    }

    let owner = body_for(addr, "user-1").await;
    for _ in 0..5 {
        assert_eq!(body_for(addr, "user-1").await, owner);
    }

    let mut seen = std::collections::HashSet::new();
    for index in 0..40 {
        let body = body_for(addr, &format!("user-{index}")).await;
        assert_eq!(body_for(addr, &format!("user-{index}")).await, body);
        seen.insert(body);
    }
    assert_eq!(
        seen.len(),
        2,
        "40 distinct keys should reach both servers, got {seen:?}"
    );
}

#[tokio::test]
async fn weighted_round_robin_follows_the_configured_ratio() {
    let first = labeled_upstream("one").await;
    let second = labeled_upstream("two").await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{first}", "{second}"]
weights = [3, 1]

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let mut one = 0;
    let mut two = 0;
    for _ in 0..8 {
        let response = roundtrip(
            addr,
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
        if response.ends_with("one") {
            one += 1;
        } else if response.ends_with("two") {
            two += 1;
        }
    }
    assert_eq!((one, two), (6, 2));
}

#[tokio::test]
async fn route_max_concurrent_limits_proxied_requests() {
    let upstream = slow_upstream(Duration::from_millis(300)).await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
max_concurrent = 1
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let first = tokio::spawn(roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let limited = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&limited),
        "HTTP/1.1 503 Service Unavailable",
        "{limited}"
    );
    assert!(
        limited.to_ascii_lowercase().contains("retry-after: 1"),
        "{limited}"
    );

    let first = first.await.expect("first request");
    assert_eq!(status(&first), "HTTP/1.1 200 OK", "{first}");
    assert!(first.ends_with("slow"), "{first}");
}

#[tokio::test]
async fn buffered_put_is_retried_on_a_dead_upstream() {
    let healthy = body_echo_upstream().await;
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind dead")
        .local_addr()
        .expect("dead addr");
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[limits]
request_buffer_bytes = 4
request_spool_bytes = 4096

[[upstreams]]
name = "app"
servers = ["{dead}", "{healthy}"]
retries = 1

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "PUT / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\
         Connection: close\r\n\r\nhello world",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    assert!(response.ends_with("hello world"), "{response}");
}

#[tokio::test]
async fn concurrent_cache_misses_share_one_upstream_fetch() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counted upstream");
    let upstream = listener.local_addr().expect("counted addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let counter = counter.clone();
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
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ncached",
                    )
                    .await;
            });
        }
    });

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[cache]
enabled = true
ttl_secs = 60
max_item_bytes = 4096

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let mut tasks = Vec::new();
    for _ in 0..8 {
        tasks.push(tokio::spawn(roundtrip(
            addr,
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )));
    }
    for task in tasks {
        let response = task.await.expect("request task");
        assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
        assert!(response.ends_with("cached"), "{response}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retry_on_5xx_retries_the_status() {
    let (upstream, hits) = flaky_upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]
retries = 1
retry_on = ["502"]

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    assert!(response.ends_with("recovered"), "{response}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn five_xx_is_not_retried_by_default() {
    let (upstream, hits) = flaky_upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]
retries = 1

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 502 Bad Gateway", "{response}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn buffered_chunked_put_is_retried_on_a_dead_upstream() {
    let healthy = body_echo_upstream().await;
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind dead")
        .local_addr()
        .expect("dead addr");
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[limits]
request_buffer_bytes = 4
request_spool_bytes = 4096

[[upstreams]]
name = "app"
servers = ["{dead}", "{healthy}"]
retries = 1

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "PUT / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
}

#[tokio::test]
async fn chunked_body_over_the_spool_limit_still_streams() {
    let upstream = hyper_echo_upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[limits]
request_buffer_bytes = 4
request_spool_bytes = 8

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "PUT / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    assert!(response.ends_with("hello world"), "{response}");
}

#[tokio::test]
async fn known_body_over_the_spool_limit_still_streams() {
    let upstream = hyper_echo_upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[limits]
request_buffer_bytes = 4
request_spool_bytes = 8

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "PUT / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\
         Connection: close\r\n\r\nhello world",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
    assert!(response.ends_with("hello world"), "{response}");
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
async fn route_access_log_sampling_overrides_the_global_rate() {
    let root = temp_root("logsample");
    std::fs::write(root.join("index.html"), "ok").unwrap();
    let log_path = root.join("access.log");

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[log]
file = "{log}"
sample = 0.0

[[routes]]
host = "quiet.local"
root = "{root}"

[[routes]]
host = "loud.local"
root = "{root}"
access_log_sample = 1.0
"#,
        log = log_path.display(),
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    for host in ["quiet.local", "loud.local"] {
        let _ = roundtrip(
            addr,
            &format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        )
        .await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let logged = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(!logged.contains("quiet.local"), "{logged}");
    assert!(logged.contains("loud.local"), "{logged}");
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
async fn global_error_page_replaces_the_default_404() {
    let root = temp_root("global-error");
    let pages = temp_root("global-pages");
    std::fs::write(pages.join("404.html"), "global not found").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"
error_root = "{pages}"
error_pages = ["404 /404.html"]

[[routes]]
host = "known.local"
root = "{root}"
"#,
        pages = pages.display(),
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /missing HTTP/1.1\r\nHost: other.local\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 404 Not Found");
    assert!(response.ends_with("global not found"), "{response}");
}

#[tokio::test]
async fn route_error_page_covers_auth_and_rate_limit() {
    let upstream = upstream().await;
    let root = temp_root("local-errors");
    let htpasswd = root.join("htpasswd");
    let hash = bcrypt::hash("secret", 4).expect("bcrypt");
    std::fs::write(&htpasswd, format!("user:{hash}\n")).unwrap();
    std::fs::write(root.join("401.html"), "login required").unwrap();
    std::fs::write(root.join("429.html"), "slow down").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "auth.local"
upstream = "app"
auth_file = "{htpasswd}"
error_root = "{root}"
error_pages = ["401 /401.html", "429 /429.html"]

[[routes]]
host = "limited.local"
upstream = "app"
requests_per_second = 1
burst = 1
error_root = "{root}"
error_pages = ["401 /401.html", "429 /429.html"]
"#,
        htpasswd = htpasswd.display(),
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let unauth = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: auth.local\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&unauth), "HTTP/1.1 401 Unauthorized");
    assert!(unauth.ends_with("login required"), "{unauth}");
    assert!(
        unauth
            .to_ascii_lowercase()
            .contains("www-authenticate: basic"),
        "{unauth}"
    );

    let first = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: limited.local\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&first), "HTTP/1.1 200 OK", "{first}");

    let limited = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: limited.local\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&limited),
        "HTTP/1.1 429 Too Many Requests",
        "{limited}"
    );
    assert!(limited.ends_with("slow down"), "{limited}");
    assert!(
        limited.to_ascii_lowercase().contains("retry-after: 1"),
        "{limited}"
    );
}

#[tokio::test]
async fn route_rate_limit_can_be_keyed_by_a_header() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "example.com"
upstream = "app"
requests_per_second = 1
burst = 1
rate_key = "header:x-api-key"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    async fn get(addr: SocketAddr, key: Option<&str>) -> String {
        let header = key
            .map(|key| format!("X-Api-Key: {key}\r\n"))
            .unwrap_or_default();
        roundtrip(
            addr,
            &format!("GET / HTTP/1.1\r\nHost: example.com\r\n{header}Connection: close\r\n\r\n"),
        )
        .await
    }

    assert_eq!(status(&get(addr, Some("key-a")).await), "HTTP/1.1 200 OK");
    assert_eq!(
        status(&get(addr, Some("key-a")).await),
        "HTTP/1.1 429 Too Many Requests"
    );
    // A different key has its own bucket.
    assert_eq!(status(&get(addr, Some("key-b")).await), "HTTP/1.1 200 OK");

    // Without the header the peer address is the key, and that bucket is
    // still full.
    assert_eq!(status(&get(addr, None).await), "HTTP/1.1 200 OK");
    assert_eq!(
        status(&get(addr, None).await),
        "HTTP/1.1 429 Too Many Requests"
    );
}

#[tokio::test]
async fn error_page_path_expands_request_variables() {
    let root = temp_root("error-vars");
    std::fs::write(root.join("error-GET.html"), "method page").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{root}"
error_pages = ["404 /error-$request_method.html"]
"#,
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /missing HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 404 Not Found", "{response}");
    assert!(response.ends_with("method page"), "{response}");
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

#[tokio::test]
async fn route_level_mtls_checks_the_certificate_identity() {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "client-ca");
    let ca = ca_params.self_signed(&ca_key).expect("ca");

    let server_key = KeyPair::generate().expect("server key");
    let server_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("server params");
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("server cert");

    let make_client = |cn: &str| {
        let key = KeyPair::generate().expect("client key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("client params");
        params.distinguished_name.push(DnType::CommonName, cn);
        let cert = params.signed_by(&key, &ca, &ca_key).expect("client cert");
        (cert, key)
    };
    let (client, client_key) = make_client("service-a");
    let (other, other_key) = make_client("service-b");

    let root = temp_root("route-mtls");
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
client_auth = "optional"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "localhost"
upstream = "app"
client_auth = true
client_cn = "service-a"
client_issuer_cn = "client-ca"
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

    async fn ask(addr: SocketAddr, config: Arc<rustls::ClientConfig>) -> String {
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let connector = tokio_rustls::TlsConnector::from(config);
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let mut tls = connector.connect(name, tcp).await.expect("handshake");
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
        String::from_utf8_lossy(&response).to_string()
    }

    let anonymous = ask(addr, Arc::new(base.clone().with_no_client_auth())).await;
    assert_eq!(status(&anonymous), "HTTP/1.1 403 Forbidden", "{anonymous}");

    let mut wrong = base
        .clone()
        .with_client_auth_cert(
            vec![rustls::pki_types::CertificateDer::from(
                other.der().to_vec(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(other_key.serialize_der().into()),
        )
        .expect("client auth config");
    wrong.alpn_protocols = vec![b"http/1.1".to_vec()];
    let wrong = ask(addr, Arc::new(wrong)).await;
    assert_eq!(status(&wrong), "HTTP/1.1 403 Forbidden", "{wrong}");

    let mut accepted = base
        .with_client_auth_cert(
            vec![rustls::pki_types::CertificateDer::from(
                client.der().to_vec(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(client_key.serialize_der().into()),
        )
        .expect("client auth config");
    accepted.alpn_protocols = vec![b"http/1.1".to_vec()];
    let accepted = ask(addr, Arc::new(accepted)).await;
    assert_eq!(status(&accepted), "HTTP/1.1 200 OK", "{accepted}");
}

#[tokio::test]
async fn tls_policy_refuses_a_cipher_suite_the_server_does_not_offer() {
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

    let root = temp_root("tls-policy");
    std::fs::write(root.join("server.pem"), server.pem()).unwrap();
    std::fs::write(root.join("server.key"), server_key.serialize_pem()).unwrap();
    std::fs::write(root.join("ca.pem"), ca.pem()).unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[tls]
cert = "{cert}"
key = "{key}"
min_version = "tls13"
cipher_suites = ["TLS13_AES_128_GCM_SHA256"]
curves = ["X25519"]

[[routes]]
host = "localhost"
root = "{root}"
"#,
        cert = root.join("server.pem").display(),
        key = root.join("server.key").display(),
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    // Offer only a TLS 1.3 suite the server excluded.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).expect("add ca");
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let rejected = match connector.connect(name, tcp).await {
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
    assert!(
        rejected,
        "a suite outside the policy must not be negotiated"
    );
}

#[tokio::test]
async fn client_crl_rejects_a_revoked_certificate() {
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa,
        KeyIdMethod, KeyPair, RevocationReason, RevokedCertParams, SerialNumber,
    };

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

    let make_client = |serial: u64| {
        let key = KeyPair::generate().expect("client key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("client params");
        params.serial_number = Some(SerialNumber::from(serial));
        let cert = params.signed_by(&key, &ca, &ca_key).expect("client cert");
        (cert, key)
    };
    let (revoked, revoked_key) = make_client(42);
    let (allowed, allowed_key) = make_client(43);

    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 1, 1),
        next_update: date_time_ymd(2027, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from(42u64),
            revocation_time: date_time_ymd(2026, 1, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca, &ca_key)
    .expect("crl");

    let root = temp_root("client-crl");
    std::fs::write(root.join("server.pem"), server.pem()).unwrap();
    std::fs::write(root.join("server.key"), server_key.serialize_pem()).unwrap();
    std::fs::write(root.join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(root.join("ca.crl.pem"), crl.pem().unwrap()).unwrap();
    std::fs::write(root.join("index.html"), "allowed").unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[tls]
cert = "{cert}"
key = "{key}"
client_ca = "{ca}"
client_crl = "{crl}"
client_auth = "required"

[[routes]]
host = "*"
root = "{root}"
"#,
        cert = root.join("server.pem").display(),
        key = root.join("server.key").display(),
        ca = root.join("ca.pem").display(),
        crl = root.join("ca.crl.pem").display(),
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let ca_der = ca.der().clone();

    async fn handshake(
        addr: SocketAddr,
        cert: &rcgen::Certificate,
        key: rcgen::KeyPair,
        ca: rustls::pki_types::CertificateDer<'static>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> bool {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).expect("add ca");
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .expect("client auth config");
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let tcp = TcpStream::connect(addr).await.expect("connect");
        match connector.connect(name, tcp).await {
            Err(_) => false,
            Ok(mut tls) => {
                if tls
                    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .await
                    .is_err()
                {
                    return false;
                }
                let mut buf = [0u8; 256];
                matches!(
                    tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await,
                    Ok(Ok(read)) if read > 0
                )
            }
        }
    }

    assert!(
        !handshake(
            addr,
            &revoked,
            revoked_key,
            ca_der.clone(),
            provider.clone()
        )
        .await,
        "a revoked certificate must be rejected"
    );
    assert!(
        handshake(addr, &allowed, allowed_key, ca_der, provider).await,
        "a non-revoked certificate must pass"
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

#[cfg(unix)]
#[tokio::test]
async fn unix_listener_serves_tls() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use tokio::net::{UnixListener, UnixStream};

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

    let dir = temp_root("unix-tls");
    std::fs::write(dir.join("server.pem"), server.pem()).unwrap();
    std::fs::write(dir.join("server.key"), server_key.serialize_pem()).unwrap();
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(dir.join("index.html"), "tls over unix").unwrap();

    let path = dir.join("elira.sock");
    let listener = UnixListener::bind(&path).expect("bind unix listener");

    let cfg = Config::parse(&format!(
        r#"
listen = "127.0.0.1:0"
listen_unix = "{}"
unix_tls = true

[tls]
cert = "{}"
key = "{}"

[[routes]]
host = "*"
root = "{}"
"#,
        path.display(),
        dir.join("server.pem").display(),
        dir.join("server.key").display(),
        dir.display()
    ))
    .expect("config");

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

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).expect("add ca");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let stream = UnixStream::connect(&path).await.expect("connect unix");
    let mut tls = connector
        .connect(name, stream)
        .await
        .expect("tls handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");

    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), tls.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => response.extend_from_slice(&chunk[..read]),
            Ok(Err(_)) => break,
        }
    }
    let response = String::from_utf8_lossy(&response).to_string();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("tls over unix"), "{response}");
    let _ = stop_tx.send(true);
}

#[tokio::test]
async fn additional_listener_serves_the_same_routes() {
    let root = temp_root("multi-listener");
    std::fs::write(root.join("index.html"), "multi").unwrap();

    let first = TcpListener::bind("127.0.0.1:0").await.expect("bind first");
    let first_addr = first.local_addr().expect("first addr");
    let second = TcpListener::bind("127.0.0.1:0").await.expect("bind second");
    let second_addr = second.local_addr().expect("second addr");

    let cfg = Config::parse(&format!(
        r#"
listen = "{first_addr}"

[[listeners]]
listen = "{second_addr}"

[[routes]]
host = "*"
root = "{}"
"#,
        root.display()
    ))
    .expect("config");
    let runtime = Arc::new(ArcSwap::from_pointee(
        Runtime::build(&cfg).expect("runtime"),
    ));
    let metrics = Arc::new(Metrics::new());
    let (stop_tx, stop_rx) = watch::channel(false);

    let options = Options::from_config(&cfg);
    let first_task = tokio::spawn(server::serve(
        first,
        runtime.clone(),
        options.clone(),
        metrics.clone(),
        stop_rx.clone(),
    ));
    let mut second_options = options;
    second_options.tls = false;
    let second_task = tokio::spawn(server::serve(
        second,
        runtime,
        second_options,
        metrics,
        stop_rx,
    ));

    for addr in [first_addr, second_addr] {
        let response = roundtrip(
            addr,
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&response), "HTTP/1.1 200 OK", "{response}");
        assert!(response.ends_with("multi"), "{response}");
    }

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), first_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), second_task).await;
}

#[tokio::test]
async fn routes_can_be_scoped_to_one_listener() {
    let root = temp_root("scoped-listener");
    std::fs::write(root.join("index.html"), "scoped").unwrap();

    let first = TcpListener::bind("127.0.0.1:0").await.expect("bind first");
    let first_addr = first.local_addr().expect("first addr");
    let second = TcpListener::bind("127.0.0.1:0").await.expect("bind second");
    let second_addr = second.local_addr().expect("second addr");

    let cfg = Config::parse(&format!(
        r#"
listen = "{first_addr}"

[[listeners]]
listen = "{second_addr}"
name = "second"

[[routes]]
host = "*"
listeners = ["second"]
root = "{}"
"#,
        root.display()
    ))
    .expect("config");
    let runtime = Arc::new(ArcSwap::from_pointee(
        Runtime::build(&cfg).expect("runtime"),
    ));
    let metrics = Arc::new(Metrics::new());
    let (stop_tx, stop_rx) = watch::channel(false);

    let first_task = tokio::spawn(server::serve(
        first,
        runtime.clone(),
        Options::from_config(&cfg),
        metrics.clone(),
        stop_rx.clone(),
    ));
    let mut second_options = Options::from_config(&cfg);
    second_options.name = "second".to_owned();
    let second_task = tokio::spawn(server::serve(
        second,
        runtime,
        second_options,
        metrics,
        stop_rx,
    ));

    let denied = roundtrip(
        first_addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&denied), "HTTP/1.1 404 Not Found", "{denied}");

    let served = roundtrip(
        second_addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&served), "HTTP/1.1 200 OK", "{served}");
    assert!(served.ends_with("scoped"), "{served}");

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), first_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), second_task).await;
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

#[tokio::test]
async fn regex_route_matches_after_prefixes() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
path = "/health"
upstream = "app"

[[routes]]
host = "*"
path_regex = "^/api/v[0-9]+/"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let matched = roundtrip(
        addr,
        "GET /api/v2/users HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&matched), "HTTP/1.1 200 OK");

    let prefix = roundtrip(
        addr,
        "GET /health HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&prefix), "HTTP/1.1 200 OK");

    let missing = roundtrip(
        addr,
        "GET /api/users HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&missing), "HTTP/1.1 404 Not Found");
}

#[tokio::test]
async fn cgi_route_runs_a_script() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_root("cgi");
    let script = root.join("hello");
    std::fs::write(
        &script,
        "#!/bin/sh\nread body\nprintf 'Content-Type: text/plain\\r\\n\\r\\ncgi:%s:%s\\n' \"$QUERY_STRING\" \"$APP_ENV\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
path = "/cgi"
cgi_pass = "{}"
cgi_param = ["APP_ENV: test"]
"#,
        script.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /cgi?name=elira HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert!(response.contains("cgi:name=elira:test"), "{response}");
}

/// A tiny FastCGI responder: it ignores params and answers every STDIN
/// terminator with a fixed response.
async fn fastcgi_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fcgi");
    let addr = listener.local_addr().expect("fcgi addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                loop {
                    let mut header = [0u8; 8];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let kind = header[1];
                    let len = u16::from_be_bytes([header[4], header[5]]) as usize;
                    let pad = header[6] as usize;
                    let mut content = vec![0u8; len + pad];
                    if stream.read_exact(&mut content).await.is_err() {
                        return;
                    }
                    // STDIN with no content terminates the request.
                    if kind == 5 && len == 0 {
                        let body = "Content-Type: text/plain\r\n\r\nfastcgi";
                        let mut record = vec![1, 6, 0, 1];
                        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
                        record.extend_from_slice(&[0, 0]);
                        record.extend_from_slice(body.as_bytes());
                        let _ = stream.write_all(&record).await;
                        let mut end = vec![1, 3, 0, 1, 0, 8, 0, 0];
                        end.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
                        let _ = stream.write_all(&end).await;
                        return;
                    }
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn fastcgi_route_talks_the_protocol() {
    let upstream = fastcgi_upstream().await;
    let root = temp_root("fastcgi");
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
fastcgi_pass = "{upstream}"
fastcgi_root = "{root}"
"#,
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /index.php HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert!(response.contains("fastcgi"), "{response}");
}

/// A tiny SCGI responder: validates the length-prefixed header block and
/// answers with the request method, URI, a custom param and the body.
async fn scgi_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind scgi");
    let addr = listener.local_addr().expect("scgi addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut length = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    if byte[0] == 0 {
                        break;
                    }
                    length.push(byte[0]);
                }
                let Some(length) = String::from_utf8(length)
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                else {
                    return;
                };
                let mut header = vec![0u8; length];
                if stream.read_exact(&mut header).await.is_err() {
                    return;
                }
                let mut parts = header.split(|byte| *byte == 0);
                if parts.next() != Some(b"SCGI".as_slice()) {
                    return;
                }
                let mut params = std::collections::HashMap::new();
                while let (Some(name), Some(value)) = (parts.next(), parts.next()) {
                    if name.is_empty() {
                        break;
                    }
                    params.insert(
                        String::from_utf8_lossy(name).to_string(),
                        String::from_utf8_lossy(value).to_string(),
                    );
                }
                let body_len = params
                    .get("CONTENT_LENGTH")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; body_len];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let response = format!(
                    "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nscgi:{}:{}:{}:{}",
                    params
                        .get("REQUEST_METHOD")
                        .map(String::as_str)
                        .unwrap_or(""),
                    params.get("REQUEST_URI").map(String::as_str).unwrap_or(""),
                    params.get("APP_ENV").map(String::as_str).unwrap_or(""),
                    String::from_utf8_lossy(&body),
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn scgi_route_talks_the_protocol() {
    let upstream = scgi_upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
scgi_pass = "{upstream}"
scgi_param = ["APP_ENV: test"]
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let response = roundtrip(
        addr,
        "GET /scgi?name=elira HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert!(
        response.contains("scgi:GET:/scgi?name=elira:test:"),
        "{response}"
    );

    let posted = roundtrip(
        addr,
        "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
    )
    .await;
    assert!(posted.contains("scgi:POST:/submit:test:data"), "{posted}");
}

#[tokio::test]
async fn cleartext_http2_is_available_with_prior_knowledge() {
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"
h2c = true

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = hyper::Request::builder()
        .uri("http://example.com/")
        .body(Empty::<Bytes>::new())
        .expect("request");
    let response = sender.send_request(request).await.expect("h2 request");
    assert_eq!(response.status(), http::StatusCode::OK);
}

#[tokio::test]
async fn grpc_trailers_survive_the_h2_upstream_pool() {
    use futures_util::stream as futures_stream;
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Frame};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind grpc upstream");
    let upstream = listener.local_addr().expect("grpc addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|_request| async {
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                    let frames = futures_stream::iter(vec![
                        Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(
                            b"hello",
                        ))),
                        Ok(Frame::trailers(trailers)),
                    ]);
                    let body = http_body_util::StreamBody::new(frames).boxed();
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(body)
                            .expect("response"),
                    )
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let config = format!(
        r#"
listen = "127.0.0.1:0"
h2c = true

[[upstreams]]
name = "app"
servers = ["{upstream}"]
h2_pool = true

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = hyper::Request::builder()
        .method(http::Method::POST)
        .uri("http://example.com/grpc")
        .header("te", "trailers")
        .header("content-type", "application/grpc")
        .body(Full::new(Bytes::from_static(b"request")))
        .expect("request");
    let response = sender.send_request(request).await.expect("grpc request");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc")
    );

    let collected = response.into_body().collect().await.expect("body");
    let trailers = collected.trailers().cloned().expect("trailers");
    assert_eq!(collected.to_bytes().as_ref(), b"hello");
    assert_eq!(
        trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("0")
    );
}

#[tokio::test]
async fn grpc_request_trailers_reach_the_h2_upstream() {
    use futures_util::stream as futures_stream;
    use http_body_util::BodyExt;
    use hyper::body::{Bytes, Frame};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind grpc upstream");
    let upstream = listener.local_addr().expect("grpc addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async move {
                        let collected = request.into_body().collect().await.expect("request body");
                        let saw = collected
                            .trailers()
                            .and_then(|trailers| trailers.get("x-request-trailer"))
                            .and_then(|value| value.to_str().ok())
                            .map(|value| value == "yes")
                            .unwrap_or(false);
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("x-saw-request-trailer", if saw { "yes" } else { "no" })
                                .body(http_body_util::Full::new(Bytes::from_static(b"ok")))
                                .expect("response"),
                        )
                    },
                );
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let config = format!(
        r#"
listen = "127.0.0.1:0"
h2c = true

[[upstreams]]
name = "app"
servers = ["{upstream}"]
h2_pool = true

[[routes]]
host = "*"
upstream = "app"
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-request-trailer", http::HeaderValue::from_static("yes"));
    let frames = futures_stream::iter(vec![
        Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(b"payload"))),
        Ok(Frame::trailers(trailers)),
    ]);
    let body = http_body_util::StreamBody::new(frames).boxed();
    let request = hyper::Request::builder()
        .method(http::Method::POST)
        .uri("http://example.com/grpc")
        .header("te", "trailers")
        .header("content-type", "application/grpc")
        .body(body)
        .expect("request");

    let response = sender.send_request(request).await.expect("grpc request");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-saw-request-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("yes")
    );
}

#[tokio::test]
async fn cache_hit_is_compressed_for_clients_that_ask() {
    let upstream = upstream().await;
    let config = format!(
        r#"
listen = "127.0.0.1:0"
server_header = false

[compression]
enabled = true
min_bytes = 32

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

    let request = "GET /big HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n";
    let first = roundtrip(addr, request).await;
    assert!(
        first
            .to_ascii_lowercase()
            .contains("content-encoding: gzip"),
        "{first}"
    );

    let second = roundtrip(addr, request).await;
    assert!(second.contains("x-cache: HIT"), "{second}");
    assert!(
        second
            .to_ascii_lowercase()
            .contains("content-encoding: gzip"),
        "{second}"
    );
    assert!(
        second
            .to_ascii_lowercase()
            .contains("vary: accept-encoding"),
        "{second}"
    );
}

#[tokio::test]
async fn stale_refresh_uses_a_conditional_request() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let conditional = Arc::new(AtomicUsize::new(0));
    let seen = conditional.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let upstream = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2048];
                let read = stream.read(&mut head).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&head[..read]).to_ascii_lowercase();
                let response = if text.contains("if-none-match: \"v1\"") {
                    seen.fetch_add(1, Ordering::SeqCst);
                    "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nETag: \"v1\"\r\n\
                     Cache-Control: max-age=1\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                };
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
stale_secs = 10
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
    assert!(first.ends_with("hello"), "{first}");

    tokio::time::sleep(Duration::from_millis(1200)).await;
    let stale = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(stale.contains("x-cache: STALE"), "{stale}");

    tokio::time::sleep(Duration::from_millis(500)).await;
    let refreshed = roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(refreshed.contains("x-cache: HIT"), "{refreshed}");
    assert_eq!(conditional.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn admin_cache_purge_respects_a_prefix() {
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
    let (addr, _stop, metrics, runtime) = start_full(&config).await;

    let metrics_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind metrics");
    let metrics_addr = metrics_listener.local_addr().expect("metrics addr");
    let (_metrics_stop, metrics_stop_rx) = watch::channel(false);
    let (reload_tx, _reload_rx) = watch::channel(0u64);
    let (drain_tx, _drain_rx) = watch::channel(false);
    server::spawn_metrics(
        metrics_listener,
        runtime,
        metrics,
        None,
        reload_tx,
        drain_tx,
        metrics_stop_rx,
    );

    let get = |host: &'static str, path: &'static str| {
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        async move { roundtrip(addr, &request).await }
    };

    let first = get("a.example", "/one").await;
    assert!(first.contains("x-cache: MISS"), "{first}");
    let _ = get("a.example", "/two").await;
    let _ = get("b.example", "/one").await;

    let hit = get("a.example", "/one").await;
    assert!(hit.contains("x-cache: HIT"), "{hit}");

    let purge = roundtrip(
        metrics_addr,
        "POST /cache/purge?prefix=a.example/one HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(purge.contains("200 OK"), "{purge}");
    assert!(purge.contains("\"purged\":1"), "{purge}");

    let purged = get("a.example", "/one").await;
    assert!(purged.contains("x-cache: MISS"), "{purged}");
    let other_path = get("a.example", "/two").await;
    assert!(other_path.contains("x-cache: HIT"), "{other_path}");
    let other_host = get("b.example", "/one").await;
    assert!(other_host.contains("x-cache: HIT"), "{other_host}");
}

#[tokio::test]
async fn route_cache_overrides_apply() {
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
path = "/nocache"
upstream = "app"
cache_enabled = false

[[routes]]
host = "*"
path = "/short"
upstream = "app"
cache_ttl_secs = 1
"#
    );
    let (addr, _stop, _metrics) = start(&config).await;

    let first = roundtrip(
        addr,
        "GET /nocache HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(!first.contains("x-cache"), "{first}");
    let second = roundtrip(
        addr,
        "GET /nocache HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(!second.contains("x-cache"), "{second}");

    let short = roundtrip(
        addr,
        "GET /short HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(short.contains("x-cache: MISS"), "{short}");
    let hit = roundtrip(
        addr,
        "GET /short HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(hit.contains("x-cache: HIT"), "{hit}");

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let expired = roundtrip(
        addr,
        "GET /short HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(expired.contains("x-cache: MISS"), "{expired}");
}

#[tokio::test]
async fn route_can_disable_the_access_log() {
    let root = temp_root("access-toggle");
    std::fs::write(root.join("index.html"), "ok").unwrap();
    let log = root.join("access.log");

    let config = format!(
        r#"
listen = "127.0.0.1:0"

[log]
file = "{log}"
max_bytes = 1048576

[[routes]]
host = "*"
path = "/silent"
root = "{root}"
access_log = false

[[routes]]
host = "*"
root = "{root}"
"#,
        log = log.display(),
        root = root.display()
    );
    let (addr, _stop, _metrics) = start(&config).await;

    roundtrip(
        addr,
        "GET /silent HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    roundtrip(
        addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let logged = std::fs::read_to_string(&log).expect("log file");
    assert!(logged.contains("GET / "), "{logged}");
    assert!(!logged.contains("GET /silent"), "{logged}");
}
