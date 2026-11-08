//! End-to-end tests: a real listener, a real upstream, real sockets.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use elira::config::Config;
use elira::server::{self, Options, Runtime};
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

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    text.len(),
                    text
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
async fn start(config: &str) -> (SocketAddr, watch::Sender<bool>) {
    let cfg = Config::parse(config).expect("parse config");
    let runtime = Arc::new(ArcSwap::from_pointee(
        Runtime::build(&cfg).expect("build runtime"),
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");

    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(server::serve(
        listener,
        runtime,
        Options::from_config(&cfg),
        stop_rx,
    ));

    (addr, stop_tx)
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
    let (addr, _stop) = start(&config).await;

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
    let (addr, _stop) = start(&config).await;

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
    let (addr, _stop) = start(&config).await;

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
    let (addr, _stop) = start(&config).await;

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
    let (addr, _stop) = start(&config).await;

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
