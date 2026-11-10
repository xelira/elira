//! Integration tests against a real HTTP/3 server.
//!
//! The server is the project's own `elira-h3` listener, configured with the
//! shared `elira-tls` fixtures. Static routes cover GET and streaming; an HTTP/1
//! echo upstream behind the same listener covers request bodies and header
//! pass-through end to end.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

use elira_h3upstream::{empty, full, Body, Error, Pool, PoolConfig, Stats};
use elira_upstream::TlsOptions;

type EchoFuture = Pin<Box<dyn Future<Output = Response<Full<Bytes>>> + Send + 'static>>;
type Handler = Arc<dyn Fn(Request<Incoming>) -> EchoFuture + Send + Sync>;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../elira-tls/tests/fixtures")
}

fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    socket.local_addr().expect("local address").port()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "elira-h3upstream-{}-{label}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The project's HTTP/3 listener. Dropping it stops the accept loop.
struct H3Server {
    port: u16,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl H3Server {
    async fn spawn_static(root: &Path) -> Self {
        let text = format!(
            r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{}"
"#,
            root.display()
        );
        Self::spawn(&text).await
    }

    async fn spawn_proxy(upstream: SocketAddr) -> Self {
        let text = format!(
            r#"
listen = "127.0.0.1:0"

[[upstreams]]
name = "app"
servers = ["{upstream}"]

[[routes]]
host = "*"
upstream = "app"
"#
        );
        Self::spawn(&text).await
    }

    async fn spawn(text: &str) -> Self {
        let config = elira_config::Config::parse(text).expect("valid server configuration");
        let proxy = Arc::new(elira_proxy::Proxy::new(&config).expect("build proxy"));
        let loader = {
            let proxy = Arc::clone(&proxy);
            Arc::new(move || (*proxy).clone())
        };

        let port = free_udp_port();
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let _ = elira_h3::serve(
                elira_h3::Config {
                    listen: format!("127.0.0.1:{port}").parse().expect("listen address"),
                    cert: fixtures().join("cert.pem"),
                    key: fixtures().join("key.pem"),
                    reuse_port: false,
                    client_ca: None,
                    client_crl: None,
                    client_auth: elira_tls::ClientAuth::Off,
                    cipher_suites: None,
                    curves: None,
                    ticket_key: None,
                    certificates: Vec::new(),
                    proxy_protocol: false,
                    idle_timeout_secs: 5,
                    early_data: false,
                },
                loader,
                Arc::new(elira_metrics::Metrics::new()),
                None,
                Arc::new(|_| {}),
                stop_rx,
            )
            .await;
        });

        // `serve` binds before its first await. Give the task a moment to be
        // scheduled; the client itself has a connect timeout if it is not.
        tokio::time::sleep(Duration::from_millis(200)).await;

        Self { port, stop, task }
    }

    fn uri(&self) -> Uri {
        format!("https://127.0.0.1:{}/", self.port)
            .parse()
            .expect("valid URI")
    }

    fn uri_for(&self, path: &str) -> Uri {
        format!("https://127.0.0.1:{}{}", self.port, path)
            .parse()
            .expect("valid URI")
    }
}

impl Drop for H3Server {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

/// Plain HTTP/1.1 server used as the application behind the HTTP/3 listener.
struct EchoServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl EchoServer {
    async fn spawn(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo listener");
        let addr = listener.local_addr().expect("echo address");

        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let handler = Arc::clone(&handler);
                        async move {
                            let response = handler(request).await;
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), service)
                        .await;
                });
            }
        });

        Self { addr, task }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn echo_handler() -> Handler {
    Arc::new(|request: Request<Incoming>| {
        Box::pin(async move {
            let method = request.method().clone();
            let path = request
                .uri()
                .path_and_query()
                .map(|value| value.as_str().to_owned())
                .unwrap_or_default();
            let test_header = request
                .headers()
                .get("x-test")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body = request
                .into_body()
                .collect()
                .await
                .expect("request body")
                .to_bytes();

            Response::builder()
                .status(StatusCode::OK)
                .header("x-method", method.as_str())
                .header("x-path", path)
                .header("x-test", test_header)
                .body(Full::new(body))
                .expect("valid response")
        })
    })
}

fn config(max_connections: usize) -> PoolConfig {
    PoolConfig {
        max_connections,
        connect_timeout: Duration::from_secs(3),
        tls: TlsOptions {
            insecure: true,
            ..TlsOptions::default()
        },
        bind: None,
    }
}

fn get() -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(empty())
        .expect("valid request")
}

async fn body_text(response: Response<Body>) -> Bytes {
    response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes()
}

async fn wait_for<F>(pool: &Pool, condition: F)
where
    F: Fn(Stats) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if condition(pool.stats()) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition was not reached; stats: {:?}",
            pool.stats()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn get_returns_the_body_and_reuses_one_connection() {
    let root = TempDir::new("static");
    std::fs::write(root.path().join("index.html"), b"hello over h3").expect("index");

    let server = H3Server::spawn_static(root.path()).await;
    let pool = Pool::new(config(2));

    for _ in 0..3 {
        let response = pool.request(server.uri(), get()).await.expect("h3 request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_text(response).await,
            Bytes::from_static(b"hello over h3")
        );
    }

    let stats = pool.stats();
    assert_eq!(stats.total_connections, 1, "sequential requests must reuse");
    assert_eq!(stats.connections, 1);
    assert_eq!(stats.active_requests, 0);
}

#[tokio::test]
async fn post_body_and_headers_are_passed_through() {
    let echo = EchoServer::spawn(echo_handler()).await;
    let server = H3Server::spawn_proxy(echo.addr).await;
    let pool = Pool::new(config(1));

    let request = Request::builder()
        .method(Method::POST)
        .uri("/echo?q=1")
        .header("x-test", "passed-through")
        .body(full(Bytes::from_static(b"streamed request body")))
        .expect("valid request");

    let response = pool
        .request(server.uri(), request)
        .await
        .expect("echo request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-method"], "POST");
    assert_eq!(response.headers()["x-path"], "/echo?q=1");
    assert_eq!(response.headers()["x-test"], "passed-through");
    assert_eq!(
        body_text(response).await,
        Bytes::from_static(b"streamed request body")
    );

    let stats = pool.stats();
    assert_eq!(stats.total_connections, 1);
    assert_eq!(stats.connections, 1);
}

#[tokio::test]
async fn concurrent_requests_share_one_connection_when_capped() {
    let root = TempDir::new("concurrent-one");
    std::fs::write(root.path().join("index.html"), b"shared").expect("index");
    let server = H3Server::spawn_static(root.path()).await;
    let pool = Pool::new(config(1));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let uri = server.uri();
        tasks.push(tokio::spawn(async move { pool.request(uri, get()).await }));
    }

    for task in tasks {
        let response = task.await.expect("request task").expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, Bytes::from_static(b"shared"));
    }

    let stats = pool.stats();
    assert_eq!(stats.total_connections, 1);
    assert_eq!(stats.connections, 1);
    assert_eq!(stats.active_requests, 0);
}

#[tokio::test]
async fn concurrent_requests_respect_the_connection_cap() {
    let echo = EchoServer::spawn(echo_handler()).await;
    let server = H3Server::spawn_proxy(echo.addr).await;
    let pool = Pool::new(config(2));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let uri = server.uri_for("/echo");
        tasks.push(tokio::spawn(async move {
            let request = Request::builder()
                .method(Method::POST)
                .uri("/echo")
                .body(full(Bytes::from_static(b"x")))
                .expect("valid request");
            pool.request(uri, request).await
        }));
    }

    for task in tasks {
        let response = task.await.expect("request task").expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, Bytes::from_static(b"x"));
    }

    let stats = pool.stats();
    assert!(
        stats.total_connections <= 2,
        "cap must be respected: {stats:?}"
    );
    assert!(
        stats.total_connections >= 1,
        "at least one connection is needed: {stats:?}"
    );
    assert_eq!(stats.connections, stats.total_connections as usize);
}

#[tokio::test]
async fn stats_track_active_requests_and_successful_handshakes() {
    let gate = Arc::new(Semaphore::new(0));
    let handler: Handler = {
        let gate = Arc::clone(&gate);
        Arc::new(move |_request| {
            let gate = Arc::clone(&gate);
            Box::pin(async move {
                let _permit = gate.acquire().await.expect("reply gate");
                Response::new(Full::new(Bytes::from_static(b"released")))
            })
        })
    };
    let echo = EchoServer::spawn(handler).await;
    let server = H3Server::spawn_proxy(echo.addr).await;
    let pool = Pool::new(config(2));

    let task = {
        let pool = pool.clone();
        let uri = server.uri();
        tokio::spawn(async move { pool.request(uri, get()).await })
    };

    wait_for(&pool, |stats| stats.active_requests == 1).await;
    let stats = pool.stats();
    assert_eq!(stats.active_requests, 1);
    assert_eq!(stats.total_connections, 1);
    assert_eq!(stats.connections, 1);

    gate.add_permits(1);
    let response = task.await.expect("request task").expect("request");
    assert_eq!(body_text(response).await, Bytes::from_static(b"released"));

    wait_for(&pool, |stats| stats.active_requests == 0).await;
    assert_eq!(pool.stats().total_connections, 1);
}

#[tokio::test]
async fn silent_server_hits_the_connect_timeout() {
    // A bound UDP socket that never answers looks like a QUIC peer that is
    // unreachable: the handshake retries until the pool's deadline fires.
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("silent udp socket");
    let port = socket.local_addr().expect("silent address").port();

    let pool = Pool::new(PoolConfig {
        max_connections: 1,
        connect_timeout: Duration::from_millis(150),
        tls: TlsOptions {
            insecure: true,
            ..TlsOptions::default()
        },
        bind: None,
    });
    let uri: Uri = format!("https://127.0.0.1:{port}/")
        .parse()
        .expect("valid URI");

    let error = pool
        .request(uri, get())
        .await
        .expect_err("the handshake must time out");
    assert!(
        matches!(error, Error::ConnectTimeout { .. }),
        "expected a connect timeout, got {error:?}"
    );

    let stats = pool.stats();
    assert_eq!(stats.total_connections, 0);
    assert_eq!(stats.connections, 0);

    drop(socket);
}

#[tokio::test]
async fn clear_text_origins_are_rejected() {
    let pool = Pool::new(config(1));
    let uri: Uri = "http://127.0.0.1:9/".parse().expect("valid URI");

    let error = pool
        .request(uri, get())
        .await
        .expect_err("HTTP/3 needs TLS");
    assert!(
        matches!(error, Error::UnsupportedScheme { ref scheme } if scheme == "http"),
        "expected an unsupported scheme, got {error:?}"
    );
    assert_eq!(pool.stats().total_connections, 0);
}
