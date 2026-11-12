use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use elira_h2::{empty, full, Body, Error, Pool, PoolConfig, Stats};
use elira_upstream::TlsOptions;

type TestFuture = Pin<Box<dyn Future<Output = Response<Full<Bytes>>> + Send + 'static>>;
type Handler = Arc<dyn Fn(Request<Incoming>) -> TestFuture + Send + Sync>;

struct TestServer {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl TestServer {
    async fn spawn_h2c(handler: Handler) -> Self {
        Self::spawn(handler, None).await
    }

    async fn spawn_tls(handler: Handler) -> Self {
        let fixtures = fixtures();
        let config =
            elira_tls::server_config(&fixtures.join("cert.pem"), &fixtures.join("key.pem"))
                .expect("fixture certificate and key");
        Self::spawn(handler, Some(Arc::new(config))).await
    }

    async fn spawn(handler: Handler, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let acceptor = tls.map(TlsAcceptor::from);

        let accepted_task = Arc::clone(&accepted);
        let connections_task = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                accepted_task.fetch_add(1, Ordering::SeqCst);

                let handler = Arc::clone(&handler);
                let acceptor = acceptor.clone();
                let task = tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let handler = Arc::clone(&handler);
                        async move {
                            let response = handler(request).await;
                            Ok::<_, Infallible>(response)
                        }
                    });

                    match acceptor {
                        Some(acceptor) => {
                            let Ok(tls) = acceptor.accept(tcp).await else {
                                return;
                            };
                            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(tls), service)
                                .await;
                        }
                        None => {
                            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(tcp), service)
                                .await;
                        }
                    }
                });

                connections_task.lock().expect("connection list").push(task);
            }
        });

        Self {
            addr,
            accepted,
            connections,
        }
    }

    fn http_uri(&self) -> Uri {
        format!("http://127.0.0.1:{}/", self.addr.port())
            .parse()
            .expect("valid URI")
    }

    fn https_localhost_uri(&self) -> Uri {
        format!("https://localhost:{}/", self.addr.port())
            .parse()
            .expect("valid URI")
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn abort_connections(&self) {
        let mut connections = self.connections.lock().expect("connection list");
        for task in connections.drain(..) {
            task.abort();
        }
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../elira-tls/tests/fixtures")
}

fn config(max_connections: usize) -> PoolConfig {
    PoolConfig {
        max_connections,
        connect_timeout: Duration::from_secs(3),
        ..PoolConfig::default()
    }
}

fn ok_handler(payload: &'static [u8]) -> Handler {
    Arc::new(move |_request| {
        Box::pin(async move {
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from_static(payload)))
                .expect("valid response")
        })
    })
}

fn slow_handler(delay: Duration) -> Handler {
    Arc::new(move |_request| {
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Response::new(Full::new(Bytes::from_static(b"slow")))
        })
    })
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
async fn h2c_request_works_and_reuses_the_connection() {
    let server = TestServer::spawn_h2c(ok_handler(b"hello")).await;
    let pool = Pool::new(config(2));

    for _ in 0..3 {
        let response = pool
            .request(server.http_uri(), get())
            .await
            .expect("h2c request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, Bytes::from_static(b"hello"));
    }

    let stats = pool.stats();
    assert_eq!(stats.total_connections, 1);
    assert_eq!(stats.connections, 1);
    assert_eq!(stats.active_streams, 0);
    assert_eq!(server.accepted(), 1, "sequential requests must reuse");
}

#[tokio::test]
async fn request_body_and_path_are_passed_through() {
    let handler: Handler = Arc::new(|request: Request<Incoming>| {
        Box::pin(async move {
            let path = request.uri().path().to_owned();
            let host = request
                .headers()
                .get(http::header::HOST)
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
                .header("x-path", path)
                .header("x-host", host)
                .body(Full::new(body))
                .expect("valid response")
        })
    });
    let server = TestServer::spawn_h2c(handler).await;
    let pool = Pool::new(config(1));

    let request = Request::builder()
        .method(Method::POST)
        .uri("/echo")
        .body(full(Bytes::from_static(b"not buffered by the pool")))
        .expect("valid request");
    let response = pool
        .request(server.http_uri(), request)
        .await
        .expect("echo request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-path"], "/echo");
    assert_eq!(
        response.headers()["x-host"],
        format!("127.0.0.1:{}", server.addr.port())
    );
    assert_eq!(
        body_text(response).await,
        Bytes::from_static(b"not buffered by the pool")
    );
}

#[tokio::test]
async fn closed_connection_is_replaced() {
    let server = TestServer::spawn_h2c(ok_handler(b"ok")).await;
    let pool = Pool::new(config(1));

    let first = pool
        .request(server.http_uri(), get())
        .await
        .expect("first request");
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(body_text(first).await, Bytes::from_static(b"ok"));
    assert_eq!(pool.stats().total_connections, 1);

    server.abort_connections();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let second = pool
        .request(server.http_uri(), get())
        .await
        .expect("second request after the server closed the connection");
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(body_text(second).await, Bytes::from_static(b"ok"));

    let stats = pool.stats();
    assert_eq!(stats.total_connections, 2, "a fresh connection was needed");
    assert_eq!(stats.connections, 1);
    assert_eq!(server.accepted(), 2);
}

#[tokio::test]
async fn stats_track_active_streams_and_successful_handshakes() {
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
    let server = TestServer::spawn_h2c(handler).await;
    let pool = Pool::new(config(2));

    let task = {
        let pool = pool.clone();
        let uri = server.http_uri();
        tokio::spawn(async move { pool.request(uri, get()).await })
    };

    wait_for(&pool, |stats| stats.active_streams == 1).await;
    let stats = pool.stats();
    assert_eq!(stats.active_streams, 1);
    assert_eq!(stats.total_connections, 1);
    assert_eq!(stats.connections, 1);

    gate.add_permits(1);
    let response = task.await.expect("request task").expect("request");
    assert_eq!(body_text(response).await, Bytes::from_static(b"released"));

    wait_for(&pool, |stats| stats.active_streams == 0).await;
    assert_eq!(pool.stats().total_connections, 1);
}

#[tokio::test]
async fn concurrent_requests_share_one_connection_when_capped() {
    let server = TestServer::spawn_h2c(slow_handler(Duration::from_millis(20))).await;
    let pool = Pool::new(config(1));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let uri = server.http_uri();
        tasks.push(tokio::spawn(async move { pool.request(uri, get()).await }));
    }

    for task in tasks {
        let response = task.await.expect("request task").expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, Bytes::from_static(b"slow"));
    }

    let stats = pool.stats();
    assert_eq!(stats.total_connections, 1);
    assert_eq!(stats.connections, 1);
    assert_eq!(server.accepted(), 1);
}

#[tokio::test]
async fn concurrent_requests_scale_up_to_the_connection_cap() {
    let server = TestServer::spawn_h2c(slow_handler(Duration::from_millis(30))).await;
    let pool = Pool::new(config(2));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let uri = server.http_uri();
        tasks.push(tokio::spawn(async move { pool.request(uri, get()).await }));
    }

    for task in tasks {
        let response = task.await.expect("request task").expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, Bytes::from_static(b"slow"));
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
    assert!(server.accepted() <= 2);
}

#[tokio::test]
async fn tls_h2_request_works_with_the_fixture_server() {
    let server = TestServer::spawn_tls(ok_handler(b"secure")).await;
    let pool = Pool::new(PoolConfig {
        max_connections: 1,
        connect_timeout: Duration::from_secs(3),

        tls: TlsOptions {
            insecure: true,
            ..TlsOptions::default()
        },
        ..PoolConfig::default()
    });

    let response = pool
        .request(server.https_localhost_uri(), get())
        .await
        .expect("TLS h2 request");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, Bytes::from_static(b"secure"));
    assert_eq!(pool.stats().total_connections, 1);
}

#[tokio::test]
async fn handshake_timeout_is_reported_as_connect_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent listener");
    let addr = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
        }
    });

    let pool = Pool::new(PoolConfig {
        max_connections: 1,
        connect_timeout: Duration::from_millis(150),
        tls: TlsOptions {
            insecure: true,
            ..TlsOptions::default()
        },
        ..PoolConfig::default()
    });
    let uri: Uri = format!("https://127.0.0.1:{}/", addr.port())
        .parse()
        .expect("valid URI");

    let error = pool
        .request(uri, get())
        .await
        .expect_err("TLS handshake must time out");
    assert!(
        matches!(error, Error::ConnectTimeout { .. }),
        "expected a connect timeout, got {error:?}"
    );

    server.abort();
}
