//! The TCP listener and the per-connection serving logic.
//!
//! This lives in the library rather than in `main` so tests can bind port 0
//! and drive the real server instead of a simplified copy of it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use http_body::Body as _;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;

use elira_accesslog::{request_id, Entry};
use elira_metrics::Metrics;

use crate::config::{Config, Health, Http3, LogFormat};
use crate::proxy::{BoxError, Proxy};

/// Everything that can change on SIGHUP. A connection keeps the runtime it
/// loaded for its current request; the next request sees the new one.
pub struct Runtime {
    proxy: Proxy,
    tls: Option<Arc<rustls::ServerConfig>>,
    log: LogFormat,
    health: Health,
    http3: Option<Http3>,
    access_log: Option<Arc<crate::access_log::AccessLog>>,
}

impl Runtime {
    pub fn build(cfg: &Config) -> anyhow::Result<Self> {
        let tls = match &cfg.tls {
            Some(tls) => Some(Arc::new(elira_tls::server_config(&tls.cert, &tls.key)?)),
            None => None,
        };

        Ok(Self {
            proxy: Proxy::new(cfg)?,
            tls,
            log: cfg.log.format,
            health: cfg.health.clone(),
            http3: cfg.http3.clone(),
            access_log: match &cfg.log.file {
                Some(path) => Some(Arc::new(crate::access_log::AccessLog::open(
                    path.clone(),
                    cfg.log.max_bytes,
                    cfg.log.keep,
                )?)),
                None => None,
            },
        })
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    pub fn log(&self) -> LogFormat {
        self.log
    }

    pub fn health(&self) -> &Health {
        &self.health
    }

    pub fn http3(&self) -> Option<&Http3> {
        self.http3.as_ref()
    }

    pub fn access_log(&self) -> Option<&Arc<crate::access_log::AccessLog>> {
        self.access_log.as_ref()
    }
}

/// What the accept loop needs. Everything here is captured at startup and a
/// reload cannot change it.
#[derive(Clone)]
pub struct Options {
    pub max_connections: usize,
    pub max_headers: usize,
    pub max_buf_size: usize,
    pub idle_timeout: Duration,
    pub proxy_protocol: bool,
    pub sendfile: bool,
    pub acme: Option<Arc<elira_acme::Acme>>,
}

impl Options {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            max_connections: cfg.limits.max_connections,
            max_headers: cfg.limits.max_headers,
            max_buf_size: cfg.limits.max_header_bytes,
            idle_timeout: Duration::from_secs(cfg.limits.idle_timeout_secs),
            proxy_protocol: cfg.proxy_protocol,
            sendfile: cfg.sendfile,
            acme: None,
        }
    }
}

/// Bind a TCP listener, optionally with SO_REUSEPORT so a replacement
/// process can share the port during a hot restart.
pub fn bind_tcp(addr: SocketAddr, reuse_port: bool) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    TcpListener::from_std(socket.into())
}

/// Accept connections until the stop channel flips, then drain.
pub async fn serve(
    listener: TcpListener,
    runtime: Arc<ArcSwap<Runtime>>,
    options: Options,
    metrics: Arc<Metrics>,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let semaphore = Arc::new(Semaphore::new(options.max_connections));
    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            _ = stop.changed() => break,

            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        // EMFILE/ENFILE return immediately and would turn this
                        // loop into a log-flooding spin.
                        tracing::warn!(error = %err, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // Blocking here would stop the loop from noticing shutdown.
                // When the limit is hit, drop the socket.
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::debug!(%peer, "connection limit reached");
                        continue;
                    }
                };

                let runtime = runtime.clone();
                let metrics = metrics.clone();
                let options = options.clone();
                let mut stop = stop.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    serve_stream(stream, peer, runtime, options, metrics, &mut stop).await;
                });
            }
        }

        while connections.try_join_next().is_some() {}
    }

    drop(listener);

    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .is_err()
    {
        tracing::warn!("some connections did not finish in time");
    }

    Ok(())
}

/// Re-probe upstreams on a timer until shutdown. Reads the current runtime
/// every tick, so a reload changes the interval and the targets.
pub fn spawn_health_loop(
    runtime: Arc<ArcSwap<Runtime>>,
    metrics: Arc<Metrics>,
    mut stop: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            let current = runtime.load_full();
            let interval = if current.health.enabled {
                Duration::from_secs(current.health.interval_secs)
            } else {
                Duration::from_secs(30)
            };

            tokio::select! {
                _ = stop.changed() => break,
                _ = tokio::time::sleep(interval) => {
                    current.proxy.check_health(&current.health).await;
                    let (up, down) = current.proxy.upstream_counts();
                    metrics.set_upstreams(up, down);
                }
            }
        }
    });
}

#[derive(Clone, Copy)]
struct ConnOptions {
    max_headers: usize,
    max_buf_size: usize,
    idle_timeout: Duration,
    h2: bool,
    secure: bool,
}

async fn serve_stream(
    mut stream: TcpStream,
    mut peer: SocketAddr,
    runtime: Arc<ArcSwap<Runtime>>,
    options: Options,
    metrics: Arc<Metrics>,
    stop: &mut watch::Receiver<bool>,
) {
    if options.proxy_protocol {
        match crate::proxy_protocol::read_peer(&mut stream).await {
            Some(real) => peer = real,
            None => {
                tracing::debug!(%peer, "missing or malformed PROXY header");
                return;
            }
        }
    }

    let conn = ConnOptions {
        max_headers: options.max_headers,
        max_buf_size: options.max_buf_size,
        idle_timeout: options.idle_timeout,
        h2: false,
        secure: false,
    };

    if let Some(acme) = &options.acme {
        match acme.accept(stream).await {
            Ok((io, h2)) => {
                let conn = ConnOptions {
                    h2,
                    secure: true,
                    ..conn
                };
                serve_conn(io, peer, runtime, conn, metrics, stop).await;
            }
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionAborted => {
                tracing::debug!(%peer, "acme validation connection");
            }
            Err(err) => tracing::debug!(%peer, error = %err, "acme handshake failed"),
        }
        return;
    }

    let tls = runtime.load().tls.clone();
    let secure = tls.is_some();

    // Plain HTTP/1.1 only: TLS and HTTP/2 have their own write paths, and the
    // fast path would duplicate them.
    if options.sendfile
        && tls.is_none()
        && crate::sendfile::try_serve(&mut stream, &runtime, &metrics, peer)
            .await
            .is_some()
    {
        return;
    }

    let conn = ConnOptions { secure, ..conn };

    match tls {
        Some(config) => {
            let acceptor = TlsAcceptor::from(config);
            // A client that never sends ClientHello must not hold a permit,
            // and with it the accept loop, forever.
            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                    let conn = ConnOptions { h2, ..conn };
                    serve_conn(stream, peer, runtime, conn, metrics, stop).await;
                }
                Ok(Err(err)) => tracing::debug!(%peer, error = %err, "tls handshake failed"),
                Err(_) => tracing::debug!(%peer, "tls handshake timed out"),
            }
        }
        None => serve_conn(stream, peer, runtime, conn, metrics, stop).await,
    }
}

async fn serve_conn<I>(
    io: I,
    peer: SocketAddr,
    runtime: Arc<ArcSwap<Runtime>>,
    opts: ConnOptions,
    metrics: Arc<Metrics>,
    stop: &mut watch::Receiver<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    metrics.connection_started();

    let idle = Arc::new(tokio::sync::Notify::new());
    let idle_for_service = idle.clone();
    let scheme = if opts.secure { "https" } else { "http" };
    let metrics_for_service = metrics.clone();

    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let runtime = runtime.clone();
        let idle = idle_for_service.clone();
        let metrics = metrics_for_service.clone();
        async move {
            // Reset the keep-alive watchdog: a request means the client is
            // still there, even if the response takes a while.
            idle.notify_one();

            // Load per request, so a reload applies to the next request on
            // an existing keep-alive connection.
            let current = runtime.load_full();

            let started = Instant::now();
            let method = req.method().clone();
            let host = req
                .headers()
                .get(hyper::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                // HTTP/2 has no Host header; the value lives in :authority.
                .or_else(|| req.uri().authority().map(|value| value.as_str().to_owned()))
                .unwrap_or_default();
            let version = req.version();
            let path = req
                .uri()
                .path_and_query()
                .map(|value| value.as_str().to_owned())
                .unwrap_or_else(|| "/".to_owned());
            let user_agent = req
                .headers()
                .get(hyper::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let id = request_id();

            let req = req.map(|body| body.map_err(|err| -> BoxError { Box::new(err) }).boxed());
            let response = current.proxy.handle(req, peer, scheme).await;
            let elapsed = started.elapsed();
            metrics.observe(response.status().as_u16(), elapsed);
            let bytes = response.body().size_hint().exact().unwrap_or(0);
            let entry = Entry {
                peer: peer.ip(),
                method,
                version,
                host,
                path,
                status: response.status(),
                bytes,
                duration: elapsed,
                user_agent,
                request_id: id,
            };

            let line = match current.log {
                LogFormat::Text => entry.line(),
                LogFormat::Json => entry.json(),
            };

            match current.access_log() {
                Some(log) => log.write(&line),
                None => tracing::info!(target: "access", "{}", line),
            }

            Ok::<_, std::convert::Infallible>(response)
        }
    });

    if opts.h2 {
        let conn = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(Duration::from_secs(30)))
            .keep_alive_timeout(Duration::from_secs(20))
            .max_header_list_size(opts.max_buf_size as u32)
            .serve_connection(TokioIo::new(io), service);
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            result = conn.as_mut() => {
                if let Err(err) = result {
                    tracing::debug!(%peer, error = %err, "connection closed");
                }
            }
            _ = stop.changed() => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer).await;
            }
            _ = idle_watch(idle.clone(), opts.idle_timeout) => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer).await;
            }
        }
    } else {
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(Some(Duration::from_secs(30)))
            .max_headers(opts.max_headers)
            .max_buf_size(opts.max_buf_size)
            .serve_connection(TokioIo::new(io), service)
            // Without this hyper refuses to hand the socket over and
            // OnUpgrade resolves with "upgrade expected but low level API
            // in use".
            .with_upgrades();
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            result = conn.as_mut() => {
                if let Err(err) = result {
                    tracing::debug!(%peer, error = %err, "connection closed");
                }
            }
            _ = stop.changed() => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer).await;
            }
            _ = idle_watch(idle.clone(), opts.idle_timeout) => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer).await;
            }
        }
    }

    metrics.connection_finished();
}

/// Serve `/metrics` on a small separate listener. Everything else is a 404.
pub fn spawn_metrics(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    mut stop: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        continue;
                    };

                    let metrics = metrics.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |req: hyper::Request<Incoming>| {
                            let metrics = metrics.clone();
                            async move {
                                let (status, body) = if req.method() == hyper::Method::GET
                                    && req.uri().path() == "/metrics"
                                {
                                    (hyper::StatusCode::OK, metrics.render())
                                } else {
                                    (hyper::StatusCode::NOT_FOUND, "not found".to_owned())
                                };

                                let response = hyper::Response::builder()
                                    .status(status)
                                    .header(
                                        hyper::header::CONTENT_TYPE,
                                        "text/plain; version=0.0.4; charset=utf-8",
                                    )
                                    .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
                                    .expect("static response");

                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });

                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
    });
}

/// Let the current request finish, but do not wait forever: a client that
/// trickles a body would otherwise pin the permit until the process dies.
async fn drain<C>(conn: std::pin::Pin<&mut C>, peer: SocketAddr)
where
    C: std::future::Future<Output = Result<(), hyper::Error>>,
{
    if tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .is_err()
    {
        tracing::debug!(%peer, "connection did not drain in time");
    }
}

/// Close a connection that has not seen a request for `timeout`.
/// A zero timeout disables the watchdog.
async fn idle_watch(idle: Arc<tokio::sync::Notify>, timeout: Duration) {
    if timeout.is_zero() {
        std::future::pending::<()>().await;
        return;
    }

    loop {
        match tokio::time::timeout(timeout, idle.notified()).await {
            Ok(()) => continue,
            Err(_) => return,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reuse_port_lets_two_listeners_share_a_port() {
        let first = bind_tcp("127.0.0.1:0".parse().unwrap(), true).expect("first bind");
        let addr = first.local_addr().expect("addr");
        let second = bind_tcp(addr, true).expect("second bind");
        assert_eq!(second.local_addr().expect("addr"), addr);
    }

    #[tokio::test]
    async fn without_reuse_port_the_second_bind_fails() {
        let first = bind_tcp("127.0.0.1:0".parse().unwrap(), false).expect("first bind");
        let addr = first.local_addr().expect("addr");
        assert!(bind_tcp(addr, false).is_err());
    }
}
