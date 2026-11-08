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
}

/// What the accept loop needs. Everything here is captured at startup and a
/// reload cannot change it.
#[derive(Clone, Copy)]
pub struct Options {
    pub max_connections: usize,
    pub max_headers: usize,
    pub max_buf_size: usize,
    pub idle_timeout: Duration,
}

impl Options {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            max_connections: cfg.limits.max_connections,
            max_headers: cfg.limits.max_headers,
            max_buf_size: cfg.limits.max_header_bytes,
            idle_timeout: Duration::from_secs(cfg.limits.idle_timeout_secs),
        }
    }
}

/// Accept connections until the stop channel flips, then drain.
pub async fn serve(
    listener: TcpListener,
    runtime: Arc<ArcSwap<Runtime>>,
    options: Options,
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
                let mut stop = stop.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    serve_stream(stream, peer, runtime, options, &mut stop).await;
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
pub fn spawn_health_loop(runtime: Arc<ArcSwap<Runtime>>, mut stop: watch::Receiver<bool>) {
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
    stream: TcpStream,
    peer: SocketAddr,
    runtime: Arc<ArcSwap<Runtime>>,
    options: Options,
    stop: &mut watch::Receiver<bool>,
) {
    let tls = runtime.load().tls.clone();
    let secure = tls.is_some();

    let conn = ConnOptions {
        max_headers: options.max_headers,
        max_buf_size: options.max_buf_size,
        idle_timeout: options.idle_timeout,
        h2: false,
        secure,
    };

    match tls {
        Some(config) => {
            let acceptor = TlsAcceptor::from(config);
            // A client that never sends ClientHello must not hold a permit,
            // and with it the accept loop, forever.
            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                    let conn = ConnOptions { h2, ..conn };
                    serve_conn(stream, peer, runtime, conn, stop).await;
                }
                Ok(Err(err)) => tracing::debug!(%peer, error = %err, "tls handshake failed"),
                Err(_) => tracing::debug!(%peer, "tls handshake timed out"),
            }
        }
        None => serve_conn(stream, peer, runtime, conn, stop).await,
    }
}

async fn serve_conn<I>(
    io: I,
    peer: SocketAddr,
    runtime: Arc<ArcSwap<Runtime>>,
    opts: ConnOptions,
    stop: &mut watch::Receiver<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let idle = Arc::new(tokio::sync::Notify::new());
    let idle_for_service = idle.clone();
    let scheme = if opts.secure { "https" } else { "http" };

    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let runtime = runtime.clone();
        let idle = idle_for_service.clone();
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
            let bytes = response.body().size_hint().exact().unwrap_or(0);
            let entry = Entry {
                peer: peer.ip(),
                method,
                version,
                host,
                path,
                status: response.status(),
                bytes,
                duration: started.elapsed(),
                user_agent,
                request_id: id,
            };

            match current.log {
                LogFormat::Text => tracing::info!(target: "access", "{}", entry.line()),
                LogFormat::Json => tracing::info!(target: "access", "{}", entry.json()),
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
