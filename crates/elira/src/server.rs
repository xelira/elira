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
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;

use elira_accesslog::{request_id, Entry};
use elira_metrics::Metrics;

use crate::config::{ClientAuthMode, Config, Health, Http3, LogFormat, TlsVersion};
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
    template: Option<elira_accesslog::Format>,
    syslog: Option<Arc<elira_accesslog::Syslog>>,
}

impl Runtime {
    pub fn build(cfg: &Config) -> anyhow::Result<Self> {
        let tls = match &cfg.tls {
            Some(tls) => {
                let mode = match tls.client_auth {
                    ClientAuthMode::Off => elira_tls::ClientAuth::Off,
                    ClientAuthMode::Optional => elira_tls::ClientAuth::Optional,
                    ClientAuthMode::Required => elira_tls::ClientAuth::Required,
                };
                let named: Vec<_> = tls
                    .certificates
                    .iter()
                    .map(|entry| elira_tls::NamedCert {
                        names: entry.names.clone(),
                        cert: entry.cert.clone(),
                        key: entry.key.clone(),
                    })
                    .collect();
                let default = if tls.cert.as_os_str().is_empty() {
                    None
                } else {
                    Some((tls.cert.as_path(), tls.key.as_path()))
                };
                let config = elira_tls::server_config_with_options(&elira_tls::ServerOptions {
                    default,
                    named: &named,
                    client_ca: tls.client_ca.as_deref(),
                    client_auth: mode,
                    tls13_only: tls.min_version == TlsVersion::Tls13,
                    ocsp: tls.ocsp.as_deref(),
                })?;
                Some(Arc::new(config))
            }
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
            template: match &cfg.log.template {
                Some(template) => Some(
                    elira_accesslog::Format::parse(template)
                        .map_err(|err| anyhow::anyhow!("log.template: {err}"))?,
                ),
                None => None,
            },
            syslog: match &cfg.log.syslog {
                Some(path) => Some(Arc::new(
                    elira_accesslog::Syslog::open(path)
                        .map_err(|err| anyhow::anyhow!("log.syslog {}: {err}", path.display()))?,
                )),
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

    /// Render one access line and send it to every configured sink.
    pub fn write_log(&self, entry: &Entry) {
        let line = match &self.template {
            Some(template) => template.render(entry),
            None => match self.log {
                LogFormat::Text => entry.line(),
                LogFormat::Json => entry.json(),
            },
        };

        if let Some(syslog) = &self.syslog {
            let _ = syslog.send("elira", &line);
        }

        match self.access_log() {
            Some(log) => log.write(&line),
            None => tracing::info!(target: "access", "{}", line),
        }
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
    pub h2c: bool,
    pub body_timeout: Option<Duration>,
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
            h2c: cfg.h2c,
            body_timeout: match cfg.limits.request_body_timeout_secs {
                0 => None,
                secs => Some(Duration::from_secs(secs)),
            },
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

/// Bind a unix listener. An existing path is not removed: silently replacing
/// another process's socket would be worse than refusing to start.
pub fn bind_unix(path: &std::path::Path) -> std::io::Result<UnixListener> {
    UnixListener::bind(path)
}

/// Accept plain HTTP/1.1 on a unix socket. There is no TLS and no PROXY
/// protocol; the peer address is localhost for logs and ACLs.
pub async fn serve_unix(
    listener: UnixListener,
    runtime: Arc<ArcSwap<Runtime>>,
    options: Options,
    metrics: Arc<Metrics>,
    stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let permits = Arc::new(Semaphore::new(options.max_connections));
    let mut stop = stop;
    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    continue;
                };
                let runtime = runtime.clone();
                let metrics = metrics.clone();
                let mut stop = stop.clone();
                let conn = ConnOptions {
                    max_headers: options.max_headers,
                    max_buf_size: options.max_buf_size,
                    idle_timeout: options.idle_timeout,
                    body_timeout: options.body_timeout,
                    h2: false,
                    secure: false,
                };
                connections.spawn(async move {
                    let _permit = permit;
                    serve_conn(
                        stream,
                        "127.0.0.1:0".parse().expect("loopback"),
                        runtime,
                        conn,
                        metrics,
                        &mut stop,
                        None,
                    )
                    .await;
                });
            }
        }
    }

    while connections.join_next().await.is_some() {}
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
    body_timeout: Option<Duration>,
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
        body_timeout: options.body_timeout,
        h2: false,
        secure: false,
    };

    if let Some(acme) = &options.acme {
        // HTTP-01 is validated over plain HTTP; there is no TLS to terminate.
        if acme.uses_http01() {
            let conn = ConnOptions {
                secure: false,
                ..conn
            };
            serve_conn(
                stream,
                peer,
                runtime,
                conn,
                metrics,
                stop,
                Some(acme.clone()),
            )
            .await;
            return;
        }
        match acme.accept(stream).await {
            Ok((io, h2)) => {
                let conn = ConnOptions {
                    h2,
                    secure: true,
                    ..conn
                };
                serve_conn(io, peer, runtime, conn, metrics, stop, Some(acme.clone())).await;
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

    // HTTP/2 with prior knowledge arrives before any TLS or HTTP/1.1 parsing.
    // Peeking leaves the bytes in place for hyper.
    if options.h2c && tls.is_none() {
        let mut preface = [0u8; 24];
        if let Ok(read) = stream.peek(&mut preface).await {
            if read == preface.len() && preface == *b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
                let conn = ConnOptions {
                    h2: true,
                    secure: false,
                    ..conn
                };
                serve_conn(stream, peer, runtime, conn, metrics, stop, None).await;
                return;
            }
        }
    }

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
                    serve_conn(
                        stream,
                        peer,
                        runtime,
                        conn,
                        metrics,
                        stop,
                        options.acme.clone(),
                    )
                    .await;
                }
                Ok(Err(err)) => tracing::debug!(%peer, error = %err, "tls handshake failed"),
                Err(_) => tracing::debug!(%peer, "tls handshake timed out"),
            }
        }
        None => serve_conn(stream, peer, runtime, conn, metrics, stop, None).await,
    }
}

async fn serve_conn<I>(
    io: I,
    peer: SocketAddr,
    runtime: Arc<ArcSwap<Runtime>>,
    opts: ConnOptions,
    metrics: Arc<Metrics>,
    stop: &mut watch::Receiver<bool>,
    acme: Option<Arc<elira_acme::Acme>>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    metrics.connection_started();

    let idle = Arc::new(tokio::sync::Notify::new());
    let idle_for_service = idle.clone();
    let scheme = if opts.secure { "https" } else { "http" };
    let body_timeout = opts.body_timeout;
    let metrics_for_service = metrics.clone();
    let acme_for_service = acme.clone();

    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let runtime = runtime.clone();
        let idle = idle_for_service.clone();
        let metrics = metrics_for_service.clone();
        let acme = acme_for_service.clone();
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

            let request_bytes = req.body().size_hint().exact().unwrap_or(0);
            let req = req.map(|body| {
                let body = body.map_err(|err| -> BoxError { Box::new(err) }).boxed();
                match body_timeout {
                    Some(idle) => elira_proxy::timeout_body(body, idle),
                    None => body,
                }
            });
            let response = if let Some(acme) = &acme {
                let token = path
                    .strip_prefix("/.well-known/acme-challenge/")
                    .map(|token| token.split('?').next().unwrap_or(token));
                match token.and_then(|token| acme.http01(token)) {
                    Some(body) => acme_response(hyper::StatusCode::OK, body),
                    None => current.proxy.handle(req, peer, scheme).await,
                }
            } else {
                current.proxy.handle(req, peer, scheme).await
            };
            let elapsed = started.elapsed();
            let status = response.status().as_u16();
            metrics.record_request(status, elapsed);
            metrics.request_bytes(request_bytes);
            if let Some(labels) = response.extensions().get::<elira_proxy::Labels>().cloned() {
                metrics.record_route(&labels.route, status, elapsed);
                if let Some(upstream) = &labels.upstream {
                    metrics.record_upstream(upstream, status, elapsed);
                }
            }
            match response
                .headers()
                .get("x-cache")
                .and_then(|v| v.to_str().ok())
            {
                Some("HIT") => metrics.cache_hit(),
                Some("MISS") => metrics.cache_miss(),
                _ => {}
            }
            let bytes = response.body().size_hint().exact().unwrap_or(0);
            metrics.response_bytes(bytes);
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

            current.write_log(&entry);

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

fn acme_response(status: hyper::StatusCode, body: String) -> hyper::Response<elira_proxy::Body> {
    let body = http_body_util::Full::new(hyper::body::Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    hyper::Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .expect("static response")
}

/// Serve only HTTP-01 challenge tokens on a plain listener.
pub fn spawn_http01(
    listener: TcpListener,
    acme: Arc<elira_acme::Acme>,
    mut stop: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let acme = acme.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |req: hyper::Request<Incoming>| {
                            let acme = acme.clone();
                            async move {
                                let token = req.uri().path().strip_prefix("/.well-known/acme-challenge/");
                                let body = token.and_then(|token| acme.http01(token)).unwrap_or_default();
                                let status = if body.is_empty() {
                                    hyper::StatusCode::NOT_FOUND
                                } else {
                                    hyper::StatusCode::OK
                                };
                                Ok::<_, std::convert::Infallible>(acme_response(status, body))
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

/// Commands accepted by the supervisor's admin listener.
#[derive(Debug, Clone, Copy)]
pub enum AdminCommand {
    Reload,
    Drain,
}

/// Aggregate metrics and status reported by worker processes.
pub fn spawn_metrics_aggregate(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    statuses: Arc<std::sync::Mutex<std::collections::HashMap<usize, String>>>,
    auth: Option<Arc<elira_auth::BasicAuth>>,
    control: tokio::sync::mpsc::Sender<AdminCommand>,
) {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let metrics = metrics.clone();
            let statuses = statuses.clone();
            let auth = auth.clone();
            let control = control.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: hyper::Request<Incoming>| {
                    let metrics = metrics.clone();
                    let statuses = statuses.clone();
                    let auth = auth.clone();
                    let control = control.clone();
                    async move {
                        if let Some(auth) = &auth {
                            let header = req
                                .headers()
                                .get(hyper::header::AUTHORIZATION)
                                .and_then(|value| value.to_str().ok());
                            if !auth.check(header) {
                                let mut response = json(
                                    hyper::StatusCode::UNAUTHORIZED,
                                    "{\"error\":\"authentication required\"}",
                                );
                                response.headers_mut().insert(
                                    hyper::header::WWW_AUTHENTICATE,
                                    hyper::header::HeaderValue::from_static(
                                        "Basic realm=\"elira\"",
                                    ),
                                );
                                return Ok::<_, std::convert::Infallible>(response);
                            }
                        }

                        let response = match (req.method(), req.uri().path()) {
                            (&hyper::Method::GET, "/metrics") => text_response(
                                hyper::StatusCode::OK,
                                "text/plain; version=0.0.4; charset=utf-8",
                                metrics.render(),
                            ),
                            (&hyper::Method::POST, "/reload") => {
                                let _ = control.try_send(AdminCommand::Reload);
                                json(hyper::StatusCode::ACCEPTED, "{\"reload\":\"queued\"}")
                            }
                            (&hyper::Method::POST, "/drain") => {
                                let _ = control.try_send(AdminCommand::Drain);
                                json(hyper::StatusCode::ACCEPTED, "{\"drain\":\"started\"}")
                            }
                            (&hyper::Method::GET, "/status") => {
                                let statuses = statuses
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                let last = statuses
                                    .values()
                                    .next()
                                    .cloned()
                                    .unwrap_or_else(|| "null".to_owned());
                                let body = format!(
                                    "{{\"workers\":{},\"snapshot\":{last}}}",
                                    statuses.len()
                                );
                                text_response(hyper::StatusCode::OK, "application/json", body)
                            }
                            _ => text_response(
                                hyper::StatusCode::NOT_FOUND,
                                "text/plain; charset=utf-8",
                                "not found".to_owned(),
                            ),
                        };
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });

                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
}

/// Serve the admin listener: `/metrics`, `/status`, reload, drain and cache
/// purge. With `auth` set, every path requires the same Basic credentials.
pub fn spawn_metrics(
    listener: TcpListener,
    runtime: Arc<ArcSwap<Runtime>>,
    metrics: Arc<Metrics>,
    auth: Option<Arc<elira_auth::BasicAuth>>,
    reload: watch::Sender<u64>,
    stop_tx: watch::Sender<bool>,
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
                    let runtime = runtime.clone();
                    let auth = auth.clone();
                    let reload = reload.clone();
                    let stop_tx = stop_tx.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |req: hyper::Request<Incoming>| {
                            let metrics = metrics.clone();
                            let runtime = runtime.clone();
                            let auth = auth.clone();
                            let reload = reload.clone();
                            let stop_tx = stop_tx.clone();
                            async move {
                                if let Some(auth) = &auth {
                                    let header = req
                                        .headers()
                                        .get(hyper::header::AUTHORIZATION)
                                        .and_then(|value| value.to_str().ok());
                                    if !auth.check(header) {
                                        let mut response = json(
                                            hyper::StatusCode::UNAUTHORIZED,
                                            "{\"error\":\"authentication required\"}",
                                        );
                                        response.headers_mut().insert(
                                            hyper::header::WWW_AUTHENTICATE,
                                            hyper::header::HeaderValue::from_static(
                                                "Basic realm=\"elira\"",
                                            ),
                                        );
                                        return Ok::<_, std::convert::Infallible>(response);
                                    }
                                }

                                let method = req.method();
                                let path = req.uri().path();

                                let response = match (method, path) {
                                    (&hyper::Method::GET, "/metrics") => {
                                        text_response(
                                            hyper::StatusCode::OK,
                                            "text/plain; version=0.0.4; charset=utf-8",
                                            metrics.render(),
                                        )
                                    }
                                    // Loading the runtime per request keeps the
                                    // answer current across a SIGHUP reload.
                                    (&hyper::Method::GET, "/status") => text_response(
                                        hyper::StatusCode::OK,
                                        "application/json",
                                        runtime.load().proxy().status().to_string(),
                                    ),
                                    (&hyper::Method::POST, "/reload") => {
                                        let _ = reload.send(rand_counter());
                                        json(hyper::StatusCode::ACCEPTED, "{\"reload\":\"queued\"}")
                                    }
                                    (&hyper::Method::POST, "/drain") => {
                                        let _ = stop_tx.send(true);
                                        json(hyper::StatusCode::ACCEPTED, "{\"drain\":\"started\"}")
                                    }
                                    (&hyper::Method::POST, "/cache/purge") => {
                                        let purged = runtime.load().proxy().purge_cache();
                                        let body = format!("{{\"purged\":{purged}}}");
                                        json(hyper::StatusCode::OK, &body)
                                    }
                                    _ => text_response(
                                        hyper::StatusCode::NOT_FOUND,
                                        "text/plain; charset=utf-8",
                                        "not found".to_owned(),
                                    ),
                                };

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

fn text_response(
    status: hyper::StatusCode,
    content_type: &'static str,
    body: String,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
        .expect("static response")
}

fn json(
    status: hyper::StatusCode,
    body: &str,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    text_response(status, "application/json", body.to_owned())
}

/// The reload channel counts signal deliveries; the value itself is not used.
fn rand_counter() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
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
