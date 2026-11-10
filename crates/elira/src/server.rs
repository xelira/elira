//! The TCP listener and the per-connection serving logic.
//!
//! This lives in the library rather than in `main` so tests can bind port 0
//! and drive the real server instead of a simplified copy of it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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

use elira_accesslog::{request_id, Entry};
use elira_metrics::{CacheResult, Metrics};

use crate::config::{
    ClientAuthMode, Config, Health, Http2, Http3, LogFormat, TlsBackend, TlsVersion,
};
use crate::proxy::{BoxError, Proxy};

/// Everything that can change on SIGHUP. A connection keeps the runtime it
/// loaded for its current request; the next request sees the new one.
pub struct Runtime {
    proxy: Proxy,
    tls: Option<Arc<elira_tls::TlsServerConfig>>,
    config: Config,
    log: LogFormat,
    health: Health,
    http3: Option<Http3>,
    access_log: Option<Arc<crate::access_log::AccessLog>>,
    access_log_sample: f64,
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
                        ocsp: entry.ocsp.clone(),
                    })
                    .collect();
                let default = if tls.cert.as_os_str().is_empty() {
                    None
                } else {
                    Some((tls.cert.as_path(), tls.key.as_path()))
                };
                let backend = match tls.backend {
                    TlsBackend::Rustls => elira_tls::Backend::Rustls,
                    TlsBackend::Openssl => elira_tls::Backend::Openssl,
                };
                let min_version = match tls.min_version {
                    TlsVersion::Tls10 => elira_tls::TlsVersion::Tls10,
                    TlsVersion::Tls11 => elira_tls::TlsVersion::Tls11,
                    TlsVersion::Tls12 => elira_tls::TlsVersion::Tls12,
                    TlsVersion::Tls13 => elira_tls::TlsVersion::Tls13,
                };
                let config = elira_tls::server_config_for(
                    &elira_tls::ServerOptions {
                        default,
                        named: &named,
                        reject_unknown_sni: tls.reject_unknown_sni,
                        verify_ocsp: tls.verify_ocsp,
                        client_ca: tls.client_ca.as_deref(),
                        client_crl: tls.client_crl.as_deref(),
                        client_auth: mode,
                        tls13_only: tls.min_version == TlsVersion::Tls13,
                        ocsp: tls.ocsp.as_deref(),
                        cipher_suites: tls.cipher_suites.as_deref(),
                        curves: tls.curves.as_deref(),
                        ticket_key: tls.ticket_key.as_deref(),
                        session_tickets: tls.session_tickets,
                        session_cache: tls.session_cache,
                        early_data: 0,
                    },
                    backend,
                    min_version,
                )?;
                Some(Arc::new(config))
            }
            None => None,
        };

        Ok(Self {
            proxy: Proxy::new(cfg)?,
            tls,
            config: cfg.clone(),
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
            access_log_sample: cfg.log.sample,
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

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn health(&self) -> &Health {
        &self.health
    }

    pub fn http3(&self) -> Option<&Http3> {
        self.http3.as_ref()
    }

    pub fn tls(&self) -> Option<&Arc<elira_tls::TlsServerConfig>> {
        self.tls.as_ref()
    }

    pub fn access_log(&self) -> Option<&Arc<crate::access_log::AccessLog>> {
        self.access_log.as_ref()
    }

    pub fn access_log_sample(&self) -> f64 {
        self.access_log_sample
    }

    /// Reopen the access-log file after external rotation.
    pub fn reopen_logs(&self) {
        if let Some(log) = &self.access_log {
            log.reopen();
        }
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

/// Counts open client connections per IP for `limits.limit_conn_per_ip`.
pub(crate) struct ConnLimiter {
    limit: usize,
    active: Mutex<HashMap<std::net::IpAddr, usize>>,
}

impl ConnLimiter {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            active: Mutex::new(HashMap::new()),
        }
    }

    fn acquire(self: &Arc<Self>, ip: std::net::IpAddr) -> Option<ConnGuard> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = active.entry(ip).or_insert(0);
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(ConnGuard {
            limiter: self.clone(),
            ip,
        })
    }
}

pub(crate) struct ConnGuard {
    limiter: Arc<ConnLimiter>,
    ip: std::net::IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut active = self
            .limiter
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = active.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&self.ip);
            }
        }
    }
}

/// What the accept loop needs. Everything here is captured at startup and a
/// reload cannot change it.
#[derive(Clone)]
pub struct Options {
    pub max_connections: usize,
    pub limit_conn_per_ip: usize,
    pub(crate) conn_limiter: Option<Arc<ConnLimiter>>,
    pub http2: Http2,
    pub max_headers: usize,
    pub max_buf_size: usize,
    pub idle_timeout: Duration,
    pub keepalive_requests: usize,
    pub client_header_timeout: Option<Duration>,
    pub proxy_protocol: bool,
    pub sendfile: bool,
    pub h2c: bool,
    pub unix_tls: bool,
    /// This TCP listener terminates TLS.
    pub tls: bool,
    /// Name used by routes scoped to this listener.
    pub name: String,
    pub body_timeout: Option<Duration>,
    pub drain_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub acme: Option<Arc<elira_acme::Acme>>,
}

impl Options {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            max_connections: cfg.limits.max_connections,
            limit_conn_per_ip: cfg.limits.limit_conn_per_ip,
            conn_limiter: (cfg.limits.limit_conn_per_ip > 0)
                .then(|| Arc::new(ConnLimiter::new(cfg.limits.limit_conn_per_ip))),
            http2: cfg.http2.clone(),
            max_headers: cfg.limits.max_headers,
            max_buf_size: cfg.limits.max_header_bytes,
            idle_timeout: Duration::from_secs(cfg.limits.idle_timeout_secs),
            keepalive_requests: cfg.limits.keepalive_requests,
            client_header_timeout: match cfg.limits.client_header_timeout_secs {
                0 => None,
                secs => Some(Duration::from_secs(secs)),
            },
            proxy_protocol: cfg.proxy_protocol,
            sendfile: cfg.sendfile,
            h2c: cfg.h2c,
            unix_tls: cfg.unix_tls,
            tls: cfg.tls.is_some() || cfg.acme.is_some(),
            name: "default".to_owned(),
            body_timeout: match cfg.limits.request_body_timeout_secs {
                0 => None,
                secs => Some(Duration::from_secs(secs)),
            },
            drain_timeout: Duration::from_secs(cfg.limits.connection_drain_secs),
            shutdown_timeout: Duration::from_secs(cfg.limits.shutdown_timeout_secs),
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
    if tokio::time::timeout(options.shutdown_timeout, drain)
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

/// Apply the configured mode and numeric owner to a freshly bound socket.
pub fn configure_unix(
    path: &std::path::Path,
    mode: Option<u32>,
    owner: Option<&str>,
) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    if let Some(mode) = mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }

    if let Some(owner) = owner {
        let (uid, gid) = owner
            .split_once(':')
            .and_then(|(uid, gid)| Some((uid.parse::<u32>().ok()?, gid.parse::<u32>().ok()?)))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "owner must look like uid:gid",
                )
            })?;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "socket path has a NUL byte",
            )
        })?;
        // SAFETY: the path is a valid NUL-terminated string and chown does not
        // retain the pointer after returning.
        let result = unsafe { libc::chown(path.as_ptr(), uid, gid) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Accept HTTP/1.1 (or HTTP/2 over TLS) on a unix socket. PROXY protocol is
/// not applied; the peer address is localhost for logs and ACLs.
pub async fn serve_unix(
    listener: UnixListener,
    runtime: Arc<ArcSwap<Runtime>>,
    options: Options,
    metrics: Arc<Metrics>,
    stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let permits = Arc::new(Semaphore::new(options.max_connections));
    let unix_tls = options.unix_tls;
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
                    keepalive_requests: options.keepalive_requests,
                    client_header_timeout: options.client_header_timeout,
                    http2: options.http2.clone(),
                    body_timeout: options.body_timeout,
                    drain_timeout: options.drain_timeout,
                    h2: false,
                    secure: false,
                };
                connections.spawn(async move {
                    let _permit = permit;
                    if !unix_tls {
                        serve_conn(
                            stream,
                            "127.0.0.1:0".parse().expect("loopback"),
                            runtime,
                            conn,
                            metrics,
                            &mut stop,
                            None,
                            None,
                            "unix".to_owned(),
                        )
                        .await;
                        return;
                    }

                    let Some(config) = runtime.load().tls().cloned() else {
                        return;
                    };
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        elira_tls::accept(&config, stream),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => {
                            metrics.tls_handshake(true);
                            let h2 = stream.alpn_protocol() == Some(b"h2".as_slice());
                            let identity = stream
                                .peer_certificate_der()
                                .and_then(|leaf| elira_tls::ClientIdentity::parse(&leaf));
                            let conn = ConnOptions {
                                h2,
                                secure: true,
                                ..conn.clone()
                            };
                            serve_conn(
                                stream,
                                "127.0.0.1:0".parse().expect("loopback"),
                                runtime,
                                conn,
                                metrics,
                                &mut stop,
                                None,
                                identity,
                                "unix".to_owned(),
                            )
                            .await;
                        }
                        Ok(Err(err)) => {
                            metrics.tls_handshake(false);
                            tracing::debug!(error = %err, "unix tls handshake failed");
                        }
                        Err(_) => {
                            metrics.tls_handshake(false);
                            tracing::debug!("unix tls handshake timed out");
                        }
                    }
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
                    let (ok, failed) = current.proxy.check_health(&current.health).await;
                    for _ in 0..ok {
                        metrics.health_check(true);
                    }
                    for _ in 0..failed {
                        metrics.health_check(false);
                    }
                    let (up, down) = current.proxy.upstream_counts();
                    metrics.set_upstreams(up, down);
                    for (upstream, active) in current.proxy.pool_loads() {
                        metrics.set_upstream_load(&upstream, active);
                    }
                    for (upstream, stats) in current.proxy.pool_h2_stats() {
                        metrics.set_h2_pool(
                            &upstream,
                            stats.connections as u64,
                            stats.active_streams as u64,
                            stats.total_connections,
                            stats.queued_streams as u64,
                        );
                    }
                    for (upstream, stats) in current.proxy.pool_h3_stats() {
                        metrics.set_h3_pool(
                            &upstream,
                            stats.connections as u64,
                            stats.active_requests as u64,
                            stats.total_connections,
                        );
                    }
                }
            }
        }
    });
}

#[derive(Clone)]
struct ConnOptions {
    max_headers: usize,
    max_buf_size: usize,
    idle_timeout: Duration,
    keepalive_requests: usize,
    client_header_timeout: Option<Duration>,
    http2: Http2,
    body_timeout: Option<Duration>,
    drain_timeout: Duration,
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

    let _conn_guard = match &options.conn_limiter {
        Some(limiter) => match limiter.acquire(peer.ip()) {
            Some(guard) => Some(guard),
            None => {
                tracing::debug!(%peer, "per-IP connection limit reached");
                return;
            }
        },
        None => None,
    };

    let conn = ConnOptions {
        max_headers: options.max_headers,
        max_buf_size: options.max_buf_size,
        idle_timeout: options.idle_timeout,
        keepalive_requests: options.keepalive_requests,
        client_header_timeout: options.client_header_timeout,
        http2: options.http2.clone(),
        body_timeout: options.body_timeout,
        drain_timeout: options.drain_timeout,
        h2: false,
        secure: false,
    };

    if let Some(acme) = options.acme.as_ref().filter(|_| options.tls) {
        // HTTP-01 is validated over plain HTTP; there is no TLS to terminate.
        if acme.uses_http01() {
            let conn = ConnOptions {
                secure: false,
                ..conn.clone()
            };
            serve_conn(
                stream,
                peer,
                runtime,
                conn,
                metrics,
                stop,
                Some(acme.clone()),
                None,
                options.name.clone(),
            )
            .await;
            return;
        }
        match acme.accept(stream).await {
            Ok((io, h2)) => {
                metrics.tls_handshake(true);
                let conn = ConnOptions {
                    h2,
                    secure: true,
                    ..conn.clone()
                };
                serve_conn(
                    io,
                    peer,
                    runtime,
                    conn,
                    metrics,
                    stop,
                    Some(acme.clone()),
                    None,
                    options.name.clone(),
                )
                .await;
            }
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionAborted => {
                tracing::debug!(%peer, "acme validation connection");
            }
            Err(err) => {
                metrics.tls_handshake(false);
                tracing::debug!(%peer, error = %err, "acme handshake failed");
            }
        }
        return;
    }

    let tls = if options.tls {
        runtime.load().tls.clone()
    } else {
        None
    };
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
                    ..conn.clone()
                };
                serve_conn(
                    stream,
                    peer,
                    runtime,
                    conn,
                    metrics,
                    stop,
                    None,
                    None,
                    options.name.clone(),
                )
                .await;
                return;
            }
        }
    }

    // Plain HTTP/1.1 only: TLS and HTTP/2 have their own write paths, and the
    // fast path would duplicate them.
    if options.sendfile
        && tls.is_none()
        && crate::sendfile::try_serve(&mut stream, &runtime, &metrics, peer, &options.name)
            .await
            .is_some()
    {
        return;
    }

    let conn = ConnOptions {
        secure,
        ..conn.clone()
    };

    match tls {
        Some(config) => {
            // A client that never sends ClientHello must not hold a permit,
            // and with it the accept loop, forever.
            match tokio::time::timeout(Duration::from_secs(10), elira_tls::accept(&config, stream))
                .await
            {
                Ok(Ok(stream)) => {
                    metrics.tls_handshake(true);
                    let h2 = stream.alpn_protocol() == Some(b"h2".as_slice());
                    let identity = stream
                        .peer_certificate_der()
                        .and_then(|leaf| elira_tls::ClientIdentity::parse(&leaf));
                    let conn = ConnOptions { h2, ..conn.clone() };
                    serve_conn(
                        stream,
                        peer,
                        runtime,
                        conn,
                        metrics,
                        stop,
                        options.acme.clone(),
                        identity,
                        options.name.clone(),
                    )
                    .await;
                }
                Ok(Err(err)) => {
                    metrics.tls_handshake(false);
                    tracing::debug!(%peer, error = %err, "tls handshake failed");
                }
                Err(_) => {
                    metrics.tls_handshake(false);
                    tracing::debug!(%peer, "tls handshake timed out");
                }
            }
        }
        None => {
            serve_conn(
                stream,
                peer,
                runtime,
                conn,
                metrics,
                stop,
                None,
                None,
                options.name.clone(),
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_conn<I>(
    io: I,
    peer: SocketAddr,
    runtime: Arc<ArcSwap<Runtime>>,
    opts: ConnOptions,
    metrics: Arc<Metrics>,
    stop: &mut watch::Receiver<bool>,
    acme: Option<Arc<elira_acme::Acme>>,
    client_cert: Option<elira_tls::ClientIdentity>,
    listener: String,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    metrics.connection_started();

    let idle = Arc::new(tokio::sync::Notify::new());
    let idle_for_service = idle.clone();
    let scheme = if opts.secure { "https" } else { "http" };
    let body_timeout = opts.body_timeout;
    let keepalive_requests = opts.keepalive_requests;
    let served_for_service = Arc::new(AtomicU64::new(0));
    let metrics_for_service = metrics.clone();
    let acme_for_service = acme.clone();
    let client_cert = client_cert.map(Arc::new);
    let listener_for_service = listener;

    let service = service_fn(move |mut req: hyper::Request<Incoming>| {
        let runtime = runtime.clone();
        let served = served_for_service.clone();
        let idle = idle_for_service.clone();
        let metrics = metrics_for_service.clone();
        let acme = acme_for_service.clone();
        let client_cert = client_cert.clone();
        let listener = listener_for_service.clone();
        async move {
            // Reset the keep-alive watchdog: a request means the client is
            // still there, even if the response takes a while.
            idle.notify_one();

            if let Some(identity) = &client_cert {
                req.extensions_mut().insert(identity.as_ref().clone());
            }

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
            let mut response = if let Some(acme) = &acme {
                let token = path
                    .strip_prefix("/.well-known/acme-challenge/")
                    .map(|token| token.split('?').next().unwrap_or(token));
                match token.and_then(|token| acme.http01(token)) {
                    Some(body) => acme_response(hyper::StatusCode::OK, body),
                    None => current.proxy.handle(req, peer, scheme, &listener).await,
                }
            } else {
                current.proxy.handle(req, peer, scheme, &listener).await
            };
            let elapsed = started.elapsed();
            let status = response.status().as_u16();
            metrics.record_request(status, elapsed);
            metrics.request_bytes(request_bytes);
            let mut upstream = None;
            let mut route_label = None;
            let mut access_log = true;
            let mut access_log_sample = current.access_log_sample();
            if let Some(labels) = response.extensions().get::<elira_proxy::Labels>().cloned() {
                metrics.record_route(&labels.route, status, elapsed);
                if let Some(name) = &labels.upstream {
                    metrics.record_upstream(name, status, elapsed);
                }
                upstream = labels.upstream;
                route_label = Some(labels.route);
                access_log = labels.access_log;
                access_log_sample = labels.access_log_sample;
            }
            let (upstream_addr, upstream_status, upstream_time) = match response
                .extensions()
                .get::<elira_proxy::UpstreamInfo>()
                .cloned()
            {
                Some(info) => (Some(info.addr), info.status, Some(info.time)),
                None => (None, None, None),
            };
            let cache_result = match response
                .headers()
                .get("x-cache")
                .and_then(|v| v.to_str().ok())
            {
                Some("HIT") => Some(CacheResult::Hit),
                Some("STALE") => Some(CacheResult::Stale),
                Some("MISS") => Some(CacheResult::Miss),
                _ => None,
            };
            if let Some(result) = cache_result {
                match result {
                    CacheResult::Hit => metrics.cache_hit(),
                    CacheResult::Miss => metrics.cache_miss(),
                    CacheResult::Stale => metrics.cache_stale(),
                }
                if let Some(route) = &route_label {
                    metrics.record_route_cache(route, result);
                }
            }
            let bytes = response.body().size_hint().exact().unwrap_or(0);
            metrics.response_bytes(bytes);
            let write_log = access_log && elira_accesslog::sampled(&id, access_log_sample);
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
                upstream,
                upstream_addr,
                upstream_status,
                upstream_time,
            };

            if write_log {
                current.write_log(&entry);
            }

            if keepalive_requests > 0
                && matches!(version, http::Version::HTTP_10 | http::Version::HTTP_11)
                && served.fetch_add(1, Ordering::Relaxed) + 1 >= keepalive_requests as u64
            {
                response.headers_mut().insert(
                    http::header::CONNECTION,
                    hyper::header::HeaderValue::from_static("close"),
                );
            }

            Ok::<_, std::convert::Infallible>(response)
        }
    });

    if opts.h2 {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .enable_connect_protocol()
            .keep_alive_interval(
                (opts.http2.keep_alive_interval_secs > 0)
                    .then(|| Duration::from_secs(opts.http2.keep_alive_interval_secs)),
            )
            .keep_alive_timeout(Duration::from_secs(
                opts.http2.keep_alive_timeout_secs.max(1),
            ))
            .max_header_list_size(opts.max_buf_size as u32);
        if let Some(streams) = opts.http2.max_concurrent_streams {
            builder.max_concurrent_streams(streams);
        }
        if let Some(size) = opts.http2.initial_stream_window_size {
            builder.initial_stream_window_size(size);
        }
        if let Some(size) = opts.http2.initial_connection_window_size {
            builder.initial_connection_window_size(size);
        }
        if let Some(size) = opts.http2.max_frame_size {
            builder.max_frame_size(size);
        }
        let conn = builder.serve_connection(TokioIo::new(io), service);
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            result = conn.as_mut() => {
                if let Err(err) = result {
                    tracing::debug!(%peer, error = %err, "connection closed");
                }
            }
            _ = stop.changed() => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer, opts.drain_timeout).await;
            }
            _ = idle_watch(idle.clone(), opts.idle_timeout) => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer, opts.drain_timeout).await;
            }
        }
    } else {
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(opts.client_header_timeout)
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
                drain(conn.as_mut(), peer, opts.drain_timeout).await;
            }
            _ = idle_watch(idle.clone(), opts.idle_timeout) => {
                conn.as_mut().graceful_shutdown();
                drain(conn.as_mut(), peer, opts.drain_timeout).await;
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
#[derive(Debug, Clone)]
pub enum AdminCommand {
    Reload,
    Drain,
    Purge(String),
}

/// Aggregate metrics and status reported by worker processes.
pub fn spawn_metrics_aggregate(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    statuses: Arc<std::sync::Mutex<std::collections::HashMap<usize, String>>>,
    config_json: Arc<std::sync::Mutex<String>>,
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
            let config_json = config_json.clone();
            let auth = auth.clone();
            let control = control.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: hyper::Request<Incoming>| {
                    let metrics = metrics.clone();
                    let statuses = statuses.clone();
                    let config_json = config_json.clone();
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
                            (&hyper::Method::GET, "/config") => {
                                let body = config_json
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .clone();
                                json(hyper::StatusCode::OK, &body)
                            }
                            (&hyper::Method::POST, "/reload") => {
                                let _ = control.try_send(AdminCommand::Reload);
                                json(hyper::StatusCode::ACCEPTED, "{\"reload\":\"queued\"}")
                            }
                            (&hyper::Method::POST, "/drain") => {
                                let _ = control.try_send(AdminCommand::Drain);
                                json(hyper::StatusCode::ACCEPTED, "{\"drain\":\"started\"}")
                            }
                            (&hyper::Method::POST, "/cache/purge") => {
                                let prefix = query_prefix(req.uri().query()).unwrap_or_default();
                                let _ = control.try_send(AdminCommand::Purge(prefix));
                                json(hyper::StatusCode::ACCEPTED, "{\"purge\":\"queued\"}")
                            }
                            (&hyper::Method::GET, "/status") => {
                                let statuses = statuses
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                let mut entries: Vec<_> = statuses.iter().collect();
                                entries.sort_by_key(|(worker, _)| **worker);
                                let snapshots = entries
                                    .iter()
                                    .map(|(worker, status)| {
                                        format!("{{\"worker\":{worker},\"status\":{status}}}")
                                    })
                                    .collect::<Vec<_>>()
                                    .join(",");
                                let body = format!("{{\"workers\":[{snapshots}]}}");
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
                                    (&hyper::Method::GET, "/config") => {
                                        config_response(runtime.load().config())
                                    }
                                    (&hyper::Method::POST, "/reload") => {
                                        let _ = reload.send(rand_counter());
                                        json(hyper::StatusCode::ACCEPTED, "{\"reload\":\"queued\"}")
                                    }
                                    (&hyper::Method::POST, "/drain") => {
                                        let _ = stop_tx.send(true);
                                        json(hyper::StatusCode::ACCEPTED, "{\"drain\":\"started\"}")
                                    }
                                    (&hyper::Method::POST, "/cache/purge") => {
                                        let prefix =
                                            query_prefix(req.uri().query()).unwrap_or_default();
                                        let purged = runtime
                                            .load()
                                            .proxy()
                                            .purge_cache_prefix(&prefix);
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

fn query_prefix(query: Option<&str>) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == "prefix").then(|| value.to_owned())
    })
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

fn config_response(config: &Config) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    match serde_json::to_string_pretty(config) {
        Ok(body) => json(hyper::StatusCode::OK, &body),
        Err(err) => {
            tracing::error!(%err, "cannot serialize the effective config");
            json(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":\"config unavailable\"}",
            )
        }
    }
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
async fn drain<C>(conn: std::pin::Pin<&mut C>, peer: SocketAddr, limit: Duration)
where
    C: std::future::Future<Output = Result<(), hyper::Error>>,
{
    if tokio::time::timeout(limit, conn).await.is_err() {
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
    async fn unix_socket_mode_and_owner_are_applied() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "elira-unix-mode-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("elira.sock");
        let listener = bind_unix(&path).expect("bind");

        let owner = format!("{}:{}", unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        });
        configure_unix(&path, Some(0o600), Some(&owner)).expect("configure");

        let metadata = std::fs::metadata(&path).expect("metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
