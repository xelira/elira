use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
pub use elira_upstream::TlsOptions;
use http::{HeaderValue, Request, Response, Uri};
use http_body::Body as _;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub type Body = BoxBody<Bytes, BoxError>;

pub fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed()
}

pub fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into())
        .map_err(|never| -> BoxError { match never {} })
        .boxed()
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections: usize,

    pub connect_timeout: Duration,

    pub bind: Option<std::net::IpAddr>,

    pub resolver: elira_upstream::Resolver,

    pub tls: TlsOptions,

    pub max_concurrent_streams: Option<usize>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 4,
            connect_timeout: Duration::from_secs(10),
            bind: None,
            resolver: elira_upstream::Resolver::default(),
            tls: TlsOptions::default(),
            max_concurrent_streams: None,
        }
    }
}

impl PoolConfig {
    pub fn new(max_connections: usize, connect_timeout: Duration, tls: TlsOptions) -> Self {
        Self {
            max_connections,
            connect_timeout,
            tls,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub connections: usize,

    pub active_streams: usize,

    pub total_connections: u64,

    pub queued_streams: usize,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("URI {uri} has no scheme")]
    MissingScheme { uri: String },

    #[error("URI scheme {scheme:?} is not supported; use http or https")]
    UnsupportedScheme { scheme: String },

    #[error("URI {uri} has no authority")]
    MissingAuthority { uri: String },

    #[error("invalid TLS server name {name:?}: {message}")]
    InvalidServerName { name: String, message: String },

    #[error("build TLS client configuration: {message}")]
    TlsConfig { message: String },

    #[error("connect to {origin} timed out after {timeout:?}")]
    ConnectTimeout { origin: String, timeout: Duration },

    #[error("connect to {origin}: {source}")]
    Connect {
        origin: String,
        #[source]
        source: io::Error,
    },

    #[error("TLS handshake with {origin}: {source}")]
    Tls {
        origin: String,
        #[source]
        source: io::Error,
    },

    #[error("{origin} did not negotiate h2 through ALPN (got {protocol:?})")]
    NoH2 {
        origin: String,
        protocol: Option<Vec<u8>>,
    },

    #[error("HTTP/2 handshake with {origin}: {source}")]
    Handshake {
        origin: String,
        #[source]
        source: hyper::Error,
    },

    #[error("request to {origin}: {source}")]
    Request {
        origin: String,
        #[source]
        source: hyper::Error,
    },

    #[error("connection pool for {origin} was closed")]
    PoolClosed { origin: String },
}

#[derive(Clone)]
pub struct Pool {
    inner: Arc<Inner>,
}

impl Pool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                origins: Mutex::new(HashMap::new()),
                counters: Arc::new(Counters::default()),
                tls: OnceLock::new(),
            }),
        }
    }

    pub fn config(&self) -> &PoolConfig {
        &self.inner.config
    }

    pub async fn request(&self, uri: Uri, request: Request<Body>) -> Result<Response<Body>, Error> {
        let origin = Origin::from_uri(&uri)?;
        let (mut parts, body) = request.into_parts();
        parts.uri = resolve_request_uri(&uri, &parts.uri);
        set_host_header(&mut parts, &origin);

        let empty_body = body.is_end_stream();
        let retryable = matches!(
            parts.method,
            http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE
        );
        let mut body = Some(body);
        let mut retried = false;

        loop {
            let stream = self.inner.connection(&origin).await?;
            let payload = body.take().unwrap_or_else(empty);
            let request = Request::from_parts(parts.clone(), payload);

            match send(stream.connection(), request).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    stream.discard();
                    drop(stream);

                    if empty_body && retryable && !retried {
                        retried = true;
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }

    pub fn stats(&self) -> Stats {
        let pools: Vec<Arc<OriginPool>> = {
            let origins = self.inner.origins.lock().unwrap_or_else(|e| e.into_inner());
            origins.values().cloned().collect()
        };

        let mut stats = Stats {
            active_streams: self.inner.counters.active.load(Ordering::Acquire),
            total_connections: self.inner.counters.total.load(Ordering::Relaxed),
            ..Stats::default()
        };

        for pool in pools {
            pool.add_stats(&mut stats);
        }
        stats
    }
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("config", &self.inner.config)
            .field("stats", &self.stats())
            .finish()
    }
}

struct Inner {
    config: PoolConfig,
    origins: Mutex<HashMap<Origin, Arc<OriginPool>>>,
    counters: Arc<Counters>,
    tls: OnceLock<Result<Arc<ClientConfig>, String>>,
}

impl Inner {
    fn origin_pool(&self, origin: &Origin) -> Arc<OriginPool> {
        let mut origins = self.origins.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pool) = origins.get(origin) {
            return Arc::clone(pool);
        }

        let pool = Arc::new(OriginPool::new(&self.config));
        origins.insert(origin.clone(), Arc::clone(&pool));
        pool
    }

    async fn connection(&self, origin: &Origin) -> Result<ActiveStream, Error> {
        let pool = self.origin_pool(origin);

        if let Some(stream) = pool.acquire() {
            return Ok(stream);
        }

        let _creating = pool.connecting.lock().await;
        if let Some(stream) = pool.acquire() {
            return Ok(stream);
        }

        let permit = match pool.slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => pool
                .slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::PoolClosed {
                    origin: origin.to_string(),
                })?,
        };

        let id = pool.next_id.fetch_add(1, Ordering::Relaxed);
        match self.connect(origin, id, permit).await {
            Ok(connection) => {
                let stream = pool.insert(connection);
                Ok(stream)
            }
            Err(error) => {
                if let Some(stream) = pool.acquire_any() {
                    return Ok(stream);
                }
                Err(error)
            }
        }
    }

    async fn connect(
        &self,
        origin: &Origin,
        id: u64,
        permit: OwnedSemaphorePermit,
    ) -> Result<Arc<Connection>, Error> {
        let timeout = self.config.connect_timeout;
        let origin_name = origin.to_string();

        let established = tokio::time::timeout(timeout, async {
            let tcp = elira_upstream::tcp_connect(
                origin.host.as_str(),
                origin.port,
                self.config.bind,
                Some(&self.config.resolver),
            )
            .await
            .map_err(|source| Error::Connect {
                origin: origin_name.clone(),
                source,
            })?;
            let _ = tcp.set_nodelay(true);

            let io: BoxedIo = match origin.scheme {
                Scheme::Http => Box::new(tcp),
                Scheme::Https => {
                    let config = self.tls_config()?;
                    let server_name = self.server_name(origin)?;
                    let connector = TlsConnector::from(config);
                    let tls = connector
                        .connect(server_name, tcp)
                        .await
                        .map_err(|source| Error::Tls {
                            origin: origin_name.clone(),
                            source,
                        })?;

                    let protocol = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                    if protocol.as_deref() != Some(b"h2") {
                        return Err(Error::NoH2 {
                            origin: origin_name.clone(),
                            protocol,
                        });
                    }
                    Box::new(tls)
                }
            };

            let (sender, driver) = http2::Builder::new(TokioExecutor::new())
                .initial_max_send_streams(self.config.max_concurrent_streams)
                .handshake(TokioIo::new(io))
                .await
                .map_err(|source| Error::Handshake {
                    origin: origin_name.clone(),
                    source,
                })?;

            Ok::<_, Error>((sender, driver))
        })
        .await;

        let (sender, driver) = match established {
            Err(_) => {
                return Err(Error::ConnectTimeout {
                    origin: origin_name,
                    timeout,
                });
            }
            Ok(Err(error)) => return Err(error),
            Ok(Ok(established)) => established,
        };

        tokio::spawn(async move {
            if let Err(error) = driver.await {
                tracing::debug!(error = %error, "upstream HTTP/2 connection closed");
            }
        });

        self.counters.total.fetch_add(1, Ordering::Relaxed);

        Ok(Arc::new(Connection {
            id,
            origin: origin.clone(),
            sender,
            active: AtomicUsize::new(0),
            counters: Arc::clone(&self.counters),
            _slot: permit,
        }))
    }

    fn tls_config(&self) -> Result<Arc<ClientConfig>, Error> {
        let config = self.tls.get_or_init(|| {
            let mut config = elira_upstream::client_config(&self.config.tls)
                .map_err(|error| format!("{error:#}"))?;
            config.alpn_protocols = vec![b"h2".to_vec()];
            Ok(Arc::new(config))
        });

        match config {
            Ok(config) => Ok(Arc::clone(config)),
            Err(message) => Err(Error::TlsConfig {
                message: message.clone(),
            }),
        }
    }

    fn server_name(&self, origin: &Origin) -> Result<ServerName<'static>, Error> {
        let name = self.config.tls.sni.as_deref().unwrap_or(&origin.host);
        ServerName::try_from(name.to_owned()).map_err(|error| Error::InvalidServerName {
            name: name.to_owned(),
            message: error.to_string(),
        })
    }
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

type BoxedIo = Box<dyn AsyncReadWrite>;

#[derive(Default)]
struct Counters {
    active: AtomicUsize,
    total: AtomicU64,
}

struct OriginPool {
    max_connections: usize,
    stream_limit: Option<usize>,
    connections: Mutex<Vec<Arc<Connection>>>,
    connecting: tokio::sync::Mutex<()>,
    slots: Arc<Semaphore>,
    next_id: AtomicU64,
}

impl OriginPool {
    fn new(config: &PoolConfig) -> Self {
        let max_connections = config.max_connections.max(1);
        Self {
            max_connections,
            stream_limit: config.max_concurrent_streams.filter(|limit| *limit > 0),
            connections: Mutex::new(Vec::new()),
            connecting: tokio::sync::Mutex::new(()),
            slots: Arc::new(Semaphore::new(max_connections)),
            next_id: AtomicU64::new(0),
        }
    }

    fn acquire(self: &Arc<Self>) -> Option<ActiveStream> {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());

        connections.retain(|connection| !connection.is_closed());
        if connections.is_empty() {
            return None;
        }

        let all_busy = connections
            .iter()
            .all(|connection| connection.active.load(Ordering::Acquire) > 0);
        if connections.len() < self.max_connections && all_busy {
            return None;
        }

        let index = connections
            .iter()
            .enumerate()
            .min_by_key(|(_, connection)| connection.active.load(Ordering::Acquire))
            .map(|(index, _)| index)?;
        let connection = Arc::clone(&connections[index]);
        drop(connections);

        Some(self.reserve(connection))
    }

    fn acquire_any(self: &Arc<Self>) -> Option<ActiveStream> {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        connections.retain(|connection| !connection.is_closed());
        let index = connections
            .iter()
            .enumerate()
            .min_by_key(|(_, connection)| connection.active.load(Ordering::Acquire))
            .map(|(index, _)| index)?;
        let connection = Arc::clone(&connections[index]);
        drop(connections);

        Some(self.reserve(connection))
    }

    fn insert(self: &Arc<Self>, connection: Arc<Connection>) -> ActiveStream {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        connections.retain(|connection| !connection.is_closed());
        connections.push(Arc::clone(&connection));
        drop(connections);

        self.reserve(connection)
    }

    fn remove(&self, id: u64) {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        connections.retain(|connection| connection.id != id);
    }

    fn reserve(self: &Arc<Self>, connection: Arc<Connection>) -> ActiveStream {
        connection.active.fetch_add(1, Ordering::AcqRel);
        connection.counters.active.fetch_add(1, Ordering::AcqRel);

        ActiveStream {
            connection,
            pool: Arc::clone(self),
        }
    }

    fn add_stats(&self, stats: &mut Stats) {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        connections.retain(|connection| !connection.is_closed());

        stats.connections += connections.len();
        if let Some(limit) = self.stream_limit {
            stats.queued_streams += connections
                .iter()
                .map(|connection| {
                    connection
                        .active
                        .load(Ordering::Acquire)
                        .saturating_sub(limit)
                })
                .sum::<usize>();
        }
    }
}

struct Connection {
    id: u64,
    origin: Origin,
    sender: http2::SendRequest<Body>,
    active: AtomicUsize,
    counters: Arc<Counters>,

    _slot: OwnedSemaphorePermit,
}

impl Connection {
    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

struct ActiveStream {
    connection: Arc<Connection>,
    pool: Arc<OriginPool>,
}

impl ActiveStream {
    fn connection(&self) -> &Connection {
        &self.connection
    }

    fn discard(&self) {
        self.pool.remove(self.connection.id);
    }
}

impl Drop for ActiveStream {
    fn drop(&mut self) {
        self.connection.active.fetch_sub(1, Ordering::AcqRel);
        self.connection
            .counters
            .active
            .fetch_sub(1, Ordering::AcqRel);
    }
}

async fn send(connection: &Connection, request: Request<Body>) -> Result<Response<Body>, Error> {
    let mut sender = connection.sender.clone();
    let response = sender
        .send_request(request)
        .await
        .map_err(|source| Error::Request {
            origin: connection.origin.to_string(),
            source,
        })?;

    let (parts, body) = response.into_parts();
    let body = body
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed();
    Ok(Response::from_parts(parts, body))
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Origin {
    scheme: Scheme,
    host: String,
    port: u16,
}

impl Origin {
    fn from_uri(uri: &Uri) -> Result<Self, Error> {
        let scheme = match uri.scheme_str() {
            Some("http") => Scheme::Http,
            Some("https") => Scheme::Https,
            Some(other) => {
                return Err(Error::UnsupportedScheme {
                    scheme: other.to_owned(),
                });
            }
            None => {
                return Err(Error::MissingScheme {
                    uri: uri.to_string(),
                });
            }
        };

        let authority = uri.authority().ok_or_else(|| Error::MissingAuthority {
            uri: uri.to_string(),
        })?;

        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() {
            return Err(Error::MissingAuthority {
                uri: uri.to_string(),
            });
        }

        Ok(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port: authority.port_u16().unwrap_or(scheme.default_port()),
        })
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };

        if self.port == self.scheme.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme.as_str(), self.authority())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

fn resolve_request_uri(target: &Uri, request: &Uri) -> Uri {
    let Some(path) = request.path_and_query() else {
        return target.clone();
    };
    if path.path() == "/" && path.query().is_none() {
        return target.clone();
    }

    let Some(authority) = target.authority() else {
        return target.clone();
    };
    let scheme = target.scheme_str().unwrap_or("http");

    format!("{scheme}://{authority}{path}")
        .parse()
        .unwrap_or_else(|_| target.clone())
}

fn set_host_header(parts: &mut http::request::Parts, origin: &Origin) {
    if parts.headers.contains_key(http::header::HOST) {
        return;
    }

    let authority = origin.authority();
    if let Ok(value) = HeaderValue::from_str(&authority) {
        parts.headers.insert(http::header::HOST, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(value: &str) -> Origin {
        Origin::from_uri(&value.parse().expect("valid URI")).expect("valid origin")
    }

    #[test]
    fn origin_uses_default_ports() {
        assert_eq!(origin("http://example.com/x").port, 80);
        assert_eq!(origin("https://example.com/x").port, 443);
        assert_eq!(origin("http://example.com:8080/x").port, 8080);
    }

    #[test]
    fn origin_normalizes_and_displays_authority() {
        let value = origin("HTTPS://Example.COM:8443/x");
        assert_eq!(value.host, "example.com");
        assert_eq!(value.to_string(), "https://example.com:8443");
    }

    #[test]
    fn origin_formats_ipv6_authority() {
        let value = origin("http://[::1]:8080/");
        assert_eq!(value.to_string(), "http://[::1]:8080");
    }

    #[test]
    fn relative_uri_is_rejected() {
        let error = Origin::from_uri(&"/only/a/path".parse().unwrap()).expect_err("no origin");
        assert!(matches!(error, Error::MissingScheme { .. }), "{error:?}");
    }

    #[test]
    fn unsupported_scheme_is_rejected() {
        let error = Origin::from_uri(&"ftp://example.com/".parse().unwrap()).expect_err("scheme");
        assert!(
            matches!(error, Error::UnsupportedScheme { ref scheme } if scheme == "ftp"),
            "{error:?}"
        );
    }

    #[test]
    fn request_path_overrides_target_root() {
        let target: Uri = "http://example.com/".parse().unwrap();
        let request: Uri = "/echo?q=1".parse().unwrap();
        assert_eq!(
            resolve_request_uri(&target, &request).to_string(),
            "http://example.com/echo?q=1"
        );
    }

    #[test]
    fn target_path_is_kept_for_a_root_request() {
        let target: Uri = "http://example.com/upstream".parse().unwrap();
        let request: Uri = "/".parse().unwrap();
        assert_eq!(
            resolve_request_uri(&target, &request).to_string(),
            "http://example.com/upstream"
        );
    }

    #[test]
    fn pool_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Pool>();
    }

    #[test]
    fn config_constructor_keeps_optional_settings_default() {
        let config = PoolConfig::new(2, Duration::from_secs(1), TlsOptions::default());
        assert_eq!(config.max_connections, 2);
        assert_eq!(config.connect_timeout, Duration::from_secs(1));
        assert_eq!(config.max_concurrent_streams, None);
    }
}
