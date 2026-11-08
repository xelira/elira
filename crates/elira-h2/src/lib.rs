//! A small HTTP/2 upstream client with its own connection pool.
//!
//! The pool deliberately does not go through `hyper-util`'s legacy `Client`:
//! that client seals its `Connect` trait and hides the per-origin connection
//! state, which makes connection accounting and clear-text prior-knowledge
//! intent hard to express. Instead, this crate owns the sockets, the TLS
//! handshakes, the `hyper::client::conn::http2` drivers and the selection
//! between them.
//!
//! Two transports are supported:
//!
//! * `http://` speaks HTTP/2 with prior knowledge (h2c). There is no HTTP/1.1
//!   upgrade dance.
//! * `https://` uses the trust decisions in [`elira_upstream::TlsOptions`] and
//!   requires the server to select `h2` through ALPN.
//!
//! Connections are multiplexed. A [`Pool`] keeps up to
//! [`PoolConfig::max_connections`] connections per origin and picks the least
//! busy one. When all existing connections have work and the cap has not been
//! reached, a new connection is opened; otherwise HTTP/2 multiplexing shares
//! the existing streams.
//!
//! Requests carry a [`Body`] that is passed straight to hyper. Nothing is
//! collected or replayed. Retrying after a broken pooled connection is only
//! possible for bodies that report end-of-stream (an empty body): a body that
//! has already been handed to a connection cannot be sent twice.

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
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;

/// Error type of request and response bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Request and response body used by the pool.
pub type Body = BoxBody<Bytes, BoxError>;

/// Build an empty body.
pub fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed()
}

/// Build a body from an in-memory buffer.
///
/// This is a convenience for callers that already have the complete payload.
/// The pool itself never buffers: pass any [`Body`] to [`Pool::request`].
pub fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into())
        .map_err(|never| -> BoxError { match never {} })
        .boxed()
}

/// Connection pool tuning.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of live connections per origin. Zero is treated as one.
    pub max_connections: usize,
    /// Deadline for DNS, TCP connect, TLS and the HTTP/2 preface together.
    pub connect_timeout: Duration,
    /// Trust settings for `https://` origins.
    ///
    /// [`TlsOptions::http2`] is ignored: this pool always offers `h2` and
    /// rejects an origin that does not negotiate it.
    pub tls: TlsOptions,
    /// Optional client-side stream limit used for the queued-stream metric and
    /// for the initial HTTP/2 send-stream window.
    ///
    /// Hyper always queues streams internally when the peer's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` is reached. The peer can lower the
    /// limit after the handshake, so [`Stats::queued_streams`] is an estimate
    /// derived from this value; it is zero when this option is `None`.
    pub max_concurrent_streams: Option<usize>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 4,
            connect_timeout: Duration::from_secs(10),
            tls: TlsOptions::default(),
            max_concurrent_streams: None,
        }
    }
}

impl PoolConfig {
    /// Build a configuration with the three settings almost every caller
    /// needs. `max_concurrent_streams` is left at its default (`None`).
    pub fn new(max_connections: usize, connect_timeout: Duration, tls: TlsOptions) -> Self {
        Self {
            max_connections,
            connect_timeout,
            tls,
            ..Self::default()
        }
    }
}

/// A point-in-time view of the pool.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Live connections across every origin.
    pub connections: usize,
    /// Requests that have been handed to a connection and not yet received
    /// response headers (including streams queued inside hyper).
    pub active_streams: usize,
    /// Successful HTTP/2 handshakes since the pool was created.
    pub total_connections: u64,
    /// Estimated number of streams waiting for a concurrency slot. See
    /// [`PoolConfig::max_concurrent_streams`].
    pub queued_streams: usize,
}

/// Failures raised before response headers are available.
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

/// An HTTP/2 connection pool.
///
/// The pool is cheap to clone: all clones share the same connections and
/// counters. It is `Send + Sync` and intended to sit behind an `Arc` (or be
/// cloned) in a proxy.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<Inner>,
}

impl Pool {
    /// Create an empty pool.
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

    /// The configuration this pool was built with.
    pub fn config(&self) -> &PoolConfig {
        &self.inner.config
    }

    /// Send one request to the origin named by `uri`.
    ///
    /// `uri` selects the origin (scheme, host and port) and supplies the
    /// request URI when the request itself only has a root path. A non-root
    /// path or a query on `request` wins over the target URI's path.
    ///
    /// # Retry policy
    ///
    /// If a pooled connection turns out to be closed, or hyper reports an
    /// error before response headers, the connection is discarded. The request
    /// is retried once only when its body reports end-of-stream, because such
    /// a body can be recreated safely; the retry uses another healthy pooled
    /// connection or opens a fresh one. Non-empty bodies are never replayed;
    /// their error is returned to the caller.
    pub async fn request(&self, uri: Uri, request: Request<Body>) -> Result<Response<Body>, Error> {
        let origin = Origin::from_uri(&uri)?;
        let (mut parts, body) = request.into_parts();
        parts.uri = resolve_request_uri(&uri, &parts.uri);
        set_host_header(&mut parts, &origin);

        let empty_body = body.is_end_stream();
        let mut body = Some(body);
        let mut retried = false;

        loop {
            let stream = self.inner.connection(&origin).await?;
            let payload = body.take().unwrap_or_else(empty);
            let request = Request::from_parts(parts.clone(), payload);

            match send(stream.connection(), request).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    // An error before the response headers means this
                    // connection cannot be trusted for the next request.
                    stream.discard();
                    drop(stream);

                    if empty_body && !retried {
                        retried = true;
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }

    /// Snapshot the pool counters and the live connections.
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

        // The normal path holds no lock: a quick mutex only protects the
        // vector while the least-active connection is reserved.
        if let Some(stream) = pool.acquire() {
            return Ok(stream);
        }

        // Creating a connection is serialized per origin. This avoids a
        // stampede of handshakes and, more importantly, prevents two tasks
        // from racing past the `max_connections` check.
        let _creating = pool.connecting.lock().await;
        if let Some(stream) = pool.acquire() {
            return Ok(stream);
        }

        let permit = match pool.slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // A closed connection that is still referenced by an
                // in-flight request can hold the last permit. Wait for that
                // request to finish and release it.
                pool.slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::PoolClosed {
                        origin: origin.to_string(),
                    })?
            }
        };

        let id = pool.next_id.fetch_add(1, Ordering::Relaxed);
        match self.connect(origin, id, permit).await {
            Ok(connection) => {
                let stream = pool.insert(connection);
                Ok(stream)
            }
            Err(error) => {
                // A failed new connection must not take a healthy, busy
                // connection out of service.
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
            let tcp = TcpStream::connect((origin.host.as_str(), origin.port))
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

        // The handshake completed, so this connection counts even if the
        // server closes it immediately afterwards.
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

/// Both plain TCP and TLS streams have to be usable by the same handshake
/// call, so they meet behind one object-safe trait.
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

    /// Reserve the least-active connection, or report that the caller should
    /// open another one.
    fn acquire(self: &Arc<Self>) -> Option<ActiveStream> {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());

        // Closed connections are useless for new requests. Dropping them here
        // also releases the semaphore permit once in-flight requests finish.
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

    /// Select a connection even if every stream slot is busy. Used as a
    /// fallback when opening a new connection fails.
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
    /// Held until the last reference to this connection goes away.
    _slot: OwnedSemaphorePermit,
}

impl Connection {
    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

/// A reserved stream slot. Dropping it makes the connection look idle again.
struct ActiveStream {
    connection: Arc<Connection>,
    pool: Arc<OriginPool>,
}

impl ActiveStream {
    fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Remove the underlying connection from the pool. The request that owned
    /// the reservation is already finished or failed.
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
    // `SendRequest::send_request` only needs `&mut self` to enqueue the
    // request. Cloning the handle gives each request its own sender, so no
    // mutex is held while waiting for the response.
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
        // `Authority::host` keeps IPv6 brackets; the stored host is bare so
        // the `(host, port)` tuple used for `TcpStream::connect` is valid.
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

    /// Value for the `Host` header and the h2 `:authority` pseudo-header.
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

/// Keep a non-root path or a query from the request while taking the scheme
/// and authority from the target URI.
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
