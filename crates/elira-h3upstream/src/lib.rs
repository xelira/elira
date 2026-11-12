use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
pub use elira_upstream::TlsOptions;
use h3::client::{Connection as H3Connection, RequestStream, SendRequest};
use h3_quinn::{BidiStream, OpenStreams, RecvStream, SendStream};
use http::request::Parts as RequestParts;
use http::{HeaderValue, Request, Response, Uri};
use http_body::{Body as _, Frame};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use quinn::Endpoint;
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub type Body = BoxBody<Bytes, BoxError>;

const RESPONSE_BODY_BUFFER: usize = 4;

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

    pub tls: TlsOptions,

    pub bind: Option<IpAddr>,

    pub resolver: elira_upstream::Resolver,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 4,
            connect_timeout: Duration::from_secs(10),
            tls: TlsOptions::default(),
            bind: None,
            resolver: elira_upstream::Resolver::default(),
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

    pub active_requests: usize,

    pub total_connections: u64,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("URI {uri} has no scheme")]
    MissingScheme { uri: String },

    #[error("URI scheme {scheme:?} is not supported; HTTP/3 requires https")]
    UnsupportedScheme { scheme: String },

    #[error("URI {uri} has no authority")]
    MissingAuthority { uri: String },

    #[error("invalid TLS server name {name:?}: {message}")]
    InvalidServerName { name: String, message: String },

    #[error("build TLS client configuration: {message}")]
    TlsConfig { message: String },

    #[error("resolve {origin}: {source}")]
    Resolve {
        origin: String,
        #[source]
        source: io::Error,
    },

    #[error("{origin} resolved to no usable address")]
    NoAddresses { origin: String },

    #[error("create the QUIC endpoint for {origin}: {source}")]
    Endpoint {
        origin: String,
        #[source]
        source: io::Error,
    },

    #[error("connect to {origin} timed out after {timeout:?}")]
    ConnectTimeout { origin: String, timeout: Duration },

    #[error("start QUIC connection to {origin}: {source}")]
    Connect {
        origin: String,
        #[source]
        source: quinn::ConnectError,
    },

    #[error("QUIC handshake with {origin}: {source}")]
    Connection {
        origin: String,
        #[source]
        source: quinn::ConnectionError,
    },

    #[error("HTTP/3 handshake with {origin}: {source}")]
    Handshake {
        origin: String,
        #[source]
        source: h3::error::ConnectionError,
    },

    #[error("send request to {origin}: {source}")]
    Request {
        origin: String,
        #[source]
        source: h3::error::StreamError,
    },

    #[error("receive response headers from {origin}: {source}")]
    Response {
        origin: String,
        #[source]
        source: h3::error::StreamError,
    },

    #[error("request body to {origin}: {source}")]
    RequestBody {
        origin: String,
        #[source]
        source: BoxError,
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
                endpoints: Mutex::new(HashMap::new()),
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
        set_host_header(&mut parts);

        let empty_body = body.is_end_stream();
        let retryable = matches!(
            parts.method,
            http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE
        );
        let mut body = Some(body);
        let mut retried = false;

        loop {
            let active = self.inner.reserve(&origin).await?;
            let payload = body.take().unwrap_or_else(empty);
            let request = Request::from_parts(parts.clone(), payload);

            match send(active.connection(), request).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    active.discard();
                    drop(active);

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
            active_requests: self.inner.counters.active.load(Ordering::Acquire),
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

    tls: OnceLock<Result<Arc<quinn::ClientConfig>, String>>,

    endpoints: Mutex<HashMap<Family, Arc<Endpoint>>>,
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

    async fn reserve(&self, origin: &Origin) -> Result<ActiveRequest, Error> {
        let pool = self.origin_pool(origin);

        if let Some(active) = pool.acquire() {
            return Ok(active);
        }

        let _creating = pool.connecting.lock().await;
        if let Some(active) = pool.acquire() {
            return Ok(active);
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
            Ok(connection) => Ok(pool.insert(connection)),
            Err(error) => {
                if let Some(active) = pool.acquire_any() {
                    return Ok(active);
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
        let server_name = self.server_name(origin)?;
        let deadline = Instant::now() + timeout;

        let addresses = match tokio::time::timeout(timeout, self.resolve(origin)).await {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(Error::ConnectTimeout {
                    origin: origin_name,
                    timeout,
                });
            }
        };
        let mut last_error = None;

        for address in addresses {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, self.connect_to(origin, address, &server_name))
                .await
            {
                Ok(Ok((driver, sender, quinn))) => {
                    let closed = spawn_driver(driver, origin_name.clone());

                    self.counters.total.fetch_add(1, Ordering::Relaxed);

                    return Ok(Arc::new(Connection {
                        id,
                        origin: origin.clone(),
                        sender: Mutex::new(sender),
                        quinn,
                        closed,
                        active: AtomicUsize::new(0),
                        counters: Arc::clone(&self.counters),
                        _slot: permit,
                    }));
                }
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    return Err(Error::ConnectTimeout {
                        origin: origin_name,
                        timeout,
                    });
                }
            }
        }

        match last_error {
            Some(error) => Err(error),
            None => Err(Error::ConnectTimeout {
                origin: origin_name,
                timeout,
            }),
        }
    }

    async fn resolve(&self, origin: &Origin) -> Result<Vec<SocketAddr>, Error> {
        let addresses = self
            .config
            .resolver
            .lookup(origin.host.as_str(), origin.port)
            .await
            .map_err(|source| Error::Resolve {
                origin: origin.to_string(),
                source,
            })?;

        if addresses.is_empty() {
            return Err(Error::NoAddresses {
                origin: origin.to_string(),
            });
        }
        Ok(addresses)
    }

    async fn connect_to(
        &self,
        origin: &Origin,
        address: SocketAddr,
        server_name: &str,
    ) -> Result<
        (
            H3Connection<h3_quinn::Connection, Bytes>,
            SendRequest<OpenStreams, Bytes>,
            quinn::Connection,
        ),
        Error,
    > {
        let origin_name = origin.to_string();
        let endpoint = self.endpoint(address.ip(), origin)?;

        let connecting =
            endpoint
                .connect(address, server_name)
                .map_err(|source| Error::Connect {
                    origin: origin_name.clone(),
                    source,
                })?;

        let quinn = connecting.await.map_err(|source| Error::Connection {
            origin: origin_name.clone(),
            source,
        })?;

        let (driver, sender) = h3::client::new(h3_quinn::Connection::new(quinn.clone()))
            .await
            .map_err(|source| Error::Handshake {
                origin: origin_name,
                source,
            })?;

        Ok((driver, sender, quinn))
    }

    fn endpoint(&self, ip: IpAddr, origin: &Origin) -> Result<Arc<Endpoint>, Error> {
        let family = Family::of(ip);
        let mut endpoints = self.endpoints.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(endpoint) = endpoints.get(&family) {
            return Ok(Arc::clone(endpoint));
        }

        let config = self.quic_config()?;
        let bind: SocketAddr = match (self.config.bind, family) {
            (Some(ip), _) => SocketAddr::new(ip, 0),
            (None, Family::V4) => SocketAddr::from(([0, 0, 0, 0], 0)),
            (None, Family::V6) => SocketAddr::from(([0; 8], 0)),
        };

        let mut endpoint = Endpoint::client(bind).map_err(|source| Error::Endpoint {
            origin: origin.to_string(),
            source,
        })?;
        endpoint.set_default_client_config((*config).clone());

        let endpoint = Arc::new(endpoint);
        endpoints.insert(family, Arc::clone(&endpoint));
        Ok(endpoint)
    }

    fn quic_config(&self) -> Result<Arc<quinn::ClientConfig>, Error> {
        let config = self.tls.get_or_init(|| {
            let mut config = elira_upstream::client_config(&self.config.tls)
                .map_err(|error| format!("{error:#}"))?;
            config.alpn_protocols = vec![b"h3".to_vec()];

            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config)
                .map_err(|error| error.to_string())?;
            Ok(Arc::new(quinn::ClientConfig::new(Arc::new(crypto))))
        });

        match config {
            Ok(config) => Ok(Arc::clone(config)),
            Err(message) => Err(Error::TlsConfig {
                message: message.clone(),
            }),
        }
    }

    fn server_name(&self, origin: &Origin) -> Result<String, Error> {
        let name = self.config.tls.sni.as_deref().unwrap_or(&origin.host);
        ServerName::try_from(name.to_owned()).map_err(|error| Error::InvalidServerName {
            name: name.to_owned(),
            message: error.to_string(),
        })?;
        Ok(name.to_owned())
    }
}

fn spawn_driver(
    mut driver: H3Connection<h3_quinn::Connection, Bytes>,
    origin: String,
) -> Arc<AtomicBool> {
    let closed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&closed);

    tokio::spawn(async move {
        let error = driver.wait_idle().await;
        flag.store(true, Ordering::Release);
        tracing::debug!(origin = %origin, error = %error, "upstream HTTP/3 connection closed");
    });

    closed
}

#[derive(Default)]
struct Counters {
    active: AtomicUsize,
    total: AtomicU64,
}

struct OriginPool {
    max_connections: usize,
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
            connections: Mutex::new(Vec::new()),
            connecting: tokio::sync::Mutex::new(()),
            slots: Arc::new(Semaphore::new(max_connections)),
            next_id: AtomicU64::new(0),
        }
    }

    fn acquire(self: &Arc<Self>) -> Option<ActiveRequest> {
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

    fn acquire_any(self: &Arc<Self>) -> Option<ActiveRequest> {
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

    fn insert(self: &Arc<Self>, connection: Arc<Connection>) -> ActiveRequest {
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

    fn reserve(self: &Arc<Self>, connection: Arc<Connection>) -> ActiveRequest {
        connection.active.fetch_add(1, Ordering::AcqRel);
        connection.counters.active.fetch_add(1, Ordering::AcqRel);

        ActiveRequest {
            connection,
            pool: Arc::clone(self),
        }
    }

    fn add_stats(&self, stats: &mut Stats) {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        connections.retain(|connection| !connection.is_closed());
        stats.connections += connections.len();
    }
}

struct Connection {
    id: u64,
    origin: Origin,

    sender: Mutex<SendRequest<OpenStreams, Bytes>>,
    quinn: quinn::Connection,
    closed: Arc<AtomicBool>,
    active: AtomicUsize,
    counters: Arc<Counters>,

    _slot: OwnedSemaphorePermit,
}

impl Connection {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.quinn.close_reason().is_some()
    }
}

struct ActiveRequest {
    connection: Arc<Connection>,
    pool: Arc<OriginPool>,
}

impl ActiveRequest {
    fn connection(&self) -> &Connection {
        &self.connection
    }

    fn discard(&self) {
        self.pool.remove(self.connection.id);
    }
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.connection.active.fetch_sub(1, Ordering::AcqRel);
        self.connection
            .counters
            .active
            .fetch_sub(1, Ordering::AcqRel);
    }
}

async fn send(connection: &Connection, request: Request<Body>) -> Result<Response<Body>, Error> {
    let origin = connection.origin.to_string();
    let mut sender = {
        let sender = connection.sender.lock().unwrap_or_else(|e| e.into_inner());
        sender.clone()
    };

    let (parts, body) = request.into_parts();
    let head = Request::from_parts(parts, ());
    let stream: RequestStream<BidiStream<Bytes>, Bytes> =
        sender
            .send_request(head)
            .await
            .map_err(|source| Error::Request {
                origin: origin.clone(),
                source,
            })?;

    let (send, mut recv) = stream.split();
    let mut body_task = tokio::spawn(pump_request_body(body, send));

    let mut body_joined = false;
    let response = tokio::select! {
        result = recv.recv_response() => {
            result.map_err(|source| Error::Response {
                origin: origin.clone(),
                source,
            })?
        }
        result = &mut body_task => {
            body_joined = true;
            match result {
                Ok(Ok(())) => recv.recv_response().await.map_err(|source| Error::Response {
                    origin: origin.clone(),
                    source,
                })?,
                Ok(Err(source)) => return Err(Error::RequestBody { origin, source }),
                Err(error) => {
                    return Err(Error::RequestBody {
                        origin,
                        source: Box::new(error),
                    });
                }
            }
        }
    };

    let body_task = if body_joined {
        None
    } else if body_task.is_finished() {
        match body_task.await {
            Ok(Ok(())) => None,
            Ok(Err(source)) => return Err(Error::RequestBody { origin, source }),
            Err(error) => {
                return Err(Error::RequestBody {
                    origin,
                    source: Box::new(error),
                });
            }
        }
    } else {
        Some(body_task)
    };

    let (parts, ()) = response.into_parts();
    let (tx, rx) = mpsc::channel(RESPONSE_BODY_BUFFER);
    tokio::spawn(drive_response(recv, body_task, tx));

    let stream = SharedStream(Mutex::new(ReceiverStream::new(rx)));
    let body = StreamBody::new(stream).boxed();

    Ok(Response::from_parts(parts, body))
}

async fn pump_request_body(
    mut body: Body,
    mut send: RequestStream<SendStream<Bytes>, Bytes>,
) -> Result<(), BoxError> {
    while let Some(frame) = Pin::new(&mut body).frame().await {
        match frame {
            Ok(frame) => match frame.into_data() {
                Ok(data) => {
                    send.send_data(data)
                        .await
                        .map_err(|error| Box::new(error) as BoxError)?;
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        send.send_trailers(trailers)
                            .await
                            .map_err(|error| Box::new(error) as BoxError)?;
                        return Ok(());
                    }
                }
            },
            Err(error) => return Err(error),
        }
    }

    send.finish()
        .await
        .map_err(|error| Box::new(error) as BoxError)
}

async fn drive_response(
    mut recv: RequestStream<RecvStream, Bytes>,
    mut body_task: Option<JoinHandle<Result<(), BoxError>>>,
    tx: mpsc::Sender<Result<Frame<Bytes>, BoxError>>,
) {
    let mut body_done = body_task.is_none();

    loop {
        let body_result = async {
            match body_task.as_mut() {
                Some(task) => Some(task.await),
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            biased;

            result = body_result, if !body_done => {
                body_done = true;
                body_task = None;
                let error = match result {
                    Some(Ok(Ok(()))) | None => None,
                    Some(Ok(Err(error))) => Some(error),
                    Some(Err(error)) => Some(Box::new(error) as BoxError),
                };
                if let Some(error) = error {
                    let _ = tx.send(Err(error)).await;
                    return;
                }
            }
            frame = recv.recv_data() => {
                match frame {
                    Ok(Some(mut buf)) => {
                        let bytes = buf.copy_to_bytes(buf.remaining());
                        if tx.send(Ok(Frame::data(bytes))).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        match recv.recv_trailers().await {
                            Ok(Some(trailers)) => {
                                let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                let _ = tx.send(Err(Box::new(error))).await;
                            }
                        }
                        break;
                    }
                    Err(error) => {
                        let _ = tx.send(Err(Box::new(error))).await;
                        break;
                    }
                }
            }
        }
    }

    if let Some(task) = body_task.take() {
        task.abort();
    }
}

struct SharedStream<S>(Mutex<S>);

impl<S: futures_util::Stream + Unpin> futures_util::Stream for SharedStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let stream = this
            .0
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Pin::new(stream).poll_next(cx)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Origin {
    host: String,
    port: u16,
}

impl Origin {
    fn from_uri(uri: &Uri) -> Result<Self, Error> {
        match uri.scheme_str() {
            Some("https") => {}
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
        }

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
            host: host.to_ascii_lowercase(),
            port: authority.port_u16().unwrap_or(443),
        })
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };

        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}", self.authority())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn of(ip: IpAddr) -> Self {
        if ip.is_ipv4() {
            Self::V4
        } else {
            Self::V6
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
    let scheme = target.scheme_str().unwrap_or("https");

    format!("{scheme}://{authority}{path}")
        .parse()
        .unwrap_or_else(|_| target.clone())
}

fn set_host_header(parts: &mut RequestParts) {
    if parts.headers.contains_key(http::header::HOST) {
        return;
    }

    let Some(authority) = parts.uri.authority() else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
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
    fn origin_uses_default_and_explicit_ports() {
        assert_eq!(origin("https://example.com/x").port, 443);
        assert_eq!(origin("https://example.com:8443/x").port, 8443);
    }

    #[test]
    fn origin_normalizes_and_displays_authority() {
        let value = origin("HTTPS://Example.COM:8443/x");
        assert_eq!(value.host, "example.com");
        assert_eq!(value.to_string(), "https://example.com:8443");
    }

    #[test]
    fn origin_formats_ipv6_authority() {
        let value = origin("https://[::1]:8443/");
        assert_eq!(value.to_string(), "https://[::1]:8443");
        assert_eq!(value.host, "::1");
    }

    #[test]
    fn relative_uri_is_rejected() {
        let error = Origin::from_uri(&"/only/a/path".parse().unwrap()).expect_err("no origin");
        assert!(matches!(error, Error::MissingScheme { .. }), "{error:?}");
    }

    #[test]
    fn clear_text_uri_is_rejected() {
        let error = Origin::from_uri(&"http://example.com/".parse().unwrap())
            .expect_err("HTTP/3 needs TLS");
        assert!(
            matches!(error, Error::UnsupportedScheme { ref scheme } if scheme == "http"),
            "{error:?}"
        );
    }

    #[test]
    fn other_schemes_are_rejected() {
        let error = Origin::from_uri(&"ftp://example.com/".parse().unwrap()).expect_err("scheme");
        assert!(
            matches!(error, Error::UnsupportedScheme { ref scheme } if scheme == "ftp"),
            "{error:?}"
        );
    }

    #[test]
    fn request_path_overrides_target_root() {
        let target: Uri = "https://example.com/".parse().unwrap();
        let request: Uri = "/echo?q=1".parse().unwrap();
        assert_eq!(
            resolve_request_uri(&target, &request).to_string(),
            "https://example.com/echo?q=1"
        );
    }

    #[test]
    fn target_path_is_kept_for_a_root_request() {
        let target: Uri = "https://example.com/upstream".parse().unwrap();
        let request: Uri = "/".parse().unwrap();
        assert_eq!(
            resolve_request_uri(&target, &request).to_string(),
            "https://example.com/upstream"
        );
    }

    #[test]
    fn host_header_matches_the_resolved_authority() {
        let mut request = Request::builder()
            .uri("https://Example.COM:8443/x")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        set_host_header(&mut request);
        assert_eq!(request.headers["host"], "Example.COM:8443");
    }

    #[test]
    fn pool_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Pool>();
        assert_send_sync::<Stats>();
    }

    #[test]
    fn config_constructor_keeps_settings() {
        let config = PoolConfig::new(2, Duration::from_secs(1), TlsOptions::default());
        assert_eq!(config.max_connections, 2);
        assert_eq!(config.connect_timeout, Duration::from_secs(1));
    }

    #[test]
    fn family_is_selected_from_the_address() {
        assert_eq!(Family::of("127.0.0.1".parse().unwrap()), Family::V4);
        assert_eq!(Family::of("::1".parse().unwrap()), Family::V6);
    }
}
