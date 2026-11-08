//! Request forwarding.
//!
//! The rules that matter here are the boring ones: never trust forwarding
//! headers from the client, never forward hop-by-hop headers, and pick an
//! upstream before touching the body.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_compression::tokio::bufread::GzipEncoder;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::header::{
    HeaderName, HeaderValue, ACCEPT_ENCODING, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING,
    CONTENT_LENGTH, CONTENT_TYPE, HOST, SERVER, TRANSFER_ENCODING, UPGRADE, VARY,
};
use http::uri::Authority;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::BufReader;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_util::io::{ReaderStream, StreamReader};

use elira_config::{Balance, Compression, Config, Health};
use elira_limit::RateLimiter;

mod files;

use files::Files;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;

#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

struct Inner {
    router: Router,
    pools: Vec<Arc<Pool>>,
    client: Client<HttpConnector, Body>,
    tunnels: Arc<Semaphore>,
    connect: Option<Vec<Authority>>,
    compression: Compression,
    max_body_bytes: usize,
    limiter: Option<Arc<RateLimiter>>,
    trusted_proxies: Vec<ipnet::IpNet>,
    timeout: Duration,
}

enum Target {
    Proxy(Arc<Pool>),
    Files(Arc<Files>),
}

struct Router {
    by_host: HashMap<String, Arc<Target>>,
    default: Option<Arc<Target>>,
}

struct Pool {
    servers: Vec<Authority>,
    health: Vec<AtomicBool>,
    active: Vec<AtomicUsize>,
    next: AtomicUsize,
    balance: Balance,
    retries: u32,
}

struct ActiveGuard<'a> {
    active: &'a AtomicUsize,
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Pool {
    fn pick(&self) -> usize {
        let count = self.servers.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);

        match self.balance {
            Balance::RoundRobin => {
                for offset in 0..count {
                    let index = (start + offset) % count;
                    if self.health[index].load(Ordering::Relaxed) {
                        return index;
                    }
                }
                // Everything looks down. Send traffic anyway: a broken probe
                // should not turn into an outage, and the checker corrects it.
                start % count
            }
            Balance::LeastConn => {
                let mut best = None;
                let mut best_active = usize::MAX;

                for offset in 0..count {
                    let index = (start + offset) % count;
                    if !self.health[index].load(Ordering::Relaxed) {
                        continue;
                    }
                    let active = self.active[index].load(Ordering::Relaxed);
                    if active < best_active {
                        best = Some(index);
                        best_active = active;
                    }
                }

                best.unwrap_or(start % count)
            }
        }
    }

    fn enter(&self, index: usize) -> ActiveGuard<'_> {
        self.active[index].fetch_add(1, Ordering::Relaxed);
        ActiveGuard {
            active: &self.active[index],
        }
    }

    fn set_health(&self, index: usize, up: bool) {
        if self.health[index].swap(up, Ordering::Relaxed) != up {
            tracing::warn!(upstream = %self.servers[index], healthy = up, "upstream health changed");
        }
    }
}

impl Router {
    fn pick(&self, host: &str) -> Option<&Arc<Target>> {
        self.by_host.get(host).or(self.default.as_ref())
    }
}

impl Proxy {
    pub fn new(cfg: &Config) -> Result<Self, Error> {
        let mut pools: HashMap<String, Arc<Pool>> = HashMap::new();
        for up in &cfg.upstreams {
            let mut servers = Vec::with_capacity(up.servers.len());
            for addr in &up.servers {
                let authority = addr.parse::<Authority>().map_err(|_| Error::BadServer {
                    upstream: up.name.clone(),
                    addr: addr.clone(),
                })?;
                servers.push(authority);
            }
            let health = (0..servers.len()).map(|_| AtomicBool::new(true)).collect();
            let active = (0..servers.len()).map(|_| AtomicUsize::new(0)).collect();
            pools.insert(
                up.name.clone(),
                Arc::new(Pool {
                    servers,
                    health,
                    active,
                    next: AtomicUsize::new(0),
                    balance: up.balance,
                    retries: up.retries,
                }),
            );
        }
        let all_pools: Vec<Arc<Pool>> = pools.values().cloned().collect();

        let mut by_host = HashMap::new();
        let mut default = None;
        for route in &cfg.routes {
            let target = match (&route.upstream, &route.root) {
                (Some(upstream), _) => {
                    let pool =
                        pools
                            .get(upstream)
                            .cloned()
                            .ok_or_else(|| Error::UnknownUpstream {
                                upstream: upstream.clone(),
                            })?;
                    Arc::new(Target::Proxy(pool))
                }
                (None, Some(root)) => Arc::new(Target::Files(Arc::new(Files::new(
                    root.clone(),
                    route.index.clone(),
                    route.spa,
                )))),
                (None, None) => {
                    return Err(Error::MissingTarget {
                        host: route.host.clone(),
                    })
                }
            };

            let host = route.host.trim().to_ascii_lowercase();
            if host == "*" {
                default = Some(target);
            } else {
                by_host.insert(host, target);
            }
        }

        let connect =
            if cfg.connect.enabled {
                let mut allowed = Vec::with_capacity(cfg.connect.allow.len());
                for target in &cfg.connect.allow {
                    allowed.push(target.parse::<Authority>().map_err(|_| {
                        Error::BadConnectTarget {
                            target: target.clone(),
                        }
                    })?);
                }
                Some(allowed)
            } else {
                None
            };

        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(5)));
        connector.set_nodelay(true);
        connector.enforce_http(true);

        let mut trusted_proxies = Vec::with_capacity(cfg.limits.trusted_proxies.len());
        for cidr in &cfg.limits.trusted_proxies {
            if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
                trusted_proxies.push(net);
            }
        }

        let limiter = if cfg.limits.requests_per_second > 0 {
            Some(Arc::new(RateLimiter::new(
                cfg.limits.requests_per_second,
                cfg.limits.burst.max(cfg.limits.requests_per_second),
            )))
        } else {
            None
        };

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Some(Duration::from_secs(30)))
            .build(connector);

        Ok(Self {
            inner: Arc::new(Inner {
                router: Router { by_host, default },
                pools: all_pools,
                client,
                tunnels: Arc::new(Semaphore::new(cfg.limits.max_connections)),
                connect,
                compression: cfg.compression.clone(),
                max_body_bytes: cfg.limits.max_body_bytes,
                limiter,
                trusted_proxies,
                timeout: Duration::from_secs(cfg.limits.upstream_timeout_secs),
            }),
        })
    }

    /// How many upstream servers are up, and how many are down.
    pub fn upstream_counts(&self) -> (usize, usize) {
        let mut up = 0;
        let mut down = 0;

        for pool in &self.inner.pools {
            for healthy in &pool.health {
                if healthy.load(Ordering::Relaxed) {
                    up += 1;
                } else {
                    down += 1;
                }
            }
        }

        (up, down)
    }

    /// Probe every upstream once and update its health flag.
    pub async fn check_health(&self, cfg: &Health) {
        if !cfg.enabled {
            return;
        }
        let timeout = Duration::from_secs(cfg.timeout_secs);
        for pool in &self.inner.pools {
            for (index, server) in pool.servers.iter().enumerate() {
                let up = probe(server, &cfg.path, timeout).await;
                pool.set_health(index, up);
            }
        }
    }

    pub async fn handle(
        &self,
        req: Request<Body>,
        peer: SocketAddr,
        scheme: &'static str,
    ) -> Response<Body> {
        if let Some(limiter) = &self.inner.limiter {
            if !limiter.check(peer.ip(), Instant::now()) {
                let mut response = text(StatusCode::TOO_MANY_REQUESTS, "too many requests");
                response
                    .headers_mut()
                    .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
                return response;
            }
        }

        self.forward(req, peer, scheme)
            .await
            .unwrap_or_else(|err| err)
    }

    /// Only a trusted peer may extend the chain; everyone else starts a new
    /// one, otherwise a client could pick its own address in the logs.
    fn forwarded_for(&self, req: &Request<Body>, peer: SocketAddr) -> String {
        if self
            .inner
            .trusted_proxies
            .iter()
            .any(|net| net.contains(&peer.ip()))
        {
            if let Some(existing) = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
            {
                return format!("{existing}, {}", peer.ip());
            }
        }

        peer.ip().to_string()
    }

    /// CONNECT is only useful when the target is already trusted; anything
    /// else turns the proxy into an open relay.
    async fn connect(&self, mut req: Request<Body>) -> Result<Response<Body>, Response<Body>> {
        let Some(allowed) = &self.inner.connect else {
            return Err(text(StatusCode::METHOD_NOT_ALLOWED, "CONNECT is disabled"));
        };

        let target = req
            .uri()
            .authority()
            .map(|value| value.as_str().to_owned())
            // hyper may hand authority-form CONNECT targets via the path.
            .or_else(|| {
                req.uri()
                    .path()
                    .parse::<Authority>()
                    .ok()
                    .map(|value| value.as_str().to_owned())
            })
            .ok_or_else(|| text(StatusCode::BAD_REQUEST, "CONNECT needs host:port"))?;

        if !allowed.iter().any(|entry| entry.as_str() == target) {
            return Err(text(StatusCode::FORBIDDEN, "CONNECT target is not allowed"));
        }

        let permit = match self.inner.tunnels.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Err(text(StatusCode::SERVICE_UNAVAILABLE, "too many tunnels")),
        };

        let mut stream =
            match tokio::time::timeout(self.inner.timeout, TcpStream::connect(target.as_str()))
                .await
            {
                Ok(Ok(stream)) => stream,
                _ => return Err(text(StatusCode::BAD_GATEWAY, "cannot reach the target")),
            };

        let client_upgrade = hyper::upgrade::on(&mut req);

        tokio::spawn(async move {
            let _permit = permit;
            match client_upgrade.await {
                Ok(client) => {
                    let mut client = TokioIo::new(client);
                    if let Err(err) = tokio::io::copy_bidirectional(&mut client, &mut stream).await
                    {
                        tracing::debug!(error = %err, "CONNECT tunnel closed");
                    }
                }
                Err(err) => tracing::debug!(error = %err, "CONNECT upgrade failed"),
            }
        });

        let body = Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed();
        Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }

    async fn forward(
        &self,
        mut req: Request<Body>,
        peer: SocketAddr,
        scheme: &'static str,
    ) -> Result<Response<Body>, Response<Body>> {
        if req.method() == Method::CONNECT {
            return self.connect(req).await;
        }
        // hyper decodes only the chunked layer. `gzip, chunked` would reach
        // the backend still gzipped and without the header saying so.
        if !transfer_encoding_is_plain_chunked(req.headers()) {
            return Err(text(
                StatusCode::NOT_IMPLEMENTED,
                "only chunked transfer encoding is supported",
            ));
        }

        if self.inner.max_body_bytes > 0 {
            if let Some(length) = req
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
            {
                if length > self.inner.max_body_bytes as u64 {
                    return Err(text(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request body too large",
                    ));
                }
            }
        }

        let accepts_gzip = accepts_gzip(req.headers());
        let is_head = req.method() == Method::HEAD;
        let forwarded_for = self.forwarded_for(&req, peer);

        let requested_upgrade = wants_upgrade(req.headers());
        let client_upgrade = requested_upgrade
            .as_ref()
            .map(|_| hyper::upgrade::on(&mut req));

        // No upgrade protocol carries a body. Refusing one keeps the raw
        // upstream write from sending a Content-Length with zero bytes.
        if requested_upgrade.is_some() {
            let has_body = req
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim() != "0")
                .unwrap_or(false)
                || req.headers().contains_key(TRANSFER_ENCODING);
            if has_body {
                return Err(text(
                    StatusCode::BAD_REQUEST,
                    "upgrade requests cannot carry a body",
                ));
            }
        }

        let host = req
            .headers()
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
            // HTTP/2 carries the host in :authority, not in a Host header.
            .or_else(|| req.uri().authority().map(|a| a.as_str().to_owned()))
            .ok_or_else(|| text(StatusCode::BAD_REQUEST, "missing Host header"))?;

        // Route on the canonical host and forward the same string. Letting
        // `admin:80@example.com` route as example.com while the backend sees
        // the raw value is a vhost-confusion bug waiting to happen.
        let (key, forward_host) = canonical_host(&host)
            .ok_or_else(|| text(StatusCode::BAD_REQUEST, "malformed Host header"))?;

        let target = self
            .inner
            .router
            .pick(&key)
            .ok_or_else(|| text(StatusCode::NOT_FOUND, "no route"))?;

        let pool = match target.as_ref() {
            Target::Proxy(pool) => pool,
            Target::Files(files) => return Ok(files.serve(&req, peer).await),
        };
        let path = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());

        // Retries are only safe when there is nothing to replay: an
        // idempotent method with no declared body.
        let can_retry = pool.retries > 0
            && !req.headers().contains_key(CONTENT_LENGTH)
            && !req.headers().contains_key(TRANSFER_ENCODING)
            && (req.method() == Method::GET
                || req.method() == Method::HEAD
                || req.method() == Method::OPTIONS);

        let (parts, body) = req.into_parts();
        let mut template = HeaderMap::new();
        let drop = connection_tokens(&parts.headers);
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name) || drop.contains(name) || is_client_forwarding(name) {
                continue;
            }
            template.append(name, value.clone());
        }

        // Everything below is set by us. A client that sent its own copies
        // had them dropped above.
        template.insert(HOST, header(&forward_host));
        template.insert("x-forwarded-for", header(&forwarded_for));
        template.insert("x-forwarded-proto", HeaderValue::from_static(scheme));
        template.insert("x-forwarded-host", header(&forward_host));
        template.insert("via", HeaderValue::from_static("1.1 elira"));

        // Upgrade is hop-by-hop, but dropping it would break websockets.
        if let Some(upgrade) = &requested_upgrade {
            template.insert(CONNECTION, HeaderValue::from_static("upgrade"));
            template.insert(UPGRADE, upgrade.clone());
        }

        let mut body = Some(body);

        if let Some(upgrade) = requested_upgrade.clone() {
            let client = client_upgrade.expect("created together with requested_upgrade");
            let index = pool.pick();
            let server = pool.servers[index].clone();
            let _active = pool.enter(index);
            let uri = upstream_uri(&server, &path)
                .ok_or_else(|| text(StatusCode::BAD_GATEWAY, "bad upstream address"))?;

            let mut upstream = Request::builder()
                .method(parts.method.clone())
                .uri(uri)
                .body(body.take().unwrap_or_else(empty))
                .map_err(|_| text(StatusCode::BAD_GATEWAY, "bad request"))?;
            *upstream.headers_mut() = template;

            return self
                .forward_upgrade(upstream, client, upgrade, server)
                .await;
        }

        let attempts = if can_retry {
            pool.retries as usize + 1
        } else {
            1
        };
        let mut response = None;

        for attempt in 0..attempts {
            let index = pool.pick();
            let server = pool.servers[index].clone();
            let _active = pool.enter(index);

            let uri = upstream_uri(&server, &path)
                .ok_or_else(|| text(StatusCode::BAD_GATEWAY, "bad upstream address"))?;
            let payload = if attempt == 0 {
                body.take().unwrap_or_else(empty)
            } else {
                empty()
            };

            let mut upstream = Request::builder()
                .method(parts.method.clone())
                .uri(uri)
                .body(payload)
                .map_err(|_| text(StatusCode::BAD_GATEWAY, "bad request"))?;
            *upstream.headers_mut() = template.clone();

            match tokio::time::timeout(self.inner.timeout, self.inner.client.request(upstream))
                .await
            {
                Ok(Ok(answer)) => {
                    response = Some(answer);
                    break;
                }
                Ok(Err(err)) => {
                    tracing::warn!(upstream = %server, error = %err, "upstream request failed");
                    if attempt + 1 == attempts {
                        return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                    }
                }
                Err(_) => {
                    tracing::warn!(upstream = %server, "upstream timed out");
                    if attempt + 1 == attempts {
                        return Err(text(StatusCode::GATEWAY_TIMEOUT, "gateway timeout"));
                    }
                }
            }
        }

        let response = response.ok_or_else(|| text(StatusCode::BAD_GATEWAY, "bad gateway"))?;

        // Same rule as the request side: hyper only unwraps `chunked`, so
        // anything else would reach the client still transfer-coded.
        if !transfer_encoding_is_plain_chunked(response.headers()) {
            return Err(text(
                StatusCode::BAD_GATEWAY,
                "unsupported transfer encoding from upstream",
            ));
        }

        let (parts, body) = response.into_parts();

        let upstream_len = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        let content_type = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let compress = self.inner.compression.enabled
            && parts.status == StatusCode::OK
            && !is_head
            && accepts_gzip
            && !parts.headers.contains_key(CONTENT_ENCODING)
            && compressible(content_type)
            && upstream_len
                .map(|length| length >= self.inner.compression.min_bytes)
                .unwrap_or(true);

        let drop = connection_tokens(&parts.headers);
        let mut builder = Response::builder().status(parts.status);
        {
            let headers = builder
                .headers_mut()
                .ok_or_else(|| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))?;
            for (name, value) in parts.headers.iter() {
                // Let hyper derive the downstream framing from the body.
                // Copying Content-Length while the body is chunked lets a
                // broken upstream truncate the response silently.
                if is_hop_by_hop(name)
                    || drop.contains(name)
                    || name == http::header::CONTENT_LENGTH
                {
                    continue;
                }
                headers.append(name, value.clone());
            }
            headers.insert(SERVER, HeaderValue::from_static("elira"));

            if compress {
                headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                headers.append(VARY, HeaderValue::from_static("accept-encoding"));
            }

            // A 101 without these two headers is a 101 the client cannot
            // act on. They are hop-by-hop, so they were stripped above.
            if parts.status == StatusCode::SWITCHING_PROTOCOLS {
                if let Some(upgrade) = &requested_upgrade {
                    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
                    headers.insert(UPGRADE, upgrade.clone());
                }
            }
        }

        let body = BodyExt::map_err(body, |err| -> BoxError { Box::new(err) }).boxed();
        let body = if compress { gzip(body) } else { body };

        builder
            .body(body)
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }

    /// Upgrades cannot go through the connection pool: hyper has to hand the
    /// socket over instead of returning it. Open a raw connection and tunnel.
    async fn forward_upgrade(
        &self,
        upstream: Request<Body>,
        client_upgrade: hyper::upgrade::OnUpgrade,
        upgrade: HeaderValue,
        server: Authority,
    ) -> Result<Response<Body>, Response<Body>> {
        // Tunnels outlive the connection task that the accept loop tracks,
        // so they need their own bound.
        let permit = match self.inner.tunnels.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Err(text(StatusCode::SERVICE_UNAVAILABLE, "too many tunnels")),
        };

        let host = server.host().trim_start_matches('[').trim_end_matches(']');
        let port = server.port_u16().unwrap_or(80);

        let mut stream = match tokio::time::timeout(
            self.inner.timeout,
            TcpStream::connect((host, port)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            _ => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
        };

        let head = serialize_head(&upstream);
        match tokio::time::timeout(self.inner.timeout, stream.write_all(head.as_bytes())).await {
            Ok(Ok(())) => {}
            _ => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
        }

        let (status, mut headers, upstream_upgrade, leftover) =
            read_head(&mut stream, self.inner.timeout).await?;

        if status != StatusCode::SWITCHING_PROTOCOLS {
            // The upstream refused the upgrade. Pass the answer through with
            // an empty body; upgrade attempts are small and rare.
            headers.insert(SERVER, HeaderValue::from_static("elira"));
            let body = Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed();
            return Response::builder()
                .status(status)
                .body(body)
                .map(|mut response| {
                    *response.headers_mut() = headers;
                    response
                })
                .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"));
        }

        // The upstream decides which protocol it accepted.
        let upgrade = upstream_upgrade.unwrap_or(upgrade);
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, upgrade);
        headers.insert(SERVER, HeaderValue::from_static("elira"));

        tokio::spawn(async move {
            let _permit = permit;
            match client_upgrade.await {
                Ok(client) => {
                    let mut client = TokioIo::new(client);
                    let mut upstream = stream;
                    // Bytes the upstream sent right after the 101 would
                    // otherwise be dropped by copy_bidirectional.
                    if !leftover.is_empty() && client.write_all(&leftover).await.is_err() {
                        return;
                    }
                    if let Err(err) =
                        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                    {
                        tracing::debug!(error = %err, "tunnel closed");
                    }
                }
                Err(err) => tracing::debug!(error = %err, "client upgrade failed"),
            }
        });

        let body = Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed();
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .body(body)
            .map(|mut response| {
                *response.headers_mut() = headers;
                response
            })
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }
}

fn serialize_head(req: &Request<Body>) -> String {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method(), path);
    for (name, value) in req.headers() {
        if let Ok(value) = value.to_str() {
            out.push_str(name.as_str());
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
    }
    out.push_str("\r\n");
    out
}

async fn read_head(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<(StatusCode, HeaderMap, Option<HeaderValue>, Vec<u8>), Response<Body>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let read = match tokio::time::timeout(timeout, stream.read(&mut chunk)).await {
            Ok(Ok(read)) => read,
            _ => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
        };
        if read == 0 {
            return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
        }
        buf.extend_from_slice(&chunk[..read]);

        while let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let rest = buf[end + 4..].to_vec();
            let mut lines = head.split("\r\n");
            let status_line = lines.next().unwrap_or_default();
            let code = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or(502);
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY);

            // 100 Continue and 103 Early Hints are not the answer.
            if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
                buf = rest;
                continue;
            }

            let mut raw = HeaderMap::new();
            for line in lines {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) else {
                    continue;
                };
                let Ok(value) = HeaderValue::from_str(value.trim()) else {
                    continue;
                };
                raw.append(name, value);
            }

            let upgrade = raw.get(UPGRADE).cloned();
            let tokens = connection_tokens(&raw);

            let mut headers = HeaderMap::new();
            for (name, value) in raw.iter() {
                if is_hop_by_hop(name) || tokens.contains(name) || name == CONTENT_LENGTH {
                    continue;
                }
                headers.append(name, value.clone());
            }

            return Ok((status, headers, upgrade, rest));
        }

        if buf.len() > 64 * 1024 {
            return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
        }
    }
}

/// One health probe: a plain HTTP/1.1 GET with `Connection: close`.
/// Anything 2xx or 3xx counts as up.
async fn probe(server: &Authority, path: &str, timeout: Duration) -> bool {
    let host = server.host().trim_start_matches('[').trim_end_matches(']');
    let port = server.port_u16().unwrap_or(80);

    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };

    let request = format!("GET {path} HTTP/1.1\r\nHost: {server}\r\nConnection: close\r\n\r\n");
    match tokio::time::timeout(timeout, stream.write_all(request.as_bytes())).await {
        Ok(Ok(())) => {}
        _ => return false,
    }

    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 64];
        let read = match tokio::time::timeout(timeout, stream.read(&mut chunk)).await {
            Ok(Ok(read)) if read > 0 => read,
            _ => return false,
        };
        buf.extend_from_slice(&chunk[..read]);

        if let Some(end) = buf.windows(2).position(|window| window == b"\r\n") {
            let line = String::from_utf8_lossy(&buf[..end]);
            return matches!(
                line.split_whitespace().nth(1),
                Some(code)
                    if code.len() == 3
                        && (code.starts_with('2') || code.starts_with('3'))
            );
        }

        if buf.len() > 1024 {
            return false;
        }
    }
}

fn wants_upgrade(headers: &HeaderMap) -> Option<HeaderValue> {
    let upgrade = headers.get(UPGRADE)?.clone();
    let connection = headers.get(CONNECTION)?.to_str().ok()?;
    connection
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        .then_some(upgrade)
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(ACCEPT_ENCODING).and_then(|v| v.to_str().ok()) else {
        return false;
    };

    value.split(',').any(|part| {
        let mut pieces = part.trim().split(';');
        let name = pieces.next().unwrap_or_default().trim();
        let quality = pieces
            .next()
            .and_then(|piece| piece.trim().strip_prefix("q="))
            .and_then(|value| value.parse::<f32>().ok())
            .unwrap_or(1.0);

        name.eq_ignore_ascii_case("gzip") && quality > 0.0
    })
}

fn compressible(content_type: &str) -> bool {
    let kind = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    kind.starts_with("text/")
        || matches!(
            kind.as_str(),
            "application/json"
                | "application/javascript"
                | "application/xml"
                | "application/rss+xml"
                | "application/atom+xml"
                | "image/svg+xml"
        )
}

fn gzip(body: Body) -> Body {
    let stream = TryStreamExt::map_err(body.into_data_stream(), std::io::Error::other);
    let reader = StreamReader::new(stream);
    let encoder = GzipEncoder::new(BufReader::new(reader));
    let stream = ReaderStream::new(encoder).map_ok(hyper::body::Frame::data);

    BodyExt::map_err(StreamBody::new(stream), |err| -> BoxError { Box::new(err) }).boxed()
}

fn upstream_uri(server: &Authority, path: &str) -> Option<Uri> {
    Uri::builder()
        .scheme("http")
        .authority(server.as_str())
        .path_and_query(path)
        .build()
        .ok()
}

fn empty() -> Body {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

fn canonical_host(raw: &str) -> Option<(String, String)> {
    if raw.contains('@') {
        return None;
    }
    let (host, port) = split_host_port(raw)?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let forward = match port {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };
    Some((host, forward))
}

/// Split an authority without trusting `Authority` to reject bad ports.
/// `example.com:abc` parses there, and the backend would read it its own way.
fn split_host_port(raw: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            value => Some(value.strip_prefix(':')?.parse::<u16>().ok()?),
        };
        return Some((host, port));
    }

    match raw.rsplit_once(':') {
        None => Some((raw, None)),
        Some((host, port)) => {
            // A bare IPv6 literal has more than one colon. Demand brackets.
            if host.contains(':') || port.is_empty() {
                return None;
            }
            Some((host, Some(port.parse::<u16>().ok()?)))
        }
    }
}

fn transfer_encoding_is_plain_chunked(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(TRANSFER_ENCODING).iter();
    let Some(value) = values.next() else {
        return true;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(text) = value.to_str() else {
        return false;
    };
    let mut tokens = text.split(',').map(str::trim);
    matches!((tokens.next(), tokens.next()), (Some(token), None) if token.eq_ignore_ascii_case("chunked"))
}

fn connection_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_client_forwarding(name: &HeaderName) -> bool {
    // Underscore aliases reach the same backend functions as their dashed
    // form, so normalize before comparing.
    let normalized = name.as_str().replace('_', "-");
    let name = normalized.as_str();

    name == "forwarded"
        || name == "x-real-ip"
        || name.starts_with("x-forwarded-")
        || matches!(
            name,
            "x-original-url" | "x-rewrite-url" | "front-end-https" | "x-url-scheme"
        )
}

fn header(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).expect("peer address and Host are valid header values")
}

pub(crate) fn text(status: StatusCode, msg: &'static str) -> Response<Body> {
    let body = Full::new(Bytes::from_static(msg.as_bytes()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(body)
        .expect("static response parts are valid")
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("upstream \"{upstream}\": \"{addr}\" is not a valid address")]
    BadServer { upstream: String, addr: String },

    #[error("route points to unknown upstream \"{upstream}\"")]
    UnknownUpstream { upstream: String },

    #[error("connect target \"{target}\" is not host:port")]
    BadConnectTarget { target: String },

    #[error("route for \"{host}\" has neither an upstream nor a root")]
    MissingTarget { host: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_host_ignores_port_and_case() {
        assert_eq!(
            canonical_host("Example.COM:8080").map(|h| h.0).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            canonical_host("example.com.").map(|h| h.0).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn canonical_host_rejects_userinfo_and_bad_port() {
        assert!(canonical_host("admin:80@example.com").is_none());
        assert!(canonical_host("example.com:abc").is_none());
        assert!(canonical_host("::1").is_none());
    }

    #[test]
    fn canonical_host_keeps_bracketed_ipv6() {
        assert_eq!(
            canonical_host("[::1]:8080").map(|h| h.1),
            Some("[::1]:8080".to_owned())
        );
    }

    #[test]
    fn hop_by_hop_headers_are_recognised() {
        assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
        assert!(is_hop_by_hop(&HeaderName::from_static("connection")));
        assert!(is_hop_by_hop(&HeaderName::from_static("proxy-connection")));
        assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
    }

    #[test]
    fn forwarding_headers_are_recognised() {
        assert!(is_client_forwarding(&HeaderName::from_static(
            "x-forwarded-for"
        )));
        assert!(is_client_forwarding(&HeaderName::from_static(
            "x-forwarded-ssl"
        )));
        assert!(is_client_forwarding(&HeaderName::from_static("x-real-ip")));
        assert!(is_client_forwarding(&HeaderName::from_static(
            "x_forwarded_for"
        )));
        assert!(!is_client_forwarding(&HeaderName::from_static("host")));
    }

    #[test]
    fn only_plain_chunked_is_accepted() {
        let mut headers = HeaderMap::new();
        assert!(transfer_encoding_is_plain_chunked(&headers));

        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert!(transfer_encoding_is_plain_chunked(&headers));

        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));
        assert!(!transfer_encoding_is_plain_chunked(&headers));
    }

    #[test]
    fn least_conn_prefers_the_idle_server() {
        let pool = Pool {
            servers: vec![
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap(),
            ],
            health: vec![AtomicBool::new(true), AtomicBool::new(true)],
            active: vec![AtomicUsize::new(0), AtomicUsize::new(5)],
            next: AtomicUsize::new(0),
            balance: Balance::LeastConn,
            retries: 0,
        };

        assert_eq!(pool.pick(), 0);
        pool.active[0].store(10, Ordering::Relaxed);
        assert_eq!(pool.pick(), 1);
    }

    #[test]
    fn upgrade_needs_both_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        assert!(wants_upgrade(&headers).is_none());

        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
        assert_eq!(
            wants_upgrade(&headers),
            Some(HeaderValue::from_static("websocket"))
        );
    }
}
