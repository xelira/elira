//! Request forwarding.
//!
//! The rules that matter here are the boring ones: never trust forwarding
//! headers from the client, never forward hop-by-hop headers, and pick an
//! upstream before touching the body.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::header::{
    HeaderName, HeaderValue, ACCEPT_ENCODING, ALT_SVC, AUTHORIZATION, CACHE_CONTROL, CONNECTION,
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, SERVER, SET_COOKIE,
    TRANSFER_ENCODING, UPGRADE, VARY, WWW_AUTHENTICATE,
};
use http::uri::Authority;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::BufReader;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::Sleep;
use tokio_util::io::{ReaderStream, StreamReader};

use elira_auth::{BasicAuth, IpAcl};
use elira_cache::Cache;
use elira_config::{Balance, Compression, Config, Health};
use elira_limit::RateLimiter;
use elira_upstream::{https_connector, TlsOptions};

pub mod files;

use files::Files;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// What the response belongs to, attached as a response extension so the
/// listener can feed per-route and per-upstream metrics without the proxy
/// holding a metrics registry.
#[derive(Clone, Debug)]
pub struct Labels {
    pub route: String,
    pub upstream: Option<String>,
}
pub type Body = BoxBody<Bytes, BoxError>;

#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

struct Inner {
    router: Router,
    pools: Vec<Arc<Pool>>,
    tunnels: Arc<Semaphore>,
    connect: Option<Vec<Authority>>,
    compression: Compression,
    server_header: bool,
    alt_svc: Option<HeaderValue>,
    max_body_bytes: usize,
    cache: Option<Arc<Cache>>,
    cache_max_item: usize,
    limiter: Option<Arc<RateLimiter>>,
    trusted_proxies: Vec<ipnet::IpNet>,
    timeout: Duration,
    body_timeout: Option<Duration>,
    tunnel_idle: Option<Duration>,
    buffer_bytes: usize,
    refreshing: Arc<Mutex<HashSet<String>>>,
}

enum Target {
    Proxy(Arc<Pool>),
    Files(Arc<Files>),
    Redirect {
        status: StatusCode,
        location: HeaderValue,
    },
}

struct RouteEntry {
    label: String,
    prefix: String,
    target: Target,
    strip_prefix: bool,
    add_headers: Vec<(HeaderName, HeaderValue)>,
    remove_headers: Vec<HeaderName>,
    auth: Option<Arc<BasicAuth>>,
    acl: Option<Arc<IpAcl>>,
    timeout: Option<Duration>,
    limiter: Option<Arc<RateLimiter>>,
    body_limit: Option<usize>,
    error_pages: Vec<(StatusCode, String, Arc<Files>)>,
}

struct Router {
    exact: HashMap<String, Vec<RouteEntry>>,
    wildcard: Vec<(String, Vec<RouteEntry>)>,
    default: Vec<RouteEntry>,
}

impl Router {
    fn pick(&self, host: &str, path: &str) -> Option<&RouteEntry> {
        let mut lists: Vec<&Vec<RouteEntry>> = Vec::with_capacity(3);

        if let Some(list) = self.exact.get(host) {
            lists.push(list);
        }
        if let Some((_, list)) = self
            .wildcard
            .iter()
            .find(|(suffix, _)| host.ends_with(suffix.as_str()))
        {
            lists.push(list);
        }
        lists.push(&self.default);

        for list in lists {
            if let Some(entry) = list.iter().find(|entry| path_matches(&entry.prefix, path)) {
                return Some(entry);
            }
        }

        None
    }
}

fn path_matches(prefix: &str, path: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    if !path.starts_with(prefix) {
        return false;
    }
    path.len() == prefix.len() || path.as_bytes()[prefix.len()] == b'/'
}

fn sort_routes(list: &mut [RouteEntry]) {
    list.sort_by_key(|entry| std::cmp::Reverse(entry.prefix.len()));
}

fn parse_header_line(line: &str) -> Option<(HeaderName, HeaderValue)> {
    let (name, value) = line.split_once(':')?;
    let name = HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
    let value = HeaderValue::from_str(value.trim()).ok()?;
    Some((name, value))
}

/// A configured backend: TCP authority or a filesystem unix socket.
#[derive(Clone, Debug)]
enum ServerAddr {
    Tcp(Authority),
    Unix(PathBuf),
}

impl std::fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(authority) => authority.fmt(f),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

impl ServerAddr {
    fn parse(value: &str) -> Option<Self> {
        if let Some(path) = value.strip_prefix("unix:") {
            return Some(Self::Unix(PathBuf::from(path)));
        }
        value.parse::<Authority>().ok().map(Self::Tcp)
    }

    fn tcp(&self) -> Option<&Authority> {
        match self {
            Self::Tcp(authority) => Some(authority),
            Self::Unix(_) => None,
        }
    }

    fn unix(&self) -> Option<&Path> {
        match self {
            Self::Unix(path) => Some(path),
            Self::Tcp(_) => None,
        }
    }
}

struct Pool {
    name: String,
    servers: Vec<ServerAddr>,
    health: Vec<AtomicBool>,
    active: Vec<AtomicUsize>,
    next: AtomicUsize,
    balance: Balance,
    retries: u32,
    scheme: &'static str,
    client: Client<HttpsConnector<HttpConnector>, Body>,
    tls: TlsOptions,
    health_path: Option<String>,
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
                // should not turn into an outage.
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

impl Proxy {
    /// Drop every cached response. Returns false when caching is disabled.
    pub fn purge_cache(&self) -> bool {
        match &self.inner.cache {
            Some(cache) => {
                cache.purge();
                true
            }
            None => false,
        }
    }

    pub fn cache_stats(&self) -> Option<(usize, usize)> {
        self.inner.cache.as_ref().map(|cache| cache.stats())
    }

    /// The current pools and their servers, for the admin status endpoint.
    pub fn status(&self) -> serde_json::Value {
        let pools: Vec<_> = self
            .inner
            .pools
            .iter()
            .map(|pool| {
                let servers: Vec<_> = pool
                    .servers
                    .iter()
                    .enumerate()
                    .map(|(index, server)| {
                        serde_json::json!({
                            "address": server.to_string(),
                            "healthy": pool.health[index].load(Ordering::Relaxed),
                            "active": pool.active[index].load(Ordering::Relaxed),
                        })
                    })
                    .collect();

                serde_json::json!({
                    "name": pool.name,
                    "balance": match pool.balance {
                        Balance::RoundRobin => "round_robin",
                        Balance::LeastConn => "least_conn",
                    },
                    "retries": pool.retries,
                    "servers": servers,
                })
            })
            .collect();

        serde_json::json!({
            "upstreams": pools,
            "cache": self.cache_stats().map(|(bytes, entries)| serde_json::json!({
                "bytes": bytes,
                "entries": entries,
            })),
        })
    }

    pub fn new(cfg: &Config) -> Result<Self, Error> {
        let mut pools: HashMap<String, Arc<Pool>> = HashMap::new();
        for up in &cfg.upstreams {
            let mut servers = Vec::with_capacity(up.servers.len());
            for addr in &up.servers {
                let server = ServerAddr::parse(addr).ok_or_else(|| Error::BadServer {
                    upstream: up.name.clone(),
                    addr: addr.clone(),
                })?;
                servers.push(server);
            }
            let health = (0..servers.len()).map(|_| AtomicBool::new(true)).collect();
            let active = (0..servers.len()).map(|_| AtomicUsize::new(0)).collect();

            // Each pool gets its own connector: trust and ALPN may differ
            // between upstreams.
            let tls = TlsOptions {
                insecure: up.tls_insecure.unwrap_or(cfg.upstream_tls.insecure),
                ca: up.tls_ca.clone().or_else(|| cfg.upstream_tls.ca.clone()),
                sni: up.sni.clone(),
                http2: up.http2.unwrap_or(cfg.upstream_tls.http2),
                tls13_only: cfg.upstream_tls.min_version == elira_config::TlsVersion::Tls13,
            };
            let connector = https_connector(&tls).map_err(|err| Error::UpstreamTls {
                reason: err.to_string(),
            })?;
            let client = Client::builder(TokioExecutor::new())
                // Hyper resolves the name for each new connection, so the
                // pool lifetime is the upper bound on DNS staleness.
                .pool_idle_timeout(Some(Duration::from_secs(up.dns_ttl_secs.unwrap_or(30))))
                .build(connector);

            pools.insert(
                up.name.clone(),
                Arc::new(Pool {
                    name: up.name.clone(),
                    servers,
                    health,
                    active,
                    next: AtomicUsize::new(0),
                    balance: up.balance,
                    retries: up.retries,
                    scheme: if up.tls { "https" } else { "http" },
                    client,
                    tls,
                    health_path: up.health_path.clone(),
                }),
            );
        }
        let all_pools: Vec<Arc<Pool>> = pools.values().cloned().collect();

        let mut exact: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut wildcard: Vec<(String, Vec<RouteEntry>)> = Vec::new();
        let mut default: Vec<RouteEntry> = Vec::new();

        for route in &cfg.routes {
            let target = if let Some(upstream) = &route.upstream {
                Target::Proxy(pools.get(upstream).cloned().ok_or_else(|| {
                    Error::UnknownUpstream {
                        upstream: upstream.clone(),
                    }
                })?)
            } else if let Some(root) = &route.root {
                Target::Files(Arc::new(Files::new(
                    root.clone(),
                    route.index.clone(),
                    route.spa,
                    route.try_files.clone(),
                    route.autoindex,
                    cfg.compression.enabled,
                    cfg.compression.min_bytes,
                )))
            } else if let Some(redirect) = &route.redirect {
                let status =
                    StatusCode::from_u16(redirect.status).map_err(|_| Error::BadRedirect {
                        host: route.host.clone(),
                    })?;
                let location =
                    HeaderValue::from_str(&redirect.to).map_err(|_| Error::BadRedirect {
                        host: route.host.clone(),
                    })?;
                Target::Redirect { status, location }
            } else {
                return Err(Error::MissingTarget {
                    host: route.host.clone(),
                });
            };

            let auth = match &route.auth_file {
                Some(path) => Some(Arc::new(BasicAuth::from_file(path).map_err(|err| {
                    Error::RouteConfig {
                        host: route.host.clone(),
                        reason: err.to_string(),
                    }
                })?)),
                None => None,
            };

            let acl = if route.ip_allow.is_empty() && route.ip_deny.is_empty() {
                None
            } else {
                Some(Arc::new(
                    IpAcl::new(&route.ip_allow, &route.ip_deny).map_err(|err| {
                        Error::RouteConfig {
                            host: route.host.clone(),
                            reason: err.to_string(),
                        }
                    })?,
                ))
            };

            let limiter = match route.requests_per_second {
                Some(rate) if rate > 0 => Some(Arc::new(RateLimiter::new(
                    rate,
                    route.burst.unwrap_or(rate).max(rate),
                ))),
                _ => None,
            };

            let error_root = route.error_root.clone().or_else(|| route.root.clone());
            let error_pages = match error_root {
                Some(root) if !route.error_pages.is_empty() => {
                    let files = Arc::new(Files::new(
                        root,
                        route.index.clone(),
                        false,
                        Vec::new(),
                        false,
                        false,
                        0,
                    ));
                    let mut pages = Vec::new();
                    for page in &route.error_pages {
                        let mut parts = page.splitn(2, char::is_whitespace);
                        let status = parts.next().and_then(|s| s.parse::<u16>().ok());
                        let path = parts.next().unwrap_or_default().trim();
                        if let Some(status) = status.and_then(|s| StatusCode::from_u16(s).ok()) {
                            pages.push((status, path.to_owned(), files.clone()));
                        }
                    }
                    pages
                }
                _ => Vec::new(),
            };

            let entry = RouteEntry {
                label: format!(
                    "{}{}",
                    route.host,
                    route.path.as_deref().unwrap_or_default()
                ),
                prefix: route.path.clone().unwrap_or_default(),
                target,
                strip_prefix: route.strip_prefix,
                add_headers: route
                    .add_headers
                    .iter()
                    .filter_map(|line| parse_header_line(line))
                    .collect(),
                remove_headers: route
                    .remove_headers
                    .iter()
                    .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
                    .collect(),
                auth,
                acl,
                timeout: route.timeout_secs.map(Duration::from_secs),
                limiter,
                body_limit: route.max_body_bytes,
                error_pages,
            };

            let host = route.host.trim().to_ascii_lowercase();
            if host == "*" {
                default.push(entry);
            } else if let Some(suffix) = host.strip_prefix('*') {
                if let Some((_, list)) = wildcard.iter_mut().find(|(known, _)| known == suffix) {
                    list.push(entry);
                } else {
                    wildcard.push((suffix.to_owned(), vec![entry]));
                }
            } else {
                exact.entry(host).or_default().push(entry);
            }
        }

        for list in exact.values_mut() {
            sort_routes(list);
        }
        for (_, list) in wildcard.iter_mut() {
            sort_routes(list);
        }
        sort_routes(&mut default);
        wildcard.sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));

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

        let cache = if cfg.cache.enabled {
            Some(Arc::new(Cache::with_disk(
                cfg.cache.max_bytes,
                Duration::from_secs(cfg.cache.ttl_secs),
                cfg.cache.dir.clone(),
                Duration::from_secs(cfg.cache.stale_secs),
            )))
        } else {
            None
        };
        let cache_max_item = cfg.cache.max_item_bytes;

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

        Ok(Self {
            inner: Arc::new(Inner {
                router: Router {
                    exact,
                    wildcard,
                    default,
                },
                pools: all_pools,
                tunnels: Arc::new(Semaphore::new(cfg.limits.max_connections)),
                connect,
                compression: cfg.compression.clone(),
                server_header: cfg.server_header,
                alt_svc: cfg.http3.as_ref().and_then(|http3| {
                    HeaderValue::from_str(&format!("h3=\":{}\"; ma=86400", http3.listen.port()))
                        .ok()
                }),
                max_body_bytes: cfg.limits.max_body_bytes,
                cache,
                cache_max_item,
                limiter,
                trusted_proxies,
                timeout: Duration::from_secs(cfg.limits.upstream_timeout_secs),
                body_timeout: match cfg.limits.upstream_body_timeout_secs {
                    0 => None,
                    secs => Some(Duration::from_secs(secs)),
                },
                tunnel_idle: match cfg.limits.websocket_idle_secs {
                    0 => None,
                    secs => Some(Duration::from_secs(secs)),
                },
                buffer_bytes: cfg.limits.response_buffer_bytes,
                refreshing: Arc::new(Mutex::new(HashSet::new())),
            }),
        })
    }

    /// Resolve a request to a static file, if the route is a static one and
    /// nothing about it needs the full response pipeline. The zero-copy path
    /// writes headers itself, so per-route headers, a hidden `Server` or
    /// `Alt-Svc` send the request through hyper instead.
    pub async fn static_file(&self, host: &str, path: &str) -> Option<std::path::PathBuf> {
        let (key, _) = canonical_host(host)?;
        let entry = self.inner.router.pick(&key, path)?;

        if !entry.add_headers.is_empty()
            || !entry.remove_headers.is_empty()
            || entry.auth.is_some()
            || entry.acl.is_some()
            || entry.limiter.is_some()
            || !entry.error_pages.is_empty()
            || !self.inner.server_header
            || self.inner.alt_svc.is_some()
        {
            return None;
        }

        match &entry.target {
            Target::Files(files) => files.resolve(path).await,
            _ => None,
        }
    }

    /// Spend one rate-limit token, if the limiter is on.
    pub fn rate_allows(&self, peer: std::net::IpAddr) -> bool {
        match &self.inner.limiter {
            Some(limiter) => limiter.check(peer, Instant::now()),
            None => true,
        }
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
            let path = pool.health_path.as_deref().unwrap_or(&cfg.path);
            for (index, server) in pool.servers.iter().enumerate() {
                let up = probe(server, path, timeout, pool.scheme == "https", &pool.tls).await;
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
        let idle = self.inner.tunnel_idle;

        tokio::spawn(async move {
            let _permit = permit;
            match client_upgrade.await {
                Ok(client) => {
                    let mut client = TokioIo::new(client);
                    if let Err(err) = tunnel(&mut client, &mut stream, idle).await {
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

        let encoding = preferred_encoding(req.headers());
        let is_head = req.method() == Method::HEAD;
        let is_get = req.method() == Method::GET;
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

        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.len() <= 64)
            .map(str::to_owned)
            .unwrap_or_else(elira_accesslog::request_id);

        let entry = self
            .inner
            .router
            .pick(&key, req.uri().path())
            .ok_or_else(|| text(StatusCode::NOT_FOUND, "no route"))?;

        // A route may set a stricter cap than the global one.
        if let Some(limit) = entry.body_limit {
            if limit > 0 {
                if let Some(length) = req
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                {
                    if length > limit as u64 {
                        return Err(text(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "request body too large",
                        ));
                    }
                }
            }
        }

        if let Some(limiter) = &entry.limiter {
            if !limiter.check(peer.ip(), Instant::now()) {
                let mut response = text(StatusCode::TOO_MANY_REQUESTS, "too many requests");
                response
                    .headers_mut()
                    .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
                return Err(response);
            }
        }

        if let Some(acl) = &entry.acl {
            if !acl.allows(peer.ip()) {
                return Err(text(StatusCode::FORBIDDEN, "forbidden"));
            }
        }

        if let Some(auth) = &entry.auth {
            let header = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok());

            if !auth.check(header) {
                let mut response = text(StatusCode::UNAUTHORIZED, "authentication required");
                response.headers_mut().insert(
                    WWW_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"elira\""),
                );
                return Err(response);
            }
        }

        let pool = match &entry.target {
            Target::Proxy(pool) => pool,
            Target::Files(files) => {
                let mut response = files.serve(&req, peer).await;
                self.apply_error_page(&mut response, entry, peer).await;
                self.apply_route(&mut response, entry, &request_id);
                return Ok(response);
            }
            Target::Redirect { status, location } => {
                let mut response =
                    Response::builder()
                        .status(*status)
                        .body(empty())
                        .map_err(|_| {
                            text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
                        })?;
                response.headers_mut().insert(LOCATION, location.clone());
                self.apply_route(&mut response, entry, &request_id);
                return Ok(response);
            }
        };
        let path = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());

        let cache_key = format!("{key}{path}");

        let upstream_path = if entry.strip_prefix {
            let rest = path
                .strip_prefix(entry.prefix.as_str())
                .unwrap_or(&path)
                .to_owned();
            if rest.is_empty() {
                "/".to_owned()
            } else if rest.starts_with('/') {
                rest
            } else {
                format!("/{rest}")
            }
        } else {
            path.clone()
        };

        // Retries are only safe when there is nothing to replay: an
        // idempotent method with no declared body.
        let can_retry = pool.retries > 0
            && !req.headers().contains_key(CONTENT_LENGTH)
            && !req.headers().contains_key(TRANSFER_ENCODING)
            && (req.method() == Method::GET
                || req.method() == Method::HEAD
                || req.method() == Method::OPTIONS);

        let (parts, body) = req.into_parts();
        // Kept for Vary matching: the response parts shadow this name later.
        let request_headers = parts.headers.clone();
        let mut template = HeaderMap::new();
        let drop = connection_tokens(&parts.headers);
        for (name, value) in parts.headers.iter() {
            if hop_by_hop(name, value) || drop.contains(name) || is_client_forwarding(name) {
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
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            template.insert("x-request-id", value);
        }

        // Upgrade is hop-by-hop, but dropping it would break websockets.
        if let Some(upgrade) = &requested_upgrade {
            template.insert(CONNECTION, HeaderValue::from_static("upgrade"));
            template.insert(UPGRADE, upgrade.clone());
        }

        let route_timeout = entry.timeout.unwrap_or(self.inner.timeout);

        let mut body = Some(body);

        if is_get && requested_upgrade.is_none() {
            if let Some(cache) = &self.inner.cache {
                let now = Instant::now();
                if let Some((hit, stale)) = cache.get_stale(&cache_key, &request_headers, now) {
                    let age = hit.age(now);
                    let mut response = cache_response(hit);
                    if let Ok(value) = HeaderValue::from_str(&age.to_string()) {
                        response.headers_mut().insert("age", value);
                    }
                    response.headers_mut().insert(
                        "x-cache",
                        HeaderValue::from_static(if stale { "STALE" } else { "HIT" }),
                    );
                    response.extensions_mut().insert(Labels {
                        route: entry.label.clone(),
                        upstream: Some(pool.name.clone()),
                    });
                    if stale {
                        self.refresh(
                            cache.clone(),
                            cache_key.clone(),
                            template.clone(),
                            request_headers.clone(),
                            upstream_path.clone(),
                            pool.clone(),
                            route_timeout,
                        );
                    }
                    self.apply_route(&mut response, entry, &request_id);
                    return Ok(response);
                }
            }
        }

        if let Some(upgrade) = requested_upgrade.clone() {
            let client = client_upgrade.expect("created together with requested_upgrade");
            let index = pool.pick();
            let server = pool.servers[index].clone();
            let _active = pool.enter(index);
            let uri = upstream_uri(&server, &upstream_path, pool.scheme)
                .ok_or_else(|| text(StatusCode::BAD_GATEWAY, "bad upstream address"))?;

            let mut upstream = Request::builder()
                .method(parts.method.clone())
                .uri(uri)
                .body(body.take().unwrap_or_else(empty))
                .map_err(|_| text(StatusCode::BAD_GATEWAY, "bad request"))?;
            *upstream.headers_mut() = template;

            return self
                .forward_upgrade(upstream, client, upgrade, server, route_timeout)
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

            let uri = upstream_uri(&server, &upstream_path, pool.scheme)
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

            match send_request(pool, &server, upstream, route_timeout).await {
                Ok(answer) => {
                    response = Some(answer);
                    break;
                }
                Err(SendError::Failed(err)) => {
                    tracing::warn!(upstream = %server, error = %err, "upstream request failed");
                    if attempt + 1 == attempts {
                        return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                    }
                }
                Err(SendError::Timeout) => {
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
        let compress_with = if self.inner.compression.enabled
            && parts.status == StatusCode::OK
            && !is_head
            && !parts.headers.contains_key(CONTENT_ENCODING)
            && compressible(content_type)
            && upstream_len
                .map(|length| length >= self.inner.compression.min_bytes)
                .unwrap_or(true)
        {
            encoding
        } else {
            None
        };

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

            if let Some(encoding) = compress_with {
                headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding));
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

        let cacheable = self.inner.cache.is_some()
            && is_get
            && requested_upgrade.is_none()
            && parts.status == StatusCode::OK
            && upstream_len
                .map(|length| length <= self.inner.cache_max_item)
                .unwrap_or(false)
            && cacheable_response(&parts.headers);

        let body = if cacheable {
            let collected = match BodyExt::collect(body).await {
                Ok(collected) => collected.to_bytes(),
                Err(err) => {
                    tracing::warn!(error = %err, "failed to buffer a cacheable response");
                    return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                }
            };

            if let Some(cache) = &self.inner.cache {
                cache.insert(
                    &cache_key,
                    &request_headers,
                    &parts.headers,
                    parts.status.as_u16(),
                    collected.to_vec(),
                    Instant::now(),
                );
            }

            Full::new(collected).map_err(|never| match never {}).boxed()
        } else {
            body
        };

        // Buffer small complete responses so the upstream socket is free
        // before a slow client finishes reading. Larger bodies stream.
        let body = if !cacheable
            && self.inner.buffer_bytes > 0
            && !is_head
            && upstream_len
                .map(|length| length <= self.inner.buffer_bytes)
                .unwrap_or(false)
        {
            match BodyExt::collect(body).await {
                Ok(collected) => Full::new(collected.to_bytes())
                    .map_err(|never| match never {})
                    .boxed(),
                Err(err) => {
                    tracing::warn!(error = %err, "failed to buffer an upstream response");
                    return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                }
            }
        } else {
            body
        };

        let body = if let Some(encoding) = compress_with {
            compress(body, encoding)
        } else {
            body
        };

        let body = match self.inner.body_timeout {
            Some(idle) => timeout_body(body, idle),
            None => body,
        };
        let mut response = builder
            .body(body)
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))?;

        if self.inner.cache.is_some() && is_get && requested_upgrade.is_none() {
            response
                .headers_mut()
                .insert("x-cache", HeaderValue::from_static("MISS"));
        }

        response.extensions_mut().insert(Labels {
            route: entry.label.clone(),
            upstream: Some(pool.name.clone()),
        });
        self.apply_error_page(&mut response, entry, peer).await;
        self.apply_route(&mut response, entry, &request_id);
        Ok(response)
    }

    /// Fetch a fresh copy in the background after serving a stale entry.
    #[allow(clippy::too_many_arguments)]
    fn refresh(
        &self,
        cache: Arc<Cache>,
        key: String,
        headers: HeaderMap,
        request_headers: HeaderMap,
        path: String,
        pool: Arc<Pool>,
        timeout: Duration,
    ) {
        {
            let mut refreshing = self
                .inner
                .refreshing
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !refreshing.insert(key.clone()) {
                return;
            }
        }

        let inflight = self.inner.refreshing.clone();
        let max_item = self.inner.cache_max_item;
        tokio::spawn(async move {
            let index = pool.pick();
            let server = pool.servers[index].clone();
            let _active = pool.enter(index);
            let uri = match upstream_uri(&server, &path, pool.scheme) {
                Some(uri) => uri,
                None => {
                    inflight
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&key);
                    return;
                }
            };

            let fetched = async {
                let mut request = Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(empty())
                    .ok()?;
                *request.headers_mut() = headers;
                let response = send_request(&pool, &server, request, timeout).await.ok()?;
                if response.status() != StatusCode::OK {
                    return None;
                }
                let length = response
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok())?;
                if length > max_item {
                    return None;
                }
                let response_headers = response.headers().clone();
                let body = BodyExt::collect(response.into_body())
                    .await
                    .ok()?
                    .to_bytes();
                Some((response_headers, body))
            }
            .await;

            if let Some((response_headers, body)) = fetched {
                cache.insert(
                    &key,
                    &request_headers,
                    &response_headers,
                    StatusCode::OK.as_u16(),
                    body.to_vec(),
                    Instant::now(),
                );
            }

            inflight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&key);
        });
    }

    /// Replace a configured error response with a file from the route root.
    /// The original status is kept even if the file itself would be a 200.
    async fn apply_error_page(
        &self,
        response: &mut Response<Body>,
        entry: &RouteEntry,
        peer: SocketAddr,
    ) {
        let status = response.status();
        let Some((_, path, files)) = entry
            .error_pages
            .iter()
            .find(|(code, _, _)| *code == status)
        else {
            return;
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri(path.clone())
            .body(empty());
        let Ok(request) = request else {
            return;
        };

        let mut page = files.serve(&request, peer).await;
        if page.status().is_success() {
            *page.status_mut() = status;
        }
        *response = page;
    }

    fn apply_route(&self, response: &mut Response<Body>, entry: &RouteEntry, request_id: &str) {
        let headers = response.headers_mut();

        for name in &entry.remove_headers {
            headers.remove(name);
        }
        for (name, value) in &entry.add_headers {
            headers.insert(name, value.clone());
        }

        if !headers.contains_key("x-request-id") {
            if let Ok(value) = HeaderValue::from_str(request_id) {
                headers.insert("x-request-id", value);
            }
        }
        if !self.inner.server_header {
            headers.remove(SERVER);
        }
        if let Some(alt) = &self.inner.alt_svc {
            headers.insert(ALT_SVC, alt.clone());
        }
    }

    /// Upgrades cannot go through the connection pool: hyper has to hand the
    /// socket over instead of returning it. Open a raw connection and tunnel.
    async fn forward_upgrade(
        &self,
        upstream: Request<Body>,
        client_upgrade: hyper::upgrade::OnUpgrade,
        upgrade: HeaderValue,
        server: ServerAddr,
        timeout: Duration,
    ) -> Result<Response<Body>, Response<Body>> {
        // Tunnels outlive the connection task that the accept loop tracks,
        // so they need their own bound.
        let permit = match self.inner.tunnels.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Err(text(StatusCode::SERVICE_UNAVAILABLE, "too many tunnels")),
        };

        let mut stream = match connect_server(&server, timeout).await {
            Some(stream) => stream,
            None => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
        };

        let head = serialize_head(&upstream);
        match tokio::time::timeout(timeout, stream.write_all(head.as_bytes())).await {
            Ok(Ok(())) => {}
            _ => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
        }

        let (status, mut headers, upstream_upgrade, leftover) =
            read_head(&mut stream, timeout).await?;

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

        let idle = self.inner.tunnel_idle;

        tokio::spawn(async move {
            let _permit = permit;
            match client_upgrade.await {
                Ok(client) => {
                    let mut client = TokioIo::new(client);
                    let mut upstream = stream;
                    // Bytes the upstream sent right after the 101 would
                    // otherwise be dropped by the copy loop.
                    if !leftover.is_empty() && client.write_all(&leftover).await.is_err() {
                        return;
                    }
                    if let Err(err) = tunnel(&mut client, &mut upstream, idle).await {
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

async fn read_head<S>(
    stream: &mut S,
    timeout: Duration,
) -> Result<(StatusCode, HeaderMap, Option<HeaderValue>, Vec<u8>), Response<Body>>
where
    S: AsyncRead + Unpin,
{
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
async fn probe(
    server: &ServerAddr,
    path: &str,
    timeout: Duration,
    tls: bool,
    options: &TlsOptions,
) -> bool {
    if let Some(socket) = server.unix() {
        let mut stream = match tokio::time::timeout(timeout, UnixStream::connect(socket)).await {
            Ok(Ok(stream)) => stream,
            _ => return false,
        };
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        if tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        return probe_response(&mut stream, timeout).await;
    }

    let authority = match server.tcp() {
        Some(authority) => authority,
        None => return false,
    };
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = authority.port_u16().unwrap_or(if tls { 443 } else { 80 });

    let stream = match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };

    let request = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    if tls {
        let config = match elira_upstream::client_config(options) {
            Ok(config) => config,
            Err(_) => return false,
        };
        let name = match options.sni.as_deref().or(Some(host)) {
            Some(name) => name.to_owned(),
            None => return false,
        };
        let name = match name.parse::<std::net::IpAddr>() {
            Ok(ip) => tokio_rustls::rustls::pki_types::ServerName::IpAddress(ip.into()),
            Err(_) => match tokio_rustls::rustls::pki_types::ServerName::try_from(name) {
                Ok(name) => name,
                Err(_) => return false,
            },
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let mut stream = match tokio::time::timeout(timeout, connector.connect(name, stream)).await
        {
            Ok(Ok(stream)) => stream,
            _ => return false,
        };
        if tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        probe_response(&mut stream, timeout).await
    } else {
        let mut stream = stream;
        if tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        probe_response(&mut stream, timeout).await
    }
}

async fn probe_response<S>(stream: &mut S, timeout: Duration) -> bool
where
    S: tokio::io::AsyncRead + Unpin,
{
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

pub fn preferred_encoding(headers: &HeaderMap) -> Option<&'static str> {
    let value = headers.get(ACCEPT_ENCODING)?.to_str().ok()?;

    let mut br = 0.0f32;
    let mut gzip = 0.0f32;

    for part in value.split(',') {
        let mut pieces = part.trim().split(';');
        let name = pieces.next().unwrap_or_default().trim();
        let quality = pieces
            .next()
            .and_then(|piece| piece.trim().strip_prefix("q="))
            .and_then(|value| value.parse::<f32>().ok())
            .unwrap_or(1.0);

        if name.eq_ignore_ascii_case("br") {
            br = quality;
        } else if name.eq_ignore_ascii_case("gzip") {
            gzip = quality;
        }
    }

    if br > 0.0 && br >= gzip {
        Some("br")
    } else if gzip > 0.0 {
        Some("gzip")
    } else {
        None
    }
}

pub fn compressible(content_type: &str) -> bool {
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

pub(crate) fn compress(body: Body, encoding: &'static str) -> Body {
    fn finish<R>(reader: R) -> Body
    where
        R: tokio::io::AsyncRead + Send + Sync + 'static,
    {
        let stream = ReaderStream::new(reader).map_ok(hyper::body::Frame::data);
        BodyExt::map_err(StreamBody::new(stream), |err| -> BoxError { Box::new(err) }).boxed()
    }

    let stream = TryStreamExt::map_err(body.into_data_stream(), std::io::Error::other);
    let reader = StreamReader::new(stream);

    match encoding {
        "br" => finish(BrotliEncoder::new(BufReader::new(reader))),
        _ => finish(GzipEncoder::new(BufReader::new(reader))),
    }
}

fn cacheable_response(headers: &HeaderMap) -> bool {
    if headers.contains_key(SET_COOKIE) {
        return false;
    }

    match headers
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => {
            let value = value.to_ascii_lowercase();
            !value.contains("no-store") && !value.contains("private")
        }
        None => true,
    }
}

fn cache_response(entry: elira_cache::Entry) -> Response<Body> {
    let status = StatusCode::from_u16(entry.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = Response::builder().status(status);

    if let Some(headers) = builder.headers_mut() {
        for (name, value) in &entry.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.append(name, value);
            }
        }
    }

    let body = Full::new(Bytes::from(entry.body))
        .map_err(|never| match never {})
        .boxed();

    builder
        .body(body)
        .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
}

fn upstream_uri(server: &ServerAddr, path: &str, scheme: &'static str) -> Option<Uri> {
    let (scheme, authority) = match server {
        ServerAddr::Tcp(authority) => (scheme, authority.as_str()),
        // TLS over a unix socket is rejected by config validation.
        ServerAddr::Unix(_) => ("http", "localhost"),
    };
    Uri::builder()
        .scheme(scheme)
        .authority(authority)
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

/// `TE: trailers` is how gRPC asks for trailer frames; dropping it breaks
/// every gRPC upstream. Other TE values really are hop-by-hop.
fn hop_by_hop(name: &HeaderName, value: &HeaderValue) -> bool {
    if name.as_str() == "te" {
        return value
            .to_str()
            .map(|value| value.trim().eq_ignore_ascii_case("trailers"))
            .map(|trailers| !trailers)
            .unwrap_or(true);
    }
    is_hop_by_hop(name)
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

    #[error("route for \"{host}\" has an invalid redirect target or status")]
    BadRedirect { host: String },

    #[error("upstream TLS: {reason}")]
    UpstreamTls { reason: String },

    #[error("route for \"{host}\": {reason}")]
    RouteConfig { host: String, reason: String },
}

/// Transport used by the raw upgrade path. Both variants behave the same for
/// the handshake and the tunnel.
enum EitherStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl AsyncRead for EitherStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for EitherStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

async fn connect_server(server: &ServerAddr, timeout: Duration) -> Option<EitherStream> {
    match server {
        ServerAddr::Tcp(authority) => {
            let host = authority
                .host()
                .trim_start_matches('[')
                .trim_end_matches(']');
            let port = authority.port_u16().unwrap_or(80);
            match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
                Ok(Ok(stream)) => Some(EitherStream::Tcp(stream)),
                _ => None,
            }
        }
        ServerAddr::Unix(path) => {
            match tokio::time::timeout(timeout, UnixStream::connect(path)).await {
                Ok(Ok(stream)) => Some(EitherStream::Unix(stream)),
                _ => None,
            }
        }
    }
}

enum SendError {
    Timeout,
    Failed(String),
}

async fn send_request(
    pool: &Pool,
    server: &ServerAddr,
    request: Request<Body>,
    timeout: Duration,
) -> Result<Response<Body>, SendError> {
    let Some(path) = server.unix() else {
        return match tokio::time::timeout(timeout, pool.client.request(request)).await {
            Ok(Ok(response)) => Ok(response
                .map(|body| BodyExt::map_err(body, |err| -> BoxError { Box::new(err) }).boxed())),
            Ok(Err(err)) => Err(SendError::Failed(err.to_string())),
            Err(_) => Err(SendError::Timeout),
        };
    };

    let work = async {
        let stream = UnixStream::connect(path).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(request).await?;
        Ok::<_, BoxError>(response)
    };

    match tokio::time::timeout(timeout, work).await {
        Ok(Ok(response)) => Ok(response
            .map(|body| BodyExt::map_err(body, |err| -> BoxError { Box::new(err) }).boxed())),
        Ok(Err(err)) => Err(SendError::Failed(err.to_string())),
        Err(_) => Err(SendError::Timeout),
    }
}

/// A body that fails when it makes no progress for `idle`. Used for both
/// client uploads and upstream downloads: a peer that stops mid-body would
/// otherwise hold a connection slot forever.
pub fn timeout_body(body: Body, idle: Duration) -> Body {
    IdleBody {
        inner: body,
        idle,
        timer: Box::pin(tokio::time::sleep(idle)),
        expired: false,
    }
    .boxed()
}

struct IdleBody {
    inner: Body,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
    expired: bool,
}

impl HttpBody for IdleBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.expired {
            return Poll::Ready(None);
        }

        if self.timer.as_mut().poll(cx).is_ready() {
            self.expired = true;
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "body made no progress",
            )))));
        }

        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + this.idle);
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Copy bytes both ways, closing the tunnel after `idle` without traffic.
async fn tunnel<A, B>(a: &mut A, b: &mut B, idle: Option<Duration>) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let forward = pipe(&mut a_read, &mut b_write, idle);
    let backward = pipe(&mut b_read, &mut a_write, idle);
    tokio::pin!(forward);
    tokio::pin!(backward);

    tokio::select! {
        result = &mut forward => result,
        result = &mut backward => result,
    }
}

async fn pipe<R, W>(read: &mut R, write: &mut W, idle: Option<Duration>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let read = match idle {
            Some(idle) => match tokio::time::timeout(idle, read.read(&mut buf)).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "tunnel idle",
                    ))
                }
            },
            None => read.read(&mut buf).await?,
        };
        if read == 0 {
            return Ok(());
        }
        write.write_all(&buf[..read]).await?;
        write.flush().await?;
    }
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
        let tls = TlsOptions::default();
        let client =
            Client::builder(TokioExecutor::new()).build(https_connector(&tls).expect("connector"));
        let pool = Pool {
            name: "test".to_owned(),
            servers: vec![
                ServerAddr::Tcp("127.0.0.1:1".parse().unwrap()),
                ServerAddr::Tcp("127.0.0.1:2".parse().unwrap()),
            ],
            health: vec![AtomicBool::new(true), AtomicBool::new(true)],
            active: vec![AtomicUsize::new(0), AtomicUsize::new(5)],
            next: AtomicUsize::new(0),
            balance: Balance::LeastConn,
            retries: 0,
            scheme: "http",
            client,
            tls,
            health_path: None,
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
