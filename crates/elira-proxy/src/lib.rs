//! Request forwarding.
//!
//! The rules that matter here are the boring ones: never trust forwarding
//! headers from the client, never forward hop-by-hop headers, and pick an
//! upstream before touching the body.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::Stream;
use http::header::{
    HeaderName, HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_TYPE, HOST, LOCATION, SERVER, TRANSFER_ENCODING, UPGRADE, VARY,
};
use http::uri::Authority;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{watch, Semaphore};
use tokio::time::Sleep;
use tokio_util::io::ReaderStream;

use elira_auth::{BasicAuth, IpAcl};
use elira_cache::Cache;
use elira_config::{Balance, Compression, Config, Health, Map, RewriteFlag};
use elira_limit::RateLimiter;
use elira_tls::ClientIdentity;

pub mod files;

mod admin;
mod apps;
mod build;
mod health;
mod helpers;
mod pool;
mod response;
mod serve;
mod tunnel;
mod variables;
pub(crate) use build::*;
use health::*;
pub(crate) use helpers::*;
pub use helpers::{compressible, preferred_encoding};
pub(crate) use pool::*;
use variables::*;

use files::Files;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// What the response belongs to, attached as a response extension so the
/// listener can feed per-route and per-upstream metrics without the proxy
/// holding a metrics registry.
#[derive(Clone, Debug)]
pub struct FastStatic {
    pub file: std::path::PathBuf,
    pub add_headers: Vec<(HeaderName, HeaderValue)>,
    pub remove_headers: Vec<HeaderName>,
    pub server_header: bool,
    pub alt_svc: Option<HeaderValue>,
    pub access_log: bool,
    pub access_log_sample: f64,
}

#[derive(Clone, Debug)]
pub struct Labels {
    pub route: String,
    pub upstream: Option<String>,
    pub access_log: bool,
    pub access_log_sample: f64,
}

/// Marks a response whose body already came from an error page.
#[derive(Clone, Copy)]
struct ErrorPageApplied;
pub type Body = BoxBody<Bytes, BoxError>;

#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

/// Shared byte budget for temporary spool files. Zero total means unlimited;
/// the used counter is still maintained for `/status`.
struct SpoolBudget {
    total: u64,
    used: Mutex<u64>,
}

struct SpoolPermit {
    budget: Arc<SpoolBudget>,
    bytes: u64,
}

impl SpoolBudget {
    fn new(total: u64) -> Self {
        Self {
            total,
            used: Mutex::new(0),
        }
    }

    fn reserve(self: &Arc<Self>, bytes: u64) -> Option<SpoolPermit> {
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.total > 0 && used.saturating_add(bytes) > self.total {
            return None;
        }
        *used = used.saturating_add(bytes);
        Some(SpoolPermit {
            budget: self.clone(),
            bytes,
        })
    }

    fn used(&self) -> u64 {
        *self
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for SpoolPermit {
    fn drop(&mut self) {
        let mut used = self
            .budget
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *used = used.saturating_sub(self.bytes);
    }
}

/// Single-flight coordination for cache misses. One request fills the entry;
/// the rest wait briefly and re-check the cache instead of stampeding the
/// upstream.
struct CacheFlights {
    entries: Mutex<HashMap<String, watch::Sender<bool>>>,
}

enum CacheFlight {
    Leader(CacheFlightGuard),
    Follower(watch::Receiver<bool>),
}

struct CacheFlightGuard {
    flights: Arc<CacheFlights>,
    key: String,
    done: watch::Sender<bool>,
}

impl CacheFlights {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn enter(self: &Arc<Self>, key: &str) -> CacheFlight {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(done) = entries.get(key) {
            return CacheFlight::Follower(done.subscribe());
        }
        let (done, _) = watch::channel(false);
        entries.insert(key.to_owned(), done.clone());
        CacheFlight::Leader(CacheFlightGuard {
            flights: self.clone(),
            key: key.to_owned(),
            done,
        })
    }
}

impl Drop for CacheFlightGuard {
    fn drop(&mut self) {
        {
            let mut entries = self
                .flights
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            entries.remove(&self.key);
        }
        let _ = self.done.send(true);
    }
}

impl SpoolPermit {
    fn grow(&mut self, bytes: u64) -> bool {
        let mut used = self
            .budget
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.budget.total > 0 && used.saturating_add(bytes) > self.budget.total {
            return false;
        }
        *used = used.saturating_add(bytes);
        self.bytes = self.bytes.saturating_add(bytes);
        true
    }
}

/// A growable reservation used while the final body size is unknown.
struct SpoolLease {
    permit: SpoolPermit,
}

impl SpoolLease {
    fn new(budget: &Arc<SpoolBudget>) -> Option<Self> {
        budget.reserve(0).map(|permit| Self { permit })
    }

    fn from_permit(permit: SpoolPermit) -> Self {
        Self { permit }
    }

    fn grow(&mut self, bytes: u64) -> bool {
        self.permit.grow(bytes)
    }
}

struct Inner {
    routers: HashMap<String, Router>,
    rewrites: Vec<CompiledRewrite>,
    maps: Vec<Map>,
    geos: Vec<CompiledGeo>,
    splits: Vec<CompiledSplit>,
    pools: Vec<Arc<Pool>>,
    tunnels: Arc<Semaphore>,
    connect: Option<Vec<Authority>>,
    compression: Compression,
    server_header: bool,
    alt_svc: Option<HeaderValue>,
    max_body_bytes: usize,
    max_headers: usize,
    max_header_bytes: usize,
    cache: Option<Arc<Cache>>,
    cache_flights: Arc<CacheFlights>,
    cache_max_item: usize,
    limiter: Option<Arc<RateLimiter>>,
    trusted_proxies: Vec<ipnet::IpNet>,
    timeout: Duration,
    body_timeout: Option<Duration>,
    tunnel_idle: Option<Duration>,
    buffer_bytes: usize,
    request_buffer_bytes: usize,
    request_spool_bytes: usize,
    spool_bytes: usize,
    spool_budget: Arc<SpoolBudget>,
    spooled: AtomicU64,
    max_app_response: usize,
    max_upstream_response: usize,
    error_pages: Vec<(StatusCode, String, Arc<Files>)>,
    fastcgi_pool: elira_fastcgi::Pool,
    refreshing: Arc<Mutex<HashSet<String>>>,
}

#[derive(Clone)]
enum Target {
    Proxy(Arc<Pool>),
    Files(Arc<Files>),
    Redirect {
        status: StatusCode,
        location: String,
    },
    Return {
        status: StatusCode,
        body: String,
        content_type: Option<String>,
    },
    FastCgi {
        target: elira_fastcgi::Target,
        root: PathBuf,
        index: String,
    },
    Cgi {
        script: PathBuf,
    },
    Module(ModuleTarget),
    Wasm(Arc<elira_wasm::WasmModule>),
}

#[derive(Clone)]
enum ModuleTarget {
    InProcess(Arc<elira_module::Module>),
    Sandbox(Arc<elira_module::ProcessModule>),
}

#[derive(Clone, Debug)]
struct ClientCertRule {
    subject_cn: Option<String>,
    issuer_cn: Option<String>,
}

impl ClientCertRule {
    fn allows(&self, identity: Option<&ClientIdentity>) -> bool {
        let Some(identity) = identity else {
            return false;
        };
        self.subject_cn
            .as_deref()
            .is_none_or(|cn| identity.subject_cn.as_deref() == Some(cn))
            && self
                .issuer_cn
                .as_deref()
                .is_none_or(|cn| identity.issuer_cn.as_deref() == Some(cn))
    }
}

#[derive(Clone)]
struct RouteEntry {
    label: String,
    host: String,
    prefix: String,
    exact: bool,
    no_regex: bool,
    regex: Option<regex::Regex>,
    target: Target,
    strip_prefix: bool,
    add_headers: Vec<(HeaderName, String)>,
    remove_headers: Vec<HeaderName>,
    request_headers: Vec<(HeaderName, String)>,
    request_remove_headers: Vec<HeaderName>,
    if_conditions: Vec<CompiledIf>,
    auth: Option<Arc<BasicAuth>>,
    acl: Option<Arc<IpAcl>>,
    timeout: Option<Duration>,
    limiter: Option<Arc<RateLimiter>>,
    rate_key: RequestKey,
    body_limit: Option<usize>,
    error_pages: Vec<(StatusCode, String, Arc<Files>)>,
    app_permits: Option<Arc<Semaphore>>,
    proxy_permits: Option<Arc<Semaphore>>,
    max_response: Option<usize>,
    fastcgi_pool: Option<Arc<elira_fastcgi::Pool>>,
    cache: Option<bool>,
    cache_ttl: Option<Duration>,
    access_log: bool,
    access_log_sample: f64,
    client_auth: Option<ClientCertRule>,
    max_upstream_response: Option<usize>,
    expires_secs: Option<u64>,
    etag: bool,
    fastcgi_param: Vec<(String, String)>,
    cgi_param: Vec<(String, String)>,
}

#[derive(Clone)]
struct Router {
    exact: HashMap<String, Vec<RouteEntry>>,
    wildcard: Vec<(String, Vec<RouteEntry>)>,
    default: Vec<RouteEntry>,
}

impl Router {
    fn from_entries(entries: Vec<RouteEntry>) -> Self {
        let mut exact: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut wildcard: Vec<(String, Vec<RouteEntry>)> = Vec::new();
        let mut default = Vec::new();

        for entry in entries {
            let host = entry.host.clone();
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

        Self {
            exact,
            wildcard,
            default,
        }
    }

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
            if let Some(entry) = list
                .iter()
                .find(|entry| entry.exact && entry.prefix == path)
            {
                return Some(entry);
            }
            let prefix = list
                .iter()
                .find(|entry| entry.regex.is_none() && path_matches(&entry.prefix, path));
            if let Some(entry) = prefix {
                if entry.no_regex {
                    return Some(entry);
                }
            }
            if let Some(entry) = list.iter().find(|entry| {
                entry
                    .regex
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(path))
            }) {
                return Some(entry);
            }
            if let Some(entry) = prefix {
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

impl Proxy {
    pub fn new(cfg: &Config) -> Result<Self, Error> {
        let (pools, all_pools) = build_pools(cfg)?;

        let mut entries: Vec<(RouteEntry, Vec<String>)> = Vec::new();
        for route in &cfg.routes {
            entries.push((build_route(route, cfg, &pools)?, route.listeners.clone()));
        }

        let routers = build_routers(cfg, entries);
        let rewrites = build_rewrites(cfg)?;
        let geos = build_geos(cfg);
        let splits = build_splits(cfg);
        let connect = build_connect(cfg)?;

        let cache = if cfg.cache.enabled {
            Some(Arc::new(Cache::with_shared_disk(
                cfg.cache.max_bytes,
                Duration::from_secs(cfg.cache.ttl_secs),
                cfg.cache.dir.clone(),
                Duration::from_secs(cfg.cache.stale_secs),
                cfg.cache.shared,
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
                routers,
                rewrites,
                maps: cfg.maps.clone(),
                geos,
                splits,
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
                max_headers: cfg.limits.max_headers,
                max_header_bytes: cfg.limits.max_header_bytes,
                cache,
                cache_flights: Arc::new(CacheFlights::new()),
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
                request_buffer_bytes: cfg.limits.request_buffer_bytes,
                request_spool_bytes: cfg.limits.request_spool_bytes,
                spool_bytes: cfg.limits.response_spool_bytes,
                spool_budget: Arc::new(SpoolBudget::new(cfg.limits.spool_budget_bytes)),
                spooled: AtomicU64::new(0),
                max_app_response: cfg.limits.max_response_bytes,
                max_upstream_response: cfg.limits.max_upstream_response_bytes,
                error_pages: match &cfg.error_root {
                    Some(root) => error_page_set(
                        root.clone(),
                        vec!["index.html".to_owned()],
                        &cfg.error_pages,
                    ),
                    None => Vec::new(),
                },
                fastcgi_pool: elira_fastcgi::Pool::new(
                    cfg.limits.fastcgi_pool_idle,
                    Duration::from_secs(cfg.limits.fastcgi_pool_idle_secs),
                ),
                refreshing: Arc::new(Mutex::new(HashSet::new())),
            }),
        })
    }

    /// Resolve a request to a static file, if the route is a static one and
    /// nothing about it needs the full response pipeline. The zero-copy path
    /// writes headers itself, so per-route headers, a hidden `Server` or
    /// `Alt-Svc` send the request through hyper instead.
    pub async fn static_file(&self, host: &str, path: &str) -> Option<std::path::PathBuf> {
        self.fast_static(
            host,
            path,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            &HeaderMap::new(),
            "default",
        )
        .await
        .map(|fast| fast.file)
    }

    fn router(&self, listener: &str) -> &Router {
        self.inner
            .routers
            .get(listener)
            .or_else(|| self.inner.routers.get("default"))
            .or_else(|| self.inner.routers.values().next())
            .expect("a configured server has at least one router")
    }

    /// Everything the sendfile fast path needs, after the same access checks
    /// as the normal route. `None` means hyper should handle the request.
    pub async fn fast_static(
        &self,
        host: &str,
        path: &str,
        peer: std::net::IpAddr,
        headers: &HeaderMap,
        listener: &str,
    ) -> Option<FastStatic> {
        let (key, _) = canonical_host(host)?;
        let entry = self.router(listener).pick(&key, path)?;
        // The fast path writes headers itself. Template expansion happens in
        // the hyper path, so hand those responses back to it.
        if entry
            .add_headers
            .iter()
            .any(|(_, value)| value.contains('$'))
        {
            return None;
        }
        // Cache headers and ETag policy belong to the Files response path.
        if entry.expires_secs.is_some() || !entry.etag {
            return None;
        }

        // Resolve the target first: a proxy route must not pay for a token or
        // an auth check here only to be handed to hyper afterwards.
        let file = match &entry.target {
            Target::Files(files) => files.resolve(path).await?,
            _ => return None,
        };

        if let Some(acl) = &entry.acl {
            if !acl.allows(peer) {
                return None;
            }
        }
        if let Some(auth) = &entry.auth {
            let header = headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok());
            if !auth.check(header) {
                return None;
            }
        }
        if let Some(limiter) = &entry.limiter {
            let bucket = request_key_value(&entry.rate_key, headers, peer, path);
            if !limiter.check(bucket.as_ref(), Instant::now()) {
                return None;
            }
        }

        Some(FastStatic {
            file,
            add_headers: entry
                .add_headers
                .iter()
                .filter_map(|(name, value)| {
                    HeaderValue::from_str(value)
                        .ok()
                        .map(|value| (name.clone(), value))
                })
                .collect(),
            remove_headers: entry.remove_headers.clone(),
            server_header: self.inner.server_header,
            alt_svc: self.inner.alt_svc.clone(),
            access_log: entry.access_log,
            access_log_sample: entry.access_log_sample,
        })
    }

    /// Spend one rate-limit token, if the limiter is on.
    pub fn rate_allows(&self, peer: std::net::IpAddr) -> bool {
        match &self.inner.limiter {
            Some(limiter) => limiter.check(&peer, Instant::now()),
            None => true,
        }
    }

    /// Probe every upstream once and update its health flag.
    pub async fn check_health(&self, cfg: &Health) -> (usize, usize) {
        if !cfg.enabled {
            return (0, 0);
        }
        let mut ok = 0;
        let mut failed = 0;
        let timeout = Duration::from_secs(cfg.timeout_secs);
        for pool in &self.inner.pools {
            let probe = Probe {
                path: pool.health_path.as_deref().unwrap_or(&cfg.path),
                method: pool.health_method.as_deref().unwrap_or(&cfg.method),
                host: pool.health_host.as_deref().or(cfg.host.as_deref()),
                expect: pool.health_status.as_deref().unwrap_or(&cfg.expect_status),
                timeout,
                tls: pool.scheme == "https",
                options: &pool.tls,
            };
            for (index, server) in pool.servers.iter().enumerate() {
                let up = probe_server(server, &probe).await;
                pool.set_health(index, up);
                if up {
                    ok += 1;
                } else {
                    failed += 1;
                }
            }
        }
        (ok, failed)
    }

    pub async fn handle(
        &self,
        req: Request<Body>,
        peer: SocketAddr,
        scheme: &'static str,
        listener: &str,
    ) -> Response<Body> {
        if self.headers_too_large(req.headers()) {
            let mut response = text(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "request headers too large",
            );
            self.apply_global_error_page(&mut response, peer).await;
            return response;
        }

        if let Some(limiter) = &self.inner.limiter {
            if !limiter.check(&peer.ip(), Instant::now()) {
                let mut response = text(StatusCode::TOO_MANY_REQUESTS, "too many requests");
                response
                    .headers_mut()
                    .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
                self.apply_global_error_page(&mut response, peer).await;
                return response;
            }
        }

        match self.forward(req, peer, scheme, listener).await {
            Ok(response) => response,
            Err(mut response) => {
                self.apply_global_error_page(&mut response, peer).await;
                response
            }
        }
    }

    /// Approximate header accounting for protocols that do not enforce the
    /// limits themselves, notably HTTP/3. HTTP/1.1 and HTTP/2 already reject
    /// oversized lists before the proxy sees them.
    fn headers_too_large(&self, headers: &HeaderMap) -> bool {
        !headers_within_limits(headers, self.inner.max_headers, self.inner.max_header_bytes)
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

    #[allow(clippy::result_large_err)]
    fn apply_rewrites(&self, req: &mut Request<Body>) -> Result<(), Response<Body>> {
        let mut path = req.uri().path().to_owned();
        let mut query = req.uri().query().map(str::to_owned);

        for _ in 0..10 {
            let mut restart = false;
            for rewrite in &self.inner.rewrites {
                let Some(captures) = rewrite.regex.captures(&path) else {
                    continue;
                };
                let target = expand_rewrite(&rewrite.replacement, &captures);
                match rewrite.flag {
                    RewriteFlag::Redirect | RewriteFlag::Permanent => {
                        let status = if rewrite.flag == RewriteFlag::Permanent {
                            StatusCode::MOVED_PERMANENTLY
                        } else {
                            StatusCode::FOUND
                        };
                        let Ok(location) = HeaderValue::from_str(&target) else {
                            return Err(text(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "rewrite location is not a valid header value",
                            ));
                        };
                        let mut response = text(status, "redirect");
                        response.headers_mut().insert(LOCATION, location);
                        return Err(response);
                    }
                    RewriteFlag::Break | RewriteFlag::Last => {
                        let (new_path, new_query) = match target.split_once('?') {
                            Some((path, query)) => (path.to_owned(), Some(query.to_owned())),
                            None => (target, None),
                        };
                        path = if new_path.starts_with('/') {
                            new_path
                        } else {
                            format!("/{new_path}")
                        };
                        query = new_query;
                        restart = rewrite.flag == RewriteFlag::Last;
                        break;
                    }
                }
            }
            if !restart {
                break;
            }
        }

        let path_and_query = match query {
            Some(query) => format!("{path}?{query}"),
            None => path,
        };
        let Ok(path_and_query) = path_and_query.parse::<http::uri::PathAndQuery>() else {
            return Err(text(StatusCode::BAD_REQUEST, "bad rewrite target"));
        };
        let mut parts = req.uri().clone().into_parts();
        parts.path_and_query = Some(path_and_query);
        let Ok(uri) = Uri::from_parts(parts) else {
            return Err(text(StatusCode::BAD_REQUEST, "bad rewrite target"));
        };
        *req.uri_mut() = uri;
        Ok(())
    }

    async fn forward(
        &self,
        mut req: Request<Body>,
        peer: SocketAddr,
        scheme: &'static str,
        listener: &str,
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

        if !self.inner.rewrites.is_empty() {
            self.apply_rewrites(&mut req)?;
        }

        let entry = self
            .router(listener)
            .pick(&key, req.uri().path())
            .ok_or_else(|| text(StatusCode::NOT_FOUND, "no route"))?;

        let request_uri = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());
        let request_port = forward_host
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let mut vars = RequestVars {
            remote_addr: peer.ip(),
            host: key.clone(),
            path: req.uri().path().to_owned(),
            query: req.uri().query().unwrap_or_default().to_owned(),
            uri: request_uri,
            method: req.method().to_string(),
            scheme,
            port: request_port,
            request_id: request_id.clone(),
            headers: req.headers().clone(),
            mapped: HashMap::new(),
        };
        vars.apply_derived(&self.inner.maps, &self.inner.geos, &self.inner.splits);

        for condition in &entry.if_conditions {
            let value = vars
                .value(&condition.variable)
                .map(|value| value.into_owned())
                .unwrap_or_default();
            let matched = condition
                .equals
                .as_ref()
                .is_some_and(|expected| value == *expected)
                || condition
                    .regex
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(&value));
            if matched {
                return Ok(self.fixed_response(
                    condition.status,
                    &condition.body,
                    condition.content_type.as_deref(),
                    &vars,
                    entry,
                    &request_id,
                ));
            }
        }

        if let Some(response) = self.check_access(&req, entry, &vars, peer).await {
            return Err(response);
        }

        let body_limit = entry.body_limit.unwrap_or(self.inner.max_body_bytes);
        let body_limit_hit = Arc::new(AtomicBool::new(false));
        if body_limit > 0 {
            let hit = body_limit_hit.clone();
            req = req.map(|body| capped_request_body(body, body_limit, hit));
        }

        let mut buffered = None;
        if (self.inner.request_buffer_bytes > 0 || self.inner.request_spool_bytes > 0)
            && requested_upgrade.is_none()
        {
            let original = std::mem::replace(req.body_mut(), empty());
            match buffer_request(
                req.headers(),
                original,
                self.inner.request_buffer_bytes,
                self.inner.request_spool_bytes,
                &self.inner.spool_budget,
            )
            .await
            {
                Ok(RequestBuffer::Stream(body)) => *req.body_mut() = body,
                Ok(RequestBuffer::Buffered(body)) => {
                    *req.body_mut() = body.body();
                    buffered = Some(body);
                }
                Err(()) => {
                    if body_limit_hit.load(Ordering::Relaxed) {
                        return Err(self.body_too_large(entry, &vars, peer).await);
                    }
                    return Err(text(StatusCode::BAD_REQUEST, "request body error"));
                }
            }
        }

        let proxy_permit = match &entry.proxy_permits {
            Some(permits) => match permits.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    let mut response = text(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "too many concurrent requests",
                    );
                    response
                        .headers_mut()
                        .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
                    self.apply_error_page(&mut response, entry, &vars, peer)
                        .await;
                    return Err(response);
                }
            },
            None => None,
        };

        let pool = match &entry.target {
            Target::Proxy(pool) => pool,
            _ => {
                return self
                    .serve_non_proxy(
                        req,
                        entry,
                        &vars,
                        peer,
                        scheme,
                        &request_id,
                        &body_limit_hit,
                    )
                    .await;
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

        let (parts, body) = req.into_parts();
        // Kept for Vary matching: the response parts shadow this name later.
        let request_headers = parts.headers.clone();
        let hash_key = (pool.balance == Balance::Hash)
            .then(|| request_key_value(&pool.hash_key, &parts.headers, peer.ip(), &path));
        let can_retry = pool.retries > 0
            && match parts.method {
                Method::GET | Method::HEAD | Method::OPTIONS => {
                    buffered.is_some()
                        || (!parts.headers.contains_key(CONTENT_LENGTH)
                            && !parts.headers.contains_key(TRANSFER_ENCODING))
                }
                Method::PUT | Method::DELETE => buffered.is_some(),
                _ => false,
            };
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
        let forwarded_port = forward_host
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let forwarded_for_value = match peer.ip() {
            std::net::IpAddr::V6(ip) => format!("\"[{ip}]\""),
            std::net::IpAddr::V4(ip) => ip.to_string(),
        };
        let forwarded = format!("for={forwarded_for_value};proto={scheme};host=\"{forward_host}\"");
        template.insert(HOST, header(&forward_host));
        template.insert("x-forwarded-for", header(&forwarded_for));
        template.insert("x-forwarded-proto", HeaderValue::from_static(scheme));
        template.insert("x-forwarded-host", header(&forward_host));
        template.insert(
            "x-forwarded-port",
            HeaderValue::from_str(&forwarded_port.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("80")),
        );
        if let Ok(value) = HeaderValue::from_str(&forwarded) {
            template.insert("forwarded", value);
        }
        template.insert("via", HeaderValue::from_static("1.1 elira"));
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            template.insert("x-request-id", value);
        }

        // Upgrade is hop-by-hop, but dropping it would break websockets.
        if let Some(upgrade) = &requested_upgrade {
            template.insert(CONNECTION, HeaderValue::from_static("upgrade"));
            template.insert(UPGRADE, upgrade.clone());
        }

        for name in &entry.request_remove_headers {
            template.remove(name);
        }
        for (name, value) in &entry.request_headers {
            if let Ok(value) = HeaderValue::from_str(&vars.render(value)) {
                template.insert(name.clone(), value);
            }
        }

        let route_timeout = entry.timeout.unwrap_or(self.inner.timeout);

        let mut body = Some(body);

        let cache_allowed = entry.cache != Some(false);
        let mut _cache_flight: Option<CacheFlightGuard> = None;
        if is_get && requested_upgrade.is_none() && cache_allowed {
            if let Some(cache) = &self.inner.cache {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                loop {
                    let now = Instant::now();
                    if let Some((hit, stale)) = cache.get_stale(&cache_key, &request_headers, now) {
                        let age = hit.age(now);
                        let body_len = hit.body.len();
                        let cached_status = hit.status;
                        let cached_type = hit
                            .headers
                            .iter()
                            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                            .map(|(_, value)| value.clone())
                            .unwrap_or_default();
                        let cached_encoding = hit
                            .headers
                            .iter()
                            .any(|(name, _)| name.eq_ignore_ascii_case("content-encoding"));
                        let validators = validators_from_entry(&hit);
                        let mut response = cache_response(hit);

                        // A cached body is stored identity-encoded, so it still
                        // has to go through the same negotiation as a fresh one.
                        if !is_head
                            && !cached_encoding
                            && cached_status == StatusCode::OK.as_u16()
                            && self.inner.compression.enabled
                            && body_len >= self.inner.compression.min_bytes
                            && compressible(&cached_type)
                        {
                            if let Some(encoding) = preferred_encoding(&request_headers) {
                                let headers = response.headers_mut();
                                headers.remove(CONTENT_LENGTH);
                                headers.remove(http::header::ETAG);
                                headers
                                    .insert(CONTENT_ENCODING, HeaderValue::from_static(encoding));
                                headers.append(VARY, HeaderValue::from_static("accept-encoding"));
                                let body = std::mem::replace(response.body_mut(), empty());
                                *response.body_mut() = compress(body, encoding);
                            }
                        }

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
                            access_log: entry.access_log,
                            access_log_sample: entry.access_log_sample,
                        });
                        if stale {
                            self.refresh(
                                cache.clone(),
                                cache_key.clone(),
                                template.clone(),
                                request_headers.clone(),
                                validators,
                                upstream_path.clone(),
                                pool.clone(),
                                route_timeout,
                                entry.cache_ttl,
                            );
                        }
                        self.apply_route(&mut response, entry, &vars, &request_id);
                        return Ok(response);
                    }

                    match self.inner.cache_flights.enter(&cache_key) {
                        CacheFlight::Leader(guard) => {
                            _cache_flight = Some(guard);
                            break;
                        }
                        CacheFlight::Follower(mut done) => {
                            if tokio::time::Instant::now() >= deadline {
                                break;
                            }
                            if !*done.borrow() {
                                let _ = tokio::time::timeout_at(deadline, done.changed()).await;
                            }
                        }
                    }
                }
            }
        }

        if let Some(upgrade) = requested_upgrade.clone() {
            let client = client_upgrade.expect("created together with requested_upgrade");
            let index = pool.pick_key(hash_key.as_deref());
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

            let result = self
                .forward_upgrade(
                    upstream,
                    client,
                    upgrade,
                    server,
                    route_timeout,
                    proxy_permit,
                )
                .await;
            match &result {
                Ok(_) => pool.record_success(index),
                Err(response) if response.status() == StatusCode::BAD_GATEWAY => {
                    pool.record_failure(index);
                }
                Err(_) => {}
            }
            return result;
        }
        let attempts = if can_retry {
            pool.retries as usize + 1
        } else {
            1
        };
        let mut response = None;

        for attempt in 0..attempts {
            let index = pool.pick_key(hash_key.as_deref());
            let server = pool.servers[index].clone();
            let _active = pool.enter(index);

            let uri = upstream_uri(&server, &upstream_path, pool.scheme)
                .ok_or_else(|| text(StatusCode::BAD_GATEWAY, "bad upstream address"))?;
            let payload = match &buffered {
                Some(buffered) => buffered.body(),
                None if attempt == 0 => body.take().unwrap_or_else(empty),
                None => empty(),
            };

            let mut upstream = Request::builder()
                .method(parts.method.clone())
                .uri(uri)
                .body(payload)
                .map_err(|_| text(StatusCode::BAD_GATEWAY, "bad request"))?;
            *upstream.headers_mut() = template.clone();

            match send_request(pool, &server, upstream, route_timeout).await {
                Ok(answer) => {
                    if attempt + 1 < attempts && pool.retry_on.status(answer.status().as_u16()) {
                        pool.record_success(index);
                        tracing::warn!(
                            upstream = %server,
                            status = answer.status().as_u16(),
                            "upstream returned a retryable status"
                        );
                        continue;
                    }
                    pool.record_success(index);
                    response = Some(answer);
                    break;
                }
                Err(SendError::Failed(err)) => {
                    if body_limit_hit.load(Ordering::Relaxed) {
                        return Err(self.body_too_large(entry, &vars, peer).await);
                    }
                    pool.record_failure(index);
                    tracing::warn!(upstream = %server, error = %err, "upstream request failed");
                    if !pool.retry_on.error || attempt + 1 == attempts {
                        return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                    }
                }
                Err(SendError::Timeout) => {
                    if body_limit_hit.load(Ordering::Relaxed) {
                        return Err(self.body_too_large(entry, &vars, peer).await);
                    }
                    pool.record_failure(index);
                    tracing::warn!(upstream = %server, "upstream timed out");
                    if !pool.retry_on.timeout || attempt + 1 == attempts {
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
        let response_cap = entry
            .max_upstream_response
            .unwrap_or(self.inner.max_upstream_response);
        if response_cap > 0 && upstream_len.is_some_and(|length| length > response_cap) {
            return Err(text(StatusCode::BAD_GATEWAY, "upstream response too large"));
        }
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

        let body = if response_cap > 0 {
            capped_body(body, response_cap)
        } else {
            body
        };

        let cacheable = self.inner.cache.is_some()
            && cache_allowed
            && is_get
            && requested_upgrade.is_none()
            && parts.status == StatusCode::OK
            && upstream_len
                .map(|length| {
                    length <= self.inner.cache_max_item
                        && (response_cap == 0 || length <= response_cap)
                })
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
                cache.insert_with_ttl(
                    &cache_key,
                    &request_headers,
                    &parts.headers,
                    parts.status.as_u16(),
                    collected.to_vec(),
                    Instant::now(),
                    entry.cache_ttl,
                );
            }

            Full::new(collected).map_err(|never| match never {}).boxed()
        } else {
            body
        };

        // Buffer small complete responses so the upstream socket is free
        // before a slow client finishes reading. Larger bodies up to the
        // spool limit go to an unlinked temporary file; anything beyond that
        // streams straight through.
        let body = if !cacheable && !is_head {
            match upstream_len {
                Some(length)
                    if self.inner.buffer_bytes > 0 && length <= self.inner.buffer_bytes =>
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
                }
                Some(length)
                    if self.inner.spool_bytes > 0
                        && length > self.inner.buffer_bytes
                        && length <= self.inner.spool_bytes =>
                {
                    match self.inner.spool_budget.reserve(length as u64) {
                        Some(permit) => match spool_body(body, length, permit).await {
                            Ok(body) => {
                                self.inner.spooled.fetch_add(1, Ordering::Relaxed);
                                body
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "failed to spool an upstream response");
                                return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                            }
                        },
                        None => {
                            tracing::debug!(
                                length,
                                "spool budget exhausted, streaming the response"
                            );
                            body
                        }
                    }
                }
                _ => body,
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
        let body = match proxy_permit {
            Some(permit) => PermitBody {
                inner: body,
                _permit: permit,
            }
            .boxed(),
            None => body,
        };
        let mut response = builder
            .body(body)
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))?;

        if self.inner.cache.is_some() && cache_allowed && is_get && requested_upgrade.is_none() {
            response
                .headers_mut()
                .insert("x-cache", HeaderValue::from_static("MISS"));
        }

        response.extensions_mut().insert(Labels {
            route: entry.label.clone(),
            upstream: Some(pool.name.clone()),
            access_log: entry.access_log,
            access_log_sample: entry.access_log_sample,
        });
        self.apply_error_page(&mut response, entry, &vars, peer)
            .await;
        self.apply_route(&mut response, entry, &vars, &request_id);
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
        validators: HeaderMap,
        path: String,
        pool: Arc<Pool>,
        timeout: Duration,
        cache_ttl: Option<Duration>,
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
                // Ask the upstream to confirm the stored representation.
                for (name, value) in &validators {
                    request.headers_mut().insert(name, value.clone());
                }
                let response = send_request(&pool, &server, request, timeout).await.ok()?;
                if response.status() == StatusCode::NOT_MODIFIED {
                    return Some((StatusCode::NOT_MODIFIED, HeaderMap::new(), Bytes::new()));
                }
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
                Some((StatusCode::OK, response_headers, body))
            }
            .await;

            match fetched {
                Some((StatusCode::NOT_MODIFIED, _, _)) => {
                    cache.revalidate(&key, &request_headers, Instant::now());
                }
                Some((_, response_headers, body)) => {
                    cache.insert_with_ttl(
                        &key,
                        &request_headers,
                        &response_headers,
                        StatusCode::OK.as_u16(),
                        body.to_vec(),
                        Instant::now(),
                        cache_ttl,
                    );
                }
                None => {}
            }

            inflight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&key);
        });
    }
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
        if let Some(h3) = &pool.h3 {
            let uri = request.uri().clone();
            let result = tokio::time::timeout(timeout, h3.request(uri, request)).await;
            return match result {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(err)) => Err(SendError::Failed(err.to_string())),
                Err(_) => Err(SendError::Timeout),
            };
        }
        if let Some(h2) = &pool.h2 {
            let uri = request.uri().clone();
            let result = tokio::time::timeout(timeout, h2.request(uri, request)).await;
            return match result {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(err)) => Err(SendError::Failed(err.to_string())),
                Err(_) => Err(SendError::Timeout),
            };
        }
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

/// A body that errors after `limit` data bytes.
/// Write a fully known response body to an unlinked temporary file and return
/// a body that reads it back. This releases the upstream connection before a
/// slow client drains the response.
async fn spool_body(
    mut body: Body,
    expected: usize,
    permit: SpoolPermit,
) -> Result<Body, BoxError> {
    let file = tempfile::tempfile()?;
    let mut file = tokio::fs::File::from_std(file);
    let mut seen = 0usize;
    let mut trailers = None;

    while let Some(frame) = body.frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(data) => {
                seen = seen.saturating_add(data.len());
                if seen > expected {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "upstream body is longer than Content-Length",
                    )));
                }
                file.write_all(&data).await?;
            }
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
            }
        }
    }

    if seen != expected {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "upstream body is shorter than Content-Length",
        )));
    }

    file.seek(SeekFrom::Start(0)).await?;
    Ok(SpooledBody {
        stream: ReaderStream::new(file),
        trailers,
        length: expected as u64,
        _permit: Some(permit),
    }
    .boxed())
}

struct SpooledBody {
    stream: ReaderStream<tokio::fs::File>,
    trailers: Option<HeaderMap>,
    length: u64,
    _permit: Option<SpoolPermit>,
}

impl HttpBody for SpooledBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.stream).poll_next(cx) {
            Poll::Ready(Some(Ok(data))) => Poll::Ready(Some(Ok(Frame::data(data)))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(Box::new(err)))),
            Poll::Ready(None) => match this.trailers.take() {
                Some(trailers) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
                None => Poll::Ready(None),
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.length)
    }
}

struct PermitBody {
    inner: Body,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl HttpBody for PermitBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

enum RequestBuffer {
    Stream(Body),
    Buffered(BufferedBody),
}

enum BufferData {
    Memory(Bytes),
    Spool(Arc<tempfile::NamedTempFile>),
}

struct BufferedBody {
    data: BufferData,
    trailers: Option<HeaderMap>,
    length: u64,
    _lease: Option<SpoolLease>,
}

impl BufferedBody {
    fn body(&self) -> Body {
        match &self.data {
            BufferData::Memory(bytes) => {
                let mut frames: Vec<Result<Frame<Bytes>, BoxError>> =
                    vec![Ok(Frame::data(bytes.clone()))];
                if let Some(trailers) = &self.trailers {
                    frames.push(Ok(Frame::trailers(trailers.clone())));
                }
                BodyExt::boxed(StreamBody::new(futures_util::stream::iter(frames)))
            }
            BufferData::Spool(file) => spool_file_body(file, self.length, self.trailers.clone()),
        }
    }
}

fn spool_file_body(
    file: &Arc<tempfile::NamedTempFile>,
    length: u64,
    trailers: Option<HeaderMap>,
) -> Body {
    let reopened = file.reopen().expect("spool temp file is still open");
    SpooledBody {
        stream: ReaderStream::new(tokio::fs::File::from_std(reopened)),
        trailers,
        length,
        _permit: None,
    }
    .boxed()
}

/// A body that yields a buffered prefix and then continues with the rest of
/// the original stream. Used when an unknown-length request outgrows the
/// buffering limits.
struct ConcatBody {
    first: Option<Body>,
    rest: Body,
    _lease: Option<SpoolLease>,
}

impl HttpBody for ConcatBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if let Some(mut first) = this.first.take() {
            match Pin::new(&mut first).poll_frame(cx) {
                Poll::Ready(Some(frame)) => {
                    this.first = Some(first);
                    return Poll::Ready(Some(frame));
                }
                Poll::Ready(None) => {}
                Poll::Pending => {
                    this.first = Some(first);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }
}

fn chain_body(first: Body, rest: Body, lease: Option<SpoolLease>) -> Body {
    ConcatBody {
        first: Some(first),
        rest,
        _lease: lease,
    }
    .boxed()
}

fn memory_body(bytes: Bytes) -> Body {
    BodyExt::boxed(StreamBody::new(futures_util::stream::iter(vec![Ok::<
        _,
        BoxError,
    >(
        Frame::data(bytes),
    )])))
}

/// Buffer a request body into memory or a temporary file. A body with a known
/// length is accepted whole when it fits. An unknown-length body is buffered
/// up to the limits; if it outgrows them, the buffered prefix is replayed and
/// the original stream continues, so the request still works but is not
/// retryable.
async fn buffer_request(
    headers: &HeaderMap,
    body: Body,
    memory_limit: usize,
    spool_limit: usize,
    budget: &Arc<SpoolBudget>,
) -> Result<RequestBuffer, ()> {
    let length = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());

    if let Some(length) = length {
        let total_limit = if spool_limit > 0 {
            spool_limit
        } else {
            memory_limit
        };
        if total_limit > 0 && length > total_limit {
            return buffer_unknown_length(body, memory_limit, spool_limit, budget).await;
        }
        return buffer_known_length(body, length, memory_limit, spool_limit, budget).await;
    }
    buffer_unknown_length(body, memory_limit, spool_limit, budget).await
}

async fn buffer_known_length(
    body: Body,
    length: usize,
    memory_limit: usize,
    spool_limit: usize,
    budget: &Arc<SpoolBudget>,
) -> Result<RequestBuffer, ()> {
    if length == 0 {
        return Ok(RequestBuffer::Stream(body));
    }
    let memory = memory_limit > 0 && length <= memory_limit;
    let spool = !memory && spool_limit > 0 && length > memory_limit && length <= spool_limit;
    if !memory && !spool {
        return Ok(RequestBuffer::Stream(body));
    }

    let lease = if spool {
        budget.reserve(length as u64).map(SpoolLease::from_permit)
    } else {
        None
    };
    if spool && lease.is_none() {
        return Ok(RequestBuffer::Stream(body));
    }

    let file = if spool {
        Some(Arc::new(tempfile::NamedTempFile::new().map_err(|_| ())?))
    } else {
        None
    };
    let mut writer = match &file {
        Some(file) => Some(tokio::fs::File::from_std(file.reopen().map_err(|_| ())?)),
        None => None,
    };

    let mut data = Vec::with_capacity(if memory { length } else { 0 });
    let mut trailers = None;
    let mut seen = 0usize;
    let mut body = body;

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ())?;
        match frame.into_data() {
            Ok(chunk) => {
                seen = seen.saturating_add(chunk.len());
                if seen > length {
                    return Err(());
                }
                match &mut writer {
                    Some(file) => file.write_all(&chunk).await.map_err(|_| ())?,
                    None => data.extend_from_slice(&chunk),
                }
            }
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
            }
        }
    }

    if seen != length {
        return Err(());
    }
    if let Some(mut writer) = writer {
        writer.flush().await.map_err(|_| ())?;
    }

    let data = match file {
        Some(file) => BufferData::Spool(file),
        None => BufferData::Memory(Bytes::from(data)),
    };
    Ok(RequestBuffer::Buffered(BufferedBody {
        data,
        trailers,
        length: length as u64,
        _lease: lease,
    }))
}

async fn buffer_unknown_length(
    body: Body,
    memory_limit: usize,
    spool_limit: usize,
    budget: &Arc<SpoolBudget>,
) -> Result<RequestBuffer, ()> {
    let total_limit = if spool_limit > 0 {
        spool_limit
    } else {
        memory_limit
    };
    if total_limit == 0 {
        return Ok(RequestBuffer::Stream(body));
    }

    let mut memory = Vec::new();
    let mut spool: Option<(
        Arc<tempfile::NamedTempFile>,
        tokio::fs::File,
        SpoolLease,
        u64,
    )> = None;
    let mut trailers = None;
    let mut body = body;

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ())?;
        let chunk = match frame.into_data() {
            Ok(chunk) => chunk,
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
                continue;
            }
        };

        if spool.is_none() && (memory_limit == 0 || memory.len() + chunk.len() <= memory_limit) {
            memory.extend_from_slice(&chunk);
            continue;
        }

        if spool.is_none() {
            if spool_limit == 0 || memory.len() + chunk.len() > spool_limit {
                memory.extend_from_slice(&chunk);
                return Ok(RequestBuffer::Stream(chain_body(
                    memory_body(Bytes::from(memory)),
                    body,
                    None,
                )));
            }

            let Some(mut lease) = SpoolLease::new(budget) else {
                memory.extend_from_slice(&chunk);
                return Ok(RequestBuffer::Stream(chain_body(
                    memory_body(Bytes::from(memory)),
                    body,
                    None,
                )));
            };
            let file = Arc::new(tempfile::NamedTempFile::new().map_err(|_| ())?);
            let mut writer = tokio::fs::File::from_std(file.reopen().map_err(|_| ())?);
            let existing = memory.len() as u64;
            if !lease.grow(existing + chunk.len() as u64) {
                memory.extend_from_slice(&chunk);
                return Ok(RequestBuffer::Stream(chain_body(
                    memory_body(Bytes::from(memory)),
                    body,
                    None,
                )));
            }
            writer.write_all(&memory).await.map_err(|_| ())?;
            writer.write_all(&chunk).await.map_err(|_| ())?;
            memory.clear();
            spool = Some((file, writer, lease, existing + chunk.len() as u64));
            continue;
        }

        let (_, writer, lease, written) = spool.as_mut().expect("spool is present");
        if *written + chunk.len() as u64 > spool_limit as u64 || !lease.grow(chunk.len() as u64) {
            let (file, writer, lease, written) = spool.take().expect("spool is present");
            drop(writer);
            let prefix = spool_file_body(&file, written, None);
            return Ok(RequestBuffer::Stream(chain_body(
                prefix,
                chain_body(memory_body(chunk), body, None),
                Some(lease),
            )));
        }

        writer.write_all(&chunk).await.map_err(|_| ())?;
        *written = written.saturating_add(chunk.len() as u64);
    }

    if let Some((file, mut writer, lease, written)) = spool {
        writer.flush().await.map_err(|_| ())?;
        drop(writer);
        return Ok(RequestBuffer::Buffered(BufferedBody {
            data: BufferData::Spool(file),
            trailers,
            length: written,
            _lease: Some(lease),
        }));
    }

    let length = memory.len() as u64;
    Ok(RequestBuffer::Buffered(BufferedBody {
        data: BufferData::Memory(Bytes::from(memory)),
        trailers,
        length,
        _lease: None,
    }))
}

fn capped_body(body: Body, limit: usize) -> Body {
    CappedBody {
        inner: body,
        limit,
        seen: 0,
        message: "upstream response too large",
        flag: None,
    }
    .boxed()
}

fn capped_request_body(body: Body, limit: usize, flag: Arc<AtomicBool>) -> Body {
    CappedBody {
        inner: body,
        limit,
        seen: 0,
        message: "request body too large",
        flag: Some(flag),
    }
    .boxed()
}

struct CappedBody {
    inner: Body,
    limit: usize,
    seen: usize,
    message: &'static str,
    flag: Option<Arc<AtomicBool>>,
}

impl HttpBody for CappedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.seen = this.seen.saturating_add(data.len());
                    if this.seen > this.limit {
                        if let Some(flag) = &this.flag {
                            flag.store(true, Ordering::Relaxed);
                        }
                        return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            this.message,
                        )))));
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, AtomicUsize};
    use tokio::io::AsyncReadExt;

    use elira_upstream::{https_connector, TlsOptions};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    #[tokio::test]
    async fn capped_body_errors_after_the_limit() {
        let frames = futures_util::stream::iter(vec![
            Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"0123456789"))),
            Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"abc"))),
        ]);
        let body = capped_body(BodyExt::boxed(StreamBody::new(frames)), 10);
        let err = BodyExt::collect(body).await.expect_err("over the cap");
        assert!(err.to_string().contains("upstream response too large"));
    }

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
    fn header_limits_count_names_values_and_overhead() {
        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static("a"), HeaderValue::from_static("1"));
        assert!(headers_within_limits(&headers, 1, 6));
        assert!(!headers_within_limits(&headers, 1, 5));
        assert!(!headers_within_limits(&headers, 0, 100));

        headers.insert(HeaderName::from_static("b"), HeaderValue::from_static("2"));
        assert!(!headers_within_limits(&headers, 1, 100));
        assert!(headers_within_limits(&headers, 2, 100));
    }

    #[test]
    fn spool_budget_reserves_and_releases_bytes() {
        let budget = Arc::new(SpoolBudget::new(100));
        let first = budget.reserve(60).expect("first reservation");
        assert_eq!(budget.used(), 60);
        assert!(budget.reserve(50).is_none(), "over budget");

        let second = budget.reserve(40).expect("fits exactly");
        assert_eq!(budget.used(), 100);
        drop(first);
        assert_eq!(budget.used(), 40);
        drop(second);
        assert_eq!(budget.used(), 0);

        let unlimited = Arc::new(SpoolBudget::new(0));
        let permit = unlimited.reserve(u64::MAX).expect("unlimited");
        drop(permit);
        assert_eq!(unlimited.used(), 0);
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
            passive: vec![
                Passive {
                    failures: AtomicU32::new(0),
                    ejected_until_ms: AtomicU64::new(0),
                },
                Passive {
                    failures: AtomicU32::new(0),
                    ejected_until_ms: AtomicU64::new(0),
                },
            ],
            failures_before_eject: 0,
            eject_for: Duration::from_secs(30),
            started: Instant::now(),
            hash_key: RequestKey::Ip,
            server_labels: vec!["127.0.0.1:1".to_owned(), "127.0.0.1:2".to_owned()],
            weights: vec![1, 1],
            total_weight: 2,
            weighted: false,
            retry_on: RetryOn::parse(&[]),
            next: AtomicUsize::new(0),
            balance: Balance::LeastConn,
            retries: 0,
            scheme: "http",
            client,
            tls,
            health_path: None,
            health_method: None,
            health_status: None,
            health_host: None,
            h2: None,
            h3: None,
        };

        assert_eq!(pool.pick(), 0);
        pool.active[0].store(10, Ordering::Relaxed);
        assert_eq!(pool.pick(), 1);
    }

    #[test]
    fn weighted_least_conn_compares_active_over_weight() {
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
            active: vec![AtomicUsize::new(3), AtomicUsize::new(3)],
            passive: vec![
                Passive {
                    failures: AtomicU32::new(0),
                    ejected_until_ms: AtomicU64::new(0),
                },
                Passive {
                    failures: AtomicU32::new(0),
                    ejected_until_ms: AtomicU64::new(0),
                },
            ],
            failures_before_eject: 0,
            eject_for: Duration::from_secs(30),
            started: Instant::now(),
            hash_key: RequestKey::Ip,
            server_labels: vec!["127.0.0.1:1".to_owned(), "127.0.0.1:2".to_owned()],
            weights: vec![1, 3],
            total_weight: 4,
            weighted: true,
            retry_on: RetryOn::parse(&[]),
            next: AtomicUsize::new(0),
            balance: Balance::LeastConn,
            retries: 0,
            scheme: "http",
            client,
            tls,
            health_path: None,
            health_method: None,
            health_status: None,
            health_host: None,
            h2: None,
            h3: None,
        };

        assert_eq!(pool.pick(), 1, "3/3 beats 3/1");
        pool.active[0].store(0, Ordering::Relaxed);
        pool.active[1].store(0, Ordering::Relaxed);
        pool.next.store(0, Ordering::Relaxed);
        assert_eq!(pool.pick(), 0);
    }

    #[tokio::test]
    async fn health_probe_honours_method_host_and_expected_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe");
        let addr = listener.local_addr().expect("probe addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let read = stream.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..read]);
                    let status = if head.starts_with("HEAD /ready ")
                        && head.to_ascii_lowercase().contains("host: health.local")
                    {
                        "204 No Content"
                    } else {
                        "503 Service Unavailable"
                    };
                    let _ = stream
                        .write_all(
                            format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n").as_bytes(),
                        )
                        .await;
                });
            }
        });

        let server = ServerAddr::Tcp(format!("{addr}").parse().expect("authority"));
        let tls = TlsOptions::default();
        let probe = |path: &'static str, expect: &'static [u16]| Probe {
            path,
            method: "HEAD",
            host: Some("health.local"),
            expect,
            timeout: Duration::from_secs(2),
            tls: false,
            options: &tls,
        };

        assert!(probe_server(&server, &probe("/ready", &[204])).await);
        assert!(probe_server(&server, &probe("/ready", &[])).await);
        assert!(!probe_server(&server, &probe("/broken", &[204])).await);
        assert!(probe_server(&server, &probe("/broken", &[503])).await);
    }

    #[test]
    fn passive_ejection_skips_a_failing_server_until_the_cooldown() {
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
            active: vec![AtomicUsize::new(0), AtomicUsize::new(0)],
            passive: vec![
                Passive {
                    failures: AtomicU32::new(0),
                    ejected_until_ms: AtomicU64::new(0),
                },
                Passive {
                    failures: AtomicU32::new(0),
                    ejected_until_ms: AtomicU64::new(0),
                },
            ],
            failures_before_eject: 2,
            eject_for: Duration::from_secs(30),
            started: Instant::now(),
            hash_key: RequestKey::Ip,
            server_labels: vec!["127.0.0.1:1".to_owned(), "127.0.0.1:2".to_owned()],
            weights: vec![1, 1],
            total_weight: 2,
            weighted: false,
            retry_on: RetryOn::parse(&[]),
            next: AtomicUsize::new(0),
            balance: Balance::RoundRobin,
            retries: 0,
            scheme: "http",
            client,
            tls,
            health_path: None,
            health_method: None,
            health_status: None,
            health_host: None,
            h2: None,
            h3: None,
        };

        pool.record_failure(0);
        pool.next.store(0, Ordering::Relaxed);
        assert_eq!(pool.pick(), 0, "one failure must not eject the server");

        pool.record_failure(0);
        pool.next.store(0, Ordering::Relaxed);
        assert_eq!(pool.pick(), 1, "the ejected server is skipped");

        // A successful request clears both the counter and the ejection.
        pool.record_success(0);
        pool.next.store(0, Ordering::Relaxed);
        assert_eq!(pool.pick(), 0);
    }

    #[test]
    fn rendezvous_only_moves_keys_owned_by_a_removed_server() {
        let labels = ["a", "b", "c"];
        for index in 0..500 {
            let key = format!("client-{index}");
            let full = labels
                .iter()
                .copied()
                .max_by_key(|label| rendezvous(&key, label))
                .expect("winner");

            for removed in labels {
                if removed == full {
                    continue;
                }
                let reduced: Vec<_> = labels
                    .iter()
                    .copied()
                    .filter(|label| *label != removed)
                    .collect();
                let winner = reduced
                    .iter()
                    .copied()
                    .max_by_key(|label| rendezvous(&key, label))
                    .expect("winner");
                assert_eq!(winner, full, "key {key} moved when {removed} was removed");
            }
        }
    }

    #[test]
    fn module_owner_must_be_root_or_the_server_user() {
        assert!(super::module_owner_allowed(0, 1000));
        assert!(super::module_owner_allowed(1000, 1000));
        assert!(!super::module_owner_allowed(1001, 1000));
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
