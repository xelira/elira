//! Request forwarding.
//!
//! The rules that matter here are the boring ones: never trust forwarding
//! headers from the client, never forward hop-by-hop headers, and pick an
//! upstream before touching the body.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, AUTHORIZATION};
use http::uri::Authority;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;

use hyper_util::client::legacy::connect::HttpConnector;
use tokio::sync::Semaphore;

use elira_auth::{BasicAuth, IpAcl};
use elira_cache::Cache;
use elira_config::{
    CacheValid, Compression, Config, Health, Map, RewriteFlag, Satisfy, SecureLink,
};
use elira_limit::RateLimiter;
use elira_tls::ClientIdentity;

pub mod files;

mod admin;
mod ajp;
mod app_target;
mod apps;
mod body;
mod build;
mod cgi_response;
mod forward;
mod health;
mod helpers;
mod pool;
mod response;
mod scgi;
mod serve;
mod tunnel;
mod uwsgi;
mod variables;
pub use body::timeout_body;
pub(crate) use body::*;
pub(crate) use build::*;
use health::*;
pub(crate) use helpers::*;
pub use helpers::{compressible, preferred_encoding};
pub(crate) use pool::*;
pub use tunnel::ConnectError;
use variables::*;

use files::{FileCache, Files};

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

/// A static response asking the proxy to route to a named location.
#[derive(Clone, Debug)]
pub(crate) struct InternalTarget(pub(crate) String);

/// Present on a request that is already inside an internal redirect.
#[derive(Clone, Debug)]
pub(crate) struct InternalRequest {
    pub(crate) name: Option<String>,
    pub(crate) count: u8,
}

/// Marks the internal subrequest made by `auth_request`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthSubrequest;

/// Marks an internal redirect requested by `X-Accel-Redirect`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AccelRedirect;
pub type Body = BoxBody<Bytes, BoxError>;

#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

/// One configured error page.
#[derive(Clone)]
pub(crate) struct ErrorPage {
    pub(crate) status: StatusCode,
    pub(crate) path: String,
    pub(crate) files: Arc<Files>,
    pub(crate) override_status: Option<StatusCode>,
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
    caches: Vec<Arc<Cache>>,
    cache_flights: Arc<CacheFlights>,
    limiter: Option<Arc<RateLimiter>>,
    trusted_proxies: Vec<ipnet::IpNet>,
    timeout: Duration,
    resolver: elira_upstream::Resolver,
    connect_timeout: Duration,
    send_timeout: Option<Duration>,
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
    error_pages: Vec<ErrorPage>,
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
    Scgi {
        target: crate::app_target::Target,
        root: Option<PathBuf>,
    },
    Uwsgi {
        target: crate::app_target::Target,
        modifier1: u8,
        modifier2: u8,
    },
    Ajp {
        target: crate::app_target::Target,
        secret: Option<String>,
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
    name: Option<String>,
    internal: bool,
    exact: bool,
    no_regex: bool,
    regex: Option<regex::Regex>,
    target: Target,
    strip_prefix: bool,
    add_headers: Vec<(HeaderName, String)>,
    remove_headers: Vec<HeaderName>,
    hide_headers: Vec<HeaderName>,
    pass_headers: Vec<HeaderName>,
    proxy_redirect: Vec<(String, String)>,
    cookie_domain: Vec<(String, String)>,
    cookie_path: Vec<(String, String)>,
    request_headers: Vec<(HeaderName, String)>,
    request_remove_headers: Vec<HeaderName>,
    auth_request: Option<String>,
    satisfy: Satisfy,
    secure_link: Option<SecureLink>,
    x_sendfile_root: Option<PathBuf>,
    if_conditions: Vec<CompiledIf>,
    auth: Option<Arc<BasicAuth>>,
    acl: Option<Arc<IpAcl>>,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    send_timeout: Option<Duration>,
    rate: Option<u64>,
    rate_after: u64,
    limiter: Option<Arc<RateLimiter>>,
    rate_key: RequestKey,
    body_limit: Option<usize>,
    error_pages: Vec<ErrorPage>,
    app_permits: Option<Arc<Semaphore>>,
    proxy_permits: Option<Arc<Semaphore>>,
    max_response: Option<usize>,
    fastcgi_pool: Option<Arc<elira_fastcgi::Pool>>,
    fastcgi_mux: Option<Arc<elira_fastcgi::MultiplexPool>>,
    cache: Option<Arc<Cache>>,
    cache_max_item: usize,
    cache_ttl: Option<Duration>,
    cache_key: Option<String>,
    cache_bypass: Vec<String>,
    cache_valid: Vec<CacheValid>,
    access_log: bool,
    access_log_sample: f64,
    client_auth: Option<ClientCertRule>,
    max_upstream_response: Option<usize>,
    expires_secs: Option<u64>,
    etag: bool,
    if_modified_since: bool,
    fastcgi_param: Vec<(String, String)>,
    cgi_param: Vec<(String, String)>,
    scgi_param: Vec<(String, String)>,
    uwsgi_param: Vec<(String, String)>,
}

impl RouteEntry {
    fn cache_ttl_for(&self, status: u16) -> Option<Duration> {
        self.cache_valid
            .iter()
            .find(|valid| valid.statuses.contains(&status))
            .map(|valid| Duration::from_secs(valid.ttl_secs))
            .or(self.cache_ttl)
    }
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
                .find(|entry| entry.name.is_none() && entry.exact && entry.prefix == path)
            {
                return Some(entry);
            }
            let prefix = list.iter().find(|entry| {
                entry.name.is_none() && entry.regex.is_none() && path_matches(&entry.prefix, path)
            });
            if let Some(entry) = prefix {
                if entry.no_regex {
                    return Some(entry);
                }
            }
            if let Some(entry) = list.iter().find(|entry| {
                entry.name.is_none()
                    && path_matches(&entry.prefix, path)
                    && entry
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

    fn pick_named(&self, host: &str, name: &str) -> Option<&RouteEntry> {
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

        lists
            .into_iter()
            .flatten()
            .find(|entry| entry.name.as_deref() == Some(name))
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
        let resolver = build_resolver(cfg);
        let (pools, all_pools) = build_pools(cfg, resolver.clone())?;
        let caches = build_caches(cfg);
        let file_cache = (cfg.limits.open_file_cache > 0).then(|| {
            Arc::new(FileCache::new(
                cfg.limits.open_file_cache,
                Duration::from_secs(cfg.limits.open_file_cache_ttl_secs),
            ))
        });

        let mut entries: Vec<(RouteEntry, Vec<String>)> = Vec::new();
        for route in &cfg.routes {
            entries.push((
                build_route(route, cfg, &pools, &caches, file_cache.as_ref())?,
                route.listeners.clone(),
            ));
        }

        let routers = build_routers(cfg, entries);
        let rewrites = build_rewrites(cfg)?;
        let geos = build_geos(cfg);
        let splits = build_splits(cfg);
        let connect = build_connect(cfg)?;

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
                caches: caches.all,
                cache_flights: Arc::new(CacheFlights::new()),
                limiter,
                trusted_proxies,
                timeout: Duration::from_secs(cfg.limits.upstream_timeout_secs),
                resolver: resolver.clone(),
                connect_timeout: Duration::from_secs(cfg.limits.upstream_connect_timeout_secs),
                send_timeout: match cfg.limits.upstream_send_timeout_secs {
                    0 => None,
                    secs => Some(Duration::from_secs(secs)),
                },
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
        // Cache headers and ETag/If-Modified-Since policy belong to the Files
        // response path.
        if entry.expires_secs.is_some() || !entry.etag || !entry.if_modified_since {
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
                resolver: &self.inner.resolver,
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

#[cfg(test)]
mod unit_tests;
