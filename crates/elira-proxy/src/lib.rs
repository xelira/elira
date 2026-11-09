//! Request forwarding.
//!
//! The rules that matter here are the boring ones: never trust forwarding
//! headers from the client, never forward hop-by-hop headers, and pick an
//! upstream before touching the body.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder};
use bytes::Bytes;
use futures_util::stream::BoxStream;
use futures_util::{Stream, StreamExt, TryStreamExt};
use http::header::{
    HeaderName, HeaderValue, ACCEPT_ENCODING, ALT_SVC, AUTHORIZATION, CACHE_CONTROL, CONNECTION,
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, LOCATION, SERVER, SET_COOKIE,
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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{watch, Semaphore};
use tokio::time::Sleep;
use tokio_util::io::{ReaderStream, StreamReader};

use elira_auth::{BasicAuth, IpAcl};
use elira_cache::Cache;
use elira_config::{Balance, Compression, Config, Health};
use elira_limit::RateLimiter;
use elira_tls::ClientIdentity;
use elira_upstream::{https_connector, TlsOptions};

pub mod files;

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
    router: Router,
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

enum Target {
    Proxy(Arc<Pool>),
    Files(Arc<Files>),
    Redirect {
        status: StatusCode,
        location: HeaderValue,
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

enum ModuleTarget {
    InProcess(Arc<elira_module::Module>),
    Sandbox(Arc<elira_module::ProcessModule>),
}

#[derive(Clone, Debug)]
enum RequestKey {
    Ip,
    Authorization,
    Header(HeaderName),
    Cookie(String),
    Uri,
}

fn parse_request_key(value: Option<&str>) -> RequestKey {
    match value {
        None | Some("ip") => RequestKey::Ip,
        Some("authorization") => RequestKey::Authorization,
        Some("uri") => RequestKey::Uri,
        Some(value) => {
            if let Some(name) = value.strip_prefix("header:") {
                HeaderName::from_bytes(name.as_bytes())
                    .map(RequestKey::Header)
                    .unwrap_or(RequestKey::Ip)
            } else if let Some(name) = value.strip_prefix("cookie:") {
                RequestKey::Cookie(name.to_owned())
            } else {
                RequestKey::Ip
            }
        }
    }
}

/// The value that identifies one bucket. A missing header or cookie falls
/// back to the peer address, so a client cannot dodge the limiter by omitting
/// it.
fn request_key_value<'a>(
    key: &RequestKey,
    headers: &'a HeaderMap,
    peer: std::net::IpAddr,
    path: &'a str,
) -> Cow<'a, str> {
    let header = |name: &HeaderName| headers.get(name).and_then(|value| value.to_str().ok());
    match key {
        RequestKey::Ip => Cow::Owned(peer.to_string()),
        RequestKey::Authorization => header(&AUTHORIZATION)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(peer.to_string())),
        RequestKey::Header(name) => header(name)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(peer.to_string())),
        RequestKey::Cookie(name) => cookie_value(headers, name)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(peer.to_string())),
        RequestKey::Uri => Cow::Borrowed(path),
    }
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    for header in headers.get_all(COOKIE) {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for part in header.split(';') {
            let Some((key, value)) = part.trim().split_once('=') else {
                continue;
            };
            if key.trim() != name {
                continue;
            }
            let value = value.trim();
            return Some(
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value),
            );
        }
    }
    None
}

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

struct RouteEntry {
    label: String,
    prefix: String,
    regex: Option<regex::Regex>,
    target: Target,
    strip_prefix: bool,
    add_headers: Vec<(HeaderName, HeaderValue)>,
    remove_headers: Vec<HeaderName>,
    request_headers: Vec<(HeaderName, HeaderValue)>,
    request_remove_headers: Vec<HeaderName>,
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
    fastcgi_param: Vec<(String, String)>,
    cgi_param: Vec<(String, String)>,
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
            if let Some(entry) = list
                .iter()
                .find(|entry| entry.regex.is_none() && path_matches(&entry.prefix, path))
            {
                return Some(entry);
            }
            if let Some(entry) = list.iter().find(|entry| {
                entry
                    .regex
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(path))
            }) {
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
    passive: Vec<Passive>,
    failures_before_eject: u32,
    eject_for: Duration,
    started: Instant,
    hash_key: RequestKey,
    server_labels: Vec<String>,
    weights: Vec<u32>,
    total_weight: u64,
    weighted: bool,
    retry_on: RetryOn,
    next: AtomicUsize,
    balance: Balance,
    retries: u32,
    scheme: &'static str,
    client: Client<HttpsConnector<HttpConnector>, Body>,
    tls: TlsOptions,
    health_path: Option<String>,
    health_method: Option<String>,
    health_status: Option<Vec<u16>>,
    health_host: Option<String>,
    h2: Option<elira_h2::Pool>,
    h3: Option<elira_h3upstream::Pool>,
}

struct ActiveGuard<'a> {
    active: &'a AtomicUsize,
}

/// Conditions that make an upstream attempt retryable.
struct RetryOn {
    error: bool,
    timeout: bool,
    statuses: Vec<u16>,
}

impl RetryOn {
    fn parse(conditions: &[String]) -> Self {
        if conditions.is_empty() {
            return Self {
                error: true,
                timeout: true,
                statuses: Vec::new(),
            };
        }
        let mut retry = Self {
            error: false,
            timeout: false,
            statuses: Vec::new(),
        };
        for condition in conditions {
            match condition.as_str() {
                "error" => retry.error = true,
                "timeout" => retry.timeout = true,
                _ => {
                    if let Ok(status) = condition.parse::<u16>() {
                        retry.statuses.push(status);
                    }
                }
            }
        }
        retry
    }

    fn status(&self, status: u16) -> bool {
        self.statuses.contains(&status)
    }
}

/// Consecutive transport failures and the end of a passive ejection.
struct Passive {
    failures: AtomicU32,
    ejected_until_ms: AtomicU64,
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Pool {
    fn pick(&self) -> usize {
        self.pick_key(None)
    }

    fn pick_key(&self, key: Option<&str>) -> usize {
        let count = self.servers.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let now = self.now_ms();

        match self.balance {
            Balance::RoundRobin => self.pick_round_robin(start, now),
            Balance::LeastConn => {
                let mut best: Option<(usize, usize, u32)> = None;

                for offset in 0..count {
                    let index = (start + offset) % count;
                    if !self.available(index, now) {
                        continue;
                    }
                    let active = self.active[index].load(Ordering::Relaxed);
                    let weight = self.weights[index];
                    let better = match best {
                        None => true,
                        Some((_, best_active, best_weight)) => {
                            (active as u128) * u128::from(best_weight)
                                < (best_active as u128) * u128::from(weight)
                        }
                    };
                    if better {
                        best = Some((index, active, weight));
                    }
                }

                best.map(|(index, _, _)| index).unwrap_or(start % count)
            }
            Balance::Hash => {
                let Some(key) = key else {
                    return self.pick_round_robin(start, now);
                };
                self.pick_rendezvous(key, now)
            }
        }
    }

    fn pick_round_robin(&self, start: usize, now: u64) -> usize {
        let count = self.servers.len();
        let base = if self.weighted {
            self.weighted_index((start as u64) % self.total_weight)
        } else {
            start % count
        };
        for offset in 0..count {
            let index = (base + offset) % count;
            if self.available(index, now) {
                return index;
            }
        }
        // Everything looks down. Send traffic anyway: a broken probe or a
        // stale ejection must not turn into an outage.
        base
    }

    fn weighted_index(&self, mut slot: u64) -> usize {
        for (index, weight) in self.weights.iter().enumerate() {
            let weight = u64::from(*weight);
            if slot < weight {
                return index;
            }
            slot -= weight;
        }
        0
    }

    fn pick_rendezvous(&self, key: &str, now: u64) -> usize {
        let mut best = None;
        let mut best_score = 0;
        for index in 0..self.servers.len() {
            if !self.available(index, now) {
                continue;
            }
            let score = rendezvous(key, &self.server_labels[index]);
            if best.is_none() || score > best_score {
                best = Some(index);
                best_score = score;
            }
        }

        if let Some(index) = best {
            return index;
        }

        // All servers are unavailable. Pick the same rendezvous winner anyway
        // instead of dropping the affinity completely.
        let mut fallback = 0;
        let mut fallback_score = 0;
        for (index, label) in self.server_labels.iter().enumerate() {
            let score = rendezvous(key, label);
            if index == 0 || score > fallback_score {
                fallback = index;
                fallback_score = score;
            }
        }
        fallback
    }

    fn available(&self, index: usize, now_ms: u64) -> bool {
        self.health[index].load(Ordering::Relaxed)
            && self.passive[index].ejected_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn record_success(&self, index: usize) {
        let passive = &self.passive[index];
        passive.failures.store(0, Ordering::Relaxed);
        if passive.ejected_until_ms.swap(0, Ordering::Relaxed) != 0 {
            tracing::info!(upstream = %self.servers[index], "upstream restored after ejection");
        }
    }

    fn record_failure(&self, index: usize) {
        if self.failures_before_eject == 0 {
            return;
        }
        let passive = &self.passive[index];
        let failures = passive.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures < self.failures_before_eject {
            return;
        }

        passive.failures.store(0, Ordering::Relaxed);
        let until = self
            .now_ms()
            .saturating_add(self.eject_for.as_millis() as u64);
        passive.ejected_until_ms.store(until, Ordering::Relaxed);
        tracing::warn!(
            upstream = %self.servers[index],
            seconds = self.eject_for.as_secs(),
            "upstream ejected after transport failures"
        );
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

    /// Drop cached responses whose host+path starts with `prefix`.
    pub fn purge_cache_prefix(&self, prefix: &str) -> usize {
        match &self.inner.cache {
            Some(cache) => cache.purge_prefix(prefix),
            None => 0,
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
                            "weight": pool.weights[index],
                            "ejected_for_ms": pool.passive[index]
                                .ejected_until_ms
                                .load(Ordering::Relaxed)
                                .saturating_sub(pool.now_ms()),
                        })
                    })
                    .collect();

                serde_json::json!({
                    "name": pool.name,
                    "balance": match pool.balance {
                        Balance::RoundRobin => "round_robin",
                        Balance::LeastConn => "least_conn",
                        Balance::Hash => "hash",
                    },
                    "retries": pool.retries,
                    "http2": pool.h2.as_ref().map(|h2| {
                        let stats = h2.stats();
                        serde_json::json!({
                            "connections": stats.connections,
                            "active_streams": stats.active_streams,
                            "total_connections": stats.total_connections,
                            "queued_streams": stats.queued_streams,
                        })
                    }),
                    "http3": pool.h3.as_ref().map(|h3| {
                        let stats = h3.stats();
                        serde_json::json!({
                            "connections": stats.connections,
                            "active_requests": stats.active_requests,
                            "total_connections": stats.total_connections,
                        })
                    }),
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
            "spooled": self.inner.spooled.load(Ordering::Relaxed),
            "spool_budget": self.inner.spool_budget.total,
            "spool_used": self.inner.spool_budget.used(),
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
            let passive = (0..servers.len())
                .map(|_| Passive {
                    failures: AtomicU32::new(0),
                    ejected_until_ms: AtomicU64::new(0),
                })
                .collect();
            let server_labels = servers.iter().map(ToString::to_string).collect();
            let weights = if up.weights.is_empty() {
                vec![1; servers.len()]
            } else {
                up.weights.clone()
            };
            let total_weight: u64 = weights.iter().map(|weight| u64::from(*weight)).sum();
            let weighted = weights.iter().any(|weight| *weight != 1);

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
                    passive,
                    failures_before_eject: up.failures_before_eject,
                    eject_for: Duration::from_secs(up.eject_secs),
                    started: Instant::now(),
                    hash_key: parse_request_key(up.hash_key.as_deref()),
                    server_labels,
                    weights,
                    total_weight,
                    weighted,
                    retry_on: RetryOn::parse(&up.retry_on),
                    next: AtomicUsize::new(0),
                    balance: up.balance,
                    retries: up.retries,
                    scheme: if up.tls { "https" } else { "http" },
                    client,
                    tls: tls.clone(),
                    health_path: up.health_path.clone(),
                    health_method: up.health_method.clone(),
                    health_status: up.health_expect_status.clone(),
                    health_host: up.health_host.clone(),
                    h3: up.h3_pool.then(|| {
                        elira_h3upstream::Pool::new(elira_h3upstream::PoolConfig {
                            max_connections: 4,
                            connect_timeout: Duration::from_secs(5),
                            tls: tls.clone(),
                        })
                    }),
                    h2: up.h2_pool.then(|| {
                        elira_h2::Pool::new(elira_h2::PoolConfig::new(
                            4,
                            Duration::from_secs(5),
                            tls.clone(),
                        ))
                    }),
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
            } else if let Some(pass) = &route.fastcgi_pass {
                let target =
                    elira_fastcgi::Target::parse(pass).map_err(|err| Error::RouteConfig {
                        host: route.host.clone(),
                        reason: err.to_string(),
                    })?;
                let root = route
                    .fastcgi_root
                    .clone()
                    .ok_or_else(|| Error::RouteConfig {
                        host: route.host.clone(),
                        reason: "fastcgi_pass needs fastcgi_root".to_owned(),
                    })?;
                Target::FastCgi {
                    target,
                    root,
                    index: route.fastcgi_index.clone(),
                }
            } else if let Some(script) = &route.cgi_pass {
                Target::Cgi {
                    script: script.clone(),
                }
            } else if let Some(path) = &route.wasm {
                let module =
                    elira_wasm::WasmModule::load(path).map_err(|err| Error::RouteConfig {
                        host: route.host.clone(),
                        reason: err.to_string(),
                    })?;
                Target::Wasm(Arc::new(module))
            } else if let Some(path) = &route.module {
                // A world-writable module is a privilege escalation waiting
                // to happen: any local user could replace the code.
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(path) {
                    if meta.permissions().mode() & 0o002 != 0 {
                        return Err(Error::RouteConfig {
                            host: route.host.clone(),
                            reason: format!("module {} is world-writable", path.display()),
                        });
                    }
                    let owner = std::os::unix::fs::MetadataExt::uid(&meta);
                    let server = unsafe { libc::geteuid() };
                    if !route.module_sandbox && !module_owner_allowed(owner, server) {
                        return Err(Error::RouteConfig {
                            host: route.host.clone(),
                            reason: format!(
                                "module {} is owned by uid {owner}, not root or the server user",
                                path.display()
                            ),
                        });
                    }
                }
                if route.module_sandbox {
                    let runner = std::env::var_os("ELIRA_MODULE_RUNNER")
                        .map(PathBuf::from)
                        .map(Ok)
                        .unwrap_or_else(std::env::current_exe)
                        .map_err(|err| Error::RouteConfig {
                            host: route.host.clone(),
                            reason: format!("cannot locate the module runner: {err}"),
                        })?;
                    Target::Module(ModuleTarget::Sandbox(Arc::new(
                        elira_module::ProcessModule::new(runner, path.clone()),
                    )))
                } else {
                    let module =
                        elira_module::Module::load(path).map_err(|err| Error::RouteConfig {
                            host: route.host.clone(),
                            reason: err.to_string(),
                        })?;
                    Target::Module(ModuleTarget::InProcess(Arc::new(module)))
                }
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
                Some(root) => error_page_set(root, route.index.clone(), &route.error_pages),
                None => Vec::new(),
            };

            let app_permits = match &target {
                Target::FastCgi { .. } | Target::Cgi { .. } | Target::Module(_) => {
                    Some(Arc::new(Semaphore::new(route.max_concurrent.unwrap_or(16))))
                }
                _ => None,
            };
            let proxy_permits = match &target {
                Target::Proxy(_) => route
                    .max_concurrent
                    .map(|limit| Arc::new(Semaphore::new(limit))),
                _ => None,
            };

            let entry = RouteEntry {
                label: format!(
                    "{}{}",
                    route.host,
                    route
                        .path
                        .as_deref()
                        .or(route.path_regex.as_deref())
                        .unwrap_or_default()
                ),
                prefix: route.path.clone().unwrap_or_default(),
                regex: route
                    .path_regex
                    .as_deref()
                    .and_then(|pattern| regex::Regex::new(pattern).ok()),
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
                request_headers: route
                    .request_headers
                    .iter()
                    .filter_map(|line| parse_header_line(line))
                    .collect(),
                request_remove_headers: route
                    .request_remove_headers
                    .iter()
                    .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
                    .collect(),
                auth,
                acl,
                timeout: route.timeout_secs.map(Duration::from_secs),
                limiter,
                rate_key: parse_request_key(route.rate_key.as_deref()),
                body_limit: route.max_body_bytes,
                error_pages,
                app_permits,
                proxy_permits,
                max_response: route.max_response_bytes,
                cache: route.cache_enabled,
                cache_ttl: route.cache_ttl_secs.map(Duration::from_secs),
                access_log: route.access_log,
                access_log_sample: route.access_log_sample.unwrap_or(cfg.log.sample),
                client_auth: route.client_auth.then(|| ClientCertRule {
                    subject_cn: route.client_cn.clone(),
                    issuer_cn: route.client_issuer_cn.clone(),
                }),
                max_upstream_response: route.max_upstream_response_bytes,
                fastcgi_param: route
                    .fastcgi_param
                    .iter()
                    .filter_map(|line| parse_param(line))
                    .collect(),
                cgi_param: route
                    .cgi_param
                    .iter()
                    .filter_map(|line| parse_param(line))
                    .collect(),
                fastcgi_pool: route.fastcgi_pool_idle.map(|idle| {
                    Arc::new(elira_fastcgi::Pool::new(
                        idle,
                        Duration::from_secs(cfg.limits.fastcgi_pool_idle_secs),
                    ))
                }),
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
        )
        .await
        .map(|fast| fast.file)
    }

    /// Everything the sendfile fast path needs, after the same access checks
    /// as the normal route. `None` means hyper should handle the request.
    pub async fn fast_static(
        &self,
        host: &str,
        path: &str,
        peer: std::net::IpAddr,
        headers: &HeaderMap,
    ) -> Option<FastStatic> {
        let (key, _) = canonical_host(host)?;
        let entry = self.inner.router.pick(&key, path)?;

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
            add_headers: entry.add_headers.clone(),
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

    /// Active requests per upstream pool, for gauges.
    pub fn pool_loads(&self) -> Vec<(String, u64)> {
        self.inner
            .pools
            .iter()
            .map(|pool| {
                let active = pool
                    .active
                    .iter()
                    .map(|counter| counter.load(Ordering::Relaxed) as u64)
                    .sum();
                (pool.name.clone(), active)
            })
            .collect()
    }

    /// Custom HTTP/2 pool statistics per upstream.
    pub fn pool_h2_stats(&self) -> Vec<(String, elira_h2::Stats)> {
        self.inner
            .pools
            .iter()
            .filter_map(|pool| pool.h2.as_ref().map(|h2| (pool.name.clone(), h2.stats())))
            .collect()
    }

    /// Custom HTTP/3 pool statistics per upstream.
    pub fn pool_h3_stats(&self) -> Vec<(String, elira_h3upstream::Stats)> {
        self.inner
            .pools
            .iter()
            .filter_map(|pool| pool.h3.as_ref().map(|h3| (pool.name.clone(), h3.stats())))
            .collect()
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

        match self.forward(req, peer, scheme).await {
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

        if let Some(rule) = &entry.client_auth {
            if !rule.allows(req.extensions().get::<ClientIdentity>()) {
                let mut response = text(StatusCode::FORBIDDEN, "client certificate required");
                self.apply_error_page(&mut response, entry, peer).await;
                return Err(response);
            }
        }

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
                        let mut response =
                            text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
                        self.apply_error_page(&mut response, entry, peer).await;
                        return Err(response);
                    }
                }
            }
        }

        if let Some(limiter) = &entry.limiter {
            let key_path = req
                .uri()
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/");
            let bucket = request_key_value(&entry.rate_key, req.headers(), peer.ip(), key_path);
            if !limiter.check(bucket.as_ref(), Instant::now()) {
                let mut response = text(StatusCode::TOO_MANY_REQUESTS, "too many requests");
                response
                    .headers_mut()
                    .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
                self.apply_error_page(&mut response, entry, peer).await;
                return Err(response);
            }
        }

        if let Some(acl) = &entry.acl {
            if !acl.allows(peer.ip()) {
                let mut response = text(StatusCode::FORBIDDEN, "forbidden");
                self.apply_error_page(&mut response, entry, peer).await;
                return Err(response);
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
                self.apply_error_page(&mut response, entry, peer).await;
                return Err(response);
            }
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
                        return Err(self.body_too_large(entry, peer).await);
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
                    self.apply_error_page(&mut response, entry, peer).await;
                    return Err(response);
                }
            },
            None => None,
        };

        let pool = match &entry.target {
            Target::Proxy(pool) => pool,
            Target::Files(files) => {
                let mut response = files.serve(&req, peer).await;
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
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
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
                self.apply_route(&mut response, entry, &request_id);
                return Ok(response);
            }
            Target::FastCgi { .. } => {
                let mut response = self.serve_fastcgi(req, entry, peer, scheme).await;
                if body_limit_hit.load(Ordering::Relaxed) {
                    return Err(self.body_too_large(entry, peer).await);
                }
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
                self.apply_error_page(&mut response, entry, peer).await;
                self.apply_route(&mut response, entry, &request_id);
                return Ok(response);
            }
            Target::Cgi { .. } => {
                let mut response = self.serve_cgi(req, entry, peer, scheme).await;
                if body_limit_hit.load(Ordering::Relaxed) {
                    return Err(self.body_too_large(entry, peer).await);
                }
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
                self.apply_error_page(&mut response, entry, peer).await;
                self.apply_route(&mut response, entry, &request_id);
                return Ok(response);
            }
            Target::Module(_) | Target::Wasm(_) => {
                let mut response = self.serve_app(req, entry, peer, scheme).await;
                if body_limit_hit.load(Ordering::Relaxed) {
                    return Err(self.body_too_large(entry, peer).await);
                }
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
                self.apply_error_page(&mut response, entry, peer).await;
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
            template.insert(name, value.clone());
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
                        self.apply_route(&mut response, entry, &request_id);
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
                        return Err(self.body_too_large(entry, peer).await);
                    }
                    pool.record_failure(index);
                    tracing::warn!(upstream = %server, error = %err, "upstream request failed");
                    if !pool.retry_on.error || attempt + 1 == attempts {
                        return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                    }
                }
                Err(SendError::Timeout) => {
                    if body_limit_hit.load(Ordering::Relaxed) {
                        return Err(self.body_too_large(entry, peer).await);
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

    /// Streaming FastCGI path: the request body goes to STDIN as it arrives
    /// and the response body leaves through a bounded channel.
    async fn serve_fastcgi(
        &self,
        req: Request<Body>,
        entry: &RouteEntry,
        peer: SocketAddr,
        scheme: &'static str,
    ) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let method = parts.method.as_str();
        let path = parts.uri.path();
        let query = parts.uri.query().unwrap_or_default();
        let host_header = parts
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let (server_name, port) = match canonical_host(host_header) {
            Some((host, forwarded)) => {
                let port = forwarded
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                (host, port)
            }
            None => (String::new(), if scheme == "https" { 443 } else { 80 }),
        };

        let mut params = vec![
            ("GATEWAY_INTERFACE".to_owned(), "CGI/1.1".to_owned()),
            ("SERVER_SOFTWARE".to_owned(), "elira".to_owned()),
            ("SERVER_PROTOCOL".to_owned(), format!("{:?}", parts.version)),
            ("REQUEST_METHOD".to_owned(), method.to_owned()),
            ("REQUEST_URI".to_owned(), parts.uri.to_string()),
            ("QUERY_STRING".to_owned(), query.to_owned()),
            ("SERVER_NAME".to_owned(), server_name),
            ("SERVER_PORT".to_owned(), port.to_string()),
            ("REMOTE_ADDR".to_owned(), peer.ip().to_string()),
            ("REMOTE_PORT".to_owned(), peer.port().to_string()),
        ];
        if let Some(value) = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            params.push(("CONTENT_TYPE".to_owned(), value.to_owned()));
        }
        let content_length = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("0");
        params.push(("CONTENT_LENGTH".to_owned(), content_length.to_owned()));
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name) || *name == CONTENT_TYPE || *name == CONTENT_LENGTH {
                continue;
            }
            if let Ok(value) = value.to_str() {
                params.push((
                    format!(
                        "HTTP_{}",
                        name.as_str().to_ascii_uppercase().replace('-', "_")
                    ),
                    value.to_owned(),
                ));
            }
        }

        let (target, root, index) = match &entry.target {
            Target::FastCgi {
                target,
                root,
                index,
            } => (target, root, index),
            _ => return text(StatusCode::INTERNAL_SERVER_ERROR, "bad target"),
        };
        let script = match application_script(root, path, index) {
            Some(script) => script,
            None => return text(StatusCode::BAD_REQUEST, "bad script path"),
        };
        params.push(("SCRIPT_FILENAME".to_owned(), script.display().to_string()));
        params.push(("SCRIPT_NAME".to_owned(), path.to_owned()));
        params.push(("DOCUMENT_ROOT".to_owned(), root.display().to_string()));
        params.extend(entry.fastcgi_param.iter().cloned());

        let limit = entry.body_limit.unwrap_or(self.inner.max_body_bytes);
        let request_body = body.into_data_stream().boxed();
        let request_body = limit_body(request_body, limit).boxed();
        let timeout = entry.timeout.unwrap_or(self.inner.timeout);

        let fastcgi_pool = entry
            .fastcgi_pool
            .as_deref()
            .unwrap_or(&self.inner.fastcgi_pool);
        let response = match fastcgi_pool
            .execute_stream(
                target,
                params,
                request_body,
                timeout,
                entry.max_response.unwrap_or(self.inner.max_app_response),
            )
            .await
        {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = %err, "FastCGI streaming request failed");
                return text(StatusCode::BAD_GATEWAY, "FastCGI request failed");
            }
        };

        let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut builder = Response::builder().status(status);
        {
            let Some(headers) = builder.headers_mut() else {
                return text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed");
            };
            for (name, value) in &response.headers {
                let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                if is_hop_by_hop(&name) || name == CONTENT_LENGTH {
                    continue;
                }
                if let Ok(value) = HeaderValue::from_str(value) {
                    headers.append(name, value);
                }
            }
            headers.insert(SERVER, HeaderValue::from_static("elira"));
        }
        let streamed =
            StreamBody::new(SharedStream(std::sync::Mutex::new(response.body)).map_ok(Frame::data));
        let body = BodyExt::map_err(streamed, |err| -> BoxError { err }).boxed();
        builder
            .body(body)
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }

    /// Streaming CGI path: stdin and stdout are piped, headers are parsed
    /// before the body is handed to hyper.
    async fn serve_cgi(
        &self,
        req: Request<Body>,
        entry: &RouteEntry,
        peer: SocketAddr,
        scheme: &'static str,
    ) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let method = parts.method.as_str();
        let path = parts.uri.path();
        let query = parts.uri.query().unwrap_or_default();
        let host_header = parts
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let (server_name, port) = match canonical_host(host_header) {
            Some((host, forwarded)) => {
                let port = forwarded
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                (host, port)
            }
            None => (String::new(), if scheme == "https" { 443 } else { 80 }),
        };

        let mut params = vec![
            ("GATEWAY_INTERFACE".to_owned(), "CGI/1.1".to_owned()),
            ("SERVER_SOFTWARE".to_owned(), "elira".to_owned()),
            ("SERVER_PROTOCOL".to_owned(), format!("{:?}", parts.version)),
            ("REQUEST_METHOD".to_owned(), method.to_owned()),
            ("REQUEST_URI".to_owned(), parts.uri.to_string()),
            ("QUERY_STRING".to_owned(), query.to_owned()),
            ("SERVER_NAME".to_owned(), server_name),
            ("SERVER_PORT".to_owned(), port.to_string()),
            ("REMOTE_ADDR".to_owned(), peer.ip().to_string()),
            ("REMOTE_PORT".to_owned(), peer.port().to_string()),
        ];
        if let Some(value) = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            params.push(("CONTENT_TYPE".to_owned(), value.to_owned()));
        }
        let content_length = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("0");
        params.push(("CONTENT_LENGTH".to_owned(), content_length.to_owned()));
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name) || *name == CONTENT_TYPE || *name == CONTENT_LENGTH {
                continue;
            }
            if let Ok(value) = value.to_str() {
                params.push((
                    format!(
                        "HTTP_{}",
                        name.as_str().to_ascii_uppercase().replace('-', "_")
                    ),
                    value.to_owned(),
                ));
            }
        }

        let script = match &entry.target {
            Target::Cgi { script } => script,
            _ => return text(StatusCode::INTERNAL_SERVER_ERROR, "bad target"),
        };
        params.push(("SCRIPT_FILENAME".to_owned(), script.display().to_string()));
        params.push(("SCRIPT_NAME".to_owned(), script.display().to_string()));
        params.push(("PATH_INFO".to_owned(), path.to_owned()));
        params.extend(entry.cgi_param.iter().cloned());

        let limit = entry.body_limit.unwrap_or(self.inner.max_body_bytes);
        let request_body = body.into_data_stream().boxed();
        let request_body = limit_body(request_body, limit).boxed();
        let timeout = entry.timeout.unwrap_or(self.inner.timeout);

        let response = match elira_cgi::execute_stream(
            elira_cgi::StreamRequest {
                script: script.clone(),
                params,
                body: request_body,
                timeout,
            },
            entry.max_response.unwrap_or(self.inner.max_app_response),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = %err, "CGI streaming request failed");
                return text(StatusCode::BAD_GATEWAY, "CGI request failed");
            }
        };

        let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut builder = Response::builder().status(status);
        {
            let Some(headers) = builder.headers_mut() else {
                return text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed");
            };
            for (name, value) in &response.headers {
                let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                if is_hop_by_hop(&name) || name == CONTENT_LENGTH {
                    continue;
                }
                if let Ok(value) = HeaderValue::from_str(value) {
                    headers.append(name, value);
                }
            }
            headers.insert(SERVER, HeaderValue::from_static("elira"));
        }
        let streamed =
            StreamBody::new(SharedStream(std::sync::Mutex::new(response.body)).map_ok(Frame::data));
        let body = BodyExt::map_err(streamed, |err| -> BoxError { err }).boxed();
        builder
            .body(body)
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }

    /// Run a FastCGI, CGI or dynamic-module route. These targets cannot be
    /// streamed into and out of hyper without buffering, so the body is
    /// bounded by the same limit as a normal request.
    async fn serve_app(
        &self,
        req: Request<Body>,
        entry: &RouteEntry,
        peer: SocketAddr,
        scheme: &'static str,
    ) -> Response<Body> {
        let _permit = match &entry.app_permits {
            Some(permits) => match permits.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => return text(StatusCode::SERVICE_UNAVAILABLE, "too many app requests"),
            },
            None => None,
        };
        let (parts, body) = req.into_parts();
        let limit = entry.body_limit.unwrap_or(self.inner.max_body_bytes);
        let body = match BodyExt::collect(body).await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                tracing::warn!(error = %err, "failed to read the application body");
                return text(StatusCode::BAD_GATEWAY, "bad request body");
            }
        };
        if limit > 0 && body.len() > limit {
            return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        }

        let method = parts.method.as_str();
        let path = parts.uri.path();
        let query = parts.uri.query().unwrap_or_default();
        let host_header = parts
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let (server_name, port) = match canonical_host(host_header) {
            Some((host, forwarded)) => {
                let port = forwarded
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                (host, port)
            }
            None => (String::new(), if scheme == "https" { 443 } else { 80 }),
        };

        let mut params = vec![
            ("GATEWAY_INTERFACE".to_owned(), "CGI/1.1".to_owned()),
            ("SERVER_SOFTWARE".to_owned(), "elira".to_owned()),
            ("SERVER_PROTOCOL".to_owned(), format!("{:?}", parts.version)),
            ("REQUEST_METHOD".to_owned(), method.to_owned()),
            ("REQUEST_URI".to_owned(), parts.uri.to_string()),
            ("QUERY_STRING".to_owned(), query.to_owned()),
            ("SERVER_NAME".to_owned(), server_name),
            ("SERVER_PORT".to_owned(), port.to_string()),
            ("REMOTE_ADDR".to_owned(), peer.ip().to_string()),
            ("REMOTE_PORT".to_owned(), peer.port().to_string()),
        ];
        if let Some(value) = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            params.push(("CONTENT_TYPE".to_owned(), value.to_owned()));
        }
        params.push(("CONTENT_LENGTH".to_owned(), body.len().to_string()));
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name) || *name == CONTENT_TYPE || *name == CONTENT_LENGTH {
                continue;
            }
            if let Ok(value) = value.to_str() {
                params.push((
                    format!(
                        "HTTP_{}",
                        name.as_str().to_ascii_uppercase().replace('-', "_")
                    ),
                    value.to_owned(),
                ));
            }
        }

        let timeout = entry.timeout.unwrap_or(self.inner.timeout);
        let result = match &entry.target {
            Target::FastCgi {
                target,
                root,
                index,
            } => {
                let mut script = match application_script(root, path, index) {
                    Some(script) => script,
                    None => return text(StatusCode::BAD_REQUEST, "bad script path"),
                };
                let _ = &mut script;
                params.push(("SCRIPT_FILENAME".to_owned(), script.display().to_string()));
                params.push(("SCRIPT_NAME".to_owned(), path.to_owned()));
                params.push(("DOCUMENT_ROOT".to_owned(), root.display().to_string()));
                match elira_fastcgi::execute(
                    target,
                    &elira_fastcgi::Request {
                        params,
                        body: body.to_vec(),
                    },
                    timeout,
                )
                .await
                {
                    Ok(response) => app_result(response.status, response.headers, response.body),
                    Err(err) => {
                        tracing::warn!(error = %err, "FastCGI request failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            Target::Cgi { .. } => Err(StatusCode::INTERNAL_SERVER_ERROR),
            Target::Module(module) => {
                let request = module_request(&parts, method, path, query, host_header, &body, peer);
                let result = match module {
                    ModuleTarget::InProcess(module) => module.call(&request),
                    ModuleTarget::Sandbox(module) => module.call(&request),
                };
                match result {
                    Ok(response) => app_result(response.status, response.headers, response.body),
                    Err(err) => {
                        tracing::warn!(error = %err, "module request failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            Target::Wasm(module) => {
                let request = module_request(&parts, method, path, query, host_header, &body, peer);
                match module.call(&request) {
                    Ok(response) => app_result(response.status, response.headers, response.body),
                    Err(err) => {
                        tracing::warn!(error = %err, "wasm module request failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
        };

        match result {
            Ok(response) => response,
            Err(status) => text(status, "application request failed"),
        }
    }

    /// Replace a configured error response with a file from the route root.
    /// The original status is kept even if the file itself would be a 200.
    async fn apply_error_page(
        &self,
        response: &mut Response<Body>,
        entry: &RouteEntry,
        peer: SocketAddr,
    ) {
        self.apply_page(response, Some(entry), peer).await;
    }

    async fn apply_global_error_page(&self, response: &mut Response<Body>, peer: SocketAddr) {
        self.apply_page(response, None, peer).await;
    }

    async fn body_too_large(&self, entry: &RouteEntry, peer: SocketAddr) -> Response<Body> {
        let mut response = text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        self.apply_error_page(&mut response, entry, peer).await;
        response
    }

    async fn apply_page(
        &self,
        response: &mut Response<Body>,
        entry: Option<&RouteEntry>,
        peer: SocketAddr,
    ) {
        if response.extensions().get::<ErrorPageApplied>().is_some() {
            return;
        }
        let status = response.status();
        let page = entry
            .and_then(|entry| {
                entry
                    .error_pages
                    .iter()
                    .find(|(code, _, _)| *code == status)
            })
            .or_else(|| {
                self.inner
                    .error_pages
                    .iter()
                    .find(|(code, _, _)| *code == status)
            });
        let Some((_, path, files)) = page else {
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
        // These describe the error itself, not the page body.
        for name in [
            WWW_AUTHENTICATE,
            http::header::RETRY_AFTER,
            http::header::ALLOW,
        ] {
            if let Some(value) = response.headers().get(&name) {
                page.headers_mut().insert(name, value.clone());
            }
        }
        page.extensions_mut().insert(ErrorPageApplied);
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
        client_permit: Option<tokio::sync::OwnedSemaphorePermit>,
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
            let _client_permit = client_permit;
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
struct Probe<'a> {
    path: &'a str,
    method: &'a str,
    host: Option<&'a str>,
    expect: &'a [u16],
    timeout: Duration,
    tls: bool,
    options: &'a TlsOptions,
}

async fn probe_server(server: &ServerAddr, probe: &Probe<'_>) -> bool {
    if let Some(socket) = server.unix() {
        let mut stream =
            match tokio::time::timeout(probe.timeout, UnixStream::connect(socket)).await {
                Ok(Ok(stream)) => stream,
                _ => return false,
            };
        let host = probe.host.unwrap_or("localhost");
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
            probe.method, probe.path
        );
        if tokio::time::timeout(probe.timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        return probe_response(&mut stream, probe.timeout, probe.expect).await;
    }

    let authority = match server.tcp() {
        Some(authority) => authority,
        None => return false,
    };
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = authority
        .port_u16()
        .unwrap_or(if probe.tls { 443 } else { 80 });

    let stream = match tokio::time::timeout(probe.timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };

    let header_host = probe.host.unwrap_or(authority.as_str());
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {header_host}\r\nConnection: close\r\n\r\n",
        probe.method, probe.path
    );
    if probe.tls {
        let config = match elira_upstream::client_config(probe.options) {
            Ok(config) => config,
            Err(_) => return false,
        };
        let name = match probe.options.sni.as_deref().or(Some(host)) {
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
        let mut stream =
            match tokio::time::timeout(probe.timeout, connector.connect(name, stream)).await {
                Ok(Ok(stream)) => stream,
                _ => return false,
            };
        if tokio::time::timeout(probe.timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        probe_response(&mut stream, probe.timeout, probe.expect).await
    } else {
        let mut stream = stream;
        if tokio::time::timeout(probe.timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        probe_response(&mut stream, probe.timeout, probe.expect).await
    }
}

async fn probe_response<S>(stream: &mut S, timeout: Duration, expect: &[u16]) -> bool
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
            let code: u16 = match line.split_whitespace().nth(1).and_then(|c| c.parse().ok()) {
                Some(code) => code,
                None => return false,
            };
            return if expect.is_empty() {
                (200..400).contains(&code)
            } else {
                expect.contains(&code)
            };
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

fn module_owner_allowed(owner: u32, server: u32) -> bool {
    owner == 0 || owner == server
}

fn validators_from_entry(entry: &elira_cache::Entry) -> HeaderMap {
    let mut validators = HeaderMap::new();
    for (name, value) in &entry.headers {
        let target = if name.eq_ignore_ascii_case("etag") {
            Some(http::header::IF_NONE_MATCH)
        } else if name.eq_ignore_ascii_case("last-modified") {
            Some(http::header::IF_MODIFIED_SINCE)
        } else {
            None
        };
        if let (Some(target), Ok(value)) = (target, HeaderValue::from_str(value)) {
            validators.insert(target, value);
        }
    }
    validators
}

fn headers_within_limits(headers: &HeaderMap, max_headers: usize, max_bytes: usize) -> bool {
    if headers.len() > max_headers {
        return false;
    }
    let bytes: usize = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
        .sum();
    bytes <= max_bytes
}

fn rendezvous(key: &str, server: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in key.bytes().chain(std::iter::once(0)).chain(server.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn error_page_set(
    root: std::path::PathBuf,
    index: Vec<String>,
    pages: &[String],
) -> Vec<(StatusCode, String, Arc<Files>)> {
    if pages.is_empty() {
        return Vec::new();
    }
    let files = Arc::new(Files::new(root, index, false, Vec::new(), false, false, 0));
    let mut out = Vec::new();
    for page in pages {
        let mut parts = page.splitn(2, char::is_whitespace);
        let status = parts.next().and_then(|s| s.parse::<u16>().ok());
        let path = parts.next().unwrap_or_default().trim();
        if let Some(status) = status.and_then(|s| StatusCode::from_u16(s).ok()) {
            out.push((status, path.to_owned(), files.clone()));
        }
    }
    out
}

fn parse_param(value: &str) -> Option<(String, String)> {
    let (name, value) = value.split_once(':')?;
    Some((name.trim().to_owned(), value.trim().to_owned()))
}

fn module_request(
    parts: &http::request::Parts,
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    body: &[u8],
    peer: SocketAddr,
) -> elira_module::Request {
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    elira_module::Request {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        host: host.to_owned(),
        headers,
        body: body.to_vec(),
        remote_addr: peer.to_string(),
    }
}

fn application_script(root: &Path, path: &str, index: &str) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    let mut relative = PathBuf::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            segment if segment.contains('\0') || segment.contains('\\') => return None,
            segment => relative.push(segment),
        }
    }
    if decoded.ends_with('/') || relative.as_os_str().is_empty() {
        relative.push(index);
    }
    Some(root.join(relative))
}

fn app_result(
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<Response<Body>, StatusCode> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).map_err(|_| StatusCode::BAD_GATEWAY)?);
    {
        let target = builder
            .headers_mut()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        for (name, value) in headers {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            if is_hop_by_hop(&name)
                || name == CONTENT_LENGTH
                || name == http::header::TRANSFER_ENCODING
            {
                continue;
            }
            if let Ok(value) = HeaderValue::from_str(&value) {
                target.append(name, value);
            }
        }
        target.insert(SERVER, HeaderValue::from_static("elira"));
    }
    let body = Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    builder
        .body(body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// `BoxBody` requires `Sync`; an application response stream is only `Send`.
/// Serialising polling through a mutex gives the type system the guarantee it
/// wants without buffering the body.
struct SharedStream<S>(std::sync::Mutex<S>);

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

fn limit_body(
    stream: elira_fastcgi::BodyStream,
    limit: usize,
) -> BoxStream<'static, Result<Bytes, elira_fastcgi::BoxError>> {
    if limit == 0 {
        return stream.boxed();
    }
    futures_util::stream::unfold(
        (stream, 0usize, limit),
        |(mut stream, total, limit)| async move {
            match stream.next().await {
                Some(Ok(chunk)) => {
                    let total = total + chunk.len();
                    if total > limit {
                        Some((
                            Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "request body too large",
                            )) as elira_fastcgi::BoxError),
                            (stream, total, limit),
                        ))
                    } else {
                        Some((Ok(chunk), (stream, total, limit)))
                    }
                }
                Some(Err(err)) => Some((Err(err), (stream, total, limit))),
                None => None,
            }
        },
    )
    .boxed()
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
