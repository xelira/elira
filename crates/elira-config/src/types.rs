//! Configuration data types and their serde defaults.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub listen: SocketAddr,
    /// Name used by `routes.listeners`. Defaults to `listener-N`.
    #[serde(default)]
    pub name: Option<String>,
    /// Terminate TLS on this listener with the shared `[tls]` settings.
    #[serde(default)]
    pub tls: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    pub listen: SocketAddr,
    /// `tcp` (default) or `udp`.
    #[serde(default)]
    pub transport: StreamTransport,
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub balance: Balance,
    /// Terminate TLS on a TCP stream with the shared `[tls]` settings.
    #[serde(default)]
    pub tls: bool,
    #[serde(default = "Stream::default_connect_secs")]
    pub connect_timeout_secs: u64,
    /// Drop an idle TCP tunnel or UDP session after this long. Zero disables.
    #[serde(default = "Stream::default_idle_secs")]
    pub idle_timeout_secs: u64,
}

impl Stream {
    fn default_connect_secs() -> u64 {
        5
    }

    fn default_idle_secs() -> u64 {
        300
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransport {
    #[default]
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    pub pattern: String,
    pub replacement: String,
    #[serde(default)]
    pub flag: RewriteFlag,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteFlag {
    #[default]
    Last,
    Break,
    Redirect,
    Permanent,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Map {
    pub name: String,
    /// Source variable including the leading `$`.
    pub source: String,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub values: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Geo {
    pub name: String,
    #[serde(default)]
    pub default: Option<String>,
    /// Network or address to value.
    pub values: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Split {
    pub name: String,
    /// Source variable including the leading `$`.
    pub source: String,
    pub buckets: Vec<SplitBucket>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SplitBucket {
    /// Percentage of the hash space, 1..100.
    pub percent: u8,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMatch {
    #[default]
    Prefix,
    Exact,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum number of request headers. Guards against header-count floods.
    #[serde(default = "Limits::default_max_headers")]
    pub max_headers: usize,

    /// Read buffer cap. A request with larger headers gets a 431.
    #[serde(default = "Limits::default_max_header_bytes")]
    pub max_header_bytes: usize,

    /// How long to wait for the upstream to answer.
    #[serde(default = "Limits::default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,

    /// How many client connections may be open at once.
    #[serde(default = "Limits::default_max_connections")]
    pub max_connections: usize,

    /// Close a keep-alive connection after this many seconds without a
    /// request. Zero disables the timer.
    #[serde(default = "Limits::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// Reject a request whose Content-Length exceeds this. Zero means no limit.
    /// A chunked body is not checked here.
    #[serde(default)]
    pub max_body_bytes: usize,

    /// Token bucket per client IP. Zero disables the limiter.
    #[serde(default)]
    pub requests_per_second: u32,

    /// Bucket depth. Zero means the same as `requests_per_second`.
    #[serde(default)]
    pub burst: u32,

    /// Peers allowed to supply X-Forwarded-For. Anything else has its
    /// forwarding headers replaced.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// Abort a client that stops sending a request body for this long. Zero
    /// disables the check.
    #[serde(default = "Limits::default_body_timeout_secs")]
    pub request_body_timeout_secs: u64,

    /// Abort an upstream that stops sending its response body for this long.
    #[serde(default = "Limits::default_body_timeout_secs")]
    pub upstream_body_timeout_secs: u64,

    /// Let an in-flight connection finish during shutdown.
    #[serde(default = "Limits::default_drain_timeout_secs")]
    pub connection_drain_secs: u64,

    /// Overall wait for the listener to stop before logging a warning.
    #[serde(default = "Limits::default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,

    /// Close an idle websocket or CONNECT tunnel. Zero disables the check.
    #[serde(default = "Limits::default_websocket_idle_secs")]
    pub websocket_idle_secs: u64,

    /// Idle FastCGI connections kept per backend.
    #[serde(default = "Limits::default_fastcgi_pool_idle")]
    pub fastcgi_pool_idle: usize,

    /// Drop an idle FastCGI connection after this many seconds.
    #[serde(default = "Limits::default_fastcgi_pool_ttl")]
    pub fastcgi_pool_idle_secs: u64,

    /// Hard cap on a streamed application response body.
    #[serde(default = "Limits::default_max_response_bytes")]
    pub max_response_bytes: usize,

    /// Refuse a proxied upstream response larger than this. Zero disables.
    #[serde(default)]
    pub max_upstream_response_bytes: usize,

    /// Buffer a request body up to this many bytes in memory before
    /// forwarding. Zero disables request buffering.
    #[serde(default)]
    pub request_buffer_bytes: usize,

    /// Spool a request body up to this many bytes to a temporary file so the
    /// client connection is free while the upstream reads it.
    #[serde(default)]
    pub request_spool_bytes: usize,

    /// Buffer an upstream response up to this many bytes before sending it,
    /// so a slow client does not hold the upstream connection. Zero streams
    /// straight through.
    #[serde(default)]
    pub response_buffer_bytes: usize,

    /// Spool an upstream response up to this many bytes to a temporary file,
    /// freeing the upstream connection before the client drains it. Zero
    /// disables disk spooling.
    #[serde(default)]
    pub response_spool_bytes: usize,

    /// Total bytes that may be held in spool files at once. Zero means no
    /// global cap. A response that does not fit streams instead of waiting.
    #[serde(default)]
    pub spool_budget_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_headers: Self::default_max_headers(),
            max_header_bytes: Self::default_max_header_bytes(),
            upstream_timeout_secs: Self::default_upstream_timeout_secs(),
            max_connections: Self::default_max_connections(),
            idle_timeout_secs: Self::default_idle_timeout_secs(),
            max_body_bytes: 0,
            requests_per_second: 0,
            burst: 0,
            trusted_proxies: Vec::new(),
            request_body_timeout_secs: Self::default_body_timeout_secs(),
            upstream_body_timeout_secs: Self::default_body_timeout_secs(),
            websocket_idle_secs: Self::default_websocket_idle_secs(),
            connection_drain_secs: Self::default_drain_timeout_secs(),
            shutdown_timeout_secs: Self::default_shutdown_timeout_secs(),
            response_buffer_bytes: 0,
            request_buffer_bytes: 0,
            request_spool_bytes: 0,
            response_spool_bytes: 0,
            spool_budget_bytes: 0,
            max_response_bytes: Self::default_max_response_bytes(),
            max_upstream_response_bytes: 0,
            fastcgi_pool_idle: Self::default_fastcgi_pool_idle(),
            fastcgi_pool_idle_secs: Self::default_fastcgi_pool_ttl(),
        }
    }
}

impl Limits {
    fn default_max_headers() -> usize {
        64
    }

    fn default_max_header_bytes() -> usize {
        16 * 1024
    }

    fn default_upstream_timeout_secs() -> u64 {
        30
    }

    fn default_max_connections() -> usize {
        1024
    }

    fn default_idle_timeout_secs() -> u64 {
        60
    }

    fn default_body_timeout_secs() -> u64 {
        30
    }

    fn default_websocket_idle_secs() -> u64 {
        3600
    }

    fn default_drain_timeout_secs() -> u64 {
        5
    }

    fn default_shutdown_timeout_secs() -> u64 {
        15
    }

    fn default_max_response_bytes() -> usize {
        64 * 1024 * 1024
    }

    fn default_fastcgi_pool_idle() -> usize {
        16
    }

    fn default_fastcgi_pool_ttl() -> u64 {
        30
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "Health::default_path")]
    pub path: String,

    /// Request method for the probe. Only GET and HEAD are accepted.
    #[serde(default = "Health::default_method")]
    pub method: String,

    /// Status codes that count as healthy. Empty means any 2xx or 3xx.
    #[serde(default)]
    pub expect_status: Vec<u16>,

    /// Host header for the probe. Defaults to the upstream authority.
    #[serde(default)]
    pub host: Option<String>,

    #[serde(default = "Health::default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default = "Health::default_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            enabled: false,
            path: Self::default_path(),
            method: Self::default_method(),
            expect_status: Vec::new(),
            host: None,
            interval_secs: Self::default_interval_secs(),
            timeout_secs: Self::default_timeout_secs(),
        }
    }
}

impl Health {
    fn default_path() -> String {
        "/health".to_owned()
    }

    fn default_method() -> String {
        "GET".to_owned()
    }

    fn default_interval_secs() -> u64 {
        5
    }

    fn default_timeout_secs() -> u64 {
        2
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Compression {
    #[serde(default = "Compression::default_enabled")]
    pub enabled: bool,

    /// Do not bother compressing bodies smaller than this.
    #[serde(default = "Compression::default_min_bytes")]
    pub min_bytes: usize,
}

impl Default for Compression {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            min_bytes: Self::default_min_bytes(),
        }
    }
}

impl Compression {
    fn default_enabled() -> bool {
        true
    }

    fn default_min_bytes() -> usize {
        1024
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Connect {
    /// Off by default: an open CONNECT proxy is an SSRF pivot, and a reverse
    /// proxy has no reason to offer one.
    #[serde(default)]
    pub enabled: bool,
    /// Exact `host:port` destinations the tunnel may reach.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Bind loopback here unless you really mean to expose the counters.
    pub listen: SocketAddr,

    /// htpasswd file guarding `/status` and the mutating admin endpoints.
    #[serde(default)]
    pub auth_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Http3 {
    pub listen: SocketAddr,
    // Defaults so a missing field names itself in the error instead of
    // surfacing as a bare serde "missing field".
    #[serde(default)]
    pub cert: PathBuf,
    #[serde(default)]
    pub key: PathBuf,
    /// PEM roots for client certificates on the QUIC listener.
    #[serde(default)]
    pub client_ca: Option<PathBuf>,
    /// PEM revocation lists for client certificates on QUIC.
    #[serde(default)]
    pub client_crl: Option<PathBuf>,
    #[serde(default)]
    pub client_auth: ClientAuthMode,
    /// Cipher suites to offer on QUIC, in preference order.
    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,
    /// Key exchange groups to offer on QUIC, in preference order.
    #[serde(default)]
    pub curves: Option<Vec<String>>,
    /// Extra certificates selected by SNI on the QUIC listener.
    #[serde(default)]
    pub certificates: Vec<ServerCert>,
    /// QUIC idle timeout in seconds.
    #[serde(default = "Http3::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// Allow 0-RTT early data on QUIC.
    #[serde(default)]
    pub early_data: bool,

    /// 32-byte ticket key shared by all QUIC workers.
    #[serde(default)]
    pub ticket_key: Option<PathBuf>,
}

impl Http3 {
    fn default_idle_timeout_secs() -> u64 {
        30
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<String>,

    /// Relative weights for `servers`. Empty means every server weighs one.
    #[serde(default)]
    pub weights: Vec<u32>,

    /// How to choose a server. `round_robin` by default.
    #[serde(default)]
    pub balance: Balance,

    /// What identifies a client for `balance = "hash"`: `ip` (default),
    /// `authorization`, `header:NAME`, `cookie:NAME` or `uri`.
    #[serde(default)]
    pub hash_key: Option<String>,

    /// Extra attempts on connection errors for bodyless idempotent requests.
    #[serde(default)]
    pub retries: u32,

    /// Conditions that trigger a retry: `error`, `timeout`, or 5xx status
    /// codes. Empty keeps the default (error and timeout).
    #[serde(default)]
    pub retry_on: Vec<String>,

    /// Connect to the servers with TLS (https).
    #[serde(default)]
    pub tls: bool,

    /// Server name for certificate validation and SNI. Needed when `servers`
    /// contains an IP address but the certificate is issued to a name.
    #[serde(default)]
    pub sni: Option<String>,

    /// Overrides `health.path` for this upstream.
    #[serde(default)]
    pub health_path: Option<String>,

    /// Overrides `health.method` for this upstream.
    #[serde(default)]
    pub health_method: Option<String>,

    /// Overrides `health.expect_status` for this upstream.
    #[serde(default)]
    pub health_expect_status: Option<Vec<u16>>,

    /// Overrides `health.host` for this upstream.
    #[serde(default)]
    pub health_host: Option<String>,

    /// Overrides `[upstream_tls] insecure` for this upstream.
    #[serde(default)]
    pub tls_insecure: Option<bool>,

    /// Overrides `[upstream_tls] ca` for this upstream.
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,

    /// Overrides `[upstream_tls] http2` for this upstream.
    #[serde(default)]
    pub http2: Option<bool>,

    /// Use Elira's own HTTP/2 pool instead of the HTTP/1.1/h2 legacy client.
    /// Clear-text upstreams speak h2c with prior knowledge.
    #[serde(default)]
    pub h2_pool: bool,

    /// Use Elira's HTTP/3 upstream pool. Requires TLS.
    #[serde(default)]
    pub h3_pool: bool,

    /// Cap the lifetime of pooled connections so a DNS change is picked up
    /// within this many seconds. Defaults to 30.
    #[serde(default)]
    pub dns_ttl_secs: Option<u64>,

    /// Eject a server after this many consecutive transport failures. Zero
    /// disables passive ejection.
    #[serde(default)]
    pub failures_before_eject: u32,

    /// How long an ejected server is skipped.
    #[serde(default = "Upstream::default_eject_secs")]
    pub eject_secs: u64,
}

impl Upstream {
    fn default_eject_secs() -> u64 {
        30
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Acme {
    pub domains: Vec<String>,
    pub contacts: Vec<String>,
    pub cache_dir: PathBuf,
    #[serde(default)]
    pub production: bool,

    /// TLS-ALPN-01 is the default and needs port 443. HTTP-01 needs a plain
    /// HTTP listener on port 80 instead.
    #[serde(default)]
    pub challenge: AcmeChallenge,

    /// Dedicated plain HTTP listener for HTTP-01 tokens. Required when the
    /// main listener is TLS or not on port 80.
    #[serde(default)]
    pub http01_listen: Option<SocketAddr>,

    /// Command that publishes a DNS-01 TXT record. Called with DOMAIN,
    /// TXT_NAME, TOKEN and VALUE in the environment.
    #[serde(default)]
    pub dns_hook: Option<PathBuf>,

    /// Optional command that removes the TXT record after validation. It gets
    /// the same environment plus ACTION=cleanup.
    #[serde(default)]
    pub dns_cleanup_hook: Option<PathBuf>,

    /// Seconds to wait after the hook before asking the CA to validate.
    #[serde(default = "Acme::default_dns_propagation_secs")]
    pub dns_propagation_secs: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeChallenge {
    #[default]
    TlsAlpn01,
    #[serde(rename = "http_01")]
    Http01,
    #[serde(rename = "dns_01")]
    Dns01,
}

impl Acme {
    fn default_dns_propagation_secs() -> u64 {
        30
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTls {
    /// Skip certificate and hostname verification. Only for internal setups.
    #[serde(default)]
    pub insecure: bool,
    /// Extra PEM roots, added to the system store.
    #[serde(default)]
    pub ca: Option<PathBuf>,
    /// Offer HTTP/2 in ALPN. Upstreams must speak h2 or h1; both are accepted.
    #[serde(default)]
    pub http2: bool,

    /// Lowest TLS version offered to upstreams.
    #[serde(default)]
    pub min_version: TlsVersion,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Balance {
    #[default]
    RoundRobin,
    LeastConn,
    Hash,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Host to match, case-insensitive. `*` catches everything else, and
    /// `*.example.com` matches any subdomain.
    pub host: String,

    /// Restrict the route to named listeners. Empty means every listener.
    #[serde(default)]
    pub listeners: Vec<String>,

    /// Path prefix. The longest matching prefix wins inside a host.
    #[serde(default)]
    pub path: Option<String>,

    /// `prefix` (default) or `exact`, like `location = /path`.
    #[serde(default, rename = "match")]
    pub match_type: RouteMatch,

    /// Skip regex routes when this prefix matches, like `location ^~`.
    #[serde(default)]
    pub no_regex: bool,

    /// Regular expression matched against the path after prefix routes.
    #[serde(default)]
    pub path_regex: Option<String>,

    /// Name of an upstream to proxy to. Exactly one target.
    #[serde(default)]
    pub upstream: Option<String>,

    /// Directory to serve files from. Exactly one target.
    #[serde(default)]
    pub root: Option<PathBuf>,

    /// Serve files from this directory by stripping `path`, nginx-style.
    #[serde(default)]
    pub alias: Option<PathBuf>,

    /// Add `Cache-Control`/`Expires` for static responses.
    #[serde(default)]
    pub expires_secs: Option<u64>,

    /// Emit an `ETag` for static responses. Defaults to true.
    #[serde(default)]
    pub etag: Option<bool>,

    /// Redirect instead of proxying or serving. Exactly one target.
    #[serde(default)]
    pub redirect: Option<Redirect>,

    /// Return a fixed status and body, with variable expansion. Exactly one
    /// target.
    #[serde(default, rename = "return")]
    pub return_response: Option<RouteReturn>,

    /// Conditional returns evaluated before the route target.
    #[serde(default, rename = "if")]
    pub if_conditions: Vec<RouteIf>,

    /// FastCGI target: `host:port` or `unix:/path`.
    #[serde(default)]
    pub fastcgi_pass: Option<String>,

    /// Document root used to build `SCRIPT_FILENAME`.
    #[serde(default)]
    pub fastcgi_root: Option<PathBuf>,

    /// Script appended when the request path ends with `/`.
    #[serde(default = "Route::default_fastcgi_index")]
    pub fastcgi_index: String,

    /// Extra FastCGI params as `NAME: value`.
    #[serde(default)]
    pub fastcgi_param: Vec<String>,

    /// Extra CGI environment variables as `NAME: value`.
    #[serde(default)]
    pub cgi_param: Vec<String>,

    /// CGI script to execute for this route.
    #[serde(default)]
    pub cgi_pass: Option<PathBuf>,

    /// Native dynamic module (`.so`) handling this route.
    #[serde(default)]
    pub module: Option<PathBuf>,

    /// Run the module in a child process instead of in the server process.
    #[serde(default)]
    pub module_sandbox: bool,

    /// WebAssembly module handling this route.
    #[serde(default)]
    pub wasm: Option<PathBuf>,

    /// Concurrent FastCGI/CGI/module requests allowed for this route. Defaults
    /// to 16 for application targets and is ignored for static/proxy routes.
    #[serde(default)]
    pub max_concurrent: Option<usize>,

    /// Files tried for a directory request, in order.
    #[serde(default = "Route::default_index")]
    pub index: Vec<String>,

    /// Serve the first index file for missing paths. For client-side routers.
    #[serde(default)]
    pub spa: bool,

    /// Remove the matched path prefix before forwarding to the upstream.
    #[serde(default)]
    pub strip_prefix: bool,

    /// Candidates tried, in order, when the path does not exist. `$uri` is
    /// replaced with the request path.
    #[serde(default)]
    pub try_files: Vec<String>,

    /// Generate a directory listing when no index file exists.
    #[serde(default)]
    pub autoindex: bool,

    /// htpasswd file with bcrypt hashes. Empty means no authentication.
    #[serde(default)]
    pub auth_file: Option<PathBuf>,

    /// CIDR blocks allowed to reach this route.
    #[serde(default)]
    pub ip_allow: Vec<String>,

    /// CIDR blocks refused on this route; wins over `ip_allow`.
    #[serde(default)]
    pub ip_deny: Vec<String>,

    /// Overrides `limits.upstream_timeout_secs` for this route.
    #[serde(default)]
    pub timeout_secs: Option<u64>,

    /// Overrides `limits.requests_per_second` for this route. Zero inherits.
    #[serde(default)]
    pub requests_per_second: Option<u32>,

    /// Bucket depth for the route limiter. Zero means the same as the rate.
    #[serde(default)]
    pub burst: Option<u32>,

    /// What identifies a client for this route's limiter: `ip` (default),
    /// `authorization`, `header:NAME` or `cookie:NAME`.
    #[serde(default)]
    pub rate_key: Option<String>,

    /// Overrides `limits.max_body_bytes` for this route.
    #[serde(default)]
    pub max_body_bytes: Option<usize>,

    /// Overrides `limits.max_response_bytes` for streamed app responses.
    #[serde(default)]
    pub max_response_bytes: Option<usize>,

    /// Overrides `limits.max_upstream_response_bytes` for proxied responses.
    #[serde(default)]
    pub max_upstream_response_bytes: Option<usize>,

    /// Idle FastCGI connections kept for this route's backend.
    #[serde(default)]
    pub fastcgi_pool_idle: Option<usize>,

    /// Overrides whether this route uses the shared cache.
    #[serde(default)]
    pub cache_enabled: Option<bool>,

    /// Overrides the cache TTL for this route.
    #[serde(default)]
    pub cache_ttl_secs: Option<u64>,

    /// Write this route's requests to the access log.
    #[serde(default = "Route::default_access_log")]
    pub access_log: bool,

    /// Fraction of this route's requests to log. Overrides `log.sample`.
    #[serde(default)]
    pub access_log_sample: Option<f64>,

    /// Require a verified client certificate on this route.
    #[serde(default)]
    pub client_auth: bool,

    /// Require this subject common name.
    #[serde(default)]
    pub client_cn: Option<String>,

    /// Require this issuer common name.
    #[serde(default)]
    pub client_issuer_cn: Option<String>,

    /// Error pages as `STATUS /path.html`, served from `error_root` or `root`.
    #[serde(default)]
    pub error_pages: Vec<String>,

    /// Directory for `error_pages` when the route proxies instead of serving.
    #[serde(default)]
    pub error_root: Option<PathBuf>,

    /// Response headers to set, as `Name: value`.
    #[serde(default)]
    pub add_headers: Vec<String>,

    /// Response headers to drop.
    #[serde(default)]
    pub remove_headers: Vec<String>,

    /// Request headers to set or replace before forwarding, as `Name: value`.
    #[serde(default)]
    pub request_headers: Vec<String>,

    /// Request headers to drop before forwarding.
    #[serde(default)]
    pub request_remove_headers: Vec<String>,
}

impl Route {
    fn default_index() -> Vec<String> {
        vec!["index.html".to_owned()]
    }

    fn default_fastcgi_index() -> String {
        "index.php".to_owned()
    }

    fn default_access_log() -> bool {
        true
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    pub to: String,
    #[serde(default = "Redirect::default_status")]
    pub status: u16,
}

impl Redirect {
    fn default_status() -> u16 {
        302
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteReturn {
    pub status: u16,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteIf {
    /// Variable including the leading `$`.
    pub variable: String,
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default)]
    pub matches: Option<String>,
    #[serde(default, rename = "return")]
    pub return_response: Option<RouteReturn>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "Cache::default_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "Cache::default_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "Cache::default_max_item_bytes")]
    pub max_item_bytes: usize,

    /// Keep response bodies on disk here instead of in memory.
    #[serde(default)]
    pub dir: Option<PathBuf>,

    /// Serve an expired entry for this long while a refresh runs in the
    /// background. Zero disables stale serving.
    #[serde(default)]
    pub stale_secs: u64,

    /// Share `dir` between processes. Entries are read through from disk;
    /// eviction remains per process.
    #[serde(default)]
    pub shared: bool,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_secs: Self::default_ttl_secs(),
            max_bytes: Self::default_max_bytes(),
            max_item_bytes: Self::default_max_item_bytes(),
            dir: None,
            stale_secs: 0,
            shared: false,
        }
    }
}

impl Cache {
    fn default_ttl_secs() -> u64 {
        60
    }

    fn default_max_bytes() -> usize {
        64 * 1024 * 1024
    }

    fn default_max_item_bytes() -> usize {
        1024 * 1024
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// Empty when omitted; `validate` names the missing field instead of
    /// letting serde report a bare "missing field" with no section context.
    #[serde(default)]
    pub cert: PathBuf,
    #[serde(default)]
    pub key: PathBuf,

    /// PEM bundle of roots a client certificate must chain to.
    #[serde(default)]
    pub client_ca: Option<PathBuf>,

    /// PEM bundle of certificate revocation lists for client certificates.
    #[serde(default)]
    pub client_crl: Option<PathBuf>,

    /// Whether to ask clients for a certificate.
    #[serde(default)]
    pub client_auth: ClientAuthMode,

    /// Lowest TLS version offered to clients.
    #[serde(default)]
    pub min_version: TlsVersion,

    /// Cipher suites to offer, in preference order. Omit for the provider's
    /// defaults.
    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,

    /// Key exchange groups to offer, in preference order.
    #[serde(default)]
    pub curves: Option<Vec<String>>,

    /// DER OCSP response to staple for the default certificate. It is read
    /// on startup and on SIGHUP, so an external renewal hook can replace it.
    #[serde(default)]
    pub ocsp: Option<PathBuf>,

    /// 32-byte key used to encrypt TLS tickets. Sharing this file between
    /// workers makes stateless sessions resumable across processes.
    #[serde(default)]
    pub ticket_key: Option<PathBuf>,

    /// Command that refreshes `ocsp` and then triggers a reload.
    #[serde(default)]
    pub ocsp_hook: Option<PathBuf>,

    /// How often `ocsp_hook` runs.
    #[serde(default = "Tls::default_ocsp_refresh_secs")]
    pub ocsp_refresh_secs: u64,

    /// TLS 1.3 session tickets sent after a handshake.
    #[serde(default = "Tls::default_session_tickets")]
    pub session_tickets: usize,

    /// In-memory session cache entries. Zero disables resumption.
    #[serde(default = "Tls::default_session_cache")]
    pub session_cache: usize,

    /// Additional certificates selected by SNI. The `cert`/`key` pair above
    /// stays the default when no name matches.
    #[serde(default)]
    pub certificates: Vec<ServerCert>,
}

/// A certificate and the names it should answer for.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerCert {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// Exact names or `*.example.com`. An empty list makes the certificate
    /// the default instead of a named one.
    #[serde(default)]
    pub names: Vec<String>,
    /// DER OCSP response to staple for this certificate.
    #[serde(default)]
    pub ocsp: Option<PathBuf>,
}

impl Tls {
    fn default_ocsp_refresh_secs() -> u64 {
        24 * 60 * 60
    }

    fn default_session_tickets() -> usize {
        2
    }

    fn default_session_cache() -> usize {
        256
    }
}

/// Client certificate policy for the TLS listener.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    #[default]
    Off,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    #[default]
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[serde(default)]
    pub format: LogFormat,

    /// Append access lines here. Without it they go to stdout via tracing.
    #[serde(default)]
    pub file: Option<PathBuf>,

    /// Rotate after this many bytes.
    #[serde(default = "Log::default_max_bytes")]
    pub max_bytes: usize,

    /// How many rotated files to keep.
    #[serde(default = "Log::default_keep")]
    pub keep: usize,

    /// Fraction of requests to write to the access log. One logs everything.
    #[serde(default = "Log::default_sample")]
    pub sample: f64,

    /// nginx-like template. Overrides `format` when set.
    #[serde(default)]
    pub template: Option<String>,

    /// Also send lines to this Unix datagram socket, usually `/dev/log`.
    #[serde(default)]
    pub syslog: Option<PathBuf>,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            file: None,
            max_bytes: Self::default_max_bytes(),
            keep: Self::default_keep(),
            sample: Self::default_sample(),
            template: None,
            syslog: None,
        }
    }
}

impl Log {
    fn default_sample() -> f64 {
        1.0
    }

    fn default_max_bytes() -> usize {
        64 * 1024 * 1024
    }

    fn default_keep() -> usize {
        3
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl<'de> Deserialize<'de> for LogFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(serde::de::Error::custom(format!(
                "unknown log format \"{other}\", expected \"text\" or \"json\""
            ))),
        }
    }
}
