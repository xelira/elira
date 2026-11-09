//! Configuration and validation.
//!
//! Everything here is plain data plus checks. No sockets, no async.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use http::header::{HeaderName, HeaderValue};
use http::uri::Authority;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,

    /// Optional HTTP/1.1 listener on a unix socket. TLS is not applied here.
    #[serde(default)]
    pub listen_unix: Option<PathBuf>,

    /// Accept HTTP/2 with prior knowledge on plain TCP (h2c).
    #[serde(default)]
    pub h2c: bool,

    /// Worker processes sharing the listener via SO_REUSEPORT. One process is
    /// the default; more needs `reuse_port = true`.
    #[serde(default = "Config::default_workers")]
    pub workers: usize,
    #[serde(default)]
    pub limits: Limits,
    /// Send our `Server: elira` header and keep the upstream one.
    #[serde(default = "Config::default_server_header")]
    pub server_header: bool,
    #[serde(default)]
    pub cache: Cache,
    #[serde(default)]
    pub upstream_tls: UpstreamTls,
    #[serde(default)]
    pub acme: Option<Acme>,
    /// Expect a PROXY protocol header on every accepted connection. Enable
    /// only when the listener is reachable solely through a load balancer.
    #[serde(default)]
    pub proxy_protocol: bool,
    /// Let a replacement process bind the same ports. Required for SIGUSR2.
    #[serde(default)]
    pub reuse_port: bool,
    /// Answer simple static GET/HEAD with sendfile(2) before hyper sees the
    /// request. Linux only.
    #[serde(default = "Config::default_sendfile")]
    pub sendfile: bool,
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub log: Log,
    #[serde(default)]
    pub health: Health,
    #[serde(default)]
    pub connect: Connect,
    #[serde(default)]
    pub compression: Compression,
    #[serde(default)]
    pub http3: Option<Http3>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, Deserialize)]
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

    /// Buffer an upstream response up to this many bytes before sending it,
    /// so a slow client does not hold the upstream connection. Zero streams
    /// straight through.
    #[serde(default)]
    pub response_buffer_bytes: usize,
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
            max_response_bytes: Self::default_max_response_bytes(),
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "Health::default_path")]
    pub path: String,

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
            interval_secs: Self::default_interval_secs(),
            timeout_secs: Self::default_timeout_secs(),
        }
    }
}

impl Health {
    fn default_path() -> String {
        "/health".to_owned()
    }

    fn default_interval_secs() -> u64 {
        5
    }

    fn default_timeout_secs() -> u64 {
        2
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Default, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Bind loopback here unless you really mean to expose the counters.
    pub listen: SocketAddr,

    /// htpasswd file guarding `/status` and the mutating admin endpoints.
    #[serde(default)]
    pub auth_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
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
    #[serde(default)]
    pub client_auth: ClientAuthMode,
    /// Extra certificates selected by SNI on the QUIC listener.
    #[serde(default)]
    pub certificates: Vec<ServerCert>,
    /// QUIC idle timeout in seconds.
    #[serde(default = "Http3::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// Allow 0-RTT early data on QUIC.
    #[serde(default)]
    pub early_data: bool,
}

impl Http3 {
    fn default_idle_timeout_secs() -> u64 {
        30
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<String>,

    /// How to choose a server. `round_robin` by default.
    #[serde(default)]
    pub balance: Balance,

    /// Extra attempts on connection errors for bodyless idempotent requests.
    #[serde(default)]
    pub retries: u32,

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
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, Default, Deserialize)]
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Balance {
    #[default]
    RoundRobin,
    LeastConn,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Host to match, case-insensitive. `*` catches everything else, and
    /// `*.example.com` matches any subdomain.
    pub host: String,

    /// Path prefix. The longest matching prefix wins inside a host.
    #[serde(default)]
    pub path: Option<String>,

    /// Regular expression matched against the path after prefix routes.
    #[serde(default)]
    pub path_regex: Option<String>,

    /// Name of an upstream to proxy to. Exactly one target.
    #[serde(default)]
    pub upstream: Option<String>,

    /// Directory to serve files from. Exactly one target.
    #[serde(default)]
    pub root: Option<PathBuf>,

    /// Redirect instead of proxying or serving. Exactly one target.
    #[serde(default)]
    pub redirect: Option<Redirect>,

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

    /// Overrides `limits.max_body_bytes` for this route.
    #[serde(default)]
    pub max_body_bytes: Option<usize>,

    /// Overrides `limits.max_response_bytes` for streamed app responses.
    #[serde(default)]
    pub max_response_bytes: Option<usize>,

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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

    /// Whether to ask clients for a certificate.
    #[serde(default)]
    pub client_auth: ClientAuthMode,

    /// Lowest TLS version offered to clients.
    #[serde(default)]
    pub min_version: TlsVersion,

    /// DER OCSP response to staple for the default certificate. It is read
    /// on startup and on SIGHUP, so an external renewal hook can replace it.
    #[serde(default)]
    pub ocsp: Option<PathBuf>,

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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerCert {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// Exact names or `*.example.com`. An empty list makes the certificate
    /// the default instead of a named one.
    #[serde(default)]
    pub names: Vec<String>,
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    #[default]
    Off,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    #[default]
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Default, Deserialize)]
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

    /// nginx-like template. Overrides `format` when set.
    #[serde(default)]
    pub template: Option<String>,

    /// Also send lines to this Unix datagram socket, usually `/dev/log`.
    #[serde(default)]
    pub syslog: Option<PathBuf>,
}

impl Log {
    fn default_max_bytes() -> usize {
        64 * 1024 * 1024
    }

    fn default_keep() -> usize {
        3
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// Read one config file, expand `${ENV}` and merge every `include`.
fn load_value(path: &Path, depth: usize) -> Result<toml::Value, Error> {
    if depth > 16 {
        return Err(Error::IncludeDepth {
            path: path.display().to_string(),
        });
    }

    let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.display().to_string(),
        source,
    })?;
    let text = substitute_env(&text)?;
    let mut value: toml::Value = toml::from_str(&text).map_err(|source| Error::Parse {
        path: path.display().to_string(),
        source,
    })?;

    let includes = take_includes(&mut value, path)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    for pattern in includes {
        let pattern_path = if Path::new(&pattern).is_absolute() {
            PathBuf::from(&pattern)
        } else {
            base.join(&pattern)
        };
        for included in expand_include(&pattern_path)? {
            let extra = load_value(&included, depth + 1)?;
            merge_values(&mut value, extra);
        }
    }

    Ok(value)
}

fn take_includes(value: &mut toml::Value, path: &Path) -> Result<Vec<String>, Error> {
    let Some(table) = value.as_table_mut() else {
        return Ok(Vec::new());
    };
    let Some(entry) = table.remove("include") else {
        return Ok(Vec::new());
    };

    let bad = || Error::BadInclude {
        path: path.display().to_string(),
        reason: "include must be a string or an array of strings".to_owned(),
    };

    match entry {
        toml::Value::String(value) => Ok(vec![value]),
        toml::Value::Array(values) => values
            .into_iter()
            .map(|value| value.as_str().map(str::to_owned).ok_or_else(bad))
            .collect(),
        _ => Err(bad()),
    }
}

/// Expand a single `*` in the file name. Directories are not globbed; nested
/// wildcards are an error, because silently doing something surprising with
/// include paths is worse than refusing.
fn expand_include(pattern: &Path) -> Result<Vec<PathBuf>, Error> {
    let name = pattern
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::BadInclude {
            path: pattern.display().to_string(),
            reason: "include path has no file name".to_owned(),
        })?;
    if !name.contains('*') {
        return Ok(vec![pattern.to_path_buf()]);
    }
    if name.matches('*').count() != 1 {
        return Err(Error::BadInclude {
            path: pattern.display().to_string(),
            reason: "only one * is allowed in a file name".to_owned(),
        });
    }

    let (prefix, suffix) = name.split_once('*').unwrap_or((name, ""));
    let dir = pattern.parent().unwrap_or_else(|| Path::new("."));
    let entries = std::fs::read_dir(dir).map_err(|source| Error::BadInclude {
        path: pattern.display().to_string(),
        reason: format!("cannot read {}: {source}", dir.display()),
    })?;
    let mut matches = Vec::new();
    for entry in entries.flatten() {
        let candidate = entry.file_name();
        let Some(candidate) = candidate.to_str() else {
            continue;
        };
        if candidate.starts_with(prefix) && candidate.ends_with(suffix) {
            matches.push(entry.path());
        }
    }
    matches.sort();
    if matches.is_empty() {
        return Err(Error::BadInclude {
            path: pattern.display().to_string(),
            reason: "no files matched".to_owned(),
        });
    }
    Ok(matches)
}

fn merge_values(base: &mut toml::Value, extra: toml::Value) {
    match (base, extra) {
        (toml::Value::Table(base), toml::Value::Table(extra)) => {
            for (key, value) in extra {
                match base.get_mut(&key) {
                    Some(existing) => merge_values(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (toml::Value::Array(base), toml::Value::Array(mut extra)) => base.append(&mut extra),
        (base, extra) => *base = extra,
    }
}

/// Replace `${NAME}` and `${NAME:-fallback}`. `$$` is a literal dollar. A
/// missing variable without a fallback is an error, not an empty string.
fn substitute_env(text: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(index) = rest.find('$') {
        out.push_str(&rest[..index]);
        rest = &rest[index..];

        if let Some(after) = rest.strip_prefix("$$") {
            out.push('$');
            rest = after;
            continue;
        }
        let Some(body) = rest.strip_prefix("${") else {
            out.push('$');
            rest = &rest[1..];
            continue;
        };
        let Some(end) = body.find('}') else {
            out.push('$');
            rest = &rest[1..];
            continue;
        };
        let expression = &body[..end];
        let (name, default) = match expression.split_once(":-") {
            Some((name, default)) => (name, Some(default)),
            None => (expression, None),
        };
        if name.is_empty() {
            return Err(Error::EnvMissing {
                name: expression.to_owned(),
            });
        }
        match std::env::var(name) {
            Ok(value) => out.push_str(&value),
            Err(_) => match default {
                Some(value) => out.push_str(value),
                None => {
                    return Err(Error::EnvMissing {
                        name: name.to_owned(),
                    })
                }
            },
        }
        rest = &body[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn parse_param(value: &str) -> Option<(String, String)> {
    let (name, value) = value.split_once(':')?;
    let name = name.trim();
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    Some((name.to_owned(), value.trim().to_owned()))
}

/// Host name without wildcards: letters, digits, dots, hyphens, underscores.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !name.starts_with('.')
        && !name.ends_with('.')
}

impl Config {
    fn default_workers() -> usize {
        1
    }

    fn default_server_header() -> bool {
        true
    }

    fn default_sendfile() -> bool {
        true
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let value = load_value(path, 0)?;
        let cfg: Config = value.try_into().map_err(Error::Toml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse a self-contained config without includes or environment
    /// substitution. `load` is the operator-facing path.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let cfg: Config = toml::from_str(text).map_err(Error::Toml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), Error> {
        if let Some(path) = &self.listen_unix {
            if path.as_os_str().is_empty() {
                return Err(Error::EmptyUnixListen);
            }
        }
        if self.limits.max_header_bytes < 8192 {
            return Err(Error::MaxHeaderBytesTooSmall);
        }
        if self.limits.max_headers == 0 {
            return Err(Error::MaxHeadersZero);
        }
        if self.limits.max_connections == 0 {
            return Err(Error::MaxConnectionsZero);
        }
        if self.limits.connection_drain_secs == 0 {
            return Err(Error::DrainTimeoutZero);
        }
        if self.limits.shutdown_timeout_secs == 0 {
            return Err(Error::ShutdownTimeoutZero);
        }
        if self.workers == 0 || self.workers > 64 {
            return Err(Error::BadWorkers);
        }
        if self.workers > 1 && !self.reuse_port {
            return Err(Error::WorkersNeedReusePort);
        }

        if self.health.enabled {
            if !self.health.path.starts_with('/')
                || self.health.path.chars().any(|c| c.is_control() || c == ' ')
            {
                return Err(Error::BadHealthPath);
            }
            if self.health.interval_secs == 0 {
                return Err(Error::BadHealthInterval);
            }
            if self.health.timeout_secs == 0 {
                return Err(Error::BadHealthTimeout);
            }
        }

        if let Some(acme) = &self.acme {
            if self.tls.is_some() {
                return Err(Error::TlsAndAcme);
            }
            if acme.domains.is_empty() {
                return Err(Error::AcmeNoDomains);
            }
            if acme.contacts.is_empty() {
                return Err(Error::AcmeNoContacts);
            }
            if acme.cache_dir.as_os_str().is_empty() {
                return Err(Error::AcmeNoCacheDir);
            }
            if acme.challenge == AcmeChallenge::Http01
                && acme.http01_listen.is_none()
                && self.listen.port() != 80
            {
                return Err(Error::Http01NeedsListener);
            }
            if acme.challenge == AcmeChallenge::Dns01
                && acme
                    .dns_hook
                    .as_ref()
                    .is_none_or(|path| path.as_os_str().is_empty())
            {
                return Err(Error::DnsHookRequired);
            }
        }

        if let Some(dir) = &self.cache.dir {
            if dir.as_os_str().is_empty() {
                return Err(Error::EmptyCacheDir);
            }
        }
        if self.cache.shared && self.cache.dir.is_none() {
            return Err(Error::SharedCacheWithoutDir);
        }

        if let Some(file) = &self.log.file {
            if file.as_os_str().is_empty() {
                return Err(Error::EmptyLogFile);
            }
            if self.log.max_bytes < 1024 {
                return Err(Error::LogRotationTooSmall);
            }
        }

        if let Some(http3) = &self.http3 {
            if http3.cert.as_os_str().is_empty() {
                return Err(Error::Http3MissingCert);
            }
            if http3.key.as_os_str().is_empty() {
                return Err(Error::Http3MissingKey);
            }
            if http3.idle_timeout_secs == 0 {
                return Err(Error::Http3IdleTimeoutZero);
            }
            if http3.client_auth != ClientAuthMode::Off {
                match &http3.client_ca {
                    Some(path) if !path.as_os_str().is_empty() => {}
                    _ => return Err(Error::Http3ClientCaRequired),
                }
            }
            let mut seen: Vec<String> = Vec::new();
            for (index, entry) in http3.certificates.iter().enumerate() {
                if entry.cert.as_os_str().is_empty() || entry.key.as_os_str().is_empty() {
                    return Err(Error::TlsCertificatePair { index });
                }
                for name in &entry.names {
                    let name = name.trim().to_ascii_lowercase();
                    if name.is_empty() || (!name.starts_with("*.") && !is_plain_name(&name)) {
                        return Err(Error::TlsCertificateName {
                            index,
                            name: name.clone(),
                        });
                    }
                    if seen.contains(&name) {
                        return Err(Error::TlsCertificateNameDuplicate { name: name.clone() });
                    }
                    seen.push(name);
                }
            }
        }

        if self.connect.enabled {
            if self.connect.allow.is_empty() {
                return Err(Error::ConnectEmptyAllow);
            }
            for target in &self.connect.allow {
                let parsed: Authority = target.parse().map_err(|_| Error::BadConnectTarget {
                    target: target.clone(),
                })?;
                if parsed.port_u16().is_none() || target.contains('@') || target.contains('/') {
                    return Err(Error::BadConnectTarget {
                        target: target.clone(),
                    });
                }
            }
        }

        for cidr in &self.limits.trusted_proxies {
            cidr.parse::<ipnet::IpNet>()
                .map_err(|_| Error::BadTrustedProxy { cidr: cidr.clone() })?;
        }

        if self.routes.is_empty() {
            return Err(Error::NoRoutes);
        }

        if let Some(tls) = &self.tls {
            let has_cert = !tls.cert.as_os_str().is_empty();
            let has_key = !tls.key.as_os_str().is_empty();
            if has_cert != has_key {
                return Err(if has_cert {
                    Error::TlsMissingKey
                } else {
                    Error::TlsMissingCert
                });
            }

            let wants_clients = tls.client_auth != ClientAuthMode::Off;
            match &tls.client_ca {
                // Off ignores the CA entirely, so a stale path is harmless.
                Some(path) if wants_clients => {
                    if path.as_os_str().is_empty() {
                        return Err(Error::TlsClientCaEmpty);
                    }
                }
                None if wants_clients => return Err(Error::TlsClientCaRequired),
                _ => {}
            }

            if tls
                .ocsp
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                return Err(Error::EmptyOcspPath);
            }
            if tls
                .ocsp_hook
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty() || tls.ocsp.is_none())
            {
                return Err(Error::OcspHookNeedsFile);
            }
            if tls.ocsp_refresh_secs == 0 && tls.ocsp_hook.is_some() {
                return Err(Error::OcspRefreshZero);
            }

            let has_default = has_cert && has_key;
            if tls.certificates.is_empty() && !has_default {
                return Err(Error::TlsMissingCert);
            }

            let mut seen: Vec<String> = Vec::new();
            for (index, entry) in tls.certificates.iter().enumerate() {
                if entry.cert.as_os_str().is_empty() || entry.key.as_os_str().is_empty() {
                    return Err(Error::TlsCertificatePair { index });
                }
                for name in &entry.names {
                    let name = name.trim().to_ascii_lowercase();
                    if name.is_empty() || (!name.starts_with("*.") && !is_plain_name(&name)) {
                        return Err(Error::TlsCertificateName {
                            index,
                            name: name.clone(),
                        });
                    }
                    if seen.contains(&name) {
                        return Err(Error::TlsCertificateNameDuplicate { name: name.clone() });
                    }
                    seen.push(name);
                }
            }
        }

        let mut names = HashSet::new();
        for up in &self.upstreams {
            if up.name.trim().is_empty() {
                return Err(Error::EmptyUpstreamName);
            }
            if !names.insert(up.name.as_str()) {
                return Err(Error::DuplicateUpstream {
                    name: up.name.clone(),
                });
            }
            if up.servers.is_empty() {
                return Err(Error::EmptyUpstream {
                    name: up.name.clone(),
                });
            }
            if up.retries > 5 {
                return Err(Error::TooManyRetries {
                    name: up.name.clone(),
                    retries: up.retries,
                });
            }
            if up.h3_pool && !up.tls {
                return Err(Error::H3PoolNeedsTls {
                    name: up.name.clone(),
                });
            }
            if up.h3_pool && up.h2_pool {
                return Err(Error::H3AndH2Pool {
                    name: up.name.clone(),
                });
            }
            if up.dns_ttl_secs == Some(0) {
                return Err(Error::BadDnsTtl {
                    name: up.name.clone(),
                });
            }
            if up.tls && up.servers.iter().any(|addr| addr.starts_with("unix:")) {
                return Err(Error::TlsOverUnix {
                    name: up.name.clone(),
                });
            }
            if let Some(path) = &up.health_path {
                if !path.starts_with('/') {
                    return Err(Error::BadUpstreamHealthPath {
                        name: up.name.clone(),
                    });
                }
            }
            for addr in &up.servers {
                check_server(addr).map_err(|_| Error::BadServer {
                    upstream: up.name.clone(),
                    addr: addr.clone(),
                })?;
            }
        }

        let mut seen = HashSet::new();
        for (index, route) in self.routes.iter().enumerate() {
            let host = route.host.trim().to_ascii_lowercase();
            if host.is_empty() {
                return Err(Error::EmptyRouteHost { index });
            }

            // The same host may appear several times with different paths;
            // only an identical pair is ambiguous.
            let discriminator = route
                .path
                .clone()
                .or_else(|| route.path_regex.clone())
                .unwrap_or_default();
            if !seen.insert((host.clone(), discriminator)) {
                return Err(Error::DuplicateRoute {
                    host: route.host.clone(),
                });
            }

            let targets = usize::from(route.upstream.is_some())
                + usize::from(route.root.is_some())
                + usize::from(route.redirect.is_some())
                + usize::from(route.fastcgi_pass.is_some())
                + usize::from(route.cgi_pass.is_some())
                + usize::from(route.module.is_some())
                + usize::from(route.wasm.is_some());
            if targets == 0 {
                return Err(Error::RouteNeedsTarget { index });
            }
            if targets > 1 {
                return Err(Error::RouteHasTwoTargets { index });
            }

            if route.fastcgi_pool_idle.is_some() && route.fastcgi_pass.is_none() {
                return Err(Error::PoolWithoutFastCgi { index });
            }

            if let Some(target) = &route.fastcgi_pass {
                if target.trim().is_empty() {
                    return Err(Error::EmptyFastCgiTarget { index });
                }
                if route
                    .fastcgi_root
                    .as_ref()
                    .is_none_or(|root| root.as_os_str().is_empty())
                {
                    return Err(Error::FastCgiNeedRoot { index });
                }
            }
            if route.fastcgi_index.contains('/') || route.fastcgi_index.contains("..") {
                return Err(Error::BadFastCgiIndex { index });
            }
            for param in route.fastcgi_param.iter().chain(route.cgi_param.iter()) {
                if parse_param(param).is_none() {
                    return Err(Error::BadAppParam {
                        index,
                        param: param.clone(),
                    });
                }
            }
            if let Some(script) = &route.cgi_pass {
                if script.as_os_str().is_empty() || !script.is_absolute() {
                    return Err(Error::BadCgiScript { index });
                }
            }
            if let Some(module) = &route.module {
                if module.as_os_str().is_empty() || !module.is_absolute() {
                    return Err(Error::BadModulePath { index });
                }
            }
            if let Some(wasm) = &route.wasm {
                if wasm.as_os_str().is_empty() || !wasm.is_absolute() {
                    return Err(Error::BadWasmPath { index });
                }
            }
            if route.module_sandbox && route.module.is_none() {
                return Err(Error::SandboxWithoutModule { index });
            }
            if route.max_concurrent == Some(0) {
                return Err(Error::BadConcurrency { index });
            }
            if route.max_response_bytes == Some(0) {
                return Err(Error::BadResponseCap { index });
            }
            if route.cache_ttl_secs == Some(0) {
                return Err(Error::BadRouteCacheTtl { index });
            }

            if let Some(path) = &route.path {
                if !path.starts_with('/') || path.chars().any(char::is_control) {
                    return Err(Error::BadPath {
                        index,
                        path: path.clone(),
                    });
                }
            }
            if route.path.is_some() && route.path_regex.is_some() {
                return Err(Error::PathAndRegex { index });
            }
            if let Some(pattern) = &route.path_regex {
                if regex::Regex::new(pattern).is_err() {
                    return Err(Error::BadPathRegex {
                        index,
                        pattern: pattern.clone(),
                    });
                }
                if route.strip_prefix {
                    return Err(Error::StripPrefixWithRegex { index });
                }
            }

            if route.strip_prefix && route.upstream.is_none() {
                return Err(Error::StripWithoutUpstream { index });
            }

            if route.autoindex && route.root.is_none() {
                return Err(Error::AutoindexWithoutRoot { index });
            }

            if route.timeout_secs == Some(0) {
                return Err(Error::BadRouteTimeout { index });
            }

            if route.requests_per_second == Some(0) {
                return Err(Error::BadRouteRate { index });
            }

            if route.error_root.is_some() && route.error_pages.is_empty() {
                return Err(Error::ErrorRootWithoutPages { index });
            }

            for page in &route.error_pages {
                let mut parts = page.splitn(2, char::is_whitespace);
                let status = parts.next().unwrap_or_default();
                let path = parts.next().unwrap_or_default().trim();
                if status.parse::<u16>().is_err()
                    || !(100..=599).contains(&status.parse::<u16>().unwrap_or(0))
                    || !path.starts_with('/')
                    || path.contains("..")
                {
                    return Err(Error::BadErrorPage {
                        index,
                        page: page.clone(),
                    });
                }
            }

            if let Some(path) = &route.auth_file {
                if path.as_os_str().is_empty() {
                    return Err(Error::EmptyAuthFile { index });
                }
            }

            for value in route.ip_allow.iter().chain(route.ip_deny.iter()) {
                value.parse::<ipnet::IpNet>().map_err(|_| Error::BadAcl {
                    index,
                    value: value.clone(),
                })?;
            }

            for candidate in &route.try_files {
                if candidate.is_empty()
                    || candidate.chars().any(char::is_control)
                    || candidate.contains("..")
                {
                    return Err(Error::BadTryFile {
                        index,
                        candidate: candidate.clone(),
                    });
                }
            }

            if let Some(upstream) = &route.upstream {
                if !names.contains(upstream.as_str()) {
                    return Err(Error::UnknownUpstream {
                        index,
                        upstream: upstream.clone(),
                    });
                }
            }

            if let Some(root) = &route.root {
                if root.as_os_str().is_empty() {
                    return Err(Error::EmptyRoot { index });
                }
                if route.spa && route.index.is_empty() {
                    return Err(Error::SpaNeedsIndex { index });
                }
                for entry in &route.index {
                    if entry.is_empty() || entry.contains('/') || entry.contains("..") {
                        return Err(Error::BadIndexEntry {
                            index,
                            entry: entry.clone(),
                        });
                    }
                }
            }

            if let Some(redirect) = &route.redirect {
                if redirect.to.is_empty() || redirect.to.chars().any(char::is_control) {
                    return Err(Error::BadRedirect { index });
                }
                if !matches!(redirect.status, 301 | 302 | 303 | 307 | 308) {
                    return Err(Error::BadRedirectStatus {
                        index,
                        status: redirect.status,
                    });
                }
            }

            for header in &route.add_headers {
                parse_header_line(header).ok_or_else(|| Error::BadHeader {
                    index,
                    header: header.clone(),
                })?;
            }
            for name in &route.remove_headers {
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| Error::BadHeader {
                    index,
                    header: name.clone(),
                })?;
            }

            if host != "*" {
                if let Some(suffix) = host.strip_prefix('*') {
                    if !suffix.starts_with('.') || suffix.len() < 2 || suffix.contains('*') {
                        return Err(Error::BadWildcardHost { index });
                    }
                } else if host.contains('*') {
                    return Err(Error::BadWildcardHost { index });
                }
            }
        }

        Ok(())
    }
}

fn parse_header_line(line: &str) -> Option<(HeaderName, HeaderValue)> {
    let (name, value) = line.split_once(':')?;
    let name = HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
    let value = HeaderValue::from_str(value.trim()).ok()?;
    Some((name, value))
}

fn check_server(addr: &str) -> Result<(), ()> {
    if let Some(path) = addr.strip_prefix("unix:") {
        if path.is_empty() || path.contains('\0') {
            return Err(());
        }
        return Ok(());
    }
    if addr.contains('@') || addr.contains('/') {
        return Err(());
    }
    let authority: Authority = addr.parse().map_err(|_| ())?;
    if authority.port_u16().is_none() {
        return Err(());
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },

    #[error("{0}")]
    Toml(#[source] toml::de::Error),

    #[error("environment variable {name} is not set")]
    EnvMissing { name: String },

    #[error("include depth exceeded at {path}")]
    IncludeDepth { path: String },

    #[error("include {path}: {reason}")]
    BadInclude { path: String, reason: String },

    #[error("no routes configured")]
    NoRoutes,

    #[error("listen_unix must not be empty")]
    EmptyUnixListen,

    #[error("limits.max_header_bytes must be at least 8192, hyper refuses smaller buffers")]
    MaxHeaderBytesTooSmall,

    #[error("limits.max_headers must be greater than zero")]
    MaxHeadersZero,

    #[error("limits.max_connections must be greater than zero")]
    MaxConnectionsZero,

    #[error("limits.connection_drain_secs must be greater than zero")]
    DrainTimeoutZero,

    #[error("limits.shutdown_timeout_secs must be greater than zero")]
    ShutdownTimeoutZero,

    #[error("workers must be between 1 and 64")]
    BadWorkers,

    #[error("workers > 1 requires reuse_port = true")]
    WorkersNeedReusePort,

    #[error("health.path must start with '/' and contain no spaces or control characters")]
    BadHealthPath,

    #[error("health.interval_secs must be greater than zero")]
    BadHealthInterval,

    #[error("health.timeout_secs must be greater than zero")]
    BadHealthTimeout,

    #[error("http3.idle_timeout_secs must be greater than zero")]
    Http3IdleTimeoutZero,

    #[error("http3.cert must not be empty")]
    Http3MissingCert,

    #[error("http3.key must not be empty")]
    Http3MissingKey,

    #[error("http3.client_ca is required unless http3.client_auth = \"off\"")]
    Http3ClientCaRequired,

    #[error("connect.enabled requires a non-empty connect.allow list")]
    ConnectEmptyAllow,

    #[error("limits.trusted_proxies: \"{cidr}\" is not a CIDR block")]
    BadTrustedProxy { cidr: String },

    #[error("connect target \"{target}\" is not host:port")]
    BadConnectTarget { target: String },

    #[error("tls.cert is required when [tls] is set and must not be empty")]
    TlsMissingCert,

    #[error("tls.key is required when [tls] is set and must not be empty")]
    TlsMissingKey,

    #[error("tls.client_ca is required unless tls.client_auth = \"off\"")]
    TlsClientCaRequired,

    #[error("tls.ocsp must not be empty")]
    EmptyOcspPath,

    #[error("tls.ocsp_hook needs a non-empty tls.ocsp path")]
    OcspHookNeedsFile,

    #[error("tls.ocsp_refresh_secs must be greater than zero")]
    OcspRefreshZero,

    #[error("tls.client_ca must not be empty")]
    TlsClientCaEmpty,

    #[error("tls.certificates[{index}] needs both cert and key")]
    TlsCertificatePair { index: usize },

    #[error("tls.certificates[{index}]: \"{name}\" is not a host name")]
    TlsCertificateName { index: usize, name: String },

    #[error("tls certificate name \"{name}\" is used twice")]
    TlsCertificateNameDuplicate { name: String },

    #[error("upstream name is empty")]
    EmptyUpstreamName,

    #[error("upstream \"{name}\" is defined twice")]
    DuplicateUpstream { name: String },

    #[error("upstream \"{name}\" has no servers")]
    EmptyUpstream { name: String },

    #[error("upstream \"{name}\": h3_pool requires tls = true")]
    H3PoolNeedsTls { name: String },

    #[error("upstream \"{name}\": h3_pool and h2_pool are mutually exclusive")]
    H3AndH2Pool { name: String },

    #[error("upstream \"{name}\": dns_ttl_secs must be greater than zero")]
    BadDnsTtl { name: String },

    #[error("upstream \"{name}\": TLS over a unix socket is not supported")]
    TlsOverUnix { name: String },

    #[error("upstream \"{name}\": health_path must start with /")]
    BadUpstreamHealthPath { name: String },

    #[error("upstream \"{name}\" has {retries} retries, the maximum is 5")]
    TooManyRetries { name: String, retries: u32 },

    #[error("upstream \"{upstream}\": \"{addr}\" is not host:port")]
    BadServer { upstream: String, addr: String },

    #[error("route {index} has an empty host")]
    EmptyRouteHost { index: usize },

    #[error("route for host \"{host}\" is defined twice")]
    DuplicateRoute { host: String },

    #[error("route {index} points to unknown upstream \"{upstream}\"")]
    UnknownUpstream { index: usize, upstream: String },

    #[error("route {index} needs exactly one of `upstream` or `root`")]
    RouteNeedsTarget { index: usize },

    #[error("route {index} has both `upstream` and `root`")]
    RouteHasTwoTargets { index: usize },

    #[error("route {index} has an empty `root`")]
    EmptyRoot { index: usize },

    #[error("route {index}: index file \"{entry}\" must be a plain file name")]
    BadIndexEntry { index: usize, entry: String },

    #[error("route {index}: `spa` needs at least one index file")]
    SpaNeedsIndex { index: usize },

    #[error("route {index}: path \"{path}\" must start with '/'")]
    BadPath { index: usize, path: String },

    #[error("route {index}: path and path_regex are mutually exclusive")]
    PathAndRegex { index: usize },

    #[error("route {index}: \"{pattern}\" is not a valid regular expression")]
    BadPathRegex { index: usize, pattern: String },

    #[error("route {index}: strip_prefix cannot be used with path_regex")]
    StripPrefixWithRegex { index: usize },

    #[error("route {index}: `strip_prefix` needs an upstream")]
    StripWithoutUpstream { index: usize },

    #[error("route {index}: fastcgi_pass must not be empty")]
    EmptyFastCgiTarget { index: usize },

    #[error("route {index}: fastcgi_pass needs fastcgi_root")]
    FastCgiNeedRoot { index: usize },

    #[error("route {index}: fastcgi_index must be a file name")]
    BadFastCgiIndex { index: usize },

    #[error("route {index}: \"{param}\" is not \"NAME: value\"")]
    BadAppParam { index: usize, param: String },

    #[error("route {index}: cgi_pass must be an absolute script path")]
    BadCgiScript { index: usize },

    #[error("route {index}: module must be an absolute path")]
    BadModulePath { index: usize },

    #[error("route {index}: wasm must be an absolute path")]
    BadWasmPath { index: usize },

    #[error("route {index}: module_sandbox needs module")]
    SandboxWithoutModule { index: usize },

    #[error("route {index}: max_concurrent must be greater than zero")]
    BadConcurrency { index: usize },

    #[error("route {index}: max_response_bytes must be greater than zero")]
    BadResponseCap { index: usize },

    #[error("route {index}: cache_ttl_secs must be greater than zero")]
    BadRouteCacheTtl { index: usize },

    #[error("route {index}: fastcgi_pool_idle is only valid on fastcgi routes")]
    PoolWithoutFastCgi { index: usize },

    #[error("route {index}: `autoindex` needs a root")]
    AutoindexWithoutRoot { index: usize },

    #[error("route {index}: auth_file must not be empty")]
    EmptyAuthFile { index: usize },

    #[error("route {index}: timeout_secs must be greater than zero")]
    BadRouteTimeout { index: usize },

    #[error("route {index}: requests_per_second must be greater than zero")]
    BadRouteRate { index: usize },

    #[error("route {index}: error_root needs at least one error_pages entry")]
    ErrorRootWithoutPages { index: usize },

    #[error("route {index}: \"{page}\" is not \"STATUS /path\"")]
    BadErrorPage { index: usize, page: String },

    #[error("route {index}: \"{value}\" is not a CIDR block")]
    BadAcl { index: usize, value: String },

    #[error("[acme] and [tls] cannot both be set")]
    TlsAndAcme,

    #[error("acme.domains must not be empty")]
    AcmeNoDomains,

    #[error("acme.contacts must not be empty")]
    AcmeNoContacts,

    #[error("acme HTTP-01 needs a listener on port 80 or acme.http01_listen")]
    Http01NeedsListener,

    #[error("acme DNS-01 needs a non-empty acme.dns_hook")]
    DnsHookRequired,

    #[error("acme.dns_cleanup_hook must not be empty")]
    EmptyDnsCleanupHook,

    #[error("acme.cache_dir must not be empty")]
    AcmeNoCacheDir,

    #[error("cache.dir must not be empty")]
    EmptyCacheDir,

    #[error("cache.shared needs cache.dir")]
    SharedCacheWithoutDir,

    #[error("log.file must not be empty")]
    EmptyLogFile,

    #[error("log.max_bytes must be at least 1024")]
    LogRotationTooSmall,

    #[error("route {index}: try_files entry \"{candidate}\" is empty or unsafe")]
    BadTryFile { index: usize, candidate: String },

    #[error("route {index}: redirect target is empty or contains control characters")]
    BadRedirect { index: usize },

    #[error("route {index}: redirect status {status} is not 301, 302, 303, 307 or 308")]
    BadRedirectStatus { index: usize, status: u16 },

    #[error("route {index}: \"{header}\" is not a `Name: value` header")]
    BadHeader { index: usize, header: String },

    #[error("route {index}: host wildcard must look like `*.example.com`")]
    BadWildcardHost { index: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
"#;

    #[test]
    fn parses_minimal() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.limits.max_headers, 64);
    }

    #[test]
    fn defaults_log_to_text_and_tls_to_none() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert_eq!(cfg.log.format, LogFormat::Text);
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn parses_tls_and_json_log() {
        let text = format!(
            "{MINIMAL}\n[tls]\ncert = \"/etc/elira/cert.pem\"\nkey = \"/etc/elira/key.pem\"\n\n[log]\nformat = \"json\"\n"
        );
        let cfg = Config::parse(&text).expect("valid config");
        let tls = cfg.tls.expect("tls section");
        assert_eq!(tls.cert, PathBuf::from("/etc/elira/cert.pem"));
        assert_eq!(tls.key, PathBuf::from("/etc/elira/key.pem"));
        assert_eq!(cfg.log.format, LogFormat::Json);
    }

    #[test]
    fn rejects_tls_without_key() {
        let text = format!("{MINIMAL}\n[tls]\ncert = \"/etc/elira/cert.pem\"\n");
        assert!(matches!(Config::parse(&text), Err(Error::TlsMissingKey)));
    }

    #[test]
    fn rejects_tls_with_empty_cert() {
        let text = format!("{MINIMAL}\n[tls]\ncert = \"\"\nkey = \"/etc/elira/key.pem\"\n");
        assert!(matches!(Config::parse(&text), Err(Error::TlsMissingCert)));
    }

    #[test]
    fn rejects_unknown_log_format() {
        let text = format!("{MINIMAL}\n[log]\nformat = \"xml\"\n");
        let err = Config::parse(&text).expect_err("unknown format");
        let msg = err.to_string();
        assert!(msg.contains("text"), "{msg}");
        assert!(msg.contains("json"), "{msg}");
    }

    #[test]
    fn rejects_unknown_field() {
        let text = format!("{MINIMAL}\nnonsense = 1\n");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_route_to_unknown_upstream() {
        let text = MINIMAL.replace("upstream = \"app\"", "upstream = \"nope\"");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::UnknownUpstream { .. })
        ));
    }

    #[test]
    fn rejects_server_without_port() {
        let text = MINIMAL.replace("127.0.0.1:3000", "127.0.0.1");
        assert!(matches!(Config::parse(&text), Err(Error::BadServer { .. })));
    }

    #[test]
    fn rejects_duplicate_host() {
        let text = format!("{MINIMAL}\n[[routes]]\nhost = \"*\"\nupstream = \"app\"\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::DuplicateRoute { .. })
        ));
    }

    #[test]
    fn allows_one_host_with_several_paths() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
path = "/api"
upstream = "app"

[[routes]]
host = "*"
upstream = "app"
"#;
        assert!(Config::parse(text).is_ok());
    }

    #[test]
    fn rejects_empty_upstream() {
        let text = MINIMAL.replace(r#"servers = ["127.0.0.1:3000"]"#, "servers = []");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::EmptyUpstream { .. })
        ));
    }

    #[test]
    fn rejects_tiny_header_buffer() {
        // hyper asserts on buffers below 8192, and the assert fires inside
        // every spawned connection. Catch it at load time instead.
        let text = format!("{MINIMAL}\n[limits]\nmax_header_bytes = 1024\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::MaxHeaderBytesTooSmall)
        ));
    }

    #[test]
    fn rejects_bad_health_path() {
        let text = format!("{MINIMAL}\n[health]\nenabled = true\npath = \"health\"\n");
        assert!(matches!(Config::parse(&text), Err(Error::BadHealthPath)));
    }

    #[test]
    fn health_is_disabled_by_default() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert!(!cfg.health.enabled);
        assert_eq!(cfg.health.path, "/health");
        assert_eq!(cfg.limits.idle_timeout_secs, 60);
        assert!(cfg.http3.is_none());
    }

    #[test]
    fn rejects_http3_without_key() {
        let text =
            format!("{MINIMAL}\n[http3]\nlisten = \"127.0.0.1:4433\"\ncert = \"cert.pem\"\n");
        assert!(matches!(Config::parse(&text), Err(Error::Http3MissingKey)));
    }

    #[test]
    fn connect_is_off_by_default() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert!(!cfg.connect.enabled);
    }

    #[test]
    fn connect_needs_targets_when_enabled() {
        let text = format!("{MINIMAL}\n[connect]\nenabled = true\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::ConnectEmptyAllow)
        ));
    }

    #[test]
    fn connect_rejects_target_without_port() {
        let text = format!("{MINIMAL}\n[connect]\nenabled = true\nallow = [\"10.0.0.5\"]\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::BadConnectTarget { .. })
        ));
    }

    #[test]
    fn rejects_a_bad_trusted_proxy_cidr() {
        let text = format!("{MINIMAL}\n[limits]\ntrusted_proxies = [\"10.0.0.0/8\", \"nope\"]\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::BadTrustedProxy { .. })
        ));
    }

    #[test]
    fn compression_is_on_by_default() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert!(cfg.compression.enabled);
        assert_eq!(cfg.compression.min_bytes, 1024);
    }

    #[test]
    fn parses_balance_and_retries() {
        let text = MINIMAL.replace(
            "servers = [\"127.0.0.1:3000\"]",
            "servers = [\"127.0.0.1:3000\"]\nbalance = \"least_conn\"\nretries = 2",
        );
        let cfg = Config::parse(&text).expect("valid config");
        assert_eq!(cfg.upstreams[0].balance, Balance::LeastConn);
        assert_eq!(cfg.upstreams[0].retries, 2);
    }

    #[test]
    fn rejects_unknown_balance() {
        let text = MINIMAL.replace(
            "servers = [\"127.0.0.1:3000\"]",
            "servers = [\"127.0.0.1:3000\"]\nbalance = \"random\"",
        );
        assert!(matches!(Config::parse(&text), Err(Error::Toml(_))));
    }

    #[test]
    fn rejects_too_many_retries() {
        let text = MINIMAL.replace(
            "servers = [\"127.0.0.1:3000\"]",
            "servers = [\"127.0.0.1:3000\"]\nretries = 9",
        );
        assert!(matches!(
            Config::parse(&text),
            Err(Error::TooManyRetries { .. })
        ));
    }

    #[test]
    fn parses_a_static_route() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/var/www"
"#;
        let cfg = Config::parse(text).expect("valid config");
        assert_eq!(cfg.upstreams.len(), 0);
        assert_eq!(
            cfg.routes[0].root.as_deref(),
            Some(std::path::Path::new("/var/www"))
        );
        assert_eq!(cfg.routes[0].index, vec!["index.html".to_owned()]);
    }

    #[test]
    fn rejects_a_route_with_two_targets() {
        let text = format!(
            "{MINIMAL}\n[[routes]]\nhost = \"both.example\"\nupstream = \"app\"\nroot = \"/srv\"\n"
        );
        assert!(matches!(
            Config::parse(&text),
            Err(Error::RouteHasTwoTargets { .. })
        ));
    }

    #[test]
    fn rejects_a_route_without_a_target() {
        let text = format!("{MINIMAL}\n[[routes]]\nhost = \"empty.example\"\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::RouteNeedsTarget { .. })
        ));
    }

    #[test]
    fn rejects_an_index_name_with_a_slash() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/var/www"
index = ["../secret"]
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::BadIndexEntry { .. })
        ));
    }

    #[test]
    fn spa_needs_an_index() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/var/www"
index = []
spa = true
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::SpaNeedsIndex { .. })
        ));
    }

    #[test]
    fn parses_path_wildcard_redirect_and_headers() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*.example.com"
path = "/api"
upstream = "app"
strip_prefix = true
add_headers = ["X-Frame-Options: DENY"]
remove_headers = ["X-Powered-By"]

[[routes]]
host = "old.example.com"
redirect = { to = "https://new.example.com", status = 301 }
"#;
        let cfg = Config::parse(text).expect("valid config");
        assert_eq!(cfg.routes[0].path.as_deref(), Some("/api"));
        assert!(cfg.routes[0].strip_prefix);
        assert_eq!(cfg.routes[0].add_headers.len(), 1);
        assert_eq!(cfg.routes[1].redirect.as_ref().map(|r| r.status), Some(301));
    }

    #[test]
    fn rejects_a_bad_redirect_status() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 200 }
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::BadRedirectStatus { .. })
        ));
    }

    #[test]
    fn rejects_strip_prefix_without_upstream() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv"
strip_prefix = true
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::StripWithoutUpstream { .. })
        ));
    }

    #[test]
    fn rejects_a_path_without_a_leading_slash() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
path = "api"
upstream = "app"
"#;
        assert!(matches!(Config::parse(text), Err(Error::BadPath { .. })));
    }

    #[test]
    fn rejects_a_header_without_a_colon() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
add_headers = ["X-Broken"]
"#;
        assert!(matches!(Config::parse(text), Err(Error::BadHeader { .. })));
    }

    #[test]
    fn rejects_a_malformed_wildcard() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "api.*.example.com"
upstream = "app"
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::BadWildcardHost { .. })
        ));
    }

    #[test]
    fn cache_is_off_by_default() {
        let cfg = Config::parse(MINIMAL).expect("valid config");
        assert!(!cfg.cache.enabled);
        assert_eq!(cfg.cache.ttl_secs, 60);
        assert!(cfg.server_header);
    }

    #[test]
    fn rejects_acme_and_tls_together() {
        let text = r#"
listen = "127.0.0.1:8080"

[tls]
cert = "cert.pem"
key = "key.pem"

[acme]
domains = ["example.com"]
contacts = ["mailto:admin@example.com"]
cache_dir = "/tmp/acme"

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
        assert!(matches!(Config::parse(text), Err(Error::TlsAndAcme)));
    }

    #[test]
    fn parses_try_files_autoindex_and_upstream_tls() {
        let text = r#"
listen = "127.0.0.1:8080"

[upstream_tls]
insecure = true

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
tls = true

[[routes]]
host = "*"
root = "/srv"
try_files = ["$uri", "$uri.html"]
autoindex = true
"#;
        let cfg = Config::parse(text).expect("valid config");
        assert_eq!(cfg.routes[0].try_files.len(), 2);
        assert!(cfg.routes[0].autoindex);
        assert!(cfg.upstreams[0].tls);
        assert!(cfg.upstream_tls.insecure);
    }

    #[test]
    fn rejects_autoindex_without_root() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
autoindex = true
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::AutoindexWithoutRoot { .. })
        ));
    }

    #[test]
    fn parses_a_log_file() {
        let text = format!(
            "{MINIMAL}\n[log]\nfile = \"/var/log/elira/access.log\"\nmax_bytes = 4096\nkeep = 5\n"
        );
        let cfg = Config::parse(&text).expect("valid config");
        assert!(cfg.log.file.is_some());
        assert_eq!(cfg.log.keep, 5);
    }

    #[test]
    fn rejects_a_tiny_log_rotation() {
        let text = format!("{MINIMAL}\n[log]\nfile = \"/tmp/a.log\"\nmax_bytes = 10\n");
        assert!(matches!(
            Config::parse(&text),
            Err(Error::LogRotationTooSmall)
        ));
    }

    #[test]
    fn parses_auth_and_acl() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
auth_file = "/etc/elira/htpasswd"
ip_allow = ["10.0.0.0/8"]
ip_deny = ["10.1.2.3/32"]
"#;
        let cfg = Config::parse(text).expect("valid config");
        assert!(cfg.routes[0].auth_file.is_some());
        assert_eq!(cfg.routes[0].ip_allow.len(), 1);
    }

    #[test]
    fn rejects_a_bad_acl() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
ip_allow = ["10.0.0.0/99"]
"#;
        assert!(matches!(Config::parse(text), Err(Error::BadAcl { .. })));
    }

    #[test]
    fn rejects_a_zero_route_timeout() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
timeout_secs = 0
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::BadRouteTimeout { .. })
        ));
    }

    #[test]
    fn client_auth_needs_a_ca() {
        let text = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
client_auth = "required"

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::TlsClientCaRequired)
        ));
    }

    #[test]
    fn http2_can_be_enabled_for_upstreams() {
        let text = r#"
listen = "127.0.0.1:8080"

[upstream_tls]
http2 = true

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
tls = true

[[routes]]
host = "*"
upstream = "app"
"#;
        let cfg = Config::parse(text).expect("valid config");
        assert!(cfg.upstream_tls.http2);
    }

    #[test]
    fn parses_sni_certificates() {
        let text = r#"
listen = "127.0.0.1:8443"

[tls]
min_version = "tls13"
client_auth = "off"

[[tls.certificates]]
cert = "/etc/elira/a.pem"
key = "/etc/elira/a.key"
names = ["a.example.com", "*.a.example.com"]

[[tls.certificates]]
cert = "/etc/elira/b.pem"
key = "/etc/elira/b.key"
names = ["b.example.com"]

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
        let cfg = Config::parse(text).expect("valid config");
        let tls = cfg.tls.expect("tls");
        assert_eq!(tls.certificates.len(), 2);
        assert_eq!(tls.min_version, TlsVersion::Tls13);
    }

    #[test]
    fn rejects_duplicate_certificate_names() {
        let text = r#"
listen = "127.0.0.1:8443"

[tls]

[[tls.certificates]]
cert = "/etc/elira/a.pem"
key = "/etc/elira/a.key"
names = ["example.com"]

[[tls.certificates]]
cert = "/etc/elira/b.pem"
key = "/etc/elira/b.key"
names = ["example.com"]

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::TlsCertificateNameDuplicate { .. })
        ));
    }

    #[test]
    fn http3_client_auth_needs_a_ca() {
        let text = r#"
listen = "127.0.0.1:8443"

[http3]
listen = "[::]:443"
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
client_auth = "required"

[[routes]]
host = "*"
redirect = { to = "https://example.com", status = 301 }
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::Http3ClientCaRequired)
        ));
    }

    #[test]
    fn parses_per_upstream_overrides_and_route_limits() {
        let text = r#"
listen = "127.0.0.1:8080"

[upstream_tls]
insecure = true
min_version = "tls13"

[[upstreams]]
name = "app"
servers = ["10.0.0.1:8443"]
tls = true
http2 = true
sni = "app.internal"
health_path = "/ready"
tls_insecure = false

[[routes]]
host = "*"
upstream = "app"
requests_per_second = 10
burst = 20
max_body_bytes = 1024
error_pages = ["404 /404.html"]
error_root = "/srv/errors"
"#;
        let cfg = Config::parse(text).expect("valid config");
        let up = &cfg.upstreams[0];
        assert_eq!(up.sni.as_deref(), Some("app.internal"));
        assert_eq!(up.health_path.as_deref(), Some("/ready"));
        assert_eq!(up.http2, Some(true));
        let route = &cfg.routes[0];
        assert_eq!(route.requests_per_second, Some(10));
        assert_eq!(route.error_pages.len(), 1);
    }

    #[test]
    fn rejects_a_bad_error_page() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv/www"
error_pages = ["404 nope"]
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::BadErrorPage { .. })
        ));
    }

    #[test]
    fn rejects_a_zero_route_rate() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv/www"
requests_per_second = 0
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::BadRouteRate { .. })
        ));
    }

    #[test]
    fn accepts_unix_upstreams_and_rejects_tls_over_them() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["unix:/run/app.sock", "127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
"#;
        assert!(Config::parse(text).is_ok());

        let tls = text.replace("name = \"app\"", "name = \"app\"\ntls = true");
        assert!(matches!(
            Config::parse(&tls),
            Err(Error::TlsOverUnix { .. })
        ));
    }

    #[test]
    fn parses_disk_cache_and_stale_window() {
        let text = r#"
listen = "127.0.0.1:8080"

[cache]
enabled = true
ttl_secs = 30
stale_secs = 120
dir = "/var/cache/elira"

[[routes]]
host = "*"
root = "/srv/www"
"#;
        let cfg = Config::parse(text).expect("valid config");
        assert_eq!(cfg.cache.stale_secs, 120);
        assert_eq!(
            cfg.cache.dir.as_deref().map(|p| p.to_str().unwrap()),
            Some("/var/cache/elira")
        );
    }

    #[test]
    fn rejects_a_zero_dns_ttl() {
        let text = r#"
listen = "127.0.0.1:8080"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
dns_ttl_secs = 0

[[routes]]
host = "*"
upstream = "app"
"#;
        assert!(matches!(Config::parse(text), Err(Error::BadDnsTtl { .. })));
    }

    #[test]
    fn http01_needs_a_port_80_listener() {
        let text = r#"
listen = "127.0.0.1:8443"

[acme]
domains = ["example.com"]
contacts = ["mailto:admin@example.com"]
cache_dir = "/tmp/acme"
challenge = "http_01"

[[routes]]
host = "*"
root = "/srv/www"
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::Http01NeedsListener)
        ));

        let with_listener = text.replace(
            "challenge = \"http_01\"",
            "challenge = \"http_01\"\nhttp01_listen = \"0.0.0.0:80\"",
        );
        assert!(Config::parse(&with_listener).is_ok());
    }

    #[test]
    fn regex_routes_are_validated() {
        let base = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
root = "/srv/www"
path_regex = "^(/[a-z]+)/"
"#;
        assert!(Config::parse(base).is_ok());

        let invalid = base.replace("^(/[a-z]+)/", "([");
        assert!(matches!(
            Config::parse(&invalid),
            Err(Error::BadPathRegex { .. })
        ));

        let both = base.replace("root = \"/srv/www\"", "root = \"/srv/www\"\npath = \"/x\"");
        assert!(matches!(
            Config::parse(&both),
            Err(Error::PathAndRegex { .. })
        ));
    }

    #[test]
    fn parses_fastcgi_cgi_and_module_targets() {
        let text = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "php.example"
fastcgi_pass = "unix:/run/php.sock"
fastcgi_root = "/srv/www"
fastcgi_index = "index.php"

[[routes]]
host = "cgi.example"
path = "/cgi"
cgi_pass = "/srv/cgi/hello"

[[routes]]
host = "module.example"
module = "/etc/elira/hello.so"
"#;
        let cfg = Config::parse(text).expect("valid targets");
        assert_eq!(cfg.routes.len(), 3);
        assert_eq!(cfg.routes[0].fastcgi_index, "index.php");
    }

    #[test]
    fn rejects_bad_fastcgi_and_module_targets() {
        let missing_root = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
fastcgi_pass = "127.0.0.1:9000"
"#;
        assert!(matches!(
            Config::parse(missing_root),
            Err(Error::FastCgiNeedRoot { .. })
        ));

        let relative = r#"
listen = "127.0.0.1:8080"

[[routes]]
host = "*"
module = "hello.so"
"#;
        assert!(matches!(
            Config::parse(relative),
            Err(Error::BadModulePath { .. })
        ));
    }

    #[test]
    fn workers_need_reuse_port() {
        let text = r#"
listen = "127.0.0.1:8080"
workers = 2

[[routes]]
host = "*"
root = "/srv/www"
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::WorkersNeedReusePort)
        ));
    }

    #[test]
    fn h2c_is_opt_in() {
        let text = r#"
listen = "127.0.0.1:8080"
h2c = true

[[routes]]
host = "*"
root = "/srv/www"
"#;
        let cfg = Config::parse(text).expect("valid config");
        assert!(cfg.h2c);
    }

    #[test]
    fn loads_includes_and_substitutes_the_environment() {
        let dir = std::env::temp_dir().join(format!("elira-config-inc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("routes")).expect("dir");

        std::env::set_var("ELIRA_TEST_PORT", "18081");
        std::fs::write(
            dir.join("elira.toml"),
            r#"
listen = "127.0.0.1:${ELIRA_TEST_PORT}"
include = ["routes/*.toml"]

[limits]
max_body_bytes = ${ELIRA_TEST_BODY:-4096}
"#,
        )
        .expect("main");
        std::fs::write(
            dir.join("routes/app.toml"),
            r#"
[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]

[[routes]]
host = "*"
upstream = "app"
"#,
        )
        .expect("fragment");

        let cfg = Config::load(&dir.join("elira.toml")).expect("load");
        assert_eq!(cfg.listen.port(), 18081);
        assert_eq!(cfg.limits.max_body_bytes, 4096);
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.upstreams.len(), 1);

        std::env::remove_var("ELIRA_TEST_PORT");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_environment_variable_is_an_error() {
        let dir = std::env::temp_dir().join(format!("elira-config-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(
            dir.join("elira.toml"),
            "listen = \"127.0.0.1:${ELIRA_TEST_MISSING}\"\n",
        )
        .expect("config");

        assert!(matches!(
            Config::load(&dir.join("elira.toml")),
            Err(Error::EnvMissing { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_include_without_matches_is_an_error() {
        let dir = std::env::temp_dir().join(format!("elira-config-incmiss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(
            dir.join("elira.toml"),
            "listen = \"127.0.0.1:8080\"\ninclude = [\"nope/*.toml\"]\n",
        )
        .expect("config");

        assert!(matches!(
            Config::load(&dir.join("elira.toml")),
            Err(Error::BadInclude { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_ocsp_and_app_concurrency() {
        let text = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
ocsp = "/tmp/ocsp.der"

[[routes]]
host = "*"
cgi_pass = "/srv/cgi/app"
max_concurrent = 4
"#;
        let cfg = Config::parse(text).expect("valid config");
        assert_eq!(cfg.routes[0].max_concurrent, Some(4));
        assert!(cfg.tls.expect("tls").ocsp.is_some());
    }

    #[test]
    fn dns01_requires_a_hook() {
        let text = r#"
listen = "127.0.0.1:8443"

[acme]
domains = ["*.example.com"]
contacts = ["mailto:admin@example.com"]
cache_dir = "/tmp/acme"
challenge = "dns_01"

[[routes]]
host = "*"
root = "/srv/www"
"#;
        assert!(matches!(Config::parse(text), Err(Error::DnsHookRequired)));
        let with_hook = text.replace(
            "challenge = \"dns_01\"",
            "challenge = \"dns_01\"\ndns_hook = \"/usr/local/bin/publish-txt\"",
        );
        assert!(Config::parse(&with_hook).is_ok());
    }

    #[test]
    fn ocsp_hook_needs_a_file_and_positive_interval() {
        let base = r#"
listen = "127.0.0.1:8443"

[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
ocsp_hook = "/usr/local/bin/fetch-ocsp"

[[routes]]
host = "*"
root = "/srv/www"
"#;
        assert!(matches!(Config::parse(base), Err(Error::OcspHookNeedsFile)));
        let with_file = base.replace(
            "ocsp_hook = \"/usr/local/bin/fetch-ocsp\"",
            "ocsp = \"/tmp/ocsp.der\"\nocsp_hook = \"/usr/local/bin/fetch-ocsp\"",
        );
        let cfg = Config::parse(&with_file).expect("valid");
        assert_eq!(cfg.tls.expect("tls").ocsp_refresh_secs, 86400);
    }

    #[test]
    fn per_route_response_cap_is_validated() {
        let text = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
cgi_pass = "/srv/cgi/app"
max_response_bytes = 1024
"#;
        let cfg = Config::parse(text).expect("valid");
        assert_eq!(cfg.routes[0].max_response_bytes, Some(1024));

        let zero = text.replace("max_response_bytes = 1024", "max_response_bytes = 0");
        assert!(matches!(
            Config::parse(&zero),
            Err(Error::BadResponseCap { .. })
        ));
    }

    #[test]
    fn per_route_fastcgi_pool_only_applies_to_fastcgi() {
        let base = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
fastcgi_pass = "127.0.0.1:9000"
fastcgi_root = "/srv"
fastcgi_pool_idle = 4
"#;
        let cfg = Config::parse(base).expect("valid");
        assert_eq!(cfg.routes[0].fastcgi_pool_idle, Some(4));

        let wrong = base.replace("fastcgi_pass = \"127.0.0.1:9000\"", "root = \"/srv\"");
        assert!(matches!(
            Config::parse(&wrong),
            Err(Error::PoolWithoutFastCgi { .. }) | Err(Error::RouteHasTwoTargets { .. })
        ));
    }

    #[test]
    fn route_cache_overrides_are_validated() {
        let base = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
root = "/srv/www"
cache_enabled = false
cache_ttl_secs = 30
"#;
        let cfg = Config::parse(base).expect("valid");
        assert_eq!(cfg.routes[0].cache_enabled, Some(false));
        assert_eq!(cfg.routes[0].cache_ttl_secs, Some(30));

        let zero = base.replace("cache_ttl_secs = 30", "cache_ttl_secs = 0");
        assert!(matches!(
            Config::parse(&zero),
            Err(Error::BadRouteCacheTtl { .. })
        ));
    }

    #[test]
    fn http3_idle_timeout_is_positive() {
        let text = r#"
listen = "127.0.0.1:8080"
[http3]
listen = "[::]:443"
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
idle_timeout_secs = 45
[[routes]]
host = "*"
root = "/srv/www"
"#;
        let cfg = Config::parse(text).expect("valid");
        assert_eq!(cfg.http3.expect("http3").idle_timeout_secs, 45);
        let zero = text.replace("idle_timeout_secs = 45", "idle_timeout_secs = 0");
        assert!(matches!(
            Config::parse(&zero),
            Err(Error::Http3IdleTimeoutZero)
        ));
    }

    #[test]
    fn tls_resumption_and_early_data_parse() {
        let text = r#"
listen = "127.0.0.1:8443"
[tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
session_tickets = 4
session_cache = 0
[http3]
listen = "[::]:443"
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
early_data = true
idle_timeout_secs = 15
[[routes]]
host = "*"
root = "/srv/www"
"#;
        let cfg = Config::parse(text).expect("valid");
        let tls = cfg.tls.expect("tls");
        assert_eq!(tls.session_tickets, 4);
        assert_eq!(tls.session_cache, 0);
        let h3 = cfg.http3.expect("http3");
        assert!(h3.early_data);
        assert_eq!(h3.idle_timeout_secs, 15);
    }

    #[test]
    fn shared_cache_needs_a_directory() {
        let text = r#"
listen = "127.0.0.1:8080"
[cache]
enabled = true
shared = true
[[routes]]
host = "*"
root = "/srv/www"
"#;
        assert!(matches!(
            Config::parse(text),
            Err(Error::SharedCacheWithoutDir)
        ));
    }

    #[test]
    fn drain_timeouts_are_configurable_and_positive() {
        let text = r#"
listen = "127.0.0.1:8080"
[limits]
connection_drain_secs = 3
shutdown_timeout_secs = 20
[[routes]]
host = "*"
root = "/srv/www"
"#;
        let cfg = Config::parse(text).expect("valid");
        assert_eq!(cfg.limits.connection_drain_secs, 3);
        assert_eq!(cfg.limits.shutdown_timeout_secs, 20);

        let zero = text.replace("connection_drain_secs = 3", "connection_drain_secs = 0");
        assert!(matches!(Config::parse(&zero), Err(Error::DrainTimeoutZero)));
    }

    #[test]
    fn wasm_routes_need_an_absolute_path() {
        let ok = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
wasm = "/etc/elira/echo.wasm"
"#;
        assert!(Config::parse(ok).is_ok());

        let relative = ok.replace("/etc/elira/echo.wasm", "echo.wasm");
        assert!(matches!(
            Config::parse(&relative),
            Err(Error::BadWasmPath { .. })
        ));
    }

    #[test]
    fn upstream_can_use_the_custom_h2_pool() {
        let text = r#"
listen = "127.0.0.1:8080"
[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
h2_pool = true
[[routes]]
host = "*"
upstream = "app"
"#;
        let cfg = Config::parse(text).expect("valid");
        assert!(cfg.upstreams[0].h2_pool);
    }

    #[test]
    fn h3_pool_needs_tls_and_excludes_h2_pool() {
        let base = r#"
listen = "127.0.0.1:8080"
[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000"]
h3_pool = true
[[routes]]
host = "*"
upstream = "app"
"#;
        assert!(matches!(
            Config::parse(base),
            Err(Error::H3PoolNeedsTls { .. })
        ));
        let tls = base.replace(
            "servers = [\"127.0.0.1:3000\"]",
            "servers = [\"127.0.0.1:3000\"]\ntls = true",
        );
        assert!(Config::parse(&tls).is_ok());
        let both = tls.replace("h3_pool = true", "h3_pool = true\nh2_pool = true");
        assert!(matches!(
            Config::parse(&both),
            Err(Error::H3AndH2Pool { .. })
        ));
    }

    #[test]
    fn app_params_are_validated() {
        let ok = r#"
listen = "127.0.0.1:8080"
[[routes]]
host = "*"
fastcgi_pass = "127.0.0.1:9000"
fastcgi_root = "/srv"
fastcgi_param = ["APP_ENV: production", "FLAG:1"]
"#;
        assert!(Config::parse(ok).is_ok());
        let bad = ok.replace("APP_ENV: production", "bad name: x");
        assert!(matches!(
            Config::parse(&bad),
            Err(Error::BadAppParam { .. })
        ));
    }
}
