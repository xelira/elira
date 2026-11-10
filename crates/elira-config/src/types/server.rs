//! Listeners, limits and process-level tuning.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::Balance;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransport {
    #[default]
    Tcp,
    Udp,
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

    /// Time limit for the upstream TCP and TLS handshake.
    #[serde(default = "Limits::default_upstream_connect_timeout_secs")]
    pub upstream_connect_timeout_secs: u64,

    /// Abort an upstream request body that stops making progress for this
    /// long. Zero disables the check.
    #[serde(default)]
    pub upstream_send_timeout_secs: u64,

    /// How many client connections may be open at once.
    #[serde(default = "Limits::default_max_connections")]
    pub max_connections: usize,

    /// Concurrent connections allowed per client IP. Zero disables the limit.
    #[serde(default)]
    pub limit_conn_per_ip: usize,

    /// Close a keep-alive connection after this many requests. Zero disables
    /// the cap.
    #[serde(default = "Limits::default_keepalive_requests")]
    pub keepalive_requests: usize,

    /// Close a keep-alive connection after this many seconds without a
    /// request. Zero disables the timer.
    #[serde(default = "Limits::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// Reject a request whose Content-Length exceeds this. Zero means no limit.
    /// A chunked body is not checked here.
    #[serde(default)]
    pub max_body_bytes: usize,

    /// Throttle every response to this many bytes per second. Zero disables.
    #[serde(default)]
    pub limit_rate: u64,

    /// Send this many bytes of a response before `limit_rate` starts.
    #[serde(default)]
    pub limit_rate_after: u64,

    /// Cache file metadata for up to this many paths. Zero disables the cache.
    #[serde(default)]
    pub open_file_cache: usize,

    /// Metadata lifetime in the open-file cache.
    #[serde(default = "Limits::default_open_file_cache_ttl_secs")]
    pub open_file_cache_ttl_secs: u64,

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

    /// Abort a client that stops sending request headers for this long. Zero
    /// disables the check.
    #[serde(default = "Limits::default_client_header_timeout_secs")]
    pub client_header_timeout_secs: u64,

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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Compression {
    #[serde(default = "Compression::default_enabled")]
    pub enabled: bool,

    /// Do not bother compressing bodies smaller than this.
    #[serde(default = "Compression::default_min_bytes")]
    pub min_bytes: usize,
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

impl Stream {
    fn default_connect_secs() -> u64 {
        5
    }

    fn default_idle_secs() -> u64 {
        300
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_headers: Self::default_max_headers(),
            max_header_bytes: Self::default_max_header_bytes(),
            upstream_timeout_secs: Self::default_upstream_timeout_secs(),
            upstream_connect_timeout_secs: Self::default_upstream_connect_timeout_secs(),
            upstream_send_timeout_secs: 0,
            keepalive_requests: Self::default_keepalive_requests(),
            max_connections: Self::default_max_connections(),
            limit_conn_per_ip: 0,
            idle_timeout_secs: Self::default_idle_timeout_secs(),
            max_body_bytes: 0,
            limit_rate: 0,
            limit_rate_after: 0,
            open_file_cache: 0,
            open_file_cache_ttl_secs: Self::default_open_file_cache_ttl_secs(),
            requests_per_second: 0,
            burst: 0,
            trusted_proxies: Vec::new(),
            request_body_timeout_secs: Self::default_body_timeout_secs(),
            client_header_timeout_secs: Self::default_client_header_timeout_secs(),
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

    fn default_upstream_connect_timeout_secs() -> u64 {
        5
    }

    fn default_max_connections() -> usize {
        1024
    }

    fn default_idle_timeout_secs() -> u64 {
        60
    }

    fn default_keepalive_requests() -> usize {
        1000
    }

    fn default_body_timeout_secs() -> u64 {
        30
    }

    fn default_client_header_timeout_secs() -> u64 {
        30
    }

    fn default_open_file_cache_ttl_secs() -> u64 {
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
