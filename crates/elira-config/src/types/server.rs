use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::Balance;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub listen: SocketAddr,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub tls: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    pub listen: SocketAddr,

    #[serde(default)]
    pub transport: StreamTransport,
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub balance: Balance,

    #[serde(default)]
    pub tls: bool,
    #[serde(default = "Stream::default_connect_secs")]
    pub connect_timeout_secs: u64,

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
    #[serde(default = "Limits::default_max_headers")]
    pub max_headers: usize,

    #[serde(default = "Limits::default_max_header_bytes")]
    pub max_header_bytes: usize,

    #[serde(default = "Limits::default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,

    #[serde(default = "Limits::default_upstream_connect_timeout_secs")]
    pub upstream_connect_timeout_secs: u64,

    #[serde(default)]
    pub upstream_send_timeout_secs: u64,

    #[serde(default = "Limits::default_max_connections")]
    pub max_connections: usize,

    #[serde(default)]
    pub limit_conn_per_ip: usize,

    #[serde(default = "Limits::default_keepalive_requests")]
    pub keepalive_requests: usize,

    #[serde(default = "Limits::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    #[serde(default)]
    pub max_body_bytes: usize,

    #[serde(default)]
    pub limit_rate: u64,

    #[serde(default)]
    pub limit_rate_after: u64,

    #[serde(default)]
    pub open_file_cache: usize,

    #[serde(default = "Limits::default_open_file_cache_ttl_secs")]
    pub open_file_cache_ttl_secs: u64,

    #[serde(default = "Limits::default_open_file_cache_max_file_bytes")]
    pub open_file_cache_max_file_bytes: usize,

    #[serde(default)]
    pub requests_per_second: u32,

    #[serde(default)]
    pub burst: u32,

    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    #[serde(default = "Limits::default_client_header_timeout_secs")]
    pub client_header_timeout_secs: u64,

    #[serde(default = "Limits::default_body_timeout_secs")]
    pub request_body_timeout_secs: u64,

    #[serde(default = "Limits::default_body_timeout_secs")]
    pub upstream_body_timeout_secs: u64,

    #[serde(default = "Limits::default_drain_timeout_secs")]
    pub connection_drain_secs: u64,

    #[serde(default = "Limits::default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,

    #[serde(default = "Limits::default_websocket_idle_secs")]
    pub websocket_idle_secs: u64,

    #[serde(default = "Limits::default_lingering_close")]
    pub lingering_close: bool,

    #[serde(default = "Limits::default_lingering_timeout_secs")]
    pub lingering_timeout_secs: u64,

    #[serde(default)]
    pub reset_timedout_connection: bool,

    #[serde(default = "Limits::default_fastcgi_pool_idle")]
    pub fastcgi_pool_idle: usize,

    #[serde(default = "Limits::default_fastcgi_pool_ttl")]
    pub fastcgi_pool_idle_secs: u64,

    #[serde(default = "Limits::default_max_response_bytes")]
    pub max_response_bytes: usize,

    #[serde(default)]
    pub max_upstream_response_bytes: usize,

    #[serde(default)]
    pub request_buffer_bytes: usize,

    #[serde(default)]
    pub request_spool_bytes: usize,

    #[serde(default)]
    pub response_buffer_bytes: usize,

    #[serde(default)]
    pub response_spool_bytes: usize,

    #[serde(default)]
    pub spool_budget_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Compression {
    #[serde(default = "Compression::default_enabled")]
    pub enabled: bool,

    #[serde(default = "Compression::default_min_bytes")]
    pub min_bytes: usize,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Connect {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Http2 {
    #[serde(default = "Http2::default_max_concurrent_streams")]
    pub max_concurrent_streams: Option<u32>,

    #[serde(default)]
    pub initial_stream_window_size: Option<u32>,

    #[serde(default)]
    pub initial_connection_window_size: Option<u32>,

    #[serde(default)]
    pub max_frame_size: Option<u32>,

    #[serde(default = "Http2::default_keep_alive_interval_secs")]
    pub keep_alive_interval_secs: u64,

    #[serde(default = "Http2::default_keep_alive_timeout_secs")]
    pub keep_alive_timeout_secs: u64,
}

impl Default for Http2 {
    fn default() -> Self {
        Self {
            max_concurrent_streams: Some(128),
            initial_stream_window_size: None,
            initial_connection_window_size: None,
            max_frame_size: None,
            keep_alive_interval_secs: Self::default_keep_alive_interval_secs(),
            keep_alive_timeout_secs: Self::default_keep_alive_timeout_secs(),
        }
    }
}

impl Http2 {
    fn default_max_concurrent_streams() -> Option<u32> {
        Some(128)
    }

    fn default_keep_alive_interval_secs() -> u64 {
        30
    }

    fn default_keep_alive_timeout_secs() -> u64 {
        20
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub listen: SocketAddr,

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
            open_file_cache_max_file_bytes: Self::default_open_file_cache_max_file_bytes(),
            requests_per_second: 0,
            burst: 0,
            trusted_proxies: Vec::new(),
            request_body_timeout_secs: Self::default_body_timeout_secs(),
            client_header_timeout_secs: Self::default_client_header_timeout_secs(),
            upstream_body_timeout_secs: Self::default_body_timeout_secs(),
            websocket_idle_secs: Self::default_websocket_idle_secs(),
            lingering_close: Self::default_lingering_close(),
            lingering_timeout_secs: Self::default_lingering_timeout_secs(),
            reset_timedout_connection: false,
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

    fn default_open_file_cache_max_file_bytes() -> usize {
        64 * 1024
    }

    fn default_websocket_idle_secs() -> u64 {
        3600
    }

    fn default_lingering_close() -> bool {
        true
    }

    fn default_lingering_timeout_secs() -> u64 {
        5
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
