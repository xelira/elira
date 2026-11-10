//! Upstreams, health checks and balancing.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::TlsVersion;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Balance {
    #[default]
    RoundRobin,
    LeastConn,
    Hash,
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

    /// Client certificate presented to upstreams.
    #[serde(default)]
    pub client_cert: Option<PathBuf>,

    /// Private key for `client_cert`.
    #[serde(default)]
    pub client_key: Option<PathBuf>,

    /// PEM CRLs for upstream server certificates.
    #[serde(default)]
    pub client_crl: Option<PathBuf>,

    /// Cipher suites offered to upstreams.
    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,

    /// Key exchange groups offered to upstreams.
    #[serde(default)]
    pub curves: Option<Vec<String>>,
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

impl Upstream {
    fn default_eject_secs() -> u64 {
        30
    }
}
