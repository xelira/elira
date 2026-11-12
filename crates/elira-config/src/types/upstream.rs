use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::TlsVersion;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ServerConfig {
    Address(String),
    Detailed(ServerOptions),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerOptions {
    pub address: String,

    #[serde(default)]
    pub backup: bool,

    #[serde(default)]
    pub down: bool,

    #[serde(default)]
    pub max_conns: usize,

    #[serde(default)]
    pub slow_start_secs: u64,
}

impl ServerConfig {
    pub fn address(&self) -> &str {
        match self {
            Self::Address(address) => address,
            Self::Detailed(options) => &options.address,
        }
    }

    pub fn backup(&self) -> bool {
        matches!(self, Self::Detailed(options) if options.backup)
    }

    pub fn down(&self) -> bool {
        matches!(self, Self::Detailed(options) if options.down)
    }

    pub fn max_conns(&self) -> usize {
        match self {
            Self::Address(_) => 0,
            Self::Detailed(options) => options.max_conns,
        }
    }

    pub fn slow_start_secs(&self) -> u64 {
        match self {
            Self::Address(_) => 0,
            Self::Detailed(options) => options.slow_start_secs,
        }
    }

    pub fn is_unix(&self) -> bool {
        self.address().starts_with("unix:")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<ServerConfig>,

    #[serde(default)]
    pub weights: Vec<u32>,

    #[serde(default)]
    pub balance: Balance,

    #[serde(default)]
    pub hash_key: Option<String>,

    #[serde(default)]
    pub retries: u32,

    #[serde(default)]
    pub retry_on: Vec<String>,

    #[serde(default)]
    pub tls: bool,

    #[serde(default)]
    pub sni: Option<String>,

    #[serde(default)]
    pub health_path: Option<String>,

    #[serde(default)]
    pub health_method: Option<String>,

    #[serde(default)]
    pub health_expect_status: Option<Vec<u16>>,

    #[serde(default)]
    pub health_host: Option<String>,

    #[serde(default)]
    pub tls_insecure: Option<bool>,

    #[serde(default)]
    pub tls_ca: Option<PathBuf>,

    #[serde(default)]
    pub http2: Option<bool>,

    #[serde(default)]
    pub bind: Option<IpAddr>,

    #[serde(default)]
    pub proxy_protocol: bool,

    #[serde(default)]
    pub h1_pool: bool,

    #[serde(default)]
    pub h2_pool: bool,

    #[serde(default)]
    pub h3_pool: bool,

    #[serde(default)]
    pub dns_ttl_secs: Option<u64>,

    #[serde(default)]
    pub keepalive: Option<usize>,

    #[serde(default)]
    pub keepalive_secs: Option<u64>,

    #[serde(default)]
    pub keepalive_requests: Option<u32>,

    #[serde(default)]
    pub failures_before_eject: u32,

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

    #[serde(default = "Health::default_method")]
    pub method: String,

    #[serde(default)]
    pub expect_status: Vec<u16>,

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
    Random,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTls {
    #[serde(default)]
    pub insecure: bool,

    #[serde(default)]
    pub ca: Option<PathBuf>,

    #[serde(default)]
    pub http2: bool,

    #[serde(default)]
    pub min_version: TlsVersion,

    #[serde(default)]
    pub client_cert: Option<PathBuf>,

    #[serde(default)]
    pub client_key: Option<PathBuf>,

    #[serde(default)]
    pub client_crl: Option<PathBuf>,

    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,

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
