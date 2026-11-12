use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    #[serde(default)]
    pub backend: TlsBackend,

    #[serde(default)]
    pub cert: PathBuf,
    #[serde(default)]
    pub key: PathBuf,

    #[serde(default)]
    pub client_ca: Option<PathBuf>,

    #[serde(default)]
    pub client_crl: Option<PathBuf>,

    #[serde(default)]
    pub client_auth: ClientAuthMode,

    #[serde(default)]
    pub min_version: TlsVersion,

    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,

    #[serde(default)]
    pub curves: Option<Vec<String>>,

    #[serde(default)]
    pub ocsp: Option<PathBuf>,

    #[serde(default)]
    pub ticket_key: Option<PathBuf>,

    #[serde(default)]
    pub ocsp_hook: Option<PathBuf>,

    #[serde(default = "Tls::default_ocsp_refresh_secs")]
    pub ocsp_refresh_secs: u64,

    #[serde(default = "Tls::default_session_tickets")]
    pub session_tickets: usize,

    #[serde(default = "Tls::default_session_cache")]
    pub session_cache: usize,

    #[serde(default)]
    pub certificates: Vec<ServerCert>,

    #[serde(default)]
    pub reject_unknown_sni: bool,

    #[serde(default)]
    pub verify_ocsp: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerCert {
    pub cert: PathBuf,
    pub key: PathBuf,

    #[serde(default)]
    pub names: Vec<String>,

    #[serde(default)]
    pub ocsp: Option<PathBuf>,
}

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
    Tls10,
    Tls11,
    #[default]
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsBackend {
    #[default]
    Rustls,
    Openssl,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Acme {
    pub domains: Vec<String>,
    pub contacts: Vec<String>,
    pub cache_dir: PathBuf,
    #[serde(default)]
    pub production: bool,

    #[serde(default)]
    pub challenge: AcmeChallenge,

    #[serde(default)]
    pub http01_listen: Option<SocketAddr>,

    #[serde(default)]
    pub dns_hook: Option<PathBuf>,

    #[serde(default)]
    pub dns_cleanup_hook: Option<PathBuf>,

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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Http3 {
    pub listen: SocketAddr,

    #[serde(default)]
    pub cert: PathBuf,
    #[serde(default)]
    pub key: PathBuf,

    #[serde(default)]
    pub client_ca: Option<PathBuf>,

    #[serde(default)]
    pub client_crl: Option<PathBuf>,
    #[serde(default)]
    pub client_auth: ClientAuthMode,

    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,

    #[serde(default)]
    pub curves: Option<Vec<String>>,

    #[serde(default)]
    pub certificates: Vec<ServerCert>,

    #[serde(default = "Http3::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    #[serde(default)]
    pub max_concurrent_bidi_streams: Option<u64>,

    #[serde(default)]
    pub stream_receive_window: Option<u64>,

    #[serde(default)]
    pub receive_window: Option<u64>,

    #[serde(default)]
    pub send_window: Option<u64>,

    #[serde(default)]
    pub early_data: bool,

    #[serde(default)]
    pub ticket_key: Option<PathBuf>,

    #[serde(default)]
    pub reject_unknown_sni: bool,
}

impl Http3 {
    fn default_idle_timeout_secs() -> u64 {
        30
    }
}

impl Acme {
    fn default_dns_propagation_secs() -> u64 {
        30
    }
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
