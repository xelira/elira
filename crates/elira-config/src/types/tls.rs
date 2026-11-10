//! TLS, ACME and HTTP/3 settings.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// TLS implementation for TCP and unix listeners. HTTP/3 always uses
    /// rustls because QUIC requires TLS 1.3.
    #[serde(default)]
    pub backend: TlsBackend,

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

    /// Reject a handshake whose SNI matches no configured name. Missing SNI
    /// is rejected too, so this needs `[[tls.certificates]]` entries.
    #[serde(default)]
    pub reject_unknown_sni: bool,
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

    /// Maximum concurrent bidirectional streams per QUIC connection.
    #[serde(default)]
    pub max_concurrent_bidi_streams: Option<u64>,

    /// Per-stream receive window in bytes.
    #[serde(default)]
    pub stream_receive_window: Option<u64>,

    /// Connection-level receive window in bytes.
    #[serde(default)]
    pub receive_window: Option<u64>,

    /// Connection-level send window in bytes.
    #[serde(default)]
    pub send_window: Option<u64>,

    /// Allow 0-RTT early data on QUIC.
    #[serde(default)]
    pub early_data: bool,

    /// 32-byte ticket key shared by all QUIC workers.
    #[serde(default)]
    pub ticket_key: Option<PathBuf>,

    /// Reject QUIC handshakes with unknown or missing SNI.
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
