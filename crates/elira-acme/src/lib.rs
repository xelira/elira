use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use futures_util::StreamExt;
use rustls::ServerConfig;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeAcceptor, ResolvesServerCertAcme, UseChallenge};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

mod dns;

const ALPN_PROTOCOLS: [&[u8]; 3] = [b"h2", b"http/1.1", b"acme-tls/1"];

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub domains: Vec<String>,

    pub contacts: Vec<String>,
    pub cache_dir: PathBuf,

    pub production: bool,
    pub challenge: Challenge,

    pub dns_hook: Option<PathBuf>,
    pub dns_cleanup_hook: Option<PathBuf>,

    pub dns_propagation_secs: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Challenge {
    #[default]
    TlsAlpn01,
    Http01,
    Dns01,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("at least one domain is required")]
    NoDomains,

    #[error("invalid domain {domain:?}: expected a fully qualified DNS name")]
    InvalidDomain { domain: String },

    #[error("at least one contact is required, for example mailto:admin@example.com")]
    NoContacts,

    #[error("invalid contact {contact:?}: expected a mailto: URI")]
    InvalidContact { contact: String },

    #[error("DNS-01 requires dns_hook")]
    DnsHookMissing,

    #[error("run dns_hook {path}: {source}")]
    DnsHook {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("dns_hook {path} exited with {status:?}")]
    DnsHookStatus { path: PathBuf, status: Option<i32> },

    #[error("cache directory path is empty")]
    EmptyCacheDir,

    #[error("create cache directory {path}: {source}")]
    CacheDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl AcmeConfig {
    pub fn prepare(&self) -> Result<(), ConfigError> {
        self.validate()?;

        std::fs::create_dir_all(&self.cache_dir).map_err(|source| ConfigError::CacheDir {
            path: self.cache_dir.clone(),
            source,
        })?;
        std::fs::set_permissions(&self.cache_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| ConfigError::CacheDir {
                path: self.cache_dir.clone(),
                source,
            },
        )
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.domains.is_empty() {
            return Err(ConfigError::NoDomains);
        }
        for domain in &self.domains {
            let name = if self.challenge == Challenge::Dns01 {
                domain.strip_prefix("*.").unwrap_or(domain)
            } else {
                domain.as_str()
            };
            if !is_valid_domain(name) {
                return Err(ConfigError::InvalidDomain {
                    domain: domain.clone(),
                });
            }
        }

        if self.contacts.is_empty() {
            return Err(ConfigError::NoContacts);
        }
        for contact in &self.contacts {
            if !is_valid_contact(contact) {
                return Err(ConfigError::InvalidContact {
                    contact: contact.clone(),
                });
            }
        }

        if self.cache_dir.as_os_str().is_empty() {
            return Err(ConfigError::EmptyCacheDir);
        }

        Ok(())
    }
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn is_valid_contact(contact: &str) -> bool {
    contact
        .strip_prefix("mailto:")
        .is_some_and(|address| !address.is_empty() && !address.chars().any(char::is_whitespace))
}

pub struct Acme {
    mode: Mode,
    renewal: Option<JoinHandle<()>>,
}

enum Mode {
    Rustls {
        acceptor: AcmeAcceptor,
        server_config: Arc<ServerConfig>,
        resolver: Arc<ResolvesServerCertAcme>,
        http01: bool,
    },
    Dns(Arc<arc_swap::ArcSwap<ServerConfig>>),
}

impl Acme {
    pub async fn start(config: AcmeConfig) -> anyhow::Result<Self> {
        config.prepare()?;

        if config.challenge == Challenge::Dns01 {
            let (server, _, _) = dns::build_config(&config).await?;
            let shared = Arc::new(arc_swap::ArcSwap::from(server));
            let renewal_config = config.clone();
            let renewal_shared = shared.clone();
            let renewal = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(12 * 60 * 60)).await;
                    match dns::build_config(&renewal_config).await {
                        Ok((server, _, _)) => {
                            renewal_shared.store(server);
                            tracing::info!("DNS-01 certificate renewed");
                        }
                        Err(error) => tracing::warn!(%error, "DNS-01 renewal failed"),
                    }
                }
            });
            return Ok(Self {
                mode: Mode::Dns(shared),
                renewal: Some(renewal),
            });
        }

        let challenge = match config.challenge {
            Challenge::TlsAlpn01 => UseChallenge::TlsAlpn01,
            Challenge::Http01 => UseChallenge::Http01,
            Challenge::Dns01 => unreachable!("handled above"),
        };
        let mut state = rustls_acme::AcmeConfig::new(config.domains.iter())
            .contact(config.contacts.iter())
            .directory_lets_encrypt(config.production)
            .challenge_type(challenge)
            .cache(DirCache::new(config.cache_dir.clone()))
            .state();
        let resolver = state.resolver();

        #[allow(deprecated)]
        let acceptor = state.acceptor();

        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs provides TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
        server_config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();

        let renewal = tokio::spawn(async move {
            while let Some(event) = state.next().await {
                match event {
                    Ok(event) => tracing::info!(?event, "acme event"),
                    Err(error) => tracing::warn!(%error, "acme error"),
                }
            }
        });

        Ok(Self {
            mode: Mode::Rustls {
                acceptor,
                server_config: Arc::new(server_config),
                resolver,
                http01: config.challenge == Challenge::Http01,
            },
            renewal: Some(renewal),
        })
    }

    pub fn http01(&self, token: &str) -> Option<String> {
        match &self.mode {
            Mode::Rustls { resolver, .. } => resolver.get_http_01_key_auth(token),
            Mode::Dns(_) => None,
        }
    }

    pub fn uses_http01(&self) -> bool {
        matches!(&self.mode, Mode::Rustls { http01: true, .. })
    }

    pub async fn accept(&self, stream: TcpStream) -> io::Result<(Box<dyn AsyncStream>, bool)> {
        match &self.mode {
            Mode::Dns(config) => {
                let acceptor = tokio_rustls::TlsAcceptor::from(config.load_full());
                let tls = acceptor.accept(stream).await?;
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                Ok((Box::new(tls), h2))
            }
            Mode::Rustls {
                acceptor,
                server_config,
                ..
            } => {
                let stream = stream.compat();
                let Some(handshake) = acceptor.accept(stream).await? else {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "TLS-ALPN-01 validation completed",
                    ));
                };
                let tls = handshake.into_stream(server_config.clone()).await?;
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                Ok((Box::new(tls.compat()), h2))
            }
        }
    }
}

impl Drop for Acme {
    fn drop(&mut self) {
        if let Some(renewal) = &self.renewal {
            renewal.abort();
        }
    }
}

pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncStream for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("elira-acme-{}-{label}-{n}", std::process::id()));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn valid_config(dir: &Path) -> AcmeConfig {
        AcmeConfig {
            domains: vec!["example.com".into()],
            contacts: vec!["mailto:admin@example.com".into()],
            cache_dir: dir.join("cache"),
            production: false,
            challenge: Challenge::TlsAlpn01,
            dns_hook: None,
            dns_cleanup_hook: None,
            dns_propagation_secs: 0,
        }
    }

    #[test]
    fn empty_domains_fail() {
        let dir = TempDir::new("empty-domains");
        let mut config = valid_config(dir.path());
        config.domains.clear();

        let err = config.validate().expect_err("empty domains");
        assert!(matches!(err, ConfigError::NoDomains), "got {err:?}");
        assert!(err.to_string().contains("domain"), "got {err}");
    }

    #[test]
    fn empty_contacts_fail() {
        let dir = TempDir::new("empty-contacts");
        let mut config = valid_config(dir.path());
        config.contacts.clear();

        let err = config.validate().expect_err("empty contacts");
        assert!(matches!(err, ConfigError::NoContacts), "got {err:?}");
        assert!(err.to_string().contains("contact"), "got {err}");
    }

    #[test]
    fn garbage_domain_fails() {
        for domain in [
            "not a domain",
            "example",
            "-broken.example",
            "*.example.com",
            "a..b",
        ] {
            let dir = TempDir::new("bad-domain");
            let mut config = valid_config(dir.path());
            config.domains = vec![domain.into()];

            let err = config.validate().expect_err("invalid domain");
            assert!(
                matches!(err, ConfigError::InvalidDomain { .. }),
                "{domain}: got {err:?}"
            );
            assert!(err.to_string().contains(domain), "{domain}: got {err}");
        }
    }

    #[test]
    fn contact_without_mailto_fails() {
        let dir = TempDir::new("bad-contact");
        let mut config = valid_config(dir.path());
        config.contacts = vec!["admin@example.com".into()];

        let err = config.validate().expect_err("invalid contact");
        assert!(
            matches!(err, ConfigError::InvalidContact { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prepare_creates_nested_cache_dir() {
        let dir = TempDir::new("cache-dir");
        let config = valid_config(dir.path());
        let nested = config.cache_dir.join("nested");

        config.prepare().expect("prepare valid config");
        assert!(config.cache_dir.is_dir(), "cache dir was not created");

        let mut config = config;
        config.cache_dir = nested.clone();
        config.prepare().expect("prepare nested cache dir");
        assert!(nested.is_dir(), "nested cache dir was not created");
    }

    #[test]
    fn valid_config_passes() {
        let dir = TempDir::new("valid");
        let config = valid_config(dir.path());

        assert!(config.validate().is_ok());
    }

    #[test]
    fn wildcards_are_allowed_only_for_dns01() {
        let dir = TempDir::new("wildcard");
        let mut config = valid_config(dir.path());
        config.domains = vec!["*.example.com".into()];
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidDomain { .. })
        ));

        config.challenge = Challenge::Dns01;
        config.dns_hook = Some(Path::new("/bin/true").to_path_buf());
        assert!(config.validate().is_ok());
    }
}
