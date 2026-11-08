//! Automatic certificates for TLS-ALPN-01.
//!
//! The server keeps serving on port 443 while this module obtains and renews
//! certificates. There is no separate HTTP listener and no reverse proxy to
//! configure: Let's Encrypt validates the domain by opening a TLS connection
//! with the `acme-tls/1` ALPN protocol, which lands on the same socket.
//!
//! `rustls-acme` does not spawn tasks of its own. Its state machine is a
//! stream, so a task in this module polls it for as long as [`Acme`] lives.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use futures_util::StreamExt;
use rustls::ServerConfig;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeAcceptor, UseChallenge};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// Order matters: a browser that offers both gets HTTP/2 first. The challenge
/// protocol has to be present as well, otherwise validation handshakes cannot
/// negotiate it on this socket.
const ALPN_PROTOCOLS: [&[u8]; 3] = [b"h2", b"http/1.1", b"acme-tls/1"];

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    /// Contacts in `mailto:` form. Let's Encrypt uses them for expiry warnings.
    pub contacts: Vec<String>,
    pub cache_dir: PathBuf,
    /// `false` selects the staging directory, which avoids production rate
    /// limits during development.
    pub production: bool,
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
    /// Check the configuration and create the cache directory.
    ///
    /// Running this before any listener starts keeps configuration mistakes
    /// from surfacing later as failed handshakes.
    pub fn prepare(&self) -> Result<(), ConfigError> {
        self.validate()?;

        // Certificate cache writes recreate the directory anyway, but failing
        // here reports an unusable path while the operator is still watching.
        std::fs::create_dir_all(&self.cache_dir).map_err(|source| ConfigError::CacheDir {
            path: self.cache_dir.clone(),
            source,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.domains.is_empty() {
            return Err(ConfigError::NoDomains);
        }
        for domain in &self.domains {
            if !is_valid_domain(domain) {
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

/// A syntactically valid DNS name with at least two labels.
///
/// ACME will not issue a certificate for a single label such as `localhost`,
/// and TLS-ALPN-01 cannot validate wildcards, so both are rejected up front.
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

/// The ACME client only understands absolute URI contacts. Mail is the only
/// form Let's Encrypt documents, so anything else is a configuration mistake.
fn is_valid_contact(contact: &str) -> bool {
    contact
        .strip_prefix("mailto:")
        .is_some_and(|address| !address.is_empty() && !address.chars().any(char::is_whitespace))
}

/// A running certificate manager.
///
/// Dropping it aborts the renewal task. Handshakes already in progress are
/// owned by the caller and are not affected.
pub struct Acme {
    acceptor: AcmeAcceptor,
    server_config: Arc<ServerConfig>,
    renewal: JoinHandle<()>,
}

impl Acme {
    pub async fn start(config: AcmeConfig) -> anyhow::Result<Self> {
        config.prepare()?;

        let mut state = rustls_acme::AcmeConfig::new(config.domains.iter())
            .contact(config.contacts.iter())
            .directory_lets_encrypt(config.production)
            .challenge_type(UseChallenge::TlsAlpn01)
            .cache(DirCache::new(config.cache_dir.clone()))
            .state();

        // The low-level acceptor is the only public way to drive a single
        // connection. Its constructor is crate-private and this accessor is
        // marked deprecated in 0.15, but the high-level `Incoming` stream
        // cannot wrap a single already-accepted socket.
        #[allow(deprecated)]
        let acceptor = state.acceptor();

        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs provides TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
        server_config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();

        // The stream never ends, but it must be polled continuously: that is
        // what loads cached certificates and starts renewals.
        let renewal = tokio::spawn(async move {
            while let Some(event) = state.next().await {
                match event {
                    Ok(event) => tracing::info!(?event, "acme event"),
                    Err(error) => tracing::warn!(%error, "acme error"),
                }
            }
        });

        Ok(Self {
            acceptor,
            server_config: Arc::new(server_config),
            renewal,
        })
    }

    /// Finish the TLS handshake and report whether HTTP/2 was negotiated.
    ///
    /// A TLS-ALPN-01 validation connection completes with no application
    /// stream; it is reported as [`io::ErrorKind::ConnectionAborted`] so the
    /// caller can drop it without serving a request.
    pub async fn accept(&self, stream: TcpStream) -> io::Result<(Box<dyn AsyncStream>, bool)> {
        let stream = stream.compat();

        let Some(handshake) = self.acceptor.accept(stream).await? else {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TLS-ALPN-01 validation completed",
            ));
        };

        let tls = handshake.into_stream(self.server_config.clone()).await?;
        let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");

        Ok((Box::new(tls.compat()), h2))
    }
}

impl Drop for Acme {
    fn drop(&mut self) {
        // Without this the renewal task would keep polling a state machine
        // whose only consumer is gone.
        self.renewal.abort();
    }
}

/// Byte stream returned by [`Acme::accept`].
///
/// The concrete type is a boxed `rustls` stream, so callers only need the
/// tokio traits.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncStream for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// Each test gets a unique directory and removes it even on panic.
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
}
