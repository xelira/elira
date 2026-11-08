//! TLS configuration.
//!
//! Certificate and key material comes from PEM files written by the operator.
//! Problems with that material must fail at startup, with the offending path in
//! the message, rather than surface later as a handshake failure.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use thiserror::Error;

/// ALPN order matters: clients that accept both get the first shared protocol.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Where the certificate chain and private key live.
#[derive(Debug, Clone)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Client certificate policy for a TLS listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// Do not request a client certificate.
    Off,
    /// Accept a client certificate when the client sends one and it chains to
    /// the configured CA. Clients without a certificate are still admitted.
    Optional,
    /// Require a certificate that chains to the configured CA.
    Required,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("parse certificates in {path}: {source}")]
    Certificates {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("no certificates in {path}")]
    NoCertificates { path: PathBuf },

    #[error("parse private key in {path}: {source}")]
    PrivateKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("no private key in {path}")]
    NoPrivateKey { path: PathBuf },

    #[error("invalid certificate {cert} and key {key}: {source}")]
    Tls {
        cert: PathBuf,
        key: PathBuf,
        #[source]
        source: rustls::Error,
    },

    #[error("client authentication requires a client CA file")]
    ClientCaRequired,

    #[error("client CA file {path} has no certificates usable for client authentication")]
    UnusableClientCa { path: PathBuf },

    #[error("build client certificate verifier from {path}: {source}")]
    ClientVerifier {
        path: PathBuf,
        #[source]
        source: rustls::server::VerifierBuilderError,
    },
}

/// Build a server configuration from a PEM certificate chain and private key.
///
/// Client certificates are not requested. Use
/// [`server_config_with_client_auth`] when a client CA trust store exists.
pub fn server_config(cert: &Path, key: &Path) -> Result<ServerConfig, Error> {
    build(cert, key, &ALPN_PROTOCOLS, None, ClientAuth::Off)
}

/// Same material as [`server_config`], but with a client certificate policy.
///
/// `client_ca` is a PEM bundle of the roots a client certificate must chain to.
/// It is read only for [`ClientAuth::Optional`] and [`ClientAuth::Required`];
/// [`ClientAuth::Off`] ignores it entirely, so a deployment that turns client
/// authentication off does not depend on the CA file still being present.
pub fn server_config_with_client_auth(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
    mode: ClientAuth,
) -> Result<ServerConfig, Error> {
    build(cert, key, &ALPN_PROTOCOLS, client_ca, mode)
}

/// Same material, but for QUIC: HTTP/3 is the only protocol a QUIC endpoint
/// can negotiate, so the ALPN list is shorter.
pub fn quic_server_config(cert: &Path, key: &Path) -> Result<ServerConfig, Error> {
    build(cert, key, &[b"h3"], None, ClientAuth::Off)
}

fn build(
    cert: &Path,
    key: &Path,
    alpn: &[&[u8]],
    client_ca: Option<&Path>,
    client_auth: ClientAuth,
) -> Result<ServerConfig, Error> {
    let chain = load_chain(cert)?;
    let key_der = load_key(key)?;
    let client_verifier = client_verifier(client_ca, client_auth)?;

    // Pick the provider explicitly. Relying on the process default breaks as
    // soon as another crate enables a second backend, which quinn does.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs provides TLS 1.2 and 1.3");

    let builder = match client_verifier {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };

    let mut config = builder
        .with_single_cert(chain, key_der)
        .map_err(|source| Error::Tls {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            source,
        })?;

    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// Build the client certificate verifier, or `None` when clients are not
/// authenticated at all.
fn client_verifier(
    client_ca: Option<&Path>,
    mode: ClientAuth,
) -> Result<Option<Arc<dyn ClientCertVerifier>>, Error> {
    if mode == ClientAuth::Off {
        return Ok(None);
    }

    let path = client_ca.ok_or(Error::ClientCaRequired)?;
    let roots = load_client_ca(path)?;

    // The two modes differ only in whether a client may omit its certificate.
    // `build` is the strict path, which is also what Required needs. The
    // provider is explicit for the same reason as in `build`: the workspace
    // links two backends, so rustls cannot pick one on its own.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
    let built = match mode {
        ClientAuth::Optional => builder.allow_unauthenticated().build(),
        ClientAuth::Off | ClientAuth::Required => builder.build(),
    };

    let verifier = built.map_err(|source| Error::ClientVerifier {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Some(verifier))
}

fn load_client_ca(path: &Path) -> Result<RootCertStore, Error> {
    let chain = load_chain(path)?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(chain);

    // A bundle that parses as PEM but yields nothing webpki accepts would leave
    // an empty trust store, which rejects every client certificate. Fail at
    // startup instead.
    if added == 0 {
        return Err(Error::UnusableClientCa {
            path: path.to_path_buf(),
        });
    }
    Ok(roots)
}

fn load_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let pem = read(path)?;
    let mut reader = pem.as_slice();

    let chain = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| Error::Certificates {
            path: path.to_path_buf(),
            source,
        })?;

    if chain.is_empty() {
        return Err(Error::NoCertificates {
            path: path.to_path_buf(),
        });
    }
    Ok(chain)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
    let pem = read(path)?;
    let mut reader = pem.as_slice();

    rustls_pemfile::private_key(&mut reader)
        .map_err(|source| Error::PrivateKey {
            path: path.to_path_buf(),
            source,
        })?
        .ok_or_else(|| Error::NoPrivateKey {
            path: path.to_path_buf(),
        })
}

fn read(path: &Path) -> Result<Vec<u8>, Error> {
    fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// Each test gets its own directory so parallel runs cannot collide, and it
    /// is removed even when an assertion panics.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("elira-tls-{}-{label}-{n}", std::process::id()));
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, name: &str, body: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, body).expect("write fixture");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    #[test]
    fn missing_certificate_file_fails() {
        let dir = TempDir::new("missing-cert");
        let cert = dir.path().join("absent.pem");
        let key = dir.write("key.pem", b"");

        let err = server_config(&cert, &key).expect_err("absent certificate");
        assert!(matches!(err, Error::Read { .. }), "got {err:?}");
        assert!(err.to_string().contains("absent.pem"), "got {err}");
    }

    #[test]
    fn empty_certificate_file_fails() {
        let dir = TempDir::new("empty-cert");
        let cert = dir.write("cert.pem", b"");
        let key = dir.write("key.pem", b"");

        let err = server_config(&cert, &key).expect_err("no certificates");
        assert!(matches!(err, Error::NoCertificates { .. }), "got {err:?}");
        assert!(err.to_string().contains("no certificates"), "got {err}");
    }

    #[test]
    fn missing_key_file_fails() {
        // A readable certificate is needed to get past chain loading, so this
        // covers the key path through the lower-level loader.
        let dir = TempDir::new("missing-key");
        let key = dir.path().join("absent.pem");

        let err = load_key(&key).expect_err("absent key");
        assert!(matches!(err, Error::Read { .. }), "got {err:?}");
        assert!(err.to_string().contains("absent.pem"), "got {err}");
    }

    #[test]
    fn empty_key_file_fails() {
        let dir = TempDir::new("empty-key");
        let key = dir.write("key.pem", b"");

        let err = load_key(&key).expect_err("no key");
        assert!(matches!(err, Error::NoPrivateKey { .. }), "got {err:?}");
        assert!(err.to_string().contains("no private key"), "got {err}");
    }

    #[test]
    fn malformed_certificate_file_fails() {
        let dir = TempDir::new("bad-cert");
        let cert = dir.write("cert.pem", b"-----BEGIN CERTIFICATE-----\n");
        let key = dir.write("key.pem", b"");

        let err = server_config(&cert, &key).expect_err("truncated certificate");
        assert!(matches!(err, Error::Certificates { .. }), "got {err:?}");
        assert!(err.to_string().contains("cert.pem"), "got {err}");
    }

    #[test]
    fn valid_pair_offers_h2_before_http1() {
        let dir = fixtures();
        let config =
            server_config(&dir.join("cert.pem"), &dir.join("key.pem")).expect("valid pair");

        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn optional_client_auth_without_ca_fails() {
        let dir = fixtures();

        let err = server_config_with_client_auth(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
            None,
            ClientAuth::Optional,
        )
        .expect_err("optional client auth without a CA");
        assert!(matches!(err, Error::ClientCaRequired), "got {err:?}");
        assert!(
            err.to_string().contains("requires a client CA"),
            "got {err}"
        );
    }

    #[test]
    fn required_client_auth_without_ca_fails() {
        let dir = fixtures();

        let err = server_config_with_client_auth(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
            None,
            ClientAuth::Required,
        )
        .expect_err("required client auth without a CA");
        assert!(matches!(err, Error::ClientCaRequired), "got {err:?}");
    }

    #[test]
    fn missing_client_ca_file_fails_with_path() {
        let dir = fixtures();
        let ca = dir.join("absent-ca.pem");

        let err = server_config_with_client_auth(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
            Some(&ca),
            ClientAuth::Required,
        )
        .expect_err("absent client CA");
        assert!(matches!(err, Error::Read { .. }), "got {err:?}");
        assert!(err.to_string().contains("absent-ca.pem"), "got {err}");
    }

    #[test]
    fn empty_client_ca_file_fails() {
        let dir = TempDir::new("empty-ca");
        let ca = dir.write("empty-ca.pem", b"");
        let fixtures = fixtures();

        let err = server_config_with_client_auth(
            &fixtures.join("cert.pem"),
            &fixtures.join("key.pem"),
            Some(&ca),
            ClientAuth::Optional,
        )
        .expect_err("empty client CA");
        assert!(matches!(err, Error::NoCertificates { .. }), "got {err:?}");
        assert!(err.to_string().contains("empty-ca.pem"), "got {err}");
    }

    #[test]
    fn client_ca_without_usable_certificate_fails() {
        let dir = TempDir::new("bad-ca");
        // Valid PEM armour around bytes that are not a certificate: the PEM
        // layer accepts it, so this covers the trust store rejecting it.
        let ca = dir.write(
            "bad-ca.pem",
            b"-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n",
        );
        let fixtures = fixtures();

        let err = server_config_with_client_auth(
            &fixtures.join("cert.pem"),
            &fixtures.join("key.pem"),
            Some(&ca),
            ClientAuth::Required,
        )
        .expect_err("unusable client CA");
        assert!(matches!(err, Error::UnusableClientCa { .. }), "got {err:?}");
        assert!(err.to_string().contains("bad-ca.pem"), "got {err}");
    }

    #[test]
    fn off_client_auth_ignores_client_ca() {
        let dir = fixtures();
        let ca = dir.join("absent-ca.pem");

        let config = server_config_with_client_auth(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
            Some(&ca),
            ClientAuth::Off,
        )
        .expect("Off must not read the CA file");

        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn optional_client_auth_builds_with_valid_ca() {
        let dir = fixtures();

        // The fixture is a self-signed CA certificate, which is enough for the
        // verifier: no client presents it in this test, only construction is
        // exercised.
        server_config_with_client_auth(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
            Some(&dir.join("cert.pem")),
            ClientAuth::Optional,
        )
        .expect("optional client auth with a CA");
    }

    #[test]
    fn required_client_auth_builds_with_valid_ca() {
        let dir = fixtures();

        server_config_with_client_auth(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
            Some(&dir.join("cert.pem")),
            ClientAuth::Required,
        )
        .expect("required client auth with a CA");
    }
}
