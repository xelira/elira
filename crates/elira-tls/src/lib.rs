//! TLS configuration.
//!
//! Certificate and key material comes from PEM files written by the operator.
//! Problems with that material must fail at startup, with the offending path in
//! the message, rather than surface later as a handshake failure.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use thiserror::Error;

/// ALPN order matters: clients that accept both get the first shared protocol.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Where the certificate chain and private key live.
#[derive(Debug, Clone)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
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
}

/// Build a server configuration from a PEM certificate chain and private key.
///
/// Client certificates are not requested: this proxy faces browsers, and mutual
/// TLS would need a trust store we do not have.
pub fn server_config(cert: &Path, key: &Path) -> Result<ServerConfig, Error> {
    build(cert, key, &ALPN_PROTOCOLS)
}

/// Same material, but for QUIC: HTTP/3 is the only protocol a QUIC endpoint
/// can negotiate, so the ALPN list is shorter.
pub fn quic_server_config(cert: &Path, key: &Path) -> Result<ServerConfig, Error> {
    build(cert, key, &[b"h3"])
}

fn build(cert: &Path, key: &Path, alpn: &[&[u8]]) -> Result<ServerConfig, Error> {
    let chain = load_chain(cert)?;
    let key_der = load_key(key)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .map_err(|source| Error::Tls {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            source,
        })?;

    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
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
}
