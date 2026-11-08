//! Upstream TLS connector.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use hyper_rustls::{FixedServerNameResolver, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// TLS settings for a single upstream.
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    /// Disable certificate and hostname verification. Only for tests and
    /// internal networks.
    pub insecure: bool,
    /// Additional CA in PEM format. `None` uses the system roots only.
    pub ca: Option<PathBuf>,
    /// Server name for SNI when it differs from the URI authority. `None`
    /// takes the name from the URI.
    pub sni: Option<String>,
}

/// Build an HTTPS connector that accepts both `https` and `http` upstreams.
///
/// HTTP/2 is intentionally not enabled: the proxy forwards to upstreams over
/// HTTP/1.1, and offering `h2` here would make hyper expect a different
/// connection setup.
pub fn https_connector(options: &TlsOptions) -> anyhow::Result<HttpsConnector<HttpConnector>> {
    let config = client_config(options)?;

    let builder = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http();

    // The resolver has to be installed before HTTP/1 is enabled because that
    // is the state that exposes the builder method.
    let builder = match &options.sni {
        Some(sni) => {
            let name = ServerName::try_from(sni.clone())
                .with_context(|| format!("invalid SNI name {sni:?}"))?;
            builder.with_server_name_resolver(FixedServerNameResolver::new(name))
        }
        None => builder,
    };

    Ok(builder.enable_http1().build())
}

fn client_config(options: &TlsOptions) -> anyhow::Result<ClientConfig> {
    // Pick the provider explicitly. Relying on the process default breaks as
    // soon as another crate installs a different backend.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("rustls provider does not support the default protocol versions")?;

    let config = if options.insecure {
        // A custom CA is irrelevant here: the verifier accepts every chain.
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification { provider }))
            .with_no_client_auth()
    } else {
        let roots = root_store(options.ca.as_deref())?;
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    Ok(config)
}

fn root_store(ca: Option<&Path>) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();

    // The native store routinely contains certificates rustls does not
    // support. Skipping them is better than making every upstream unusable.
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }

    let Some(path) = ca else {
        return Ok(roots);
    };

    let pem = std::fs::read(path)
        .with_context(|| format!("failed to read CA file {}", path.display()))?;
    let mut reader = pem.as_slice();
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse CA file {} as PEM", path.display()))?;

    if certs.is_empty() {
        anyhow::bail!("CA file {} contains no certificates", path.display());
    }

    for (index, cert) in certs.into_iter().enumerate() {
        roots.add(cert).with_context(|| {
            format!(
                "failed to add certificate #{} from CA file {}",
                index + 1,
                path.display()
            )
        })?;
    }

    Ok(roots)
}

/// Verifier used by `insecure = true`. It skips chain and hostname checks but
/// still verifies the handshake signature, so a broken server cannot be
/// mistaken for a working one.
#[derive(Debug)]
struct NoCertificateVerification {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use bytes::Bytes;
    use http::{Response, StatusCode, Uri};
    use http_body_util::{Empty, Full};
    use hyper::service::service_fn;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::{https_connector, TlsOptions};

    struct TestServer {
        addr: SocketAddr,
        cert_pem: String,
    }

    impl TestServer {
        async fn spawn() -> Self {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("generate self-signed certificate");
            let cert_der = CertificateDer::from(cert.cert.der().to_vec());
            let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
            let cert_pem = cert.cert.pem();

            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("aws-lc-rs supports the default protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("valid test certificate");
            let acceptor = TlsAcceptor::from(Arc::new(config));

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test listener");
            let addr = listener.local_addr().expect("listener address");

            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let service = service_fn(|_request| async {
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    });
                }
            });

            Self { addr, cert_pem }
        }

        fn localhost_uri(&self) -> Uri {
            format!("https://localhost:{}/", self.addr.port())
                .parse()
                .expect("valid URI")
        }

        fn ip_uri(&self) -> Uri {
            format!("https://127.0.0.1:{}/", self.addr.port())
                .parse()
                .expect("valid URI")
        }
    }

    struct TempCa(PathBuf);

    impl TempCa {
        fn write(pem: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("elira-upstream-ca-{}-{id}.pem", std::process::id()));
            std::fs::write(&path, pem).expect("write temporary CA");
            Self(path)
        }

        fn path(&self) -> PathBuf {
            self.0.clone()
        }
    }

    impl Drop for TempCa {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    async fn get(
        options: &TlsOptions,
        uri: Uri,
    ) -> Result<StatusCode, hyper_util::client::legacy::Error> {
        let connector = https_connector(options).expect("build connector");
        let client: Client<_, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);
        client.get(uri).await.map(|response| response.status())
    }

    #[tokio::test]
    async fn insecure_connector_accepts_self_signed_certificate() {
        let server = TestServer::spawn().await;
        let status = get(
            &TlsOptions {
                insecure: true,
                ca: None,
                sni: None,
            },
            server.localhost_uri(),
        )
        .await
        .expect("insecure request should succeed");

        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn default_verification_rejects_self_signed_certificate() {
        let server = TestServer::spawn().await;
        get(&TlsOptions::default(), server.localhost_uri())
            .await
            .expect_err("self-signed certificate must be rejected");
    }

    #[tokio::test]
    async fn custom_ca_and_sni_accept_self_signed_certificate() {
        let server = TestServer::spawn().await;
        let ca = TempCa::write(&server.cert_pem);

        let status = get(
            &TlsOptions {
                insecure: false,
                ca: Some(ca.path()),
                // The URI uses an IP literal, so the certificate name has to
                // come from the explicit SNI override.
                sni: Some("localhost".to_owned()),
            },
            server.ip_uri(),
        )
        .await
        .expect("request trusted through the custom CA should succeed");

        assert_eq!(status, StatusCode::OK);
    }

    #[test]
    fn missing_ca_file_is_reported_with_its_path() {
        let path = std::env::temp_dir().join(format!(
            "elira-upstream-missing-ca-{}.pem",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let error = https_connector(&TlsOptions {
            ca: Some(path.clone()),
            ..TlsOptions::default()
        })
        .expect_err("missing CA file must fail");

        let message = format!("{error:#}");
        assert!(
            message.contains(&path.display().to_string()),
            "error should mention {path:?}: {message}"
        );
    }
}
