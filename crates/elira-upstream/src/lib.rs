mod resolver;

pub use resolver::{Resolver, ResolverOptions};

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use hyper_rustls::{FixedServerNameResolver, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    pub insecure: bool,

    pub ca: Option<PathBuf>,

    pub sni: Option<String>,

    pub http2: bool,

    pub tls13_only: bool,

    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,

    pub client_crl: Option<PathBuf>,

    pub cipher_suites: Option<Vec<String>>,
    pub curves: Option<Vec<String>>,

    pub connect_timeout: Option<Duration>,

    pub local_address: Option<std::net::IpAddr>,
}

pub fn https_connector(
    options: &TlsOptions,
    resolver: Resolver,
) -> anyhow::Result<HttpsConnector<HttpConnector<Resolver>>> {
    let config = client_config(options)?;

    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_nodelay(true);
    if let Some(timeout) = options.connect_timeout {
        http.set_connect_timeout(Some(timeout));
    }
    http.set_local_address(options.local_address);

    let builder = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http();

    let builder = match &options.sni {
        Some(sni) => {
            let name = ServerName::try_from(sni.clone())
                .with_context(|| format!("invalid SNI name {sni:?}"))?;
            builder.with_server_name_resolver(FixedServerNameResolver::new(name))
        }
        None => builder,
    };

    if options.http2 {
        Ok(builder.enable_http1().enable_http2().wrap_connector(http))
    } else {
        Ok(builder.enable_http1().wrap_connector(http))
    }
}

pub fn client_config(options: &TlsOptions) -> anyhow::Result<ClientConfig> {
    let provider = Arc::new(crypto_provider(options)?);
    let versions: &[&rustls::SupportedProtocolVersion] = if options.tls13_only {
        &[&rustls::version::TLS13]
    } else {
        rustls::ALL_VERSIONS
    };
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .context("rustls provider does not support the requested protocol versions")?;

    let crls = match options.client_crl.as_deref() {
        Some(path) => load_crls(path)?,
        None => Vec::new(),
    };
    let builder = if options.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification { provider }))
    } else {
        let roots = root_store(options.ca.as_deref())?;
        if crls.is_empty() {
            builder.with_root_certificates(roots)
        } else {
            let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .with_crls(crls)
            .build()
            .context("failed to build a CRL-aware upstream verifier")?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
        }
    };

    let config = match (&options.client_cert, &options.client_key) {
        (Some(cert), Some(key)) => {
            let (chain, key) = client_auth(cert, key)?;
            builder
                .with_client_auth_cert(chain, key)
                .context("upstream rejected the client certificate and key pair")
        }
        _ => Ok(builder.with_no_client_auth()),
    }?;

    Ok(config)
}

fn crypto_provider(options: &TlsOptions) -> anyhow::Result<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();

    if let Some(names) = &options.cipher_suites {
        if names.is_empty() {
            anyhow::bail!("upstream_tls.cipher_suites is empty");
        }
        let mut suites = Vec::with_capacity(names.len());
        for name in names {
            let suite = rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES
                .iter()
                .copied()
                .find(|suite| format!("{:?}", suite.suite()) == *name)
                .with_context(|| format!("unknown TLS cipher suite {name:?}"))?;
            suites.push(suite);
        }
        provider.cipher_suites = suites;
    }

    if let Some(names) = &options.curves {
        if names.is_empty() {
            anyhow::bail!("upstream_tls.curves is empty");
        }
        let mut groups = Vec::with_capacity(names.len());
        for name in names {
            let group = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS
                .iter()
                .copied()
                .find(|group| format!("{:?}", group.name()).eq_ignore_ascii_case(name))
                .with_context(|| format!("unknown TLS key exchange group {name:?}"))?;
            groups.push(group);
        }
        provider.kx_groups = groups;
    }

    Ok(provider)
}

fn load_crls(path: &Path) -> anyhow::Result<Vec<CertificateRevocationListDer<'static>>> {
    let pem = std::fs::read(path)
        .with_context(|| format!("failed to read CRL file {}", path.display()))?;
    let mut reader = pem.as_slice();
    let crls = rustls_pemfile::crls(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse CRL file {} as PEM", path.display()))?;

    if crls.is_empty() {
        anyhow::bail!("CRL file {} contains no CRLs", path.display());
    }

    Ok(crls)
}

fn client_auth(
    cert: &Path,
    key: &Path,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = std::fs::read(cert)
        .with_context(|| format!("failed to read client certificate {}", cert.display()))?;
    let mut reader = cert_pem.as_slice();
    let chain = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed to parse client certificate {} as PEM",
                cert.display()
            )
        })?;

    if chain.is_empty() {
        anyhow::bail!(
            "client certificate {} contains no certificates",
            cert.display()
        );
    }

    let key_pem = read_private_key(key)?;
    let mut reader = key_pem.as_slice();
    let key = rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to parse client key {} as PEM", key.display()))?
        .with_context(|| format!("client key {} contains no private key", key.display()))?;

    Ok((chain, key))
}

fn read_private_key(path: &Path) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect client key {}", path.display()))?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("client key {} is a symlink", path.display());
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "elira: warning: client key {} is mode {mode:o}; expected 0600",
            path.display()
        );
    }
    std::fs::read(path).with_context(|| format!("failed to read client key {}", path.display()))
}

pub async fn tcp_connect(
    host: &str,
    port: u16,
    bind: Option<std::net::IpAddr>,
    resolver: Option<&Resolver>,
) -> std::io::Result<tokio::net::TcpStream> {
    if bind.is_none() && resolver.is_none() {
        let stream = tokio::net::TcpStream::connect((host, port)).await?;
        let _ = stream.set_nodelay(true);
        return Ok(stream);
    }

    let addrs = match resolver {
        Some(resolver) => resolver.lookup(host, port).await?,
        None => tokio::net::lookup_host((host, port)).await?.collect(),
    };

    let Some(bind) = bind else {
        let mut last = None;
        for addr in addrs {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Err(err) => last = Some(err),
            }
        }
        return Err(last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no usable address")
        }));
    };

    let mut last = None;
    for addr in addrs {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        if let Err(err) = socket.bind(std::net::SocketAddr::new(bind, 0)) {
            last = Some(err);
            continue;
        }
        match socket.connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) => last = Some(err),
        }
    }

    Err(last.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no usable address")
    }))
}

fn root_store(ca: Option<&Path>) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();

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

    use super::{client_config, https_connector, Resolver, ResolverOptions, TlsOptions};

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
        let connector = https_connector(options, Resolver::default()).expect("build connector");
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
                http2: false,
                tls13_only: false,
                ..TlsOptions::default()
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

                sni: Some("localhost".to_owned()),
                http2: false,
                tls13_only: false,
                ..TlsOptions::default()
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

        let error = https_connector(
            &TlsOptions {
                ca: Some(path.clone()),
                ..TlsOptions::default()
            },
            Resolver::default(),
        )
        .expect_err("missing CA file must fail");

        let message = format!("{error:#}");
        assert!(
            message.contains(&path.display().to_string()),
            "error should mention {path:?}: {message}"
        );
    }

    #[test]
    fn cipher_suite_policy_is_applied() {
        let options = TlsOptions {
            cipher_suites: Some(vec!["TLS13_AES_128_GCM_SHA256".to_owned()]),
            ..TlsOptions::default()
        };
        client_config(&options).expect("known cipher suite should be accepted");

        let error = client_config(&TlsOptions {
            cipher_suites: Some(vec!["TLS13_NOPE".to_owned()]),
            ..TlsOptions::default()
        })
        .expect_err("unknown cipher suite must fail");
        assert!(
            format!("{error:#}").contains("TLS13_NOPE"),
            "error should mention the suite: {error:#}"
        );
    }

    #[test]
    fn curve_policy_is_applied() {
        let options = TlsOptions {
            curves: Some(vec!["X25519".to_owned()]),
            ..TlsOptions::default()
        };
        client_config(&options).expect("known curve should be accepted");

        let error = client_config(&TlsOptions {
            curves: Some(vec!["X9999".to_owned()]),
            ..TlsOptions::default()
        })
        .expect_err("unknown curve must fail");
        assert!(
            format!("{error:#}").contains("X9999"),
            "error should mention the curve: {error:#}"
        );
    }

    #[tokio::test]
    async fn static_resolver_hosts_win_over_system_dns() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "backend.test".to_owned(),
            vec![std::net::IpAddr::from([127, 0, 0, 1])],
        );
        let resolver = Resolver::new(ResolverOptions {
            ttl: std::time::Duration::from_secs(30),
            negative_ttl: std::time::Duration::from_secs(5),
            hosts,
        });

        let addrs = resolver
            .lookup("BACKEND.test.", 8080)
            .await
            .expect("static host");
        assert_eq!(
            addrs,
            vec![std::net::SocketAddr::from(([127, 0, 0, 1], 8080))]
        );
    }

    #[test]
    fn empty_policy_lists_are_rejected() {
        let error = client_config(&TlsOptions {
            cipher_suites: Some(Vec::new()),
            ..TlsOptions::default()
        })
        .expect_err("empty cipher suite list must fail");
        assert!(format!("{error:#}").contains("cipher_suites"));

        let error = client_config(&TlsOptions {
            curves: Some(Vec::new()),
            ..TlsOptions::default()
        })
        .expect_err("empty curve list must fail");
        assert!(format!("{error:#}").contains("curves"));
    }
}
