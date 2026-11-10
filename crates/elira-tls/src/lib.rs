//! TLS configuration.
//!
//! Certificate and key material comes from PEM files written by the operator.
//! Problems with that material must fail at startup, with the offending path in
//! the message, rather than surface later as a handshake failure.

use std::fs;
use std::io;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ClientHello, ProducesTickets, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::{RootCertStore, ServerConfig};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod openssl_backend;

/// A certificate that answers for a set of Server Name Indication values.
#[derive(Debug, Clone)]
pub struct NamedCert {
    pub names: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// DER OCSP response to staple for this certificate.
    pub ocsp: Option<PathBuf>,
}

/// Everything a TLS listener can be configured with.
pub struct ServerOptions<'a> {
    /// The certificate used when SNI does not match anything.
    pub default: Option<(&'a Path, &'a Path)>,
    pub named: &'a [NamedCert],
    pub client_ca: Option<&'a Path>,
    /// Pem bundle of CRLs used when a client certificate is presented.
    pub client_crl: Option<&'a Path>,
    pub client_auth: ClientAuth,
    pub tls13_only: bool,
    /// DER OCSP response for the default certificate.
    pub ocsp: Option<&'a Path>,
    /// Cipher suites to offer. `None` keeps the provider defaults.
    pub cipher_suites: Option<&'a [String]>,
    /// Key exchange groups to offer. `None` keeps the provider defaults.
    pub curves: Option<&'a [String]>,
    /// 32-byte key file for stateless TLS tickets shared between workers.
    pub ticket_key: Option<&'a Path>,
    /// TLS 1.3 tickets per handshake.
    pub session_tickets: usize,
    /// In-memory session cache entries; zero disables resumption.
    pub session_cache: usize,
    /// Maximum 0-RTT early data in bytes; zero disables early data.
    pub early_data: u32,
}

/// ALPN order matters: clients that accept both get the first shared protocol.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

type NamedCertKey = (Vec<String>, Arc<CertifiedKey>);

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

/// TLS implementation for inbound TCP listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Rustls,
    Openssl,
}

/// Lowest TLS protocol version offered by the OpenSSL backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

/// A built server configuration for either TLS backend.
#[derive(Clone)]
pub enum TlsServerConfig {
    Rustls(Arc<rustls::ServerConfig>),
    Openssl(Arc<openssl::ssl::SslAcceptor>),
}

/// An accepted TLS stream, regardless of backend.
pub enum TlsStream<S> {
    Rustls(Box<tokio_rustls::server::TlsStream<S>>),
    Openssl(tokio_openssl::SslStream<S>),
}

impl<S> TlsStream<S> {
    /// Negotiated ALPN protocol, if the client offered one.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Rustls(stream) => stream.get_ref().1.alpn_protocol(),
            Self::Openssl(stream) => stream.ssl().selected_alpn_protocol(),
        }
    }

    /// DER bytes of the verified client certificate.
    pub fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        match self {
            Self::Rustls(stream) => stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|leaf| leaf.as_ref().to_vec()),
            Self::Openssl(stream) => stream
                .ssl()
                .peer_certificate()
                .and_then(|certificate| certificate.to_der().ok()),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Openssl(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Rustls(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Openssl(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(stream) => Pin::new(stream).poll_flush(context),
            Self::Openssl(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Openssl(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

/// Build the configured backend.
pub fn server_config_for(
    options: &ServerOptions<'_>,
    backend: Backend,
    min_version: TlsVersion,
) -> Result<TlsServerConfig, Error> {
    match backend {
        Backend::Rustls => Ok(TlsServerConfig::Rustls(Arc::new(
            server_config_with_options(options)?,
        ))),
        Backend::Openssl => Ok(TlsServerConfig::Openssl(Arc::new(
            openssl_backend::acceptor(options, min_version)?,
        ))),
    }
}

/// Complete the TLS handshake on an accepted socket.
pub async fn accept<S>(config: &TlsServerConfig, stream: S) -> Result<TlsStream<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match config {
        TlsServerConfig::Rustls(config) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
            let stream = acceptor
                .accept(stream)
                .await
                .map_err(|error| Error::Handshake(error.to_string()))?;
            Ok(TlsStream::Rustls(Box::new(stream)))
        }
        TlsServerConfig::Openssl(config) => {
            let ssl = openssl::ssl::Ssl::new(config.context())
                .map_err(|error| Error::Handshake(error.to_string()))?;
            let mut stream = tokio_openssl::SslStream::new(ssl, stream)
                .map_err(|error| Error::Handshake(error.to_string()))?;
            Pin::new(&mut stream)
                .accept()
                .await
                .map_err(|error| Error::Handshake(error.to_string()))?;
            Ok(TlsStream::Openssl(stream))
        }
    }
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

    #[error("parse CRLs in {path}: {source}")]
    Crls {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("no CRLs in {path}")]
    NoCrls { path: PathBuf },

    #[error("ticket key: {0}")]
    TicketKey(String),

    #[error("TLS handshake failed: {0}")]
    Handshake(String),

    #[error("unsupported TLS option: {option}")]
    UnsupportedOption { option: String },

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

    #[error("private key in {path} cannot be used for signing")]
    SigningKey { path: PathBuf },

    #[error("parse certificate {path}: {reason}")]
    ParseCertificate { path: PathBuf, reason: String },

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

    #[error("unknown cipher suite {name:?}")]
    UnknownCipherSuite { name: String },

    #[error("unknown key exchange group {name:?}")]
    UnknownCurve { name: String },

    #[error("QUIC requires TLS 1.3 cipher suites")]
    QuicNeedsTls13Suite,
}

/// Build a server configuration from a PEM certificate chain and private key.
///
/// Client certificates are not requested. Use
/// [`server_config_with_client_auth`] when a client CA trust store exists.
pub fn server_config(cert: &Path, key: &Path) -> Result<ServerConfig, Error> {
    server_config_with_options(&ServerOptions {
        default: Some((cert, key)),
        named: &[],
        client_ca: None,
        client_crl: None,
        client_auth: ClientAuth::Off,
        tls13_only: false,
        ocsp: None,
        cipher_suites: None,
        curves: None,
        ticket_key: None,
        session_tickets: 2,
        session_cache: 256,
        early_data: 0,
    })
}

/// Build a TLS listener with SNI-selected certificates, optional client
/// authentication, and a chosen minimum protocol version.
pub fn server_config_with_options(options: &ServerOptions<'_>) -> Result<ServerConfig, Error> {
    build(options, &ALPN_PROTOCOLS)
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
    server_config_with_options(&ServerOptions {
        default: Some((cert, key)),
        named: &[],
        client_ca,
        client_crl: None,
        client_auth: mode,
        tls13_only: false,
        ocsp: None,
        cipher_suites: None,
        curves: None,
        ticket_key: None,
        session_tickets: 2,
        session_cache: 256,
        early_data: 0,
    })
}

/// Same material, but for QUIC: HTTP/3 is the only protocol a QUIC endpoint
/// can negotiate, so the ALPN list is shorter.
pub fn quic_server_config(cert: &Path, key: &Path) -> Result<ServerConfig, Error> {
    quic_server_config_with_client_auth(cert, key, None, ClientAuth::Off)
}

/// QUIC always uses TLS 1.3; only the client certificate policy varies.
pub fn quic_server_config_with_client_auth(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
    mode: ClientAuth,
) -> Result<ServerConfig, Error> {
    quic_server_config_full(cert, key, &[], client_ca, mode, 0, None, None, None, None)
}

/// QUIC listener with SNI-selected certificates as well as client auth.
#[allow(clippy::too_many_arguments)]
pub fn quic_server_config_full(
    cert: &Path,
    key: &Path,
    named: &[NamedCert],
    client_ca: Option<&Path>,
    mode: ClientAuth,
    early_data: u32,
    cipher_suites: Option<&[String]>,
    curves: Option<&[String]>,
    client_crl: Option<&Path>,
    ticket_key: Option<&Path>,
) -> Result<ServerConfig, Error> {
    build(
        &ServerOptions {
            default: Some((cert, key)),
            named,
            client_ca,
            client_crl,
            client_auth: mode,
            tls13_only: true,
            ocsp: None,
            cipher_suites,
            curves,
            ticket_key,
            session_tickets: 2,
            session_cache: 256,
            early_data,
        },
        &[b"h3"],
    )
}

fn crypto_provider(
    cipher_suites: Option<&[String]>,
    curves: Option<&[String]>,
) -> Result<CryptoProvider, Error> {
    let defaults = rustls::crypto::aws_lc_rs::default_provider();

    let cipher_suites = match cipher_suites {
        None => defaults.cipher_suites,
        Some(names) => {
            let mut selected = Vec::with_capacity(names.len());
            for name in names {
                let wanted = name.trim();
                let suite = rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES
                    .iter()
                    .find(|suite| {
                        suite
                            .suite()
                            .as_str()
                            .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
                    })
                    .copied()
                    .ok_or_else(|| Error::UnknownCipherSuite {
                        name: wanted.to_owned(),
                    })?;
                selected.push(suite);
            }
            selected
        }
    };

    let kx_groups = match curves {
        None => defaults.kx_groups,
        Some(names) => {
            let mut selected = Vec::with_capacity(names.len());
            for name in names {
                let wanted = name.trim();
                let group = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS
                    .iter()
                    .find(|group| {
                        group
                            .name()
                            .as_str()
                            .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
                    })
                    .copied()
                    .ok_or_else(|| Error::UnknownCurve {
                        name: wanted.to_owned(),
                    })?;
                selected.push(group);
            }
            selected
        }
    };

    Ok(CryptoProvider {
        cipher_suites,
        kx_groups,
        ..defaults
    })
}

struct KeyTicketer {
    key: LessSafeKey,
    name: [u8; 16],
    lifetime: u32,
}

impl std::fmt::Debug for KeyTicketer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyTicketer")
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl KeyTicketer {
    fn new(bytes: [u8; 32]) -> Result<Self, Error> {
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &bytes)
                .map_err(|_| Error::TicketKey("invalid AES-256-GCM key".to_owned()))?,
        );
        let mut name = [0u8; 16];
        name.copy_from_slice(&bytes[..16]);
        Ok(Self {
            key,
            name,
            lifetime: 12 * 60 * 60,
        })
    }
}

impl ProducesTickets for KeyTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        aws_lc_rs::rand::fill(&mut nonce_bytes).ok()?;
        let mut ciphertext = plain.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(&self.name[..]),
                &mut ciphertext,
            )
            .ok()?;
        let mut ticket = Vec::with_capacity(16 + 12 + ciphertext.len());
        ticket.extend_from_slice(&self.name);
        ticket.extend_from_slice(&nonce_bytes);
        ticket.extend_from_slice(&ciphertext);
        Some(ticket)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        if cipher.len() < 16 + 12 + 16 || cipher[..16] != self.name {
            return None;
        }
        let nonce = Nonce::assume_unique_for_key(cipher[16..28].try_into().ok()?);
        let mut plain = cipher[28..].to_vec();
        self.key
            .open_in_place(nonce, Aad::from(&self.name[..]), &mut plain)
            .ok()
            .map(|value| value.to_vec())
    }
}

fn load_ticket_key(path: &Path) -> Result<[u8; 32], Error> {
    match fs::read(path) {
        Ok(bytes) => decode_ticket_key(path, &bytes),
        Err(err) if err.kind() == io::ErrorKind::NotFound => create_ticket_key(path),
        Err(source) => Err(Error::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn decode_ticket_key(path: &Path, bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.len() != 32 {
        return Err(Error::TicketKey(format!(
            "{} must contain exactly 32 bytes",
            path.display()
        )));
    }
    let mode = fs::metadata(path)
        .map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::TicketKey(format!(
            "{} is mode {mode:o}; expected 0600",
            path.display()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Ok(key)
}

fn create_ticket_key(path: &Path) -> Result<[u8; 32], Error> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    match options.open(path) {
        Ok(mut file) => {
            let mut key = [0u8; 32];
            aws_lc_rs::rand::fill(&mut key)
                .map_err(|_| Error::TicketKey("cannot generate a ticket key".to_owned()))?;
            file.write_all(&key).map_err(|source| Error::Read {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(key)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            let bytes = fs::read(path).map_err(|source| Error::Read {
                path: path.to_path_buf(),
                source,
            })?;
            decode_ticket_key(path, &bytes)
        }
        Err(source) => Err(Error::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn build(options: &ServerOptions<'_>, alpn: &[&[u8]]) -> Result<ServerConfig, Error> {
    // Pick the provider explicitly. Relying on the process default breaks as
    // soon as another crate enables a second backend, which quinn does.
    let provider = Arc::new(crypto_provider(options.cipher_suites, options.curves)?);
    if options.tls13_only
        && options.cipher_suites.is_some()
        && provider
            .cipher_suites
            .iter()
            .any(|suite| !matches!(suite, rustls::SupportedCipherSuite::Tls13(_)))
    {
        return Err(Error::QuicNeedsTls13Suite);
    }
    let client_verifier = client_verifier(
        options.client_ca,
        options.client_auth,
        options.client_crl,
        provider.clone(),
    )?;

    let versions: &[&rustls::SupportedProtocolVersion] = if options.tls13_only {
        &[&rustls::version::TLS13]
    } else {
        rustls::ALL_VERSIONS
    };
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("aws-lc-rs supports the requested protocol versions");

    let builder = match client_verifier {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };

    let ocsp = read_ocsp(options.ocsp)?;

    let named = build_named(options.named)?;

    let default = match options.default {
        Some((cert, key)) => Some(Arc::new(certified(cert, key, ocsp)?)),
        None => None,
    };

    if default.is_none() && named.is_empty() {
        return Err(Error::NoCertificates {
            path: PathBuf::new(),
        });
    }

    let resolver = NamedResolver { named, default };
    let mut config = builder.with_cert_resolver(Arc::new(resolver));
    if let Some(path) = options.ticket_key {
        config.ticketer = Arc::new(KeyTicketer::new(load_ticket_key(path)?)?);
    }
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.send_tls13_tickets = options.session_tickets;
    config.session_storage = if options.session_cache == 0 {
        Arc::new(rustls::server::NoServerSessionStorage {})
    } else {
        rustls::server::ServerSessionMemoryCache::new(options.session_cache)
    };
    config.max_early_data_size = options.early_data;
    Ok(config)
}

fn build_named(named: &[NamedCert]) -> Result<Vec<NamedCertKey>, Error> {
    let mut out = Vec::with_capacity(named.len());
    for entry in named {
        out.push((
            entry.names.clone(),
            Arc::new(certified(
                &entry.cert,
                &entry.key,
                read_ocsp(entry.ocsp.as_deref())?,
            )?),
        ));
    }
    Ok(out)
}

fn read_ocsp(path: Option<&Path>) -> Result<Option<Vec<u8>>, Error> {
    match path {
        Some(path) => Ok(Some(fs::read(path).map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?)),
        None => Ok(None),
    }
}

fn certified(cert: &Path, key: &Path, ocsp: Option<Vec<u8>>) -> Result<CertifiedKey, Error> {
    let chain = load_chain(cert)?;
    let key_der = load_key(key)?;
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der).map_err(|_| {
        Error::SigningKey {
            path: key.to_path_buf(),
        }
    })?;
    let mut certified = CertifiedKey::new(chain, signing);
    certified.ocsp = ocsp;
    Ok(certified)
}

/// SNI dispatcher. Exact names win; `*.example.com` matches exactly one label.
/// A client without SNI gets the default certificate.
#[derive(Debug)]
struct NamedResolver {
    named: Vec<NamedCertKey>,
    default: Option<Arc<CertifiedKey>>,
}

impl NamedResolver {
    fn pick(&self, name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let Some(name) = name else {
            return self.default.clone();
        };
        let name = name.to_ascii_lowercase();

        for (names, key) in &self.named {
            for pattern in names {
                let pattern = pattern.to_ascii_lowercase();
                if pattern == name {
                    return Some(key.clone());
                }
                if let Some(suffix) = pattern.strip_prefix("*.") {
                    let suffix = format!(".{suffix}");
                    if let Some(prefix) = name.strip_suffix(suffix.as_str()) {
                        // The dot is part of the suffix, so `prefix` is the
                        // label before it. A nested name must not match.
                        if !prefix.is_empty() && !prefix.ends_with('.') && !prefix.contains('.') {
                            return Some(key.clone());
                        }
                    }
                }
            }
        }

        self.default.clone()
    }
}

impl ResolvesServerCert for NamedResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.pick(hello.server_name())
    }
}

/// Build the client certificate verifier, or `None` when clients are not
/// authenticated at all.
fn client_verifier(
    client_ca: Option<&Path>,
    mode: ClientAuth,
    client_crl: Option<&Path>,
    provider: Arc<CryptoProvider>,
) -> Result<Option<Arc<dyn ClientCertVerifier>>, Error> {
    if mode == ClientAuth::Off {
        return Ok(None);
    }

    let path = client_ca.ok_or(Error::ClientCaRequired)?;
    let roots = load_client_ca(path)?;

    // The two modes differ only in whether a client may omit its certificate.
    // `build` is the strict path, which is also what Required needs.
    let builder = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
    let builder = match client_crl {
        Some(path) => builder.with_crls(load_crls(path)?),
        None => builder,
    };
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

fn load_crls(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>, Error> {
    let pem = read(path)?;
    let mut reader = pem.as_slice();
    let crls = rustls_pemfile::crls(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| Error::Crls {
            path: path.to_path_buf(),
            source,
        })?;
    if crls.is_empty() {
        return Err(Error::NoCrls {
            path: path.to_path_buf(),
        });
    }
    Ok(crls)
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

/// Identity taken from a verified client certificate during the TLS handshake.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientIdentity {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
}

impl ClientIdentity {
    /// Parse the common names out of a DER-encoded leaf certificate.
    pub fn parse(leaf: &[u8]) -> Option<Self> {
        let (_, certificate) = x509_parser::parse_x509_certificate(leaf).ok()?;
        let subject = certificate.subject();
        let subject_cn = subject
            .iter_common_name()
            .next()
            .and_then(|value| value.as_str().ok())
            .map(str::to_owned);
        let issuer = certificate.issuer();
        let issuer_cn = issuer
            .iter_common_name()
            .next()
            .and_then(|value| value.as_str().ok())
            .map(str::to_owned);
        Some(Self {
            subject_cn,
            issuer_cn,
        })
    }
}

/// Expiry of the leaf certificate, for an operational gauge.
pub fn certificate_expiry(path: &Path) -> Result<std::time::SystemTime, Error> {
    let chain = load_chain(path)?;
    let leaf = chain.first().ok_or_else(|| Error::ParseCertificate {
        path: path.to_path_buf(),
        reason: "empty chain".to_owned(),
    })?;
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|error| {
        Error::ParseCertificate {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
    })?;
    let timestamp = certificate.validity().not_after.timestamp();
    if timestamp < 0 {
        return Err(Error::ParseCertificate {
            path: path.to_path_buf(),
            reason: "expiry before the Unix epoch".to_owned(),
        });
    }
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64))
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

    #[test]
    fn sni_matching_is_exact_and_wildcard_shallow() {
        let fixtures = fixtures();
        let key = Arc::new(
            certified(&fixtures.join("cert.pem"), &fixtures.join("key.pem"), None)
                .expect("fixture certificate"),
        );
        let resolver = NamedResolver {
            named: vec![(
                vec![
                    "a.example.com".to_owned(),
                    "*.b.example.com".to_owned(),
                    "*.wild.example.com".to_owned(),
                ],
                key.clone(),
            )],
            default: Some(key.clone()),
        };

        assert!(resolver.pick(Some("A.Example.COM")).is_some());
        assert!(resolver.pick(Some("x.b.example.com")).is_some());
        assert!(
            resolver.pick(Some("deep.x.b.example.com")).is_some(),
            "no match should still fall back to the default"
        );
        assert!(resolver.pick(Some("x.wild.example.com")).is_some());

        let no_default = NamedResolver {
            named: vec![(vec!["*.b.example.com".to_owned()], key)],
            default: None,
        };
        assert!(no_default.pick(Some("b.example.com")).is_none());
        assert!(no_default.pick(Some("x.b.example.com")).is_some());
        assert!(no_default.pick(Some("deep.x.b.example.com")).is_none());
    }

    #[test]
    fn shared_ticket_key_round_trips_between_configs() {
        let fixtures = fixtures();
        let dir = TempDir::new("ticket");
        let key_path = dir.path().join("ticket.key");

        let build = |key_path: &Path| {
            server_config_with_options(&ServerOptions {
                default: Some((&fixtures.join("cert.pem"), &fixtures.join("key.pem"))),
                named: &[],
                client_ca: None,
                client_crl: None,
                client_auth: ClientAuth::Off,
                tls13_only: false,
                ocsp: None,
                cipher_suites: None,
                curves: None,
                ticket_key: Some(key_path),
                session_tickets: 2,
                session_cache: 256,
                early_data: 0,
            })
            .expect("ticket config")
        };

        let first = build(&key_path);
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let ticket = first.ticketer.encrypt(b"session state").expect("encrypt");
        let second = build(&key_path);
        assert_eq!(
            second.ticketer.decrypt(&ticket).as_deref(),
            Some(b"session state".as_slice())
        );

        let other_dir = TempDir::new("ticket-other");
        let other = build(&other_dir.path().join("ticket.key"));
        assert!(other.ticketer.decrypt(&ticket).is_none());
    }

    #[test]
    fn sni_certificates_carry_their_own_ocsp() {
        let fixtures = fixtures();
        let dir = TempDir::new("sni-ocsp");
        let ocsp_a = dir.write("a.ocsp", b"ocsp-for-a");
        let ocsp_b = dir.write("b.ocsp", b"ocsp-for-b");

        let named = vec![
            NamedCert {
                names: vec!["a.example.com".to_owned()],
                cert: fixtures.join("cert.pem"),
                key: fixtures.join("key.pem"),
                ocsp: Some(ocsp_a),
            },
            NamedCert {
                names: vec!["b.example.com".to_owned()],
                cert: fixtures.join("cert.pem"),
                key: fixtures.join("key.pem"),
                ocsp: Some(ocsp_b),
            },
        ];

        let resolver = NamedResolver {
            named: build_named(&named).expect("named certificates"),
            default: None,
        };

        let a = resolver.pick(Some("a.example.com")).expect("a");
        assert_eq!(a.ocsp.as_deref(), Some(&b"ocsp-for-a"[..]));
        let b = resolver.pick(Some("b.example.com")).expect("b");
        assert_eq!(b.ocsp.as_deref(), Some(&b"ocsp-for-b"[..]));
    }

    #[test]
    fn cipher_suites_and_curves_are_selected() {
        let fixtures = fixtures();
        let suites = vec!["TLS13_AES_128_GCM_SHA256".to_owned()];
        let curves = vec!["X25519".to_owned()];

        let config = server_config_with_options(&ServerOptions {
            default: Some((&fixtures.join("cert.pem"), &fixtures.join("key.pem"))),
            named: &[],
            client_ca: None,
            client_crl: None,
            client_auth: ClientAuth::Off,
            tls13_only: true,
            ocsp: None,
            cipher_suites: Some(&suites),
            curves: Some(&curves),
            ticket_key: None,
            session_tickets: 2,
            session_cache: 256,
            early_data: 0,
        })
        .expect("restricted policy");

        let provider = config.crypto_provider();
        assert_eq!(provider.cipher_suites.len(), 1);
        assert_eq!(
            provider.cipher_suites[0].suite().as_str(),
            Some("TLS13_AES_128_GCM_SHA256")
        );
        assert_eq!(provider.kx_groups.len(), 1);
        assert_eq!(provider.kx_groups[0].name().as_str(), Some("X25519"));
    }

    #[test]
    fn unknown_tls_policy_names_fail() {
        let fixtures = fixtures();
        let suites = vec!["NOT_A_SUITE".to_owned()];
        let err = server_config_with_options(&ServerOptions {
            default: Some((&fixtures.join("cert.pem"), &fixtures.join("key.pem"))),
            named: &[],
            client_ca: None,
            client_crl: None,
            client_auth: ClientAuth::Off,
            tls13_only: false,
            ocsp: None,
            cipher_suites: Some(&suites),
            curves: None,
            ticket_key: None,
            session_tickets: 2,
            session_cache: 256,
            early_data: 0,
        })
        .expect_err("unknown suite");
        assert!(matches!(err, Error::UnknownCipherSuite { .. }), "{err:?}");

        let curves = vec!["NOT_A_CURVE".to_owned()];
        let err = server_config_with_options(&ServerOptions {
            default: Some((&fixtures.join("cert.pem"), &fixtures.join("key.pem"))),
            named: &[],
            client_ca: None,
            client_crl: None,
            client_auth: ClientAuth::Off,
            tls13_only: false,
            ocsp: None,
            cipher_suites: None,
            curves: Some(&curves),
            ticket_key: None,
            session_tickets: 2,
            session_cache: 256,
            early_data: 0,
        })
        .expect_err("unknown curve");
        assert!(matches!(err, Error::UnknownCurve { .. }), "{err:?}");
    }

    #[test]
    fn quic_rejects_a_tls12_cipher_suite() {
        let fixtures = fixtures();
        let suites = vec!["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_owned()];
        let err = quic_server_config_full(
            &fixtures.join("cert.pem"),
            &fixtures.join("key.pem"),
            &[],
            None,
            ClientAuth::Off,
            0,
            Some(&suites),
            None,
            None,
            None,
        )
        .expect_err("TLS 1.2 suite on QUIC");
        assert!(matches!(err, Error::QuicNeedsTls13Suite), "{err:?}");
    }
}
