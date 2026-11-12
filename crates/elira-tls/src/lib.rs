use std::fs;
use std::io;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspResponse, OcspResponseStatus};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ClientHello, ProducesTickets, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::{RootCertStore, ServerConfig, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod openssl_backend;
mod ticket;

#[derive(Debug, Clone)]
pub struct NamedCert {
    pub names: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,

    pub ocsp: Option<PathBuf>,
}

pub struct ServerOptions<'a> {
    pub default: Option<(&'a Path, &'a Path)>,
    pub named: &'a [NamedCert],

    pub reject_unknown_sni: bool,

    pub verify_ocsp: bool,
    pub client_ca: Option<&'a Path>,

    pub client_crl: Option<&'a Path>,
    pub client_auth: ClientAuth,
    pub tls13_only: bool,

    pub ocsp: Option<&'a Path>,

    pub cipher_suites: Option<&'a [String]>,

    pub curves: Option<&'a [String]>,

    pub ticket_key: Option<&'a Path>,

    pub session_tickets: usize,

    pub session_cache: usize,

    pub early_data: u32,
}

const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

type NamedCertKey = (Vec<String>, Arc<CertifiedKey>);

#[derive(Debug, Clone)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    Off,

    Optional,

    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Rustls,
    Openssl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

#[derive(Clone)]
pub enum TlsServerConfig {
    Rustls(Arc<rustls::ServerConfig>),
    Openssl(Arc<openssl::ssl::SslAcceptor>),
}

pub enum TlsStream<S> {
    Rustls(Box<tokio_rustls::server::TlsStream<S>>),
    Openssl(tokio_openssl::SslStream<S>),
}

impl<S> TlsStream<S> {
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Rustls(stream) => stream.get_ref().1.alpn_protocol(),
            Self::Openssl(stream) => stream.ssl().selected_alpn_protocol(),
        }
    }

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

    #[error("verify OCSP for {path}: {reason}")]
    OcspVerification { path: PathBuf, reason: String },

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

pub fn server_config(cert: &Path, key: &Path) -> Result<ServerConfig, Error> {
    server_config_with_options(&ServerOptions {
        default: Some((cert, key)),
        named: &[],
        reject_unknown_sni: false,
        verify_ocsp: false,
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

pub fn server_config_with_options(options: &ServerOptions<'_>) -> Result<ServerConfig, Error> {
    build(options, &ALPN_PROTOCOLS)
}

pub fn server_config_with_client_auth(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
    mode: ClientAuth,
) -> Result<ServerConfig, Error> {
    server_config_with_options(&ServerOptions {
        default: Some((cert, key)),
        named: &[],
        reject_unknown_sni: false,
        verify_ocsp: false,
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

pub fn quic_server_config(cert: &Path, key: &Path) -> Result<ServerConfig, Error> {
    quic_server_config_with_client_auth(cert, key, None, ClientAuth::Off)
}

pub fn quic_server_config_with_client_auth(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
    mode: ClientAuth,
) -> Result<ServerConfig, Error> {
    quic_server_config_full(
        cert,
        key,
        &[],
        client_ca,
        mode,
        0,
        None,
        None,
        None,
        None,
        false,
    )
}

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
    reject_unknown_sni: bool,
) -> Result<ServerConfig, Error> {
    build(
        &ServerOptions {
            default: Some((cert, key)),
            named,
            reject_unknown_sni,
            verify_ocsp: false,
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

    let named = build_named(options.named, options.verify_ocsp)?;

    let default = match options.default {
        Some((cert, key)) => Some(Arc::new(certified(cert, key, ocsp, options.verify_ocsp)?)),
        None => None,
    };

    if default.is_none() && named.is_empty() {
        return Err(Error::NoCertificates {
            path: PathBuf::new(),
        });
    }

    let resolver = NamedResolver {
        named,
        default,
        reject_unknown: options.reject_unknown_sni,
    };
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

fn build_named(named: &[NamedCert], verify_ocsp: bool) -> Result<Vec<NamedCertKey>, Error> {
    let mut out = Vec::with_capacity(named.len());
    for entry in named {
        out.push((
            entry.names.clone(),
            Arc::new(certified(
                &entry.cert,
                &entry.key,
                read_ocsp(entry.ocsp.as_deref())?,
                verify_ocsp,
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

pub(crate) fn verify_ocsp_response(
    cert_path: &Path,
    chain: &[CertificateDer<'_>],
    response: &[u8],
) -> Result<(), Error> {
    let reason = |reason: String| Error::OcspVerification {
        path: cert_path.to_path_buf(),
        reason,
    };

    let leaf = X509::from_der(chain[0].as_ref()).map_err(|err| reason(err.to_string()))?;
    let issuer = chain
        .get(1)
        .ok_or_else(|| reason("certificate chain has no issuer".to_owned()))?;
    let issuer = X509::from_der(issuer.as_ref()).map_err(|err| reason(err.to_string()))?;

    let response = OcspResponse::from_der(response).map_err(|err| reason(err.to_string()))?;
    if response.status() != OcspResponseStatus::SUCCESSFUL {
        return Err(reason(
            "responder did not return a successful status".to_owned(),
        ));
    }
    let basic = response.basic().map_err(|err| reason(err.to_string()))?;

    let mut store = X509StoreBuilder::new().map_err(|err| reason(err.to_string()))?;
    store
        .add_cert(issuer.clone())
        .map_err(|err| reason(err.to_string()))?;
    let store = store.build();
    let mut certs = Stack::new().map_err(|err| reason(err.to_string()))?;
    certs
        .push(issuer.clone())
        .map_err(|err| reason(err.to_string()))?;
    basic
        .verify(certs.as_ref(), &store, OcspFlag::empty())
        .map_err(|err| reason(err.to_string()))?;

    let id = OcspCertId::from_cert(MessageDigest::sha1(), &leaf, &issuer)
        .map_err(|err| reason(err.to_string()))?;
    let status = basic
        .find_status(&id)
        .ok_or_else(|| reason("response does not cover this certificate".to_owned()))?;
    if status.status != OcspCertStatus::GOOD {
        return Err(reason("certificate is not reported as good".to_owned()));
    }
    Ok(())
}

fn certified(
    cert: &Path,
    key: &Path,
    ocsp: Option<Vec<u8>>,
    verify_ocsp: bool,
) -> Result<CertifiedKey, Error> {
    let chain = load_chain(cert)?;
    let key_der = load_key(key)?;
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der).map_err(|_| {
        Error::SigningKey {
            path: key.to_path_buf(),
        }
    })?;
    if verify_ocsp {
        if let Some(response) = &ocsp {
            verify_ocsp_response(cert, &chain, response)?;
        }
    }
    let mut certified = CertifiedKey::new(chain, signing);
    certified.ocsp = ocsp;
    Ok(certified)
}

#[derive(Debug)]
struct NamedResolver {
    named: Vec<NamedCertKey>,
    default: Option<Arc<CertifiedKey>>,
    reject_unknown: bool,
}

pub(crate) fn name_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    if pattern == name {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let suffix = format!(".{suffix}");
    name.strip_suffix(&suffix)
        .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
}

impl NamedResolver {
    fn pick(&self, name: Option<&str>, schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let Some(name) = name else {
            return if self.reject_unknown {
                None
            } else {
                self.default.clone()
            };
        };
        let name = name.to_ascii_lowercase();
        let mut fallback = None;

        for (names, key) in &self.named {
            let matches = names.iter().any(|pattern| name_matches(pattern, &name));
            if !matches {
                continue;
            }
            if key.key.choose_scheme(schemes).is_some() {
                return Some(key.clone());
            }
            if fallback.is_none() {
                fallback = Some(key.clone());
            }
        }

        fallback.or_else(|| {
            if self.reject_unknown {
                None
            } else {
                self.default.clone()
            }
        })
    }
}

impl ResolvesServerCert for NamedResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.pick(hello.server_name(), hello.signature_schemes())
    }
}

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

    if added == 0 {
        return Err(Error::UnusableClientCa {
            path: path.to_path_buf(),
        });
    }
    Ok(roots)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientIdentity {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
}

impl ClientIdentity {
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

pub(crate) fn load_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
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
    let pem = read_key(path)?;
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

fn read_key(path: &Path) -> Result<Vec<u8>, Error> {
    let meta = fs::symlink_metadata(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.file_type().is_symlink() {
        return Err(Error::PrivateKey {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "key is a symlink"),
        });
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "elira: warning: private key {} is mode {mode:o}; expected 0600",
            path.display()
        );
    }
    fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
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

        fn write_key(&self, name: &str, body: &[u8]) -> PathBuf {
            let path = self.write(name, body);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod fixture");
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
        let dir = TempDir::new("missing-key");
        let key = dir.path().join("absent.pem");

        let err = load_key(&key).expect_err("absent key");
        assert!(matches!(err, Error::Read { .. }), "got {err:?}");
        assert!(err.to_string().contains("absent.pem"), "got {err}");
    }

    #[test]
    fn empty_key_file_fails() {
        let dir = TempDir::new("empty-key");
        let key = dir.write_key("key.pem", b"");

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
            certified(
                &fixtures.join("cert.pem"),
                &fixtures.join("key.pem"),
                None,
                false,
            )
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
            reject_unknown: false,
        };

        assert!(resolver.pick(Some("A.Example.COM"), &[]).is_some());
        assert!(resolver.pick(Some("x.b.example.com"), &[]).is_some());
        assert!(
            resolver.pick(Some("deep.x.b.example.com"), &[]).is_some(),
            "no match should still fall back to the default"
        );
        assert!(resolver.pick(Some("x.wild.example.com"), &[]).is_some());

        let no_default = NamedResolver {
            named: vec![(vec!["*.b.example.com".to_owned()], key)],
            default: None,
            reject_unknown: false,
        };
        assert!(no_default.pick(Some("b.example.com"), &[]).is_none());
        assert!(no_default.pick(Some("x.b.example.com"), &[]).is_some());
        assert!(no_default.pick(Some("deep.x.b.example.com"), &[]).is_none());
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
                reject_unknown_sni: false,
                verify_ocsp: false,
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
            named: build_named(&named, false).expect("named certificates"),
            default: None,
            reject_unknown: false,
        };

        let a = resolver.pick(Some("a.example.com"), &[]).expect("a");
        assert_eq!(a.ocsp.as_deref(), Some(&b"ocsp-for-a"[..]));
        let b = resolver.pick(Some("b.example.com"), &[]).expect("b");
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
            reject_unknown_sni: false,
            verify_ocsp: false,
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
            reject_unknown_sni: false,
            verify_ocsp: false,
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
            reject_unknown_sni: false,
            verify_ocsp: false,
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
            false,
        )
        .expect_err("TLS 1.2 suite on QUIC");
        assert!(matches!(err, Error::QuicNeedsTls13Suite), "{err:?}");
    }
}

#[cfg(test)]
mod wildcard_tests {
    use super::name_matches;

    #[test]
    fn wildcard_matches_one_label_only() {
        assert!(name_matches("*.example.com", "a.example.com"));
        assert!(!name_matches("*.example.com", "example.com"));
        assert!(!name_matches("*.example.com", "a.b.example.com"));
        assert!(!name_matches("*.example.com", "notexample.com"));
        assert!(name_matches("example.com", "example.com"));
    }
}
