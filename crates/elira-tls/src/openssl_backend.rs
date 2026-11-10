//! OpenSSL TLS backend, including legacy protocol versions.
//!
//! The rustls path stays the default. This backend exists so a listener can
//! offer TLS 1.0/1.1 to old clients while keeping the rest of the proxy on
//! rustls.

use std::path::Path;
use std::sync::Arc;

use openssl::pkey::PKey;
use openssl::ssl::{
    AlpnError, NameType, SniError, SslAcceptor, SslContextBuilder, SslFiletype, SslMethod,
    SslOptions, SslVerifyMode, SslVersion,
};
use openssl::x509::store::X509Lookup;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;

use crate::ticket;
use crate::{ClientAuth, Error, ServerOptions, TlsVersion};

const ALPN: &[u8] = b"\x02h2\x08http/1.1";

pub fn acceptor(
    options: &ServerOptions<'_>,
    min_version: TlsVersion,
) -> Result<SslAcceptor, Error> {
    let ticket_key = options.ticket_key.map(crate::load_ticket_key).transpose()?;

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .map_err(|error| handshake(error.to_string()))?;
    configure(
        &mut builder,
        options,
        options.default,
        options.ocsp,
        min_version,
    )?;

    let mut named = Vec::new();
    for cert in options.named {
        let mut context = SslContextBuilder::new(SslMethod::tls_server())
            .map_err(|error| handshake(error.to_string()))?;
        configure(
            &mut context,
            options,
            Some((cert.cert.as_path(), cert.key.as_path())),
            cert.ocsp.as_deref(),
            min_version,
        )?;
        let context = context.build();
        if let Some(key) = &ticket_key {
            ticket::install(&context, key)?;
        }
        named.push((cert.names.clone(), Arc::new(context)));
    }
    let named = Arc::new(named);

    builder.set_servername_callback(move |ssl, _alert| {
        let Some(name) = ssl.servername(NameType::HOST_NAME) else {
            return Ok(());
        };
        let name = name.to_ascii_lowercase();
        if let Some((_, context)) = named.iter().find(|(names, _)| {
            names.iter().any(|pattern| {
                let pattern = pattern.to_ascii_lowercase();
                pattern == name
                    || pattern
                        .strip_prefix("*.")
                        .is_some_and(|suffix| name.ends_with(suffix))
            })
        }) {
            ssl.set_ssl_context(context)
                .map_err(|_| SniError::ALERT_FATAL)?;
        }
        Ok(())
    });

    let acceptor = builder.build();
    if let Some(key) = &ticket_key {
        ticket::install(acceptor.context(), key)?;
    }
    Ok(acceptor)
}

fn configure(
    builder: &mut SslContextBuilder,
    options: &ServerOptions<'_>,
    cert: Option<(&Path, &Path)>,
    ocsp: Option<&Path>,
    min_version: TlsVersion,
) -> Result<(), Error> {
    if let Some((cert, key)) = cert {
        builder
            .set_certificate_file(cert, SslFiletype::PEM)
            .map_err(|_| Error::Certificates {
                path: cert.to_owned(),
                source: std::io::Error::other("OpenSSL rejected the certificate"),
            })?;
        let key = PKey::private_key_from_pem(&std::fs::read(key).map_err(|source| {
            Error::PrivateKey {
                path: key.to_owned(),
                source,
            }
        })?)
        .map_err(|_| Error::PrivateKey {
            path: key.to_owned(),
            source: std::io::Error::other("OpenSSL rejected the private key"),
        })?;
        builder
            .set_private_key(&key)
            .map_err(|error| handshake(error.to_string()))?;
        builder
            .check_private_key()
            .map_err(|error| handshake(error.to_string()))?;
    }

    builder
        .set_min_proto_version(Some(version(min_version)))
        .map_err(|error| handshake(error.to_string()))?;
    if matches!(min_version, TlsVersion::Tls10 | TlsVersion::Tls11) {
        builder.clear_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
        builder.set_security_level(0);
        if options.cipher_suites.is_none() {
            builder
                .set_cipher_list("DEFAULT:@SECLEVEL=0")
                .map_err(|error| handshake(error.to_string()))?;
        }
    }
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| handshake(error.to_string()))?;

    match options.client_auth {
        ClientAuth::Off => {}
        ClientAuth::Optional => {
            builder.set_verify(SslVerifyMode::PEER);
        }
        ClientAuth::Required => {
            builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }
    }
    if let Some(ca) = options.client_ca {
        builder.set_ca_file(ca).map_err(|_| Error::Read {
            path: ca.to_owned(),
            source: std::io::Error::other("OpenSSL rejected the CA bundle"),
        })?;
    }
    if options.client_crl.is_some() {
        let mut store = X509StoreBuilder::new().map_err(|error| handshake(error.to_string()))?;
        add_ca(&mut store, options.client_ca)?;
        add_crls(&mut store, options.client_crl)?;
        builder.set_cert_store(store.build());
    }

    builder.set_alpn_select_callback(|_ssl, client| {
        openssl::ssl::select_next_proto(ALPN, client).ok_or(AlpnError::NOACK)
    });

    if let Some(suites) = options.cipher_suites {
        let (pre13, tls13) = cipher_lists(suites)?;
        if !pre13.is_empty() {
            builder
                .set_cipher_list(&pre13)
                .map_err(|error| handshake(error.to_string()))?;
        }
        if !tls13.is_empty() {
            builder
                .set_ciphersuites(&tls13)
                .map_err(|error| handshake(error.to_string()))?;
        }
    }
    if let Some(curves) = options.curves {
        let list = curves
            .iter()
            .map(|curve| curve_name(curve))
            .collect::<Result<Vec<_>, _>>()?
            .join(":");
        builder
            .set_groups_list(&list)
            .map_err(|error| handshake(error.to_string()))?;
    }

    builder
        .set_num_tickets(options.session_tickets)
        .map_err(|error| handshake(error.to_string()))?;
    if options.session_cache == 0 {
        builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::OFF);
    }

    if let Some(ocsp) = ocsp {
        let data = std::fs::read(ocsp).map_err(|source| Error::Read {
            path: ocsp.to_owned(),
            source,
        })?;
        let data = Arc::new(data);
        builder
            .set_status_callback(move |ssl| {
                ssl.set_ocsp_status(&data)
                    .map_err(|_| openssl::error::ErrorStack::get())?;
                Ok(true)
            })
            .map_err(|error| handshake(error.to_string()))?;
    }

    // Explicitly disable renegotiation and old unsafe options.
    builder.set_options(SslOptions::NO_RENEGOTIATION);
    Ok(())
}

fn add_ca(store: &mut X509StoreBuilder, ca: Option<&Path>) -> Result<(), Error> {
    let Some(ca) = ca else {
        return Ok(());
    };
    let data = std::fs::read(ca).map_err(|source| Error::Read {
        path: ca.to_owned(),
        source,
    })?;
    for cert in X509::stack_from_pem(&data).map_err(|_| Error::Certificates {
        path: ca.to_owned(),
        source: std::io::Error::other("OpenSSL rejected the CA bundle"),
    })? {
        store
            .add_cert(cert)
            .map_err(|error| handshake(error.to_string()))?;
    }
    Ok(())
}

fn add_crls(store: &mut X509StoreBuilder, crl: Option<&Path>) -> Result<(), Error> {
    let Some(crl) = crl else {
        return Ok(());
    };
    let data = std::fs::read(crl).map_err(|source| Error::Read {
        path: crl.to_owned(),
        source,
    })?;
    if data.is_empty() {
        return Err(Error::NoCrls {
            path: crl.to_owned(),
        });
    }
    let lookup = store
        .add_lookup(X509Lookup::file())
        .map_err(|error| handshake(error.to_string()))?;
    lookup
        .load_crl_file(crl, SslFiletype::PEM)
        .map_err(|_| Error::Crls {
            path: crl.to_owned(),
            source: std::io::Error::other("OpenSSL rejected the CRL bundle"),
        })?;
    store
        .set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL)
        .map_err(|error| handshake(error.to_string()))?;
    Ok(())
}

fn version(version: TlsVersion) -> SslVersion {
    match version {
        TlsVersion::Tls10 => SslVersion::TLS1,
        TlsVersion::Tls11 => SslVersion::TLS1_1,
        TlsVersion::Tls12 => SslVersion::TLS1_2,
        TlsVersion::Tls13 => SslVersion::TLS1_3,
    }
}

fn cipher_lists(suites: &[String]) -> Result<(String, String), Error> {
    let mut pre13 = Vec::new();
    let mut tls13 = Vec::new();
    for suite in suites {
        if let Some(name) = suite.strip_prefix("TLS13_") {
            tls13.push(format!("TLS_{name}"));
            continue;
        }
        let mapped = match suite.as_str() {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => "ECDHE-ECDSA-AES128-GCM-SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => "ECDHE-ECDSA-AES256-GCM-SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-ECDSA-CHACHA20-POLY1305",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => "ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => "ECDHE-RSA-AES256-GCM-SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-RSA-CHACHA20-POLY1305",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" => "ECDHE-ECDSA-AES128-SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => "ECDHE-ECDSA-AES256-SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => "ECDHE-RSA-AES128-SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => "ECDHE-RSA-AES256-SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256" => "AES128-GCM-SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384" => "AES256-GCM-SHA384",
            other => {
                return Err(Error::UnsupportedOption {
                    option: format!("cipher suite {other} for the OpenSSL backend"),
                })
            }
        };
        pre13.push(mapped.to_owned());
    }
    Ok((pre13.join(":"), tls13.join(":")))
}

fn curve_name(curve: &str) -> Result<&'static str, Error> {
    match curve {
        "X25519" => Ok("X25519"),
        "secp256r1" | "P-256" => Ok("P-256"),
        "secp384r1" | "P-384" => Ok("P-384"),
        "secp521r1" | "P-521" => Ok("P-521"),
        other => Err(Error::UnsupportedOption {
            option: format!("curve {other} for the OpenSSL backend"),
        }),
    }
}

fn handshake(reason: String) -> Error {
    Error::Handshake(reason)
}
