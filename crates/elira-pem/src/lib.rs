use std::io::{self, Read};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rustls_pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs1KeyDer,
    PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn sections(mut reader: impl Read) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    let text = String::from_utf8(data).map_err(|_| invalid("PEM is not valid UTF-8"))?;
    let mut sections = Vec::new();
    let mut current: Option<(String, String)> = None;

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let label = rest
                .strip_suffix("-----")
                .ok_or_else(|| invalid("malformed PEM begin line"))?;
            current = Some((label.to_owned(), String::new()));
            continue;
        }
        if let Some(rest) = line.strip_prefix("-----END ") {
            let label = rest
                .strip_suffix("-----")
                .ok_or_else(|| invalid("malformed PEM end line"))?;
            let Some((begin, body)) = current.take() else {
                return Err(invalid("PEM end without begin"));
            };
            if begin != label {
                return Err(invalid("PEM labels do not match"));
            }
            let der = STANDARD
                .decode(body.as_bytes())
                .map_err(|_| invalid("invalid PEM base64"))?;
            sections.push((begin, der));
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push_str(line);
        }
    }

    if current.is_some() {
        return Err(invalid("unterminated PEM section"));
    }
    Ok(sections)
}

pub fn certs(reader: impl Read) -> io::Result<Vec<CertificateDer<'static>>> {
    Ok(sections(reader)?
        .into_iter()
        .filter(|(label, _)| matches!(label.as_str(), "CERTIFICATE" | "X509 CERTIFICATE"))
        .map(|(_, der)| CertificateDer::from(der))
        .collect())
}

pub fn crls(reader: impl Read) -> io::Result<Vec<CertificateRevocationListDer<'static>>> {
    Ok(sections(reader)?
        .into_iter()
        .filter(|(label, _)| matches!(label.as_str(), "X509 CRL" | "CRL"))
        .map(|(_, der)| CertificateRevocationListDer::from(der))
        .collect())
}

pub fn private_key(reader: impl Read) -> io::Result<Option<PrivateKeyDer<'static>>> {
    for (label, der) in sections(reader)? {
        match label.as_str() {
            "PRIVATE KEY" => return Ok(Some(PrivatePkcs8KeyDer::from(der).into())),
            "RSA PRIVATE KEY" => return Ok(Some(PrivatePkcs1KeyDer::from(der).into())),
            "EC PRIVATE KEY" => return Ok(Some(PrivateSec1KeyDer::from(der).into())),
            _ => {}
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_certificates_and_keys() {
        let cert = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        let certs = certs(cert.as_bytes()).expect("certs");
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), &[1, 2, 3]);

        let key = "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n";
        let key = private_key(key.as_bytes()).expect("key").expect("present");
        assert_eq!(key.secret_der(), &[1, 2, 3]);
    }

    #[test]
    fn rejects_mismatched_labels() {
        let pem = "-----BEGIN CERTIFICATE-----\nAQID\n-----END PRIVATE KEY-----\n";
        assert!(certs(pem.as_bytes()).is_err());
    }
}
