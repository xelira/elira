//! Upstream health probes.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use elira_upstream::TlsOptions;

use crate::ServerAddr;

pub(crate) struct Probe<'a> {
    pub(crate) path: &'a str,
    pub(crate) method: &'a str,
    pub(crate) host: Option<&'a str>,
    pub(crate) expect: &'a [u16],
    pub(crate) timeout: Duration,
    pub(crate) tls: bool,
    pub(crate) options: &'a TlsOptions,
}

pub(crate) async fn probe_server(server: &ServerAddr, probe: &Probe<'_>) -> bool {
    if let Some(socket) = server.unix() {
        let mut stream =
            match tokio::time::timeout(probe.timeout, UnixStream::connect(socket)).await {
                Ok(Ok(stream)) => stream,
                _ => return false,
            };
        let host = probe.host.unwrap_or("localhost");
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
            probe.method, probe.path
        );
        if tokio::time::timeout(probe.timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        return probe_response(&mut stream, probe.timeout, probe.expect).await;
    }

    let authority = match server.tcp() {
        Some(authority) => authority,
        None => return false,
    };
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = authority
        .port_u16()
        .unwrap_or(if probe.tls { 443 } else { 80 });

    let stream = match tokio::time::timeout(probe.timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };

    let header_host = probe.host.unwrap_or(authority.as_str());
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {header_host}\r\nConnection: close\r\n\r\n",
        probe.method, probe.path
    );
    if probe.tls {
        let config = match elira_upstream::client_config(probe.options) {
            Ok(config) => config,
            Err(_) => return false,
        };
        let name = match probe.options.sni.as_deref().or(Some(host)) {
            Some(name) => name.to_owned(),
            None => return false,
        };
        let name = match name.parse::<std::net::IpAddr>() {
            Ok(ip) => tokio_rustls::rustls::pki_types::ServerName::IpAddress(ip.into()),
            Err(_) => match tokio_rustls::rustls::pki_types::ServerName::try_from(name) {
                Ok(name) => name,
                Err(_) => return false,
            },
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let mut stream =
            match tokio::time::timeout(probe.timeout, connector.connect(name, stream)).await {
                Ok(Ok(stream)) => stream,
                _ => return false,
            };
        if tokio::time::timeout(probe.timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        probe_response(&mut stream, probe.timeout, probe.expect).await
    } else {
        let mut stream = stream;
        if tokio::time::timeout(probe.timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        probe_response(&mut stream, probe.timeout, probe.expect).await
    }
}

pub(crate) async fn probe_response<S>(stream: &mut S, timeout: Duration, expect: &[u16]) -> bool
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 64];
        let read = match tokio::time::timeout(timeout, stream.read(&mut chunk)).await {
            Ok(Ok(read)) if read > 0 => read,
            _ => return false,
        };
        buf.extend_from_slice(&chunk[..read]);

        if let Some(end) = buf.windows(2).position(|window| window == b"\r\n") {
            let line = String::from_utf8_lossy(&buf[..end]);
            let code: u16 = match line.split_whitespace().nth(1).and_then(|c| c.parse().ok()) {
                Some(code) => code,
                None => return false,
            };
            return if expect.is_empty() {
                (200..400).contains(&code)
            } else {
                expect.contains(&code)
            };
        }

        if buf.len() > 1024 {
            return false;
        }
    }
}
