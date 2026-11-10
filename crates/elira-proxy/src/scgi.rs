//! SCGI client.
//!
//! SCGI is a simple length-prefixed request followed by CGI-style response
//! headers. One connection carries one request; the server closes after the
//! response.

use std::path::PathBuf;
use std::time::Duration;

use http::uri::Authority;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

#[derive(Clone, Debug)]
pub(crate) enum Target {
    Tcp(Authority),
    Unix(PathBuf),
}

impl Target {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        if let Some(path) = value.strip_prefix("unix:") {
            return Some(Self::Unix(PathBuf::from(path)));
        }
        value.parse::<Authority>().ok().map(Self::Tcp)
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(authority) => authority.fmt(formatter),
            Self::Unix(path) => write!(formatter, "unix:{}", path.display()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("scgi: {0}")]
    Io(#[from] std::io::Error),

    #[error("scgi response is larger than the configured cap")]
    TooLarge,

    #[error("scgi response: {0}")]
    BadResponse(String),

    #[error("scgi exchange timed out")]
    Timeout,
}

pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(crate) async fn execute(
    target: &Target,
    params: &[(String, String)],
    body: &[u8],
    timeout: Duration,
    max_response: usize,
) -> Result<Response, Error> {
    let work = exchange(target, params, body, max_response);
    if timeout.is_zero() {
        work.await
    } else {
        tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| Error::Timeout)?
    }
}

async fn exchange(
    target: &Target,
    params: &[(String, String)],
    body: &[u8],
    max_response: usize,
) -> Result<Response, Error> {
    let mut stream: Box<dyn Io> = match target {
        Target::Tcp(authority) => Box::new(TcpStream::connect(authority.as_str()).await?),
        Target::Unix(path) => Box::new(UnixStream::connect(path).await?),
    };

    let mut params = params.to_vec();
    if !params
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("CONTENT_LENGTH"))
    {
        params.push(("CONTENT_LENGTH".to_owned(), body.len().to_string()));
    }

    let mut header = Vec::new();
    header.extend_from_slice(b"SCGI\0");
    for (name, value) in &params {
        header.extend_from_slice(name.as_bytes());
        header.push(0);
        header.extend_from_slice(value.as_bytes());
        header.push(0);
    }

    let mut packet = Vec::with_capacity(header.len() + body.len() + 16);
    packet.extend_from_slice(header.len().to_string().as_bytes());
    packet.push(0);
    packet.extend_from_slice(&header);
    packet.extend_from_slice(body);
    stream.write_all(&packet).await?;
    stream.flush().await?;

    let (status, headers, mut response) = read_head(&mut stream).await?;

    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok());

    match content_length {
        Some(length) => {
            if max_response > 0 && length > max_response {
                return Err(Error::TooLarge);
            }
            while response.len() < length {
                let mut chunk = [0u8; 8192];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(Error::BadResponse(
                        "closed before Content-Length bytes".to_owned(),
                    ));
                }
                response.extend_from_slice(&chunk[..read]);
                if max_response > 0 && response.len() > max_response {
                    return Err(Error::TooLarge);
                }
            }
            response.truncate(length);
        }
        None => loop {
            let mut chunk = [0u8; 8192];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
            if max_response > 0 && response.len() > max_response {
                return Err(Error::TooLarge);
            }
        },
    }

    Ok(Response {
        status,
        headers,
        body: response,
    })
}

async fn read_head(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Error> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];

    let split = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Error::BadResponse(
                "connection closed before the header block".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        if buffer.len() > 64 * 1024 {
            return Err(Error::BadResponse("header block is too large".to_owned()));
        }
    };

    let head = String::from_utf8_lossy(&buffer[..split]).to_string();
    let body = buffer[split + 4..].to_vec();
    let mut status = None;
    let mut headers = Vec::new();

    for line in head.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.starts_with("HTTP/") {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok());
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::BadResponse(format!("bad header line {line:?}")));
        };
        if name.eq_ignore_ascii_case("status") {
            status = value
                .split_whitespace()
                .next()
                .and_then(|code| code.parse::<u16>().ok());
        } else {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }

    let status = status.unwrap_or_else(|| {
        if headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("location"))
        {
            302
        } else {
            200
        }
    });

    Ok((status, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parses_tcp_and_unix() {
        assert!(matches!(
            Target::parse("127.0.0.1:9000"),
            Some(Target::Tcp(_))
        ));
        assert!(matches!(
            Target::parse("unix:/run/app.sock"),
            Some(Target::Unix(_))
        ));
        assert!(Target::parse("not a target").is_none());
    }

    #[test]
    fn response_defaults_to_200_and_302_for_location() {
        let (status, headers, body) = parse_for_test(b"Content-Type: text/plain\r\n\r\nhi");
        assert_eq!(status, 200);
        assert_eq!(headers.len(), 1);
        assert_eq!(body, b"hi");

        let (status, _, _) = parse_for_test(b"Location: /next\r\n\r\n");
        assert_eq!(status, 302);
    }

    fn parse_for_test(raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("header split");
        let head = String::from_utf8_lossy(&raw[..split]);
        let body = raw[split + 4..].to_vec();
        let mut status = None;
        let mut headers = Vec::new();
        for line in head.split("\r\n") {
            let (name, value) = line.split_once(':').expect("header");
            if name.eq_ignore_ascii_case("status") {
                status = value
                    .split_whitespace()
                    .next()
                    .and_then(|code| code.parse::<u16>().ok());
            } else {
                headers.push((name.to_owned(), value.trim().to_owned()));
            }
        }
        let status = status.unwrap_or_else(|| {
            if headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("location"))
            {
                302
            } else {
                200
            }
        });
        (status, headers, body)
    }
}
