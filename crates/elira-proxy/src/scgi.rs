//! SCGI client.
//!
//! SCGI is a simple length-prefixed request followed by CGI-style response
//! headers. One connection carries one request; the server closes after the
//! response.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use crate::app_target::Target;
use crate::cgi_response::{self, Response};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("scgi: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Response(#[from] cgi_response::Error),

    #[error("scgi exchange timed out")]
    Timeout,
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

    Ok(cgi_response::read(&mut stream, max_response).await?)
}
