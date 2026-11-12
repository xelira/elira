use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use crate::app_target::Target;
use crate::cgi_response::{self, Response};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("uwsgi: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Response(#[from] cgi_response::Error),

    #[error("uwsgi: {0}")]
    BadRequest(String),

    #[error("uwsgi exchange timed out")]
    Timeout,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(crate) async fn execute(
    target: &Target,
    modifier1: u8,
    modifier2: u8,
    params: &[(String, String)],
    body: &[u8],
    timeout: Duration,
    max_response: usize,
) -> Result<Response, Error> {
    let work = exchange(target, modifier1, modifier2, params, body, max_response);
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
    modifier1: u8,
    modifier2: u8,
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

    let mut variables = Vec::new();
    for (name, value) in &params {
        if name.len() > u16::MAX as usize || value.len() > u16::MAX as usize {
            return Err(Error::BadRequest("parameter is too long".to_owned()));
        }
        variables.extend_from_slice(&(name.len() as u16).to_le_bytes());
        variables.extend_from_slice(name.as_bytes());
        variables.extend_from_slice(&(value.len() as u16).to_le_bytes());
        variables.extend_from_slice(value.as_bytes());
    }
    if variables.len() > u16::MAX as usize {
        return Err(Error::BadRequest("parameter block is too large".to_owned()));
    }

    let mut packet = Vec::with_capacity(variables.len() + body.len() + 4);
    packet.push(modifier1);
    packet.push(modifier2);
    packet.extend_from_slice(&(variables.len() as u16).to_le_bytes());
    packet.extend_from_slice(&variables);
    packet.extend_from_slice(body);
    stream.write_all(&packet).await?;
    stream.flush().await?;

    Ok(cgi_response::read(&mut stream, max_response).await?)
}
