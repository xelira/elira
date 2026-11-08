//! A small FastCGI client.
//!
//! [`execute`] and [`execute_stream`] open one connection per request and
//! speak the `RESPONDER` role. [`Pool`] adds optional connection reuse: idle
//! connections are keyed by [`Target`], capped per target, and discarded when
//! they go stale or sit longer than the configured TTL.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use elira_fastcgi::{execute, Request, Target};
//!
//! # async fn example() -> Result<(), elira_fastcgi::Error> {
//! let target = Target::parse("127.0.0.1:9000")?;
//! let request = Request {
//!     params: vec![
//!         ("REQUEST_METHOD".to_owned(), "GET".to_owned()),
//!         ("SCRIPT_FILENAME".to_owned(), "/srv/www/index.php".to_owned()),
//!     ],
//!     body: Vec::new(),
//! };
//! let response = execute(&target, &request, Duration::from_secs(30)).await?;
//! println!("{}", response.status);
//! # Ok(())
//! # }
//! ```

mod error;
mod pool;
mod protocol;
mod response;
mod socket;
mod stream;
mod target;

use std::time::Duration;

pub use error::Error;
pub use pool::Pool;
pub use stream::{execute_stream, BodyStream, StreamResponse};
pub use target::Target;

/// Boxed error type carried by streaming request and response bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

use bytes::BytesMut;
use protocol::RecordType;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// A request handed to a FastCGI responder.
///
/// `params` is the CGI variable list as-is; the proxy builds it from the
/// incoming request. The client adds nothing (no `CONTENT_LENGTH`, no
/// `GATEWAY_INTERFACE`), because silently changing parameters makes the
/// proxy impossible to reason about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    /// Name-value pairs sent in PARAMS records.
    pub params: Vec<(String, String)>,
    /// Request body sent in STDIN records.
    pub body: Vec<u8>,
}

/// A response collected from a FastCGI responder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// HTTP status. Defaults to 200, or 302 when only `Location` is present.
    pub status: u16,
    /// Response headers in the order the application sent them. Header names
    /// keep their original case; the `Status` pseudo-header is not included.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
    /// STDERR text decoded lossily, plus a note when `APP_STATUS` was non-zero.
    pub stderr: String,
}

/// Send one request to `target` and read its response.
///
/// A zero `timeout` means no timeout. A non-zero timeout covers the whole
/// exchange: connect, writing, and reading until `END_REQUEST`.
pub async fn execute(
    target: &Target,
    request: &Request,
    timeout: Duration,
) -> Result<Response, Error> {
    if timeout.is_zero() {
        exchange_target(target, request).await
    } else {
        match tokio::time::timeout(timeout, exchange_target(target, request)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout {
                target: target.to_string(),
                duration: timeout,
            }),
        }
    }
}

async fn exchange_target(target: &Target, request: &Request) -> Result<Response, Error> {
    match target {
        Target::Tcp(_) | Target::TcpName(_) => {
            let address = match target {
                Target::Tcp(address) => *address,
                Target::TcpName(name) => tokio::net::lookup_host(name)
                    .await
                    .map_err(|source| Error::Connect {
                        target: target.to_string(),
                        source,
                    })?
                    .next()
                    .ok_or_else(|| Error::Connect {
                        target: target.to_string(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "host has no addresses",
                        ),
                    })?,
                Target::Unix(_) => unreachable!(),
            };
            let mut stream =
                TcpStream::connect(address)
                    .await
                    .map_err(|source| Error::Connect {
                        target: target.to_string(),
                        source,
                    })?;
            exchange(&mut stream, request).await
        }
        Target::Unix(path) => {
            let mut stream = UnixStream::connect(path)
                .await
                .map_err(|source| Error::Connect {
                    target: target.to_string(),
                    source,
                })?;
            exchange(&mut stream, request).await
        }
    }
}

async fn exchange<S>(stream: &mut S, request: &Request) -> Result<Response, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_request(stream, request).await?;
    read_response(stream).await
}

async fn write_request<S>(stream: &mut S, request: &Request) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    write_request_with_flags(stream, request, false).await
}

pub(crate) async fn write_request_keep_alive<S>(
    stream: &mut S,
    request: &Request,
) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    write_request_with_flags(stream, request, true).await
}

async fn write_request_with_flags<S>(
    stream: &mut S,
    request: &Request,
    keep_conn: bool,
) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    write_record(
        stream,
        RecordType::BeginRequest,
        &protocol::begin_request_body_with_keep_conn(keep_conn),
    )
    .await?;

    let params = protocol::encode_params(&request.params)?;
    write_stream(stream, RecordType::Params, &params).await?;
    write_stream(stream, RecordType::Stdin, &request.body).await?;

    stream.flush().await.map_err(write_error)
}

/// Write one stream type, split into records no larger than the 16-bit
/// content length, then the empty record that terminates it.
async fn write_stream<S>(stream: &mut S, record_type: RecordType, data: &[u8]) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    if data.is_empty() {
        return write_record(stream, record_type, data).await;
    }

    for chunk in data.chunks(protocol::MAX_CONTENT) {
        write_record(stream, record_type, chunk).await?;
    }
    write_record(stream, record_type, &[]).await
}

pub(crate) async fn write_record<S>(
    stream: &mut S,
    record_type: RecordType,
    content: &[u8],
) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    if content.len() > protocol::MAX_CONTENT {
        return Err(Error::Request(format!(
            "{} record is {} bytes; the maximum is {}",
            record_type.name(),
            content.len(),
            protocol::MAX_CONTENT
        )));
    }

    let header =
        protocol::encode_header(record_type, protocol::REQUEST_ID, content.len() as u16, 0);
    stream.write_all(&header).await.map_err(write_error)?;
    stream.write_all(content).await.map_err(write_error)
}

pub(crate) async fn read_response<S>(stream: &mut S) -> Result<Response, Error>
where
    S: AsyncRead + Unpin,
{
    let mut stdout = BytesMut::new();
    let mut stderr = BytesMut::new();

    loop {
        let Some(record) = protocol::read_record(stream).await? else {
            return Err(Error::Protocol(
                "connection closed before END_REQUEST".to_owned(),
            ));
        };

        if record.request_id != protocol::REQUEST_ID {
            return Err(Error::Protocol(format!(
                "record for request {}, expected {}",
                record.request_id,
                protocol::REQUEST_ID
            )));
        }

        match RecordType::from_u8(record.record_type) {
            Some(RecordType::Stdout) => stdout.extend_from_slice(&record.content),
            Some(RecordType::Stderr) => stderr.extend_from_slice(&record.content),
            Some(RecordType::EndRequest) => {
                let (app_status, protocol_status) = decode_end_request(&record.content)?;
                if protocol_status != 0 {
                    return Err(Error::Protocol(format!(
                        "server ended the request with protocol status {protocol_status} ({})",
                        protocol_status_name(protocol_status)
                    )));
                }
                return response::parse(&stdout, &stderr, app_status);
            }
            Some(other) => {
                return Err(Error::Protocol(format!(
                    "unexpected {} record while waiting for the response",
                    other.name()
                )))
            }
            None => {
                return Err(Error::Protocol(format!(
                    "unexpected record type {} while waiting for the response",
                    record.record_type
                )))
            }
        }
    }
}

pub(crate) fn decode_end_request(content: &[u8]) -> Result<(u32, u8), Error> {
    if content.len() != 8 {
        return Err(Error::Protocol(format!(
            "END_REQUEST body is {} bytes; expected 8",
            content.len()
        )));
    }

    let mut app = [0u8; 4];
    app.copy_from_slice(&content[..4]);
    Ok((u32::from_be_bytes(app), content[4]))
}

pub(crate) fn protocol_status_name(status: u8) -> &'static str {
    match status {
        1 => "multiplexing not supported",
        2 => "server overloaded",
        3 => "unknown role",
        _ => "unknown protocol status",
    }
}

pub(crate) fn write_error(source: std::io::Error) -> Error {
    Error::Io {
        context: "writing FastCGI request",
        source,
    }
}
