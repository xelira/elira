//! Streaming FastCGI exchanges.
//!
//! [`execute_stream`] sends the request body as it is produced and hands the
//! response body back while the responder is still writing it. Memory stays
//! bounded by the channel capacities and the `max_stdout` budget: neither the
//! request nor the response body is collected.
//!
//! A dedicated reader task owns the read half of the socket and forwards
//! FastCGI records over a bounded channel. That keeps record framing out of
//! `tokio::select!` (a partially read record cannot be cancelled) and lets the
//! request pump and the response reader make progress independently. When the
//! response headers are complete, the record receiver is handed to a
//! background task that forwards body chunks over a second bounded channel.
//! Dropping the body stream closes that channel, which stops both tasks and
//! closes the socket.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{mpsc, oneshot};

use crate::protocol::{self, Record, RecordType};
use crate::Target;
use crate::{decode_end_request, protocol_status_name, response, write_record, BoxError, Error};

/// A streaming body: request input or response output.
pub type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + Send>>;

/// A response whose headers are available but whose body is still arriving.
pub struct StreamResponse {
    /// HTTP status. Defaults to 200, or 302 when only `Location` is present.
    pub status: u16,
    /// Response headers in the order the application sent them.
    pub headers: Vec<(String, String)>,
    /// Body chunks. The stream ends at `END_REQUEST` and yields an error if
    /// the connection breaks or the responder exceeds `max_stdout`.
    pub body: BodyStream,
    /// STDERR text that arrived before the response headers were complete.
    ///
    /// FastCGI can keep writing STDERR after the headers, but the value is
    /// already in the caller's hands at that point; later bytes are drained
    /// and discarded rather than buffered without bound.
    pub stderr: String,
}

impl fmt::Debug for StreamResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &"<stream>")
            .field("stderr", &self.stderr)
            .finish()
    }
}

/// Records buffered between the socket reader and the response forwarder.
const RECORD_CHANNEL_CAPACITY: usize = 16;

/// Body chunks buffered between the forwarder and the caller.
///
/// A slow caller stops draining this channel, which stops the forwarder, then
/// the record channel, then the socket read: that is the backpressure path.
const BODY_CHANNEL_CAPACITY: usize = 8;

/// Largest STDERR prefix returned in [`StreamResponse::stderr`].
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// Send one request to `target` with a streaming body and return a streaming
/// response.
///
/// A zero `timeout` disables deadlines. A non-zero timeout covers connecting,
/// writing each record, reading the header block, and reading every later
/// record (including time spent waiting for the responder to send one).
/// `max_stdout` bounds the total number of STDOUT bytes, header block
/// included; crossing it makes the body stream yield an error and stop.
pub async fn execute_stream(
    target: &Target,
    params: Vec<(String, String)>,
    body: BodyStream,
    timeout: Duration,
    max_stdout: usize,
) -> Result<StreamResponse, Error> {
    let target_name = target.to_string();

    match target {
        Target::Tcp(_) | Target::TcpName(_) => {
            let address = with_deadline(timeout, &target_name, resolve(target)).await?;
            let stream = with_deadline(timeout, &target_name, async {
                TcpStream::connect(address)
                    .await
                    .map_err(|source| Error::Connect {
                        target: target_name.clone(),
                        source,
                    })
            })
            .await?;
            stream_exchange(stream, params, body, timeout, max_stdout, target_name).await
        }
        Target::Unix(path) => {
            let stream = with_deadline(timeout, &target_name, async {
                UnixStream::connect(path)
                    .await
                    .map_err(|source| Error::Connect {
                        target: target_name.clone(),
                        source,
                    })
            })
            .await?;
            stream_exchange(stream, params, body, timeout, max_stdout, target_name).await
        }
    }
}

async fn resolve(target: &Target) -> Result<SocketAddr, Error> {
    match target {
        Target::Tcp(address) => Ok(*address),
        Target::TcpName(name) => tokio::net::lookup_host(name)
            .await
            .map_err(|source| Error::Connect {
                target: target.to_string(),
                source,
            })?
            .next()
            .ok_or_else(|| Error::Connect {
                target: target.to_string(),
                source: io::Error::new(io::ErrorKind::NotFound, "host has no addresses"),
            }),
        Target::Unix(_) => unreachable!("Unix targets are connected directly"),
    }
}

async fn stream_exchange<S>(
    stream: S,
    params: Vec<(String, String)>,
    mut body: BodyStream,
    timeout: Duration,
    max_stdout: usize,
    target: String,
) -> Result<StreamResponse, Error>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);

    // The reader task lives until the response forwarder (or this function)
    // drops the shutdown sender. Detaching the handle is intentional: the
    // task is cancelled through that channel, not through `abort`.
    let (record_tx, mut record_rx) = mpsc::channel(RECORD_CHANNEL_CAPACITY);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(read_records(
        reader,
        record_tx,
        shutdown_rx,
        timeout,
        target.clone(),
    ));

    // BEGIN_REQUEST and PARAMS must precede STDIN. Writing them before the
    // loop keeps the request preamble in one place and means an encoding
    // error fails before any body chunk is consumed.
    with_deadline(
        timeout,
        &target,
        write_record(
            &mut writer,
            RecordType::BeginRequest,
            &protocol::begin_request_body(),
        ),
    )
    .await?;

    let encoded_params = protocol::encode_params(&params)?;
    write_stream_timed(
        &mut writer,
        RecordType::Params,
        &encoded_params,
        timeout,
        &target,
    )
    .await?;
    flush_timed(&mut writer, timeout, &target).await?;

    let mut stdout = BytesMut::new();
    let mut stderr = BytesMut::new();
    let mut total_stdout = 0usize;
    let mut stdin_done = false;

    loop {
        let event = if stdin_done {
            match record_rx.recv().await {
                Some(item) => Event::Record(item),
                None => Event::RecordsClosed,
            }
        } else {
            tokio::select! {
                item = record_rx.recv() => match item {
                    Some(item) => Event::Record(item),
                    None => Event::RecordsClosed,
                },
                chunk = body.next() => Event::Body(chunk),
            }
        };

        match event {
            Event::RecordsClosed => {
                return Err(Error::Protocol(
                    "connection closed before END_REQUEST".to_owned(),
                ));
            }
            Event::Body(Some(Err(error))) => return Err(Error::RequestBody(error)),
            Event::Body(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    continue;
                }
                write_frames_timed(&mut writer, RecordType::Stdin, &chunk, timeout, &target)
                    .await?;
                flush_timed(&mut writer, timeout, &target).await?;
            }
            Event::Body(None) => {
                // The caller's stream ending early is the STDIN terminator,
                // not an error: the responder still needs the empty record
                // before it will start answering.
                with_deadline(
                    timeout,
                    &target,
                    write_record(&mut writer, RecordType::Stdin, &[]),
                )
                .await?;
                flush_timed(&mut writer, timeout, &target).await?;
                stdin_done = true;
            }
            Event::Record(Err(error)) => return Err(error),
            Event::Record(Ok(record)) => {
                if record.request_id != protocol::REQUEST_ID {
                    return Err(Error::Protocol(format!(
                        "record for request {}, expected {}",
                        record.request_id,
                        protocol::REQUEST_ID
                    )));
                }

                match RecordType::from_u8(record.record_type) {
                    Some(RecordType::Stdout) => {
                        total_stdout = total_stdout.saturating_add(record.content.len());
                        if total_stdout > max_stdout {
                            return Err(Error::Response(format!(
                                "STDOUT exceeds the configured limit of {max_stdout} bytes"
                            )));
                        }

                        stdout.extend_from_slice(&record.content);
                        let Some((header_end, body_start)) =
                            response::find_header_terminator(&stdout)
                        else {
                            continue;
                        };

                        let (status, headers) =
                            response::parse_header_block(&stdout[..header_end])?;
                        let prefix = Bytes::copy_from_slice(&stdout[body_start..]);

                        // The responder answered before reading the whole
                        // request. Terminate STDIN anyway; the body stream is
                        // dropped when this function returns.
                        if !stdin_done {
                            let _ = with_deadline(
                                timeout,
                                &target,
                                write_record(&mut writer, RecordType::Stdin, &[]),
                            )
                            .await;
                            let _ = flush_timed(&mut writer, timeout, &target).await;
                        }

                        let (body_tx, body_rx) = mpsc::channel(BODY_CHANNEL_CAPACITY);
                        let stderr = String::from_utf8_lossy(&stderr).into_owned();
                        tokio::spawn(forward_body(
                            record_rx,
                            prefix,
                            body_tx,
                            max_stdout,
                            total_stdout,
                            shutdown_tx,
                        ));

                        return Ok(StreamResponse {
                            status,
                            headers,
                            body: Box::pin(ChannelStream { receiver: body_rx }),
                            stderr,
                        });
                    }
                    Some(RecordType::Stderr) => {
                        let room = MAX_STDERR_BYTES.saturating_sub(stderr.len());
                        if room > 0 {
                            let take = record.content.len().min(room);
                            stderr.extend_from_slice(&record.content[..take]);
                        }
                    }
                    Some(RecordType::EndRequest) => {
                        let (_, protocol_status) = decode_end_request(&record.content)?;
                        if protocol_status != 0 {
                            return Err(Error::Protocol(format!(
                                "server ended the request with protocol status \
                                 {protocol_status} ({})",
                                protocol_status_name(protocol_status)
                            )));
                        }
                        return Err(Error::Response(
                            "END_REQUEST arrived before the CGI header block was complete"
                                .to_owned(),
                        ));
                    }
                    Some(other) => {
                        return Err(Error::Protocol(format!(
                            "unexpected {} record while waiting for the response",
                            other.name()
                        )));
                    }
                    None => {
                        return Err(Error::Protocol(format!(
                            "unexpected record type {} while waiting for the response",
                            record.record_type
                        )));
                    }
                }
            }
        }
    }
}

enum Event {
    Record(Result<Record, Error>),
    RecordsClosed,
    Body(Option<Result<Bytes, BoxError>>),
}

/// Read records until the response forwarder drops its shutdown sender.
async fn read_records<S>(
    mut reader: ReadHalf<S>,
    transmitter: mpsc::Sender<Result<Record, Error>>,
    mut shutdown: oneshot::Receiver<()>,
    timeout: Duration,
    target: String,
) where
    S: AsyncRead + Send + 'static,
{
    loop {
        // Cancelling `read_record` here is safe because the whole exchange is
        // ending: the socket is about to be dropped.
        let result = tokio::select! {
            _ = &mut shutdown => return,
            result = with_deadline(timeout, &target, protocol::read_record(&mut reader)) => result,
        };

        let (item, failed) = match result {
            Ok(Some(record)) => (Ok(record), false),
            Ok(None) => return,
            Err(error) => (Err(error), true),
        };

        tokio::select! {
            _ = &mut shutdown => return,
            sent = transmitter.send(item) => {
                if sent.is_err() {
                    return;
                }
            }
        }

        if failed {
            return;
        }
    }
}

/// Forward STDOUT records to the caller's body stream.
#[allow(clippy::too_many_arguments)]
async fn forward_body(
    mut records: mpsc::Receiver<Result<Record, Error>>,
    prefix: Bytes,
    transmitter: mpsc::Sender<Result<Bytes, BoxError>>,
    max_stdout: usize,
    mut total_stdout: usize,
    shutdown: oneshot::Sender<()>,
) {
    // Holding this sender is what keeps the reader task alive. When this task
    // returns, the sender drops and the reader stops even if it is blocked in
    // a read.
    let _shutdown = shutdown;

    if !prefix.is_empty() && transmitter.send(Ok(prefix)).await.is_err() {
        return;
    }

    loop {
        let item = tokio::select! {
            _ = transmitter.closed() => return,
            item = records.recv() => item,
        };

        let Some(item) = item else {
            let _ = transmitter
                .send(Err(Box::new(Error::Protocol(
                    "connection closed before END_REQUEST".to_owned(),
                ))))
                .await;
            return;
        };

        let record = match item {
            Ok(record) => record,
            Err(error) => {
                let _ = transmitter.send(Err(Box::new(error))).await;
                return;
            }
        };

        if record.request_id != protocol::REQUEST_ID {
            let _ = transmitter
                .send(Err(Box::new(Error::Protocol(format!(
                    "record for request {}, expected {}",
                    record.request_id,
                    protocol::REQUEST_ID
                )))))
                .await;
            return;
        }

        match RecordType::from_u8(record.record_type) {
            Some(RecordType::Stdout) => {
                total_stdout = total_stdout.saturating_add(record.content.len());
                if total_stdout > max_stdout {
                    let _ = transmitter
                        .send(Err(Box::new(Error::Response(format!(
                            "STDOUT exceeds the configured limit of {max_stdout} bytes"
                        )))))
                        .await;
                    return;
                }

                if !record.content.is_empty()
                    && transmitter
                        .send(Ok(Bytes::from(record.content)))
                        .await
                        .is_err()
                {
                    return;
                }
            }
            // Later STDERR bytes are drained but cannot reach the header
            // snapshot that was already returned.
            Some(RecordType::Stderr) => {}
            Some(RecordType::EndRequest) => {
                match decode_end_request(&record.content) {
                    Ok((_, 0)) => {}
                    Ok((_, protocol_status)) => {
                        let _ = transmitter
                            .send(Err(Box::new(Error::Protocol(format!(
                                "server ended the request with protocol status \
                                 {protocol_status} ({})",
                                protocol_status_name(protocol_status)
                            )))))
                            .await;
                    }
                    Err(error) => {
                        let _ = transmitter.send(Err(Box::new(error))).await;
                    }
                }
                return;
            }
            Some(other) => {
                let _ = transmitter
                    .send(Err(Box::new(Error::Protocol(format!(
                        "unexpected {} record while waiting for the response",
                        other.name()
                    )))))
                    .await;
                return;
            }
            None => {
                let _ = transmitter
                    .send(Err(Box::new(Error::Protocol(format!(
                        "unexpected record type {} while waiting for the response",
                        record.record_type
                    )))))
                    .await;
                return;
            }
        }
    }
}

async fn flush_timed<S>(stream: &mut S, timeout: Duration, target: &str) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    with_deadline(timeout, target, async {
        stream.flush().await.map_err(crate::write_error)
    })
    .await
}

async fn write_frames_timed<S>(
    stream: &mut S,
    record_type: RecordType,
    data: &[u8],
    timeout: Duration,
    target: &str,
) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    for chunk in data.chunks(protocol::MAX_CONTENT) {
        with_deadline(timeout, target, write_record(stream, record_type, chunk)).await?;
    }
    Ok(())
}

async fn write_stream_timed<S>(
    stream: &mut S,
    record_type: RecordType,
    data: &[u8],
    timeout: Duration,
    target: &str,
) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    if !data.is_empty() {
        write_frames_timed(stream, record_type, data, timeout, target).await?;
    }
    with_deadline(timeout, target, write_record(stream, record_type, &[])).await
}

async fn with_deadline<F, T>(duration: Duration, target: &str, future: F) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>>,
{
    if duration.is_zero() {
        future.await
    } else {
        match tokio::time::timeout(duration, future).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout {
                target: target.to_owned(),
                duration,
            }),
        }
    }
}

/// Minimal adapter from a bounded Tokio channel to [`futures_core::Stream`].
struct ChannelStream {
    receiver: mpsc::Receiver<Result<Bytes, BoxError>>,
}

impl Stream for ChannelStream {
    type Item = Result<Bytes, BoxError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}
