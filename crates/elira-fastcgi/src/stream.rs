use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use futures_util::StreamExt;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::pool::PoolHandle;
use crate::protocol::{self, Record, RecordType};
use crate::socket::{reunite, Socket, SocketRead, SocketWrite};
use crate::Target;
use crate::{decode_end_request, protocol_status_name, response, write_record, BoxError, Error};

pub type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + Send>>;

pub struct StreamResponse {
    pub status: u16,

    pub headers: Vec<(String, String)>,

    pub body: BodyStream,

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

const RECORD_CHANNEL_CAPACITY: usize = 16;

const BODY_CHANNEL_CAPACITY: usize = 8;

const MAX_STDERR_BYTES: usize = 64 * 1024;

pub async fn execute_stream(
    target: &Target,
    params: Vec<(String, String)>,
    body: BodyStream,
    timeout: Duration,
    max_stdout: usize,
) -> Result<StreamResponse, Error> {
    let target_name = target.to_string();
    let socket = with_deadline(timeout, &target_name, Socket::connect(target)).await?;
    stream_exchange(
        socket,
        params,
        body,
        timeout,
        max_stdout,
        target_name,
        false,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn stream_exchange(
    socket: Socket,
    params: Vec<(String, String)>,
    mut body: BodyStream,
    timeout: Duration,
    max_stdout: usize,
    target: String,
    keep_conn: bool,
    pool: Option<PoolHandle>,
) -> Result<StreamResponse, Error> {
    let (reader, mut writer) = socket.into_split();

    let (record_tx, mut record_rx) = mpsc::channel(RECORD_CHANNEL_CAPACITY);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (read_half_tx, read_half_rx) = if pool.is_some() {
        let (sender, receiver) = oneshot::channel();
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };
    tokio::spawn(read_records(
        reader,
        record_tx,
        shutdown_rx,
        read_half_tx,
        timeout,
        target.clone(),
    ));

    with_deadline(
        timeout,
        &target,
        write_record(
            &mut writer,
            RecordType::BeginRequest,
            &protocol::begin_request_body_with_keep_conn(keep_conn),
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
                            writer,
                            read_half_rx,
                            pool,
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

async fn read_records(
    mut reader: SocketRead,
    transmitter: mpsc::Sender<Result<Record, Error>>,
    mut shutdown: oneshot::Receiver<()>,
    mut read_half: Option<oneshot::Sender<SocketRead>>,
    timeout: Duration,
    target: String,
) {
    loop {
        let result = tokio::select! {
            _ = &mut shutdown => return,
            result = with_deadline(timeout, &target, protocol::read_record(&mut reader)) => result,
        };

        let (item, failed, is_end) = match result {
            Ok(Some(record)) => {
                let is_end = record.record_type == RecordType::EndRequest as u8;
                (Ok(record), false, is_end)
            }
            Ok(None) => return,
            Err(error) => (Err(error), true, false),
        };

        let sent = tokio::select! {
            _ = &mut shutdown => return,
            sent = transmitter.send(item) => sent,
        };

        if sent.is_err() || failed {
            return;
        }

        if is_end {
            if let Some(sender) = read_half.take() {
                let _ = sender.send(reader);
            }
            return;
        }
    }
}

enum BodyEvent {
    Item(Result<Bytes, BoxError>),

    End(Option<(Socket, PoolHandle)>),
}

#[allow(clippy::too_many_arguments)]
async fn forward_body(
    mut records: mpsc::Receiver<Result<Record, Error>>,
    prefix: Bytes,
    transmitter: mpsc::Sender<BodyEvent>,
    max_stdout: usize,
    mut total_stdout: usize,
    shutdown: oneshot::Sender<()>,
    writer: SocketWrite,
    read_half: Option<oneshot::Receiver<SocketRead>>,
    pool: Option<PoolHandle>,
) {
    let _shutdown = shutdown;

    if !prefix.is_empty() && transmitter.send(BodyEvent::Item(Ok(prefix))).await.is_err() {
        return;
    }

    loop {
        let item = tokio::select! {
            _ = transmitter.closed() => return,
            item = records.recv() => item,
        };

        let Some(item) = item else {
            let _ = transmitter
                .send(BodyEvent::Item(Err(Box::new(Error::Protocol(
                    "connection closed before END_REQUEST".to_owned(),
                )))))
                .await;
            return;
        };

        let record = match item {
            Ok(record) => record,
            Err(error) => {
                let _ = transmitter
                    .send(BodyEvent::Item(Err(Box::new(error))))
                    .await;
                return;
            }
        };

        if record.request_id != protocol::REQUEST_ID {
            let _ = transmitter
                .send(BodyEvent::Item(Err(Box::new(Error::Protocol(format!(
                    "record for request {}, expected {}",
                    record.request_id,
                    protocol::REQUEST_ID
                ))))))
                .await;
            return;
        }

        match RecordType::from_u8(record.record_type) {
            Some(RecordType::Stdout) => {
                total_stdout = total_stdout.saturating_add(record.content.len());
                if total_stdout > max_stdout {
                    let _ = transmitter
                        .send(BodyEvent::Item(Err(Box::new(Error::Response(format!(
                            "STDOUT exceeds the configured limit of {max_stdout} bytes"
                        ))))))
                        .await;
                    return;
                }

                if !record.content.is_empty()
                    && transmitter
                        .send(BodyEvent::Item(Ok(Bytes::from(record.content))))
                        .await
                        .is_err()
                {
                    return;
                }
            }

            Some(RecordType::Stderr) => {}
            Some(RecordType::EndRequest) => {
                let clean = match decode_end_request(&record.content) {
                    Ok((_, 0)) => true,
                    Ok((_, protocol_status)) => {
                        let _ = transmitter
                            .send(BodyEvent::Item(Err(Box::new(Error::Protocol(format!(
                                "server ended the request with protocol status \
                                 {protocol_status} ({})",
                                protocol_status_name(protocol_status)
                            ))))))
                            .await;
                        false
                    }
                    Err(error) => {
                        let _ = transmitter
                            .send(BodyEvent::Item(Err(Box::new(error))))
                            .await;
                        false
                    }
                };

                if clean {
                    let reusable = match (read_half, pool) {
                        (Some(receiver), Some(pool)) => match receiver.await {
                            Ok(reader) => reunite(reader, writer).map(|socket| (socket, pool)),
                            Err(_) => None,
                        },
                        _ => None,
                    };

                    let _ = transmitter.send(BodyEvent::End(reusable)).await;
                }
                return;
            }
            Some(other) => {
                let _ = transmitter
                    .send(BodyEvent::Item(Err(Box::new(Error::Protocol(format!(
                        "unexpected {} record while waiting for the response",
                        other.name()
                    ))))))
                    .await;
                return;
            }
            None => {
                let _ = transmitter
                    .send(BodyEvent::Item(Err(Box::new(Error::Protocol(format!(
                        "unexpected record type {} while waiting for the response",
                        record.record_type
                    ))))))
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

pub(crate) async fn with_deadline<F, T>(
    duration: Duration,
    target: &str,
    future: F,
) -> Result<T, Error>
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

struct ChannelStream {
    receiver: mpsc::Receiver<BodyEvent>,
}

impl Stream for ChannelStream {
    type Item = Result<Bytes, BoxError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(context) {
            Poll::Ready(Some(BodyEvent::Item(item))) => Poll::Ready(Some(item)),
            Poll::Ready(Some(BodyEvent::End(reusable))) => {
                if let Some((socket, pool)) = reusable {
                    pool.release(socket);
                }
                Poll::Ready(None)
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
