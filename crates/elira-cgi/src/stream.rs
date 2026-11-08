//! Streaming CGI execution.
//!
//! [`execute_stream`] spawns the script, copies the request body stream into
//! its stdin, and returns as soon as the CGI header block is complete. The
//! remaining stdout is forwarded by a background task over a bounded channel,
//! so a slow caller applies backpressure to the child instead of making the
//! proxy buffer the whole response.
//!
//! Stdin is written by a separate task: writing a large body before reading
//! stdout would deadlock as soon as the script fills the stdout pipe. STDERR
//! is drained in another task so a chatty script cannot block either. The
//! child is killed when the caller drops the body stream, when the deadline
//! elapses, or when the stdout limit is crossed.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::{
    base_command, kill_and_reap, parse_header_block, split_headers, BoxError, Error,
    MAX_STDERR_BYTES,
};

/// A streaming body: request input or response output.
pub type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + Send>>;

/// A CGI request whose body arrives as a stream.
pub struct StreamRequest {
    /// Absolute path to the executable script.
    pub script: PathBuf,
    /// Environment variables passed to the script.
    pub params: Vec<(String, String)>,
    /// Request body chunks written to the script's standard input.
    pub body: BodyStream,
    /// Deadline for the header block and for each later stdout read.
    ///
    /// [`Duration::ZERO`] disables the deadline. A timed-out child is killed
    /// and reaped before the error is reported.
    pub timeout: Duration,
}

impl fmt::Debug for StreamRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamRequest")
            .field("script", &self.script)
            .field("params", &self.params)
            .field("body", &"<stream>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// A CGI response whose headers are available but whose body is still
/// arriving.
pub struct StreamResponse {
    /// HTTP status code. Defaults to 200, or 302 for `Location` without an
    /// explicit `Status`.
    pub status: u16,
    /// Response headers in script order. The CGI `Status` header is consumed.
    pub headers: Vec<(String, String)>,
    /// Body chunks. The stream ends when the script closes stdout and yields
    /// an error if the child fails, times out, or exceeds `max_stdout`.
    pub body: BodyStream,
    /// STDERR text that arrived before the header block was complete.
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

/// Body chunks buffered between the child's stdout and the caller.
const BODY_CHANNEL_CAPACITY: usize = 8;

/// Runs one CGI script and returns its headers plus a streaming body.
///
/// `max_stdout` bounds the total stdout bytes, header block included. Crossing
/// it makes the body stream yield an error and kills the child.
pub async fn execute_stream(
    request: StreamRequest,
    max_stdout: usize,
) -> Result<StreamResponse, Error> {
    let StreamRequest {
        script,
        params,
        mut body,
        timeout: deadline,
    } = request;

    let mut command = base_command(&script, &params)?;
    let mut child = command.spawn().map_err(|source| Error::Spawn {
        path: script.clone(),
        source,
    })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("CGI stdin was not piped"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("CGI stdout was not piped"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("CGI stderr was not piped"))?;

    // The writer task must make progress while this task reads stdout. If the
    // header phase fails, aborting it closes stdin when the handle drops.
    let writer = tokio::spawn(async move {
        write_body_stream(stdin, &mut body).await;
    });

    let headers = read_headers(&mut stdout, &mut stderr, max_stdout);
    let headers = if deadline.is_zero() {
        match headers.await {
            Ok(headers) => headers,
            Err(error) => {
                writer.abort();
                kill_and_reap(&mut child).await;
                return Err(error);
            }
        }
    } else {
        match timeout(deadline, headers).await {
            Ok(Ok(headers)) => headers,
            Ok(Err(error)) => {
                writer.abort();
                kill_and_reap(&mut child).await;
                return Err(error);
            }
            Err(_) => {
                writer.abort();
                kill_and_reap(&mut child).await;
                return Err(Error::Timeout);
            }
        }
    };

    let (body_tx, body_rx) = mpsc::channel(BODY_CHANNEL_CAPACITY);
    tokio::spawn(stream_tail(
        stdout,
        stderr,
        writer,
        child,
        body_tx,
        headers.prefix,
        headers.total,
        max_stdout,
        deadline,
    ));

    Ok(StreamResponse {
        status: headers.status,
        headers: headers.headers,
        body: Box::pin(ChannelStream { receiver: body_rx }),
        stderr: headers.stderr,
    })
}

struct HeaderInfo {
    status: u16,
    headers: Vec<(String, String)>,
    prefix: Bytes,
    stderr: String,
    total: usize,
}

/// Read stdout until the blank line that ends the CGI header block.
async fn read_headers(
    stdout: &mut ChildStdout,
    stderr: &mut ChildStderr,
    max_stdout: usize,
) -> Result<HeaderInfo, Error> {
    let mut buffer = BytesMut::new();
    let mut stderr_bytes = BytesMut::new();
    let mut total = 0usize;
    let mut stdout_chunk = [0u8; 16 * 1024];
    let mut stderr_chunk = [0u8; 8 * 1024];
    let mut stderr_open = true;

    loop {
        tokio::select! {
            result = stdout.read(&mut stdout_chunk) => {
                let read = result.map_err(Error::Io)?;
                if read == 0 {
                    return Err(if buffer.is_empty() {
                        Error::Malformed("empty CGI response")
                    } else {
                        Error::Malformed("missing CGI header terminator")
                    });
                }

                total = total.saturating_add(read);
                if total > max_stdout {
                    return Err(Error::Malformed("stdout exceeds the configured limit"));
                }
                buffer.extend_from_slice(&stdout_chunk[..read]);

                if let Some((header_block, body)) = split_headers(&buffer) {
                    let (status, headers) = parse_header_block(header_block)?;
                    let prefix = Bytes::copy_from_slice(body);
                    return Ok(HeaderInfo {
                        status,
                        headers,
                        prefix,
                        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
                        total,
                    });
                }
            }
            result = stderr.read(&mut stderr_chunk), if stderr_open => {
                let read = result.map_err(Error::Io)?;
                if read == 0 {
                    stderr_open = false;
                } else {
                    let room = MAX_STDERR_BYTES.saturating_sub(stderr_bytes.len());
                    if room > 0 {
                        let take = read.min(room);
                        stderr_bytes.extend_from_slice(&stderr_chunk[..take]);
                    }
                }
            }
        }
    }
}

/// Copy the request stream into the child's stdin and close it at the end.
async fn write_body_stream(mut stdin: ChildStdin, body: &mut BodyStream) {
    while let Some(item) = body.next().await {
        let Ok(chunk) = item else {
            break;
        };
        if chunk.is_empty() {
            continue;
        }

        match stdin.write_all(&chunk).await {
            Ok(()) => {}
            // A script may stop reading before the body ends. EPIPE means the
            // exchange is over from its side, not that the request failed.
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => break,
            Err(_) => break,
        }
    }

    let _ = stdin.shutdown().await;
}

/// Forward the rest of stdout, watching for the caller going away.
#[allow(clippy::too_many_arguments)]
async fn stream_tail(
    mut stdout: ChildStdout,
    stderr: ChildStderr,
    writer: JoinHandle<()>,
    mut child: Child,
    transmitter: mpsc::Sender<Result<Bytes, BoxError>>,
    prefix: Bytes,
    mut total: usize,
    max_stdout: usize,
    deadline: Duration,
) {
    // STDERR is drained for the whole life of the script. The returned
    // response already contains the pre-header bytes, so later output is
    // discarded rather than buffered.
    let stderr_task = tokio::spawn(async move {
        drain_stderr(stderr).await;
    });

    if !prefix.is_empty() && transmitter.send(Ok(prefix)).await.is_err() {
        stop_child(&mut child, &writer).await;
        stderr_task.abort();
        return;
    }

    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let result = tokio::select! {
            _ = transmitter.closed() => {
                stop_child(&mut child, &writer).await;
                stderr_task.abort();
                return;
            }
            result = read_stdout(&mut stdout, &mut buffer, deadline) => result,
        };

        match result {
            Ok(0) => {
                // The script closed stdout. Wait for it to exit so a timeout
                // after the body cannot leave a zombie behind, but stop early
                // if the caller drops the body while the script lingers.
                let caller_gone = tokio::select! {
                    _ = transmitter.closed() => true,
                    _ = wait_child(&mut child, deadline) => false,
                };
                if caller_gone {
                    stop_child(&mut child, &writer).await;
                }
                writer.abort();
                // Do not await the drain task: a grandchild may still hold
                // the pipe open, and there is nothing left to do with stderr.
                stderr_task.abort();
                return;
            }
            Ok(read) => {
                total = total.saturating_add(read);
                if total > max_stdout {
                    let _ = transmitter
                        .send(Err(Box::new(Error::Malformed(
                            "stdout exceeds the configured limit",
                        ))))
                        .await;
                    stop_child(&mut child, &writer).await;
                    stderr_task.abort();
                    return;
                }

                if transmitter
                    .send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                    .await
                    .is_err()
                {
                    stop_child(&mut child, &writer).await;
                    stderr_task.abort();
                    return;
                }
            }
            Err(error) => {
                let _ = transmitter.send(Err(Box::new(error))).await;
                stop_child(&mut child, &writer).await;
                stderr_task.abort();
                return;
            }
        }
    }
}

async fn read_stdout(
    stdout: &mut ChildStdout,
    buffer: &mut [u8],
    deadline: Duration,
) -> Result<usize, Error> {
    if deadline.is_zero() {
        stdout.read(buffer).await.map_err(Error::Io)
    } else {
        match timeout(deadline, stdout.read(buffer)).await {
            Ok(result) => result.map_err(Error::Io),
            Err(_) => Err(Error::Timeout),
        }
    }
}

async fn wait_child(child: &mut Child, deadline: Duration) -> Result<(), Error> {
    if deadline.is_zero() {
        child.wait().await.map(|_| ()).map_err(Error::Io)
    } else {
        match timeout(deadline, child.wait()).await {
            Ok(result) => result.map(|_| ()).map_err(Error::Io),
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                Err(Error::Timeout)
            }
        }
    }
}

async fn drain_stderr(mut stderr: ChildStderr) {
    let mut chunk = [0u8; 8 * 1024];
    loop {
        match stderr.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

async fn stop_child(child: &mut Child, writer: &JoinHandle<()>) {
    writer.abort();
    // `kill_on_drop` also covers this, but waiting here reaps the process while
    // the task still owns it instead of leaving the reaping to the runtime.
    let _ = child.start_kill();
    let _ = child.wait().await;
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
