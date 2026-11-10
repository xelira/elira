//! Request and response body plumbing.
//!
//! Buffering, spooling and the shared byte budget live here so the forwarding
//! path can wrap a body without knowing where it is stored.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::Stream;
use http::header::CONTENT_LENGTH;
use http::HeaderMap;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{BodyExt, StreamBody};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::Sleep;
use tokio_util::io::ReaderStream;

use crate::*;

/// Shared byte budget for temporary spool files. Zero total means unlimited;
/// the used counter is still maintained for `/status`.
pub(crate) struct SpoolBudget {
    pub(crate) total: u64,
    used: Mutex<u64>,
}

pub(crate) struct SpoolPermit {
    budget: Arc<SpoolBudget>,
    bytes: u64,
}

impl SpoolBudget {
    pub(crate) fn new(total: u64) -> Self {
        Self {
            total,
            used: Mutex::new(0),
        }
    }

    pub(crate) fn reserve(self: &Arc<Self>, bytes: u64) -> Option<SpoolPermit> {
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.total > 0 && used.saturating_add(bytes) > self.total {
            return None;
        }
        *used = used.saturating_add(bytes);
        Some(SpoolPermit {
            budget: self.clone(),
            bytes,
        })
    }

    pub(crate) fn used(&self) -> u64 {
        *self
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for SpoolPermit {
    fn drop(&mut self) {
        let mut used = self
            .budget
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *used = used.saturating_sub(self.bytes);
    }
}

/// Single-flight coordination for cache misses. One request fills the entry;
/// the rest wait briefly and re-check the cache instead of stampeding the
/// upstream.
pub(crate) struct CacheFlights {
    entries: Mutex<HashMap<String, watch::Sender<bool>>>,
}

pub(crate) enum CacheFlight {
    Leader(CacheFlightGuard),
    Follower(watch::Receiver<bool>),
}

pub(crate) struct CacheFlightGuard {
    flights: Arc<CacheFlights>,
    key: String,
    done: watch::Sender<bool>,
}

impl CacheFlights {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn enter(self: &Arc<Self>, key: &str) -> CacheFlight {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(done) = entries.get(key) {
            return CacheFlight::Follower(done.subscribe());
        }
        let (done, _) = watch::channel(false);
        entries.insert(key.to_owned(), done.clone());
        CacheFlight::Leader(CacheFlightGuard {
            flights: self.clone(),
            key: key.to_owned(),
            done,
        })
    }
}

impl Drop for CacheFlightGuard {
    fn drop(&mut self) {
        {
            let mut entries = self
                .flights
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            entries.remove(&self.key);
        }
        let _ = self.done.send(true);
    }
}

impl SpoolPermit {
    pub(crate) fn grow(&mut self, bytes: u64) -> bool {
        let mut used = self
            .budget
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.budget.total > 0 && used.saturating_add(bytes) > self.budget.total {
            return false;
        }
        *used = used.saturating_add(bytes);
        self.bytes = self.bytes.saturating_add(bytes);
        true
    }
}

/// A growable reservation used while the final body size is unknown.
pub(crate) struct SpoolLease {
    permit: SpoolPermit,
}

impl SpoolLease {
    pub(crate) fn new(budget: &Arc<SpoolBudget>) -> Option<Self> {
        budget.reserve(0).map(|permit| Self { permit })
    }

    pub(crate) fn from_permit(permit: SpoolPermit) -> Self {
        Self { permit }
    }

    pub(crate) fn grow(&mut self, bytes: u64) -> bool {
        self.permit.grow(bytes)
    }
}

/// A body that fails when it makes no progress for `idle`. Used for both
/// client uploads and upstream downloads: a peer that stops mid-body would
/// otherwise hold a connection slot forever.
pub fn timeout_body(body: Body, idle: Duration) -> Body {
    IdleBody {
        inner: body,
        idle,
        timer: Box::pin(tokio::time::sleep(idle)),
        expired: false,
    }
    .boxed()
}

/// Spread a response body over time at roughly `rate` bytes per second. The
/// first `after` bytes are sent without delay, matching `limit_rate_after`.
pub fn rate_limit_body(body: Body, rate: u64, after: u64) -> Body {
    if rate == 0 {
        return body;
    }
    RateBody {
        inner: body,
        rate,
        after,
        sent: 0,
        pending: None,
        started: tokio::time::Instant::now(),
        delay: None,
    }
    .boxed()
}

/// Keep `hold` alive until the response body is finished. Used by per-route
/// concurrency limits, which must cover streamed responses.
pub(crate) fn hold_body(body: Body, hold: Box<dyn Send + Sync>) -> Body {
    HoldBody {
        inner: body,
        _hold: hold,
    }
    .boxed()
}

struct HoldBody {
    inner: Body,
    _hold: Box<dyn Send + Sync>,
}

impl HttpBody for HoldBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct RateBody {
    inner: Body,
    rate: u64,
    after: u64,
    sent: u64,
    pending: Option<Bytes>,
    started: tokio::time::Instant,
    delay: Option<Pin<Box<Sleep>>>,
}

impl HttpBody for RateBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();

        if let Some(delay) = &mut this.delay {
            match delay.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => this.delay = None,
            }
        }

        if let Some(data) = this.pending.take() {
            return this.emit(data);
        }

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => this.emit(data),
                Err(frame) => Poll::Ready(Some(Ok(frame))),
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream() && self.pending.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl RateBody {
    fn emit(&mut self, data: Bytes) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        const CHUNK: usize = 16 * 1024;
        let take = data.len().min(CHUNK);
        let mut head = data;
        let tail = head.split_off(take);
        if !tail.is_empty() {
            self.pending = Some(tail);
        }
        self.sent = self.sent.saturating_add(head.len() as u64);
        if self.rate > 0 {
            let billable = self.sent.saturating_sub(self.after);
            let target = Duration::from_secs_f64(billable as f64 / self.rate as f64);
            let deadline = self.started + target;
            if deadline > tokio::time::Instant::now() {
                self.delay = Some(Box::pin(tokio::time::sleep_until(deadline)));
            }
        }
        Poll::Ready(Some(Ok(Frame::data(head))))
    }
}

/// A body that errors after `limit` data bytes.
/// Write a fully known response body to an unlinked temporary file and return
/// a body that reads it back. This releases the upstream connection before a
/// slow client drains the response.
pub(crate) async fn spool_body(
    mut body: Body,
    expected: usize,
    permit: SpoolPermit,
) -> Result<Body, BoxError> {
    let file = tempfile::tempfile()?;
    let mut file = tokio::fs::File::from_std(file);
    let mut seen = 0usize;
    let mut trailers = None;

    while let Some(frame) = body.frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(data) => {
                seen = seen.saturating_add(data.len());
                if seen > expected {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "upstream body is longer than Content-Length",
                    )));
                }
                file.write_all(&data).await?;
            }
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
            }
        }
    }

    if seen != expected {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "upstream body is shorter than Content-Length",
        )));
    }

    file.seek(SeekFrom::Start(0)).await?;
    Ok(SpooledBody {
        stream: ReaderStream::new(file),
        trailers,
        length: expected as u64,
        _permit: Some(permit),
    }
    .boxed())
}

pub(crate) struct SpooledBody {
    stream: ReaderStream<tokio::fs::File>,
    trailers: Option<HeaderMap>,
    length: u64,
    _permit: Option<SpoolPermit>,
}

impl HttpBody for SpooledBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.stream).poll_next(cx) {
            Poll::Ready(Some(Ok(data))) => Poll::Ready(Some(Ok(Frame::data(data)))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(Box::new(err)))),
            Poll::Ready(None) => match this.trailers.take() {
                Some(trailers) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
                None => Poll::Ready(None),
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.length)
    }
}

pub(crate) struct PermitBody {
    pub(crate) inner: Body,
    pub(crate) _permit: tokio::sync::OwnedSemaphorePermit,
}

impl HttpBody for PermitBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pub(crate) enum RequestBuffer {
    Stream(Body),
    Buffered(BufferedBody),
}

pub(crate) enum BufferData {
    Memory(Bytes),
    Spool(Arc<tempfile::NamedTempFile>),
}

pub(crate) struct BufferedBody {
    data: BufferData,
    trailers: Option<HeaderMap>,
    length: u64,
    _lease: Option<SpoolLease>,
}

impl BufferedBody {
    pub(crate) fn body(&self) -> Body {
        match &self.data {
            BufferData::Memory(bytes) => {
                let mut frames: Vec<Result<Frame<Bytes>, BoxError>> =
                    vec![Ok(Frame::data(bytes.clone()))];
                if let Some(trailers) = &self.trailers {
                    frames.push(Ok(Frame::trailers(trailers.clone())));
                }
                BodyExt::boxed(StreamBody::new(futures_util::stream::iter(frames)))
            }
            BufferData::Spool(file) => spool_file_body(file, self.length, self.trailers.clone()),
        }
    }
}

pub(crate) fn spool_file_body(
    file: &Arc<tempfile::NamedTempFile>,
    length: u64,
    trailers: Option<HeaderMap>,
) -> Body {
    let reopened = file.reopen().expect("spool temp file is still open");
    SpooledBody {
        stream: ReaderStream::new(tokio::fs::File::from_std(reopened)),
        trailers,
        length,
        _permit: None,
    }
    .boxed()
}

/// A body that yields a buffered prefix and then continues with the rest of
/// the original stream. Used when an unknown-length request outgrows the
/// buffering limits.
pub(crate) struct ConcatBody {
    first: Option<Body>,
    rest: Body,
    _lease: Option<SpoolLease>,
}

impl HttpBody for ConcatBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if let Some(mut first) = this.first.take() {
            match Pin::new(&mut first).poll_frame(cx) {
                Poll::Ready(Some(frame)) => {
                    this.first = Some(first);
                    return Poll::Ready(Some(frame));
                }
                Poll::Ready(None) => {}
                Poll::Pending => {
                    this.first = Some(first);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }
}

pub(crate) fn chain_body(first: Body, rest: Body, lease: Option<SpoolLease>) -> Body {
    ConcatBody {
        first: Some(first),
        rest,
        _lease: lease,
    }
    .boxed()
}

pub(crate) fn memory_body(bytes: Bytes) -> Body {
    BodyExt::boxed(StreamBody::new(futures_util::stream::iter(vec![Ok::<
        _,
        BoxError,
    >(
        Frame::data(bytes),
    )])))
}

/// Buffer a request body into memory or a temporary file. A body with a known
/// length is accepted whole when it fits. An unknown-length body is buffered
/// up to the limits; if it outgrows them, the buffered prefix is replayed and
/// the original stream continues, so the request still works but is not
/// retryable.
pub(crate) async fn buffer_request(
    headers: &HeaderMap,
    body: Body,
    memory_limit: usize,
    spool_limit: usize,
    budget: &Arc<SpoolBudget>,
) -> Result<RequestBuffer, ()> {
    let length = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());

    if let Some(length) = length {
        let total_limit = if spool_limit > 0 {
            spool_limit
        } else {
            memory_limit
        };
        if total_limit > 0 && length > total_limit {
            return buffer_unknown_length(body, memory_limit, spool_limit, budget).await;
        }
        return buffer_known_length(body, length, memory_limit, spool_limit, budget).await;
    }
    buffer_unknown_length(body, memory_limit, spool_limit, budget).await
}

pub(crate) async fn buffer_known_length(
    body: Body,
    length: usize,
    memory_limit: usize,
    spool_limit: usize,
    budget: &Arc<SpoolBudget>,
) -> Result<RequestBuffer, ()> {
    if length == 0 {
        return Ok(RequestBuffer::Stream(body));
    }
    let memory = memory_limit > 0 && length <= memory_limit;
    let spool = !memory && spool_limit > 0 && length > memory_limit && length <= spool_limit;
    if !memory && !spool {
        return Ok(RequestBuffer::Stream(body));
    }

    let lease = if spool {
        budget.reserve(length as u64).map(SpoolLease::from_permit)
    } else {
        None
    };
    if spool && lease.is_none() {
        return Ok(RequestBuffer::Stream(body));
    }

    let file = if spool {
        Some(Arc::new(tempfile::NamedTempFile::new().map_err(|_| ())?))
    } else {
        None
    };
    let mut writer = match &file {
        Some(file) => Some(tokio::fs::File::from_std(file.reopen().map_err(|_| ())?)),
        None => None,
    };

    let mut data = Vec::with_capacity(if memory { length } else { 0 });
    let mut trailers = None;
    let mut seen = 0usize;
    let mut body = body;

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ())?;
        match frame.into_data() {
            Ok(chunk) => {
                seen = seen.saturating_add(chunk.len());
                if seen > length {
                    return Err(());
                }
                match &mut writer {
                    Some(file) => file.write_all(&chunk).await.map_err(|_| ())?,
                    None => data.extend_from_slice(&chunk),
                }
            }
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
            }
        }
    }

    if seen != length {
        return Err(());
    }
    if let Some(mut writer) = writer {
        writer.flush().await.map_err(|_| ())?;
    }

    let data = match file {
        Some(file) => BufferData::Spool(file),
        None => BufferData::Memory(Bytes::from(data)),
    };
    Ok(RequestBuffer::Buffered(BufferedBody {
        data,
        trailers,
        length: length as u64,
        _lease: lease,
    }))
}

pub(crate) async fn buffer_unknown_length(
    body: Body,
    memory_limit: usize,
    spool_limit: usize,
    budget: &Arc<SpoolBudget>,
) -> Result<RequestBuffer, ()> {
    let total_limit = if spool_limit > 0 {
        spool_limit
    } else {
        memory_limit
    };
    if total_limit == 0 {
        return Ok(RequestBuffer::Stream(body));
    }

    let mut memory = Vec::new();
    let mut spool: Option<(
        Arc<tempfile::NamedTempFile>,
        tokio::fs::File,
        SpoolLease,
        u64,
    )> = None;
    let mut trailers = None;
    let mut body = body;

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ())?;
        let chunk = match frame.into_data() {
            Ok(chunk) => chunk,
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
                continue;
            }
        };

        if spool.is_none() && (memory_limit == 0 || memory.len() + chunk.len() <= memory_limit) {
            memory.extend_from_slice(&chunk);
            continue;
        }

        if spool.is_none() {
            if spool_limit == 0 || memory.len() + chunk.len() > spool_limit {
                memory.extend_from_slice(&chunk);
                return Ok(RequestBuffer::Stream(chain_body(
                    memory_body(Bytes::from(memory)),
                    body,
                    None,
                )));
            }

            let Some(mut lease) = SpoolLease::new(budget) else {
                memory.extend_from_slice(&chunk);
                return Ok(RequestBuffer::Stream(chain_body(
                    memory_body(Bytes::from(memory)),
                    body,
                    None,
                )));
            };
            let file = Arc::new(tempfile::NamedTempFile::new().map_err(|_| ())?);
            let mut writer = tokio::fs::File::from_std(file.reopen().map_err(|_| ())?);
            let existing = memory.len() as u64;
            if !lease.grow(existing + chunk.len() as u64) {
                memory.extend_from_slice(&chunk);
                return Ok(RequestBuffer::Stream(chain_body(
                    memory_body(Bytes::from(memory)),
                    body,
                    None,
                )));
            }
            writer.write_all(&memory).await.map_err(|_| ())?;
            writer.write_all(&chunk).await.map_err(|_| ())?;
            memory.clear();
            spool = Some((file, writer, lease, existing + chunk.len() as u64));
            continue;
        }

        let (_, writer, lease, written) = spool.as_mut().expect("spool is present");
        if *written + chunk.len() as u64 > spool_limit as u64 || !lease.grow(chunk.len() as u64) {
            let (file, writer, lease, written) = spool.take().expect("spool is present");
            drop(writer);
            let prefix = spool_file_body(&file, written, None);
            return Ok(RequestBuffer::Stream(chain_body(
                prefix,
                chain_body(memory_body(chunk), body, None),
                Some(lease),
            )));
        }

        writer.write_all(&chunk).await.map_err(|_| ())?;
        *written = written.saturating_add(chunk.len() as u64);
    }

    if let Some((file, mut writer, lease, written)) = spool {
        writer.flush().await.map_err(|_| ())?;
        drop(writer);
        return Ok(RequestBuffer::Buffered(BufferedBody {
            data: BufferData::Spool(file),
            trailers,
            length: written,
            _lease: Some(lease),
        }));
    }

    let length = memory.len() as u64;
    Ok(RequestBuffer::Buffered(BufferedBody {
        data: BufferData::Memory(Bytes::from(memory)),
        trailers,
        length,
        _lease: None,
    }))
}

pub(crate) fn capped_body(body: Body, limit: usize) -> Body {
    CappedBody {
        inner: body,
        limit,
        seen: 0,
        message: "upstream response too large",
        flag: None,
    }
    .boxed()
}

pub(crate) fn capped_request_body(body: Body, limit: usize, flag: Arc<AtomicBool>) -> Body {
    CappedBody {
        inner: body,
        limit,
        seen: 0,
        message: "request body too large",
        flag: Some(flag),
    }
    .boxed()
}

pub(crate) struct CappedBody {
    inner: Body,
    limit: usize,
    seen: usize,
    message: &'static str,
    flag: Option<Arc<AtomicBool>>,
}

impl HttpBody for CappedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.seen = this.seen.saturating_add(data.len());
                    if this.seen > this.limit {
                        if let Some(flag) = &this.flag {
                            flag.store(true, Ordering::Relaxed);
                        }
                        return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            this.message,
                        )))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pub(crate) struct IdleBody {
    inner: Body,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
    expired: bool,
}

impl HttpBody for IdleBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.expired {
            return Poll::Ready(None);
        }

        if self.timer.as_mut().poll(cx).is_ready() {
            self.expired = true;
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "body made no progress",
            )))));
        }

        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + this.idle);
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
