use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder};
use async_compression::Level;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING};
use http::header::{CONTENT_ENCODING, CONTENT_TYPE, LOCATION, REFRESH, SERVER, SET_COOKIE, VARY};
use http::{HeaderMap, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;

use crate::helpers::{compressible, connection_tokens, is_hop_by_hop};

const MAX_HEAD: usize = 64 * 1024;
const MAX_LINE: usize = 8 * 1024;
const MAX_TRAILERS: usize = 64;

pub(crate) trait RawIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RawIo for T {}

pub(crate) struct RawConn {
    stream: Box<dyn RawIo>,
    buffer: Vec<u8>,
    read_timeout: Option<Duration>,
    idle_since: Instant,
}

impl RawConn {
    pub(crate) fn boxed(stream: Box<dyn RawIo>, read_timeout: Option<Duration>) -> Self {
        Self {
            stream,
            buffer: Vec::with_capacity(4096),
            read_timeout,
            idle_since: Instant::now(),
        }
    }

    async fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; 8192];
        let read = match self.read_timeout {
            Some(timeout) => tokio::time::timeout(timeout, self.stream.read(&mut chunk))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "upstream body timed out")
                })??,
            None => self.stream.read(&mut chunk).await?,
        };
        self.buffer.extend_from_slice(&chunk[..read]);
        Ok(read)
    }

    async fn read_head(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(index) = find_head_end(&self.buffer) {
                let head = self.buffer[..index - 4].to_vec();
                self.buffer.drain(..index);
                return Ok(head);
            }
            if self.buffer.len() > MAX_HEAD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream response head is too large",
                ));
            }
            if self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed before the response head",
                ));
            }
        }
    }

    async fn read_line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(index) = find_crlf(&self.buffer) {
                let line = self.buffer[..index].to_vec();
                self.buffer.drain(..index + 2);
                return Ok(line);
            }
            if self.buffer.len() > MAX_LINE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream chunk line is too long",
                ));
            }
            if self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed in a chunked body",
                ));
            }
        }
    }

    async fn copy_exact<W>(&mut self, mut len: u64, out: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        while len > 0 {
            if self.buffer.is_empty() && self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed in the response body",
                ));
            }
            let take = (self.buffer.len() as u64).min(len) as usize;
            out.write_all(&self.buffer[..take]).await?;
            self.buffer.drain(..take);
            len -= take as u64;
        }
        Ok(())
    }

    async fn copy_to_end<W>(&mut self, out: &mut W) -> io::Result<u64>
    where
        W: AsyncWrite + Unpin,
    {
        let mut written = 0u64;
        loop {
            if !self.buffer.is_empty() {
                written += self.buffer.len() as u64;
                out.write_all(&self.buffer).await?;
                self.buffer.clear();
            }
            if self.fill().await? == 0 {
                return Ok(written);
            }
        }
    }

    async fn copy_chunked<W>(&mut self, out: &mut W) -> io::Result<u64>
    where
        W: AsyncWrite + Unpin,
    {
        let mut written = 0u64;
        loop {
            let line = self.read_line().await?;
            let size_text = line.split(|byte| *byte == b';').next().unwrap_or_default();
            let size = std::str::from_utf8(size_text)
                .ok()
                .and_then(|text| u64::from_str_radix(text.trim(), 16).ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            out.write_all(&line).await?;
            out.write_all(b"\r\n").await?;
            written = written.saturating_add(size);
            if size == 0 {
                let mut trailers = 0usize;
                loop {
                    let trailer = self.read_line().await?;
                    if trailer.is_empty() {
                        out.write_all(b"\r\n").await?;
                        return Ok(written);
                    }
                    trailers += 1;
                    if trailers > MAX_TRAILERS || trailer.len() > MAX_LINE {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "too many response trailers",
                        ));
                    }
                    if !trailer.contains(&b':') || trailer.starts_with(b" ") {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "bad response trailer",
                        ));
                    }
                    out.write_all(&trailer).await?;
                    out.write_all(b"\r\n").await?;
                }
            }
            self.copy_exact(size, out).await?;
            let mut crlf = [0u8; 2];
            self.read_into(&mut crlf).await?;
            if &crlf != b"\r\n" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "chunk is not followed by CRLF",
                ));
            }
            out.write_all(b"\r\n").await?;
        }
    }

    async fn read_into(&mut self, target: &mut [u8]) -> io::Result<()> {
        let mut filled = 0usize;
        while filled < target.len() {
            if self.buffer.is_empty() && self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed in the response body",
                ));
            }
            let take = (target.len() - filled).min(self.buffer.len());
            target[filled..filled + take].copy_from_slice(&self.buffer[..take]);
            self.buffer.drain(..take);
            filled += take;
        }
        Ok(())
    }

    async fn read_chunked_limited(&mut self, limit: usize) -> io::Result<ChunkedBody> {
        let mut body = Vec::new();
        loop {
            let line = self.read_line().await?;
            let size_text = line.split(|byte| *byte == b';').next().unwrap_or_default();
            let size = std::str::from_utf8(size_text)
                .ok()
                .and_then(|text| u64::from_str_radix(text.trim(), 16).ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                loop {
                    if self.read_line().await?.is_empty() {
                        return Ok(ChunkedBody::Complete(body));
                    }
                }
            }
            if size > (limit.saturating_sub(body.len())) as u64 {
                let mut restored = line;
                restored.extend_from_slice(b"\r\n");
                self.buffer.splice(0..0, restored);
                return Ok(ChunkedBody::Partial(body));
            }
            let mut chunk = vec![0u8; size as usize];
            self.read_into(&mut chunk).await?;
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            self.read_into(&mut crlf).await?;
            if &crlf != b"\r\n" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "chunk is not followed by CRLF",
                ));
            }
            if body.len() >= limit {
                return Ok(ChunkedBody::Partial(body));
            }
        }
    }

    async fn read_exact_vec(&mut self, mut len: u64) -> io::Result<Vec<u8>> {
        let mut body = Vec::with_capacity(len.min(256 * 1024) as usize);
        while len > 0 {
            if self.buffer.is_empty() && self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed in the response body",
                ));
            }
            let take = (self.buffer.len() as u64).min(len) as usize;
            body.extend_from_slice(&self.buffer[..take]);
            self.buffer.drain(..take);
            len -= take as u64;
        }
        Ok(body)
    }

    fn is_reusable(&self) -> bool {
        self.buffer.is_empty()
    }
}

enum ChunkedBody {
    Complete(Vec<u8>),
    Partial(Vec<u8>),
}

#[derive(Clone, Copy)]
enum Framing {
    None,
    Length(u64),
    Chunked,
    Close,
}

impl RawConn {
    async fn pipe_exact(
        &mut self,
        mut len: u64,
        tx: &mpsc::Sender<io::Result<Bytes>>,
    ) -> io::Result<()> {
        while len > 0 {
            if self.buffer.is_empty() && self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed in the response body",
                ));
            }
            let take = (self.buffer.len() as u64).min(len) as usize;
            let chunk = Bytes::copy_from_slice(&self.buffer[..take]);
            self.buffer.drain(..take);
            tx.send(Ok(chunk))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "compressor stopped"))?;
            len -= take as u64;
        }
        Ok(())
    }

    async fn pipe_chunked(&mut self, tx: &mpsc::Sender<io::Result<Bytes>>) -> io::Result<()> {
        loop {
            let line = self.read_line().await?;
            let size_text = line.split(|byte| *byte == b';').next().unwrap_or_default();
            let size = std::str::from_utf8(size_text)
                .ok()
                .and_then(|text| u64::from_str_radix(text.trim(), 16).ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                loop {
                    if self.read_line().await?.is_empty() {
                        return Ok(());
                    }
                }
            }
            self.pipe_exact(size, tx).await?;
            let mut crlf = [0u8; 2];
            self.read_into(&mut crlf).await?;
            if &crlf != b"\r\n" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "chunk is not followed by CRLF",
                ));
            }
        }
    }

    async fn pipe_to_end(&mut self, tx: &mpsc::Sender<io::Result<Bytes>>) -> io::Result<()> {
        loop {
            if !self.buffer.is_empty() {
                let chunk = Bytes::copy_from_slice(&self.buffer);
                self.buffer.clear();
                tx.send(Ok(chunk))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "compressor stopped"))?;
            }
            if self.fill().await? == 0 {
                return Ok(());
            }
        }
    }
}

async fn compress_buffer(body: Vec<u8>, encoding: &'static str) -> io::Result<Vec<u8>> {
    let reader = BufReader::new(std::io::Cursor::new(body));
    let mut reader: Box<dyn AsyncRead + Unpin + Send> = match encoding {
        "br" => Box::new(BrotliEncoder::with_quality(reader, Level::Fastest)),
        _ => Box::new(GzipEncoder::with_quality(reader, Level::Fastest)),
    };
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await?;
    Ok(out)
}

async fn stream_compressed<W>(
    conn: RawConn,
    framing: Framing,
    encoding: &'static str,
    client: &mut W,
) -> Result<(u64, bool, RawConn), ()>
where
    W: AsyncWrite + Unpin,
{
    let reusable = !matches!(framing, Framing::Close);
    let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(8);
    let handle = tokio::spawn(async move {
        let mut conn = conn;
        let result = match framing {
            Framing::None => Ok(()),
            Framing::Length(length) => conn.pipe_exact(length, &tx).await,
            Framing::Chunked => conn.pipe_chunked(&tx).await,
            Framing::Close => conn.pipe_to_end(&tx).await,
        };
        if let Err(error) = result {
            let _ = tx.send(Err(error)).await;
        }
        drop(tx);
        conn
    });

    let reader = BufReader::new(StreamReader::new(ReceiverStream::new(rx)));
    let mut reader: Box<dyn AsyncRead + Unpin + Send> = match encoding {
        "br" => Box::new(BrotliEncoder::with_quality(reader, Level::Fastest)),
        _ => Box::new(GzipEncoder::with_quality(reader, Level::Fastest)),
    };

    let mut sent = 0u64;
    let mut buffer = [0u8; 8192];
    let result = async {
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            client.write_all(format!("{read:x}\r\n").as_bytes()).await?;
            client.write_all(&buffer[..read]).await?;
            client.write_all(b"\r\n").await?;
            sent += read as u64;
        }
        client.write_all(b"0\r\n\r\n").await?;
        client.flush().await
    }
    .await;

    if result.is_err() {
        handle.abort();
        return Err(());
    }
    let conn = handle.await.map_err(|_| ())?;
    Ok((sent, reusable && conn.is_reusable(), conn))
}

#[derive(Default)]
struct RawEntry {
    idle: Vec<RawConn>,
    created: u64,
    reused: u64,
    errors: u64,
    active: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RawPoolStats {
    pub idle: usize,
    pub active: u64,
    pub created: u64,
    pub reused: u64,
    pub errors: u64,
}

pub(crate) struct RawPool {
    entries: Mutex<HashMap<String, RawEntry>>,
    max_idle: usize,
    idle_timeout: Duration,
}

impl RawPool {
    pub(crate) fn new(max_idle: usize, idle_timeout: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_idle,
            idle_timeout,
        }
    }

    pub(crate) async fn take(&self, key: &str) -> Option<RawConn> {
        loop {
            let mut conn = {
                let mut entries = self
                    .entries
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let entry = entries.get_mut(key)?;
                let conn = entry.idle.pop()?;
                if conn.idle_since.elapsed() >= self.idle_timeout {
                    continue;
                }
                entry.reused = entry.reused.saturating_add(1);
                entry.active = entry.active.saturating_add(1);
                conn
            };
            let mut probe = [0u8; 1];
            match futures_util::FutureExt::now_or_never(conn.stream.read(&mut probe)) {
                None => return Some(conn),
                Some(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => return Some(conn),
                _ => continue,
            }
        }
    }

    pub(crate) fn put(&self, key: String, conn: RawConn) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.entry(key).or_default();
        entry.active = entry.active.saturating_sub(1);
        if entry.idle.len() < self.max_idle {
            let mut conn = conn;
            conn.idle_since = Instant::now();
            entry.idle.push(conn);
        }
    }

    pub(crate) fn created(&self, key: &str) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.entry(key.to_owned()).or_default();
        entry.created = entry.created.saturating_add(1);
        entry.active = entry.active.saturating_add(1);
    }

    pub(crate) fn error(&self, key: &str) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.entry(key.to_owned()).or_default();
        entry.errors = entry.errors.saturating_add(1);
    }

    pub(crate) fn release(&self, key: &str) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = entries.get_mut(key) {
            entry.active = entry.active.saturating_sub(1);
        }
    }

    pub(crate) fn failed(&self, key: &str) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.entry(key.to_owned()).or_default();
        entry.errors = entry.errors.saturating_add(1);
        entry.active = entry.active.saturating_sub(1);
    }

    pub(crate) fn stats(&self) -> HashMap<String, RawPoolStats> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries
            .iter()
            .map(|(key, entry)| {
                (
                    key.clone(),
                    RawPoolStats {
                        idle: entry.idle.len(),
                        active: entry.active,
                        created: entry.created,
                        reused: entry.reused,
                        errors: entry.errors,
                    },
                )
            })
            .collect()
    }
}

pub(crate) struct HeaderRules<'a> {
    pub(crate) hide: &'a [HeaderName],
    pub(crate) pass: &'a [HeaderName],
    pub(crate) add: &'a [(HeaderName, String)],
    pub(crate) remove: &'a [HeaderName],
    pub(crate) redirect: &'a [(String, String)],
    pub(crate) cookie_domain: &'a [(String, String)],
    pub(crate) cookie_path: &'a [(String, String)],
    pub(crate) pages: &'a [crate::ErrorPage],
}

pub(crate) struct RelayResult {
    pub(crate) status: u16,
    pub(crate) bytes: u64,
    pub(crate) keepalive: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward<W>(
    pool: &RawPool,
    key: &str,
    mut conn: RawConn,
    client: &mut W,
    request_head: &[u8],
    early_hints: Option<&[u8]>,
    budget: &Arc<crate::SpoolBudget>,
    head_timeout: Duration,
    client_keepalive: bool,
    is_head: bool,
    compression: Option<(&'static str, usize)>,
    rules: HeaderRules<'_>,
    server_header: bool,
    request_id: &str,
    date: &str,
) -> io::Result<RelayResult>
where
    W: AsyncWrite + Unpin,
{
    if let Some(hints) = early_hints {
        if client.write_all(hints).await.is_err() || client.flush().await.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "client stopped before early hints",
            ));
        }
    }
    let response_head = tokio::time::timeout(head_timeout, async {
        conn.stream.write_all(request_head).await?;
        conn.stream.flush().await?;
        let mut head = conn.read_head().await?;
        loop {
            let parsed = parse_response(&head)?;
            if parsed.status / 100 != 1 || parsed.status == 101 {
                return Ok((parsed, head));
            }
            head = conn.read_head().await?;
        }
    })
    .await;

    let (mut parsed, _) = match response_head {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream timed out",
            ))
        }
    };

    let mut page_body = None;
    let mut page_type = None;
    let mut page_location = None;
    if let Some(page) = rules
        .pages
        .iter()
        .find(|page| page.status.as_u16() == parsed.status)
    {
        if let Some(named) = &page.named {
            match named.as_ref() {
                crate::Target::Return {
                    status,
                    body,
                    content_type,
                } => {
                    let body = body.as_bytes().to_vec();
                    let final_status = page
                        .override_status
                        .map(|value| value.as_u16())
                        .unwrap_or_else(|| {
                            if status.is_success() {
                                parsed.status
                            } else {
                                status.as_u16()
                            }
                        });
                    parsed.status = final_status;
                    parsed.length = Some(body.len() as u64);
                    parsed.chunked = false;
                    parsed.bodyless = false;
                    page_type = content_type.clone();
                    page_body = Some(body);
                }
                crate::Target::Redirect { status, location } => {
                    let final_status = page
                        .override_status
                        .map(|value| value.as_u16())
                        .unwrap_or_else(|| {
                            if status.is_success() {
                                parsed.status
                            } else {
                                status.as_u16()
                            }
                        });
                    parsed.status = final_status;
                    parsed.length = Some(0);
                    parsed.chunked = false;
                    parsed.bodyless = false;
                    page_location = Some(location.clone());
                    page_body = Some(Vec::new());
                }
                _ => {}
            }
        } else if let Some(files) = &page.files {
            if let Some(file) = files.resolve(&page.path).await {
                let body = match files.cached_body(&file).await {
                    Some(body) => Some(body.to_vec()),
                    None => tokio::fs::read(&file).await.ok(),
                };
                if let Some(body) = body.filter(|body| body.len() <= 1024 * 1024) {
                    let status = page
                        .override_status
                        .map(|status| status.as_u16())
                        .unwrap_or(parsed.status);
                    parsed.status = status;
                    parsed.length = Some(body.len() as u64);
                    parsed.chunked = false;
                    parsed.bodyless = false;
                    page_type = Some(crate::files::content_type(&file).to_owned());
                    page_body = Some(body);
                }
            }
        }
    }

    let close_delimited =
        !parsed.chunked && parsed.length.is_none() && !is_head && !parsed.bodyless;
    let framed = parsed.chunked || parsed.length.is_some() || parsed.bodyless || is_head;
    let upstream_keepalive = parsed.keepalive && framed && !close_delimited;
    let keepalive = client_keepalive && framed && !close_delimited;
    let content_type = parsed
        .headers
        .iter()
        .find(|(name, _)| name == CONTENT_TYPE)
        .and_then(|(_, value)| value.to_str().ok())
        .unwrap_or_default();
    let compress = if page_body.is_some() {
        None
    } else {
        compression.filter(|(_, minimum)| {
            parsed.status == 200
                && !is_head
                && !parsed.bodyless
                && !parsed
                    .headers
                    .iter()
                    .any(|(name, _)| name == CONTENT_ENCODING)
                && compressible(content_type)
                && parsed
                    .length
                    .map(|length| length >= *minimum as u64)
                    .unwrap_or(true)
        })
    };

    let mut chunked_prefix = None;
    let buffered = match compress {
        Some((encoding, _)) if !is_head && !parsed.bodyless => match parsed.length {
            Some(length) if length <= 256 * 1024 => match budget.reserve(length) {
                Some(_permit) => {
                    let body = conn.read_exact_vec(length).await?;
                    Some((encoding, compress_buffer(body, encoding).await?))
                }
                None => None,
            },
            None if parsed.chunked => match budget.reserve(256 * 1024) {
                Some(_permit) => match conn.read_chunked_limited(256 * 1024).await? {
                    ChunkedBody::Complete(body) => {
                        Some((encoding, compress_buffer(body, encoding).await?))
                    }
                    ChunkedBody::Partial(prefix) => {
                        chunked_prefix = Some(prefix);
                        None
                    }
                },
                None => None,
            },
            _ => None,
        },
        _ => None,
    };
    let compress = if chunked_prefix.is_some() {
        None
    } else {
        compress
    };

    let status = StatusCode::from_u16(parsed.status)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad upstream status"))?;
    let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::with_capacity(parsed.headers.len() + 4);
    for (name, value) in &parsed.headers {
        if page_body.is_some()
            && !matches!(
                name.as_str(),
                "www-authenticate" | "retry-after" | "allow" | "date"
            )
        {
            continue;
        }
        if compress.is_some() && (name == CONTENT_LENGTH || name == TRANSFER_ENCODING) {
            continue;
        }
        if server_header && name.as_str() == "server" {
            continue;
        }
        if rules.remove.iter().any(|drop| drop == name) {
            continue;
        }
        if rules.hide.iter().any(|hide| hide == name) && !rules.pass.iter().any(|pass| pass == name)
        {
            continue;
        }
        let mut value = value.clone();
        if name.as_str() == LOCATION.as_str() {
            if let Some(rewritten) = crate::forward::rewrite_prefix(&value, rules.redirect) {
                value = rewritten;
            }
        } else if name.as_str() == REFRESH.as_str() {
            if let Some(rewritten) = crate::forward::rewrite_refresh(&value, rules.redirect) {
                value = rewritten;
            }
        } else if name.as_str() == SET_COOKIE.as_str() {
            value = crate::forward::rewrite_cookie(&value, rules.cookie_domain, rules.cookie_path);
        }
        headers.push((name.clone(), value));
    }
    if let Some((encoding, body)) = &buffered {
        headers
            .retain(|(name, _)| name != CONTENT_ENCODING && name != VARY && name != CONTENT_LENGTH);
        headers.push((
            CONTENT_ENCODING,
            HeaderValue::from_str(encoding).unwrap_or_else(|_| HeaderValue::from_static("gzip")),
        ));
        headers.push((VARY, HeaderValue::from_static("accept-encoding")));
        if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
            headers.push((CONTENT_LENGTH, value));
        }
    } else if let Some((encoding, _)) = compress {
        headers.retain(|(name, _)| {
            name != CONTENT_ENCODING && name != VARY && name != TRANSFER_ENCODING
        });
        headers.push((
            CONTENT_ENCODING,
            HeaderValue::from_str(encoding).unwrap_or_else(|_| HeaderValue::from_static("gzip")),
        ));
        headers.push((VARY, HeaderValue::from_static("accept-encoding")));
        headers.push((TRANSFER_ENCODING, HeaderValue::from_static("chunked")));
    }
    if let Some(body) = &page_body {
        headers.retain(|(name, _)| name != CONTENT_TYPE && name != CONTENT_LENGTH);
        if let Some(content_type) = &page_type {
            if let Ok(value) = HeaderValue::from_str(content_type) {
                headers.push((CONTENT_TYPE, value));
            }
        }
        if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
            headers.push((CONTENT_LENGTH, value));
        }
    }
    if let Some(location) = &page_location {
        if let Ok(value) = HeaderValue::from_str(location) {
            headers.retain(|(name, _)| name != LOCATION);
            headers.push((LOCATION, value));
        }
    }
    if server_header {
        headers.push((SERVER, HeaderValue::from_static("elira")));
    }
    if !headers.iter().any(|(name, _)| name.as_str() == "date") {
        if let Ok(value) = HeaderValue::from_str(date) {
            headers.push((http::header::DATE, value));
        }
    }
    if !headers
        .iter()
        .any(|(name, _)| name.as_str() == "x-request-id")
    {
        if let Ok(value) = HeaderValue::from_str(request_id) {
            headers.push((HeaderName::from_static("x-request-id"), value));
        }
    }
    for (name, value) in rules.add {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.retain(|(known, _)| known != name);
            headers.push((name.clone(), value));
        }
    }
    for name in rules.remove {
        headers.retain(|(known, _)| known != name);
    }

    let mut response = Vec::with_capacity(256 + headers.len() * 32);
    response.extend_from_slice(b"HTTP/1.1 ");
    response.extend_from_slice(parsed.status.to_string().as_bytes());
    response.push(b' ');
    response.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
    response.extend_from_slice(b"\r\n");
    for (name, value) in &headers {
        response.extend_from_slice(name.as_str().as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(value.as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(if keepalive {
        b"connection: keep-alive\r\n\r\n"
    } else {
        b"connection: close\r\n\r\n"
    });
    if client.write_all(&response).await.is_err() || client.flush().await.is_err() {
        pool.release(key);
        return Ok(RelayResult {
            status: parsed.status,
            bytes: 0,
            keepalive: false,
        });
    }

    let mut bytes = 0u64;
    if let Some(body) = page_body {
        bytes = body.len() as u64;
        if !is_head
            && parsed.status != 204
            && parsed.status != 304
            && (client.write_all(&body).await.is_err() || client.flush().await.is_err())
        {
            pool.release(key);
            return Ok(RelayResult {
                status: parsed.status,
                bytes: 0,
                keepalive: false,
            });
        }
        pool.release(key);
        return Ok(RelayResult {
            status: parsed.status,
            bytes,
            keepalive,
        });
    }
    if let Some(prefix) = chunked_prefix {
        if !prefix.is_empty() {
            client
                .write_all(format!("{:x}\r\n", prefix.len()).as_bytes())
                .await?;
            client.write_all(&prefix).await?;
            client.write_all(b"\r\n").await?;
        }
        bytes = prefix.len() as u64 + conn.copy_chunked(client).await?;
        client.flush().await?;
        if upstream_keepalive && conn.is_reusable() {
            pool.put(key.to_owned(), conn);
        } else {
            pool.release(key);
        }
        return Ok(RelayResult {
            status: parsed.status,
            bytes,
            keepalive,
        });
    }
    if let Some((_, body)) = &buffered {
        bytes = body.len() as u64;
        if client.write_all(body).await.is_err() || client.flush().await.is_err() {
            pool.release(key);
            return Ok(RelayResult {
                status: parsed.status,
                bytes: 0,
                keepalive: false,
            });
        }
        if upstream_keepalive && conn.is_reusable() {
            pool.put(key.to_owned(), conn);
        } else {
            pool.release(key);
        }
        return Ok(RelayResult {
            status: parsed.status,
            bytes,
            keepalive,
        });
    }
    if let Some((encoding, _)) = compress {
        let framing = if is_head || parsed.bodyless {
            Framing::None
        } else if let Some(length) = parsed.length {
            Framing::Length(length)
        } else if parsed.chunked {
            Framing::Chunked
        } else {
            Framing::Close
        };
        match stream_compressed(conn, framing, encoding, client).await {
            Ok((sent, reusable, conn)) => {
                bytes = sent;
                if upstream_keepalive && reusable {
                    pool.put(key.to_owned(), conn);
                } else {
                    pool.release(key);
                }
            }
            Err(()) => {
                pool.release(key);
                return Ok(RelayResult {
                    status: parsed.status,
                    bytes,
                    keepalive: false,
                });
            }
        }
        return Ok(RelayResult {
            status: parsed.status,
            bytes,
            keepalive,
        });
    }

    let copy = async {
        if !is_head && !parsed.bodyless {
            if let Some(length) = parsed.length {
                conn.copy_exact(length, client).await?;
                bytes = length;
            } else if parsed.chunked {
                bytes = conn.copy_chunked(client).await?;
            } else {
                bytes = conn.copy_to_end(client).await?;
            }
            client.flush().await?;
        }
        Ok::<(), io::Error>(())
    }
    .await;
    if copy.is_err() {
        pool.release(key);
        return Ok(RelayResult {
            status: parsed.status,
            bytes,
            keepalive: false,
        });
    }

    if upstream_keepalive && conn.is_reusable() {
        pool.put(key.to_owned(), conn);
    } else {
        pool.release(key);
    }

    Ok(RelayResult {
        status: parsed.status,
        bytes,
        keepalive,
    })
}

struct ParsedResponse {
    status: u16,
    headers: Vec<(HeaderName, HeaderValue)>,
    length: Option<u64>,
    chunked: bool,
    bodyless: bool,
    keepalive: bool,
}

fn parse_response(head: &[u8]) -> io::Result<ParsedResponse> {
    let text = std::str::from_utf8(head)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "upstream head is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty upstream response"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad upstream version",
        ));
    }
    let status: u16 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .filter(|status| (100..1000).contains(status))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad upstream status"))?;

    let mut raw = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "folded upstream header",
            ));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream header without a colon",
            ));
        };
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad upstream header name"))?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad upstream header value"))?;
        raw.append(name, value);
    }

    let mut length: Option<u64> = None;
    for value in raw.get_all(CONTENT_LENGTH).iter() {
        let parsed: u64 = value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad content-length"))?;
        match length {
            Some(known) if known != parsed => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "conflicting content-length values",
                ))
            }
            _ => length = Some(parsed),
        }
    }

    let transfer = raw
        .get_all(TRANSFER_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let chunked = !transfer.is_empty();
    if chunked && (transfer.len() != 1 || transfer[0] != "chunked" || length.is_some()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported upstream transfer encoding",
        ));
    }

    let drop = connection_tokens(&raw);
    let mut headers = Vec::with_capacity(raw.len());
    let mut seen_length = false;
    for (name, value) in raw.iter() {
        if is_hop_by_hop(name) && !(name == TRANSFER_ENCODING && chunked) {
            continue;
        }
        if drop.contains(name) {
            continue;
        }
        if name == CONTENT_LENGTH {
            if seen_length {
                continue;
            }
            seen_length = true;
        }
        headers.push((name.clone(), value.clone()));
    }

    let bodyless = status == 204 || status == 304 || status < 200;
    let http11 = version == "HTTP/1.1";
    let connection_close = raw.get_all(CONNECTION).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"))
        })
    });
    let connection_keepalive = raw.get_all(CONNECTION).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("keep-alive"))
        })
    });
    let keepalive = !connection_close && (http11 || connection_keepalive);

    Ok(ParsedResponse {
        status,
        headers,
        length: if bodyless { None } else { length },
        chunked,
        bodyless,
        keepalive,
    })
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn stream() -> tokio::net::TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        tokio::net::TcpStream::connect(addr).await.expect("connect")
    }

    #[tokio::test]
    async fn idle_connections_expire() {
        let pool = RawPool::new(4, Duration::from_millis(10));
        let conn = RawConn::boxed(Box::new(stream().await), None);
        pool.put("app".to_owned(), conn);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(pool.take("app").await.is_none());
    }

    #[tokio::test]
    async fn fresh_connections_are_reused() {
        let pool = RawPool::new(4, Duration::from_secs(60));
        let conn = RawConn::boxed(Box::new(stream().await), None);
        pool.put("app".to_owned(), conn);
        assert!(pool.take("app").await.is_some());
    }
}
