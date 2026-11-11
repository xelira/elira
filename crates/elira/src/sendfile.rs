//! Zero-copy static responses.
//!
//! hyper owns the socket and only lets a body yield bytes, so `sendfile(2)`
//! cannot be reached from inside it. Instead the first request on a plain
//! HTTP/1.1 connection is peeked before hyper sees it: a simple GET or HEAD
//! for a file we know how to serve is answered here with `sendfile`, and
//! everything else is left in the socket for hyper. `peek` does not consume,
//! so falling back costs nothing.
//!
//! Single ranges and conditional requests are answered here too: the file is
//! already open and the validators are cheap. Multi-range requests still take
//! the normal path because that answer needs a multipart body.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use arc_swap::ArcSwap;
use http::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::TcpStream;

use elira_accesslog::{request_id, Entry};

use crate::server::Runtime;
use elira_metrics::Metrics;

const PEEK: usize = 16 * 1024;
const MAX_HEAD: usize = 64 * 1024;

/// Result of trying to answer a plain HTTP/1.1 connection without hyper.
pub(crate) enum FastOutcome {
    /// The connection was fully served and is closed.
    Served,
    /// The current request (and anything after it) must go to hyper.
    Fallback(PrefixedStream),
}

/// A socket that first replays bytes already read from it, then continues
/// reading from the underlying stream. Used when a fast static request is
/// followed by something only hyper can answer.
pub(crate) struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    stream: TcpStream,
}

impl PrefixedStream {
    pub(crate) fn plain(stream: TcpStream) -> Self {
        Self {
            prefix: Vec::new(),
            pos: 0,
            stream,
        }
    }
}

impl tokio::io::AsyncRead for PrefixedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let len = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + len]);
            this.pos += len;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

struct Parsed {
    method: String,
    path: String,
    host: String,
    user_agent: Option<String>,
    headers: http::HeaderMap,
    keepalive: bool,
    has_body: bool,
}

/// Answer as many keep-alive static requests as possible before handing the
/// connection to hyper. The first request that needs the full pipeline is
/// replayed through [`PrefixedStream`].
pub(crate) async fn try_serve(
    mut stream: TcpStream,
    runtime: &ArcSwap<Runtime>,
    metrics: &Metrics,
    peer: SocketAddr,
    listener: &str,
    min_bytes: u64,
    idle: Option<Duration>,
) -> FastOutcome {
    if !cfg!(target_os = "linux") {
        return FastOutcome::Fallback(PrefixedStream::plain(stream));
    }

    let mut buf = Vec::with_capacity(PEEK);
    loop {
        let head_end = match read_head(&mut stream, &mut buf, idle).await {
            Ok(end) => end,
            Err(_) => return FastOutcome::Served,
        };
        let Some(parsed) = parse_head(&buf[..head_end]) else {
            return FastOutcome::Fallback(PrefixedStream {
                prefix: buf,
                pos: 0,
                stream,
            });
        };
        let keepalive = parsed.keepalive;
        if parsed.has_body {
            return FastOutcome::Fallback(PrefixedStream {
                prefix: buf,
                pos: 0,
                stream,
            });
        }
        let path_only = parsed.path.split('?').next().unwrap_or(&parsed.path);
        let current = runtime.load_full();
        let Some(fast) = current
            .proxy()
            .fast_static(
                &parsed.host,
                path_only,
                peer.ip(),
                &parsed.headers,
                listener,
            )
            .await
        else {
            return FastOutcome::Fallback(PrefixedStream {
                prefix: buf,
                pos: 0,
                stream,
            });
        };
        if !current.proxy().rate_allows(peer.ip()) {
            return FastOutcome::Fallback(PrefixedStream {
                prefix: buf,
                pos: 0,
                stream,
            });
        }

        let file = fast.file;
        let meta = fast.meta;
        if !meta.is_file() {
            return FastOutcome::Fallback(PrefixedStream {
                prefix: buf,
                pos: 0,
                stream,
            });
        }
        let content_type = crate::proxy::files::content_type(&file);
        if elira_proxy::compressible(content_type)
            && elira_proxy::preferred_encoding(&parsed.headers).is_some()
        {
            return FastOutcome::Fallback(PrefixedStream {
                prefix: buf,
                pos: 0,
                stream,
            });
        }
        if let Some(encoding) = elira_proxy::preferred_encoding(&parsed.headers) {
            let sibling = std::path::PathBuf::from(format!("{}.{}", file.display(), encoding));
            if tokio::fs::metadata(&sibling)
                .await
                .map(|meta| meta.is_file())
                .unwrap_or(false)
            {
                return FastOutcome::Fallback(PrefixedStream {
                    prefix: buf,
                    pos: 0,
                    stream,
                });
            }
        }

        let len = meta.len();
        let small = len < min_bytes;
        let cached = if small { fast.cached.clone() } else { None };
        if small && cached.is_none() {
            return FastOutcome::Fallback(PrefixedStream {
                prefix: buf,
                pos: 0,
                stream,
            });
        }

        let modified = meta.modified().ok();
        let etag = crate::proxy::files::etag(len, modified);
        let not_modified = parsed
            .headers
            .get(http::header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
            .map(|value| etag_matches(value, &etag))
            .or_else(|| {
                parsed
                    .headers
                    .get(http::header::IF_MODIFIED_SINCE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| httpdate::parse_http_date(value).ok())
                    .map(|since| modified.map(|modified| modified <= since).unwrap_or(false))
            })
            .unwrap_or(false);
        let range = if not_modified {
            None
        } else {
            match parsed
                .headers
                .get(http::header::RANGE)
                .and_then(|value| value.to_str().ok())
            {
                Some(value) => match parse_range(value, len) {
                    Some(range) => Some(range),
                    None => {
                        return FastOutcome::Fallback(PrefixedStream {
                            prefix: buf,
                            pos: 0,
                            stream,
                        })
                    }
                },
                None => None,
            }
        };

        // From here the response is ours: consume the head.
        buf.drain(..head_end);
        let started = std::time::Instant::now();
        metrics.connection_started();
        let id = request_id();
        let status = if not_modified {
            http::StatusCode::NOT_MODIFIED
        } else if range.is_some() {
            http::StatusCode::PARTIAL_CONTENT
        } else {
            http::StatusCode::OK
        };
        let (offset, body_len) = match range {
            Some((start, end)) => (start, end - start + 1),
            None => (0, len),
        };

        let mut headers: Vec<(String, String)> = vec![
            ("content-type".to_owned(), content_type.to_owned()),
            ("accept-ranges".to_owned(), "bytes".to_owned()),
            ("etag".to_owned(), etag),
            ("x-content-type-options".to_owned(), "nosniff".to_owned()),
            ("x-request-id".to_owned(), id.clone()),
        ];
        if !not_modified {
            headers.push(("content-length".to_owned(), body_len.to_string()));
        }
        if let Some((start, end)) = range {
            headers.push((
                "content-range".to_owned(),
                format!("bytes {start}-{end}/{len}"),
            ));
        }
        if let Some(modified) = modified {
            headers.push((
                "last-modified".to_owned(),
                httpdate::fmt_http_date(modified),
            ));
        }
        if fast.server_header {
            headers.push(("server".to_owned(), "elira".to_owned()));
        }
        if let Some(alt) = &fast.alt_svc {
            if let Ok(value) = alt.to_str() {
                headers.push(("alt-svc".to_owned(), value.to_owned()));
            }
        }
        for name in &fast.remove_headers {
            headers.retain(|(known, _)| known != name.as_str());
        }
        for (name, value) in &fast.add_headers {
            if let Ok(value) = value.to_str() {
                headers.retain(|(known, _)| known != name.as_str());
                headers.push((name.as_str().to_owned(), value.to_owned()));
            }
        }

        let mut response = format!(
            "HTTP/1.1 {} {}\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        );
        for (name, value) in &headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str(if keepalive {
            "connection: keep-alive\r\n\r\n"
        } else {
            "connection: close\r\n\r\n"
        });
        if stream.write_all(response.as_bytes()).await.is_err() {
            metrics.connection_finished();
            return FastOutcome::Served;
        }

        if parsed.method == "GET" && !not_modified && body_len > 0 {
            if let Some(cached) = cached {
                if stream.write_all(&cached).await.is_err() {
                    metrics.connection_finished();
                    return FastOutcome::Served;
                }
            } else if let Ok(file) = std::fs::File::open(&file) {
                let _ = send_file(&stream, file, offset, body_len).await;
            }
        }

        let entry = Entry {
            peer: peer.ip(),
            method: Method::from_bytes(parsed.method.as_bytes()).unwrap_or(Method::GET),
            version: http::Version::HTTP_11,
            host: parsed.host,
            path: parsed.path,
            status,
            bytes: if parsed.method == "HEAD" || not_modified {
                0
            } else {
                body_len
            },
            duration: started.elapsed(),
            user_agent: parsed.user_agent,
            request_id: id,
            upstream: None,
            upstream_addr: None,
            upstream_status: None,
            upstream_time: None,
            variables: std::collections::HashMap::new(),
        };
        metrics.observe(status.as_u16(), started.elapsed());
        metrics.connection_finished();
        if fast.access_log && elira_accesslog::sampled(&entry.request_id, fast.access_log_sample) {
            current.write_log(&entry);
        }

        if !keepalive {
            return FastOutcome::Served;
        }
    }
}

async fn read_head(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    idle: Option<Duration>,
) -> std::io::Result<usize> {
    loop {
        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            return Ok(pos + 4);
        }
        if buf.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        let mut chunk = [0u8; 4096];
        let read = match idle {
            Some(timeout) => tokio::time::timeout(timeout, stream.read(&mut chunk))
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "idle"))??,
            None => stream.read(&mut chunk).await?,
        };
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

fn parse_head(head: &[u8]) -> Option<Parsed> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut request = lines.next()?.split(' ');
    let method = request.next()?;
    let path = request.next()?;
    let version = request.next()?;
    if version != "HTTP/1.1" || (method != "GET" && method != "HEAD") {
        return None;
    }

    let mut host = None;
    let mut user_agent = None;
    let mut headers = http::HeaderMap::new();
    let mut keepalive = true;
    let mut has_body = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if let (Ok(header), Ok(header_value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            headers.append(header, header_value);
        }
        match name.as_str() {
            "host" => host = Some(value.to_owned()),
            "user-agent" => user_agent = Some(value.to_owned()),
            "connection" => {
                if value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("close"))
                {
                    keepalive = false;
                }
            }
            "content-length" => {
                if value.parse::<u64>().ok().is_some_and(|length| length > 0) {
                    has_body = true;
                }
            }
            "transfer-encoding" | "upgrade" | "if-range" | "expect" => return None,
            _ => {}
        }
    }
    Some(Parsed {
        method: method.to_owned(),
        path: path.to_owned(),
        host: host?,
        user_agent,
        headers,
        keepalive,
        has_body,
    })
}

fn etag_matches(header: &str, etag: &str) -> bool {
    header.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*"
            || candidate == etag
            || candidate
                .strip_prefix("W/")
                .map(|value| value == etag)
                .unwrap_or(false)
    })
}

/// One satisfiable byte range. `None` covers multiple ranges and malformed
/// values, which the normal path answers correctly.
fn parse_range(value: &str, len: u64) -> Option<(u64, u64)> {
    let value = value.strip_prefix("bytes=")?;
    if value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    let (start, end) = if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        if suffix == 0 {
            return None;
        }
        (len.checked_sub(suffix)?, len.checked_sub(1)?)
    } else {
        let start: u64 = start.parse().ok()?;
        let end = if end.is_empty() {
            len.checked_sub(1)?
        } else {
            end.parse().ok()?
        };
        (start, end)
    };
    if start > end || end >= len {
        return None;
    }
    Some((start, end))
}

#[cfg(target_os = "linux")]
async fn send_file(
    stream: &TcpStream,
    file: std::fs::File,
    offset: u64,
    len: u64,
) -> io::Result<()> {
    let input = file.as_raw_fd();
    let output = stream.as_raw_fd();
    let mut offset: i64 = offset as i64;
    let mut remaining = len;

    while remaining > 0 {
        stream.writable().await?;
        let count = remaining.min(1 << 20) as usize;
        let result = stream.try_io(Interest::WRITABLE, || {
            let written = unsafe { libc::sendfile(output, input, &mut offset, count) };
            if written < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(written as usize)
            }
        });

        match result {
            Ok(0) => break,
            Ok(written) => remaining -= written as u64,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn send_file(
    _stream: &TcpStream,
    _file: std::fs::File,
    _offset: u64,
    _len: u64,
) -> io::Result<()> {
    Err(io::Error::other("sendfile is only implemented on Linux"))
}
