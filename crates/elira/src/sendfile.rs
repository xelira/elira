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

use arc_swap::ArcSwap;
use http::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use elira_accesslog::{request_id, Entry};

use crate::server::Runtime;
use elira_metrics::Metrics;

const PEEK: usize = 16 * 1024;

/// Returns `Some(())` when the request was answered here, `None` when it
/// should go to hyper. Bytes are only consumed once the response is decided.
pub(crate) async fn try_serve(
    stream: &mut TcpStream,
    runtime: &ArcSwap<Runtime>,
    metrics: &Metrics,
    peer: SocketAddr,
) -> Option<()> {
    if !cfg!(target_os = "linux") {
        return None;
    }

    let started = std::time::Instant::now();
    let mut buf = [0u8; PEEK];
    let read = stream.peek(&mut buf).await.ok()?;
    let head = &buf[..read];

    let end = head.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let text = std::str::from_utf8(&head[..end]).ok()?;

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
    let mut request_headers = http::HeaderMap::new();

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
            request_headers.append(header, header_value);
        }

        match name.as_str() {
            "host" => host = Some(value.to_owned()),
            "user-agent" => user_agent = Some(value.to_owned()),
            // Multi-range and upgrade need hyper.
            "upgrade" => return None,
            _ => {}
        }
    }

    let host = host?;
    let path_only = path.split('?').next().unwrap_or(path);

    let current = runtime.load_full();
    let fast = current
        .proxy()
        .fast_static(&host, path_only, peer.ip(), &request_headers)
        .await?;
    let file = fast.file;
    let meta = tokio::fs::metadata(&file).await.ok()?;
    if !meta.is_file() {
        return None;
    }

    let content_type = crate::proxy::files::content_type(&file);

    // Compressible files and precompressed siblings are served by the normal
    // path, which knows how to set Content-Encoding and Vary.
    if elira_proxy::compressible(content_type)
        && elira_proxy::preferred_encoding(&request_headers).is_some()
    {
        return None;
    }

    if let Some(encoding) = elira_proxy::preferred_encoding(&request_headers) {
        let sibling = std::path::PathBuf::from(format!("{}.{}", file.display(), encoding));
        if tokio::fs::metadata(&sibling)
            .await
            .map(|meta| meta.is_file())
            .unwrap_or(false)
        {
            return None;
        }
    }

    if !current.proxy().rate_allows(peer.ip()) {
        return None;
    }

    let len = meta.len();
    let modified = meta.modified().ok();
    let etag = crate::proxy::files::etag(len, modified);

    let not_modified = request_headers
        .get(http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(|value| etag_matches(value, &etag))
        .or_else(|| {
            request_headers
                .get(http::header::IF_MODIFIED_SINCE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| httpdate::parse_http_date(value).ok())
                .map(|since| modified.map(|modified| modified <= since).unwrap_or(false))
        })
        .unwrap_or(false);

    let range = if not_modified {
        None
    } else {
        match request_headers
            .get(http::header::RANGE)
            .and_then(|value| value.to_str().ok())
        {
            Some(value) => match parse_range(value, len) {
                Some(range) => Some(range),
                // Multiple ranges need a multipart body; let hyper do it.
                None => return None,
            },
            None => None,
        }
    };

    // From here on the connection is ours: consume the header and answer.
    metrics.connection_started();
    let mut discard = vec![0u8; end];
    if stream.read_exact(&mut discard).await.is_err() {
        return Some(());
    }

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
    if not_modified || range.is_some() {
        // A 304 has no body; a 206 still states the selected length.
    }
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
    response.push_str("connection: close\r\n\r\n");

    if stream.write_all(response.as_bytes()).await.is_err() {
        return Some(());
    }

    if method == "GET" && !not_modified && body_len > 0 {
        let file = match std::fs::File::open(&file) {
            Ok(file) => file,
            Err(_) => return Some(()),
        };
        let _ = send_file(stream, file, offset, body_len).await;
    }

    let entry = Entry {
        peer: peer.ip(),
        method: Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET),
        version: http::Version::HTTP_11,
        host,
        path: path.to_owned(),
        status,
        bytes: if method == "HEAD" || not_modified {
            0
        } else {
            body_len
        },
        duration: started.elapsed(),
        user_agent,
        request_id: id,
        upstream: None,
    };

    metrics.observe(status.as_u16(), started.elapsed());
    metrics.connection_finished();

    if fast.access_log {
        current.write_log(&entry);
    }

    Some(())
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
    // `AsyncFd` wants to own the descriptor. Duplicate it so the socket is
    // closed once, by the original `TcpStream`.
    let duplicate = unsafe { libc::dup(stream.as_raw_fd()) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `OwnedFd` owns a private duplicate and closes it on drop, so the
    // descriptor stays valid for as long as `AsyncFd` holds it.
    let async_fd = unsafe { tokio::io::unix::AsyncFd::register(OwnedFd(duplicate)) }
        .map_err(|err| io::Error::other(err.to_string()))?;

    let mut offset: i64 = offset as i64;
    let mut remaining = len;

    while remaining > 0 {
        let mut guard = async_fd.writable().await?;

        let result = guard.try_io(|inner| {
            let output = inner.get_ref().as_raw_fd();
            let count = remaining.min(1 << 20) as usize;
            let written = unsafe { libc::sendfile(output, input, &mut offset, count) };

            if written < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(written as usize)
            }
        });

        match result {
            Ok(Ok(0)) => break,
            Ok(Ok(written)) => remaining -= written as u64,
            Ok(Err(err)) => return Err(err),
            Err(_would_block) => continue,
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
struct OwnedFd(std::os::fd::RawFd);

#[cfg(target_os = "linux")]
impl AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

#[cfg(target_os = "linux")]
impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
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
