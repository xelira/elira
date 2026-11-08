//! Zero-copy static responses.
//!
//! hyper owns the socket and only lets a body yield bytes, so `sendfile(2)`
//! cannot be reached from inside it. Instead the first request on a plain
//! HTTP/1.1 connection is peeked before hyper sees it: a simple GET or HEAD
//! for a file we know how to serve is answered here with `sendfile`, and
//! everything else is left in the socket for hyper. `peek` does not consume,
//! so falling back costs nothing.
//!
//! Range and conditional requests deliberately take the slow path: hyper
//! already implements them correctly, and duplicating that here would be a
//! second place to get them wrong.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use arc_swap::ArcSwap;
use http::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use elira_accesslog::{request_id, Entry};

use crate::config::LogFormat;
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
            // Let hyper answer the harder cases.
            "range" | "if-none-match" | "if-modified-since" | "upgrade" => return None,
            _ => {}
        }
    }

    let host = host?;
    let path_only = path.split('?').next().unwrap_or(path);

    let current = runtime.load_full();
    let file = current.proxy().static_file(&host, path_only).await?;
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

    // From here on the connection is ours: consume the header and answer.
    metrics.connection_started();
    let mut discard = vec![0u8; end];
    if stream.read_exact(&mut discard).await.is_err() {
        return Some(());
    }

    let len = meta.len();
    let modified = meta.modified().ok();
    let etag = crate::proxy::files::etag(len, modified);

    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {len}\r\n\
         etag: {etag}\r\n"
    );
    if let Some(modified) = modified {
        response.push_str(&format!(
            "last-modified: {}\r\n",
            httpdate::fmt_http_date(modified)
        ));
    }
    response.push_str("connection: close\r\n\r\n");

    if stream.write_all(response.as_bytes()).await.is_err() {
        return Some(());
    }

    if method == "GET" && len > 0 {
        let file = match std::fs::File::open(&file) {
            Ok(file) => file,
            Err(_) => return Some(()),
        };
        let _ = send_file(stream, file, len).await;
    }

    let entry = Entry {
        peer: peer.ip(),
        method: Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET),
        version: http::Version::HTTP_11,
        host,
        path: path.to_owned(),
        status: http::StatusCode::OK,
        bytes: if method == "HEAD" { 0 } else { len },
        duration: started.elapsed(),
        user_agent,
        request_id: request_id(),
    };

    metrics.observe(http::StatusCode::OK.as_u16(), started.elapsed());
    metrics.connection_finished();

    let line = match current.log() {
        LogFormat::Text => entry.line(),
        LogFormat::Json => entry.json(),
    };

    match current.access_log() {
        Some(log) => log.write(&line),
        None => tracing::info!(target: "access", "{}", line),
    }

    Some(())
}

#[cfg(target_os = "linux")]
async fn send_file(stream: &TcpStream, file: std::fs::File, len: u64) -> io::Result<()> {
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

    let mut offset: i64 = 0;
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
async fn send_file(_stream: &TcpStream, _file: std::fs::File, _len: u64) -> io::Result<()> {
    Err(io::Error::other("sendfile is only implemented on Linux"))
}
