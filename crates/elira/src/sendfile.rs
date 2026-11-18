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

pub(crate) enum FastOutcome {
    Served,

    Fallback(PrefixedStream),
}

pub(crate) trait FastIo:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> FastIo for T {}

pub(crate) trait KtlsSend {
    fn ktls_sendfile(&mut self, file: &std::fs::File, len: u64) -> Option<std::io::Result<u64>>;
}

impl<S> KtlsSend for elira_tls::TlsStream<S> {
    fn ktls_sendfile(&mut self, file: &std::fs::File, len: u64) -> Option<std::io::Result<u64>> {
        #[cfg(target_os = "linux")]
        {
            elira_tls::TlsStream::<S>::ktls_sendfile(self, file, 0, len)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (file, len);
            None
        }
    }
}

pub(crate) struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    stream: Box<dyn FastIo>,
}

impl PrefixedStream {
    pub(crate) fn plain(stream: TcpStream) -> Self {
        Self::with_prefix(stream, Vec::new())
    }

    pub(crate) fn with_prefix(stream: impl FastIo + 'static, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            pos: 0,
            stream: Box::new(stream),
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
        std::pin::Pin::new(&mut *self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().stream).poll_shutdown(cx)
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_serve(
    mut stream: TcpStream,
    runtime: &ArcSwap<Runtime>,
    metrics: &Metrics,
    peer: SocketAddr,
    listener: &str,
    min_bytes: u64,
    compression_min_bytes: Option<u64>,
    idle: Option<Duration>,
    header_timeout: Option<Duration>,
    max_headers: usize,
    max_header_bytes: usize,
) -> FastOutcome {
    if !cfg!(target_os = "linux") {
        return FastOutcome::Fallback(PrefixedStream::plain(stream));
    }

    let max_head = max_header_bytes.clamp(8192, MAX_HEAD);
    let mut buf = Vec::with_capacity(PEEK);
    loop {
        let head_end = match read_head(&mut stream, &mut buf, idle, header_timeout, max_head).await
        {
            Ok(end) => end,
            Err(_) => return FastOutcome::Served,
        };
        let Some(parsed) = parse_head(&buf[..head_end], max_headers) else {
            return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        };
        let keepalive = parsed.keepalive;
        if parsed.has_body {
            return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
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
            let id = request_id();
            let outcome = current
                .proxy()
                .fast_proxy(
                    &mut stream,
                    elira_proxy::FastProxyRequest {
                        host: &parsed.host,
                        path: &parsed.path,
                        method: &parsed.method,
                        headers: &parsed.headers,
                        keepalive: parsed.keepalive,
                    },
                    peer,
                    listener,
                    "http",
                    &id,
                )
                .await;
            let result = match outcome {
                elira_proxy::FastProxyOutcome::Disabled => {
                    return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
                }
                elira_proxy::FastProxyOutcome::NotEligible(reason) => {
                    metrics.fast_proxy_fallback(reason.as_str());
                    return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
                }
                elira_proxy::FastProxyOutcome::Served(result) => {
                    metrics.fast_proxy_hit();
                    result
                }
            };
            buf.drain(..head_end);
            metrics.connection_started();
            metrics.record_route(&result.route, result.status, result.elapsed);
            metrics.record_upstream(&result.upstream, result.status, result.elapsed);
            let entry = Entry {
                peer: peer.ip(),
                method: Method::from_bytes(parsed.method.as_bytes()).unwrap_or(Method::GET),
                version: http::Version::HTTP_11,
                host: parsed.host,
                path: parsed.path,
                status: http::StatusCode::from_u16(result.status)
                    .unwrap_or(http::StatusCode::BAD_GATEWAY),
                bytes: if parsed.method == "HEAD" {
                    0
                } else {
                    result.bytes
                },
                duration: result.elapsed,
                user_agent: parsed.user_agent,
                request_id: id,
                upstream: Some(result.upstream),
                upstream_addr: Some(result.upstream_addr),
                upstream_status: Some(result.status),
                upstream_time: Some(result.elapsed),
                variables: std::collections::HashMap::new(),
            };
            metrics.observe(result.status, result.elapsed);
            metrics.connection_finished();
            if result.access_log
                && elira_accesslog::sampled(&entry.request_id, result.access_log_sample)
            {
                current.write_log(&entry);
            }
            if !result.keepalive {
                return FastOutcome::Served;
            }
            continue;
        };
        if !current.proxy().rate_allows(peer.ip()) {
            return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        }

        let file = fast.file;
        let meta = fast.meta;
        if !meta.is_file() {
            return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        }
        let content_type = crate::proxy::files::content_type(&file);
        let len = meta.len();
        if elira_proxy::compressible(content_type)
            && elira_proxy::preferred_encoding(&parsed.headers).is_some()
            && compression_min_bytes
                .map(|minimum| len >= minimum)
                .unwrap_or(false)
        {
            return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        }
        if let Some(encoding) = elira_proxy::preferred_encoding(&parsed.headers) {
            let sibling = std::path::PathBuf::from(format!("{}.{}", file.display(), encoding));
            if tokio::fs::metadata(&sibling)
                .await
                .map(|meta| meta.is_file())
                .unwrap_or(false)
            {
                return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
            }
        }

        let small = len < min_bytes;
        let cached = if small { fast.cached.clone() } else { None };
        if small && cached.is_none() {
            return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
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
                    None => return FastOutcome::Fallback(PrefixedStream::with_prefix(stream, buf)),
                },
                None => None,
            }
        };

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
        metrics.record_route(&fast.route, status.as_u16(), started.elapsed());
        metrics.record_route_bytes(
            &fast.route,
            head_end as u64,
            if parsed.method == "HEAD" || not_modified {
                0
            } else {
                body_len
            },
        );

        let mut headers: Vec<(String, String)> = vec![
            (
                "date".to_owned(),
                httpdate::fmt_http_date(std::time::SystemTime::now()),
            ),
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
        if let Some(name) = &fast.download {
            headers.retain(|(known, _)| {
                known != "content-disposition" && known != "content-security-policy"
            });
            headers.push((
                "content-disposition".to_owned(),
                format!("attachment; filename=\"{name}\""),
            ));
            headers.push(("content-security-policy".to_owned(), "sandbox".to_owned()));
        }

        let cached = if range.is_none() && !not_modified && parsed.method == "GET" {
            cached
        } else {
            None
        };
        if let Some(body) = &cached {
            if body.len() as u64 != body_len {
                metrics.connection_finished();
                return FastOutcome::Served;
            }
        }

        let mut response = Vec::with_capacity(512);
        response.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\n",
                status.as_u16(),
                status.canonical_reason().unwrap_or("")
            )
            .as_bytes(),
        );
        for (name, value) in &headers {
            response.extend_from_slice(name.as_bytes());
            response.extend_from_slice(b": ");
            response.extend_from_slice(value.as_bytes());
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(if keepalive {
            b"connection: keep-alive\r\n\r\n"
        } else {
            b"connection: close\r\n\r\n"
        });
        if let Some(body) = &cached {
            response.extend_from_slice(body);
        }
        if stream.write_all(&response).await.is_err() {
            metrics.connection_finished();
            return FastOutcome::Served;
        }

        if parsed.method == "GET" && !not_modified && body_len > 0 && cached.is_none() {
            if let Ok(file) =
                elira_proxy::files::open_beneath_dir(fast.root_dir.as_deref(), &fast.root, &file)
            {
                if send_file(&stream, file, offset, body_len).await.is_err() {
                    metrics.connection_finished();
                    return FastOutcome::Served;
                }
            } else {
                metrics.connection_finished();
                return FastOutcome::Served;
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

pub(crate) enum StaticOutcome {
    Served,
    Fallback(PrefixedStream),
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_static<S>(
    mut stream: S,
    runtime: &ArcSwap<Runtime>,
    metrics: &Metrics,
    peer: SocketAddr,
    listener: &str,
    idle: Option<Duration>,
    header_timeout: Option<Duration>,
    max_headers: usize,
    max_header_bytes: usize,
) -> StaticOutcome
where
    S: FastIo + KtlsSend + 'static,
{
    let max_head = max_header_bytes.clamp(8192, MAX_HEAD);
    let mut buf = Vec::with_capacity(PEEK);
    loop {
        let head_end = match read_head(&mut stream, &mut buf, idle, header_timeout, max_head).await
        {
            Ok(end) => end,
            Err(_) => return StaticOutcome::Served,
        };
        let Some(parsed) = parse_head(&buf[..head_end], max_headers) else {
            return StaticOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        };
        if parsed.has_body {
            return StaticOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
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
            return StaticOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        };
        if !current.proxy().rate_allows(peer.ip()) {
            return StaticOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        }
        if !fast.meta.is_file()
            || parsed.headers.contains_key(http::header::RANGE)
            || parsed.headers.contains_key(http::header::IF_NONE_MATCH)
            || parsed.headers.contains_key(http::header::IF_MODIFIED_SINCE)
        {
            return StaticOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        }
        let content_type = crate::proxy::files::content_type(&fast.file);
        if elira_proxy::compressible(content_type)
            && elira_proxy::preferred_encoding(&parsed.headers).is_some()
        {
            return StaticOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        }
        let len = fast.meta.len();
        let cached = fast.cached.clone().filter(|body| body.len() as u64 == len);
        let modified = fast.meta.modified().ok();
        let etag = crate::proxy::files::etag(len, modified);
        let id = request_id();
        let mut headers: Vec<(String, String)> = vec![
            (
                "date".to_owned(),
                httpdate::fmt_http_date(std::time::SystemTime::now()),
            ),
            ("content-type".to_owned(), content_type.to_owned()),
            ("accept-ranges".to_owned(), "bytes".to_owned()),
            ("etag".to_owned(), etag),
            ("x-content-type-options".to_owned(), "nosniff".to_owned()),
            ("x-request-id".to_owned(), id.clone()),
            ("content-length".to_owned(), len.to_string()),
        ];
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
        if let Some(name) = &fast.download {
            headers.retain(|(known, _)| {
                known != "content-disposition" && known != "content-security-policy"
            });
            headers.push((
                "content-disposition".to_owned(),
                format!("attachment; filename=\"{name}\""),
            ));
            headers.push(("content-security-policy".to_owned(), "sandbox".to_owned()));
        }

        let keepalive = parsed.keepalive;
        let started = std::time::Instant::now();
        metrics.connection_started();
        let mut response = Vec::with_capacity(512);
        response.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        for (name, value) in &headers {
            response.extend_from_slice(name.as_bytes());
            response.extend_from_slice(b": ");
            response.extend_from_slice(value.as_bytes());
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(if keepalive {
            b"connection: keep-alive\r\n\r\n"
        } else {
            b"connection: close\r\n\r\n"
        });
        if let Some(cached) = &cached {
            if parsed.method != "HEAD" {
                response.extend_from_slice(cached);
            }
            if stream.write_all(&response).await.is_err() {
                metrics.connection_finished();
                return StaticOutcome::Served;
            }
        } else {
            if stream.write_all(&response).await.is_err() {
                metrics.connection_finished();
                return StaticOutcome::Served;
            }
            if parsed.method != "HEAD" {
                let Some(mut file) = elira_proxy::files::open_beneath_dir(
                    fast.root_dir.as_deref(),
                    &fast.root,
                    &fast.file,
                )
                .ok() else {
                    metrics.connection_finished();
                    return StaticOutcome::Served;
                };
                let mut sent = 0u64;
                if let Some(Ok(written)) = stream.ktls_sendfile(&file, len) {
                    sent = written;
                }
                if sent < len {
                    use std::io::Seek;
                    if file.seek(std::io::SeekFrom::Start(sent)).is_err() {
                        metrics.connection_finished();
                        return StaticOutcome::Served;
                    }
                    let mut file = tokio::fs::File::from_std(file);
                    if tokio::io::copy(&mut file, &mut stream).await.is_err() {
                        metrics.connection_finished();
                        return StaticOutcome::Served;
                    }
                }
            }
        }
        metrics.record_route(&fast.route, 200, started.elapsed());
        metrics.record_route_bytes(
            &fast.route,
            head_end as u64,
            if parsed.method == "HEAD" { 0 } else { len },
        );
        let entry = Entry {
            peer: peer.ip(),
            method: Method::from_bytes(parsed.method.as_bytes()).unwrap_or(Method::GET),
            version: http::Version::HTTP_11,
            host: parsed.host,
            path: parsed.path,
            status: http::StatusCode::OK,
            bytes: if parsed.method == "HEAD" { 0 } else { len },
            duration: started.elapsed(),
            user_agent: parsed.user_agent,
            request_id: id,
            upstream: None,
            upstream_addr: None,
            upstream_status: None,
            upstream_time: None,
            variables: std::collections::HashMap::new(),
        };
        metrics.observe(200, started.elapsed());
        metrics.connection_finished();
        if fast.access_log && elira_accesslog::sampled(&entry.request_id, fast.access_log_sample) {
            current.write_log(&entry);
        }
        buf.drain(..head_end);
        if !keepalive {
            return StaticOutcome::Served;
        }
    }
}

pub(crate) enum ProxyOutcome {
    Served,
    Fallback(PrefixedStream),
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_proxy<S>(
    mut stream: S,
    runtime: &ArcSwap<Runtime>,
    metrics: &Metrics,
    peer: SocketAddr,
    listener: &str,
    scheme: &'static str,
    idle: Option<Duration>,
    header_timeout: Option<Duration>,
    max_headers: usize,
    max_header_bytes: usize,
) -> ProxyOutcome
where
    S: FastIo + 'static,
{
    let max_head = max_header_bytes.clamp(8192, MAX_HEAD);
    let mut buf = Vec::with_capacity(PEEK);
    loop {
        let head_end = match read_head(&mut stream, &mut buf, idle, header_timeout, max_head).await
        {
            Ok(end) => end,
            Err(_) => return ProxyOutcome::Served,
        };
        let Some(parsed) = parse_head(&buf[..head_end], max_headers) else {
            return ProxyOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        };
        if parsed.has_body || parsed.headers.contains_key(http::header::UPGRADE) {
            return ProxyOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        }
        let current = runtime.load_full();
        if !current.proxy().fast_proxy_enabled() {
            return ProxyOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
        }
        let id = request_id();
        let result = current
            .proxy()
            .fast_proxy(
                &mut stream,
                elira_proxy::FastProxyRequest {
                    host: &parsed.host,
                    path: &parsed.path,
                    method: &parsed.method,
                    headers: &parsed.headers,
                    keepalive: parsed.keepalive,
                },
                peer,
                listener,
                scheme,
                &id,
            )
            .await;
        let result = match result {
            elira_proxy::FastProxyOutcome::Disabled => {
                return ProxyOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
            }
            elira_proxy::FastProxyOutcome::NotEligible(reason) => {
                metrics.fast_proxy_fallback(reason.as_str());
                return ProxyOutcome::Fallback(PrefixedStream::with_prefix(stream, buf));
            }
            elira_proxy::FastProxyOutcome::Served(result) => {
                metrics.fast_proxy_hit();
                result
            }
        };
        buf.drain(..head_end);
        metrics.connection_started();
        metrics.record_route(&result.route, result.status, result.elapsed);
        metrics.record_upstream(&result.upstream, result.status, result.elapsed);
        let entry = Entry {
            peer: peer.ip(),
            method: Method::from_bytes(parsed.method.as_bytes()).unwrap_or(Method::GET),
            version: http::Version::HTTP_11,
            host: parsed.host,
            path: parsed.path,
            status: http::StatusCode::from_u16(result.status)
                .unwrap_or(http::StatusCode::BAD_GATEWAY),
            bytes: if parsed.method == "HEAD" {
                0
            } else {
                result.bytes
            },
            duration: result.elapsed,
            user_agent: parsed.user_agent,
            request_id: id,
            upstream: Some(result.upstream),
            upstream_addr: Some(result.upstream_addr),
            upstream_status: Some(result.status),
            upstream_time: Some(result.elapsed),
            variables: std::collections::HashMap::new(),
        };
        metrics.observe(result.status, result.elapsed);
        metrics.connection_finished();
        if result.access_log
            && elira_accesslog::sampled(&entry.request_id, result.access_log_sample)
        {
            current.write_log(&entry);
        }
        if !result.keepalive {
            return ProxyOutcome::Served;
        }
    }
}

async fn read_head<R>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    idle: Option<Duration>,
    header_timeout: Option<Duration>,
    max_head: usize,
) -> std::io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let deadline = header_timeout.map(|timeout| tokio::time::Instant::now() + timeout);
    loop {
        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            return Ok(pos + 4);
        }
        if buf.len() > max_head {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        let mut chunk = [0u8; 4096];
        let read = if let Some(deadline) = deadline {
            tokio::time::timeout_at(deadline, stream.read(&mut chunk))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "header timeout")
                })??
        } else {
            match idle {
                Some(timeout) => tokio::time::timeout(timeout, stream.read(&mut chunk))
                    .await
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "idle"))??,
                None => stream.read(&mut chunk).await?,
            }
        };
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

fn parse_head(head: &[u8], max_headers: usize) -> Option<Parsed> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut request = lines.next()?.split(' ');
    let method = request.next()?;
    let path = request.next()?;
    let version = request.next()?;
    if version != "HTTP/1.1" || (method != "GET" && method != "HEAD") || !path.starts_with('/') {
        return None;
    }

    let mut host = None;
    let mut user_agent = None;
    let mut headers = http::HeaderMap::new();
    let mut keepalive = true;
    let mut has_body = false;
    let mut seen_content_length = false;
    let mut header_count = 0usize;
    for line in lines {
        if line.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > max_headers {
            return None;
        }
        if line.starts_with([' ', '\t']) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || name.contains([' ', '\t']) {
            return None;
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        let header = http::header::HeaderName::from_bytes(name.as_bytes()).ok()?;
        let header_value = http::header::HeaderValue::from_str(value).ok()?;
        headers.append(header, header_value);
        match name.as_str() {
            "host" => {
                if host.is_some() {
                    return None;
                }
                host = Some(value.to_owned());
            }
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
                if seen_content_length {
                    return None;
                }
                seen_content_length = true;
                match value.parse::<u64>() {
                    Ok(length) => has_body = length > 0,
                    Err(_) => return None,
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
            // SAFETY: `output` and `input` are descriptors owned by `stream` and `file`
            // for the whole loop; `offset` points to a stack local and `count` is a bounded
            // chunk size. `sendfile` does not retain the pointer after returning.
            let written = unsafe { libc::sendfile(output, input, &mut offset, count) };
            if written < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(written as usize)
            }
        });

        match result {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
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

#[cfg(test)]
mod tests {
    use super::parse_head;

    #[test]
    fn fast_path_parses_origin_form_requests() {
        let parsed = parse_head(
            b"GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n",
            16,
        )
        .expect("parsed");
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/index.html?x=1");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.user_agent.as_deref(), Some("test"));
        assert!(parsed.keepalive);
        assert!(!parsed.has_body);
    }

    #[test]
    fn fast_path_rejects_ambiguous_framing_and_hosts() {
        let cases: &[&[u8]] = &[
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: nope\r\n\r\n",
            b"GET / HTTP/1.0\r\nHost: a\r\n\r\n",
        ];
        for head in cases {
            assert!(
                parse_head(head, 16).is_none(),
                "accepted {:?}",
                String::from_utf8_lossy(head)
            );
        }
        assert!(parse_head(b"GET / HTTP/1.1\r\nHost: a\r\nx-one: 1\r\n\r\n", 1).is_none());
    }
}
