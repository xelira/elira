//! Static files.
//!
//! The rules that matter are the unglamorous ones: never let a request escape
//! the root, answer conditional requests so browsers stop re-downloading, and
//! honour a single byte range so video and resumable downloads work.

use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::header::{
    ACCEPT_RANGES, ALLOW, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, ETAG, EXPIRES, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED, VARY,
};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use super::{text, BoxError};

pub(crate) struct Files {
    root: PathBuf,
    prefix: Option<String>,
    index: Vec<String>,
    spa: bool,
    try_files: Vec<String>,
    fallback_name: Option<String>,
    autoindex: bool,
    compress: bool,
    min_bytes: u64,
    expires: Option<u64>,
    etag: bool,
}

impl Files {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        root: PathBuf,
        prefix: Option<String>,
        index: Vec<String>,
        spa: bool,
        try_files: Vec<String>,
        autoindex: bool,
        compress: bool,
        min_bytes: usize,
        expires: Option<u64>,
        etag: bool,
    ) -> Self {
        let mut try_files = try_files;
        let fallback_name = if try_files.last().is_some_and(|name| name.starts_with('@')) {
            try_files.pop()
        } else {
            None
        };
        Self {
            root,
            prefix,
            index,
            spa,
            try_files,
            fallback_name,
            autoindex,
            compress,
            min_bytes: min_bytes as u64,
            expires,
            etag,
        }
    }

    pub(crate) async fn serve(
        &self,
        req: &Request<super::Body>,
        peer: SocketAddr,
    ) -> Response<super::Body> {
        let _ = peer;

        if req.method() != Method::GET && req.method() != Method::HEAD {
            let mut response = text(
                StatusCode::METHOD_NOT_ALLOWED,
                "only GET and HEAD are served here",
            );
            response
                .headers_mut()
                .insert(ALLOW, http::HeaderValue::from_static("GET, HEAD"));
            return response;
        }

        let decoded = match percent_encoding::percent_decode_str(req.uri().path()).decode_utf8() {
            Ok(decoded) => decoded.into_owned(),
            Err(_) => return text(StatusCode::BAD_REQUEST, "path is not valid UTF-8"),
        };
        let decoded = match &self.prefix {
            Some(prefix) => decoded.strip_prefix(prefix).unwrap_or(&decoded).to_owned(),
            None => decoded,
        };

        let mut relative = PathBuf::new();
        for segment in decoded.split('/') {
            match segment {
                "" | "." => continue,
                // Reject before touching the filesystem. `..` is the only
                // segment that can climb out of the root.
                ".." => return text(StatusCode::FORBIDDEN, "path traversal is not allowed"),
                segment if segment.contains('\0') || segment.contains('\\') => {
                    return text(StatusCode::BAD_REQUEST, "bad path")
                }
                segment => relative.push(segment),
            }
        }

        let root = match tokio::fs::canonicalize(&self.root).await {
            Ok(root) => root,
            Err(_) => return text(StatusCode::NOT_FOUND, "not found"),
        };

        let mut candidate = root.join(&relative);
        let mut meta = tokio::fs::metadata(&candidate).await.ok();

        if let Some(current) = &meta {
            if current.is_dir() {
                if !decoded.ends_with('/') {
                    return redirect(&decoded);
                }
                if let Some((path, index_meta)) = self.index_for(&candidate).await {
                    candidate = path;
                    meta = Some(index_meta);
                } else if self.autoindex {
                    return self.listing(&candidate, &decoded).await;
                } else {
                    meta = None;
                }
            }
        }

        if meta.is_none() {
            if let Some(path) = self.try_files(&root, &relative).await {
                candidate = path;
                meta = tokio::fs::metadata(&candidate).await.ok();
            }
        }

        let Some(meta) = meta else {
            if let Some(name) = &self.fallback_name {
                let mut response = text(StatusCode::NOT_FOUND, "internal redirect");
                response
                    .extensions_mut()
                    .insert(crate::InternalTarget(name.clone()));
                return response;
            }
            return self.fallback(&root, req).await;
        };

        let resolved = match tokio::fs::canonicalize(&candidate).await {
            Ok(resolved) => resolved,
            Err(_) => return text(StatusCode::NOT_FOUND, "not found"),
        };

        // Belt and braces against symlinks that point outside the root.
        if !resolved.starts_with(&root) {
            return text(StatusCode::FORBIDDEN, "path is outside the root");
        }

        self.send(req, &resolved, &meta).await
    }

    pub(crate) async fn resolve(&self, raw_path: &str) -> Option<PathBuf> {
        let decoded = percent_encoding::percent_decode_str(raw_path)
            .decode_utf8()
            .ok()?
            .into_owned();
        let decoded = match &self.prefix {
            Some(prefix) => decoded.strip_prefix(prefix).unwrap_or(&decoded).to_owned(),
            None => decoded,
        };

        let mut relative = PathBuf::new();
        for segment in decoded.split('/') {
            match segment {
                "" | "." => continue,
                ".." => return None,
                segment if segment.contains('\0') || segment.contains('\\') => return None,
                segment => relative.push(segment),
            }
        }

        let root = tokio::fs::canonicalize(&self.root).await.ok()?;
        let mut candidate = root.join(&relative);
        let mut meta = tokio::fs::metadata(&candidate).await.ok();

        if let Some(current) = &meta {
            if current.is_dir() {
                if !decoded.ends_with('/') {
                    return None;
                }
                match self.index_for(&candidate).await {
                    Some((path, index_meta)) => {
                        candidate = path;
                        meta = Some(index_meta);
                    }
                    None => return None,
                }
            }
        }

        if meta.is_none() {
            candidate = self.try_files(&root, &relative).await?;
            meta = tokio::fs::metadata(&candidate).await.ok();
        }

        meta?;
        let resolved = tokio::fs::canonicalize(&candidate).await.ok()?;
        if !resolved.starts_with(&root) {
            return None;
        }

        Some(resolved)
    }

    async fn index_for(&self, dir: &Path) -> Option<(PathBuf, std::fs::Metadata)> {
        for name in &self.index {
            let path = dir.join(name);
            if let Ok(meta) = tokio::fs::metadata(&path).await {
                if meta.is_file() {
                    return Some((path, meta));
                }
            }
        }
        None
    }

    async fn try_files(&self, root: &Path, relative: &Path) -> Option<PathBuf> {
        let uri = relative.to_string_lossy();

        for pattern in &self.try_files {
            let candidate = pattern.replace("$uri", &uri);
            let path = root.join(candidate.trim_start_matches('/'));
            if let Ok(meta) = tokio::fs::metadata(&path).await {
                if meta.is_file() {
                    return Some(path);
                }
            }
        }

        None
    }

    async fn listing(&self, dir: &Path, decoded: &str) -> Response<super::Body> {
        let mut entries = Vec::new();

        if let Ok(mut read) = tokio::fs::read_dir(dir).await {
            while let Ok(Some(entry)) = read.next_entry().await {
                let name = entry.file_name().to_string_lossy().to_string();
                let is_dir = entry
                    .file_type()
                    .await
                    .map(|kind| kind.is_dir())
                    .unwrap_or(false);
                entries.push((name, is_dir));
            }
        }

        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut html =
            String::from("<!doctype html><meta charset=\"utf-8\"><title>Index</title><ul>");
        if decoded != "/" {
            html.push_str("<li><a href=\"../\">../</a></li>");
        }
        for (name, is_dir) in entries {
            let suffix = if is_dir { "/" } else { "" };
            let escaped = escape_html(&name);
            html.push_str(&format!(
                "<li><a href=\"{escaped}{suffix}\">{escaped}{suffix}</a></li>"
            ));
        }
        html.push_str("</ul>");

        let body = http_body_util::Full::new(Bytes::from(html))
            .map_err(|never| match never {})
            .boxed();
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(http::header::CACHE_CONTROL, "no-store")
            .body(body)
            .expect("static response")
    }

    async fn fallback(&self, root: &Path, req: &Request<super::Body>) -> Response<super::Body> {
        if !self.spa {
            return text(StatusCode::NOT_FOUND, "not found");
        }

        let index = root.join(
            self.index
                .first()
                .map(String::as_str)
                .unwrap_or("index.html"),
        );
        let resolved = match tokio::fs::canonicalize(&index).await {
            Ok(resolved) => resolved,
            Err(_) => return text(StatusCode::NOT_FOUND, "not found"),
        };
        let meta = match tokio::fs::metadata(&resolved).await {
            Ok(meta) => meta,
            Err(_) => return text(StatusCode::NOT_FOUND, "not found"),
        };

        self.send(req, &resolved, &meta).await
    }

    async fn send(
        &self,
        req: &Request<super::Body>,
        path: &Path,
        meta: &std::fs::Metadata,
    ) -> Response<super::Body> {
        let content_type = content_type(path);

        // A precompressed sibling wins when the client accepts it. The
        // content type still comes from the original extension.
        let mut path = path.to_path_buf();
        let mut content_encoding = None;
        if let Some(encoding) = crate::preferred_encoding(req.headers()) {
            let candidate = PathBuf::from(format!("{}.{}", path.display(), encoding));
            if let Ok(meta) = tokio::fs::metadata(&candidate).await {
                if meta.is_file() {
                    path = candidate;
                    content_encoding = Some(encoding);
                }
            }
        }

        let meta = match tokio::fs::metadata(&path).await {
            Ok(meta) => meta,
            Err(_) => meta.clone(),
        };
        let path = path.as_path();
        let len = meta.len();
        let modified = meta.modified().ok();
        let etag_value = self.etag.then(|| etag(len, modified));
        let etag = etag_value.as_deref().unwrap_or_default();

        if not_modified(req, etag_value.as_deref(), modified) {
            let mut response = Response::new(empty());
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            if let Some(etag) = etag_value {
                response.headers_mut().insert(
                    ETAG,
                    http::HeaderValue::from_str(&etag).expect("etag is ASCII"),
                );
            }
            if let Some(modified) = modified {
                response.headers_mut().insert(
                    LAST_MODIFIED,
                    http::HeaderValue::from_str(&httpdate::fmt_http_date(modified))
                        .expect("http date is ASCII"),
                );
            }
            return response;
        }

        enum Selection {
            Full,
            Single(ByteRange),
            Multi(Vec<ByteRange>),
        }

        let range_allowed = match req
            .headers()
            .get(IF_RANGE)
            .and_then(|value| value.to_str().ok())
        {
            Some(condition) => if_range_matches(condition, etag, modified),
            None => true,
        };

        let selection = if !range_allowed {
            Selection::Full
        } else {
            match req
                .headers()
                .get(http::header::RANGE)
                .and_then(|value| value.to_str().ok())
            {
                Some(value) => match parse_ranges(value, len) {
                    Some(Ok(mut ranges)) if ranges.len() == 1 => {
                        Selection::Single(ranges.remove(0))
                    }
                    Some(Ok(ranges)) => Selection::Multi(ranges),
                    Some(Err(())) => {
                        let mut response =
                            text(StatusCode::RANGE_NOT_SATISFIABLE, "range not satisfiable");
                        response.headers_mut().insert(
                            CONTENT_RANGE,
                            http::HeaderValue::from_str(&format!("bytes */{len}")).expect("ASCII"),
                        );
                        return response;
                    }
                    None => Selection::Full,
                },
                None => Selection::Full,
            }
        };

        let status = match &selection {
            Selection::Full => StatusCode::OK,
            Selection::Single(_) | Selection::Multi(_) => StatusCode::PARTIAL_CONTENT,
        };
        let length = match &selection {
            Selection::Full => Some(len),
            Selection::Single(range) => Some(range.end - range.start + 1),
            Selection::Multi(_) => None,
        };
        let boundary = match &selection {
            Selection::Multi(_) => Some(multipart_boundary()),
            _ => None,
        };

        // Compress only the whole representation: a range is a byte range of
        // the identity body, and a precompressed sibling is already encoded.
        let compress_with = if self.compress
            && status == StatusCode::OK
            && req.method() != Method::HEAD
            && length.is_some_and(|length| length >= self.min_bytes)
            && content_encoding.is_none()
            && crate::compressible(content_type)
        {
            crate::preferred_encoding(req.headers())
        } else {
            None
        };

        let mut builder = Response::builder()
            .status(status)
            .header(ACCEPT_RANGES, "bytes")
            .header("x-content-type-options", "nosniff");
        if let Some(seconds) = self.expires {
            builder = builder
                .header(CACHE_CONTROL, format!("public, max-age={seconds}"))
                .header(
                    EXPIRES,
                    httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(seconds)),
                );
        }
        builder = match &boundary {
            Some(boundary) => builder.header(
                CONTENT_TYPE,
                format!("multipart/byteranges; boundary={boundary}"),
            ),
            None => builder.header(CONTENT_TYPE, content_type),
        };

        // A compressed body has no fixed length, and its ETag would belong to
        // a different representation, so both are dropped.
        if compress_with.is_none() {
            if let Some(length) = length {
                builder = builder.header(CONTENT_LENGTH, length);
            }
            if let Some(etag) = &etag_value {
                builder = builder.header(ETAG, etag);
            }
        }

        if let Some(modified) = modified {
            builder = builder.header(LAST_MODIFIED, httpdate::fmt_http_date(modified));
        }
        if let Selection::Single(range) = &selection {
            builder = builder.header(
                CONTENT_RANGE,
                format!("bytes {}-{}/{len}", range.start, range.end),
            );
        }
        if let Some(encoding) = content_encoding.or(compress_with) {
            builder = builder
                .header(CONTENT_ENCODING, encoding)
                .header(VARY, "accept-encoding");
        }

        // A HEAD response carries the headers but no body, and hyper will not
        // send a body for it anyway.
        if req.method() == Method::HEAD || length.is_some_and(|length| length == 0) {
            return builder.body(empty()).unwrap_or_else(|_| {
                text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
            });
        }

        let mut file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(_) => return text(StatusCode::NOT_FOUND, "not found"),
        };

        let body = match selection {
            Selection::Full => {
                let stream = ReaderStream::new(file.take(len)).map_ok(Frame::data);
                BodyExt::map_err(StreamBody::new(stream), |err| -> BoxError { Box::new(err) })
                    .boxed()
            }
            Selection::Single(range) => {
                if range.start > 0 && file.seek(SeekFrom::Start(range.start)).await.is_err() {
                    return text(StatusCode::INTERNAL_SERVER_ERROR, "cannot seek the file");
                }
                let stream =
                    ReaderStream::new(file.take(range.end - range.start + 1)).map_ok(Frame::data);
                BodyExt::map_err(StreamBody::new(stream), |err| -> BoxError { Box::new(err) })
                    .boxed()
            }
            Selection::Multi(ranges) => multipart_body(
                file,
                ranges,
                len,
                content_type,
                boundary.expect("multi-range selection has a boundary"),
            ),
        };
        let body = if let Some(encoding) = compress_with {
            crate::compress(body, encoding)
        } else {
            body
        };

        builder
            .body(body)
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }
}

fn empty() -> BoxBody<Bytes, BoxError> {
    http_body_util::Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

fn redirect(path: &str) -> Response<BoxBody<Bytes, BoxError>> {
    let location = format!("{path}/");
    let mut response = text(StatusCode::MOVED_PERMANENTLY, "moved");
    response.headers_mut().insert(
        http::header::LOCATION,
        http::HeaderValue::from_str(&location).expect("path came from a parsed URI"),
    );
    response
}

pub fn etag(len: u64, modified: Option<SystemTime>) -> String {
    let stamp = modified
        .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("\"{len:x}-{stamp:x}\"")
}

/// RFC 7233 If-Range: a strong entity tag or an exact Last-Modified date.
/// Weak tags never match, since a weak validator cannot prove that the
/// selected bytes are still the same representation.
fn if_range_matches(condition: &str, etag: &str, modified: Option<SystemTime>) -> bool {
    let condition = condition.trim();
    if condition.starts_with('"') {
        return condition == etag;
    }
    if condition.starts_with("W/") {
        return false;
    }
    match modified {
        Some(modified) => httpdate::fmt_http_date(modified) == condition,
        None => false,
    }
}

fn not_modified(
    req: &Request<BoxBody<Bytes, BoxError>>,
    etag: Option<&str>,
    modified: Option<SystemTime>,
) -> bool {
    if let (Some(etag), Some(value)) = (
        etag,
        req.headers()
            .get(IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok()),
    ) {
        return value.trim() == "*" || value.split(',').any(|tag| tag.trim() == etag);
    }

    if let (Some(value), Some(modified)) = (
        req.headers()
            .get(IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok()),
        modified,
    ) {
        if let Ok(since) = httpdate::parse_http_date(value) {
            // HTTP dates have one-second resolution.
            return modified <= since + Duration::from_secs(1);
        }
    }

    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ByteRange {
    start: u64,
    end: u64,
}

/// Maximum ranges honoured in one request. Beyond this the request is
/// rejected rather than turning one request into thousands of file seeks.
const MAX_RANGES: usize = 64;

/// Parse a `Range` header. `None` means "ignore the header and send the whole
/// file"; `Some(Err(()))` means no requested range is satisfiable.
fn parse_ranges(value: &str, len: u64) -> Option<Result<Vec<ByteRange>, ()>> {
    let list = value.strip_prefix("bytes=")?;
    if len == 0 {
        return Some(Err(()));
    }

    let mut ranges = Vec::new();
    for item in list.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if let Some(range) = parse_one_range(item, len) {
            ranges.push(range);
            if ranges.len() > MAX_RANGES {
                return Some(Err(()));
            }
        }
    }

    if ranges.is_empty() {
        return Some(Err(()));
    }

    // Coalesce touching or overlapping ranges so the multipart body does not
    // repeat bytes and `0-4,3-9` becomes a single range.
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<ByteRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(last) = merged.last_mut() {
            if range.start <= last.end.saturating_add(1) {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        merged.push(range);
    }
    Some(Ok(merged))
}

fn parse_one_range(value: &str, len: u64) -> Option<ByteRange> {
    let (start, end) = value.split_once('-')?;
    let start = start.trim();
    let end = end.trim();

    if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        if suffix == 0 {
            return None;
        }
        return Some(ByteRange {
            start: len.saturating_sub(suffix),
            end: len - 1,
        });
    }

    let start: u64 = start.parse().ok()?;
    if start >= len {
        return None;
    }

    let end = if end.is_empty() {
        len - 1
    } else {
        end.parse::<u64>().ok()?.min(len - 1)
    };

    if end < start {
        return None;
    }

    Some(ByteRange { start, end })
}

fn multipart_boundary() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("elira-{nanos:x}-{:x}", NEXT.fetch_add(1, Ordering::Relaxed))
}

fn multipart_body(
    file: tokio::fs::File,
    ranges: Vec<ByteRange>,
    total: u64,
    content_type: &'static str,
    boundary: String,
) -> super::Body {
    struct State {
        file: tokio::fs::File,
        ranges: Vec<ByteRange>,
        total: u64,
        content_type: &'static str,
        boundary: String,
        index: usize,
        remaining: u64,
        header_pending: bool,
        tail_sent: bool,
    }

    async fn step(mut state: State) -> std::io::Result<Option<(Frame<Bytes>, State)>> {
        loop {
            if state.header_pending {
                state.header_pending = false;
                let range = state.ranges[state.index];
                state.remaining = range.end - range.start + 1;
                state.file.seek(SeekFrom::Start(range.start)).await?;
                let header = format!(
                    "--{}\r\nContent-Type: {}\r\nContent-Range: bytes {}-{}/{}\r\n\r\n",
                    state.boundary, state.content_type, range.start, range.end, state.total
                );
                return Ok(Some((Frame::data(Bytes::from(header)), state)));
            }

            if state.remaining > 0 {
                let take = state.remaining.min(64 * 1024);
                let mut buffer = vec![0u8; take as usize];
                state.file.read_exact(&mut buffer).await?;
                state.remaining -= take;
                return Ok(Some((Frame::data(Bytes::from(buffer)), state)));
            }

            if state.index + 1 < state.ranges.len() {
                state.index += 1;
                state.header_pending = true;
                continue;
            }

            if !state.tail_sent {
                state.tail_sent = true;
                let tail = format!("--{}--\r\n", state.boundary);
                return Ok(Some((Frame::data(Bytes::from(tail)), state)));
            }

            return Ok(None);
        }
    }

    let state = State {
        file,
        ranges,
        total,
        content_type,
        boundary,
        index: 0,
        remaining: 0,
        header_pending: true,
        tail_sent: false,
    };

    let stream = futures_util::stream::try_unfold(state, step);
    BodyExt::map_err(StreamBody::new(stream), |err| -> BoxError { Box::new(err) }).boxed()
}

fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());

    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            ch => out.push(ch),
        }
    }

    out
}

pub fn content_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();

    match extension.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_clamped_merged_and_capped() {
        assert_eq!(
            parse_ranges("bytes=0-9", 100).map(|r| r.ok()),
            Some(Some(vec![ByteRange { start: 0, end: 9 }]))
        );
        assert_eq!(
            parse_ranges("bytes=90-", 100).map(|r| r.ok()),
            Some(Some(vec![ByteRange { start: 90, end: 99 }]))
        );
        assert_eq!(
            parse_ranges("bytes=-10", 100).map(|r| r.ok()),
            Some(Some(vec![ByteRange { start: 90, end: 99 }]))
        );
        assert_eq!(
            parse_ranges("bytes=0-1,3-4", 100).map(|r| r.ok()),
            Some(Some(vec![
                ByteRange { start: 0, end: 1 },
                ByteRange { start: 3, end: 4 }
            ]))
        );
        assert_eq!(
            parse_ranges("bytes=0-4,3-9", 100).map(|r| r.ok()),
            Some(Some(vec![ByteRange { start: 0, end: 9 }]))
        );
        assert_eq!(
            parse_ranges("bytes=abc,0-2", 100).map(|r| r.ok()),
            Some(Some(vec![ByteRange { start: 0, end: 2 }]))
        );
        assert!(matches!(parse_ranges("bytes=100-", 100), Some(Err(()))));
        assert!(matches!(parse_ranges("bytes=abc", 100), Some(Err(()))));
        assert!(parse_ranges("items=0-9", 100).is_none());

        let many = (0..65)
            .map(|index| format!("{index}-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(matches!(
            parse_ranges(&format!("bytes={many}"), 1000),
            Some(Err(()))
        ));
    }

    #[test]
    fn if_range_requires_a_strong_match() {
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let tag = etag(10, Some(modified));
        assert!(!tag.starts_with("W/"));
        assert!(if_range_matches(&tag, &tag, Some(modified)));
        assert!(if_range_matches(
            &httpdate::fmt_http_date(modified),
            &tag,
            Some(modified)
        ));
        assert!(!if_range_matches("W/\"weak\"", &tag, Some(modified)));
        assert!(!if_range_matches("\"other\"", &tag, Some(modified)));
        assert!(!if_range_matches("\"other\"", &tag, None));
    }

    #[test]
    fn content_type_follows_the_extension() {
        assert_eq!(
            content_type(Path::new("a.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(content_type(Path::new("a.WASM")), "application/wasm");
        assert_eq!(content_type(Path::new("a.bin")), "application/octet-stream");
    }
}
