//! Static files.
//!
//! The rules that matter are the unglamorous ones: never let a request escape
//! the root, answer conditional requests so browsers stop re-downloading, and
//! honour a single byte range so video and resumable downloads work.

use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::header::{
    ACCEPT_RANGES, ALLOW, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
    IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, VARY,
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
    index: Vec<String>,
    spa: bool,
    try_files: Vec<String>,
    autoindex: bool,
}

impl Files {
    pub(crate) fn new(
        root: PathBuf,
        index: Vec<String>,
        spa: bool,
        try_files: Vec<String>,
        autoindex: bool,
    ) -> Self {
        Self {
            root,
            index,
            spa,
            try_files,
            autoindex,
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
        let etag = etag(len, modified);

        if not_modified(req, &etag, modified) {
            let mut response = Response::new(empty());
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            response.headers_mut().insert(
                ETAG,
                http::HeaderValue::from_str(&etag).expect("etag is ASCII"),
            );
            if let Some(modified) = modified {
                response.headers_mut().insert(
                    LAST_MODIFIED,
                    http::HeaderValue::from_str(&httpdate::fmt_http_date(modified))
                        .expect("http date is ASCII"),
                );
            }
            return response;
        }

        let range = req
            .headers()
            .get(http::header::RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| parse_range(value, len));

        let (status, start, end) = match range {
            Some(Ok(range)) => (StatusCode::PARTIAL_CONTENT, range.start, range.end),
            Some(Err(())) => {
                let mut response = text(StatusCode::RANGE_NOT_SATISFIABLE, "range not satisfiable");
                response.headers_mut().insert(
                    CONTENT_RANGE,
                    http::HeaderValue::from_str(&format!("bytes */{len}")).expect("ASCII"),
                );
                return response;
            }
            None => (StatusCode::OK, 0, len.saturating_sub(1)),
        };

        let length = if len == 0 { 0 } else { end - start + 1 };

        let mut builder = Response::builder()
            .status(status)
            .header(CONTENT_TYPE, content_type)
            .header(CONTENT_LENGTH, length)
            .header(ACCEPT_RANGES, "bytes")
            .header(ETAG, etag)
            .header("x-content-type-options", "nosniff");

        if let Some(modified) = modified {
            builder = builder.header(LAST_MODIFIED, httpdate::fmt_http_date(modified));
        }
        if status == StatusCode::PARTIAL_CONTENT {
            builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{len}"));
        }
        if let Some(encoding) = content_encoding {
            builder = builder
                .header(CONTENT_ENCODING, encoding)
                .header(VARY, "accept-encoding");
        }

        // A HEAD response carries the headers but no body, and hyper will not
        // send a body for it anyway.
        if req.method() == Method::HEAD || length == 0 {
            return builder.body(empty()).unwrap_or_else(|_| {
                text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
            });
        }

        let mut file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(_) => return text(StatusCode::NOT_FOUND, "not found"),
        };
        if start > 0 && file.seek(SeekFrom::Start(start)).await.is_err() {
            return text(StatusCode::INTERNAL_SERVER_ERROR, "cannot seek the file");
        }

        let stream = ReaderStream::new(file.take(length)).map_ok(Frame::data);
        let body =
            BodyExt::map_err(StreamBody::new(stream), |err| -> BoxError { Box::new(err) }).boxed();

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
    format!("W/\"{len:x}-{stamp:x}\"")
}

fn not_modified(
    req: &Request<BoxBody<Bytes, BoxError>>,
    etag: &str,
    modified: Option<SystemTime>,
) -> bool {
    if let Some(value) = req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
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

#[derive(Debug, PartialEq, Eq)]
struct ByteRange {
    start: u64,
    end: u64,
}

/// One range only. A multi-range request falls back to the whole file, which
/// is allowed and avoids generating a multipart body.
fn parse_range(value: &str, len: u64) -> Option<Result<ByteRange, ()>> {
    let list = value.strip_prefix("bytes=")?;
    if list.contains(',') {
        return None;
    }

    let (start, end) = list.split_once('-')?;
    let start = start.trim();
    let end = end.trim();

    if len == 0 {
        return Some(Err(()));
    }

    if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        if suffix == 0 {
            return Some(Err(()));
        }
        let start = len.saturating_sub(suffix);
        return Some(Ok(ByteRange {
            start,
            end: len - 1,
        }));
    }

    let start: u64 = start.parse().ok()?;
    if start >= len {
        return Some(Err(()));
    }

    let end = if end.is_empty() {
        len - 1
    } else {
        end.parse::<u64>().ok()?.min(len - 1)
    };

    if end < start {
        return Some(Err(()));
    }

    Some(Ok(ByteRange { start, end }))
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
    fn ranges_are_clamped_and_suffixes_work() {
        assert_eq!(
            parse_range("bytes=0-9", 100).map(|r| r.ok()),
            Some(Some(ByteRange { start: 0, end: 9 }))
        );
        assert_eq!(
            parse_range("bytes=90-", 100).map(|r| r.ok()),
            Some(Some(ByteRange { start: 90, end: 99 }))
        );
        assert_eq!(
            parse_range("bytes=-10", 100).map(|r| r.ok()),
            Some(Some(ByteRange { start: 90, end: 99 }))
        );
        assert!(matches!(parse_range("bytes=100-", 100), Some(Err(()))));
        assert!(parse_range("bytes=0-1,3-4", 100).is_none());
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
