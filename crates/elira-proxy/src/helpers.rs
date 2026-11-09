//! Small pure helpers shared by routing, forwarding and the raw upgrade path.
//!
//! These do not touch proxy state: header classification, authority parsing,
//! fixed responses and the few request/response adapters that would otherwise
//! sit in the middle of `lib.rs`.

use std::net::SocketAddr;
use std::sync::Arc;

use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::header::{
    HeaderName, HeaderValue, ACCEPT_ENCODING, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH,
    CONTENT_TYPE, SERVER, SET_COOKIE, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, StreamBody};
use tokio::io::BufReader;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::files::Files;
use crate::{Body, BoxError, ServerAddr};

pub(crate) fn serialize_head(req: &Request<Body>) -> String {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method(), path);
    for (name, value) in req.headers() {
        if let Ok(value) = value.to_str() {
            out.push_str(name.as_str());
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
    }
    out.push_str("\r\n");
    out
}

/// A request upgrades only when it carries both `Upgrade` and a
/// `Connection: upgrade` token.
pub(crate) fn wants_upgrade(headers: &HeaderMap) -> Option<HeaderValue> {
    let upgrade = headers.get(UPGRADE)?.clone();
    let connection = headers.get(CONNECTION)?.to_str().ok()?;
    connection
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        .then_some(upgrade)
}

pub fn preferred_encoding(headers: &HeaderMap) -> Option<&'static str> {
    let value = headers.get(ACCEPT_ENCODING)?.to_str().ok()?;

    let mut br = 0.0f32;
    let mut gzip = 0.0f32;

    for part in value.split(',') {
        let mut pieces = part.trim().split(';');
        let name = pieces.next().unwrap_or_default().trim();
        let quality = pieces
            .next()
            .and_then(|piece| piece.trim().strip_prefix("q="))
            .and_then(|value| value.parse::<f32>().ok())
            .unwrap_or(1.0);

        if name.eq_ignore_ascii_case("br") {
            br = quality;
        } else if name.eq_ignore_ascii_case("gzip") {
            gzip = quality;
        }
    }

    if br > 0.0 && br >= gzip {
        Some("br")
    } else if gzip > 0.0 {
        Some("gzip")
    } else {
        None
    }
}

pub fn compressible(content_type: &str) -> bool {
    let kind = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    kind.starts_with("text/")
        || matches!(
            kind.as_str(),
            "application/json"
                | "application/javascript"
                | "application/xml"
                | "application/rss+xml"
                | "application/atom+xml"
                | "image/svg+xml"
        )
}

pub(crate) fn compress(body: Body, encoding: &'static str) -> Body {
    fn finish<R>(reader: R) -> Body
    where
        R: tokio::io::AsyncRead + Send + Sync + 'static,
    {
        let stream = ReaderStream::new(reader).map_ok(hyper::body::Frame::data);
        BodyExt::map_err(StreamBody::new(stream), |err| -> BoxError { Box::new(err) }).boxed()
    }

    let stream = TryStreamExt::map_err(body.into_data_stream(), std::io::Error::other);
    let reader = StreamReader::new(stream);

    match encoding {
        "br" => finish(BrotliEncoder::new(BufReader::new(reader))),
        _ => finish(GzipEncoder::new(BufReader::new(reader))),
    }
}

pub(crate) fn cacheable_response(headers: &HeaderMap) -> bool {
    if headers.contains_key(SET_COOKIE) {
        return false;
    }

    match headers
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => {
            let value = value.to_ascii_lowercase();
            !value.contains("no-store") && !value.contains("private")
        }
        None => true,
    }
}

pub(crate) fn cache_response(entry: elira_cache::Entry) -> Response<Body> {
    let status = StatusCode::from_u16(entry.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = Response::builder().status(status);

    if let Some(headers) = builder.headers_mut() {
        for (name, value) in &entry.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.append(name, value);
            }
        }
    }

    let body = Full::new(Bytes::from(entry.body))
        .map_err(|never| match never {})
        .boxed();

    builder
        .body(body)
        .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
}

pub(crate) fn upstream_uri(server: &ServerAddr, path: &str, scheme: &'static str) -> Option<Uri> {
    let (scheme, authority) = match server {
        ServerAddr::Tcp(authority) => (scheme, authority.as_str()),
        // TLS over a unix socket is rejected by config validation.
        ServerAddr::Unix(_) => ("http", "localhost"),
    };
    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path)
        .build()
        .ok()
}

pub(crate) fn empty() -> Body {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

pub(crate) fn canonical_host(raw: &str) -> Option<(String, String)> {
    if raw.contains('@') {
        return None;
    }
    let (host, port) = split_host_port(raw)?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let forward = match port {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };
    Some((host, forward))
}

/// Split an authority without trusting `Authority` to reject bad ports.
/// `example.com:abc` parses there, and the backend would read it its own way.
pub(crate) fn split_host_port(raw: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            value => Some(value.strip_prefix(':')?.parse::<u16>().ok()?),
        };
        return Some((host, port));
    }

    match raw.rsplit_once(':') {
        None => Some((raw, None)),
        Some((host, port)) => {
            // A bare IPv6 literal has more than one colon. Demand brackets.
            if host.contains(':') || port.is_empty() {
                return None;
            }
            Some((host, Some(port.parse::<u16>().ok()?)))
        }
    }
}

pub(crate) fn transfer_encoding_is_plain_chunked(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(TRANSFER_ENCODING).iter();
    let Some(value) = values.next() else {
        return true;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(text) = value.to_str() else {
        return false;
    };
    let mut tokens = text.split(',').map(str::trim);
    matches!((tokens.next(), tokens.next()), (Some(token), None) if token.eq_ignore_ascii_case("chunked"))
}

pub(crate) fn connection_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

pub(crate) fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// `TE: trailers` is how gRPC asks for trailer frames; dropping it breaks
/// every gRPC upstream. Other TE values really are hop-by-hop.
pub(crate) fn hop_by_hop(name: &HeaderName, value: &HeaderValue) -> bool {
    if name.as_str() == "te" {
        return value
            .to_str()
            .map(|value| value.trim().eq_ignore_ascii_case("trailers"))
            .map(|trailers| !trailers)
            .unwrap_or(true);
    }
    is_hop_by_hop(name)
}

pub(crate) fn is_client_forwarding(name: &HeaderName) -> bool {
    // Underscore aliases reach the same backend functions as their dashed
    // form, so normalize before comparing.
    let normalized = name.as_str().replace('_', "-");
    let name = normalized.as_str();

    name == "forwarded"
        || name == "x-real-ip"
        || name.starts_with("x-forwarded-")
        || matches!(
            name,
            "x-original-url" | "x-rewrite-url" | "front-end-https" | "x-url-scheme"
        )
}

pub(crate) fn header(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).expect("peer address and Host are valid header values")
}

pub(crate) fn text(status: StatusCode, msg: &'static str) -> Response<Body> {
    let body = Full::new(Bytes::from_static(msg.as_bytes()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(body)
        .expect("static response parts are valid")
}

pub(crate) fn module_owner_allowed(owner: u32, server: u32) -> bool {
    owner == 0 || owner == server
}

pub(crate) fn validators_from_entry(entry: &elira_cache::Entry) -> HeaderMap {
    let mut validators = HeaderMap::new();
    for (name, value) in &entry.headers {
        let target = if name.eq_ignore_ascii_case("etag") {
            Some(http::header::IF_NONE_MATCH)
        } else if name.eq_ignore_ascii_case("last-modified") {
            Some(http::header::IF_MODIFIED_SINCE)
        } else {
            None
        };
        if let (Some(target), Ok(value)) = (target, HeaderValue::from_str(value)) {
            validators.insert(target, value);
        }
    }
    validators
}

pub(crate) fn headers_within_limits(
    headers: &HeaderMap,
    max_headers: usize,
    max_bytes: usize,
) -> bool {
    if headers.len() > max_headers {
        return false;
    }
    let bytes: usize = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
        .sum();
    bytes <= max_bytes
}

pub(crate) fn error_page_set(
    root: std::path::PathBuf,
    index: Vec<String>,
    pages: &[String],
) -> Vec<(StatusCode, String, Arc<Files>)> {
    if pages.is_empty() {
        return Vec::new();
    }
    let files = Arc::new(Files::new(
        root,
        None,
        index,
        false,
        Vec::new(),
        false,
        false,
        0,
        None,
        true,
    ));
    let mut out = Vec::new();
    for page in pages {
        let mut parts = page.splitn(2, char::is_whitespace);
        let status = parts.next().and_then(|s| s.parse::<u16>().ok());
        let path = parts.next().unwrap_or_default().trim();
        if let Some(status) = status.and_then(|s| StatusCode::from_u16(s).ok()) {
            out.push((status, path.to_owned(), files.clone()));
        }
    }
    out
}

pub(crate) fn parse_param(value: &str) -> Option<(String, String)> {
    let (name, value) = value.split_once(':')?;
    Some((name.trim().to_owned(), value.trim().to_owned()))
}

pub(crate) fn module_request(
    parts: &http::request::Parts,
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    body: &[u8],
    peer: SocketAddr,
) -> elira_module::Request {
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    elira_module::Request {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        host: host.to_owned(),
        headers,
        body: body.to_vec(),
        remote_addr: peer.to_string(),
    }
}

pub(crate) fn app_result(
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<Response<Body>, StatusCode> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).map_err(|_| StatusCode::BAD_GATEWAY)?);
    {
        let target = builder
            .headers_mut()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        for (name, value) in headers {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            if is_hop_by_hop(&name)
                || name == CONTENT_LENGTH
                || name == http::header::TRANSFER_ENCODING
            {
                continue;
            }
            if let Ok(value) = HeaderValue::from_str(&value) {
                target.append(name, value);
            }
        }
        target.insert(SERVER, HeaderValue::from_static("elira"));
    }
    let body = Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    builder
        .body(body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
