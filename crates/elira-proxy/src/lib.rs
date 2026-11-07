//! Request forwarding.
//!
//! The rules that matter here are the boring ones: never trust forwarding
//! headers from the client, never forward hop-by-hop headers, and pick an
//! upstream before touching the body.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    HeaderName, HeaderValue, CACHE_CONTROL, CONNECTION, CONTENT_TYPE, HOST, SERVER,
    TRANSFER_ENCODING,
};
use http::uri::Authority;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use elira_config::Config;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;

#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

struct Inner {
    router: Router,
    client: Client<HttpConnector, Incoming>,
    timeout: Duration,
}

struct Router {
    by_host: HashMap<String, Arc<Pool>>,
    default: Option<Arc<Pool>>,
}

struct Pool {
    servers: Vec<Authority>,
    next: AtomicUsize,
}

impl Pool {
    fn pick(&self) -> &Authority {
        let i = self.next.fetch_add(1, Ordering::Relaxed);
        &self.servers[i % self.servers.len()]
    }
}

impl Router {
    fn pick(&self, host: &str) -> Option<&Arc<Pool>> {
        self.by_host.get(host).or(self.default.as_ref())
    }
}

impl Proxy {
    pub fn new(cfg: &Config) -> Result<Self, Error> {
        let mut pools: HashMap<String, Arc<Pool>> = HashMap::new();
        for up in &cfg.upstreams {
            let mut servers = Vec::with_capacity(up.servers.len());
            for addr in &up.servers {
                let authority = addr.parse::<Authority>().map_err(|_| Error::BadServer {
                    upstream: up.name.clone(),
                    addr: addr.clone(),
                })?;
                servers.push(authority);
            }
            pools.insert(
                up.name.clone(),
                Arc::new(Pool {
                    servers,
                    next: AtomicUsize::new(0),
                }),
            );
        }

        let mut by_host = HashMap::new();
        let mut default = None;
        for route in &cfg.routes {
            let pool =
                pools
                    .get(&route.upstream)
                    .cloned()
                    .ok_or_else(|| Error::UnknownUpstream {
                        upstream: route.upstream.clone(),
                    })?;
            let host = route.host.trim().to_ascii_lowercase();
            if host == "*" {
                default = Some(pool);
            } else {
                by_host.insert(host, pool);
            }
        }

        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(5)));
        connector.set_nodelay(true);
        connector.enforce_http(true);

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Some(Duration::from_secs(30)))
            .build(connector);

        Ok(Self {
            inner: Arc::new(Inner {
                router: Router { by_host, default },
                client,
                timeout: Duration::from_secs(cfg.limits.upstream_timeout_secs),
            }),
        })
    }

    pub async fn handle(&self, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
        self.forward(req, peer).await.unwrap_or_else(|err| err)
    }

    async fn forward(
        &self,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<Response<Body>, Response<Body>> {
        if req.method() == Method::CONNECT {
            return Err(text(
                StatusCode::METHOD_NOT_ALLOWED,
                "CONNECT is not supported",
            ));
        }
        // No upgrade path yet: passing Upgrade through would orphan the
        // connection on the client side.
        if req.headers().contains_key(http::header::UPGRADE) {
            return Err(text(
                StatusCode::NOT_IMPLEMENTED,
                "upgrade is not supported",
            ));
        }
        // hyper decodes only the chunked layer. `gzip, chunked` would reach
        // the backend still gzipped and without the header saying so.
        if !transfer_encoding_is_plain_chunked(req.headers()) {
            return Err(text(
                StatusCode::NOT_IMPLEMENTED,
                "only chunked transfer encoding is supported",
            ));
        }

        let host = req
            .headers()
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
            // HTTP/2 carries the host in :authority, not in a Host header.
            .or_else(|| req.uri().authority().map(|a| a.as_str().to_owned()))
            .ok_or_else(|| text(StatusCode::BAD_REQUEST, "missing Host header"))?;

        // Route on the canonical host and forward the same string. Letting
        // `admin:80@example.com` route as example.com while the backend sees
        // the raw value is a vhost-confusion bug waiting to happen.
        let (key, forward_host) = canonical_host(&host)
            .ok_or_else(|| text(StatusCode::BAD_REQUEST, "malformed Host header"))?;

        let pool = self
            .inner
            .router
            .pick(&key)
            .ok_or_else(|| text(StatusCode::NOT_FOUND, "no route"))?;
        let server = pool.pick().clone();

        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");

        let uri = Uri::builder()
            .scheme("http")
            .authority(server.as_str())
            .path_and_query(path)
            .build()
            .map_err(|_| text(StatusCode::BAD_GATEWAY, "bad upstream address"))?;

        let (parts, body) = req.into_parts();
        let mut upstream = Request::builder()
            .method(parts.method)
            .uri(uri)
            .body(body)
            .map_err(|_| text(StatusCode::BAD_GATEWAY, "bad request"))?;

        let drop = connection_tokens(&parts.headers);
        let headers = upstream.headers_mut();
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name) || drop.contains(name) || is_client_forwarding(name) {
                continue;
            }
            headers.append(name, value.clone());
        }

        // Everything below is set by us. A client that sent its own copies
        // had them dropped above.
        headers.insert(HOST, header(&forward_host));
        headers.insert("x-forwarded-for", header(&peer.ip().to_string()));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        headers.insert("x-forwarded-host", header(&forward_host));
        headers.insert("via", HeaderValue::from_static("1.1 elira"));

        let response =
            match tokio::time::timeout(self.inner.timeout, self.inner.client.request(upstream))
                .await
            {
                Ok(Ok(response)) => response,
                Ok(Err(err)) => {
                    tracing::warn!(upstream = %server, error = %err, "upstream request failed");
                    return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                }
                Err(_) => {
                    tracing::warn!(upstream = %server, "upstream timed out");
                    return Err(text(StatusCode::GATEWAY_TIMEOUT, "gateway timeout"));
                }
            };

        let (parts, body) = response.into_parts();
        let drop = connection_tokens(&parts.headers);
        let mut builder = Response::builder().status(parts.status);
        {
            let headers = builder
                .headers_mut()
                .ok_or_else(|| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))?;
            for (name, value) in parts.headers.iter() {
                // Let hyper derive the downstream framing from the body.
                // Copying Content-Length while the body is chunked lets a
                // broken upstream truncate the response silently.
                if is_hop_by_hop(name)
                    || drop.contains(name)
                    || name == http::header::CONTENT_LENGTH
                {
                    continue;
                }
                headers.append(name, value.clone());
            }
            headers.insert(SERVER, HeaderValue::from_static("elira"));
        }

        let body = body.map_err(|err| -> BoxError { Box::new(err) }).boxed();

        builder
            .body(body)
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }
}

fn canonical_host(raw: &str) -> Option<(String, String)> {
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
fn split_host_port(raw: &str) -> Option<(&str, Option<u16>)> {
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

fn transfer_encoding_is_plain_chunked(headers: &HeaderMap) -> bool {
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

fn connection_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
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

fn is_client_forwarding(name: &HeaderName) -> bool {
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

fn header(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).expect("peer address and Host are valid header values")
}

fn text(status: StatusCode, msg: &'static str) -> Response<Body> {
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("upstream \"{upstream}\": \"{addr}\" is not a valid address")]
    BadServer { upstream: String, addr: String },

    #[error("route points to unknown upstream \"{upstream}\"")]
    UnknownUpstream { upstream: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_host_ignores_port_and_case() {
        assert_eq!(
            canonical_host("Example.COM:8080").map(|h| h.0).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            canonical_host("example.com.").map(|h| h.0).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn canonical_host_rejects_userinfo_and_bad_port() {
        assert!(canonical_host("admin:80@example.com").is_none());
        assert!(canonical_host("example.com:abc").is_none());
        assert!(canonical_host("::1").is_none());
    }

    #[test]
    fn canonical_host_keeps_bracketed_ipv6() {
        assert_eq!(
            canonical_host("[::1]:8080").map(|h| h.1),
            Some("[::1]:8080".to_owned())
        );
    }

    #[test]
    fn hop_by_hop_headers_are_recognised() {
        assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
        assert!(is_hop_by_hop(&HeaderName::from_static("connection")));
        assert!(is_hop_by_hop(&HeaderName::from_static("proxy-connection")));
        assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
    }

    #[test]
    fn forwarding_headers_are_recognised() {
        assert!(is_client_forwarding(&HeaderName::from_static(
            "x-forwarded-for"
        )));
        assert!(is_client_forwarding(&HeaderName::from_static(
            "x-forwarded-ssl"
        )));
        assert!(is_client_forwarding(&HeaderName::from_static("x-real-ip")));
        assert!(is_client_forwarding(&HeaderName::from_static(
            "x_forwarded_for"
        )));
        assert!(!is_client_forwarding(&HeaderName::from_static("host")));
    }

    #[test]
    fn only_plain_chunked_is_accepted() {
        let mut headers = HeaderMap::new();
        assert!(transfer_encoding_is_plain_chunked(&headers));

        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert!(transfer_encoding_is_plain_chunked(&headers));

        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));
        assert!(!transfer_encoding_is_plain_chunked(&headers));
    }
}
