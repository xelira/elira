//! Response finalisation: route headers, fixed returns and error pages.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ALT_SVC, CONTENT_LENGTH, CONTENT_TYPE, SERVER, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};

use elira_cache::Cache;

use crate::*;

impl Proxy {
    /// Replace a configured error response with a file from the route root.
    /// The original status is kept even if the file itself would be a 200.
    pub(crate) async fn apply_error_page(
        &self,
        response: &mut Response<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
    ) {
        self.apply_page(response, Some(entry), Some(vars), peer)
            .await;
    }

    pub(crate) async fn apply_global_error_page(
        &self,
        response: &mut Response<Body>,
        peer: SocketAddr,
    ) {
        self.apply_page(response, None, None, peer).await;
    }

    pub(crate) async fn body_too_large(
        &self,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
    ) -> Response<Body> {
        let mut response = text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        self.apply_error_page(&mut response, entry, vars, peer)
            .await;
        response
    }

    pub(crate) async fn apply_page(
        &self,
        response: &mut Response<Body>,
        entry: Option<&RouteEntry>,
        vars: Option<&RequestVars>,
        peer: SocketAddr,
    ) {
        if response.extensions().get::<ErrorPageApplied>().is_some() {
            return;
        }
        let status = response.status();
        let page = entry
            .and_then(|entry| entry.error_pages.iter().find(|page| page.status == status))
            .or_else(|| {
                self.inner
                    .error_pages
                    .iter()
                    .find(|page| page.status == status)
            });
        let Some(page) = page else {
            return;
        };
        let path = match vars {
            Some(vars) => vars.render(&page.path),
            None => page.path.clone(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(empty());
        let Ok(request) = request else {
            return;
        };

        let mut page_response = page.files.serve(&request, peer).await;
        if let Some(override_status) = page.override_status {
            *page_response.status_mut() = override_status;
        } else if page_response.status().is_success() {
            *page_response.status_mut() = status;
        }
        // These describe the error itself, not the page body.
        for name in [
            WWW_AUTHENTICATE,
            http::header::RETRY_AFTER,
            http::header::ALLOW,
        ] {
            if let Some(value) = response.headers().get(&name) {
                page_response.headers_mut().insert(name, value.clone());
            }
        }
        page_response.extensions_mut().insert(ErrorPageApplied);
        *response = page_response;
    }

    pub(crate) fn fixed_response(
        &self,
        status: StatusCode,
        body: &str,
        content_type: Option<&str>,
        vars: &RequestVars,
        entry: &RouteEntry,
        request_id: &str,
    ) -> Response<Body> {
        let rendered = vars.render(body);
        let has_body = !rendered.is_empty()
            && status != StatusCode::NO_CONTENT
            && status != StatusCode::NOT_MODIFIED;
        let body = if has_body {
            Full::new(Bytes::from(rendered))
                .map_err(|never| match never {})
                .boxed()
        } else {
            empty()
        };
        let mut response = match Response::builder().status(status).body(body) {
            Ok(response) => response,
            Err(_) => return text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"),
        };
        if has_body {
            let value = content_type
                .map(|value| vars.render(value))
                .unwrap_or_else(|| "text/plain; charset=utf-8".to_owned());
            if let Ok(value) = HeaderValue::from_str(&value) {
                response.headers_mut().insert(CONTENT_TYPE, value);
            }
        }
        response.extensions_mut().insert(Labels {
            route: entry.label.clone(),
            upstream: None,
            access_log: entry.access_log,
            access_log_sample: entry.access_log_sample,
        });
        self.apply_route(&mut response, entry, vars, request_id);
        response
    }

    pub(crate) fn apply_route(
        &self,
        response: &mut Response<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        request_id: &str,
    ) {
        let headers = response.headers_mut();

        for name in &entry.remove_headers {
            headers.remove(name);
        }
        for (name, value) in &entry.add_headers {
            if let Ok(value) = HeaderValue::from_str(&vars.render(value)) {
                headers.insert(name.clone(), value);
            }
        }

        if !headers.contains_key("x-request-id") {
            if let Ok(value) = HeaderValue::from_str(request_id) {
                headers.insert("x-request-id", value);
            }
        }
        if !self.inner.server_header {
            headers.remove(SERVER);
        }
        if let Some(alt) = &self.inner.alt_svc {
            headers.insert(ALT_SVC, alt.clone());
        }
    }

    /// Fetch a fresh copy in the background after serving a stale entry.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn refresh(
        &self,
        cache: Arc<Cache>,
        key: String,
        headers: HeaderMap,
        request_headers: HeaderMap,
        validators: HeaderMap,
        path: String,
        pool: Arc<Pool>,
        timeout: Duration,
        connect_timeout: Duration,
        cache_ttl: Option<Duration>,
    ) {
        {
            let mut refreshing = self
                .inner
                .refreshing
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !refreshing.insert(key.clone()) {
                return;
            }
        }

        let inflight = self.inner.refreshing.clone();
        let max_item = self.inner.cache_max_item;
        tokio::spawn(async move {
            let index = pool.pick();
            let server = pool.servers[index].clone();
            let _active = pool.enter(index);
            let uri = match upstream_uri(&server, &path, pool.scheme) {
                Some(uri) => uri,
                None => {
                    inflight
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&key);
                    return;
                }
            };

            let fetched = async {
                let mut request = Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(empty())
                    .ok()?;
                *request.headers_mut() = headers;
                // Ask the upstream to confirm the stored representation.
                for (name, value) in &validators {
                    request.headers_mut().insert(name, value.clone());
                }
                let response = send_request(&pool, &server, request, timeout, connect_timeout)
                    .await
                    .ok()?;
                if response.status() == StatusCode::NOT_MODIFIED {
                    return Some((StatusCode::NOT_MODIFIED, HeaderMap::new(), Bytes::new()));
                }
                if response.status() != StatusCode::OK {
                    return None;
                }
                let length = response
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok())?;
                if length > max_item {
                    return None;
                }
                let response_headers = response.headers().clone();
                let body = BodyExt::collect(response.into_body())
                    .await
                    .ok()?
                    .to_bytes();
                Some((StatusCode::OK, response_headers, body))
            }
            .await;

            match fetched {
                Some((StatusCode::NOT_MODIFIED, _, _)) => {
                    cache.revalidate(&key, &request_headers, Instant::now());
                }
                Some((_, response_headers, body)) => {
                    cache.insert_with_ttl(
                        &key,
                        &request_headers,
                        &response_headers,
                        StatusCode::OK.as_u16(),
                        body.to_vec(),
                        Instant::now(),
                        cache_ttl,
                    );
                }
                None => {}
            }

            inflight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&key);
        });
    }

    /// Serve a file named by an upstream `X-Sendfile` header, restricted to
    /// the route's `x_sendfile_root`.
    pub(crate) async fn sendfile_response(
        &self,
        raw_path: &str,
        root: &Path,
        entry: &RouteEntry,
        request_headers: &HeaderMap,
        peer: SocketAddr,
    ) -> Response<Body> {
        let path = Path::new(raw_path);
        if !path.is_absolute() {
            return text(StatusCode::FORBIDDEN, "X-Sendfile path is not absolute");
        }
        let root = match tokio::fs::canonicalize(root).await {
            Ok(root) => root,
            Err(_) => return text(StatusCode::NOT_FOUND, "X-Sendfile root is missing"),
        };
        let path = match tokio::fs::canonicalize(path).await {
            Ok(path) => path,
            Err(_) => return text(StatusCode::NOT_FOUND, "X-Sendfile file is missing"),
        };
        if !path.starts_with(&root) {
            return text(StatusCode::FORBIDDEN, "X-Sendfile path is outside the root");
        }

        let relative = path.strip_prefix(&root).unwrap_or_else(|_| Path::new(""));
        let mut uri = String::from("/");
        uri.push_str(&relative.to_string_lossy());
        let files = crate::files::Files::new(
            root,
            None,
            Vec::new(),
            false,
            Vec::new(),
            false,
            self.inner.compression.enabled,
            self.inner.compression.min_bytes,
            entry.expires_secs,
            entry.etag,
            entry.if_modified_since,
        );
        let mut request = match Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(empty())
        {
            Ok(request) => request,
            Err(_) => return text(StatusCode::BAD_REQUEST, "bad X-Sendfile path"),
        };
        let mut headers = request_headers.clone();
        headers.remove(CONTENT_LENGTH);
        headers.remove(http::header::TRANSFER_ENCODING);
        *request.headers_mut() = headers;
        files.serve(&request, peer).await
    }
}
