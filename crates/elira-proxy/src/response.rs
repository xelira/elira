//! Response finalisation: route headers, fixed returns and error pages.

use std::net::SocketAddr;

use bytes::Bytes;
use http::header::{ALT_SVC, CONTENT_TYPE, SERVER, WWW_AUTHENTICATE};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};

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
            .and_then(|entry| {
                entry
                    .error_pages
                    .iter()
                    .find(|(code, _, _)| *code == status)
            })
            .or_else(|| {
                self.inner
                    .error_pages
                    .iter()
                    .find(|(code, _, _)| *code == status)
            });
        let Some((_, path, files)) = page else {
            return;
        };
        let path = match vars {
            Some(vars) => vars.render(path),
            None => path.clone(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(empty());
        let Ok(request) = request else {
            return;
        };

        let mut page = files.serve(&request, peer).await;
        if page.status().is_success() {
            *page.status_mut() = status;
        }
        // These describe the error itself, not the page body.
        for name in [
            WWW_AUTHENTICATE,
            http::header::RETRY_AFTER,
            http::header::ALLOW,
        ] {
            if let Some(value) = response.headers().get(&name) {
                page.headers_mut().insert(name, value.clone());
            }
        }
        page.extensions_mut().insert(ErrorPageApplied);
        *response = page;
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
}
