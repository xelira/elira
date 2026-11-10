//! Access checks and non-proxy target dispatch.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use http::header::{AUTHORIZATION, CONTENT_LENGTH, LOCATION, WWW_AUTHENTICATE};
use http::{HeaderValue, Method, Request, Response, StatusCode};

use elira_tls::ClientIdentity;

use crate::*;

impl Proxy {
    /// Reject the request when a route-level rule says so. The caller turns
    /// the returned response into the error path, so the global error page
    /// still applies.
    pub(crate) async fn check_access(
        &self,
        req: &Request<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
    ) -> Option<Response<Body>> {
        if let Some(rule) = &entry.client_auth {
            if !rule.allows(req.extensions().get::<ClientIdentity>()) {
                let mut response = text(StatusCode::FORBIDDEN, "client certificate required");
                self.apply_error_page(&mut response, entry, vars, peer)
                    .await;
                return Some(response);
            }
        }

        // A route may set a stricter cap than the global one.
        if let Some(limit) = entry.body_limit {
            if limit > 0 {
                if let Some(length) = req
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                {
                    if length > limit as u64 {
                        let mut response =
                            text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
                        self.apply_error_page(&mut response, entry, vars, peer)
                            .await;
                        return Some(response);
                    }
                }
            }
        }

        if let Some(limiter) = &entry.limiter {
            let key_path = req
                .uri()
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/");
            let bucket = request_key_value(&entry.rate_key, req.headers(), peer.ip(), key_path);
            if !limiter.check(bucket.as_ref(), Instant::now()) {
                let mut response = text(StatusCode::TOO_MANY_REQUESTS, "too many requests");
                response
                    .headers_mut()
                    .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
                self.apply_error_page(&mut response, entry, vars, peer)
                    .await;
                return Some(response);
            }
        }

        if let Some(acl) = &entry.acl {
            if !acl.allows(peer.ip()) {
                let mut response = text(StatusCode::FORBIDDEN, "forbidden");
                self.apply_error_page(&mut response, entry, vars, peer)
                    .await;
                return Some(response);
            }
        }

        if let Some(auth) = &entry.auth {
            let header = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok());

            if !auth.check(header) {
                let mut response = text(StatusCode::UNAUTHORIZED, "authentication required");
                response.headers_mut().insert(
                    WWW_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"elira\""),
                );
                self.apply_error_page(&mut response, entry, vars, peer)
                    .await;
                return Some(response);
            }
        }

        None
    }

    /// Serve every target that does not need the upstream pool. `forward`
    /// calls this only after `Target::Proxy` was ruled out.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn serve_non_proxy(
        &self,
        mut req: Request<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
        scheme: &'static str,
        listener: &str,
        request_id: &str,
        body_limit_hit: &AtomicBool,
    ) -> Result<Response<Body>, Response<Body>> {
        match &entry.target {
            Target::Proxy(_) => unreachable!("proxy targets are served by forward"),
            Target::Files(files) => {
                let mut response = files.serve(&req, peer).await;
                if let Some(target) = response.extensions_mut().remove::<InternalTarget>() {
                    let count = req
                        .extensions()
                        .get::<InternalRequest>()
                        .map(|internal| internal.count)
                        .unwrap_or(0);
                    req.extensions_mut().insert(InternalRequest {
                        name: Some(target.0),
                        count: count.saturating_add(1),
                    });
                    return Box::pin(self.forward(req, peer, scheme, listener)).await;
                }
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
                self.apply_error_page(&mut response, entry, vars, peer)
                    .await;
                self.apply_route(&mut response, entry, vars, request_id);
                Ok(response)
            }
            Target::Redirect { status, location } => {
                let Ok(location) = HeaderValue::from_str(&vars.render(location)) else {
                    return Err(text(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "redirect target is not a valid header value",
                    ));
                };
                let mut response =
                    Response::builder()
                        .status(*status)
                        .body(empty())
                        .map_err(|_| {
                            text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
                        })?;
                response.headers_mut().insert(LOCATION, location);
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
                self.apply_route(&mut response, entry, vars, request_id);
                Ok(response)
            }
            Target::Return {
                status,
                body,
                content_type,
            } => Ok(self.fixed_response(
                *status,
                body,
                content_type.as_deref(),
                vars,
                entry,
                request_id,
            )),
            Target::FastCgi { .. } => {
                let mut response = self.serve_fastcgi(req, entry, peer, scheme).await;
                if body_limit_hit.load(Ordering::Relaxed) {
                    return Err(self.body_too_large(entry, vars, peer).await);
                }
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
                self.apply_error_page(&mut response, entry, vars, peer)
                    .await;
                self.apply_route(&mut response, entry, vars, request_id);
                Ok(response)
            }
            Target::Cgi { .. } => {
                let mut response = self.serve_cgi(req, entry, peer, scheme).await;
                if body_limit_hit.load(Ordering::Relaxed) {
                    return Err(self.body_too_large(entry, vars, peer).await);
                }
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
                self.apply_error_page(&mut response, entry, vars, peer)
                    .await;
                self.apply_route(&mut response, entry, vars, request_id);
                Ok(response)
            }
            Target::Scgi { .. }
            | Target::Uwsgi { .. }
            | Target::Ajp { .. }
            | Target::Module(_)
            | Target::Wasm(_) => {
                let mut response = self.serve_app(req, entry, peer, scheme).await;
                if body_limit_hit.load(Ordering::Relaxed) {
                    return Err(self.body_too_large(entry, vars, peer).await);
                }
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                });
                self.apply_error_page(&mut response, entry, vars, peer)
                    .await;
                self.apply_route(&mut response, entry, vars, request_id);
                Ok(response)
            }
        }
    }

    /// Run the configured auth_request subrequest. A 2xx allows the request;
    /// 401/403 are passed through; anything else becomes a 500.
    pub(crate) async fn authorize(
        &self,
        req: &Request<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
        scheme: &'static str,
        listener: &str,
    ) -> Result<(), Response<Body>> {
        let Some(path) = &entry.auth_request else {
            return Ok(());
        };

        let mut headers = req.headers().clone();
        headers.remove(CONTENT_LENGTH);
        headers.remove(http::header::TRANSFER_ENCODING);
        headers.remove(http::header::CONNECTION);
        headers.remove(http::header::UPGRADE);
        let mut subrequest = Request::builder()
            .method(Method::GET)
            .uri(path.as_str())
            .body(empty())
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "bad auth_request URI"))?;
        *subrequest.headers_mut() = headers;
        subrequest.extensions_mut().insert(InternalRequest {
            name: None,
            count: 1,
        });
        subrequest.extensions_mut().insert(AuthSubrequest);

        let response = match Box::pin(self.forward(subrequest, peer, scheme, listener)).await {
            Ok(response) => response,
            Err(response) => response,
        };
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let status = if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            status
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        let mut denied = text(status, "authorization failed");
        if let Some(value) = response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .cloned()
        {
            denied
                .headers_mut()
                .insert(http::header::WWW_AUTHENTICATE, value);
        }
        self.apply_error_page(&mut denied, entry, vars, peer).await;
        Err(denied)
    }
}
