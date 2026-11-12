use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{AUTHORIZATION, CONTENT_LENGTH, LOCATION, WWW_AUTHENTICATE};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use md5::{Digest, Md5};

use elira_tls::ClientIdentity;

use crate::*;

impl Proxy {
    pub(crate) async fn check_secure_link(
        &self,
        req: &Request<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
    ) -> Result<(), Response<Body>> {
        let Some(link) = &entry.secure_link else {
            return Ok(());
        };

        let path = req.uri().path();
        let valid = if let (Some(md5), Some(expires)) = (&link.md5, &link.expires) {
            let provided = vars.render(md5);
            let expires = vars.render(expires);
            let Ok(timestamp) = expires.parse::<u64>() else {
                return Err(self
                    .secure_deny(StatusCode::FORBIDDEN, entry, vars, peer)
                    .await);
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            if now > timestamp {
                return Err(self.secure_deny(StatusCode::GONE, entry, vars, peer).await);
            }
            let expected = digest(&format!("{expires}{path}{}", link.secret));
            matches_hash(&provided, &expected)
        } else {
            let trimmed = path.trim_start_matches('/');
            let (provided, rest) = trimmed.split_once('/').unwrap_or((trimmed, ""));
            let rest = format!("/{rest}");
            let expected = digest(&format!("{}{rest}", link.secret));
            matches_hash(provided, &expected)
        };

        if valid {
            Ok(())
        } else {
            Err(self
                .secure_deny(StatusCode::FORBIDDEN, entry, vars, peer)
                .await)
        }
    }

    async fn secure_deny(
        &self,
        status: StatusCode,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
    ) -> Response<Body> {
        let mut response = text(status, "invalid secure link");
        self.apply_error_page(&mut response, entry, vars, peer)
            .await;
        response
    }

    pub(crate) async fn check_access(
        &self,
        req: &Request<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
    ) -> Option<Response<Body>> {
        if let Some(response) = self.check_always(req, entry, vars, peer).await {
            return Some(response);
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

    async fn check_always(
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
            if !rate_allowed(limiter, bucket.as_ref(), entry.rate_delay).await {
                let mut response = text(StatusCode::TOO_MANY_REQUESTS, "too many requests");
                response
                    .headers_mut()
                    .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
                self.apply_error_page(&mut response, entry, vars, peer)
                    .await;
                return Some(response);
            }
        }

        None
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn check_any_access(
        &self,
        req: &Request<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
        scheme: &'static str,
        listener: &str,
    ) -> Result<(), Response<Body>> {
        if let Some(response) = self.check_always(req, entry, vars, peer).await {
            return Err(response);
        }

        let mut configured = false;
        let mut denials = Vec::new();

        if let Some(acl) = &entry.acl {
            configured = true;
            if acl.allows(peer.ip()) {
                return Ok(());
            }
            let mut response = text(StatusCode::FORBIDDEN, "forbidden");
            self.apply_error_page(&mut response, entry, vars, peer)
                .await;
            denials.push(response);
        }

        if let Some(auth) = &entry.auth {
            configured = true;
            let header = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok());
            if auth.check(header) {
                return Ok(());
            }
            let mut response = text(StatusCode::UNAUTHORIZED, "authentication required");
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"elira\""),
            );
            self.apply_error_page(&mut response, entry, vars, peer)
                .await;
            denials.push(response);
        }

        if entry.auth_request.is_some() {
            configured = true;
            match self
                .authorize(req, entry, vars, peer, scheme, listener)
                .await
            {
                Ok(()) => return Ok(()),
                Err(response) => denials.push(response),
            }
        }

        if !configured {
            return Ok(());
        }

        denials.sort_by_key(|response| match response.status() {
            StatusCode::UNAUTHORIZED => 0,
            StatusCode::FORBIDDEN => 1,
            _ => 2,
        });
        Err(denials.remove(0))
    }

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
                    mapped: vars.mapped.clone(),
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
                    mapped: vars.mapped.clone(),
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
            Target::FastCgi { .. }
            | Target::Cgi { .. }
            | Target::Scgi { .. }
            | Target::Uwsgi { .. }
            | Target::Ajp { .. }
            | Target::Module(_)
            | Target::Wasm(_) => {
                self.serve_dynamic(
                    &entry.target,
                    req,
                    entry,
                    vars,
                    peer,
                    scheme,
                    request_id,
                    body_limit_hit,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_dynamic(
        &self,
        target: &Target,
        req: Request<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
        scheme: &'static str,
        request_id: &str,
        body_limit_hit: &AtomicBool,
    ) -> Result<Response<Body>, Response<Body>> {
        let request_headers = req.headers().clone();
        let path = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());
        let cache_eligible = entry.cache.is_some()
            && req.method() == Method::GET
            && !cache_bypass(entry, vars)
            && req.extensions().get::<AuthSubrequest>().is_none()
            && req.extensions().get::<AccelRedirect>().is_none()
            && !entry.internal
            && entry.name.is_none()
            && entry.auth_request.is_none()
            && entry.client_auth.is_none();
        let cache_key = cache_eligible.then(|| cache_key_for(entry, vars, &vars.host, &path));

        if let (Some(cache), Some(key)) = (&entry.cache, &cache_key) {
            if let Some(hit) = cache.get(key, &request_headers, Instant::now()) {
                let mut response = cache_response(hit);
                response
                    .headers_mut()
                    .insert("x-cache", HeaderValue::from_static("HIT"));
                response.extensions_mut().insert(Labels {
                    route: entry.label.clone(),
                    upstream: None,
                    access_log: entry.access_log,
                    access_log_sample: entry.access_log_sample,
                    mapped: vars.mapped.clone(),
                });
                self.apply_route(&mut response, entry, vars, request_id);
                return Ok(response);
            }
        }

        let mut response = match target {
            Target::FastCgi { .. } => self.serve_fastcgi(req, entry, peer, scheme).await,
            Target::Cgi { .. } => self.serve_cgi(req, entry, peer, scheme).await,
            _ => self.serve_app(req, entry, peer, scheme).await,
        };
        if body_limit_hit.load(Ordering::Relaxed) {
            return Err(self.body_too_large(entry, vars, peer).await);
        }
        response.extensions_mut().insert(Labels {
            route: entry.label.clone(),
            upstream: None,
            access_log: entry.access_log,
            access_log_sample: entry.access_log_sample,
            mapped: vars.mapped.clone(),
        });
        self.apply_error_page(&mut response, entry, vars, peer)
            .await;

        if let (Some(cache), Some(key)) = (&entry.cache, &cache_key) {
            let status = response.status().as_u16();
            let explicitly_valid = entry
                .cache_valid
                .iter()
                .any(|valid| valid.statuses.contains(&status));
            if (status == StatusCode::OK.as_u16() || explicitly_valid)
                && response.extensions().get::<ErrorPageApplied>().is_none()
                && cacheable_response(response.headers())
            {
                let ttl = entry.cache_ttl_for(status);
                let (parts, mut body) = response.into_parts();
                let limit = entry.cache_max_item;
                let mut chunks: Vec<Bytes> = Vec::new();
                let mut total = 0usize;
                let mut overflow = None;
                let mut failed = false;
                while let Some(frame) = body.frame().await {
                    match frame {
                        Ok(frame) => {
                            let Ok(data) = frame.into_data() else {
                                continue;
                            };
                            total = total.saturating_add(data.len());
                            if total > limit {
                                overflow = Some(data);
                                break;
                            }
                            chunks.push(data);
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "failed to buffer an app response");
                            failed = true;
                            break;
                        }
                    }
                }

                if failed {
                    response = text(StatusCode::BAD_GATEWAY, "bad gateway");
                } else if let Some(data) = overflow {
                    let head = futures_util::stream::iter(
                        chunks
                            .into_iter()
                            .map(|chunk| Ok::<_, BoxError>(Frame::data(chunk)))
                            .chain(std::iter::once(Ok(Frame::data(data)))),
                    );
                    let tail = body.into_data_stream().map(|chunk| chunk.map(Frame::data));
                    let streamed = StreamBody::new(head.chain(tail));
                    response = Response::from_parts(parts, BodyExt::boxed(streamed));
                } else {
                    let bytes = Bytes::from(chunks.concat());
                    cache.insert_with_ttl(
                        key,
                        &request_headers,
                        &parts.headers,
                        status,
                        bytes.to_vec(),
                        Instant::now(),
                        ttl,
                    );
                    let body = http_body_util::Full::new(bytes)
                        .map_err(|never| -> BoxError { match never {} })
                        .boxed();
                    response = Response::from_parts(parts, body);
                    response
                        .headers_mut()
                        .insert("x-cache", HeaderValue::from_static("MISS"));
                }
            }
        }

        self.apply_route(&mut response, entry, vars, request_id);
        Ok(response)
    }

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
        let depth = req
            .extensions()
            .get::<InternalRequest>()
            .map(|internal| internal.count)
            .unwrap_or(0)
            .saturating_add(1);
        if depth > 4 {
            return Err(text(StatusCode::INTERNAL_SERVER_ERROR, "auth_request loop"));
        }
        let mut subrequest = Request::builder()
            .method(Method::GET)
            .uri(path.as_str())
            .body(empty())
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "bad auth_request URI"))?;
        *subrequest.headers_mut() = headers;
        subrequest.extensions_mut().insert(InternalRequest {
            name: None,
            count: depth,
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

fn digest(value: &str) -> (String, String) {
    let mut hasher = Md5::new();
    hasher.update(value.as_bytes());
    let bytes = hasher.finalize();
    let base64 = URL_SAFE_NO_PAD.encode(bytes);
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    (base64, hex)
}

fn matches_hash(provided: &str, expected: &(String, String)) -> bool {
    let provided = provided.trim();
    provided == expected.0 || provided.eq_ignore_ascii_case(&expected.1)
}
