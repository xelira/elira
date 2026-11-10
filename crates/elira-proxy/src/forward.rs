//! Request forwarding and rewrites.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::header::{
    HeaderValue, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION,
    SERVER, SET_COOKIE, TRANSFER_ENCODING, UPGRADE, VARY,
};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};

use elira_config::{Balance, Satisfy};

use crate::*;

impl Proxy {
    /// Only a trusted peer may extend the chain; everyone else starts a new
    /// one, otherwise a client could pick its own address in the logs.
    fn forwarded_for(&self, req: &Request<Body>, peer: SocketAddr) -> String {
        if self
            .inner
            .trusted_proxies
            .iter()
            .any(|net| net.contains(&peer.ip()))
        {
            if let Some(existing) = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
            {
                return format!("{existing}, {}", peer.ip());
            }
        }

        peer.ip().to_string()
    }

    #[allow(clippy::result_large_err)]
    fn apply_rewrites(&self, req: &mut Request<Body>) -> Result<(), Response<Body>> {
        let mut path = req.uri().path().to_owned();
        let mut query = req.uri().query().map(str::to_owned);

        for _ in 0..10 {
            let mut restart = false;
            for rewrite in &self.inner.rewrites {
                let Some(captures) = rewrite.regex.captures(&path) else {
                    continue;
                };
                let target = expand_rewrite(&rewrite.replacement, &captures);
                match rewrite.flag {
                    RewriteFlag::Redirect | RewriteFlag::Permanent => {
                        let status = if rewrite.flag == RewriteFlag::Permanent {
                            StatusCode::MOVED_PERMANENTLY
                        } else {
                            StatusCode::FOUND
                        };
                        let Ok(location) = HeaderValue::from_str(&target) else {
                            return Err(text(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "rewrite location is not a valid header value",
                            ));
                        };
                        let mut response = text(status, "redirect");
                        response.headers_mut().insert(LOCATION, location);
                        return Err(response);
                    }
                    RewriteFlag::Break | RewriteFlag::Last => {
                        let (new_path, new_query) = match target.split_once('?') {
                            Some((path, query)) => (path.to_owned(), Some(query.to_owned())),
                            None => (target, None),
                        };
                        path = if new_path.starts_with('/') {
                            new_path
                        } else {
                            format!("/{new_path}")
                        };
                        query = new_query;
                        restart = rewrite.flag == RewriteFlag::Last;
                        break;
                    }
                }
            }
            if !restart {
                break;
            }
        }

        let path_and_query = match query {
            Some(query) => format!("{path}?{query}"),
            None => path,
        };
        let Ok(path_and_query) = path_and_query.parse::<http::uri::PathAndQuery>() else {
            return Err(text(StatusCode::BAD_REQUEST, "bad rewrite target"));
        };
        let mut parts = req.uri().clone().into_parts();
        parts.path_and_query = Some(path_and_query);
        let Ok(uri) = Uri::from_parts(parts) else {
            return Err(text(StatusCode::BAD_REQUEST, "bad rewrite target"));
        };
        *req.uri_mut() = uri;
        Ok(())
    }

    pub(crate) async fn forward(
        &self,
        mut req: Request<Body>,
        peer: SocketAddr,
        scheme: &'static str,
        listener: &str,
    ) -> Result<Response<Body>, Response<Body>> {
        let connect_protocol = req
            .extensions()
            .get::<hyper::ext::Protocol>()
            .map(|protocol| protocol.as_str().to_owned());
        if req.method() == Method::CONNECT && connect_protocol.is_none() {
            return self.connect(req).await;
        }
        if connect_protocol
            .as_deref()
            .is_some_and(|protocol| protocol != "websocket")
        {
            return Err(text(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported CONNECT protocol",
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

        if self.inner.max_body_bytes > 0 {
            if let Some(length) = req
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
            {
                if length > self.inner.max_body_bytes as u64 {
                    return Err(text(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request body too large",
                    ));
                }
            }
        }

        let encoding = preferred_encoding(req.headers());
        let is_head = req.method() == Method::HEAD;
        let is_get = req.method() == Method::GET;
        let forwarded_for = self.forwarded_for(&req, peer);

        let requested_upgrade = wants_upgrade(req.headers()).or_else(|| {
            connect_protocol
                .as_ref()
                .map(|_| HeaderValue::from_static("websocket"))
        });
        let client_upgrade = requested_upgrade
            .as_ref()
            .map(|_| hyper::upgrade::on(&mut req));

        // No upgrade protocol carries a body. Refusing one keeps the raw
        // upstream write from sending a Content-Length with zero bytes.
        if requested_upgrade.is_some() {
            let has_body = req
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim() != "0")
                .unwrap_or(false)
                || req.headers().contains_key(TRANSFER_ENCODING);
            if has_body {
                return Err(text(
                    StatusCode::BAD_REQUEST,
                    "upgrade requests cannot carry a body",
                ));
            }
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

        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.len() <= 64)
            .map(str::to_owned)
            .unwrap_or_else(elira_accesslog::request_id);

        if !self.inner.rewrites.is_empty() {
            self.apply_rewrites(&mut req)?;
        }

        let internal = req.extensions_mut().remove::<InternalRequest>();
        if internal
            .as_ref()
            .is_some_and(|internal| internal.count > 10)
        {
            return Err(text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal redirect loop",
            ));
        }
        let entry = match internal
            .as_ref()
            .and_then(|internal| internal.name.as_deref())
        {
            Some(name) => self.router(listener).pick_named(&key, name),
            None => self.router(listener).pick(&key, req.uri().path()),
        }
        .ok_or_else(|| text(StatusCode::NOT_FOUND, "no route"))?;
        if entry.internal && internal.is_none() {
            return Err(text(StatusCode::NOT_FOUND, "no route"));
        }
        let internal_count = internal.as_ref().map_or(0, |internal| internal.count);
        if let Some(internal) = internal {
            req.extensions_mut().insert(InternalRequest {
                name: None,
                count: internal.count,
            });
        }

        let vars = self.request_vars(&req, &key, &forward_host, scheme, peer, &request_id);

        if let Some(response) = self.if_response(entry, &vars, &request_id) {
            return Ok(response);
        }

        self.check_secure_link(&req, entry, &vars, peer).await?;

        match entry.satisfy {
            Satisfy::All => {
                if let Some(response) = self.check_access(&req, entry, &vars, peer).await {
                    return Err(response);
                }
                self.authorize(&req, entry, &vars, peer, scheme, listener)
                    .await?;
            }
            Satisfy::Any => {
                self.check_any_access(&req, entry, &vars, peer, scheme, listener)
                    .await?;
            }
        }

        let (buffered, body_limit_hit) = self.prepare_body(&mut req, entry, &vars, peer).await?;

        let proxy_permit = self.acquire_proxy_permit(entry, &vars, peer).await?;

        let pool = match &entry.target {
            Target::Proxy(pool) => pool,
            _ => {
                return self
                    .serve_non_proxy(
                        req,
                        entry,
                        &vars,
                        peer,
                        scheme,
                        listener,
                        &request_id,
                        &body_limit_hit,
                    )
                    .await;
            }
        };
        let path = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());

        let cache_key = entry
            .cache_key
            .as_ref()
            .map(|template| vars.render(template))
            .filter(|key| !key.is_empty())
            .unwrap_or_else(|| format!("{key}{path}"));
        let cache_bypass = entry.cache_bypass.iter().any(|template| {
            let value = variable_or_empty(&vars, template);
            !value.is_empty() && value != "0"
        });

        let upstream_path = if entry.strip_prefix {
            let rest = path
                .strip_prefix(entry.prefix.as_str())
                .unwrap_or(&path)
                .to_owned();
            if rest.is_empty() {
                "/".to_owned()
            } else if rest.starts_with('/') {
                rest
            } else {
                format!("/{rest}")
            }
        } else {
            path.clone()
        };

        let auth_subrequest = req.extensions().get::<AuthSubrequest>().is_some();
        let accel_redirect = req.extensions().get::<AccelRedirect>().is_some();
        let (parts, body) = req.into_parts();
        // Kept for Vary matching: the response parts shadow this name later.
        let request_headers = parts.headers.clone();
        let hash_key = (pool.balance == Balance::Hash)
            .then(|| request_key_value(&pool.hash_key, &parts.headers, peer.ip(), &path));
        let can_retry = pool.retries > 0
            && match parts.method {
                Method::GET | Method::HEAD | Method::OPTIONS => {
                    buffered.is_some()
                        || (!parts.headers.contains_key(CONTENT_LENGTH)
                            && !parts.headers.contains_key(TRANSFER_ENCODING))
                }
                Method::PUT | Method::DELETE => buffered.is_some(),
                _ => false,
            };
        let template = self.upstream_template(
            &parts.headers,
            entry,
            &vars,
            &forward_host,
            &forwarded_for,
            scheme,
            &request_id,
            peer,
            requested_upgrade.as_ref(),
        );

        let route_timeout = entry.timeout.unwrap_or(self.inner.timeout);
        let connect_timeout = entry.connect_timeout.unwrap_or(self.inner.connect_timeout);
        let send_timeout = entry
            .send_timeout
            .or(self.inner.send_timeout)
            .filter(|timeout| !timeout.is_zero());

        let mut body = Some(body);

        let cache_allowed =
            entry.cache != Some(false) && !auth_subrequest && !accel_redirect && !cache_bypass;
        let mut _cache_flight: Option<CacheFlightGuard> = None;
        if is_get && requested_upgrade.is_none() && cache_allowed {
            let (hit, flight) = self
                .cache_lookup(
                    entry,
                    &vars,
                    &request_id,
                    pool,
                    &cache_key,
                    &request_headers,
                    &template,
                    &upstream_path,
                    is_head,
                    route_timeout,
                    connect_timeout,
                    peer,
                )
                .await;
            _cache_flight = flight;
            if let Some(response) = hit {
                return Ok(response);
            }
        }

        if let Some(upgrade) = requested_upgrade.clone() {
            let client = client_upgrade.expect("created together with requested_upgrade");
            let index = pool
                .pick_key(hash_key.as_deref())
                .ok_or_else(|| text(StatusCode::BAD_GATEWAY, "no upstream available"))?;
            let server = pool.servers[index].clone();
            let _active = pool.enter(index);
            let uri = upstream_uri(&server, &upstream_path, pool.scheme)
                .ok_or_else(|| text(StatusCode::BAD_GATEWAY, "bad upstream address"))?;

            let method = if connect_protocol.is_some() {
                Method::GET
            } else {
                parts.method.clone()
            };
            let mut upstream = Request::builder()
                .method(method)
                .uri(uri)
                .body(body.take().unwrap_or_else(empty))
                .map_err(|_| text(StatusCode::BAD_GATEWAY, "bad request"))?;
            *upstream.headers_mut() = template;

            let result = self
                .forward_upgrade(
                    upstream,
                    client,
                    upgrade,
                    server,
                    connect_timeout,
                    pool.tls.local_address,
                    &pool.resolver,
                    pool.proxy_protocol,
                    peer,
                    route_timeout,
                    proxy_permit,
                    connect_protocol.is_some(),
                )
                .await;
            match &result {
                Ok(_) => pool.record_success(index),
                Err(response) if response.status() == StatusCode::BAD_GATEWAY => {
                    pool.record_failure(index);
                }
                Err(_) => {}
            }
            return result;
        }
        let response = self
            .send_upstream(
                pool,
                &parts.method,
                &upstream_path,
                &template,
                hash_key.as_deref(),
                buffered.as_ref(),
                &mut body,
                can_retry,
                route_timeout,
                connect_timeout,
                send_timeout,
                &body_limit_hit,
                entry,
                &vars,
                peer,
            )
            .await?;

        self.finalize_response(
            response,
            pool,
            entry,
            &vars,
            &request_id,
            peer,
            is_head,
            is_get,
            requested_upgrade.as_ref(),
            encoding,
            cache_allowed,
            &cache_key,
            &request_headers,
            proxy_permit,
            scheme,
            listener,
            internal_count,
        )
        .await
    }

    fn request_vars(
        &self,
        req: &Request<Body>,
        key: &str,
        forward_host: &str,
        scheme: &'static str,
        peer: SocketAddr,
        request_id: &str,
    ) -> RequestVars {
        let request_uri = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());
        let request_port = forward_host
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let mut vars = RequestVars {
            remote_addr: peer.ip(),
            host: key.to_owned(),
            path: req.uri().path().to_owned(),
            query: req.uri().query().unwrap_or_default().to_owned(),
            uri: request_uri,
            method: req.method().to_string(),
            scheme,
            port: request_port,
            request_id: request_id.to_owned(),
            headers: req.headers().clone(),
            mapped: HashMap::new(),
        };
        vars.apply_derived(&self.inner.maps, &self.inner.geos, &self.inner.splits);

        vars
    }

    fn if_response(
        &self,
        entry: &RouteEntry,
        vars: &RequestVars,
        request_id: &str,
    ) -> Option<Response<Body>> {
        for condition in &entry.if_conditions {
            let value = vars
                .value(&condition.variable)
                .map(|value| value.into_owned())
                .unwrap_or_default();
            let matched = condition
                .equals
                .as_ref()
                .is_some_and(|expected| value == *expected)
                || condition
                    .regex
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(&value));
            if matched {
                return Some(self.fixed_response(
                    condition.status,
                    &condition.body,
                    condition.content_type.as_deref(),
                    vars,
                    entry,
                    request_id,
                ));
            }
        }

        None
    }

    #[allow(clippy::too_many_arguments)]
    fn upstream_template(
        &self,
        headers: &HeaderMap,
        entry: &RouteEntry,
        vars: &RequestVars,
        forward_host: &str,
        forwarded_for: &str,
        scheme: &'static str,
        request_id: &str,
        peer: SocketAddr,
        requested_upgrade: Option<&HeaderValue>,
    ) -> HeaderMap {
        let mut template = HeaderMap::new();
        let drop = connection_tokens(headers);
        for (name, value) in headers.iter() {
            if hop_by_hop(name, value) || drop.contains(name) || is_client_forwarding(name) {
                continue;
            }
            template.append(name, value.clone());
        }

        // Everything below is set by us. A client that sent its own copies
        // had them dropped above.
        let forwarded_port = forward_host
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let forwarded_for_value = match peer.ip() {
            std::net::IpAddr::V6(ip) => format!("\"[{ip}]\""),
            std::net::IpAddr::V4(ip) => ip.to_string(),
        };
        let forwarded = format!("for={forwarded_for_value};proto={scheme};host=\"{forward_host}\"");
        template.insert(HOST, header(forward_host));
        template.insert("x-forwarded-for", header(forwarded_for));
        template.insert("x-forwarded-proto", HeaderValue::from_static(scheme));
        template.insert("x-forwarded-host", header(forward_host));
        template.insert(
            "x-forwarded-port",
            HeaderValue::from_str(&forwarded_port.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("80")),
        );
        if let Ok(value) = HeaderValue::from_str(&forwarded) {
            template.insert("forwarded", value);
        }
        template.insert("via", HeaderValue::from_static("1.1 elira"));
        if let Ok(value) = HeaderValue::from_str(request_id) {
            template.insert("x-request-id", value);
        }

        // Upgrade is hop-by-hop, but dropping it would break websockets.
        if let Some(upgrade) = &requested_upgrade {
            template.insert(CONNECTION, HeaderValue::from_static("upgrade"));
            template.insert(UPGRADE, (*upgrade).clone());
        }

        for name in &entry.request_remove_headers {
            template.remove(name);
        }
        for (name, value) in &entry.request_headers {
            if let Ok(value) = HeaderValue::from_str(&vars.render(value)) {
                template.insert(name.clone(), value);
            }
        }

        template
    }

    async fn prepare_body(
        &self,
        req: &mut Request<Body>,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
    ) -> Result<(Option<BufferedBody>, Arc<AtomicBool>), Response<Body>> {
        let body_limit = entry.body_limit.unwrap_or(self.inner.max_body_bytes);
        let body_limit_hit = Arc::new(AtomicBool::new(false));
        if body_limit > 0 {
            let hit = body_limit_hit.clone();
            let original = std::mem::replace(req.body_mut(), empty());
            *req.body_mut() = capped_request_body(original, body_limit, hit);
        }

        let mut buffered = None;
        if (self.inner.request_buffer_bytes > 0 || self.inner.request_spool_bytes > 0)
            && wants_upgrade(req.headers()).is_none()
        {
            let original = std::mem::replace(req.body_mut(), empty());
            match buffer_request(
                req.headers(),
                original,
                self.inner.request_buffer_bytes,
                self.inner.request_spool_bytes,
                &self.inner.spool_budget,
            )
            .await
            {
                Ok(RequestBuffer::Stream(body)) => *req.body_mut() = body,
                Ok(RequestBuffer::Buffered(body)) => {
                    *req.body_mut() = body.body();
                    buffered = Some(body);
                }
                Err(()) => {
                    if body_limit_hit.load(Ordering::Relaxed) {
                        return Err(self.body_too_large(entry, vars, peer).await);
                    }
                    return Err(text(StatusCode::BAD_REQUEST, "request body error"));
                }
            }
        }

        Ok((buffered, body_limit_hit))
    }

    async fn acquire_proxy_permit(
        &self,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, Response<Body>> {
        let permit = match &entry.proxy_permits {
            Some(permits) => match permits.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    let mut response = text(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "too many concurrent requests",
                    );
                    response
                        .headers_mut()
                        .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
                    self.apply_error_page(&mut response, entry, vars, peer)
                        .await;
                    return Err(response);
                }
            },
            None => None,
        };
        Ok(permit)
    }

    /// Look up a cached representation, including the stale path. Returns the
    /// response to send, or nothing plus the single-flight guard the caller
    /// must keep for the duration of the upstream request.
    #[allow(clippy::too_many_arguments)]
    async fn cache_lookup(
        &self,
        entry: &RouteEntry,
        vars: &RequestVars,
        request_id: &str,
        pool: &Arc<Pool>,
        cache_key: &str,
        request_headers: &HeaderMap,
        template: &HeaderMap,
        upstream_path: &str,
        is_head: bool,
        route_timeout: Duration,
        connect_timeout: Duration,
        peer: SocketAddr,
    ) -> (Option<Response<Body>>, Option<CacheFlightGuard>) {
        let mut flight = None;
        if let Some(cache) = &self.inner.cache {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            loop {
                let now = Instant::now();
                if let Some((hit, stale)) = cache.get_stale(cache_key, request_headers, now) {
                    let age = hit.age(now);
                    let body_len = hit.body.len();
                    let cached_status = hit.status;
                    let cached_type = hit
                        .headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                        .map(|(_, value)| value.clone())
                        .unwrap_or_default();
                    let cached_encoding = hit
                        .headers
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case("content-encoding"));
                    let validators = validators_from_entry(&hit);
                    let mut response = cache_response(hit);

                    // A cached body is stored identity-encoded, so it still
                    // has to go through the same negotiation as a fresh one.
                    if !is_head
                        && !cached_encoding
                        && cached_status == StatusCode::OK.as_u16()
                        && self.inner.compression.enabled
                        && body_len >= self.inner.compression.min_bytes
                        && compressible(&cached_type)
                    {
                        if let Some(encoding) = preferred_encoding(request_headers) {
                            let headers = response.headers_mut();
                            headers.remove(CONTENT_LENGTH);
                            headers.remove(http::header::ETAG);
                            headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding));
                            headers.append(VARY, HeaderValue::from_static("accept-encoding"));
                            let body = std::mem::replace(response.body_mut(), empty());
                            *response.body_mut() = compress(body, encoding);
                        }
                    }

                    if let Ok(value) = HeaderValue::from_str(&age.to_string()) {
                        response.headers_mut().insert("age", value);
                    }
                    response.headers_mut().insert(
                        "x-cache",
                        HeaderValue::from_static(if stale { "STALE" } else { "HIT" }),
                    );
                    response.extensions_mut().insert(Labels {
                        route: entry.label.clone(),
                        upstream: Some(pool.name.clone()),
                        access_log: entry.access_log,
                        access_log_sample: entry.access_log_sample,
                    });
                    if stale {
                        self.refresh(
                            cache.clone(),
                            cache_key.to_owned(),
                            template.clone(),
                            request_headers.clone(),
                            validators,
                            upstream_path.to_owned(),
                            pool.clone(),
                            route_timeout,
                            connect_timeout,
                            peer,
                            entry.cache_ttl_for(cached_status),
                        );
                    }
                    self.apply_route(&mut response, entry, vars, request_id);
                    return (Some(response), flight);
                }

                match self.inner.cache_flights.enter(cache_key) {
                    CacheFlight::Leader(guard) => {
                        flight = Some(guard);
                        break;
                    }
                    CacheFlight::Follower(mut done) => {
                        if tokio::time::Instant::now() >= deadline {
                            break;
                        }
                        if !*done.borrow() {
                            let _ = tokio::time::timeout_at(deadline, done.changed()).await;
                        }
                    }
                }
            }
        }
        (None, flight)
    }

    /// Pick upstream servers and retry according to the pool policy.
    #[allow(clippy::too_many_arguments)]
    async fn send_upstream(
        &self,
        pool: &Pool,
        method: &Method,
        upstream_path: &str,
        template: &HeaderMap,
        hash_key: Option<&str>,
        buffered: Option<&BufferedBody>,
        body: &mut Option<Body>,
        can_retry: bool,
        route_timeout: Duration,
        connect_timeout: Duration,
        send_timeout: Option<Duration>,
        body_limit_hit: &AtomicBool,
        entry: &RouteEntry,
        vars: &RequestVars,
        peer: SocketAddr,
    ) -> Result<Response<Body>, Response<Body>> {
        let attempts = if can_retry {
            pool.retries as usize + 1
        } else {
            1
        };
        let mut response = None;

        for attempt in 0..attempts {
            let index = pool
                .pick_key(hash_key)
                .ok_or_else(|| text(StatusCode::BAD_GATEWAY, "no upstream available"))?;
            let server = pool.servers[index].clone();
            let _active = pool.enter(index);

            let uri = upstream_uri(&server, upstream_path, pool.scheme)
                .ok_or_else(|| text(StatusCode::BAD_GATEWAY, "bad upstream address"))?;
            let payload = match &buffered {
                Some(buffered) => buffered.body(),
                None if attempt == 0 => body.take().unwrap_or_else(empty),
                None => empty(),
            };
            // Bound stalls while the body is written to the upstream. The
            // timer restarts on each chunk, so a large but steady upload is
            // not cut off.
            let payload = match send_timeout {
                Some(idle) => crate::body::timeout_body(payload, idle),
                None => payload,
            };

            let mut upstream = Request::builder()
                .method(method.clone())
                .uri(uri)
                .body(payload)
                .map_err(|_| text(StatusCode::BAD_GATEWAY, "bad request"))?;
            *upstream.headers_mut() = template.clone();

            match send_request(
                pool,
                &server,
                upstream,
                route_timeout,
                connect_timeout,
                peer,
            )
            .await
            {
                Ok(answer) => {
                    if attempt + 1 < attempts && pool.retry_on.status(answer.status().as_u16()) {
                        pool.record_success(index);
                        tracing::warn!(
                            upstream = %server,
                            status = answer.status().as_u16(),
                            "upstream returned a retryable status"
                        );
                        continue;
                    }
                    pool.record_success(index);
                    response = Some(answer);
                    break;
                }
                Err(SendError::Failed(err)) => {
                    if body_limit_hit.load(Ordering::Relaxed) {
                        return Err(self.body_too_large(entry, vars, peer).await);
                    }
                    pool.record_failure(index);
                    tracing::warn!(upstream = %server, error = %err, "upstream request failed");
                    if !pool.retry_on.error || attempt + 1 == attempts {
                        return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                    }
                }
                Err(SendError::Timeout) => {
                    if body_limit_hit.load(Ordering::Relaxed) {
                        return Err(self.body_too_large(entry, vars, peer).await);
                    }
                    pool.record_failure(index);
                    tracing::warn!(upstream = %server, "upstream timed out");
                    if !pool.retry_on.timeout || attempt + 1 == attempts {
                        return Err(text(StatusCode::GATEWAY_TIMEOUT, "gateway timeout"));
                    }
                }
            }
        }

        response.ok_or_else(|| text(StatusCode::BAD_GATEWAY, "bad gateway"))
    }

    /// Turn the upstream response into the client response: transfer coding,
    /// headers, cache insertion, buffering and compression.
    #[allow(clippy::too_many_arguments)]
    async fn finalize_response(
        &self,
        response: Response<Body>,
        pool: &Pool,
        entry: &RouteEntry,
        vars: &RequestVars,
        request_id: &str,
        peer: SocketAddr,
        is_head: bool,
        is_get: bool,
        requested_upgrade: Option<&HeaderValue>,
        encoding: Option<&'static str>,
        cache_allowed: bool,
        cache_key: &str,
        request_headers: &HeaderMap,
        proxy_permit: Option<tokio::sync::OwnedSemaphorePermit>,
        scheme: &'static str,
        listener: &str,
        internal_count: u8,
    ) -> Result<Response<Body>, Response<Body>> {
        // Same rule as the request side: hyper only unwraps `chunked`, so
        // anything else would reach the client still transfer-coded.
        if !transfer_encoding_is_plain_chunked(response.headers()) {
            return Err(text(
                StatusCode::BAD_GATEWAY,
                "unsupported transfer encoding from upstream",
            ));
        }

        let (parts, body) = response.into_parts();

        if let Some(location) = parts
            .headers
            .get("x-accel-redirect")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
        {
            if !location.starts_with('/') {
                return Err(text(StatusCode::BAD_GATEWAY, "bad X-Accel-Redirect"));
            }
            if internal_count >= 10 {
                return Err(text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal redirect loop",
                ));
            }
            let mut headers = request_headers.clone();
            headers.remove(CONTENT_LENGTH);
            headers.remove(TRANSFER_ENCODING);
            headers.remove(CONNECTION);
            headers.remove(UPGRADE);
            let mut request = Request::builder()
                .method(Method::GET)
                .uri(location)
                .body(empty())
                .map_err(|_| text(StatusCode::BAD_GATEWAY, "bad X-Accel-Redirect"))?;
            *request.headers_mut() = headers;
            request.extensions_mut().insert(InternalRequest {
                name: None,
                count: internal_count.saturating_add(1),
            });
            request.extensions_mut().insert(AccelRedirect);
            return Box::pin(self.forward(request, peer, scheme, listener)).await;
        }

        if let Some(path) = parts
            .headers
            .get("x-sendfile")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
        {
            let Some(root) = &entry.x_sendfile_root else {
                return Err(text(
                    StatusCode::FORBIDDEN,
                    "X-Sendfile is not configured for this route",
                ));
            };
            let mut response = self
                .sendfile_response(&path, root, entry, request_headers, peer)
                .await;
            response.extensions_mut().insert(Labels {
                route: entry.label.clone(),
                upstream: Some(pool.name.clone()),
                access_log: entry.access_log,
                access_log_sample: entry.access_log_sample,
            });
            self.apply_error_page(&mut response, entry, vars, peer)
                .await;
            self.apply_route(&mut response, entry, vars, request_id);
            return Ok(response);
        }

        let upstream_len = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        let content_type = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let response_cap = entry
            .max_upstream_response
            .unwrap_or(self.inner.max_upstream_response);
        if response_cap > 0 && upstream_len.is_some_and(|length| length > response_cap) {
            return Err(text(StatusCode::BAD_GATEWAY, "upstream response too large"));
        }
        let compress_with = if self.inner.compression.enabled
            && parts.status == StatusCode::OK
            && !is_head
            && !parts.headers.contains_key(CONTENT_ENCODING)
            && compressible(content_type)
            && upstream_len
                .map(|length| length >= self.inner.compression.min_bytes)
                .unwrap_or(true)
        {
            encoding
        } else {
            None
        };

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
                    || (entry.hide_headers.contains(name) && !entry.pass_headers.contains(name))
                {
                    continue;
                }
                let mut value = value.clone();
                if name == LOCATION {
                    if let Some(rewritten) = rewrite_prefix(&value, &entry.proxy_redirect) {
                        value = rewritten;
                    }
                } else if name == http::header::REFRESH {
                    if let Some(rewritten) = rewrite_refresh(&value, &entry.proxy_redirect) {
                        value = rewritten;
                    }
                } else if name == SET_COOKIE {
                    value = rewrite_cookie(&value, &entry.cookie_domain, &entry.cookie_path);
                }
                headers.append(name, value);
            }
            headers.insert(SERVER, HeaderValue::from_static("elira"));

            if let Some(encoding) = compress_with {
                headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding));
                headers.append(VARY, HeaderValue::from_static("accept-encoding"));
            }

            // A 101 without these two headers is a 101 the client cannot
            // act on. They are hop-by-hop, so they were stripped above.
            if parts.status == StatusCode::SWITCHING_PROTOCOLS {
                if let Some(upgrade) = requested_upgrade {
                    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
                    headers.insert(UPGRADE, upgrade.clone());
                }
            }
        }

        let body = if response_cap > 0 {
            capped_body(body, response_cap)
        } else {
            body
        };

        let status_code = parts.status.as_u16();
        let explicitly_valid = entry
            .cache_valid
            .iter()
            .any(|valid| valid.statuses.contains(&status_code));
        let store_ttl = entry.cache_ttl_for(status_code);
        let cacheable = self.inner.cache.is_some()
            && cache_allowed
            && is_get
            && requested_upgrade.is_none()
            && (status_code == StatusCode::OK.as_u16() || explicitly_valid)
            && upstream_len
                .map(|length| {
                    length <= self.inner.cache_max_item
                        && (response_cap == 0 || length <= response_cap)
                })
                .unwrap_or(false)
            && cacheable_response(&parts.headers);

        let body = if cacheable {
            let collected = match BodyExt::collect(body).await {
                Ok(collected) => collected.to_bytes(),
                Err(err) => {
                    tracing::warn!(error = %err, "failed to buffer a cacheable response");
                    return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                }
            };

            if let Some(cache) = &self.inner.cache {
                cache.insert_with_ttl(
                    cache_key,
                    request_headers,
                    &parts.headers,
                    parts.status.as_u16(),
                    collected.to_vec(),
                    Instant::now(),
                    store_ttl,
                );
            }

            Full::new(collected).map_err(|never| match never {}).boxed()
        } else {
            body
        };

        // Buffer small complete responses so the upstream socket is free
        // before a slow client finishes reading. Larger bodies up to the
        // spool limit go to an unlinked temporary file; anything beyond that
        // streams straight through.
        let body = if !cacheable && !is_head {
            match upstream_len {
                Some(length)
                    if self.inner.buffer_bytes > 0 && length <= self.inner.buffer_bytes =>
                {
                    match BodyExt::collect(body).await {
                        Ok(collected) => Full::new(collected.to_bytes())
                            .map_err(|never| match never {})
                            .boxed(),
                        Err(err) => {
                            tracing::warn!(error = %err, "failed to buffer an upstream response");
                            return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                        }
                    }
                }
                Some(length)
                    if self.inner.spool_bytes > 0
                        && length > self.inner.buffer_bytes
                        && length <= self.inner.spool_bytes =>
                {
                    match self.inner.spool_budget.reserve(length as u64) {
                        Some(permit) => match spool_body(body, length, permit).await {
                            Ok(body) => {
                                self.inner.spooled.fetch_add(1, Ordering::Relaxed);
                                body
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "failed to spool an upstream response");
                                return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
                            }
                        },
                        None => {
                            tracing::debug!(
                                length,
                                "spool budget exhausted, streaming the response"
                            );
                            body
                        }
                    }
                }
                _ => body,
            }
        } else {
            body
        };

        let body = if let Some(encoding) = compress_with {
            compress(body, encoding)
        } else {
            body
        };

        let body = match self.inner.body_timeout {
            Some(idle) => timeout_body(body, idle),
            None => body,
        };
        let body = match proxy_permit {
            Some(permit) => PermitBody {
                inner: body,
                _permit: permit,
            }
            .boxed(),
            None => body,
        };
        let mut response = builder
            .body(body)
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))?;

        if self.inner.cache.is_some() && cache_allowed && is_get && requested_upgrade.is_none() {
            response
                .headers_mut()
                .insert("x-cache", HeaderValue::from_static("MISS"));
        }

        response.extensions_mut().insert(Labels {
            route: entry.label.clone(),
            upstream: Some(pool.name.clone()),
            access_log: entry.access_log,
            access_log_sample: entry.access_log_sample,
        });
        self.apply_error_page(&mut response, entry, vars, peer)
            .await;
        self.apply_route(&mut response, entry, vars, request_id);
        Ok(response)
    }
}

fn variable_or_empty(vars: &RequestVars, template: &str) -> String {
    if let Some(name) = template.strip_prefix('$') {
        if !name.is_empty() && !name.contains('$') && !name.contains('{') {
            return vars
                .value(name)
                .map(|value| value.into_owned())
                .unwrap_or_default();
        }
    }
    vars.render(template)
}

fn rewrite_prefix(value: &HeaderValue, rules: &[(String, String)]) -> Option<HeaderValue> {
    let text = value.to_str().ok()?;
    for (from, to) in rules {
        if let Some(rest) = text.strip_prefix(from) {
            return HeaderValue::from_str(&format!("{to}{rest}")).ok();
        }
    }
    None
}

fn rewrite_refresh(value: &HeaderValue, rules: &[(String, String)]) -> Option<HeaderValue> {
    let text = value.to_str().ok()?;
    let (head, url) = text.split_once("url=")?;
    let rewritten = rewrite_prefix(&HeaderValue::from_str(url).ok()?, rules)?;
    HeaderValue::from_str(&format!("{head}url={}", rewritten.to_str().ok()?)).ok()
}

fn rewrite_cookie(
    value: &HeaderValue,
    domains: &[(String, String)],
    paths: &[(String, String)],
) -> HeaderValue {
    let Ok(text) = value.to_str() else {
        return value.clone();
    };
    let mut out = String::new();
    for (index, part) in text.split(';').enumerate() {
        if index > 0 {
            out.push(';');
        }
        let part = part.trim();
        if let Some((name, attribute)) = part.split_once('=') {
            let replacement = if name.eq_ignore_ascii_case("domain") {
                match_domain(attribute, domains)
            } else if name.eq_ignore_ascii_case("path") {
                match_path(attribute, paths)
            } else {
                None
            };
            if let Some(attribute) = replacement {
                out.push(' ');
                out.push_str(name);
                out.push('=');
                out.push_str(&attribute);
                continue;
            }
        }
        out.push(' ');
        out.push_str(part);
    }
    HeaderValue::from_str(out.trim_start()).unwrap_or_else(|_| value.clone())
}

fn match_domain(value: &str, rules: &[(String, String)]) -> Option<String> {
    for (from, to) in rules {
        if value.eq_ignore_ascii_case(from) {
            return Some(to.clone());
        }
        let suffix = format!(".{}", from.to_ascii_lowercase());
        if value.to_ascii_lowercase().ends_with(&suffix) {
            return Some(format!("{to}{}", &value[value.len() - suffix.len()..]));
        }
    }
    None
}

fn match_path(value: &str, rules: &[(String, String)]) -> Option<String> {
    for (from, to) in rules {
        if let Some(rest) = value.strip_prefix(from) {
            return Some(format!("{to}{rest}"));
        }
    }
    None
}
