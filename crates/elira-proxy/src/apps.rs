use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::stream::BoxStream;
use futures_util::{StreamExt, TryStreamExt};
use http::header::{HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE, HOST, SERVER};
use http::{Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};

use crate::*;

const HARD_BODY_LIMIT: usize = 16 * 1024 * 1024;

impl Proxy {
    pub(crate) async fn serve_fastcgi(
        &self,
        req: Request<Body>,
        entry: &RouteEntry,
        peer: SocketAddr,
        scheme: &'static str,
    ) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let method = parts.method.as_str();
        let path = parts.uri.path();
        let query = parts.uri.query().unwrap_or_default();
        let host_header = parts
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let (server_name, port) = match canonical_host(host_header) {
            Some((host, forwarded)) => {
                let port = forwarded
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                (host, port)
            }
            None => (String::new(), if scheme == "https" { 443 } else { 80 }),
        };

        let mut params = vec![
            ("GATEWAY_INTERFACE".to_owned(), "CGI/1.1".to_owned()),
            ("SERVER_SOFTWARE".to_owned(), "elira".to_owned()),
            ("SERVER_PROTOCOL".to_owned(), format!("{:?}", parts.version)),
            ("REQUEST_METHOD".to_owned(), method.to_owned()),
            ("REQUEST_URI".to_owned(), parts.uri.to_string()),
            ("QUERY_STRING".to_owned(), query.to_owned()),
            ("SERVER_NAME".to_owned(), server_name.clone()),
            ("SERVER_PORT".to_owned(), port.to_string()),
            ("REMOTE_ADDR".to_owned(), peer.ip().to_string()),
            ("REMOTE_PORT".to_owned(), peer.port().to_string()),
        ];
        if let Some(value) = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            params.push(("CONTENT_TYPE".to_owned(), value.to_owned()));
        }
        if let Some(value) = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
        {
            params.push(("CONTENT_LENGTH".to_owned(), value.to_owned()));
        }
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name)
                || *name == CONTENT_TYPE
                || *name == CONTENT_LENGTH
                || is_forwarding_header(name)
            {
                continue;
            }
            if let Ok(value) = value.to_str() {
                params.push((
                    format!(
                        "HTTP_{}",
                        name.as_str().to_ascii_uppercase().replace('-', "_")
                    ),
                    value.to_owned(),
                ));
            }
        }

        append_forwarded_params(&mut params, peer, scheme);

        let (target, root, index) = match &entry.target {
            Target::FastCgi {
                target,
                root,
                index,
            } => (target, root, index),
            _ => return text(StatusCode::INTERNAL_SERVER_ERROR, "bad target"),
        };
        let script = match application_script(root, path, index).await {
            Some(script) => script,
            None => return text(StatusCode::BAD_REQUEST, "bad script path"),
        };
        params.push(("SCRIPT_FILENAME".to_owned(), script.display().to_string()));
        params.push(("SCRIPT_NAME".to_owned(), path.to_owned()));
        params.push(("DOCUMENT_ROOT".to_owned(), root.display().to_string()));
        params.extend(entry.fastcgi_param.iter().cloned());

        let limit = entry.body_limit.unwrap_or(self.inner.max_body_bytes);
        let request_body = body.into_data_stream().boxed();
        let request_body = limit_body(request_body, limit).boxed();
        let timeout = entry.timeout.unwrap_or(self.inner.timeout);

        let max_response = entry.max_response.unwrap_or(self.inner.max_app_response);

        if let Some(mux) = &entry.fastcgi_mux {
            let mut stream = request_body;
            let mut body = Vec::new();
            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(chunk) => body.extend_from_slice(&chunk),
                    Err(err) => {
                        tracing::warn!(error = %err, "FastCGI request body failed");
                        return text(StatusCode::BAD_GATEWAY, "FastCGI request failed");
                    }
                }
            }
            return match mux
                .execute(target, &params, &body, timeout, max_response)
                .await
            {
                Ok(response) => app_result(response.status, response.headers, response.body)
                    .unwrap_or_else(|status| text(status, "FastCGI response failed")),
                Err(err) => {
                    tracing::warn!(error = %err, "FastCGI multiplexed request failed");
                    text(StatusCode::BAD_GATEWAY, "FastCGI request failed")
                }
            };
        }

        let fastcgi_pool = entry
            .fastcgi_pool
            .as_deref()
            .unwrap_or(&self.inner.fastcgi_pool);
        let response = match fastcgi_pool
            .execute_stream(target, params, request_body, timeout, max_response)
            .await
        {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = %err, "FastCGI streaming request failed");
                return text(StatusCode::BAD_GATEWAY, "FastCGI request failed");
            }
        };

        let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut builder = Response::builder().status(status);
        {
            let Some(headers) = builder.headers_mut() else {
                return text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed");
            };
            for (name, value) in &response.headers {
                let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                if is_hop_by_hop(&name) || name == CONTENT_LENGTH {
                    continue;
                }
                if let Ok(value) = HeaderValue::from_str(value) {
                    headers.append(name, value);
                }
            }
            headers.insert(SERVER, HeaderValue::from_static("elira"));
        }
        let streamed =
            StreamBody::new(SharedStream(std::sync::Mutex::new(response.body)).map_ok(Frame::data));
        let body = BodyExt::map_err(streamed, |err| -> BoxError { err }).boxed();
        builder
            .body(body)
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }

    pub(crate) async fn serve_cgi(
        &self,
        req: Request<Body>,
        entry: &RouteEntry,
        peer: SocketAddr,
        scheme: &'static str,
    ) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let method = parts.method.as_str();
        let path = parts.uri.path();
        let query = parts.uri.query().unwrap_or_default();
        let host_header = parts
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let (server_name, port) = match canonical_host(host_header) {
            Some((host, forwarded)) => {
                let port = forwarded
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                (host, port)
            }
            None => (String::new(), if scheme == "https" { 443 } else { 80 }),
        };

        let mut params = vec![
            ("GATEWAY_INTERFACE".to_owned(), "CGI/1.1".to_owned()),
            ("SERVER_SOFTWARE".to_owned(), "elira".to_owned()),
            ("SERVER_PROTOCOL".to_owned(), format!("{:?}", parts.version)),
            ("REQUEST_METHOD".to_owned(), method.to_owned()),
            ("REQUEST_URI".to_owned(), parts.uri.to_string()),
            ("QUERY_STRING".to_owned(), query.to_owned()),
            ("SERVER_NAME".to_owned(), server_name.clone()),
            ("SERVER_PORT".to_owned(), port.to_string()),
            ("REMOTE_ADDR".to_owned(), peer.ip().to_string()),
            ("REMOTE_PORT".to_owned(), peer.port().to_string()),
        ];
        if let Some(value) = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            params.push(("CONTENT_TYPE".to_owned(), value.to_owned()));
        }
        if let Some(value) = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
        {
            params.push(("CONTENT_LENGTH".to_owned(), value.to_owned()));
        }
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name)
                || *name == CONTENT_TYPE
                || *name == CONTENT_LENGTH
                || is_forwarding_header(name)
            {
                continue;
            }
            if let Ok(value) = value.to_str() {
                params.push((
                    format!(
                        "HTTP_{}",
                        name.as_str().to_ascii_uppercase().replace('-', "_")
                    ),
                    value.to_owned(),
                ));
            }
        }

        append_forwarded_params(&mut params, peer, scheme);

        let script = match &entry.target {
            Target::Cgi { script } => script,
            _ => return text(StatusCode::INTERNAL_SERVER_ERROR, "bad target"),
        };
        params.push(("SCRIPT_FILENAME".to_owned(), script.display().to_string()));
        params.push(("SCRIPT_NAME".to_owned(), script.display().to_string()));
        params.push(("PATH_INFO".to_owned(), path.to_owned()));
        params.extend(entry.cgi_param.iter().cloned());

        let limit = entry.body_limit.unwrap_or(self.inner.max_body_bytes);
        let request_body = body.into_data_stream().boxed();
        let request_body = limit_body(request_body, limit).boxed();
        let timeout = entry.timeout.unwrap_or(self.inner.timeout);

        let response = match tokio::time::timeout(
            timeout,
            elira_cgi::execute_stream(
                elira_cgi::StreamRequest {
                    script: script.clone(),
                    params,
                    body: request_body,
                    timeout,
                },
                entry.max_response.unwrap_or(self.inner.max_app_response),
            ),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "CGI streaming request failed");
                return text(StatusCode::BAD_GATEWAY, "CGI request failed");
            }
            Err(_) => {
                return text(StatusCode::GATEWAY_TIMEOUT, "CGI request timed out");
            }
        };

        let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut builder = Response::builder().status(status);
        {
            let Some(headers) = builder.headers_mut() else {
                return text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed");
            };
            for (name, value) in &response.headers {
                let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                if is_hop_by_hop(&name) || name == CONTENT_LENGTH {
                    continue;
                }
                if let Ok(value) = HeaderValue::from_str(value) {
                    headers.append(name, value);
                }
            }
            headers.insert(SERVER, HeaderValue::from_static("elira"));
        }
        let streamed =
            StreamBody::new(SharedStream(std::sync::Mutex::new(response.body)).map_ok(Frame::data));
        let body = BodyExt::map_err(streamed, |err| -> BoxError { err }).boxed();
        builder
            .body(body)
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }

    pub(crate) async fn serve_app(
        &self,
        req: Request<Body>,
        entry: &RouteEntry,
        peer: SocketAddr,
        scheme: &'static str,
    ) -> Response<Body> {
        let _permit = match &entry.app_permits {
            Some(permits) => match permits.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => return text(StatusCode::SERVICE_UNAVAILABLE, "too many app requests"),
            },
            None => None,
        };
        let (parts, body) = req.into_parts();
        let limit = entry.body_limit.unwrap_or(self.inner.max_body_bytes);
        let limit = if limit == 0 { HARD_BODY_LIMIT } else { limit };
        if let Some(length) = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
        {
            if length > limit {
                return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
            }
        }
        let mut collected = Vec::new();
        let mut body = body;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        if collected.len().saturating_add(data.len()) > limit {
                            return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
                        }
                        collected.extend_from_slice(&data);
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "failed to read the application body");
                    return text(StatusCode::BAD_GATEWAY, "bad request body");
                }
            }
        }
        let body = bytes::Bytes::from(collected);

        let method = parts.method.as_str();
        let path = parts.uri.path();
        let query = parts.uri.query().unwrap_or_default();
        let host_header = parts
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let (server_name, port) = match canonical_host(host_header) {
            Some((host, forwarded)) => {
                let port = forwarded
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                (host, port)
            }
            None => (String::new(), if scheme == "https" { 443 } else { 80 }),
        };

        let mut params = vec![
            ("GATEWAY_INTERFACE".to_owned(), "CGI/1.1".to_owned()),
            ("SERVER_SOFTWARE".to_owned(), "elira".to_owned()),
            ("SERVER_PROTOCOL".to_owned(), format!("{:?}", parts.version)),
            ("REQUEST_METHOD".to_owned(), method.to_owned()),
            ("REQUEST_URI".to_owned(), parts.uri.to_string()),
            ("QUERY_STRING".to_owned(), query.to_owned()),
            ("SERVER_NAME".to_owned(), server_name.clone()),
            ("SERVER_PORT".to_owned(), port.to_string()),
            ("REMOTE_ADDR".to_owned(), peer.ip().to_string()),
            ("REMOTE_PORT".to_owned(), peer.port().to_string()),
        ];
        if let Some(value) = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            params.push(("CONTENT_TYPE".to_owned(), value.to_owned()));
        }
        params.push(("CONTENT_LENGTH".to_owned(), body.len().to_string()));
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name)
                || *name == CONTENT_TYPE
                || *name == CONTENT_LENGTH
                || is_forwarding_header(name)
            {
                continue;
            }
            if let Ok(value) = value.to_str() {
                params.push((
                    format!(
                        "HTTP_{}",
                        name.as_str().to_ascii_uppercase().replace('-', "_")
                    ),
                    value.to_owned(),
                ));
            }
        }

        append_forwarded_params(&mut params, peer, scheme);

        let timeout = entry.timeout.unwrap_or(self.inner.timeout);
        let result = match &entry.target {
            Target::FastCgi {
                target,
                root,
                index,
            } => {
                let mut script = match application_script(root, path, index).await {
                    Some(script) => script,
                    None => return text(StatusCode::BAD_REQUEST, "bad script path"),
                };
                let _ = &mut script;
                params.push(("SCRIPT_FILENAME".to_owned(), script.display().to_string()));
                params.push(("SCRIPT_NAME".to_owned(), path.to_owned()));
                params.push(("DOCUMENT_ROOT".to_owned(), root.display().to_string()));
                match elira_fastcgi::execute(
                    target,
                    &elira_fastcgi::Request {
                        params,
                        body: body.to_vec(),
                    },
                    timeout,
                )
                .await
                {
                    Ok(response) => app_result(response.status, response.headers, response.body),
                    Err(err) => {
                        tracing::warn!(error = %err, "FastCGI request failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            Target::Cgi { .. } => Err(StatusCode::INTERNAL_SERVER_ERROR),
            Target::Module(module) => {
                let request = module_request(&parts, method, path, query, host_header, &body, peer);
                let module = match module {
                    ModuleTarget::InProcess(module) => ModuleTarget::InProcess(module.clone()),
                    ModuleTarget::Sandbox(module) => ModuleTarget::Sandbox(module.clone()),
                };
                let result = tokio::task::spawn_blocking(move || match module {
                    ModuleTarget::InProcess(module) => module.call(&request),
                    ModuleTarget::Sandbox(module) => module.call(&request),
                })
                .await;
                match result {
                    Ok(Ok(response)) => {
                        app_result(response.status, response.headers, response.body)
                    }
                    Ok(Err(err)) => {
                        tracing::warn!(error = %err, "module request failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "module task failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            Target::Wasm(module) => {
                let request = module_request(&parts, method, path, query, host_header, &body, peer);
                match module.call(&request) {
                    Ok(response) => app_result(response.status, response.headers, response.body),
                    Err(err) => {
                        tracing::warn!(error = %err, "wasm module request failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            Target::Scgi { target, root } => {
                if let Some(root) = root {
                    params.push(("DOCUMENT_ROOT".to_owned(), root.display().to_string()));
                }
                params.extend(entry.scgi_param.iter().cloned());
                match crate::scgi::execute(
                    target,
                    &params,
                    &body,
                    timeout,
                    entry.max_response.unwrap_or(self.inner.max_app_response),
                )
                .await
                {
                    Ok(response) => app_result(response.status, response.headers, response.body),
                    Err(err) => {
                        tracing::warn!(error = %err, "SCGI request failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            Target::Uwsgi {
                target,
                modifier1,
                modifier2,
            } => {
                params.extend(entry.uwsgi_param.iter().cloned());
                match crate::uwsgi::execute(
                    target,
                    *modifier1,
                    *modifier2,
                    &params,
                    &body,
                    timeout,
                    entry.max_response.unwrap_or(self.inner.max_app_response),
                )
                .await
                {
                    Ok(response) => app_result(response.status, response.headers, response.body),
                    Err(err) => {
                        tracing::warn!(error = %err, "uWSGI request failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            Target::Ajp { target, secret } => {
                let mut headers: Vec<(String, String)> = parts
                    .headers
                    .iter()
                    .filter(|(name, _)| !is_hop_by_hop(name) && !is_forwarding_header(name))
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.as_str().to_owned(), value.to_owned()))
                    })
                    .collect();
                headers.push(("x-forwarded-for".to_owned(), peer.ip().to_string()));
                headers.push(("x-real-ip".to_owned(), peer.ip().to_string()));
                headers.push(("x-forwarded-proto".to_owned(), scheme.to_owned()));
                let request = crate::ajp::Request {
                    method,
                    protocol: format!("{:?}", parts.version),
                    uri: path,
                    query,
                    remote_addr: peer.ip().to_string(),
                    server_name: &server_name,
                    server_port: port,
                    secure: scheme == "https",
                    headers: &headers,
                    secret: secret.as_deref(),
                    body: &body,
                };
                match crate::ajp::execute(
                    target,
                    &request,
                    timeout,
                    entry.max_response.unwrap_or(self.inner.max_app_response),
                )
                .await
                {
                    Ok(response) => app_result(response.status, response.headers, response.body),
                    Err(err) => {
                        tracing::warn!(error = %err, "AJP request failed");
                        Err(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
        };

        match result {
            Ok(response) => response,
            Err(status) => text(status, "application request failed"),
        }
    }
}

async fn application_script(root: &Path, path: &str, index: &str) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    let mut relative = PathBuf::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            segment if segment.contains('\0') || segment.contains('\\') => return None,
            segment if segment.starts_with('.') && segment != ".well-known" => return None,
            segment => relative.push(segment),
        }
    }
    if decoded.ends_with('/') || relative.as_os_str().is_empty() {
        relative.push(index);
    }
    let root = tokio::fs::canonicalize(root).await.ok()?;
    let candidate = root.join(relative);
    match tokio::fs::canonicalize(&candidate).await {
        Ok(resolved) if resolved.starts_with(&root) => Some(resolved),
        Ok(_) => None,
        Err(_) => Some(candidate),
    }
}

struct SharedStream<S>(std::sync::Mutex<S>);

impl<S: futures_util::Stream + Unpin> futures_util::Stream for SharedStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let stream = this
            .0
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Pin::new(stream).poll_next(cx)
    }
}

fn limit_body(
    stream: elira_fastcgi::BodyStream,
    limit: usize,
) -> BoxStream<'static, Result<Bytes, elira_fastcgi::BoxError>> {
    let limit = if limit == 0 { HARD_BODY_LIMIT } else { limit };
    futures_util::stream::unfold(
        (stream, 0usize, limit),
        |(mut stream, total, limit)| async move {
            match stream.next().await {
                Some(Ok(chunk)) => {
                    let total = total + chunk.len();
                    if total > limit {
                        Some((
                            Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "request body too large",
                            )) as elira_fastcgi::BoxError),
                            (stream, total, limit),
                        ))
                    } else {
                        Some((Ok(chunk), (stream, total, limit)))
                    }
                }
                Some(Err(err)) => Some((Err(err), (stream, total, limit))),
                None => None,
            }
        },
    )
    .boxed()
}
