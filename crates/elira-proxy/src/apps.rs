//! FastCGI, CGI and dynamic module targets.

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

impl Proxy {
    /// Streaming FastCGI path: the request body goes to STDIN as it arrives
    /// and the response body leaves through a bounded channel.
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
            ("SERVER_NAME".to_owned(), server_name),
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
        let content_length = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("0");
        params.push(("CONTENT_LENGTH".to_owned(), content_length.to_owned()));
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name) || *name == CONTENT_TYPE || *name == CONTENT_LENGTH {
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

        let (target, root, index) = match &entry.target {
            Target::FastCgi {
                target,
                root,
                index,
            } => (target, root, index),
            _ => return text(StatusCode::INTERNAL_SERVER_ERROR, "bad target"),
        };
        let script = match application_script(root, path, index) {
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

        let fastcgi_pool = entry
            .fastcgi_pool
            .as_deref()
            .unwrap_or(&self.inner.fastcgi_pool);
        let response = match fastcgi_pool
            .execute_stream(
                target,
                params,
                request_body,
                timeout,
                entry.max_response.unwrap_or(self.inner.max_app_response),
            )
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

    /// Streaming CGI path: stdin and stdout are piped, headers are parsed
    /// before the body is handed to hyper.
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
            ("SERVER_NAME".to_owned(), server_name),
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
        let content_length = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("0");
        params.push(("CONTENT_LENGTH".to_owned(), content_length.to_owned()));
        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name) || *name == CONTENT_TYPE || *name == CONTENT_LENGTH {
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

        let response = match elira_cgi::execute_stream(
            elira_cgi::StreamRequest {
                script: script.clone(),
                params,
                body: request_body,
                timeout,
            },
            entry.max_response.unwrap_or(self.inner.max_app_response),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = %err, "CGI streaming request failed");
                return text(StatusCode::BAD_GATEWAY, "CGI request failed");
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

    /// Run a FastCGI, CGI or dynamic-module route. These targets cannot be
    /// streamed into and out of hyper without buffering, so the body is
    /// bounded by the same limit as a normal request.
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
        let body = match BodyExt::collect(body).await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                tracing::warn!(error = %err, "failed to read the application body");
                return text(StatusCode::BAD_GATEWAY, "bad request body");
            }
        };
        if limit > 0 && body.len() > limit {
            return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        }

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
            ("SERVER_NAME".to_owned(), server_name),
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
            if is_hop_by_hop(name) || *name == CONTENT_TYPE || *name == CONTENT_LENGTH {
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

        let timeout = entry.timeout.unwrap_or(self.inner.timeout);
        let result = match &entry.target {
            Target::FastCgi {
                target,
                root,
                index,
            } => {
                let mut script = match application_script(root, path, index) {
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
                let result = match module {
                    ModuleTarget::InProcess(module) => module.call(&request),
                    ModuleTarget::Sandbox(module) => module.call(&request),
                };
                match result {
                    Ok(response) => app_result(response.status, response.headers, response.body),
                    Err(err) => {
                        tracing::warn!(error = %err, "module request failed");
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
            _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
        };

        match result {
            Ok(response) => response,
            Err(status) => text(status, "application request failed"),
        }
    }
}

fn application_script(root: &Path, path: &str, index: &str) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    let mut relative = PathBuf::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            segment if segment.contains('\0') || segment.contains('\\') => return None,
            segment => relative.push(segment),
        }
    }
    if decoded.ends_with('/') || relative.as_os_str().is_empty() {
        relative.push(index);
    }
    Some(root.join(relative))
}

/// `BoxBody` requires `Sync`; an application response stream is only `Send`.
/// Serialising polling through a mutex gives the type system the guarantee it
/// wants without buffering the body.
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
    if limit == 0 {
        return stream.boxed();
    }
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
