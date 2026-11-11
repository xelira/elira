//! Raw upgrade tunnels: websockets, CONNECT and protocol switches.
//!
//! An upgrade bypasses the HTTP client pool: the request head is written by
//! hand, the 101 is parsed before hyper sees a response, and both directions
//! are copied directly.

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_LENGTH, SERVER, UPGRADE};
use http::uri::Authority;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use crate::*;

/// Why a CONNECT target was refused.
#[derive(Debug, Clone, Copy)]
pub enum ConnectError {
    Disabled,
    Forbidden,
    BadTarget,
}

impl ConnectError {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Disabled => StatusCode::METHOD_NOT_ALLOWED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::BadTarget => StatusCode::BAD_REQUEST,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Disabled => "CONNECT is disabled",
            Self::Forbidden => "CONNECT target is not allowed",
            Self::BadTarget => "CONNECT needs host:port",
        }
    }
}

impl Proxy {
    /// Validate a CONNECT target without opening the tunnel. The HTTP/3 path
    /// uses this and then owns the QUIC stream directly.
    pub fn connect_target<B>(&self, req: &Request<B>) -> Result<String, ConnectError> {
        let allowed = self.inner.connect.as_ref().ok_or(ConnectError::Disabled)?;
        let target = req
            .uri()
            .authority()
            .map(|value| value.as_str().to_owned())
            // hyper may hand authority-form CONNECT targets via the path.
            .or_else(|| {
                req.uri()
                    .path()
                    .parse::<Authority>()
                    .ok()
                    .map(|value| value.as_str().to_owned())
            })
            .ok_or(ConnectError::BadTarget)?;
        if !allowed.iter().any(|entry| entry.as_str() == target) {
            return Err(ConnectError::Forbidden);
        }
        Ok(target)
    }

    /// CONNECT is only useful when the target is already trusted; anything
    /// else turns the proxy into an open relay.
    pub(crate) async fn connect(
        &self,
        mut req: Request<Body>,
    ) -> Result<Response<Body>, Response<Body>> {
        let target = self
            .connect_target(&req)
            .map_err(|error| text(error.status(), error.message()))?;

        let permit = match self.inner.tunnels.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Err(text(StatusCode::SERVICE_UNAVAILABLE, "too many tunnels")),
        };

        let mut stream =
            match tokio::time::timeout(self.inner.timeout, TcpStream::connect(target.as_str()))
                .await
            {
                Ok(Ok(stream)) => stream,
                _ => return Err(text(StatusCode::BAD_GATEWAY, "cannot reach the target")),
            };

        let client_upgrade = hyper::upgrade::on(&mut req);
        let idle = self.inner.tunnel_idle;

        tokio::spawn(async move {
            let _permit = permit;
            match client_upgrade.await {
                Ok(client) => {
                    let mut client = TokioIo::new(client);
                    if let Err(err) = tunnel(&mut client, &mut stream, idle).await {
                        tracing::debug!(error = %err, "CONNECT tunnel closed");
                    }
                }
                Err(err) => tracing::debug!(error = %err, "CONNECT upgrade failed"),
            }
        });

        let body = Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed();
        Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }

    /// Upgrades cannot go through the connection pool: hyper has to hand the
    /// socket over instead of returning it. Open a raw connection and tunnel.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn forward_upgrade(
        &self,
        upstream: Request<Body>,
        client_upgrade: crate::ClientUpgrade,
        upgrade: HeaderValue,
        server: ServerAddr,
        connect_timeout: Duration,
        bind: Option<std::net::IpAddr>,
        resolver: &elira_upstream::Resolver,
        proxy_protocol: bool,
        peer: SocketAddr,
        timeout: Duration,
        client_permit: Option<tokio::sync::OwnedSemaphorePermit>,
        extended_connect: bool,
        hold: Option<Box<dyn Send + Sync>>,
    ) -> Result<Response<Body>, Response<Body>> {
        // Tunnels outlive the connection task that the accept loop tracks,
        // so they need their own bound.
        let permit = match self.inner.tunnels.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Err(text(StatusCode::SERVICE_UNAVAILABLE, "too many tunnels")),
        };

        let mut stream = match connect_server(&server, connect_timeout, bind, resolver).await {
            Some(stream) => stream,
            None => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
        };

        if proxy_protocol {
            if let EitherStream::Tcp(tcp) = &mut stream {
                let dest = match tcp.peer_addr() {
                    Ok(dest) => dest,
                    Err(_) => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
                };
                let header = crate::pool::proxy_header(peer, dest);
                match tokio::time::timeout(connect_timeout, tcp.write_all(&header)).await {
                    Ok(Ok(())) => {}
                    _ => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
                }
            }
        }

        let head = serialize_head(&upstream);
        match tokio::time::timeout(timeout, stream.write_all(head.as_bytes())).await {
            Ok(Ok(())) => {}
            _ => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
        }

        let (status, mut headers, upstream_upgrade, leftover) =
            read_head(&mut stream, timeout).await?;

        if status != StatusCode::SWITCHING_PROTOCOLS {
            if extended_connect {
                return Err(text(
                    StatusCode::BAD_GATEWAY,
                    "upstream refused the upgrade",
                ));
            }
            // The upstream refused the upgrade. Pass the answer through with
            // an empty body; upgrade attempts are small and rare.
            headers.insert(SERVER, HeaderValue::from_static("elira"));
            let body = Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed();
            return Response::builder()
                .status(status)
                .body(body)
                .map(|mut response| {
                    *response.headers_mut() = headers;
                    response
                })
                .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"));
        }

        // The upstream decides which protocol it accepted.
        let upgrade = upstream_upgrade.unwrap_or(upgrade);
        if !extended_connect {
            headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
            headers.insert(UPGRADE, upgrade);
        }
        headers.insert(SERVER, HeaderValue::from_static("elira"));

        let idle = self.inner.tunnel_idle;

        tokio::spawn(async move {
            let _permit = permit;
            let _client_permit = client_permit;
            let _hold = hold;
            let client = match client_upgrade {
                crate::ClientUpgrade::Hyper(upgrade) => upgrade
                    .await
                    .map(|client| Box::new(TokioIo::new(client)) as crate::UpgradeStream)
                    .map_err(|err| err.to_string()),
                crate::ClientUpgrade::External(upgrade) => {
                    upgrade.await.map_err(|err| err.to_string())
                }
            };
            match client {
                Ok(mut client) => {
                    let mut upstream = stream;
                    // Bytes the upstream sent right after the 101 would
                    // otherwise be dropped by the copy loop.
                    if !leftover.is_empty() && client.write_all(&leftover).await.is_err() {
                        return;
                    }
                    if let Err(err) = tunnel(&mut client, &mut upstream, idle).await {
                        tracing::debug!(error = %err, "tunnel closed");
                    }
                }
                Err(err) => tracing::debug!(error = %err, "client upgrade failed"),
            }
        });

        let body = Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed();
        let status = if extended_connect {
            StatusCode::OK
        } else {
            StatusCode::SWITCHING_PROTOCOLS
        };
        Response::builder()
            .status(status)
            .body(body)
            .map(|mut response| {
                *response.headers_mut() = headers;
                response
            })
            .map_err(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
    }
}

pub(crate) async fn read_head<S>(
    stream: &mut S,
    timeout: Duration,
) -> Result<(StatusCode, HeaderMap, Option<HeaderValue>, Vec<u8>), Response<Body>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let read = match tokio::time::timeout(timeout, stream.read(&mut chunk)).await {
            Ok(Ok(read)) => read,
            _ => return Err(text(StatusCode::BAD_GATEWAY, "bad gateway")),
        };
        if read == 0 {
            return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
        }
        buf.extend_from_slice(&chunk[..read]);

        while let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let rest = buf[end + 4..].to_vec();
            let mut lines = head.split("\r\n");
            let status_line = lines.next().unwrap_or_default();
            let code = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or(502);
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY);

            // 100 Continue and 103 Early Hints are not the answer.
            if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
                buf = rest;
                continue;
            }

            let mut raw = HeaderMap::new();
            for line in lines {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) else {
                    continue;
                };
                let Ok(value) = HeaderValue::from_str(value.trim()) else {
                    continue;
                };
                raw.append(name, value);
            }

            let upgrade = raw.get(UPGRADE).cloned();
            let tokens = connection_tokens(&raw);

            let mut headers = HeaderMap::new();
            for (name, value) in raw.iter() {
                if is_hop_by_hop(name) || tokens.contains(name) || name == CONTENT_LENGTH {
                    continue;
                }
                headers.append(name, value.clone());
            }

            return Ok((status, headers, upgrade, rest));
        }

        if buf.len() > 64 * 1024 {
            return Err(text(StatusCode::BAD_GATEWAY, "bad gateway"));
        }
    }
}

pub(crate) enum EitherStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl AsyncRead for EitherStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for EitherStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

async fn connect_server(
    server: &ServerAddr,
    timeout: Duration,
    bind: Option<std::net::IpAddr>,
    resolver: &elira_upstream::Resolver,
) -> Option<EitherStream> {
    match server {
        ServerAddr::Tcp(authority) => {
            let host = authority
                .host()
                .trim_start_matches('[')
                .trim_end_matches(']');
            let port = authority.port_u16().unwrap_or(80);
            match tokio::time::timeout(
                timeout,
                elira_upstream::tcp_connect(host, port, bind, Some(resolver)),
            )
            .await
            {
                Ok(Ok(stream)) => Some(EitherStream::Tcp(stream)),
                _ => None,
            }
        }
        ServerAddr::Unix(path) => {
            match tokio::time::timeout(timeout, UnixStream::connect(path)).await {
                Ok(Ok(stream)) => Some(EitherStream::Unix(stream)),
                _ => None,
            }
        }
    }
}

/// Copy bytes both ways, closing the tunnel after `idle` without traffic.
pub(crate) async fn tunnel<A, B>(
    a: &mut A,
    b: &mut B,
    idle: Option<Duration>,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let forward = pipe(&mut a_read, &mut b_write, idle);
    let backward = pipe(&mut b_read, &mut a_write, idle);
    tokio::pin!(forward);
    tokio::pin!(backward);

    tokio::select! {
        result = &mut forward => result,
        result = &mut backward => result,
    }
}

pub(crate) async fn pipe<R, W>(
    read: &mut R,
    write: &mut W,
    idle: Option<Duration>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let read = match idle {
            Some(idle) => match tokio::time::timeout(idle, read.read(&mut buf)).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "tunnel idle",
                    ))
                }
            },
            None => read.read(&mut buf).await?,
        };
        if read == 0 {
            return Ok(());
        }
        write.write_all(&buf[..read]).await?;
        write.flush().await?;
    }
}
