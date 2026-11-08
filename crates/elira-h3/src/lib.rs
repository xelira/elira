//! HTTP/3 listener.
//!
//! HTTP/3 runs on QUIC over UDP and shares nothing with the TCP listener but
//! the routing table. Request bodies are buffered up to a limit; streaming
//! them would need a body type that is not `Sync`, which the hyper client used
//! for the upstream hop does not accept.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body::{Body as _, Frame};
use http_body_util::{BodyExt, StreamBody};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;

use elira_accesslog::{request_id, Entry};
use elira_config::LogFormat;
use elira_proxy::{BoxError, Proxy};

pub struct Config {
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub reuse_port: bool,
}

pub async fn serve(
    cfg: Config,
    proxy: Proxy,
    log: LogFormat,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls = elira_tls::quic_server_config(&cfg.cert, &cfg.key)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let server = quinn::ServerConfig::with_crypto(Arc::new(crypto));

    let endpoint = bind(cfg.listen, server, cfg.reuse_port).await?;
    tracing::info!(listen = %cfg.listen, "http/3 listening");

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let proxy = proxy.clone();

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            let peer = conn.remote_address();
                            if let Err(err) = connection(conn, peer, proxy, log).await {
                                tracing::debug!(%peer, error = %err, "http/3 connection closed");
                            }
                        }
                        Err(err) => tracing::debug!(error = %err, "http/3 handshake failed"),
                    }
                });
            }
        }
    }

    endpoint.close(0u32.into(), b"shutdown");
    endpoint.wait_idle().await;
    Ok(())
}

/// QUIC sockets are released by quinn's driver task, not by the `Endpoint`
/// drop itself. A reload that rebinds on the same port needs a moment.
async fn bind(
    addr: SocketAddr,
    server: quinn::ServerConfig,
    reuse_port: bool,
) -> std::io::Result<quinn::Endpoint> {
    let mut last = None;

    for _ in 0..20 {
        match try_bind(addr, server.clone(), reuse_port) {
            Ok(endpoint) => return Ok(endpoint),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
                last = Some(err);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(err) => return Err(err),
        }
    }

    Err(last.expect("the loop only exits early with an error"))
}

fn try_bind(
    addr: SocketAddr,
    server: quinn::ServerConfig,
    reuse_port: bool,
) -> std::io::Result<quinn::Endpoint> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let runtime = quinn::default_runtime()
        .ok_or_else(|| std::io::Error::other("no async runtime for quinn"))?;

    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server),
        socket.into(),
        runtime,
    )
}

async fn connection(
    conn: quinn::Connection,
    peer: SocketAddr,
    proxy: Proxy,
    log: LogFormat,
) -> Result<(), BoxError> {
    let mut conn =
        h3::server::Connection::<h3_quinn::Connection, Bytes>::new(h3_quinn::Connection::new(conn))
            .await?;

    while let Some(resolver) = conn.accept().await? {
        let (req, stream) = resolver.resolve_request().await?;
        let proxy = proxy.clone();

        tokio::spawn(async move {
            if let Err(err) = request(req, stream, peer, proxy, log).await {
                tracing::debug!(%peer, error = %err, "http/3 request failed");
            }
        });
    }

    Ok(())
}

async fn request<S, B>(
    req: Request<()>,
    stream: h3::server::RequestStream<S, B>,
    peer: SocketAddr,
    proxy: Proxy,
    log: LogFormat,
) -> Result<(), BoxError>
where
    S: h3::quic::BidiStream<B> + Send + 'static,
    S::RecvStream: Send + 'static,
    B: Buf + From<Bytes> + Send + 'static,
{
    let started = Instant::now();
    let id = request_id();
    let method = req.method().clone();
    let version = req.version();
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let host = req
        .uri()
        .authority()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_default();
    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let (mut send, recv) = stream.split();

    // Bridge the QUIC receive stream into a body. A channel keeps the body
    // Send + Sync, which the hyper client on the upstream hop requires.
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, BoxError>>(4);
    tokio::spawn(async move {
        let mut recv = recv;
        loop {
            match recv.recv_data().await {
                Ok(Some(mut buf)) => {
                    let bytes = buf.copy_to_bytes(buf.remaining());
                    if tx.send(Ok(Frame::data(bytes))).await.is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    if let Ok(Some(trailers)) = recv.recv_trailers().await {
                        let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    }
                    return;
                }
                Err(err) => {
                    let _ = tx.send(Err(Box::new(err))).await;
                    return;
                }
            }
        }
    });

    let body = StreamBody::new(ReceiverStream::new(rx)).boxed();

    let (parts, ()) = req.into_parts();
    let request = Request::from_parts(parts, body);

    let response = proxy.handle(request, peer, "https").await;
    let status = response.status();
    let bytes = response.body().size_hint().exact().unwrap_or(0);

    let (parts, body) = response.into_parts();
    let mut out = Response::builder().status(parts.status);
    {
        let headers = out
            .headers_mut()
            .ok_or("cannot build the response headers")?;
        for (name, value) in parts.headers.iter() {
            // HTTP/3 frames by stream, not by length.
            if name == http::header::CONTENT_LENGTH || name == http::header::TRANSFER_ENCODING {
                continue;
            }
            headers.append(name, value.clone());
        }
    }
    send.send_response(out.body(())?).await?;

    let mut body = body;
    while let Some(frame) = std::pin::Pin::new(&mut body).frame().await {
        match frame {
            Ok(frame) => match frame.into_data() {
                Ok(data) => send.send_data(B::from(data)).await?,
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        send.send_trailers(trailers).await?;
                    }
                }
            },
            Err(err) => return Err(err),
        }
    }
    send.finish().await?;

    let entry = Entry {
        peer: peer.ip(),
        method,
        version,
        host,
        path,
        status,
        bytes,
        duration: started.elapsed(),
        user_agent,
        request_id: id,
    };
    match log {
        LogFormat::Text => tracing::info!(target: "access", "{}", entry.line()),
        LogFormat::Json => tracing::info!(target: "access", "{}", entry.json()),
    }

    Ok(())
}
