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
use http_body::Body as _;
use http_body_util::{BodyExt, Full};
use tokio::sync::watch;

use elira_accesslog::{request_id, Entry};
use elira_config::LogFormat;
use elira_proxy::{Body, BoxError, Proxy};

/// A request larger than this gets a 413 instead of eating memory.
const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

pub struct Config {
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
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

    let endpoint = quinn::Endpoint::server(server, cfg.listen)?;
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
    mut stream: h3::server::RequestStream<S, B>,
    peer: SocketAddr,
    proxy: Proxy,
    log: LogFormat,
) -> Result<(), BoxError>
where
    S: h3::quic::BidiStream<B> + Send + 'static,
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

    let body = read_body(&mut stream).await?;

    let (parts, ()) = req.into_parts();
    let request = Request::from_parts(parts, full(body));

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
    stream.send_response(out.body(())?).await?;

    let mut body = body;
    while let Some(frame) = std::pin::Pin::new(&mut body).frame().await {
        match frame {
            Ok(frame) => match frame.into_data() {
                Ok(data) => stream.send_data(B::from(data)).await?,
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        stream.send_trailers(trailers).await?;
                    }
                }
            },
            Err(err) => return Err(err),
        }
    }
    stream.finish().await?;

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

async fn read_body<S, B>(stream: &mut h3::server::RequestStream<S, B>) -> Result<Bytes, BoxError>
where
    S: h3::quic::RecvStream,
    B: Buf,
{
    let mut out = Vec::new();

    while let Some(mut buf) = stream.recv_data().await? {
        let len = buf.remaining();
        if out.len() + len > MAX_REQUEST_BODY {
            return Err("request body too large".into());
        }
        out.extend_from_slice(&buf.copy_to_bytes(len));
    }

    Ok(Bytes::from(out))
}

fn full(bytes: Bytes) -> Body {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}
