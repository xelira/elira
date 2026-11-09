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
use elira_metrics::Metrics;
use elira_proxy::{BoxError, Proxy};

mod proxy_udp;

pub struct Config {
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub reuse_port: bool,
    pub client_ca: Option<PathBuf>,
    pub client_crl: Option<PathBuf>,
    pub client_auth: elira_tls::ClientAuth,
    pub cipher_suites: Option<Vec<String>>,
    pub curves: Option<Vec<String>>,
    pub ticket_key: Option<PathBuf>,
    pub certificates: Vec<elira_tls::NamedCert>,
    pub proxy_protocol: bool,
    pub idle_timeout_secs: u64,
    pub early_data: bool,
}

pub async fn serve(
    cfg: Config,
    proxy: Arc<dyn Fn() -> Proxy + Send + Sync>,
    metrics: Arc<Metrics>,
    body_timeout: Option<std::time::Duration>,
    log: Arc<dyn Fn(&Entry) + Send + Sync>,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls = elira_tls::quic_server_config_full(
        &cfg.cert,
        &cfg.key,
        &cfg.certificates,
        cfg.client_ca.as_deref(),
        cfg.client_auth,
        if cfg.early_data { u32::MAX } else { 0 },
        cfg.cipher_suites.as_deref(),
        cfg.curves.as_deref(),
        cfg.client_crl.as_deref(),
        cfg.ticket_key.as_deref(),
    )?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(cfg.idle_timeout_secs))
            .map_err(|_| anyhow::anyhow!("invalid QUIC idle timeout"))?,
    ));
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(transport));

    let (endpoint, clients) = bind(cfg.listen, server, cfg.reuse_port, cfg.proxy_protocol).await?;
    tracing::info!(listen = %cfg.listen, "http/3 listening");

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let proxy = proxy.clone();
                let metrics = metrics.clone();
                let log = log.clone();
                let clients = clients.clone();

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            metrics.quic_connection();
                            let peer = conn.remote_address();
                            if let Err(err) = connection(
                                conn,
                                peer,
                                proxy,
                                metrics,
                                body_timeout,
                                log,
                                clients,
                            )
                            .await
                            {
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
type Clients = proxy_udp::Clients;

async fn bind(
    addr: SocketAddr,
    server: quinn::ServerConfig,
    reuse_port: bool,
    proxy_protocol: bool,
) -> std::io::Result<(quinn::Endpoint, Option<Clients>)> {
    let mut last = None;

    for _ in 0..20 {
        match try_bind(addr, server.clone(), reuse_port, proxy_protocol) {
            Ok(bound) => return Ok(bound),
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
    proxy_protocol: bool,
) -> std::io::Result<(quinn::Endpoint, Option<Clients>)> {
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

    if proxy_protocol {
        let (socket, clients) = proxy_udp::ProxyUdpSocket::new(socket.into())?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server),
            socket,
            runtime,
        )?;
        Ok((endpoint, Some(clients)))
    } else {
        Ok((
            quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server),
                socket.into(),
                runtime,
            )?,
            None,
        ))
    }
}

async fn connection(
    conn: quinn::Connection,
    transport: SocketAddr,
    proxy: Arc<dyn Fn() -> Proxy + Send + Sync>,
    metrics: Arc<Metrics>,
    body_timeout: Option<std::time::Duration>,
    log: Arc<dyn Fn(&Entry) + Send + Sync>,
    clients: Option<Clients>,
) -> Result<(), BoxError> {
    // The QUIC transport peer is the load balancer when PROXY protocol is on;
    // the map holds the address from its header.
    let peer = clients
        .as_ref()
        .and_then(|map| map.lock().ok().and_then(|map| map.get(&transport).copied()))
        .unwrap_or(transport);

    let client_cert = conn
        .peer_identity()
        .and_then(|identity| {
            identity
                .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .and_then(|chain| {
            chain
                .first()
                .and_then(|leaf| elira_tls::ClientIdentity::parse(leaf.as_ref()))
        })
        .map(Arc::new);

    let mut conn =
        h3::server::Connection::<h3_quinn::Connection, Bytes>::new(h3_quinn::Connection::new(conn))
            .await?;

    while let Some(resolver) = conn.accept().await? {
        let (req, stream) = resolver.resolve_request().await?;
        let proxy = proxy.clone();
        let metrics = metrics.clone();
        let log = log.clone();
        let client_cert = client_cert.clone();

        tokio::spawn(async move {
            if let Err(err) = request(
                req,
                stream,
                peer,
                proxy,
                metrics,
                body_timeout,
                log,
                client_cert,
            )
            .await
            {
                tracing::debug!(%peer, error = %err, "http/3 request failed");
            }
        });
    }

    if let Some(map) = clients {
        if let Ok(mut map) = map.lock() {
            map.remove(&transport);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn request<S, B>(
    req: Request<()>,
    stream: h3::server::RequestStream<S, B>,
    peer: SocketAddr,
    proxy: Arc<dyn Fn() -> Proxy + Send + Sync>,
    metrics: Arc<Metrics>,
    body_timeout: Option<std::time::Duration>,
    log: Arc<dyn Fn(&Entry) + Send + Sync>,
    client_cert: Option<Arc<elira_tls::ClientIdentity>>,
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
            let frame = match body_timeout {
                Some(idle) => match tokio::time::timeout(idle, recv.recv_data()).await {
                    Ok(frame) => frame,
                    Err(_) => {
                        let _ = tx
                            .send(Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "request body made no progress",
                            ))))
                            .await;
                        return;
                    }
                },
                None => recv.recv_data().await,
            };
            match frame {
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
    let mut request = Request::from_parts(parts, body);
    if let Some(identity) = &client_cert {
        request.extensions_mut().insert(identity.as_ref().clone());
    }

    let response = proxy().handle(request, peer, "https").await;
    let status = response.status();
    let elapsed = started.elapsed();
    let status_code = status.as_u16();
    metrics.record_request(status_code, elapsed);
    let log_request = response
        .extensions()
        .get::<elira_proxy::Labels>()
        .map(|labels| labels.access_log)
        .unwrap_or(true);
    let mut upstream = None;
    let mut log_sample = 1.0;
    if let Some(labels) = response.extensions().get::<elira_proxy::Labels>().cloned() {
        metrics.record_route(&labels.route, status_code, elapsed);
        if let Some(name) = &labels.upstream {
            metrics.record_upstream(name, status_code, elapsed);
        }
        upstream = labels.upstream;
        log_sample = labels.access_log_sample;
    }
    match response
        .headers()
        .get("x-cache")
        .and_then(|value| value.to_str().ok())
    {
        Some("HIT") => metrics.cache_hit(),
        Some("MISS") => metrics.cache_miss(),
        _ => {}
    }
    let bytes = response.body().size_hint().exact().unwrap_or(0);
    metrics.response_bytes(bytes);

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

    let write_log = log_request && elira_accesslog::sampled(&id, log_sample);
    let entry = Entry {
        peer: peer.ip(),
        method,
        version,
        host,
        path,
        status,
        bytes,
        duration: elapsed,
        user_agent,
        request_id: id,
        upstream,
    };
    if write_log {
        log(&entry);
    }

    Ok(())
}
