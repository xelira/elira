//! Layer-4 TCP and UDP proxying.
//!
//! Each configured stream gets its own listener and a small balance table.
//! TCP tunnels are idle-timed per read; UDP sessions are keyed by client
//! address and expire after the configured idle period.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex, Semaphore};

use elira_metrics::Metrics;

use crate::config::{Balance, Stream, StreamTransport};
use crate::server::Runtime;

/// A bound stream listener, created before privileges are dropped.
pub enum Bound {
    Tcp(TcpListener, Stream),
    Udp(UdpSocket, Stream),
}

/// Bind one stream listener. Returns immediately so the caller can bind every
/// socket before switching users.
pub async fn bind(stream: &Stream) -> io::Result<Bound> {
    match stream.transport {
        StreamTransport::Tcp => Ok(Bound::Tcp(
            TcpListener::bind(stream.listen).await?,
            stream.clone(),
        )),
        StreamTransport::Udp => Ok(Bound::Udp(
            UdpSocket::bind(stream.listen).await?,
            stream.clone(),
        )),
    }
}

/// Spawn the accept loop for one bound listener.
pub fn spawn(
    bound: Bound,
    runtime: Arc<ArcSwap<Runtime>>,
    max_connections: usize,
    metrics: Arc<Metrics>,
    stop: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    match bound {
        Bound::Tcp(listener, stream) => tokio::spawn(serve_tcp(
            listener,
            stream,
            runtime,
            max_connections,
            metrics,
            stop,
        )),
        Bound::Udp(socket, stream) => {
            tokio::spawn(serve_udp(socket, stream, runtime, metrics, stop))
        }
    }
}

struct Balancer {
    next: AtomicUsize,
    active: Vec<AtomicUsize>,
    balance: Balance,
    upstreams: Vec<String>,
}

impl Balancer {
    fn new(stream: &Stream) -> Self {
        Self {
            next: AtomicUsize::new(0),
            active: (0..stream.upstreams.len())
                .map(|_| AtomicUsize::new(0))
                .collect(),
            balance: stream.balance,
            upstreams: stream.upstreams.clone(),
        }
    }

    fn pick(&self, client: IpAddr) -> usize {
        let count = self.upstreams.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        match self.balance {
            Balance::LeastConn => {
                let mut best = start % count;
                let mut best_active = usize::MAX;
                for offset in 0..count {
                    let index = (start + offset) % count;
                    let active = self.active[index].load(Ordering::Relaxed);
                    if active < best_active {
                        best = index;
                        best_active = active;
                    }
                }
                best
            }
            Balance::Hash => {
                let mut hash = 0xcbf2_9ce4_8422_2325u64;
                for byte in client.to_string().bytes() {
                    hash ^= u64::from(byte);
                    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
                }
                (hash % count as u64) as usize
            }
            Balance::RoundRobin => start % count,
            Balance::Random => {
                let mut value = start as u64;
                value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
                value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                value ^= value >> 31;
                (value % count as u64) as usize
            }
        }
    }

    fn enter(&self, index: usize) -> ActiveGuard<'_> {
        self.active[index].fetch_add(1, Ordering::Relaxed);
        ActiveGuard {
            active: &self.active[index],
        }
    }
}

struct ActiveGuard<'a> {
    active: &'a AtomicUsize,
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn serve_tcp(
    listener: TcpListener,
    stream: Stream,
    runtime: Arc<ArcSwap<Runtime>>,
    max_connections: usize,
    metrics: Arc<Metrics>,
    mut stop: watch::Receiver<bool>,
) {
    let balancer = Arc::new(Balancer::new(&stream));
    let permits = Arc::new(Semaphore::new(max_connections));
    let connect_timeout = Duration::from_secs(stream.connect_timeout_secs);
    let idle =
        (stream.idle_timeout_secs > 0).then(|| Duration::from_secs(stream.idle_timeout_secs));
    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let Ok((client, peer)) = accepted else { continue };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    continue;
                };
                let balancer = balancer.clone();
                let runtime = runtime.clone();
                let metrics = metrics.clone();
                let mut stop = stop.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handle_tcp(
                        client,
                        peer.ip(),
                        balancer,
                        runtime,
                        stream.tls,
                        connect_timeout,
                        idle,
                        metrics,
                        &mut stop,
                    )
                    .await
                    {
                        tracing::debug!(%peer, error = %err, "stream connection failed");
                    }
                });
            }
        }
    }

    while connections.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp(
    client: TcpStream,
    client_ip: IpAddr,
    balancer: Arc<Balancer>,
    runtime: Arc<ArcSwap<Runtime>>,
    tls: bool,
    connect_timeout: Duration,
    idle: Option<Duration>,
    metrics: Arc<Metrics>,
    stop: &mut watch::Receiver<bool>,
) -> io::Result<()> {
    metrics.connection_started();
    let result = async {
        tokio::select! {
            result = async {
                if tls {
                    let client = accept_tls(client, &runtime, &metrics).await?;
                    proxy_stream(client, &balancer, client_ip, connect_timeout, idle).await
                } else {
                    proxy_stream(client, &balancer, client_ip, connect_timeout, idle).await
                }
            } => result,
            _ = stop.changed() => Ok(()),
        }
    }
    .await;
    metrics.connection_finished();
    result
}

async fn proxy_stream<C>(
    client: C,
    balancer: &Balancer,
    client_ip: IpAddr,
    connect_timeout: Duration,
    idle: Option<Duration>,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let (upstream, index) = connect_upstream(balancer, client_ip, connect_timeout).await?;
    let _active = balancer.enter(index);
    run_tunnel(client, upstream, idle).await
}

async fn connect_upstream(
    balancer: &Balancer,
    client_ip: IpAddr,
    timeout: Duration,
) -> io::Result<(TcpStream, usize)> {
    let first = balancer.pick(client_ip);
    let mut last = None;
    for offset in 0..balancer.upstreams.len() {
        let index = (first + offset) % balancer.upstreams.len();
        let address = &balancer.upstreams[index];
        match tokio::time::timeout(timeout, TcpStream::connect(address.as_str())).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok((stream, index));
            }
            Ok(Err(err)) => last = Some(err),
            Err(_) => {
                last = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream connect timed out",
                ));
            }
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("no stream upstreams")))
}

async fn run_tunnel<C, U>(client: C, upstream: U, idle: Option<Duration>) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let client_to_upstream = pump(&mut client_read, &mut upstream_write, idle);
    let upstream_to_client = pump(&mut upstream_read, &mut client_write, idle);
    tokio::pin!(client_to_upstream);
    tokio::pin!(upstream_to_client);
    tokio::select! {
        result = &mut client_to_upstream => result,
        result = &mut upstream_to_client => result,
    }
}

async fn pump<R, W>(reader: &mut R, writer: &mut W, idle: Option<Duration>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = match idle {
            Some(idle) => match tokio::time::timeout(idle, reader.read(&mut buffer)).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "stream idle timeout",
                    ));
                }
            },
            None => reader.read(&mut buffer).await?,
        };
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).await?;
    }
    let _ = writer.shutdown().await;
    Ok(())
}

struct UdpSession {
    upstream: Arc<UdpSocket>,
    _active: OwnedActive,
}

/// Active guard that owns an `Arc` to the balancer and a server index.
struct OwnedActive {
    balancer: Arc<Balancer>,
    index: usize,
}

impl Drop for OwnedActive {
    fn drop(&mut self) {
        self.balancer.active[self.index].fetch_sub(1, Ordering::Relaxed);
    }
}

async fn serve_udp(
    socket: UdpSocket,
    stream: Stream,
    _runtime: Arc<ArcSwap<Runtime>>,
    metrics: Arc<Metrics>,
    mut stop: watch::Receiver<bool>,
) {
    let socket = Arc::new(socket);
    let balancer = Arc::new(Balancer::new(&stream));
    let sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let idle =
        (stream.idle_timeout_secs > 0).then(|| Duration::from_secs(stream.idle_timeout_secs));
    let mut buffer = vec![0u8; 65_535];

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            received = socket.recv_from(&mut buffer) => {
                let Ok((size, client)) = received else { continue };
                let upstream = {
                    let mut guard = sessions.lock().await;
                    match guard.get(&client) {
                        Some(session) => session.upstream.clone(),
                        None => {
                            let index = balancer.pick(client.ip());
                            balancer.active[index].fetch_add(1, Ordering::Relaxed);
                            let address = balancer.upstreams[index].clone();
                            let upstream = match UdpSocket::bind(("0.0.0.0", 0)).await {
                                Ok(socket) => socket,
                                Err(_) => {
                                    balancer.active[index].fetch_sub(1, Ordering::Relaxed);
                                    continue;
                                }
                            };
                            if upstream.connect(address.as_str()).await.is_err() {
                                balancer.active[index].fetch_sub(1, Ordering::Relaxed);
                                continue;
                            }
                            let upstream = Arc::new(upstream);
                            let session = UdpSession {
                                upstream: upstream.clone(),
                                _active: OwnedActive {
                                    balancer: balancer.clone(),
                                    index,
                                },
                            };
                            guard.insert(client, session);
                            let sessions = sessions.clone();
                            let socket = socket.clone();
                            let metrics = metrics.clone();
                            let reply_upstream = upstream.clone();
                            tokio::spawn(async move {
                                metrics.connection_started();
                                let mut reply = vec![0u8; 65_535];
                                loop {
                                    let received = match idle {
                                        Some(idle) => {
                                            match tokio::time::timeout(
                                                idle,
                                                reply_upstream.recv(&mut reply),
                                            )
                                            .await
                                            {
                                                Ok(result) => result,
                                                Err(_) => break,
                                            }
                                        }
                                        None => reply_upstream.recv(&mut reply).await,
                                    };
                                    let Ok(size) = received else { break };
                                    if socket.send_to(&reply[..size], client).await.is_err() {
                                        break;
                                    }
                                }
                                metrics.connection_finished();
                                sessions.lock().await.remove(&client);
                            });
                            upstream
                        }
                    }
                };
                let _ = upstream.send(&buffer[..size]).await;
            }
        }
    }
}

/// Accept a TCP stream with TLS when the stream asks for it.
async fn accept_tls(
    stream: TcpStream,
    runtime: &ArcSwap<Runtime>,
    metrics: &Metrics,
) -> io::Result<elira_tls::TlsStream<TcpStream>> {
    let Some(config) = runtime.load().tls().cloned() else {
        return Err(io::Error::other(
            "stream TLS requested but no TLS config is loaded",
        ));
    };
    match tokio::time::timeout(Duration::from_secs(10), elira_tls::accept(&config, stream)).await {
        Ok(Ok(stream)) => {
            metrics.tls_handshake(true);
            Ok(stream)
        }
        Ok(Err(err)) => {
            metrics.tls_handshake(false);
            Err(io::Error::other(err.to_string()))
        }
        Err(_) => {
            metrics.tls_handshake(false);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "stream TLS handshake timed out",
            ))
        }
    }
}
