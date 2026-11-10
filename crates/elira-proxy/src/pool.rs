//! Upstream pools, balancing and passive ejection.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::uri::Authority;
use http::{Request, Response};
use http_body_util::BodyExt;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use elira_config::Balance;
use elira_upstream::TlsOptions;

use crate::variables::RequestKey;
use crate::{Body, BoxError};

/// A configured backend: TCP authority or a filesystem unix socket.
#[derive(Clone, Debug)]
pub(crate) enum ServerAddr {
    Tcp(Authority),
    Unix(PathBuf),
}

impl std::fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(authority) => authority.fmt(f),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

impl ServerAddr {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        if let Some(path) = value.strip_prefix("unix:") {
            return Some(Self::Unix(PathBuf::from(path)));
        }
        value.parse::<Authority>().ok().map(Self::Tcp)
    }

    pub(crate) fn tcp(&self) -> Option<&Authority> {
        match self {
            Self::Tcp(authority) => Some(authority),
            Self::Unix(_) => None,
        }
    }

    pub(crate) fn unix(&self) -> Option<&Path> {
        match self {
            Self::Unix(path) => Some(path),
            Self::Tcp(_) => None,
        }
    }
}

pub(crate) struct Pool {
    pub(crate) name: String,
    pub(crate) servers: Vec<ServerAddr>,
    pub(crate) health: Vec<AtomicBool>,
    pub(crate) active: Vec<AtomicUsize>,
    pub(crate) passive: Vec<Passive>,
    pub(crate) failures_before_eject: u32,
    pub(crate) eject_for: Duration,
    pub(crate) started: Instant,
    pub(crate) hash_key: RequestKey,
    pub(crate) server_labels: Vec<String>,
    pub(crate) weights: Vec<u32>,
    pub(crate) total_weight: u64,
    pub(crate) weighted: bool,
    pub(crate) retry_on: RetryOn,
    pub(crate) next: AtomicUsize,
    pub(crate) balance: Balance,
    pub(crate) retries: u32,
    pub(crate) scheme: &'static str,
    pub(crate) client: Client<HttpsConnector<HttpConnector>, Body>,
    pub(crate) tls: TlsOptions,
    pub(crate) tls_config: Arc<tokio_rustls::rustls::ClientConfig>,
    pub(crate) proxy_protocol: bool,
    pub(crate) health_path: Option<String>,
    pub(crate) health_method: Option<String>,
    pub(crate) health_status: Option<Vec<u16>>,
    pub(crate) health_host: Option<String>,
    pub(crate) h2: Option<elira_h2::Pool>,
    pub(crate) h3: Option<elira_h3upstream::Pool>,
}

pub(crate) struct ActiveGuard<'a> {
    pub(crate) active: &'a AtomicUsize,
}

/// Conditions that make an upstream attempt retryable.
pub(crate) struct RetryOn {
    pub(crate) error: bool,
    pub(crate) timeout: bool,
    pub(crate) statuses: Vec<u16>,
}

impl RetryOn {
    pub(crate) fn parse(conditions: &[String]) -> Self {
        if conditions.is_empty() {
            return Self {
                error: true,
                timeout: true,
                statuses: Vec::new(),
            };
        }
        let mut retry = Self {
            error: false,
            timeout: false,
            statuses: Vec::new(),
        };
        for condition in conditions {
            match condition.as_str() {
                "error" => retry.error = true,
                "timeout" => retry.timeout = true,
                _ => {
                    if let Ok(status) = condition.parse::<u16>() {
                        retry.statuses.push(status);
                    }
                }
            }
        }
        retry
    }

    pub(crate) fn status(&self, status: u16) -> bool {
        self.statuses.contains(&status)
    }
}

/// Consecutive transport failures and the end of a passive ejection.
pub(crate) struct Passive {
    pub(crate) failures: AtomicU32,
    pub(crate) ejected_until_ms: AtomicU64,
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Pool {
    pub(crate) fn pick(&self) -> usize {
        self.pick_key(None)
    }

    pub(crate) fn pick_key(&self, key: Option<&str>) -> usize {
        let count = self.servers.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let now = self.now_ms();

        match self.balance {
            Balance::RoundRobin => self.pick_round_robin(start, now),
            Balance::LeastConn => {
                let mut best: Option<(usize, usize, u32)> = None;

                for offset in 0..count {
                    let index = (start + offset) % count;
                    if !self.available(index, now) {
                        continue;
                    }
                    let active = self.active[index].load(Ordering::Relaxed);
                    let weight = self.weights[index];
                    let better = match best {
                        None => true,
                        Some((_, best_active, best_weight)) => {
                            (active as u128) * u128::from(best_weight)
                                < (best_active as u128) * u128::from(weight)
                        }
                    };
                    if better {
                        best = Some((index, active, weight));
                    }
                }

                best.map(|(index, _, _)| index).unwrap_or(start % count)
            }
            Balance::Hash => {
                let Some(key) = key else {
                    return self.pick_round_robin(start, now);
                };
                self.pick_rendezvous(key, now)
            }
            Balance::Random => self.pick_random(start as u64, now),
        }
    }

    fn pick_random(&self, seed: u64, now: u64) -> usize {
        let count = self.servers.len();
        let slot = splitmix64(seed);
        let base = if self.weighted {
            self.weighted_index(slot % self.total_weight)
        } else {
            (slot % count as u64) as usize
        };
        for offset in 0..count {
            let index = (base + offset) % count;
            if self.available(index, now) {
                return index;
            }
        }
        base
    }

    fn pick_round_robin(&self, start: usize, now: u64) -> usize {
        let count = self.servers.len();
        let base = if self.weighted {
            self.weighted_index((start as u64) % self.total_weight)
        } else {
            start % count
        };
        for offset in 0..count {
            let index = (base + offset) % count;
            if self.available(index, now) {
                return index;
            }
        }
        // Everything looks down. Send traffic anyway: a broken probe or a
        // stale ejection must not turn into an outage.
        base
    }

    fn weighted_index(&self, mut slot: u64) -> usize {
        for (index, weight) in self.weights.iter().enumerate() {
            let weight = u64::from(*weight);
            if slot < weight {
                return index;
            }
            slot -= weight;
        }
        0
    }

    fn pick_rendezvous(&self, key: &str, now: u64) -> usize {
        let mut best = None;
        let mut best_score = 0;
        for index in 0..self.servers.len() {
            if !self.available(index, now) {
                continue;
            }
            let score = rendezvous(key, &self.server_labels[index]);
            if best.is_none() || score > best_score {
                best = Some(index);
                best_score = score;
            }
        }

        if let Some(index) = best {
            return index;
        }

        // All servers are unavailable. Pick the same rendezvous winner anyway
        // instead of dropping the affinity completely.
        let mut fallback = 0;
        let mut fallback_score = 0;
        for (index, label) in self.server_labels.iter().enumerate() {
            let score = rendezvous(key, label);
            if index == 0 || score > fallback_score {
                fallback = index;
                fallback_score = score;
            }
        }
        fallback
    }

    fn available(&self, index: usize, now_ms: u64) -> bool {
        self.health[index].load(Ordering::Relaxed)
            && self.passive[index].ejected_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub(crate) fn record_success(&self, index: usize) {
        let passive = &self.passive[index];
        passive.failures.store(0, Ordering::Relaxed);
        if passive.ejected_until_ms.swap(0, Ordering::Relaxed) != 0 {
            tracing::info!(upstream = %self.servers[index], "upstream restored after ejection");
        }
    }

    pub(crate) fn record_failure(&self, index: usize) {
        if self.failures_before_eject == 0 {
            return;
        }
        let passive = &self.passive[index];
        let failures = passive.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures < self.failures_before_eject {
            return;
        }

        passive.failures.store(0, Ordering::Relaxed);
        let until = self
            .now_ms()
            .saturating_add(self.eject_for.as_millis() as u64);
        passive.ejected_until_ms.store(until, Ordering::Relaxed);
        tracing::warn!(
            upstream = %self.servers[index],
            seconds = self.eject_for.as_secs(),
            "upstream ejected after transport failures"
        );
    }

    pub(crate) fn enter(&self, index: usize) -> ActiveGuard<'_> {
        self.active[index].fetch_add(1, Ordering::Relaxed);
        ActiveGuard {
            active: &self.active[index],
        }
    }

    pub(crate) fn set_health(&self, index: usize, up: bool) {
        if self.health[index].swap(up, Ordering::Relaxed) != up {
            tracing::warn!(upstream = %self.servers[index], healthy = up, "upstream health changed");
        }
    }
}

/// Deterministic 64-bit avalanche used to spread `random` picks without a
/// full RNG dependency.
fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

pub(crate) fn rendezvous(key: &str, server: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in key.bytes().chain(std::iter::once(0)).chain(server.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Why one upstream attempt failed.
pub(crate) enum SendError {
    Timeout,
    Failed(String),
}

pub(crate) async fn send_request(
    pool: &Pool,
    server: &ServerAddr,
    request: Request<Body>,
    timeout: Duration,
    connect_timeout: Duration,
    peer: SocketAddr,
) -> Result<Response<Body>, SendError> {
    if pool.proxy_protocol && server.tcp().is_some() {
        return send_direct(pool, server, request, timeout, connect_timeout, peer).await;
    }
    let Some(path) = server.unix() else {
        if let Some(h3) = &pool.h3 {
            let uri = request.uri().clone();
            let result = tokio::time::timeout(timeout, h3.request(uri, request)).await;
            return match result {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(err)) => Err(SendError::Failed(err.to_string())),
                Err(_) => Err(SendError::Timeout),
            };
        }
        if let Some(h2) = &pool.h2 {
            let uri = request.uri().clone();
            let result = tokio::time::timeout(timeout, h2.request(uri, request)).await;
            return match result {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(err)) => Err(SendError::Failed(err.to_string())),
                Err(_) => Err(SendError::Timeout),
            };
        }
        return match tokio::time::timeout(timeout, pool.client.request(request)).await {
            Ok(Ok(response)) => Ok(response
                .map(|body| BodyExt::map_err(body, |err| -> BoxError { Box::new(err) }).boxed())),
            Ok(Err(err)) => Err(SendError::Failed(err.to_string())),
            Err(_) => Err(SendError::Timeout),
        };
    };

    let stream = match tokio::time::timeout(connect_timeout, UnixStream::connect(path)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(SendError::Failed(err.to_string())),
        Err(_) => return Err(SendError::Timeout),
    };

    let work = async {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(request).await?;
        Ok::<_, BoxError>(response)
    };

    match tokio::time::timeout(timeout, work).await {
        Ok(Ok(response)) => Ok(response
            .map(|body| BodyExt::map_err(body, |err| -> BoxError { Box::new(err) }).boxed())),
        Ok(Err(err)) => Err(SendError::Failed(err.to_string())),
        Err(_) => Err(SendError::Timeout),
    }
}

/// Send a request over a fresh connection preceded by a PROXY protocol v1
/// header.
///
/// The header names the client of the request that opened the connection, so
/// it cannot be reused from a pool shared by several clients. This path
/// therefore always opens a new connection and speaks HTTP/1.1.
async fn send_direct(
    pool: &Pool,
    server: &ServerAddr,
    request: Request<Body>,
    timeout: Duration,
    connect_timeout: Duration,
    peer: SocketAddr,
) -> Result<Response<Body>, SendError> {
    let Some(authority) = server.tcp() else {
        return Err(SendError::Failed(
            "proxy_protocol needs a TCP upstream".to_owned(),
        ));
    };
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = authority
        .port_u16()
        .unwrap_or(if pool.scheme == "https" { 443 } else { 80 });

    let connect = async {
        let mut stream = elira_upstream::tcp_connect(&host, port, pool.tls.local_address)
            .await
            .map_err(|err| SendError::Failed(err.to_string()))?;
        let _ = stream.set_nodelay(true);
        let dest = stream
            .peer_addr()
            .map_err(|err| SendError::Failed(err.to_string()))?;
        stream
            .write_all(&proxy_header(peer, dest))
            .await
            .map_err(|err| SendError::Failed(err.to_string()))?;

        if pool.scheme == "https" {
            let name = pool.tls.sni.clone().unwrap_or_else(|| host.clone());
            let name = match name.parse::<IpAddr>() {
                Ok(ip) => ServerName::IpAddress(ip.into()),
                Err(_) => {
                    ServerName::try_from(name).map_err(|err| SendError::Failed(err.to_string()))?
                }
            };
            let connector = TlsConnector::from(pool.tls_config.clone());
            let tls = connector
                .connect(name, stream)
                .await
                .map_err(|err| SendError::Failed(err.to_string()))?;
            Ok::<Box<dyn DirectIo>, SendError>(Box::new(tls))
        } else {
            Ok::<Box<dyn DirectIo>, SendError>(Box::new(stream))
        }
    };

    let stream = match tokio::time::timeout(connect_timeout, connect).await {
        Ok(result) => result?,
        Err(_) => return Err(SendError::Timeout),
    };

    let work = async {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(request).await?;
        Ok::<_, BoxError>(response)
    };

    match tokio::time::timeout(timeout, work).await {
        Ok(Ok(response)) => Ok(response
            .map(|body| BodyExt::map_err(body, |err| -> BoxError { Box::new(err) }).boxed())),
        Ok(Err(err)) => Err(SendError::Failed(err.to_string())),
        Err(_) => Err(SendError::Timeout),
    }
}

trait DirectIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> DirectIo for T {}

/// Encode a PROXY protocol v1 header. Mixed address families cannot be
/// expressed by v1, so they fall back to `UNKNOWN`, which still tells the
/// upstream that the protocol is in use.
pub(crate) fn proxy_header(client: SocketAddr, server: SocketAddr) -> Vec<u8> {
    match (client, server) {
        (SocketAddr::V4(client), SocketAddr::V4(server)) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            client.ip(),
            server.ip(),
            client.port(),
            server.port()
        )
        .into_bytes(),
        (SocketAddr::V6(client), SocketAddr::V6(server)) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            client.ip(),
            server.ip(),
            client.port(),
            server.port()
        )
        .into_bytes(),
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}
