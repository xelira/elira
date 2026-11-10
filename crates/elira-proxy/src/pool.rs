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
use elira_upstream::{Resolver, TlsOptions};

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
    pub(crate) backup: Vec<bool>,
    pub(crate) down: Vec<bool>,
    pub(crate) max_conns: Vec<usize>,
    pub(crate) slow_start: Vec<Duration>,
    pub(crate) recover_at: Vec<AtomicU64>,
    pub(crate) passive: Vec<Passive>,
    pub(crate) failures_before_eject: u32,
    pub(crate) eject_for: Duration,
    pub(crate) started: Instant,
    pub(crate) hash_key: RequestKey,
    pub(crate) server_labels: Vec<String>,
    pub(crate) weights: Vec<u32>,
    pub(crate) retry_on: RetryOn,
    pub(crate) next: AtomicUsize,
    pub(crate) balance: Balance,
    pub(crate) retries: u32,
    pub(crate) scheme: &'static str,
    pub(crate) client: Client<HttpsConnector<HttpConnector<Resolver>>, Body>,
    pub(crate) tls: TlsOptions,
    pub(crate) tls_config: Arc<tokio_rustls::rustls::ClientConfig>,
    pub(crate) resolver: Resolver,
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
    pub(crate) fn pick(&self) -> Option<usize> {
        self.pick_key(None)
    }

    pub(crate) fn pick_key(&self, key: Option<&str>) -> Option<usize> {
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let now = self.now_ms();

        match self.balance {
            Balance::RoundRobin => self.pick_round_robin(start as u64, now),
            Balance::LeastConn => self.pick_least_conn(start, now),
            Balance::Hash => match key {
                Some(key) => self.pick_rendezvous(key, now),
                None => self.pick_round_robin(start as u64, now),
            },
            Balance::Random => self.pick_round_robin(splitmix64(start as u64), now),
        }
    }

    /// Try healthy servers first, then fall back to any server that is not
    /// explicitly `down`. A failed health probe or a stale ejection must not
    /// turn into an outage, but an operator's `down` flag is respected.
    fn candidate(&self, index: usize, now: u64, fallback: bool) -> bool {
        let backup_ready =
            (0..self.servers.len()).any(|other| !self.backup[other] && self.selectable(other, now));
        if self.down[index] || (self.backup[index] && backup_ready) {
            return false;
        }
        if fallback {
            return true;
        }
        self.selectable(index, now)
    }

    fn selectable(&self, index: usize, now: u64) -> bool {
        if self.down[index]
            || !self.health[index].load(Ordering::Relaxed)
            || self.passive[index].ejected_until_ms.load(Ordering::Relaxed) > now
        {
            return false;
        }
        let max = self.max_conns[index];
        max == 0 || self.active[index].load(Ordering::Relaxed) < max
    }

    fn pick_least_conn(&self, start: usize, now: u64) -> Option<usize> {
        let count = self.servers.len();
        for fallback in [false, true] {
            let mut best: Option<(usize, usize, u64)> = None;
            for offset in 0..count {
                let index = (start + offset) % count;
                if !self.candidate(index, now, fallback) {
                    continue;
                }
                let active = self.active[index].load(Ordering::Relaxed);
                let weight = self.effective_weight(index, now);
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
            if let Some((index, _, _)) = best {
                return Some(index);
            }
        }
        None
    }

    fn pick_round_robin(&self, start: u64, now: u64) -> Option<usize> {
        for fallback in [false, true] {
            if let Some(index) = self.pick_weighted(start, now, fallback) {
                return Some(index);
            }
        }
        None
    }

    fn pick_weighted(&self, start: u64, now: u64, fallback: bool) -> Option<usize> {
        let count = self.servers.len();
        let total: u64 = (0..count)
            .filter(|&index| self.candidate(index, now, fallback))
            .map(|index| self.effective_weight(index, now))
            .sum();
        if total == 0 {
            return None;
        }
        let mut slot = start % total;
        for index in 0..count {
            if !self.candidate(index, now, fallback) {
                continue;
            }
            let weight = self.effective_weight(index, now);
            if slot < weight {
                return Some(index);
            }
            slot -= weight;
        }
        None
    }

    /// Weight scaled by an in-progress slow start. A server that just came
    /// back receives a fraction of its configured weight, and the fraction
    /// grows until the ramp window closes.
    fn effective_weight(&self, index: usize, now: u64) -> u64 {
        let base = u64::from(self.weights[index]);
        let until = self.recover_at[index].load(Ordering::Relaxed);
        if until <= now {
            return base;
        }
        let window = self.slow_start[index].as_millis() as u64;
        if window == 0 {
            return base;
        }
        let elapsed = window.saturating_sub(until - now);
        (base.saturating_mul(elapsed) / window).max(1)
    }

    fn pick_rendezvous(&self, key: &str, now: u64) -> Option<usize> {
        for fallback in [false, true] {
            let mut best = None;
            let mut best_score = 0;
            for index in 0..self.servers.len() {
                if !self.candidate(index, now, fallback) {
                    continue;
                }
                let score = rendezvous(key, &self.server_labels[index]);
                if best.is_none() || score > best_score {
                    best = Some(index);
                    best_score = score;
                }
            }
            if let Some(index) = best {
                return Some(index);
            }
        }
        None
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub(crate) fn record_success(&self, index: usize) {
        let passive = &self.passive[index];
        passive.failures.store(0, Ordering::Relaxed);
        if passive.ejected_until_ms.swap(0, Ordering::Relaxed) != 0 {
            self.start_slow_start(index);
            tracing::info!(upstream = %self.servers[index], "upstream restored after ejection");
        }
    }

    fn start_slow_start(&self, index: usize) {
        let window = self.slow_start[index].as_millis() as u64;
        if window > 0 {
            self.recover_at[index].store(self.now_ms().saturating_add(window), Ordering::Relaxed);
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
        self.recover_at[index].store(0, Ordering::Relaxed);
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
            if up {
                self.start_slow_start(index);
            }
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
        let mut stream =
            elira_upstream::tcp_connect(&host, port, pool.tls.local_address, Some(&pool.resolver))
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
