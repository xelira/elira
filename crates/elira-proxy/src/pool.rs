//! Upstream pools, balancing and passive ejection.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use http::uri::Authority;
use http::{Request, Response};
use http_body_util::BodyExt;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

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
        }
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
) -> Result<Response<Body>, SendError> {
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

    let work = async {
        let stream = UnixStream::connect(path).await?;
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
