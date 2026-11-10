//! Cached DNS resolution shared by every upstream of a proxy.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hyper_util::client::legacy::connect::dns::Name;
use tower_service::Service;

/// Tunables and static entries for [`Resolver`].
#[derive(Debug, Clone, Default)]
pub struct ResolverOptions {
    /// How long a successful answer is reused. Zero disables caching.
    pub ttl: Duration,
    /// How long an empty answer is reused. Zero disables negative caching.
    pub negative_ttl: Duration,
    /// Names that never reach the system resolver. Keys are lower-case.
    pub hosts: HashMap<String, Vec<IpAddr>>,
}

#[derive(Clone)]
pub struct Resolver {
    inner: Arc<Inner>,
}

struct Inner {
    options: ResolverOptions,
    cache: Mutex<HashMap<String, Cached>>,
}

#[derive(Clone)]
struct Cached {
    expires: Instant,
    addrs: Vec<IpAddr>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("ttl", &self.inner.options.ttl)
            .field("negative_ttl", &self.inner.options.negative_ttl)
            .field("static_hosts", &self.inner.options.hosts.len())
            .finish()
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new(ResolverOptions::default())
    }
}

impl Resolver {
    pub fn new(options: ResolverOptions) -> Self {
        Self {
            inner: Arc::new(Inner {
                options,
                cache: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Resolve `host` and attach `port` to every answer.
    pub async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let key = normalize(host);
        if let Some(addrs) = self.inner.options.hosts.get(&key) {
            return Ok(addrs.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
        }

        if let Some(addrs) = self.cached(&key) {
            return Ok(addrs
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect());
        }

        let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
            .await?
            .map(|addr| addr.ip())
            .collect();
        let ttl = if addrs.is_empty() {
            self.inner.options.negative_ttl
        } else {
            self.inner.options.ttl
        };
        if ttl > Duration::ZERO {
            self.store(key, ttl, &addrs);
        }
        Ok(addrs
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    fn cached(&self, key: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.lock();
        let now = Instant::now();
        match cache.get(key) {
            Some(entry) if entry.expires > now => Some(entry.addrs.clone()),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    fn store(&self, key: String, ttl: Duration, addrs: &[IpAddr]) {
        self.lock().insert(
            key,
            Cached {
                expires: Instant::now() + ttl,
                addrs: addrs.to_vec(),
            },
        );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Cached>> {
        self.inner
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Service<Name> for Resolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let resolver = self.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = resolver.lookup(&host, 0).await?;
            Ok(addrs.into_iter())
        })
    }
}

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}
