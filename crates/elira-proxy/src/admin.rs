//! Admin status and cache/pool introspection.

use std::sync::atomic::Ordering;

use elira_config::Balance;

use crate::*;

impl Proxy {
    /// Drop every cached response. Returns false when caching is disabled.
    pub fn purge_cache(&self) -> bool {
        match &self.inner.cache {
            Some(cache) => {
                cache.purge();
                true
            }
            None => false,
        }
    }

    /// Drop cached responses whose host+path starts with `prefix`.
    pub fn purge_cache_prefix(&self, prefix: &str) -> usize {
        match &self.inner.cache {
            Some(cache) => cache.purge_prefix(prefix),
            None => 0,
        }
    }

    pub fn cache_stats(&self) -> Option<(usize, usize)> {
        self.inner.cache.as_ref().map(|cache| cache.stats())
    }

    /// The current pools and their servers, for the admin status endpoint.
    pub fn status(&self) -> serde_json::Value {
        let pools: Vec<_> = self
            .inner
            .pools
            .iter()
            .map(|pool| {
                let servers: Vec<_> = pool
                    .servers
                    .iter()
                    .enumerate()
                    .map(|(index, server)| {
                        serde_json::json!({
                            "address": server.to_string(),
                            "healthy": pool.health[index].load(Ordering::Relaxed),
                            "active": pool.active[index].load(Ordering::Relaxed),
                            "weight": pool.weights[index],
                            "ejected_for_ms": pool.passive[index]
                                .ejected_until_ms
                                .load(Ordering::Relaxed)
                                .saturating_sub(pool.now_ms()),
                        })
                    })
                    .collect();

                serde_json::json!({
                    "name": pool.name,
                    "balance": match pool.balance {
                        Balance::RoundRobin => "round_robin",
                        Balance::LeastConn => "least_conn",
                        Balance::Hash => "hash",
                        Balance::Random => "random",
                    },
                    "retries": pool.retries,
                    "http2": pool.h2.as_ref().map(|h2| {
                        let stats = h2.stats();
                        serde_json::json!({
                            "connections": stats.connections,
                            "active_streams": stats.active_streams,
                            "total_connections": stats.total_connections,
                            "queued_streams": stats.queued_streams,
                        })
                    }),
                    "http3": pool.h3.as_ref().map(|h3| {
                        let stats = h3.stats();
                        serde_json::json!({
                            "connections": stats.connections,
                            "active_requests": stats.active_requests,
                            "total_connections": stats.total_connections,
                        })
                    }),
                    "servers": servers,
                })
            })
            .collect();

        serde_json::json!({
            "upstreams": pools,
            "cache": self.cache_stats().map(|(bytes, entries)| serde_json::json!({
                "bytes": bytes,
                "entries": entries,
            })),
            "spooled": self.inner.spooled.load(Ordering::Relaxed),
            "spool_budget": self.inner.spool_budget.total,
            "spool_used": self.inner.spool_budget.used(),
        })
    }

    /// Active requests per upstream pool, for gauges.
    pub fn pool_loads(&self) -> Vec<(String, u64)> {
        self.inner
            .pools
            .iter()
            .map(|pool| {
                let active = pool
                    .active
                    .iter()
                    .map(|counter| counter.load(Ordering::Relaxed) as u64)
                    .sum();
                (pool.name.clone(), active)
            })
            .collect()
    }

    /// Custom HTTP/2 pool statistics per upstream.
    pub fn pool_h2_stats(&self) -> Vec<(String, elira_h2::Stats)> {
        self.inner
            .pools
            .iter()
            .filter_map(|pool| pool.h2.as_ref().map(|h2| (pool.name.clone(), h2.stats())))
            .collect()
    }

    /// Custom HTTP/3 pool statistics per upstream.
    pub fn pool_h3_stats(&self) -> Vec<(String, elira_h3upstream::Stats)> {
        self.inner
            .pools
            .iter()
            .filter_map(|pool| pool.h3.as_ref().map(|h3| (pool.name.clone(), h3.stats())))
            .collect()
    }

    /// How many upstream servers are up, and how many are down.
    pub fn upstream_counts(&self) -> (usize, usize) {
        let mut up = 0;
        let mut down = 0;

        for pool in &self.inner.pools {
            for healthy in &pool.health {
                if healthy.load(Ordering::Relaxed) {
                    up += 1;
                } else {
                    down += 1;
                }
            }
        }

        (up, down)
    }
}
