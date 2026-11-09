# Elira backlog

Living list for the self-improvement loop. One item per session.

## Rules

1. Pick the first unchecked item in the highest tier.
2. Implement it end to end, including tests and docs.
3. `cargo fmt`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`.
4. Commit and push. Mark the item `[x]` and add any follow-up as a new item.
5. If an item turns out to be a project rather than a task, split it into
   acceptance-sized pieces and move the leftovers to the appropriate tier.

`scripts/backlog.sh next` prints the next item. `make next-task` wraps it.

## S — correctness and availability

- [x] OCSP hook when `workers > 1`: run it in the supervisor and SIGHUP workers.
- [x] DNS-01 cleanup hook: remove the TXT record after validation.

- [x] Admin `/drain` and `/reload` in worker mode.

## A — security and operations

- [x] Reject module files owned by a user other than the server user when
  sandboxing is off.
- [x] Per-route `max_response_bytes`.
- [x] Per-route/global cap on proxied upstream responses.
- [x] Error pages for local errors and a global fallback.
- [x] Access-log sampling globally and per route.
- [x] Per-route mTLS with subject and issuer CN filters.
- [x] Per-route rate-limit keys: header, cookie or Authorization.
- [x] OCSP stapling for SNI certificates on TCP and QUIC.
- [x] TLS cipher suite and curve policy for TCP and HTTP/3.
- [x] Admin `GET /config` with the effective configuration.
- [x] Request header overrides and removals per route.
- [x] Passive upstream ejection after consecutive transport failures.
- [x] Rendezvous hash balancing by IP, header, cookie, Authorization or URI.
- [x] Multipart byte ranges for static files.
- [x] Disk spooling for large upstream responses.
- [x] TLS on the unix listener, reusing the `[tls]` configuration.
- [x] End-to-end gRPC trailer test through the custom HTTP/2 pool.
- [x] Per-route cache hit/miss/stale metrics.
- [x] Weighted round robin and least-connections balancing.
- [x] Streaming request-body cap for chunked uploads.
- [x] Configurable health probe method, status codes and Host.
- [x] `If-Range` with strong ETags and exact Last-Modified dates.
- [x] Header count and size limits for HTTP/3.
- [x] End-to-end gRPC request trailers through the HTTP/2 pool.
- [x] Global spool budget with streaming fallback.
- [x] CRL checks for client certificates on TCP and QUIC.
- [x] Per-route concurrency limit for proxied requests.
- [x] Request body buffering and spooling for early release and retries.
- [x] Single-flight cache fills for concurrent misses.
- [x] `retry_on` policy for transport errors, timeouts and 5xx responses.
- [x] Unix socket mode and numeric owner configuration.
- [x] Buffering for chunked request bodies with a replayed prefix on overflow.
- [x] Prefix replay for known-length bodies above the spool limit.
- [x] Additional TCP listeners with per-listener TLS.
- [x] Privilege drop, RLIMIT_NOFILE and PID file.
- [x] L4 TCP/UDP stream proxying with TLS termination.
- [x] Shared TLS 1.3 ticket keys across workers.
- [x] Per-route FastCGI pool size.
- [x] Purge tests through the admin listener in both single and worker mode.
- [x] Per-route cache enable/TTL overrides.
- [x] Configurable FastCGI pool size per route.
- [x] `/status` per-worker snapshots instead of the last worker's snapshot.
- [x] Wire prefix cache purge into the admin API and per-worker broadcast.

## B — performance and compatibility

- [x] QUIC idle timeout configuration.
- [x] QUIC 0-RTT server-side switch (`http3.early_data`).
- [x] 0-RTT integration test with a QUIC client.
- [x] TLS handshake and QUIC connection metrics.
- [x] Per-route FastCGI pool size.
- [x] TLS session ticket and resumption settings.
- [x] Upstream name in access logs.
- [x] `cache.purge` by host/path prefix through the admin API.
- [x] Expand parser fuzz targets.
- [x] Cache prefix invalidation API.

## C — large projects

- [x] Upstream pool active-request gauge.
- [x] Cache stale and health-check counters.
- [x] Configurable connection drain and shutdown timeouts.
- [x] TLS certificate expiry metric.
- [x] Per-route access-log toggle.
- [x] RFC 7239 Forwarded and X-Forwarded-Port.
- [x] Cache-Control must-revalidate. Disk format bumped to ELIRA2.
- [x] Expires/Date TTL fallback.
- [x] Request Cache-Control/Pragma no-cache bypass.
- [x] Custom HTTP/2 upstream client with pool stats.
- [x] Prometheus gauges for the custom HTTP/2 pool.

- [x] Shared disk cache read-through (`cache.shared`).
- [x] Global eviction and locking for the shared cache.
- [x] Deduplicate concurrent writes of the same key in the shared cache.

- [x] Worker socket handoff: not implemented by design; a worker drains on
  SIGTERM and in-flight connections are not transferred.

- [x] WASM module runtime beside the native `.so` ABI, including a fuel budget.
- [x] Upstream HTTP/3 pool (`h3_pool`).
- [x] Prometheus gauges for the HTTP/3 upstream pool.
- [x] Custom FastCGI/CGI params.
- [x] DNS-01 against a real production CA, verified on
  `elira-dns-prod.owaw.online` through Cloudflare and Let's Encrypt.
- [x] Scripted-peer tests for truncated and trailing FastCGI/CGI streaming
  framing.

## N — nginx parity

### Section 1 leftovers (architecture)

- [x] `chroot` support after config load and before runtime files.
- [x] `worker_cpu_affinity`.
- [x] Per-listener route sets via `routes.listeners`.

### Section 2 — routing and configuration language

- [x] Variables in `request_headers`, `add_headers` and redirects;
  `$remote_addr`, `$host`, `$request_uri`, `$request_id` at minimum.
- [x] Variables in `error_pages` paths.
- [ ] `rewrite` rules, `return` with variables, `if`, `map`, `geo`,
  `split_clients`.
- [ ] `location =`, `^~`, nested and named locations, `internal`.
- [ ] `alias` (distinct from `root`).
- [ ] `auth_request` subrequests.
- [ ] `satisfy any/all` for auth plus ACL combinations.
- [ ] `secure_link`.
- [ ] `X-Accel-Redirect` and `X-Sendfile` from upstream responses.
- [ ] `error_page` status overrides (`=200`) and named locations.
- [ ] `expires`, `add_header ... always`, `etag off`,
  `if_modified_since off`.

### Section 3 — proxying and cache

- [ ] Per-status cache TTL (`proxy_cache_valid`), cache key and bypass
  directives, cache zones, manager/loader.
- [ ] FastCGI/CGI response caching.
- [ ] Upstream client certificates, upstream CRL and upstream cipher policy.
- [ ] Separate connect/send/read timeouts.
- [ ] `proxy_protocol on` toward upstreams and `proxy_bind`.
- [ ] `proxy_redirect`, `proxy_cookie_domain/path`, `proxy_hide_header`.
- [ ] Upstream keepalive tuning: `keepalive`, `keepalive_requests`, per-server
  `max_conns`, `backup`, `down`, `slow_start`, `random`.
- [ ] Configurable resolver with runtime DNS and TTL policy.

### Section 4 — limits and operations

- [ ] `limit_rate` and `limit_rate_after` bandwidth throttling.
- [ ] `limit_conn` per-IP concurrent connection limits.
- [ ] `limit_req` delay/nodelay semantics on top of the token bucket.
- [ ] `keepalive_requests` per connection.
- [ ] Configurable `client_header_timeout`, `lingering_close`,
  `reset_timedout_connection`.
- [ ] Log reopen on SIGUSR1 for external rotation.
- [ ] `open_file_cache`.
- [ ] `worker_rlimit_nofile` propagation tuning and `worker_processes auto`.

### Section 5 — HTTP details

- [ ] `103 Early Hints`.
- [ ] `h2c Upgrade`.
- [ ] Dual RSA + ECDSA certificates per name.
- [ ] Verify stapled OCSP responses (`ssl_stapling_verify`).
- [ ] `ssl_reject_handshake` for unknown SNI.
- [ ] HTTP/2 max concurrent streams and window tuning.
- [ ] HTTP/3 QUIC transport tuning exposed in `[http3]`.

### Section 6 — observability

- [ ] `$upstream_addr`, `$upstream_status`, `$upstream_response_time` in
  access logs and templates.
- [ ] Map-derived log variables.
- [ ] Request/response bytes and timings split per route and upstream.

### Section 7 — performance

- [ ] `io_uring`/AIO and `open_file_cache` for static files.
- [ ] Zero-copy `sendfile` through TLS and HTTP/2.
- [ ] Benchmark and tune the tokio/hyper hot path against nginx baselines.

## Done

- [x] Streaming FastCGI and CGI.
- [x] Aggregated worker metrics and `/status`.
- [x] App concurrency limits and module path checks.
- [x] FastCGI connection pool.
- [x] OCSP file and refresh hook.
- [x] DNS-01 via an external hook.
- [x] Module sandbox in a child process.
