# Elira

[![ci](https://github.com/xelira/elira/actions/workflows/ci.yml/badge.svg)](https://github.com/xelira/elira/actions/workflows/ci.yml)
[![release](https://github.com/xelira/elira/actions/workflows/release.yml/badge.svg)](https://github.com/xelira/elira/actions/workflows/release.yml)
![MSRV](https://img.shields.io/badge/MSRV-1.88%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Other languages: [Русский](README.ru.md) · Changelog: [CHANGELOG.md](CHANGELOG.md)

Elira is an HTTP/1.1, HTTP/2 and HTTP/3 server and reverse proxy written in
Rust. It can serve static files, proxy requests, terminate TLS, cache
responses, mirror traffic, and run as a pool of worker processes.

Version 0.1.0. The configuration format and APIs may still change, but the
main subsystems are complete — there are no stubs behind the advertised
features. Pronounced *eh-LEE-rah*.

## Request flow at a glance

```
   HTTP/1.1 + TLS        HTTP/2 (h2/h2c)        HTTP/3 over QUIC
          |                      |                       |
   PROXY v1/v2 (opt-in)          |          PROXY v2 datagrams (opt-in)
          +----------------------+-----------------------+
                                 |
                    +------------v-------------+
                    | listener / accept loop   |
                    | limits.max_connections   |
                    +------------+-------------+
                                 |
              +------------------+-------------------+
              |                                      |
      simple GET/HEAD                        everything else
      sendfile / fast_proxy                  (hyper service)
              |                                      |
      +-------v--------+                  +----------v-----------+
      | direct relay to|                  | Router and policies: |
      | upstream pool  |                  | auth, ACL, limits,   |
      +-------+--------+                  | rewrites, cache      |
              |                           +----------+-----------+
              |                                      |
              |                  +-------------------+------------------+
              |                  |          |           |              |
              |              static      cache       app          upstream
              |              files       HIT/MISS   FastCGI/     pools (h1/h2/h3)
              |                                      WASM/CGI
              +--------------------------+--------------------+
                                         |
                              access log + Prometheus metrics
```

With `workers > 1` the listener sockets share the port via `SO_REUSEPORT`;
each worker runs this pipeline independently. `limits.shared_limits = true`
splits connection and rate-limit quotas between workers by index so the
combined ceiling stays at the configured value.

## Build and run

```sh
cargo build --release
./target/release/elira check --config elira.toml
./target/release/elira run --config elira.toml
```

Or through cargo:

```sh
cargo run -p elira -- check --config elira.toml
cargo run -p elira -- run --config elira.toml
```

`check` reads and validates the configuration without opening sockets —
suitable for CI and systemd units. `migrate` converts part of an nginx config
into TOML:

```sh
./target/release/elira migrate /etc/nginx/nginx.conf > elira.toml
```

It translates `proxy_pass`, `root`, `try_files`, `add_header`, `allow`/`deny`,
htpasswd, gzip, TLS and regex locations. Review the result by hand.

Prebuilt Linux binaries (GNU and musl, x86-64 and arm64) are published in
[GitHub Releases](https://github.com/xelira/elira/releases).

## Minimal configuration

```toml
listen = "0.0.0.0:8080"

[limits]
max_connections = 4096
idle_timeout_secs = 60
upstream_timeout_secs = 30

[log]
format = "text"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000", "127.0.0.1:3001"]
balance = "least_conn"
health_path = "/ready"

[[routes]]
host = "*"
upstream = "app"
```

Static files:

```toml
[[routes]]
host = "example.com"
root = "/srv/www"
index = ["index.html"]
try_files = ["$uri", "$uri.html"]
```

TLS and HTTP/3:

```toml
[tls]
cert = "/etc/elira/cert.pem"
key = "/etc/elira/key.pem"

[http3]
listen = "0.0.0.0:443"
cert = "/etc/elira/cert.pem"
key = "/etc/elira/key.pem"
```

Configuration can be split across files with
`include = ["/etc/elira/conf.d/*.toml"]`; `${ENV}` substitution is supported.
The full reference is in [docs/configuration.md](docs/configuration.md)
(currently in Russian).

## fast_proxy

`fast_proxy = true` enables a raw HTTP/1.1 relay: requests and responses move
between the client and upstream without hyper, through a dedicated connection
pool.

```toml
[[routes]]
host = "api.example.com"
upstream = "app"
fast_proxy = true
```

Supported: plain HTTP/1.1 clients and clients after TLS termination; HTTP and
HTTPS upstreams including SNI and client certificates; bodyless `GET`/`HEAD`;
gzip/brotli with buffering up to 256 KiB and streaming for larger bodies;
`add_headers`/`remove_headers`, `proxy_hide_header`/`proxy_pass_header`;
`request_headers`/`request_remove_headers`; `proxy_redirect`,
`proxy_cookie_domain`, `proxy_cookie_path`; static and named `error_pages`
without variables; `early_hints`; one retry of `GET`/`HEAD` if an already open
upstream connection breaks before the response; and a pool with a 60-second
idle TTL and metrics.

Anything else falls back to the normal path automatically. The flag is
opt-in because the raw path does not apply auth, ACL, `secure_link`, `if`,
cache, rate/conn limits, rewrites, `X-Sendfile`,
`max_upstream_response_bytes`, TLS/Unix/H2/H3 upstreams, hash balancing, or
variables in headers — and it does not write per-route `Labels` metrics.

## Cache with tags

The cache reads tags from `Surrogate-Key` and `Cache-Tag`:

```text
Surrogate-Key: catalog product-42
Cache-Tag: catalog
```

Purge by tag:

```text
POST /cache/purge?tag=catalog
```

Memory and disk entries, a shared disk cache, and broadcast purges to all
workers are supported. The disk format is `ELIRA3`; older `ELIRA2` files load
without tags.

Also available: `X-Cache: HIT|MISS|STALE`, `Vary`, `Cache-Control`,
`s-maxage`, `max-age`, `Age`, `must-revalidate`, stale-while-revalidate,
single-flight fills, named zones with independent budgets, and
`require_explicit = true` by default — responses without `Cache-Control` or
`Expires` are not cached unless you opt in. Sensitive headers such as
`Authorization`, `Cookie`, `X-API-Key`, `X-Auth-*`, `*-token` and any header
listed in `[cache].sensitive_headers` bypass the cache entirely.

## Traffic mirroring

```toml
[[routes]]
host = "*"
upstream = "app"
mirror = "shadow"
mirror_percent = 100
```

`mirror` sends a copy of the request to another upstream and ignores its
response. `GET`/`HEAD` with an empty or already buffered body are mirrored;
the sample decision is deterministic on `request_id`. Useful for shadow
warming, canary checks and collecting metrics from a new version.

## Adaptive concurrency

```toml
[limits]
adaptive_concurrency = true
adaptive_target_ms = 50
adaptive_min = 8
adaptive_max = 256
```

An AIMD limit on concurrent proxied requests: it shrinks above the target
latency and grows while latency stays low. New proxied requests receive `503`
at the limit. Static files, cache hits and locally generated responses are
not limited. With `shared_limits = true` the quota is split between workers.

## TLS and kTLS

rustls is the default backend. `backend = "openssl"` enables OpenSSL,
including TLS 1.0/1.1 and kernel TLS:

```toml
[tls]
backend = "openssl"
ktls = true
ktls_zerocopy = false
```

`ktls = true` sets `SSL_OP_ENABLE_KTLS`; `ktls_zerocopy = true` additionally
sets `SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE` — faster, but a file modified
during transmission can produce corrupted TLS records. Large static files go
through `SSL_sendfile` when kTLS is active. If the kernel has no `tls` ULP,
Elira falls back to async copying without hyper. SNI certificates, RSA and
ECDSA names, mTLS, CRL, OCSP, shared TLS 1.3 ticket keys and custom
cipher/curve policies are supported. The certificate and private key are
matched at startup, so a bad pair is a config error rather than a failing
handshake.

## HTTP/3 and 0-RTT

HTTP/3 uses a separate UDP listener. With `early_data = true` only
idempotent methods are allowed before the QUIC handshake completes:
`GET`, `HEAD`, `OPTIONS`, `TRACE`. Non-idempotent methods receive
`425 Too Early` to prevent POST/PUT/DELETE replay. Session tickets are
single-use; the seen-ticket table is per process, so strict cross-worker
anti-replay is not guaranteed.

## Dynamic upstream weights

```text
POST /upstream/weight?upstream=app&index=0&weight=3
```

Changes a server's weight without reload or restart and broadcasts to all
workers. An unknown upstream or index returns `{"updated":false}`.

## Reload and signals

| Signal | Effect |
| --- | --- |
| `SIGHUP` | Reloads routes, upstreams, certificates, TLS, cache, health checks and log format. HTTP/1.1 and HTTP/2 connections survive. |
| `SIGUSR1` | Reopens the access log file. |
| `SIGUSR2` | Hot restart: starts a new process, waits for readiness, then stops the old one. Requires `reuse_port = true`. |
| `SIGINT`, `SIGTERM` | Graceful shutdown with a bounded drain timeout. |

With `workers > 1` the supervisor shares the port via `SO_REUSEPORT`,
restarts workers one at a time and reports `READY=1`/`MAINPID` to systemd.
When `user` is set, it drops root and keeps only `CAP_NET_BIND_SERVICE`.

## Features

### Protocols

- HTTP/1.1, HTTP/2 over TLS and h2c prior knowledge, HTTP/3 over QUIC.
- WebSocket over HTTP/1.1, HTTP/2 (RFC 8441) and HTTP/3.
- `CONNECT` over HTTP/1.1, HTTP/2 and HTTP/3 with a `host:port` allowlist.
- `103 Early Hints` on HTTP/1.1 and in `fast_proxy`.

### Routing and static files

- Exact hosts, `*.example.com`, `host = "*"`, longest prefix, `match = "exact"`,
  `no_regex`, `path_regex`.
- Nested locations, named `@locations`, `internal`, `try_files`, SPA fallback,
  autoindex.
- `strip_prefix`, redirects, `return`, regex rewrites, `map`/`geo`/`split`,
  conditional `if` responses.
- Request/response headers, Basic auth (bcrypt), IPv4/IPv6 ACL,
  `auth_request`, `secure_link`, `satisfy any/all`, opt-in stripping of
  `Authorization` after local auth.
- `X-Accel-Redirect` and `X-Sendfile` from allowed directories.
- Named error pages, including `"404 =200 /soft-404.html"`.
- Index files, MIME, ETag, `If-None-Match`, `If-Modified-Since`, byte ranges
  (including multipart), HEAD, precompressed `.br`/`.gz`, gzip/brotli,
  `sendfile(2)` on plain HTTP/1.1, `force_download`.
- Path traversal, symlink escapes and special files are rejected.

### Upstreams

- `round_robin`, `least_conn`, rendezvous hashing, random.
- Weights, `backup`, `down`, `max_conns`, slow start.
- Active health checks and passive ejection after transport failures.
- Idempotent retries and a configurable `retry_on` policy.
- Separate connect/send/read timeouts.
- TCP and Unix sockets, DNS cache with positive and negative TTL,
  `resolver.pin`.
- TLS to upstreams: CA, `insecure`, SNI, client certificates, CRL.
- PROXY protocol v1 towards upstreams.
- Dedicated HTTP/2 and HTTP/3 pools with connection/stream metrics.
- FastCGI (with multiplexing), SCGI, uWSGI, AJP13, CGI.
- Native `.so` modules and a WebAssembly sandbox.

### Limits and security

- Token bucket by IP, header, cookie or `Authorization`.
- Connection, header, body and response-rate limits, optionally split
  between workers.
- Adaptive concurrency.
- Request/response body timeouts, WebSocket/CONNECT idle timeouts.
- Hop-by-hop headers and `Connection` tokens are removed.
- `Forwarded`/`X-Forwarded-*` are cleared and rebuilt only for
  `trusted_proxies`.
- PROXY protocol v1/v2 before TLS and HTTP; v2 on QUIC with a trusted-peer
  check.
- `user`/`group`, chroot, CPU affinity, `worker_rlimit_nofile`, PID file.
- Include cycles, secret-file permissions, `openat2` for static files.

### Observability

- Access log in text/JSON, request id, rotation, nginx-like templates, syslog.
- `$upstream_addr`, `$upstream_status`, `$upstream_response_time`.
- Prometheus metrics, `/status`, `/config`, `/metrics`.
- Per-route, per-upstream, cache, TLS, QUIC and pool metrics.
- `fast_proxy` hit/fallback reasons and pool idle/active/created/reused/errors.
- L4 TCP/UDP proxy with balancing, idle timeout and TLS.
- Multiple TCP listeners with separate TLS and route sets.

## Admin listener

Enabled with a `[metrics]` section:

| Request | Response |
| --- | --- |
| `GET /metrics` | Prometheus text |
| `GET /status` | JSON: upstreams, servers, health, requests, cache |
| `GET /config` | Effective config as JSON, secrets redacted |
| `POST /reload` | Same as `SIGHUP` |
| `POST /drain` | Graceful shutdown |
| `POST /cache/purge` | Purge by `?prefix=` or `?tag=` |
| `POST /upstream/weight` | `?upstream=NAME&index=N&weight=W` |

There is no TLS on this listener. Bind it to loopback or set `auth_file`; a
non-loopback listener without `auth_file` refuses to start. POST requests
also require the `x-elira-admin: 1` header, otherwise `403`.

## Performance

Local bench: 16 vCPU, Linux 6.12, nginx 1.30.4 as upstream and reference,
`oha -z 5s -c 50`, `GET /index.html`.

| Scenario | nginx | Elira normal | Elira `fast_proxy` |
| --- | ---: | ---: | ---: |
| Static, 11 B | 125k | **225k** | **225k** |
| Static, 1 MiB | 16.0k | **30.2k** | **30.2k** |
| Proxy, 11 B | 57.8k | 54.0k | **80.8k** |
| Proxy, 4 KiB, gzip | 47.3k | 40.7k | **45.6k** |

Small static files require `[limits] open_file_cache`. `fast_proxy` adds
about +40% over nginx for tiny proxied responses and +50% over Elira's normal
path. Compressed proxying nearly catches up with nginx. TLS static is
encryption-bound; kTLS may change that on hosts with kernel `tls` support.
Details and the benchmark method are in
[docs/benchmarks.md](docs/benchmarks.md).

## Tests

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
cargo audit
```

End-to-end tests use real sockets and cover routing, headers, ranges,
compression, cache and `Vary`, stale updates, auth/ACL, TLS and mTLS, PROXY
protocol, Unix listeners, upstreams, hot restart, access logs, `fast_proxy`,
mirroring, error pages, 0-RTT and cache tags. Request-smuggling framing,
ambiguous path normalization and atomic runtime swaps under load are tested
separately.

```sh
cargo bench -p elira-cache
cargo bench -p elira-config
./scripts/bench-check.sh http://127.0.0.1:8080/ baseline.txt
```

## Limitations

- `fast_proxy` does not cover auth/ACL, cache, `secure_link`, `if`, rewrites,
  rate/conn limits, `X-Sendfile`, `max_upstream_response_bytes`, Unix/H2/H3
  upstreams, hash balancing or variables in headers — such requests use the
  normal path.
- `sendfile(2)` works only on plain HTTP/1.1. TLS clients use a separate fast
  path; kTLS requires `backend = "openssl"` and kernel `tls` support.
- `ktls_zerocopy` can emit corrupted TLS records if a file changes while it
  is being sent.
- `SIGHUP` preserves upstream pools, cache, token buckets and the adaptive
  limiter when the proxy configuration is unchanged. Changing routes,
  upstreams, cache or limits rebuilds `Proxy` and resets that state.
- HTTP/3 supports SNI certificates via `[[http3.certificates]]`. WebTransport
  and arbitrary extended CONNECT return `501`.
- The HTTP/3 listener survives `SIGHUP` unless its address, certificates or
  client-auth settings change.
- ACME TLS-ALPN-01 needs port 443; HTTP-01 needs a port-80 listener or
  `acme.http01_listen`.
- Native modules have full process privileges; use WebAssembly for
  untrusted code.
- FastCGI and CGI buffer request bodies; large uploads are cut by limits.
- DNS uses the system resolver, without SRV. `resolver.pin` protects against
  rebinding but needs static IPs or trusted DNS.
- `chrono` arrives transitively through `rustls-acme` and is marked
  unmaintained; it is tracked by `cargo audit` and `cargo deny`.

## Repository layout

- `crates/elira` — binary, listeners, runtime, sendfile, access log, admin API.
- `crates/elira-config` — TOML types, defaults, validation.
- `crates/elira-proxy` — routing, proxying, static files, health, `fast_proxy`,
  adaptive concurrency.
- `crates/elira-tls` — PEM, SNI, mTLS, ALPN, CRL/OCSP, kTLS.
- `crates/elira-pem` — own PEM parser.
- `crates/elira-upstream` — HTTPS connector, resolver, trust.
- `crates/elira-cache` — memory, disk, tags, stale.
- `crates/elira-auth` — htpasswd and IP ACL.
- `crates/elira-limit` — token bucket.
- `crates/elira-accesslog` — formatting, templates, syslog, request id.
- `crates/elira-metrics` — counters, histograms, Prometheus.
- `crates/elira-h3` — QUIC endpoint and HTTP/3.
- `crates/elira-h2`, `elira-h1upstream`, `elira-h3upstream` — upstream pools.
- `crates/elira-acme` — ACME state and domain validation.
- `crates/elira-fastcgi`, `elira-cgi`, `elira-module`, `elira-wasm` — app
  backends.
- `crates/elira-migrate` — nginx config converter.

Architecture notes: [docs/architecture.md](docs/architecture.md).
Security notes: [SECURITY.md](SECURITY.md).
Repository setup notes: [docs/github-setup.md](docs/github-setup.md).

## License

MIT.
