# Elira

HTTP server and reverse proxy. Early, but the boring parts are done properly.

Pronounced *eh-LEE-rah*.

## Run

```
cargo run -- run --config elira.toml
cargo run -- check --config elira.toml
```

SIGHUP reloads routes, upstreams, certificates and the log format without
dropping connections. The listen address and connection limits need a
restart, and the server says so instead of pretending otherwise.

## Config

```toml
listen = "127.0.0.1:8080"

[limits]
max_headers = 64
max_header_bytes = 16384
upstream_timeout_secs = 30
max_connections = 1024
idle_timeout_secs = 60
max_body_bytes = 8388608
requests_per_second = 100
burst = 200
trusted_proxies = ["10.0.0.0/8"]

[compression]
enabled = true
min_bytes = 1024

[tls]
cert = "/etc/elira/cert.pem"
key = "/etc/elira/key.pem"

[log]
format = "text"          # or "json"

[health]
enabled = true
path = "/health"
interval_secs = 5
timeout_secs = 2

[http3]
listen = "0.0.0.0:443"
cert = "/etc/elira/cert.pem"
key = "/etc/elira/key.pem"

[connect]
enabled = false                 # an open CONNECT proxy is an SSRF pivot
allow = ["10.0.0.5:5432"]       # exact host:port destinations only

[metrics]
listen = "127.0.0.1:9090"

[cache]
enabled = true
ttl_secs = 60
max_item_bytes = 1048576

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000", "127.0.0.1:3001"]
balance = "least_conn"
retries = 1

[[routes]]
host = "*"               # or example.com, or *.example.com
upstream = "app"

[[routes]]
host = "*"
path = "/api"            # longest prefix wins
upstream = "app"
strip_prefix = true      # /api/users reaches the backend as /users

[[routes]]
host = "old.example.com"
redirect = { to = "https://new.example.com/", status = 301 }

# A static route uses `root` instead of `upstream`.
[[routes]]
host = "static.example.com"
root = "/srv/www"
index = ["index.html"]
spa = false              # true serves index.html for client-side routes
add_headers = ["X-Frame-Options: DENY"]
remove_headers = ["X-Powered-By"]
```

## What it does today

- routes on Host, ignoring case, port and userinfo; HTTP/2 uses `:authority`
- round-robins across the servers of an upstream
- TLS via rustls, ALPN `h2` then `http/1.1`, certificates reload on SIGHUP
- HTTP/1.1, HTTP/2, and HTTP/3 over QUIC on a separate UDP listener
- websockets and other `Upgrade` protocols, tunneled over a raw upstream socket
- `CONNECT` tunnels, off by default and limited to an explicit `host:port` list
- static files: index files, MIME types, ETag and `If-None-Match`,
  `If-Modified-Since`, single byte ranges, `HEAD`, optional SPA fallback
- Prometheus metrics on a separate listener: requests by status class,
  latency histogram, in-flight connections, healthy upstreams
- round-robins or least-conn across upstreams, retries a dead one for bodyless
  idempotent requests
- gzip for compressible responses when the client asks, with `Vary`
- per-IP token-bucket rate limiting and a `Content-Length` body cap
- `trusted_proxies` so `X-Forwarded-For` is only extended by peers you name
- PROXY protocol v1 and v2, so a load balancer can pass the real client address
- routes by exact host, `*.wildcard`, longest path prefix, with `strip_prefix`
- redirect routes, per-route `add_headers`/`remove_headers`, `Server` can be hidden
- `X-Request-Id` echoed and forwarded, `Alt-Svc` advertises HTTP/3
- brotli and gzip, plus precompressed `.br`/`.gz` static siblings
- an in-memory cache for small `GET` responses with `X-Cache: HIT/MISS`
- `try_files` and generated directory listings (`autoindex`)
- TLS to upstreams, with a custom CA or an explicit insecure mode
- ACME (Let's Encrypt, TLS-ALPN-01) instead of a static `[tls]` block
- hot restart on `SIGUSR2` with `reuse_port = true`, no dropped connections
- access log in text or JSON, with a request id per line
- active health checks: a server that stops answering 2xx/3xx stops receiving
  traffic, and comes back on its own
- strips hop-by-hop headers, including the tokens named in `Connection`
- drops client-supplied `Forwarded`, any `X-Forwarded-*`, `X-Real-IP`,
  `X-Original-URL`, `X-Rewrite-URL`, and the underscore aliases, then sets
  its own
- 64 headers, 16 KiB buffer, 30 s header read timeout, 1024 connections,
  60 s idle timeout
- 30 s upstream timeout, 10 s drain on SIGINT or SIGTERM

## Not yet

`CONNECT` is disabled unless `[connect]` names the destinations, and it is
HTTP/1.1 only. Static files are streamed through userspace, not `sendfile`:
hyper owns the socket and never hands it to the body, so zero-copy needs a
connection takeover that this architecture does not do. Multi-range requests
fall back to the whole file. The HTTP/3 listener is restarted on SIGHUP, which
resets its live connections; HTTP/1.1 and HTTP/2 connections survive a reload.
The ACME path compiles and is wired, but has not been run against a real CA.

## Layout

- `crates/elira-config` — parsing and validation, no I/O beyond reading the file
- `crates/elira-proxy` — request forwarding, header hygiene, health probing
- `crates/elira-tls` — certificate loading
- `crates/elira-accesslog` — log formatting
- `crates/elira-h3` — HTTP/3 over QUIC
- `crates/elira` — the library, its `server` module, and the binary

## Tests

```
cargo test
```

The unit tests cover config validation, header hygiene, log escaping and
TLS loading. `crates/elira/tests/proxy.rs` drives the real listener over
real sockets: routing, spoofed headers, idle shutdown, websockets and
CONNECT.

## License

MIT.
