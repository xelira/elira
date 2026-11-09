# Elira

HTTP server and reverse proxy. Early, but the boring parts are done properly.

Pronounced *eh-LEE-rah*.

## Run

```
cargo build --release
cargo run -- run --config elira.toml
cargo run -- check --config elira.toml
cargo run -- migrate /etc/nginx/nginx.conf > elira.toml
```

`check` parses and validates without opening sockets. `migrate` converts a
subset of nginx configuration and prints what it could not carry over.

SIGHUP reloads routes, upstreams, certificates, TLS settings, cache policy,
health checks and the access log without dropping HTTP/1.1 or HTTP/2
connections. The listen addresses and connection limits need a restart, and
the server says so instead of pretending otherwise.

SIGUSR2 starts a replacement and waits for it to bind every listener before
draining the old process. If the replacement fails, the old process keeps
running. This needs `reuse_port = true`. The same readiness moment sends
`READY=1` and `MAINPID` to systemd, so the unit uses `Type=notify`.

## Config

```toml
listen = "0.0.0.0:8080"
# include = ["/etc/elira/conf.d/*.toml"]   # ${ENV} is substituted in values
listen_unix = "/run/elira.sock"   # optional unix listener
unix_tls = false                  # true terminates TLS with [tls]
# listen_unix_mode = 0o660
# listen_unix_owner = "1000:1000"
# h2c = true                      # HTTP/2 with prior knowledge on plain TCP
# workers = 4                     # needs reuse_port = true

[limits]
max_headers = 64
max_header_bytes = 16384
max_connections = 1024
idle_timeout_secs = 60
upstream_timeout_secs = 30
request_body_timeout_secs = 30
upstream_body_timeout_secs = 30
websocket_idle_secs = 3600
max_body_bytes = 8388608
requests_per_second = 100
burst = 200
response_buffer_bytes = 65536
response_spool_bytes = 8388608
trusted_proxies = ["10.0.0.0/8"]

[compression]
enabled = true
min_bytes = 1024

[tls]
cert = "/etc/elira/cert.pem"
key = "/etc/elira/key.pem"
# client_ca = "/etc/elira/clients.pem"
# client_auth = "optional"       # or "required"
# min_version = "tls12"

# Extra certificates selected by SNI. The pair above stays the default.
# [[tls.certificates]]
# cert = "/etc/elira/other.pem"
# key = "/etc/elira/other.key"
# names = ["other.example.com", "*.other.example.com"]

[log]
format = "text"                  # or "json"
# file = "/var/log/elira/access.log"
# max_bytes = 67108864
# keep = 3
# template = '$remote_addr "$request" $status $body_bytes_sent $request_time'
# syslog = "/dev/log"

[health]
enabled = true
path = "/health"
interval_secs = 5
timeout_secs = 2

[http3]
listen = "0.0.0.0:443"
cert = "/etc/elira/cert.pem"
key = "/etc/elira/key.pem"
# client_ca = "/etc/elira/clients.pem"
# client_auth = "required"

[connect]
enabled = false                 # an open CONNECT proxy is an SSRF pivot
allow = ["10.0.0.5:5432"]       # exact host:port destinations only

[metrics]
listen = "127.0.0.1:9090"
# auth_file = "/etc/elira/admin.htpasswd"

[cache]
enabled = true
ttl_secs = 60
stale_secs = 120                # serve stale while one refresh runs
max_bytes = 67108864
max_item_bytes = 1048576
# dir = "/var/cache/elira"      # bodies on disk, metadata in memory

# ACME instead of a static [tls] block. TLS-ALPN-01 only, needs port 443.
# [acme]
# domains = ["example.com", "www.example.com"]
# contacts = ["mailto:admin@example.com"]
# cache_dir = "/var/lib/elira/acme"
# production = true
# challenge = "http_01"           # default is "tls_alpn_01"
# http01_listen = "0.0.0.0:80"    # dedicated plain listener for HTTP-01

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000", "127.0.0.1:3001"]
balance = "least_conn"
retries = 1
dns_ttl_secs = 10               # cap on pooled connection lifetime
# tls = true
# http2 = true
# sni = "app.internal"          # needed when servers contains an IP
# health_path = "/ready"
# tls_ca = "/etc/elira/internal.pem"
# tls_insecure = false

[[upstreams]]
name = "container"
servers = ["unix:/run/app.sock"]

[[routes]]
host = "*"                      # or example.com, or *.example.com
upstream = "app"

[[routes]]
host = "*"
path = "/api"                   # longest prefix wins
upstream = "app"
strip_prefix = true             # /api/users reaches the backend as /users
timeout_secs = 5
requests_per_second = 50
max_body_bytes = 1048576
error_pages = ["502 /502.html"]
error_root = "/srv/errors"

[[routes]]
host = "old.example.com"
redirect = { to = "https://new.example.com/", status = 301 }

# Application targets: FastCGI, CGI and native modules.
[[routes]]
host = "php.example.com"
fastcgi_pass = "unix:/run/php.sock"
fastcgi_root = "/srv/www"
fastcgi_index = "index.php"

[[routes]]
host = "cgi.example.com"
path = "/cgi"
cgi_pass = "/srv/cgi/hello"

[[routes]]
host = "module.example.com"
module = "/etc/elira/hello.so"

# A static route uses root instead of upstream.
[[routes]]
host = "static.example.com"
root = "/srv/www"
index = ["index.html"]
spa = false                    # true serves index.html for client-side routes
try_files = ["$uri", "$uri.html"]
autoindex = false
auth_file = "/etc/elira/static.htpasswd"
ip_allow = ["10.0.0.0/8"]
add_headers = ["X-Frame-Options: DENY"]
remove_headers = ["X-Powered-By"]
```

The full reference, reload table and error list live in
[docs/configuration.md](docs/configuration.md). How a request moves through
the code is in [docs/architecture.md](docs/architecture.md).

## What it does

Routing:

- exact hosts, `*.example.com`, `host = "*"`, longest path prefix and
  `path_regex` after prefixes- `strip_prefix`, redirect routes, fixed `return` responses, regex `rewrites`,
  `try_files`, SPA fallback, directory listings
- per-route `add_headers`/`remove_headers` for responses and
  `request_headers`/`request_remove_headers` for upstream requests, with
  `$variable` expansion, plus `timeout_secs`, token bucket, concurrency limit,
  body cap and error pages
- HTTP Basic auth from htpasswd (bcrypt) and IPv4/IPv6 allow/deny lists

Upstreams:

- round robin, least connections and rendezvous hashing by IP, header, cookie,
  Authorization or URI, with per-server weights for round robin and least
  connections; active health checks with configurable method, expected status
  and Host, passive ejection
  after repeated transport failures, retries for idempotent requests,
  including buffered `PUT`/`DELETE` bodies, with a configurable `retry_on`
  policy for errors, timeouts and 5xx statuses
- streaming FastCGI over TCP (including DNS names) or unix sockets with an
  idle connection pool, streaming CGI scripts, and native `.so` modules
  (in-process or in a child runner) and sandboxed WebAssembly modules
- TCP and unix sockets in the same pool
- TLS with a custom CA, explicit `insecure`, per-upstream SNI and HTTP/2
- WebSocket and other `Upgrade` tunnelling, `CONNECT` with an explicit allowlist
- custom HTTP/2 and HTTP/3 upstream pools with connection/stream stats,
  selectable per upstream
- RFC 7239 `Forwarded` plus `X-Forwarded-For/Proto/Host/Port`, with the
  client-supplied copies dropped and the chain extended only for
  `trusted_proxies`

TLS:

- rustls with ALPN `h2` then `http/1.1`; HTTP/3 uses `h3`
- SNI-selected certificates on TCP and QUIC, minimum TLS version, and
  explicit cipher-suite/curve policy per listener
- shared TLS 1.3 ticket keys across workers for cross-process resumption
- mutual TLS on TCP and QUIC, optional or required, with per-route
  subject/issuer CN checks and client CRLs

HTTP:

- HTTP/1.1, HTTP/2 (TLS or h2c with prior knowledge), HTTP/3 over QUIC
- response trailers (gRPC `grpc-status`) forwarded end to end
- optional TLS and HTTP/2 on the unix listener, using the same `[tls]`
- body progress timeouts, websocket/CONNECT idle timeout and request-body caps
  enforced on streamed uploads, not only `Content-Length`
- optional memory or temporary-file buffering of upstream responses, with a
  global spool budget
- gzip/brotli, `Alt-Svc`, `Server` hiding, `X-Request-Id`

Static files:

- index files, MIME types, `ETag`, `If-None-Match`, `If-Modified-Since`
- `root` and `alias`, optional `expires_secs` and `etag = false`
- single and multipart byte ranges, `If-Range` and strong `ETag`s; `HEAD`;
  precompressed `.br`/`.gz` siblings
- on-the-fly compression; path traversal and symlink escapes rejected
- `sendfile(2)` for plain HTTP/1.1 GET/HEAD, including single ranges,
  conditionals and protected routes

Cache:

- small `GET` responses with `X-Cache: HIT`, `MISS` or `STALE`
- single-flight miss filling, so concurrent misses share one upstream fetch
- `Vary`, `Cache-Control`, `s-maxage`/`max-age`, `Age`
- `Authorization`/`Cookie` requests never read or write the cache
- optional disk bodies that survive a restart, and stale-while-revalidate with
  one background refresh using `If-None-Match`/`If-Modified-Since`

Ops:

- multiple TCP listeners with per-listener TLS and routes scoped to a
  listener, optional privilege drop, chroot, CPU affinity,
  `worker_rlimit_nofile` and a PID file
- L4 TCP and UDP stream proxying with round robin, least connections or
  client-IP hashing, idle timeouts and optional TLS termination
- Prometheus metrics plus JSON `/status` and `/config` on the admin listener
- `POST /reload`, `POST /drain`, `POST /cache/purge`, optional Basic auth
- text or JSON access log with request id, file rotation, nginx-like templates
  and syslog
- PROXY protocol v1/v2 before TLS and HTTP, and v2 over QUIC datagrams
- ACME via TLS-ALPN-01, HTTP-01 or DNS-01 (external hook, Cloudflare helper,
  wildcards), verified
  against Let's Encrypt staging and production
- `elira migrate` for nginx `proxy_pass`/`root`, `try_files`, `add_header`,
  `allow`/`deny`, auth files, gzip, TLS and regex locations
- `workers > 1`: supervised worker processes sharing the port via SO_REUSEPORT,
  with rolling restart on SIGUSR2 and an aggregated `/metrics`/`/status` in the
  supervisor

## Admin listener

With `[metrics]` set:

| Request | Result |
| --- | --- |
| `GET /metrics` | Prometheus text |
| `GET /status` | upstreams, servers, health, active requests, cache stats |
| `GET /config` | effective configuration as JSON |
| `POST /reload` | same as SIGHUP |
| `POST /drain` | graceful shutdown |
| `POST /cache/purge` | drop cached responses |

The listener has no TLS. Put it on loopback or set `auth_file`.

## Not yet

- `sendfile` still declines TLS, HTTP/2, compression and multi-range
  responses; those go through hyper or a multipart body. Single ranges,
  conditionals, auth, ACLs and per-route headers stay on the fast path.
- The HTTP/3 listener survives a reload when its address, certificate and
  client-auth settings did not change. Replacing the certificate file restarts
  the endpoint and resets live QUIC connections.
- ACME via TLS-ALPN-01 needs port 443; HTTP-01 needs a listener on port 80 or
  `acme.http01_listen`.
- Dynamic modules are native shared libraries and run in-process with full
  privileges. FastCGI and CGI buffer the request body; they do not stream very
  large uploads.
- FastCGI/CGI bodies stream with bounded channels; very large uploads are cut
  by `max_response_bytes`/`max_body_bytes`.
- `workers` and listener changes need a restart. SIGHUP reloads routes in every
  worker; SIGUSR2 rolls the workers one by one. Increasing `workers` on SIGHUP
  adds processes, decreasing needs a restart. In worker mode `/metrics` and
  `/status` are aggregated by the supervisor, and `/config` shows the snapshot
  it last reloaded; `POST /reload` and `/drain` are
  handled there; `/cache/purge?prefix=` is broadcast to workers.
- DNS resolution uses the system resolver. `dns_ttl_secs` bounds how long a
  pooled connection may outlive a DNS change.

## Layout

- `crates/elira` — binary, listener, runtime, sendfile, access log, admin API
- `crates/elira-config` — TOML types, defaults, validation, errors
- `crates/elira-proxy` — routing, forwarding, cache use, static files, health
- `crates/elira-tls` — PEM loading, SNI resolver, mTLS verifier, ALPN
- `crates/elira-upstream` — HTTPS connector and trust options
- `crates/elira-cache` — bounded response cache, disk bodies, stale window
- `crates/elira-auth` — htpasswd Basic auth and IP ACLs
- `crates/elira-limit` — token bucket
- `crates/elira-accesslog` — entry formatting, templates, syslog, request id
- `crates/elira-metrics` — counters, histogram, Prometheus rendering
- `crates/elira-h3` — QUIC endpoint and HTTP/3 request bridge
- `crates/elira-acme` — TLS-ALPN-01 certificate state machine
- `crates/elira-migrate` — nginx config to TOML

## Development artifacts

`target/debug` can grow past tens of gigabytes because of debug info and
incremental state. The workspace disables both for `dev` and `test`. To trim an
existing tree:

```
make prune-target             # remove debug artifacts above 20 GiB
make prune-target LIMIT_GB=8  # or another limit
```

## Tests and benchmarks

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo bench -p elira-cache
cargo bench -p elira-config
make load URL=https://example.com/
```

The end-to-end suite drives real sockets: routing, header spoofing, static
ranges, compression, cache privacy and `Vary`, stale refresh, auth and ACLs,
sendfile fallbacks, TLS and mutual TLS handshakes, PROXY protocol, unix
listeners and upstreams, a failed hot restart, and access logs.

## License

MIT.
