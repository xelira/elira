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

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000", "127.0.0.1:3001"]

[[routes]]
host = "*"               # or example.com; `*` catches the rest
upstream = "app"
```

## What it does today

- routes on Host, ignoring case, port and userinfo; HTTP/2 uses `:authority`
- round-robins across the servers of an upstream
- TLS via rustls, ALPN `h2` then `http/1.1`, certificates reload on SIGHUP
- HTTP/1.1, HTTP/2, and HTTP/3 over QUIC on a separate UDP listener
- websockets and other `Upgrade` protocols, tunneled over a raw upstream socket
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

HTTP/3 request bodies are buffered up to 8 MiB; larger ones get a 413. The
response side streams. `CONNECT` still gets a 405. The HTTP/3 listener is
configured at startup and needs a restart to change.

## Layout

- `crates/elira-config` — parsing and validation, no I/O beyond reading the file
- `crates/elira-proxy` — request forwarding, header hygiene, health probing
- `crates/elira-tls` — certificate loading
- `crates/elira-accesslog` — log formatting
- `crates/elira-h3` — HTTP/3 over QUIC
- `crates/elira` — the binary

## License

MIT.
