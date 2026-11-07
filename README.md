# Elira

HTTP server and reverse proxy. Early: HTTP/1.1 only, no TLS yet.

Pronounced *eh-LEE-rah*.

## Run

```
cargo run -- run --config elira.toml
```

Check a config without starting anything:

```
cargo run -- check --config elira.toml
```

## Config

```toml
listen = "127.0.0.1:8080"

[limits]
max_headers = 64
max_header_bytes = 16384
upstream_timeout_secs = 30

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000", "127.0.0.1:3001"]

[[routes]]
host = "*"            # or example.com; `*` catches the rest
upstream = "app"
```

## What it does today

- routes on Host, ignoring port and case
- round-robins across the servers of an upstream
- strips hop-by-hop headers, including the ones named in `Connection`
- drops client-supplied `Forwarded`, `X-Forwarded-*` and `X-Real-IP`,
  then sets its own
- caps headers at 64 entries and 16 KiB, times out upstreams at 30s
- drains connections on SIGINT or SIGTERM instead of cutting them

## Not yet

TLS, HTTP/2, HTTP/3, config reload, health checks, access logs,
websockets. Websocket and CONNECT requests get a 501 and 405 rather
than a half-open connection.

## Layout

- `crates/elira-config` — parsing and validation, no I/O beyond reading the file
- `crates/elira-proxy` — request forwarding, header hygiene
- `crates/elira` — the binary

## License

MIT.
