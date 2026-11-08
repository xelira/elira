# Fuzz targets

This directory is a separate Cargo workspace so the fuzz-only dependencies do
not end up in the normal build. It requires nightly Rust and `cargo-fuzz`:

```
cargo install cargo-fuzz --locked
cargo fuzz build
```

Run a target:

```
cargo fuzz run config
cargo fuzz run migrate
cargo fuzz run headers
cargo fuzz run proxy_protocol
```

The `Makefile` wraps the same commands:

```
make fuzz FUZZ_TARGET=config FUZZ_TIME=60
```

Targets:

- `config` — `elira_config::Config::parse`.
- `migrate` — `elira_migrate::migrate`.
- `headers` — `elira_proxy::preferred_encoding` and
  `elira_proxy::compressible`, driven by arbitrary Accept-Encoding values and
  content types.
- `proxy_protocol` — the public `elira::proxy_protocol::read_peer` entry
  point. The v1/v2 parsers are private, so the target feeds the input through
  a loopback `TcpStream`; this is slower than a pure parser target but keeps
  the fuzzer on a public API.
