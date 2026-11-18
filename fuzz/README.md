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
cargo fuzz run fastcgi_target
cargo fuzz run accesslog_format
cargo fuzz run module_json
```

`scripts/fuzz.sh` wraps the run with a duration and a clear error when
`cargo-fuzz` is missing:

```
scripts/fuzz.sh config 60
```

The `Makefile` wraps the same command:

```
make fuzz FUZZ_TARGET=config FUZZ_TIME=60
```

Targets:

- `config` — `elira_config::Config::parse`. The corpus covers includes,
  environment substitution, worker/reuse-port, FastCGI, CGI and native-module
  examples.
- `migrate` — `elira_migrate::migrate`. The corpus includes regex locations
  and `try_files`.
- `headers` — `elira_proxy::preferred_encoding` and
  `elira_proxy::compressible`, driven by arbitrary Accept-Encoding values and
  content types.
- `proxy_protocol` — the public `elira::proxy_protocol::read_peer` entry
  point. The v1/v2 parsers are private, so the target feeds the input through
  a loopback `TcpStream`; this is slower than a pure parser target but keeps
  the fuzzer on a public API.
- `fastcgi_target` — `elira_fastcgi::Target::parse`, the parser behind
  `fastcgi_pass` (`host:port`, bracketed IPv6, and `unix:/path`).
- `accesslog_format` — `elira_accesslog::Format::parse` on an arbitrary
  template, then `render` against a fixed `Entry`. This covers the `$variable`
  parser and the log-escaping paths.
- `module_json` — `serde_json::from_slice` into `elira_module::Request` and
  `elira_module::Response`, the envelope a native module returns across the
  ABI. It includes base64-body and invalid-UTF-8 handling.

Corpus seeds live in `fuzz/corpus/<target>/`. Add a minimal input there when a
target starts from a shape the mutator is unlikely to discover on its own.

## What a crash means

A crash is an input under `fuzz/artifacts/<target>/` that made the target panic,
abort, overflow, or hit a sanitizer. For these targets that is a parser or
renderer bug in the crate under test, not a fuzzer harness bug: the harness
only feeds bytes and drops the result, so the panic came from the library. Keep
the artifact, minimize it with `cargo fuzz tmin <target> <artifact>`, and add it
as a regression test in the owning crate before changing the target.
