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

- [ ] Upstream HTTP/2 connection pool metrics: hyper's legacy client does not
  expose pool internals; needs a custom connector or client.

- [x] Shared disk cache read-through (`cache.shared`).
- [x] Global eviction and locking for the shared cache.
- [ ] Deduplicate concurrent writes of the same key in the shared cache.

- [ ] Worker exit during a streaming app response: document that an incomplete
  chunked body is the only observable outcome, or move the client socket into
  the supervisor.

- [ ] WASM module runtime beside the native `.so` ABI.
- [ ] Upstream HTTP/3.
- [ ] DNS-01 against a real production CA with a controlled zone.
- [ ] Fuzz the FastCGI/CGI streaming state machines with a scripted peer.

## Done

- [x] Streaming FastCGI and CGI.
- [x] Aggregated worker metrics and `/status`.
- [x] App concurrency limits and module path checks.
- [x] FastCGI connection pool.
- [x] OCSP file and refresh hook.
- [x] DNS-01 via an external hook.
- [x] Module sandbox in a child process.
