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

- [ ] OCSP hook when `workers > 1`: run it in the supervisor and SIGHUP workers.
- [ ] DNS-01 cleanup hook: remove the TXT record after validation.
- [ ] Worker exit during a streaming app response: ensure the client gets a
  clean error instead of a truncated chunked body.

## A — security and operations

- [ ] Reject module files owned by a user other than the server user when
  sandboxing is off.
- [ ] Per-route `max_response_bytes`.
- [ ] Configurable FastCGI pool size per upstream instead of a global limit.
- [ ] `/status` per-worker snapshots instead of the last worker's snapshot.

## B — performance and compatibility

- [ ] QUIC idle timeout and 0-RTT configuration.
- [ ] TLS session ticket and resumption settings.
- [ ] Upstream HTTP/2 connection pool metrics.
- [ ] `cache.purge` by host/path prefix through the admin API.

## C — large projects

- [ ] WASM module runtime beside the native `.so` ABI.
- [ ] Upstream HTTP/3.
- [ ] DNS-01 against a real production CA with a controlled zone.

## Done

- [x] Streaming FastCGI and CGI.
- [x] Aggregated worker metrics and `/status`.
- [x] App concurrency limits and module path checks.
- [x] FastCGI connection pool.
- [x] OCSP file and refresh hook.
- [x] DNS-01 via an external hook.
- [x] Module sandbox in a child process.
