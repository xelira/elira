# Benchmarks

Baseline numbers from the local `elira` stand. The goal is to track the
tokio/hyper hot path against nginx, not to win a synthetic contest.

## Environment

- Debian 13, Linux 6.12, 4 vCPU, 5 GiB RAM.
- `nginx:alpine` in Docker with `worker_processes auto`, `sendfile on`,
  `keepalive 64` to the backend.
- `williamyeh/wrk` in Docker, host networking.
- Elira release build, `workers = 4`, `reuse_port = true`,
  `keepalive_requests = 100000`, access-log sampling `0`.
- Static file: 549-byte `index.html`; large file: 1 MiB `big.bin`.
- Proxy backend: nginx on `127.0.0.1:18090`.

## Results

Static `549 B`, `wrk -t2 -c50 -d10s`:

| Server | Requests/sec | p50 | p99 |
| --- | ---: | ---: | ---: |
| nginx | 46.5k | 0.78 ms | 3.5 ms |
| Elira | 51.7k | 0.63 ms | 4.1 ms |

Static `1 MiB`, `wrk -t2 -c20 -d10s`:

| Server | Requests/sec | Throughput |
| --- | ---: | ---: |
| nginx | 3.07k | 3.0 GB/s |
| Elira | 2.91k | 2.84 GB/s |

Proxy `549 B`, `wrk -t2 -c50 -d10s`:

| Server | Requests/sec | p50 | p99 |
| --- | ---: | ---: | ---: |
| nginx | 21.5k | 2.0 ms | 6.3 ms |
| Elira | 15.0k | 3.0 ms | 7.3 ms |

## Findings

- The fast static path now keeps the connection and serves every keep-alive
  `GET`/`HEAD`, falling back to hyper through a prefixed stream when a request
  needs the full pipeline.
- Small file bodies and canonical paths are cached in `open_file_cache`.
  Caching canonical paths and reusing metadata from `fast_static` removed two
  syscalls per request and moved the small-file case from 10k to 38k req/s.
- The sendfile fast path now handles large files on every keep-alive request,
  so the 1 MiB case is close to nginx.
- Small compressible files used to fall back to hyper whenever the client sent
  `Accept-Encoding`, even when the body was below `compression.min_bytes` and
  would not be compressed. Serving them through the fast path moved small
  static files from 35k to 225k req/s on a 16-vCPU local run, slightly ahead of
  nginx.
- The proxy gap is roughly 1.4x and comes from hyper's generic request path
  plus per-request bookkeeping, not from the upstream connection pool. The
  pool reuses about one upstream connection per client connection.
- The opt-in `h1_pool` reuses connections correctly but measured only
  marginally above the legacy client on this stand (~13.4k vs ~12.8k req/s),
  so it is not enabled by default.
- Runtime worker threads are divided across `workers`, so four worker
  processes do not oversubscribe four cores.

## Next steps

- Profile the hyper proxy path: header copying and the access-log/labels
  extensions are the likely remaining costs.

## Regression check

`scripts/bench-check.sh` runs `wrk --latency`, extracts requests/sec and p99,
and compares them with a baseline file. Without a baseline file it writes one,
so the first run records the current numbers:

```sh
./scripts/bench-check.sh http://127.0.0.1:8080/ /tmp/elira-baseline.txt
```

Later runs fail when requests/sec drop or p99 grows by more than
`THRESHOLD` percent (default `10`). Environment variables
`DURATION`, `CONNECTIONS`, `THREADS` and `THRESHOLD` override the defaults.
The same check is available as `make bench-check BASELINE=...`.

## Local 16-vCPU run

`oha -z 8s -c 50`, nginx 1.30.4 as both upstream and the reference frontend,
small file 11 bytes, large file 1 MiB:

| Scenario | nginx | Elira normal | Elira `fast_proxy` |
| --- | ---: | ---: | ---: |
| Static 11 B | 125k | 225k | 225k |
| Static 1 MiB | 16.0k | 30.2k | 30.2k |
| Proxy 11 B | 57.8k | 54.0k | 80.8k |
| Proxy 4 KiB, gzip | 47.3k | 40.7k | 45.6k |

The small-file result requires `[limits] open_file_cache`; the fast static path
no longer falls back on `Accept-Encoding` when the body is below
`[compression].min_bytes`. The proxy numbers are for `GET /index.html` with the
compression headers a browser sends. `fast_proxy = true` moves eligible routes
to a raw HTTP/1.1 relay with its own upstream pool and beats nginx by about 40%
on this run. It compresses small known-length bodies after buffering and streams
larger ones; requests outside its narrow eligibility set fall back to the hyper
path.


## Soak и память

`scripts/soak.sh` запускает длительную нагрузку и раз в секунду снимает
`VmRSS` процесса `elira`:

```sh
DURATION=10m CONNECTIONS=200 ./scripts/soak.sh http://127.0.0.1:8080/
```

В конце печатается `peak_rss_kb`. Через `PID=...` можно указать конкретный
процесс, если `elira` запущена не одна. Цель — проверить, что кэш,
spool-бюджеты и буферы `fast_proxy` не дают неограниченного роста памяти.
