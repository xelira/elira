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
| Elira | 10.3k | 6.2 ms | 20 ms |

Static `1 MiB`, `wrk -t2 -c20 -d10s`:

| Server | Requests/sec | Throughput |
| --- | ---: | ---: |
| nginx | 3.07k | 3.0 GB/s |
| Elira | 1.51k | 1.48 GB/s |

Proxy `549 B`, `wrk -t2 -c50 -d10s`:

| Server | Requests/sec | p50 | p99 |
| --- | ---: | ---: | ---: |
| nginx | 21.5k | 2.0 ms | 6.3 ms |
| Elira | 11.5k | 4.0 ms | 20 ms |

## Findings

- The sendfile fast path only serves the first request on a plain HTTP/1.1
  connection; later keep-alive requests go through hyper. This is why large
  static files do not reach nginx throughput.
- Using sendfile for small files is slower than hyper streaming. The
  `sendfile_min_bytes` threshold (default 64 KiB) avoids that regression:
  the 549-byte case improved from 6.8k to 10.3k req/s.
- `open_file_cache` removed a further ~20% of static metadata work.
- The proxy gap is roughly 1.9x and comes from hyper's generic request path
  plus per-request bookkeeping, not from the upstream connection pool.

## Next steps

- A persistent static connection loop that keeps serving `GET`/`HEAD` after
  the first sendfile response would close most of the large-file gap.
- Caching small file bodies alongside metadata would cut the remaining
  per-request `open`/`read` cost.
