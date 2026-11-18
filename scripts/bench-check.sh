#!/usr/bin/env bash

set -euo pipefail

url="${1:-http://127.0.0.1:8080/}"
baseline="${2:-}"
duration="${DURATION:-10s}"
connections="${CONNECTIONS:-50}"
threads="${THREADS:-4}"
threshold="${THRESHOLD:-10}"

if ! command -v wrk >/dev/null 2>&1; then
    echo "error: wrk is required (apt-get install wrk)" >&2
    exit 2
fi

if [[ ! "$url" =~ ^https?:// ]]; then
    echo "error: URL must start with http:// or https:// (got: $url)" >&2
    exit 2
fi

output="$(wrk -t"$threads" -c"$connections" -d"$duration" --latency "$url")"
printf '%s\n' "$output"

rps="$(printf '%s\n' "$output" | awk '/Requests\/sec:/{print $2; exit}')"
p99="$(printf '%s\n' "$output" | awk '/^ *99%/{gsub(/ms/,"",$2); print $2; exit}')"

if [[ -z "$rps" || -z "$p99" ]]; then
    echo "error: cannot parse wrk output" >&2
    exit 1
fi

if [[ -z "$baseline" ]]; then
    echo "rps=$rps"
    echo "p99_ms=$p99"
    exit 0
fi

if [[ ! -f "$baseline" ]]; then
    printf 'rps=%s\np99_ms=%s\n' "$rps" "$p99" >"$baseline"
    echo "wrote baseline $baseline (rps=$rps, p99=${p99}ms)"
    exit 0
fi

base_rps="$(awk -F= '$1=="rps"{print $2; exit}' "$baseline")"
base_p99="$(awk -F= '$1=="p99_ms"{print $2; exit}' "$baseline")"

if [[ -z "$base_rps" || -z "$base_p99" ]]; then
    echo "error: baseline $baseline must contain rps= and p99_ms=" >&2
    exit 2
fi

status=0
if ! awk -v cur="$rps" -v base="$base_rps" -v limit="$threshold" \
    'BEGIN{exit !(cur + 0 < (base + 0) * (1 - limit / 100))}'; then
    echo "regression: rps $rps is below baseline $base_rps by more than ${threshold}%" >&2
    status=1
fi
if ! awk -v cur="$p99" -v base="$base_p99" -v limit="$threshold" \
    'BEGIN{exit !(cur + 0 <= (base + 0) * (1 + limit / 100))}'; then
    echo "regression: p99 ${p99}ms is above baseline ${base_p99}ms by more than ${threshold}%" >&2
    status=1
fi

if [[ "$status" -eq 0 ]]; then
    echo "ok: rps=$rps (baseline $base_rps), p99=${p99}ms (baseline ${base_p99}ms)"
fi
exit "$status"
