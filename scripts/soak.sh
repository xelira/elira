#!/usr/bin/env bash

set -euo pipefail

url="${1:-http://127.0.0.1:8080/}"
duration="${DURATION:-60s}"
connections="${CONNECTIONS:-100}"
pid="${PID:-$(pgrep -x elira | head -1 || true)}"

if ! [[ "$url" =~ ^https?:// ]]; then
    echo "error: URL must start with http:// or https:// (got: $url)" >&2
    exit 2
fi

if command -v oha >/dev/null 2>&1; then
    oha --no-tui -z "$duration" -c "$connections" "$url" >/dev/null &
elif command -v wrk >/dev/null 2>&1; then
    wrk -t4 -c"$connections" -d"$duration" "$url" >/dev/null &
else
    echo "error: neither oha nor wrk is installed" >&2
    exit 1
fi
loader=$!

peak=0
while kill -0 "$loader" 2>/dev/null; do
    if [[ -n "$pid" && -r "/proc/$pid/status" ]]; then
        rss="$(awk '/VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
    else
        rss=0
    fi
    if [[ "$rss" =~ ^[0-9]+$ ]] && (( rss > peak )); then
        peak=$rss
    fi
    sleep 1
done
wait "$loader"

if [[ "$peak" -gt 0 ]]; then
    echo "peak_rss_kb=$peak"
else
    echo "peak_rss_kb=unknown"
fi
