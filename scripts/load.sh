#!/usr/bin/env bash
# Run a small HTTP load test with oha or wrk.
#
# Usage: scripts/load.sh [URL]
#
# Environment:
#   DURATION     test duration (default: 10s)
#   CONNECTIONS  concurrent connections (default: 50)
#   THREADS      wrk threads (default: 4)

set -euo pipefail

url="${1:-http://127.0.0.1:8080/}"
duration="${DURATION:-10s}"
connections="${CONNECTIONS:-50}"
threads="${THREADS:-4}"

if [[ ! "$url" =~ ^https?:// ]]; then
    echo "error: URL must start with http:// or https:// (got: $url)" >&2
    exit 2
fi

if command -v oha >/dev/null 2>&1; then
    exec oha --no-tui -z "$duration" -c "$connections" "$url"
fi

if command -v wrk >/dev/null 2>&1; then
    # wrk requires its numeric options to be attached, as in -t4.
    exec wrk -t"$threads" -c"$connections" -d"$duration" "$url"
fi

cat >&2 <<'EOF'
error: neither oha nor wrk is installed.

Install one of them first:
  cargo install oha --locked
  # or your distribution's wrk package, for example:
  sudo apt-get install wrk
EOF
exit 1
