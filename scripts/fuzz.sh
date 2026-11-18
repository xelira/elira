#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "usage: $0 <target> [duration-seconds]" >&2
    exit 64
}

[ "$#" -ge 1 ] || usage
target=$1
duration=${2:-60}

case $target in
    '' | *[!A-Za-z0-9_-]*) usage ;;
esac

if [[ ! $duration =~ ^[1-9][0-9]*$ ]]; then
    echo "error: duration must be a positive number of seconds (got: $duration)" >&2
    exit 64
fi

if ! command -v cargo-fuzz >/dev/null 2>&1; then
    cat >&2 <<'EOF'
error: cargo-fuzz is not installed.
       cargo install cargo-fuzz --locked
EOF
    exit 2
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

exec cargo fuzz run "$target" -- -max_total_time="$duration"
