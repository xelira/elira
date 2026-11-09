#!/bin/sh
# Keep target/debug under a size limit. Incremental state is deleted first,
# then the debug tree itself; release and cross artifacts are untouched.
set -eu
limit_gb="${1:-20}"
target_dir="${CARGO_TARGET_DIR:-target}/debug"

case "$limit_gb" in
  ''|*[!0-9]*) echo "limit must be a positive integer number of GiB" >&2; exit 2 ;;
esac
if [ "$limit_gb" -lt 1 ]; then
  echo "limit must be at least 1 GiB" >&2
  exit 2
fi

[ -d "$target_dir" ] || { echo "$target_dir does not exist"; exit 0; }
limit_mb=$((limit_gb * 1024))
size_mb=$(du -sm "$target_dir" | cut -f1)

if [ "$size_mb" -le "$limit_mb" ]; then
  echo "$target_dir is ${size_mb} MiB, within ${limit_gb} GiB"
  exit 0
fi

if [ -d "$target_dir/incremental" ]; then
  echo "removing $target_dir/incremental"
  rm -rf "$target_dir/incremental"
  size_mb=$(du -sm "$target_dir" | cut -f1)
fi

if [ "$size_mb" -gt "$limit_mb" ]; then
  echo "removing $target_dir (${size_mb} MiB, limit ${limit_gb} GiB)"
  rm -rf "$target_dir"
else
  echo "$target_dir is ${size_mb} MiB, within ${limit_gb} GiB"
fi
