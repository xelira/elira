#!/bin/sh

set -eu
file="BACKLOG.md"
[ -f "$file" ] || { echo "no $file" >&2; exit 1; }
awk '
  /^## / { tier = $0; next }
  /^- \[ \]/ { print tier; print; exit }
' "$file"
