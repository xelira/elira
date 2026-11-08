#!/bin/sh
# Print the next backlog item. The file is the source of truth; this only
# avoids grepping tiers by hand.
set -eu
file="${1:-BACKLOG.md}"
[ -f "$file" ] || { echo "no $file" >&2; exit 1; }
awk '
  /^## / { tier = $0; next }
  /^- \[ \]/ { print tier; print; exit }
' "$file"
