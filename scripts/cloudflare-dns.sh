#!/bin/sh
# Publish or remove an ACME DNS-01 TXT record through the Cloudflare API.
#
# Environment:
#   CLOUDFLARE_API_TOKEN  token with Zone:Read and DNS:Edit
#   DOMAIN                identifier being validated (may start with "*.")
#   TXT_NAME              full record name, e.g. _acme-challenge.example.com
#   VALUE                 TXT value
#   TOKEN                 ACME challenge token (unused here)
#   ACTION                "cleanup" to delete, anything else to publish
#
# The script is used as both dns_hook and dns_cleanup_hook. It never prints the
# token and fails closed when the API rejects a request.
set -eu

: "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
: "${TXT_NAME:?TXT_NAME is required}"
: "${VALUE:?VALUE is required}"

API="https://api.cloudflare.com/client/v4"
AUTH="Authorization: Bearer ${CLOUDFLARE_API_TOKEN}"

zones=$(curl -fsS -H "$AUTH" "$API/zones?per_page=50")
zone_id=$(printf '%s' "$zones" | python3 -c '
import json, sys
txt = sys.argv[1].lower()
zones = json.load(sys.stdin).get("result", [])
matches = [z for z in zones if txt == z["name"] or txt.endswith("." + z["name"])]
if not matches:
    sys.exit("no Cloudflare zone matches " + txt)
print(max(matches, key=lambda z: len(z["name"]))["id"])
' "$TXT_NAME")

records=$(curl -fsS -G -H "$AUTH" \
    --data-urlencode "type=TXT" \
    --data-urlencode "name=$TXT_NAME" \
    "$API/zones/$zone_id/dns_records")

existing=$(printf '%s' "$records" | python3 -c '
import json, sys
value = sys.argv[1]
for record in json.load(sys.stdin).get("result", []):
    if record.get("content") == value:
        print(record["id"])
' "$VALUE")

if [ "${ACTION:-publish}" = "cleanup" ]; then
    for id in $existing; do
        curl -fsS -X DELETE -H "$AUTH" "$API/zones/$zone_id/dns_records/$id" >/dev/null
    done
    exit 0
fi

# Replace an identical stale record before creating a fresh one.
for id in $existing; do
    curl -fsS -X DELETE -H "$AUTH" "$API/zones/$zone_id/dns_records/$id" >/dev/null
done

body=$(python3 -c '
import json, sys
print(json.dumps({
    "type": "TXT",
    "name": sys.argv[1],
    "content": sys.argv[2],
    "ttl": 60,
}))
' "$TXT_NAME" "$VALUE")

response=$(curl -fsS -X POST -H "$AUTH" -H "Content-Type: application/json" \
    --data "$body" "$API/zones/$zone_id/dns_records")

printf '%s' "$response" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if not data.get("success"):
    sys.exit("Cloudflare rejected the DNS record: " + json.dumps(data.get("errors")))
'
