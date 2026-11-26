#!/usr/bin/env bash
# End-to-end check of a running stack: the dashboard serves, its /api proxy reaches
# the API, and a scan of the shipped snapshot produces the expected results.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:3000}"
API_URL="${API_URL:-http://localhost:8000}"

echo "Dashboard serves the app"
curl -fsS "$BASE_URL/" | grep -q '<div id="root">'
curl -fsS "$BASE_URL/scans/some-id" | grep -q '<div id="root">'   # client-side route

echo "API is healthy, directly and through the dashboard's proxy"
curl -fsS "$API_URL/api/health" | jq -e '.status == "ok"' > /dev/null
curl -fsS "$BASE_URL/api/health" | jq -e '.status == "ok"' > /dev/null

echo "Starting a scan"
scan_id=$(curl -fsS -X POST "$BASE_URL/api/scans" | jq -r '.id')

for _ in $(seq 1 30); do
  status=$(curl -fsS "$BASE_URL/api/scans/$scan_id" | jq -r '.status')
  [ "$status" != "RUNNING" ] && break
  sleep 1
done

scan=$(curl -fsS "$BASE_URL/api/scans/$scan_id")
echo "$scan" | jq '{status, score, counts, fail_counts_by_severity}'
echo "$scan" | jq -e '
  .status == "COMPLETED"
  and .score == 60
  and .counts == {"PASS": 27, "FAIL": 18, "CANNOT_SCAN": 4}
' > /dev/null

curl -fsS "$BASE_URL/api/scans/$scan_id/findings?status=fail&page_size=100" \
  | jq -e '.total == 18 and .items[0].severity == "CRITICAL"' > /dev/null

echo "Smoke test passed"
