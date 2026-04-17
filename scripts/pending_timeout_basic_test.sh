#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

TEST_DIR=$(get_test_dir)
OUTPUT_FILE="$TEST_DIR/curl_output.txt"

test_name "Pending queue: no whitelist, no blacklist — HTTPS request held for timeout then rejected"
test_description "With no whitelist and no blacklist configured, and --pending-timeout=2s, a curl request to https://github.com must be held for ~2s then rejected with HTTP 403 (reason: blacklisted). Tests that the pending queue activates for ALL unclassified requests regardless of whether a whitelist is present."

test_execution_start
mkdir -p "$TEST_DIR"

START_TIME=$(date +%s%N)
HTTP_STATUS=$(./aiproxy \
  --pending-timeout 2s \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --log-file "$TEST_DIR/aiproxy.log" \
  -- curl -s -w "%{http_code}" -o "$OUTPUT_FILE" https://github.com || true)
END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))

RESPONSE_BODY=$(cat "$OUTPUT_FILE")

test_execution_end

# Verify HTTP 403
if [ "$HTTP_STATUS" != "403" ]; then
  echo "HTTP status : $HTTP_STATUS"
  echo "Response    : $RESPONSE_BODY"
  echo "Elapsed     : ${ELAPSED_MS}ms"
  test_fail "Expected HTTP 403 (pending timeout → rejected as blacklisted), got: $HTTP_STATUS"
fi

# Verify response matches blacklist rejection shape (Decision 60)
if ! echo "$RESPONSE_BODY" | grep -q '"error":"forbidden"'; then
  echo "Response: $RESPONSE_BODY"
  test_fail "Response must contain \"error\":\"forbidden\""
fi

if ! echo "$RESPONSE_BODY" | grep -q '"reason":"blacklisted"'; then
  echo "Response: $RESPONSE_BODY"
  test_fail "Response must contain \"reason\":\"blacklisted\" (pending timeout matches blacklist response shape)"
fi

if ! echo "$RESPONSE_BODY" | grep -q '"request_id":"req_'; then
  echo "Response: $RESPONSE_BODY"
  test_fail "Response must contain a request_id field"
fi

# Verify timing: request must have been held for approximately 2s
if [ "$ELAPSED_MS" -lt 1800 ]; then
  echo "Elapsed: ${ELAPSED_MS}ms"
  test_fail "Request completed in ${ELAPSED_MS}ms — expected ~2s hold. Pending queue may not be active for requests arriving without a whitelist."
fi

if [ "$ELAPSED_MS" -gt 6000 ]; then
  echo "Elapsed: ${ELAPSED_MS}ms"
  test_fail "Request took ${ELAPSED_MS}ms — expected ~2s (pending timeout 2s + proxy startup overhead)"
fi

# Verify proxy log shows pending queue was enabled
if ! grep -q "pending queue enabled" "$TEST_DIR/aiproxy.log"; then
  cat "$TEST_DIR/aiproxy.log"
  test_fail "Expected 'pending queue enabled' INFO log at startup"
fi

# Verify proxy log shows the request was held in pending queue
if ! grep -q "request pending" "$TEST_DIR/aiproxy.log"; then
  cat "$TEST_DIR/aiproxy.log"
  test_fail "Expected 'request pending' INFO log when request entered the queue"
fi

# Verify proxy log shows pending timeout was reached
if ! grep -q "pending request timed out" "$TEST_DIR/aiproxy.log"; then
  cat "$TEST_DIR/aiproxy.log"
  test_fail "Expected 'pending request timed out' WARN log"
fi

test_pass
