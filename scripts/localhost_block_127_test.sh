#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Localhost blocking: 127.0.0.1 request blocked"
test_description "Tests that requests to 127.0.0.1 are blocked with HTTP 403 and delayed by 1 second (SSRF protection)"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Using wrapper mode - unset NO_PROXY so curl goes through proxy
# The proxy will then block the request (as intended by the test)
START_TIME=$(date +%s)

HTTP_STATUS=$(timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- bash -c "NO_PROXY='' curl -s -w '%{http_code}' -o '$TEST_DIR/curl_output.txt' http://127.0.0.1:8080/test" || true)

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# Read the response body
RESPONSE_BODY=$(cat "$TEST_DIR/curl_output.txt")

test_execution_end

# Verify HTTP 403
if [ "$HTTP_STATUS" != "403" ]; then
  cat "$TEST_DIR/curl_output.txt"
  test_fail "Expected HTTP 403, got: $HTTP_STATUS"
fi

# Verify JSON error response contains localhost_blocked
if ! echo "$RESPONSE_BODY" | grep -q "localhost_blocked"; then
  echo "Response body: $RESPONSE_BODY"
  test_fail "Response should contain 'localhost_blocked' error"
fi

# Verify 1 second delay (allow some margin for system timing)
if [ $ELAPSED -lt 1 ]; then
  test_fail "Expected at least 1 second delay, got: ${ELAPSED}s"
fi

# Verify ERROR log entry
if ! grep -q "ERROR.*localhost request blocked.*SSRF protection" "$TEST_DIR/aiproxy.log"; then
  cat "$TEST_DIR/aiproxy.log"
  test_fail "Expected ERROR log entry for localhost blocking"
fi

test_pass