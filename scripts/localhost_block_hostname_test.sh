#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Localhost blocking: localhost hostname blocked"
test_description "Tests that requests to 'localhost' hostname are blocked with HTTP 403 (SSRF protection)"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Using wrapper mode - unset NO_PROXY so curl goes through proxy
# The proxy will then block the request (as intended by the test)
HTTP_STATUS=$(timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- bash -c "NO_PROXY='' curl -s -w '%{http_code}' -o '$TEST_DIR/curl_output.txt' http://localhost:8080/test" || true)

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

# Verify ERROR log entry with localhost hostname
if ! grep -q "ERROR.*localhost request blocked.*host=localhost" "$TEST_DIR/aiproxy.log"; then
  cat "$TEST_DIR/aiproxy.log"
  test_fail "Expected ERROR log entry for localhost hostname blocking"
fi

test_pass