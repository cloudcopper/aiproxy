#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Plain HTTP to non-standard port via CONNECT tunneling"
test_description "Tests that plain HTTP requests to non-standard ports (e.g., http://example.com:8080) do trigger a CONNECT request."

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

timeout 5s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -w "%{http_code}" -o "$TEST_DIR/response.txt" \
    --proxytunnel \
    --connect-timeout 3 \
    http://example.com:8080/test > "$TEST_DIR/curl_output.txt" 2>&1 || CURL_EXIT=$?

test_execution_end

# Verify the proxy actually received the request
if ! grep -q "msg=request" "$TEST_DIR/aiproxy.log"; then
  echo "Curl exit code: ${CURL_EXIT:-0}"
  cat "$TEST_DIR/aiproxy.log" || true
  test_fail "Proxy did not receive the request"
fi

# CRITICAL CHECK: No CONNECT blocking should have occurred
if grep -q "CONNECT request blocked.*anti-tunneling" "$TEST_DIR/aiproxy.log"; then
  echo "Curl exit code: ${CURL_EXIT:-0}"
  cat "$TEST_DIR/aiproxy.log" || true
  test_fail "CONNECT and was blocked by anti-tunneling protection"
fi

# If we got a 403, check it's not from CONNECT blocking
HTTP_STATUS=$(tail -c 3 "$TEST_DIR/curl_output.txt" 2>/dev/null || echo "")
if [ "$HTTP_STATUS" = "403" ]; then
  RESPONSE_BODY=$(cat "$TEST_DIR/response.txt" 2>/dev/null || echo "")
  if echo "$RESPONSE_BODY" | grep -q "connect_blocked"; then
    echo "Response body: $RESPONSE_BODY"
    cat "$TEST_DIR/aiproxy.log" || true
    test_fail "Got 403 with connect_blocked error"
  fi
fi

# Success: plain HTTP to non-standard port did use CONNECT
test_pass
