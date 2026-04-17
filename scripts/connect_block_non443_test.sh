#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
RESPONSE_FILE="$TEST_DIR/response.json"

test_name "CONNECT blocking: non-443 ports blocked"
test_description "Tests that CONNECT requests to non-443 ports are blocked with HTTP 403, 1-second delay, and proper JSON error (anti-tunneling protection)"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Using wrapper mode - simpler than background mode
# No need to start proxy in background, extract port, or use -x flag
# Environment variables (HTTP_PROXY/HTTPS_PROXY) are set automatically

# Measure time - when CONNECT blocking is enabled, there should be 1 second delay
START_TIME=$(date +%s)

# Use --proxytunnel to force CONNECT method even for HTTP
# Target example.com:8080 (non-443 port) - should be blocked before DNS resolution
# Note: No timeout wrapper needed - wrapper mode will exit when curl completes
timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -w "%{http_code}" -o "$RESPONSE_FILE" \
    --proxytunnel \
    --connect-timeout 3 \
    http://example.com:8080/test > "$TEST_DIR/curl_output.txt" 2>&1 || CURL_EXIT=$?

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# Extract HTTP status code
HTTP_STATUS=$(cat "$TEST_DIR/curl_output.txt" 2>/dev/null || echo "")

# Get response body if it exists
if [ -f "$RESPONSE_FILE" ] && [ -s "$RESPONSE_FILE" ]; then
  RESPONSE_BODY=$(cat "$RESPONSE_FILE")
else
  RESPONSE_BODY=""
fi

test_execution_end

# When CONNECT is blocked, curl may either:
# 1. Return HTTP 403 with error response (ideal)
# 2. Return error code 56 (Failure receiving network data) - common with --proxytunnel
# Both are acceptable as long as timing and logs confirm blocking occurred

# First, verify 1 second delay (critical - proves blocking happened)
if [ $ELAPSED -lt 1 ]; then
  echo "Elapsed time: ${ELAPSED}s"
  cat "$TEST_DIR/aiproxy.log" || true
  test_fail "Expected at least 1 second delay for blocked CONNECT, got: ${ELAPSED}s (likely CONNECT blocking is disabled)"
fi

# Verify WARN log entry confirms CONNECT was blocked
if ! grep -q "WARN.*CONNECT request blocked.*anti-tunneling protection" "$TEST_DIR/aiproxy.log"; then
  echo "Elapsed time: ${ELAPSED}s"
  echo "HTTP status: $HTTP_STATUS"
  cat "$TEST_DIR/aiproxy.log" || true
  test_fail "Expected WARN log entry for CONNECT blocking (blocking may not be working)"
fi

# Verify curl failed or returned 403
# Exit code 56 = "Failure in receiving network data" is expected when CONNECT is rejected
# Exit code 0 with HTTP 403 is also acceptable
if [ "$HTTP_STATUS" = "403" ]; then
  # Successfully got HTTP 403 response - verify JSON error format
  if ! echo "$RESPONSE_BODY" | grep -q "connect_blocked"; then
    echo "Response body: $RESPONSE_BODY"
    test_fail "HTTP 403 response should contain 'connect_blocked' error"
  fi
elif [ "${CURL_EXIT:-0}" != "56" ] && [ "${CURL_EXIT:-0}" != "0" ]; then
  # Unexpected curl exit code
  echo "curl exit code: ${CURL_EXIT:-0}"
  echo "HTTP status: $HTTP_STATUS"
  echo "Elapsed time: ${ELAPSED}s"
  test_fail "Expected curl exit code 56 (receive error) or 0 (with 403), got: ${CURL_EXIT:-0}"
fi

# If we got here, blocking is working correctly:
# - 1 second delay occurred
# - WARN log entry exists
# - curl failed with expected error code OR returned 403

test_pass