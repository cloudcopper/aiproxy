#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Blacklist: request to blacklisted URL is blocked"
test_description "Tests that a URL matching a blacklist rule is rejected with HTTP 403 immediately (no delay)"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data" "$TEST_DIR/certs"

# Create a blacklist rules file containing a blocked host
cat > "$TEST_DIR/rules/blacklist.json" <<'EOF'
[{"id":"block-blocked","scheme":"http","host":"blocked.example.com"}]
EOF

# Using wrapper mode - simpler than background mode
# No need to start proxy in background, extract port, or use -x flag
# Environment variables (HTTP_PROXY/HTTPS_PROXY) are set automatically

# Measure time for the blacklisted request (should be immediate, not delayed)
START_TIME=$(date +%s%N)
HTTP_STATUS=$(timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --blacklist-rules "$TEST_DIR/rules/blacklist.json" \
  --tls-cert "$TEST_DIR/certs/ca-cert.pem" \
  --tls-key "$TEST_DIR/certs/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -w "%{http_code}" -o "$TEST_DIR/curl_output.txt" http://blocked.example.com/api/v1 || true)
END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))

# Read the response body
RESPONSE_BODY=$(cat "$TEST_DIR/curl_output.txt")

test_execution_end

# Verify HTTP 403 for blacklisted URL
if [ "$HTTP_STATUS" != "403" ]; then
  echo "Response body: $RESPONSE_BODY"
  test_fail "Expected HTTP 403 for blacklisted URL, got: $HTTP_STATUS"
fi

# Verify JSON error response contains correct fields
if ! echo "$RESPONSE_BODY" | grep -q '"error":"forbidden"'; then
  echo "Response body: $RESPONSE_BODY"
  test_fail "Response should contain '\"error\":\"forbidden\"'"
fi

if ! echo "$RESPONSE_BODY" | grep -q '"reason":"blacklisted"'; then
  echo "Response body: $RESPONSE_BODY"
  test_fail "Response should contain '\"reason\":\"blacklisted\"'"
fi

if ! echo "$RESPONSE_BODY" | grep -q '"request_id":"req_'; then
  echo "Response body: $RESPONSE_BODY"
  test_fail "Response should contain a request_id starting with 'req_'"
fi

# Verify NO artificial delay (blacklist rejection must be < 500ms)
if [ $ELAPSED_MS -gt 500 ]; then
  test_fail "Blacklist rejection should be immediate, took ${ELAPSED_MS}ms (expected < 500ms)"
fi

# Verify WARN log entry for blocked request
if ! grep -q "request blocked by blacklist" "$TEST_DIR/aiproxy.log"; then
  cat "$TEST_DIR/aiproxy.log"
  test_fail "Expected WARN log entry for blacklist blocking"
fi

# Verify the blacklist was loaded at startup
if ! grep -q "blacklist loaded" "$TEST_DIR/aiproxy.log"; then
  cat "$TEST_DIR/aiproxy.log"
  test_fail "Expected 'blacklist loaded' INFO log at startup"
fi

test_pass
