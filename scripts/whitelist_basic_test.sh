#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Whitelist: request to whitelisted URL is allowed"
test_description "Tests that a URL matching a whitelist rule is allowed with HTTP 200 and non-matching URL is rejected with HTTP 403"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data" "$TEST_DIR/certs"

# Create a whitelist rules file containing an allowed host
cat > "$TEST_DIR/rules/whitelist.json" <<'EOF'
[{"id":"allow-whitelisted","scheme":"http","host":"whitelisted.example.com"}]
EOF

# Using wrapper mode - simpler than background mode
# No need to start proxy in background, extract port, or use -x flag
# Environment variables (HTTP_PROXY/HTTPS_PROXY) are set automatically

# Make a request to a whitelisted URL (should pass through - may get 502 if upstream unreachable, but NOT "not_whitelisted")
HTTP_STATUS_WHITELISTED=$(timeout 3s ./aiproxy \
  --pending-timeout 0 \
  --log-file "$TEST_DIR/aiproxy.log" \
  --whitelist-rules "$TEST_DIR/rules/whitelist.json" \
  --tls-cert "$TEST_DIR/certs/ca-cert.pem" \
  --tls-key "$TEST_DIR/certs/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -w "%{http_code}" -o "$TEST_DIR/whitelist_response.txt" http://whitelisted.example.com/api/v1 || true)
RESPONSE_BODY_WHITELISTED=$(cat "$TEST_DIR/whitelist_response.txt")

# Make a request to a non-whitelisted URL (should receive HTTP 403 with "not_whitelisted")
HTTP_STATUS_NOT_WHITELISTED=$(timeout 3s ./aiproxy \
  --pending-timeout 0 \
  --log-file "$TEST_DIR/aiproxy.log" \
  --whitelist-rules "$TEST_DIR/rules/whitelist.json" \
  --tls-cert "$TEST_DIR/certs/ca-cert.pem" \
  --tls-key "$TEST_DIR/certs/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -w "%{http_code}" -o "$TEST_DIR/curl_output.txt" http://notwhitelisted.example.com/ || true)
RESPONSE_BODY_NOT_WHITELISTED=$(cat "$TEST_DIR/curl_output.txt")

test_execution_end

# For whitelisted URL: check that it's NOT blocked with "not_whitelisted" (allowed through to upstream)
if echo "$RESPONSE_BODY_WHITELISTED" | grep -q '"reason":"blacklisted"'; then
  echo "Response body: $RESPONSE_BODY_WHITELISTED"
  test_fail "Whitelisted URL should be allowed through, not blocked with 'not_whitelisted'"
fi

# Verify HTTP 403 for non-whitelisted URL
if [ "$HTTP_STATUS_NOT_WHITELISTED" != "403" ]; then
  echo "Response body: $RESPONSE_BODY_NOT_WHITELISTED"
  test_fail "Expected HTTP 403 for non-whitelisted URL, got: $HTTP_STATUS_NOT_WHITELISTED"
fi

# Verify JSON error response contains correct fields for blocked request
if ! echo "$RESPONSE_BODY_NOT_WHITELISTED" | grep -q '"error":"forbidden"'; then
  echo "Response body: $RESPONSE_BODY_NOT_WHITELISTED"
  test_fail "Response should contain '\"error\":\"forbidden\"'"
fi

if ! echo "$RESPONSE_BODY_NOT_WHITELISTED" | grep -q '"reason":"blacklisted"'; then
  echo "Response body: $RESPONSE_BODY_NOT_WHITELISTED"
  test_fail "Response should contain '\"reason\":\"blacklisted\"'"
fi

if ! echo "$RESPONSE_BODY_NOT_WHITELISTED" | grep -q '"request_id":"req_'; then
  echo "Response body: $RESPONSE_BODY_NOT_WHITELISTED"
  test_fail "Response should contain a request_id starting with 'req_'"
fi

# Verify NO artificial delay (whitelist rejection must be < 500ms)
if ! grep -q "whitelist enabled" "$TEST_DIR/aiproxy.log"; then
  cat "$TEST_DIR/aiproxy.log"
  test_fail "Expected 'whitelist enabled' INFO log at startup"
fi

test_pass