#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
OUTPUT_FILE="$TEST_DIR/curl_output.txt"

test_name "CONNECT to port 443 allowed for HTTPS/TLS bumping"
test_description "Tests that CONNECT requests to port 443 are allowed and TLS bumping works correctly for HTTPS traffic"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

cat > "$TEST_DIR/rules/whitelist.json" <<'EOF'
[{"id":"allow-github-api","scheme":"https","host":"api.github.com"}]
EOF

# Using wrapper mode - simplest approach for testing HTTPS
# CONNECT to :443 should be allowed, and TLS bumping should work
# We test against a real HTTPS site (api.github.com)
timeout 3s ./aiproxy \
  --whitelist-rules "$TEST_DIR/rules/whitelist.json" \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -o /dev/null -w "\n%{http_code}\n" https://api.github.com > "$OUTPUT_FILE" || true

# Read the status code (the only line that is exactly 3 digits)
CURL_STATUS=$(grep -xE '[0-9]{3}' "$OUTPUT_FILE" || echo "")

test_execution_end

# Verify successful response (200 or redirect 30x)
# GitHub API returns 200 for GET / and may return other codes
# We just verify the request succeeded (not 403, not 502, not timeout)
if [ -z "$CURL_STATUS" ]; then
  cat "$OUTPUT_FILE"
  cat "$TEST_DIR/aiproxy.log" || true
  test_fail "Failed to get HTTP status code from curl"
fi

# Any 2xx or 3xx is success (CONNECT to :443 worked)
# 4xx from upstream means CONNECT worked but upstream rejected (still passes our test)
# 403 would indicate CONNECT blocking (failure)
# 502 would indicate TLS bumping failure (failure)
if [ "$CURL_STATUS" = "403" ]; then
  cat "$OUTPUT_FILE"
  cat "$TEST_DIR/aiproxy.log" || true
  test_fail "CONNECT to :443 was blocked (should be allowed for HTTPS/TLS bumping)"
fi

if [ "$CURL_STATUS" = "502" ]; then
  cat "$OUTPUT_FILE"
  cat "$TEST_DIR/aiproxy.log" || true
  test_fail "TLS bumping failed (502 Bad Gateway)"
fi

# Verify no CONNECT blocking log entry
if grep -q "CONNECT request blocked" "$TEST_DIR/aiproxy.log"; then
  cat "$TEST_DIR/aiproxy.log"
  test_fail "CONNECT to :443 should not be blocked"
fi

# Success: CONNECT to :443 was allowed and request completed
test_pass
