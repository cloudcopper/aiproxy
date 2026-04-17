#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
OUTPUT_FILE="$TEST_DIR/curl_output.txt"

test_name "Proxy curl test with wrapper mode"
test_description "Tests that aiproxy can proxy HTTPS requests using curl via wrapper mode (no manual env vars needed)"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

cat > "$TEST_DIR/rules/whitelist.json" <<'EOF'
[{"id":"allow-github","scheme":"https","host":"github.com"}]
EOF

# Using wrapper mode - no need for background processes, port parsing, or env vars
# curl writes status code surrounded by newlines so we can extract it cleanly
# Logs go to a separate file so curl output is clean
timeout 3s ./aiproxy \
  --whitelist-rules "$TEST_DIR/rules/whitelist.json" \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -o /dev/null -w "\n%{http_code}\n" https://github.com > "$OUTPUT_FILE" || true

# Read the status code (the only line that is exactly 3 digits)
CURL_STATUS=$(grep -xE '[0-9]{3}' "$OUTPUT_FILE")

# Verify successful response
if [ "$CURL_STATUS" != "200" ]; then
  cat "$OUTPUT_FILE"
  test_fail "curl request failed with status: $CURL_STATUS (expected 200)"
fi

test_execution_end

test_pass
