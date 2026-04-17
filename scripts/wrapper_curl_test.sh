#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Wrapper mode curl test"
test_description "Tests that aiproxy wrapper mode can proxy HTTPS requests using curl"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

cat > "$TEST_DIR/rules/whitelist.json" <<'EOF'
[{"id":"allow-github","scheme":"https","host":"github.com"}]
EOF

# Using wrapper mode - much simpler than background process management!
# No need to:
#  - Start proxy in background
#  - Parse logs to find port
#  - Set environment variables manually
#  - Manage cleanup with traps
# Just run: timeout 3s ./aiproxy -- <command>
# Logs go to a separate file so curl output is clean

CURL_OUTPUT=$(timeout 3s ./aiproxy \
  --whitelist-rules "$TEST_DIR/rules/whitelist.json" \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -o /dev/null -w "%{http_code}" https://github.com)

# Verify successful response
if ! echo "$CURL_OUTPUT" | grep -q "200"; then
  echo "$CURL_OUTPUT"
  test_fail "curl request failed (expected 200 in output)"
fi

test_execution_end

test_pass
