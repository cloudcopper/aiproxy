#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Wrapper mode: curl works after cd with relative cert path"
test_description "Tests that HTTPS proxying via curl succeeds even when the wrapped command changes its working directory. Uses a relative cert path — if it is not resolved to absolute before injection, curl will fail to find the CA cert after cd."

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

cat > "$TEST_DIR/rules/whitelist.json" <<'EOF'
[{"id":"allow-github","scheme":"https","host":"github.com"}]
EOF

# Run wrapper with a RELATIVE cert path (TEST_DIR is relative: scripts/rm-*.d/).
# The wrapped command changes directory to /tmp before running curl.
# If the cert path injected into SSL_CERT_FILE is still relative, curl cannot
# find the CA cert from /tmp and the HTTPS request fails.
CURL_OUTPUT=$(timeout 5s ./aiproxy \
  --whitelist-rules "$TEST_DIR/rules/whitelist.json" \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key  "$TEST_DIR/ca-key.pem" \
  -- bash -c 'cd /tmp && curl -s -o /dev/null -w "%{http_code}" https://github.com')

if ! echo "$CURL_OUTPUT" | grep -q "200"; then
  echo "$CURL_OUTPUT"
  test_fail "curl request failed after cd (expected 200, got: $CURL_OUTPUT) — cert path likely not absolute"
fi

test_execution_end

test_pass
