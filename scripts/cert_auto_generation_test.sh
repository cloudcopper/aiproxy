#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Auto-generation of CA certificates"
test_description "Tests that aiproxy generates CA certificates when none exist"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"
timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

test -f "$TEST_DIR/ca-cert.pem" || test_fail "Certificate file not created"
test -f "$TEST_DIR/ca-key.pem" || test_fail "Key file not created"

# Check permissions (Linux stat vs macOS stat)
if [ "$(uname)" = "Linux" ]; then
    KEY_PERMS=$(stat -c "%a" "$TEST_DIR/ca-key.pem" 2>/dev/null)
    CERT_PERMS=$(stat -c "%a" "$TEST_DIR/ca-cert.pem" 2>/dev/null)
else
    KEY_PERMS=$(stat -f "%A" "$TEST_DIR/ca-key.pem" 2>/dev/null | tail -c 4)
    CERT_PERMS=$(stat -f "%A" "$TEST_DIR/ca-cert.pem" 2>/dev/null | tail -c 4)
fi

test "$KEY_PERMS" = "600" || test_fail "Private key has incorrect permissions: $KEY_PERMS (expected 0600)"
test "$CERT_PERMS" = "644" || test_fail "Certificate has incorrect permissions: $CERT_PERMS (expected 0644)"
test_execution_end

test_pass
