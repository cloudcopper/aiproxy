#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Warning for insecure key permissions"
test_description "Tests that aiproxy warns when private key has insecure permissions"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Generate certificates first
timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

# Make key world-readable (insecure)
chmod 644 "$TEST_DIR/ca-key.pem"

# Start and check for warning, logs go to file
timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

grep -q "insecure permissions" "$TEST_DIR/aiproxy.log" || test_fail "Did not warn about insecure permissions"
test_execution_end

test_pass
