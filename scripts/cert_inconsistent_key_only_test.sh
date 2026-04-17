#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
LOG_FILE="$TEST_DIR/test.log"

test_name "Inconsistent state - key exists, certificate missing"
test_description "Tests that aiproxy detects inconsistent state when key exists but certificate is missing"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Generate certificates first
timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

# Remove cert to create inconsistent state
rm -f "$TEST_DIR/ca-cert.pem"

# Try to start - should detect inconsistent state, logs go to file
timeout 3s ./aiproxy \
  --log-file "$LOG_FILE" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true || true

grep -q "inconsistent" "$LOG_FILE" || test_fail "Did not detect inconsistent state"
test_execution_end

test_pass