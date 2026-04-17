#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
LOG_FILE="$TEST_DIR/test.log"

test_name "TLS bumping enabled on startup"
test_description "Tests that aiproxy starts with TLS bumping enabled and generates CA certificates"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Start proxy - runs until command completes, then shuts down cleanly
timeout 3s ./aiproxy \
  --log-file "$LOG_FILE" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

# Verify certificates were generated
test -f "$TEST_DIR/ca-cert.pem" || test_fail "CA certificate not generated"
test -f "$TEST_DIR/ca-key.pem" || test_fail "CA key not generated"

# Verify TLS bumping enabled log message
grep -qi "tls bumping enabled" "$LOG_FILE" || test_fail "TLS bumping not enabled"
test_execution_end

test_pass
