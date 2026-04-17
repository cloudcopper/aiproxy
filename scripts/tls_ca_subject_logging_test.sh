#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
LOG_FILE="$TEST_DIR/test.log"

test_name "CA subject logging"
test_description "Tests that TLS bumping logs show CA certificate subject information"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Start proxy - runs until command completes, then shuts down cleanly
timeout 3s ./aiproxy \
  --log-file "$LOG_FILE" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

# Verify CA subject in TLS bumping log
grep -qi 'tls bumping enabled.*ca_subject' "$LOG_FILE" || test_fail "CA subject not found in TLS bumping logs"
test_execution_end

test_pass
