#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
LOG_FILE="$TEST_DIR/test.log"

test_name "TLS bumping with existing certificates"
test_description "Tests that aiproxy uses existing CA certificates for TLS bumping instead of generating new ones"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Generate certificates first
timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

test -f "$TEST_DIR/ca-cert.pem" || test_fail "Prerequisite failed: certificate not created"
test -f "$TEST_DIR/ca-key.pem" || test_fail "Prerequisite failed: key not created"

# Start proxy with existing certs, logs go to file
timeout 3s ./aiproxy \
  --log-file "$LOG_FILE" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

# Verify certificates were loaded (not generated)
grep -qi "loading existing ca certificate" "$LOG_FILE" || test_fail "Certificates not loaded properly"

# Verify TLS bumping enabled
grep -qi "tls bumping enabled" "$LOG_FILE" || test_fail "TLS bumping not enabled"
test_execution_end

test_pass