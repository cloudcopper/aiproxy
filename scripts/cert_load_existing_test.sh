#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Loading existing certificates"
test_description "Tests that aiproxy loads existing CA certificates instead of generating new ones"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# First generate certificates
timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

# Now load them, logs go to file
timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/load.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

grep -qi "ca certificate loaded" "$TEST_DIR/load.log" || test_fail "Did not load existing certificates"
test_execution_end

test_pass