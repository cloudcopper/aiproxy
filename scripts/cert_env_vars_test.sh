#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Configuration via environment variables"
test_description "Tests that aiproxy can be configured using AIPROXY_TLS_CERT and AIPROXY_TLS_KEY environment variables"

test_execution_start
export AIPROXY_TLS_CERT="$TEST_DIR/ca-cert.pem"
export AIPROXY_TLS_KEY="$TEST_DIR/ca-key.pem"
export AIPROXY_ADMIN_SECRET="test123"

mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  -- true

test -f "$TEST_DIR/ca-cert.pem" || test_fail "Certificate not generated via environment variables"
test -f "$TEST_DIR/ca-key.pem" || test_fail "Key not generated via environment variables"

unset AIPROXY_TLS_CERT AIPROXY_TLS_KEY AIPROXY_ADMIN_SECRET
test_execution_end

test_pass
