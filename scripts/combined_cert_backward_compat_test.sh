#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
LOG_FILE="$TEST_DIR/aiproxy-separate.log"

test_name "Backward compatibility with separate files"
test_description "Tests that aiproxy still supports loading certificate and key from separate files"

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo ""
    echo "**Status**: SKIP"
    echo ""
    echo "**Reason**: OpenSSL not found"
    exit 0
fi

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data" "$TEST_DIR/certs"

# Generate separate cert and key files
openssl ecparam -name prime256v1 -genkey -noout -out "$TEST_DIR/certs/key.pem" 2>/dev/null
openssl req -new -x509 -key "$TEST_DIR/certs/key.pem" -out "$TEST_DIR/certs/cert.pem" -days 365 \
    -subj "/CN=Test Separate Cert" 2>/dev/null

# Start aiproxy with SEPARATE cert files, logs go to file
timeout 3s ./aiproxy \
    --listen "127.0.0.1:18080" \
    --webui-listen "127.0.0.1:18081" \
    --log-file "$LOG_FILE" \
    --tls-cert "$TEST_DIR/certs/cert.pem" \
    --tls-key "$TEST_DIR/certs/key.pem" \
    --admin-secret "test-secret-123" \
    --insecure-certs \
    -- true

# Process will exit (expected) - verify separate files loaded correctly from logs
grep -qi "loading existing ca certificate" "$LOG_FILE" || test_fail "Separate files loading failed"
test_execution_end

test_pass
