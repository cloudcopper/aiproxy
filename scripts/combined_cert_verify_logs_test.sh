#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
LOG_FILE="$TEST_DIR/aiproxy.log"

test_name "Verify certificate loading from logs"
test_description "Tests that aiproxy logs show successful certificate loading from combined file and certificate manager initialization"

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

# Generate combined cert file
openssl ecparam -name prime256v1 -genkey -noout -out "$TEST_DIR/certs/key.pem" 2>/dev/null
openssl req -new -x509 -key "$TEST_DIR/certs/key.pem" \
    -out "$TEST_DIR/certs/cert.pem" \
    -days 365 \
    -subj "/CN=Test Combined Cert/O=AIProxy Test" 2>/dev/null
cat "$TEST_DIR/certs/cert.pem" "$TEST_DIR/certs/key.pem" > "$TEST_DIR/certs/combined.pem"
chmod 600 "$TEST_DIR/certs/combined.pem"

# Start aiproxy with combined cert file, logs go to file
timeout 3s ./aiproxy \
    --listen "127.0.0.1:18080" \
    --webui-listen "127.0.0.1:18081" \
    --log-file "$LOG_FILE" \
    --tls-cert "$TEST_DIR/certs/combined.pem" \
    --tls-key "$TEST_DIR/certs/combined.pem" \
    --admin-secret "test-secret-123" \
    --insecure-certs \
    -- true

# Check logs for successful combined file loading
grep -qi "loading ca certificate from combined file" "$LOG_FILE" || test_fail "Combined file loading not detected in logs"
grep -qi "successfully loaded ca certificate from combined file" "$LOG_FILE" || test_fail "Certificate loading failed"

# Verify certificate manager was initialized
grep -qi "certificate manager initialized" "$LOG_FILE" || test_fail "Certificate manager initialization failed"
test_execution_end

test_pass
