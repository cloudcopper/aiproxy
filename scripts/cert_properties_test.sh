#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Validate certificate properties with OpenSSL"
test_description "Tests that generated certificates have correct properties: ECDSA P-256, CA:TRUE, Certificate Sign"

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo ""
    echo "**Status**: SKIP"
    echo ""
    echo "**Reason**: OpenSSL not found"
    exit 0
fi

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Generate certificates
timeout 3s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- true

# Check algorithm
openssl x509 -in "$TEST_DIR/ca-cert.pem" -text -noout | grep -q "prime256v1" || test_fail "Certificate does not use ECDSA P-256"

# Check CA constraints
openssl x509 -in "$TEST_DIR/ca-cert.pem" -text -noout | grep -q "CA:TRUE" || test_fail "Certificate missing CA:TRUE constraint"

# Check Key Usage
openssl x509 -in "$TEST_DIR/ca-cert.pem" -text -noout | grep -q "Certificate Sign" || test_fail "Certificate missing Certificate Sign key usage"
test_execution_end

test_pass
