#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)

test_name "Generate combined certificate file"
test_description "Tests that a combined PEM file with both certificate and key can be generated using OpenSSL"

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo ""
    echo "**Status**: SKIP"
    echo ""
    echo "**Reason**: OpenSSL not found"
    exit 0
fi

test_execution_start
mkdir -p "$TEST_DIR/certs"

# Generate a self-signed certificate and key using OpenSSL
openssl ecparam -name prime256v1 -genkey -noout -out "$TEST_DIR/certs/key.pem"
openssl req -new -x509 -key "$TEST_DIR/certs/key.pem" \
    -out "$TEST_DIR/certs/cert.pem" \
    -days 365 \
    -subj "/CN=Test Combined Cert/O=AIProxy Test" \
    -extensions v3_ca \
    -config <(cat <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[ req_distinguished_name ]

[ v3_ca ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
)

# Combine certificate and key into one file (cert first, then key)
cat "$TEST_DIR/certs/cert.pem" "$TEST_DIR/certs/key.pem" > "$TEST_DIR/certs/combined.pem"
chmod 600 "$TEST_DIR/certs/combined.pem"

# Verify the combined file has both blocks
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$TEST_DIR/certs/combined.pem")
KEY_COUNT=$(grep -c "BEGIN EC PRIVATE KEY" "$TEST_DIR/certs/combined.pem")

test "$CERT_COUNT" -eq 1 || test_fail "Combined file has $CERT_COUNT certificate blocks (expected 1)"
test "$KEY_COUNT" -eq 1 || test_fail "Combined file has $KEY_COUNT key blocks (expected 1)"
test_execution_end

test_pass
