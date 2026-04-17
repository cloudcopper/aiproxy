#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
OUTPUT_FILE="$TEST_DIR/curl_output.txt"
RESPONSE_FILE="$TEST_DIR/response.json"

test_name "badssl.com self-signed certificate test"
test_description "Tests that aiproxy returns HTTP 502 with JSON error when proxying requests to HTTPS sites with self-signed certificates (badssl.com). Validates that certificate details are NOT exposed to clients (security requirement)."

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Using wrapper mode - no need for background processes, port parsing, or manual --proxy/--cacert
# curl writes response body to file, status code goes to output file surrounded by newlines
# Logs go to a separate file so curl output is clean
cat > "$TEST_DIR/rules/whitelist.json" <<'EOF'
[{"id":"allow-badssl","scheme":"https","host":"self-signed.badssl.com"}]
EOF

timeout 3s ./aiproxy \
  --whitelist-rules "$TEST_DIR/rules/whitelist.json" \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -w "\n%{http_code}\n" -o "$RESPONSE_FILE" https://self-signed.badssl.com/ > "$OUTPUT_FILE" || true

# Read the status code (the only line that is exactly 3 digits)
CURL_STATUS=$(grep -xE '[0-9]{3}' "$OUTPUT_FILE")

# Verify we got a 502 response (not 200, not connection error)
if [ "$CURL_STATUS" != "502" ]; then
  cat "$OUTPUT_FILE"
  echo "Response body:" || true
  cat "$RESPONSE_FILE" || true
  test_fail "Expected HTTP 502, got: $CURL_STATUS"
fi

# Verify response file exists and is not empty
if [ ! -s "$RESPONSE_FILE" ]; then
  cat "$OUTPUT_FILE"
  test_fail "Response body is empty or missing"
fi

# Verify JSON structure and extract fields
if command -v jq >/dev/null 2>&1; then
  # Use jq for precise validation
  ERROR_TYPE=$(jq -r '.error' "$RESPONSE_FILE" 2>/dev/null || echo "")
  REASON=$(jq -r '.reason' "$RESPONSE_FILE" 2>/dev/null || echo "")
  REQUEST_ID=$(jq -r '.request_id' "$RESPONSE_FILE" 2>/dev/null || echo "")

  if [ "$ERROR_TYPE" != "bad_gateway" ]; then
    cat "$RESPONSE_FILE" || true
    test_fail "Expected error='bad_gateway', got '$ERROR_TYPE'"
  fi

  if [ "$REASON" != "upstream connection failed" ]; then
    cat "$RESPONSE_FILE" || true
    test_fail "Expected reason='upstream connection failed', got '$REASON'"
  fi

  if [[ ! "$REQUEST_ID" =~ ^req_ ]]; then
    cat "$RESPONSE_FILE" || true
    test_fail "Expected request_id to start with 'req_', got '$REQUEST_ID'"
  fi
else
  # Fallback: grep-based validation
  grep -q '"error".*"bad_gateway"' "$RESPONSE_FILE" || {
    cat "$RESPONSE_FILE" || true
    test_fail "Missing or incorrect 'error' field in JSON response"
  }

  grep -q '"reason".*"upstream connection failed"' "$RESPONSE_FILE" || {
    cat "$RESPONSE_FILE" || true
    test_fail "Missing or incorrect 'reason' field in JSON response"
  }

  grep -q '"request_id".*"req_' "$RESPONSE_FILE" || {
    cat "$RESPONSE_FILE" || true
    test_fail "Missing or incorrect 'request_id' field in JSON response"
  }
fi

# Security validation: Verify NO certificate details leaked in response body
RESPONSE_BODY=$(cat "$RESPONSE_FILE")

# Check for forbidden strings that would indicate information disclosure
if echo "$RESPONSE_BODY" | grep -iq "self-signed"; then
  cat "$RESPONSE_FILE" || true
  test_fail "Response body leaked 'self-signed' certificate detail (security violation)"
fi

if echo "$RESPONSE_BODY" | grep -iq "x509"; then
  cat "$RESPONSE_FILE" || true
  test_fail "Response body leaked 'x509' error detail (security violation)"
fi

# Check for certificate validation error details
if echo "$RESPONSE_BODY" | grep -Eiq "certificate.*(expired|invalid|verify|untrusted|unknown)"; then
  cat "$RESPONSE_FILE" || true
  test_fail "Response body leaked certificate validation details (security violation)"
fi

if echo "$RESPONSE_BODY" | grep -iq "tls:"; then
  cat "$RESPONSE_FILE" || true
  test_fail "Response body leaked TLS error details (security violation)"
fi

test_execution_end

test_pass
