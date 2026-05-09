#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_common.sh"

# Get test-specific temp directory
TEST_DIR=$(get_test_dir)
RESPONSE_FILE="$TEST_DIR/response.json"

test_name "CONNECT to non-443 port: ACCEPTED (MITM, not blocked)"
test_description "Tests that CONNECT requests to non-443 ports are now ACCEPTED and traffic flows through the normal pipeline (universal CONNECT MITM)"

test_execution_start
mkdir -p "$TEST_DIR/rules" "$TEST_DIR/data"

# Create a simple whitelist rule that allows the request
cat > "$TEST_DIR/rules/whitelist.json" <<EOF
[
  {
    "id": "allow-test",
    "method": "GET",
    "scheme": "http",
    "host": "example.com",
    "path": "/test"
  }
]
EOF

# Use wrapper mode with a backend server
# Start a simple HTTP server on a non-443 port
BACKEND_PORT=8080
python3 -c "
import http.server, socketserver
class H(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello from backend')
    def log_message(self, format, *args):
        pass
with socketserver.TCPServer(('127.0.0.1', $BACKEND_PORT), H) as httpd:
    httpd.serve_forever()
" &
BACKEND_PID=$!
trap "kill $BACKEND_PID 2>/dev/null; wait $BACKEND_PID 2>/dev/null" EXIT

sleep 1

# Start aiproxy in wrapper mode
# The curl command will CONNECT to our backend on non-443 port
# With CONNECT MITM, this should be accepted and the request should flow through
timeout 10s ./aiproxy \
  --log-file "$TEST_DIR/aiproxy.log" \
  --tls-cert "$TEST_DIR/ca-cert.pem" \
  --tls-key "$TEST_DIR/ca-key.pem" \
  --admin-secret test123 \
  -- curl -s -w "%{http_code}" -o "$RESPONSE_FILE" \
    --proxytunnel \
    --connect-timeout 5 \
    --max-time 5 \
    "http://127.0.0.1:$BACKEND_PORT/test" > "$TEST_DIR/curl_output.txt" 2>&1 || CURL_EXIT=$?

test_execution_end

# Verify the proxy accepted the CONNECT (no CONNECT blocked message)
if grep -q "CONNECT request blocked.*anti-tunneling" "$TEST_DIR/aiproxy.log"; then
  echo "Curl exit code: ${CURL_EXIT:-0}"
  cat "$TEST_DIR/aiproxy.log" || true
  test_fail "CONNECT should be ACCEPTED (not blocked) - CONNECT MITM not working"
fi

# Verify CONNECT MITM was logged
if ! grep -q "CONNECT MITM enabled" "$TEST_DIR/aiproxy.log"; then
  echo "Curl exit code: ${CURL_EXIT:-0}"
  cat "$TEST_DIR/aiproxy.log" || true
  test_fail "Expected 'CONNECT MITM enabled' log message"
fi

# If curl got a response, verify it's not a connect_blocked error
HTTP_STATUS=$(tail -c 3 "$TEST_DIR/curl_output.txt" 2>/dev/null || echo "")
if [ "$HTTP_STATUS" = "403" ]; then
  RESPONSE_BODY=$(cat "$RESPONSE_FILE" 2>/dev/null || echo "")
  if echo "$RESPONSE_BODY" | grep -q "connect_blocked"; then
    echo "Response body: $RESPONSE_BODY"
    test_fail "Got 403 with connect_blocked error - CONNECT should be accepted"
  fi
fi

# Success: CONNECT was accepted (not blocked), MITM enabled
test_pass
