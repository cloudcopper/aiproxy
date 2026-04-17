# The aiproxy

Security proxy for AI agent with access control and WebUI.

## Features

- HTTP/HTTPS proxy with TLS interception
- Auto-generated CA certificates
- Whitelist/blacklist access control with glob patterns
- Interval-based rate limiting (global; per-rule TODO)
- Pending request queue with timeout (admin approval UI)
- Per-rule statistics (TODO)
- Logs with autorotation
- Real-time WebUI: dashboard, pending viewer, rule management (rate-limit viewer and log viewer TODO)

## Quick Start

```aiproxy -- curl https://github.com```

```bash
# Create required directories
mkdir -p ./certs
# Run proxy in daemon mode, logs to stdout by default
./aiproxy --listen=localhost:8881
# Test through proxy
CURL_CA_BUNDLE=./certs/ca-cert.pem curl -x localhost:8881 https://github.com
```
