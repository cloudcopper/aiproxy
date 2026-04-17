# TODO - Future Features

## Rules UI
- [ ] Add `port`, `port_range`, `port_ranges` fields to the add-rule form (currently omitted; requires mutual-exclusion UI: radio to select port mode)
- [ ] Add `rpm` field to the add-rule form (deferred: rpm enforcement not yet implemented in v1)

## Performance & Scalability
- [ ] Connection pooling optimization
- [ ] Memory pooling for request/response buffers
- [ ] Performance profiling and benchmarking
- [ ] Cancel delayed requests when client disconnects (use `req.Context().Done()` in rate limiter, remove from store, log cancellation)

## Security Enhancements
- [ ] Rate limiting for login attempts (max N failures per IP per minute, prevents brute-force)
- [ ] Mutual TLS (mTLS) support for client authentication
  - [ ] Require clients to present valid certificates to proxy
  - [ ] Configure `http.Server.TLSConfig.ClientAuth` in proxy listener
  - [ ] Add `--client-ca` flag to specify trusted client CA certificates
  - [ ] Add `--require-client-cert` flag to enable/disable mTLS
  - [ ] Client certificate validation and logging
  - [ ] Per-client access control based on certificate CN/SAN
- [ ] Audit log for all admin actions (immutable log of rule changes, approvals, denials)
- [ ] IP-based access control for proxy (whitelist client IPs)
- [ ] Per-client API key authentication for proxy
- [ ] Rate limiting by client IP (not just by endpoint)
- [ ] DDoS protection mechanisms
- [ ] Request signature verification
- [ ] Webhook/notification system for security events (threshold-based, what is "suspicious" TBD)
- [ ] SSRF Protection Enhancements (localhost blocking implemented in v1)
  - [ ] Block all private IP ranges (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
  - [ ] Block link-local addresses (169.254.0.0/16, fe80::/10)
  - [ ] Configurable SSRF protection via flags (e.g., `--block-localhost`, `--block-private-ips`)
  - [ ] DNS result caching to reduce DNS lookup overhead
  - [ ] Metrics/stats for blocked SSRF requests (counts per IP range)
  - [ ] Whitelist exceptions for specific localhost/private services
  - [ ] DNS rebinding attack mitigation (TTL-aware caching)
- [ ] Input validation limits documentation and enforcement
  - [ ] Document max rate limit bounds (e.g., 1-10000 req/min)
  - [ ] Document glob pattern complexity limits (e.g., max 5 `**` wildcards per pattern)
  - [ ] Enforce max method pattern length (e.g., 50 chars)
  - [ ] Enforce max URL pattern length (e.g., 2048 chars)
  - [ ] Rate limit for pending queue size (prevent OOM from thousands of pending requests)
- [ ] STRIDE threat modeling documentation
  - [ ] Spoofing (authentication boundaries)
  - [ ] Tampering (integrity checks)
  - [ ] Repudiation (audit logging)
  - [ ] Information Disclosure (encryption, log sanitization)
  - [ ] Denial of Service (rate limiting, resource limits)
  - [ ] Elevation of Privilege (authorization checks)
- [ ] DREAD scoring for vulnerability prioritization
  - [ ] Damage, Reproducibility, Exploitability, Affected users, Discoverability
- [ ] Security review checklist (from golang-security skill)

## Content Filtering & Inspection
- [ ] Header sanitization rules (remove/modify specific headers, e.g., X-Forwarded-For, Proxy-Authorization)
- [ ] Request/response size limits (prevent memory exhaustion from huge payloads)
- [ ] Content-Type filtering (allow only JSON, block binaries)
- [ ] Deep packet inspection for malicious payloads
- [ ] SQL injection / XSS pattern detection
- [ ] Custom request/response body transformation rules
- [ ] Sensitive data redaction in logs (credit cards, SSNs, etc.)
- [ ] Request body inspection for sensitive data (API keys, tokens, passwords)

## Advanced Access Control
- [ ] Regex pattern support (in addition to glob)
- [ ] Exact match optimization (hash lookup before glob matching)
- [ ] Rule testing/simulation mode
- [ ] Query/params matching in rules
  - [ ] Match against specific query parameter names and values (e.g., `?model=gpt-4`)
  - [ ] Support glob patterns per query parameter value
  - [ ] Decision required: ordered (positional) vs. unordered (key-based) param matching
  - [ ] Decision required: partial match (rule params are a subset) vs. exact match (all params must match)
  - [ ] Consider: params matching is only meaningful for GET/HEAD (POST bodies are out of scope — streaming)
- [ ] Rule string shorthand / DSL for human-friendly single-line rule authoring
  - [ ] Object format is canonical; string shorthand is syntactic sugar that parses into the object form
  - [ ] Syntax sketch: `[METHOD] [SCHEME://]HOST[:PORT][/PATH]`
  - [ ] Port range syntax: `:8080-9090`, port list: `:80,443`, any port: omit or `:*`
  - [ ] Subdomain wildcard: `**.evil.com` = bare domain + all subdomains
  - [ ] Scheme wildcard: omit scheme or use `*://` to match http and https
  - [ ] Useful for CLI one-liners, config file hand-editing, and quick rule prototyping
  - [ ] Prerequisite: stable object rule format must be in production first

## Monitoring & Observability
- [ ] Advanced logging (ie multiple log files, access.log etc)
- [ ] Application logging strategy documentation
  - [ ] Document slog initialization and configuration
  - [ ] Document structured logging attributes (request_id, client_ip, rule_id, etc.)
  - [ ] Document error logging patterns (single handling rule from BEST_PRACTICES.md)
  - [ ] Document PII handling policy in application logs (separate from access logs)
  - [ ] Document samber/oops integration for production error tracking
  - [ ] Clarify distinction: application logs (slog) vs access logs (text file)
  - [ ] Document log levels usage: debug (dev), info (normal ops), warn (degraded), error (failed ops)
   - [ ] Document log destinations: stdout (default) or file (with lumberjack rotation)

## Operational Features
- [ ] Graceful shutdown (drain connections before exit)
- [ ] Configurable concurrent pending request limit (safety: default 10,000 max to prevent OOM)
- [ ] Configuration hot-reload (watch config files for changes)
- [ ] Admin API (REST/gRPC) for automation
- [ ] Backup/restore functionality for all JSON files
- [ ] Import/export rules in different formats (CSV, YAML)
- [ ] Bulk rule operations (import 1000s of rules efficiently)
- [ ] Rule validation before applying (dry-run mode)

## WebUI Enhancements
- [ ] Dark mode theme
- [ ] Rule search and filtering

## Caching & Optimization
- [ ] Response caching for repeated API calls (cache-control aware)
- [ ] Cache invalidation strategies
- [ ] ETag/If-None-Match support
- [ ] Upstream connection pooling
- [ ] HTTP/2 support
- [ ] WebSocket proxying

## Protocol & Integration
- [ ] Integration with external auth services (API key validation service)

## CLI & Usability Enhancements
- [x] `--version` flag support with build info injection via ldflags
  - [x] Requires explicit implementation (go-flags does not provide it)
- [ ] Recursive protection - ```aiproxy -- aiproxy -- bash```

## Documentation
- [ ] Docker Compose example with volume mounts
 
## Miscellaneous
- [ ] Support for multiple CA certificates (per-domain certs)
- [ ] Automatic upstream certificate validation
- [ ] DNS-over-HTTPS support
- [ ] IPv6 support
- [ ] Proxy protocol support (HAProxy PROXY protocol)
- [ ] Request prioritization (QoS)
- [ ] Circuit breaker pattern for failing upstreams
- [ ] Retry logic with exponential backoff
- [ ] Request deduplication (collapse identical concurrent requests)

---

## Notes
- Features are listed in no particular order
- Prioritize based on user feedback and security requirements
- Keep v1 simple and focused on core functionality
- Each feature should be evaluated for complexity vs. value before implementation
