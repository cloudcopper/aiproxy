# AIProxy - Specification Summary

## Document Status
🔄 **IN PROGRESS** - Specification complete, Phases 1–4 complete, Phase 6 substantially complete (auth, dashboard, pending viewer, rule management, cert download implemented; rate-limited requests viewer and log viewer remain)

## Documents
- **IDEA.md** - Complete v1 specification with all design decisions finalized
- **TODO.md** - Future features for post-v1 releases

---

## Key Specifications Summary

This summary is intentionally high-level. For authoritative, detailed
specification, configuration, and operational requirements, see IDEA.md.

### Architecture (High-Level)
- **Language**: Go
- **Proxy**: goproxy with TLS bumping
- **Configuration**: go-flags (CLI + env)
- **WebUI**: templ + htmx + SSE
- **Storage**: JSON files
- **Deployment**: Container (Podman/Docker)

### Core Functionality (High-Level)
- Access control (whitelist/blacklist + pending approvals)
- Interval-based rate limiting
- Per-rule stats + access log rotation
- WebUI with real-time updates

---

## Design Decisions (All Finalized)

| Topic | Decision | Rationale |
|-------|----------|-----------|
| **Admin Secret** | CLI argument (optional; WebUI login disabled if empty) | Secure by default, no secrets in files |
| **Log Output** | stdout by default, optional file output | Flexible, container-friendly |
| **Pending Dedup** | Single entry, count waiters | Efficient, intuitive UX |
| **Rate Limit** | Interval-based hold | Simple, predictable behavior |
| **Stats** | Per-rule granularity | Matches rule definitions |
| **Access Log** | Text (Apache-style) | Easy grepping, familiar format |
| **Real-Time Updates** | SSE (not polling) | Efficient, instant updates |
| **Streaming** | io.Copy, no buffering | Memory efficient, no size limits |
| **Cert Download** | Public endpoint | CA cert alone not sensitive |
| **Missing Files** | Continue (deny all) | Secure by default |

---

## Implementation Phases

### Phase 2: Rule Engine (Days 3-4)
- [x] Glob pattern matching (via reqrules package)
- [x] Blacklist loading (--blacklist-rules) and request blocking
- [x] Whitelist loading (--whitelist-rules) and request allowing
- [x] Request filtering logic (blacklist blocking implemented)
- [x] HTTP 403 error responses (JSON)

### Phase 3: Pending Queue (Days 5-6)
- [x] In-memory queue with deduplication (`internal/pending/queue.go`)
- [x] Request holding mechanism (goroutines + `done` channel per entry)
- [x] Timeout handling (`time.NewTimer`, not `time.After`; `testing/synctest` for tests)
- [x] No persistence this phase — state is in-memory only, lost on restart
- [x] Proxy integration: `allowWhitelist` passes unknown requests to `holdPending`; response identical to blacklist rejection
- [x] `Proxy.PendingCount()` wired to real queue (`PendingTimeout: 0` = immediate rejection mode, queue always active)
- [x] Unit + integration tests (goleak for goroutine leak detection)
- [x] `Entry.Waiters()` atomic waiter count; `Proxy.PendingItems()` exposed; WebUI wired via direct `Pending: proxyServer` assignment in `main.go` — no adapter (Decisions 61–64)

### Phase 4: Rate Limiting (Day 7)
- [x] Request delay logic
- [x] Global rate limiter (simple interval-based limiter)

### Phase 5: Statistics & Logging (Days 8-9)
- [X] Log rotation

### Phase 6: WebUI (Days 10-14)
- [x] HTTP server + auth (session cookies)
- [x] SSE infrastructure
- [x] templ templates + htmx
- [x] Dashboard and pending viewer
- [x] Rule management (add/edit/delete whitelist2/blacklist2)
- [x] Certificate download

### Phase 7: Advanced operations
- [ ] Per-rule rate limiter (interval-based limiter)
- [ ] Per-rule stats collector
- [ ] Rate-limited requests viewer (separate page with SSE)
- [ ] Stats persistence (stats.json)
- [ ] Log viewer (?)
- [ ] API tokens substitution/injection

### Phase 8: Container & Docs (Days 15-16)
- [ ] Containerfile (multi-stage)
- [ ] Example configs
- [ ] Integration testing
- [ ] README documentation

---

## Dependencies

```go
require (
    github.com/elazarl/goproxy v0.0.0-20231117061959-7cc037d33fb5
    github.com/bmatcuk/doublestar/v4 v4.6.1
    github.com/a-h/templ v0.2.543
    github.com/jessevdk/go-flags v1.6.1  // Configuration management
)
```

Internal packages (no external deps):
- `internal/reqrules` - Thread-safe rule storage and glob matching
- `internal/rules` - JSON file loading for blacklist/whitelist rules

---

## Success Criteria (v1)

### Functional Requirements
- ✅ HTTP/HTTPS proxy with TLS interception
- ✅ Whitelist/blacklist access control with glob patterns
- ✅ Pending request queue with admin approval
- ✅ Interval-based rate limiting (global + per-rule)
- ✅ Per-rule statistics (persistent)
- ✅ Access log with rotation
- ✅ WebUI with real-time updates (SSE)
- ✅ Certificate auto-generation and download
- ✅ Container deployment (Podman/Docker)

### Non-Functional Requirements
- ✅ Handle hundreds of concurrent connections
- ✅ Idiomatic Go code (readable, maintainable)
- ✅ Memory efficient (streaming, no buffering)
- ✅ Simple deployment (single binary + config)
- ✅ Secure by default (deny unknown, network isolation)
- ✅ No external dependencies (JSON files only)

### Out of Scope (v1)
- ❌ Graceful shutdown
- ❌ Client authentication
- ❌ Request/response body inspection
- ❌ Header sanitization
- ❌ Distributed deployment
- ❌ High availability
- ❌ Metrics export (Prometheus)
- ❌ Audit logging

---

## Risk Assessment

### Low Risk
- goproxy library (mature, widely used)
- Glob matching (well-understood, library available)
- JSON file storage (simple, no external deps)
- SSE (native HTTP, well-supported by htmx)

### Medium Risk
- TLS certificate generation (need to test with various clients)
- Pending request deduplication (coordination between goroutines)
- Rate limiting accuracy (clock drift, concurrent requests)
- Access log rotation (file I/O under concurrent load)

### Mitigation Strategies
- TLS: Use standard Go crypto libs, test with curl/browsers/AI SDKs
- Deduplication: Use sync.Map or mutex-protected map
- Rate limiting: Accept ~100ms accuracy variance (sufficient for AI workloads)
- Log rotation: Use atomic file operations, mutex-protected writes

