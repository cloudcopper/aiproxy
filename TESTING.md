# Testing Organization

This document defines test organization principles for this project.
It covers where tests live, what each category owns, and what is prohibited.
There are no implementation details here — only structural rules.

---

## Core Decision Rule

> **Does the test require a compiled binary to run?**
>
> - **Yes** → `scripts/`
> - **No, but it tests the system via public API** → `internal/integration_tests/`
> - **No, and it tests a package's internal behavior** → unit test, same package as the code

Apply this rule for every new test. There is no other placement.

---

## Test Categories

### 1. Unit Tests

**Where**: Same directory as the package under test, same `package` name.

**Own**: Internal behavior of a single package — logic, edge cases, error paths.

**Rules**:
- Same package declaration as production code (`package foo`, not `package foo_test`)
- Access to unexported symbols is allowed and expected
- Everything the test creates, it controls — local listeners, subprocesses, temp files, in-process servers are all fine when they are the package's own concern
- Nothing outside the test process's control — no remote hosts, no external services, no pre-built project binaries
- Must pass under `go test -race ./...`

**Prohibited**:
- ❌ External test packages (`package foo_test`) — black-box unit tests are not used in this project
- ❌ Connections to remote hosts or external services
- ❌ Running or depending on a pre-built project binary

**Example layout**:
```
internal/
  foo/
    foo.go
    foo_basic_test.go       ← package foo (same package, white-box)
    foo_edge_cases_test.go  ← package foo (same package, white-box)
  bar/
    bar.go
    bar_test.go             ← package bar (same package, white-box)
```

**Test files within a package are split by concern. There is no requirement to have a single `<package>_test.go` file.**

---

### 2. Integration Tests

**Where**: `internal/integration_tests/`

**Own**: System behavior exercised through the public API — starting real servers,
making real HTTP/HTTPS/WebUI requests, validating responses and logs.

**Rules**:
- Separate package (`package integration_tests`)
- Build tag `//go:build integration` on every file — excluded from `go test ./...`
- No access to unexported symbols of any package — public API only
- May start real listeners and make real network connections within the test process
- Do NOT start or require a compiled binary — server is instantiated via Go API
- Run with: `go test -tags=integration -race ./internal/integration_tests/...`

**Prohibited**:
- ❌ Accessing unexported fields or functions of any package
- ❌ Running or depending on a compiled binary
- ❌ Tests that pass without the `integration` build tag being set

**Example layout**:
```
internal/
  integration_tests/
    foo_basic_test.go       ← package integration_tests, //go:build integration
    foo_tls_test.go         ← package integration_tests, //go:build integration
    bar_auth_test.go        ← package integration_tests, //go:build integration
```

**Test files are split by concern, not by package. There is no limit on the number of files.
All files in this directory share the same package and build tag.**

---

### 3. Script Tests

**Where**: `scripts/`

**Own**: Behavior that can only be verified against a real compiled binary — startup
sequences, CLI flag parsing, file permission checks, real OS-level TLS behavior,
subprocess lifecycle, signal handling, and any behavior that requires running the
actual program as an external process.

**Rules**:
- Each test is a standalone shell script (`*_test.sh`)
- Require a pre-built binary to exist — they do not build it themselves
- May invoke Go helpers via `go run helpers/<helper>.go` (see below)
- Output Markdown (consistent with `scripts/test_common.sh` conventions)
- Must not duplicate coverage already provided by unit tests
- Should re-verify behavior already covered by integration tests, but through the real compiled binary and real OS — script tests and integration tests covering the same behavior are not redundant; they validate different layers

**Prohibited**:
- ❌ Running `go build` or `go test` inside a script test
- ❌ Importing or depending on internal Go packages

**Example layout**:
```
scripts/
  helpers/
    json_assert.go      ← single-file Go helper, invoked via go run
    cert_check.go       ← single-file Go helper, invoked via go run
  test_common.sh        ← shared shell functions (output formatting, pass/fail)
  blacklist_test.sh     ← tests binary behavior: blacklist blocking
  tls_cert_test.sh      ← tests binary behavior: cert generation on disk
  test.sh               ← runner: executes all *_test.sh, outputs aggregated Markdown
```

---

## Go Helpers for Script Tests

Script tests may use Go helpers for assertions that are impractical in shell
(JSON field validation, certificate parsing, portable timing).

**Rules**:
- Each helper is a **single `.go` file** in `scripts/helpers/`
- Invoked via `go run helpers/<helper>.go <args>`
- No helper may span multiple files
- Helpers are assertion tools only — they do not start processes or manage state
- Go build cache makes repeated invocations fast after first compile

**Example invocation in a shell test**:
```bash
go run helpers/json_assert.go "$RESPONSE_FILE" .error forbidden
go run helpers/json_assert.go "$RESPONSE_FILE" .reason blacklisted
```

---

## Makefile Targets

| Target | Command | Scope |
|---|---|---|
| `unit-tests` | `go test -race ./...` | Unit tests only |
| `integration-tests` | `go test -tags=integration -race ./internal/integration_tests/...` | Integration tests only |
| `script-tests` | `./scripts/test.sh` | Script tests (requires built binary) |
| `test` | unit → integration → script | All tests in order |

---

## Prohibited Patterns (Project-Wide)

| Pattern | Reason |
|---|---|
| `package foo_test` (external test package) | Black-box unit tests are not used — all unit tests are white-box |
| Multi-file Go helpers in `scripts/helpers/` | Each helper must be a single file for `go run` simplicity |
| Script tests that `go build` or `go test` | Scripts assume binary is pre-built |
| Integration tests accessing unexported symbols | Integration tests validate public API contracts only |
| Unit tests connecting to remote hosts or external services | Unit tests must control everything they create |
| Script tests duplicating unit test coverage | Script tests validate binary+OS layer, not package logic |

---

## Quick Reference

```
New test to write — ask:

1. Does it need the compiled binary?
   YES  → scripts/*_test.sh
          (use go run helpers/<helper>.go for complex assertions)

2. Does it test system behavior via public API?
   YES  → internal/integration_tests/*_test.go
          (package integration_tests, //go:build integration)

3. Does it test internal logic of one package?
   YES  → internal/<package>/<package>_<concern>_test.go
          (package <package>, white-box, no build tag)
```
