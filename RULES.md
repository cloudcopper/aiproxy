# AIProxy Rule Format Specification

## Overview

Rules define what the proxy allows or blocks. Both whitelist and blacklist use
the same rule object format. The distinction is purely which list a rule lives
in — not its structure.

Rules are stored in JSON files as arrays of objects. Each object is one rule.

---

## Rule Object Schema

```json
{
  "id":          "string (required)",
  "comment":     "string (optional)",
  "method":      "string (optional)",
  "scheme":      "string (optional)",
  "host":        "string (optional)",
  "path":        "string (optional)",
  "port":        0,
  "port_range":  [0, 0],
  "port_ranges": [[0, 0]],
  "rpm":         0,
  "priority":    0
}
```

### Field Reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | **yes** | Unique within file. Sort order is `(priority ASC, id ASC)`; first match wins. |
| `comment` | string | no | Human-readable description. Ignored by matcher. |
| `method` | string | no | HTTP method. Absent = any method. |
| `scheme` | string | no | `"http"` or `"https"`. Absent = any scheme. |
| `host` | string | no | Glob pattern. Absent = any host. Use `"*"` for explicit any. |
| `path` | string | no | Glob pattern. Absent = any path. Use `"*"` for explicit any. |
| `port` | int | no | Single port. `0` or absent = any port. Mutually exclusive with `port_range` and `port_ranges`. |
| `port_range` | [int, int] | no | One `[low, high]` inclusive range. Mutually exclusive with `port` and `port_ranges`. |
| `port_ranges` | [[int, int]] | no | Multiple `[low, high]` ranges. Mutually exclusive with `port` and `port_range`. |
| `rpm` | int | no | Whitelist only: rate limit in requests per minute. `0` or absent = no per-rule limit (global limit applies). Ignored on blacklist rules. |
| `priority` | int | no | Match priority. Lower number = checked first. Default `0`. Rules with equal priority are sorted by `id`. Must be `>= 0`. |

---

## Matching Semantics

A rule matches a request when **all present fields match**. Absent fields are
not constrained — they match any value.

### method

Exact string match against the HTTP request method (`GET`, `POST`, `PUT`,
`DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `TRACE`).

Absent means any method matches.

### scheme

Exact string match against the request scheme. Valid values: `"http"`,
`"https"`.

Absent means any scheme matches.

### host

Glob pattern match against the request hostname (without port).

- `"api.openai.com"` — exact host match
- `"*.openai.com"` — one subdomain label: matches `api.openai.com` but not `deep.api.openai.com`
- `"**.openai.com"` — any depth: matches `openai.com`, `api.openai.com`, `deep.api.openai.com`
- `"*"` — explicit any host

Uses `doublestar` glob semantics. `*` does not match `.` in host position; `**`
matches across `.` boundaries.

Absent means any host matches.

### path

Glob pattern match against the request URL path (the `/...` component, without
query string).

- `"/v1/chat/completions"` — exact path match
- `"/v1/*"` — one path segment wildcard
- `"/v1/**"` — any depth under `/v1/`
- `"*"` — explicit any path

Absent means any path matches.

### port, port_range, port_ranges

At most one of these three fields may be set. All three absent (or `port: 0`)
means any port matches.

- `"port": 443` — single port
- `"port_range": [8080, 9090]` — all ports from 8080 to 9090 inclusive
- `"port_ranges": [[80, 80], [443, 443], [8080, 9090]]` — multiple ranges

Port `0` is treated as absent (any port). Range bounds must satisfy `low > 0`
and `low <= high`.

---

## Rule Identity and Priority

### ID

Every rule must have a non-empty `id` string. IDs must be unique within a file.
Duplicate IDs are a fatal load error.

IDs are user-defined strings. The proxy imposes no format constraint. Examples:
`"openai-completions"`, `"0010"`, `"block-evil-corp"`.

### Priority

Rules are sorted by `(priority ASC, id ASC)` before matching. Lower `priority`
value means the rule is checked first. Absent or `0` is the default priority;
all default-priority rules are ordered among themselves by `id`.

Use `priority` when you need a rule to fire before other rules regardless of
its `id` string:

```json
{"id": "block-admin-everywhere", "priority": 0, "path": "/admin/**"},
{"id": "allow-specific-admin",   "priority": 1, "host": "safe.example.com", "path": "/admin/**"}
```

When all rules share the same `priority` (the common case), ordering is
determined by `id` alone — identical to the previous behaviour.

**Lexicographic sort caveat for ID**: if you use numeric strings as IDs, pad
them to equal width for predictable ordering. `"010"` sorts before `"020"`
correctly; `"10"` sorts before `"9"` incorrectly.

Recommended naming strategies:

- **Semantic prefix**: `"a-openai-api"`, `"b-github"`, `"z-fallback"` — letter
  prefix controls ordering, name describes the rule
- **Zero-padded numeric**: `"0010"`, `"0020"`, `"0030"` — leave gaps for
  future insertion
- **Semantic only** (no ordering intent): `"block-evil-corp"` — when rule order
  does not matter (e.g., all blacklist rules are independent)

### First Match Wins

Matching stops at the first matching rule (in `priority ASC, id ASC` order).
Remaining rules are not evaluated.

---

## Whitelist vs Blacklist Behaviour

The rule schema is identical for both lists. The difference is what happens on
a match:

| List | On match |
|---|---|
| Whitelist | Request is allowed (subject to `rpm` rate limiting) |
| Blacklist | Request is rejected with HTTP 403 |

The `rpm` field is meaningful only on whitelist rules. On blacklist rules it is
present in the schema for consistency but is ignored by the matcher.

---

## Validation Rules (Enforced at Load Time)

Violations are fatal errors — the proxy refuses to start:

- `id` is required and must be non-empty
- All `id` values must be unique within the file
- At most one of `port`, `port_range`, `port_ranges` may be set
- `port_range` bounds: both values > 0, `low <= high`
- Each entry in `port_ranges`: same constraints as `port_range`
- `scheme`, if present, must be `"http"` or `"https"`
- `method`, if present, must be a valid HTTP method
- `host` and `path`, if present, must be valid glob patterns (validated by the
  glob library at load time)
- `rpm`, if present, must be `>= 0`; `0` means no per-rule rate limit (global limit applies)
- `priority`, if present, must be `>= 0`; negative values are rejected

---

## Examples

### Whitelist Rules

```json
[
  {
    "id": "openai-completions",
    "comment": "OpenAI chat completions, rate limited",
    "method": "POST",
    "scheme": "https",
    "host": "api.openai.com",
    "path": "/v1/chat/completions",
    "rpm": 20
  },
  {
    "id": "github-readonly",
    "comment": "GitHub API read-only access",
    "method": "GET",
    "scheme": "https",
    "host": "api.github.com",
    "path": "/repos/**"
  },
  {
    "id": "pypi-any",
    "comment": "Allow all PyPI access for pip installs",
    "scheme": "https",
    "host": "*.pypi.org"
  }
]
```

### Blacklist Rules

```json
[
  {
    "id": "block-evil-domain",
    "comment": "Block evil.com and all subdomains, any scheme, method, port, path",
    "host": "**.evil.com"
  },
  {
    "id": "block-admin-paths",
    "comment": "Block admin paths on any host",
    "path": "/admin/**"
  },
  {
    "id": "block-internal-high-ports",
    "comment": "Block access to internal services on non-standard ports",
    "host": "internal.corp",
    "port_range": [8080, 9090]
  },
  {
    "id": "block-plain-http-external",
    "comment": "Block unencrypted HTTP to any external host",
    "scheme": "http"
  }
]
```

---

## File Format

```json
[
  { "id": "first-rule",  ... },
  { "id": "second-rule", ... }
]
```

- Files are JSON arrays of rule objects
- File order does not affect matching order — rules are always sorted by `id`
  before matching
- Missing file is not an error — the proxy starts with an empty rule set
- Empty file or empty array `[]` is valid
- Malformed JSON or invalid rule → fatal load error

---

## Future (See TODO.md)

- **Query/params matching** — match against URL query parameters by name and
  value
- **Rule string shorthand / DSL** — human-friendly single-line syntax that
  parses into the object form; object format is canonical, DSL is sugar added
  in a later phase
