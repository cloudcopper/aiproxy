# Best Practices

Development principles for the AIProxy project.

## ⚠️ CRITICAL: Documentation-First Development

**ALWAYS UPDATE DOCUMENTATION BEFORE IMPLEMENTING CODE.**

### The Rule

1. **FIRST**: Update IDEA.md with the design decision
2. **SECOND**: Get user approval of documented design
3. **THIRD**: Implement the code
4. **FOURTH**: Update documentation if implementation differs

### What Requires Documentation First

- Adding libraries or dependencies
- Adding CLI flags or environment variables
- Changing file formats or schemas
- Adding features or modifying behavior
- Changing request flow or architecture
- Modifying defaults or configuration

### If You Implement Before Documenting

**STOP IMMEDIATELY:**
1. Acknowledge the mistake
2. Ask user if they want to keep the implementation
3. Update documentation to match (if keeping) or revert code (if not)

---

## ⚠️ CRITICAL: Test-Driven Development

**TESTS MUST BE WRITTEN BEFORE IMPLEMENTATION.**

### The Rule

1. **FIRST**: Document the feature in IDEA.md
2. **SECOND**: Write tests defining expected behavior
3. **THIRD**: Implement minimal code to pass tests
4. **FOURTH**: Refactor while keeping tests green

### When Tests Are Required

Write tests for:
- ✅ Business logic (access control, rate limiting, deduplication)
- ✅ Security-critical code (validation, authentication, glob pattern safety)
- ✅ Complex algorithms (glob matching, rate limit calculations)
- ✅ Integration points (file I/O, rule loading, stats collection)
- ✅ Error handling and edge cases

Skip tests for:
- ❌ Trivial code (getters/setters, struct initialization)
- ❌ Third-party library behavior (framework internals)
- ❌ Standard library functionality
- ❌ Main function entry point wiring

### Verification Checklist

Before marking implementation complete:
- [ ] Tests exist for all business logic
- [ ] All tests pass
- [ ] Tests cover happy path AND error cases
- [ ] Tests use table-driven patterns (where appropriate)
- [ ] Test names clearly describe scenario and expected behavior
- [ ] Tests are fast (<100ms each, except integration tests)

---

## Project-Specific Practices

### Dependencies

- Keep dependencies minimal
- Prefer standard library where possible
- Document why each dependency is necessary
- Evaluate binary size impact

### Testing Strategy

Focus tests on value:
- ✅ Business logic and security-critical code
- ✅ Complex algorithms and integration points
- ❌ Trivial code or third-party library behavior

See `golang-testing` and `golang-stretchr-testify` skills for patterns.

### File I/O

- Use atomic writes (temp file + rename)
- Validate JSON after reading
- Handle missing files gracefully

### Deployment

- All directories must be pre-created (see DONT.md)
- Use environment variables for configuration
- Run as non-root user in containers
- Externalize persistent data via volume mounts

---

## When to Deviate

**The Documentation-First rule (above) and Test-Driven Development rule are NOT guidelines — they cannot be deviated from.**

The deviation policy below applies only to coding practices and project-specific practices:

These are guidelines. Deviate when:
- Strong technical reason exists (document it)
- Experimenting (mark as experimental)
- External constraints force it (document why)

Document all deviations in code comments or commit messages.
