# Agent Documentation Guide

This file provides the recommended reading order for AI agents working on this project.

## ⚠️ CRITICAL RULE: DOCUMENTATION BEFORE CODE

**YOU MUST UPDATE DOCUMENTATION BEFORE WRITING ANY CODE.**

Before working on this project, read the "Documentation-First Development" section in BEST_PRACTICES.md (it's step 2 in the reading order below).

**NEVER** implement code before:
1. Updating IDEA.md with the design decision
2. Getting user approval of the documented design
3. Updating other affected documentation

**IF YOU VIOLATE THIS RULE:**
- Stop immediately
- Acknowledge the mistake
- Ask if user wants to keep the code or revert
- Update docs to match what was built (if keeping code)

## Documentation Reading Order

When starting work on this project, agents should read documentation in this order:

1. **AGENTS.md** (this file) - Start here to understand documentation structure and CRITICAL RULES
2. **BEST_PRACTICES.md** - Read "Documentation-First Development" section IMMEDIATELY, then continue with full read
3. **DONT.md** - Critical constraints and prohibited practices
4. **TESTING.md** - Test organization principles: what goes where and what is prohibited
5. **IDEA.md** - Complete v1 specification (the source of truth)
6. **SUMMARY.md** - Project overview and current status
7. **TODO.md** - Future features planned for post-v1

## Why This Order?

- **AGENTS.md** - Orients you to the documentation structure
- **DONT.md** - Read this BEFORE reading IDEA.md to avoid forming wrong assumptions
- **TESTING.md** - Read this before writing any test — defines what goes where
- **IDEA.md** - The complete specification; all design decisions are documented here
- **BEST_PRACTICES.md** - Development principles, testing strategy, and coding standards
- **SUMMARY.md** - Quick reference for project status and key points
- **TODO.md** - Context on what's explicitly out of scope for v1

## Documentation Principles

- **Specification-first approach**: IDEA.md is the authoritative source
- **Design decisions finalized**: No open questions remain for v1
- **Constraints documented**: DONT.md lists prohibited practices
- **Best practices documented**: BEST_PRACTICES.md provides development guidelines
- **Scope clarity**: v1 features in IDEA.md, future features in TODO.md

## Skills Reference

This project follows idiomatic Go practices

Key skills for this project include:
- `golang-project-layout` - Directory structure
- `golang-cli` - Command-line interface patterns
- `golang-code-style` - Go conventions
- `golang-testing` - Testing patterns and best practices
- `golang-concurrency` - Goroutines and channels
- `golang-error-handling` - slog integration
- `golang-security` - Security best practices
- `golang-design-patterns` - Idiomatic patterns
- `htmx`
