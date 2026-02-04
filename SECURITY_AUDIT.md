# Security Self-Audit: sec_auditor

**Audit Date:** 2026-01-06
**Auditor:** Automated Analysis
**Version:** 0.1.0

---

## Executive Summary

This document contains a security self-audit of the `sec_auditor` codebase. Ironically, a tool designed to find security vulnerabilities in other codebases contains several security issues itself. This audit identifies those issues, tracks remediation progress, and outlines areas requiring deeper research.

---

## Critical Findings

### 1. VULN-001: Weak UUID Generation
**Severity:** High
**Location:** `src/models/finding.rs:388-402`
**Status:** REMEDIATED

**Description:**
The custom `uuid_v4()` function uses timestamp-derived "randomness" via a Linear Congruential Generator (LCG). This produces predictable, potentially colliding identifiers.

```rust
// BEFORE (vulnerable)
fn uuid_v4() -> String {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)...;
    let random: u64 = (timestamp as u64).wrapping_mul(6364136223846793005);
    // ...
}
```

**Impact:**
- Finding deduplication failures
- Potential ID prediction in multi-tenant scenarios
- Violates UUID v4 specification (requires 122 bits of randomness)

**Remediation:**
Replaced with proper UUID v4 generation using cryptographic randomness.

---

### 2. VULN-002: Ignored CLI Security Flags
**Severity:** High
**Location:** `src/main.rs:188-194`
**Status:** REMEDIATED

**Description:**
Three CLI flags are captured but completely ignored:
- `--secrets` - Cannot disable secret detection
- `--provenance` - Cannot enable provenance verification
- `--min-severity` - Cannot filter findings by severity

```rust
// BEFORE (vulnerable)
Commands::Scan {
    secrets: _,      // Ignored!
    provenance: _,   // Ignored!
    min_severity: _, // Ignored!
}
```

**Impact:**
- Users cannot configure security analysis as documented
- False sense of security when users believe they've enabled features

**Remediation:**
Wired up all CLI flags to actual configuration options.

---

### 3. VULN-003: TOCTOU Race Condition in Repository Cloning
**Severity:** Medium
**Location:** `src/crawler/git.rs:48-58`
**Status:** REMEDIATED

**Description:**
Time-of-check-time-of-use vulnerability in repository cloning logic.

```rust
// BEFORE (vulnerable)
if target_dir.exists() {
    if let Ok(git_repo) = git2::Repository::open(&target_dir) {
        if git_repo.is_bare() == false {
            return Ok(target_dir);  // Race window here
        }
    }
    std::fs::remove_dir_all(&target_dir)?;  // Another race window
}
```

**Impact:**
- Directory manipulation between check and use
- Potential symlink attacks in shared environments

**Remediation:**
Added file locking mechanism for clone operations.

---

### 4. VULN-004: Synchronous I/O Blocking Async Runtime
**Severity:** Medium
**Location:** Multiple files
**Status:** REMEDIATED

**Description:**
Synchronous `std::fs` operations inside async functions block the Tokio runtime:
- `src/analyzer/sca.rs:255` - `std::fs::read_to_string`
- `src/analyzer/sca.rs:308` - `std::fs::read_to_string`
- `src/analyzer/sca.rs:350` - `std::fs::read_to_string`

**Impact:**
- Thread starvation under high load
- Degraded performance with slow storage

**Remediation:**
Replaced with `tokio::fs` async operations.

---

### 5. VULN-005: Unbounded Parallelism
**Severity:** Medium
**Location:** `src/analyzer/sast.rs:212-215`
**Status:** REMEDIATED

**Description:**
Rayon parallel iteration without bounds on memory consumption.

**Impact:**
- Memory exhaustion on large repositories
- OOM kills in containerized environments

**Remediation:**
Added configurable thread pool with memory-aware chunking.

---

### 6. VULN-006: Parser Object Recreation
**Severity:** Low (Performance)
**Location:** `src/analyzer/sast.rs:99`
**Status:** REMEDIATED

**Description:**
A new tree-sitter parser is created for each file despite maintaining a parser cache in the struct.

**Impact:**
- Wasted CPU cycles on parser initialization
- Increased memory churn

**Remediation:**
Refactored to reuse cached parsers with proper mutex guards.

---

### 7. VULN-007: No Rate Limiting for External APIs
**Severity:** Low
**Location:** `src/analyzer/sca.rs`
**Status:** REMEDIATED

**Description:**
OSV API queries are fired in rapid succession without rate limiting.

**Impact:**
- API throttling/blocking
- Potential for IP-based bans

**Remediation:**
Added configurable rate limiting between API calls.

---

### 8. VULN-008: Missing Graceful Shutdown
**Severity:** Low
**Location:** `src/main.rs`
**Status:** REMEDIATED

**Description:**
No signal handling for SIGTERM/SIGINT. Long-running scans cannot be cleanly interrupted.

**Impact:**
- Orphaned temporary directories
- Incomplete scan results with no indication of interruption

**Remediation:**
Added tokio signal handling with cleanup procedures.

---

## Informational Findings

### INFO-001: Unused Dependency
**Location:** `Cargo.toml:74`

The `entropy` crate is listed as a dependency but entropy calculation is done manually in `secrets.rs:218-236`. Either use the crate or remove it.

### INFO-002: Debug Logging of Potentially Sensitive Data
**Location:** `src/crawler/github.rs:90`

Repository metadata is logged at debug level with derived Debug trait, which could include sensitive information in log files.

### INFO-003: API Key in Request Headers
**Location:** `src/ai/mod.rs:113`

LLM API keys are passed in headers. If reqwest error logging is enabled, keys could be leaked in error messages.

### INFO-004: Hardcoded Entropy Threshold
**Location:** `src/analyzer/secrets.rs:351`

High-entropy string detection only matches strings 20+ characters, potentially missing shorter API keys.

---

## Remediation Tracking

| ID | Issue | Severity | Status | Commit |
|----|-------|----------|--------|--------|
| VULN-001 | Weak UUID | High | REMEDIATED | - |
| VULN-002 | Ignored CLI flags | High | REMEDIATED | - |
| VULN-003 | TOCTOU in cloning | Medium | REMEDIATED | - |
| VULN-004 | Sync I/O blocking | Medium | REMEDIATED | - |
| VULN-005 | Unbounded parallelism | Medium | REMEDIATED | - |
| VULN-006 | Parser recreation | Low | REMEDIATED | - |
| VULN-007 | No API rate limiting | Low | REMEDIATED | - |
| VULN-008 | No graceful shutdown | Low | REMEDIATED | - |

---

## New Security Queries Added (2026-01-31)

Added 16 new security queries across all supported languages to address previously identified coverage gaps:

| Language | Query ID | Severity | Description |
|----------|----------|----------|-------------|
| Rust | `rust/panic-in-library` | Medium | Panic in library code (DoS) |
| Rust | `rust/lazy-static-race` | Low | Lazy static initialization races |
| Rust | `rust/refcell-usage` | Low | RefCell dynamic borrow violations |
| Rust | `rust/unbounded-vec-push` | Medium | Unbounded Vec growth in loops |
| Python | `python/requests-no-timeout` | Medium | HTTP requests without timeout |
| Python | `python/tempfile-mktemp` | High | Insecure temporary file creation |
| Python | `python/logging-format-injection` | Medium | Logging format string injection |
| Python | `python/dynamic-import` | High | Dynamic import with user input |
| JavaScript | `js/prototype-pollution` | High | Prototype pollution via Object.assign |
| JavaScript | `js/dynamic-require` | Medium | Dynamic module loading |
| JavaScript | `js/mutable-exports` | Low | Mutable exported constants |
| JavaScript | `js/unhandled-json-parse` | Low | Unhandled JSON parsing |
| Go | `go/defer-in-loop` | Medium | Defer inside loop |
| Go | `go/sync-map-assertion` | Low | Sync.Map type assertion panic |
| Go | `go/unbuffered-channel` | Low | Potential channel deadlock |
| Go | `go/context-no-timeout` | Low | Context without timeout |

---

## Security Query Coverage

The following vulnerability patterns are now detected:

### Rust ✅
- `panic!` in library code (availability DoS) - `rust/panic-in-library`
- `lazy_static` initialization races - `rust/lazy-static-race`
- `RefCell` borrow violations at runtime - `rust/refcell-usage`
- Unbounded `Vec::push` in loops (memory DoS) - `rust/unbounded-vec-push`

### Python ✅
- `requests` without timeout parameter (connection DoS) - `python/requests-no-timeout`
- `tempfile.mktemp` race conditions - `python/tempfile-mktemp`
- `logging.basicConfig` format string injection - `python/logging-format-injection`
- `__import__` with user input - `python/dynamic-import`

### JavaScript ✅
- Prototype pollution via `Object.assign`/spread - `js/prototype-pollution`
- `require()` with dynamic/user-controlled paths - `js/dynamic-require`
- Missing `Object.freeze` on exported constants - `js/mutable-exports`
- `JSON.parse` without try-catch - `js/unhandled-json-parse`

### Go ✅
- `defer` in loops (resource exhaustion) - `go/defer-in-loop`
- `sync.Map` type assertion panics - `go/sync-map-assertion`
- Unbuffered channel deadlocks - `go/unbuffered-channel`
- `context.Background()` without timeout - `go/context-no-timeout`

---

## Lessons Learned

1. **Dogfooding is essential** - Running sec_auditor against itself would have caught several of these issues
2. **CLI testing is critical** - Flag handling bugs are easy to miss without integration tests
3. **Async Rust requires discipline** - Mixing sync/async I/O is a common pitfall
4. **Security tools need security audits** - The irony of a security scanner with security bugs underscores that all code needs review

---

## Appendix: Test Commands

```bash
# Run the tool against itself
cargo run -- scan .

# Verify CLI flags work
cargo run -- scan . --no-secrets --provenance --min-severity high

# Check for memory issues with large repo
cargo run -- scan https://github.com/nickel-lang/nickel
```
