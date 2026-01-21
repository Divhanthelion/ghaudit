# Deep Research Topics for sec_auditor

This document outlines areas requiring deeper investigation, potential research directions, and context for each topic. These are not simple bug fixes but substantial areas where academic rigor or extended research would improve the tool.

---

## 1. Tree-sitter Query Optimization and Completeness

### Context
The current SAST engine uses 40+ tree-sitter queries across 4 languages. These queries were designed heuristically without formal coverage analysis.

### Research Questions
- What is the false positive/negative rate of current queries against known vulnerability datasets (e.g., NIST SARD, Juliet Test Suite)?
- Can we use machine learning to generate or refine tree-sitter queries from labeled vulnerability data?
- How do our queries compare to commercial SAST tools (Semgrep, CodeQL) in detection rates?

### Relevant Files
- `src/analyzer/queries.rs` - All query definitions
- `src/analyzer/sast.rs` - Query execution logic

### Proposed Research
1. Create a benchmark suite from CVE-labeled code samples
2. Measure precision/recall of each query
3. Investigate semantic analysis (data flow, taint tracking) to reduce false positives
4. Compare against Semgrep rule corpus for coverage gaps

### External Resources
- [Semgrep Registry](https://semgrep.dev/explore) - 3000+ community rules
- [CodeQL Query Suites](https://github.com/github/codeql) - GitHub's query patterns
- [NIST SARD](https://samate.nist.gov/SARD/) - Software Assurance Reference Dataset

---

## 2. Entropy-Based Secret Detection Accuracy

### Context
The secret detector uses Shannon entropy to identify high-entropy strings that might be secrets. The current threshold (4.5 bits/char) was chosen heuristically.

### Research Questions
- What is the optimal entropy threshold to maximize true positives while minimizing false positives?
- How does character set composition affect optimal thresholds (base64 vs hex vs alphanumeric)?
- Can we train a classifier that considers entropy + context + structural patterns?

### Relevant Files
- `src/analyzer/secrets.rs:218-243` - Entropy calculation
- `src/analyzer/secrets.rs:341-398` - High-entropy string detection

### Proposed Research
1. Collect a labeled dataset of true secrets vs. benign high-entropy strings
2. Analyze entropy distributions for different secret types (API keys, JWTs, passwords)
3. Investigate contextual features (variable names, file types, surrounding code)
4. Evaluate ML classifiers (Random Forest, XGBoost) vs. pure entropy thresholds

### Key Insight from Code
```rust
// Current threshold: 4.5 bits/char
// Base64 theoretical max: 6.0 bits/char
// Alphanumeric theoretical max: 5.95 bits/char
// This means threshold is ~75% of theoretical max - is this optimal?
```

### External Resources
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Comprehensive secret scanner
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Pattern-based secret detection
- Academic paper: "How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories" (NDSS 2019)

---

## 3. SLSA Provenance Verification at Scale

### Context
The SLSA verifier checks supply chain provenance via Sigstore/Rekor, but the ecosystem is immature. Most crates.io packages lack attestations.

### Research Questions
- What percentage of crates.io/npm/PyPI packages have verifiable provenance?
- How can we incentivize or bootstrap provenance adoption?
- What's the performance impact of Rekor lookups at scale (1000+ dependencies)?
- Can we cache/precompute provenance data?

### Relevant Files
- `src/provenance/slsa.rs` - SLSA verification logic
- `src/provenance/slsa.rs:42-83` - Crate verification flow

### Proposed Research
1. Crawl crates.io to measure provenance coverage
2. Analyze Rekor log growth and query latency trends
3. Design a provenance cache with appropriate TTL
4. Investigate trust propagation (if A is verified and depends on B, what does that imply?)

### Current Limitation in Code
```rust
// From slsa.rs:120-121
attestation_url: None, // crates.io doesn't have attestations yet
```
This shows the ecosystem gap that needs addressing.

### External Resources
- [SLSA Framework](https://slsa.dev/) - Official specification
- [Sigstore](https://www.sigstore.dev/) - Keyless signing infrastructure
- [Rekor](https://github.com/sigstore/rekor) - Transparency log

---

## 4. LLM-Assisted Vulnerability Detection

### Context
The AI module supports LLM-based analysis but falls back to heuristics. The effectiveness of LLMs for security analysis is underexplored.

### Research Questions
- How do different LLMs (GPT-4, Claude, Llama) compare for vulnerability detection?
- What prompt engineering techniques maximize security analysis accuracy?
- Can we fine-tune open models on vulnerability-labeled code?
- What's the cost/benefit of LLM analysis vs. traditional SAST?

### Relevant Files
- `src/ai/mod.rs` - LLM integration
- `src/ai/mod.rs:440-464` - System prompt design
- `src/ai/mod.rs:214-282` - Heuristic fallback

### Proposed Research
1. Benchmark multiple LLMs against Juliet Test Suite
2. Experiment with few-shot vs. zero-shot prompting
3. Investigate chain-of-thought prompting for complex vulnerabilities
4. Measure token cost per finding vs. traditional SAST compute cost

### Current Prompt Strategy
```rust
const SECURITY_SYSTEM_PROMPT: &str = r#"You are an expert security code reviewer...
Always respond with structured JSON in this format:
{
  "vulnerabilities": [...]
}
```
This could be improved with few-shot examples, CWE context, or language-specific guidance.

### External Resources
- [LLMs for Code Security](https://arxiv.org/abs/2312.04724) - Academic survey
- [SecureBench](https://github.com/eth-sri/securebench) - LLM security benchmark
- [CodeQL + AI Experiments](https://github.blog/2023-06-14-codeql-code-scanning-with-ai/) - GitHub's research

---

## 5. Concurrency Model Optimization

### Context
The codebase uses a hybrid Tokio/Rayon model. The interaction between these runtimes is complex and potentially suboptimal.

### Research Questions
- What's the optimal balance between Tokio worker threads and Rayon threads?
- How should we tune channel buffer sizes for maximum throughput?
- Can we use adaptive concurrency based on system load?
- What's the memory/CPU tradeoff of different parallelism strategies?

### Relevant Files
- `src/config.rs:99-117` - Concurrency configuration
- `src/lib.rs` - Scanner orchestration
- `src/analyzer/sast.rs:208-228` - Parallel file analysis

### Proposed Research
1. Profile the application under various workloads
2. Experiment with work-stealing vs. work-sharing strategies
3. Measure context switching overhead between runtimes
4. Investigate `tokio-rayon` bridge patterns for better integration

### Current Configuration Defaults
```rust
pub concurrent_clones: usize,  // default: 4
pub channel_buffer: usize,     // default: 100
pub tokio_workers: usize,      // default: 0 (auto)
pub rayon_threads: usize,      // default: 0 (auto)
```
These defaults were chosen without benchmarking.

### External Resources
- [Tokio Internals](https://tokio.rs/tokio/tutorial) - Understanding the runtime
- [Rayon FAQ](https://github.com/rayon-rs/rayon/blob/master/FAQ.md) - Parallelism patterns
- [Async Rust Book](https://rust-lang.github.io/async-book/) - Best practices

---

## 6. Dependency Vulnerability Database Accuracy

### Context
SCA relies on OSV for vulnerability data. The accuracy and completeness of this data source is critical.

### Research Questions
- How does OSV compare to NVD, Snyk, GitHub Advisory Database in coverage?
- What's the typical lag between CVE publication and OSV entry?
- Can we cross-reference multiple databases to improve coverage?
- How do we handle version range ambiguity in vulnerability reports?

### Relevant Files
- `src/analyzer/sca.rs` - SCA engine
- `src/analyzer/sca.rs:78-118` - OSV query logic
- `src/analyzer/sca.rs:146-249` - Vulnerability conversion

### Proposed Research
1. Compare CVE coverage between OSV and other databases
2. Measure time-to-detection for new vulnerabilities
3. Analyze false positive rates from version range mismatches
4. Investigate federated querying of multiple databases

### Version Parsing Issue
```rust
// From sca.rs:264 - Fragile version parsing
let clean_version = version_str.trim_start_matches(|c| c == '^' || c == '~' || ...);
```
This doesn't handle complex semver ranges correctly.

### External Resources
- [OSV Schema](https://ossf.github.io/osv-schema/) - Data format specification
- [deps.dev](https://deps.dev/) - Google's dependency insights
- [Snyk Vulnerability Database](https://snyk.io/vuln/) - Commercial alternative

---

## 7. Cross-Language Vulnerability Patterns

### Context
Many vulnerabilities have cross-language manifestations (SQL injection exists in Rust, Python, JS, Go). Our queries are language-siloed.

### Research Questions
- Can we create abstract vulnerability patterns that compile to multiple language queries?
- How do language-specific idioms affect vulnerability manifestation?
- Can we share remediation guidance across languages?

### Relevant Files
- `src/analyzer/queries.rs` - All language-specific queries

### Example Pattern
SQL Injection appears in all four languages but with different syntax:
```
Rust:   query(&format!("SELECT * FROM {}", user_input))
Python: cursor.execute("SELECT * FROM %s" % user_input)
JS:     db.query("SELECT * FROM " + userInput)
Go:     db.Query("SELECT * FROM " + userInput)
```

### Proposed Research
1. Create a domain-specific language (DSL) for vulnerability patterns
2. Compile DSL to tree-sitter queries for each language
3. Validate pattern equivalence across languages
4. Investigate LLVM IR or WebAssembly for language-agnostic analysis

---

## 8. Privacy-Preserving Security Analysis

### Context
The tool clones repositories and potentially sends code to external LLMs. This raises privacy concerns.

### Research Questions
- Can we analyze code without full repository access (e.g., streaming analysis)?
- How can we use LLMs without sending raw code (embeddings, abstractions)?
- What differential privacy techniques apply to security findings?

### Relevant Files
- `src/ai/mod.rs:84-129` - LLM API interaction
- `src/crawler/git.rs` - Repository cloning

### Proposed Research
1. Investigate homomorphic encryption for code analysis
2. Explore code abstraction/anonymization before LLM submission
3. Design local-first analysis with optional cloud augmentation
4. Study GDPR/compliance implications of code analysis

---

## Priority Matrix

| Topic | Impact | Complexity | Priority |
|-------|--------|------------|----------|
| Tree-sitter Query Optimization | High | Medium | P1 |
| Entropy Secret Detection | Medium | Low | P1 |
| LLM-Assisted Detection | High | High | P2 |
| SLSA Provenance at Scale | Medium | Medium | P2 |
| Concurrency Optimization | Medium | Medium | P2 |
| Dependency DB Accuracy | Medium | Low | P3 |
| Cross-Language Patterns | High | High | P3 |
| Privacy-Preserving Analysis | Low | High | P4 |

---

## Next Steps

1. **Immediate**: Set up benchmark infrastructure using Juliet Test Suite
2. **Short-term**: Implement cross-database SCA queries (OSV + GitHub Advisory)
3. **Medium-term**: Experiment with LLM prompt variations and measure accuracy
4. **Long-term**: Design and implement cross-language vulnerability DSL
