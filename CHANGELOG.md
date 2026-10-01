# Changelog

## 0.2.0

A rebuild of the scanner with a focus on correct, trustworthy results.

### Changed

- **Renamed** the crate and binary from `sec_auditor` to `ghaudit`.
- **Dependency scanning now uses osv-scanner.**
  - Covers every lockfile format osv-scanner supports, at any depth.
  - Severities come from CVSS scores.
  - Advisories are de-duplicated by alias.
  - Findings point at the lockfile line and name the fixed version.
  - The previous built-in scanner marked every advisory "unknown", so they were all
    filtered out of the report.
- **Code rules rewritten.**
  - 34 precise rules; TypeScript and TSX are now parsed with their own grammars.
  - Every rule has tested examples and counter-examples.
  - Removed rules that fired on ordinary code (`unwrap`, every file read, `RefCell`,
    `JSON.parse`, ...).
  - Fixed two rules that never compiled, and several that flagged the safe form of the
    code.
- **Secret detection.**
  - Now scans every text file (`.env`, YAML, JSON, ...), not only source code.
  - Adds GitHub fine-grained, GitLab, OpenAI, Anthropic, Hugging Face, npm, PyPI and
    Azure formats.
  - Secrets are masked everywhere, including snippets and fingerprints.
  - Fixed a crash on non-ASCII text and a filter that discarded random keys starting
    with a capital letter.
- **File discovery.**
  - Dependency and build directories are skipped at any depth.
  - `.gitignore` is honored.
  - Symlinks are never followed.
- **CLI.**
  - `--no-sast`, `--no-secrets`, `--no-sca` turn analyzers off.
  - `--fail-on` and documented exit codes (0/1/2/3).
  - Global options work after the subcommand.
  - Logs go to stderr.
  - `--languages`, `--max-file-size` and `--exclude` are honored.
  - The output path is checked before scanning.
  - Ctrl-C cleans up.
- **Failures are reported.** A missing osv-scanner, an unreachable LLM endpoint or a
  failed clone marks the scan incomplete (exit 3) instead of looking clean.
- **SARIF.**
  - Validates against the 2.1.0 schema.
  - Line numbers are 1-based and paths use `/`.
  - Fingerprints are stable across runs.
  - Includes GitHub `security-severity` scores and CWE tags.
- **Remote repositories** are cloned with the system `git`. Tokens are passed without
  exposing them on the command line, and clones are always cleaned up.
- **Config files** reject unknown keys; `ghaudit.example.toml` documents every setting.

### Removed

- The SLSA/Sigstore "provenance" module and the `verify` command. crates.io does not
  publish attestations, and the module performed no cryptographic verification.
- The scan-result cache, which could return stale results.
- Unused dependencies (octocrab, git2, sigstore-verification, redb, osv, cargo-lock, ...).

## 0.1.0

Initial version.
