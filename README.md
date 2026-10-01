# ghaudit

[![CI](https://github.com/Divhanthelion/ghaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/Divhanthelion/ghaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A security scanner for GitHub repositories. Point it at a local checkout, a single
repository, or a whole organization, and it reports:

- **Risky code**: SQL built from strings, shell commands from dynamic input, unsafe
  deserialization, disabled TLS verification, weak crypto and more. It uses 34
  syntax-aware rules across Rust, Python, JavaScript/TypeScript and Go.
- **Leaked credentials** in any text file, including `.env`, YAML and JSON. This covers
  20 provider formats (GitHub, AWS, Stripe, OpenAI, Anthropic, GitLab, npm, ...) plus
  secret-named assignments. Secrets are always masked in the output.
- **Vulnerable dependencies** in every common lockfile and manifest, via Google's
  [osv-scanner](https://github.com/google/osv-scanner) and the OSV database.

Results come out as readable text, JSON, or SARIF for GitHub code scanning. The exit
codes are designed for CI gates.

```text
$ ghaudit scan ./shop
ghaudit 0.2.0 scan of ./shop @ 3f9c1e27a0b4
5 files, 27 lines, 2 dependencies in 3.3s

CRITICAL secret     Stripe live secret key  [secret/stripe-key]
           .env:2:12
           > 2 | STRIPE_KEY=sk_l********
           Fix: Revoke and rotate this credential now (assume it is compromised once committed), ...

CRITICAL dependency django 2.0.0: SQL injection in Django  [osv/GHSA-hmr4-m2h5-33qx]
           requirements.txt:1:1
           GHSA-hmr4-m2h5-33qx (CVE-2020-7471, PYSEC-2020-35)  CVSS 9.8
           Fix: Upgrade django to 2.2.10 or later.

HIGH     code       SQL built from strings  [python/sql-injection]
           app/db.py:4:5
           > 4 |     cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
           Fix: Pass values as parameters: cursor.execute("... WHERE id = %s", (user_id,)), ...

Findings: 4 critical, 12 high, 14 medium, 4 low  (5 code, 2 secret, 27 dependency)
Analyzers: sast ok  secrets ok  sca ok  ai off
```

## Install

```bash
cargo install --git https://github.com/Divhanthelion/ghaudit
```

This needs Rust 1.88+ and `git` on your `PATH`. Dependency scanning also needs
[osv-scanner](https://google.github.io/osv-scanner/installation/) v2:

```bash
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest   # or brew/scoop/a release binary
```

Without osv-scanner, ghaudit still runs the other analyzers. It reports the scan as
**incomplete** (exit code 3) rather than clean; use `--no-sca` if you don't need
dependency checks.

## Usage

```bash
ghaudit scan .                                   # a local directory
ghaudit scan rust-lang/regex                     # a GitHub repository (shallow clone)
ghaudit scan https://github.com/owner/repo/tree/main/src
ghaudit org my-company --max-repos 50            # every repo in an org (needs a token)
ghaudit user octocat
ghaudit search 'topic:cli language:go stars:>500' --max-repos 20
ghaudit rules                                    # list the code rules
```

Set `GITHUB_TOKEN` (or pass `--token`) for private repositories, org/user/search scans
and higher API rate limits.

Common options:

| Option | Effect |
|---|---|
| `-f text\|json\|sarif` | Report format (default `text`) |
| `-o FILE` | Write the report to a file (checked before the scan starts) |
| `--no-sast`, `--no-secrets`, `--no-sca` | Turn analyzers off |
| `--languages rust,python` | Limit code analysis to these languages |
| `--exclude 'docs/**'` | Skip paths (gitignore syntax; repeatable; also applied to osv-scanner) |
| `--min-severity medium` | Leave lower-severity findings out of the report |
| `--fail-on critical` | Severity that makes the exit code 1 (default `high`; `never` to disable) |
| `--ai` | Also ask a local LLM for review (see below) |
| `-c ghaudit.toml` | Load settings from a file ([example](ghaudit.example.toml)) |

Logs go to stderr, so `ghaudit scan . -f json > report.json` always produces valid JSON.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan complete, nothing at or above `--fail-on` |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Usage or runtime error |
| 3 | Scan finished, but part of it failed (e.g. osv-scanner missing, a repo failed to clone) |

If findings meet the threshold *and* part of the scan failed, the exit code is 1; the
report still lists what failed.

### In GitHub Actions

```yaml
- name: Install ghaudit and osv-scanner
  run: |
    cargo install --git https://github.com/Divhanthelion/ghaudit
    go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
    echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"
- name: Scan
  run: ghaudit scan . -f sarif -o ghaudit.sarif --fail-on never
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ghaudit.sarif
```

The SARIF output has stable fingerprints, so alerts are tracked across runs instead of
reopening. It also carries `security-severity` scores, so GitHub labels alerts
critical/high/medium/low.

## What it detects

### Code rules

Each rule is a [tree-sitter](https://tree-sitter.github.io/) query over the syntax tree,
so matches in comments or strings don't count. Every rule ships with examples it must
flag and near-misses it must not; both are run as tests.

| Rule | Severity | What | CWE |
|---|---|---|---|
| `rust/unsafe-block` | info | Unsafe block | CWE-119 |
| `rust/unsafe-impl` | low | Unsafe trait implementation | CWE-362 |
| `rust/transmute` | medium | mem::transmute | CWE-843 |
| `rust/shell-command` | medium | Command runs a shell | CWE-78 |
| `rust/sql-format` | high | SQL built with format! | CWE-89 |
| `rust/tls-verification-disabled` | high | TLS certificate verification disabled | CWE-295 |
| `rust/weak-hash` | medium | Weak hash algorithm | CWE-328 |
| `rust/weak-cipher` | high | Broken cipher | CWE-327 |
| `python/eval` | high | eval/exec on dynamic input | CWE-95 |
| `python/sql-injection` | high | SQL built from strings | CWE-89 |
| `python/subprocess-shell` | high | subprocess with shell=True | CWE-78 |
| `python/os-command` | high | os.system/os.popen on dynamic input | CWE-78 |
| `python/unsafe-deserialization` | high | pickle/marshal/dill/shelve loads | CWE-502 |
| `python/yaml-load` | high | yaml.load without a safe loader | CWE-502 |
| `python/weak-hash` | medium | Weak hash algorithm | CWE-328 |
| `python/weak-cipher` | high | Broken cipher or ECB mode | CWE-327 |
| `python/tls-verification-disabled` | high | TLS certificate verification disabled | CWE-295 |
| `python/request-without-timeout` | low | HTTP request without timeout | CWE-400 |
| `python/flask-debug` | medium | Flask debug mode | CWE-489 |
| `python/insecure-tempfile` | medium | tempfile.mktemp | CWE-377 |
| `js/eval` | high | eval / new Function on dynamic input | CWE-95 |
| `js/command-injection` | high | Shell command built from dynamic input | CWE-78 |
| `js/sql-injection` | high | SQL built from strings | CWE-89 |
| `js/html-injection` | medium | innerHTML/document.write with dynamic input | CWE-79 |
| `js/dangerously-set-inner-html` | medium | dangerouslySetInnerHTML | CWE-79 |
| `js/tls-verification-disabled` | high | TLS certificate verification disabled | CWE-295 |
| `js/weak-crypto` | medium | Weak hash or cipher | CWE-327, CWE-328 |
| `js/regex-dos` | medium | Regex with nested quantifiers | CWE-1333 |
| `go/sql-injection` | high | SQL built from strings | CWE-89 |
| `go/shell-command` | medium | exec.Command runs a shell | CWE-78 |
| `go/tls-verification-disabled` | high | TLS certificate verification disabled | CWE-295 |
| `go/weak-random` | low | math/rand used | CWE-338 |
| `go/weak-crypto` | medium | Weak hash or cipher | CWE-327, CWE-328 |
| `go/unsafe-pointer` | info | unsafe.Pointer | CWE-119 |

JavaScript rules also run on TypeScript and TSX. `info` findings are hidden unless you
pass `--min-severity info`.

### Secrets

The provider formats are:

- **Code hosting**: GitHub classic and fine-grained tokens, GitLab
- **Cloud**: AWS access key ID and secret key, Google API key, Azure storage key
- **Payments and messaging**: Stripe live key, Slack token and webhook, SendGrid, Twilio
- **AI services**: OpenAI, Anthropic, Hugging Face
- **Package registries**: npm, PyPI
- **Other**: PEM private keys, JWTs, and passwords in database connection strings

On top of these, values assigned to secret-like names (`password`, `api_key`,
`client_secret`, ...) are flagged. These matches are filtered against placeholders
(`changeme`, `<your-key>`), references (`${VAR}`, `os.environ[...]`) and identifier-like
values.

Lockfiles and minified files are skipped. Provider tokens are reported even in test
directories, because a live token in a fixture is still leaked. Generic matches are
skipped in tests, examples and docs.

### Dependencies

osv-scanner reads Cargo.lock, package-lock.json, yarn.lock, pnpm-lock.yaml,
requirements.txt, poetry.lock, Pipfile.lock, uv.lock, go.mod, Gemfile.lock,
composer.lock, pom.xml, gradle lockfiles and more, at any depth.

Each advisory becomes one finding. It carries the CVSS-based severity, the advisory ID
and its aliases (CVE, GHSA, ...), the lockfile line, and the lowest version that fixes it.

## Suppressing findings

Add `ghaudit:ignore` in a comment on the line, or on the line above:

```python
digest = hashlib.md5(data).hexdigest()  # ghaudit:ignore[python/weak-hash] cache key only
```

`ghaudit:ignore` with no list silences every rule on that line. `[secret/]` silences one
family. To ignore whole paths, use `--exclude` or `exclude = [...]` in the config file.
To ignore specific dependency advisories, use osv-scanner's own `osv-scanner.toml`.

## Optional: LLM review

`--ai` sends each source file (up to `ai.max_files`, default 50) to an OpenAI-compatible
chat endpoint. That can be LM Studio (the default, `http://localhost:1234`), Ollama,
llama.cpp or vLLM.

Configure it with `[ai]` in the config file, or with `GHAUDIT_AI_URL` and
`GHAUDIT_AI_MODEL`. AI findings are labeled `ai` and their confidence is capped at
medium: treat them as leads, not verdicts.

## Limitations

- The code rules match patterns. They don't track data flow: they flag *a SQL string
  built from variables*, not *user input that reaches SQL*. That is why the rule set is
  small and aims at a low false-positive rate.
- Secret detection looks at the current files only, not git history. Run
  [gitleaks](https://github.com/gitleaks/gitleaks) or
  [trufflehog](https://github.com/trufflesecurity/trufflehog) over history when it matters.
- Repositories are cloned at depth 1 from their default branch.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how a scan works, module by module
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup and writing new rules
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT
