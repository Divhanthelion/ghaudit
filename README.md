# ghaudit

[![CI](https://github.com/Divhanthelion/ghaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/Divhanthelion/ghaudit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Divhanthelion/ghaudit)](https://github.com/Divhanthelion/ghaudit/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A security scanner for GitHub repositories. Point it at a local checkout, a single
repository, or a whole organization, and it reports:

- **Risky code**: SQL built from strings, shell commands from dynamic input, unsafe
  deserialization, disabled TLS verification, weak crypto and more. It uses 37
  syntax-aware rules across Rust, Python, JavaScript/TypeScript and Go.
- **Leaked credentials** in any file, including `.env`, YAML, JSON and binaries. This
  covers over 20 provider formats (GitHub, AWS, Stripe, OpenAI, Anthropic, GitLab, npm,
  ...) plus secret-named assignments. Secrets are always masked in the output.
- **Vulnerable and malicious dependencies** in every common lockfile and manifest, via
  Google's [osv-scanner](https://github.com/google/osv-scanner) and the OSV database.
- **Insecure GitHub Actions workflows and composite actions**. These are the patterns
  behind the 2024–2026 CI supply-chain attacks:
  - script injection;
  - "pwn request" checkouts;
  - unpinned or previously compromised actions;
  - over-broad tokens and secrets reachable by anyone.
- **Hidden Unicode**: Trojan Source bidi tricks and invisible code, and invisible
  instructions in AI-agent files such as `.cursorrules`, `CLAUDE.md` and `.mcp.json`.

Results come out as readable text, JSON, or SARIF for GitHub code scanning. The exit
codes are designed for CI gates.

It is built to scan code you don't trust: a repository cannot use its own ignore files,
suppression comments or osv-scanner config to hide from the scan, and inputs crafted to
exhaust a scanner (YAML alias bombs, deeply nested code, megabyte-long lines) cost
bounded time and memory. See [Scanning repositories you don't control](#scanning-repositories-you-dont-control).

```text
$ ghaudit scan ./shop
ghaudit 0.2.1 scan of ./shop @ 3f9c1e27a0b4
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
Analyzers: sast ok  secrets ok  sca ok  workflows ok  ai off
```

## Install

Download a binary for Linux, macOS or Windows from
[Releases](https://github.com/Divhanthelion/ghaudit/releases). Every release ships
`SHA256SUMS` and signed build provenance, so you can check that a binary was built by
this repository's release workflow from the tagged source:

```bash
gh attestation verify ghaudit-v0.2.1-x86_64-unknown-linux-gnu.tar.gz --repo Divhanthelion/ghaudit
```

Or build from source (Rust 1.88+):

```bash
cargo install --git https://github.com/Divhanthelion/ghaudit
```

ghaudit needs `git` on your `PATH` for remote scans. Dependency scanning also needs
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
| `--no-sast`, `--no-secrets`, `--no-sca`, `--no-workflows` | Turn analyzers off |
| `--languages rust,python` | Limit code analysis to these languages |
| `--exclude 'docs/**'` | Skip paths (gitignore syntax; repeatable; also applied to osv-scanner) |
| `--min-severity medium` | Leave lower-severity findings out of the report |
| `--fail-on critical` | Severity that makes the exit code 1 (default `high`; `never` to disable) |
| `--trust-repo`, `--no-trust-repo` | Honor (or not) the scanned repository's own ignore files, `ghaudit:ignore` comments and `osv-scanner.toml`; by default only local directories are trusted |
| `--ai` | Also ask a local LLM for review (see below) |
| `-c ghaudit.toml` | Load settings from a file ([example](ghaudit.example.toml)) |

Logs and the per-repository progress of org/user/search scans go to stderr, so
`ghaudit scan . -f json > report.json` always produces valid JSON.

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
permissions:
  contents: read
  security-events: write # upload SARIF to code scanning

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false
  - name: Install ghaudit (verifying its build provenance) and osv-scanner
    env:
      GH_TOKEN: ${{ github.token }}
      VERSION: v0.2.1
    run: |
      archive="ghaudit-$VERSION-x86_64-unknown-linux-gnu.tar.gz"
      gh release download "$VERSION" -R Divhanthelion/ghaudit -p "$archive"
      gh attestation verify "$archive" -R Divhanthelion/ghaudit
      tar xzf "$archive" && sudo mv "${archive%.tar.gz}/ghaudit" /usr/local/bin/
      go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.6.0
      echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"
  - name: Scan
    run: ghaudit scan . -f sarif -o ghaudit.sarif --fail-on never
  - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4
    with:
      sarif_file: ghaudit.sarif
```

Drop `--fail-on never` to make the job fail on high-severity findings instead of only
reporting them.

The SARIF output has stable fingerprints, so alerts are tracked across runs instead of
reopening. It also carries `security-severity` scores, so GitHub labels alerts
critical/high/medium/low.

## Scanning repositories you don't control

A cloned repository is treated as untrusted, because its author may have written it to
fool scanners:

- **Its own controls are ignored.** Its `.gitignore`/`.ignore` files, `ghaudit:ignore`
  comments and `osv-scanner.toml` files could otherwise hide files, findings and
  vulnerable packages. Local directories are trusted by default; `--trust-repo`,
  `--no-trust-repo` or `trust_repo` in the config file change that. Even in trusted
  scans, files git tracks are scanned when they match an ignore pattern.
- **The clone runs nothing it controls**: no hooks, submodules, symlinks or Git LFS
  downloads (whose server the repository's `.lfsconfig` chooses). Your token is only
  sent over HTTPS, to the GitHub host.
- **Costs are bounded.** Each file gets a 5-second budget for code analysis, and each
  repository gets `github.repo_timeout_secs` (default 30 minutes). Workflow YAML that
  expands beyond 100,000 nodes is refused and reported. One rule reports at most 25
  findings per file; the rest are counted. Ctrl-C or SIGTERM stops the scan and deletes
  the clone.
- **Nothing is skipped silently.** Files over `max_file_size`, minified files, and
  files that hit the time budget are listed in the report's `skipped` section. Files
  with NUL bytes are still searched for credentials, and UTF-16 files are decoded.
- **Output is safe to print.** Control and invisible characters in paths, code and
  messages are shown as `<U+001B>`-style escapes, so a file name cannot rewrite your
  terminal.

## What it detects

### Code rules

Each rule is a [tree-sitter](https://tree-sitter.github.io/) query over the syntax tree,
so matches in comments or strings don't count. Every rule ships with examples it must
flag and near-misses it must not; both are run as tests.

The SQL rules follow one step of data flow: a SQL string built in a variable and passed
to a query function later in the same function is flagged too.

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
| `python/subprocess-shell` | high | subprocess with shell=True (or getoutput, create_subprocess_shell) | CWE-78 |
| `python/os-command` | high | os.system/os.popen on dynamic input | CWE-78 |
| `python/unsafe-deserialization` | high | pickle/marshal/dill/shelve loads | CWE-502 |
| `python/yaml-load` | high | yaml.load without a safe loader | CWE-502 |
| `python/weak-hash` | medium | Weak hash algorithm | CWE-328 |
| `python/weak-cipher` | high | Broken cipher or ECB mode | CWE-327 |
| `python/tls-verification-disabled` | high | TLS certificate verification disabled | CWE-295 |
| `python/request-without-timeout` | low | HTTP request without timeout | CWE-400 |
| `python/flask-debug` | medium | Flask debug mode | CWE-489 |
| `python/insecure-tempfile` | medium | tempfile.mktemp | CWE-377 |
| `js/eval` | high | eval / new Function / vm.run* on dynamic input | CWE-95 |
| `js/command-injection` | high | Shell command built from dynamic input | CWE-78 |
| `js/sql-injection` | high | SQL built from strings | CWE-89 |
| `js/html-injection` | medium | innerHTML, document.write or jQuery .html() with dynamic input | CWE-79 |
| `js/dangerously-set-inner-html` | medium | dangerouslySetInnerHTML | CWE-79 |
| `js/tls-verification-disabled` | high | TLS certificate verification disabled | CWE-295 |
| `js/weak-crypto` | medium | Weak hash or cipher | CWE-327, CWE-328 |
| `js/regex-dos` | medium | Regex with nested quantifiers | CWE-1333 |
| `js/sanitizer-bypass` | medium | Angular bypassSecurityTrust* on dynamic content | CWE-79 |
| `js/nosql-injection` | high | MongoDB `$where` built from dynamic input | CWE-943 |
| `go/sql-injection` | high | SQL built from strings | CWE-89 |
| `go/shell-command` | medium | exec.Command runs a shell on a dynamic command | CWE-78 |
| `go/tls-verification-disabled` | high | TLS certificate verification disabled | CWE-295 |
| `go/weak-random` | low | math/rand used | CWE-338 |
| `go/weak-crypto` | medium | Weak hash or cipher | CWE-327, CWE-328 |
| `go/unsafe-pointer` | info | unsafe.Pointer | CWE-119 |
| `go/template-escape-bypass` | medium | template.HTML (and JS, URL, ...) on dynamic content | CWE-79 |

JavaScript rules also run on TypeScript and TSX. `info` findings are hidden unless you
pass `--min-severity info`.

Findings in tests, examples and documentation (`tests/`, `examples/`, `docs/`,
`*_test.go`, `*.spec.ts`, Markdown, ...) are reported as `info`: visible with
`--min-severity info`, but not failing builds. Minified files are not run through the
code rules.

### Secrets

The provider formats are:

- **Code hosting**: GitHub classic and fine-grained tokens, GitLab (including runner
  registration tokens)
- **Cloud**: AWS access key ID and secret key, Google API key, Azure storage key
- **Payments and messaging**: Stripe live key, Slack tokens and incoming/workflow
  webhooks, SendGrid, Twilio
- **AI services**: OpenAI, Anthropic (API keys and Claude OAuth tokens), Hugging Face
- **Package registries**: npm (including `.npmrc` auth tokens), PyPI and TestPyPI
- **Other**: PEM private keys, JWTs, and passwords in database connection strings

On top of these, values assigned to secret-like names (`password`, `api_key`,
`client_secret`, ...) are flagged, in code (`cfg["password"] = "..."`,
`password: str = "..."`) and in config files, shell scripts and Dockerfiles
(`export TOKEN=...`, `ENV API_KEY ...`). These matches are filtered against placeholders
(`changeme`, `<your-key>`), references (`${VAR}`, `os.environ[...]`), identifier-like
values, hashes and hex addresses.

Lockfiles and minified files are skipped. Provider tokens are reported even in tests and
docs, because a live token in a fixture is still leaked, but at medium severity at most
there. Generic matches are skipped in tests, examples, docs and translation catalogs.

Secret values never appear in a report: not in messages, not in the context lines of
other findings, and not in a form a fingerprint could be checked against.

### GitHub Actions workflows

Files in `.github/workflows/` and composite actions (`action.yml` anywhere) are checked
for:

| Rule | Severity | What | Real-world example |
|---|---|---|---|
| `gha/template-injection` | critical\* | `${{ github.event.issue.title }}`-style attacker-controlled values pasted into `run:` or `github-script` | Ultralytics (2024), nx "s1ngularity" (2025) |
| `gha/untrusted-checkout` | critical | `pull_request_target`/`workflow_run`/`issue_comment` that checks out the PR's code ("pwn request"), with `actions/checkout`, `gh pr checkout` or `git fetch` | Trivy, TanStack, AsyncAPI (2026) |
| `gha/compromised-action` | high | Mutable tag of an action whose tags were hijacked before | tj-actions/changed-files (2025), trivy-action (2026) |
| `gha/unpinned-action` | medium\*\* | `uses:` by tag or branch instead of a commit SHA, or a `docker://` image without a digest | same |
| `gha/excessive-permissions` | high / medium | `permissions: write-all`, no permissions block, or workflow-wide write scopes on a privileged trigger | |
| `gha/public-trigger-with-secrets` | high | Issue/comment-triggered job that uses secrets without checking who triggered it | |
| `gha/self-hosted-runner` | medium | Self-hosted runner reachable from pull requests | Shai-Hulud 2.0 (2025) |
| `gha/secrets-inherit` | medium | `secrets: inherit` into an external reusable workflow | |
| `gha/all-secrets-exposed` | high | `toJSON(secrets)` | |
| `gha/unanalyzable-workflow` | medium / low | A workflow ghaudit cannot parse, or one that expands to an absurd size | |

\* Medium when the trigger cannot carry secrets (e.g. `pull_request` from a fork); low
for `inputs.*` of reusable workflows and composite actions.
\*\* Info for GitHub's own `actions/*` and `github/*`.

Expressions are parsed, not pattern-matched. Any spelling of a field is recognized
(`GitHub.Event['issue'].title`), as are values passed through `env:` and later
interpolated as `${{ env.X }}`. Values that can only be booleans
(`${{ github.event.issue.title == 'bug' }}`) are not flagged. Findings point at the
exact line of the expression.

These are deliberately a high-confidence subset. For deeper workflow analysis, use
[zizmor](https://github.com/zizmorcore/zizmor) as well.

### Hidden Unicode

- `unicode/bidi-control`: bidirectional control characters in code and configuration,
  which make code display differently from how it runs (Trojan Source, CVE-2021-42574).
- `unicode/invisible-text`: zero-width characters, Unicode "tag" characters, Hangul
  fillers (valid as JavaScript identifiers), direction marks next to code, and variation
  selectors used to smuggle payloads (GlassWorm, 2025). They can hide instructions in AI
  agent files (`.cursorrules`, `AGENTS.md`, `CLAUDE.md`, `SKILL.md`,
  `.github/copilot-instructions.md`, `.cursor/rules/`, `.claude/`, MCP configs, ...) and
  code in source files.

Legitimate uses are left alone: emoji sequences, joiners inside Persian or Indic words,
and typography in translation catalogs.

### Dependencies

osv-scanner reads Cargo.lock, package-lock.json, yarn.lock, pnpm-lock.yaml,
requirements.txt, poetry.lock, Pipfile.lock, uv.lock, go.mod, Gemfile.lock,
composer.lock, pom.xml, gradle lockfiles and more, at any depth.

Each advisory becomes one finding. It carries the CVSS-based severity, the advisory ID
and its aliases (CVE, GHSA, ...), the lockfile line, and the lowest version that fixes it.

Known-malicious packages (OpenSSF `MAL-` reports) are always critical, because
installing one may already have compromised the machine.

## Suppressing findings

Add `ghaudit:ignore` in a comment on the line, or on the line above:

```python
digest = hashlib.md5(data).hexdigest()  # ghaudit:ignore[python/weak-hash] cache key only
```

`ghaudit:ignore` with no list silences every rule on that line. `[secret/]` silences one
family. To ignore whole paths, use `--exclude` or `exclude = [...]` in the config file.
To ignore specific dependency advisories, use osv-scanner's own `osv-scanner.toml`.

Comments and `osv-scanner.toml` files are honored only in trusted scans (by default,
local directories), so a repository you are auditing cannot silence its own findings.
The report counts suppressed findings.

## Optional: LLM review

`--ai` sends each source file (up to `ai.max_files`, default 50) to an OpenAI-compatible
chat endpoint. That can be LM Studio (the default, `http://localhost:1234`), Ollama,
llama.cpp or vLLM.

Configure it with `[ai]` in the config file, or with `GHAUDIT_AI_URL` and
`GHAUDIT_AI_MODEL`. AI findings are labeled `ai` and their confidence is capped at
medium: treat them as leads, not verdicts. Detected credentials are replaced with
`********` before a file is sent to the model.

## Limitations

- The code rules match patterns, with at most one step of data flow (a variable
  assigned in the same function). They flag *a SQL string built from variables*, not
  *user input that reaches SQL*. That is why the rule set is small and aims at a low
  false-positive rate.
- Secret detection looks at the current files only, not git history. Run
  [gitleaks](https://github.com/gitleaks/gitleaks) or
  [trufflehog](https://github.com/trufflesecurity/trufflehog) over history when it matters.
- Repositories are cloned at depth 1 from their default branch.
- Workflow checks read workflow files only; they don't inspect what a referenced action
  does internally, or repository settings such as branch protection.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how a scan works, module by module
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup and writing new rules
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT
