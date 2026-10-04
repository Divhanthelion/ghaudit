# ghaudit

[![CI](https://github.com/Divhanthelion/ghaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/Divhanthelion/ghaudit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Divhanthelion/ghaudit)](https://github.com/Divhanthelion/ghaudit/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A security scanner for GitHub repositories. Point it at a local checkout, a single
repository, or a whole organization, and it reports:

- **Risky code**: SQL built from strings, shell commands from dynamic input, unsafe
  deserialization, disabled TLS verification, weak crypto and more. It uses 37
  syntax-aware rules across Rust, Python, JavaScript/TypeScript and Go.
- **Leaked credentials** in any file, including `.env`, YAML, JSON and binaries, and
  with `--history` in every commit. This covers over 20 provider formats (GitHub, AWS,
  Stripe, OpenAI, Anthropic, GitLab, npm, ...) plus secret-named assignments. Secrets
  are always masked in the output.
- **Vulnerable and malicious dependencies** in every common lockfile and manifest, via
  Google's [osv-scanner](https://github.com/google/osv-scanner) and the OSV database.
- **Insecure GitHub Actions workflows and composite actions**. These are the patterns
  behind the 2024–2026 CI supply-chain attacks:
  - script injection;
  - "pwn request" checkouts;
  - unpinned or previously compromised actions;
  - over-broad tokens and secrets reachable by anyone.
- **Weak repository and organization settings**, read from the GitHub API: an
  unprotected default branch, secret scanning or Dependabot turned off, workflows that
  get a write token or can approve pull requests, fork pull requests that see secrets,
  webhooks without TLS or a secret, organizations that don't require 2FA, and more.
- **Dangerous AI-agent and editor configs** committed to the repository: Claude Code
  hooks and helpers, Copilot auto-approval (CVE-2025-53773), VS Code tasks that run when
  the folder opens, Codex and Gemini "never ask" modes, and MCP servers started from
  unpinned packages or reached over plain HTTP.
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
ghaudit 0.3.0 scan of ./shop @ 3f9c1e27a0b4
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
Analyzers: sast ok  secrets ok  history off  sca ok  workflows ok  agents ok  settings ok  ai off
Settings: 21 passed, 2 failed, 0 not assessable
```

## Install

Build from source (Rust 1.88+):

```bash
cargo install --git https://github.com/Divhanthelion/ghaudit ghaudit
# or, from a checkout: cargo install --path .   (or run in place: cargo run --release -- scan .)
```

The repository also holds the [desktop app](#desktop-app), so name the `ghaudit` package
when installing from git. Installing the CLI never builds the app.

Tagged versions also publish binaries for Linux, macOS and Windows on
[Releases](https://github.com/Divhanthelion/ghaudit/releases), with `SHA256SUMS` and
signed build provenance, so you can check that a binary was built by this repository's
release workflow from the tagged source:

```bash
gh attestation verify ghaudit-v0.3.0-x86_64-unknown-linux-gnu.tar.gz --repo Divhanthelion/ghaudit
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
ghaudit user octocat                             # your own login: private repos too
ghaudit search 'topic:cli language:go stars:>500' --max-repos 20
ghaudit scan . --history                         # also search every commit for credentials
ghaudit rules                                    # list every rule
```

Set `GITHUB_TOKEN` (or pass `--token`) for private repositories, org/user/search scans,
the settings audit and higher API rate limits. `ghaudit user` with your own login lists
your private repositories as well as public ones.

Common options:

| Option | Effect |
|---|---|
| `-f text\|json\|sarif` | Report format (default `text`) |
| `-o FILE` | Write the report to a file (checked before the scan starts) |
| `--no-sast`, `--no-secrets`, `--no-sca`, `--no-workflows`, `--no-agents`, `--no-settings` | Turn analyzers off |
| `--history` | Also search git history for credentials removed from the files (clones full history) |
| `--baseline report.json` | Report only findings that are not in an earlier `-f json` report |
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
      VERSION: v0.3.0
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
critical/high/medium/low. Settings findings have no file; they link to the settings page
that fixes them.

### Only new findings: baselines

To adopt ghaudit on an existing codebase without fixing everything first, record what
is there today and gate on what is new:

```bash
ghaudit scan . -f json -o ghaudit-baseline.json --fail-on never
ghaudit scan . --baseline ghaudit-baseline.json       # reports and fails only on new findings
```

Findings are matched by fingerprint, which ignores line numbers, so moving code does not
make old findings new. The report counts the findings the baseline hid. In multi-repo
scans the repository is part of the match. `baseline = "..."` in `[report]` sets it in
the config file.

## Desktop app

The desktop app runs ghaudit without the command line and explains the results in plain
language.

- **Scan**: "Scan my repositories" scans everything you own in one click. Or pick one
  repository, a folder on this computer, an organization, someone's repositories or a
  GitHub search, and choose the checks, git history, archived repositories and forks.
  A row per repository shows the scan as it runs (status, findings, time, errors), and
  Cancel stops it within seconds.
- **Open a saved report**: the app also browses JSON reports the CLI writes (`-f json`).
- **Overview**: whether the scan is complete, how many problems there are at each
  severity and what each severity means, what kinds of problems they are, and which
  repositories have the most.
- **Findings**: filter by severity, kind, repository or any text (a file, a package, a
  CVE), sort, and group by repository. Select one to see what was found, the code
  around it (credentials masked), how to fix it, and links to the file on GitHub, the
  commit, the advisory or the settings page.
- **Settings**: a grid of every repository's security settings, each passed, needing
  attention, or couldn't be checked. A check that couldn't run is shown as a gap with
  its reason, never as a pass. Select a square to see what it means and open the
  settings page.
- **Coverage**: which checks ran, which didn't and why, and files that weren't fully
  analyzed. A gap is never shown as a pass.
- **Only what's new**: compare with an earlier report to hide what it already had,
  as `--baseline` does.
- **Save and export**: save the report as JSON (to open again or compare with later),
  SARIF (for GitHub code scanning) or text.

GitHub access comes, in this order, from `GITHUB_TOKEN`, from the
[GitHub CLI](https://cli.github.com/)'s login (`gh auth login`), or from a token you
paste into the app, which keeps it in the system keychain (Windows Credential Manager,
the macOS Keychain or the Secret Service), never in a file. The token stays in the
app's Rust side and is never shown or logged. Dependency checks need osv-scanner; the
app finds it on `PATH` or where `winget install --id Google.OSVScanner` puts it, and
offers to scan without dependency checks if it's missing.

Run it from a checkout (Rust 1.90+; on Linux, first install Tauri's
[system libraries](https://v2.tauri.app/start/prerequisites/#linux)):

```bash
cargo run -p ghaudit-desktop        # or, with tauri-cli installed: cd app && cargo tauri dev
```

The app is built to show untrusted content safely. Report text from scanned repositories
is only ever displayed as text, never as HTML. The window runs under a strict content
security policy and can call nothing but the app's own commands: it has no access to
files, the shell or the network. Files and folders are chosen through the system's
dialogs, and links open only to github.com and osv.dev. Like the CLI, the app only
reads from GitHub.

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
  sent over HTTPS, to the GitHub host. The history search turns off external diff
  drivers, textconv filters and signature checks, so a repository's `.git/config` or
  `.gitattributes` cannot make it run a command either.
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
Rust unit tests count as tests: code under `#[cfg(test)]` and `#[test]` functions.

Secret values never appear in a report: not in messages, not in the context lines of
other findings, and not in a form a fingerprint could be checked against.

#### In git history

A credential deleted in a later commit is still leaked: anyone who can clone the
repository can recover it. `--history` (or `history = true`) searches every commit on
every branch and reports each credential that is gone from the current files once, at
the newest commit that added it:

```text
CRITICAL secret     GitHub token in git history  [secret/github-token]
           src/settings.py:6:10 in commit 10bdc4b11c77
           > 6 | TOKEN = "ghp_********"
           GitHub token found: ghp_******** Added in commit 10bdc4b11c77 (2020-09-14) and gone
           from the current files, but anyone who can clone the repository can recover it from
           history.
```

Repositories are then cloned with full history instead of depth 1. The search streams
`git log -p` (a 10,000-commit history with 80 MB of diffs takes about 6 seconds) and
stops after 10 minutes or 1 GiB of diffs, saying so in the report. `--exclude` patterns apply to historical paths
too. Credentials still in the current files are reported by the normal scan, not twice.
The fix is always to revoke the credential: rewriting history does not reach clones
that already exist.

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

### Repository and organization settings

With a token, ghaudit reads each repository's settings from the GitHub API (read-only:
it never changes anything). Every check ends as **pass**, **fail** or **not
assessable**. A check the token cannot see is reported as not assessable, never as a
pass. Failures are findings that link to the settings page that fixes them; the JSON
report's `settings` section lists every check.

| Area | Checks |
|---|---|
| Default branch | No protection (rulesets or classic branch protection), direct pushes, no required review, force pushes, deletion, admins exempt |
| Security features | Secret scanning, push protection, Dependabot alerts and security updates, private vulnerability reporting |
| Actions | `GITHUB_TOKEN` writable by default, workflows can approve pull requests, SHA pinning not required, any action allowed, weak approval for fork pull requests, fork pull requests get secrets or a write token, self-hosted runners on a public repository |
| Access | Deploy keys with write access or unused for a year, outside collaborators with admin, deployment environments without protection rules |
| Webhooks | TLS verification off, plain HTTP, no secret |
| Organization (`ghaudit org`) | 2FA not required, members without 2FA or with SMS 2FA, members get write or admin on every repository, and the Actions and webhook checks at organization level |

`ghaudit rules` lists all 38 with their severities. GitHub shows most of these settings
only to repository admins (and organization owners), so scan with an admin's token to
assess them all. Local directories are audited when their `origin` remote is on the
configured GitHub host.

### AI agent and editor configuration

Config files committed to a repository configure the tools of everyone who opens it:
an agent may start an MCP server, run a hook or skip its confirmation prompts. ghaudit
reads `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` and other `mcp.json` files,
`claude_desktop_config.json`, `mcp_config.json`, `.claude/settings.json` (and
`settings.local.json`), `.vscode/settings.json`, `.vscode/tasks.json`,
`.gemini/settings.json`, `.zed/settings.json` and `.codex/config.toml`.

| Rule | Severity | What |
|---|---|---|
| `agent/dangerous-command` | high | A hook, credential helper, task or MCP server command that downloads or decodes code and runs it (`curl ... \| sh`, `iex`, `base64 -d \| sh`, reverse shells) |
| `agent/auto-approve` | high / medium / low | Tool calls run without asking: VS Code `chat.tools.autoApprove` (CVE-2025-53773), Codex `approval_policy = "never"` or `danger-full-access`, Claude Code `Bash` allowed outright, any package install allowed (`Bash(npm install:*)`, `Bash(npx:*)`) or `enableAllProjectMcpServers`, MCP servers marked `trust: true`, Gemini `autoAccept` |
| `agent/command-on-open` | medium / low | VS Code tasks with `runOn: folderOpen`; Claude Code hooks, `apiKeyHelper` and other command settings |
| `agent/mcp-unpinned-package` | medium | MCP server started with `npx`, `uvx`, `pipx run`, `pnpm dlx`, `bunx` or `docker run` without a pinned version, so each start can fetch different code |
| `agent/mcp-insecure-transport` | medium | Remote MCP server reached over plain `http://` |

Comments in these JSON files (JSONC) are understood.

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

RustSec also publishes informational advisories, which are labeled as such:
`unmaintained` crates (no known flaw, but no fixes coming; low unless rated) and
`unsound` ones (safe code can cause undefined behavior; their own rating, or unknown).

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
- Secrets are matched by format, not verified against the provider: a match may be
  revoked already. Git history is searched only with `--history`, and only the branches
  a clone fetches (not pull request refs or other forks).
- Without `--history`, repositories are cloned at depth 1 from their default branch.
- Workflow checks read workflow files only; they don't inspect what a referenced action
  does internally.
- The settings audit needs a token, and admin access for most checks. Organization
  rulesets that target a repository are counted as protection; their bypass lists are
  not analyzed.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how a scan works, module by module, and
  how the desktop app is put together
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup and writing new rules
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT
