# Changelog

## 0.3.0

Three new analyzers and two new modes, aimed at auditing the repositories you own.

### New

- **Repository and organization settings audit** (`settings`, on by default, needs a
  token). 38 checks read from the GitHub API, read-only:
  - default branch protection, via rulesets (including organization rulesets) or
    classic protection;
  - secret scanning, push protection, Dependabot, private vulnerability reporting;
  - Actions: default token permissions, workflows approving pull requests, SHA pinning,
    allowed actions, fork pull request approval and secrets, self-hosted runners on
    public repositories;
  - deploy keys, webhooks, outside collaborators with admin, environments;
  - for `ghaudit org`, the organization itself: 2FA requirement and members without
    2FA, default member permission, Actions and webhooks.

  Each check is pass, fail or **not assessable**; a check the token cannot see is never
  counted as a pass. Failures link to the settings page that fixes them, in text and
  SARIF output, and the JSON report lists every check in a new `settings` section.
  Local directories are audited through their `origin` remote. `--no-settings` turns it
  off.
- **AI agent and editor config checks** (`agents`, on by default): download-and-run
  commands in hooks, helpers, tasks and MCP servers; auto-approval (VS Code
  `chat.tools.autoApprove`, Codex `approval_policy = "never"`, Claude Code `Bash`
  allow-all and `enableAllProjectMcpServers`, Gemini `autoAccept`, MCP `trust: true`);
  VS Code tasks that run on folder open; MCP servers from unpinned `npx`/`uvx`/`docker`
  packages or over plain HTTP. Covers `.mcp.json` and other MCP configs, `.claude/`,
  `.vscode/`, `.gemini/`, `.zed/` and `.codex/`. `--no-agents` turns it off.
- **Git history search** (`--history`, `history = true`): every commit on every branch
  is searched for credentials that are gone from the current files. Each is reported
  once, at the newest commit that added it, with the commit in the text, JSON
  (`commit`) and SARIF output. Repositories are cloned with full history in this mode.
  Diff drivers, textconv filters and signature checks are off, so a repository's git
  config cannot run anything, and the search stops at 1 GiB or 10 minutes, saying so.
- **Baselines** (`--baseline report.json`, `baseline = "..."`): report and gate only on
  findings that are not in an earlier JSON report. Matching uses fingerprints, which
  ignore line numbers; the report counts the findings the baseline hid.
- **`ghaudit user <your-login>` includes your private repositories** when the token is
  yours (GitHub's public listing omits them).

### Improved

- Secret placeholders: values with counting or keyboard runs (`12345`, `abcdef`,
  `a1b2c3`, `qwerty`) are treated as test data, which removes the most common false
  positives in fixtures and code dumps.
- `ghaudit rules` lists the agent and settings checks too, and sizes its columns to fit.
- The text report ends with a settings summary (passed, failed, not assessable).

### For developers

- `GitHub::probe` returns any 4xx response for the caller to judge, while rate limits
  and server errors stay errors.
- Analyzer order in reports: `sast`, `secrets`, `history`, `sca`, `workflows`,
  `agents`, `settings`, `ai`. Scripts that index `analyzers` by position need updating.

## 0.2.1

Hardening for scanning repositories you don't control, plus accuracy work across every
analyzer. Each fix below has a regression test.

### Security

- **Cloned repositories can no longer hide findings.** By default their `.gitignore` and
  `.ignore` files, `ghaudit:ignore` comments and `osv-scanner.toml` files are not
  honored; osv-scanner runs with `--config <empty> --no-ignore`. Local directories are
  still trusted. New `trust_repo` setting and `--trust-repo`/`--no-trust-repo` flags.
  Files git tracks are scanned even when an ignore rule matches them.
- **No file is skipped silently.** Files over `max_file_size`, minified files and files
  that hit the analysis time limit are listed in a new `skipped` report section. UTF-16
  files are decoded, and files with NUL bytes are still searched for credentials.
- **Bounded cost on hostile input.**
  - Workflow YAML that expands past 100,000 nodes (alias bombs) is refused and reported
    as `gha/unanalyzable-workflow`. It used to need over 5 GB of memory; deeply nested
    flow YAML used to hang.
  - Code analysis has a 5-second budget per file.
  - Per-finding work is now linear: a 32,000-line file that took 20 seconds takes
    under 2, and a 1 MiB line no longer produces a 200 MB report.
  - Each rule keeps at most 25 findings per file. The rest are counted in a new
    `omitted` section, so thousands of decoys cannot push real findings out of SARIF's
    5,000-result limit.
  - `github.repo_timeout_secs` (default 1800) bounds each repository, and SIGTERM now
    cleans up like Ctrl-C.
- **Clones run nothing the repository controls.** Git LFS is disabled, so a
  `.lfsconfig` can no longer make git-lfs contact a server of its choosing.
  `protocol.ext.allow=never` is set. The token is only sent over http(s).
- **Secret leaks closed.**
  - Credentials are masked before files are sent to the optional LLM, and in its replies.
  - Fingerprints of every finding on a line holding a secret now use a fully masked
    line. In 0.2.0, code findings on such a line hashed the raw line, which allowed
    offline guessing of weak passwords.
  - Secrets are masked in finding messages too.
- Every git command ghaudit runs disables `core.fsmonitor`, so the `.git/config` of a
  downloaded project scanned as a local directory cannot run a command.
- **Terminal escapes neutralized.** File names, code and error output can no longer
  inject escape sequences into the text report or logs.
- **Target confusion fixed.** `gitlab.com/a/b` (or any non-GitHub URL) is now an error
  instead of a scan of `github.com/a/b`.
- On Linux and macOS, backslashes in file names are no longer rewritten to `/`, so
  `src\app.py` cannot pose as `src/app.py`.

### Workflows

- Rebuilt on a position-preserving YAML parser: findings point at the exact line.
- `${{ }}` expressions are parsed:
  - any spelling of a field is recognized (`GitHub.Event['issue'].title`), as are
    `toJSON(github.event...)`, `format()`, `join()` and values passed through `env:`;
  - boolean-only expressions (`github.event.issue.title == 'x'`) are no longer flagged;
  - a `}}` inside a quoted string no longer ends the expression.
- New checks and coverage:
  - composite actions (`action.yml`);
  - `inputs.*` in reusable workflows (low severity);
  - pwn requests via `gh pr checkout`, `git fetch ... pull/`, `issue_comment` and
    `env:` indirection;
  - `docker://` images without a digest;
  - workflow-wide write permissions on privileged triggers;
  - every `toJSON(secrets)` occurrence.
- Fewer false positives:
  - the actor check must be in an `if:` condition;
  - using `secrets.GITHUB_TOKEN` alone does not count as reading secrets;
  - block-scalar `uses:` values and non-`owner/repo` references are handled;
  - GitHub's own `actions/*` are `info` when unpinned.
- `uses:` matching is case-insensitive (`TJ-Actions/Changed-Files@v45`).

### Code rules

- SQL rules follow one step of data flow: a SQL string built in a variable and executed
  later in the same function is flagged (Python, JavaScript, Go, Rust). The engine
  supports this through a `#bound?` predicate.
- New rules: `js/sanitizer-bypass` (Angular), `js/nosql-injection` (MongoDB `$where`),
  `go/template-escape-bypass` (`template.HTML`).
- New sinks:
  - JavaScript: `vm.runIn*Context` and jQuery `.html()`;
  - Python: Django `objects.raw()`, `subprocess.getoutput`,
    `asyncio.create_subprocess_shell`, imported `system()`/`loads()`, and `shell=True`
    on imported `run`.
- False positives fixed:
  - `exec.Command("git", "sh")`, and shell commands that are constant strings;
  - `new Function` with only literal arguments;
  - `innerHTML += 'literal'`;
  - delimiter-separated regexes such as `([^,]+,)*`.
- Columns count characters, not bytes; SARIF declares `columnKind: unicodeCodePoints`
  and percent-encodes URIs.
- Findings in tests, examples and docs are reported as `info` instead of failing builds.

### Secrets

- New formats:
  - GitLab runner registration tokens;
  - Slack workflow webhooks;
  - Hugging Face org tokens;
  - Claude OAuth tokens;
  - TestPyPI tokens;
  - `.npmrc` auth tokens.
- Tokens ending in `-` or `_` (Google, SendGrid) are no longer missed.
- Generic assignments now also cover `cfg["password"] = ...`, type-annotated
  assignments, template literals, shell `export`, Dockerfile `ENV`/`ARG`, indented PEM
  keys and `redis://:password@host`.
- Fewer false positives: hex values, checksum/digest names, translation catalogs, and
  repetitive fakes behind a real prefix.
- Provider tokens in tests and docs are capped at medium severity (private keys: low).
- Recall on the gitleaks test corpus: 71.5% → 74.9% of true-positive files, with no
  new false positives.

### Hidden Unicode

- Also checks configuration files and many more languages (Java, C#, Ruby, shell, ...).
- Detects Hangul fillers, variation-selector payloads (GlassWorm), blank-looking
  characters, and direction marks next to code.
- Flags only valid subdivision-flag sequences as legitimate, not any line containing 🏴.
- Covers more agent files: `SKILL.md`, `.github/instructions/`, `.github/prompts/`,
  `.windsurf/`, `.claude/`, `.kiro/` and others.
- Agent files are never downgraded as documentation.
- Typography in translation catalogs (ZWNJ in Persian, ZWSP in Thai) is no longer
  flagged.

### Other

- Org/user/search scans print one progress line per repository to stderr.
  `buffer_unordered` means one slow repository no longer stalls the rest.
- Clone errors are one line.

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
- **GitHub Actions workflow checks** (new). Nine checks: template injection, pwn-request
  checkouts, unpinned and previously compromised actions, token permissions,
  publicly-triggerable jobs with secrets, self-hosted runners, `secrets: inherit`, and
  `toJSON(secrets)`.
- **Hidden Unicode checks** (new): Trojan Source bidi characters, and invisible text in
  code and AI-agent instruction files.
- **Malicious packages**: OpenSSF `MAL-` advisories are reported as critical.
- **osv-scanner integration hardening.**
  - Passes `--all-vulns`.
  - Treats exit code 127 with complete JSON as a warning.
  - Accepts exit 128 (no packages).
- **SARIF.**
  - Caps output at 5,000 results, keeping the most severe and noting the rest.
  - Truncates descriptions to GitHub's 1,000-character limit.
  - Uses its own `partialFingerprints` key.
- **Secret formats.** Current GitLab token formats (routable PATs and deploy, runner and
  CI tokens) and Slack rotating, refresh and app tokens.
- **Release binaries** for Linux (x86_64, arm64), macOS (Intel, Apple silicon) and
  Windows. They ship with checksums and signed build provenance.
- **CI.** Every action is pinned to a commit SHA, and Dependabot keeps the pins
  current.

### Removed

- The SLSA/Sigstore "provenance" module and the `verify` command. crates.io does not
  publish attestations, and the module performed no cryptographic verification.
- The scan-result cache, which could return stale results.
- Unused dependencies (octocrab, git2, sigstore-verification, redb, osv, cargo-lock, ...).

## 0.1.0

Initial version.
