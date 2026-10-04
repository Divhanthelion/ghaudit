# Contributing

## Setup

You need:

- Rust 1.88 or newer (1.90 for the desktop app)
- `git`
- optionally, [osv-scanner](https://google.github.io/osv-scanner/installation/) for
  dependency scanning
- for the desktop app on Linux, Tauri's
  [system libraries](https://v2.tauri.app/start/prerequisites/#linux)

Then:

```bash
cargo build
cargo test                                   # unit + end-to-end tests
cargo test --test cli -- --include-ignored   # also the live osv-scanner test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

These work on the `ghaudit` package, the workspace's default member. For the desktop app:

```bash
cargo run -p ghaudit-desktop
cargo test -p ghaudit-desktop
cargo clippy -p ghaudit-desktop --all-targets -- -D warnings
```

CI runs all of the above on Linux, macOS and Windows,
checks the minimum Rust version, and validates ghaudit's SARIF output against the
official schema.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains how the pieces fit together.

## Adding a code rule

Rules live in `src/analyzer/rules/<language>.rs`.

1. Write the code you want to catch, and see its syntax tree:

   ```bash
   echo 'yaml.load(data)' | cargo run --example syntax_tree -- python
   ```

2. Write a tree-sitter query that matches it. Capture the node to report as
   `@finding`. Narrow the match with predicates (`#eq?`, `#match?`, `#not-match?`), and
   use `requires` for file-level conditions such as an import. To follow a value
   through a variable, give the rule a `bindings` query that captures the assigned
   variable as `@var`, and require `(#bound? @arg)` in the main query (see the SQL
   rules).

3. Fill in the `Rule`:
   - `id`: `<language>/<kebab-name>`;
   - `severity` and `confidence`;
   - at least one CWE;
   - a `message` that says what is wrong and why it matters;
   - a concrete `remediation`.

4. Add `examples` the rule must flag and `counter_examples` it must not: the safe form
   of the same code, the same function name on an unrelated object, and so on. Run
   `cargo test every_rule`.

The bar for a new rule: on ordinary, well-written code it should almost never fire. If
a pattern only becomes a vulnerability when untrusted input reaches it, require a
non-constant argument (see the `python/eval` rule for the idiom).

## Adding a secret pattern

Add a `provider(...)` entry in `src/analyzer/secrets.rs` and a test. Keep test tokens
out of the source: assemble them at runtime with `tok(&["prefix_", "rest"])`, as the
existing tests do, so ghaudit's own scans stay clean.

Avoid counting runs (`12345`, `abcdef`) in test tokens: the detector treats them as
placeholders.

## Adding a settings check

Add a `SettingsRule` to `RULES` in `src/analyzer/settings.rs`, then the check itself in
the helper for its area (`branch_checks`, `actions_checks`, ...). Every check must end
in `pass`, `fail` or `na` (not assessable): read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#settings-analyzersettingsrs)
for when a 404 or 403 may count as "off". Check field names against GitHub's
[OpenAPI description](https://github.com/github/rest-api-description), and test the
pass, fail and not-assessable cases with canned responses.

## Adding an agent-config check

Agent and editor configs are handled in `src/analyzer/agents.rs`: map the file in
`kind()`, read it in the tool's method, and report through `push` (or `command` for
anything that runs a command, so the download-and-execute check applies). Cite the
tool's documentation for the setting in the test.

## Working on the desktop app

The UI in `ui/` is plain HTML, CSS and JavaScript modules with no build step: edit and
restart the app. Two rules keep it safe to show reports of repositories you don't trust:

- Never turn a string into HTML. Build elements with `h()` from `ui/js/dom.js`, which
  inserts text as text nodes. `app/tests/security.rs` fails on `innerHTML` and the like.
- The page gets no Tauri permissions beyond the app's own commands. To add a command,
  write it in `app/src/lib.rs`, list it in `app/build.rs` and grant `allow-<name>` in
  `app/capabilities/default.json`. File access, dialogs and links stay in Rust.

Plain-language wording for severities, kinds of findings and checks lives in
`ui/js/explain.js`.

## Commit style

Small, focused commits with an imperative subject line ("Add go/weak-random rule").
