# Contributing

## Setup

You need:

- Rust 1.88 or newer
- `git`
- optionally, [osv-scanner](https://google.github.io/osv-scanner/installation/) for
  dependency scanning

Then:

```bash
cargo build
cargo test                                   # unit + end-to-end tests
cargo test --test cli -- --include-ignored   # also the live osv-scanner test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

CI runs all of the above on Linux, macOS and Windows, checks the minimum Rust version,
and validates ghaudit's SARIF output against the official schema.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains how the pieces fit together.

## Adding a code rule

Rules live in `src/analyzer/rules/<language>.rs`.

1. Write the code you want to catch, and see its syntax tree:

   ```bash
   echo 'yaml.load(data)' | cargo run --example syntax_tree -- python
   ```

2. Write a tree-sitter query that matches it. Capture the node to report as
   `@finding`. Narrow the match with predicates (`#eq?`, `#match?`, `#not-match?`), and
   use `requires` for file-level conditions such as an import.

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

## Commit style

Small, focused commits with an imperative subject line ("Add go/weak-random rule").
