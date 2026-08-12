# ghaudit

Rust security analysis engine for GitHub repositories (crate name `sec_auditor`). Scans a repo or local path for SAST findings, SCA/OSV dependencies, secrets, and optional SLSA provenance. Writes text, JSON, or SARIF.

## Requirements

- [Rust](https://rustup.rs/)
- A GitHub token in `GITHUB_TOKEN` for remote scans

## Build

```bash
git clone https://github.com/Divhanthelion/ghaudit.git
cd ghaudit
cargo build --release
```

## Usage

```bash
export GITHUB_TOKEN=ghp_...
cargo run --release -- scan Divhanthelion/ghaudit
cargo run --release -- scan ./path/to/checkout -f sarif -o report.sarif
```

Binary name after install: `sec_auditor`.

## License

MIT
