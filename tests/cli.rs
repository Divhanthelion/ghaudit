//! End-to-end tests: run the real `ghaudit` binary against small projects.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Credentials are assembled at runtime so this file contains none.
fn stripe_key() -> String {
    ["sk_live_", "4eC39HqLyjWDarjtT1zdp7dcXyZ"].concat()
}

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

/// A project with one issue of each kind, plus decoys that must be ignored.
fn project() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "app/db.py",
        "def find(cur, name):\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
    );
    write(
        root,
        "web/view.js",
        "function show(el, c) {\n  el.innerHTML = c.body;\n}\n",
    );
    write(root, ".env", &format!("STRIPE_KEY={}\n", stripe_key()));
    // Third-party and ignored code must not be scanned.
    write(root, "node_modules/lib/index.js", "eval(input);\n");
    write(root, "generated/out.py", "eval(user_input)\n");
    write(root, ".gitignore", "generated/\n");
    // Suppressed on purpose.
    write(
        root,
        "app/tool.py",
        "import os\nos.system(cmd)  # ghaudit:ignore[python/os-command]\n",
    );
    dir
}

fn ghaudit() -> Command {
    let mut cmd = Command::cargo_bin("ghaudit").unwrap();
    cmd.env_remove("GITHUB_TOKEN").env("NO_COLOR", "1");
    cmd
}

fn json_report(args: &[&str]) -> (Value, i32) {
    let out = ghaudit().args(args).output().unwrap();
    let report = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}):\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    (report, out.status.code().unwrap())
}

fn rule_ids(report: &Value) -> Vec<String> {
    let mut ids: Vec<String> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

#[test]
fn json_report_finds_issues_and_skips_ignored_paths() {
    let dir = project();
    let (report, code) = json_report(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--no-sca",
        "-f",
        "json",
    ]);
    assert_eq!(
        rule_ids(&report),
        vec![
            "js/html-injection",
            "python/sql-injection",
            "secret/stripe-key"
        ],
        "node_modules, gitignored files and suppressed lines must not appear"
    );
    assert_eq!(
        code, 1,
        "a critical finding fails the default --fail-on high"
    );
    assert_eq!(report["stats"]["by_category"]["secret"], 1);
    let analyzers: Vec<(&str, &str)> = report["analyzers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["analyzer"].as_str().unwrap(),
                a["state"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        analyzers,
        vec![
            ("sast", "completed"),
            ("secrets", "completed"),
            ("sca", "skipped"),
            ("ai", "skipped")
        ]
    );
}

#[test]
fn secrets_never_appear_in_any_output_format() {
    let dir = project();
    for format in ["text", "json", "sarif"] {
        ghaudit()
            .args([
                "scan",
                dir.path().to_str().unwrap(),
                "--no-sca",
                "-f",
                format,
            ])
            .assert()
            .stdout(predicate::str::contains(stripe_key()).not())
            .stdout(predicate::str::contains("sk_l********"));
    }
}

#[test]
fn thresholds_control_exit_code_and_contents() {
    let dir = project();
    let path = dir.path().to_str().unwrap();
    ghaudit()
        .args(["scan", path, "--no-sca", "--fail-on", "never"])
        .assert()
        .code(0);
    ghaudit()
        .args([
            "scan",
            path,
            "--no-sca",
            "--no-secrets",
            "--fail-on",
            "critical",
        ])
        .assert()
        .code(0);
    let (report, _) = json_report(&[
        "scan",
        path,
        "--no-sca",
        "-f",
        "json",
        "--min-severity",
        "critical",
    ]);
    assert_eq!(rule_ids(&report), vec!["secret/stripe-key"]);
}

#[test]
fn analyzers_can_be_turned_off() {
    let dir = project();
    let (report, code) = json_report(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--no-sca",
        "--no-secrets",
        "--languages",
        "javascript",
        "-f",
        "json",
    ]);
    assert_eq!(rule_ids(&report), vec!["js/html-injection"]);
    assert_eq!(code, 0, "a medium finding is below the default threshold");
}

#[test]
fn logs_go_to_stderr_and_stdout_stays_parseable() {
    let dir = project();
    let out = ghaudit()
        .args([
            "-vv",
            "scan",
            dir.path().to_str().unwrap(),
            "--no-sca",
            "-f",
            "json",
        ])
        .output()
        .unwrap();
    serde_json::from_slice::<Value>(&out.stdout).expect("stdout is pure JSON even with -vv");
    assert!(!out.stderr.is_empty(), "verbose logs are written to stderr");
}

#[test]
fn sarif_is_github_compatible_and_stable() {
    let dir = project();
    let run = || {
        let out = ghaudit()
            .args([
                "scan",
                dir.path().to_str().unwrap(),
                "--no-sca",
                "-f",
                "sarif",
            ])
            .output()
            .unwrap();
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    let (a, b) = (run(), run());
    assert_eq!(a["version"], "2.1.0");
    let results = a["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    for r in results {
        let loc = &r["locations"][0]["physicalLocation"];
        assert!(loc["region"]["startLine"].as_u64().unwrap() >= 1);
        assert!(
            !loc["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .contains('\\')
        );
    }
    let fingerprints = |v: &Value| -> Vec<Value> {
        v["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["fingerprints"].clone())
            .collect()
    };
    assert_eq!(
        fingerprints(&a),
        fingerprints(&b),
        "fingerprints must not change between runs"
    );
}

#[test]
fn output_file_is_written_and_bad_paths_fail_fast() {
    let dir = project();
    let out_dir = tempfile::tempdir().unwrap();
    let report = out_dir.path().join("report.json");
    ghaudit()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-sca",
            "-f",
            "json",
            "-o",
            report.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
    let parsed: Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 3);
    assert_eq!(
        fs::read_dir(out_dir.path()).unwrap().count(),
        1,
        "no temporary files left behind"
    );

    let missing = out_dir.path().join("no/such/dir/r.json");
    ghaudit()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "-o",
            missing.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot write"));
}

#[test]
fn missing_osv_scanner_makes_the_scan_incomplete_not_clean() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "requirements.txt", "django==2.0.0\n");
    let config = dir.path().join("ghaudit.toml");
    fs::write(
        &config,
        "[sca]\nosv_scanner = \"ghaudit-test-no-such-binary\"\n",
    )
    .unwrap();
    ghaudit()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "-c",
            config.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("INCOMPLETE SCAN"))
        .stdout(predicate::str::contains("osv-scanner not found"));
}

#[cfg(unix)]
#[test]
fn dependency_findings_from_osv_scanner() {
    use std::os::unix::fs::PermissionsExt;
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/osv-scanner");
    let project = tempfile::tempdir().unwrap();
    for f in ["Cargo.lock", "requirements.txt", "svc/go.mod"] {
        write(
            project.path(),
            f,
            &fs::read_to_string(fixtures.join(f)).unwrap(),
        );
    }
    // Stand-in for osv-scanner that prints recorded real output for this project.
    let root = project.path().canonicalize().unwrap();
    let output = fs::read_to_string(fixtures.join("multi-ecosystem.json"))
        .unwrap()
        .replace("__ROOT__", root.to_str().unwrap());
    let tools = tempfile::tempdir().unwrap();
    fs::write(tools.path().join("out.json"), output).unwrap();
    let fake = tools.path().join("osv-scanner");
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\ncat '{}'\nexit 1\n",
            tools.path().join("out.json").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let config = tools.path().join("ghaudit.toml");
    fs::write(
        &config,
        format!("[sca]\nosv_scanner = \"{}\"\n", fake.display()),
    )
    .unwrap();

    let (report, code) = json_report(&[
        "scan",
        root.to_str().unwrap(),
        "-c",
        config.to_str().unwrap(),
        "-f",
        "json",
    ]);
    assert_eq!(code, 1);
    assert_eq!(report["stats"]["dependencies_scanned"], 6);
    let deps: Vec<&Value> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["category"] == "dependency")
        .collect();
    assert_eq!(deps.len(), 15);
    let smallvec = deps
        .iter()
        .find(|f| f["dependency"]["advisory"] == "RUSTSEC-2019-0009")
        .unwrap();
    assert_eq!(smallvec["severity"], "critical");
    assert_eq!(smallvec["location"]["path"], "Cargo.lock");
    assert_eq!(smallvec["dependency"]["fixed_versions"][0], "0.6.10");
}

#[test]
fn rules_command_lists_every_rule() {
    let out = ghaudit().args(["rules", "-f", "json"]).output().unwrap();
    let rules: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert!(rules.len() >= 30);
    assert!(
        rules
            .iter()
            .all(|r| r["id"].as_str().unwrap().contains('/'))
    );
}

#[test]
fn usage_errors_exit_2() {
    ghaudit()
        .args(["scan", "definitely not a target"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid target"));
    ghaudit()
        .args(["scan", "."])
        .arg("--min-severity")
        .arg("extreme")
        .assert()
        .code(2);
    ghaudit().args(["org", "bad org name"]).assert().code(2);
    ghaudit()
        .args(["scan", ".", "--no-sast", "--no-sca", "--no-secrets"])
        .assert()
        .code(2);
}

/// Runs the real osv-scanner against the fixture lockfiles. Opt-in because it needs
/// osv-scanner on PATH and network access; CI runs it with `--include-ignored`.
/// `GHAUDIT_TEST_OSV_SCANNER` overrides the binary; `GHAUDIT_TEST_OSV_OFFLINE=1` uses
/// osv-scanner's offline databases instead of the API.
#[test]
#[ignore = "needs osv-scanner and network access"]
fn real_osv_scanner_reports_known_vulnerabilities() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/osv-scanner");
    let project = tempfile::tempdir().unwrap();
    for f in ["Cargo.lock", "requirements.txt", "svc/go.mod"] {
        write(
            project.path(),
            f,
            &fs::read_to_string(fixtures.join(f)).unwrap(),
        );
    }
    let program =
        std::env::var("GHAUDIT_TEST_OSV_SCANNER").unwrap_or_else(|_| "osv-scanner".into());
    let extra = if std::env::var("GHAUDIT_TEST_OSV_OFFLINE").is_ok() {
        r#"["--offline-vulnerabilities", "--download-offline-databases"]"#
    } else {
        "[]"
    };
    let config = project.path().join("ghaudit.toml");
    fs::write(
        &config,
        format!("[sca]\nosv_scanner = {program:?}\nextra_args = {extra}\n"),
    )
    .unwrap();

    let (report, code) = json_report(&[
        "scan",
        project.path().to_str().unwrap(),
        "-c",
        config.to_str().unwrap(),
        "--no-sast",
        "--no-secrets",
        "-f",
        "json",
    ]);
    assert_eq!(
        report["analyzers"][2]["state"], "completed",
        "{:#}",
        report["analyzers"]
    );
    assert_eq!(code, 1);
    let advisories: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["dependency"]["advisory"].as_str())
        .collect();
    // smallvec 0.6.9: double free, CVSS 9.8. Stable, old advisory.
    let smallvec = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["dependency"]["package"] == "smallvec" && f["severity"] == "critical");
    assert!(
        smallvec.is_some(),
        "expected a critical smallvec advisory, got {advisories:?}"
    );
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["dependency"]["package"] == "django")
    );
}
