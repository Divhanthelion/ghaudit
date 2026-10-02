//! Security settings of repositories and organizations, read from the GitHub API.
//!
//! Many compromises go through settings rather than code: a default branch anyone with
//! write access can force-push, a `GITHUB_TOKEN` with write access by default, a
//! webhook that skips TLS verification, a deploy key with write access nobody remembers.
//!
//! Every check reports pass, fail or not assessable. Most settings are visible only to
//! admins, so a token without admin access gets "not assessable", never a pass. A 404 is
//! read as "disabled" only when the token is known to have admin access, because GitHub
//! also answers 404 to tokens that may not look.

use crate::error::{Error, Result};
use crate::github::{GitHub, Probe};
use crate::model::{Category, CheckStatus, Confidence, Finding, Location, SettingsCheck, Severity};
use serde_json::Value;

/// Metadata for `ghaudit rules` and the docs.
pub struct SettingsRule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
}

const fn rule(id: &'static str, name: &'static str, severity: Severity) -> SettingsRule {
    SettingsRule { id, name, severity }
}

pub static RULES: &[SettingsRule] = &[
    rule(
        "settings/default-branch-unprotected",
        "Default branch has no protection",
        Severity::High,
    ),
    rule(
        "settings/direct-push-allowed",
        "Default branch accepts direct pushes",
        Severity::Medium,
    ),
    rule(
        "settings/no-required-review",
        "Pull requests need no approving review",
        Severity::Low,
    ),
    rule(
        "settings/force-push-allowed",
        "Force pushes allowed on the default branch",
        Severity::Medium,
    ),
    rule(
        "settings/branch-deletion-allowed",
        "Default branch can be deleted",
        Severity::Low,
    ),
    rule(
        "settings/admins-bypass-protection",
        "Branch protection does not apply to admins",
        Severity::Low,
    ),
    rule(
        "settings/secret-scanning-disabled",
        "Secret scanning disabled",
        Severity::Medium,
    ),
    rule(
        "settings/push-protection-disabled",
        "Secret push protection disabled",
        Severity::Medium,
    ),
    rule(
        "settings/dependabot-alerts-disabled",
        "Dependabot alerts disabled",
        Severity::Medium,
    ),
    rule(
        "settings/dependabot-updates-disabled",
        "Dependabot security updates disabled",
        Severity::Low,
    ),
    rule(
        "settings/private-vulnerability-reporting-disabled",
        "Private vulnerability reporting disabled",
        Severity::Low,
    ),
    rule(
        "settings/actions-default-token-write",
        "GITHUB_TOKEN has write access by default",
        Severity::Medium,
    ),
    rule(
        "settings/actions-can-approve-prs",
        "Workflows can approve pull requests",
        Severity::Medium,
    ),
    rule(
        "settings/actions-sha-pinning-not-required",
        "Actions need not be pinned to a SHA",
        Severity::Low,
    ),
    rule(
        "settings/actions-all-allowed",
        "Any action from anyone may run",
        Severity::Low,
    ),
    rule(
        "settings/fork-pr-approval-weak",
        "Fork pull request workflows run with little approval",
        Severity::Low,
    ),
    rule(
        "settings/fork-pr-secrets",
        "Fork pull request workflows get secrets or a write token",
        Severity::High,
    ),
    rule(
        "settings/self-hosted-runner-public",
        "Self-hosted runner on a public repository",
        Severity::High,
    ),
    rule(
        "settings/deploy-key-write",
        "Deploy key with write access",
        Severity::Medium,
    ),
    rule(
        "settings/deploy-key-stale",
        "Deploy key unused for a year",
        Severity::Low,
    ),
    rule(
        "settings/webhook-insecure-ssl",
        "Webhook skips TLS verification",
        Severity::High,
    ),
    rule(
        "settings/webhook-plain-http",
        "Webhook delivers over plain HTTP",
        Severity::Medium,
    ),
    rule(
        "settings/webhook-no-secret",
        "Webhook without a secret",
        Severity::Medium,
    ),
    rule(
        "settings/outside-collaborator-admin",
        "Outside collaborator with admin access",
        Severity::Medium,
    ),
    rule(
        "settings/environment-unprotected",
        "Deployment environment without protection",
        Severity::Medium,
    ),
    rule(
        "settings/org-2fa-not-required",
        "Organization does not require 2FA",
        Severity::High,
    ),
    rule(
        "settings/org-members-without-2fa",
        "Organization members without 2FA",
        Severity::High,
    ),
    rule(
        "settings/org-members-insecure-2fa",
        "Organization members using SMS 2FA",
        Severity::Low,
    ),
    rule(
        "settings/org-default-permission",
        "Members get write or admin on every repository",
        Severity::High,
    ),
    rule(
        "settings/org-actions-default-token-write",
        "Org default GITHUB_TOKEN has write access",
        Severity::Medium,
    ),
    rule(
        "settings/org-actions-can-approve-prs",
        "Org workflows can approve pull requests",
        Severity::Medium,
    ),
    rule(
        "settings/org-actions-sha-pinning-not-required",
        "Org does not require SHA-pinned actions",
        Severity::Low,
    ),
    rule(
        "settings/org-actions-all-allowed",
        "Org allows any action from anyone",
        Severity::Low,
    ),
    rule(
        "settings/org-fork-pr-approval-weak",
        "Org fork pull request workflows run with little approval",
        Severity::Low,
    ),
    rule(
        "settings/org-fork-pr-secrets",
        "Org fork pull request workflows get secrets or a write token",
        Severity::High,
    ),
    rule(
        "settings/org-webhook-insecure-ssl",
        "Org webhook skips TLS verification",
        Severity::High,
    ),
    rule(
        "settings/org-webhook-plain-http",
        "Org webhook delivers over plain HTTP",
        Severity::Medium,
    ),
    rule(
        "settings/org-webhook-no-secret",
        "Org webhook without a secret",
        Severity::Medium,
    ),
];

/// Outcome of auditing one repository or organization.
#[derive(Debug, Default)]
pub struct Audit {
    pub checks: Vec<SettingsCheck>,
    pub findings: Vec<Finding>,
}

impl Audit {
    /// (passed, failed, not assessable)
    pub fn counts(&self) -> (usize, usize, usize) {
        let n = |s| self.checks.iter().filter(|c| c.status == s).count();
        (
            n(CheckStatus::Pass),
            n(CheckStatus::Fail),
            n(CheckStatus::NotAssessable),
        )
    }
}

const NEED_ADMIN: &str = "needs a token with admin access to the repository";
const NEED_OWNER: &str = "needs an organization owner's token";

/// Records results for one target.
struct Ctx {
    target: String,
    /// Web URL of the repository or organization, for links to settings pages.
    web: String,
    audit: Audit,
}

/// A failed check, as a finding.
struct Fail<'a> {
    check: String,
    severity: Severity,
    title: &'a str,
    message: String,
    fix: &'a str,
    /// Settings page relative to `Ctx::web`, e.g. `settings/branches`.
    page: &'a str,
    /// Identifies this instance (a webhook's ID, a key's ID) for the fingerprint.
    basis: String,
}

impl Ctx {
    fn new(target: String, web: String) -> Self {
        Self {
            target,
            web,
            audit: Audit::default(),
        }
    }

    fn record(&mut self, check: &str, status: CheckStatus, detail: Option<String>) {
        // A check that already failed (e.g. for another webhook) stays failed.
        if let Some(existing) = self.audit.checks.iter_mut().find(|c| c.check == check) {
            if status == CheckStatus::Fail {
                existing.status = CheckStatus::Fail;
                existing.detail = detail;
            }
            return;
        }
        self.audit.checks.push(SettingsCheck {
            target: self.target.clone(),
            check: check.to_string(),
            status,
            detail,
        });
    }

    fn pass(&mut self, check: &str) {
        self.record(check, CheckStatus::Pass, None);
    }

    fn na(&mut self, check: &str, why: impl Into<String>) {
        self.record(check, CheckStatus::NotAssessable, Some(why.into()));
    }

    fn fail(&mut self, f: Fail) {
        self.record(&f.check, CheckStatus::Fail, Some(f.message.clone()));
        let url = format!("{}/{}", self.web, f.page);
        let mut finding = Finding::new(
            f.check.clone(),
            Category::Settings,
            f.severity,
            Confidence::High,
            f.title,
            f.message,
            Location::new(f.page, 1, 1),
            &format!("{}|{}", self.target, f.basis),
        )
        .with_cwe([cwe(&f.check)])
        .with_remediation(f.fix);
        finding.help_url = Some(url);
        self.audit.findings.push(finding);
    }
}

fn cwe(check: &str) -> &'static str {
    let c = check
        .trim_start_matches("settings/")
        .trim_start_matches("org-");
    match c {
        "secret-scanning-disabled" | "push-protection-disabled" => "CWE-798",
        "dependabot-alerts-disabled" | "dependabot-updates-disabled" => "CWE-1395",
        "actions-default-token-write" | "actions-can-approve-prs" => "CWE-250",
        "webhook-insecure-ssl" => "CWE-295",
        "webhook-plain-http" => "CWE-319",
        "webhook-no-secret" => "CWE-345",
        "2fa-not-required" | "members-without-2fa" | "members-insecure-2fa" => "CWE-308",
        "default-permission" => "CWE-276",
        "fork-pr-secrets" | "private-vulnerability-reporting-disabled" => "CWE-200",
        _ => "CWE-284",
    }
}

/// Why a probe that did not answer cannot be read as a setting.
fn why_not(p: &Probe, need: &str) -> String {
    match (p.status, p.message()) {
        (403 | 404, "") => need.to_string(),
        (403 | 404, msg) => format!("{need} (GitHub: {msg})"),
        (status, msg) => format!("unexpected answer {status} {msg}")
            .trim()
            .to_string(),
    }
}

fn bool_at(v: &Value, path: &[&str]) -> Option<bool> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_bool()
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

/// Escape characters a branch name may contain that are special in a URL path.
fn path_segment(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '%' => "%25".into(),
            '#' => "%23".into(),
            '?' => "%3F".into(),
            ' ' => "%20".into(),
            c => c.to_string(),
        })
        .collect()
}

/// Audit one repository's settings.
pub async fn audit_repo(gh: &GitHub, owner: &str, name: &str) -> Result<Audit> {
    let base = format!("/repos/{owner}/{name}");
    let mut ctx = Ctx::new(
        format!("{owner}/{name}"),
        format!("{}/{owner}/{name}", gh.web_url()),
    );
    let repo = gh.probe(base.as_str(), &[]).await?;
    if !repo.ok() {
        return Err(Error::GitHub(format!(
            "cannot read the settings of {owner}/{name}: {} {}",
            repo.status,
            repo.message()
        )));
    }
    let facts = &repo.body;
    let admin = bool_at(facts, &["permissions", "admin"]).unwrap_or(false);
    let private = bool_at(facts, &["private"]).unwrap_or(false);
    let archived = bool_at(facts, &["archived"]).unwrap_or(false);
    let branch = str_at(facts, &["default_branch"])
        .unwrap_or("main")
        .to_string();
    let b = path_segment(&branch);
    let page = [("per_page", "100")];

    let (
        branch_info,
        rules,
        alerts,
        fixes,
        pvr,
        actions,
        workflow,
        fork_public,
        fork_private,
        runners,
        keys,
        hooks,
        outside,
        envs,
    ) = tokio::join!(
        gh.probe(format!("{base}/branches/{b}"), &[]),
        gh.probe(format!("{base}/rules/branches/{b}"), &page),
        gh.probe(format!("{base}/vulnerability-alerts"), &[]),
        gh.probe(format!("{base}/automated-security-fixes"), &[]),
        gh.probe(format!("{base}/private-vulnerability-reporting"), &[]),
        gh.probe(format!("{base}/actions/permissions"), &[]),
        gh.probe(format!("{base}/actions/permissions/workflow"), &[]),
        gh.probe(
            format!("{base}/actions/permissions/fork-pr-contributor-approval"),
            &[]
        ),
        gh.probe(
            format!("{base}/actions/permissions/fork-pr-workflows-private-repos"),
            &[]
        ),
        gh.probe(format!("{base}/actions/runners"), &page),
        gh.probe(format!("{base}/keys"), &page),
        gh.probe(format!("{base}/hooks"), &page),
        gh.probe(
            format!("{base}/collaborators"),
            &[("affiliation", "outside"), ("per_page", "100")]
        ),
        gh.probe(format!("{base}/environments"), &page),
    );
    let branch_info = branch_info?;

    if !archived {
        let protected =
            branch_info.ok() && bool_at(&branch_info.body, &["protected"]) == Some(true);
        let classic = if protected {
            Some(
                gh.probe(format!("{base}/branches/{b}/protection"), &[])
                    .await?,
            )
        } else {
            None
        };
        branch_checks(
            &mut ctx,
            &branch,
            &branch_info,
            &rules?,
            classic.as_ref(),
            admin,
        );
        actions_checks(
            &mut ctx,
            "",
            private,
            &actions?,
            &workflow?,
            &fork_public?,
            &fork_private?,
            NEED_ADMIN,
        );
        runner_check(&mut ctx, private, &runners?);
    }
    security_checks(&mut ctx, facts, private, admin, &alerts?, &fixes?, &pvr?);
    key_checks(&mut ctx, &keys?);
    webhook_checks(&mut ctx, "", &hooks?, NEED_ADMIN);
    collaborator_check(&mut ctx, &outside?);
    environment_check(&mut ctx, &envs?);
    Ok(ctx.audit)
}

/// Audit an organization's own settings (not its repositories').
pub async fn audit_org(gh: &GitHub, org: &str) -> Result<Audit> {
    let base = format!("/orgs/{org}");
    let mut ctx = Ctx::new(
        format!("org:{org}"),
        format!("{}/organizations/{org}", gh.web_url()),
    );
    let (info, no_2fa, sms_2fa, actions, workflow, fork_public, fork_private, hooks) = tokio::join!(
        gh.probe(base.as_str(), &[]),
        gh.probe(
            format!("{base}/members"),
            &[("filter", "2fa_disabled"), ("per_page", "100")]
        ),
        gh.probe(
            format!("{base}/members"),
            &[("filter", "2fa_insecure"), ("per_page", "100")]
        ),
        gh.probe(format!("{base}/actions/permissions"), &[]),
        gh.probe(format!("{base}/actions/permissions/workflow"), &[]),
        gh.probe(
            format!("{base}/actions/permissions/fork-pr-contributor-approval"),
            &[]
        ),
        gh.probe(
            format!("{base}/actions/permissions/fork-pr-workflows-private-repos"),
            &[]
        ),
        gh.probe(format!("{base}/hooks"), &[("per_page", "100")]),
    );
    let info = info?;
    if !info.ok() {
        return Err(Error::GitHub(format!(
            "cannot read the settings of organization {org}: {} {}",
            info.status,
            info.message()
        )));
    }
    org_checks(&mut ctx, &info.body, &no_2fa?, &sms_2fa?);
    actions_checks(
        &mut ctx,
        "org-",
        false,
        &actions?,
        &workflow?,
        &fork_public?,
        &fork_private?,
        NEED_OWNER,
    );
    webhook_checks(&mut ctx, "org-", &hooks?, NEED_OWNER);
    Ok(ctx.audit)
}

/// Rules from active rulesets that apply to the branch.
fn active_rules(rules: &Probe) -> Vec<&Value> {
    if !rules.ok() {
        return Vec::new();
    }
    rules
        .body
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn has_rule(rules: &[&Value], kind: &str) -> bool {
    rules
        .iter()
        .any(|r| r.get("type").and_then(Value::as_str) == Some(kind))
}

fn branch_checks(
    ctx: &mut Ctx,
    branch: &str,
    info: &Probe,
    rules: &Probe,
    classic: Option<&Probe>,
    admin: bool,
) {
    const PROTECTIVE: &[&str] = &[
        "pull_request",
        "non_fast_forward",
        "deletion",
        "update",
        "required_status_checks",
        "required_signatures",
        "required_linear_history",
        "merge_queue",
    ];
    let checks = [
        "settings/default-branch-unprotected",
        "settings/direct-push-allowed",
        "settings/no-required-review",
        "settings/force-push-allowed",
        "settings/branch-deletion-allowed",
        "settings/admins-bypass-protection",
    ];
    if !info.ok() {
        let why = if info.status == 404 {
            format!("branch {branch} not found (empty repository?)")
        } else {
            why_not(info, NEED_ADMIN)
        };
        for c in checks {
            ctx.na(c, why.clone());
        }
        return;
    }
    let rules_list = active_rules(rules);
    let protected_classic = bool_at(&info.body, &["protected"]) == Some(true);
    let ruleset = PROTECTIVE.iter().any(|k| has_rule(&rules_list, k));
    if !(protected_classic || ruleset) {
        ctx.fail(Fail {
            check: checks[0].into(),
            severity: Severity::High,
            title: "Default branch has no protection",
            message: format!(
                "No branch protection rule or ruleset applies to `{branch}`. Anyone with write access (or a leaked token, or a compromised workflow with a write token) can push, force-push or delete it, and code reaches it without review."
            ),
            fix: "Add a ruleset for the default branch that requires pull requests and blocks force pushes and deletion (Settings → Rules → Rulesets).",
            page: "settings/rules",
            basis: branch.to_string(),
        });
        // The finer checks would all fail for the same reason.
        return;
    }
    ctx.pass(checks[0]);

    // Classic protection, when present, is readable only with admin access.
    let classic_body = classic.filter(|p| p.ok()).map(|p| &p.body);
    let classic_known = !protected_classic || classic_body.is_some();
    let classic_why = classic.map(|p| why_not(p, NEED_ADMIN)).unwrap_or_default();
    let classic_flag = |path: &[&str]| classic_body.and_then(|b| bool_at(b, path));

    // Direct pushes and reviews.
    let pr_rule = rules_list
        .iter()
        .find(|r| r.get("type").and_then(Value::as_str) == Some("pull_request"));
    let classic_reviews = classic_body.and_then(|b| b.get("required_pull_request_reviews"));
    if pr_rule.is_some() || classic_reviews.is_some() {
        ctx.pass(checks[1]);
        let approvals = pr_rule
            .and_then(|r| r.pointer("/parameters/required_approving_review_count"))
            .and_then(Value::as_u64)
            .into_iter()
            .chain(
                classic_reviews
                    .and_then(|c| c.get("required_approving_review_count"))
                    .and_then(Value::as_u64),
            )
            .max()
            .unwrap_or(0);
        if approvals >= 1 {
            ctx.pass(checks[2]);
        } else {
            ctx.fail(Fail {
                check: checks[2].into(),
                severity: Severity::Low,
                title: "Pull requests need no approving review",
                message: format!(
                    "Changes to `{branch}` go through pull requests, but nobody has to approve them, so one compromised account can merge anything."
                ),
                fix: "Require at least one approving review (and, ideally, approval of the most recent push). On a one-person project this may not be practical.",
                page: "settings/rules",
                basis: branch.to_string(),
            });
        }
    } else if classic_known {
        ctx.fail(Fail {
            check: checks[1].into(),
            severity: Severity::Medium,
            title: "Default branch accepts direct pushes",
            message: format!(
                "`{branch}` is protected, but changes do not have to go through a pull request, so they skip review and pull-request checks."
            ),
            fix: "Require a pull request before merging in the branch's ruleset or protection rule.",
            page: "settings/rules",
            basis: branch.to_string(),
        });
        ctx.na(checks[2], "pull requests are not required");
    } else {
        ctx.na(checks[1], classic_why.clone());
        ctx.na(checks[2], classic_why.clone());
    }

    for (check, rule_kind, field, severity, title, what) in [
        (
            checks[3],
            "non_fast_forward",
            "allow_force_pushes",
            Severity::Medium,
            "Force pushes allowed on the default branch",
            "rewrite its history, which can remove reviewed commits or slip in unreviewed ones",
        ),
        (
            checks[4],
            "deletion",
            "allow_deletions",
            Severity::Low,
            "Default branch can be deleted",
            "delete it",
        ),
    ] {
        if has_rule(&rules_list, rule_kind) {
            ctx.pass(check);
            continue;
        }
        match classic_flag(&[field, "enabled"]) {
            Some(false) => ctx.pass(check),
            Some(true) => ctx.fail(Fail {
                check: check.into(),
                severity,
                title,
                message: format!("People with push access to `{branch}` can {what}."),
                fix: "Block force pushes and deletion of the default branch in its ruleset or protection rule.",
                page: "settings/rules",
                basis: branch.to_string(),
            }),
            // Rulesets only, without this rule; classic protection absent.
            None if !protected_classic => ctx.fail(Fail {
                check: check.into(),
                severity,
                title,
                message: format!("People with push access to `{branch}` can {what}."),
                fix: "Block force pushes and deletion of the default branch in its ruleset.",
                page: "settings/rules",
                basis: branch.to_string(),
            }),
            None => ctx.na(check, classic_why.clone()),
        }
    }

    // Admin bypass is visible for classic protection only.
    match classic_flag(&["enforce_admins", "enabled"]) {
        Some(true) => ctx.pass(checks[5]),
        Some(false) => ctx.fail(Fail {
            check: checks[5].into(),
            severity: Severity::Low,
            title: "Branch protection does not apply to admins",
            message: format!(
                "Repository admins can push to `{branch}` without the protection rule's checks."
            ),
            fix: "Enable \"Do not allow bypassing the above settings\" (enforce for administrators).",
            page: "settings/branches",
            basis: branch.to_string(),
        }),
        None if protected_classic && !admin => ctx.na(checks[5], classic_why),
        None => {} // rulesets only: bypass lists need separate permissions; not judged
    }
}

#[allow(clippy::too_many_arguments)]
fn security_checks(
    ctx: &mut Ctx,
    repo: &Value,
    private: bool,
    admin: bool,
    alerts: &Probe,
    fixes: &Probe,
    pvr: &Probe,
) {
    // Secret scanning on private repositories needs a paid plan, so it weighs less.
    let weight = if private {
        Severity::Low
    } else {
        Severity::Medium
    };
    let analysis = repo.get("security_and_analysis").filter(|v| !v.is_null());
    for (check, key, title, what, fix) in [
        (
            "settings/secret-scanning-disabled",
            "secret_scanning",
            "Secret scanning disabled",
            "GitHub does not alert on credentials committed to this repository.",
            "Enable secret scanning (Settings → Advanced Security).",
        ),
        (
            "settings/push-protection-disabled",
            "secret_scanning_push_protection",
            "Secret push protection disabled",
            "Pushes containing recognizable credentials are not blocked, so a leaked token reaches the history before anyone is alerted.",
            "Enable push protection for secret scanning (Settings → Advanced Security).",
        ),
    ] {
        match analysis.and_then(|a| str_at(a, &[key, "status"])) {
            Some("enabled") => ctx.pass(check),
            Some(_) => ctx.fail(Fail {
                check: check.into(),
                severity: weight,
                title,
                message: what.into(),
                fix,
                page: "settings/security_analysis",
                basis: key.into(),
            }),
            None => ctx.na(
                check,
                "the token cannot see security_and_analysis (needs admin access, or the Administration permission for an app token)",
            ),
        }
    }

    let check = "settings/dependabot-alerts-disabled";
    match alerts.status {
        204 | 200 => ctx.pass(check),
        404 if admin => ctx.fail(Fail {
            check: check.into(),
            severity: Severity::Medium,
            title: "Dependabot alerts disabled",
            message: "GitHub does not alert on known-vulnerable dependencies in this repository."
                .into(),
            fix: "Enable Dependabot alerts (Settings → Advanced Security).",
            page: "settings/security_analysis",
            basis: "alerts".into(),
        }),
        _ => ctx.na(check, why_not(alerts, NEED_ADMIN)),
    }

    let check = "settings/dependabot-updates-disabled";
    match fixes.status {
        200 if bool_at(&fixes.body, &["enabled"]) == Some(true)
            && bool_at(&fixes.body, &["paused"]) != Some(true) =>
        {
            ctx.pass(check)
        }
        200 => ctx.fail(Fail {
            check: check.into(),
            severity: Severity::Low,
            title: "Dependabot security updates disabled",
            message: "Dependabot security updates are paused, so fixes for vulnerable dependencies are not proposed.".into(),
            fix: "Resume Dependabot security updates (Settings → Advanced Security).",
            page: "settings/security_analysis",
            basis: "updates".into(),
        }),
        404 if admin => ctx.fail(Fail {
            check: check.into(),
            severity: Severity::Low,
            title: "Dependabot security updates disabled",
            message: "Dependabot does not open pull requests that fix vulnerable dependencies.".into(),
            fix: "Enable Dependabot security updates (Settings → Advanced Security).",
            page: "settings/security_analysis",
            basis: "updates".into(),
        }),
        _ => ctx.na(check, why_not(fixes, NEED_ADMIN)),
    }

    // Applies to public repositories only.
    if !private {
        let check = "settings/private-vulnerability-reporting-disabled";
        match (pvr.ok(), bool_at(&pvr.body, &["enabled"])) {
            (true, Some(true)) => ctx.pass(check),
            (true, Some(false)) => ctx.fail(Fail {
                check: check.into(),
                severity: Severity::Low,
                title: "Private vulnerability reporting disabled",
                message: "Security researchers have no private way to report a vulnerability, so reports may arrive as public issues.".into(),
                fix: "Enable private vulnerability reporting (Settings → Advanced Security), and add a SECURITY.md.",
                page: "settings/security_analysis",
                basis: "pvr".into(),
            }),
            _ => ctx.na(check, why_not(pvr, NEED_ADMIN)),
        }
    }
}

/// Actions policy checks, shared by repositories and organizations (`prefix` "org-").
#[allow(clippy::too_many_arguments)]
fn actions_checks(
    ctx: &mut Ctx,
    prefix: &str,
    private: bool,
    actions: &Probe,
    workflow: &Probe,
    fork_public: &Probe,
    fork_private: &Probe,
    need: &str,
) {
    let id = |name: &str| format!("settings/{prefix}{name}");
    let who = if prefix.is_empty() {
        "this repository"
    } else {
        "repositories of this organization"
    };

    if actions.ok() {
        if bool_at(&actions.body, &["enabled"]) == Some(false)
            || str_at(&actions.body, &["enabled_repositories"]) == Some("none")
        {
            // Actions are off: nothing below can run.
            for name in [
                "actions-all-allowed",
                "actions-sha-pinning-not-required",
                "actions-default-token-write",
                "actions-can-approve-prs",
                "fork-pr-approval-weak",
                "fork-pr-secrets",
            ] {
                ctx.pass(&id(name));
            }
            return;
        }
        if str_at(&actions.body, &["allowed_actions"]) == Some("all") {
            ctx.fail(Fail {
                check: id("actions-all-allowed"),
                severity: Severity::Low,
                title: "Any action from anyone may run",
                message: format!("Workflows in {who} may use any action from any GitHub account, so one typo or compromised action runs with the workflow's secrets."),
                fix: "Allow only actions by GitHub, verified creators and an explicit list (Settings → Actions → General).",
                page: "settings/actions",
                basis: "allowed_actions".into(),
            });
        } else {
            ctx.pass(&id("actions-all-allowed"));
        }
        match bool_at(&actions.body, &["sha_pinning_required"]) {
            Some(true) => ctx.pass(&id("actions-sha-pinning-not-required")),
            Some(false) => ctx.fail(Fail {
                check: id("actions-sha-pinning-not-required"),
                severity: Severity::Low,
                title: "Actions need not be pinned to a SHA",
                message: format!("GitHub can refuse to run actions referenced by a mutable tag in {who}; that policy is off, so a moved tag (as in the tj-actions/changed-files compromise) changes what runs."),
                fix: "Enable \"Require actions to be pinned to a full-length commit SHA\" (Settings → Actions → General).",
                page: "settings/actions",
                basis: "sha_pinning_required".into(),
            }),
            None => ctx.na(&id("actions-sha-pinning-not-required"), "not reported by this GitHub version"),
        }
    } else {
        ctx.na(&id("actions-all-allowed"), why_not(actions, need));
        ctx.na(
            &id("actions-sha-pinning-not-required"),
            why_not(actions, need),
        );
    }

    if workflow.ok() {
        if str_at(&workflow.body, &["default_workflow_permissions"]) == Some("write") {
            ctx.fail(Fail {
                check: id("actions-default-token-write"),
                severity: Severity::Medium,
                title: "GITHUB_TOKEN has write access by default",
                message: format!("Every workflow in {who} that does not set `permissions:` gets a token that can push code, create releases and edit issues. A compromised step or action inherits it."),
                fix: "Set the default workflow permissions to read (Settings → Actions → General → Workflow permissions) and grant write per job.",
                page: "settings/actions",
                basis: "default_workflow_permissions".into(),
            });
        } else {
            ctx.pass(&id("actions-default-token-write"));
        }
        if bool_at(&workflow.body, &["can_approve_pull_request_reviews"]) == Some(true) {
            ctx.fail(Fail {
                check: id("actions-can-approve-prs"),
                severity: Severity::Medium,
                title: "Workflows can approve pull requests",
                message: format!("Workflows in {who} can create and approve pull requests, so a compromised workflow can satisfy a required review on its own."),
                fix: "Turn off \"Allow GitHub Actions to create and approve pull requests\" (Settings → Actions → General).",
                page: "settings/actions",
                basis: "can_approve_pull_request_reviews".into(),
            });
        } else {
            ctx.pass(&id("actions-can-approve-prs"));
        }
    } else {
        ctx.na(&id("actions-default-token-write"), why_not(workflow, need));
        ctx.na(&id("actions-can-approve-prs"), why_not(workflow, need));
    }

    // Public repositories: how much approval a fork's pull request needs to run workflows.
    if !private {
        match str_at(&fork_public.body, &["approval_policy"]).filter(|_| fork_public.ok()) {
            Some("first_time_contributors_new_to_github") => ctx.fail(Fail {
                check: id("fork-pr-approval-weak"),
                severity: Severity::Low,
                title: "Fork pull request workflows run with little approval",
                message: format!("Workflows on pull requests from forks in {who} run without approval unless the author's account is brand new, so any established account can run code in your CI."),
                fix: "Require approval for all external contributors (Settings → Actions → General → Approval for running fork pull request workflows).",
                page: "settings/actions",
                basis: "approval_policy".into(),
            }),
            Some(_) => ctx.pass(&id("fork-pr-approval-weak")),
            None if fork_public.status == 404 && prefix.is_empty() => {} // not a public repo setting here
            None => ctx.na(&id("fork-pr-approval-weak"), why_not(fork_public, need)),
        }
    }

    // Private repositories (and org defaults for them): what fork pull requests receive.
    if private || !prefix.is_empty() {
        let check = id("fork-pr-secrets");
        if fork_private.ok() {
            let runs = bool_at(
                &fork_private.body,
                &["run_workflows_from_fork_pull_requests"],
            ) == Some(true);
            let secrets =
                bool_at(&fork_private.body, &["send_secrets_and_variables"]) == Some(true);
            let write =
                bool_at(&fork_private.body, &["send_write_tokens_to_workflows"]) == Some(true);
            if runs && (secrets || write) {
                let what = match (secrets, write) {
                    (true, true) => "secrets and a write token",
                    (true, false) => "secrets",
                    _ => "a write token",
                };
                ctx.fail(Fail {
                    check,
                    severity: Severity::High,
                    title: "Fork pull request workflows get secrets or a write token",
                    message: format!("Workflows triggered by pull requests from forks of private repositories in {who} receive {what}. Anyone who can fork can read them by changing the workflow in their pull request."),
                    fix: "Stop sending secrets and write tokens to fork pull request workflows (Settings → Actions → General → Fork pull request workflows).",
                    page: "settings/actions",
                    basis: what.into(),
                });
            } else {
                ctx.pass(&check);
            }
        } else if !(fork_private.status == 404 && prefix.is_empty()) {
            ctx.na(&check, why_not(fork_private, need));
        }
    }
}

fn runner_check(ctx: &mut Ctx, private: bool, runners: &Probe) {
    let check = "settings/self-hosted-runner-public";
    if private {
        return;
    }
    if !runners.ok() {
        ctx.na(check, why_not(runners, NEED_ADMIN));
        return;
    }
    let list: Vec<&Value> = runners
        .body
        .get("runners")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    if list.is_empty() {
        ctx.pass(check);
        return;
    }
    let persistent = list
        .iter()
        .filter(|r| bool_at(r, &["ephemeral"]) != Some(true))
        .count();
    ctx.fail(Fail {
        check: check.into(),
        severity: if persistent > 0 {
            Severity::High
        } else {
            Severity::Medium
        },
        title: "Self-hosted runner on a public repository",
        message: format!(
            "This public repository has {} self-hosted runner(s), {persistent} of them persistent. A workflow run from a fork's pull request can execute code on them, and a persistent runner keeps whatever the attacker leaves behind.",
            list.len()
        ),
        fix: "Use GitHub-hosted runners for public repositories, or ephemeral, isolated self-hosted runners that only run approved workflows.",
        page: "settings/actions/runners",
        basis: "runners".into(),
    });
}

fn key_checks(ctx: &mut Ctx, keys: &Probe) {
    let write = "settings/deploy-key-write";
    let stale = "settings/deploy-key-stale";
    if !keys.ok() {
        ctx.na(write, why_not(keys, NEED_ADMIN));
        ctx.na(stale, why_not(keys, NEED_ADMIN));
        return;
    }
    let now = chrono::Utc::now();
    let age_days = |field: &str, key: &Value| {
        key.get(field)
            .and_then(Value::as_str)
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| (now - t.with_timezone(&chrono::Utc)).num_days())
    };
    for key in keys.body.as_array().into_iter().flatten() {
        let title = key.get("title").and_then(Value::as_str).unwrap_or("?");
        let id = key.get("id").and_then(Value::as_u64).unwrap_or_default();
        if bool_at(key, &["read_only"]) == Some(false) {
            ctx.fail(Fail {
                check: write.into(),
                severity: Severity::Medium,
                title: "Deploy key with write access",
                message: format!("Deploy key `{title}` can push to this repository, bypassing user accounts and their 2FA. Whoever holds the private key can change the code."),
                fix: "Make the key read-only unless it must push, and keep the private key in a secrets manager.",
                page: "settings/keys",
                basis: id.to_string(),
            });
        }
        let unused = match age_days("last_used", key) {
            Some(days) => days > 365,
            None => age_days("created_at", key).is_some_and(|d| d > 365),
        };
        if unused {
            ctx.fail(Fail {
                check: stale.into(),
                severity: Severity::Low,
                title: "Deploy key unused for a year",
                message: format!("Deploy key `{title}` has not been used for over a year. Unused keys are access nobody watches."),
                fix: "Delete deploy keys that are no longer used.",
                page: "settings/keys",
                basis: id.to_string(),
            });
        }
    }
    ctx.pass(write);
    ctx.pass(stale);
}

fn webhook_checks(ctx: &mut Ctx, prefix: &str, hooks: &Probe, need: &str) {
    let id = |name: &str| format!("settings/{prefix}webhook-{name}");
    let names = ["insecure-ssl", "plain-http", "no-secret"];
    if !hooks.ok() {
        for n in names {
            ctx.na(&id(n), why_not(hooks, need));
        }
        return;
    }
    for hook in hooks.body.as_array().into_iter().flatten() {
        if bool_at(hook, &["active"]) == Some(false) {
            continue;
        }
        let config = hook.get("config").unwrap_or(&Value::Null);
        let url = str_at(config, &["url"]).unwrap_or_default();
        let host = url
            .split_once("://")
            .map_or(url, |(_, r)| r)
            .split('/')
            .next()
            .unwrap_or_default();
        let hook_id = hook.get("id").and_then(Value::as_u64).unwrap_or_default();
        let insecure = match config.get("insecure_ssl") {
            Some(Value::String(s)) => s == "1",
            Some(Value::Number(n)) => n.as_u64() == Some(1),
            _ => false,
        };
        if insecure {
            ctx.fail(Fail {
                check: id("insecure-ssl"),
                severity: Severity::High,
                title: "Webhook skips TLS verification",
                message: format!("The webhook to `{host}` does not verify the server's certificate, so anyone on the network path can impersonate it and receive the event payloads."),
                fix: "Enable SSL verification on the webhook and give the receiving server a valid certificate.",
                page: "settings/hooks",
                basis: hook_id.to_string(),
            });
        }
        if url.starts_with("http://") {
            ctx.fail(Fail {
                check: id("plain-http"),
                severity: Severity::Medium,
                title: "Webhook delivers over plain HTTP",
                message: format!("Event payloads are sent to `{host}` unencrypted."),
                fix: "Use an https:// URL for the webhook.",
                page: "settings/hooks",
                basis: hook_id.to_string(),
            });
        }
        let has_secret = config
            .get("secret")
            .is_some_and(|s| s.as_str().is_some_and(|s| !s.is_empty()));
        if !has_secret {
            ctx.fail(Fail {
                check: id("no-secret"),
                severity: Severity::Medium,
                title: "Webhook without a secret",
                message: format!("The webhook to `{host}` has no secret, so its receiver cannot tell GitHub's deliveries from forged ones."),
                fix: "Set a webhook secret and verify the X-Hub-Signature-256 header in the receiver.",
                page: "settings/hooks",
                basis: hook_id.to_string(),
            });
        }
    }
    for n in names {
        ctx.pass(&id(n));
    }
}

fn collaborator_check(ctx: &mut Ctx, outside: &Probe) {
    let check = "settings/outside-collaborator-admin";
    if !outside.ok() {
        // Personal repositories have no outside collaborators: GitHub answers 422/404.
        if outside.status != 422 {
            ctx.na(check, why_not(outside, NEED_ADMIN));
        }
        return;
    }
    for user in outside.body.as_array().into_iter().flatten() {
        if bool_at(user, &["permissions", "admin"]) == Some(true) {
            let login = user.get("login").and_then(Value::as_str).unwrap_or("?");
            ctx.fail(Fail {
                check: check.into(),
                severity: Severity::Medium,
                title: "Outside collaborator with admin access",
                message: format!("`{login}` is not a member of the organization but has admin access: they can change settings, add collaborators and disable protection."),
                fix: "Give outside collaborators the least access they need (usually write or triage).",
                page: "settings/access",
                basis: login.to_string(),
            });
        }
    }
    ctx.pass(check);
}

fn environment_check(ctx: &mut Ctx, envs: &Probe) {
    let check = "settings/environment-unprotected";
    if !envs.ok() {
        ctx.na(check, why_not(envs, NEED_ADMIN));
        return;
    }
    let list = envs
        .body
        .get("environments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for env in &list {
        let name = env.get("name").and_then(Value::as_str).unwrap_or_default();
        let lower = name.to_ascii_lowercase();
        let sensitive = [
            "prod", "release", "deploy", "live", "publish", "pypi", "npm",
        ]
        .iter()
        .any(|w| lower.contains(w));
        if !sensitive {
            continue;
        }
        let reviewers = env
            .get("protection_rules")
            .and_then(Value::as_array)
            .is_some_and(|rules| {
                rules
                    .iter()
                    .any(|r| r.get("type").and_then(Value::as_str) == Some("required_reviewers"))
            });
        let branch_policy = env
            .get("deployment_branch_policy")
            .is_some_and(|p| !p.is_null());
        if !reviewers && !branch_policy {
            ctx.fail(Fail {
                check: check.into(),
                severity: Severity::Medium,
                title: "Deployment environment without protection",
                message: format!("Environment `{name}` has neither required reviewers nor a deployment branch policy, so a workflow on any branch, including one a contributor just pushed, can use its secrets."),
                fix: "Add required reviewers or restrict the environment to protected branches (Settings → Environments).",
                page: "settings/environments",
                basis: name.to_string(),
            });
        }
    }
    ctx.pass(check);
}

fn org_checks(ctx: &mut Ctx, org: &Value, no_2fa: &Probe, sms_2fa: &Probe) {
    let check = "settings/org-2fa-not-required";
    match bool_at(org, &["two_factor_requirement_enabled"]) {
        Some(true) => ctx.pass(check),
        Some(false) => ctx.fail(Fail {
            check: check.into(),
            severity: Severity::High,
            title: "Organization does not require 2FA",
            message: "Members can sign in with a password alone. One phished or reused password gives access to every repository that member can reach.".into(),
            fix: "Require two-factor authentication for everyone in the organization (Settings → Authentication security).",
            page: "settings/security",
            basis: "2fa".into(),
        }),
        None => ctx.na(check, NEED_OWNER),
    }

    for (check, probe, severity, title, what, fix) in [
        (
            "settings/org-members-without-2fa",
            no_2fa,
            Severity::High,
            "Organization members without 2FA",
            "have no second factor",
            "Ask them to enable 2FA, or require 2FA for the organization (which removes members without it).",
        ),
        (
            "settings/org-members-insecure-2fa",
            sms_2fa,
            Severity::Low,
            "Organization members using SMS 2FA",
            "use SMS as their second factor, which SIM-swap attacks defeat",
            "Ask them to switch to a passkey, security key or authenticator app.",
        ),
    ] {
        if !probe.ok() {
            ctx.na(check, why_not(probe, NEED_OWNER));
            continue;
        }
        let logins: Vec<&str> = probe
            .body
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| m.get("login").and_then(Value::as_str))
            .collect();
        if logins.is_empty() {
            ctx.pass(check);
            continue;
        }
        let mut shown = logins
            .iter()
            .take(10)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        if logins.len() > 10 {
            shown.push_str(", ...");
        }
        ctx.fail(Fail {
            check: check.into(),
            severity,
            title,
            message: format!("{} member(s) {what}: {shown}.", logins.len()),
            fix,
            page: "people",
            basis: check.into(),
        });
    }

    let check = "settings/org-default-permission";
    match str_at(org, &["default_repository_permission"]) {
        Some(p @ ("write" | "admin")) => ctx.fail(Fail {
            check: check.into(),
            severity: if p == "admin" {
                Severity::High
            } else {
                Severity::Medium
            },
            title: "Members get write or admin on every repository",
            message: format!("The base permission is `{p}`: every member, and every compromised member account, can {} every repository in the organization.", if p == "admin" { "administer" } else { "push to" }),
            fix: "Set the base permission to read or none and grant access per team (Settings → Member privileges).",
            page: "settings/member_privileges",
            basis: p.into(),
        }),
        Some(_) => ctx.pass(check),
        None => ctx.na(check, NEED_OWNER),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn probe(status: u16, body: Value) -> Probe {
        Probe { status, body }
    }

    fn ctx() -> Ctx {
        Ctx::new("o/r".into(), "https://github.com/o/r".into())
    }

    fn status(c: &Ctx, check: &str) -> Option<CheckStatus> {
        c.audit
            .checks
            .iter()
            .find(|x| x.check == check)
            .map(|x| x.status)
    }

    fn rules(kinds: &[(&str, Value)]) -> Probe {
        probe(
            200,
            Value::Array(
                kinds
                    .iter()
                    .map(|(k, p)| json!({"type": k, "parameters": p, "ruleset_id": 1}))
                    .collect(),
            ),
        )
    }

    #[test]
    fn unprotected_default_branch_is_one_high_finding() {
        let mut c = ctx();
        let info = probe(200, json!({"name": "main", "protected": false}));
        branch_checks(&mut c, "main", &info, &rules(&[]), None, false);
        assert_eq!(c.audit.findings.len(), 1);
        let f = &c.audit.findings[0];
        assert_eq!(
            (f.rule_id.as_str(), f.severity, f.category),
            (
                "settings/default-branch-unprotected",
                Severity::High,
                Category::Settings
            )
        );
        assert_eq!(
            f.help_url.as_deref(),
            Some("https://github.com/o/r/settings/rules")
        );
    }

    #[test]
    fn rulesets_are_evaluated_rule_by_rule() {
        let mut c = ctx();
        let info = probe(200, json!({"protected": false}));
        let r = rules(&[
            (
                "pull_request",
                json!({"required_approving_review_count": 0}),
            ),
            ("non_fast_forward", json!({})),
        ]);
        branch_checks(&mut c, "main", &info, &r, None, false);
        assert_eq!(
            status(&c, "settings/default-branch-unprotected"),
            Some(CheckStatus::Pass)
        );
        assert_eq!(
            status(&c, "settings/direct-push-allowed"),
            Some(CheckStatus::Pass)
        );
        assert_eq!(
            status(&c, "settings/no-required-review"),
            Some(CheckStatus::Fail)
        );
        assert_eq!(
            status(&c, "settings/force-push-allowed"),
            Some(CheckStatus::Pass)
        );
        assert_eq!(
            status(&c, "settings/branch-deletion-allowed"),
            Some(CheckStatus::Fail)
        );
    }

    #[test]
    fn classic_protection_unreadable_without_admin_is_not_a_pass() {
        let mut c = ctx();
        let info = probe(200, json!({"protected": true}));
        let classic = probe(
            403,
            json!({"message": "Resource not accessible by integration"}),
        );
        branch_checks(&mut c, "main", &info, &rules(&[]), Some(&classic), false);
        assert_eq!(
            status(&c, "settings/default-branch-unprotected"),
            Some(CheckStatus::Pass)
        );
        for check in [
            "settings/direct-push-allowed",
            "settings/force-push-allowed",
            "settings/admins-bypass-protection",
        ] {
            assert_eq!(
                status(&c, check),
                Some(CheckStatus::NotAssessable),
                "{check}"
            );
        }
        assert!(c.audit.checks.iter().any(|x| {
            x.detail
                .as_deref()
                .is_some_and(|d| d.contains("Resource not accessible by integration"))
        }));
        assert!(c.audit.findings.is_empty());
    }

    #[test]
    fn classic_protection_with_admin() {
        let mut c = ctx();
        let info = probe(200, json!({"protected": true}));
        let classic = probe(
            200,
            json!({
                "required_pull_request_reviews": {"required_approving_review_count": 1},
                "allow_force_pushes": {"enabled": true},
                "allow_deletions": {"enabled": false},
                "enforce_admins": {"enabled": false}
            }),
        );
        branch_checks(&mut c, "main", &info, &rules(&[]), Some(&classic), true);
        let failed: Vec<&str> = c
            .audit
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert_eq!(
            failed,
            vec![
                "settings/force-push-allowed",
                "settings/admins-bypass-protection"
            ]
        );
    }

    #[test]
    fn missing_security_analysis_is_not_assessable_and_404_needs_admin() {
        let mut c = ctx();
        let repo = json!({"security_and_analysis": null});
        let pvr = probe(200, json!({"enabled": false}));
        security_checks(
            &mut c,
            &repo,
            false,
            false,
            &probe(404, json!({})),
            &probe(404, json!({})),
            &pvr,
        );
        assert_eq!(
            status(&c, "settings/secret-scanning-disabled"),
            Some(CheckStatus::NotAssessable)
        );
        assert_eq!(
            status(&c, "settings/dependabot-alerts-disabled"),
            Some(CheckStatus::NotAssessable)
        );
        assert_eq!(
            status(&c, "settings/private-vulnerability-reporting-disabled"),
            Some(CheckStatus::Fail)
        );

        let mut c = ctx();
        let repo = json!({"security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "disabled"}
        }});
        security_checks(
            &mut c,
            &repo,
            false,
            true,
            &probe(
                404,
                json!({"message": "Vulnerability alerts are disabled."}),
            ),
            &probe(200, json!({"enabled": true, "paused": false})),
            &pvr,
        );
        assert_eq!(
            status(&c, "settings/secret-scanning-disabled"),
            Some(CheckStatus::Pass)
        );
        assert_eq!(
            status(&c, "settings/push-protection-disabled"),
            Some(CheckStatus::Fail)
        );
        assert_eq!(
            status(&c, "settings/dependabot-alerts-disabled"),
            Some(CheckStatus::Fail)
        );
        assert_eq!(
            status(&c, "settings/dependabot-updates-disabled"),
            Some(CheckStatus::Pass)
        );
    }

    #[test]
    fn actions_policy() {
        let mut c = ctx();
        actions_checks(
            &mut c,
            "",
            false,
            &probe(
                200,
                json!({"enabled": true, "allowed_actions": "all", "sha_pinning_required": false}),
            ),
            &probe(
                200,
                json!({"default_workflow_permissions": "write", "can_approve_pull_request_reviews": true}),
            ),
            &probe(
                200,
                json!({"approval_policy": "first_time_contributors_new_to_github"}),
            ),
            &probe(404, json!({})),
            NEED_ADMIN,
        );
        let mut failed: Vec<&str> = c
            .audit
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        failed.sort();
        assert_eq!(
            failed,
            vec![
                "settings/actions-all-allowed",
                "settings/actions-can-approve-prs",
                "settings/actions-default-token-write",
                "settings/actions-sha-pinning-not-required",
                "settings/fork-pr-approval-weak",
            ]
        );
        // Proxy or permission refusals are not passes.
        let mut c = ctx();
        let denied = probe(
            403,
            json!({"message": "Must have admin rights to Repository."}),
        );
        actions_checks(
            &mut c, "", true, &denied, &denied, &denied, &denied, NEED_ADMIN,
        );
        assert!(c.audit.findings.is_empty());
        assert!(
            c.audit
                .checks
                .iter()
                .all(|x| x.status == CheckStatus::NotAssessable)
        );
    }

    #[test]
    fn private_fork_pull_requests_with_secrets() {
        let mut c = ctx();
        let ok = probe(200, json!({}));
        actions_checks(
            &mut c,
            "",
            true,
            &probe(
                200,
                json!({"enabled": true, "allowed_actions": "selected", "sha_pinning_required": true}),
            ),
            &probe(
                200,
                json!({"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false}),
            ),
            &ok,
            &probe(
                200,
                json!({"run_workflows_from_fork_pull_requests": true, "send_secrets_and_variables": true, "send_write_tokens_to_workflows": false, "require_approval_for_fork_pr_workflows": true}),
            ),
            NEED_ADMIN,
        );
        assert_eq!(c.audit.findings.len(), 1);
        assert_eq!(c.audit.findings[0].severity, Severity::High);
        assert!(c.audit.findings[0].message.contains("receive secrets"));
    }

    #[test]
    fn webhooks_keys_collaborators_and_environments() {
        let mut c = ctx();
        let hooks = probe(
            200,
            json!([
                {"id": 1, "active": true, "config": {"url": "http://ci.example/hook", "insecure_ssl": "1"}},
                {"id": 2, "active": true, "config": {"url": "https://ok.example/hook", "insecure_ssl": "0", "secret": "********"}},
                {"id": 3, "active": false, "config": {"url": "http://off.example"}}
            ]),
        );
        webhook_checks(&mut c, "", &hooks, NEED_ADMIN);
        let mut got: Vec<&str> = c
            .audit
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                "settings/webhook-insecure-ssl",
                "settings/webhook-no-secret",
                "settings/webhook-plain-http"
            ]
        );
        assert_eq!(
            status(&c, "settings/webhook-no-secret"),
            Some(CheckStatus::Fail)
        );

        let mut c = ctx();
        let keys = probe(
            200,
            json!([
                {"id": 7, "title": "ci", "read_only": false, "created_at": "2020-01-01T00:00:00Z", "last_used": "2020-02-01T00:00:00Z"},
                {"id": 8, "title": "fresh", "read_only": true, "created_at": chrono::Utc::now().to_rfc3339()}
            ]),
        );
        key_checks(&mut c, &keys);
        let got: Vec<&str> = c
            .audit
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert_eq!(
            got,
            vec!["settings/deploy-key-write", "settings/deploy-key-stale"]
        );

        let mut c = ctx();
        collaborator_check(
            &mut c,
            &probe(
                200,
                json!([{"login": "contractor", "permissions": {"admin": true}}, {"login": "helper", "permissions": {"admin": false}}]),
            ),
        );
        assert_eq!(c.audit.findings.len(), 1);
        assert!(c.audit.findings[0].message.contains("contractor"));

        let mut c = ctx();
        environment_check(
            &mut c,
            &probe(
                200,
                json!({"environments": [
                    {"name": "production", "protection_rules": [], "deployment_branch_policy": null},
                    {"name": "pypi", "protection_rules": [{"type": "required_reviewers"}], "deployment_branch_policy": null},
                    {"name": "preview", "protection_rules": [], "deployment_branch_policy": null}
                ]}),
            ),
        );
        assert_eq!(c.audit.findings.len(), 1);
        assert!(c.audit.findings[0].message.contains("production"));
    }

    #[test]
    fn organization_settings() {
        let mut c = Ctx::new(
            "org:acme".into(),
            "https://github.com/organizations/acme".into(),
        );
        org_checks(
            &mut c,
            &json!({"two_factor_requirement_enabled": false, "default_repository_permission": "write"}),
            &probe(200, json!([{"login": "alice"}, {"login": "bob"}])),
            &probe(403, json!({"message": "Must be an organization owner"})),
        );
        let mut got: Vec<(&str, Severity)> = c
            .audit
            .findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.severity))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("settings/org-2fa-not-required", Severity::High),
                ("settings/org-default-permission", Severity::Medium),
                ("settings/org-members-without-2fa", Severity::High),
            ]
        );
        assert!(
            c.audit
                .findings
                .iter()
                .any(|f| f.message.contains("alice, bob"))
        );
        assert_eq!(
            status(&c, "settings/org-members-insecure-2fa"),
            Some(CheckStatus::NotAssessable)
        );
        // A non-owner sees null for these fields.
        let mut c = Ctx::new("org:acme".into(), String::new());
        org_checks(
            &mut c,
            &json!({}),
            &probe(403, json!({})),
            &probe(403, json!({})),
        );
        assert!(c.audit.findings.is_empty());
        assert_eq!(c.audit.counts(), (0, 0, 4));
    }

    #[test]
    fn every_rule_is_listed() {
        let src = include_str!("settings.rs");
        for r in RULES {
            let name = r.id.trim_start_matches("settings/");
            let short = name.trim_start_matches("org-");
            assert!(src.contains(name) || src.contains(short), "{} unused", r.id);
        }
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
    }
}
