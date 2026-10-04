// Plain-language explanations of everything a report contains, in one place so the
// wording stays consistent across the app.

/** Most severe first. `unknown` is shown as "Unrated" and counts as medium. */
export const SEVERITIES = [
  {
    id: "critical",
    label: "Critical",
    advice: "Fix now",
    text: "Could be exploited easily, or is a live credential anyone can use. Deal with these first.",
  },
  {
    id: "high",
    label: "High",
    advice: "Fix soon",
    text: "A serious weakness an attacker could use to get in, steal data or take over the project.",
  },
  {
    id: "medium",
    label: "Medium",
    advice: "Plan a fix",
    text: "A real risk, but harder to exploit, or less damaging if it is.",
  },
  {
    id: "unknown",
    label: "Unrated",
    advice: "Treat as medium",
    text: "A known vulnerability whose advisory gives no rating. Treat it as medium until you know more.",
  },
  {
    id: "low",
    label: "Low",
    advice: "When convenient",
    text: "A minor weakness or a hardening step. Worth doing, but not urgent.",
  },
  {
    id: "info",
    label: "Info",
    advice: "For your information",
    text: "Not a problem on its own: usually something in tests, examples or docs.",
  },
];

export const SEVERITY = Object.fromEntries(SEVERITIES.map((s) => [s.id, s]));

/** Sort key: higher is more severe (unrated sits between medium and low). */
export const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s.id, SEVERITIES.length - i]));

export const CATEGORIES = [
  {
    id: "secret",
    label: "Secrets",
    icon: "key",
    text: "Passwords, API keys and tokens written into files or git history. Anyone who can read the repository can use them.",
  },
  {
    id: "dependency",
    label: "Dependencies",
    icon: "package",
    text: "Third-party packages with known vulnerabilities, from the OSV database.",
  },
  {
    id: "sast",
    label: "Code",
    icon: "code",
    text: "Risky patterns in source code, such as database queries or shell commands built from strings.",
  },
  {
    id: "workflow",
    label: "Workflows",
    icon: "workflow",
    text: "GitHub Actions set up in a way that could let outsiders run code with your secrets or write access.",
  },
  {
    id: "agent",
    label: "AI agent configs",
    icon: "bot",
    text: "Settings committed for AI coding tools and editors that run commands or skip confirmations.",
  },
  {
    id: "settings",
    label: "Repository settings",
    icon: "sliders",
    text: "GitHub settings such as branch protection, secret scanning and Dependabot.",
  },
  {
    id: "ai",
    label: "AI review",
    icon: "sparkle",
    text: "Suggestions from a language model. Leads to check, not verdicts.",
  },
];

export const CATEGORY = Object.fromEntries(CATEGORIES.map((c) => [c.id, c]));

export const CONFIDENCE = {
  high: "Almost certainly a real issue.",
  medium: "Probably real, but check it.",
  low: "Could be a false alarm.",
};

/** The analyzers in report order, with what each one checks. */
export const ANALYZERS = [
  { id: "sast", label: "Code rules", text: "Risky code patterns in Rust, Python, JavaScript, TypeScript and Go." },
  { id: "secrets", label: "Secrets in files", text: "Passwords, keys and tokens in the current files." },
  { id: "history", label: "Secrets in git history", text: "Credentials deleted from the files but still in earlier commits." },
  { id: "sca", label: "Dependencies", text: "Known vulnerabilities in packages, using osv-scanner." },
  { id: "workflows", label: "GitHub Actions workflows", text: "Workflows that outsiders could abuse." },
  { id: "agents", label: "AI agent configs", text: "Editor and AI-agent settings committed to the repository." },
  { id: "settings", label: "Repository settings", text: "Security settings, read from GitHub." },
  { id: "ai", label: "AI review", text: "Optional review by a local language model." },
];

export const ANALYZER = Object.fromEntries(ANALYZERS.map((a) => [a.id, a]));

export const ANALYZER_STATE = {
  completed: { label: "Checked", icon: "checkCircle", cls: "ok" },
  skipped: { label: "Not run", icon: "minusCircle", cls: "skipped" },
  failed: { label: "Failed", icon: "xCircle", cls: "failed" },
};

export const CHECK_STATUS = {
  pass: { label: "Passed", short: "Pass", icon: "check", text: "This setting is configured safely." },
  fail: { label: "Needs attention", short: "Fail", icon: "close", text: "This setting is unsafe. It is also listed under Findings, with how to fix it." },
  not_assessable: {
    label: "Couldn't check",
    short: "Couldn't check",
    icon: "helpCircle",
    text: "ghaudit couldn't read this setting, so it may or may not be safe: a gap in what was checked, not a pass. The reason says why; often the token isn't an admin of the repository, or GitHub doesn't offer the feature there.",
  },
};

/** A severity's label for any id, including ones a newer ghaudit might add. */
export function severityLabel(id) {
  return SEVERITY[id]?.label ?? id;
}

export function categoryLabel(id) {
  return CATEGORY[id]?.label ?? id;
}

export function analyzerLabel(id) {
  return ANALYZER[id]?.label ?? id;
}

/**
 * Settings checks in report order, grouped by area, each with a short label that says
 * what a pass means (the column headings of the settings grid). Names of checks a newer
 * ghaudit adds come from the rule catalog.
 */
export const SETTINGS_AREAS = [
  {
    id: "branch",
    label: "Default branch",
    checks: [
      ["settings/default-branch-unprotected", "Branch protected"],
      ["settings/direct-push-allowed", "No direct pushes"],
      ["settings/no-required-review", "Review required"],
      ["settings/force-push-allowed", "No force pushes"],
      ["settings/branch-deletion-allowed", "Can't be deleted"],
      ["settings/admins-bypass-protection", "Applies to admins"],
    ],
  },
  {
    id: "features",
    label: "Security features",
    checks: [
      ["settings/secret-scanning-disabled", "Secret scanning"],
      ["settings/push-protection-disabled", "Push protection"],
      ["settings/dependabot-alerts-disabled", "Dependabot alerts"],
      ["settings/dependabot-updates-disabled", "Dependabot updates"],
      ["settings/private-vulnerability-reporting-disabled", "Private reporting"],
    ],
  },
  {
    id: "actions",
    label: "GitHub Actions",
    checks: [
      ["settings/actions-default-token-write", "Read-only token"],
      ["settings/actions-can-approve-prs", "Can't approve PRs"],
      ["settings/actions-sha-pinning-not-required", "SHA pins required"],
      ["settings/actions-all-allowed", "Actions limited"],
      ["settings/fork-pr-approval-weak", "Fork PRs approved"],
      ["settings/fork-pr-secrets", "No secrets for forks"],
      ["settings/self-hosted-runner-public", "No public runners"],
    ],
  },
  {
    id: "access",
    label: "Access",
    checks: [
      ["settings/deploy-key-write", "Read-only deploy keys"],
      ["settings/deploy-key-stale", "No stale deploy keys"],
      ["settings/outside-collaborator-admin", "No outside admins"],
      ["settings/environment-unprotected", "Environments protected"],
    ],
  },
  {
    id: "webhooks",
    label: "Webhooks",
    checks: [
      ["settings/webhook-insecure-ssl", "Verify TLS"],
      ["settings/webhook-plain-http", "HTTPS only"],
      ["settings/webhook-no-secret", "Have a secret"],
    ],
  },
  {
    id: "org",
    label: "Organization",
    checks: [
      ["settings/org-2fa-not-required", "2FA required"],
      ["settings/org-members-without-2fa", "Members use 2FA"],
      ["settings/org-members-insecure-2fa", "No SMS 2FA"],
      ["settings/org-default-permission", "Limited default access"],
      ["settings/org-actions-default-token-write", "Read-only token"],
      ["settings/org-actions-can-approve-prs", "Can't approve PRs"],
      ["settings/org-actions-sha-pinning-not-required", "SHA pins required"],
      ["settings/org-actions-all-allowed", "Actions limited"],
      ["settings/org-fork-pr-approval-weak", "Fork PRs approved"],
      ["settings/org-fork-pr-secrets", "No secrets for forks"],
      ["settings/org-webhook-insecure-ssl", "Webhooks verify TLS"],
      ["settings/org-webhook-plain-http", "Webhooks use HTTPS"],
      ["settings/org-webhook-no-secret", "Webhooks have a secret"],
    ],
  },
];
