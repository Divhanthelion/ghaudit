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
  fail: { label: "Needs attention", short: "Fail", icon: "close", text: "This setting is unsafe. It is also listed as a finding." },
  not_assessable: {
    label: "Couldn't check",
    short: "Couldn't check",
    icon: "helpCircle",
    text: "GitHub didn't let this token see the setting. This is a gap in what was checked, not a pass.",
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
