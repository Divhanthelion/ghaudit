//! Hardcoded credential detection.
//!
//! Two kinds of detection:
//! 1. **Provider patterns**: token formats with a recognizable prefix or shape
//!    (`ghp_...`, `AKIA...`, PEM private key blocks). High confidence; they run
//!    on every file, binary files and tests included, because a live token in a test
//!    fixture is still a leaked token. In tests, docs and examples they are reported
//!    at reduced severity, since most are fakes.
//! 2. **Generic assignments**: a value assigned to a secret-like name
//!    (`password = "..."`, `API_KEY: ...`). Filtered hard against placeholders,
//!    references (`${VAR}`, `process.env.X`) and identifier-like values; skipped
//!    in test, example, docs and translation paths.
//!
//! Matched values never leave this module unredacted: messages and snippets show only
//! a short prefix.

use crate::model::{Category, Confidence, Finding, LineIndex, Location, Severity, Snippet};
use regex::{Captures, Regex};
use std::sync::LazyLock;

const SNIPPET_CONTEXT: usize = 1;
const REMEDIATION: &str = "Revoke and rotate this credential now (assume it is compromised once committed), then load it from the environment or a secrets manager. Removing it from the latest commit does not remove it from git history.";

struct Provider {
    id: &'static str,
    name: &'static str,
    /// Capture group 1 (or the whole match if absent) is the secret value.
    regex: Regex,
    severity: Severity,
    confidence: Confidence,
}

fn provider(
    id: &'static str,
    name: &'static str,
    pattern: &str,
    severity: Severity,
    confidence: Confidence,
) -> Provider {
    Provider {
        id,
        name,
        regex: Regex::new(pattern).expect("valid secret pattern"),
        severity,
        confidence,
    }
}

static PROVIDERS: LazyLock<Vec<Provider>> = LazyLock::new(|| {
    use Confidence as C;
    use Severity as S;
    vec![
        provider(
            "secret/aws-access-key-id",
            "AWS access key ID",
            r"\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})\b",
            S::High,
            C::High,
        ),
        provider(
            "secret/aws-secret-access-key",
            "AWS secret access key",
            r#"(?i)aws[_\-.]?(?:secret|private)[_\-.]?(?:access[_\-.]?)?key["']?\s*(?:=|:|:=|=>)\s*["']?([A-Za-z0-9/+]{40})"#,
            S::Critical,
            C::High,
        ),
        provider(
            "secret/github-token",
            "GitHub token",
            r"\b(gh[pousr]_[A-Za-z0-9]{36,251})",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/github-fine-grained-token",
            "GitHub fine-grained token",
            r"\b(github_pat_[A-Za-z0-9_]{82})",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/gitlab-token",
            "GitLab token",
            // Personal, deploy, runner, CI-build, trigger, feed, OAuth... tokens, including
            // the routable format (`glpat-<payload>.<2><7>`) introduced in GitLab 17.
            r"\b((?:glpat|gldt|glrt|glcbt|glptt|glft|glffct|glimt|glagent|gloas|glsoat)-[0-9A-Za-z_\-]{20,300}(?:\.[0-9a-z]{9})?)",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/gitlab-token",
            "GitLab runner registration token",
            r"\b(GR1348941[0-9A-Za-z_\-]{20})",
            S::High,
            C::High,
        ),
        provider(
            "secret/slack-token",
            "Slack token",
            // Bot/user/legacy tokens, rotating (xoxe.xoxb-) and refresh (xoxe-) tokens,
            // and app-level tokens (xapp-).
            r"\b(xoxe\.xox[bp]-\d-[A-Za-z0-9]{100,}|xox[abposre]-[A-Za-z0-9-]{10,}|xapp-\d-[A-Za-z0-9-]{20,})",
            S::High,
            C::High,
        ),
        provider(
            "secret/slack-webhook",
            "Slack webhook URL",
            // Incoming webhooks, and Workflow Builder webhooks and triggers.
            r"(https://hooks\.slack\.com/(?:services/T[A-Z0-9]+/B[A-Z0-9]+|(?:workflows|triggers)/T[A-Z0-9]+/A[A-Z0-9]+/\d+)/[A-Za-z0-9]{20,})",
            S::Medium,
            C::High,
        ),
        provider(
            "secret/stripe-key",
            "Stripe live secret key",
            r"\b((?:sk|rk)_live_[A-Za-z0-9]{24,})",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/google-api-key",
            "Google API key",
            r"\b(AIza[0-9A-Za-z_\-]{35})",
            S::High,
            C::High,
        ),
        provider(
            "secret/openai-key",
            "OpenAI API key",
            r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}T3BlbkFJ[A-Za-z0-9_\-]{16,})",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/anthropic-key",
            "Anthropic API key",
            // API and admin keys, and Claude OAuth access/refresh tokens.
            r"\b(sk-ant-(?:api|admin|oat|ort)\d{2}-[A-Za-z0-9_\-]{80,})",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/huggingface-token",
            "Hugging Face token",
            // User tokens and (legacy) organization API tokens.
            r"\b((?:hf|api_org)_[A-Za-z]{34})",
            S::High,
            C::High,
        ),
        provider(
            "secret/npm-token",
            "npm access token",
            r"\b(npm_[A-Za-z0-9]{36})",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/npm-token",
            "npm registry token in .npmrc",
            // `//registry.npmjs.org/:_authToken=...`; `${NPM_TOKEN}` references don't match.
            r"//[^\s:]+/:_auth(?:Token)?\s*=\s*([A-Za-z0-9_\-.+/=]{20,})",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/pypi-token",
            "PyPI upload token",
            // pypi.org and test.pypi.org macaroons.
            r"\b(pypi-(?:AgEIcHlwaS5vcmc|AgENdGVzdC5weXBpLm9yZw)[A-Za-z0-9_\-]{50,})",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/sendgrid-key",
            "SendGrid API key",
            r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})",
            S::High,
            C::High,
        ),
        provider(
            "secret/twilio-key",
            "Twilio API key",
            r"\b(SK[0-9a-f]{32})",
            S::High,
            C::Medium,
        ),
        provider(
            "secret/azure-storage-key",
            "Azure storage account key",
            r"AccountKey=([A-Za-z0-9+/]{86}==)",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/private-key",
            "Private key",
            // The header must be followed by key material (raw newlines or `\\n` escapes in a
            // string literal), so documentation that merely names the header is not flagged.
            // Lines may be indented (YAML block scalars, heredocs).
            r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)(?:\r?\n|(?:\\r)?\\n)(?:[ \t]*[A-Za-z-]+: [^\r\n\\]*(?:\r?\n|(?:\\r)?\\n))*(?:[ \t]*(?:\r?\n|(?:\\r)?\\n))?[ \t]*([A-Za-z0-9+/=]{40,})",
            S::Critical,
            C::High,
        ),
        provider(
            "secret/jwt",
            "JSON Web Token",
            r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})",
            S::Medium,
            C::Medium,
        ),
        provider(
            "secret/connection-string-password",
            "Password in connection string",
            // The user may be empty: `redis://:password@host`.
            r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^\s:/@'"]*:([^\s@'"/]+)@[^\s'"]+"#,
            S::High,
            C::High,
        ),
    ]
});

/// Words that make a name secret-like.
const SECRET_NAME: &str = r"[A-Za-z0-9_.\-]*(?:secret|passwd|password|passphrase|pwd|token|api[_\-.]?key|apikey|access[_\-.]?key|private[_\-.]?key|client[_\-.]?secret|auth[_\-.]?key|credentials?)[A-Za-z0-9_.\-]*";

/// `name = "value"`, `"name": "value"`, `name: 'value'`, `name := "value"`, `name => 'value'`,
/// `cfg["name"] = "value"`, `name: str = "value"` and `` name = `value` ``.
static QUOTED_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)(?P<key>{SECRET_NAME})["'`]?\]?(?:\s*:\s*[A-Za-z_][A-Za-z0-9_.<>\[\]| ]{{0,40}}?)?\s*(?:=|:|:=|=>|\?\?=)\s*(?:[rbuf]?["'`])(?P<val>[^"'`\s]{{8,256}})["'`]"#
    ))
    .unwrap()
});

/// Unquoted `NAME=value` / `name: value` lines (also `export`, Dockerfile `ENV`/`ARG`),
/// only in config-style files.
static BARE_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?im)^[ \t]*(?:(?:export|ENV|ARG)[ \t]+)?(?P<key>{SECRET_NAME})[ \t]*[=:][ \t]*(?P<val>[^\s"'#;(){{}}\[\]<>$%,]{{8,256}})[ \t]*(?:#.*)?$"#
    ))
    .unwrap()
});

/// Dockerfile `ENV NAME value` (space-separated form).
static DOCKER_ENV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?im)^[ \t]*ENV[ \t]+(?P<key>{SECRET_NAME})[ \t]+(?P<val>[^\s"'#$=]{{8,256}})[ \t]*$"#
    ))
    .unwrap()
});

/// Names that contain a secret word but describe something else (`token_url`, `max_tokens`).
static NON_SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(tokens|tokenizer|tokenize|_?(url|uri|path|file|dir|name|names|type|header|endpoint|length|len|count|size|limit|field|param|prefix|format|mode|expiry|expires|expiration|ttl|timeout|policy|hint|label|placeholder|template|regex|pattern|id|ids|env|var|ref|arn|version|algorithm|alg|scheme|kind|style|hash|length|min|max|enabled|required|rotation|store|provider|manager|reset|confirmation|confirm|checksum|digest|fingerprint|sha|sha1|sha256|sha512|integrity)$)",
    )
    .unwrap()
});

/// Values that are clearly not real credentials. Keyboard and counting runs
/// (`12345`, `abcdef`, `a1b2c3`) are as good as absent from random tokens.
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(12345|23456|34567|45678|56789|67890|abcdef|a1b2c3|qwerty|example|sample|dummy|changeme|change_me|change-me|replace|your[_\-]?|placeholder|redacted|insert|fake|mock|todo|tbd|xxxx|\*\*\*|\.\.\.|<|>|\$\{|\{\{|%\(|\$\(|process\.env|os\.environ|getenv|env\(|^none$|^null$|^nil$|^undefined$|^true$|^false$|^password$|^secret$|^token$)",
    )
    .unwrap()
});

pub struct SecretDetector;

/// Findings for one file plus the raw values found, so callers can mask those values
/// wherever else they might be displayed (e.g. in context lines of other findings).
#[derive(Debug, Default)]
pub struct SecretScan {
    pub findings: Vec<Finding>,
    pub values: Vec<String>,
}

/// Finds any of a file's secret values in a single pass, however many there are.
pub struct Masker(Option<Regex>);

impl Masker {
    pub fn new(values: &[String]) -> Self {
        let mut sorted: Vec<&str> = values
            .iter()
            .map(String::as_str)
            .filter(|v| !v.is_empty())
            .collect();
        // Longest first, so a value that contains another is masked as a whole.
        sorted.sort_by_key(|v| std::cmp::Reverse(v.len()));
        sorted.dedup();
        if sorted.is_empty() {
            return Self(None);
        }
        let pattern = sorted
            .iter()
            .map(|v| regex::escape(v))
            .collect::<Vec<_>>()
            .join("|");
        let re = regex::RegexBuilder::new(&pattern)
            .size_limit(256 << 20)
            .build()
            .expect("escaped literals always compile");
        Self(Some(re))
    }

    pub fn is_match(&self, s: &str) -> bool {
        self.0.as_ref().is_some_and(|re| re.is_match(s))
    }

    /// Each value replaced with its short redacted form (`ghp_********`).
    pub fn redact<'a>(&self, s: &'a str) -> std::borrow::Cow<'a, str> {
        match &self.0 {
            Some(re) => re.replace_all(s, |c: &Captures| redact(&c[0])),
            None => s.into(),
        }
    }

    /// Each value replaced with `********`, revealing nothing about it.
    pub fn mask<'a>(&self, s: &'a str) -> std::borrow::Cow<'a, str> {
        match &self.0 {
            Some(re) => re.replace_all(s, "********"),
            None => s.into(),
        }
    }

    /// Redact the values in the snippets and messages of `findings`.
    pub fn redact_findings(&self, findings: &mut [Finding]) {
        if self.0.is_none() {
            return;
        }
        for f in findings {
            if let Some(snippet) = &mut f.snippet {
                for line in &mut snippet.lines {
                    if let std::borrow::Cow::Owned(r) = self.redact(line) {
                        *line = r;
                    }
                }
            }
            if let std::borrow::Cow::Owned(r) = self.redact(&f.message) {
                f.message = r;
            }
        }
    }
}

/// Mask every value in `values` in the snippets and messages of `findings`.
pub fn redact_snippets(findings: &mut [Finding], values: &[String]) {
    Masker::new(values).redact_findings(findings);
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector {
    pub fn new() -> Self {
        // Compile the patterns up front so a bad regex fails at startup, not mid-scan.
        LazyLock::force(&PROVIDERS);
        Self
    }

    /// Files whose content is machine-generated hashes or minified code.
    pub fn should_scan(rel_path: &str) -> bool {
        let name = rel_path
            .rsplit('/')
            .next()
            .unwrap_or(rel_path)
            .to_ascii_lowercase();
        const SKIP_NAMES: &[&str] = &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "cargo.lock",
            "go.sum",
            "poetry.lock",
            "pipfile.lock",
            "composer.lock",
            "gemfile.lock",
            "uv.lock",
        ];
        const SKIP_SUFFIXES: &[&str] = &[".min.js", ".min.css", ".map", ".svg", ".lock"];
        !SKIP_NAMES.contains(&name.as_str()) && !SKIP_SUFFIXES.iter().any(|s| name.ends_with(s))
    }

    /// Find credentials in one text file. `rel_path` uses `/` separators.
    pub fn detect(&self, rel_path: &str, content: &str) -> SecretScan {
        self.scan(rel_path, content, false)
    }

    /// Find provider credentials in a binary file's (lossily decoded) content.
    pub fn detect_binary(&self, rel_path: &str, content: &str) -> SecretScan {
        self.scan(rel_path, content, true)
    }

    fn scan(&self, rel_path: &str, content: &str, binary: bool) -> SecretScan {
        let index = LineIndex::new(content);
        let test = is_test_path(rel_path);
        // Rust keeps unit tests in the source file, under `#[cfg(test)]`.
        let test_code = if !test && !binary && rel_path.ends_with(".rs") {
            crate::analyzer::sast::rust_test_ranges(content)
        } else {
            Vec::new()
        };
        let in_test_code = |offset: usize| test_code.iter().any(|r| r.contains(&offset));
        let mut findings = Vec::new();
        let mut values: Vec<String> = Vec::new();
        // Byte ranges already reported, so one value is reported once.
        let mut covered: Vec<(usize, usize)> = Vec::new();
        let overlaps = |covered: &[(usize, usize)], m: &regex::Match| {
            covered.iter().any(|&(s, e)| m.start() < e && s < m.end())
        };

        for p in PROVIDERS.iter() {
            for caps in p.regex.captures_iter(content) {
                let m = secret_group(&caps);
                let value = m.as_str();
                if continues_token(content, m.end()) || overlaps(&covered, &m) {
                    continue;
                }
                if p.id != "secret/private-key" && is_placeholder(value) {
                    continue;
                }
                if p.id == "secret/connection-string-password" && is_reference(value) {
                    continue;
                }
                covered.push((m.start(), m.end()));
                values.push(value.to_string());
                let is_key = p.id == "secret/private-key";
                if let (true, Some(body)) = (is_key, caps.get(2)) {
                    // Key material must not appear in any snippet.
                    values.push(body.as_str().to_string());
                }
                let mut severity = p.severity;
                let unit_test = in_test_code(m.start());
                if test || unit_test {
                    // Most keys and tokens in tests and docs are fakes: report, quietly.
                    severity = if is_key {
                        Severity::Low
                    } else {
                        severity.min(Severity::Medium)
                    };
                }
                let mut finding = build(
                    &index,
                    rel_path,
                    m.start(),
                    value,
                    p.id,
                    p.name,
                    severity,
                    p.confidence,
                );
                if test {
                    finding
                        .message
                        .push_str(" (in test, example or documentation files)");
                } else if unit_test {
                    finding.message.push_str(" (in test code)");
                }
                if binary {
                    finding.message.push_str(" (in a binary file)");
                    finding.snippet = None;
                } else if is_key {
                    let (line, column) = index.position(m.start());
                    finding.snippet = Snippet::from_index(&index, line, column, 0)
                        .map(|sn| sn.redact(value, &redact(value)));
                }
                findings.push(finding);
            }
        }

        if test || binary || is_generic_exempt(rel_path) {
            redact_snippets(&mut findings, &values);
            return SecretScan { findings, values };
        }
        let mut generic = |re: &Regex| {
            for caps in re.captures_iter(content) {
                let (Some(key), Some(val)) = (caps.name("key"), caps.name("val")) else {
                    continue;
                };
                // Generic matches in tests are fixtures, as in test files (skipped above).
                if overlaps(&covered, &val)
                    || NON_SECRET_KEY.is_match(key.as_str())
                    || in_test_code(val.start())
                {
                    continue;
                }
                let value = val.as_str();
                // Hex constants and addresses, unless the name says it is a private key.
                let hex = value.starts_with("0x") || value.starts_with("0X");
                if (hex && !key.as_str().to_ascii_lowercase().contains("private"))
                    || !looks_like_secret(value)
                {
                    continue;
                }
                covered.push((val.start(), val.end()));
                values.push(value.to_string());
                findings.push(build(
                    &index,
                    rel_path,
                    val.start(),
                    value,
                    "secret/generic-assignment",
                    "Hardcoded secret",
                    Severity::Medium,
                    Confidence::Medium,
                ));
            }
        };
        generic(&QUOTED_ASSIGNMENT);
        if is_config_file(rel_path) {
            generic(&BARE_ASSIGNMENT);
            generic(&DOCKER_ENV);
        }
        redact_snippets(&mut findings, &values);
        SecretScan { findings, values }
    }
}

fn secret_group<'h>(caps: &Captures<'h>) -> regex::Match<'h> {
    caps.get(1)
        .or_else(|| caps.get(0))
        .expect("group 0 always exists")
}

/// Whether the character after a match continues the token, i.e. the match is only
/// part of a longer string. (A trailing `\b` would wrongly reject tokens that end in
/// `-` or `_`, which Google and SendGrid keys can.)
fn continues_token(content: &str, end: usize) -> bool {
    content[end..]
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/'))
}

#[allow(clippy::too_many_arguments)]
fn build(
    index: &LineIndex,
    rel_path: &str,
    offset: usize,
    value: &str,
    rule_id: &str,
    name: &str,
    severity: Severity,
    confidence: Confidence,
) -> Finding {
    let (line, column) = index.position(offset);
    let masked = redact(value);
    let line_text = index.line(line).unwrap_or_default();
    let snippet =
        Snippet::from_index(index, line, column, SNIPPET_CONTEXT).map(|s| s.redact(value, &masked));
    Finding::new(
        rule_id,
        Category::Secret,
        severity,
        confidence,
        name,
        format!("{name} found: {masked}"),
        Location::new(rel_path, line, column).with_end(line, column + value.chars().count()),
        // Never derived from the value itself: a fingerprint of a short password
        // could be brute-forced.
        &line_text.replace(value, "********"),
    )
    .with_snippet(snippet)
    .with_cwe(["CWE-798"])
    .with_remediation(REMEDIATION)
}

/// Keep a short prefix (useful to recognize the token type) and hide the rest,
/// without revealing the secret's length.
pub fn redact(value: &str) -> String {
    let shown: String = if value.chars().count() >= 16 {
        value.chars().take(4).collect()
    } else {
        String::new()
    };
    format!("{shown}********")
}

fn is_placeholder(value: &str) -> bool {
    PLACEHOLDER.is_match(value) || distinct_chars(value) < 5 || {
        // Judge a prefixed token (`GR1348941...`, `AKIA...`) by its random part.
        let tail: Vec<char> = value.chars().rev().take(16).collect();
        tail.len() == 16 && distinct_chars(&tail.iter().collect::<String>()) < 5
    }
}

/// `${DB_PASSWORD}`, `$PASSWORD`, `%(pw)s`, `env:API_KEY`: the value is read from elsewhere.
fn is_reference(value: &str) -> bool {
    value.starts_with('$') || value.starts_with('%') || value.starts_with('{') || {
        // `env:NAME`, as LLM gateway and agent configs write environment lookups.
        value
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("env:"))
            && value.len() > 4
            && value[4..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
}

fn distinct_chars(s: &str) -> usize {
    let mut chars: Vec<char> = s.chars().collect();
    chars.sort_unstable();
    chars.dedup();
    chars.len()
}

/// Heuristics for a value assigned to a secret-like name.
fn looks_like_secret(value: &str) -> bool {
    if is_placeholder(value) || is_reference(value) {
        return false;
    }
    // Paths, URLs without credentials, and dotted references (settings.SECRET_KEY).
    if value.starts_with('/') || value.starts_with("./") || value.contains("://") {
        return false;
    }
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_lower = value.chars().any(|c| c.is_lowercase());
    let has_upper = value.chars().any(|c| c.is_uppercase());
    let has_symbol = value.chars().any(|c| !c.is_alphanumeric());
    // Identifier-like words: SECRET_KEY_NAME, user-password-field, AccessToken.
    let wordy = value
        .chars()
        .all(|c| c.is_alphabetic() || c == '_' || c == '-' || c == '.');
    if wordy && !has_digit {
        return false;
    }
    let classes = [has_digit, has_lower, has_upper, has_symbol]
        .iter()
        .filter(|&&b| b)
        .count();
    classes >= 2 && shannon_entropy(value) >= 2.5
}

/// Bits of entropy per character.
pub fn shannon_entropy(s: &str) -> f64 {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in &chars {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let len = chars.len() as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Tests, fixtures, examples and documentation: findings there are usually fakes or
/// illustrations, so they are reported at reduced severity (or not at all, for
/// generic secret matches).
pub fn is_test_path(rel_path: &str) -> bool {
    let lower = rel_path.to_ascii_lowercase();
    let in_dir = lower.split('/').rev().skip(1).any(|seg| {
        matches!(
            seg,
            "test"
                | "tests"
                | "__tests__"
                | "spec"
                | "specs"
                | "testdata"
                | "test-data"
                | "test_data"
                | "fixtures"
                | "fixture"
                | "examples"
                | "example"
                | "samples"
                | "sample"
                | "mocks"
                | "__mocks__"
                | "docs"
                | "doc"
                | "docs_src"
        )
    });
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    in_dir
        || name.starts_with("test_")
        || [
            "_test.go", "_test.py", "_test.rs", ".test.js", ".test.ts", ".test.tsx", ".spec.js", ".spec.ts", ".spec.tsx", "_spec.rb",
        ]
        .iter()
        .any(|s| name.ends_with(s))
        || name.contains(".example") // .env.example, config.example.yml
        || name.contains(".sample")
        || [".md", ".rst", ".adoc"].iter().any(|s| name.ends_with(s))
}

/// Translation catalogs: `"password": "Mot de passe"` is a label, not a password.
fn is_generic_exempt(rel_path: &str) -> bool {
    rel_path
        .to_ascii_lowercase()
        .split('/')
        .rev()
        .skip(1)
        .any(|seg| {
            matches!(
                seg,
                "locales" | "locale" | "i18n" | "l10n" | "translations" | "lang" | "langs"
            )
        })
}

fn is_config_file(rel_path: &str) -> bool {
    let name = rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .to_ascii_lowercase();
    name.starts_with(".env")
        || name.ends_with(".env")
        || [
            ".ini",
            ".cfg",
            ".conf",
            ".properties",
            ".yaml",
            ".yml",
            ".toml",
            ".tfvars",
            ".npmrc",
            ".pypirc",
            ".sh",
            ".bash",
            ".zsh",
            ".envrc",
            ".dockerfile",
        ]
        .iter()
        .any(|ext| name.ends_with(ext))
        || name.starts_with("dockerfile")
        || name.starts_with("containerfile")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test tokens are assembled at runtime so this source file does not itself
    // contain anything that looks like a live credential.
    fn tok(parts: &[&str]) -> String {
        parts.concat()
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn detect(path: &str, content: &str) -> Vec<Finding> {
        SecretDetector::new().detect(path, content).findings
    }

    #[test]
    fn provider_tokens_are_found_in_any_text_file() {
        let gh = tok(&["ghp_", "R8d2kLq9ZxT4mWn7Bv1Cy6Pa3Hs5Je0Fu2Gk"]);
        let aws = tok(&["AKIA", "Q3ZJ7VYN2WXK5MDR"]);
        let cases = [
            (
                "config/settings.yaml",
                format!("github:\n  token: {gh}\n"),
                "secret/github-token",
            ),
            (
                ".env",
                format!("AWS_ACCESS_KEY_ID={aws}\n"),
                "secret/aws-access-key-id",
            ),
            (
                "deploy/values.json",
                format!("{{\"key\": \"{aws}\"}}"),
                "secret/aws-access-key-id",
            ),
            (
                "src/app.rs",
                format!("let t = \"{gh}\";"),
                "secret/github-token",
            ),
        ];
        for (path, content, rule) in cases {
            assert_eq!(ids(&detect(path, &content)), vec![rule], "{path}");
        }
    }

    #[test]
    fn newer_token_formats() {
        let samples = [
            (
                tok(&[
                    "github_pat_",
                    "11BQ7XKMA0rT4wZp8nLs2v_",
                    &"aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3"[..59],
                ]),
                "secret/github-fine-grained-token",
            ),
            (
                tok(&["glpat-", "x7Rk2Lm9Pq4Tz8Wn3Vb6"]),
                "secret/gitlab-token",
            ),
            (
                tok(&[
                    "sk-proj-",
                    "a8F3kZ9qL2mX7wR4tY6u",
                    "T3BlbkFJ",
                    "p5Nc8Vb2Hj6Gd9Sx3Lq1",
                ]),
                "secret/openai-key",
            ),
            (
                tok(&[
                    "sk-ant-api03-",
                    &"Zq8Xr3Lm7Kp2Wt9Vn4Bc6Hy1Jd5Fs0Ga".repeat(3)[..95],
                    "AA",
                ]),
                "secret/anthropic-key",
            ),
            (
                tok(&["npm_", "q7Rk2Lm9Pt4Tz8Wn3Vb6Hy1Jd5Fs0GaXc4Eu"]),
                "secret/npm-token",
            ),
            (
                tok(&["hf_", "ZqXrLmKpWtVnBcHyJdFsGaQeRtYuIoPlKw"]),
                "secret/huggingface-token",
            ),
        ];
        for (secret, rule) in samples {
            let found = detect("src/config.py", &format!("KEY = \"{secret}\"\n"));
            assert!(
                ids(&found).contains(&rule),
                "{rule} not found in {secret}: {:?}",
                ids(&found)
            );
        }
    }

    #[test]
    fn gitlab_and_slack_current_formats() {
        let routable = tok(&[
            "glpat-",
            "YzowCm86MTpwOjE3ZnA0dGcuMDHpqlKHnlEA",
            ".121e8269o",
        ]);
        let found = detect("ci.env", &format!("TOKEN={routable}\n"));
        assert_eq!(ids(&found), vec!["secret/gitlab-token"]);
        assert_eq!(
            found[0].location.end_column - found[0].location.start_column,
            routable.len(),
            "whole routable token matched"
        );
        let runner = tok(&["glrt-", "t1_Zx9Qp2Lm7Kw4Rt8VbN3c"]);
        assert_eq!(ids(&detect("a.sh", &runner)), vec!["secret/gitlab-token"]);
        let app = tok(&[
            "xapp-1-",
            "A07QK2MZP4R-4829163057281-9f3c7e1b5d8a2f60e4b7c9d1",
        ]);
        assert_eq!(
            ids(&detect("a.py", &format!("t = '{app}'"))),
            vec!["secret/slack-token"]
        );
    }

    #[test]
    fn secrets_are_redacted_everywhere() {
        let gh = tok(&["ghp_", "R8d2kLq9ZxT4mWn7Bv1Cy6Pa3Hs5Je0Fu2Gk"]);
        let f = &detect("a.py", &format!("x = 1\ntoken = \"{gh}\"\ny = 2\n"))[0];
        let serialized = serde_json::to_string(f).unwrap();
        assert!(
            !serialized.contains(&gh),
            "secret leaked into finding: {serialized}"
        );
        assert!(f.message.contains("ghp_********"));
        assert!(
            f.snippet
                .as_ref()
                .unwrap()
                .lines
                .iter()
                .any(|l| l.contains("ghp_********"))
        );
        assert_eq!((f.location.start_line, f.location.start_column), (2, 10));
    }

    #[test]
    fn generic_assignments_in_code_and_config() {
        let hits = detect("app/settings.py", "DB_PASSWORD = \"Tr0ub4dor&3xq\"\n");
        assert_eq!(ids(&hits), vec!["secret/generic-assignment"]);
        let hits = detect("deploy/.env.production", "API_KEY=9fK2xQ7mZp4LwR8v\n");
        assert_eq!(ids(&hits), vec!["secret/generic-assignment"]);
        let hits = detect("k8s/app.yaml", "  client_secret: Zx9Qp2Lm7Kw4Rt8V\n");
        assert_eq!(ids(&hits), vec!["secret/generic-assignment"]);
    }

    #[test]
    fn random_keys_starting_with_a_capital_are_not_mistaken_for_identifiers() {
        let hits = detect("app.js", "const apiKey = \"Xk9mPqR2sT7vW3yZ5aB8\";\n");
        assert_eq!(ids(&hits), vec!["secret/generic-assignment"]);
    }

    #[test]
    fn placeholders_references_and_identifiers_are_ignored() {
        let clean = [
            ("app.py", "password = os.environ[\"DB_PASSWORD\"]"),
            ("app.py", "password = \"changeme123\""),
            ("app.py", "api_key = \"<your-api-key>\""),
            ("app.py", "token = \"${GITHUB_TOKEN}\""),
            ("blueprint.txt", "\"api_key\": \"env:OPENROUTER_API_KEY\","),
            ("app.js", "const SECRET_KEY = \"SECRET_KEY_NAME\";"),
            ("app.js", "const passwordField = \"user-password-input\";"),
            ("app.py", "token_url = \"https://example.com/oauth/token\""),
            ("app.py", "max_tokens = \"40960000\""),
            ("app.py", "password = \"xxxxxxxxxxxx\""),
            (
                "app.py",
                "api_secret = \"a1b2c3d4e5f67890abcdef1234567890\"",
            ),
            ("app.rs", "let secret = \"my-api-key-12345\";"),
            ("app.py", "password = \"Qwerty!2024\""),
            (".env", "DATABASE_PASSWORD=${DB_PASS}"),
            (".env", "SECRET_KEY="),
            ("docs/setup.md", "password = \"Tr0ub4dor&3xq\""),
            ("tests/test_db.py", "password = \"Tr0ub4dor&3xq\""),
            (".env.example", "API_KEY=9fK2xQ7mZp4LwR8v"),
            (
                "app.py",
                &format!(
                    "aws_access_key_id = \"{}\"",
                    tok(&["AKIA", "IOSFODNN7EXAMPLE"])
                ),
            ),
            (
                "app.py",
                "url = \"postgres://user:${PGPASSWORD}@db:5432/app\"",
            ),
        ];
        for (path, content) in clean {
            let hits = detect(path, content);
            assert!(hits.is_empty(), "{path}: {content} -> {:?}", ids(&hits));
        }
    }

    #[test]
    fn context_lines_never_show_another_secret() {
        let stripe = tok(&["sk_live_", "4eC39HqLyjWDarjtT1zdp7dcXyZ"]);
        let db = tok(&["postgres://admin:", "Pr0dPassw0rd9", "@db:5432/app"]);
        let content = format!("DATABASE_URL={db}\nSTRIPE_KEY={stripe}\n");
        let findings = detect(".env", &content);
        assert_eq!(findings.len(), 2);
        let all = serde_json::to_string(&findings).unwrap();
        assert!(!all.contains("Pr0dPassw0rd9"), "{all}");
        assert!(!all.contains(&stripe), "{all}");
    }

    #[test]
    fn provider_tokens_are_still_reported_in_tests() {
        let gh = tok(&["ghp_", "R8d2kLq9ZxT4mWn7Bv1Cy6Pa3Hs5Je0Fu2Gk"]);
        assert_eq!(
            ids(&detect("tests/fixtures/repo.json", &gh)),
            vec!["secret/github-token"]
        );
    }

    #[test]
    fn rust_unit_tests_count_as_test_code() {
        let pw = tok(&["Tr0ub4", "dor&3xq"]);
        let gh = tok(&["ghp_", "R8d2kLq9ZxT4mWn7Bv1Cy6Pa3Hs5Je0Fu2Gk"]);
        let src = format!(
            "fn real() {{ let password = \"{pw}\"; }}\n\
             \n\
             #[cfg(test)]\n\
             mod tests {{\n\
             \x20   #[test]\n\
             \x20   fn hashes() {{\n\
             \x20       let password = \"{pw}\";\n\
             \x20       let token = \"{gh}\";\n\
             \x20   }}\n\
             }}\n\
             \n\
             #[tokio::test(flavor = \"multi_thread\")]\n\
             async fn more() {{ let secret = \"{pw}\"; }}\n"
        );
        let hits = detect("src/auth.rs", &src);
        assert_eq!(
            ids(&hits),
            vec!["secret/github-token", "secret/generic-assignment"],
            "provider tokens in tests are still reported; generic matches only outside them"
        );
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].message.ends_with("(in test code)"));
        assert_eq!(hits[1].location.start_line, 1);
        // Other languages are not parsed as Rust.
        assert_eq!(detect("src/auth.py", &src).len(), 4);
    }

    #[test]
    fn connection_strings_and_private_keys() {
        let dsn = tok(&[
            "dsn := \"postgres://admin:",
            "S3cr3tPw9",
            "@db.internal:5432/app\"",
        ]);
        let hits = detect("src/db.go", &dsn);
        assert_eq!(ids(&hits), vec!["secret/connection-string-password"]);
        let body = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun";
        let key = tok(&[
            "-----BEGIN ",
            "RSA PRIVATE KEY-----\n",
            body,
            "\nVZ2pPOVDOgBpT/SPsOq\n-----END RSA PRIVATE KEY-----\n",
        ]);
        let found = detect("deploy/key.pem", &key);
        assert_eq!(ids(&found), vec!["secret/private-key"]);
        let json = serde_json::to_string(&found).unwrap();
        assert!(!json.contains(body), "key material leaked: {json}");

        // Inside a JSON string, newlines are `\n` escapes.
        let escaped = tok(&[
            "{\"key\": \"-----BEGIN ",
            "PRIVATE KEY-----\\n",
            body,
            "\\n\"}",
        ]);
        assert_eq!(
            ids(&detect("creds.json", &escaped)),
            vec!["secret/private-key"]
        );

        // Documentation that only names the header is not a key.
        let docs = tok(&["Paste the -----BEGIN ", "PRIVATE KEY----- block here."]);
        assert!(detect("README.txt", &docs).is_empty());
    }

    #[test]
    fn non_ascii_content_does_not_panic_and_columns_count_characters() {
        let content =
            "# café ünïcödé\npassword = \"pässwörd-Ç9x2Lq\"\nnote = \"日本語のテキスト\"\n";
        let hits = detect("app.py", content);
        assert_eq!(ids(&hits), vec!["secret/generic-assignment"]);
        assert_eq!(hits[0].location.start_column, 13);
    }

    #[test]
    fn lockfiles_and_minified_files_are_skipped() {
        assert!(!SecretDetector::should_scan("web/package-lock.json"));
        assert!(!SecretDetector::should_scan("static/app.min.js"));
        assert!(SecretDetector::should_scan(".env"));
        assert!(SecretDetector::should_scan("config/prod.yaml"));
    }

    #[test]
    fn tokens_ending_in_dash_or_underscore_are_found() {
        let key = tok(&["AIza", "SyD3x9QmTz4LwR8vKp2Nc7Hj5Gf1Bd0Aex-"]);
        assert_eq!(key.len(), 39);
        assert_eq!(
            ids(&detect("app.js", &format!("const k = \"{key}\";"))),
            vec!["secret/google-api-key"]
        );
        // ...but not as a prefix of a longer string.
        assert!(detect("app.js", &format!("const k = \"{key}xyz\";")).is_empty());
    }

    #[test]
    fn newer_providers() {
        let cases = [
            (
                tok(&["GR1348941", "zx9Qp2Lm7Kw4Rt8VbN3c"]),
                "secret/gitlab-token",
            ),
            (
                tok(&[
                    "https://hooks.slack.com/workflows/",
                    "T05QK7MZP/A06RX2LWN/846201937564018273/",
                    "Zq8Xr3Lm7Kp2Wt9Vn4Bc6Hy1",
                ]),
                "secret/slack-webhook",
            ),
            (
                tok(&["api_org_", "ZqXrLmKpWtVnBcHyJdFsGaQeRtYuIoPlKw"]),
                "secret/huggingface-token",
            ),
            (
                tok(&[
                    "sk-ant-oat01-",
                    &"Zq8Xr3Lm7Kp2Wt9Vn4Bc6Hy1Jd5Fs0Ga".repeat(3)[..90],
                ]),
                "secret/anthropic-key",
            ),
            (
                tok(&["pypi-", "AgENdGVzdC5weXBpLm9yZw", &"Ab1Cd2Ef3Gh4".repeat(6)]),
                "secret/pypi-token",
            ),
        ];
        for (secret, rule) in cases {
            assert_eq!(
                ids(&detect("deploy.py", &format!("X = '{secret}'\n"))),
                vec![rule],
                "{rule}"
            );
        }
        // A fixed prefix does not make a repetitive fake look random.
        assert!(
            detect(
                "x.py",
                &format!("X = '{}'", tok(&["GR1348941", "12312312312312312312"]))
            )
            .is_empty()
        );
        let npmrc = tok(&[
            "//registry.npmjs.org/:_authToken=",
            "7f3c9e1b-5d8a-4f60-9e4b-c7d1a2f86b30",
        ]);
        assert_eq!(ids(&detect(".npmrc", &npmrc)), vec!["secret/npm-token"]);
        assert!(detect(".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}").is_empty());
    }

    #[test]
    fn more_assignment_shapes() {
        let pw = "Tr0ub4dor&3xq";
        for (path, line) in [
            ("app.py", format!("config[\"password\"] = \"{pw}\"")),
            ("app.py", format!("password: str = \"{pw}\"")),
            ("app.ts", format!("const password: string = \"{pw}\";")),
            ("app.js", format!("const password = `{pw}`;")),
            ("deploy.sh", format!("export DB_PASSWORD={pw}")),
            ("Dockerfile", format!("ENV DB_PASSWORD={pw}")),
            ("Dockerfile", format!("ENV DB_PASSWORD {pw}")),
            ("build/Dockerfile.prod", format!("ARG API_TOKEN={pw}")),
        ] {
            assert_eq!(
                ids(&detect(path, &line)),
                vec!["secret/generic-assignment"],
                "{path}: {line}"
            );
        }
        let redis = tok(&[
            "REDIS_URL = \"redis://:",
            "Sup3rS3cretPw",
            "@cache:6379/0\"",
        ]);
        assert_eq!(
            ids(&detect("app.py", &redis)),
            vec!["secret/connection-string-password"]
        );
    }

    #[test]
    fn indented_private_keys() {
        let body = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun";
        let yaml = tok(&[
            "tls:\n  key: |\n    -----BEGIN ",
            "RSA PRIVATE KEY-----\n    ",
            body,
            "\n    -----END RSA PRIVATE KEY-----\n",
        ]);
        let found = detect("deploy/values.yaml", &yaml);
        assert_eq!(ids(&found), vec!["secret/private-key"]);
        assert!(!serde_json::to_string(&found).unwrap().contains(body));
    }

    #[test]
    fn tests_and_docs_are_reported_at_lower_severity() {
        let gh = tok(&["ghp_", "R8d2kLq9ZxT4mWn7Bv1Cy6Pa3Hs5Je0Fu2Gk"]);
        let f = detect(
            "docs/api.md",
            &format!("curl -H 'Authorization: token {gh}'"),
        );
        assert_eq!(
            (f[0].rule_id.as_str(), f[0].severity),
            ("secret/github-token", Severity::Medium)
        );
        assert!(f[0].message.contains("test, example or documentation"));
        let key = tok(&[
            "-----BEGIN ",
            "PRIVATE KEY-----\n",
            "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
            "\n",
        ]);
        assert_eq!(
            detect("tests/data/key.pem", &key)[0].severity,
            Severity::Low
        );
        assert_eq!(
            detect("deploy/key.pem", &key)[0].severity,
            Severity::Critical
        );
    }

    #[test]
    fn generic_false_positive_shapes() {
        for (path, line) in [
            ("app.py", "private_key_checksum = \"9f2c4e1b7a3d5f60\""),
            (
                "app.js",
                "const tokenAddress = \"0x6B175474E89094C44Da98b954EedeAC495271d0F\";",
            ),
            (
                "app.py",
                "token_sha256 = \"3f9a1c5e7b2d4f6081a3c5e7b9d1f3a5\"",
            ),
            ("web/locales/fr.json", "\"password\": \"Mot-de-passe9\""),
        ] {
            assert!(detect(path, line).is_empty(), "{path}: {line}");
        }
        // A private key in hex is still a private key.
        let eth = tok(&[
            "private_key = \"0x",
            "4c0883a69102937d6231471b5dbb6204fe512961708279f2e3e8a5d4b8e3e2ab\"",
        ]);
        assert_eq!(
            ids(&detect("deploy.py", &eth)),
            vec!["secret/generic-assignment"]
        );
    }

    #[test]
    fn binary_files_get_provider_patterns_only() {
        let gh = tok(&["ghp_", "R8d2kLq9ZxT4mWn7Bv1Cy6Pa3Hs5Je0Fu2Gk"]);
        let content = format!("\n\n\x01\x02 {gh} \npassword = \"Tr0ub4dor&3xq\"");
        let f = SecretDetector::new()
            .detect_binary("assets/app.bin", &content)
            .findings;
        assert_eq!(ids(&f), vec!["secret/github-token"]);
        assert!(f[0].message.contains("binary"));
        assert!(f[0].snippet.is_none());
    }

    #[test]
    fn fingerprints_do_not_depend_on_the_secret() {
        let a = detect("app.py", "password = \"Tr0ub4dor&3xq\"\n");
        let b = detect("app.py", "password = \"Zx9Qp2Lm7Kw4!\"\n");
        assert_eq!(a[0].fingerprint, b[0].fingerprint);
    }

    #[test]
    fn masker_handles_overlaps_and_many_values() {
        let m = Masker::new(&["abcdefghijklmnopq".into(), "abcdefgh".into()]);
        assert_eq!(
            m.mask("x abcdefghijklmnopq y abcdefgh"),
            "x ******** y ********"
        );
        assert_eq!(m.redact("abcdefghijklmnopq"), "abcd********");
        let many: Vec<String> = (0..20_000).map(|i| format!("tok{i:08}x")).collect();
        let m = Masker::new(&many);
        assert!(m.is_match("... tok00019999x ..."));
        assert!(!Masker::new(&[]).is_match("anything"));
    }

    #[test]
    fn entropy() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn redaction_does_not_reveal_length() {
        assert_eq!(redact("short"), "********");
        assert_eq!(redact("ghp_abcdefghijklmnop"), "ghp_********");
        assert_eq!(redact("ghp_abcdefghijklmnopqrstuvwxyz"), "ghp_********");
    }
}
