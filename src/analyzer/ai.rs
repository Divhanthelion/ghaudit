//! Optional LLM review through any OpenAI-compatible chat endpoint
//! (LM Studio, Ollama, llama.cpp server, vLLM, ...).
//!
//! Model output is advisory: findings are tagged `ai`, confidence is capped at
//! medium, and line numbers the model invents are clamped to the file.

use crate::config::AiConfig;
use crate::discovery::Language;
use crate::model::{Category, Confidence, Finding, Location, Severity, Snippet};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Characters of source sent per request; long files are cut at a line boundary.
const MAX_SOURCE_CHARS: usize = 12_000;

const SYSTEM_PROMPT: &str = r#"You are a meticulous application security reviewer.
Report only concrete, exploitable security vulnerabilities in the code you are given:
injection, unsafe deserialization, path traversal, SSRF, authentication or authorization
flaws, cryptographic misuse, and secrets. Do not report style issues, missing tests,
or speculative problems. If there is nothing to report, return an empty list.

Reply with JSON only, in exactly this shape:
{"findings": [{"title": "SQL injection", "severity": "high", "confidence": "medium",
"line": 42, "description": "...", "remediation": "...", "cwe": "CWE-89"}]}
severity is one of critical, high, medium, low. confidence is one of high, medium, low.
line is the 1-based line number in the file as shown."#;

pub struct AiAnalyzer {
    client: Client,
    url: String,
    model: String,
}

impl AiAnalyzer {
    pub fn new(config: &AiConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            client,
            url: config.url.clone(),
            model: config.model.clone(),
        })
    }

    /// Verify the endpoint answers before sending every file to it.
    pub async fn check(&self) -> Result<(), String> {
        let models = self.url.replace("/chat/completions", "/models");
        match self
            .client
            .get(&models)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => Ok(()),
            Ok(r) => Err(format!("{models} answered {}", r.status())),
            Err(e) => Err(format!("no OpenAI-compatible server at {}: {e}", self.url)),
        }
    }

    pub async fn analyze(
        &self,
        path: &str,
        language: Language,
        source: &str,
    ) -> Result<Vec<Finding>, String> {
        let (code, truncated) = truncate_at_line(source, MAX_SOURCE_CHARS);
        let numbered: String = code
            .lines()
            .enumerate()
            .map(|(i, l)| format!("{:>5} {l}\n", i + 1))
            .collect();
        let note = if truncated {
            "\n(The file is truncated; review only what is shown.)"
        } else {
            ""
        };
        let user = format!(
            "File: {path}\nLanguage: {}\n\n```\n{numbered}```{note}",
            language.config_name()
        );

        let request = ChatRequest {
            model: &self.model,
            temperature: 0.0,
            messages: vec![
                Message {
                    role: "system",
                    content: SYSTEM_PROMPT.to_string(),
                },
                Message {
                    role: "user",
                    content: user,
                },
            ],
        };
        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("{} answered {}", self.url, response.status()));
        }
        let body: ChatResponse = response.json().await.map_err(|e| e.to_string())?;
        let content = body
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .unwrap_or_default();
        Ok(parse_findings(&content, path, source))
    }
}

/// Turn the model's reply into findings. Malformed replies yield no findings.
pub fn parse_findings(reply: &str, path: &str, source: &str) -> Vec<Finding> {
    let Some(items) = extract_items(reply) else {
        return Vec::new();
    };
    let line_count = source.lines().count().max(1);
    items
        .into_iter()
        .filter(|i| !i.title.trim().is_empty())
        .map(|item| {
            let line = item.line.unwrap_or(1).clamp(1, line_count);
            let severity = item.severity.parse::<Severity>().unwrap_or(Severity::Low);
            let confidence = match item.confidence.to_ascii_lowercase().as_str() {
                "high" | "medium" => Confidence::Medium,
                _ => Confidence::Low,
            };
            let line_text = source.lines().nth(line - 1).unwrap_or_default();
            let mut f = Finding::new(
                format!("ai/{}", slug(&item.title)),
                Category::Ai,
                severity,
                confidence,
                item.title.trim(),
                if item.description.trim().is_empty() {
                    item.title.trim()
                } else {
                    item.description.trim()
                },
                Location::new(path, line, 1),
                &format!("{}|{line_text}", item.title),
            )
            .with_snippet(Snippet::around(source, line, 2));
            if let Some(cwe) = item.cwe.filter(|c| c.starts_with("CWE-")) {
                f = f.with_cwe([cwe]);
            }
            if !item.remediation.trim().is_empty() {
                f = f.with_remediation(item.remediation.trim());
            }
            f
        })
        .collect()
}

/// Accept `{"findings": [...]}`, `{"vulnerabilities": [...]}` or a bare array, optionally
/// wrapped in a markdown code fence or surrounded by prose.
fn extract_items(reply: &str) -> Option<Vec<Item>> {
    #[derive(Deserialize)]
    struct Wrapper {
        #[serde(alias = "vulnerabilities")]
        findings: Vec<Item>,
    }
    let candidates = [
        reply
            .find('{')
            .zip(reply.rfind('}'))
            .map(|(s, e)| &reply[s..=e]),
        reply
            .find('[')
            .zip(reply.rfind(']'))
            .map(|(s, e)| &reply[s..=e]),
    ];
    for candidate in candidates.into_iter().flatten() {
        if let Ok(w) = serde_json::from_str::<Wrapper>(candidate) {
            return Some(w.findings);
        }
        if let Ok(items) = serde_json::from_str::<Vec<Item>>(candidate) {
            return Some(items);
        }
    }
    None
}

fn slug(title: &str) -> String {
    let mut out = String::new();
    for c in title.to_ascii_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out = out.trim_end_matches('-');
    if out.is_empty() {
        "issue".into()
    } else {
        out.chars().take(48).collect()
    }
}

/// Cut `s` to at most `max` characters, at a line boundary when possible.
fn truncate_at_line(s: &str, max: usize) -> (&str, bool) {
    match s.char_indices().nth(max) {
        None => (s, false),
        Some((byte, _)) => {
            let cut = s[..byte].rfind('\n').unwrap_or(byte);
            (&s[..cut], true)
        }
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    temperature: f32,
    messages: Vec<Message>,
}

#[derive(Serialize, Deserialize)]
struct Message {
    role: &'static str,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ReplyMessage,
}

#[derive(Deserialize)]
struct ReplyMessage {
    #[serde(default)]
    content: String,
}

#[derive(Deserialize)]
struct Item {
    #[serde(default, alias = "vulnerability_type")]
    title: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    line: Option<usize>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    remediation: String,
    #[serde(default, alias = "cwe_id")]
    cwe: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "import os\nq = input()\nos.system(q)\n";

    #[test]
    fn parses_fenced_object_and_clamps_lines() {
        let reply = "Here you go:\n```json\n{\"findings\": [{\"title\": \"Command Injection\", \"severity\": \"critical\", \"confidence\": \"high\", \"line\": 99, \"description\": \"input reaches os.system\", \"remediation\": \"use a list\", \"cwe\": \"CWE-78\"}]}\n```";
        let f = parse_findings(reply, "a.py", SRC);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "ai/command-injection");
        assert_eq!(f[0].category, Category::Ai);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(
            f[0].confidence,
            Confidence::Medium,
            "model confidence is capped"
        );
        assert_eq!(
            f[0].location.start_line, 3,
            "line 99 clamped to the last line"
        );
        assert_eq!(f[0].cwe, vec!["CWE-78"]);
    }

    #[test]
    fn accepts_the_legacy_array_shape() {
        let reply = "[{\"vulnerability_type\": \"SQL Injection\", \"severity\": \"high\", \"confidence\": \"low\", \"line\": 2, \"description\": \"d\", \"cwe_id\": \"CWE-89\"}]";
        let f = parse_findings(reply, "a.py", SRC);
        assert_eq!(f[0].title, "SQL Injection");
        assert_eq!(f[0].confidence, Confidence::Low);
    }

    #[test]
    fn garbage_and_empty_replies_yield_nothing() {
        assert!(parse_findings("I could not find anything.", "a.py", SRC).is_empty());
        assert!(parse_findings("{\"findings\": []}", "a.py", SRC).is_empty());
    }

    #[test]
    fn truncation_is_utf8_safe() {
        let s = "é\n".repeat(10);
        let (cut, truncated) = truncate_at_line(&s, 5);
        assert!(truncated);
        assert_eq!(cut, "é\né");
        assert_eq!(truncate_at_line("short", 100), ("short", false));
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("SQL Injection (blind)"), "sql-injection-blind");
        assert_eq!(slug("!!!"), "issue");
    }
}
