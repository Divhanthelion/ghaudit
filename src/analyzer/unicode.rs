//! Invisible and direction-changing Unicode.
//!
//! - **Trojan Source** (CVE-2021-42574): bidirectional control characters make code
//!   display differently from how the compiler reads it.
//! - **Hidden instructions for AI agents** ("Rules File Backdoor", 2025): zero-width
//!   and Unicode tag characters smuggle text a human reviewer cannot see into files
//!   such as `.cursorrules`, `CLAUDE.md` or MCP configs, which coding agents follow.

use crate::discovery::Language;
use crate::model::{Category, Confidence, Finding, Location, Severity, Snippet};

/// Files AI coding agents read as instructions or tool configuration.
pub fn is_agent_file(rel_path: &str) -> bool {
    let name = rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "agents.md"
            | "claude.md"
            | "gemini.md"
            | ".cursorrules"
            | ".windsurfrules"
            | ".clinerules"
            | "copilot-instructions.md"
            | ".mcp.json"
            | "mcp.json"
    ) || (rel_path.contains(".cursor/rules/") && name.ends_with(".mdc"))
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn is_tag(c: char) -> bool {
    matches!(c, '\u{E0000}'..='\u{E007F}')
}

fn is_zero_width(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
    )
}

/// Scan source code and agent files. Prose (e.g. Markdown in RTL languages) legitimately
/// uses these characters, so other files are left alone.
pub fn applies_to(rel_path: &str, language: Option<Language>) -> bool {
    language.is_some() || is_agent_file(rel_path)
}

pub fn detect(rel_path: &str, content: &str) -> Vec<Finding> {
    let agent = is_agent_file(rel_path);
    let mut findings = Vec::new();
    for (i, line) in content.lines().enumerate() {
        // A byte-order mark at the very start of a file is normal.
        let line = if i == 0 {
            line.trim_start_matches('\u{FEFF}')
        } else {
            line
        };
        // Tag characters are also used by subdivision flag emoji (🏴 + tags).
        let flag_emoji = line.contains('\u{1F3F4}');
        let Some((col, c)) = line.chars().enumerate().find(|&(_, c)| {
            is_bidi(c) || (is_tag(c) && !flag_emoji) || (agent && is_zero_width(c))
        }) else {
            continue;
        };
        let (rule, title, message, severity) = if is_bidi(c) {
            (
                "unicode/bidi-control",
                "Bidirectional control character",
                format!(
                    "U+{:04X} reorders how this line is displayed, so reviewers can see different code than the compiler runs (Trojan Source).",
                    c as u32
                ),
                Severity::High,
            )
        } else {
            (
                "unicode/invisible-text",
                "Invisible characters",
                format!(
                    "U+{:04X} is invisible. In {} it can carry text that tools and AI agents read but people reviewing the file cannot see.",
                    c as u32,
                    if agent {
                        "an AI agent instruction file"
                    } else {
                        "source code"
                    }
                ),
                if agent || is_tag(c) {
                    Severity::High
                } else {
                    Severity::Medium
                },
            )
        };
        let visible: String = line
            .chars()
            .map(|ch| {
                if is_bidi(ch) || is_tag(ch) || is_zero_width(ch) {
                    format!("<U+{:04X}>", ch as u32)
                } else {
                    ch.to_string()
                }
            })
            .collect();
        let mut snippet = Snippet::around(content, i + 1, 0);
        if let Some(s) = &mut snippet {
            s.lines = vec![visible.clone()];
        }
        findings.push(
            Finding::new(rule, Category::Sast, severity, Confidence::High, title, message, Location::new(rel_path, i + 1, col + 1), &visible)
                .with_snippet(snippet)
                .with_cwe(["CWE-451"])
                .with_remediation("Remove the character, or replace it with a visible escape sequence if it is needed in a string."),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trojan_source_in_code() {
        let src = "let access = \"user\u{202E} \u{2066}// admin\u{2069} \u{2066}\";\n";
        let f = detect("src/auth.rs", src);
        assert_eq!(f.len(), 1, "one finding per line");
        assert_eq!(f[0].rule_id, "unicode/bidi-control");
        assert_eq!(f[0].location.start_column, 19);
        assert!(f[0].snippet.as_ref().unwrap().lines[0].contains("<U+202E>"));
    }

    #[test]
    fn hidden_instructions_in_agent_files() {
        let hidden: String = "ignore previous"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        let f = detect(".cursorrules", &format!("Use TypeScript.{hidden}\n"));
        assert_eq!(
            (f[0].rule_id.as_str(), f[0].severity),
            ("unicode/invisible-text", Severity::High)
        );
        let f = detect("CLAUDE.md", "Run tests\u{200B}\u{200B} first\n");
        assert_eq!(f[0].rule_id, "unicode/invisible-text");
        assert!(is_agent_file(".cursor/rules/style.mdc"));
    }

    #[test]
    fn legitimate_uses_are_ignored() {
        assert!(
            detect("src/a.rs", "\u{FEFF}fn main() {}\n").is_empty(),
            "leading BOM"
        );
        assert!(detect("src/a.js", "const flag = \"\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}\";\n").is_empty());
        assert!(
            detect("src/a.js", "const family = \"👨\u{200D}👩\";\n").is_empty(),
            "ZWJ emoji in code"
        );
        assert!(!applies_to("docs/arabic.md", None));
    }
}
