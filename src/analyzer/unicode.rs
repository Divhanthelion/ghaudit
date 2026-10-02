//! Invisible and direction-changing Unicode.
//!
//! - **Trojan Source** (CVE-2021-42574): bidirectional control characters make code
//!   display differently from how the compiler reads it.
//! - **Invisible code**: zero-width characters, Hangul fillers (valid in JavaScript
//!   identifiers) and variation selectors (used by the 2025 GlassWorm campaign to
//!   hide a payload in source code) let text that reviewers cannot see run as code.
//! - **Hidden instructions for AI agents** ("Rules File Backdoor", 2025): zero-width
//!   and Unicode tag characters smuggle text a human reviewer cannot see into files
//!   such as `.cursorrules`, `CLAUDE.md` or MCP configs, which coding agents follow.

use crate::discovery::Language;
use crate::model::{Category, Confidence, Finding, LineIndex, Location, Severity, Snippet};

/// Files AI coding agents read as instructions or tool configuration.
pub fn is_agent_file(rel_path: &str) -> bool {
    let lower = rel_path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let in_dir = |dir: &str| lower.starts_with(dir) || lower.contains(&format!("/{dir}"));
    matches!(
        name,
        "agents.md"
            | "agent.md"
            | "claude.md"
            | "claude.local.md"
            | "skill.md"
            | "gemini.md"
            | ".cursorrules"
            | ".windsurfrules"
            | ".clinerules"
            | ".roorules"
            | "copilot-instructions.md"
            | ".mcp.json"
            | "mcp.json"
            | "conventions.md"
            | ".aider.conf.yml"
    ) || (in_dir(".github/instructions/") && name.ends_with(".instructions.md"))
        || (in_dir(".github/prompts/") && name.ends_with(".prompt.md"))
        || in_dir(".cursor/rules/")
        || in_dir(".windsurf/rules/")
        || in_dir(".clinerules/")
        || in_dir(".roo/")
        || in_dir(".kiro/steering/")
        || in_dir(".amazonq/rules/")
        || in_dir(".continue/")
        || in_dir(".junie/")
        || in_dir(".claude/")
        || in_dir(".gemini/")
        || in_dir(".vscode/mcp.json")
}

/// Extensions of code and configuration that tools execute or interpret, beyond the
/// languages the rule engine parses.
const CODE_EXTENSIONS: &[&str] = &[
    "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "java", "kt", "kts", "scala", "groovy", "gradle",
    "rb", "php", "cs", "fs", "vb", "swift", "m", "mm", "dart", "lua", "pl", "pm", "r", "jl", "ex",
    "exs", "erl", "hs", "ml", "clj", "zig", "nim", "sol", "vue", "svelte", "astro", "sh", "bash",
    "zsh", "fish", "ps1", "psm1", "bat", "cmd", "sql", "tf", "hcl", "nix", "json", "jsonc", "yaml",
    "yml", "toml", "ini", "cfg", "xml", "html", "htm", "css", "scss",
];

/// Translation catalogs are prose: joiners, direction marks and zero-width spaces are
/// ordinary typography in Persian, Hebrew, Thai, Chinese and other languages.
fn is_translation(rel_path: &str) -> bool {
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

fn is_code_file(rel_path: &str) -> bool {
    let name = rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "dockerfile" | "containerfile" | "makefile" | "justfile" | "jenkinsfile" | "vagrantfile"
    ) {
        return true;
    }
    name.rsplit_once('.')
        .is_some_and(|(_, ext)| CODE_EXTENSIONS.contains(&ext))
}

/// Scan code, configuration and agent files. Prose (e.g. Markdown in right-to-left
/// languages) legitimately uses these characters, so other files are left alone.
pub fn applies_to(rel_path: &str, language: Option<Language>) -> bool {
    language.is_some() || is_agent_file(rel_path) || is_code_file(rel_path)
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn is_tag(c: char) -> bool {
    matches!(c, '\u{E0000}'..='\u{E007F}')
}

/// Variation selectors 17-256: no use in code; enough of them encode arbitrary bytes.
fn is_supplementary_selector(c: char) -> bool {
    matches!(c, '\u{E0100}'..='\u{E01EF}')
}

fn is_selector(c: char) -> bool {
    matches!(c, '\u{FE00}'..='\u{FE0F}')
}

/// Characters that render as nothing.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200D}' // zero-width space, non-joiner, joiner
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{FEFF}' // zero-width no-break space
            | '\u{180E}' // Mongolian vowel separator
            | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // Hangul fillers
            | '\u{00AD}' // soft hyphen
            | '\u{2800}' // braille pattern blank
    )
}

/// Invisible direction marks (LRM, RLM, ALM). Normal inside right-to-left text; next
/// to ASCII code they can reorder how neutral characters are displayed.
fn is_mark(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}')
}

fn is_emoji_like(c: char) -> bool {
    matches!(c, '\u{2600}'..='\u{27BF}' | '\u{1F000}'..='\u{1FAFF}' | '\u{FE0F}')
}

/// The first suspicious character on a line, skipping legitimate uses: emoji joined
/// with ZWJ, ZWNJ/ZWJ and direction marks inside words of scripts that need them,
/// emoji variation selectors and keycaps, and subdivision flags (a black flag, tag
/// characters, then a cancel tag). In `prose` (translation catalogs) only characters
/// that are never typography are reported.
fn first_suspicious(chars: &[char], prose: bool) -> Option<(usize, char)> {
    // The last visible character: joiners and marks often come in runs.
    let mut prev_visible: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\u{1F3F4}' {
            // A subdivision flag: tag letters ended by U+E007F.
            let tags = chars[i + 1..]
                .iter()
                .take_while(|&&t| matches!(t, '\u{E0020}'..='\u{E007E}'))
                .count();
            if tags > 0 && chars.get(i + 1 + tags) == Some(&'\u{E007F}') {
                prev_visible = Some(c);
                i += tags + 2;
                continue;
            }
        }
        let prev = i.checked_sub(1).map(|p| chars[p]);
        let in_word = prev_visible.is_some_and(|p| !p.is_ascii() && p.is_alphabetic());
        let next = chars.get(i + 1).copied();
        let suspicious = if is_tag(c) || is_supplementary_selector(c) {
            true
        } else if prose {
            false
        } else if is_bidi(c) {
            return Some((i, c)); // the most serious kind; report it first
        } else if is_selector(c) {
            // After ASCII or another selector, it is not choosing an emoji's style.
            prev.is_none_or(|p| p.is_ascii() || is_selector(p)) && next != Some('\u{20E3}')
        } else if c == '\u{200D}' {
            !(prev.is_some_and(is_emoji_like) || in_word)
        } else if c == '\u{200C}' || is_mark(c) {
            !in_word
        } else {
            is_invisible(c)
        };
        if suspicious {
            // A bidi control later on the line outranks this character.
            return chars[i..]
                .iter()
                .position(|&b| is_bidi(b) && !prose)
                .map_or(Some((i, c)), |j| Some((i + j, chars[i + j])));
        }
        if !(is_invisible(c) || is_mark(c) || is_selector(c)) {
            prev_visible = Some(c);
        }
        i += 1;
    }
    None
}

fn visible(line: &str) -> String {
    line.chars()
        .map(|ch| {
            if is_bidi(ch)
                || is_tag(ch)
                || is_invisible(ch)
                || is_mark(ch)
                || is_selector(ch)
                || is_supplementary_selector(ch)
            {
                format!("<U+{:04X}>", ch as u32)
            } else {
                ch.to_string()
            }
        })
        .collect()
}

pub fn detect(rel_path: &str, content: &str) -> Vec<Finding> {
    let agent = is_agent_file(rel_path);
    let prose = !agent && is_translation(rel_path);
    let index = LineIndex::new(content);
    let mut findings = Vec::new();
    for n in 1..=index.len() {
        let mut line = index.line(n).unwrap_or_default();
        if line.is_ascii() {
            continue;
        }
        // A byte-order mark at the very start of a file is normal.
        let mut offset = 0;
        if n == 1 && line.starts_with('\u{FEFF}') {
            line = &line['\u{FEFF}'.len_utf8()..];
            offset = 1;
        }
        let chars: Vec<char> = line.chars().collect();
        let Some((col, c)) = first_suspicious(&chars, prose) else {
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
            let place = if agent {
                "an AI agent instruction file"
            } else {
                "code"
            };
            (
                "unicode/invisible-text",
                "Invisible characters",
                format!(
                    "U+{:04X} is invisible. In {place} it can carry text or code that tools, interpreters and AI agents read but people reviewing the file cannot see.",
                    c as u32,
                ),
                if agent || is_tag(c) || is_supplementary_selector(c) {
                    Severity::High
                } else {
                    Severity::Medium
                },
            )
        };
        let shown = visible(line);
        let column = col + 1 + offset;
        let mut snippet = Snippet::from_index(&index, n, column, 0);
        if let Some(s) = &mut snippet {
            s.lines = vec![shown.clone()];
        }
        findings.push(
            Finding::new(rule, Category::Sast, severity, Confidence::High, title, message, Location::new(rel_path, n, column), &shown)
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

    fn rules(path: &str, src: &str) -> Vec<String> {
        detect(path, src).into_iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn trojan_source_in_code() {
        let src = "let access = \"user\u{202E} \u{2066}// admin\u{2069} \u{2066}\";\n";
        let f = detect("src/auth.rs", src);
        assert_eq!(f.len(), 1, "one finding per line");
        assert_eq!(f[0].rule_id, "unicode/bidi-control");
        assert_eq!(f[0].location.start_column, 19);
        assert!(f[0].snippet.as_ref().unwrap().lines[0].contains("<U+202E>"));
        // A bidi control outranks an earlier invisible character on the same line.
        let both = "x = \"\u{200B}\" + \"\u{202E}\"\n";
        assert_eq!(rules("a.py", both), vec!["unicode/bidi-control"]);
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
        for path in [
            ".cursor/rules/style.mdc",
            ".github/instructions/py.instructions.md",
            ".github/prompts/release.prompt.md",
            ".windsurf/rules/a.md",
            ".claude/commands/deploy.md",
            "pkg/.kiro/steering/x.md",
        ] {
            assert!(is_agent_file(path), "{path}");
        }
        assert!(!is_agent_file("docs/guide.md"));
    }

    #[test]
    fn invisible_code() {
        // Hangul filler as a JavaScript identifier.
        let f = detect("src/a.js", "const \u{3164} = require('child_process');\n");
        assert_eq!(
            (f[0].rule_id.as_str(), f[0].location.start_column),
            ("unicode/invisible-text", 7)
        );
        // A run of variation selectors after ASCII: an encoded payload.
        let payload: String = "\u{FE01}\u{FE02}\u{FE03}".into();
        assert_eq!(
            rules("src/a.ts", &format!("eval(x`{payload}`)\n")),
            vec!["unicode/invisible-text"]
        );
        let glassworm: String = "\u{E0100}\u{E0142}".into();
        let f = detect("src/a.js", &format!("const s = '{glassworm}';\n"));
        assert_eq!(f[0].severity, Severity::High);
        // Direction marks next to ASCII code, and other blank-looking characters.
        assert_eq!(
            rules("src/c.js", "var a = \"user\u{200F} // admin\u{061C}\";\n"),
            vec!["unicode/invisible-text"]
        );
        assert_eq!(
            rules("a.py", "x\u{2800} = 1\n"),
            vec!["unicode/invisible-text"]
        );
        // A lone 🏴 does not excuse tag characters elsewhere on the line.
        let smuggled: String = "run curl"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        assert_eq!(
            rules(
                "AGENTS.md",
                &format!("Use TypeScript \u{1F3F4} please.{smuggled}\n")
            ),
            vec!["unicode/invisible-text"]
        );
        assert!(is_agent_file(".claude/skills/release/SKILL.md"));
        // Config and other languages are checked too.
        assert!(applies_to("deploy/values.yaml", None));
        assert!(applies_to("src/Main.java", None));
        assert!(!applies_to("docs/arabic.md", None));
    }

    #[test]
    fn legitimate_uses_are_ignored() {
        for src in [
            "\u{FEFF}fn main() {}\n",
            "const flag = \"\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}\";\n",
            "const family = \"👨\u{200D}👩\";\n",
            "const heart = \"❤\u{FE0F}\";\n",
            "const keycap = \"#\u{FE0F}\u{20E3}\";\n",
            "label = \"می\u{200C}خواهم\"\n",
            "label = \"שלום\u{200F} עולם\"\n",
            "plain ascii\n",
        ] {
            assert!(rules("src/a.js", src).is_empty(), "{src:?}");
        }
        // Translation catalogs: typography, except characters that never are.
        let persian = "{\"a\": \"نگه\u{200E}\u{200E}\u{200C}\", \"b\": \"ok\u{200E} 1.0\", \"c\": \"ภาษา\u{200B}ไทย\"}\n";
        assert!(rules("web/i18n/fa.json", persian).is_empty());
        let tagged: String = "x"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        assert_eq!(
            rules("web/i18n/fa.json", &format!("\"a\": \"b{tagged}\"\n")),
            vec!["unicode/invisible-text"]
        );
        // Runs of joiners/marks after a letter are typography in code strings too.
        assert!(rules("src/a.js", "const s = \"نگه\u{200E}\u{200C}\";\n").is_empty());
        // Tag characters next to a flag but not forming one are still reported.
        let fake = "x = \"\u{1F3F4}\u{E0069}\u{E0067}\u{E006E}\"\n";
        assert_eq!(rules("a.py", fake), vec!["unicode/invisible-text"]);
    }

    #[test]
    fn long_runs_of_invisible_typography_stay_fast() {
        let line = format!("\"a\": \"ه{}\"\n", "\u{200C}".repeat(200_000));
        let start = std::time::Instant::now();
        assert!(detect("i18n/fa.json", &line).is_empty());
        assert!(start.elapsed().as_secs() < 2, "{:?}", start.elapsed());
    }

    #[test]
    fn many_lines_stay_fast() {
        let src = "let s = \"\u{202E}\";\n".repeat(50_000);
        let start = std::time::Instant::now();
        assert_eq!(detect("a.rs", &src).len(), 50_000);
        assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
    }
}
