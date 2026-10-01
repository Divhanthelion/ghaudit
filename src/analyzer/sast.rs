//! Rule engine: parses source files with tree-sitter and runs each language's rules.
//!
//! A rule is a tree-sitter query (a pattern over the syntax tree, not over raw text),
//! so `eval(x)` in code matches but the word "eval" in a comment or string does not.
//! Queries are compiled once per grammar when the engine is built; parsers are
//! cached per thread because analysis runs on a rayon thread pool.

use super::rules::{self, Rule, RuleLanguage};
use crate::discovery::Language;
use crate::model::{Category, Finding, Location, Snippet};
use regex::Regex;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

/// Lines of context on each side of a finding.
const SNIPPET_CONTEXT: usize = 2;

thread_local! {
    static PARSERS: RefCell<HashMap<Language, Parser>> = RefCell::new(HashMap::new());
}

fn grammar(language: Language) -> tree_sitter::Language {
    match language {
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
    }
}

/// Grammars a rule written for `lang` runs against.
fn grammars_for(lang: RuleLanguage) -> &'static [Language] {
    match lang {
        RuleLanguage::Rust => &[Language::Rust],
        RuleLanguage::Python => &[Language::Python],
        RuleLanguage::JavaScript => &[Language::JavaScript, Language::TypeScript, Language::Tsx],
        RuleLanguage::Go => &[Language::Go],
    }
}

struct CompiledRule {
    rule: &'static Rule,
    query: Query,
    /// Index of the `@finding` capture: the node whose position is reported.
    finding_capture: u32,
    requires: Option<Regex>,
}

pub struct SastEngine {
    rules: HashMap<Language, Vec<CompiledRule>>,
}

impl SastEngine {
    /// Build an engine for the given configured language names (`rust`, `typescript`, ...).
    pub fn new(languages: &[String]) -> Result<Self, String> {
        let mut by_grammar: HashMap<Language, Vec<CompiledRule>> = HashMap::new();
        for rule in rules::all() {
            for &lang in grammars_for(rule.language) {
                if !languages.iter().any(|l| l == lang.config_name()) {
                    continue;
                }
                // JSX-only rules have no meaning in plain TypeScript.
                if rule.jsx && lang == Language::TypeScript {
                    continue;
                }
                by_grammar
                    .entry(lang)
                    .or_default()
                    .push(compile(rule, lang)?);
            }
        }
        Ok(Self { rules: by_grammar })
    }

    /// Whether any rule applies to files of this language.
    pub fn handles(&self, language: Language) -> bool {
        self.rules.contains_key(&language)
    }

    /// Run every applicable rule over one file.
    pub fn analyze(&self, path: &str, language: Language, source: &str) -> Vec<Finding> {
        let Some(rules) = self.rules.get(&language) else {
            return Vec::new();
        };
        let Some(tree) = parse(language, source) else {
            return Vec::new();
        };
        let lines: Vec<&str> = source.lines().collect();
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let mut cursor = QueryCursor::new();

        for compiled in rules {
            if let Some(re) = &compiled.requires
                && !re.is_match(source)
            {
                continue;
            }
            let mut matches = cursor.matches(&compiled.query, tree.root_node(), source.as_bytes());
            while let Some(m) = matches.next() {
                let Some(capture) = m
                    .captures
                    .iter()
                    .find(|c| c.index == compiled.finding_capture)
                else {
                    continue;
                };
                let node = capture.node;
                // Alternations in a query can match the same node more than once.
                if !seen.insert((compiled.rule.id, node.start_byte())) {
                    continue;
                }
                let start = node.start_position();
                let end = node.end_position();
                let line = start.row + 1;
                let line_text = lines.get(start.row).copied().unwrap_or_default();
                let rule = compiled.rule;
                findings.push(
                    Finding::new(
                        rule.id,
                        Category::Sast,
                        rule.severity,
                        rule.confidence,
                        rule.name,
                        rule.message,
                        Location::new(path, line, start.column + 1)
                            .with_end(end.row + 1, end.column + 1),
                        line_text,
                    )
                    .with_snippet(Snippet::around(source, line, SNIPPET_CONTEXT))
                    .with_cwe(rule.cwe.iter().copied())
                    .with_remediation(rule.remediation),
                );
            }
        }
        findings
    }
}

fn compile(rule: &'static Rule, lang: Language) -> Result<CompiledRule, String> {
    let query = Query::new(&grammar(lang), rule.query)
        .map_err(|e| format!("rule {} does not compile for {lang:?}: {e}", rule.id))?;
    let finding_capture = query
        .capture_index_for_name("finding")
        .ok_or_else(|| format!("rule {} has no @finding capture", rule.id))?;
    let requires = rule
        .requires
        .map(Regex::new)
        .transpose()
        .map_err(|e| format!("rule {} has an invalid `requires` regex: {e}", rule.id))?;
    Ok(CompiledRule {
        rule,
        query,
        finding_capture,
        requires,
    })
}

fn parse(language: Language, source: &str) -> Option<tree_sitter::Tree> {
    PARSERS.with(|cell| {
        let mut parsers = cell.borrow_mut();
        let parser = match parsers.entry(language) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let mut p = Parser::new();
                p.set_language(&grammar(language)).ok()?;
                e.insert(p)
            }
        };
        parser.parse(source, None)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SUPPORTED_LANGUAGES;

    fn engine() -> SastEngine {
        let langs: Vec<String> = SUPPORTED_LANGUAGES.iter().map(|s| s.to_string()).collect();
        SastEngine::new(&langs).expect("all rules compile")
    }

    fn example_targets(rule: &Rule) -> Vec<(Language, &'static str)> {
        match rule.language {
            RuleLanguage::Rust => vec![(Language::Rust, "x.rs")],
            RuleLanguage::Python => vec![(Language::Python, "x.py")],
            RuleLanguage::Go => vec![(Language::Go, "x.go")],
            RuleLanguage::JavaScript if rule.jsx => {
                vec![(Language::JavaScript, "x.jsx"), (Language::Tsx, "x.tsx")]
            }
            RuleLanguage::JavaScript => vec![
                (Language::JavaScript, "x.js"),
                (Language::TypeScript, "x.ts"),
                (Language::Tsx, "x.tsx"),
            ],
        }
    }

    /// Every rule carries examples it must flag and near-misses it must not.
    /// This is the regression suite for the rule set.
    #[test]
    fn every_rule_matches_its_examples_and_not_its_counter_examples() {
        let engine = engine();
        let mut failures = Vec::new();
        for rule in rules::all() {
            assert!(!rule.examples.is_empty(), "{} has no examples", rule.id);
            assert!(
                !rule.counter_examples.is_empty(),
                "{} has no counter-examples",
                rule.id
            );
            for (lang, path) in example_targets(rule) {
                for ex in rule.examples {
                    let hits = engine.analyze(path, lang, ex);
                    if !hits.iter().any(|f| f.rule_id == rule.id) {
                        failures.push(format!("{} [{lang:?}] missed:\n{ex}", rule.id));
                    }
                }
                for ex in rule.counter_examples {
                    let hits = engine.analyze(path, lang, ex);
                    if hits.iter().any(|f| f.rule_id == rule.id) {
                        failures.push(format!("{} [{lang:?}] false positive on:\n{ex}", rule.id));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "\n{}", failures.join("\n\n"));
    }

    #[test]
    fn rule_ids_are_unique_and_namespaced() {
        let mut ids = HashSet::new();
        for rule in rules::all() {
            assert!(ids.insert(rule.id), "duplicate rule id {}", rule.id);
            let prefix = match rule.language {
                RuleLanguage::Rust => "rust/",
                RuleLanguage::Python => "python/",
                RuleLanguage::JavaScript => "js/",
                RuleLanguage::Go => "go/",
            };
            assert!(
                rule.id.starts_with(prefix),
                "{} should start with {prefix}",
                rule.id
            );
            assert!(!rule.cwe.is_empty(), "{} has no CWE", rule.id);
        }
    }

    #[test]
    fn findings_carry_position_snippet_and_metadata() {
        let src = "import os\n\n\ndef f(cmd):\n    os.system(cmd)\n";
        let findings = engine().analyze("app/run.py", Language::Python, src);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "python/os-command")
            .unwrap();
        assert_eq!((f.location.start_line, f.location.start_column), (5, 5));
        assert_eq!(f.location.path, "app/run.py");
        assert_eq!(f.cwe, vec!["CWE-78"]);
        let snippet = f.snippet.as_ref().unwrap();
        assert_eq!(snippet.first_line, 3);
        assert!(snippet.lines.iter().any(|l| l.contains("os.system")));
    }

    #[test]
    fn language_selection_limits_rules() {
        let engine = SastEngine::new(&["python".to_string()]).unwrap();
        assert!(engine.handles(Language::Python));
        assert!(!engine.handles(Language::Rust));
        assert!(
            engine
                .analyze("a.rs", Language::Rust, "fn f(){ unsafe { g() } }")
                .is_empty()
        );
    }

    #[test]
    fn comments_and_strings_do_not_match() {
        let src = "# os.system(cmd)\nmsg = \"eval(user_input)\"\n";
        assert!(engine().analyze("a.py", Language::Python, src).is_empty());
    }
}
