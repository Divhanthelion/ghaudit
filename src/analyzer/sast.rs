//! Rule engine: parses source files with tree-sitter and runs each language's rules.
//!
//! A rule is a tree-sitter query (a pattern over the syntax tree, not over raw text),
//! so `eval(x)` in code matches but the word "eval" in a comment or string does not.
//! Queries are compiled once per grammar when the engine is built; parsers are
//! cached per thread because analysis runs on a rayon thread pool.
//!
//! Parsing and querying run under a per-file time budget: input crafted to make
//! tree-sitter slow (deep nesting, huge generated files) costs at most that long, and
//! the file is reported as not fully analyzed.

use super::rules::{self, Rule, RuleLanguage};
use crate::discovery::Language;
use crate::model::{Category, Finding, LineIndex, Location, Snippet};
use regex::Regex;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use streaming_iterator::StreamingIterator;
use tree_sitter::{
    ParseOptions, Parser, Query, QueryCursor, QueryCursorOptions, QueryPredicateArg,
};

/// Lines of context on each side of a finding.
const SNIPPET_CONTEXT: usize = 2;
/// Time for parsing and running every rule on one file. Real files take milliseconds.
pub const FILE_BUDGET: Duration = Duration::from_secs(5);

/// Findings for one file.
#[derive(Debug, Default)]
pub struct SastResult {
    pub findings: Vec<Finding>,
    /// Analysis stopped early (time budget exceeded or scan cancelled).
    pub incomplete: bool,
}

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
    /// The rule's `bindings` query and the index of its `@var` capture.
    bindings: Option<(Query, u32)>,
}

/// Nodes that start a new variable scope, per grammar.
fn is_scope(kind: &str) -> bool {
    matches!(
        kind,
        // Python
        "function_definition" | "lambda"
        // JavaScript / TypeScript
        | "function_declaration" | "function_expression" | "function" | "arrow_function"
        | "method_definition" | "generator_function_declaration" | "generator_function"
        // Go
        | "method_declaration" | "func_literal"
        // Rust
        | "function_item" | "closure_expression"
    )
}

fn scope_of(node: tree_sitter::Node) -> usize {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if is_scope(parent.kind()) {
            return parent.id();
        }
        current = parent;
    }
    current.id()
}

/// Variables (scope, name) assigned a dangerous value, with where each assignment starts.
type Bound = HashMap<(usize, String), Vec<usize>>;

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
        self.analyze_with(path, language, source, &AtomicBool::new(false))
            .findings
    }

    /// Run every applicable rule over one file, within [`FILE_BUDGET`], stopping early
    /// when `cancel` is set.
    pub fn analyze_with(
        &self,
        path: &str,
        language: Language,
        source: &str,
        cancel: &AtomicBool,
    ) -> SastResult {
        let mut out = SastResult::default();
        let Some(rules) = self.rules.get(&language) else {
            return out;
        };
        let deadline = Instant::now() + FILE_BUDGET;
        let expired = || cancel.load(Ordering::Relaxed) || Instant::now() > deadline;
        let Some(tree) = parse(language, source, &expired) else {
            out.incomplete = true;
            return out;
        };
        let index = LineIndex::new(source);
        let mut seen = HashSet::new();
        let mut cursor = QueryCursor::new();
        let mut stop = |_: &tree_sitter::QueryCursorState| {
            if expired() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };

        for compiled in rules {
            if expired() {
                out.incomplete = true;
                break;
            }
            if let Some(re) = &compiled.requires
                && !re.is_match(source)
            {
                continue;
            }
            let bound = match &compiled.bindings {
                Some((query, var)) => {
                    let mut bound = Bound::new();
                    let mut matches = cursor.matches_with_options(
                        query,
                        tree.root_node(),
                        source.as_bytes(),
                        QueryCursorOptions::new().progress_callback(&mut stop),
                    );
                    while let Some(m) = matches.next() {
                        for c in m.captures.iter().filter(|c| c.index == *var) {
                            let name = source[c.node.byte_range()].to_string();
                            bound
                                .entry((scope_of(c.node), name))
                                .or_default()
                                .push(c.node.start_byte());
                        }
                    }
                    bound
                }
                None => Bound::new(),
            };
            let mut matches = cursor.matches_with_options(
                &compiled.query,
                tree.root_node(),
                source.as_bytes(),
                QueryCursorOptions::new().progress_callback(&mut stop),
            );
            while let Some(m) = matches.next() {
                let Some(capture) = m
                    .captures
                    .iter()
                    .find(|c| c.index == compiled.finding_capture)
                else {
                    continue;
                };
                let all_bound = compiled
                    .query
                    .general_predicates(m.pattern_index)
                    .iter()
                    .all(|p| match p.args.first() {
                        Some(QueryPredicateArg::Capture(i)) => {
                            m.captures.iter().filter(|c| c.index == *i).all(|c| {
                                let name = &source[c.node.byte_range()];
                                bound
                                    .get(&(scope_of(c.node), name.to_string()))
                                    .is_some_and(|at| at.iter().any(|&s| s < c.node.start_byte()))
                            })
                        }
                        _ => false,
                    });
                if !all_bound {
                    continue;
                }
                let node = capture.node;
                // Alternations in a query can match the same node more than once.
                if !seen.insert((compiled.rule.id, node.start_byte())) {
                    continue;
                }
                let start = node.start_position();
                let end = node.end_position();
                let line = start.row + 1;
                let line_text = index.line(line).unwrap_or_default();
                // tree-sitter columns count bytes; reports count characters.
                let column = char_column(line_text, start.column);
                let end_column =
                    char_column(index.line(end.row + 1).unwrap_or_default(), end.column);
                let rule = compiled.rule;
                out.findings.push(
                    Finding::new(
                        rule.id,
                        Category::Sast,
                        rule.severity,
                        rule.confidence,
                        rule.name,
                        rule.message,
                        Location::new(path, line, column).with_end(end.row + 1, end_column),
                        line_text,
                    )
                    .with_snippet(Snippet::from_index(&index, line, column, SNIPPET_CONTEXT))
                    .with_cwe(rule.cwe.iter().copied())
                    .with_remediation(rule.remediation),
                );
            }
        }
        if expired() {
            out.incomplete = true;
        }
        out
    }
}

/// 1-based character column of a byte offset within a line.
fn char_column(line: &str, byte: usize) -> usize {
    line.get(..byte).map_or(byte, |s| s.chars().count()) + 1
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
    let bindings = match rule.bindings {
        Some(text) => {
            let q = Query::new(&grammar(lang), text).map_err(|e| {
                format!("rule {} bindings do not compile for {lang:?}: {e}", rule.id)
            })?;
            let var = q
                .capture_index_for_name("var")
                .ok_or_else(|| format!("rule {} bindings have no @var capture", rule.id))?;
            Some((q, var))
        }
        None => None,
    };
    for i in 0..query.pattern_count() {
        for p in query.general_predicates(i) {
            let ok = &*p.operator == "bound?"
                && bindings.is_some()
                && matches!(p.args.as_ref(), [QueryPredicateArg::Capture(_)]);
            if !ok {
                return Err(format!(
                    "rule {}: unsupported predicate #{} (only #bound? @capture, with `bindings`)",
                    rule.id, p.operator
                ));
            }
        }
    }
    Ok(CompiledRule {
        rule,
        query,
        finding_capture,
        requires,
        bindings,
    })
}

fn parse(
    language: Language,
    source: &str,
    expired: &dyn Fn() -> bool,
) -> Option<tree_sitter::Tree> {
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
        let bytes = source.as_bytes();
        let mut stop = |_: &tree_sitter::ParseState| {
            if expired() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let tree = parser.parse_with_options(
            &mut |i, _| bytes.get(i..).unwrap_or_default(),
            None,
            Some(ParseOptions::new().progress_callback(&mut stop)),
        );
        if tree.is_none() {
            // A halted parse would otherwise resume on the next call.
            parser.reset();
        }
        tree
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
    fn columns_count_characters_not_bytes() {
        let src = "msg = \"héllo wörld\"; eval(x)\n";
        let f = engine().analyze("a.py", Language::Python, src);
        let eval = f.iter().find(|f| f.rule_id == "python/eval").unwrap();
        assert_eq!(eval.location.start_column, 22);
    }

    #[test]
    fn cancelled_analysis_is_marked_incomplete() {
        let cancel = AtomicBool::new(true);
        let r = engine().analyze_with("a.py", Language::Python, "eval(x)\n", &cancel);
        assert!(r.incomplete);
        assert!(r.findings.is_empty());
        // The thread's cached parser still works afterwards.
        assert_eq!(
            engine()
                .analyze("a.py", Language::Python, "eval(x)\n")
                .len(),
            1
        );
    }

    #[test]
    fn comments_and_strings_do_not_match() {
        let src = "# os.system(cmd)\nmsg = \"eval(user_input)\"\n";
        assert!(engine().analyze("a.py", Language::Python, src).is_empty());
    }
}
