//! SAST rule definitions.
//!
//! Each rule is a tree-sitter query plus metadata. Every rule must:
//! - capture the reported node as `@finding`;
//! - list `examples` it flags and `counter_examples` (near-misses) it must not flag.
//!   The engine's tests run both lists, so a rule cannot silently stop working.
//!
//! The set favors precision over recall: a rule that fires on ordinary code trains
//! people to ignore the tool. Patterns that need data-flow tracking to be useful
//! (e.g. "any file read is path traversal") are deliberately left out.

mod go;
mod javascript;
mod python;
mod rust;

use crate::model::{Confidence, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleLanguage {
    Rust,
    Python,
    /// JavaScript rules also run on TypeScript and TSX.
    JavaScript,
    Go,
}

#[derive(Debug)]
pub struct Rule {
    pub id: &'static str,
    pub language: RuleLanguage,
    /// Short title shown in reports.
    pub name: &'static str,
    /// What was found and why it matters.
    pub message: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub cwe: &'static [&'static str],
    pub remediation: &'static str,
    /// Tree-sitter query; may contain several top-level patterns.
    pub query: &'static str,
    /// Only run when the file matches this regex (e.g. an import is present).
    pub requires: Option<&'static str>,
    /// Uses JSX syntax: skipped for plain `.ts` files.
    pub jsx: bool,
    pub examples: &'static [&'static str],
    pub counter_examples: &'static [&'static str],
}

/// Every rule, grouped by language.
pub fn all() -> impl Iterator<Item = &'static Rule> {
    rust::RULES
        .iter()
        .chain(python::RULES)
        .chain(javascript::RULES)
        .chain(go::RULES)
}
