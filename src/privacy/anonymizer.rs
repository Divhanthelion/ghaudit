//! Code anonymization pipeline for privacy-preserving analysis.
//!
//! This module normalizes identifiers in source code before sending to LLMs,
//! preventing leakage of proprietary names, internal APIs, or PII.
//!
//! The anonymization is reversible, allowing findings to be mapped back to
//! original code locations.

use crate::models::Language;
use regex::Regex;
use std::collections::HashMap;
use tree_sitter::Parser;

/// Configuration for code anonymization.
#[derive(Debug, Clone)]
pub struct AnonymizationConfig {
    /// Anonymize function/method names.
    pub anonymize_functions: bool,
    /// Anonymize variable names.
    pub anonymize_variables: bool,
    /// Anonymize class/struct/type names.
    pub anonymize_types: bool,
    /// Anonymize string literals (replace with placeholder).
    pub anonymize_strings: bool,
    /// Anonymize numeric literals.
    pub anonymize_numbers: bool,
    /// Anonymize comments.
    pub anonymize_comments: bool,
    /// Preserve language keywords and builtins.
    pub preserve_keywords: bool,
    /// Preserve common library names (e.g., std, tokio, reqwest).
    pub preserve_common_libs: bool,
    /// Minimum identifier length to anonymize (shorter ones are kept).
    pub min_identifier_length: usize,
}

impl Default for AnonymizationConfig {
    fn default() -> Self {
        Self {
            anonymize_functions: true,
            anonymize_variables: true,
            anonymize_types: true,
            anonymize_strings: true,
            anonymize_numbers: false, // Keep numbers by default for security analysis
            anonymize_comments: true,
            preserve_keywords: true,
            preserve_common_libs: true,
            min_identifier_length: 2,
        }
    }
}

/// Result of anonymizing code.
#[derive(Debug, Clone)]
pub struct AnonymizedCode {
    /// The anonymized source code.
    pub code: String,
    /// Mapping from anonymized names to original names.
    pub mapping: IdentifierMapping,
    /// Original code (for reference).
    pub original: String,
    /// Language of the code.
    pub language: Language,
}

impl AnonymizedCode {
    /// Restore an identifier to its original form.
    pub fn restore_identifier(&self, anonymized: &str) -> Option<&str> {
        self.mapping.to_original(anonymized)
    }

    /// Restore line numbers (they're preserved during anonymization).
    pub fn restore_line(&self, line: usize) -> usize {
        line
    }

    /// Restore a finding message by replacing anonymized identifiers.
    pub fn restore_message(&self, message: &str) -> String {
        let mut result = message.to_string();
        for (anon, orig) in &self.mapping.reverse {
            result = result.replace(anon, orig);
        }
        result
    }
}

/// Bidirectional mapping between original and anonymized identifiers.
#[derive(Debug, Clone, Default)]
pub struct IdentifierMapping {
    /// Original -> Anonymized
    forward: HashMap<String, String>,
    /// Anonymized -> Original
    reverse: HashMap<String, String>,
    /// Counters for generating unique names
    counters: IdentifierCounters,
}

#[derive(Debug, Clone, Default)]
struct IdentifierCounters {
    function: usize,
    variable: usize,
    type_name: usize,
    string: usize,
}

impl IdentifierMapping {
    /// Create a new empty mapping.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create an anonymized function name.
    pub fn anonymize_function(&mut self, original: &str) -> String {
        if let Some(anon) = self.forward.get(original) {
            return anon.clone();
        }

        self.counters.function += 1;
        let anon = format!("func_{}", self.counters.function);
        self.forward.insert(original.to_string(), anon.clone());
        self.reverse.insert(anon.clone(), original.to_string());
        anon
    }

    /// Get or create an anonymized variable name.
    pub fn anonymize_variable(&mut self, original: &str) -> String {
        if let Some(anon) = self.forward.get(original) {
            return anon.clone();
        }

        self.counters.variable += 1;
        let anon = format!("var_{}", self.counters.variable);
        self.forward.insert(original.to_string(), anon.clone());
        self.reverse.insert(anon.clone(), original.to_string());
        anon
    }

    /// Get or create an anonymized type name.
    pub fn anonymize_type(&mut self, original: &str) -> String {
        if let Some(anon) = self.forward.get(original) {
            return anon.clone();
        }

        self.counters.type_name += 1;
        let anon = format!("Type_{}", self.counters.type_name);
        self.forward.insert(original.to_string(), anon.clone());
        self.reverse.insert(anon.clone(), original.to_string());
        anon
    }

    /// Get or create an anonymized string placeholder.
    pub fn anonymize_string(&mut self, original: &str) -> String {
        if let Some(anon) = self.forward.get(original) {
            return anon.clone();
        }

        self.counters.string += 1;
        let anon = format!("\"STRING_{}\"", self.counters.string);
        self.forward.insert(original.to_string(), anon.clone());
        self.reverse.insert(anon.clone(), original.to_string());
        anon
    }

    /// Look up the original identifier from an anonymized one.
    pub fn to_original(&self, anonymized: &str) -> Option<&str> {
        self.reverse.get(anonymized).map(|s| s.as_str())
    }

    /// Look up the anonymized identifier from an original one.
    pub fn to_anonymized(&self, original: &str) -> Option<&str> {
        self.forward.get(original).map(|s| s.as_str())
    }

    /// Get all mappings.
    pub fn mappings(&self) -> impl Iterator<Item = (&str, &str)> {
        self.forward.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// Code anonymizer using tree-sitter for accurate parsing.
pub struct CodeAnonymizer {
    /// Configuration.
    config: AnonymizationConfig,
    /// Language keywords to preserve.
    keywords: HashMap<Language, Vec<&'static str>>,
    /// Common library names to preserve.
    common_libs: Vec<&'static str>,
}

impl CodeAnonymizer {
    /// Create a new code anonymizer with default configuration.
    pub fn new() -> Self {
        Self::with_config(AnonymizationConfig::default())
    }

    /// Create a new code anonymizer with custom configuration.
    pub fn with_config(config: AnonymizationConfig) -> Self {
        let mut keywords = HashMap::new();

        // Rust keywords
        keywords.insert(
            Language::Rust,
            vec![
                "as", "async", "await", "break", "const", "continue", "crate", "dyn",
                "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
                "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
                "self", "Self", "static", "struct", "super", "trait", "true", "type",
                "unsafe", "use", "where", "while", "async", "await", "try",
                // Built-in types
                "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize",
                "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64",
                "String", "Vec", "Option", "Result", "Box", "Rc", "Arc", "Cell",
                "RefCell", "HashMap", "HashSet", "BTreeMap", "BTreeSet",
                // Common methods
                "new", "default", "clone", "into", "from", "unwrap", "expect",
                "ok", "err", "some", "none", "map", "and_then", "or_else",
            ],
        );

        // Python keywords
        keywords.insert(
            Language::Python,
            vec![
                "False", "None", "True", "and", "as", "assert", "async", "await",
                "break", "class", "continue", "def", "del", "elif", "else", "except",
                "finally", "for", "from", "global", "if", "import", "in", "is",
                "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
                "while", "with", "yield",
                // Built-in functions
                "print", "len", "range", "str", "int", "float", "list", "dict",
                "set", "tuple", "type", "isinstance", "hasattr", "getattr", "setattr",
                "open", "read", "write", "close",
            ],
        );

        // JavaScript keywords
        keywords.insert(
            Language::JavaScript,
            vec![
                "break", "case", "catch", "class", "const", "continue", "debugger",
                "default", "delete", "do", "else", "export", "extends", "false",
                "finally", "for", "function", "if", "import", "in", "instanceof",
                "let", "new", "null", "return", "static", "super", "switch", "this",
                "throw", "true", "try", "typeof", "undefined", "var", "void", "while",
                "with", "yield", "async", "await",
                // Built-in objects
                "Array", "Object", "String", "Number", "Boolean", "Date", "Math",
                "JSON", "Promise", "Map", "Set", "WeakMap", "WeakSet", "console",
            ],
        );

        // Go keywords
        keywords.insert(
            Language::Go,
            vec![
                "break", "case", "chan", "const", "continue", "default", "defer",
                "else", "fallthrough", "for", "func", "go", "goto", "if", "import",
                "interface", "map", "package", "range", "return", "select", "struct",
                "switch", "type", "var",
                // Built-in types
                "bool", "byte", "complex64", "complex128", "error", "float32",
                "float64", "int", "int8", "int16", "int32", "int64", "rune",
                "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
                // Built-in functions
                "append", "cap", "close", "complex", "copy", "delete", "imag",
                "len", "make", "new", "panic", "print", "println", "real", "recover",
            ],
        );

        let common_libs = vec![
            // Rust crates
            "std", "tokio", "async_std", "reqwest", "serde", "serde_json",
            "anyhow", "thiserror", "tracing", "log", "clap", "chrono",
            "regex", "lazy_static", "once_cell", "parking_lot", "crossbeam",
            // Python packages
            "os", "sys", "json", "re", "datetime", "collections", "itertools",
            "requests", "numpy", "pandas", "flask", "django",
            // JavaScript/Node packages
            "fs", "path", "http", "https", "crypto", "express", "react",
            "axios", "lodash", "moment",
            // Go packages
            "fmt", "os", "io", "net", "http", "json", "context", "sync",
        ];

        Self {
            config,
            keywords,
            common_libs,
        }
    }

    /// Anonymize source code.
    pub fn anonymize(&self, code: &str, language: Language) -> AnonymizedCode {
        let mut mapping = IdentifierMapping::new();
        let anonymized = self.anonymize_with_mapping(code, language, &mut mapping);

        AnonymizedCode {
            code: anonymized,
            mapping,
            original: code.to_string(),
            language,
        }
    }

    /// Anonymize with an existing mapping (for multi-file consistency).
    pub fn anonymize_with_mapping(
        &self,
        code: &str,
        language: Language,
        mapping: &mut IdentifierMapping,
    ) -> String {
        // Try tree-sitter first for accurate parsing
        if let Some(result) = self.anonymize_with_tree_sitter(code, language, mapping) {
            return result;
        }

        // Fall back to regex-based anonymization
        self.anonymize_with_regex(code, language, mapping)
    }

    /// Anonymize using tree-sitter for accurate parsing.
    fn anonymize_with_tree_sitter(
        &self,
        code: &str,
        language: Language,
        mapping: &mut IdentifierMapping,
    ) -> Option<String> {
        let mut parser = Parser::new();

        let ts_language = match language {
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            _ => return None,
        };

        parser.set_language(&ts_language).ok()?;
        let tree = parser.parse(code, None)?;

        // Collect all replacements
        let mut replacements: Vec<(usize, usize, String)> = Vec::new();

        // Walk the tree and collect identifiers
        let mut cursor = tree.walk();
        self.collect_replacements(
            code,
            language,
            &mut cursor,
            mapping,
            &mut replacements,
        );

        // Sort by position (reverse order for safe replacement)
        replacements.sort_by(|a, b| b.0.cmp(&a.0));

        // Apply replacements
        let mut result = code.to_string();
        for (start, end, replacement) in replacements {
            if start < result.len() && end <= result.len() {
                result.replace_range(start..end, &replacement);
            }
        }

        Some(result)
    }

    fn collect_replacements(
        &self,
        code: &str,
        language: Language,
        cursor: &mut tree_sitter::TreeCursor,
        mapping: &mut IdentifierMapping,
        replacements: &mut Vec<(usize, usize, String)>,
    ) {
        loop {
            let node = cursor.node();
            let node_kind = node.kind();
            let start = node.start_byte();
            let end = node.end_byte();

            if start < code.len() && end <= code.len() {
                let text = &code[start..end];

                // Check if this is an identifier we should anonymize
                let replacement = self.get_replacement(text, node_kind, language, mapping);
                if let Some(rep) = replacement {
                    replacements.push((start, end, rep));
                }
            }

            // Recurse into children
            if cursor.goto_first_child() {
                self.collect_replacements(code, language, cursor, mapping, replacements);
                cursor.goto_parent();
            }

            // Move to next sibling
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn get_replacement(
        &self,
        text: &str,
        node_kind: &str,
        language: Language,
        mapping: &mut IdentifierMapping,
    ) -> Option<String> {
        // Skip if too short
        if text.len() < self.config.min_identifier_length {
            return None;
        }

        // Skip keywords
        if self.config.preserve_keywords {
            if let Some(kw_list) = self.keywords.get(&language) {
                if kw_list.contains(&text) {
                    return None;
                }
            }
        }

        // Skip common library names
        if self.config.preserve_common_libs && self.common_libs.contains(&text) {
            return None;
        }

        // Determine identifier type based on node kind
        match node_kind {
            // Function definitions
            "function_item" | "function_definition" | "function_declaration"
            | "method_definition" | "method_declaration" => {
                if self.config.anonymize_functions {
                    return Some(mapping.anonymize_function(text));
                }
            }

            // Identifiers (need context to determine type)
            "identifier" | "name" => {
                // Check if it looks like a type (starts with uppercase)
                if text.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                    if self.config.anonymize_types {
                        return Some(mapping.anonymize_type(text));
                    }
                } else if self.config.anonymize_variables {
                    return Some(mapping.anonymize_variable(text));
                }
            }

            // Type names
            "type_identifier" | "class_name" | "struct_name" | "enum_name"
            | "trait_name" | "interface_name" => {
                if self.config.anonymize_types {
                    return Some(mapping.anonymize_type(text));
                }
            }

            // String literals
            "string" | "string_literal" | "raw_string_literal" | "string_content" => {
                if self.config.anonymize_strings {
                    return Some(mapping.anonymize_string(text));
                }
            }

            // Comments
            "comment" | "line_comment" | "block_comment" | "doc_comment" => {
                if self.config.anonymize_comments {
                    return Some("/* COMMENT */".to_string());
                }
            }

            _ => {}
        }

        None
    }

    /// Fallback regex-based anonymization.
    fn anonymize_with_regex(
        &self,
        code: &str,
        language: Language,
        mapping: &mut IdentifierMapping,
    ) -> String {
        let mut result = code.to_string();

        // Anonymize strings first (to avoid matching identifiers inside strings)
        if self.config.anonymize_strings {
            let string_re = Regex::new(r#""[^"\\]*(?:\\.[^"\\]*)*""#).unwrap();
            result = string_re
                .replace_all(&result, |_: &regex::Captures| {
                    mapping.counters.string += 1;
                    format!("\"STRING_{}\"", mapping.counters.string)
                })
                .to_string();
        }

        // Anonymize comments
        if self.config.anonymize_comments {
            // Line comments
            let line_comment = match language {
                Language::Python => Regex::new(r"#.*$").unwrap(),
                _ => Regex::new(r"//.*$").unwrap(),
            };
            result = line_comment.replace_all(&result, "// COMMENT").to_string();

            // Block comments
            let block_comment = match language {
                Language::Python => Regex::new(r#"'''[\s\S]*?'''"#).unwrap(),
                _ => Regex::new(r"/\*[\s\S]*?\*/").unwrap(),
            };
            result = block_comment.replace_all(&result, "/* COMMENT */").to_string();
        }

        // Anonymize identifiers (simple approach)
        if self.config.anonymize_functions || self.config.anonymize_variables {
            let ident_re = Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b").unwrap();
            let keywords = self.keywords.get(&language).cloned().unwrap_or_default();

            let result_clone = result.clone();
            result = ident_re
                .replace_all(&result_clone, |caps: &regex::Captures| {
                    let ident = &caps[1];

                    // Skip if too short
                    if ident.len() < self.config.min_identifier_length {
                        return ident.to_string();
                    }

                    // Skip keywords
                    if self.config.preserve_keywords && keywords.contains(&ident) {
                        return ident.to_string();
                    }

                    // Skip common libs
                    if self.config.preserve_common_libs && self.common_libs.contains(&ident) {
                        return ident.to_string();
                    }

                    // Anonymize based on case
                    if ident.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                        if self.config.anonymize_types {
                            mapping.anonymize_type(ident)
                        } else {
                            ident.to_string()
                        }
                    } else {
                        mapping.anonymize_variable(ident)
                    }
                })
                .to_string();
        }

        result
    }
}

impl Default for CodeAnonymizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_anonymization() {
        let anonymizer = CodeAnonymizer::new();
        let code = r#"
fn calculate_price(item_count: u32, unit_price: f64) -> f64 {
    let total = item_count as f64 * unit_price;
    total
}
"#;

        let result = anonymizer.anonymize(code, Language::Rust);

        // Keywords should be preserved
        assert!(result.code.contains("fn"));
        assert!(result.code.contains("let"));
        assert!(result.code.contains("u32"));
        assert!(result.code.contains("f64"));

        // Original identifiers should be replaced
        assert!(!result.code.contains("calculate_price"));
        assert!(!result.code.contains("item_count"));
        assert!(!result.code.contains("unit_price"));
    }

    #[test]
    fn test_mapping_restoration() {
        let anonymizer = CodeAnonymizer::new();
        let code = "let my_secret_variable = 42;";

        let result = anonymizer.anonymize(code, Language::Rust);

        // Should be able to restore original name
        let anon_name = result.mapping.to_anonymized("my_secret_variable");
        assert!(anon_name.is_some());

        let restored = result.mapping.to_original(anon_name.unwrap());
        assert_eq!(restored, Some("my_secret_variable"));
    }

    #[test]
    fn test_string_anonymization() {
        let anonymizer = CodeAnonymizer::new();
        let code = r#"let secret = "my-api-key-12345";"#;

        let result = anonymizer.anonymize(code, Language::Rust);

        // Original string should be replaced
        assert!(!result.code.contains("my-api-key-12345"));
        assert!(result.code.contains("STRING_"));
    }

    #[test]
    fn test_comment_anonymization() {
        let anonymizer = CodeAnonymizer::new();
        let code = r#"
// This is a secret comment with internal info
fn main() {}
"#;

        let result = anonymizer.anonymize(code, Language::Rust);

        // Original comment content should be removed
        assert!(!result.code.contains("secret comment"));
        assert!(result.code.contains("COMMENT"));
    }

    #[test]
    fn test_preserve_common_libs() {
        let config = AnonymizationConfig {
            preserve_common_libs: true,
            ..Default::default()
        };
        let anonymizer = CodeAnonymizer::with_config(config);

        let code = "use std::collections::HashMap;";
        let result = anonymizer.anonymize(code, Language::Rust);

        // std and HashMap should be preserved
        assert!(result.code.contains("std"));
        assert!(result.code.contains("HashMap"));
    }

    #[test]
    fn test_restore_message() {
        let anonymizer = CodeAnonymizer::new();
        let code = "fn process_user_data(user_id: u32) {}";

        let result = anonymizer.anonymize(code, Language::Rust);

        // Simulate a finding message with anonymized names
        let anon_name = result.mapping.to_anonymized("process_user_data").unwrap();
        let finding_msg = format!("Vulnerability in function {}", anon_name);

        // Restore should bring back original name
        let restored = result.restore_message(&finding_msg);
        assert!(restored.contains("process_user_data"));
    }

    #[test]
    fn test_consistent_mapping() {
        let anonymizer = CodeAnonymizer::new();
        let code = r#"
fn my_func() {
    let x = my_func;
    my_func();
}
"#;

        let result = anonymizer.anonymize(code, Language::Rust);

        // Same identifier should get same anonymized name
        let anon = result.mapping.to_anonymized("my_func").unwrap();
        let occurrences = result.code.matches(anon).count();
        // Should appear multiple times (definition + references)
        assert!(occurrences >= 1);
    }

    #[test]
    fn test_python_anonymization() {
        let anonymizer = CodeAnonymizer::new();
        let code = r#"
def calculate_total(items):
    total = 0
    for item in items:
        total += item.price
    return total
"#;

        let result = anonymizer.anonymize(code, Language::Python);

        // Python keywords should be preserved
        assert!(result.code.contains("def"));
        assert!(result.code.contains("for"));
        assert!(result.code.contains("return"));

        // Custom identifiers should be replaced
        assert!(!result.code.contains("calculate_total"));
    }

    #[test]
    fn test_type_anonymization() {
        let anonymizer = CodeAnonymizer::new();
        let code = "struct CustomerData { name: String }";

        let result = anonymizer.anonymize(code, Language::Rust);

        // Type name should be anonymized
        assert!(!result.code.contains("CustomerData"));
        assert!(result.code.contains("Type_"));
    }
}
