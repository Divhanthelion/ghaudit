//! Static Application Security Testing (SAST) engine using tree-sitter.

use crate::analyzer::queries::{get_queries_for_language, SecurityQuery};
use crate::config::AnalysisConfig;
use crate::error::{AuditorError, Result};
use crate::models::{
    CodeSnippet, Confidence, Finding, Language, Location, SastCategory, Severity, SourceFile,
};
use rayon::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info, warn};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

// Thread-local parser cache to avoid recreating parsers for each file
// while maintaining thread safety for Rayon parallel iteration.
thread_local! {
    static PARSER_CACHE: RefCell<HashMap<Language, Parser>> = RefCell::new(HashMap::new());
}

/// SAST engine for analyzing source code.
pub struct SastEngine {
    /// Analysis configuration
    config: AnalysisConfig,
}

impl SastEngine {
    /// Create a new SAST engine.
    pub fn new(config: AnalysisConfig) -> Result<Self> {
        // Verify parsers can be created for configured languages
        let mut parser_count = 0;
        for lang_str in &config.languages {
            let lang = match lang_str.as_str() {
                "rust" => Some(Language::Rust),
                "python" => Some(Language::Python),
                "javascript" | "typescript" => Some(Language::JavaScript),
                "go" => Some(Language::Go),
                _ => None,
            };
            if let Some(l) = lang {
                if Self::create_parser(l).is_ok() {
                    parser_count += 1;
                }
            }
        }

        info!("SAST engine initialized with {} language parsers", parser_count);

        Ok(Self { config })
    }

    /// Create a parser for a specific language.
    fn create_parser(language: Language) -> Result<Parser> {
        let mut parser = Parser::new();

        let ts_language = match language {
            Language::Rust => tree_sitter_rust::LANGUAGE,
            Language::Python => tree_sitter_python::LANGUAGE,
            Language::JavaScript | Language::TypeScript => tree_sitter_javascript::LANGUAGE,
            Language::Go => tree_sitter_go::LANGUAGE,
            _ => {
                return Err(AuditorError::Parse(format!(
                    "Unsupported language: {:?}",
                    language
                )))
            }
        };

        parser
            .set_language(&ts_language.into())
            .map_err(|e| AuditorError::Parse(format!("Failed to set language: {}", e)))?;

        Ok(parser)
    }

    /// Get a parser from thread-local cache, creating one if needed.
    ///
    /// This allows parser reuse within a thread while maintaining
    /// thread safety for parallel analysis.
    fn get_cached_parser(language: Language) -> Result<()> {
        PARSER_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if !cache.contains_key(&language) {
                let parser = Self::create_parser(language)?;
                cache.insert(language, parser);
            }
            Ok(())
        })
    }

    /// Parse content using a thread-local cached parser.
    fn parse_with_cache(language: Language, content: &str) -> Result<tree_sitter::Tree> {
        Self::get_cached_parser(language)?;

        PARSER_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            let parser = cache.get_mut(&language).ok_or_else(|| {
                AuditorError::Parse(format!("Parser not in cache for {:?}", language))
            })?;

            parser.parse(content, None).ok_or_else(|| {
                AuditorError::Parse("Failed to parse file".to_string())
            })
        })
    }

    /// Analyze a single file.
    pub fn analyze_file(&self, file: &mut SourceFile) -> Result<Vec<Finding>> {
        // Get language and path before borrowing for content
        let language = file.language;
        let file_path = file.path.clone();

        if !language.is_supported() {
            debug!("Skipping unsupported language: {:?}", language);
            return Ok(Vec::new());
        }

        // Load content if not already loaded
        let content = file.load_content()?.to_string();

        // Parse the file using thread-local cached parser
        let tree = Self::parse_with_cache(language, &content)?;

        // Get queries for this language
        let queries = get_queries_for_language(language);
        let mut findings = Vec::new();

        // Run each security query
        for security_query in queries {
            match self.run_query(&security_query, &tree, &content, &file_path) {
                Ok(query_findings) => {
                    findings.extend(query_findings);
                }
                Err(e) => {
                    warn!(
                        "Query {} failed on {}: {}",
                        security_query.id,
                        file_path.display(),
                        e
                    );
                }
            }
        }

        debug!(
            "Found {} findings in {}",
            findings.len(),
            file_path.display()
        );
        Ok(findings)
    }

    /// Run a security query on a parsed tree.
    fn run_query(
        &self,
        security_query: &SecurityQuery,
        tree: &tree_sitter::Tree,
        source: &str,
        file_path: &Path,
    ) -> Result<Vec<Finding>> {
        let ts_language = match security_query.language {
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::JavaScript | Language::TypeScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            _ => return Ok(Vec::new()),
        };

        let query = Query::new(&ts_language, security_query.query)
            .map_err(|e| AuditorError::Parse(format!("Invalid query {}: {}", security_query.id, e)))?;

        let is_hardcoded_query = security_query.id.contains("hardcoded");
        let capture_names: Vec<String> = query.capture_names().iter().map(|s| s.to_string()).collect();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());

        let mut findings = Vec::new();

        while let Some(match_) = matches.next() {
            // Get the primary capture (usually the main node of interest)
            if let Some(capture) = match_.captures.first() {
                // For hardcoded-secret/password queries, validate the value isn't a sentinel
                if is_hardcoded_query {
                    let value_text = match_.captures.iter()
                        .find(|c| capture_names.get(c.index as usize).map(|n| n.as_str()) == Some("value"))
                        .and_then(|c| c.node.utf8_text(source.as_bytes()).ok());

                    if let Some(value) = value_text {
                        let inner = value.trim_matches(|c: char| c == '"' || c == '\'');
                        if !Self::looks_like_real_secret(inner) {
                            debug!("Filtered hardcoded FP: {} = {:?}", security_query.id, inner);
                            continue;
                        }
                    }
                }

                let node = capture.node;
                let start = node.start_position();
                let end = node.end_position();

                let location = Location::new(
                    file_path.to_path_buf(),
                    start.row + 1, // Convert to 1-indexed
                    start.column + 1,
                )
                .with_end(end.row + 1, end.column + 1)
                .with_language(security_query.language);

                let snippet = Some(CodeSnippet::from_content(
                    source,
                    start.row + 1,
                    3, // Default context lines
                ));

                let sast_category = categorize_finding(security_query.id);

                let mut finding = Finding::sast(
                    security_query.id,
                    security_query.name,
                    security_query.description,
                    location,
                    security_query.severity,
                )
                .with_sast_category(sast_category)
                .with_confidence(determine_confidence(security_query, &node, source))
                .with_remediation(security_query.remediation);

                if let Some(snippet) = snippet {
                    finding = finding.with_snippet(snippet);
                }

                // Add CWE metadata
                for cwe in security_query.cwes {
                    finding = finding.with_metadata("cwe", serde_json::json!(cwe));
                }

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    /// Check if a string value looks like a real hardcoded secret vs a sentinel/marker.
    fn looks_like_real_secret(value: &str) -> bool {
        // Too short to be a real secret
        if value.len() < 8 {
            return false;
        }

        // Known non-secret patterns: XML/HTML tags, bracket markers, BOS/EOS tokens
        let lower = value.to_lowercase();
        if lower.starts_with('<') || lower.starts_with('[') || lower.starts_with('{') {
            return false;
        }

        // Common sentinel values
        let sentinels = [
            "none", "null", "true", "false", "undefined", "n/a",
            "changeme", "replace_me", "your_", "example", "test",
        ];
        for sentinel in sentinels {
            if lower.contains(sentinel) {
                return false;
            }
        }

        // Must have some character diversity (real secrets aren't all the same char class)
        let has_digit = value.chars().any(|c| c.is_ascii_digit());
        let has_alpha = value.chars().any(|c| c.is_ascii_alphabetic());
        let has_special = value.chars().any(|c| !c.is_ascii_alphanumeric());

        // Real secrets typically mix character classes
        // A string like "TOOL_CALLS" (all caps + underscore) with no digits is unlikely a secret
        if !has_digit && !has_special {
            return false;
        }

        // If it's short and only alpha+underscore, not a secret
        if value.len() < 16 && !has_digit {
            return false;
        }

        has_alpha || has_digit
    }

    /// Analyze multiple files in parallel with bounded parallelism.
    ///
    /// Files are processed in batches to control memory usage, which is
    /// important for large repositories with thousands of files.
    pub fn analyze_files(&self, files: &mut [SourceFile]) -> Result<Vec<Finding>> {
        info!("Analyzing {} files with SAST engine", files.len());

        let mut all_findings = Vec::new();

        // Process files in batches to control memory usage
        let batch_size = 500; // Files per parallel batch
        let total_batches = (files.len() + batch_size - 1) / batch_size;

        for (batch_idx, batch) in files.chunks_mut(batch_size).enumerate() {
            debug!("Processing batch {}/{} ({} files)", batch_idx + 1, total_batches, batch.len());

            // Use rayon for parallel analysis within each batch
            let results: Vec<Result<Vec<Finding>>> = batch
                .par_iter_mut()
                .map(|file| self.analyze_file(file))
                .collect();

            // Collect findings from this batch
            for result in results {
                match result {
                    Ok(findings) => all_findings.extend(findings),
                    Err(e) => warn!("Analysis error: {}", e),
                }
            }
        }

        info!("SAST analysis complete. Found {} total findings", all_findings.len());
        Ok(all_findings)
    }

    /// Check if the SAST engine supports a language.
    pub fn supports_language(&self, language: Language) -> bool {
        let lang_str = match language {
            Language::Rust => "rust",
            Language::Python => "python",
            Language::JavaScript | Language::TypeScript => "javascript",
            Language::Go => "go",
            _ => return false,
        };
        self.config.languages.iter().any(|l| l == lang_str)
    }
}

/// Categorize a finding based on the query ID.
fn categorize_finding(query_id: &str) -> SastCategory {
    if query_id.contains("unsafe") {
        SastCategory::UnsafeCode
    } else if query_id.contains("injection") || query_id.contains("sql") || query_id.contains("cmd") {
        SastCategory::Injection
    } else if query_id.contains("xss") || query_id.contains("innerhtml") || query_id.contains("document-write") {
        SastCategory::Xss
    } else if query_id.contains("path") || query_id.contains("traversal") {
        SastCategory::PathTraversal
    } else if query_id.contains("crypto") || query_id.contains("weak") {
        SastCategory::Crypto
    } else if query_id.contains("auth") || query_id.contains("password") || query_id.contains("secret") {
        SastCategory::Auth
    } else if query_id.contains("race") || query_id.contains("toctou") || query_id.contains("mktemp") {
        SastCategory::RaceCondition
    } else if query_id.contains("dos") || query_id.contains("redos") || query_id.contains("timeout") {
        SastCategory::Dos
    } else if query_id.contains("memory") || query_id.contains("transmute") || query_id.contains("pointer") {
        SastCategory::MemorySafety
    } else if query_id.contains("panic") || query_id.contains("refcell") {
        SastCategory::MemorySafety
    } else if query_id.contains("unbounded") || query_id.contains("defer-in-loop") {
        SastCategory::UnboundedResource
    } else if query_id.contains("prototype") || query_id.contains("pollution") {
        SastCategory::PrototypePollution
    } else {
        SastCategory::Other
    }
}

/// Determine confidence level based on context.
fn determine_confidence(
    query: &SecurityQuery,
    node: &tree_sitter::Node,
    source: &str,
) -> Confidence {
    // Start with medium confidence
    let mut confidence = Confidence::Medium;

    // High severity patterns typically have high confidence
    if matches!(query.severity, Severity::Critical | Severity::High) {
        confidence = Confidence::High;
    }

    // Check for mitigating factors in surrounding context
    let node_text = node
        .utf8_text(source.as_bytes())
        .unwrap_or("");

    // Look for test-related patterns (lower confidence)
    if node_text.contains("test") || node_text.contains("mock") || node_text.contains("example") {
        confidence = Confidence::Low;
    }

    // Look for safety comments in Rust (higher confidence of false positive)
    if query.language == Language::Rust {
        // Check if there's a SAFETY comment before the node
        let start_byte = node.start_byte().saturating_sub(200);
        let end_byte = node.start_byte();
        // Find valid UTF-8 char boundaries to avoid panicking on multi-byte chars
        let start = source
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= start_byte)
            .last()
            .unwrap_or(0);
        let end = source
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= end_byte)
            .last()
            .unwrap_or(0);
        let before = &source[start..end];
        if before.contains("// SAFETY:") || before.contains("// safety:") {
            confidence = Confidence::Low;
        }
    }

    confidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_unsafe_detection() {
        let config = AnalysisConfig::default();
        let engine = SastEngine::new(config).unwrap();

        let code = r#"
fn main() {
    unsafe {
        let ptr = 0x1234 as *mut i32;
        *ptr = 42;
    }
}
"#;

        let mut file = SourceFile {
            path: "test.rs".into(),
            absolute_path: "test.rs".into(),
            language: Language::Rust,
            size: code.len() as u64,
            content: Some(code.to_string()),
        };

        let findings = engine.analyze_file(&mut file).unwrap();
        assert!(!findings.is_empty(), "Should detect unsafe block");
    }

    #[test]
    fn test_python_eval_detection() {
        let config = AnalysisConfig::default();
        let engine = SastEngine::new(config).unwrap();

        let code = r#"
user_input = input()
result = eval(user_input)
"#;

        let mut file = SourceFile {
            path: "test.py".into(),
            absolute_path: "test.py".into(),
            language: Language::Python,
            size: code.len() as u64,
            content: Some(code.to_string()),
        };

        let findings = engine.analyze_file(&mut file).unwrap();
        assert!(!findings.is_empty(), "Should detect eval usage");
    }
}
