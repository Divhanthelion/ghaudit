//! Static Application Security Testing (SAST) engine using tree-sitter.

use crate::analyzer::queries::{get_queries_for_language, SecurityQuery};
use crate::analyzer::taint::{analyze_taint, SinkCategory, TaintAnalysisResult};
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

    /// Parsers for each language
    parsers: HashMap<Language, Parser>,

    /// Whether to use taint analysis for FP reduction
    enable_taint_analysis: bool,
}

impl SastEngine {
    /// Create a new SAST engine.
    pub fn new(config: AnalysisConfig) -> Result<Self> {
        let mut parsers = HashMap::new();

        // Initialize parsers for supported languages
        if config.languages.iter().any(|l| l == "rust") {
            if let Ok(parser) = Self::create_parser(Language::Rust) {
                parsers.insert(Language::Rust, parser);
            }
        }

        if config.languages.iter().any(|l| l == "python") {
            if let Ok(parser) = Self::create_parser(Language::Python) {
                parsers.insert(Language::Python, parser);
            }
        }

        if config.languages.iter().any(|l| l == "javascript" || l == "typescript") {
            if let Ok(parser) = Self::create_parser(Language::JavaScript) {
                parsers.insert(Language::JavaScript, parser);
            }
        }

        if config.languages.iter().any(|l| l == "go") {
            if let Ok(parser) = Self::create_parser(Language::Go) {
                parsers.insert(Language::Go, parser);
            }
        }

        info!("SAST engine initialized with {} language parsers", parsers.len());

        Ok(Self {
            config,
            parsers,
            enable_taint_analysis: true, // Enable by default for FP reduction
        })
    }

    /// Enable or disable taint analysis for false positive reduction.
    pub fn with_taint_analysis(mut self, enable: bool) -> Self {
        self.enable_taint_analysis = enable;
        self
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

        // Run taint analysis if enabled (for FP reduction)
        let taint_result = if self.enable_taint_analysis {
            match analyze_taint(language, &tree, &content) {
                Ok(result) => {
                    debug!(
                        "Taint analysis for {}: {} sources, {} sinks, {} flows",
                        file_path.display(),
                        result.source_count,
                        result.sink_count,
                        result.flows.len()
                    );
                    Some(result)
                }
                Err(e) => {
                    warn!("Taint analysis failed for {}: {}", file_path.display(), e);
                    None
                }
            }
        } else {
            None
        };

        // Get queries for this language
        let queries = get_queries_for_language(language);
        let mut findings = Vec::new();

        // Run each security query
        for security_query in queries {
            match self.run_query(&security_query, &tree, &content, &file_path) {
                Ok(query_findings) => {
                    // Filter findings using taint analysis results
                    let filtered = if let Some(ref taint) = taint_result {
                        self.filter_with_taint(query_findings, taint, &security_query)
                    } else {
                        query_findings
                    };
                    findings.extend(filtered);
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

        // Add taint flow findings for confirmed data flow vulnerabilities
        if let Some(ref taint) = taint_result {
            for flow in &taint.flows {
                let location = Location::new(
                    file_path.clone(),
                    flow.sink_line,
                    1,
                )
                .with_language(language);

                let severity = match flow.sink.category {
                    SinkCategory::SqlQuery | SinkCategory::CommandExec | SinkCategory::CodeEval => {
                        Severity::Critical
                    }
                    SinkCategory::HtmlOutput | SinkCategory::FilePath => Severity::High,
                    SinkCategory::Deserialization | SinkCategory::LdapQuery | SinkCategory::XPathQuery => {
                        Severity::High
                    }
                    SinkCategory::LogOutput => Severity::Medium,
                };

                let category = match flow.sink.category {
                    SinkCategory::SqlQuery => SastCategory::Injection,
                    SinkCategory::CommandExec => SastCategory::Injection,
                    SinkCategory::CodeEval => SastCategory::Injection,
                    SinkCategory::HtmlOutput => SastCategory::Xss,
                    SinkCategory::FilePath => SastCategory::PathTraversal,
                    _ => SastCategory::Other,
                };

                let mut finding = Finding::sast(
                    &format!("taint-flow-{:?}", flow.sink.category),
                    &format!("Taint flow to {:?} sink", flow.sink.category),
                    &format!(
                        "Untrusted data flows from {} (line {}) to {} (line {}) without sanitization",
                        flow.source.pattern, flow.source_line, flow.sink.pattern, flow.sink_line
                    ),
                    location,
                    severity,
                )
                .with_sast_category(category)
                .with_confidence(Confidence::High) // Taint-confirmed findings have high confidence
                .with_metadata("taint_source", serde_json::json!(flow.source.pattern))
                .with_metadata("taint_sink", serde_json::json!(flow.sink.pattern))
                .with_metadata("source_line", serde_json::json!(flow.source_line))
                .with_metadata("sink_line", serde_json::json!(flow.sink_line));

                findings.push(finding);
            }
        }

        debug!(
            "Found {} findings in {}",
            findings.len(),
            file_path.display()
        );
        Ok(findings)
    }

    /// Filter findings using taint analysis to reduce false positives.
    ///
    /// If a finding is about a potential injection but taint analysis
    /// shows no data flow from untrusted sources, reduce its confidence.
    fn filter_with_taint(
        &self,
        findings: Vec<Finding>,
        taint: &TaintAnalysisResult,
        query: &SecurityQuery,
    ) -> Vec<Finding> {
        findings
            .into_iter()
            .filter_map(|mut finding| {
                // Check if this is an injection-related finding
                let is_injection = query.id.contains("injection")
                    || query.id.contains("sql")
                    || query.id.contains("cmd")
                    || query.id.contains("eval")
                    || query.id.contains("xss");

                if is_injection {
                    // Check if taint analysis found any flows to this location
                    let line = finding.location.start_line;
                    let has_taint_flow = taint.flows.iter().any(|f| {
                        f.sink_line == line
                            || (f.sink_line.saturating_sub(2) <= line && line <= f.sink_line + 2)
                    });

                    if !has_taint_flow && taint.source_count > 0 {
                        // No taint flow detected but sources exist - lower confidence
                        finding = finding.with_confidence(Confidence::Low);
                        debug!(
                            "Lowered confidence for {} at line {} (no taint flow)",
                            query.id, line
                        );
                    } else if has_taint_flow {
                        // Taint flow confirmed - high confidence
                        finding = finding.with_confidence(Confidence::High);
                        debug!(
                            "Confirmed taint flow for {} at line {}",
                            query.id, line
                        );
                    }
                }

                Some(finding)
            })
            .collect()
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

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());

        let mut findings = Vec::new();

        while let Some(match_) = matches.next() {
            // Get the primary capture (usually the main node of interest)
            if let Some(capture) = match_.captures.first() {
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

    /// Analyze multiple files in parallel with bounded parallelism.
    ///
    /// Files are processed in batches to control memory usage, which is
    /// important for large repositories with thousands of files.
    pub fn analyze_files(&self, files: &mut [SourceFile]) -> Result<Vec<Finding>> {
        info!("Analyzing {} files with SAST engine", files.len());

        let mut all_findings = Vec::new();

        // Process files in batches to control memory usage
        let batch_size = self.config.max_file_size.min(500); // Default to 500 if not configured
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
        self.parsers.contains_key(&language)
    }

    /// Get supported languages.
    pub fn supported_languages(&self) -> Vec<Language> {
        self.parsers.keys().copied().collect()
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

/// Helper extension trait for AnalysisConfig to avoid Option handling.
trait AnalysisConfigExt {
    fn include_snippets(&self) -> Option<bool>;
    fn snippet_lines(&self) -> Option<usize>;
}

impl AnalysisConfigExt for AnalysisConfig {
    fn include_snippets(&self) -> Option<bool> {
        Some(true) // Default to true
    }

    fn snippet_lines(&self) -> Option<usize> {
        Some(3) // Default context lines
    }
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
