//! AI-driven vulnerability analysis module.
//!
//! This module provides AI-powered analysis capabilities using local LLM inference.
//! Note: Full candle integration requires additional setup and model files.
//! This implementation provides the interface and can use external LLM APIs as fallback.

use crate::error::{AuditorError, Result};
use crate::models::{Confidence, Finding, Language, Location, Severity};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, warn};

/// AI analyzer for advanced vulnerability detection.
pub struct AiAnalyzer {
    /// HTTP client for API calls
    client: Client,

    /// Whether to use local inference (when available)
    use_local: bool,

    /// API endpoint for external LLM (optional fallback)
    api_endpoint: Option<String>,

    /// API key for external LLM
    api_key: Option<String>,

    /// Maximum tokens for context
    max_context_tokens: usize,
}

impl AiAnalyzer {
    /// Create a new AI analyzer.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            use_local: false, // Default to API since candle requires additional setup
            api_endpoint: std::env::var("LLM_API_ENDPOINT").ok(),
            api_key: std::env::var("LLM_API_KEY").ok(),
            max_context_tokens: 4096,
        }
    }

    /// Enable local inference (requires candle and model setup).
    pub fn with_local_inference(mut self, enabled: bool) -> Self {
        self.use_local = enabled;
        self
    }

    /// Set the API endpoint for external LLM.
    pub fn with_api_endpoint(mut self, endpoint: String) -> Self {
        self.api_endpoint = Some(endpoint);
        self
    }

    /// Set the API key for external LLM.
    pub fn with_api_key(mut self, key: String) -> Self {
        self.api_key = Some(key);
        self
    }

    /// Analyze a code snippet for vulnerabilities.
    pub async fn analyze_snippet(
        &self,
        code: &str,
        language: Language,
        context: &AnalysisContext,
    ) -> Result<Vec<Finding>> {
        if self.use_local {
            // Local inference not fully implemented - would use candle
            warn!("Local inference not available, falling back to heuristic analysis");
            return self.heuristic_analysis(code, language, context);
        }

        if let (Some(ref endpoint), Some(ref key)) = (&self.api_endpoint, &self.api_key) {
            return self.api_analysis(code, language, context, endpoint, key).await;
        }

        // Fallback to heuristic analysis
        self.heuristic_analysis(code, language, context)
    }

    /// Analyze using external LLM API.
    async fn api_analysis(
        &self,
        code: &str,
        language: Language,
        context: &AnalysisContext,
        endpoint: &str,
        api_key: &str,
    ) -> Result<Vec<Finding>> {
        let prompt = self.build_security_prompt(code, language, context);

        let request = LlmRequest {
            model: "gpt-4".to_string(), // Or configured model
            messages: vec![
                LlmMessage {
                    role: "system".to_string(),
                    content: SECURITY_SYSTEM_PROMPT.to_string(),
                },
                LlmMessage {
                    role: "user".to_string(),
                    content: prompt,
                },
            ],
            max_tokens: 1000,
            temperature: 0.1, // Low temperature for consistent security analysis
        };

        let response = self
            .client
            .post(endpoint)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AuditorError::Analysis(format!(
                "LLM API error: {}",
                response.status()
            )));
        }

        let llm_response: LlmResponse = response.json().await?;

        // Parse the response into findings
        self.parse_llm_response(&llm_response, context)
    }

    /// Build a security-focused prompt for the LLM with Chain-of-Thought structure.
    fn build_security_prompt(&self, code: &str, language: Language, context: &AnalysisContext) -> String {
        let mut prompt = String::new();

        // Add few-shot examples for Rust to calibrate detection
        if language == Language::Rust {
            prompt.push_str(RUST_FEW_SHOT_EXAMPLES);
            prompt.push_str("\n\n---\n\n### NOW ANALYZE THE FOLLOWING CODE:\n\n");
        }

        prompt.push_str(&format!(
            "**Language**: {}\n",
            language
        ));

        if let Some(ref function_name) = context.function_name {
            prompt.push_str(&format!("**Function**: {}\n", function_name));
        }

        if !context.callers.is_empty() {
            prompt.push_str(&format!("**Called by**: {}\n", context.callers.join(", ")));
        }

        if !context.callees.is_empty() {
            prompt.push_str(&format!("**Calls**: {}\n", context.callees.join(", ")));
        }

        if !context.data_sources.is_empty() {
            prompt.push_str(&format!("**Data Sources**: {}\n", context.data_sources.join(", ")));
        }

        prompt.push_str("\n**Code to Analyze**:\n```");
        prompt.push_str(match language {
            Language::Rust => "rust",
            Language::Python => "python",
            Language::JavaScript | Language::TypeScript => "javascript",
            Language::Go => "go",
            _ => "",
        });
        prompt.push_str("\n");
        prompt.push_str(code);
        prompt.push_str("\n```\n\n");

        prompt.push_str(ANALYSIS_INSTRUCTIONS);

        prompt.push_str("\n\n**IMPORTANT**: Follow the Chain-of-Thought protocol. First analyze surface, invariants, data flow, and compiler checks. Only THEN determine if vulnerabilities exist. Output valid JSON.");

        prompt
    }

    /// Parse LLM response into findings with Chain-of-Thought metadata.
    fn parse_llm_response(&self, response: &LlmResponse, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let content = response
            .choices
            .first()
            .map(|c| &c.message.content)
            .ok_or_else(|| AuditorError::Analysis("Empty LLM response".to_string()))?;

        // Parse structured response
        let mut findings = Vec::new();

        // Extract JSON from response (handle markdown code blocks)
        let json_content = Self::extract_json_from_response(content);

        // Try to parse as JSON first
        if let Ok(parsed) = serde_json::from_str::<LlmAnalysisResult>(&json_content) {
            // Log Chain-of-Thought reasoning for debugging
            if let Some(ref cot) = parsed.chain_of_thought {
                debug!("CoT Surface: {:?}", cot.surface_analysis);
                debug!("CoT Invariant: {:?}", cot.invariant_analysis);
                debug!("CoT DataFlow: {:?}", cot.data_flow);
                debug!("CoT Compiler: {:?}", cot.compiler_check);
            }

            for vuln in parsed.vulnerabilities {
                let severity = match vuln.severity.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Unknown,
                };

                let confidence = match vuln.confidence.to_lowercase().as_str() {
                    "high" => Confidence::High,
                    "medium" => Confidence::Medium,
                    _ => Confidence::Low,
                };

                let location = Location::new(
                    context.file_path.clone(),
                    vuln.line.unwrap_or(1),
                    1,
                );

                let mut finding = Finding::sast(
                    format!("ai/{}", vuln.vulnerability_type.to_lowercase().replace(' ', "-").replace(':', "-")),
                    &vuln.vulnerability_type,
                    &vuln.description,
                    location,
                    severity,
                )
                .with_confidence(confidence)
                .with_remediation(&vuln.remediation)
                .with_metadata("detection_method", serde_json::json!("llm_cot"));

                // Add evidence if provided
                if let Some(ref evidence) = vuln.evidence {
                    finding = finding.with_metadata("evidence", serde_json::json!(evidence));
                }

                // Add CWE ID if provided
                if let Some(ref cwe_id) = vuln.cwe_id {
                    finding = finding.with_metadata("cwe_id", serde_json::json!(cwe_id));
                }

                // Add Chain-of-Thought metadata if available
                if let Some(ref cot) = parsed.chain_of_thought {
                    if let Some(ref analysis) = cot.data_flow {
                        finding = finding.with_metadata("cot_data_flow", serde_json::json!(analysis));
                    }
                }

                findings.push(finding);
            }
        } else {
            // Fallback: parse free-form text response
            debug!("Could not parse structured response: {}", content);
        }

        Ok(findings)
    }

    /// Extract JSON from a response that may be wrapped in markdown code blocks.
    fn extract_json_from_response(content: &str) -> String {
        // Try to find JSON in code blocks
        if let Some(start) = content.find("```json") {
            let after_marker = &content[start + 7..];
            if let Some(end) = after_marker.find("```") {
                return after_marker[..end].trim().to_string();
            }
        }

        // Try plain code blocks
        if let Some(start) = content.find("```") {
            let after_marker = &content[start + 3..];
            // Skip language identifier if present
            let json_start = after_marker.find('\n').map(|i| i + 1).unwrap_or(0);
            let after_newline = &after_marker[json_start..];
            if let Some(end) = after_newline.find("```") {
                return after_newline[..end].trim().to_string();
            }
        }

        // Try to find raw JSON object
        if let Some(start) = content.find('{') {
            if let Some(end) = content.rfind('}') {
                if end > start {
                    return content[start..=end].to_string();
                }
            }
        }

        // Return as-is
        content.to_string()
    }

    /// Heuristic analysis without LLM.
    fn heuristic_analysis(
        &self,
        code: &str,
        language: Language,
        context: &AnalysisContext,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Pattern-based heuristics for common issues
        let patterns = match language {
            Language::Rust => vec![
                ("std::mem::transmute", "Potential type confusion", Severity::High),
                ("ptr::write_volatile", "Volatile write may have race conditions", Severity::Medium),
                ("from_raw_parts", "Unchecked slice creation from raw parts", Severity::High),
                ("ManuallyDrop", "Manual memory management may leak", Severity::Medium),
                ("UnsafeCell", "Interior mutability may cause data races", Severity::Medium),
            ],
            Language::Python => vec![
                ("subprocess.call", "Shell command execution", Severity::Medium),
                ("yaml.load", "Unsafe YAML loading (use safe_load)", Severity::High),
                ("marshal.loads", "Unsafe deserialization", Severity::Critical),
            ],
            Language::JavaScript => vec![
                ("dangerouslySetInnerHTML", "React XSS risk", Severity::High),
                ("new Function(", "Dynamic function creation", Severity::High),
                ("setTimeout(", "Potential code injection if string", Severity::Medium),
                (".createContextualFragment", "DOM-based XSS", Severity::High),
                ("location.href =", "Open redirect potential", Severity::Medium),
            ],
            Language::Go => vec![
                ("cgo", "CGO introduces memory safety risks", Severity::Medium),
                ("reflect.SliceHeader", "Unsafe slice manipulation", Severity::High),
                ("unsafe.Pointer", "Unsafe pointer usage", Severity::High),
                ("//#nosec", "Security check disabled", Severity::Low),
            ],
            _ => vec![],
        };

        for (pattern, description, severity) in patterns {
            if code.contains(pattern) {
                let line = code
                    .lines()
                    .enumerate()
                    .find(|(_, l)| l.contains(pattern))
                    .map(|(i, _)| i + 1)
                    .unwrap_or(1);

                let location = Location::new(context.file_path.clone(), line, 1);

                let finding = Finding::sast(
                    format!("ai-heuristic/{}", pattern.replace("::", "-").replace('.', "-")),
                    format!("Heuristic: {}", pattern),
                    description,
                    location,
                    severity,
                )
                .with_confidence(Confidence::Low)
                .with_metadata("detection_method", serde_json::json!("heuristic"));

                findings.push(finding);
            }
        }

        // Check for common security anti-patterns
        findings.extend(self.check_security_antipatterns(code, language, context));

        Ok(findings)
    }

    /// Check for common security anti-patterns.
    fn check_security_antipatterns(
        &self,
        code: &str,
        language: Language,
        context: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for TODO/FIXME related to security
        for (line_num, line) in code.lines().enumerate() {
            let line_lower = line.to_lowercase();

            if (line_lower.contains("todo") || line_lower.contains("fixme") || line_lower.contains("hack"))
                && (line_lower.contains("security")
                    || line_lower.contains("vuln")
                    || line_lower.contains("auth")
                    || line_lower.contains("crypt")
                    || line_lower.contains("inject")
                    || line_lower.contains("xss"))
            {
                let location = Location::new(context.file_path.clone(), line_num + 1, 1)
                    .with_language(language);

                let finding = Finding::sast(
                    "ai-heuristic/security-todo",
                    "Security-Related TODO",
                    format!("Developer note indicates security concern: {}", line.trim()),
                    location,
                    Severity::Medium,
                )
                .with_confidence(Confidence::Medium)
                .with_remediation("Address the security concern noted in this comment.");

                findings.push(finding);
            }
        }

        // Check for disabled security features
        let disabled_patterns = [
            ("verify=False", "SSL verification disabled"),
            ("check=False", "Subprocess check disabled"),
            ("shell=True", "Shell execution enabled"),
            ("dangerouslySetInnerHTML", "React sanitization bypassed"),
            ("trustAllCerts", "Certificate validation disabled"),
            ("csrf_exempt", "CSRF protection disabled"),
            ("@nosecurity", "Security checks disabled"),
            ("CORS: *", "CORS allows all origins"),
        ];

        for (pattern, description) in disabled_patterns {
            if code.contains(pattern) {
                let line = code
                    .lines()
                    .enumerate()
                    .find(|(_, l)| l.contains(pattern))
                    .map(|(i, _)| i + 1)
                    .unwrap_or(1);

                let location = Location::new(context.file_path.clone(), line, 1)
                    .with_language(language);

                let finding = Finding::sast(
                    "ai-heuristic/disabled-security",
                    "Disabled Security Control",
                    description,
                    location,
                    Severity::High,
                )
                .with_confidence(Confidence::High);

                findings.push(finding);
            }
        }

        findings
    }

    /// Check if AI analysis is available.
    pub fn is_available(&self) -> bool {
        self.use_local || (self.api_endpoint.is_some() && self.api_key.is_some())
    }
}

impl Default for AiAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Context for AI analysis.
#[derive(Debug, Clone, Default)]
pub struct AnalysisContext {
    /// File path being analyzed
    pub file_path: std::path::PathBuf,

    /// Function or method name
    pub function_name: Option<String>,

    /// Functions that call this code
    pub callers: Vec<String>,

    /// Functions called by this code
    pub callees: Vec<String>,

    /// Data flow information
    pub data_sources: Vec<String>,

    /// Additional context
    pub metadata: std::collections::HashMap<String, String>,
}

/// LLM API request structure.
#[derive(Debug, Serialize)]
struct LlmRequest {
    model: String,
    messages: Vec<LlmMessage>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Debug, Serialize, Deserialize)]
struct LlmMessage {
    role: String,
    content: String,
}

/// LLM API response structure.
#[derive(Debug, Deserialize)]
struct LlmResponse {
    choices: Vec<LlmChoice>,
}

#[derive(Debug, Deserialize)]
struct LlmChoice {
    message: LlmMessage,
}

/// Structured analysis result from LLM with Chain-of-Thought.
#[derive(Debug, Deserialize)]
struct LlmAnalysisResult {
    /// Chain-of-thought reasoning (optional for backward compatibility)
    #[serde(default)]
    chain_of_thought: Option<ChainOfThought>,
    /// Detected vulnerabilities
    vulnerabilities: Vec<LlmVulnerability>,
}

/// Chain-of-Thought reasoning structure.
#[derive(Debug, Deserialize, Default)]
struct ChainOfThought {
    #[serde(default)]
    surface_analysis: Option<String>,
    #[serde(default)]
    invariant_analysis: Option<String>,
    #[serde(default)]
    data_flow: Option<String>,
    #[serde(default)]
    compiler_check: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LlmVulnerability {
    vulnerability_type: String,
    severity: String,
    confidence: String,
    description: String,
    #[serde(default)]
    line: Option<usize>,
    remediation: String,
    /// Evidence from the code
    #[serde(default)]
    evidence: Option<String>,
    /// CWE identifier
    #[serde(default)]
    cwe_id: Option<String>,
}

/// System prompt for security analysis with Chain-of-Thought reasoning.
///
/// This prompt implements the research-backed "Role + CoT + Protocol" structure
/// that reduces hallucinations and improves precision in vulnerability detection.
const SECURITY_SYSTEM_PROMPT: &str = r#"You are a specialized Security Auditor Agent. Your mission is to identify cryptographic failures, memory safety violations, injection flaws, and logic vulnerabilities with precision and minimal false positives.

### ANALYSIS PROTOCOL (Chain of Thought)

You MUST follow these steps in order before rendering a verdict:

**Step 1: Surface Analysis**
- Identify all public entry points (exported functions, API handlers, main)
- List all `unsafe` blocks, FFI calls, or dangerous function calls
- Note all external inputs (user data, network, files, environment)

**Step 2: Invariant Analysis**
For each `unsafe` block or dangerous operation:
- Explicitly state the safety contract required
- Identify what invariants must hold (pointer validity, bounds, lifetimes)
- Check if surrounding code upholds these invariants

**Step 3: Data Flow Tracing**
- Trace user-controlled inputs from sources to sinks
- Identify all transformations and sanitization steps
- Determine if tainted data reaches sensitive operations unsanitized

**Step 4: Compiler Verification (for Rust)**
- Specify if the potential vulnerability would be caught by the borrow checker
- Mark issues as "Compiler Enforced" if the type system prevents exploitation
- Only report as vulnerability if it bypasses compiler guarantees

**Step 5: Verdict**
- Only after completing Steps 1-4, determine if a vulnerability exists
- Assign confidence based on certainty of the data flow and invariant violations

### OUTPUT FORMAT

Respond STRICTLY in JSON with the following structure:
{
  "chain_of_thought": {
    "surface_analysis": "What entry points and dangerous operations were found",
    "invariant_analysis": "What safety contracts exist and are they upheld",
    "data_flow": "How does untrusted data flow through the code",
    "compiler_check": "What does the compiler guarantee (for Rust)"
  },
  "vulnerabilities": [
    {
      "vulnerability_type": "CWE-XXX: Name",
      "severity": "critical|high|medium|low",
      "confidence": "high|medium|low",
      "description": "Detailed technical description",
      "line": 42,
      "evidence": "The specific code pattern that indicates the vulnerability",
      "remediation": "Specific fix with code example if applicable",
      "cwe_id": "CWE-XXX"
    }
  ]
}

### SEVERITY GUIDELINES

- **Critical**: Remote code execution, authentication bypass, privilege escalation
- **High**: SQL injection, command injection, unsafe deserialization, memory corruption
- **Medium**: XSS, information disclosure, insecure defaults, path traversal
- **Low**: Information leakage, missing headers, minor configuration issues

### CONFIDENCE GUIDELINES

- **High**: Clear data flow from source to sink, missing sanitization is evident
- **Medium**: Likely vulnerability but depends on runtime conditions or external factors
- **Low**: Suspicious pattern but cannot confirm exploitability from static analysis

If no vulnerabilities are found, return:
{
  "chain_of_thought": { ... analysis ... },
  "vulnerabilities": []
}"#;

/// Few-shot examples for Rust vulnerability detection.
/// These calibrate the model's detection threshold and reduce false positives.
const RUST_FEW_SHOT_EXAMPLES: &str = r#"
### FEW-SHOT EXAMPLE 1: Use-After-Free (TRUE POSITIVE)

```rust
use std::cell::RefCell;
use std::rc::Rc;

fn vulnerable_uaf() {
    let data = Rc::new(RefCell::new(vec![1, 2, 3]));
    let reference = data.borrow();
    let ptr = reference.as_ptr();  // Raw pointer to inner data
    drop(reference);
    drop(data);  // Data is freed here
    unsafe {
        // Use-after-free: ptr is now dangling
        println!("{}", *ptr);  // CWE-416
    }
}
```

**Analysis:**
{
  "chain_of_thought": {
    "surface_analysis": "Found unsafe block with raw pointer dereference",
    "invariant_analysis": "Raw pointer requires underlying data to be alive; data is dropped before use",
    "data_flow": "ptr derived from data, data dropped, ptr dereferenced",
    "compiler_check": "Borrow checker cannot track raw pointers - NOT compiler enforced"
  },
  "vulnerabilities": [{
    "vulnerability_type": "CWE-416: Use After Free",
    "severity": "high",
    "confidence": "high",
    "description": "Raw pointer `ptr` is dereferenced after `data` is dropped, causing use-after-free",
    "line": 11,
    "evidence": "println!(\"{}\", *ptr) after drop(data)",
    "remediation": "Keep Rc alive while using raw pointer, or use safe references",
    "cwe_id": "CWE-416"
  }]
}

### FEW-SHOT EXAMPLE 2: Race Condition (TRUE POSITIVE)

```rust
use std::sync::{Arc, Mutex};
use std::thread;

fn vulnerable_race() {
    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for _ in 0..10 {
        let counter = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            let mut num = counter.lock().unwrap();
            let current = *num;  // Read value
            // Lock is dropped here due to temporary scope
            drop(num);
            // TOCTOU gap: another thread can modify counter here
            let new_counter = Arc::clone(&counter);
            let mut num = new_counter.lock().unwrap();
            *num = current + 1;  // Write stale value - race condition!
        });
        handles.push(handle);
    }
}
```

**Analysis:**
{
  "chain_of_thought": {
    "surface_analysis": "Mutex with multiple threads, lock acquired and released multiple times",
    "invariant_analysis": "Counter increment requires atomic read-modify-write; lock released between read and write",
    "data_flow": "Value read under lock, lock dropped, value written under new lock",
    "compiler_check": "Rust prevents data races but not logic races - race condition possible"
  },
  "vulnerabilities": [{
    "vulnerability_type": "CWE-362: Race Condition",
    "severity": "medium",
    "confidence": "high",
    "description": "TOCTOU vulnerability: Mutex lock is released between reading and writing counter, allowing stale value writes",
    "line": 14,
    "evidence": "drop(num) followed by separate lock acquisition and write",
    "remediation": "Keep lock held during entire read-modify-write: `*num += 1` without dropping lock",
    "cwe_id": "CWE-362"
  }]
}

### FEW-SHOT EXAMPLE 3: Safe Usage of Unsafe (FALSE POSITIVE - DO NOT REPORT)

```rust
fn safe_slice_from_raw_parts(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    // Bounds checking BEFORE unsafe operation
    if offset.checked_add(len)? > data.len() {
        return None;
    }

    // This unsafe is actually safe because:
    // 1. Bounds are verified above
    // 2. Source slice is borrowed, so data is valid
    // 3. Alignment is correct (u8 has alignment 1)
    unsafe {
        let ptr = data.as_ptr().add(offset);
        Some(std::slice::from_raw_parts(ptr, len))
    }
}
```

**Analysis:**
{
  "chain_of_thought": {
    "surface_analysis": "Found unsafe block with from_raw_parts and pointer arithmetic",
    "invariant_analysis": "from_raw_parts requires valid ptr, correct len, and proper alignment. All invariants upheld: bounds checked, ptr from valid slice, u8 alignment trivially satisfied",
    "data_flow": "Input bounds validated before any unsafe operation",
    "compiler_check": "Lifetime tied to input slice borrow - compiler ensures data validity"
  },
  "vulnerabilities": []
}

This is NOT a vulnerability because the bounds check before the unsafe block ensures all safety invariants are upheld.
"#;

/// Instructions for analysis.
const ANALYSIS_INSTRUCTIONS: &str = r#"
Analyze this code for security vulnerabilities. Consider:

1. **Input Validation**: Is user input properly validated and sanitized?
2. **Authentication**: Are there authentication bypass risks?
3. **Authorization**: Are access controls properly enforced?
4. **Injection**: Can malicious input affect execution (SQL, command, code)?
5. **Data Exposure**: Could sensitive data be leaked?
6. **Cryptography**: Are cryptographic operations secure?
7. **Race Conditions**: Are there TOCTOU or other timing issues?
8. **Error Handling**: Do errors reveal sensitive information?

Provide your analysis as structured JSON with vulnerabilities found.
"#;

// ============================================================================
// Compiler-in-the-Loop Feedback System
// ============================================================================

/// Result of running the compiler on code.
#[derive(Debug, Clone)]
pub struct CompilerFeedback {
    /// Whether the code compiled successfully.
    pub compiles: bool,
    /// Compiler errors if compilation failed.
    pub errors: Vec<CompilerDiagnostic>,
    /// Compiler warnings.
    pub warnings: Vec<CompilerDiagnostic>,
    /// Raw stderr output.
    pub raw_output: String,
    /// Time taken for compilation.
    pub compile_time_ms: u64,
}

/// A single compiler diagnostic (error or warning).
#[derive(Debug, Clone)]
pub struct CompilerDiagnostic {
    /// Diagnostic level (error, warning, note, help).
    pub level: DiagnosticLevel,
    /// Error/warning code (e.g., E0382, W0000).
    pub code: Option<String>,
    /// Primary message.
    pub message: String,
    /// File where the diagnostic occurred.
    pub file: Option<PathBuf>,
    /// Line number.
    pub line: Option<usize>,
    /// Column number.
    pub column: Option<usize>,
    /// Span of the problematic code.
    pub span: Option<String>,
    /// Suggested fix from the compiler.
    pub suggestion: Option<String>,
}

/// Diagnostic severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Error,
    Warning,
    Note,
    Help,
}

/// Compiler feedback loop for validating LLM-generated fixes.
///
/// This implements a "compiler-in-the-loop" pattern where:
/// 1. LLM suggests a vulnerability fix
/// 2. We inject the fix into a temporary crate
/// 3. We run `cargo check` to validate the fix compiles
/// 4. We parse compiler feedback and return it to the LLM for refinement
pub struct CompilerFeedbackLoop {
    /// Directory for temporary crates.
    temp_dir: PathBuf,
    /// Cargo path (default: "cargo").
    cargo_path: String,
    /// Timeout for cargo check in seconds.
    timeout_secs: u64,
    /// Additional Cargo.toml dependencies to include.
    extra_dependencies: HashMap<String, String>,
    /// Edition to use (default: 2021).
    edition: String,
}

impl Default for CompilerFeedbackLoop {
    fn default() -> Self {
        Self::new()
    }
}

impl CompilerFeedbackLoop {
    /// Create a new compiler feedback loop.
    pub fn new() -> Self {
        Self {
            temp_dir: std::env::temp_dir().join("sec_auditor_cfl"),
            cargo_path: "cargo".to_string(),
            timeout_secs: 30,
            extra_dependencies: HashMap::new(),
            edition: "2021".to_string(),
        }
    }

    /// Set the temporary directory for crates.
    pub fn with_temp_dir(mut self, dir: PathBuf) -> Self {
        self.temp_dir = dir;
        self
    }

    /// Set the cargo path.
    pub fn with_cargo_path(mut self, path: String) -> Self {
        self.cargo_path = path;
        self
    }

    /// Set the compilation timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Add extra dependencies for the temporary crate.
    pub fn with_dependency(mut self, name: &str, version: &str) -> Self {
        self.extra_dependencies.insert(name.to_string(), version.to_string());
        self
    }

    /// Check if Rust code compiles and return compiler feedback.
    pub fn check_rust_code(&self, code: &str) -> Result<CompilerFeedback> {
        let start = std::time::Instant::now();

        // Create temporary crate directory
        let crate_dir = self.create_temp_crate(code)?;

        // Run cargo check
        let output = self.run_cargo_check(&crate_dir)?;

        let compile_time_ms = start.elapsed().as_millis() as u64;

        // Parse compiler output
        let feedback = self.parse_compiler_output(&output, compile_time_ms);

        // Clean up (best effort)
        let _ = std::fs::remove_dir_all(&crate_dir);

        Ok(feedback)
    }

    /// Check if a code fix would compile when applied to existing code.
    pub fn validate_fix(
        &self,
        original_code: &str,
        fixed_code: &str,
        dependencies: &[(&str, &str)],
    ) -> Result<FixValidation> {
        // First check if original code compiles
        let original_feedback = self.check_rust_code(original_code)?;

        // Add dependencies and check fixed code
        let mut cfl = self.clone();
        for (name, version) in dependencies {
            cfl = cfl.with_dependency(name, version);
        }
        let fixed_feedback = cfl.check_rust_code(fixed_code)?;

        // Compute lengths before moving errors
        let original_error_count = original_feedback.errors.len();
        let fixed_error_count = fixed_feedback.errors.len();

        Ok(FixValidation {
            original_compiles: original_feedback.compiles,
            fixed_compiles: fixed_feedback.compiles,
            original_errors: original_error_count,
            fixed_errors: fixed_error_count,
            original_warnings: original_feedback.warnings.len(),
            fixed_warnings: fixed_feedback.warnings.len(),
            new_errors: fixed_feedback.errors,
            improvement: original_error_count as i32 - fixed_error_count as i32,
        })
    }

    /// Create a temporary crate with the given code.
    fn create_temp_crate(&self, code: &str) -> Result<PathBuf> {
        // Create unique directory
        let crate_name = format!("cfl_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        let crate_dir = self.temp_dir.join(&crate_name);

        std::fs::create_dir_all(&crate_dir).map_err(|e| {
            AuditorError::Analysis(format!("Failed to create temp crate dir: {}", e))
        })?;

        // Create Cargo.toml
        let mut deps = String::new();
        for (name, version) in &self.extra_dependencies {
            deps.push_str(&format!("{} = \"{}\"\n", name, version));
        }

        let cargo_toml = format!(
            r#"[package]
name = "{}"
version = "0.1.0"
edition = "{}"

[dependencies]
{}
"#,
            crate_name, self.edition, deps
        );

        std::fs::write(crate_dir.join("Cargo.toml"), cargo_toml).map_err(|e| {
            AuditorError::Analysis(format!("Failed to write Cargo.toml: {}", e))
        })?;

        // Create src directory
        let src_dir = crate_dir.join("src");
        std::fs::create_dir_all(&src_dir).map_err(|e| {
            AuditorError::Analysis(format!("Failed to create src dir: {}", e))
        })?;

        // Write main.rs or lib.rs
        let main_rs = if code.contains("fn main(") {
            code.to_string()
        } else {
            format!("{}\n\nfn main() {{}}", code)
        };

        std::fs::write(src_dir.join("main.rs"), main_rs).map_err(|e| {
            AuditorError::Analysis(format!("Failed to write main.rs: {}", e))
        })?;

        Ok(crate_dir)
    }

    /// Run cargo check on a crate directory.
    fn run_cargo_check(&self, crate_dir: &Path) -> Result<std::process::Output> {
        let output = Command::new(&self.cargo_path)
            .args(["check", "--message-format=json"])
            .current_dir(crate_dir)
            .output()
            .map_err(|e| AuditorError::Analysis(format!("Failed to run cargo check: {}", e)))?;

        Ok(output)
    }

    /// Parse compiler output into structured feedback.
    fn parse_compiler_output(&self, output: &std::process::Output, compile_time_ms: u64) -> CompilerFeedback {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Parse JSON messages from stdout (cargo check --message-format=json)
        for line in stdout.lines() {
            if let Ok(msg) = serde_json::from_str::<CargoMessage>(line) {
                if let CargoMessage::CompilerMessage { message } = msg {
                    let level = match message.level.as_str() {
                        "error" => DiagnosticLevel::Error,
                        "warning" => DiagnosticLevel::Warning,
                        "note" => DiagnosticLevel::Note,
                        "help" => DiagnosticLevel::Help,
                        _ => continue,
                    };

                    let diag = CompilerDiagnostic {
                        level,
                        code: message.code.map(|c| c.code),
                        message: message.message,
                        file: message.spans.first().and_then(|s| {
                            s.file_name.as_ref().map(PathBuf::from)
                        }),
                        line: message.spans.first().map(|s| s.line_start),
                        column: message.spans.first().map(|s| s.column_start),
                        span: message.spans.first().and_then(|s| s.text.first().map(|t| t.text.clone())),
                        suggestion: message.children.iter()
                            .find(|c| c.level == "help")
                            .map(|c| c.message.clone()),
                    };

                    match level {
                        DiagnosticLevel::Error => errors.push(diag),
                        DiagnosticLevel::Warning => warnings.push(diag),
                        _ => {}
                    }
                }
            }
        }

        CompilerFeedback {
            compiles: output.status.success() && errors.is_empty(),
            errors,
            warnings,
            raw_output: stderr,
            compile_time_ms,
        }
    }

    /// Generate a prompt enhancement with compiler feedback for LLM.
    pub fn format_feedback_for_llm(&self, feedback: &CompilerFeedback) -> String {
        if feedback.compiles {
            return "The code compiles successfully with no errors.".to_string();
        }

        let mut prompt = String::new();
        prompt.push_str("## COMPILER FEEDBACK\n\n");
        prompt.push_str("The code does NOT compile. Here are the errors:\n\n");

        for (i, err) in feedback.errors.iter().enumerate() {
            prompt.push_str(&format!("### Error {} ", i + 1));
            if let Some(ref code) = err.code {
                prompt.push_str(&format!("[{}]", code));
            }
            prompt.push('\n');

            prompt.push_str(&format!("**Message**: {}\n", err.message));

            if let (Some(ref file), Some(line)) = (&err.file, err.line) {
                prompt.push_str(&format!("**Location**: {}:{}\n", file.display(), line));
            }

            if let Some(ref span) = err.span {
                prompt.push_str(&format!("**Code**: `{}`\n", span));
            }

            if let Some(ref suggestion) = err.suggestion {
                prompt.push_str(&format!("**Suggestion**: {}\n", suggestion));
            }

            prompt.push('\n');
        }

        if !feedback.warnings.is_empty() {
            prompt.push_str(&format!("\nThere are also {} warnings.\n", feedback.warnings.len()));
        }

        prompt.push_str("\nPlease revise your fix to address these compiler errors.");

        prompt
    }
}

impl Clone for CompilerFeedbackLoop {
    fn clone(&self) -> Self {
        Self {
            temp_dir: self.temp_dir.clone(),
            cargo_path: self.cargo_path.clone(),
            timeout_secs: self.timeout_secs,
            extra_dependencies: self.extra_dependencies.clone(),
            edition: self.edition.clone(),
        }
    }
}

/// Result of validating a code fix.
#[derive(Debug, Clone)]
pub struct FixValidation {
    /// Whether the original code compiles.
    pub original_compiles: bool,
    /// Whether the fixed code compiles.
    pub fixed_compiles: bool,
    /// Number of errors in original code.
    pub original_errors: usize,
    /// Number of errors in fixed code.
    pub fixed_errors: usize,
    /// Number of warnings in original code.
    pub original_warnings: usize,
    /// Number of warnings in fixed code.
    pub fixed_warnings: usize,
    /// New errors introduced by the fix.
    pub new_errors: Vec<CompilerDiagnostic>,
    /// Improvement score (positive = fewer errors after fix).
    pub improvement: i32,
}

impl FixValidation {
    /// Check if the fix is valid (code compiles or improves).
    pub fn is_valid(&self) -> bool {
        self.fixed_compiles || self.improvement > 0
    }

    /// Check if the fix introduced new errors.
    pub fn introduced_errors(&self) -> bool {
        self.fixed_errors > self.original_errors
    }
}

// Cargo JSON message types
#[derive(Debug, Deserialize)]
#[serde(tag = "reason")]
enum CargoMessage {
    #[serde(rename = "compiler-message")]
    CompilerMessage { message: CompilerMessageInner },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct CompilerMessageInner {
    level: String,
    code: Option<CompilerCode>,
    message: String,
    #[serde(default)]
    spans: Vec<CompilerSpan>,
    #[serde(default)]
    children: Vec<CompilerChild>,
}

#[derive(Debug, Deserialize)]
struct CompilerCode {
    code: String,
}

#[derive(Debug, Deserialize)]
struct CompilerSpan {
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    line_start: usize,
    #[serde(default)]
    column_start: usize,
    #[serde(default)]
    text: Vec<CompilerText>,
}

#[derive(Debug, Deserialize)]
struct CompilerText {
    text: String,
}

#[derive(Debug, Deserialize)]
struct CompilerChild {
    level: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heuristic_analysis() {
        let analyzer = AiAnalyzer::new();
        let code = r#"
            import yaml
            data = yaml.load(user_input)  # Unsafe YAML loading!
        "#;

        let context = AnalysisContext {
            file_path: "test.py".into(),
            ..Default::default()
        };

        let findings = analyzer
            .heuristic_analysis(code, Language::Python, &context)
            .unwrap();

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.description.contains("YAML")));
    }

    #[test]
    fn test_security_todo_detection() {
        let analyzer = AiAnalyzer::new();
        let code = r#"
            // TODO: Fix this security vulnerability before release
            fn handle_auth() {}
        "#;

        let context = AnalysisContext {
            file_path: "test.rs".into(),
            ..Default::default()
        };

        let findings = analyzer.check_security_antipatterns(code, Language::Rust, &context);

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("TODO")));
    }

    #[test]
    fn test_compiler_feedback_valid_code() {
        let cfl = CompilerFeedbackLoop::new();

        let valid_code = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;

        let feedback = cfl.check_rust_code(valid_code).unwrap();
        assert!(feedback.compiles, "Valid code should compile");
        assert!(feedback.errors.is_empty(), "Valid code should have no errors");
    }

    #[test]
    fn test_compiler_feedback_invalid_code() {
        let cfl = CompilerFeedbackLoop::new();

        let invalid_code = r#"
fn broken() {
    let x: String = 42;  // Type error: expected String, got i32
}
"#;

        let feedback = cfl.check_rust_code(invalid_code).unwrap();
        assert!(!feedback.compiles, "Invalid code should not compile");
        assert!(!feedback.errors.is_empty(), "Invalid code should have errors");
    }

    #[test]
    fn test_compiler_feedback_borrow_error() {
        let cfl = CompilerFeedbackLoop::new();

        let borrow_error_code = r#"
fn borrow_problem() {
    let mut s = String::from("hello");
    let r1 = &s;
    let r2 = &mut s;  // Error: cannot borrow as mutable while immutable borrow exists
    println!("{} {}", r1, r2);
}
"#;

        let feedback = cfl.check_rust_code(borrow_error_code).unwrap();
        assert!(!feedback.compiles, "Code with borrow error should not compile");
        // The error should be about borrowing
        let has_borrow_error = feedback.errors.iter().any(|e| {
            e.message.contains("borrow") || e.code.as_ref().map(|c| c == "E0502").unwrap_or(false)
        });
        assert!(has_borrow_error, "Should detect borrow error");
    }

    #[test]
    fn test_format_feedback_for_llm() {
        let cfl = CompilerFeedbackLoop::new();

        let feedback = CompilerFeedback {
            compiles: false,
            errors: vec![CompilerDiagnostic {
                level: DiagnosticLevel::Error,
                code: Some("E0382".to_string()),
                message: "use of moved value: `s`".to_string(),
                file: Some(PathBuf::from("src/main.rs")),
                line: Some(5),
                column: Some(10),
                span: Some("println!(\"{}\", s);".to_string()),
                suggestion: Some("consider cloning the value".to_string()),
            }],
            warnings: vec![],
            raw_output: String::new(),
            compile_time_ms: 100,
        };

        let prompt = cfl.format_feedback_for_llm(&feedback);

        assert!(prompt.contains("COMPILER FEEDBACK"));
        assert!(prompt.contains("E0382"));
        assert!(prompt.contains("use of moved value"));
        assert!(prompt.contains("consider cloning"));
    }
}
