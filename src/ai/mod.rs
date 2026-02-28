//! AI-driven vulnerability analysis module using LM Studio.
//!
//! This module provides AI-powered analysis using a local LLM via LM Studio's
//! OpenAI-compatible API endpoint (default: http://localhost:1234/v1).
//!
//! LM Studio provides a local HTTP server that mimics the OpenAI API, allowing
//! us to use local models without cloud dependencies or API keys.

use crate::error::{AuditorError, Result};
use crate::models::{Confidence, Finding, Language, Location, Severity};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// LM Studio API endpoint (OpenAI-compatible).
const LMSTUDIO_DEFAULT_URL: &str = "http://localhost:1234/v1/chat/completions";

/// Default timeout for AI requests (2 minutes - local models can be slow).
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Default model to use (LM Studio uses loaded model, this is just for API compatibility).
const DEFAULT_MODEL: &str = "local-model";

/// AI analyzer for advanced vulnerability detection using LM Studio.
pub struct AiAnalyzer {
    /// HTTP client for API calls
    client: Client,
    /// LM Studio API endpoint
    api_endpoint: String,
    /// Model name (for API compatibility)
    model: String,
    /// Maximum tokens per response
    max_tokens: u32,
    /// Temperature for generation
    temperature: f32,
    /// Whether AI analysis is enabled
    enabled: bool,
    /// Maximum file size to analyze (skip large files)
    max_file_size: usize,
    /// Cache for analysis results
    result_cache: HashMap<String, Vec<Finding>>,
}

impl AiAnalyzer {
    /// Create a new AI analyzer with LM Studio integration.
    pub fn new() -> Self {
        let api_endpoint = std::env::var("LMSTUDIO_URL")
            .unwrap_or_else(|_| LMSTUDIO_DEFAULT_URL.to_string());

        let model = std::env::var("LMSTUDIO_MODEL")
            .unwrap_or_else(|_| DEFAULT_MODEL.to_string());

        let timeout_secs = std::env::var("LMSTUDIO_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS);

        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_endpoint,
            model,
            max_tokens: 2048,
            temperature: 0.1, // Low temperature for consistent security analysis
            enabled: true,
            max_file_size: 100 * 1024, // 100KB max file size
            result_cache: HashMap::new(),
        }
    }

    /// Create analyzer with custom endpoint.
    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.api_endpoint = endpoint;
        self
    }

    /// Create analyzer with custom model name.
    pub fn with_model(mut self, model: String) -> Self {
        self.model = model;
        self
    }

    /// Disable AI analysis.
    pub fn disabled() -> Self {
        let mut analyzer = Self::new();
        analyzer.enabled = false;
        analyzer
    }

    /// Check if LM Studio is available.
    pub async fn is_available(&self) -> bool {
        if !self.enabled {
            return false;
        }

        // Try to connect to LM Studio
        match self.check_health().await {
            Ok(true) => {
                info!("LM Studio is available at {}", self.api_endpoint);
                true
            }
            Ok(false) => {
                warn!("LM Studio is not running at {}", self.api_endpoint);
                false
            }
            Err(e) => {
                warn!("Failed to check LM Studio availability: {}", e);
                false
            }
        }
    }

    /// Check LM Studio health by making a simple request.
    async fn check_health(&self) -> Result<bool> {
        // Try to get models list or make a simple completion
        let health_url = self.api_endpoint.replace("/chat/completions", "/models");
        
        match self.client.get(&health_url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => {
                // Try the completions endpoint directly with a minimal request
                let test_request = LlmRequest {
                    model: self.model.clone(),
                    messages: vec![
                        LlmMessage {
                            role: "user".to_string(),
                            content: "hi".to_string(),
                        },
                    ],
                    max_tokens: Some(1),
                    temperature: Some(0.1),
                };

                match self.client.post(&self.api_endpoint).json(&test_request).send().await {
                    Ok(response) => Ok(response.status().is_success()),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    /// Analyze a code snippet for vulnerabilities.
    pub async fn analyze_snippet(
        &self,
        code: &str,
        language: Language,
        context: &AnalysisContext,
    ) -> Result<Vec<Finding>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        // Skip files that are too large
        if code.len() > self.max_file_size {
            debug!("Skipping AI analysis for large file: {} bytes", code.len());
            return Ok(Vec::new());
        }

        // Check cache
        let cache_key = format!("{}:{}", context.file_path.display(), code.len());
        if let Some(cached) = self.result_cache.get(&cache_key) {
            debug!("Using cached AI analysis for {}", context.file_path.display());
            return Ok(cached.clone());
        }

        // Analyze via LM Studio
        let findings = self.lmstudio_analysis(code, language, context).await?;
        
        // Cache results
        // Note: In a real implementation, we'd use a proper cache with content hashing
        // For now, we skip caching to avoid stale results across different files with same length
        
        Ok(findings)
    }

    /// Perform analysis using LM Studio.
    async fn lmstudio_analysis(
        &self,
        code: &str,
        language: Language,
        context: &AnalysisContext,
    ) -> Result<Vec<Finding>> {
        let prompt = self.build_security_prompt(code, language, context);

        let request = LlmRequest {
            model: self.model.clone(),
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
            max_tokens: Some(self.max_tokens),
            temperature: Some(self.temperature),
        };

        debug!("Sending AI analysis request to LM Studio for {}", context.file_path.display());

        let response = self
            .client
            .post(&self.api_endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| AuditorError::Analysis(format!("LM Studio request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuditorError::Analysis(format!(
                "LM Studio API error ({}): {}",
                status, body
            )));
        }

        let llm_response: LlmResponse = response
            .json()
            .await
            .map_err(|e| AuditorError::Analysis(format!("Failed to parse LM Studio response: {}", e)))?;

        // Parse the response into findings
        self.parse_llm_response(&llm_response, context)
    }

    /// Build a security-focused prompt for the LLM.
    fn build_security_prompt(&self, code: &str, language: Language, context: &AnalysisContext) -> String {
        let mut prompt = String::with_capacity(code.len() + 1000);

        prompt.push_str(&format!("Analyze the following {} code for security vulnerabilities.\n\n", language));

        // Add file context
        prompt.push_str(&format!("File: {}\n", context.file_path.display()));
        
        if let Some(ref function_name) = context.function_name {
            prompt.push_str(&format!("Function: {}\n", function_name));
        }

        // Add code
        prompt.push_str("\n```");
        prompt.push_str(match language {
            Language::Rust => "rust",
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::TypeScript => "typescript",
            Language::Go => "go",
            Language::Java => "java",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Ruby => "ruby",
            Language::Unknown => "",
        });
        prompt.push('\n');
        
        // Truncate code if too long
        let max_code_len = 8000;
        if code.len() > max_code_len {
            prompt.push_str(&code[..max_code_len]);
            prompt.push_str("\n\n[... truncated ...]");
        } else {
            prompt.push_str(code);
        }
        
        prompt.push_str("\n```\n\n");
        prompt.push_str(ANALYSIS_INSTRUCTIONS);

        prompt
    }

    /// Parse LLM response into findings.
    fn parse_llm_response(&self, response: &LlmResponse, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let content = response
            .choices
            .first()
            .map(|c| &c.message.content)
            .ok_or_else(|| AuditorError::Analysis("Empty LLM response".to_string()))?;

        let mut findings = Vec::new();

        // Extract JSON from response
        let json_content = Self::extract_json_from_response(content);

        // Try to parse as structured JSON
        if let Ok(parsed) = serde_json::from_str::<LlmAnalysisResult>(&json_content) {
            debug!("AI found {} vulnerabilities", parsed.vulnerabilities.len());

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
                    format!("ai-{}", vuln.vulnerability_type.to_lowercase().replace(' ', "-")),
                    &vuln.vulnerability_type,
                    &vuln.description,
                    location,
                    severity,
                )
                .with_confidence(confidence)
                .with_metadata("detection_method", serde_json::json!("ai_llm"));

                if !vuln.remediation.is_empty() {
                    finding = finding.with_remediation(&vuln.remediation);
                }

                if let Some(ref cwe) = vuln.cwe_id {
                    finding = finding.with_metadata("cwe_id", serde_json::json!(cwe));
                }

                findings.push(finding);
            }
        } else {
            // Try to extract any JSON array from the response
            if let Some(start) = json_content.find('[') {
                if let Some(end) = json_content.rfind(']') {
                    let array_content = &json_content[start..=end];
                    if let Ok(vulns) = serde_json::from_str::<Vec<LlmVulnerability>>(array_content) {
                        for vuln in vulns {
                            let finding = Finding::sast(
                                format!("ai-{}", vuln.vulnerability_type.to_lowercase().replace(' ', "-")),
                                &vuln.vulnerability_type,
                                &vuln.description,
                                Location::new(context.file_path.clone(), vuln.line.unwrap_or(1), 1),
                                match vuln.severity.to_lowercase().as_str() {
                                    "critical" => Severity::Critical,
                                    "high" => Severity::High,
                                    "medium" => Severity::Medium,
                                    "low" => Severity::Low,
                                    _ => Severity::Unknown,
                                },
                            );
                            findings.push(finding);
                        }
                    }
                }
            }
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
            let json_start = after_marker.find('\n').map(|i| i + 1).unwrap_or(0);
            let after_newline = &after_marker[json_start..];
            if let Some(end) = after_newline.find("```") {
                return after_newline[..end].trim().to_string();
            }
        }

        // Try to find raw JSON object or array
        if let Some(start) = content.find(|c| c == '{' || c == '[') {
            let end_char = if content.chars().nth(start) == Some('{') { '}' } else { ']' };
            if let Some(end) = content.rfind(end_char) {
                if end > start {
                    return content[start..=end].to_string();
                }
            }
        }

        content.to_string()
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
    pub file_path: PathBuf,
    /// Function or method name
    pub function_name: Option<String>,
    /// Functions that call this code
    pub callers: Vec<String>,
    /// Functions called by this code
    pub callees: Vec<String>,
    /// Data flow information
    pub data_sources: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

// API Types

#[derive(Debug, Serialize)]
struct LlmRequest {
    model: String,
    messages: Vec<LlmMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LlmMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct LlmResponse {
    choices: Vec<LlmChoice>,
}

#[derive(Debug, Deserialize)]
struct LlmChoice {
    message: LlmMessage,
}

#[derive(Debug, Deserialize)]
struct LlmAnalysisResult {
    #[serde(default)]
    vulnerabilities: Vec<LlmVulnerability>,
}

#[derive(Debug, Deserialize)]
struct LlmVulnerability {
    vulnerability_type: String,
    severity: String,
    confidence: String,
    description: String,
    #[serde(default)]
    line: Option<usize>,
    #[serde(default)]
    remediation: String,
    #[serde(default)]
    cwe_id: Option<String>,
}

// Prompts

const SECURITY_SYSTEM_PROMPT: &str = r#"You are a security code analyzer. Your task is to identify security vulnerabilities in code.

Output your findings as a JSON array with the following structure:
[
  {
    "vulnerability_type": "SQL Injection",
    "severity": "high",
    "confidence": "high",
    "description": "User input is directly concatenated into SQL query without sanitization",
    "line": 42,
    "remediation": "Use parameterized queries or prepared statements",
    "cwe_id": "CWE-89"
  }
]

Severity levels: critical, high, medium, low
Confidence levels: high, medium, low

Be concise and focus on actual vulnerabilities, not style issues. If no vulnerabilities are found, return an empty array []."#;

const ANALYSIS_INSTRUCTIONS: &str = r#"Focus on these vulnerability categories:

1. **Injection** (SQL, Command, LDAP, XPath) - Look for string concatenation with user input
2. **XSS** - Look for unescaped output in HTML/JS contexts
3. **Path Traversal** - Look for file operations with user-controlled paths
4. **Authentication/Authorization** - Look for missing checks, weak crypto
5. **Insecure Deserialization** - Look for deserialize operations with untrusted data
6. **SSRF** - Look for requests to URLs from user input
7. **Cryptographic Issues** - Look for weak algorithms, hardcoded keys

Return findings as JSON."#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_from_response() {
        let response = r#"```json
{"vulnerabilities": []}
```"#;
        let extracted = AiAnalyzer::extract_json_from_response(response);
        assert!(extracted.contains("vulnerabilities"));

        let response2 = r#"{"vulnerabilities": [{"severity": "high"}]}"#;
        let extracted2 = AiAnalyzer::extract_json_from_response(response2);
        assert!(extracted2.contains("severity"));
    }
}
