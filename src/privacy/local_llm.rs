//! Local-first LLM inference tier for privacy-preserving analysis.
//!
//! This module provides local inference capabilities using quantized models,
//! allowing security analysis without sending code to external APIs.
//!
//! # Architecture
//!
//! The local LLM tier operates in a tiered approach:
//! 1. **Local-first**: Try local inference with quantized CodeLlama
//! 2. **Fallback**: If local fails or confidence is low, can optionally use cloud API
//!
//! # Supported Models
//!
//! - CodeLlama 7B (Q4_K_M quantization) - ~4GB RAM
//! - CodeLlama 13B (Q4_K_M quantization) - ~8GB RAM
//! - CodeLlama 34B (Q4_K_M quantization) - ~20GB RAM (recommended)

use crate::error::{AuditorError, Result};
use crate::models::{Finding, FindingCategory, Language, Location, Severity, Confidence};
use crate::privacy::anonymizer::{AnonymizationConfig, CodeAnonymizer};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Configuration for local LLM inference.
#[derive(Debug, Clone)]
pub struct LocalLlmConfig {
    /// Path to the quantized model file (GGUF format).
    pub model_path: Option<PathBuf>,
    /// Model context window size.
    pub context_size: usize,
    /// Number of tokens to generate.
    pub max_tokens: usize,
    /// Temperature for sampling (0.0 = deterministic).
    pub temperature: f32,
    /// Number of threads for inference.
    pub num_threads: usize,
    /// GPU layers to offload (0 = CPU only).
    pub gpu_layers: usize,
    /// Local llama.cpp server endpoint (if using server mode).
    pub server_endpoint: Option<String>,
    /// Timeout for inference requests.
    pub timeout: Duration,
    /// Whether to anonymize code before sending to local model.
    pub anonymize_code: bool,
    /// Minimum confidence threshold for accepting local results.
    pub min_confidence: f32,
    /// Whether to allow fallback to cloud API.
    pub allow_cloud_fallback: bool,
}

impl Default for LocalLlmConfig {
    fn default() -> Self {
        Self {
            model_path: None,
            context_size: 4096,
            max_tokens: 1024,
            temperature: 0.1, // Low temperature for consistent analysis
            num_threads: num_cpus::get(),
            gpu_layers: 0,
            server_endpoint: Some("http://127.0.0.1:8080".to_string()),
            timeout: Duration::from_secs(120),
            anonymize_code: true,
            min_confidence: 0.7,
            allow_cloud_fallback: false, // Privacy-first by default
        }
    }
}

/// Model size/quality tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelTier {
    /// 7B parameter model - fastest, lowest quality
    Small,
    /// 13B parameter model - balanced
    Medium,
    /// 34B parameter model - highest quality
    Large,
}

impl ModelTier {
    /// Estimated RAM requirement for Q4_K_M quantization.
    pub fn ram_requirement_gb(&self) -> f32 {
        match self {
            ModelTier::Small => 4.0,
            ModelTier::Medium => 8.0,
            ModelTier::Large => 20.0,
        }
    }

    /// Recommended context size.
    pub fn recommended_context_size(&self) -> usize {
        match self {
            ModelTier::Small => 4096,
            ModelTier::Medium => 8192,
            ModelTier::Large => 16384,
        }
    }

    /// Model identifier for llama.cpp.
    pub fn model_name(&self) -> &'static str {
        match self {
            ModelTier::Small => "codellama-7b-instruct.Q4_K_M.gguf",
            ModelTier::Medium => "codellama-13b-instruct.Q4_K_M.gguf",
            ModelTier::Large => "codellama-34b-instruct.Q4_K_M.gguf",
        }
    }
}

/// Result from local LLM analysis.
#[derive(Debug, Clone)]
pub struct LocalAnalysisResult {
    /// Detected vulnerabilities.
    pub findings: Vec<Finding>,
    /// Raw model response.
    pub raw_response: String,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    /// Whether the result was from local inference.
    pub is_local: bool,
    /// Inference time in milliseconds.
    pub inference_time_ms: u64,
    /// Tokens processed.
    pub tokens_processed: usize,
}

/// Request format for llama.cpp server.
#[derive(Debug, Serialize)]
struct LlamaServerRequest {
    prompt: String,
    n_predict: usize,
    temperature: f32,
    stop: Vec<String>,
    stream: bool,
}

/// Response format from llama.cpp server.
#[derive(Debug, Deserialize)]
struct LlamaServerResponse {
    content: String,
    #[serde(default)]
    tokens_evaluated: usize,
    #[serde(default)]
    tokens_predicted: usize,
    #[serde(default)]
    timings: Option<LlamaTimings>,
}

#[derive(Debug, Deserialize)]
struct LlamaTimings {
    #[serde(default)]
    predicted_ms: f64,
    #[serde(default)]
    prompt_ms: f64,
}

/// Local LLM inference engine.
pub struct LocalLlmEngine {
    /// Configuration.
    config: LocalLlmConfig,
    /// HTTP client for server mode.
    client: Client,
    /// Code anonymizer.
    anonymizer: CodeAnonymizer,
    /// Security analysis prompt template.
    prompt_template: String,
}

impl LocalLlmEngine {
    /// Create a new local LLM engine with default configuration.
    pub fn new() -> Self {
        Self::with_config(LocalLlmConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: LocalLlmConfig) -> Self {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        let anonymizer_config = AnonymizationConfig {
            anonymize_strings: config.anonymize_code,
            anonymize_comments: config.anonymize_code,
            ..Default::default()
        };
        let anonymizer = CodeAnonymizer::with_config(anonymizer_config);

        let prompt_template = Self::build_prompt_template();

        Self {
            config,
            client,
            anonymizer,
            prompt_template,
        }
    }

    /// Build the security analysis prompt template.
    fn build_prompt_template() -> String {
        r#"[INST] You are a security vulnerability analyzer. Analyze the following code for security issues.

For each vulnerability found, respond with a JSON object in this exact format:
```json
{
  "vulnerabilities": [
    {
      "type": "vulnerability type (e.g., SQL Injection, XSS, Buffer Overflow)",
      "severity": "critical|high|medium|low",
      "line": line_number,
      "description": "brief description of the issue",
      "fix": "suggested remediation"
    }
  ],
  "confidence": 0.0-1.0
}
```

If no vulnerabilities are found, respond with:
```json
{"vulnerabilities": [], "confidence": 0.9}
```

Language: {language}
Code:
```{lang_ext}
{code}
```

Analyze for: SQL injection, command injection, XSS, buffer overflows, use-after-free,
race conditions, path traversal, insecure deserialization, and cryptographic issues.
[/INST]"#
            .to_string()
    }

    /// Check if local inference is available.
    pub async fn is_available(&self) -> bool {
        if let Some(ref endpoint) = self.config.server_endpoint {
            // Check if llama.cpp server is running
            let health_url = format!("{}/health", endpoint);
            match self.client.get(&health_url).send().await {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            }
        } else if let Some(ref model_path) = self.config.model_path {
            // Check if model file exists
            model_path.exists()
        } else {
            false
        }
    }

    /// Analyze code for vulnerabilities using local LLM.
    pub async fn analyze(
        &self,
        code: &str,
        language: Language,
    ) -> Result<LocalAnalysisResult> {
        let start = std::time::Instant::now();

        // Optionally anonymize code
        let (analysis_code, anonymized) = if self.config.anonymize_code {
            let anon = self.anonymizer.anonymize(code, language);
            (anon.code.clone(), Some(anon))
        } else {
            (code.to_string(), None)
        };

        // Build prompt
        let prompt = self.build_prompt(&analysis_code, language);

        // Run inference
        let response = self.run_inference(&prompt).await?;

        let inference_time = start.elapsed().as_millis() as u64;

        // Parse response
        let mut result = self.parse_response(&response.content, language)?;
        result.inference_time_ms = inference_time;
        result.tokens_processed = response.tokens_evaluated + response.tokens_predicted;
        result.is_local = true;
        result.raw_response = response.content;

        // De-anonymize findings if needed
        if let Some(anon) = anonymized {
            for finding in &mut result.findings {
                finding.description = anon.restore_message(&finding.description);
                finding.title = anon.restore_message(&finding.title);
            }
        }

        // Check confidence threshold
        if result.confidence < self.config.min_confidence && self.config.allow_cloud_fallback {
            warn!(
                "Local inference confidence ({:.2}) below threshold ({:.2})",
                result.confidence, self.config.min_confidence
            );
            // Caller can decide whether to use cloud fallback
        }

        Ok(result)
    }

    /// Build the analysis prompt.
    fn build_prompt(&self, code: &str, language: Language) -> String {
        let lang_ext = match language {
            Language::Rust => "rust",
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::Go => "go",
            Language::Java => "java",
            Language::C => "c",
            Language::Cpp => "cpp",
            _ => "text",
        };

        self.prompt_template
            .replace("{language}", &format!("{:?}", language))
            .replace("{lang_ext}", lang_ext)
            .replace("{code}", code)
    }

    /// Run inference via llama.cpp server.
    async fn run_inference(&self, prompt: &str) -> Result<LlamaServerResponse> {
        let endpoint = self
            .config
            .server_endpoint
            .as_ref()
            .ok_or_else(|| AuditorError::Config("No server endpoint configured".into()))?;

        let request = LlamaServerRequest {
            prompt: prompt.to_string(),
            n_predict: self.config.max_tokens,
            temperature: self.config.temperature,
            stop: vec!["[/INST]".to_string(), "```\n\n".to_string()],
            stream: false,
        };

        let url = format!("{}/completion", endpoint);
        debug!("Sending request to local LLM server: {}", url);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AuditorError::Analysis(format!("Local LLM request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuditorError::Analysis(format!(
                "Local LLM server error: {} - {}",
                status, body
            )));
        }

        let result: LlamaServerResponse = response
            .json()
            .await
            .map_err(|e| AuditorError::Parse(format!("Failed to parse LLM response: {}", e)))?;

        Ok(result)
    }

    /// Parse the LLM response into findings.
    fn parse_response(
        &self,
        response: &str,
        language: Language,
    ) -> Result<LocalAnalysisResult> {
        // Extract JSON from response
        let json_str = self.extract_json(response);

        let parsed: LlmAnalysisResponse = serde_json::from_str(&json_str).unwrap_or_else(|e| {
            debug!("Failed to parse LLM JSON response: {}", e);
            LlmAnalysisResponse {
                vulnerabilities: vec![],
                confidence: 0.5,
            }
        });

        let findings: Vec<Finding> = parsed
            .vulnerabilities
            .into_iter()
            .map(|v| self.vuln_to_finding(v, language))
            .collect();

        Ok(LocalAnalysisResult {
            findings,
            raw_response: String::new(),
            confidence: parsed.confidence,
            is_local: true,
            inference_time_ms: 0,
            tokens_processed: 0,
        })
    }

    /// Extract JSON from potentially wrapped response.
    fn extract_json(&self, response: &str) -> String {
        // Try to find JSON in code blocks
        if let Some(start) = response.find("```json") {
            let after_start = &response[start + 7..];
            if let Some(end) = after_start.find("```") {
                return after_start[..end].trim().to_string();
            }
        }

        // Try to find raw JSON object
        if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                return response[start..=end].to_string();
            }
        }

        // Return empty response
        r#"{"vulnerabilities": [], "confidence": 0.5}"#.to_string()
    }

    /// Convert LLM vulnerability to Finding.
    fn vuln_to_finding(&self, vuln: LlmVulnerability, language: Language) -> Finding {
        let severity = match vuln.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Medium,
        };

        let location = Location::new(
            PathBuf::new(), // Caller should set the actual path
            vuln.line.unwrap_or(1),
            1,
        )
        .with_language(language);

        Finding {
            id: uuid::Uuid::new_v4().to_string(),
            category: FindingCategory::Ai,
            severity,
            title: vuln.vuln_type,
            description: vuln.description,
            location,
            snippet: None,
            vulnerability: None,
            confidence: Confidence::Medium,
            rule_id: "ai/local-llm".to_string(),
            remediation: vuln.fix,
            metadata: std::collections::HashMap::new(),
            discovered_at: chrono::Utc::now(),
        }
    }

    /// Analyze multiple code snippets in batch.
    pub async fn analyze_batch(
        &self,
        snippets: Vec<(String, Language)>,
    ) -> Vec<Result<LocalAnalysisResult>> {
        let mut results = Vec::with_capacity(snippets.len());

        for (code, language) in snippets {
            results.push(self.analyze(&code, language).await);
        }

        results
    }

    /// Get model information.
    pub async fn get_model_info(&self) -> Result<ModelInfo> {
        let endpoint = self
            .config
            .server_endpoint
            .as_ref()
            .ok_or_else(|| AuditorError::Config("No server endpoint configured".into()))?;

        let url = format!("{}/props", endpoint);

        let response = self.client.get(&url).send().await.map_err(|e| {
            AuditorError::Analysis(format!("Failed to get model info: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(AuditorError::Analysis(
                "Failed to get model info".into(),
            ));
        }

        let props: serde_json::Value = response.json().await.map_err(|e| {
            AuditorError::Parse(format!("Failed to parse model info: {}", e))
        })?;

        Ok(ModelInfo {
            model_name: props
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            context_size: props
                .get("n_ctx")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
            vocab_size: props
                .get("n_vocab")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
        })
    }
}

impl Default for LocalLlmEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// LLM response structure.
#[derive(Debug, Deserialize)]
struct LlmAnalysisResponse {
    vulnerabilities: Vec<LlmVulnerability>,
    confidence: f32,
}

/// Vulnerability from LLM response.
#[derive(Debug, Deserialize)]
struct LlmVulnerability {
    #[serde(rename = "type")]
    vuln_type: String,
    severity: String,
    line: Option<usize>,
    description: String,
    #[serde(default)]
    fix: Option<String>,
}

/// Information about the loaded model.
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub model_name: String,
    pub context_size: usize,
    pub vocab_size: usize,
}

/// Tiered inference strategy.
pub struct TieredInference {
    /// Local LLM engine.
    local: LocalLlmEngine,
    /// Whether to use local-only mode.
    local_only: bool,
    /// Cloud API endpoint (if fallback allowed).
    cloud_endpoint: Option<String>,
    /// Cloud API key.
    cloud_api_key: Option<String>,
}

impl TieredInference {
    /// Create a new tiered inference system (local-only by default).
    pub fn new() -> Self {
        Self {
            local: LocalLlmEngine::new(),
            local_only: true,
            cloud_endpoint: None,
            cloud_api_key: None,
        }
    }

    /// Create with cloud fallback enabled.
    pub fn with_cloud_fallback(cloud_endpoint: String, api_key: String) -> Self {
        let mut config = LocalLlmConfig::default();
        config.allow_cloud_fallback = true;

        Self {
            local: LocalLlmEngine::with_config(config),
            local_only: false,
            cloud_endpoint: Some(cloud_endpoint),
            cloud_api_key: Some(api_key),
        }
    }

    /// Analyze code using tiered approach.
    pub async fn analyze(
        &self,
        code: &str,
        language: Language,
    ) -> Result<LocalAnalysisResult> {
        // Try local first
        if self.local.is_available().await {
            match self.local.analyze(code, language).await {
                Ok(result) if result.confidence >= self.local.config.min_confidence => {
                    info!(
                        "Local inference succeeded with confidence {:.2}",
                        result.confidence
                    );
                    return Ok(result);
                }
                Ok(result) => {
                    warn!(
                        "Local inference confidence ({:.2}) below threshold",
                        result.confidence
                    );
                    if self.local_only {
                        return Ok(result); // Return low-confidence result if local-only
                    }
                    // Fall through to cloud
                }
                Err(e) => {
                    warn!("Local inference failed: {}", e);
                    if self.local_only {
                        return Err(e);
                    }
                    // Fall through to cloud
                }
            }
        } else if self.local_only {
            return Err(AuditorError::Config(
                "Local LLM not available and cloud fallback disabled".into(),
            ));
        }

        // Fallback to cloud if allowed
        if !self.local_only {
            self.analyze_with_cloud(code, language).await
        } else {
            Err(AuditorError::Config(
                "No inference backend available".into(),
            ))
        }
    }

    /// Analyze using cloud API (only used as fallback).
    async fn analyze_with_cloud(
        &self,
        _code: &str,
        _language: Language,
    ) -> Result<LocalAnalysisResult> {
        // This would implement cloud API fallback
        // For privacy reasons, this is disabled by default
        Err(AuditorError::Config(
            "Cloud fallback not implemented - use local inference".into(),
        ))
    }
}

impl Default for TieredInference {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for configuring local LLM.
pub struct LocalLlmConfigBuilder {
    config: LocalLlmConfig,
}

impl LocalLlmConfigBuilder {
    /// Start building configuration.
    pub fn new() -> Self {
        Self {
            config: LocalLlmConfig::default(),
        }
    }

    /// Set model path.
    pub fn model_path(mut self, path: PathBuf) -> Self {
        self.config.model_path = Some(path);
        self
    }

    /// Set server endpoint.
    pub fn server_endpoint(mut self, endpoint: &str) -> Self {
        self.config.server_endpoint = Some(endpoint.to_string());
        self
    }

    /// Set context size.
    pub fn context_size(mut self, size: usize) -> Self {
        self.config.context_size = size;
        self
    }

    /// Set max tokens.
    pub fn max_tokens(mut self, tokens: usize) -> Self {
        self.config.max_tokens = tokens;
        self
    }

    /// Set temperature.
    pub fn temperature(mut self, temp: f32) -> Self {
        self.config.temperature = temp;
        self
    }

    /// Set GPU layers.
    pub fn gpu_layers(mut self, layers: usize) -> Self {
        self.config.gpu_layers = layers;
        self
    }

    /// Enable/disable code anonymization.
    pub fn anonymize_code(mut self, enable: bool) -> Self {
        self.config.anonymize_code = enable;
        self
    }

    /// Set minimum confidence threshold.
    pub fn min_confidence(mut self, confidence: f32) -> Self {
        self.config.min_confidence = confidence;
        self
    }

    /// Allow cloud fallback.
    pub fn allow_cloud_fallback(mut self, allow: bool) -> Self {
        self.config.allow_cloud_fallback = allow;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> LocalLlmConfig {
        self.config
    }
}

impl Default for LocalLlmConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = LocalLlmConfigBuilder::new()
            .server_endpoint("http://localhost:8080")
            .context_size(8192)
            .max_tokens(2048)
            .temperature(0.2)
            .anonymize_code(true)
            .min_confidence(0.8)
            .build();

        assert_eq!(config.server_endpoint, Some("http://localhost:8080".to_string()));
        assert_eq!(config.context_size, 8192);
        assert_eq!(config.max_tokens, 2048);
        assert!((config.temperature - 0.2).abs() < f32::EPSILON);
        assert!(config.anonymize_code);
        assert!((config.min_confidence - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn test_model_tier_info() {
        assert_eq!(ModelTier::Small.ram_requirement_gb(), 4.0);
        assert_eq!(ModelTier::Medium.ram_requirement_gb(), 8.0);
        assert_eq!(ModelTier::Large.ram_requirement_gb(), 20.0);

        assert_eq!(ModelTier::Small.recommended_context_size(), 4096);
        assert_eq!(ModelTier::Large.recommended_context_size(), 16384);
    }

    #[test]
    fn test_default_config() {
        let config = LocalLlmConfig::default();

        assert!(config.anonymize_code);
        assert!(!config.allow_cloud_fallback);
        assert!((config.temperature - 0.1).abs() < f32::EPSILON);
        assert_eq!(config.context_size, 4096);
    }

    #[test]
    fn test_json_extraction() {
        let engine = LocalLlmEngine::new();

        // Test code block extraction
        let response = r#"Here is the analysis:
```json
{"vulnerabilities": [], "confidence": 0.9}
```
End of analysis."#;
        let json = engine.extract_json(response);
        assert!(json.contains("vulnerabilities"));
        assert!(json.contains("0.9"));

        // Test raw JSON extraction
        let response2 = r#"Analysis: {"vulnerabilities": [{"type": "XSS"}], "confidence": 0.8}"#;
        let json2 = engine.extract_json(response2);
        assert!(json2.contains("XSS"));
    }

    #[test]
    fn test_prompt_building() {
        let engine = LocalLlmEngine::new();
        let prompt = engine.build_prompt("fn main() {}", Language::Rust);

        assert!(prompt.contains("[INST]"));
        assert!(prompt.contains("fn main() {}"));
        assert!(prompt.contains("rust"));
        assert!(prompt.contains("SQL injection"));
    }

    #[test]
    fn test_parse_empty_response() {
        let engine = LocalLlmEngine::new();

        let result = engine.parse_response(
            r#"{"vulnerabilities": [], "confidence": 0.95}"#,
            Language::Rust,
        );

        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert!(analysis.findings.is_empty());
        assert!((analysis.confidence - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_parse_vulnerability_response() {
        let engine = LocalLlmEngine::new();

        let response = r#"{
            "vulnerabilities": [
                {
                    "type": "SQL Injection",
                    "severity": "high",
                    "line": 42,
                    "description": "User input directly concatenated into SQL query"
                }
            ],
            "confidence": 0.85
        }"#;

        let result = engine.parse_response(response, Language::Python);
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].severity, Severity::High);
        assert!((analysis.confidence - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_tiered_inference_local_only() {
        let inference = TieredInference::new();
        assert!(inference.local_only);
        assert!(inference.cloud_endpoint.is_none());
    }

    #[test]
    fn test_severity_mapping() {
        let engine = LocalLlmEngine::new();

        let critical = LlmVulnerability {
            vuln_type: "Test".to_string(),
            severity: "critical".to_string(),
            line: None,
            description: "Test".to_string(),
            fix: None,
        };
        let finding = engine.vuln_to_finding(critical, Language::Rust);
        assert_eq!(finding.severity, Severity::Critical);

        let low = LlmVulnerability {
            vuln_type: "Test".to_string(),
            severity: "LOW".to_string(), // Test case insensitivity
            line: None,
            description: "Test".to_string(),
            fix: None,
        };
        let finding = engine.vuln_to_finding(low, Language::Rust);
        assert_eq!(finding.severity, Severity::Low);
    }
}
