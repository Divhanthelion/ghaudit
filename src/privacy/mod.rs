//! Privacy-preserving code analysis module.
//!
//! This module provides privacy features for secure code analysis:
//! - Code anonymization pipeline for removing PII from code before LLM analysis
//! - Local-first inference tier using quantized models
//! - Identifier normalization to prevent data leakage
//!
//! # Privacy-First Architecture
//!
//! The privacy module implements a tiered approach:
//!
//! 1. **Code Anonymization**: Before any analysis, code can be anonymized to remove
//!    proprietary identifiers, internal API names, and potential PII.
//!
//! 2. **Local LLM Inference**: Quantized CodeLlama models can run entirely locally,
//!    ensuring code never leaves the user's machine.
//!
//! 3. **Optional Cloud Fallback**: If local confidence is low, users can opt-in to
//!    cloud-based analysis (disabled by default).

mod anonymizer;
mod local_llm;

pub use anonymizer::*;
pub use local_llm::*;
