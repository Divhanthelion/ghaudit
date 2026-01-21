//! Cross-language vulnerability pattern infrastructure.
//!
//! This module provides an Abstract Pattern Intermediate Representation (APIR)
//! that enables defining security vulnerability patterns once and applying them
//! across multiple programming languages.
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! | Pattern DSL      | --> | APIR (Abstract)  | --> | Language Mapping |
//! | (Human-readable) |     | (Canonical)      |     | (Concrete AST)   |
//! +------------------+     +------------------+     +------------------+
//!                                  |
//!                                  v
//!                          +------------------+
//!                          | Tree-sitter      |
//!                          | Pattern Matching |
//!                          +------------------+
//! ```
//!
//! # Pattern Categories
//!
//! - **Injection**: SQL, Command, XSS, LDAP, XPath
//! - **Cryptographic**: Weak algorithms, hardcoded keys, insecure RNG
//! - **Memory Safety**: Buffer overflows, use-after-free, null dereference
//! - **Authentication**: Hardcoded credentials, weak session management
//! - **Authorization**: IDOR, privilege escalation
//! - **Data Exposure**: PII leakage, verbose errors

mod apir;
mod lang_mapping;

pub use apir::*;
pub use lang_mapping::*;
