//! Language mapping tables for cross-language vulnerability patterns.
//!
//! This module maps abstract APIR concepts to concrete tree-sitter node types
//! and function names for each supported programming language.

use crate::crosslang::apir::{
    AbstractNodeType, AbstractPattern, EndpointCategory, NameMatcher, VulnerabilityPattern,
};
use crate::models::Language;
use std::collections::HashMap;

/// Language-specific mapping configuration.
#[derive(Debug, Clone)]
pub struct LanguageMapping {
    /// Language identifier.
    pub language: Language,
    /// Node type mappings.
    pub node_types: NodeTypeMapping,
    /// Source endpoint mappings (taint sources).
    pub sources: EndpointMapping,
    /// Sink endpoint mappings (dangerous operations).
    pub sinks: EndpointMapping,
    /// Sanitizer function mappings.
    pub sanitizers: EndpointMapping,
}

impl LanguageMapping {
    /// Get mapping for a specific language.
    pub fn for_language(lang: Language) -> Self {
        match lang {
            Language::Rust => rust_mapping(),
            Language::Python => python_mapping(),
            Language::JavaScript => javascript_mapping(),
            Language::Go => go_mapping(),
            Language::Java => java_mapping(),
            Language::C | Language::Cpp => c_mapping(),
            _ => default_mapping(lang),
        }
    }
}

/// Mapping from abstract node types to concrete tree-sitter node types.
#[derive(Debug, Clone, Default)]
pub struct NodeTypeMapping {
    mappings: HashMap<AbstractNodeType, Vec<String>>,
}

impl NodeTypeMapping {
    /// Create a new node type mapping.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a mapping.
    pub fn add(&mut self, abstract_type: AbstractNodeType, concrete_types: Vec<&str>) {
        self.mappings.insert(
            abstract_type,
            concrete_types.iter().map(|s| s.to_string()).collect(),
        );
    }

    /// Get concrete types for an abstract type.
    pub fn get(&self, abstract_type: &AbstractNodeType) -> Vec<&str> {
        self.mappings
            .get(abstract_type)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }
}

/// Mapping for data flow endpoints (sources, sinks, sanitizers).
#[derive(Debug, Clone, Default)]
pub struct EndpointMapping {
    /// Function/method names by category.
    by_category: HashMap<EndpointCategory, Vec<EndpointInfo>>,
}

impl EndpointMapping {
    /// Create a new endpoint mapping.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an endpoint.
    pub fn add(&mut self, category: EndpointCategory, info: EndpointInfo) {
        self.by_category.entry(category).or_default().push(info);
    }

    /// Get endpoints for a category.
    pub fn get(&self, category: &EndpointCategory) -> &[EndpointInfo] {
        self.by_category
            .get(category)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all endpoints.
    pub fn all(&self) -> impl Iterator<Item = (&EndpointCategory, &Vec<EndpointInfo>)> {
        self.by_category.iter()
    }
}

/// Information about a specific endpoint (function/method).
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    /// Function/method name pattern.
    pub name: NameMatcher,
    /// Optional receiver type (for method calls).
    pub receiver: Option<String>,
    /// Which argument positions are tainted/sinks.
    pub arg_positions: Vec<usize>,
    /// Whether return value is tainted.
    pub returns_tainted: bool,
    /// Required module/import.
    pub module: Option<String>,
}

impl EndpointInfo {
    /// Create a simple function endpoint.
    pub fn function(name: &str) -> Self {
        Self {
            name: NameMatcher::Exact(name.to_string()),
            receiver: None,
            arg_positions: vec![0],
            returns_tainted: true,
            module: None,
        }
    }

    /// Create a method endpoint.
    pub fn method(receiver: &str, name: &str) -> Self {
        Self {
            name: NameMatcher::Exact(name.to_string()),
            receiver: Some(receiver.to_string()),
            arg_positions: vec![0],
            returns_tainted: true,
            module: None,
        }
    }

    /// Set argument positions.
    pub fn with_args(mut self, positions: Vec<usize>) -> Self {
        self.arg_positions = positions;
        self
    }

    /// Set module requirement.
    pub fn with_module(mut self, module: &str) -> Self {
        self.module = Some(module.to_string());
        self
    }

    /// Set return taint.
    pub fn returns(mut self, tainted: bool) -> Self {
        self.returns_tainted = tainted;
        self
    }
}

/// Create Rust language mapping.
fn rust_mapping() -> LanguageMapping {
    let mut node_types = NodeTypeMapping::new();

    // Node type mappings for Rust
    node_types.add(AbstractNodeType::Function, vec!["function_item"]);
    node_types.add(AbstractNodeType::Method, vec!["function_item"]); // In impl block
    node_types.add(AbstractNodeType::Class, vec!["struct_item", "enum_item"]);
    node_types.add(AbstractNodeType::Struct, vec!["struct_item"]);
    node_types.add(AbstractNodeType::Module, vec!["mod_item"]);
    node_types.add(AbstractNodeType::Parameter, vec!["parameter"]);
    node_types.add(AbstractNodeType::Variable, vec!["identifier"]);
    node_types.add(AbstractNodeType::Assignment, vec!["let_declaration", "assignment_expression"]);
    node_types.add(AbstractNodeType::CallExpression, vec!["call_expression"]);
    node_types.add(AbstractNodeType::MemberAccess, vec!["field_expression"]);
    node_types.add(AbstractNodeType::IfStatement, vec!["if_expression"]);
    node_types.add(AbstractNodeType::ForLoop, vec!["for_expression"]);
    node_types.add(AbstractNodeType::WhileLoop, vec!["while_expression"]);
    node_types.add(AbstractNodeType::Return, vec!["return_expression"]);
    node_types.add(AbstractNodeType::StringLiteral, vec!["string_literal", "raw_string_literal"]);
    node_types.add(AbstractNodeType::TryBlock, vec!["try_expression"]);

    let mut sources = EndpointMapping::new();

    // User input sources in Rust
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::function("read_line").with_module("std::io"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::function("args").with_module("std::env"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("Request", "body"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("Request", "query"),
    );

    // Environment sources
    sources.add(
        EndpointCategory::Environment,
        EndpointInfo::function("var").with_module("std::env"),
    );
    sources.add(
        EndpointCategory::Environment,
        EndpointInfo::function("var_os").with_module("std::env"),
    );

    let mut sinks = EndpointMapping::new();

    // SQL injection sinks
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("Connection", "execute").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("Connection", "query").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::function("query!").with_args(vec![0]).with_module("sqlx"),
    );

    // Command injection sinks
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::method("Command", "new").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::method("Command", "arg").with_args(vec![0]),
    );

    // File system sinks
    sinks.add(
        EndpointCategory::FileSystem,
        EndpointInfo::function("read_to_string").with_args(vec![0]).with_module("std::fs"),
    );
    sinks.add(
        EndpointCategory::FileSystem,
        EndpointInfo::function("write").with_args(vec![0]).with_module("std::fs"),
    );
    sinks.add(
        EndpointCategory::FileSystem,
        EndpointInfo::method("File", "open").with_args(vec![0]),
    );

    let mut sanitizers = EndpointMapping::new();

    // SQL sanitizers (parameterized queries)
    sanitizers.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::function("bind").returns(true),
    );

    // General sanitizers
    sanitizers.add(
        EndpointCategory::Custom("html".to_string()),
        EndpointInfo::function("escape").with_module("html_escape"),
    );

    LanguageMapping {
        language: Language::Rust,
        node_types,
        sources,
        sinks,
        sanitizers,
    }
}

/// Create Python language mapping.
fn python_mapping() -> LanguageMapping {
    let mut node_types = NodeTypeMapping::new();

    node_types.add(AbstractNodeType::Function, vec!["function_definition"]);
    node_types.add(AbstractNodeType::Method, vec!["function_definition"]);
    node_types.add(AbstractNodeType::Class, vec!["class_definition"]);
    node_types.add(AbstractNodeType::Module, vec!["module"]);
    node_types.add(AbstractNodeType::Parameter, vec!["parameter", "default_parameter"]);
    node_types.add(AbstractNodeType::Variable, vec!["identifier"]);
    node_types.add(AbstractNodeType::Assignment, vec!["assignment", "augmented_assignment"]);
    node_types.add(AbstractNodeType::CallExpression, vec!["call"]);
    node_types.add(AbstractNodeType::MemberAccess, vec!["attribute"]);
    node_types.add(AbstractNodeType::IfStatement, vec!["if_statement"]);
    node_types.add(AbstractNodeType::ForLoop, vec!["for_statement"]);
    node_types.add(AbstractNodeType::WhileLoop, vec!["while_statement"]);
    node_types.add(AbstractNodeType::Return, vec!["return_statement"]);
    node_types.add(AbstractNodeType::StringLiteral, vec!["string"]);
    node_types.add(AbstractNodeType::TryBlock, vec!["try_statement"]);
    node_types.add(AbstractNodeType::Import, vec!["import_statement", "import_from_statement"]);

    let mut sources = EndpointMapping::new();

    // User input sources
    sources.add(EndpointCategory::UserInput, EndpointInfo::function("input"));
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("request", "args").with_module("flask"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("request", "form").with_module("flask"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("request", "GET").with_module("django"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("request", "POST").with_module("django"),
    );
    sources.add(EndpointCategory::UserInput, EndpointInfo::function("argv").with_module("sys"));

    // Environment
    sources.add(
        EndpointCategory::Environment,
        EndpointInfo::method("os.environ", "get"),
    );
    sources.add(
        EndpointCategory::Environment,
        EndpointInfo::function("getenv").with_module("os"),
    );

    let mut sinks = EndpointMapping::new();

    // SQL injection sinks
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("cursor", "execute").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("cursor", "executemany").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::function("raw").with_args(vec![0]).with_module("django.db"),
    );

    // Command injection sinks
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("system").with_args(vec![0]).with_module("os"),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("popen").with_args(vec![0]).with_module("os"),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("call").with_args(vec![0]).with_module("subprocess"),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("run").with_args(vec![0]).with_module("subprocess"),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("Popen").with_args(vec![0]).with_module("subprocess"),
    );

    // Code execution sinks
    sinks.add(
        EndpointCategory::Custom("code_execution".to_string()),
        EndpointInfo::function("eval").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::Custom("code_execution".to_string()),
        EndpointInfo::function("exec").with_args(vec![0]),
    );

    // File system sinks
    sinks.add(
        EndpointCategory::FileSystem,
        EndpointInfo::function("open").with_args(vec![0]),
    );

    // Deserialization sinks
    sinks.add(
        EndpointCategory::Custom("deserialization".to_string()),
        EndpointInfo::function("loads").with_args(vec![0]).with_module("pickle"),
    );
    sinks.add(
        EndpointCategory::Custom("deserialization".to_string()),
        EndpointInfo::function("load").with_args(vec![0]).with_module("pickle"),
    );
    sinks.add(
        EndpointCategory::Custom("deserialization".to_string()),
        EndpointInfo::function("safe_load").with_args(vec![0]).with_module("yaml"),
    );

    let mut sanitizers = EndpointMapping::new();

    // SQL sanitizers
    sanitizers.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::function("escape_string"),
    );

    // HTML sanitizers
    sanitizers.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::function("escape").with_module("html"),
    );
    sanitizers.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::function("escape").with_module("markupsafe"),
    );

    // Path sanitizers
    sanitizers.add(
        EndpointCategory::FileSystem,
        EndpointInfo::function("realpath").with_module("os.path"),
    );
    sanitizers.add(
        EndpointCategory::FileSystem,
        EndpointInfo::function("normpath").with_module("os.path"),
    );

    LanguageMapping {
        language: Language::Python,
        node_types,
        sources,
        sinks,
        sanitizers,
    }
}

/// Create JavaScript language mapping.
fn javascript_mapping() -> LanguageMapping {
    let mut node_types = NodeTypeMapping::new();

    node_types.add(AbstractNodeType::Function, vec!["function_declaration", "function", "arrow_function"]);
    node_types.add(AbstractNodeType::Method, vec!["method_definition"]);
    node_types.add(AbstractNodeType::Class, vec!["class_declaration", "class"]);
    node_types.add(AbstractNodeType::Variable, vec!["identifier"]);
    node_types.add(AbstractNodeType::Assignment, vec!["assignment_expression", "variable_declarator"]);
    node_types.add(AbstractNodeType::CallExpression, vec!["call_expression"]);
    node_types.add(AbstractNodeType::MemberAccess, vec!["member_expression"]);
    node_types.add(AbstractNodeType::IfStatement, vec!["if_statement"]);
    node_types.add(AbstractNodeType::ForLoop, vec!["for_statement", "for_in_statement", "for_of_statement"]);
    node_types.add(AbstractNodeType::WhileLoop, vec!["while_statement"]);
    node_types.add(AbstractNodeType::Return, vec!["return_statement"]);
    node_types.add(AbstractNodeType::StringLiteral, vec!["string", "template_string"]);
    node_types.add(AbstractNodeType::TryBlock, vec!["try_statement"]);
    node_types.add(AbstractNodeType::Import, vec!["import_statement"]);

    let mut sources = EndpointMapping::new();

    // Browser sources
    sources.add(EndpointCategory::UserInput, EndpointInfo::method("document", "getElementById"));
    sources.add(EndpointCategory::UserInput, EndpointInfo::method("document", "querySelector"));
    sources.add(EndpointCategory::UserInput, EndpointInfo::method("window", "location"));
    sources.add(EndpointCategory::UserInput, EndpointInfo::method("document", "cookie"));
    sources.add(EndpointCategory::UserInput, EndpointInfo::method("URLSearchParams", "get"));

    // Node.js sources
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("req", "params"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("req", "query"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("req", "body"),
    );

    // Environment
    sources.add(
        EndpointCategory::Environment,
        EndpointInfo::method("process.env", ""),
    );

    let mut sinks = EndpointMapping::new();

    // DOM XSS sinks
    sinks.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::method("element", "innerHTML").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::method("element", "outerHTML").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::method("document", "write").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::method("document", "writeln").with_args(vec![0]),
    );

    // Code execution
    sinks.add(
        EndpointCategory::Custom("code_execution".to_string()),
        EndpointInfo::function("eval").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::Custom("code_execution".to_string()),
        EndpointInfo::function("Function").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::Custom("code_execution".to_string()),
        EndpointInfo::function("setTimeout").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::Custom("code_execution".to_string()),
        EndpointInfo::function("setInterval").with_args(vec![0]),
    );

    // Node.js command execution
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("exec").with_args(vec![0]).with_module("child_process"),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("execSync").with_args(vec![0]).with_module("child_process"),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("spawn").with_args(vec![0]).with_module("child_process"),
    );

    // SQL (Node.js)
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("connection", "query").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::function("raw").with_args(vec![0]),
    );

    let mut sanitizers = EndpointMapping::new();

    // HTML sanitizers
    sanitizers.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::function("encodeURIComponent"),
    );
    sanitizers.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::function("sanitize").with_module("DOMPurify"),
    );
    sanitizers.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::method("element", "textContent"),
    );

    LanguageMapping {
        language: Language::JavaScript,
        node_types,
        sources,
        sinks,
        sanitizers,
    }
}

/// Create Go language mapping.
fn go_mapping() -> LanguageMapping {
    let mut node_types = NodeTypeMapping::new();

    node_types.add(AbstractNodeType::Function, vec!["function_declaration"]);
    node_types.add(AbstractNodeType::Method, vec!["method_declaration"]);
    node_types.add(AbstractNodeType::Struct, vec!["struct_type"]);
    node_types.add(AbstractNodeType::Variable, vec!["identifier"]);
    node_types.add(AbstractNodeType::Assignment, vec!["short_var_declaration", "assignment_statement"]);
    node_types.add(AbstractNodeType::CallExpression, vec!["call_expression"]);
    node_types.add(AbstractNodeType::MemberAccess, vec!["selector_expression"]);
    node_types.add(AbstractNodeType::IfStatement, vec!["if_statement"]);
    node_types.add(AbstractNodeType::ForLoop, vec!["for_statement"]);
    node_types.add(AbstractNodeType::Return, vec!["return_statement"]);
    node_types.add(AbstractNodeType::StringLiteral, vec!["interpreted_string_literal", "raw_string_literal"]);
    node_types.add(AbstractNodeType::Import, vec!["import_declaration"]);

    let mut sources = EndpointMapping::new();

    // HTTP sources
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("Request", "FormValue"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("Request", "URL.Query"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("Request", "Body"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::function("Args").with_module("os"),
    );

    // Environment
    sources.add(
        EndpointCategory::Environment,
        EndpointInfo::function("Getenv").with_module("os"),
    );

    let mut sinks = EndpointMapping::new();

    // SQL
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("DB", "Exec").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("DB", "Query").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("DB", "QueryRow").with_args(vec![0]),
    );

    // Command execution
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("Command").with_args(vec![0]).with_module("os/exec"),
    );

    // HTML
    sinks.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::method("ResponseWriter", "Write").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::function("Fprint").with_args(vec![1]).with_module("fmt"),
    );

    let mut sanitizers = EndpointMapping::new();

    // HTML
    sanitizers.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::function("EscapeString").with_module("html"),
    );

    // Path
    sanitizers.add(
        EndpointCategory::FileSystem,
        EndpointInfo::function("Clean").with_module("path/filepath"),
    );

    LanguageMapping {
        language: Language::Go,
        node_types,
        sources,
        sinks,
        sanitizers,
    }
}

/// Create Java language mapping.
fn java_mapping() -> LanguageMapping {
    let mut node_types = NodeTypeMapping::new();

    node_types.add(AbstractNodeType::Function, vec!["method_declaration"]);
    node_types.add(AbstractNodeType::Method, vec!["method_declaration"]);
    node_types.add(AbstractNodeType::Class, vec!["class_declaration"]);
    node_types.add(AbstractNodeType::Variable, vec!["identifier"]);
    node_types.add(AbstractNodeType::Assignment, vec!["assignment_expression"]);
    node_types.add(AbstractNodeType::CallExpression, vec!["method_invocation"]);
    node_types.add(AbstractNodeType::MemberAccess, vec!["field_access"]);
    node_types.add(AbstractNodeType::IfStatement, vec!["if_statement"]);
    node_types.add(AbstractNodeType::ForLoop, vec!["for_statement", "enhanced_for_statement"]);
    node_types.add(AbstractNodeType::WhileLoop, vec!["while_statement"]);
    node_types.add(AbstractNodeType::Return, vec!["return_statement"]);
    node_types.add(AbstractNodeType::StringLiteral, vec!["string_literal"]);
    node_types.add(AbstractNodeType::TryBlock, vec!["try_statement"]);
    node_types.add(AbstractNodeType::Import, vec!["import_declaration"]);

    let mut sources = EndpointMapping::new();

    // HTTP sources
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("HttpServletRequest", "getParameter"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("HttpServletRequest", "getHeader"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("HttpServletRequest", "getCookies"),
    );
    sources.add(
        EndpointCategory::UserInput,
        EndpointInfo::method("HttpServletRequest", "getInputStream"),
    );

    let mut sinks = EndpointMapping::new();

    // SQL
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("Statement", "executeQuery").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("Statement", "execute").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("Connection", "prepareStatement").with_args(vec![0]),
    );

    // Command
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::method("Runtime", "exec").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::method("ProcessBuilder", "command").with_args(vec![0]),
    );

    // Deserialization
    sinks.add(
        EndpointCategory::Custom("deserialization".to_string()),
        EndpointInfo::method("ObjectInputStream", "readObject"),
    );

    let mut sanitizers = EndpointMapping::new();

    // OWASP ESAPI
    sanitizers.add(
        EndpointCategory::HtmlOutput,
        EndpointInfo::method("ESAPI.encoder()", "encodeForHTML"),
    );
    sanitizers.add(
        EndpointCategory::DatabaseQuery,
        EndpointInfo::method("ESAPI.encoder()", "encodeForSQL"),
    );

    LanguageMapping {
        language: Language::Java,
        node_types,
        sources,
        sinks,
        sanitizers,
    }
}

/// Create C/C++ language mapping.
fn c_mapping() -> LanguageMapping {
    let mut node_types = NodeTypeMapping::new();

    node_types.add(AbstractNodeType::Function, vec!["function_definition"]);
    node_types.add(AbstractNodeType::Struct, vec!["struct_specifier"]);
    node_types.add(AbstractNodeType::Variable, vec!["identifier"]);
    node_types.add(AbstractNodeType::Assignment, vec!["assignment_expression"]);
    node_types.add(AbstractNodeType::CallExpression, vec!["call_expression"]);
    node_types.add(AbstractNodeType::MemberAccess, vec!["field_expression"]);
    node_types.add(AbstractNodeType::IfStatement, vec!["if_statement"]);
    node_types.add(AbstractNodeType::ForLoop, vec!["for_statement"]);
    node_types.add(AbstractNodeType::WhileLoop, vec!["while_statement"]);
    node_types.add(AbstractNodeType::Return, vec!["return_statement"]);
    node_types.add(AbstractNodeType::StringLiteral, vec!["string_literal"]);

    let mut sources = EndpointMapping::new();

    sources.add(EndpointCategory::UserInput, EndpointInfo::function("scanf"));
    sources.add(EndpointCategory::UserInput, EndpointInfo::function("gets"));
    sources.add(EndpointCategory::UserInput, EndpointInfo::function("fgets"));
    sources.add(EndpointCategory::UserInput, EndpointInfo::function("getenv"));
    sources.add(EndpointCategory::UserInput, EndpointInfo::function("read"));
    sources.add(EndpointCategory::UserInput, EndpointInfo::function("recv"));

    let mut sinks = EndpointMapping::new();

    // Buffer overflow sinks
    sinks.add(
        EndpointCategory::MemoryOperation,
        EndpointInfo::function("strcpy").with_args(vec![1]),
    );
    sinks.add(
        EndpointCategory::MemoryOperation,
        EndpointInfo::function("strcat").with_args(vec![1]),
    );
    sinks.add(
        EndpointCategory::MemoryOperation,
        EndpointInfo::function("sprintf").with_args(vec![1]),
    );
    sinks.add(
        EndpointCategory::MemoryOperation,
        EndpointInfo::function("gets").with_args(vec![0]),
    );

    // Format string sinks
    sinks.add(
        EndpointCategory::Custom("format_string".to_string()),
        EndpointInfo::function("printf").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::Custom("format_string".to_string()),
        EndpointInfo::function("fprintf").with_args(vec![1]),
    );

    // Command execution
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("system").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("popen").with_args(vec![0]),
    );
    sinks.add(
        EndpointCategory::CommandExecution,
        EndpointInfo::function("execve").with_args(vec![0]),
    );

    let mut sanitizers = EndpointMapping::new();

    // Safe alternatives
    sanitizers.add(
        EndpointCategory::MemoryOperation,
        EndpointInfo::function("strncpy"),
    );
    sanitizers.add(
        EndpointCategory::MemoryOperation,
        EndpointInfo::function("strncat"),
    );
    sanitizers.add(
        EndpointCategory::MemoryOperation,
        EndpointInfo::function("snprintf"),
    );

    LanguageMapping {
        language: Language::C,
        node_types,
        sources,
        sinks,
        sanitizers,
    }
}

/// Default/fallback mapping for unsupported languages.
fn default_mapping(lang: Language) -> LanguageMapping {
    LanguageMapping {
        language: lang,
        node_types: NodeTypeMapping::new(),
        sources: EndpointMapping::new(),
        sinks: EndpointMapping::new(),
        sanitizers: EndpointMapping::new(),
    }
}

// ============================================================================
// SQL Injection Pattern Registry
// ============================================================================

/// Comprehensive SQL injection pattern registry for cross-language detection.
#[derive(Debug, Clone, Default)]
pub struct SqlInjectionRegistry {
    /// Database-specific sinks by language.
    pub sinks: HashMap<Language, Vec<SqlSink>>,
    /// ORM-specific patterns by language.
    pub orm_patterns: HashMap<Language, Vec<OrmPattern>>,
    /// SQL sanitizers by language.
    pub sanitizers: HashMap<Language, Vec<SqlSanitizer>>,
    /// String concatenation patterns (dangerous in SQL context).
    pub concat_patterns: HashMap<Language, Vec<String>>,
}

/// Information about a SQL execution sink.
#[derive(Debug, Clone)]
pub struct SqlSink {
    /// Database driver/library name.
    pub driver: String,
    /// Function or method name.
    pub function: String,
    /// Receiver type for method calls.
    pub receiver: Option<String>,
    /// Argument positions that are vulnerable to injection.
    pub vulnerable_args: Vec<usize>,
    /// Whether this is a prepared statement factory (potentially safe).
    pub is_prepared_factory: bool,
    /// Risk level (raw query is higher than parameterized).
    pub risk: SqlRisk,
}

/// Risk level for SQL operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlRisk {
    /// Direct raw query execution - highest risk.
    RawQuery,
    /// Query building without obvious parameterization.
    QueryBuilder,
    /// Prepared statement creation - safe if used correctly.
    PreparedStatement,
    /// ORM method that could be misused.
    OrmMethod,
}

/// ORM-specific SQL injection pattern.
#[derive(Debug, Clone)]
pub struct OrmPattern {
    /// ORM name (e.g., "SQLAlchemy", "ActiveRecord", "Hibernate").
    pub orm: String,
    /// Method that could be vulnerable.
    pub method: String,
    /// Pattern to detect unsafe usage (e.g., string interpolation in args).
    pub unsafe_pattern: String,
    /// Safe alternative pattern.
    pub safe_alternative: String,
}

/// SQL sanitization method.
#[derive(Debug, Clone)]
pub struct SqlSanitizer {
    /// Library/module name.
    pub library: String,
    /// Function name.
    pub function: String,
    /// Receiver type for method calls.
    pub receiver: Option<String>,
    /// Description of what this sanitizer does.
    pub description: String,
}

impl SqlInjectionRegistry {
    /// Create a new registry with all SQL injection patterns.
    pub fn new() -> Self {
        let mut registry = Self::default();

        // Register patterns for each language
        registry.register_rust_sql();
        registry.register_python_sql();
        registry.register_javascript_sql();
        registry.register_go_sql();
        registry.register_java_sql();
        registry.register_c_sql();

        registry
    }

    /// Get SQL sinks for a specific language.
    pub fn sinks_for(&self, lang: Language) -> &[SqlSink] {
        self.sinks.get(&lang).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get ORM patterns for a specific language.
    pub fn orm_patterns_for(&self, lang: Language) -> &[OrmPattern] {
        self.orm_patterns.get(&lang).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get SQL sanitizers for a specific language.
    pub fn sanitizers_for(&self, lang: Language) -> &[SqlSanitizer] {
        self.sanitizers.get(&lang).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Register Rust SQL injection patterns.
    fn register_rust_sql(&mut self) {
        let sinks = vec![
            // sqlx
            SqlSink {
                driver: "sqlx".to_string(),
                function: "query".to_string(),
                receiver: None,
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "sqlx".to_string(),
                function: "query_as".to_string(),
                receiver: None,
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "sqlx".to_string(),
                function: "query_scalar".to_string(),
                receiver: None,
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // diesel (raw_sql is the only danger)
            SqlSink {
                driver: "diesel".to_string(),
                function: "sql".to_string(),
                receiver: None,
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "diesel".to_string(),
                function: "sql_query".to_string(),
                receiver: None,
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // rusqlite
            SqlSink {
                driver: "rusqlite".to_string(),
                function: "execute".to_string(),
                receiver: Some("Connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "rusqlite".to_string(),
                function: "query".to_string(),
                receiver: Some("Connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "rusqlite".to_string(),
                function: "prepare".to_string(),
                receiver: Some("Connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: true,
                risk: SqlRisk::PreparedStatement,
            },
            // tokio-postgres
            SqlSink {
                driver: "tokio-postgres".to_string(),
                function: "query".to_string(),
                receiver: Some("Client".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "tokio-postgres".to_string(),
                function: "execute".to_string(),
                receiver: Some("Client".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // mysql
            SqlSink {
                driver: "mysql".to_string(),
                function: "query".to_string(),
                receiver: Some("Conn".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "mysql".to_string(),
                function: "exec".to_string(),
                receiver: Some("Conn".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // sea-orm raw queries
            SqlSink {
                driver: "sea-orm".to_string(),
                function: "query_all".to_string(),
                receiver: Some("DatabaseConnection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
        ];

        let orm_patterns = vec![
            OrmPattern {
                orm: "diesel".to_string(),
                method: "filter".to_string(),
                unsafe_pattern: r#"sql::<.*>\(.*format!.*\)"#.to_string(),
                safe_alternative: "Use diesel's DSL instead of raw SQL in filter".to_string(),
            },
            OrmPattern {
                orm: "sea-orm".to_string(),
                method: "from_raw_sql".to_string(),
                unsafe_pattern: r#"from_raw_sql.*\+|format!"#.to_string(),
                safe_alternative: "Use SeaORM's query builder with bind parameters".to_string(),
            },
        ];

        let sanitizers = vec![
            SqlSanitizer {
                library: "sqlx".to_string(),
                function: "bind".to_string(),
                receiver: Some("Query".to_string()),
                description: "Parameterized query binding".to_string(),
            },
            SqlSanitizer {
                library: "rusqlite".to_string(),
                function: "params!".to_string(),
                receiver: None,
                description: "Rusqlite parameter macro".to_string(),
            },
        ];

        self.sinks.insert(Language::Rust, sinks);
        self.orm_patterns.insert(Language::Rust, orm_patterns);
        self.sanitizers.insert(Language::Rust, sanitizers);
        self.concat_patterns.insert(Language::Rust, vec![
            r#"format!\s*\(\s*"[^"]*SELECT"#.to_string(),
            r#"format!\s*\(\s*"[^"]*INSERT"#.to_string(),
            r#"format!\s*\(\s*"[^"]*UPDATE"#.to_string(),
            r#"format!\s*\(\s*"[^"]*DELETE"#.to_string(),
            r#"\+\s*".*WHERE"#.to_string(),
        ]);
    }

    /// Register Python SQL injection patterns.
    fn register_python_sql(&mut self) {
        let sinks = vec![
            // sqlite3
            SqlSink {
                driver: "sqlite3".to_string(),
                function: "execute".to_string(),
                receiver: Some("cursor".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "sqlite3".to_string(),
                function: "executemany".to_string(),
                receiver: Some("cursor".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "sqlite3".to_string(),
                function: "executescript".to_string(),
                receiver: Some("cursor".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // psycopg2
            SqlSink {
                driver: "psycopg2".to_string(),
                function: "execute".to_string(),
                receiver: Some("cursor".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "psycopg2".to_string(),
                function: "mogrify".to_string(),
                receiver: Some("cursor".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // mysql-connector-python
            SqlSink {
                driver: "mysql.connector".to_string(),
                function: "execute".to_string(),
                receiver: Some("cursor".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // PyMySQL
            SqlSink {
                driver: "pymysql".to_string(),
                function: "execute".to_string(),
                receiver: Some("cursor".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // asyncpg
            SqlSink {
                driver: "asyncpg".to_string(),
                function: "execute".to_string(),
                receiver: Some("connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "asyncpg".to_string(),
                function: "fetch".to_string(),
                receiver: Some("connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // Django
            SqlSink {
                driver: "django".to_string(),
                function: "raw".to_string(),
                receiver: Some("Manager".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "django".to_string(),
                function: "extra".to_string(),
                receiver: Some("QuerySet".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::OrmMethod,
            },
            // SQLAlchemy
            SqlSink {
                driver: "sqlalchemy".to_string(),
                function: "text".to_string(),
                receiver: None,
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "sqlalchemy".to_string(),
                function: "execute".to_string(),
                receiver: Some("engine".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
        ];

        let orm_patterns = vec![
            OrmPattern {
                orm: "Django".to_string(),
                method: "extra".to_string(),
                unsafe_pattern: r#"extra\s*\(.*where\s*=\s*\[.*%s"#.to_string(),
                safe_alternative: "Use Django's ORM methods or parameterized raw()".to_string(),
            },
            OrmPattern {
                orm: "Django".to_string(),
                method: "raw".to_string(),
                unsafe_pattern: r#"raw\s*\(.*%.*%"#.to_string(),
                safe_alternative: "Use %s placeholders with params argument".to_string(),
            },
            OrmPattern {
                orm: "SQLAlchemy".to_string(),
                method: "filter".to_string(),
                unsafe_pattern: r#"filter\s*\(.*text\s*\(.*\+|%|f""#.to_string(),
                safe_alternative: "Use SQLAlchemy's column comparison or bindparams".to_string(),
            },
            OrmPattern {
                orm: "SQLAlchemy".to_string(),
                method: "execute".to_string(),
                unsafe_pattern: r#"execute\s*\(.*f"|.*\+.*\+|.*%s.*%"#.to_string(),
                safe_alternative: "Use text() with bindparams".to_string(),
            },
        ];

        let sanitizers = vec![
            SqlSanitizer {
                library: "psycopg2".to_string(),
                function: "sql.Identifier".to_string(),
                receiver: None,
                description: "Safe identifier quoting for psycopg2".to_string(),
            },
            SqlSanitizer {
                library: "psycopg2".to_string(),
                function: "sql.Literal".to_string(),
                receiver: None,
                description: "Safe literal quoting for psycopg2".to_string(),
            },
            SqlSanitizer {
                library: "mysql.connector".to_string(),
                function: "escape_string".to_string(),
                receiver: Some("connection".to_string()),
                description: "MySQL string escaping".to_string(),
            },
            SqlSanitizer {
                library: "sqlalchemy".to_string(),
                function: "bindparam".to_string(),
                receiver: None,
                description: "SQLAlchemy bind parameter".to_string(),
            },
        ];

        self.sinks.insert(Language::Python, sinks);
        self.orm_patterns.insert(Language::Python, orm_patterns);
        self.sanitizers.insert(Language::Python, sanitizers);
        self.concat_patterns.insert(Language::Python, vec![
            r#"f"[^"]*SELECT.*\{"#.to_string(),
            r#"f"[^"]*INSERT.*\{"#.to_string(),
            r#"f"[^"]*UPDATE.*\{"#.to_string(),
            r#"f"[^"]*DELETE.*\{"#.to_string(),
            r#"".*SELECT.*"\s*%"#.to_string(),
            r#"".*WHERE.*"\s*\+"#.to_string(),
            r#"\.format\s*\(.*\).*SELECT"#.to_string(),
        ]);
    }

    /// Register JavaScript SQL injection patterns.
    fn register_javascript_sql(&mut self) {
        let sinks = vec![
            // mysql/mysql2
            SqlSink {
                driver: "mysql".to_string(),
                function: "query".to_string(),
                receiver: Some("connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "mysql2".to_string(),
                function: "query".to_string(),
                receiver: Some("connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "mysql2".to_string(),
                function: "execute".to_string(),
                receiver: Some("connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // pg (node-postgres)
            SqlSink {
                driver: "pg".to_string(),
                function: "query".to_string(),
                receiver: Some("client".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "pg".to_string(),
                function: "query".to_string(),
                receiver: Some("pool".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // better-sqlite3
            SqlSink {
                driver: "better-sqlite3".to_string(),
                function: "prepare".to_string(),
                receiver: Some("db".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: true,
                risk: SqlRisk::PreparedStatement,
            },
            SqlSink {
                driver: "better-sqlite3".to_string(),
                function: "exec".to_string(),
                receiver: Some("db".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // Sequelize
            SqlSink {
                driver: "sequelize".to_string(),
                function: "query".to_string(),
                receiver: Some("sequelize".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // Knex
            SqlSink {
                driver: "knex".to_string(),
                function: "raw".to_string(),
                receiver: Some("knex".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "knex".to_string(),
                function: "whereRaw".to_string(),
                receiver: Some("query".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::QueryBuilder,
            },
            SqlSink {
                driver: "knex".to_string(),
                function: "havingRaw".to_string(),
                receiver: Some("query".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::QueryBuilder,
            },
            SqlSink {
                driver: "knex".to_string(),
                function: "orderByRaw".to_string(),
                receiver: Some("query".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::QueryBuilder,
            },
            // Prisma (raw queries)
            SqlSink {
                driver: "prisma".to_string(),
                function: "$queryRaw".to_string(),
                receiver: Some("prisma".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "prisma".to_string(),
                function: "$executeRaw".to_string(),
                receiver: Some("prisma".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // TypeORM
            SqlSink {
                driver: "typeorm".to_string(),
                function: "query".to_string(),
                receiver: Some("connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "typeorm".to_string(),
                function: "query".to_string(),
                receiver: Some("manager".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
        ];

        let orm_patterns = vec![
            OrmPattern {
                orm: "Sequelize".to_string(),
                method: "query".to_string(),
                unsafe_pattern: r#"query\s*\(\s*`[^`]*\$\{"#.to_string(),
                safe_alternative: "Use replacements option with ? placeholders".to_string(),
            },
            OrmPattern {
                orm: "Knex".to_string(),
                method: "whereRaw".to_string(),
                unsafe_pattern: r#"whereRaw\s*\(\s*`[^`]*\$\{"#.to_string(),
                safe_alternative: "Use ? placeholders with bindings array".to_string(),
            },
            OrmPattern {
                orm: "TypeORM".to_string(),
                method: "where".to_string(),
                unsafe_pattern: r#"where\s*\(\s*`[^`]*\$\{"#.to_string(),
                safe_alternative: "Use query builder parameters with :param syntax".to_string(),
            },
        ];

        let sanitizers = vec![
            SqlSanitizer {
                library: "mysql".to_string(),
                function: "escape".to_string(),
                receiver: Some("connection".to_string()),
                description: "MySQL string escaping".to_string(),
            },
            SqlSanitizer {
                library: "mysql".to_string(),
                function: "escapeId".to_string(),
                receiver: Some("connection".to_string()),
                description: "MySQL identifier escaping".to_string(),
            },
            SqlSanitizer {
                library: "pg".to_string(),
                function: "escapeLiteral".to_string(),
                receiver: Some("client".to_string()),
                description: "PostgreSQL literal escaping".to_string(),
            },
            SqlSanitizer {
                library: "pg".to_string(),
                function: "escapeIdentifier".to_string(),
                receiver: Some("client".to_string()),
                description: "PostgreSQL identifier escaping".to_string(),
            },
            SqlSanitizer {
                library: "sqlstring".to_string(),
                function: "escape".to_string(),
                receiver: None,
                description: "SQL string escaping library".to_string(),
            },
        ];

        self.sinks.insert(Language::JavaScript, sinks);
        self.orm_patterns.insert(Language::JavaScript, orm_patterns);
        self.sanitizers.insert(Language::JavaScript, sanitizers);
        self.concat_patterns.insert(Language::JavaScript, vec![
            r#"`[^`]*SELECT[^`]*\$\{"#.to_string(),
            r#"`[^`]*INSERT[^`]*\$\{"#.to_string(),
            r#"`[^`]*UPDATE[^`]*\$\{"#.to_string(),
            r#"`[^`]*DELETE[^`]*\$\{"#.to_string(),
            r#"".*SELECT.*"\s*\+"#.to_string(),
            r#"'.*SELECT.*'\s*\+"#.to_string(),
        ]);
    }

    /// Register Go SQL injection patterns.
    fn register_go_sql(&mut self) {
        let sinks = vec![
            // database/sql
            SqlSink {
                driver: "database/sql".to_string(),
                function: "Exec".to_string(),
                receiver: Some("DB".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "database/sql".to_string(),
                function: "Query".to_string(),
                receiver: Some("DB".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "database/sql".to_string(),
                function: "QueryRow".to_string(),
                receiver: Some("DB".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "database/sql".to_string(),
                function: "Prepare".to_string(),
                receiver: Some("DB".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: true,
                risk: SqlRisk::PreparedStatement,
            },
            // GORM
            SqlSink {
                driver: "gorm".to_string(),
                function: "Raw".to_string(),
                receiver: Some("DB".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "gorm".to_string(),
                function: "Exec".to_string(),
                receiver: Some("DB".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "gorm".to_string(),
                function: "Where".to_string(),
                receiver: Some("DB".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::OrmMethod,
            },
            // sqlx (Go)
            SqlSink {
                driver: "sqlx".to_string(),
                function: "Get".to_string(),
                receiver: Some("DB".to_string()),
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "sqlx".to_string(),
                function: "Select".to_string(),
                receiver: Some("DB".to_string()),
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // pgx
            SqlSink {
                driver: "pgx".to_string(),
                function: "Exec".to_string(),
                receiver: Some("Conn".to_string()),
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "pgx".to_string(),
                function: "Query".to_string(),
                receiver: Some("Conn".to_string()),
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
        ];

        let orm_patterns = vec![
            OrmPattern {
                orm: "GORM".to_string(),
                method: "Where".to_string(),
                unsafe_pattern: r#"Where\s*\(\s*fmt\.Sprintf"#.to_string(),
                safe_alternative: "Use ? placeholders with separate arguments".to_string(),
            },
            OrmPattern {
                orm: "GORM".to_string(),
                method: "Raw".to_string(),
                unsafe_pattern: r#"Raw\s*\(\s*.*\+"#.to_string(),
                safe_alternative: "Use ? placeholders with variadic args".to_string(),
            },
        ];

        let sanitizers = vec![
            SqlSanitizer {
                library: "database/sql".to_string(),
                function: "Prepare".to_string(),
                receiver: Some("DB".to_string()),
                description: "Prepared statement (safe when used correctly)".to_string(),
            },
            SqlSanitizer {
                library: "squirrel".to_string(),
                function: "Eq".to_string(),
                receiver: None,
                description: "Squirrel query builder equality condition".to_string(),
            },
        ];

        self.sinks.insert(Language::Go, sinks);
        self.orm_patterns.insert(Language::Go, orm_patterns);
        self.sanitizers.insert(Language::Go, sanitizers);
        self.concat_patterns.insert(Language::Go, vec![
            r#"fmt\.Sprintf\s*\(\s*"[^"]*SELECT"#.to_string(),
            r#"fmt\.Sprintf\s*\(\s*"[^"]*INSERT"#.to_string(),
            r#"fmt\.Sprintf\s*\(\s*"[^"]*UPDATE"#.to_string(),
            r#"fmt\.Sprintf\s*\(\s*"[^"]*DELETE"#.to_string(),
            r#"".*SELECT.*"\s*\+"#.to_string(),
        ]);
    }

    /// Register Java SQL injection patterns.
    fn register_java_sql(&mut self) {
        let sinks = vec![
            // JDBC Statement
            SqlSink {
                driver: "jdbc".to_string(),
                function: "executeQuery".to_string(),
                receiver: Some("Statement".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "jdbc".to_string(),
                function: "execute".to_string(),
                receiver: Some("Statement".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "jdbc".to_string(),
                function: "executeUpdate".to_string(),
                receiver: Some("Statement".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "jdbc".to_string(),
                function: "addBatch".to_string(),
                receiver: Some("Statement".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // PreparedStatement creation
            SqlSink {
                driver: "jdbc".to_string(),
                function: "prepareStatement".to_string(),
                receiver: Some("Connection".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: true,
                risk: SqlRisk::PreparedStatement,
            },
            // Hibernate HQL
            SqlSink {
                driver: "hibernate".to_string(),
                function: "createQuery".to_string(),
                receiver: Some("Session".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::OrmMethod,
            },
            SqlSink {
                driver: "hibernate".to_string(),
                function: "createSQLQuery".to_string(),
                receiver: Some("Session".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "hibernate".to_string(),
                function: "createNativeQuery".to_string(),
                receiver: Some("EntityManager".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // JPA
            SqlSink {
                driver: "jpa".to_string(),
                function: "createQuery".to_string(),
                receiver: Some("EntityManager".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::OrmMethod,
            },
            SqlSink {
                driver: "jpa".to_string(),
                function: "createNativeQuery".to_string(),
                receiver: Some("EntityManager".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // Spring JDBC
            SqlSink {
                driver: "spring-jdbc".to_string(),
                function: "query".to_string(),
                receiver: Some("JdbcTemplate".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "spring-jdbc".to_string(),
                function: "queryForObject".to_string(),
                receiver: Some("JdbcTemplate".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "spring-jdbc".to_string(),
                function: "execute".to_string(),
                receiver: Some("JdbcTemplate".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "spring-jdbc".to_string(),
                function: "update".to_string(),
                receiver: Some("JdbcTemplate".to_string()),
                vulnerable_args: vec![0],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            // MyBatis
            SqlSink {
                driver: "mybatis".to_string(),
                function: "${".to_string(),  // String interpolation in XML
                receiver: None,
                vulnerable_args: vec![],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
        ];

        let orm_patterns = vec![
            OrmPattern {
                orm: "Hibernate".to_string(),
                method: "createQuery".to_string(),
                unsafe_pattern: r#"createQuery\s*\(\s*"[^"]*"\s*\+"#.to_string(),
                safe_alternative: "Use named parameters with setParameter()".to_string(),
            },
            OrmPattern {
                orm: "JPA".to_string(),
                method: "createQuery".to_string(),
                unsafe_pattern: r#"createQuery\s*\(\s*.*\+"#.to_string(),
                safe_alternative: "Use JPQL named parameters".to_string(),
            },
            OrmPattern {
                orm: "Spring".to_string(),
                method: "query".to_string(),
                unsafe_pattern: r#"query\s*\(\s*"[^"]*"\s*\+|String\.format"#.to_string(),
                safe_alternative: "Use ? placeholders with PreparedStatementSetter".to_string(),
            },
            OrmPattern {
                orm: "MyBatis".to_string(),
                method: "select".to_string(),
                unsafe_pattern: r#"\$\{[^}]+\}"#.to_string(),
                safe_alternative: "Use #{} instead of ${} for parameters".to_string(),
            },
        ];

        let sanitizers = vec![
            SqlSanitizer {
                library: "owasp-esapi".to_string(),
                function: "encodeForSQL".to_string(),
                receiver: Some("Encoder".to_string()),
                description: "OWASP ESAPI SQL encoding".to_string(),
            },
            SqlSanitizer {
                library: "jdbc".to_string(),
                function: "setString".to_string(),
                receiver: Some("PreparedStatement".to_string()),
                description: "PreparedStatement parameter binding".to_string(),
            },
            SqlSanitizer {
                library: "hibernate".to_string(),
                function: "setParameter".to_string(),
                receiver: Some("Query".to_string()),
                description: "Hibernate query parameter binding".to_string(),
            },
        ];

        self.sinks.insert(Language::Java, sinks);
        self.orm_patterns.insert(Language::Java, orm_patterns);
        self.sanitizers.insert(Language::Java, sanitizers);
        self.concat_patterns.insert(Language::Java, vec![
            r#""[^"]*SELECT[^"]*"\s*\+"#.to_string(),
            r#""[^"]*INSERT[^"]*"\s*\+"#.to_string(),
            r#""[^"]*UPDATE[^"]*"\s*\+"#.to_string(),
            r#""[^"]*DELETE[^"]*"\s*\+"#.to_string(),
            r#"String\.format\s*\(\s*"[^"]*SELECT"#.to_string(),
        ]);
    }

    /// Register C/C++ SQL injection patterns.
    fn register_c_sql(&mut self) {
        let sinks = vec![
            // MySQL C API
            SqlSink {
                driver: "mysql".to_string(),
                function: "mysql_query".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "mysql".to_string(),
                function: "mysql_real_query".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "mysql".to_string(),
                function: "mysql_stmt_prepare".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: true,
                risk: SqlRisk::PreparedStatement,
            },
            // SQLite C API
            SqlSink {
                driver: "sqlite3".to_string(),
                function: "sqlite3_exec".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "sqlite3".to_string(),
                function: "sqlite3_prepare".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: true,
                risk: SqlRisk::PreparedStatement,
            },
            SqlSink {
                driver: "sqlite3".to_string(),
                function: "sqlite3_prepare_v2".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: true,
                risk: SqlRisk::PreparedStatement,
            },
            // PostgreSQL libpq
            SqlSink {
                driver: "libpq".to_string(),
                function: "PQexec".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "libpq".to_string(),
                function: "PQexecParams".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "libpq".to_string(),
                function: "PQprepare".to_string(),
                receiver: None,
                vulnerable_args: vec![2],
                is_prepared_factory: true,
                risk: SqlRisk::PreparedStatement,
            },
            // ODBC
            SqlSink {
                driver: "odbc".to_string(),
                function: "SQLExecDirect".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: false,
                risk: SqlRisk::RawQuery,
            },
            SqlSink {
                driver: "odbc".to_string(),
                function: "SQLPrepare".to_string(),
                receiver: None,
                vulnerable_args: vec![1],
                is_prepared_factory: true,
                risk: SqlRisk::PreparedStatement,
            },
        ];

        let sanitizers = vec![
            SqlSanitizer {
                library: "mysql".to_string(),
                function: "mysql_real_escape_string".to_string(),
                receiver: None,
                description: "MySQL string escaping".to_string(),
            },
            SqlSanitizer {
                library: "sqlite3".to_string(),
                function: "sqlite3_mprintf".to_string(),
                receiver: None,
                description: "SQLite safe formatting with %q".to_string(),
            },
            SqlSanitizer {
                library: "libpq".to_string(),
                function: "PQescapeLiteral".to_string(),
                receiver: None,
                description: "PostgreSQL literal escaping".to_string(),
            },
            SqlSanitizer {
                library: "libpq".to_string(),
                function: "PQescapeIdentifier".to_string(),
                receiver: None,
                description: "PostgreSQL identifier escaping".to_string(),
            },
        ];

        self.sinks.insert(Language::C, sinks);
        self.orm_patterns.insert(Language::C, vec![]);  // No ORMs in C
        self.sanitizers.insert(Language::C, sanitizers);
        self.concat_patterns.insert(Language::C, vec![
            r#"sprintf\s*\([^,]+,\s*"[^"]*SELECT"#.to_string(),
            r#"sprintf\s*\([^,]+,\s*"[^"]*INSERT"#.to_string(),
            r#"sprintf\s*\([^,]+,\s*"[^"]*UPDATE"#.to_string(),
            r#"sprintf\s*\([^,]+,\s*"[^"]*DELETE"#.to_string(),
            r#"snprintf\s*\([^,]+,[^,]+,\s*"[^"]*SELECT"#.to_string(),
            r#"strcat\s*\([^,]+,\s*"[^"]*WHERE"#.to_string(),
        ]);
    }

    /// Generate tree-sitter query for SQL injection detection in a specific language.
    pub fn generate_query(&self, lang: Language) -> String {
        let sinks = self.sinks_for(lang);

        let mut queries = Vec::new();

        for sink in sinks {
            if sink.is_prepared_factory {
                continue; // Skip prepared statements for now
            }

            let query = match lang {
                Language::Rust => {
                    if sink.receiver.is_some() {
                        format!(
                            r#"(call_expression
  function: (field_expression
    value: (_)
    field: (field_identifier) @method_name)
  arguments: (arguments
    (string_literal) @query_string)
  (#eq? @method_name "{}")) @sql_sink"#,
                            sink.function
                        )
                    } else {
                        format!(
                            r#"(call_expression
  function: (identifier) @func_name
  arguments: (arguments
    (string_literal) @query_string)
  (#eq? @func_name "{}")) @sql_sink"#,
                            sink.function
                        )
                    }
                }
                Language::Python => {
                    format!(
                        r#"(call
  function: (attribute
    attribute: (identifier) @method_name)
  arguments: (argument_list
    (string) @query_string)
  (#eq? @method_name "{}")) @sql_sink"#,
                        sink.function
                    )
                }
                Language::JavaScript => {
                    format!(
                        r#"(call_expression
  function: (member_expression
    property: (property_identifier) @method_name)
  arguments: (arguments
    (string) @query_string)
  (#eq? @method_name "{}")) @sql_sink"#,
                        sink.function
                    )
                }
                Language::Go => {
                    format!(
                        r#"(call_expression
  function: (selector_expression
    field: (field_identifier) @method_name)
  arguments: (argument_list
    (interpreted_string_literal) @query_string)
  (#eq? @method_name "{}")) @sql_sink"#,
                        sink.function
                    )
                }
                Language::Java => {
                    format!(
                        r#"(method_invocation
  name: (identifier) @method_name
  arguments: (argument_list
    (string_literal) @query_string)
  (#eq? @method_name "{}")) @sql_sink"#,
                        sink.function
                    )
                }
                Language::C | Language::Cpp => {
                    format!(
                        r#"(call_expression
  function: (identifier) @func_name
  arguments: (argument_list
    (string_literal) @query_string)
  (#eq? @func_name "{}")) @sql_sink"#,
                        sink.function
                    )
                }
                _ => continue,
            };

            queries.push(query);
        }

        queries.join("\n\n")
    }
}

/// Pattern compiler that converts APIR patterns to tree-sitter queries.
pub struct PatternCompiler {
    mappings: HashMap<Language, LanguageMapping>,
}

impl PatternCompiler {
    /// Create a new pattern compiler with default mappings.
    pub fn new() -> Self {
        let mut mappings = HashMap::new();

        for lang in &[
            Language::Rust,
            Language::Python,
            Language::JavaScript,
            Language::Go,
            Language::Java,
            Language::C,
        ] {
            mappings.insert(*lang, LanguageMapping::for_language(*lang));
        }

        Self { mappings }
    }

    /// Get the mapping for a language.
    pub fn mapping_for(&self, lang: Language) -> Option<&LanguageMapping> {
        self.mappings.get(&lang)
    }

    /// Compile an abstract pattern to a tree-sitter query for a specific language.
    pub fn compile(
        &self,
        pattern: &VulnerabilityPattern,
        language: Language,
    ) -> Result<String, String> {
        let mapping = self
            .mappings
            .get(&language)
            .ok_or_else(|| format!("No mapping for language {:?}", language))?;

        self.compile_pattern(&pattern.pattern, mapping)
    }

    fn compile_pattern(
        &self,
        pattern: &AbstractPattern,
        mapping: &LanguageMapping,
    ) -> Result<String, String> {
        match pattern {
            AbstractPattern::Empty => Ok(String::new()),

            AbstractPattern::Node(node) => {
                let concrete_types = mapping.node_types.get(&node.node_type);
                if concrete_types.is_empty() {
                    return Err(format!("No mapping for node type {:?}", node.node_type));
                }

                let type_str = concrete_types.first().unwrap();
                let capture = node
                    .capture
                    .as_ref()
                    .map(|c| format!(" @{}", c))
                    .unwrap_or_default();

                Ok(format!("({}{})", type_str, capture))
            }

            AbstractPattern::FunctionCall(_fc) => {
                let call_types = mapping.node_types.get(&AbstractNodeType::CallExpression);
                let call_type = call_types.first().copied().unwrap_or("call_expression");

                Ok(format!(
                    "({} function: (identifier) @func_name)",
                    call_type
                ))
            }

            AbstractPattern::AnyOf(patterns) => {
                let compiled: Result<Vec<_>, _> = patterns
                    .iter()
                    .map(|p| self.compile_pattern(p, mapping))
                    .collect();

                let compiled = compiled?;
                Ok(format!("[{}]", compiled.join(" ")))
            }

            AbstractPattern::AllOf(patterns) => {
                let compiled: Result<Vec<_>, _> = patterns
                    .iter()
                    .map(|p| self.compile_pattern(p, mapping))
                    .collect();

                let compiled = compiled?;
                Ok(compiled.join("\n"))
            }

            AbstractPattern::DataFlow(_) => {
                // Data flow requires taint analysis, not simple pattern matching
                Err("DataFlow patterns require taint analysis infrastructure".to_string())
            }

            _ => Err(format!("Pattern type {:?} not yet implemented", pattern)),
        }
    }
}

impl Default for PatternCompiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_mapping() {
        let mapping = LanguageMapping::for_language(Language::Rust);

        let func_types = mapping.node_types.get(&AbstractNodeType::Function);
        assert!(func_types.contains(&"function_item"));

        let sources = mapping.sources.get(&EndpointCategory::UserInput);
        assert!(!sources.is_empty());
    }

    #[test]
    fn test_python_mapping() {
        let mapping = LanguageMapping::for_language(Language::Python);

        let call_types = mapping.node_types.get(&AbstractNodeType::CallExpression);
        assert!(call_types.contains(&"call"));

        let sinks = mapping.sinks.get(&EndpointCategory::CommandExecution);
        assert!(!sinks.is_empty());

        // Check for os.system
        let has_system = sinks.iter().any(|e| {
            if let NameMatcher::Exact(name) = &e.name {
                name == "system"
            } else {
                false
            }
        });
        assert!(has_system);
    }

    #[test]
    fn test_javascript_mapping() {
        let mapping = LanguageMapping::for_language(Language::JavaScript);

        let sinks = mapping.sinks.get(&EndpointCategory::HtmlOutput);
        assert!(!sinks.is_empty());

        // Check for innerHTML
        let has_inner_html = sinks.iter().any(|e| {
            if let NameMatcher::Exact(name) = &e.name {
                name == "innerHTML"
            } else {
                false
            }
        });
        assert!(has_inner_html);
    }

    #[test]
    fn test_endpoint_info_builder() {
        let endpoint = EndpointInfo::method("Connection", "query")
            .with_args(vec![0, 1])
            .with_module("mysql")
            .returns(false);

        assert_eq!(endpoint.receiver, Some("Connection".to_string()));
        assert_eq!(endpoint.arg_positions, vec![0, 1]);
        assert_eq!(endpoint.module, Some("mysql".to_string()));
        assert!(!endpoint.returns_tainted);
    }

    #[test]
    fn test_pattern_compiler() {
        let compiler = PatternCompiler::new();

        assert!(compiler.mapping_for(Language::Rust).is_some());
        assert!(compiler.mapping_for(Language::Python).is_some());
    }

    #[test]
    fn test_c_buffer_overflow_sinks() {
        let mapping = LanguageMapping::for_language(Language::C);

        let memory_sinks = mapping.sinks.get(&EndpointCategory::MemoryOperation);
        assert!(!memory_sinks.is_empty());

        // Check for strcpy
        let has_strcpy = memory_sinks.iter().any(|e| {
            if let NameMatcher::Exact(name) = &e.name {
                name == "strcpy"
            } else {
                false
            }
        });
        assert!(has_strcpy);
    }

    #[test]
    fn test_sql_injection_registry_rust() {
        let registry = SqlInjectionRegistry::new();

        let rust_sinks = registry.sinks_for(Language::Rust);
        assert!(!rust_sinks.is_empty());

        // Check for sqlx query
        let has_sqlx = rust_sinks.iter().any(|s| s.driver == "sqlx" && s.function == "query");
        assert!(has_sqlx);

        // Check for diesel raw SQL
        let has_diesel = rust_sinks.iter().any(|s| s.driver == "diesel" && s.function == "sql");
        assert!(has_diesel);

        // Check for rusqlite
        let has_rusqlite = rust_sinks.iter().any(|s| s.driver == "rusqlite" && s.function == "execute");
        assert!(has_rusqlite);
    }

    #[test]
    fn test_sql_injection_registry_python() {
        let registry = SqlInjectionRegistry::new();

        let python_sinks = registry.sinks_for(Language::Python);
        assert!(!python_sinks.is_empty());

        // Check for cursor.execute
        let has_execute = python_sinks.iter().any(|s| s.function == "execute");
        assert!(has_execute);

        // Check for Django raw
        let has_django = python_sinks.iter().any(|s| s.driver == "django" && s.function == "raw");
        assert!(has_django);

        // Check ORM patterns
        let orm_patterns = registry.orm_patterns_for(Language::Python);
        assert!(!orm_patterns.is_empty());

        let has_sqlalchemy = orm_patterns.iter().any(|p| p.orm == "SQLAlchemy");
        assert!(has_sqlalchemy);
    }

    #[test]
    fn test_sql_injection_registry_javascript() {
        let registry = SqlInjectionRegistry::new();

        let js_sinks = registry.sinks_for(Language::JavaScript);
        assert!(!js_sinks.is_empty());

        // Check for knex.raw
        let has_knex = js_sinks.iter().any(|s| s.driver == "knex" && s.function == "raw");
        assert!(has_knex);

        // Check for Prisma
        let has_prisma = js_sinks.iter().any(|s| s.driver == "prisma");
        assert!(has_prisma);

        // Check sanitizers
        let sanitizers = registry.sanitizers_for(Language::JavaScript);
        assert!(!sanitizers.is_empty());
    }

    #[test]
    fn test_sql_injection_registry_go() {
        let registry = SqlInjectionRegistry::new();

        let go_sinks = registry.sinks_for(Language::Go);
        assert!(!go_sinks.is_empty());

        // Check for database/sql
        let has_db_sql = go_sinks.iter().any(|s| s.driver == "database/sql" && s.function == "Query");
        assert!(has_db_sql);

        // Check for GORM
        let has_gorm = go_sinks.iter().any(|s| s.driver == "gorm" && s.function == "Raw");
        assert!(has_gorm);
    }

    #[test]
    fn test_sql_injection_registry_java() {
        let registry = SqlInjectionRegistry::new();

        let java_sinks = registry.sinks_for(Language::Java);
        assert!(!java_sinks.is_empty());

        // Check for JDBC
        let has_jdbc = java_sinks.iter().any(|s| s.driver == "jdbc" && s.function == "executeQuery");
        assert!(has_jdbc);

        // Check for Hibernate
        let has_hibernate = java_sinks.iter().any(|s| s.driver == "hibernate");
        assert!(has_hibernate);

        // Check for Spring
        let has_spring = java_sinks.iter().any(|s| s.driver == "spring-jdbc");
        assert!(has_spring);
    }

    #[test]
    fn test_sql_injection_registry_c() {
        let registry = SqlInjectionRegistry::new();

        let c_sinks = registry.sinks_for(Language::C);
        assert!(!c_sinks.is_empty());

        // Check for MySQL C API
        let has_mysql = c_sinks.iter().any(|s| s.function == "mysql_query");
        assert!(has_mysql);

        // Check for SQLite C API
        let has_sqlite = c_sinks.iter().any(|s| s.function == "sqlite3_exec");
        assert!(has_sqlite);

        // Check for PostgreSQL libpq
        let has_libpq = c_sinks.iter().any(|s| s.function == "PQexec");
        assert!(has_libpq);
    }

    #[test]
    fn test_sql_risk_classification() {
        let registry = SqlInjectionRegistry::new();

        let rust_sinks = registry.sinks_for(Language::Rust);

        // Raw queries should have RawQuery risk
        let raw_query_sink = rust_sinks.iter().find(|s| s.function == "query" && s.driver == "sqlx");
        assert!(raw_query_sink.is_some());
        assert_eq!(raw_query_sink.unwrap().risk, SqlRisk::RawQuery);

        // Prepared statement factories should have PreparedStatement risk
        let prepared_sink = rust_sinks.iter().find(|s| s.function == "prepare" && s.driver == "rusqlite");
        assert!(prepared_sink.is_some());
        assert_eq!(prepared_sink.unwrap().risk, SqlRisk::PreparedStatement);
    }

    #[test]
    fn test_sql_query_generation() {
        let registry = SqlInjectionRegistry::new();

        let rust_query = registry.generate_query(Language::Rust);
        assert!(!rust_query.is_empty());
        assert!(rust_query.contains("@sql_sink"));

        let python_query = registry.generate_query(Language::Python);
        assert!(!python_query.is_empty());
        assert!(python_query.contains("execute"));
    }
}
