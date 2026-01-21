//! Abstract Pattern Intermediate Representation (APIR).
//!
//! APIR provides a language-agnostic way to define security vulnerability patterns.
//! Patterns are defined in an abstract form and then compiled to language-specific
//! tree-sitter queries.

use std::collections::HashMap;

/// A complete vulnerability pattern definition.
#[derive(Debug, Clone)]
pub struct VulnerabilityPattern {
    /// Unique identifier for the pattern.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Detailed description.
    pub description: String,
    /// CWE identifier(s).
    pub cwes: Vec<String>,
    /// Severity level.
    pub severity: PatternSeverity,
    /// Pattern category.
    pub category: PatternCategory,
    /// The abstract pattern definition.
    pub pattern: AbstractPattern,
    /// Languages this pattern applies to (empty = all supported).
    pub languages: Vec<String>,
    /// Remediation guidance.
    pub remediation: String,
    /// Example vulnerable code snippets.
    pub examples: Vec<PatternExample>,
    /// Tags for filtering.
    pub tags: Vec<String>,
}

impl VulnerabilityPattern {
    /// Create a new pattern builder.
    pub fn builder(id: impl Into<String>) -> VulnerabilityPatternBuilder {
        VulnerabilityPatternBuilder::new(id)
    }
}

/// Builder for vulnerability patterns.
pub struct VulnerabilityPatternBuilder {
    pattern: VulnerabilityPattern,
}

impl VulnerabilityPatternBuilder {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            pattern: VulnerabilityPattern {
                id: id.into(),
                name: String::new(),
                description: String::new(),
                cwes: vec![],
                severity: PatternSeverity::Medium,
                category: PatternCategory::Other,
                pattern: AbstractPattern::Empty,
                languages: vec![],
                remediation: String::new(),
                examples: vec![],
                tags: vec![],
            },
        }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.pattern.name = name.into();
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.pattern.description = desc.into();
        self
    }

    pub fn cwe(mut self, cwe: impl Into<String>) -> Self {
        self.pattern.cwes.push(cwe.into());
        self
    }

    pub fn severity(mut self, severity: PatternSeverity) -> Self {
        self.pattern.severity = severity;
        self
    }

    pub fn category(mut self, category: PatternCategory) -> Self {
        self.pattern.category = category;
        self
    }

    pub fn pattern(mut self, pattern: AbstractPattern) -> Self {
        self.pattern.pattern = pattern;
        self
    }

    pub fn language(mut self, lang: impl Into<String>) -> Self {
        self.pattern.languages.push(lang.into());
        self
    }

    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.pattern.remediation = remediation.into();
        self
    }

    pub fn example(mut self, example: PatternExample) -> Self {
        self.pattern.examples.push(example);
        self
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.pattern.tags.push(tag.into());
        self
    }

    pub fn build(self) -> VulnerabilityPattern {
        self.pattern
    }
}

/// Severity levels for patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Categories of vulnerability patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternCategory {
    /// SQL, Command, XSS, etc.
    Injection,
    /// Weak crypto, hardcoded keys
    Cryptography,
    /// Buffer overflow, UAF
    MemorySafety,
    /// Hardcoded creds, weak sessions
    Authentication,
    /// IDOR, privilege escalation
    Authorization,
    /// PII leakage
    DataExposure,
    /// Race conditions
    Concurrency,
    /// Path traversal
    PathTraversal,
    /// Insecure deserialization
    Deserialization,
    /// Configuration issues
    Configuration,
    /// Other/uncategorized
    Other,
}

/// Example code for a pattern (vulnerable or safe).
#[derive(Debug, Clone)]
pub struct PatternExample {
    /// Language of the example.
    pub language: String,
    /// The code snippet.
    pub code: String,
    /// Whether this is vulnerable or safe code.
    pub vulnerable: bool,
    /// Explanation of why it's vulnerable/safe.
    pub explanation: String,
}

/// Abstract pattern definition - the core of APIR.
/// Note: Serialization is handled manually to avoid recursion limit issues.
#[derive(Debug, Clone)]
pub enum AbstractPattern {
    /// No pattern (placeholder).
    Empty,

    /// Match a specific AST node type.
    Node(NodePattern),

    /// Match a function/method call.
    FunctionCall(FunctionCallPattern),

    /// Match a binary operation.
    BinaryOp(BinaryOpPattern),

    /// Match data flow from source to sink.
    DataFlow(DataFlowPattern),

    /// Match a sequence of patterns.
    Sequence(Vec<AbstractPattern>),

    /// Match any of the patterns.
    AnyOf(Vec<AbstractPattern>),

    /// Match all patterns.
    AllOf(Vec<AbstractPattern>),

    /// Negation - match if pattern does NOT match.
    Not(Box<AbstractPattern>),

    /// Match a string literal.
    StringLiteral(StringPattern),

    /// Match a variable/identifier.
    Identifier(IdentifierPattern),

    /// Match an assignment.
    Assignment(AssignmentPattern),

    /// Match a conditional.
    Conditional(ConditionalPattern),

    /// Match a loop construct.
    Loop(LoopPattern),

    /// Custom tree-sitter query (escape hatch).
    Custom(CustomPattern),
}

impl AbstractPattern {
    /// Create a function call pattern.
    pub fn function_call(name: impl Into<String>) -> Self {
        AbstractPattern::FunctionCall(FunctionCallPattern {
            name: NameMatcher::Exact(name.into()),
            receiver: None,
            args: vec![],
            modifiers: vec![],
        })
    }

    /// Create a data flow pattern.
    pub fn data_flow(source: DataFlowEndpoint, sink: DataFlowEndpoint) -> Self {
        AbstractPattern::DataFlow(DataFlowPattern {
            source,
            sink,
            sanitizers: vec![],
            propagators: vec![],
        })
    }

    /// Create an "any of" pattern.
    pub fn any_of(patterns: Vec<AbstractPattern>) -> Self {
        AbstractPattern::AnyOf(patterns)
    }

    /// Create an "all of" pattern.
    pub fn all_of(patterns: Vec<AbstractPattern>) -> Self {
        AbstractPattern::AllOf(patterns)
    }

    /// Negate this pattern.
    pub fn not(self) -> Self {
        AbstractPattern::Not(Box::new(self))
    }
}

/// Pattern for matching AST nodes by type.
#[derive(Debug, Clone)]
pub struct NodePattern {
    /// Abstract node type.
    pub node_type: AbstractNodeType,
    /// Child patterns.
    pub children: Vec<AbstractPattern>,
    /// Capture name for this node.
    pub capture: Option<String>,
}

/// Abstract node types that map to concrete AST nodes per language.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AbstractNodeType {
    Function,
    Method,
    Class,
    Struct,
    Module,
    Parameter,
    Argument,
    Variable,
    Constant,
    Assignment,
    BinaryExpression,
    UnaryExpression,
    CallExpression,
    MemberAccess,
    IndexAccess,
    IfStatement,
    ForLoop,
    WhileLoop,
    Return,
    Import,
    StringLiteral,
    NumberLiteral,
    BooleanLiteral,
    ArrayLiteral,
    ObjectLiteral,
    TryBlock,
    CatchBlock,
    Custom(String),
}

/// Pattern for matching function/method calls.
#[derive(Debug, Clone)]
pub struct FunctionCallPattern {
    /// Function name matcher.
    pub name: NameMatcher,
    /// Optional receiver (for method calls).
    pub receiver: Option<Box<AbstractPattern>>,
    /// Argument patterns.
    pub args: Vec<ArgumentPattern>,
    /// Required modifiers (async, static, etc.).
    pub modifiers: Vec<String>,
}

/// Pattern for matching binary operations.
#[derive(Debug, Clone)]
pub struct BinaryOpPattern {
    /// Operator to match.
    pub operator: BinaryOperator,
    /// Left operand pattern.
    pub left: Box<AbstractPattern>,
    /// Right operand pattern.
    pub right: Box<AbstractPattern>,
}

/// Abstract binary operators.
#[derive(Debug, Clone)]
pub enum BinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    Equal,
    NotEqual,
    LessThan,
    LessEqual,
    GreaterThan,
    GreaterEqual,
    And,
    Or,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    Concatenation,
    Assignment,
    Custom(String),
}

/// Data flow pattern for taint analysis.
#[derive(Debug, Clone)]
pub struct DataFlowPattern {
    /// Where tainted data originates.
    pub source: DataFlowEndpoint,
    /// Where tainted data must not reach.
    pub sink: DataFlowEndpoint,
    /// Functions that sanitize the data.
    pub sanitizers: Vec<DataFlowEndpoint>,
    /// Functions that propagate taint.
    pub propagators: Vec<DataFlowEndpoint>,
}

/// Endpoint in a data flow (source, sink, or sanitizer).
#[derive(Debug, Clone)]
pub struct DataFlowEndpoint {
    /// Category of the endpoint.
    pub category: EndpointCategory,
    /// Specific function/method names.
    pub names: Vec<NameMatcher>,
    /// Argument positions that are tainted/sinks.
    pub arg_positions: Vec<usize>,
    /// Return value is tainted/sink.
    pub returns: bool,
}

impl DataFlowEndpoint {
    /// Create a user input source.
    pub fn user_input() -> Self {
        Self {
            category: EndpointCategory::UserInput,
            names: vec![],
            arg_positions: vec![],
            returns: true,
        }
    }

    /// Create a database query sink.
    pub fn database_query() -> Self {
        Self {
            category: EndpointCategory::DatabaseQuery,
            names: vec![],
            arg_positions: vec![0],
            returns: false,
        }
    }

    /// Create a command execution sink.
    pub fn command_exec() -> Self {
        Self {
            category: EndpointCategory::CommandExecution,
            names: vec![],
            arg_positions: vec![0],
            returns: false,
        }
    }

    /// Create an HTML output sink.
    pub fn html_output() -> Self {
        Self {
            category: EndpointCategory::HtmlOutput,
            names: vec![],
            arg_positions: vec![0],
            returns: false,
        }
    }
}

/// Categories of data flow endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointCategory {
    /// User-controlled input.
    UserInput,
    /// Environment variables.
    Environment,
    /// File system operations.
    FileSystem,
    /// Network requests.
    Network,
    /// Database queries.
    DatabaseQuery,
    /// Command execution.
    CommandExecution,
    /// HTML/DOM output.
    HtmlOutput,
    /// Logging.
    Logging,
    /// Cryptographic operations.
    Cryptographic,
    /// Memory operations.
    MemoryOperation,
    /// Custom category.
    Custom(String),
}

/// Name matching strategies.
#[derive(Debug, Clone)]
pub enum NameMatcher {
    /// Exact match.
    Exact(String),
    /// Prefix match.
    Prefix(String),
    /// Suffix match.
    Suffix(String),
    /// Contains substring.
    Contains(String),
    /// Regex match.
    Regex(String),
    /// Any of these names.
    AnyOf(Vec<String>),
}

impl NameMatcher {
    /// Check if a name matches this pattern.
    pub fn matches(&self, name: &str) -> bool {
        match self {
            NameMatcher::Exact(s) => name == s,
            NameMatcher::Prefix(p) => name.starts_with(p),
            NameMatcher::Suffix(s) => name.ends_with(s),
            NameMatcher::Contains(c) => name.contains(c),
            NameMatcher::Regex(r) => {
                regex::Regex::new(r).map(|re| re.is_match(name)).unwrap_or(false)
            }
            NameMatcher::AnyOf(names) => names.iter().any(|n| n == name),
        }
    }
}

/// Pattern for matching function arguments.
#[derive(Debug, Clone)]
pub struct ArgumentPattern {
    /// Position (0-indexed).
    pub position: usize,
    /// Pattern to match the argument.
    pub pattern: Box<AbstractPattern>,
    /// Is this argument required?
    pub required: bool,
}

/// Pattern for matching string literals.
#[derive(Debug, Clone)]
pub struct StringPattern {
    /// Matcher for the string content.
    pub content: NameMatcher,
    /// Include raw/template strings.
    pub include_raw: bool,
    /// Include interpolated strings.
    pub include_interpolated: bool,
}

/// Pattern for matching identifiers.
#[derive(Debug, Clone)]
pub struct IdentifierPattern {
    /// Name matcher.
    pub name: NameMatcher,
    /// Scope constraints.
    pub scope: Option<ScopeConstraint>,
}

/// Scope constraints for identifier matching.
#[derive(Debug, Clone)]
pub enum ScopeConstraint {
    /// Must be local variable.
    Local,
    /// Must be parameter.
    Parameter,
    /// Must be global/module-level.
    Global,
    /// Must be class/struct member.
    Member,
    /// Any scope.
    Any,
}

/// Pattern for matching assignments.
#[derive(Debug, Clone)]
pub struct AssignmentPattern {
    /// Left-hand side (target).
    pub target: Box<AbstractPattern>,
    /// Right-hand side (value).
    pub value: Box<AbstractPattern>,
    /// Assignment type (=, +=, etc.).
    pub assignment_type: Option<String>,
}

/// Pattern for matching conditionals.
#[derive(Debug, Clone)]
pub struct ConditionalPattern {
    /// Condition expression pattern.
    pub condition: Box<AbstractPattern>,
    /// Then branch pattern.
    pub then_branch: Option<Box<AbstractPattern>>,
    /// Else branch pattern.
    pub else_branch: Option<Box<AbstractPattern>>,
}

/// Pattern for matching loops.
#[derive(Debug, Clone)]
pub struct LoopPattern {
    /// Loop type.
    pub loop_type: LoopType,
    /// Condition/iteration pattern.
    pub iterator: Option<Box<AbstractPattern>>,
    /// Body pattern.
    pub body: Option<Box<AbstractPattern>>,
}

/// Types of loops.
#[derive(Debug, Clone)]
pub enum LoopType {
    For,
    ForEach,
    While,
    DoWhile,
    Loop,
    Any,
}

/// Custom pattern using raw tree-sitter query.
#[derive(Debug, Clone)]
pub struct CustomPattern {
    /// Language-specific queries.
    pub queries: HashMap<String, String>,
    /// Default query (if language not in map).
    pub default: Option<String>,
}

/// Registry of vulnerability patterns.
#[derive(Debug, Clone, Default)]
pub struct PatternRegistry {
    patterns: HashMap<String, VulnerabilityPattern>,
    by_category: HashMap<PatternCategory, Vec<String>>,
    by_language: HashMap<String, Vec<String>>,
}

impl PatternRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry with built-in patterns.
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        register_builtin_patterns(&mut registry);
        registry
    }

    /// Register a pattern.
    pub fn register(&mut self, pattern: VulnerabilityPattern) {
        let id = pattern.id.clone();

        // Index by category
        self.by_category
            .entry(pattern.category)
            .or_default()
            .push(id.clone());

        // Index by language
        if pattern.languages.is_empty() {
            // Applies to all languages
            for lang in &["rust", "python", "javascript", "go", "java", "c", "cpp"] {
                self.by_language
                    .entry(lang.to_string())
                    .or_default()
                    .push(id.clone());
            }
        } else {
            for lang in &pattern.languages {
                self.by_language
                    .entry(lang.clone())
                    .or_default()
                    .push(id.clone());
            }
        }

        self.patterns.insert(id, pattern);
    }

    /// Get a pattern by ID.
    pub fn get(&self, id: &str) -> Option<&VulnerabilityPattern> {
        self.patterns.get(id)
    }

    /// Get all patterns.
    pub fn all(&self) -> impl Iterator<Item = &VulnerabilityPattern> {
        self.patterns.values()
    }

    /// Get patterns by category.
    pub fn by_category(&self, category: PatternCategory) -> Vec<&VulnerabilityPattern> {
        self.by_category
            .get(&category)
            .map(|ids| ids.iter().filter_map(|id| self.patterns.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get patterns for a specific language.
    pub fn for_language(&self, language: &str) -> Vec<&VulnerabilityPattern> {
        self.by_language
            .get(language)
            .map(|ids| ids.iter().filter_map(|id| self.patterns.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get pattern count.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Check if registry is empty.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

/// Register built-in vulnerability patterns.
fn register_builtin_patterns(registry: &mut PatternRegistry) {
    // SQL Injection
    registry.register(
        VulnerabilityPattern::builder("sql-injection")
            .name("SQL Injection")
            .description("User input concatenated into SQL query without proper sanitization")
            .cwe("CWE-89")
            .severity(PatternSeverity::Critical)
            .category(PatternCategory::Injection)
            .pattern(AbstractPattern::data_flow(
                DataFlowEndpoint::user_input(),
                DataFlowEndpoint::database_query(),
            ))
            .remediation("Use parameterized queries or prepared statements")
            .tag("owasp-top-10")
            .tag("injection")
            .build(),
    );

    // Command Injection
    registry.register(
        VulnerabilityPattern::builder("command-injection")
            .name("Command Injection")
            .description("User input passed to command execution without sanitization")
            .cwe("CWE-78")
            .severity(PatternSeverity::Critical)
            .category(PatternCategory::Injection)
            .pattern(AbstractPattern::data_flow(
                DataFlowEndpoint::user_input(),
                DataFlowEndpoint::command_exec(),
            ))
            .remediation("Use safe APIs that don't invoke shell, or sanitize input")
            .tag("owasp-top-10")
            .tag("injection")
            .build(),
    );

    // XSS
    registry.register(
        VulnerabilityPattern::builder("xss")
            .name("Cross-Site Scripting (XSS)")
            .description("User input rendered in HTML without encoding")
            .cwe("CWE-79")
            .severity(PatternSeverity::High)
            .category(PatternCategory::Injection)
            .pattern(AbstractPattern::data_flow(
                DataFlowEndpoint::user_input(),
                DataFlowEndpoint::html_output(),
            ))
            .remediation("HTML encode all user input before rendering")
            .tag("owasp-top-10")
            .tag("xss")
            .build(),
    );

    // Hardcoded Credentials
    registry.register(
        VulnerabilityPattern::builder("hardcoded-credentials")
            .name("Hardcoded Credentials")
            .description("Credentials or secrets hardcoded in source code")
            .cwe("CWE-798")
            .severity(PatternSeverity::High)
            .category(PatternCategory::Authentication)
            .pattern(AbstractPattern::AllOf(vec![
                AbstractPattern::Node(NodePattern {
                    node_type: AbstractNodeType::Assignment,
                    children: vec![],
                    capture: Some("assignment".to_string()),
                }),
                AbstractPattern::AnyOf(vec![
                    AbstractPattern::Identifier(IdentifierPattern {
                        name: NameMatcher::Contains("password".to_string()),
                        scope: None,
                    }),
                    AbstractPattern::Identifier(IdentifierPattern {
                        name: NameMatcher::Contains("secret".to_string()),
                        scope: None,
                    }),
                    AbstractPattern::Identifier(IdentifierPattern {
                        name: NameMatcher::Contains("api_key".to_string()),
                        scope: None,
                    }),
                ]),
            ]))
            .remediation("Use environment variables or secure secret management")
            .tag("secrets")
            .build(),
    );

    // Weak Cryptography
    registry.register(
        VulnerabilityPattern::builder("weak-crypto")
            .name("Weak Cryptographic Algorithm")
            .description("Use of deprecated or weak cryptographic algorithms")
            .cwe("CWE-327")
            .severity(PatternSeverity::Medium)
            .category(PatternCategory::Cryptography)
            .pattern(AbstractPattern::function_call(""))
            .remediation("Use strong, modern cryptographic algorithms")
            .tag("crypto")
            .build(),
    );

    // Path Traversal
    registry.register(
        VulnerabilityPattern::builder("path-traversal")
            .name("Path Traversal")
            .description("User input used in file path without sanitization")
            .cwe("CWE-22")
            .severity(PatternSeverity::High)
            .category(PatternCategory::PathTraversal)
            .pattern(AbstractPattern::data_flow(
                DataFlowEndpoint::user_input(),
                DataFlowEndpoint {
                    category: EndpointCategory::FileSystem,
                    names: vec![],
                    arg_positions: vec![0],
                    returns: false,
                },
            ))
            .remediation("Validate and canonicalize file paths before use")
            .tag("owasp-top-10")
            .tag("path-traversal")
            .build(),
    );

    // Insecure Deserialization
    registry.register(
        VulnerabilityPattern::builder("insecure-deserialization")
            .name("Insecure Deserialization")
            .description("Deserializing untrusted data without validation")
            .cwe("CWE-502")
            .severity(PatternSeverity::High)
            .category(PatternCategory::Deserialization)
            .pattern(AbstractPattern::data_flow(
                DataFlowEndpoint::user_input(),
                DataFlowEndpoint {
                    category: EndpointCategory::Custom("deserialization".to_string()),
                    names: vec![],
                    arg_positions: vec![0],
                    returns: false,
                },
            ))
            .remediation("Validate deserialized data or use safe serialization formats")
            .tag("owasp-top-10")
            .build(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_builder() {
        let pattern = VulnerabilityPattern::builder("test-pattern")
            .name("Test Pattern")
            .description("A test pattern")
            .cwe("CWE-123")
            .severity(PatternSeverity::High)
            .category(PatternCategory::Injection)
            .tag("test")
            .build();

        assert_eq!(pattern.id, "test-pattern");
        assert_eq!(pattern.name, "Test Pattern");
        assert_eq!(pattern.cwes, vec!["CWE-123"]);
        assert_eq!(pattern.severity, PatternSeverity::High);
        assert_eq!(pattern.category, PatternCategory::Injection);
    }

    #[test]
    fn test_name_matcher() {
        assert!(NameMatcher::Exact("execute".to_string()).matches("execute"));
        assert!(!NameMatcher::Exact("execute".to_string()).matches("exec"));

        assert!(NameMatcher::Prefix("get".to_string()).matches("getUser"));
        assert!(!NameMatcher::Prefix("get".to_string()).matches("setUser"));

        assert!(NameMatcher::Suffix("Async".to_string()).matches("fetchAsync"));
        assert!(!NameMatcher::Suffix("Async".to_string()).matches("fetchSync"));

        assert!(NameMatcher::Contains("Sql".to_string()).matches("executeSqlQuery"));

        assert!(NameMatcher::AnyOf(vec!["exec".to_string(), "eval".to_string()]).matches("exec"));
        assert!(!NameMatcher::AnyOf(vec!["exec".to_string(), "eval".to_string()]).matches("run"));
    }

    #[test]
    fn test_pattern_registry() {
        let registry = PatternRegistry::with_builtins();

        assert!(!registry.is_empty());
        assert!(registry.get("sql-injection").is_some());
        assert!(registry.get("command-injection").is_some());

        let injection_patterns = registry.by_category(PatternCategory::Injection);
        assert!(!injection_patterns.is_empty());
    }

    #[test]
    fn test_data_flow_pattern() {
        let pattern = AbstractPattern::data_flow(
            DataFlowEndpoint::user_input(),
            DataFlowEndpoint::database_query(),
        );

        if let AbstractPattern::DataFlow(df) = pattern {
            assert_eq!(df.source.category, EndpointCategory::UserInput);
            assert_eq!(df.sink.category, EndpointCategory::DatabaseQuery);
        } else {
            panic!("Expected DataFlow pattern");
        }
    }

    #[test]
    fn test_composite_patterns() {
        let any_of = AbstractPattern::any_of(vec![
            AbstractPattern::function_call("exec"),
            AbstractPattern::function_call("eval"),
        ]);

        if let AbstractPattern::AnyOf(patterns) = any_of {
            assert_eq!(patterns.len(), 2);
        } else {
            panic!("Expected AnyOf pattern");
        }

        let negated = AbstractPattern::function_call("safe").not();

        if let AbstractPattern::Not(_) = negated {
            // OK
        } else {
            panic!("Expected Not pattern");
        }
    }
}
