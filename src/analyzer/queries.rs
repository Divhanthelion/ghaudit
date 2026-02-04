//! Tree-sitter query definitions for security analysis.

use crate::models::{Language, Severity};

/// A security query pattern.
#[derive(Debug, Clone)]
pub struct SecurityQuery {
    /// Unique identifier for this query
    pub id: &'static str,

    /// Human-readable name
    pub name: &'static str,

    /// Description of what this query detects
    pub description: &'static str,

    /// Tree-sitter query string
    pub query: &'static str,

    /// Target language
    pub language: Language,

    /// Severity of findings from this query
    pub severity: Severity,

    /// CWE IDs related to this query
    pub cwes: &'static [&'static str],

    /// Remediation advice
    pub remediation: &'static str,
}

/// Get all security queries for Rust.
pub fn rust_queries() -> Vec<SecurityQuery> {
    vec![
        // Unsafe code detection
        SecurityQuery {
            id: "rust/unsafe-block",
            name: "Unsafe Block Usage",
            description: "Detects usage of unsafe blocks which bypass Rust's safety guarantees",
            query: r#"(unsafe_block) @unsafe_usage"#,
            language: Language::Rust,
            severity: Severity::Medium,
            cwes: &["CWE-119", "CWE-416"],
            remediation: "Review unsafe block for memory safety. Add SAFETY comment documenting invariants.",
        },
        SecurityQuery {
            id: "rust/unsafe-fn",
            name: "Unsafe Function Definition",
            description: "Detects unsafe function definitions which expose unsafe operations to callers",
            query: r#"
            (function_item
              (function_modifiers
                "unsafe" @unsafe_kw
              )
              name: (identifier) @fn_name
            ) @unsafe_fn
            "#,
            language: Language::Rust,
            severity: Severity::Medium,
            cwes: &["CWE-119"],
            remediation: "Ensure safety invariants are documented and callers are aware of requirements.",
        },
        SecurityQuery {
            id: "rust/unsafe-impl",
            name: "Unsafe Trait Implementation",
            description: "Detects unsafe trait implementations",
            query: r#"
            (impl_item
              "unsafe" @unsafe_kw
            ) @unsafe_impl
            "#,
            language: Language::Rust,
            severity: Severity::Medium,
            cwes: &["CWE-119"],
            remediation: "Verify that all trait safety requirements are upheld.",
        },
        SecurityQuery {
            id: "rust/raw-pointer-deref",
            name: "Raw Pointer Dereference",
            description: "Detects raw pointer dereferences which can cause undefined behavior",
            query: r#"
            (unary_expression
              "*" @op
              (identifier) @ptr
              (#match? @ptr "^(ptr|raw|p_)")
            ) @deref
            "#,
            language: Language::Rust,
            severity: Severity::High,
            cwes: &["CWE-119", "CWE-476"],
            remediation: "Ensure pointer validity before dereferencing. Consider using safe abstractions.",
        },
        SecurityQuery {
            id: "rust/transmute",
            name: "Transmute Usage",
            description: "Detects std::mem::transmute which can cause undefined behavior",
            query: r#"
            (call_expression
              function: (scoped_identifier
                path: (scoped_identifier
                  path: (identifier) @std (#eq? @std "std")
                  name: (identifier) @mem (#eq? @mem "mem")
                )
                name: (identifier) @transmute (#eq? @transmute "transmute")
              )
            ) @transmute_call
            "#,
            language: Language::Rust,
            severity: Severity::High,
            cwes: &["CWE-843"],
            remediation: "Avoid transmute when possible. Use safer alternatives like from_ne_bytes.",
        },
        SecurityQuery {
            id: "rust/unwrap-panic",
            name: "Unwrap/Expect in Library Code",
            description: "Detects .unwrap() and .expect() calls which can panic",
            query: r#"
            (call_expression
              function: (field_expression
                field: (field_identifier) @method
                (#match? @method "^(unwrap|expect)$")
              )
            ) @unwrap_call
            "#,
            language: Language::Rust,
            severity: Severity::Low,
            cwes: &["CWE-755"],
            remediation: "Use proper error handling with ? operator or match instead of unwrap.",
        },
        // Note: Format string vulnerabilities in Rust are rare because format! macros
        // require compile-time format strings. True format string injection would require
        // using format_args! with runtime strings, which is uncommon. The taint analyzer
        // handles data flow tracking for such cases. A simple pattern match here would
        // produce too many false positives on safe code like format!("Bearer {}", token).
        SecurityQuery {
            id: "rust/command-injection",
            name: "Potential Command Injection",
            description: "Detects Command::new with potential string interpolation",
            query: r#"
            (call_expression
              function: (scoped_identifier
                name: (identifier) @new (#eq? @new "new")
              )
              arguments: (arguments
                (call_expression
                  function: (field_expression
                    field: (field_identifier) @method
                    (#match? @method "^(format|to_string)$")
                  )
                )
              )
            ) @cmd_injection
            "#,
            language: Language::Rust,
            severity: Severity::High,
            cwes: &["CWE-78"],
            remediation: "Validate and sanitize command arguments. Use allowlists for permitted commands.",
        },
        SecurityQuery {
            id: "rust/sql-string",
            name: "SQL String Construction",
            description: "Detects potential SQL injection through string concatenation",
            query: r#"
            (call_expression
              function: (scoped_identifier
                name: (identifier) @method
                (#match? @method "^(query|execute)$")
              )
              arguments: (arguments
                (binary_expression
                  operator: "+"
                )
              )
            ) @sql_injection
            "#,
            language: Language::Rust,
            severity: Severity::Critical,
            cwes: &["CWE-89"],
            remediation: "Use parameterized queries instead of string concatenation.",
        },
        SecurityQuery {
            id: "rust/path-traversal",
            name: "Potential Path Traversal",
            description: "Detects file operations with potential path traversal",
            query: r#"
            (call_expression
              function: (scoped_identifier
                path: (scoped_identifier
                  name: (identifier) @fs (#eq? @fs "fs")
                )
                name: (identifier) @method
                (#match? @method "^(read|write|open|create|remove).*$")
              )
            ) @path_op
            "#,
            language: Language::Rust,
            severity: Severity::Medium,
            cwes: &["CWE-22"],
            remediation: "Validate paths and use canonicalize() to resolve symlinks.",
        },
        SecurityQuery {
            id: "rust/hardcoded-secret",
            name: "Hardcoded Secret Pattern",
            description: "Detects variables named like secrets with string literal values",
            query: r#"
            (let_declaration
              pattern: (identifier) @var_name
              value: (string_literal) @value
              (#match? @var_name "(?i)(api_key|apikey|secret|token|password|passwd|auth|credential)")
            ) @hardcoded_secret
            "#,
            language: Language::Rust,
            severity: Severity::High,
            cwes: &["CWE-798"],
            remediation: "Store secrets in environment variables or a secrets manager.",
        },
        SecurityQuery {
            id: "rust/weak-crypto",
            name: "Weak Cryptography",
            description: "Detects usage of weak cryptographic algorithms",
            query: r#"
            (use_declaration
              argument: (scoped_identifier) @import
              (#match? @import "(md5|sha1|rc4|des|md4)")
            ) @weak_crypto
            "#,
            language: Language::Rust,
            severity: Severity::High,
            cwes: &["CWE-327", "CWE-328"],
            remediation: "Use strong cryptography: SHA-256+, AES-GCM, ChaCha20-Poly1305.",
        },
        // NEW: Detect panic! in library code (availability DoS)
        SecurityQuery {
            id: "rust/panic-in-library",
            name: "Panic in Library Code",
            description: "Detects panic! macro calls in library code which can cause denial of service",
            query: r#"
            (macro_invocation
              macro: (identifier) @macro_name
              (#eq? @macro_name "panic")
            ) @panic_call
            "#,
            language: Language::Rust,
            severity: Severity::Medium,
            cwes: &["CWE-400", "CWE-755"],
            remediation: "Return Result::Err instead of panicking in library code. Panic should be reserved for unrecoverable errors.",
        },
        // NEW: Detect lazy_static usage (potential initialization races)
        SecurityQuery {
            id: "rust/lazy-static-race",
            name: "Lazy Static Initialization Race",
            description: "Detects lazy_static usage which may have initialization race conditions in multi-threaded contexts",
            query: r#"
            (macro_invocation
              macro: (identifier) @macro_name
              (#eq? @macro_name "lazy_static")
            ) @lazy_static_usage
            "#,
            language: Language::Rust,
            severity: Severity::Low,
            cwes: &["CWE-362", "CWE-362"],
            remediation: "Consider using std::sync::LazyLock (Rust 1.80+) or once_cell for safer lazy initialization.",
        },
        // NEW: Detect RefCell usage (runtime borrow violations)
        SecurityQuery {
            id: "rust/refcell-usage",
            name: "RefCell Dynamic Borrow",
            description: "Detects RefCell usage which can cause runtime panic on borrow violations",
            query: r#"
            (call_expression
              function: (scoped_identifier
                path: (identifier) @cell (#eq? @cell "RefCell")
                name: (identifier) @new (#eq? @new "new")
              )
            ) @refcell_usage
            "#,
            language: Language::Rust,
            severity: Severity::Low,
            cwes: &["CWE-400"],
            remediation: "Use RefCell carefully. Consider alternatives like Mutex or RwLock for thread-safe interior mutability.",
        },
        // NEW: Detect unbounded Vec::push in loops (memory DoS)
        SecurityQuery {
            id: "rust/unbounded-vec-push",
            name: "Unbounded Vec Growth in Loop",
            description: "Detects unbounded Vec::push operations in loops that can lead to memory exhaustion",
            query: r#"
            (for_expression
              body: (block
                (call_expression
                  function: (field_expression
                    field: (field_identifier) @push (#eq? @push "push")
                  ) @vec_push
                )
              )
            ) @unbounded_push
            "#,
            language: Language::Rust,
            severity: Severity::Medium,
            cwes: &["CWE-400", "CWE-770"],
            remediation: "Add bounds checking or capacity limits before pushing to vectors in loops.",
        },
    ]
}

/// Get all security queries for Python.
pub fn python_queries() -> Vec<SecurityQuery> {
    vec![
        SecurityQuery {
            id: "python/exec-eval",
            name: "Dangerous Exec/Eval",
            description: "Detects exec() and eval() which can execute arbitrary code",
            query: r#"
            (call
              function: (identifier) @fn_name
              (#match? @fn_name "^(exec|eval|compile)$")
            ) @dangerous_call
            "#,
            language: Language::Python,
            severity: Severity::Critical,
            cwes: &["CWE-94", "CWE-95"],
            remediation: "Avoid exec/eval. Use ast.literal_eval for safe literal parsing.",
        },
        SecurityQuery {
            id: "python/sql-injection",
            name: "SQL Injection",
            description: "Detects SQL queries built with string formatting",
            query: r#"
            (call
              function: (attribute
                attribute: (identifier) @method
                (#match? @method "^(execute|executemany)$")
              )
              arguments: (argument_list
                (binary_operator
                  operator: "%"
                )
              )
            ) @sql_injection
            "#,
            language: Language::Python,
            severity: Severity::Critical,
            cwes: &["CWE-89"],
            remediation: "Use parameterized queries with placeholders.",
        },
        SecurityQuery {
            id: "python/command-injection",
            name: "Command Injection",
            description: "Detects os.system and subprocess with shell=True",
            query: r#"
            (call
              function: (attribute
                object: (identifier) @module (#eq? @module "os")
                attribute: (identifier) @method (#eq? @method "system")
              )
            ) @cmd_injection
            "#,
            language: Language::Python,
            severity: Severity::Critical,
            cwes: &["CWE-78"],
            remediation: "Use subprocess with shell=False and list arguments.",
        },
        SecurityQuery {
            id: "python/pickle-load",
            name: "Insecure Deserialization",
            description: "Detects pickle.load which can execute arbitrary code",
            query: r#"
            (call
              function: (attribute
                object: (identifier) @module (#eq? @module "pickle")
                attribute: (identifier) @method (#match? @method "^(load|loads)$")
              )
            ) @pickle_load
            "#,
            language: Language::Python,
            severity: Severity::Critical,
            cwes: &["CWE-502"],
            remediation: "Use JSON or other safe serialization formats for untrusted data.",
        },
        SecurityQuery {
            id: "python/hardcoded-password",
            name: "Hardcoded Password",
            description: "Detects hardcoded passwords in assignments",
            query: r#"
            (assignment
              left: (identifier) @var
              right: (string) @value
              (#match? @var "(?i)(password|passwd|secret|token|api_key)")
            ) @hardcoded_pw
            "#,
            language: Language::Python,
            severity: Severity::High,
            cwes: &["CWE-798"],
            remediation: "Use environment variables or a secrets manager.",
        },
        SecurityQuery {
            id: "python/assert-security",
            name: "Assert Used for Security",
            description: "Detects assert statements that may be stripped in production",
            query: r#"
            (assert_statement
              (comparison_operator) @condition
            ) @assert
            "#,
            language: Language::Python,
            severity: Severity::Medium,
            cwes: &["CWE-617"],
            remediation: "Use proper if/raise for security checks, not assert.",
        },
        SecurityQuery {
            id: "python/debug-true",
            name: "Debug Mode Enabled",
            description: "Detects DEBUG=True which may leak sensitive information",
            query: r#"
            (assignment
              left: (identifier) @var (#eq? @var "DEBUG")
              right: (true) @value
            ) @debug_true
            "#,
            language: Language::Python,
            severity: Severity::Medium,
            cwes: &["CWE-489"],
            remediation: "Ensure DEBUG is False in production.",
        },
        SecurityQuery {
            id: "python/weak-crypto",
            name: "Weak Cryptography",
            description: "Detects usage of weak cryptographic algorithms",
            query: r#"
            (import_from_statement
              module_name: (dotted_name) @module
              (#match? @module "(md5|sha1|DES|RC4)")
            ) @weak_crypto
            "#,
            language: Language::Python,
            severity: Severity::High,
            cwes: &["CWE-327"],
            remediation: "Use strong algorithms: SHA-256+, AES-GCM.",
        },
        // NEW: Detect requests without timeout (connection DoS)
        SecurityQuery {
            id: "python/requests-no-timeout",
            name: "HTTP Request Without Timeout",
            description: "Detects requests library calls without timeout parameter which can cause connection DoS",
            query: r#"
            (call
              function: (attribute
                object: (identifier) @requests (#eq? @requests "requests")
                attribute: (identifier) @method
                (#match? @method "^(get|post|put|delete|patch|head|options|request)$")
              )
              arguments: (argument_list) @args
              (#not-match? @args "timeout")
            ) @no_timeout_request
            "#,
            language: Language::Python,
            severity: Severity::Medium,
            cwes: &["CWE-400"],
            remediation: "Always specify a timeout parameter for HTTP requests to prevent indefinite hanging.",
        },
        // NEW: Detect tempfile.mktemp race condition
        SecurityQuery {
            id: "python/tempfile-mktemp",
            name: "Insecure Temporary File Creation",
            description: "Detects tempfile.mktemp usage which is vulnerable to race conditions",
            query: r#"
            (call
              function: (attribute
                object: (identifier) @tempfile (#eq? @tempfile "tempfile")
                attribute: (identifier) @mktemp (#eq? @mktemp "mktemp")
              )
            ) @mktemp_race
            "#,
            language: Language::Python,
            severity: Severity::High,
            cwes: &["CWE-377", "CWE-362"],
            remediation: "Use tempfile.mkstemp() or NamedTemporaryFile instead of mktemp to avoid race conditions.",
        },
        // NEW: Detect logging format string injection
        SecurityQuery {
            id: "python/logging-format-injection",
            name: "Logging Format String Injection",
            description: "Detects logging calls that may be vulnerable to format string injection",
            query: r#"
            (call
              function: (attribute
                object: (identifier) @logger (#match? @logger "^(logging|logger|log)$")
                attribute: (identifier) @method
                (#match? @method "^(debug|info|warning|error|critical|exception)$")
              )
              arguments: (argument_list
                (string) @msg
                (#match? @msg "%")
              )
            ) @format_injection
            "#,
            language: Language::Python,
            severity: Severity::Medium,
            cwes: &["CWE-134"],
            remediation: "Use %-style formatting with a tuple or use f-strings (Python 3.6+) instead of passing user data to log messages.",
        },
        // NEW: Detect __import__ with user input
        SecurityQuery {
            id: "python/dynamic-import",
            name: "Dynamic Import with User Input",
            description: "Detects __import__ or importlib usage which can execute arbitrary code",
            query: r#"
            (call
              function: (identifier) @import
              (#eq? @import "__import__")
            ) @dynamic_import
            "#,
            language: Language::Python,
            severity: Severity::High,
            cwes: &["CWE-94", "CWE-95"],
            remediation: "Avoid dynamic imports with user-controlled input. Use a whitelist of allowed modules if necessary.",
        },
    ]
}

/// Get all security queries for JavaScript.
pub fn javascript_queries() -> Vec<SecurityQuery> {
    vec![
        SecurityQuery {
            id: "js/eval",
            name: "Eval Usage",
            description: "Detects eval() which can execute arbitrary code",
            query: r#"
            (call_expression
              function: (identifier) @fn_name (#eq? @fn_name "eval")
            ) @eval_call
            "#,
            language: Language::JavaScript,
            severity: Severity::Critical,
            cwes: &["CWE-94", "CWE-95"],
            remediation: "Avoid eval(). Use JSON.parse for data, proper functions for logic.",
        },
        SecurityQuery {
            id: "js/innerhtml",
            name: "innerHTML Assignment",
            description: "Detects innerHTML which can lead to XSS",
            query: r#"
            (assignment_expression
              left: (member_expression
                property: (property_identifier) @prop (#eq? @prop "innerHTML")
              )
            ) @innerhtml
            "#,
            language: Language::JavaScript,
            severity: Severity::High,
            cwes: &["CWE-79"],
            remediation: "Use textContent or DOM methods instead of innerHTML.",
        },
        SecurityQuery {
            id: "js/document-write",
            name: "document.write Usage",
            description: "Detects document.write which can lead to XSS",
            query: r#"
            (call_expression
              function: (member_expression
                object: (identifier) @obj (#eq? @obj "document")
                property: (property_identifier) @prop (#eq? @prop "write")
              )
            ) @doc_write
            "#,
            language: Language::JavaScript,
            severity: Severity::High,
            cwes: &["CWE-79"],
            remediation: "Use DOM manipulation methods instead of document.write.",
        },
        SecurityQuery {
            id: "js/hardcoded-secret",
            name: "Hardcoded Secret",
            description: "Detects hardcoded secrets in variable declarations",
            query: r#"
            (variable_declarator
              name: (identifier) @var
              value: (string) @value
              (#match? @var "(?i)(api_key|apikey|secret|token|password|auth)")
            ) @hardcoded
            "#,
            language: Language::JavaScript,
            severity: Severity::High,
            cwes: &["CWE-798"],
            remediation: "Use environment variables for secrets.",
        },
        SecurityQuery {
            id: "js/sql-concat",
            name: "SQL String Concatenation",
            description: "Detects SQL queries built with string concatenation",
            query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @method (#match? @method "^(query|execute)$")
              )
              arguments: (arguments
                (binary_expression
                  operator: "+"
                  left: (string) @sql (#match? @sql "(?i)(SELECT|INSERT|UPDATE|DELETE)")
                )
              )
            ) @sql_injection
            "#,
            language: Language::JavaScript,
            severity: Severity::Critical,
            cwes: &["CWE-89"],
            remediation: "Use parameterized queries.",
        },
        SecurityQuery {
            id: "js/shell-exec",
            name: "Shell Command Execution",
            description: "Detects child_process exec with potential command injection",
            query: r#"
            (call_expression
              function: (identifier) @fn (#match? @fn "^(exec|execSync)$")
            ) @shell_exec
            "#,
            language: Language::JavaScript,
            severity: Severity::High,
            cwes: &["CWE-78"],
            remediation: "Use execFile with array arguments instead of exec.",
        },
        SecurityQuery {
            id: "js/regex-dos",
            name: "ReDoS Vulnerable Regex",
            description: "Detects regexes with nested quantifiers that may cause ReDoS",
            query: r#"
            (regex
              pattern: (regex_pattern) @pattern
              (#match? @pattern "\\(.+\\+\\).+\\+|\\(.+\\*\\).+\\*")
            ) @redos
            "#,
            language: Language::JavaScript,
            severity: Severity::Medium,
            cwes: &["CWE-1333"],
            remediation: "Simplify regex or use a timeout. Avoid nested quantifiers.",
        },
        SecurityQuery {
            id: "js/no-csrf",
            name: "Missing CSRF Protection",
            description: "Detects form submissions without CSRF tokens",
            query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @method (#match? @method "^(post|put|delete)$")
              )
            ) @http_call
            "#,
            language: Language::JavaScript,
            severity: Severity::Medium,
            cwes: &["CWE-352"],
            remediation: "Include CSRF tokens in state-changing requests.",
        },
        // NEW: Detect prototype pollution via Object.assign
        SecurityQuery {
            id: "js/prototype-pollution",
            name: "Prototype Pollution Risk",
            description: "Detects Object.assign or spread operator that may allow prototype pollution",
            query: r#"
            (call_expression
              function: (member_expression
                object: (identifier) @obj (#eq? @obj "Object")
                property: (property_identifier) @method
                (#eq? @method "assign")
              )
              arguments: (arguments
                (identifier) @target (#match? @target "^(target|dst|dest|destination)$")
              )
            ) @prototype_pollution
            "#,
            language: Language::JavaScript,
            severity: Severity::High,
            cwes: &["CWE-915", "CWE-1321"],
            remediation: "Use Object.assign with an empty object as target, or use structuredClone. Validate property keys to block __proto__ and constructor.",
        },
        // NEW: Detect dynamic require with user-controlled paths
        SecurityQuery {
            id: "js/dynamic-require",
            name: "Dynamic Module Loading",
            description: "Detects require() with dynamic or potentially user-controlled paths",
            query: r#"
            (call_expression
              function: (identifier) @require (#eq? @require "require")
              arguments: (arguments
                [
                  (identifier) @dynamic
                  (template_string) @template
                  (binary_expression) @concat
                ]
              )
            ) @dynamic_require
            "#,
            language: Language::JavaScript,
            severity: Severity::Medium,
            cwes: &["CWE-94", "CWE-95"],
            remediation: "Avoid dynamic require paths. Use a whitelist of allowed modules if dynamic loading is necessary.",
        },
        // NEW: Detect missing Object.freeze on exported constants
        SecurityQuery {
            id: "js/mutable-exports",
            name: "Mutable Exported Constants",
            description: "Detects exported objects/arrays that are not frozen, allowing external mutation",
            query: r#"
            (export_statement
              (lexical_declaration
                (variable_declarator
                  name: (identifier) @const_name
                  value: [
                    (object) @obj_value
                    (array) @arr_value
                  ]
                )
              )
            ) @mutable_export
            "#,
            language: Language::JavaScript,
            severity: Severity::Low,
            cwes: &["CWE-665"],
            remediation: "Use Object.freeze() on exported constants to prevent external mutation: export const CONFIG = Object.freeze({...}).",
        },
        // NEW: Detect JSON.parse without try-catch
        SecurityQuery {
            id: "js/unhandled-json-parse",
            name: "Unhandled JSON Parsing",
            description: "Detects JSON.parse calls that may throw on invalid input",
            query: r#"
            (call_expression
              function: (member_expression
                object: (identifier) @json (#eq? @json "JSON")
                property: (property_identifier) @parse (#eq? @parse "parse")
              )
            ) @json_parse
            "#,
            language: Language::JavaScript,
            severity: Severity::Low,
            cwes: &["CWE-755", "CWE-248"],
            remediation: "Wrap JSON.parse in a try-catch block to handle malformed JSON gracefully.",
        },
    ]
}

/// Get all security queries for Go.
pub fn go_queries() -> Vec<SecurityQuery> {
    vec![
        SecurityQuery {
            id: "go/sql-injection",
            name: "SQL Injection",
            description: "Detects SQL queries built with string concatenation",
            query: r#"
            (call_expression
              function: (selector_expression
                field: (field_identifier) @method
                (#match? @method "^(Query|Exec|QueryRow)$")
              )
              arguments: (argument_list
                (binary_expression
                  operator: "+"
                )
              )
            ) @sql_injection
            "#,
            language: Language::Go,
            severity: Severity::Critical,
            cwes: &["CWE-89"],
            remediation: "Use prepared statements with placeholders.",
        },
        SecurityQuery {
            id: "go/command-injection",
            name: "Command Injection",
            description: "Detects os/exec with potential command injection",
            query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @pkg (#eq? @pkg "exec")
                field: (field_identifier) @method (#eq? @method "Command")
              )
            ) @cmd_exec
            "#,
            language: Language::Go,
            severity: Severity::High,
            cwes: &["CWE-78"],
            remediation: "Validate command arguments. Use allowlists for commands.",
        },
        SecurityQuery {
            id: "go/hardcoded-cred",
            name: "Hardcoded Credential",
            description: "Detects hardcoded credentials in variable declarations",
            query: r#"
            (short_var_declaration
              left: (expression_list
                (identifier) @var
                (#match? @var "(?i)(password|secret|token|apikey|api_key)")
              )
              right: (expression_list
                (interpreted_string_literal) @value
              )
            ) @hardcoded
            "#,
            language: Language::Go,
            severity: Severity::High,
            cwes: &["CWE-798"],
            remediation: "Use environment variables or a secrets manager.",
        },
        SecurityQuery {
            id: "go/tls-insecure",
            name: "Insecure TLS Configuration",
            description: "Detects InsecureSkipVerify which disables TLS certificate validation",
            query: r#"
            (keyed_element
              (field_identifier) @field (#eq? @field "InsecureSkipVerify")
              (true) @value
            ) @insecure_tls
            "#,
            language: Language::Go,
            severity: Severity::High,
            cwes: &["CWE-295"],
            remediation: "Enable proper TLS certificate validation.",
        },
        SecurityQuery {
            id: "go/weak-random",
            name: "Weak Random Number Generator",
            description: "Detects math/rand usage which is not cryptographically secure",
            query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @pkg (#eq? @pkg "rand")
                field: (field_identifier) @method
                (#match? @method "^(Int|Intn|Float|Read)$")
              )
            ) @weak_rand
            "#,
            language: Language::Go,
            severity: Severity::Medium,
            cwes: &["CWE-338"],
            remediation: "Use crypto/rand for security-sensitive random numbers.",
        },
        SecurityQuery {
            id: "go/path-traversal",
            name: "Path Traversal",
            description: "Detects file operations with potential path traversal",
            query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @pkg (#match? @pkg "^(os|ioutil)$")
                field: (field_identifier) @method
                (#match? @method "^(Open|Create|ReadFile|WriteFile)$")
              )
            ) @path_op
            "#,
            language: Language::Go,
            severity: Severity::Medium,
            cwes: &["CWE-22"],
            remediation: "Validate and sanitize file paths. Use filepath.Clean.",
        },
        SecurityQuery {
            id: "go/unhandled-error",
            name: "Unhandled Error",
            description: "Detects ignored error return values",
            query: r#"
            (assignment_statement
              left: (expression_list
                (identifier) @blank (#eq? @blank "_")
              )
              right: (expression_list
                (call_expression)
              )
            ) @ignored_error
            "#,
            language: Language::Go,
            severity: Severity::Low,
            cwes: &["CWE-755"],
            remediation: "Handle errors appropriately instead of ignoring them.",
        },
        // NEW: Detect defer in loops (resource exhaustion)
        SecurityQuery {
            id: "go/defer-in-loop",
            name: "Defer Inside Loop",
            description: "Detects defer statements inside loops that can cause resource exhaustion",
            query: r#"
            (for_statement
              body: (block
                (defer_statement) @defer
              )
            ) @defer_in_loop
            "#,
            language: Language::Go,
            severity: Severity::Medium,
            cwes: &["CWE-400", "CWE-770"],
            remediation: "Move defer outside the loop or use an anonymous function to execute and release resources immediately.",
        },
        // NEW: Detect sync.Map type assertions
        SecurityQuery {
            id: "go/sync-map-assertion",
            name: "Sync.Map Type Assertion Panic",
            description: "Detects type assertions on sync.Map values that can panic at runtime",
            query: r#"
            (call_expression
              function: (selector_expression
                operand: (call_expression
                  function: (selector_expression
                    operand: (identifier) @sm (#eq? @sm "sync")
                    field: (field_identifier) @map (#eq? @map "Map")
                  )
                )
                field: (field_identifier) @load (#eq? @load "Load")
              )
            ) @sync_map_load
            "#,
            language: Language::Go,
            severity: Severity::Low,
            cwes: &["CWE-400", "CWE-754"],
            remediation: "Use the two-value form of type assertion (value, ok := ...) to handle type mismatches gracefully.",
        },
        // NEW: Detect unbuffered channel operations that may deadlock
        SecurityQuery {
            id: "go/unbuffered-channel",
            name: "Potential Channel Deadlock",
            description: "Detects unbuffered channel operations within the same function that may cause deadlock",
            query: r#"
            (call_expression
              function: (identifier) @make (#eq? @make "make")
              arguments: (argument_list
                (channel_type)
              )
            ) @unbuffered_channel
            "#,
            language: Language::Go,
            severity: Severity::Low,
            cwes: &["CWE-833", "CWE-662"],
            remediation: "Use buffered channels or ensure proper goroutine coordination to prevent deadlocks.",
        },
        // NEW: Detect context.Background without timeout
        SecurityQuery {
            id: "go/context-no-timeout",
            name: "Context Without Timeout",
            description: "Detects context.Background() usage which lacks cancellation/timeout",
            query: r#"
            (call_expression
              function: (selector_expression
                operand: (identifier) @ctx (#eq? @ctx "context")
                field: (field_identifier) @bg (#eq? @bg "Background")
              )
            ) @context_background
            "#,
            language: Language::Go,
            severity: Severity::Low,
            cwes: &["CWE-400"],
            remediation: "Use context.WithTimeout() or context.WithDeadline() instead of context.Background() for operations that should not run indefinitely.",
        },
    ]
}

/// Get all queries for a specific language.
pub fn get_queries_for_language(language: Language) -> Vec<SecurityQuery> {
    match language {
        Language::Rust => rust_queries(),
        Language::Python => python_queries(),
        Language::JavaScript | Language::TypeScript => javascript_queries(),
        Language::Go => go_queries(),
        _ => Vec::new(),
    }
}

/// Get all security queries across all languages.
pub fn all_queries() -> Vec<SecurityQuery> {
    let mut queries = Vec::new();
    queries.extend(rust_queries());
    queries.extend(python_queries());
    queries.extend(javascript_queries());
    queries.extend(go_queries());
    queries
}
