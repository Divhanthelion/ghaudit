use super::{Rule, RuleLanguage};
use crate::model::{Confidence, Severity};

pub static RULES: &[Rule] = &[
    Rule {
        id: "rust/unsafe-block",
        language: RuleLanguage::Rust,
        name: "Unsafe block",
        message: "An unsafe block opts out of the compiler's memory-safety checks. Not a bug by itself, but every one is a place a memory-safety bug can hide.",
        severity: Severity::Info,
        confidence: Confidence::High,
        cwe: &["CWE-119"],
        remediation: "Keep unsafe blocks minimal and document the invariants they rely on in a `// SAFETY:` comment.",
        query: r#"(unsafe_block) @finding"#,
        requires: None,
        jsx: false,
        examples: &["fn f() { unsafe { libc::free(p) } }"],
        counter_examples: &["fn f() { let unsafe_count = 1; }"],
    },
    Rule {
        id: "rust/unsafe-impl",
        language: RuleLanguage::Rust,
        name: "Unsafe trait implementation",
        message: "`unsafe impl` (commonly Send or Sync) promises the compiler a thread-safety or memory invariant it cannot verify. A wrong promise causes data races or undefined behavior.",
        severity: Severity::Low,
        confidence: Confidence::High,
        cwe: &["CWE-362"],
        remediation: "Confirm the type really upholds the trait's safety contract and document why.",
        query: r#"(impl_item "unsafe") @finding"#,
        requires: None,
        jsx: false,
        examples: &["struct P(*mut u8);\nunsafe impl Send for P {}"],
        counter_examples: &["impl Send for P {}", "unsafe fn f() {}"],
    },
    Rule {
        id: "rust/transmute",
        language: RuleLanguage::Rust,
        name: "mem::transmute",
        message: "transmute reinterprets bits as another type with no checks; a size, alignment or validity mismatch is undefined behavior.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: &["CWE-843"],
        remediation: "Prefer safe conversions (from_ne_bytes, to_bits, pointer casts, bytemuck) over transmute.",
        query: r#"
(call_expression
  function: [
    (identifier) @f
    (scoped_identifier name: (identifier) @f)
    (generic_function function: [(identifier) @f (scoped_identifier name: (identifier) @f)])
  ]
  (#eq? @f "transmute")) @finding
"#,
        requires: None,
        jsx: false,
        examples: &[
            "fn f(x: u32) -> f32 { unsafe { std::mem::transmute(x) } }",
            "fn f(x: u32) -> f32 { unsafe { mem::transmute::<u32, f32>(x) } }",
            "use std::mem::transmute;\nfn f(x: u32) -> f32 { unsafe { transmute(x) } }",
        ],
        counter_examples: &[
            "fn f(x: u32) -> f32 { f32::from_bits(x) }",
            "fn f() { my_transmute(1); }",
        ],
    },
    Rule {
        id: "rust/shell-command",
        language: RuleLanguage::Rust,
        name: "Command runs a shell",
        message: "Starting a shell (sh -c, cmd /C, PowerShell) means the shell parses the command string. If any part of it comes from user input, this is command injection.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: &["CWE-78"],
        remediation: "Run the program directly with Command::new(program).args([...]) so arguments are never parsed by a shell.",
        query: r#"
(call_expression
  function: (scoped_identifier path: (_) @ty name: (identifier) @new)
  arguments: (arguments . (string_literal (string_content) @prog))
  (#match? @ty "(^|::)Command$")
  (#eq? @new "new")
  (#match? @prog "^(sh|bash|zsh|dash|ksh|fish|cmd|cmd\\.exe|powershell|powershell\\.exe|pwsh|/bin/sh|/bin/bash|/usr/bin/bash)$")) @finding
"#,
        requires: None,
        jsx: false,
        examples: &[
            "fn f(c: &str) { Command::new(\"sh\").arg(\"-c\").arg(c).status(); }",
            "fn f() { std::process::Command::new(\"cmd.exe\").args([\"/C\", x]); }",
        ],
        counter_examples: &[
            "fn f() { Command::new(\"git\").args([\"status\"]).status(); }",
            "fn f() { Builder::new(\"sh\"); }",
        ],
    },
    Rule {
        id: "rust/sql-format",
        language: RuleLanguage::Rust,
        name: "SQL built with format!",
        message: "A SQL statement is assembled with format! and passed to a query function. Interpolated values are not escaped, so untrusted input leads to SQL injection.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: &["CWE-89"],
        remediation: "Use bind parameters (sqlx `.bind()`, rusqlite `params![]`, diesel's query builder) instead of formatting values into SQL.",
        query: r#"
(call_expression
  function: [
    (identifier) @m
    (field_expression field: (field_identifier) @m)
    (scoped_identifier name: (identifier) @m)
    (generic_function function: [(identifier) @m (field_expression field: (field_identifier) @m) (scoped_identifier name: (identifier) @m)])
  ]
  arguments: (arguments . [
    (macro_invocation macro: (identifier) @mac (token_tree . (string_literal) @fmt))
    (reference_expression value: (macro_invocation macro: (identifier) @mac (token_tree . (string_literal) @fmt)))
  ])
  (#match? @m "^(query|query_as|query_scalar|query_one|query_opt|query_row|query_map|execute|execute_batch|batch_execute|simple_query|prepare|prepare_cached|raw_sql|sql_query)$")
  (#eq? @mac "format")
  (#match? @fmt "(?i)\\b(select|insert|update|delete|drop|create|alter|replace)\\b")) @finding
"#,
        requires: None,
        jsx: false,
        examples: &[
            "async fn f(p: &PgPool, id: &str) { sqlx::query(&format!(\"SELECT * FROM users WHERE id = '{}'\", id)).fetch_all(p).await; }",
            "fn f(c: &Connection, n: &str) { c.execute(&format!(\"DELETE FROM t WHERE name = '{n}'\"), []); }",
            "fn f(c: &mut Client, t: &str) { c.batch_execute(&format!(\"DROP TABLE {}\", t)); }",
        ],
        counter_examples: &[
            "async fn f(p: &PgPool, id: i32) { sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(id).fetch_all(p).await; }",
            "fn f(c: &Connection, n: &str) { c.execute(\"DELETE FROM t WHERE name = ?1\", params![n]); }",
            "fn f(s: &Search, q: &str) { s.query(&format!(\"title:{}\", q)); }",
        ],
    },
    Rule {
        id: "rust/tls-verification-disabled",
        language: RuleLanguage::Rust,
        name: "TLS certificate verification disabled",
        message: "Certificate or hostname verification is turned off, so any machine on the network path can impersonate the server (man-in-the-middle).",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-295"],
        remediation: "Keep verification on. To trust a private CA, add its certificate as a root instead of disabling checks.",
        query: r#"
(call_expression
  function: (field_expression field: (field_identifier) @m)
  arguments: (arguments . (boolean_literal) @v)
  (#match? @m "^danger_accept_invalid_(certs|hostnames)$")
  (#eq? @v "true")) @finding

(call_expression
  function: (field_expression field: (field_identifier) @m)
  arguments: (arguments . (scoped_identifier name: (identifier) @mode))
  (#eq? @m "set_verify")
  (#eq? @mode "NONE")) @finding
"#,
        requires: None,
        jsx: false,
        examples: &[
            "fn f() { reqwest::Client::builder().danger_accept_invalid_certs(true).build(); }",
            "fn f(b: &mut SslConnectorBuilder) { b.set_verify(SslVerifyMode::NONE); }",
        ],
        counter_examples: &[
            "fn f() { reqwest::Client::builder().danger_accept_invalid_certs(false).build(); }",
            "fn f(b: &mut SslConnectorBuilder) { b.set_verify(SslVerifyMode::PEER); }",
        ],
    },
    Rule {
        id: "rust/weak-hash",
        language: RuleLanguage::Rust,
        name: "Weak hash algorithm",
        message: "MD5 and SHA-1 are broken for collision resistance. Fine for non-security checksums, unsafe for signatures, integrity checks against an attacker, or password hashing.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: &["CWE-328"],
        remediation: "Use SHA-256/SHA-3/BLAKE3 for integrity, and argon2/scrypt/bcrypt for passwords.",
        query: r#"
(use_declaration argument: (_) @arg
  (#match? @arg "(^|::|\\{|,\\s*)(md5|md4|sha1|sha1_smol|Md5|Md4|Sha1)(::|\\}|,|$)")) @finding
"#,
        requires: None,
        jsx: false,
        examples: &[
            "use md5::{Md5, Digest};",
            "use sha1::Sha1;",
            "use ring::digest::{SHA256, Sha1};",
        ],
        counter_examples: &[
            "use sha2::Sha256;",
            "use crate::nodes::md5sum_cache;",
            "use blake3::Hasher;",
        ],
    },
    Rule {
        id: "rust/weak-cipher",
        language: RuleLanguage::Rust,
        name: "Broken cipher",
        message: "DES, 3DES and RC4 are cryptographically broken and must not protect data.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-327"],
        remediation: "Use an AEAD cipher such as AES-GCM or ChaCha20-Poly1305.",
        query: r#"
(use_declaration argument: (_) @arg
  (#match? @arg "(^|::|\\{|,\\s*)(des|rc4|Des|TdesEde2|TdesEde3|TdesEee3|Rc4)(::|\\}|,|$)")) @finding
"#,
        requires: None,
        jsx: false,
        examples: &[
            "use des::Des;",
            "use rc4::{Rc4, KeyInit};",
            "use des::{TdesEde3, cipher::KeyInit};",
        ],
        counter_examples: &[
            "use aes_gcm::Aes256Gcm;",
            "use crate::modes::describe;",
            "use serde::de::Deserialize;",
        ],
    },
];
