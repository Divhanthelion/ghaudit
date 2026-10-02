use super::{Rule, RuleLanguage};
use crate::model::{Confidence, Severity};

pub static RULES: &[Rule] = &[
    Rule {
        id: "go/sql-injection",
        language: RuleLanguage::Go,
        name: "SQL built from strings",
        message: "A SQL statement is built with + or fmt.Sprintf and passed to database/sql. Values are not escaped, so untrusted input leads to SQL injection.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-89"],
        remediation: "Use placeholders: db.Query(\"SELECT ... WHERE id = $1\", id).",
        query: r#"
(call_expression
  function: (selector_expression field: (field_identifier) @m)
  arguments: (argument_list (binary_expression) @q)
  (#match? @m "^(Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext|Raw)$")
  (#match? @q "(?is)\\b(select\\s.+\\sfrom|insert\\s+into|update\\s.+\\sset|delete\\s+from|drop\\s+table)\\b")) @finding

(call_expression
  function: (selector_expression field: (field_identifier) @m)
  arguments: (argument_list
    (call_expression
      function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn)
      arguments: (argument_list . (interpreted_string_literal) @q)))
  (#match? @m "^(Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext|Raw)$")
  (#eq? @pkg "fmt")
  (#eq? @fn "Sprintf")
  (#match? @q "(?is)\\b(select\\s.+\\sfrom|insert\\s+into|update\\s.+\\sset|delete\\s+from|drop\\s+table)\\b")) @finding

(call_expression
  function: (selector_expression field: (field_identifier) @m)
  arguments: (argument_list (identifier) @arg)
  (#match? @m "^(Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext|Raw)$")
  (#bound? @arg)) @finding
"#,
        requires: None,
        bindings: Some(
            r#"
(short_var_declaration
  left: (expression_list . (identifier) @var)
  right: (expression_list . (binary_expression) @q)
  (#match? @q "(?is)\\b(select\\s.+\\sfrom|insert\\s+into|update\\s.+\\sset|delete\\s+from|drop\\s+table)\\b"))

(short_var_declaration
  left: (expression_list . (identifier) @var)
  right: (expression_list .
    (call_expression
      function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn)
      arguments: (argument_list . (interpreted_string_literal) @q)))
  (#eq? @pkg "fmt")
  (#eq? @fn "Sprintf")
  (#match? @q "(?is)\\b(select\\s.+\\sfrom|insert\\s+into|update\\s.+\\sset|delete\\s+from|drop\\s+table)\\b"))

(assignment_statement
  left: (expression_list . (identifier) @var)
  right: (expression_list . (binary_expression) @q)
  (#match? @q "(?is)\\b(select\\s.+\\sfrom|insert\\s+into|update\\s.+\\sset|delete\\s+from|drop\\s+table)\\b"))
"#,
        ),
        jsx: false,
        examples: &[
            "package m\nfunc f() { db.Query(\"SELECT * FROM users WHERE id = \" + id) }",
            "package m\nfunc f() { db.QueryContext(ctx, fmt.Sprintf(\"SELECT * FROM t WHERE name = '%s'\", n)) }",
            "package m\nfunc f(db *sql.DB, n string) {\n\tq := fmt.Sprintf(\"SELECT * FROM t WHERE name = '%s'\", n)\n\trows, err := db.QueryContext(ctx, q)\n\t_ = rows\n\t_ = err\n}",
            "package m\nfunc f(db *sql.DB, id string) {\n\tq := \"DELETE FROM t WHERE id = \" + id\n\tif _, err := db.Exec(q); err != nil {\n\t\tpanic(err)\n\t}\n}",
        ],
        counter_examples: &[
            "package m\nfunc f() { db.Query(\"SELECT * FROM users WHERE id = $1\", id) }",
            "package m\nfunc f() { log.Exec(prefix + suffix) }",
            "package m\nfunc f(db *sql.DB, id string) {\n\tq := \"SELECT * FROM t WHERE id = $1\"\n\tdb.Query(q, id)\n}",
            "package m\nfunc a(n string) { q := \"SELECT * FROM t WHERE n = \" + n; _ = q }\nfunc b(db *sql.DB, q string) { db.Query(q) }",
        ],
    },
    Rule {
        id: "go/shell-command",
        language: RuleLanguage::Go,
        name: "exec.Command runs a shell",
        message: "The command is run through a shell (sh -c, cmd /C). If any part of the command string comes from user input, this is command injection.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: &["CWE-78"],
        remediation: "Call the program directly: exec.Command(\"git\", \"clone\", url).",
        // The program is a shell, its flag runs a command string, and that string is
        // not a constant.
        query: r#"
(call_expression
  function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn)
  arguments: (argument_list
    . (interpreted_string_literal) @prog
    . (interpreted_string_literal) @flag
    . [(identifier) (binary_expression) (call_expression) (selector_expression) (index_expression)])
  (#eq? @pkg "exec")
  (#eq? @fn "Command")
  (#match? @prog "^\"(sh|bash|zsh|dash|cmd|cmd\\.exe|powershell|powershell\\.exe|pwsh|/bin/sh|/bin/bash)\"$")
  (#match? @flag "^\"(-[a-z]*c|/[cC]|-[Cc]ommand)\"$")) @finding

(call_expression
  function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn)
  arguments: (argument_list
    . (_)
    . (interpreted_string_literal) @prog
    . (interpreted_string_literal) @flag
    . [(identifier) (binary_expression) (call_expression) (selector_expression) (index_expression)])
  (#eq? @pkg "exec")
  (#eq? @fn "CommandContext")
  (#match? @prog "^\"(sh|bash|zsh|dash|cmd|cmd\\.exe|powershell|powershell\\.exe|pwsh|/bin/sh|/bin/bash)\"$")
  (#match? @flag "^\"(-[a-z]*c|/[cC]|-[Cc]ommand)\"$")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "package m\nfunc f() { exec.Command(\"sh\", \"-c\", cmd).Run() }",
            "package m\nfunc f() { exec.CommandContext(ctx, \"bash\", \"-lc\", c) }",
            "package m\nfunc f() { exec.Command(\"cmd\", \"/C\", \"dir \" + p) }",
        ],
        counter_examples: &[
            "package m\nfunc f() { exec.Command(\"git\", \"status\").Run() }",
            "package m\nfunc f() { exec.Command(\"git\", \"sh\").Run() }",
            "package m\nfunc f() { exec.Command(\"bash\", \"deploy.sh\").Run() }",
            "package m\nfunc f() { exec.Command(\"sh\", \"-c\", \"make clean\").Run() }",
        ],
    },
    Rule {
        id: "go/tls-verification-disabled",
        language: RuleLanguage::Go,
        name: "TLS certificate verification disabled",
        message: "InsecureSkipVerify turns off certificate checks, so anyone on the network path can impersonate the server.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-295"],
        remediation: "Remove InsecureSkipVerify. To trust a private CA, set RootCAs in tls.Config.",
        query: r#"
(keyed_element
  key: (literal_element (identifier) @k)
  value: (literal_element (true))
  (#eq? @k "InsecureSkipVerify")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &["package m\nvar c = &tls.Config{InsecureSkipVerify: true}"],
        counter_examples: &[
            "package m\nvar c = &tls.Config{InsecureSkipVerify: false}",
            "package m\nvar c = &tls.Config{MinVersion: tls.VersionTLS12}",
        ],
    },
    Rule {
        id: "go/weak-random",
        language: RuleLanguage::Go,
        name: "math/rand used",
        message: "math/rand is predictable. That is fine for simulations and jitter, but not for tokens, passwords, keys or anything an attacker should not guess.",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        cwe: &["CWE-338"],
        remediation: "Use crypto/rand for security-sensitive values.",
        query: r#"
(call_expression
  function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn)
  (#eq? @pkg "rand")
  (#match? @fn "^(Int|Intn|IntN|Int31|Int31n|Int32|Int32N|Int63|Int63n|Int64|Int64N|Uint32|Uint64|Float32|Float64|Perm|Shuffle|N)$")) @finding
"#,
        // Only when math/rand is imported under its own name; a file using crypto/rand
        // as `rand` must alias math/rand, so `rand.X` would not refer to it.
        requires: Some(r#"(?m)^\s*(import\s+)?"math/rand(/v2)?""#),
        bindings: None,
        jsx: false,
        examples: &[
            "package m\nimport \"math/rand\"\nfunc token() int { return rand.Intn(1000000) }",
        ],
        counter_examples: &[
            "package m\nimport \"crypto/rand\"\nfunc f(b []byte) { rand.Read(b) }",
            "package m\nimport (\n\tmrand \"math/rand\"\n\t\"crypto/rand\"\n)\nfunc f() { rand.Int(rand.Reader, max) }",
        ],
    },
    Rule {
        id: "go/weak-crypto",
        language: RuleLanguage::Go,
        name: "Weak hash or cipher",
        message: "MD5/SHA-1 are broken for collision resistance; DES and RC4 do not protect data.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: &["CWE-327", "CWE-328"],
        remediation: "Use crypto/sha256 for hashing and AES-GCM (crypto/cipher) or chacha20poly1305 for encryption.",
        query: r#"
(call_expression
  function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn)
  (#match? @pkg "^(md5|sha1)$")
  (#match? @fn "^(New|Sum)$")) @finding

(call_expression
  function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn)
  (#match? @pkg "^(des|rc4)$")
  (#match? @fn "^(NewCipher|NewTripleDESCipher)$")) @finding
"#,
        requires: Some(r#""crypto/(md5|sha1|des|rc4)""#),
        bindings: None,
        jsx: false,
        examples: &[
            "package m\nimport \"crypto/md5\"\nfunc f(b []byte) { md5.Sum(b) }",
            "package m\nimport \"crypto/des\"\nfunc f(k []byte) { des.NewCipher(k) }",
        ],
        counter_examples: &[
            "package m\nimport \"crypto/sha256\"\nfunc f(b []byte) { sha256.Sum256(b) }",
            "package m\nimport \"example.com/md5\"\nfunc f(b []byte) { md5.Sum(b) }",
        ],
    },
    Rule {
        id: "go/unsafe-pointer",
        language: RuleLanguage::Go,
        name: "unsafe.Pointer",
        message: "unsafe.Pointer bypasses Go's type and memory safety. Not a bug by itself, but a place memory corruption can hide.",
        severity: Severity::Info,
        confidence: Confidence::High,
        cwe: &["CWE-119"],
        remediation: "Avoid unsafe where possible; follow the documented valid patterns for unsafe.Pointer conversions.",
        query: r#"
(selector_expression operand: (identifier) @pkg field: (field_identifier) @f
  (#eq? @pkg "unsafe")
  (#eq? @f "Pointer")) @finding

(qualified_type package: (package_identifier) @pkg name: (type_identifier) @f
  (#eq? @pkg "unsafe")
  (#eq? @f "Pointer")) @finding
"#,
        requires: Some(r#""unsafe""#),
        bindings: None,
        jsx: false,
        examples: &[
            "package m\nimport \"unsafe\"\nfunc f(p *int) uintptr { return uintptr(unsafe.Pointer(p)) }",
        ],
        counter_examples: &["package m\nfunc f(p *int) *int { return p }"],
    },
    Rule {
        id: "go/template-escape-bypass",
        language: RuleLanguage::Go,
        name: "html/template escaping bypassed",
        message: "Converting a value to template.HTML (or JS, URL, CSS, ...) tells html/template it is already safe, so it is inserted without escaping. If it contains user input, this is cross-site scripting.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: &["CWE-79"],
        remediation: "Pass plain strings to the template and let it escape them; convert only constants or sanitized HTML.",
        query: r#"
(call_expression
  function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @t)
  arguments: (argument_list . [(identifier) (binary_expression) (call_expression) (selector_expression) (index_expression)])
  (#eq? @pkg "template")
  (#match? @t "^(HTML|HTMLAttr|JS|JSStr|URL|CSS|Srcset)$")) @finding
"#,
        requires: Some(r#""html/template""#),
        bindings: None,
        jsx: false,
        examples: &[
            "package m\nimport \"html/template\"\nfunc f(c string) template.HTML { return template.HTML(c) }",
            "package m\nimport \"html/template\"\nfunc f(r *Req) any { return template.HTML(\"<b>\" + r.Name + \"</b>\") }",
        ],
        counter_examples: &[
            "package m\nimport \"html/template\"\nconst logo = template.HTML(\"<svg></svg>\")",
            "package m\nimport \"text/template\"\nfunc f(c string) any { return template.HTML(c) }",
        ],
    },
];
