//! Rules for JavaScript. They also run on TypeScript and TSX, whose grammars share
//! these node types.

use super::{Rule, RuleLanguage};
use crate::model::{Confidence, Severity};

pub static RULES: &[Rule] = &[
    Rule {
        id: "js/eval",
        language: RuleLanguage::JavaScript,
        name: "eval / new Function on dynamic input",
        message: "eval() and the Function constructor run a string as code. If the string is influenced by user input, the attacker can run arbitrary code.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: &["CWE-95"],
        remediation: "Parse data with JSON.parse, or look the operation up in an explicit table of allowed functions.",
        query: r#"
(call_expression
  function: (identifier) @f
  arguments: (arguments . [(identifier) (member_expression) (call_expression) (subscript_expression) (binary_expression) (template_string (template_substitution))])
  (#eq? @f "eval")) @finding

(new_expression
  constructor: (identifier) @c
  arguments: (arguments [(identifier) (member_expression) (call_expression) (subscript_expression) (binary_expression) (template_string (template_substitution))])
  (#eq? @c "Function")) @finding

(call_expression
  function: (member_expression object: (identifier) @o property: (property_identifier) @m)
  arguments: (arguments . [(identifier) (member_expression) (call_expression) (subscript_expression) (binary_expression) (template_string (template_substitution))])
  (#eq? @o "vm")
  (#match? @m "^(runInContext|runInNewContext|runInThisContext|compileFunction)$")) @finding

(new_expression
  constructor: (member_expression object: (identifier) @o property: (property_identifier) @c)
  arguments: (arguments . [(identifier) (member_expression) (call_expression) (subscript_expression) (binary_expression) (template_string (template_substitution))])
  (#eq? @o "vm")
  (#eq? @c "Script")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "const r = eval(input);",
            "eval(`${a} + ${b}`);",
            "const fn = new Function('a', body);",
            "vm.runInNewContext(req.body.expr, sandbox);",
            "const s = new vm.Script(code);",
        ],
        counter_examples: &[
            "eval('1 + 1');",
            "model.eval(x);",
            "const f = new Map();",
            "const add = new Function('a', 'b', 'return a + b');",
            "vm.runInNewContext('1 + 1', sandbox);",
        ],
    },
    Rule {
        id: "js/command-injection",
        language: RuleLanguage::JavaScript,
        name: "Shell command built from dynamic input",
        message: "child_process.exec/execSync (and spawn with shell: true) pass the command through a shell. A non-constant command string allows command injection.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: &["CWE-78"],
        remediation: "Use execFile/spawn with an argument array and without shell: true.",
        query: r#"
(call_expression
  function: (identifier) @f
  arguments: (arguments . [(identifier) (member_expression) (call_expression) (binary_expression) (template_string (template_substitution))])
  (#match? @f "^(exec|execSync)$")) @finding

(call_expression
  function: (member_expression object: (identifier) @o property: (property_identifier) @f)
  arguments: (arguments . [(identifier) (member_expression) (call_expression) (binary_expression) (template_string (template_substitution))])
  (#match? @o "^(child_process|childProcess|cp)$")
  (#match? @f "^(exec|execSync)$")) @finding

(call_expression
  function: [(identifier) @f (member_expression property: (property_identifier) @f)]
  arguments: (arguments (object (pair key: (property_identifier) @k value: (true))))
  (#match? @f "^(spawn|spawnSync|execFile|execFileSync)$")
  (#eq? @k "shell")) @finding
"#,
        requires: Some(r"child_process"),
        bindings: None,
        jsx: false,
        examples: &[
            "const { exec } = require('child_process');\nexec(`git clone ${url}`);",
            "import * as cp from 'child_process';\ncp.execSync('rm -rf ' + dir);",
            "const { spawn } = require('child_process');\nspawn(cmd, args, { shell: true });",
        ],
        counter_examples: &[
            "const { execFile } = require('child_process');\nexecFile('git', ['clone', url]);",
            "const { exec } = require('child_process');\nexec('ls -la');",
            "const re = /a/; re.exec(input); // child_process not used here",
            "exec(`git clone ${url}`);",
        ],
    },
    Rule {
        id: "js/sql-injection",
        language: RuleLanguage::JavaScript,
        name: "SQL built from strings",
        message: "A SQL statement is built with + or a template literal and passed to a query function. Values are not escaped, so untrusted input leads to SQL injection.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-89"],
        remediation: "Use placeholders (db.query('... WHERE id = $1', [id])) or a tagged-template API that parameterizes values.",
        query: r#"
(call_expression
  function: (member_expression property: (property_identifier) @m)
  arguments: (arguments . [(binary_expression) (template_string (template_substitution))] @q)
  (#match? @m "^(query|execute|exec|raw|prepare|unsafe|\\$queryRawUnsafe|\\$executeRawUnsafe)$")
  (#match? @q "(?is)\\b(select\\s.+\\sfrom|insert\\s+into|update\\s.+\\sset|delete\\s+from|drop\\s+table)\\b")) @finding

(call_expression
  function: (member_expression property: (property_identifier) @m)
  arguments: (arguments . (identifier) @arg)
  (#match? @m "^(query|execute|exec|raw|prepare|unsafe|\\$queryRawUnsafe|\\$executeRawUnsafe)$")
  (#bound? @arg)) @finding
"#,
        requires: None,
        bindings: Some(
            r#"
(variable_declarator
  name: (identifier) @var
  value: [(binary_expression) (template_string (template_substitution))] @q
  (#match? @q "(?is)\\b(select\\s.+\\sfrom|insert\\s+into|update\\s.+\\sset|delete\\s+from|drop\\s+table)\\b"))

(assignment_expression
  left: (identifier) @var
  right: [(binary_expression) (template_string (template_substitution))] @q
  (#match? @q "(?is)\\b(select\\s.+\\sfrom|insert\\s+into|update\\s.+\\sset|delete\\s+from|drop\\s+table)\\b"))
"#,
        ),
        jsx: false,
        examples: &[
            "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
            "conn.execute(\"DELETE FROM orders WHERE id = \" + id);",
            "await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE name = '${name}'`);",
            "async function f(db, id) {\n  const sql = `SELECT * FROM users WHERE id = ${id}`;\n  const rows = await db.query(sql);\n}",
            "let q;\nq = \"DELETE FROM t WHERE id = \" + id;\nconn.execute(q).then(done);",
        ],
        counter_examples: &[
            "db.query('SELECT * FROM users WHERE id = $1', [id]);",
            "async function f(db, id) {\n  const sql = 'SELECT * FROM users WHERE id = $1';\n  await db.query(sql, [id]);\n}",
            "function a(id) { const sql = `SELECT * FROM t WHERE id = ${id}`; }\nfunction b(db, sql) { db.query(sql); }",
            "await prisma.$queryRaw`SELECT * FROM t WHERE name = ${name}`;",
            "cache.query(`select-${key}`);",
            "re.exec(`${a}${b}`);",
        ],
    },
    Rule {
        id: "js/html-injection",
        language: RuleLanguage::JavaScript,
        name: "HTML built from dynamic input",
        message: "Dynamic content is written as HTML (innerHTML, outerHTML, insertAdjacentHTML, document.write). If it contains user input, this is cross-site scripting.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: &["CWE-79"],
        remediation: "Use textContent or DOM APIs, or sanitize with a library such as DOMPurify before inserting HTML.",
        query: r#"
(assignment_expression
  left: (member_expression property: (property_identifier) @p)
  right: [(identifier) (member_expression) (call_expression) (subscript_expression) (binary_expression) (template_string (template_substitution))]
  (#match? @p "^(innerHTML|outerHTML)$")) @finding

(augmented_assignment_expression
  left: (member_expression property: (property_identifier) @p)
  right: [(identifier) (member_expression) (call_expression) (subscript_expression) (binary_expression) (template_string (template_substitution))]
  (#match? @p "^(innerHTML|outerHTML)$")) @finding

(call_expression
  function: (member_expression
    object: (call_expression function: (identifier) @j)
    property: (property_identifier) @m)
  arguments: (arguments . [(identifier) (member_expression) (call_expression) (subscript_expression) (binary_expression) (template_string (template_substitution))])
  (#match? @j "^(\\$|jQuery)$")
  (#eq? @m "html")) @finding

(call_expression
  function: (member_expression
    object: (call_expression function: (identifier) @j)
    property: (property_identifier) @m)
  arguments: (arguments . [(binary_expression) (template_string (template_substitution))])
  (#match? @j "^(\\$|jQuery)$")
  (#match? @m "^(append|prepend|after|before|replaceWith)$")) @finding

(call_expression
  function: (member_expression property: (property_identifier) @m)
  arguments: (arguments (_) . [(identifier) (member_expression) (call_expression) (binary_expression) (template_string (template_substitution))])
  (#eq? @m "insertAdjacentHTML")) @finding

(call_expression
  function: (member_expression object: (identifier) @o property: (property_identifier) @m)
  arguments: (arguments . [(identifier) (member_expression) (call_expression) (binary_expression) (template_string (template_substitution))])
  (#eq? @o "document")
  (#match? @m "^(write|writeln)$")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "el.innerHTML = comment.body;",
            "el.innerHTML = `<b>${name}</b>`;",
            "list.innerHTML += item;",
            "el.insertAdjacentHTML('beforeend', html);",
            "document.write('<p>' + msg + '</p>');",
            "$('#out').html(data.message);",
            "jQuery(el).append(`<li>${item.name}</li>`);",
        ],
        counter_examples: &[
            "list.innerHTML += '<li>static</li>';",
            "$('#out').html('<b>static</b>');",
            "$('#out').text(data.message);",
            "$('#list').append(node);",
            "el.innerHTML = '';",
            "el.innerHTML = `<br>`;",
            "el.textContent = comment.body;",
            "document.write('<p>static</p>');",
        ],
    },
    Rule {
        id: "js/dangerously-set-inner-html",
        language: RuleLanguage::JavaScript,
        name: "dangerouslySetInnerHTML",
        message: "React renders this value as raw HTML. Unless it is sanitized, user-controlled content here is cross-site scripting.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: &["CWE-79"],
        remediation: "Render text through JSX, or sanitize the HTML (e.g. DOMPurify.sanitize) right where it is passed.",
        query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "dangerouslySetInnerHTML")) @finding"#,
        requires: None,
        bindings: None,
        jsx: true,
        examples: &["const C = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;"],
        counter_examples: &["const C = ({ text }) => <div>{text}</div>;"],
    },
    Rule {
        id: "js/tls-verification-disabled",
        language: RuleLanguage::JavaScript,
        name: "TLS certificate verification disabled",
        message: "Certificate verification is turned off, so anyone on the network path can impersonate the server.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-295"],
        remediation: "Remove rejectUnauthorized: false / NODE_TLS_REJECT_UNAUTHORIZED=0. To trust a private CA, pass it via the `ca` option or NODE_EXTRA_CA_CERTS.",
        query: r#"
(pair key: [(property_identifier) (string)] @k value: (false)
  (#match? @k "^[\"']?rejectUnauthorized[\"']?$")) @finding

(assignment_expression
  left: (member_expression property: (property_identifier) @p)
  right: [(string) (number)] @v
  (#eq? @p "NODE_TLS_REJECT_UNAUTHORIZED")
  (#match? @v "^[\"']?0[\"']?$")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "const agent = new https.Agent({ rejectUnauthorized: false });",
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
        ],
        counter_examples: &[
            "const agent = new https.Agent({ rejectUnauthorized: true });",
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';",
        ],
    },
    Rule {
        id: "js/weak-crypto",
        language: RuleLanguage::JavaScript,
        name: "Weak hash or cipher",
        message: "MD5/SHA-1 are broken for collision resistance; DES, RC4, Blowfish and ECB mode do not protect data.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: &["CWE-327", "CWE-328"],
        remediation: "Use SHA-256 or better for hashing and aes-256-gcm or chacha20-poly1305 for encryption.",
        query: r#"
(call_expression
  function: (member_expression property: (property_identifier) @m)
  arguments: (arguments . (string) @alg)
  (#eq? @m "createHash")
  (#match? @alg "^[\"'](?i:md5|md4|sha1|sha-1)[\"']$")) @finding

(call_expression
  function: (member_expression property: (property_identifier) @m)
  arguments: (arguments . (string) @alg)
  (#match? @m "^createCipher(iv)?$")
  (#match? @alg "^[\"'](?i:des|des-|rc4|rc2|bf|blowfish|aes-\\d+-ecb)")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "const h = crypto.createHash('md5').update(pw).digest('hex');",
            "crypto.createCipheriv('des-ede3-cbc', key, iv);",
            "crypto.createCipheriv(\"aes-128-ecb\", key, null);",
        ],
        counter_examples: &[
            "crypto.createHash('sha256');",
            "crypto.createCipheriv('aes-256-gcm', key, iv);",
        ],
    },
    Rule {
        id: "js/regex-dos",
        language: RuleLanguage::JavaScript,
        name: "Regex with nested quantifiers",
        message: "A quantified group that itself contains a quantifier (e.g. (a+)+) can take exponential time on crafted input (ReDoS).",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: &["CWE-1333"],
        remediation: "Rewrite the pattern so repetitions cannot overlap (e.g. (a+)+ becomes a+), or bound the input length.",
        query: r#"
(regex pattern: (regex_pattern) @p
  (#match? @p "\\([^()]*[+*][^()]*\\)[+*{]")
  (#not-match? @p "\\(\\[\\^(,|;|:|\\\\/|/|\\\\.|\\|| |\\\\s)\\][+*](,|;|:|\\\\/|/|\\\\.|\\|| |\\\\s)\\??\\)[+*]|\\((,|;|:|\\\\/|/|\\\\.|\\|| |\\\\s)\\[\\^(,|;|:|\\\\/|/|\\\\.|\\|| |\\\\s)\\][+*]\\)[+*]")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "const re = /^(a+)+$/;",
            "const email = /^([a-zA-Z0-9]+\\s?)*$/;",
        ],
        counter_examples: &[
            "const csv = /^([^,]+,)*[^,]+$/;",
            "const path = /^(\\/[^\\/]+)+$/;",
            "const re = /^(\\d+)\\.(\\d+)$/;",
            "const re = /(a|b)+/;",
            "const re = /^a+$/;",
        ],
    },
    Rule {
        id: "js/sanitizer-bypass",
        language: RuleLanguage::JavaScript,
        name: "Angular sanitizer bypassed for dynamic content",
        message: "bypassSecurityTrust* tells Angular to render the value without sanitizing it. If the value contains user input, this is cross-site scripting.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: &["CWE-79"],
        remediation: "Let Angular sanitize the value (bind it normally), or sanitize it yourself (e.g. DOMPurify) right before trusting it.",
        query: r#"
(call_expression
  function: (member_expression property: (property_identifier) @m)
  arguments: (arguments . [(identifier) (member_expression) (call_expression) (subscript_expression) (binary_expression) (template_string (template_substitution))])
  (#match? @m "^bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)$")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &["this.html = this.sanitizer.bypassSecurityTrustHtml(comment.body);"],
        counter_examples: &["this.icon = this.sanitizer.bypassSecurityTrustHtml('<svg></svg>');"],
    },
    Rule {
        id: "js/nosql-injection",
        language: RuleLanguage::JavaScript,
        name: "MongoDB $where with dynamic code",
        message: "$where runs JavaScript on the database server. Building it from a variable or string lets user input become server-side code.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: &["CWE-943"],
        remediation: "Express the condition with query operators ($eq, $gt, $regex, ...) instead of $where.",
        query: r#"
(pair
  key: [(property_identifier) (string)] @k
  value: [(identifier) (member_expression) (call_expression) (subscript_expression) (binary_expression) (template_string (template_substitution))]
  (#match? @k "^[\"']?\\$where[\"']?$")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "db.users.find({ $where: `this.name == '${req.query.name}'` });",
            "User.find({ '$where': 'this.age > ' + age });",
        ],
        counter_examples: &[
            "db.users.find({ $where: function () { return this.a > 1; } });",
            "db.users.find({ name: req.query.name });",
        ],
    },
];
