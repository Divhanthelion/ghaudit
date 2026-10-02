use super::{Rule, RuleLanguage};
use crate::model::{Confidence, Severity};

pub static RULES: &[Rule] = &[
    Rule {
        id: "python/eval",
        language: RuleLanguage::Python,
        name: "eval/exec on dynamic input",
        message: "eval() or exec() runs a string as Python code. If the string is influenced by user input, the attacker can run arbitrary code.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: &["CWE-95"],
        remediation: "Parse data instead of executing it: json.loads, ast.literal_eval, or an explicit dispatch table.",
        query: r#"
(call
  function: (identifier) @f
  arguments: (argument_list . [(identifier) (attribute) (call) (subscript) (binary_operator) (string (interpolation))])
  (#match? @f "^(eval|exec)$")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "result = eval(user_input)",
            "exec(request.form['code'])",
            "eval(f\"{a} + {b}\")",
        ],
        counter_examples: &["x = eval(\"1 + 2\")", "model.eval()", "ast.literal_eval(s)"],
    },
    Rule {
        id: "python/sql-injection",
        language: RuleLanguage::Python,
        name: "SQL built from strings",
        message: "A SQL statement is built with %-formatting, +, .format() or an f-string and then executed. Values are not escaped, so untrusted input leads to SQL injection.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-89"],
        remediation: "Pass values as parameters: cursor.execute(\"... WHERE id = %s\", (user_id,)), or use your ORM's query API.",
        query: r#"
(call
  function: (attribute attribute: (identifier) @m)
  arguments: (argument_list . [
    (binary_operator)
    (string (interpolation))
    (call function: (attribute object: (string) attribute: (identifier) @fmt) (#eq? @fmt "format"))
  ] @q)
  (#match? @m "^(execute|executemany|executescript|raw|mogrify)$")
  (#match? @q "(?i)\\b(select|insert|update|delete|drop|create|alter|replace)\\b")) @finding

(call
  function: [(identifier) @t (attribute attribute: (identifier) @t)]
  arguments: (argument_list . [(binary_operator) (string (interpolation))] @q)
  (#eq? @t "text")
  (#match? @q "(?i)\\b(select|insert|update|delete|drop|create|alter)\\b")) @finding

(call
  function: (attribute object: (attribute attribute: (identifier) @o) attribute: (identifier) @m)
  arguments: (argument_list . [(binary_operator) (string (interpolation)) (call function: (attribute attribute: (identifier) @f2))])
  (#eq? @o "objects")
  (#eq? @m "raw")) @finding

(call
  function: [(attribute attribute: (identifier) @m) (identifier) @m]
  arguments: (argument_list . (identifier) @arg)
  (#match? @m "^(execute|executemany|executescript|raw|mogrify|text)$")
  (#bound? @arg)) @finding
"#,
        requires: None,
        bindings: Some(
            r#"
(assignment
  left: (identifier) @var
  right: [
    (binary_operator)
    (string (interpolation))
    (call function: (attribute object: (string) attribute: (identifier) @fmt) (#eq? @fmt "format"))
  ] @q
  (#match? @q "(?i)\\b(select|insert|update|delete|drop|create|alter|replace)\\b"))
"#,
        ),
        jsx: false,
        examples: &[
            "cur.execute(\"SELECT * FROM users WHERE id = %s\" % user_id)",
            "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
            "cur.execute(\"DELETE FROM t WHERE id=\" + str(i))",
            "cur.execute(\"SELECT {} FROM t\".format(col))",
            "db.session.execute(text(f\"SELECT * FROM x WHERE y = {y}\"))",
            "def f(cur, name):\n    q = f\"SELECT * FROM users WHERE name = '{name}'\"\n    log(q)\n    cur.execute(q)",
            "def f(cur, t):\n    sql = \"DROP TABLE \" + t\n    rows = cur.execute(sql).fetchall()",
            "User.objects.raw(f\"SELECT * FROM auth_user WHERE id = {uid}\")",
        ],
        counter_examples: &[
            "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
            "cur.execute(query, params)",
            "log.info(\"select %s\" % x)",
            "pool.execute(task_a + task_b)",
            "def f(cur, x):\n    q = \"SELECT * FROM t WHERE id = %s\"\n    cur.execute(q, (x,))",
            "def a(n):\n    q = f\"SELECT {n}\"\n\ndef b(cur, q):\n    cur.execute(q)",
            "def f(cur, n):\n    cur.execute(q)\n    q = f\"SELECT {n}\"",
            "User.objects.raw(\"SELECT * FROM auth_user WHERE id = %s\", [uid])",
        ],
    },
    Rule {
        id: "python/subprocess-shell",
        language: RuleLanguage::Python,
        name: "subprocess with shell=True",
        message: "The command is passed to a shell and is not a fixed string. If any part of it comes from user input, this is command injection.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: &["CWE-78"],
        remediation: "Pass a list of arguments with shell=False (the default): subprocess.run([\"ls\", path]).",
        query: r#"
(call
  function: [(identifier) @fn (attribute attribute: (identifier) @fn)]
  arguments: (argument_list
    . [(identifier) (attribute) (call) (subscript) (binary_operator) (string (interpolation))]
    (keyword_argument name: (identifier) @k value: (true)))
  (#match? @fn "^(run|call|check_call|check_output|Popen)$")
  (#eq? @k "shell")) @finding

(call
  function: [(identifier) @fn (attribute attribute: (identifier) @fn)]
  arguments: (argument_list . [(identifier) (attribute) (call) (subscript) (binary_operator) (string (interpolation))])
  (#match? @fn "^(getoutput|getstatusoutput|create_subprocess_shell)$")) @finding
"#,
        // Any import of subprocess or asyncio, so `from subprocess import run` counts.
        requires: Some(r"\b(subprocess|asyncio)\b"),
        bindings: None,
        jsx: false,
        examples: &[
            "subprocess.run(cmd, shell=True)",
            "subprocess.Popen(\"tar xf \" + name, shell=True, stdout=PIPE)",
            "subprocess.check_output(f\"ping {host}\", shell=True)",
            "from subprocess import run\nrun(cmd, shell=True)",
            "import subprocess\nout = subprocess.getoutput(\"du -sh \" + path)",
            "import asyncio\nawait asyncio.create_subprocess_shell(cmd)",
        ],
        counter_examples: &[
            "subprocess.run([\"ls\", path])",
            "subprocess.run(cmd, shell=False)",
            "subprocess.run(\"make clean\", shell=True)",
            "import asyncio\nawait asyncio.create_subprocess_exec(\"ls\", path)",
            "runner.run(task, shell=True)",
        ],
    },
    Rule {
        id: "python/os-command",
        language: RuleLanguage::Python,
        name: "os.system/os.popen on dynamic input",
        message: "os.system and os.popen run their argument through a shell. A non-constant command string allows command injection.",
        severity: Severity::High,
        confidence: Confidence::Medium,
        cwe: &["CWE-78"],
        remediation: "Use subprocess.run([...]) with a list of arguments.",
        query: r#"
(call
  function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
  arguments: (argument_list . [(identifier) (attribute) (call) (subscript) (binary_operator) (string (interpolation))])
  (#eq? @mod "os")
  (#match? @fn "^(system|popen)$")) @finding

(call
  function: (identifier) @fn
  arguments: (argument_list . [(identifier) (attribute) (call) (subscript) (binary_operator) (string (interpolation))])
  (#match? @fn "^(system|popen)$")) @finding
"#,
        // `os.system(...)`, or `system(...)` after `from os import system`.
        requires: Some(r"\bos\.(system|popen)\b|from\s+os\s+import\b[^\n]*\b(system|popen)\b"),
        bindings: None,
        jsx: false,
        examples: &[
            "os.system(cmd)",
            "os.popen(\"cat \" + path)",
            "os.system(f\"rm {f}\")",
            "from os import system\nsystem(\"rm -rf \" + d)",
        ],
        counter_examples: &[
            "os.system(\"clear\")",
            "os.path.join(a, b)",
            "def system(x): pass\nsystem(x)",
        ],
    },
    Rule {
        id: "python/unsafe-deserialization",
        language: RuleLanguage::Python,
        name: "Unsafe deserialization",
        message: "pickle, marshal, dill and shelve can execute arbitrary code while loading. Never load data an attacker can influence.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-502"],
        remediation: "Use a data-only format such as JSON, or sign and verify the data before loading it.",
        query: r#"
(call
  function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
  (#match? @mod "^(pickle|cPickle|_pickle|dill|marshal|shelve)$")
  (#match? @fn "^(load|loads|Unpickler|open)$")) @finding

(call
  function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
  (#match? @mod "^(pd|pandas)$")
  (#eq? @fn "read_pickle")) @finding

(call
  function: (identifier) @fn
  (#match? @fn "^(loads|load|Unpickler)$")) @finding
"#,
        // A bare `loads(...)` counts only after `from pickle import loads` (or dill, marshal).
        requires: Some(
            r"\b(pickle|cPickle|_pickle|dill|marshal|shelve)\.|\b(pd|pandas)\.read_pickle\b|from\s+(pickle|cPickle|_pickle|dill|marshal)\s+import\b[^\n]*\b(loads?|Unpickler)\b",
        ),
        bindings: None,
        jsx: false,
        examples: &[
            "data = pickle.loads(blob)",
            "obj = pickle.load(open(p, 'rb'))",
            "df = pd.read_pickle(path)",
            "db = shelve.open(name)",
            "from pickle import loads\nobj = loads(request.data)",
        ],
        counter_examples: &[
            "data = json.loads(blob)",
            "pickle.dumps(obj)",
            "from json import loads\nobj = loads(body)",
        ],
    },
    Rule {
        id: "python/yaml-load",
        language: RuleLanguage::Python,
        name: "yaml.load without a safe loader",
        message: "yaml.load with the default or full Loader can construct arbitrary Python objects from the document, which can lead to code execution.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-502"],
        remediation: "Use yaml.safe_load(), or yaml.load(data, Loader=yaml.SafeLoader).",
        query: r#"
(call
  function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
  arguments: (argument_list) @args
  (#eq? @mod "yaml")
  (#eq? @fn "load")
  (#not-match? @args "(SafeLoader|CSafeLoader|BaseLoader)")) @finding

(call
  function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
  (#eq? @mod "yaml")
  (#match? @fn "^(unsafe_load|unsafe_load_all)$")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "cfg = yaml.load(f)",
            "cfg = yaml.load(f, Loader=yaml.Loader)",
            "cfg = yaml.unsafe_load(s)",
        ],
        counter_examples: &[
            "cfg = yaml.safe_load(f)",
            "cfg = yaml.load(f, Loader=yaml.SafeLoader)",
        ],
    },
    Rule {
        id: "python/weak-hash",
        language: RuleLanguage::Python,
        name: "Weak hash algorithm",
        message: "MD5 and SHA-1 are broken for collision resistance and must not be used for signatures, tokens or passwords.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        cwe: &["CWE-328"],
        remediation: "Use hashlib.sha256 or better. For non-security checksums, pass usedforsecurity=False to document the intent.",
        query: r#"
(call
  function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
  arguments: (argument_list) @args
  (#eq? @mod "hashlib")
  (#match? @fn "^(md5|sha1|md4)$")
  (#not-match? @args "usedforsecurity\\s*=\\s*False")) @finding

(call
  function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
  arguments: (argument_list . (string) @alg) @args
  (#eq? @mod "hashlib")
  (#eq? @fn "new")
  (#match? @alg "^[\"'](?i:md5|sha1|md4)[\"']$")
  (#not-match? @args "usedforsecurity\\s*=\\s*False")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "h = hashlib.md5(data).hexdigest()",
            "hashlib.sha1(pw.encode())",
            "hashlib.new('md5', data)",
        ],
        counter_examples: &[
            "hashlib.sha256(data)",
            "hashlib.md5(data, usedforsecurity=False)",
            "hashlib.new('sha256')",
        ],
    },
    Rule {
        id: "python/weak-cipher",
        language: RuleLanguage::Python,
        name: "Broken cipher or ECB mode",
        message: "DES, 3DES, RC2, RC4 and Blowfish are broken or obsolete, and ECB mode leaks patterns in the plaintext.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-327"],
        remediation: "Use AES-GCM or ChaCha20-Poly1305 (e.g. cryptography's AESGCM).",
        query: r#"
(import_from_statement
  module_name: (dotted_name) @mod
  name: (dotted_name) @n
  (#match? @mod "^(Crypto|Cryptodome)\\.Cipher$")
  (#match? @n "^(DES|DES3|ARC2|ARC4|Blowfish|XOR)$")) @finding

(attribute attribute: (identifier) @a (#eq? @a "MODE_ECB")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "from Crypto.Cipher import DES",
            "c = AES.new(key, AES.MODE_ECB)",
        ],
        counter_examples: &[
            "from Crypto.Cipher import AES",
            "c = AES.new(key, AES.MODE_GCM)",
        ],
    },
    Rule {
        id: "python/tls-verification-disabled",
        language: RuleLanguage::Python,
        name: "TLS certificate verification disabled",
        message: "Certificate verification is turned off, so anyone on the network path can impersonate the server.",
        severity: Severity::High,
        confidence: Confidence::High,
        cwe: &["CWE-295"],
        remediation: "Remove verify=False. To trust a private CA, pass verify=\"/path/to/ca.pem\".",
        query: r#"
(call
  arguments: (argument_list (keyword_argument name: (identifier) @k value: (false)))
  (#eq? @k "verify")) @finding

(attribute object: (identifier) @mod attribute: (identifier) @a
  (#eq? @mod "ssl")
  (#match? @a "^(_create_unverified_context|CERT_NONE)$")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &[
            "requests.get(url, verify=False)",
            "httpx.Client(verify=False)",
            "ctx = ssl._create_unverified_context()",
            "ctx.verify_mode = ssl.CERT_NONE",
        ],
        counter_examples: &[
            "requests.get(url, verify=True)",
            "requests.get(url, verify=ca_path)",
            "ctx.verify_mode = ssl.CERT_REQUIRED",
        ],
    },
    Rule {
        id: "python/request-without-timeout",
        language: RuleLanguage::Python,
        name: "HTTP request without timeout",
        message: "requests has no default timeout: a slow or malicious server can hang this call (and the worker running it) forever.",
        severity: Severity::Low,
        confidence: Confidence::High,
        cwe: &["CWE-400"],
        remediation: "Pass timeout=(connect_seconds, read_seconds).",
        query: r#"
(call
  function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
  arguments: (argument_list) @args
  (#eq? @mod "requests")
  (#match? @fn "^(get|post|put|patch|delete|head|options|request)$")
  (#not-match? @args "timeout\\s*=")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &["r = requests.get(url)", "requests.post(url, json=body)"],
        counter_examples: &["requests.get(url, timeout=10)", "session.get(url)"],
    },
    Rule {
        id: "python/flask-debug",
        language: RuleLanguage::Python,
        name: "Flask debug mode",
        message: "The Werkzeug debugger lets anyone who can reach it run Python code on the server.",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: &["CWE-489"],
        remediation: "Never enable debug=True outside local development; read it from configuration.",
        query: r#"
(call
  function: (attribute attribute: (identifier) @fn)
  arguments: (argument_list (keyword_argument name: (identifier) @k value: (true)))
  (#eq? @fn "run")
  (#eq? @k "debug")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &["app.run(host=\"0.0.0.0\", debug=True)"],
        counter_examples: &["app.run(debug=False)", "app.run()"],
    },
    Rule {
        id: "python/insecure-tempfile",
        language: RuleLanguage::Python,
        name: "tempfile.mktemp",
        message: "mktemp returns a name without creating the file; another process can create it first (race condition, possible symlink attack).",
        severity: Severity::Medium,
        confidence: Confidence::High,
        cwe: &["CWE-377"],
        remediation: "Use tempfile.mkstemp(), NamedTemporaryFile() or TemporaryDirectory().",
        query: r#"
(call
  function: (attribute object: (identifier) @mod attribute: (identifier) @fn)
  (#eq? @mod "tempfile")
  (#eq? @fn "mktemp")) @finding
"#,
        requires: None,
        bindings: None,
        jsx: false,
        examples: &["path = tempfile.mktemp()"],
        counter_examples: &["fd, path = tempfile.mkstemp()"],
    },
];
