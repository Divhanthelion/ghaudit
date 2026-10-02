//! GitHub Actions expressions (`${{ ... }}`): finding them in strings, parsing them,
//! and deciding whether their value can be chosen by an outside attacker.
//!
//! Parsing, rather than matching text, is what lets the analyzer see that
//! `${{ github.event.issue.title == 'bug' }}` is a harmless boolean while
//! `${{ github.event.issue.title || 'none' }}` and
//! `${{ GitHub.Event['issue'].title }}` are the title itself.

use std::collections::HashMap;

/// One `${{ ... }}` in a string.
#[derive(Debug, PartialEq, Eq)]
pub struct Embedded<'a> {
    /// Byte offset of `${{` in the string.
    pub start: usize,
    /// The whole expression, `${{` to `}}`.
    pub text: &'a str,
    /// What is between the braces.
    pub body: &'a str,
}

/// Every `${{ ... }}` in `s`. A `}}` inside a quoted string does not end the expression.
pub fn embedded(s: &str) -> Vec<Embedded<'_>> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = s[from..].find("${{") {
        let start = from + i;
        let body_start = start + 3;
        let mut quoted = false;
        let mut end = None;
        let bytes = s.as_bytes();
        let mut j = body_start;
        while j < bytes.len() {
            match bytes[j] {
                b'\'' => quoted = !quoted,
                b'}' if !quoted && bytes.get(j + 1) == Some(&b'}') => {
                    end = Some(j);
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        let Some(end) = end else { break };
        out.push(Embedded {
            start,
            text: &s[start..end + 2],
            body: &s[body_start..end],
        });
        from = end + 2;
    }
    out
}

/// One step of a context access: `.name`, `['name']`, `.*` or `[expr]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    Name(String),
    Any,
}

#[derive(Debug, PartialEq)]
pub enum Expr {
    Literal,
    /// `github.event.issue.title`, lowercased (contexts are case-insensitive).
    Path(Vec<Seg>),
    Call(String, Vec<Expr>),
    /// Property access on something other than a context, e.g. `fromJSON(x).a`.
    Deref(Box<Expr>),
    /// `!x` and comparisons: always a boolean.
    Boolean,
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Literal,
    Dot,
    Star,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
    Not,
    Cmp,
    And,
    Or,
}

fn tokenize(s: &str) -> Option<Vec<Tok>> {
    let chars: Vec<char> = s.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '\'' => {
                // 'it''s': a doubled quote is an escaped quote.
                i += 1;
                loop {
                    match chars.get(i) {
                        None => return None,
                        Some('\'') if chars.get(i + 1) == Some(&'\'') => i += 2,
                        Some('\'') => break,
                        Some(_) => i += 1,
                    }
                }
                i += 1;
                toks.push(Tok::Literal);
            }
            c if c.is_ascii_digit()
                || (c == '-' && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit())) =>
            {
                i += 1;
                while chars
                    .get(i)
                    .is_some_and(|d| d.is_ascii_alphanumeric() || *d == '.')
                {
                    i += 1;
                }
                toks.push(Tok::Literal);
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while chars
                    .get(i)
                    .is_some_and(|d| d.is_ascii_alphanumeric() || *d == '_' || *d == '-')
                {
                    i += 1;
                }
                let word: String = chars[start..i]
                    .iter()
                    .collect::<String>()
                    .to_ascii_lowercase();
                // `true`, `null` and friends are literals unless a property access follows.
                let after_dot = toks.last() == Some(&Tok::Dot);
                match word.as_str() {
                    "true" | "false" | "null" | "nan" | "infinity" if !after_dot => {
                        toks.push(Tok::Literal)
                    }
                    _ => toks.push(Tok::Ident(word)),
                }
            }
            '.' => {
                toks.push(Tok::Dot);
                i += 1;
            }
            '*' => {
                toks.push(Tok::Star);
                i += 1;
            }
            '[' => {
                toks.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                toks.push(Tok::RBracket);
                i += 1;
            }
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            ',' => {
                toks.push(Tok::Comma);
                i += 1;
            }
            '&' if chars.get(i + 1) == Some(&'&') => {
                toks.push(Tok::And);
                i += 2;
            }
            '|' if chars.get(i + 1) == Some(&'|') => {
                toks.push(Tok::Or);
                i += 2;
            }
            '=' | '!' if chars.get(i + 1) == Some(&'=') => {
                toks.push(Tok::Cmp);
                i += 2;
            }
            '<' | '>' => {
                toks.push(Tok::Cmp);
                i += if chars.get(i + 1) == Some(&'=') { 2 } else { 1 };
            }
            '!' => {
                toks.push(Tok::Not);
                i += 1;
            }
            _ => return None,
        }
    }
    Some(toks)
}

/// Parse an expression body. `None` when it is not valid expression syntax.
pub fn parse(body: &str) -> Option<Expr> {
    let toks = tokenize(body)?;
    let mut p = P {
        toks,
        pos: 0,
        depth: 0,
    };
    let e = p.or()?;
    (p.pos == p.toks.len()).then_some(e)
}

/// Recursion bound for nested parentheses, calls and brackets.
const MAX_DEPTH: usize = 64;

struct P {
    toks: Vec<Tok>,
    pos: usize,
    depth: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Every nested sub-expression starts here, so this bounds the recursion.
    fn or(&mut self) -> Option<Expr> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        let mut left = self.and()?;
        while self.eat(&Tok::Or) {
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        self.depth -= 1;
        Some(left)
    }

    fn and(&mut self) -> Option<Expr> {
        let mut left = self.cmp()?;
        while self.eat(&Tok::And) {
            let right = self.cmp()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    fn cmp(&mut self) -> Option<Expr> {
        let left = self.unary()?;
        if self.eat(&Tok::Cmp) {
            self.unary()?;
            while self.eat(&Tok::Cmp) {
                self.unary()?;
            }
            return Some(Expr::Boolean);
        }
        Some(left)
    }

    fn unary(&mut self) -> Option<Expr> {
        let mut negated = false;
        while self.eat(&Tok::Not) {
            negated = true;
        }
        let e = self.postfix()?;
        Some(if negated { Expr::Boolean } else { e })
    }

    fn postfix(&mut self) -> Option<Expr> {
        let mut expr = match self.toks.get(self.pos).cloned()? {
            Tok::Literal => {
                self.pos += 1;
                Expr::Literal
            }
            Tok::LParen => {
                self.pos += 1;
                let e = self.or()?;
                self.eat(&Tok::RParen).then_some(())?;
                e
            }
            Tok::Ident(name) => {
                self.pos += 1;
                if self.eat(&Tok::LParen) {
                    let mut args = Vec::new();
                    if !self.eat(&Tok::RParen) {
                        loop {
                            args.push(self.or()?);
                            if self.eat(&Tok::RParen) {
                                break;
                            }
                            self.eat(&Tok::Comma).then_some(())?;
                        }
                    }
                    Expr::Call(name, args)
                } else {
                    Expr::Path(vec![Seg::Name(name)])
                }
            }
            _ => return None,
        };
        loop {
            let seg = if self.eat(&Tok::Dot) {
                match self.toks.get(self.pos).cloned()? {
                    Tok::Ident(name) => {
                        self.pos += 1;
                        Seg::Name(name)
                    }
                    Tok::Star => {
                        self.pos += 1;
                        Seg::Any
                    }
                    _ => return None,
                }
            } else if self.eat(&Tok::LBracket) {
                // `['name']` was rewritten to `.name` before parsing; what is left is
                // `[*]`, a number or a computed index, any of which can select any field.
                if !self.eat(&Tok::Star) {
                    self.or()?;
                }
                self.eat(&Tok::RBracket).then_some(())?;
                Seg::Any
            } else {
                break;
            };
            expr = match expr {
                Expr::Path(mut segs) => {
                    segs.push(seg);
                    Expr::Path(segs)
                }
                Expr::Deref(inner) => Expr::Deref(inner),
                other => Expr::Deref(Box::new(other)),
            };
        }
        Some(expr)
    }
}

/// Rewrite `['name']` property access to `.name`, so the parser sees one form.
fn normalize_brackets(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    let mut quoted = false;
    while i < chars.len() {
        let c = chars[i];
        if !quoted && c == '[' && chars.get(i + 1) == Some(&'\'') {
            let name_len = chars[i + 2..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == '_' || **c == '-')
                .count();
            let close = i + 2 + name_len;
            if name_len > 0 && chars.get(close) == Some(&'\'') && chars.get(close + 1) == Some(&']')
            {
                out.push('.');
                out.extend(&chars[i + 2..close]);
                i = close + 2;
                continue;
            }
        }
        if c == '\'' {
            quoted = !quoted;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Fields an outside attacker can set: issue and pull request text, branch names,
/// commit messages and author names. `*` matches any one segment. Numbers, SHAs and
/// repository names are not included.
const ATTACKER_FIELDS: &[&str] = &[
    "github.head_ref",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.pull_request.head.repo.description",
    "github.event.pull_request.head.repo.homepage",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.commits.*.committer.email",
    "github.event.commits.*.committer.name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.head_commit.committer.email",
    "github.event.head_commit.committer.name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
    "github.event.workflow_run.head_repository.description",
    "github.event.workflow_run.pull_requests.*.head.ref",
    "github.event.release.name",
    "github.event.release.body",
    "github.event.release.tag_name",
];

#[derive(Debug, PartialEq, Eq)]
enum Reach {
    /// The path is (inside) an attacker-controlled field.
    Field,
    /// The path is an object that contains one (matters when serialized).
    Container,
    None,
}

fn reach(path: &[Seg]) -> Reach {
    let mut best = Reach::None;
    for field in ATTACKER_FIELDS {
        let pattern: Vec<&str> = field.split('.').collect();
        let common = path.len().min(pattern.len());
        let agrees = (0..common).all(|i| match (&path[i], pattern[i]) {
            (_, "*") | (Seg::Any, _) => true,
            (Seg::Name(n), p) => n == p,
        });
        if !agrees {
            continue;
        }
        if path.len() >= pattern.len() {
            return Reach::Field;
        }
        best = Reach::Container;
    }
    best
}

pub fn display(path: &[Seg]) -> String {
    path.iter()
        .map(|s| match s {
            Seg::Name(n) => n.as_str(),
            Seg::Any => "*",
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Where untrusted values can come from besides the event payload.
#[derive(Debug, Default, Clone)]
pub struct Scope {
    /// Environment variables (lowercased names) whose value is attacker-controlled,
    /// mapped to the field they come from.
    pub env: HashMap<String, String>,
    /// Treat `inputs.*` as untrusted: reusable workflows and composite actions get
    /// them from a caller that may pass attacker-controlled text.
    pub inputs: bool,
    /// Every environment variable's definition (lowercased name), tainted or not.
    pub raw: HashMap<String, String>,
}

/// The kind of untrusted value an expression can produce.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Taint {
    /// Set directly by an outsider (`github.event.issue.title`, or an env var holding it).
    Attacker(String),
    /// A reusable workflow's or composite action's input.
    Input(String),
}

/// Whether the string value of `expr` can carry attacker-chosen text.
pub fn taint(expr: &Expr, scope: &Scope) -> Option<Taint> {
    match expr {
        Expr::Literal | Expr::Boolean => None,
        Expr::Path(path) => path_taint(path, scope, false),
        Expr::Deref(inner) => taint(inner, scope),
        // `a && b` yields `b` when `a` is truthy, else the falsy (harmless) `a`.
        Expr::And(_, b) => taint(b, scope),
        Expr::Or(a, b) => taint(a, scope).or_else(|| taint(b, scope)),
        Expr::Call(name, args) => match name.as_str() {
            "contains" | "startswith" | "endswith" | "success" | "failure" | "always"
            | "cancelled" | "hashfiles" => None,
            "tojson" => args.iter().find_map(|a| match a {
                Expr::Path(path) => path_taint(path, scope, true),
                other => taint(other, scope),
            }),
            _ => args.iter().find_map(|a| taint(a, scope)),
        },
    }
}

fn path_taint(path: &[Seg], scope: &Scope, serialized: bool) -> Option<Taint> {
    match reach(path) {
        Reach::Field => return Some(Taint::Attacker(display(path))),
        Reach::Container if serialized => return Some(Taint::Attacker(display(path))),
        _ => {}
    }
    match path {
        [Seg::Name(ctx), Seg::Name(var), ..] if ctx == "env" => scope
            .env
            .get(var)
            .map(|from| Taint::Attacker(format!("env.{var} (from {from})"))),
        [Seg::Name(ctx), rest @ ..] if ctx == "inputs" && scope.inputs && !rest.is_empty() => {
            Some(Taint::Input(display(path)))
        }
        _ => None,
    }
}

/// Whether the expression serializes the whole `secrets` context.
pub fn serializes_secrets(expr: &Expr) -> bool {
    match expr {
        Expr::Call(name, args) => {
            (name == "tojson"
                && args
                    .iter()
                    .any(|a| matches!(a, Expr::Path(p) if p == &[Seg::Name("secrets".into())])))
                || args.iter().any(serializes_secrets)
        }
        Expr::And(a, b) | Expr::Or(a, b) => serializes_secrets(a) || serializes_secrets(b),
        Expr::Deref(inner) => serializes_secrets(inner),
        _ => false,
    }
}

/// Parse an expression body, accepting `['name']` keys.
pub fn parse_body(body: &str) -> Option<Expr> {
    parse(&normalize_brackets(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(body: &str) -> Option<Taint> {
        taint(&parse_body(body).expect(body), &Scope::default())
    }

    fn attacker(path: &str) -> Option<Taint> {
        Some(Taint::Attacker(path.into()))
    }

    #[test]
    fn extraction_respects_quotes() {
        let s = "echo ${{ format('{0}}}', github.head_ref) }} and ${{ x }}";
        let e = embedded(s);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].body, " format('{0}}}', github.head_ref) ");
        assert_eq!(e[1].text, "${{ x }}");
        assert_eq!(&s[e[1].start..e[1].start + 3], "${{");
        assert!(embedded("${{ unterminated").is_empty());
    }

    #[test]
    fn attacker_fields_in_any_spelling() {
        assert_eq!(
            t("github.event.issue.title"),
            attacker("github.event.issue.title")
        );
        assert_eq!(
            t("GitHub.Event.Issue.Title"),
            attacker("github.event.issue.title")
        );
        assert_eq!(
            t("github.event['issue']['body']"),
            attacker("github.event.issue.body")
        );
        assert_eq!(
            t("github.event.commits[0].message"),
            attacker("github.event.commits.*.message")
        );
        assert_eq!(
            t("join(github.event.commits.*.author.name, ', ')"),
            attacker("github.event.commits.*.author.name")
        );
        assert_eq!(
            t("github.event.pull_request.title || 'untitled'"),
            attacker("github.event.pull_request.title")
        );
        assert_eq!(
            t("format('PR: {0}', github.event.pull_request.body)"),
            attacker("github.event.pull_request.body")
        );
        assert_eq!(
            t("toJSON(github.event.pull_request.head)"),
            attacker("github.event.pull_request.head")
        );
        assert_eq!(t("toJSON(github.event)"), attacker("github.event"));
        assert_eq!(
            t("github.event.workflow_run.pull_requests[0].head.ref"),
            attacker("github.event.workflow_run.pull_requests.*.head.ref")
        );
    }

    #[test]
    fn booleans_numbers_and_safe_fields_are_not_tainted() {
        for body in [
            "github.event.issue.title == 'bug'",
            "!github.event.issue.title",
            "contains(github.event.comment.body, '/deploy')",
            "startsWith(github.head_ref, 'release/')",
            "github.event.pull_request.number",
            "github.event.pull_request.head.sha",
            "github.event.issue.title && 'yes'",
            "github.event.pull_request.head",
            "'a' || 'b'",
            "true",
        ] {
            assert_eq!(t(body), None, "{body}");
        }
    }

    #[test]
    fn env_and_inputs_follow_the_scope() {
        let mut scope = Scope::default();
        scope
            .env
            .insert("title".into(), "github.event.issue.title".into());
        let e = parse_body("env.TITLE").unwrap();
        assert_eq!(
            taint(&e, &scope),
            attacker("env.title (from github.event.issue.title)")
        );
        let i = parse_body("inputs.name").unwrap();
        assert_eq!(taint(&i, &scope), None);
        scope.inputs = true;
        assert_eq!(taint(&i, &scope), Some(Taint::Input("inputs.name".into())));
    }

    #[test]
    fn secrets_serialization() {
        assert!(serializes_secrets(&parse_body("toJSON(secrets)").unwrap()));
        assert!(serializes_secrets(&parse_body("tojson(SECRETS)").unwrap()));
        assert!(!serializes_secrets(
            &parse_body("toJSON(secrets.TOKEN)").unwrap()
        ));
        assert!(!serializes_secrets(&parse_body("secrets.TOKEN").unwrap()));
    }

    #[test]
    fn invalid_syntax_is_rejected_not_misread() {
        assert!(parse_body("github.event.issue.title +").is_none());
        assert!(parse_body("a ~ b").is_none());
        assert!(parse_body(&"(".repeat(200)).is_none());
        assert_eq!(
            parse_body(&format!("{}x", "!".repeat(100_000))),
            Some(Expr::Boolean)
        );
    }
}
