//! A YAML tree that keeps source positions, built from saphyr-parser's event stream.
//!
//! Workflow findings need exact lines, and workflow files may come from a hostile
//! repository. Anchored nodes are shared, not copied, when an alias refers to them,
//! and the tree's logical size (an aliased subtree counts each time it is used) is
//! capped, so an "alias bomb" is refused instead of exhausting memory. The parser
//! itself rejects pathological nesting.
//!
//! Scalars are kept as strings (YAML 1.2: `on` is the string "on", not `true`).

use saphyr_parser::{Event, Parser, Span};
use std::collections::HashMap;
use std::rc::Rc;

/// Logical nodes allowed in one document. Real workflows have a few thousand.
pub const MAX_NODES: usize = 100_000;

#[derive(Debug)]
pub enum Error {
    /// Not valid YAML (or nested deeper than the parser allows).
    Syntax(String),
    /// More than [`MAX_NODES`] nodes once aliases are expanded.
    TooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Syntax(e) => write!(f, "invalid YAML: {e}"),
            Error::TooLarge => write!(
                f,
                "more than {MAX_NODES} YAML nodes once aliases are expanded"
            ),
        }
    }
}

#[derive(Debug)]
pub enum Kind {
    Scalar(String),
    Seq(Vec<Rc<Node>>),
    Map(Vec<(Rc<Node>, Rc<Node>)>),
}

#[derive(Debug)]
pub struct Node {
    pub kind: Kind,
    /// 1-based line of the node's first character.
    pub line: usize,
    /// 0-based character column of the node's first character.
    pub col: usize,
    /// Where the node ends (exclusive), same units.
    pub end_line: usize,
    pub end_col: usize,
    /// Nodes in this subtree, counting aliased subtrees each time they are used.
    size: usize,
}

impl Node {
    pub fn as_str(&self) -> Option<&str> {
        match &self.kind {
            Kind::Scalar(value) => Some(value),
            _ => None,
        }
    }

    /// Value of `key` in a mapping.
    pub fn get(&self, key: &str) -> Option<&Node> {
        self.entries()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
    }

    /// Key/value pairs of a mapping (nothing for other nodes).
    pub fn entries(&self) -> impl Iterator<Item = (&Node, &Node)> {
        let entries: &[(Rc<Node>, Rc<Node>)] = match &self.kind {
            Kind::Map(m) => m,
            _ => &[],
        };
        entries.iter().map(|(k, v)| (k.as_ref(), v.as_ref()))
    }

    /// Items of a sequence (nothing for other nodes).
    pub fn items(&self) -> impl Iterator<Item = &Node> {
        let items: &[Rc<Node>] = match &self.kind {
            Kind::Seq(s) => s,
            _ => &[],
        };
        items.iter().map(Rc::as_ref)
    }

    pub fn is_map(&self) -> bool {
        matches!(self.kind, Kind::Map(_))
    }

    /// Every scalar value in the subtree (mapping keys excluded), in document order.
    pub fn scalars<'a>(&'a self, out: &mut Vec<&'a Node>) {
        match &self.kind {
            Kind::Scalar(_) => out.push(self),
            Kind::Seq(items) => items.iter().for_each(|n| n.scalars(out)),
            Kind::Map(entries) => entries.iter().for_each(|(_, v)| v.scalars(out)),
        }
    }
}

enum Frame {
    Seq {
        span: Span,
        anchor: usize,
        items: Vec<Rc<Node>>,
        size: usize,
    },
    Map {
        span: Span,
        anchor: usize,
        entries: Vec<(Rc<Node>, Rc<Node>)>,
        key: Option<Rc<Node>>,
        size: usize,
    },
}

/// Parse the first document of `text`. `Ok(None)` for an empty file.
pub fn parse(text: &str) -> Result<Option<Rc<Node>>, Error> {
    let mut anchors: HashMap<usize, Rc<Node>> = HashMap::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Rc<Node>> = None;

    for event in Parser::new_from_str(text) {
        let (event, span) = event.map_err(|e| Error::Syntax(e.to_string()))?;
        let node = match event {
            Event::Scalar(value, _, anchor, _) => {
                let node = Rc::new(Node {
                    kind: Kind::Scalar(value.into_owned()),
                    line: span.start.line(),
                    col: span.start.col(),
                    end_line: span.end.line(),
                    end_col: span.end.col(),
                    size: 1,
                });
                remember(&mut anchors, anchor, &node);
                node
            }
            Event::Alias(id) => anchors
                .get(&id)
                .cloned()
                .ok_or_else(|| Error::Syntax("alias to an unknown anchor".into()))?,
            Event::SequenceStart(anchor, _) => {
                stack.push(Frame::Seq {
                    span,
                    anchor,
                    items: Vec::new(),
                    size: 1,
                });
                continue;
            }
            Event::MappingStart(anchor, _) => {
                stack.push(Frame::Map {
                    span,
                    anchor,
                    entries: Vec::new(),
                    key: None,
                    size: 1,
                });
                continue;
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let (start, anchor, kind, size) = match stack.pop() {
                    Some(Frame::Seq {
                        span,
                        anchor,
                        items,
                        size,
                    }) => (span, anchor, Kind::Seq(items), size),
                    Some(Frame::Map {
                        span,
                        anchor,
                        entries,
                        size,
                        ..
                    }) => (span, anchor, Kind::Map(entries), size),
                    None => return Err(Error::Syntax("unbalanced collection".into())),
                };
                let node = Rc::new(Node {
                    kind,
                    line: start.start.line(),
                    col: start.start.col(),
                    end_line: span.end.line(),
                    end_col: span.end.col(),
                    size,
                });
                remember(&mut anchors, anchor, &node);
                node
            }
            Event::DocumentEnd if root.is_some() => break,
            _ => continue,
        };
        attach(&mut stack, &mut root, node)?;
    }
    Ok(root)
}

fn remember(anchors: &mut HashMap<usize, Rc<Node>>, anchor: usize, node: &Rc<Node>) {
    if anchor > 0 {
        anchors.insert(anchor, Rc::clone(node));
    }
}

fn attach(stack: &mut [Frame], root: &mut Option<Rc<Node>>, node: Rc<Node>) -> Result<(), Error> {
    let added = node.size;
    let size = match stack.last_mut() {
        None => {
            root.get_or_insert(node);
            return Ok(());
        }
        Some(Frame::Seq { items, size, .. }) => {
            items.push(node);
            size
        }
        Some(Frame::Map {
            entries, key, size, ..
        }) => {
            match key.take() {
                Some(k) => entries.push((k, node)),
                None => *key = Some(node),
            }
            size
        }
    };
    *size = size.saturating_add(added);
    if *size > MAX_NODES {
        return Err(Error::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_and_lookup() {
        let doc = parse("on: push\njobs:\n  build:\n    steps:\n      - run: |\n          make\n")
            .unwrap()
            .unwrap();
        assert_eq!(doc.get("on").unwrap().as_str(), Some("push"));
        let step = doc
            .get("jobs")
            .and_then(|j| j.get("build"))
            .and_then(|b| b.get("steps"))
            .and_then(|s| s.items().next())
            .unwrap();
        let run = step.get("run").unwrap();
        assert_eq!(run.as_str(), Some("make\n"));
        // A block scalar starts at its first content line.
        assert_eq!((run.line, run.col), (6, 10));
        let (key, _) = doc.entries().nth(1).unwrap();
        assert_eq!((key.as_str(), key.line, key.col), (Some("jobs"), 2, 0));
    }

    #[test]
    fn aliases_are_shared_and_merged_into_place() {
        let doc = parse("a: &x {k: v}\nb: *x\n").unwrap().unwrap();
        assert_eq!(
            doc.get("b").and_then(|b| b.get("k")).and_then(Node::as_str),
            Some("v")
        );
    }

    #[test]
    fn alias_bombs_are_refused() {
        let mut yaml = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            let refs = vec![format!("*a{}", i - 1); 10].join(", ");
            yaml.push_str(&format!("a{i}: &a{i} [{refs}]\n"));
        }
        assert!(matches!(parse(&yaml), Err(Error::TooLarge)));
    }

    #[test]
    fn syntax_errors_and_empty_files() {
        assert!(matches!(parse("on: [push\njobs: {"), Err(Error::Syntax(_))));
        assert!(matches!(parse(&"[".repeat(100_000)), Err(Error::Syntax(_))));
        assert!(parse("").unwrap().is_none());
        assert!(parse("# only a comment\n").unwrap().is_none());
    }
}
