//! Local taint analysis using tree-sitter-graph.
//!
//! This module provides intra-procedural taint tracking to reduce false positives
//! in SAST analysis. It constructs a data flow graph from the AST and traces
//! taint propagation from sources to sinks.

use crate::error::Result;
use crate::models::Language;
use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Node;
use tracing::{debug, trace};

/// Represents a taint source (where untrusted data enters).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintSource {
    /// Identifier or pattern that marks a source.
    pub pattern: String,
    /// Source category (e.g., "user_input", "network", "file").
    pub category: TaintCategory,
    /// The byte range in source code.
    pub byte_range: (usize, usize),
    /// Variable name if applicable.
    pub variable: Option<String>,
}

/// Represents a taint sink (where tainted data causes vulnerabilities).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintSink {
    /// Function or pattern that marks a sink.
    pub pattern: String,
    /// Sink category (e.g., "sql_query", "command_exec", "file_write").
    pub category: SinkCategory,
    /// The byte range in source code.
    pub byte_range: (usize, usize),
    /// Which argument index is sensitive (0-indexed).
    pub sensitive_arg: usize,
}

/// Represents a sanitizer (where taint is removed).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sanitizer {
    /// Function or pattern that sanitizes data.
    pub pattern: String,
    /// What kind of taint it removes.
    pub removes: Vec<TaintCategory>,
    /// The byte range in source code.
    pub byte_range: (usize, usize),
}

/// Categories of taint sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintCategory {
    /// User input from web requests, CLI args, etc.
    UserInput,
    /// Data from network sources.
    Network,
    /// Data from file system.
    FileSystem,
    /// Data from environment variables.
    Environment,
    /// Data from database queries.
    Database,
    /// Generic untrusted data.
    Untrusted,
}

/// Categories of taint sinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkCategory {
    /// SQL query execution.
    SqlQuery,
    /// Command/shell execution.
    CommandExec,
    /// File path operations.
    FilePath,
    /// HTML/template rendering (XSS).
    HtmlOutput,
    /// Code evaluation (eval, exec).
    CodeEval,
    /// Deserialization operations.
    Deserialization,
    /// Log injection.
    LogOutput,
    /// LDAP queries.
    LdapQuery,
    /// XPath queries.
    XPathQuery,
}

/// A node in the taint flow graph.
#[derive(Debug, Clone)]
pub struct TaintNode {
    /// Unique identifier for this node.
    pub id: usize,
    /// The kind of node (variable, call, etc.).
    pub kind: TaintNodeKind,
    /// Variable name if this represents a variable.
    pub name: Option<String>,
    /// Byte range in source.
    pub byte_range: (usize, usize),
    /// Line number (1-indexed).
    pub line: usize,
    /// Current taint status.
    pub tainted: HashSet<TaintCategory>,
}

/// The kind of taint node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintNodeKind {
    /// A variable definition or reference.
    Variable,
    /// A function/method call.
    Call,
    /// A binary operation (concatenation, etc.).
    BinaryOp,
    /// A parameter definition.
    Parameter,
    /// A return statement.
    Return,
    /// A literal value (safe).
    Literal,
    /// An assignment target.
    Assignment,
}

/// An edge in the taint flow graph representing data flow.
#[derive(Debug, Clone)]
pub struct TaintEdge {
    /// Source node ID.
    pub from: usize,
    /// Target node ID.
    pub to: usize,
    /// Edge type.
    pub kind: TaintEdgeKind,
}

/// The kind of taint edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintEdgeKind {
    /// Direct assignment (x = y).
    Assignment,
    /// Argument passing.
    Argument,
    /// Return value.
    Return,
    /// Data flows through an operation.
    DataFlow,
    /// Implicit flow (control dependence).
    ImplicitFlow,
}

/// The local taint flow graph for a single function/method.
#[derive(Debug, Default)]
pub struct TaintGraph {
    /// All nodes in the graph.
    nodes: Vec<TaintNode>,
    /// All edges in the graph.
    edges: Vec<TaintEdge>,
    /// Map from byte position to node ID for quick lookups.
    position_to_node: HashMap<usize, usize>,
    /// Map from variable name to node IDs.
    variable_nodes: HashMap<String, Vec<usize>>,
}

impl TaintGraph {
    /// Create a new empty taint graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, node: TaintNode) -> usize {
        let id = self.nodes.len();
        self.position_to_node.insert(node.byte_range.0, id);
        if let Some(ref name) = node.name {
            self.variable_nodes
                .entry(name.clone())
                .or_default()
                .push(id);
        }
        self.nodes.push(TaintNode { id, ..node });
        id
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, edge: TaintEdge) {
        self.edges.push(edge);
    }

    /// Get a node by ID.
    pub fn get_node(&self, id: usize) -> Option<&TaintNode> {
        self.nodes.get(id)
    }

    /// Get a mutable node by ID.
    pub fn get_node_mut(&mut self, id: usize) -> Option<&mut TaintNode> {
        self.nodes.get_mut(id)
    }

    /// Find nodes by variable name.
    pub fn find_by_name(&self, name: &str) -> Vec<&TaintNode> {
        self.variable_nodes
            .get(name)
            .map(|ids| ids.iter().filter_map(|&id| self.nodes.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all edges from a node.
    pub fn edges_from(&self, node_id: usize) -> Vec<&TaintEdge> {
        self.edges.iter().filter(|e| e.from == node_id).collect()
    }

    /// Get all edges to a node.
    pub fn edges_to(&self, node_id: usize) -> Vec<&TaintEdge> {
        self.edges.iter().filter(|e| e.to == node_id).collect()
    }

    /// Propagate taint through the graph using a worklist algorithm.
    pub fn propagate_taint(&mut self, sources: &[TaintSource], sanitizers: &[Sanitizer]) {
        // Initialize taint from sources
        for source in sources {
            if let Some(&node_id) = self.position_to_node.get(&source.byte_range.0) {
                if let Some(node) = self.nodes.get_mut(node_id) {
                    node.tainted.insert(source.category);
                    trace!("Initialized taint at node {} from source {:?}", node_id, source.pattern);
                }
            }
            // Also check by variable name
            if let Some(ref var) = source.variable {
                if let Some(ids) = self.variable_nodes.get(var) {
                    for &id in ids {
                        if let Some(node) = self.nodes.get_mut(id) {
                            node.tainted.insert(source.category);
                        }
                    }
                }
            }
        }

        // Build sanitizer position set
        let sanitizer_positions: HashSet<usize> = sanitizers
            .iter()
            .map(|s| s.byte_range.0)
            .collect();

        // Worklist algorithm for taint propagation
        let mut worklist: VecDeque<usize> = self
            .nodes
            .iter()
            .filter(|n| !n.tainted.is_empty())
            .map(|n| n.id)
            .collect();

        let mut visited: HashSet<usize> = HashSet::new();

        while let Some(node_id) = worklist.pop_front() {
            if visited.contains(&node_id) {
                continue;
            }
            visited.insert(node_id);

            let current_taint: HashSet<TaintCategory> = self
                .nodes
                .get(node_id)
                .map(|n| n.tainted.clone())
                .unwrap_or_default();

            if current_taint.is_empty() {
                continue;
            }

            // Propagate to successors
            let outgoing: Vec<usize> = self
                .edges
                .iter()
                .filter(|e| e.from == node_id)
                .map(|e| e.to)
                .collect();

            for target_id in outgoing {
                // Check if target is sanitized
                if let Some(target) = self.nodes.get(target_id) {
                    if sanitizer_positions.contains(&target.byte_range.0) {
                        // Find which sanitizer and what it removes
                        for sanitizer in sanitizers {
                            if sanitizer.byte_range.0 == target.byte_range.0 {
                                let remaining: HashSet<TaintCategory> = current_taint
                                    .iter()
                                    .filter(|t| !sanitizer.removes.contains(t))
                                    .copied()
                                    .collect();
                                if !remaining.is_empty() {
                                    if let Some(target_node) = self.nodes.get_mut(target_id) {
                                        let old_len = target_node.tainted.len();
                                        target_node.tainted.extend(remaining);
                                        if target_node.tainted.len() > old_len {
                                            worklist.push_back(target_id);
                                        }
                                    }
                                }
                                break;
                            }
                        }
                        continue;
                    }
                }

                // Normal propagation
                if let Some(target_node) = self.nodes.get_mut(target_id) {
                    let old_len = target_node.tainted.len();
                    target_node.tainted.extend(current_taint.iter());
                    if target_node.tainted.len() > old_len {
                        worklist.push_back(target_id);
                    }
                }
            }
        }
    }

    /// Check if a sink receives tainted data.
    pub fn check_sink(&self, sink: &TaintSink) -> Option<Vec<TaintCategory>> {
        // Find the node at the sink position
        if let Some(&node_id) = self.position_to_node.get(&sink.byte_range.0) {
            if let Some(node) = self.nodes.get(node_id) {
                if !node.tainted.is_empty() {
                    return Some(node.tainted.iter().copied().collect());
                }
            }
        }

        // Also check edges going into the sink position
        for edge in &self.edges {
            if let Some(target) = self.nodes.get(edge.to) {
                if target.byte_range.0 >= sink.byte_range.0
                    && target.byte_range.1 <= sink.byte_range.1
                    && !target.tainted.is_empty()
                {
                    return Some(target.tainted.iter().copied().collect());
                }
            }
        }

        None
    }

    /// Get all tainted nodes.
    pub fn tainted_nodes(&self) -> Vec<&TaintNode> {
        self.nodes.iter().filter(|n| !n.tainted.is_empty()).collect()
    }
}

/// Builder for constructing taint graphs from tree-sitter ASTs.
pub struct TaintGraphBuilder {
    /// The language being analyzed.
    language: Language,
    /// Known source patterns for this language.
    source_patterns: Vec<SourcePattern>,
    /// Known sink patterns for this language.
    sink_patterns: Vec<SinkPattern>,
    /// Known sanitizer patterns for this language.
    sanitizer_patterns: Vec<SanitizerPattern>,
}

/// A pattern for identifying taint sources.
#[derive(Debug, Clone)]
pub struct SourcePattern {
    /// Function names or patterns that introduce taint.
    pub functions: Vec<String>,
    /// Parameter positions that are tainted (for callbacks).
    pub tainted_params: Vec<usize>,
    /// The category of taint introduced.
    pub category: TaintCategory,
}

/// A pattern for identifying taint sinks.
#[derive(Debug, Clone)]
pub struct SinkPattern {
    /// Function names that are sinks.
    pub functions: Vec<String>,
    /// Which argument positions are sensitive.
    pub sensitive_args: Vec<usize>,
    /// The category of sink.
    pub category: SinkCategory,
}

/// A pattern for identifying sanitizers.
#[derive(Debug, Clone)]
pub struct SanitizerPattern {
    /// Function names that sanitize.
    pub functions: Vec<String>,
    /// What categories they sanitize.
    pub sanitizes: Vec<TaintCategory>,
}

impl TaintGraphBuilder {
    /// Create a new builder for the given language.
    pub fn new(language: Language) -> Self {
        let (source_patterns, sink_patterns, sanitizer_patterns) = match language {
            Language::Python => Self::python_patterns(),
            Language::JavaScript | Language::TypeScript => Self::javascript_patterns(),
            Language::Rust => Self::rust_patterns(),
            Language::Go => Self::go_patterns(),
            _ => (vec![], vec![], vec![]),
        };

        Self {
            language,
            source_patterns,
            sink_patterns,
            sanitizer_patterns,
        }
    }

    /// Define Python-specific taint patterns.
    fn python_patterns() -> (Vec<SourcePattern>, Vec<SinkPattern>, Vec<SanitizerPattern>) {
        let sources = vec![
            SourcePattern {
                functions: vec![
                    "input".into(),
                    "raw_input".into(),
                    "request.GET.get".into(),
                    "request.POST.get".into(),
                    "request.args.get".into(),
                    "request.form.get".into(),
                    "request.values.get".into(),
                    "request.json".into(),
                    "request.data".into(),
                    "sys.argv".into(),
                    "os.environ.get".into(),
                    "os.getenv".into(),
                ],
                tainted_params: vec![],
                category: TaintCategory::UserInput,
            },
            SourcePattern {
                functions: vec![
                    "open".into(),
                    "read".into(),
                    "readlines".into(),
                    "readline".into(),
                ],
                tainted_params: vec![],
                category: TaintCategory::FileSystem,
            },
        ];

        let sinks = vec![
            SinkPattern {
                functions: vec![
                    "execute".into(),
                    "executemany".into(),
                    "executescript".into(),
                    "raw".into(),
                    "cursor.execute".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::SqlQuery,
            },
            SinkPattern {
                functions: vec![
                    "eval".into(),
                    "exec".into(),
                    "compile".into(),
                    "execfile".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::CodeEval,
            },
            SinkPattern {
                functions: vec![
                    "os.system".into(),
                    "os.popen".into(),
                    "subprocess.call".into(),
                    "subprocess.run".into(),
                    "subprocess.Popen".into(),
                    "commands.getoutput".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::CommandExec,
            },
            SinkPattern {
                functions: vec![
                    "render_template_string".into(),
                    "Markup".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::HtmlOutput,
            },
            SinkPattern {
                functions: vec![
                    "open".into(),
                    "os.path.join".into(),
                    "pathlib.Path".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::FilePath,
            },
        ];

        let sanitizers = vec![
            SanitizerPattern {
                functions: vec![
                    "escape".into(),
                    "html.escape".into(),
                    "markupsafe.escape".into(),
                    "cgi.escape".into(),
                    "bleach.clean".into(),
                ],
                sanitizes: vec![TaintCategory::UserInput],
            },
            SanitizerPattern {
                functions: vec![
                    "int".into(),
                    "float".into(),
                    "bool".into(),
                ],
                sanitizes: vec![TaintCategory::UserInput, TaintCategory::Network],
            },
            SanitizerPattern {
                functions: vec![
                    "shlex.quote".into(),
                    "pipes.quote".into(),
                ],
                sanitizes: vec![TaintCategory::UserInput],
            },
        ];

        (sources, sinks, sanitizers)
    }

    /// Define JavaScript-specific taint patterns.
    fn javascript_patterns() -> (Vec<SourcePattern>, Vec<SinkPattern>, Vec<SanitizerPattern>) {
        let sources = vec![
            SourcePattern {
                functions: vec![
                    "req.query".into(),
                    "req.body".into(),
                    "req.params".into(),
                    "req.headers".into(),
                    "process.argv".into(),
                    "process.env".into(),
                    "document.location".into(),
                    "window.location".into(),
                    "location.search".into(),
                    "location.hash".into(),
                    "document.URL".into(),
                    "document.referrer".into(),
                    "document.cookie".into(),
                ],
                tainted_params: vec![],
                category: TaintCategory::UserInput,
            },
        ];

        let sinks = vec![
            SinkPattern {
                functions: vec![
                    "eval".into(),
                    "Function".into(),
                    "setTimeout".into(),
                    "setInterval".into(),
                    "setImmediate".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::CodeEval,
            },
            SinkPattern {
                functions: vec![
                    "innerHTML".into(),
                    "outerHTML".into(),
                    "document.write".into(),
                    "document.writeln".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::HtmlOutput,
            },
            SinkPattern {
                functions: vec![
                    "exec".into(),
                    "execSync".into(),
                    "spawn".into(),
                    "spawnSync".into(),
                    "execFile".into(),
                    "execFileSync".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::CommandExec,
            },
            SinkPattern {
                functions: vec![
                    "query".into(),
                    "execute".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::SqlQuery,
            },
        ];

        let sanitizers = vec![
            SanitizerPattern {
                functions: vec![
                    "encodeURIComponent".into(),
                    "encodeURI".into(),
                    "escape".into(),
                    "sanitizeHtml".into(),
                    "DOMPurify.sanitize".into(),
                ],
                sanitizes: vec![TaintCategory::UserInput],
            },
            SanitizerPattern {
                functions: vec![
                    "parseInt".into(),
                    "parseFloat".into(),
                    "Number".into(),
                ],
                sanitizes: vec![TaintCategory::UserInput, TaintCategory::Network],
            },
        ];

        (sources, sinks, sanitizers)
    }

    /// Define Rust-specific taint patterns.
    fn rust_patterns() -> (Vec<SourcePattern>, Vec<SinkPattern>, Vec<SanitizerPattern>) {
        let sources = vec![
            SourcePattern {
                functions: vec![
                    "std::env::args".into(),
                    "std::env::var".into(),
                    "std::env::vars".into(),
                    "std::io::stdin".into(),
                    "read_line".into(),
                ],
                tainted_params: vec![],
                category: TaintCategory::UserInput,
            },
            SourcePattern {
                functions: vec![
                    "std::fs::read".into(),
                    "std::fs::read_to_string".into(),
                    "tokio::fs::read".into(),
                ],
                tainted_params: vec![],
                category: TaintCategory::FileSystem,
            },
        ];

        let sinks = vec![
            SinkPattern {
                functions: vec![
                    "std::process::Command::new".into(),
                    "Command::new".into(),
                    "tokio::process::Command::new".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::CommandExec,
            },
            SinkPattern {
                functions: vec![
                    "sqlx::query".into(),
                    "diesel::sql_query".into(),
                    "rusqlite::Connection::execute".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::SqlQuery,
            },
            SinkPattern {
                functions: vec![
                    "std::fs::write".into(),
                    "std::fs::create_dir".into(),
                    "std::fs::remove_file".into(),
                    "std::path::Path::new".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::FilePath,
            },
        ];

        let sanitizers = vec![
            SanitizerPattern {
                functions: vec![
                    "html_escape::encode_text".into(),
                    "askama::MarkupDisplay".into(),
                ],
                sanitizes: vec![TaintCategory::UserInput],
            },
            SanitizerPattern {
                functions: vec![
                    "parse".into(),
                    "from_str".into(),
                ],
                sanitizes: vec![TaintCategory::UserInput],
            },
        ];

        (sources, sinks, sanitizers)
    }

    /// Define Go-specific taint patterns.
    fn go_patterns() -> (Vec<SourcePattern>, Vec<SinkPattern>, Vec<SanitizerPattern>) {
        let sources = vec![
            SourcePattern {
                functions: vec![
                    "http.Request.FormValue".into(),
                    "http.Request.URL.Query".into(),
                    "http.Request.Body".into(),
                    "http.Request.Header.Get".into(),
                    "os.Args".into(),
                    "os.Getenv".into(),
                    "flag.String".into(),
                    "flag.Arg".into(),
                    "bufio.NewReader".into(),
                    "bufio.NewScanner".into(),
                ],
                tainted_params: vec![],
                category: TaintCategory::UserInput,
            },
        ];

        let sinks = vec![
            SinkPattern {
                functions: vec![
                    "exec.Command".into(),
                    "os/exec.Command".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::CommandExec,
            },
            SinkPattern {
                functions: vec![
                    "db.Query".into(),
                    "db.Exec".into(),
                    "db.QueryRow".into(),
                    "sql.DB.Query".into(),
                    "sql.DB.Exec".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::SqlQuery,
            },
            SinkPattern {
                functions: vec![
                    "template.HTML".into(),
                    "http.ResponseWriter.Write".into(),
                    "fmt.Fprintf".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::HtmlOutput,
            },
            SinkPattern {
                functions: vec![
                    "os.Open".into(),
                    "os.Create".into(),
                    "ioutil.ReadFile".into(),
                    "ioutil.WriteFile".into(),
                    "filepath.Join".into(),
                ],
                sensitive_args: vec![0],
                category: SinkCategory::FilePath,
            },
        ];

        let sanitizers = vec![
            SanitizerPattern {
                functions: vec![
                    "html.EscapeString".into(),
                    "template.HTMLEscapeString".into(),
                    "url.QueryEscape".into(),
                    "url.PathEscape".into(),
                ],
                sanitizes: vec![TaintCategory::UserInput],
            },
            SanitizerPattern {
                functions: vec![
                    "strconv.Atoi".into(),
                    "strconv.ParseInt".into(),
                    "strconv.ParseFloat".into(),
                ],
                sanitizes: vec![TaintCategory::UserInput, TaintCategory::Network],
            },
        ];

        (sources, sinks, sanitizers)
    }

    /// Build a taint graph from a parsed tree-sitter tree.
    pub fn build_graph(
        &self,
        tree: &tree_sitter::Tree,
        source_code: &str,
    ) -> Result<(TaintGraph, Vec<TaintSource>, Vec<TaintSink>, Vec<Sanitizer>)> {
        let mut graph = TaintGraph::new();
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // Walk the tree and build nodes
        self.walk_node(
            tree.root_node(),
            source_code,
            &mut graph,
            &mut sources,
            &mut sinks,
            &mut sanitizers,
        )?;

        Ok((graph, sources, sinks, sanitizers))
    }

    /// Recursively walk tree nodes and build the taint graph.
    fn walk_node(
        &self,
        node: Node,
        source_code: &str,
        graph: &mut TaintGraph,
        sources: &mut Vec<TaintSource>,
        sinks: &mut Vec<TaintSink>,
        sanitizers: &mut Vec<Sanitizer>,
    ) -> Result<Option<usize>> {
        let kind = node.kind();
        let byte_range = (node.start_byte(), node.end_byte());
        let line = node.start_position().row + 1;

        let node_text = node
            .utf8_text(source_code.as_bytes())
            .unwrap_or("")
            .to_string();

        let node_id = match kind {
            // Variable declarations and references
            "identifier" | "variable_name" | "name" => {
                let id = graph.add_node(TaintNode {
                    id: 0,
                    kind: TaintNodeKind::Variable,
                    name: Some(node_text.clone()),
                    byte_range,
                    line,
                    tainted: HashSet::new(),
                });
                Some(id)
            }

            // Function calls - check for sources, sinks, sanitizers
            "call" | "call_expression" | "method_call" | "function_call" => {
                let func_name = self.extract_function_name(&node, source_code);

                // Check if it's a source
                for pattern in &self.source_patterns {
                    if pattern.functions.iter().any(|f| func_name.contains(f)) {
                        sources.push(TaintSource {
                            pattern: func_name.clone(),
                            category: pattern.category,
                            byte_range,
                            variable: None,
                        });
                        debug!("Found taint source: {} at line {}", func_name, line);
                    }
                }

                // Check if it's a sink
                for pattern in &self.sink_patterns {
                    if pattern.functions.iter().any(|f| func_name.contains(f)) {
                        for &arg_idx in &pattern.sensitive_args {
                            sinks.push(TaintSink {
                                pattern: func_name.clone(),
                                category: pattern.category,
                                byte_range,
                                sensitive_arg: arg_idx,
                            });
                        }
                        debug!("Found taint sink: {} at line {}", func_name, line);
                    }
                }

                // Check if it's a sanitizer
                for pattern in &self.sanitizer_patterns {
                    if pattern.functions.iter().any(|f| func_name.contains(f)) {
                        sanitizers.push(Sanitizer {
                            pattern: func_name.clone(),
                            removes: pattern.sanitizes.clone(),
                            byte_range,
                        });
                        debug!("Found sanitizer: {} at line {}", func_name, line);
                    }
                }

                let id = graph.add_node(TaintNode {
                    id: 0,
                    kind: TaintNodeKind::Call,
                    name: Some(func_name),
                    byte_range,
                    line,
                    tainted: HashSet::new(),
                });
                Some(id)
            }

            // Assignments create data flow edges
            "assignment" | "assignment_expression" | "let_declaration" | "variable_declaration"
            | "short_var_declaration" => {
                let id = graph.add_node(TaintNode {
                    id: 0,
                    kind: TaintNodeKind::Assignment,
                    name: None,
                    byte_range,
                    line,
                    tainted: HashSet::new(),
                });

                // Process children and create edges
                let mut child_ids = Vec::new();
                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        if let Some(child_id) =
                            self.walk_node(child, source_code, graph, sources, sinks, sanitizers)?
                        {
                            child_ids.push((i, child_id));
                        }
                    }
                }

                // Create flow from RHS to LHS
                if child_ids.len() >= 2 {
                    let (_, lhs_id) = child_ids[0];
                    for &(idx, rhs_id) in &child_ids[1..] {
                        graph.add_edge(TaintEdge {
                            from: rhs_id,
                            to: lhs_id,
                            kind: TaintEdgeKind::Assignment,
                        });
                    }
                }

                Some(id)
            }

            // Binary operations propagate taint
            "binary_expression" | "binary_operator" | "concatenation" => {
                let id = graph.add_node(TaintNode {
                    id: 0,
                    kind: TaintNodeKind::BinaryOp,
                    name: None,
                    byte_range,
                    line,
                    tainted: HashSet::new(),
                });

                // Both operands flow into the result
                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        if let Some(child_id) =
                            self.walk_node(child, source_code, graph, sources, sinks, sanitizers)?
                        {
                            graph.add_edge(TaintEdge {
                                from: child_id,
                                to: id,
                                kind: TaintEdgeKind::DataFlow,
                            });
                        }
                    }
                }

                Some(id)
            }

            // String literals are safe (no taint)
            "string" | "string_literal" | "raw_string_literal" | "interpreted_string_literal" => {
                let id = graph.add_node(TaintNode {
                    id: 0,
                    kind: TaintNodeKind::Literal,
                    name: None,
                    byte_range,
                    line,
                    tainted: HashSet::new(),
                });
                Some(id)
            }

            // Parameters can be tainted
            "parameter" | "formal_parameter" | "parameter_declaration" => {
                let param_name = self.extract_param_name(&node, source_code);
                let id = graph.add_node(TaintNode {
                    id: 0,
                    kind: TaintNodeKind::Parameter,
                    name: Some(param_name),
                    byte_range,
                    line,
                    tainted: HashSet::new(),
                });
                Some(id)
            }

            // Return statements propagate taint to caller
            "return_statement" | "return_expression" => {
                let id = graph.add_node(TaintNode {
                    id: 0,
                    kind: TaintNodeKind::Return,
                    name: None,
                    byte_range,
                    line,
                    tainted: HashSet::new(),
                });

                // Process return value
                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        if let Some(child_id) =
                            self.walk_node(child, source_code, graph, sources, sinks, sanitizers)?
                        {
                            graph.add_edge(TaintEdge {
                                from: child_id,
                                to: id,
                                kind: TaintEdgeKind::Return,
                            });
                        }
                    }
                }

                Some(id)
            }

            // For other nodes, just recurse into children
            _ => {
                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        self.walk_node(child, source_code, graph, sources, sinks, sanitizers)?;
                    }
                }
                None
            }
        };

        Ok(node_id)
    }

    /// Extract function name from a call node.
    fn extract_function_name(&self, node: &Node, source_code: &str) -> String {
        // Try different child patterns based on language
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                match kind {
                    "identifier" | "property_identifier" | "field_identifier" | "attribute" => {
                        return child
                            .utf8_text(source_code.as_bytes())
                            .unwrap_or("")
                            .to_string();
                    }
                    "member_expression" | "attribute_expression" | "selector_expression" => {
                        // Get the full qualified name
                        return child
                            .utf8_text(source_code.as_bytes())
                            .unwrap_or("")
                            .to_string();
                    }
                    "function" => {
                        return child
                            .utf8_text(source_code.as_bytes())
                            .unwrap_or("")
                            .to_string();
                    }
                    _ => {}
                }
            }
        }

        // Fallback: use first named child
        node.named_child(0)
            .and_then(|c| c.utf8_text(source_code.as_bytes()).ok())
            .unwrap_or("")
            .to_string()
    }

    /// Extract parameter name from a parameter node.
    fn extract_param_name(&self, node: &Node, source_code: &str) -> String {
        for i in 0..node.named_child_count() {
            if let Some(child) = node.named_child(i) {
                if child.kind() == "identifier" || child.kind() == "name" {
                    return child
                        .utf8_text(source_code.as_bytes())
                        .unwrap_or("")
                        .to_string();
                }
            }
        }
        "unknown".to_string()
    }
}

/// Result of taint analysis.
#[derive(Debug)]
pub struct TaintAnalysisResult {
    /// Taint flows from sources to sinks.
    pub flows: Vec<TaintFlow>,
    /// Number of sources found.
    pub source_count: usize,
    /// Number of sinks found.
    pub sink_count: usize,
    /// Number of sanitizers found.
    pub sanitizer_count: usize,
}

/// A complete taint flow from source to sink.
#[derive(Debug)]
pub struct TaintFlow {
    /// The source of taint.
    pub source: TaintSource,
    /// The sink receiving tainted data.
    pub sink: TaintSink,
    /// Categories of taint that reached the sink.
    pub taint_categories: Vec<TaintCategory>,
    /// Line number of source.
    pub source_line: usize,
    /// Line number of sink.
    pub sink_line: usize,
}

/// Perform local taint analysis on a parsed file.
pub fn analyze_taint(
    language: Language,
    tree: &tree_sitter::Tree,
    source_code: &str,
) -> Result<TaintAnalysisResult> {
    let builder = TaintGraphBuilder::new(language);
    let (mut graph, sources, sinks, sanitizers) = builder.build_graph(tree, source_code)?;

    debug!(
        "Built taint graph: {} sources, {} sinks, {} sanitizers",
        sources.len(),
        sinks.len(),
        sanitizers.len()
    );

    // Propagate taint
    graph.propagate_taint(&sources, &sanitizers);

    // Check for flows to sinks
    let mut flows = Vec::new();
    for sink in &sinks {
        if let Some(categories) = graph.check_sink(sink) {
            // Find the corresponding source
            for source in &sources {
                if categories.contains(&source.category) {
                    flows.push(TaintFlow {
                        source: source.clone(),
                        sink: sink.clone(),
                        taint_categories: categories.clone(),
                        source_line: graph
                            .position_to_node
                            .get(&source.byte_range.0)
                            .and_then(|&id| graph.get_node(id))
                            .map(|n| n.line)
                            .unwrap_or(0),
                        sink_line: graph
                            .position_to_node
                            .get(&sink.byte_range.0)
                            .and_then(|&id| graph.get_node(id))
                            .map(|n| n.line)
                            .unwrap_or(0),
                    });
                }
            }
        }
    }

    debug!("Found {} taint flows", flows.len());

    Ok(TaintAnalysisResult {
        flows,
        source_count: sources.len(),
        sink_count: sinks.len(),
        sanitizer_count: sanitizers.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_taint_detection() {
        let code = r#"
user_input = input("Enter query: ")
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)
"#;

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(code, None).unwrap();

        let result = analyze_taint(Language::Python, &tree, code).unwrap();
        assert!(result.source_count > 0, "Should find input() as source");
        assert!(result.sink_count > 0, "Should find execute() as sink");
    }

    #[test]
    fn test_taint_graph_propagation() {
        let mut graph = TaintGraph::new();

        // Create source node
        let source_id = graph.add_node(TaintNode {
            id: 0,
            kind: TaintNodeKind::Variable,
            name: Some("user_input".into()),
            byte_range: (0, 10),
            line: 1,
            tainted: HashSet::new(),
        });

        // Create intermediate node
        let mid_id = graph.add_node(TaintNode {
            id: 0,
            kind: TaintNodeKind::Variable,
            name: Some("query".into()),
            byte_range: (20, 30),
            line: 2,
            tainted: HashSet::new(),
        });

        // Create sink node
        let sink_id = graph.add_node(TaintNode {
            id: 0,
            kind: TaintNodeKind::Call,
            name: Some("execute".into()),
            byte_range: (40, 50),
            line: 3,
            tainted: HashSet::new(),
        });

        // Add edges
        graph.add_edge(TaintEdge {
            from: source_id,
            to: mid_id,
            kind: TaintEdgeKind::Assignment,
        });
        graph.add_edge(TaintEdge {
            from: mid_id,
            to: sink_id,
            kind: TaintEdgeKind::Argument,
        });

        // Propagate taint
        let sources = vec![TaintSource {
            pattern: "input".into(),
            category: TaintCategory::UserInput,
            byte_range: (0, 10),
            variable: Some("user_input".into()),
        }];

        graph.propagate_taint(&sources, &[]);

        // Check that taint reached the sink
        let sink = TaintSink {
            pattern: "execute".into(),
            category: SinkCategory::SqlQuery,
            byte_range: (40, 50),
            sensitive_arg: 0,
        };

        let result = graph.check_sink(&sink);
        assert!(result.is_some(), "Taint should reach the sink");
        assert!(
            result.unwrap().contains(&TaintCategory::UserInput),
            "UserInput taint should be present"
        );
    }

    #[test]
    fn test_sanitizer_blocks_taint() {
        let mut graph = TaintGraph::new();

        // Create source -> sanitizer -> sink chain
        let source_id = graph.add_node(TaintNode {
            id: 0,
            kind: TaintNodeKind::Variable,
            name: Some("user_input".into()),
            byte_range: (0, 10),
            line: 1,
            tainted: HashSet::new(),
        });

        let sanitizer_id = graph.add_node(TaintNode {
            id: 0,
            kind: TaintNodeKind::Call,
            name: Some("escape".into()),
            byte_range: (20, 30),
            line: 2,
            tainted: HashSet::new(),
        });

        let sink_id = graph.add_node(TaintNode {
            id: 0,
            kind: TaintNodeKind::Call,
            name: Some("execute".into()),
            byte_range: (40, 50),
            line: 3,
            tainted: HashSet::new(),
        });

        graph.add_edge(TaintEdge {
            from: source_id,
            to: sanitizer_id,
            kind: TaintEdgeKind::Argument,
        });
        graph.add_edge(TaintEdge {
            from: sanitizer_id,
            to: sink_id,
            kind: TaintEdgeKind::Argument,
        });

        let sources = vec![TaintSource {
            pattern: "input".into(),
            category: TaintCategory::UserInput,
            byte_range: (0, 10),
            variable: Some("user_input".into()),
        }];

        let sanitizers = vec![Sanitizer {
            pattern: "escape".into(),
            removes: vec![TaintCategory::UserInput],
            byte_range: (20, 30),
        }];

        graph.propagate_taint(&sources, &sanitizers);

        let sink = TaintSink {
            pattern: "execute".into(),
            category: SinkCategory::SqlQuery,
            byte_range: (40, 50),
            sensitive_arg: 0,
        };

        let result = graph.check_sink(&sink);
        assert!(
            result.is_none(),
            "Sanitizer should block taint from reaching sink"
        );
    }
}
