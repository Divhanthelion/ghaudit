//! Cross-file name resolution using stack-graphs.
//!
//! This module provides inter-procedural analysis capabilities by building
//! stack-graphs that resolve names across file boundaries. This enables:
//! - Tracking data flow through function calls
//! - Resolving imported symbols to their definitions
//! - Cross-module taint propagation
//!
//! Stack-graphs were developed by GitHub for code navigation and provide
//! incremental, precise name resolution without requiring a full type system.

use crate::error::{AuditorError, Result};
use crate::models::Language;
use stack_graphs::arena::Handle;
use stack_graphs::graph::{Node, NodeID, StackGraph};
use stack_graphs::partial::PartialPaths;
use stack_graphs::stitching::{Database, ForwardPartialPathStitcher, GraphEdgeCandidates, StitcherConfig};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// A resolved reference to a symbol definition.
#[derive(Debug, Clone)]
pub struct ResolvedReference {
    /// The file where the reference occurs.
    pub reference_file: PathBuf,
    /// Line number of the reference.
    pub reference_line: usize,
    /// The symbol name being referenced.
    pub symbol: String,
    /// The file where the definition is located.
    pub definition_file: PathBuf,
    /// Line number of the definition.
    pub definition_line: usize,
    /// Kind of definition (function, class, variable, etc.).
    pub definition_kind: DefinitionKind,
}

/// The kind of symbol definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionKind {
    /// Function or method definition.
    Function,
    /// Class or struct definition.
    Class,
    /// Variable or constant.
    Variable,
    /// Module or namespace.
    Module,
    /// Import/export binding.
    Import,
    /// Unknown or other.
    Unknown,
}

/// Cross-file name resolution context.
#[derive(Debug, Clone)]
pub struct ResolutionContext {
    /// File where the query originates.
    pub file: PathBuf,
    /// Symbol being resolved.
    pub symbol: String,
    /// Line number of the reference.
    pub line: usize,
    /// Column number of the reference.
    pub column: usize,
}

/// Cross-file symbol index entry.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// File containing the symbol.
    pub file: PathBuf,
    /// Symbol name (possibly qualified).
    pub name: String,
    /// Kind of symbol.
    pub kind: DefinitionKind,
    /// Line number.
    pub line: usize,
    /// Column number.
    pub column: usize,
    /// Whether this symbol is exported.
    pub exported: bool,
}

/// Cross-file name resolver using stack-graphs.
///
/// This builds an incremental index of symbol definitions and references
/// across multiple files, enabling cross-file data flow analysis.
pub struct NameResolver {
    /// The underlying stack graph.
    graph: StackGraph,
    /// Partial paths database for incremental resolution.
    partials: PartialPaths,
    /// Database for path stitching.
    database: Database,
    /// File handles in the graph.
    file_handles: HashMap<PathBuf, Handle<stack_graphs::graph::File>>,
    /// Symbol index for fast lookups.
    symbol_index: HashMap<String, Vec<SymbolEntry>>,
    /// Languages supported.
    languages: HashSet<Language>,
}

impl Default for NameResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl NameResolver {
    /// Create a new name resolver.
    pub fn new() -> Self {
        let graph = StackGraph::new();
        let partials = PartialPaths::new();
        let database = Database::new();

        let mut languages = HashSet::new();
        languages.insert(Language::Python);
        languages.insert(Language::JavaScript);
        languages.insert(Language::Rust);
        languages.insert(Language::Go);

        Self {
            graph,
            partials,
            database,
            file_handles: HashMap::new(),
            symbol_index: HashMap::new(),
            languages,
        }
    }

    /// Check if a language is supported.
    pub fn supports_language(&self, language: Language) -> bool {
        self.languages.contains(&language)
    }

    /// Index a file's symbols into the graph.
    ///
    /// This parses the file, extracts symbol definitions and references,
    /// and adds them to the stack graph for later resolution.
    pub fn index_file(&mut self, path: &Path, content: &str, language: Language) -> Result<usize> {
        if !self.supports_language(language) {
            return Ok(0);
        }

        debug!("Indexing symbols in {}", path.display());

        // Get or create file handle
        let file_name = path
            .to_string_lossy()
            .to_string();
        let file_handle = self.graph.get_or_create_file(&file_name);
        self.file_handles.insert(path.to_path_buf(), file_handle);

        // Extract symbols based on language
        let symbols = match language {
            Language::Python => self.extract_python_symbols(path, content)?,
            Language::JavaScript | Language::TypeScript => {
                self.extract_javascript_symbols(path, content)?
            }
            Language::Rust => self.extract_rust_symbols(path, content)?,
            Language::Go => self.extract_go_symbols(path, content)?,
            _ => Vec::new(),
        };

        // Add symbols to index
        let count = symbols.len();
        for symbol in symbols {
            self.symbol_index
                .entry(symbol.name.clone())
                .or_default()
                .push(symbol);
        }

        debug!("Indexed {} symbols from {}", count, path.display());
        Ok(count)
    }

    /// Extract symbols from Python source code.
    fn extract_python_symbols(&self, path: &Path, content: &str) -> Result<Vec<SymbolEntry>> {
        let mut symbols = Vec::new();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .map_err(|e| AuditorError::Parse(format!("Failed to set Python language: {}", e)))?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| AuditorError::Parse("Failed to parse Python file".to_string()))?;

        self.walk_python_tree(path, content, tree.root_node(), &mut symbols, true);
        Ok(symbols)
    }

    /// Walk Python AST to extract symbols.
    fn walk_python_tree(
        &self,
        path: &Path,
        content: &str,
        node: tree_sitter::Node,
        symbols: &mut Vec<SymbolEntry>,
        is_top_level: bool,
    ) {
        match node.kind() {
            "function_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Function,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported: is_top_level,
                        });
                    }
                }
            }
            "class_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Class,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported: is_top_level,
                        });
                    }
                }
            }
            "import_statement" | "import_from_statement" => {
                // Track imports
                for child in node.children(&mut node.walk()) {
                    if child.kind() == "dotted_name" || child.kind() == "aliased_import" {
                        if let Ok(text) = child.utf8_text(content.as_bytes()) {
                            let name = if let Some(alias_pos) = text.find(" as ") {
                                text[alias_pos + 4..].trim().to_string()
                            } else {
                                text.split('.').last().unwrap_or(text).to_string()
                            };

                            symbols.push(SymbolEntry {
                                file: path.to_path_buf(),
                                name,
                                kind: DefinitionKind::Import,
                                line: child.start_position().row + 1,
                                column: child.start_position().column + 1,
                                exported: false,
                            });
                        }
                    }
                }
            }
            "assignment" => {
                // Track module-level variable assignments
                if is_top_level {
                    if let Some(left) = node.child_by_field_name("left") {
                        if left.kind() == "identifier" {
                            if let Ok(name) = left.utf8_text(content.as_bytes()) {
                                symbols.push(SymbolEntry {
                                    file: path.to_path_buf(),
                                    name: name.to_string(),
                                    kind: DefinitionKind::Variable,
                                    line: left.start_position().row + 1,
                                    column: left.start_position().column + 1,
                                    exported: true,
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let child_is_top_level = is_top_level && node.kind() == "module";
            self.walk_python_tree(path, content, child, symbols, child_is_top_level);
        }
    }

    /// Extract symbols from JavaScript/TypeScript source code.
    fn extract_javascript_symbols(&self, path: &Path, content: &str) -> Result<Vec<SymbolEntry>> {
        let mut symbols = Vec::new();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .map_err(|e| AuditorError::Parse(format!("Failed to set JS language: {}", e)))?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| AuditorError::Parse("Failed to parse JavaScript file".to_string()))?;

        self.walk_javascript_tree(path, content, tree.root_node(), &mut symbols, true, false);
        Ok(symbols)
    }

    /// Walk JavaScript AST to extract symbols.
    fn walk_javascript_tree(
        &self,
        path: &Path,
        content: &str,
        node: tree_sitter::Node,
        symbols: &mut Vec<SymbolEntry>,
        is_top_level: bool,
        is_exported: bool,
    ) {
        match node.kind() {
            "function_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Function,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported: is_exported || is_top_level,
                        });
                    }
                }
            }
            "class_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Class,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported: is_exported || is_top_level,
                        });
                    }
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                // Track const/let/var declarations
                for child in node.children(&mut node.walk()) {
                    if child.kind() == "variable_declarator" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if name_node.kind() == "identifier" {
                                if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                                    symbols.push(SymbolEntry {
                                        file: path.to_path_buf(),
                                        name: name.to_string(),
                                        kind: DefinitionKind::Variable,
                                        line: name_node.start_position().row + 1,
                                        column: name_node.start_position().column + 1,
                                        exported: is_exported,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            "export_statement" => {
                // Mark children as exported
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.walk_javascript_tree(path, content, child, symbols, false, true);
                }
                return;
            }
            "import_statement" => {
                // Track imports
                for child in node.children(&mut node.walk()) {
                    if child.kind() == "import_specifier" || child.kind() == "identifier" {
                        if let Ok(name) = child.utf8_text(content.as_bytes()) {
                            let name = if let Some(alias_pos) = name.find(" as ") {
                                name[alias_pos + 4..].trim().to_string()
                            } else {
                                name.to_string()
                            };

                            symbols.push(SymbolEntry {
                                file: path.to_path_buf(),
                                name,
                                kind: DefinitionKind::Import,
                                line: child.start_position().row + 1,
                                column: child.start_position().column + 1,
                                exported: false,
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let child_is_top_level = is_top_level && node.kind() == "program";
            self.walk_javascript_tree(path, content, child, symbols, child_is_top_level, false);
        }
    }

    /// Extract symbols from Rust source code.
    fn extract_rust_symbols(&self, path: &Path, content: &str) -> Result<Vec<SymbolEntry>> {
        let mut symbols = Vec::new();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .map_err(|e| AuditorError::Parse(format!("Failed to set Rust language: {}", e)))?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| AuditorError::Parse("Failed to parse Rust file".to_string()))?;

        self.walk_rust_tree(path, content, tree.root_node(), &mut symbols, true, false);
        Ok(symbols)
    }

    /// Walk Rust AST to extract symbols.
    fn walk_rust_tree(
        &self,
        path: &Path,
        content: &str,
        node: tree_sitter::Node,
        symbols: &mut Vec<SymbolEntry>,
        is_top_level: bool,
        is_pub: bool,
    ) {
        // Check for pub modifier
        let has_pub = node.children(&mut node.walk()).any(|c| {
            c.kind() == "visibility_modifier"
                && c.utf8_text(content.as_bytes())
                    .map(|t| t.starts_with("pub"))
                    .unwrap_or(false)
        });

        match node.kind() {
            "function_item" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Function,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported: has_pub || is_pub,
                        });
                    }
                }
            }
            "struct_item" | "enum_item" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Class,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported: has_pub || is_pub,
                        });
                    }
                }
            }
            "impl_item" => {
                // Track impl blocks - extract methods
                if let Some(body) = node.child_by_field_name("body") {
                    let mut cursor = body.walk();
                    for child in body.children(&mut cursor) {
                        self.walk_rust_tree(path, content, child, symbols, false, has_pub);
                    }
                }
                return;
            }
            "mod_item" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Module,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported: has_pub,
                        });
                    }
                }
            }
            "const_item" | "static_item" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Variable,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported: has_pub || is_pub,
                        });
                    }
                }
            }
            "use_declaration" => {
                // Track use imports
                for child in node.children(&mut node.walk()) {
                    if child.kind() == "use_tree" || child.kind() == "scoped_identifier" {
                        self.extract_rust_use_tree(path, content, child, symbols, has_pub);
                    }
                }
            }
            _ => {}
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let child_is_top_level = is_top_level && node.kind() == "source_file";
            self.walk_rust_tree(path, content, child, symbols, child_is_top_level, false);
        }
    }

    /// Extract symbols from Rust use trees.
    fn extract_rust_use_tree(
        &self,
        path: &Path,
        content: &str,
        node: tree_sitter::Node,
        symbols: &mut Vec<SymbolEntry>,
        is_pub: bool,
    ) {
        if let Ok(text) = node.utf8_text(content.as_bytes()) {
            // Get the final name being imported
            let name = if let Some(alias) = text.strip_suffix(" as _") {
                return; // Skip wildcard imports
            } else if let Some((_, alias)) = text.rsplit_once(" as ") {
                alias.trim().to_string()
            } else {
                text.rsplit("::").next().unwrap_or(text).to_string()
            };

            if !name.is_empty() && name != "*" && name != "{" {
                symbols.push(SymbolEntry {
                    file: path.to_path_buf(),
                    name,
                    kind: DefinitionKind::Import,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    exported: is_pub,
                });
            }
        }
    }

    /// Extract symbols from Go source code.
    fn extract_go_symbols(&self, path: &Path, content: &str) -> Result<Vec<SymbolEntry>> {
        let mut symbols = Vec::new();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .map_err(|e| AuditorError::Parse(format!("Failed to set Go language: {}", e)))?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| AuditorError::Parse("Failed to parse Go file".to_string()))?;

        self.walk_go_tree(path, content, tree.root_node(), &mut symbols);
        Ok(symbols)
    }

    /// Walk Go AST to extract symbols.
    fn walk_go_tree(
        &self,
        path: &Path,
        content: &str,
        node: tree_sitter::Node,
        symbols: &mut Vec<SymbolEntry>,
    ) {
        match node.kind() {
            "function_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        // In Go, exported symbols start with uppercase
                        let exported = name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Function,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported,
                        });
                    }
                }
            }
            "method_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                        let exported = name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
                        symbols.push(SymbolEntry {
                            file: path.to_path_buf(),
                            name: name.to_string(),
                            kind: DefinitionKind::Function,
                            line: name_node.start_position().row + 1,
                            column: name_node.start_position().column + 1,
                            exported,
                        });
                    }
                }
            }
            "type_declaration" => {
                // Handle type Foo struct {...}
                for child in node.children(&mut node.walk()) {
                    if child.kind() == "type_spec" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                                let exported =
                                    name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
                                symbols.push(SymbolEntry {
                                    file: path.to_path_buf(),
                                    name: name.to_string(),
                                    kind: DefinitionKind::Class,
                                    line: name_node.start_position().row + 1,
                                    column: name_node.start_position().column + 1,
                                    exported,
                                });
                            }
                        }
                    }
                }
            }
            "const_declaration" | "var_declaration" => {
                // Track package-level constants and variables
                for child in node.children(&mut node.walk()) {
                    if child.kind() == "const_spec" || child.kind() == "var_spec" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                                let exported =
                                    name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
                                symbols.push(SymbolEntry {
                                    file: path.to_path_buf(),
                                    name: name.to_string(),
                                    kind: DefinitionKind::Variable,
                                    line: name_node.start_position().row + 1,
                                    column: name_node.start_position().column + 1,
                                    exported,
                                });
                            }
                        }
                    }
                }
            }
            "import_declaration" => {
                for child in node.children(&mut node.walk()) {
                    if child.kind() == "import_spec" {
                        if let Some(path_node) = child.child_by_field_name("path") {
                            if let Ok(import_path) = path_node.utf8_text(content.as_bytes()) {
                                let name = import_path
                                    .trim_matches('"')
                                    .rsplit('/')
                                    .next()
                                    .unwrap_or("")
                                    .to_string();

                                if !name.is_empty() {
                                    symbols.push(SymbolEntry {
                                        file: path.to_path_buf(),
                                        name,
                                        kind: DefinitionKind::Import,
                                        line: path_node.start_position().row + 1,
                                        column: path_node.start_position().column + 1,
                                        exported: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_go_tree(path, content, child, symbols);
        }
    }

    /// Resolve a symbol reference to its definition(s).
    pub fn resolve(&self, context: &ResolutionContext) -> Vec<ResolvedReference> {
        let mut results = Vec::new();

        // First try exact match
        if let Some(entries) = self.symbol_index.get(&context.symbol) {
            for entry in entries {
                // Don't resolve to the same location
                if entry.file == context.file && entry.line == context.line {
                    continue;
                }

                // Prioritize exported definitions
                if entry.exported && entry.kind != DefinitionKind::Import {
                    results.push(ResolvedReference {
                        reference_file: context.file.clone(),
                        reference_line: context.line,
                        symbol: context.symbol.clone(),
                        definition_file: entry.file.clone(),
                        definition_line: entry.line,
                        definition_kind: entry.kind,
                    });
                }
            }
        }

        // If no exported definitions, try all definitions
        if results.is_empty() {
            if let Some(entries) = self.symbol_index.get(&context.symbol) {
                for entry in entries {
                    if entry.file == context.file && entry.line == context.line {
                        continue;
                    }

                    if entry.kind != DefinitionKind::Import {
                        results.push(ResolvedReference {
                            reference_file: context.file.clone(),
                            reference_line: context.line,
                            symbol: context.symbol.clone(),
                            definition_file: entry.file.clone(),
                            definition_line: entry.line,
                            definition_kind: entry.kind,
                        });
                    }
                }
            }
        }

        results
    }

    /// Find all references to a symbol.
    pub fn find_references(&self, symbol: &str) -> Vec<&SymbolEntry> {
        self.symbol_index
            .get(symbol)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all exported symbols.
    pub fn get_exports(&self) -> Vec<&SymbolEntry> {
        self.symbol_index
            .values()
            .flat_map(|entries| entries.iter())
            .filter(|e| e.exported && e.kind != DefinitionKind::Import)
            .collect()
    }

    /// Get all symbols in a file.
    pub fn get_file_symbols(&self, path: &Path) -> Vec<&SymbolEntry> {
        self.symbol_index
            .values()
            .flat_map(|entries| entries.iter())
            .filter(|e| e.file == path)
            .collect()
    }

    /// Get the total number of indexed symbols.
    pub fn symbol_count(&self) -> usize {
        self.symbol_index.values().map(|v| v.len()).sum()
    }

    /// Get the number of indexed files.
    pub fn file_count(&self) -> usize {
        self.file_handles.len()
    }

    /// Clear all indexed data.
    pub fn clear(&mut self) {
        self.graph = StackGraph::new();
        self.partials = PartialPaths::new();
        self.database = Database::new();
        self.file_handles.clear();
        self.symbol_index.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_symbol_extraction() {
        let mut resolver = NameResolver::new();

        let code = r#"
import os
from pathlib import Path

class MyClass:
    def method(self):
        pass

def my_function():
    pass

MY_CONSTANT = 42
"#;

        let count = resolver
            .index_file(Path::new("test.py"), code, Language::Python)
            .unwrap();

        assert!(count >= 4, "Should find at least 4 symbols, got {}", count);

        // Check specific symbols
        let symbols = resolver.find_references("my_function");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].kind, DefinitionKind::Function);

        let symbols = resolver.find_references("MyClass");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].kind, DefinitionKind::Class);
    }

    #[test]
    fn test_javascript_symbol_extraction() {
        let mut resolver = NameResolver::new();

        let code = r#"
import { foo } from 'bar';

export function myExportedFunction() {}

function privateFunction() {}

export class MyClass {}

const myConstant = 42;
"#;

        let count = resolver
            .index_file(Path::new("test.js"), code, Language::JavaScript)
            .unwrap();

        assert!(count >= 4, "Should find at least 4 symbols, got {}", count);

        let symbols = resolver.find_references("myExportedFunction");
        assert_eq!(symbols.len(), 1);
        assert!(symbols[0].exported);
    }

    #[test]
    fn test_rust_symbol_extraction() {
        let mut resolver = NameResolver::new();

        let code = r#"
use std::collections::HashMap;

pub struct MyStruct {
    field: i32,
}

impl MyStruct {
    pub fn new() -> Self {
        Self { field: 0 }
    }

    fn private_method(&self) {}
}

pub fn public_function() {}

fn private_function() {}

pub const MY_CONST: i32 = 42;
"#;

        let count = resolver
            .index_file(Path::new("test.rs"), code, Language::Rust)
            .unwrap();

        assert!(count >= 4, "Should find at least 4 symbols, got {}", count);

        let symbols = resolver.find_references("MyStruct");
        assert_eq!(symbols.len(), 1);
        assert!(symbols[0].exported);
    }

    #[test]
    fn test_go_symbol_extraction() {
        let mut resolver = NameResolver::new();

        let code = r#"
package main

import "fmt"

type MyStruct struct {
    Field int
}

func (m *MyStruct) Method() {}

func ExportedFunc() {}

func privateFunc() {}

const MyConst = 42
var myVar = "hello"
"#;

        let count = resolver
            .index_file(Path::new("test.go"), code, Language::Go)
            .unwrap();

        assert!(count >= 4, "Should find at least 4 symbols, got {}", count);

        let symbols = resolver.find_references("ExportedFunc");
        assert_eq!(symbols.len(), 1);
        assert!(symbols[0].exported);

        let symbols = resolver.find_references("privateFunc");
        assert_eq!(symbols.len(), 1);
        assert!(!symbols[0].exported);
    }

    #[test]
    fn test_cross_file_resolution() {
        let mut resolver = NameResolver::new();

        // File 1: defines a function
        let code1 = "def my_function():\n    pass\n";
        resolver
            .index_file(Path::new("module1.py"), code1, Language::Python)
            .unwrap();

        // File 2: uses the function
        let code2 = "from module1 import my_function\nmy_function()\n";
        resolver
            .index_file(Path::new("module2.py"), code2, Language::Python)
            .unwrap();

        // Try to resolve the reference
        let context = ResolutionContext {
            file: Path::new("module2.py").to_path_buf(),
            symbol: "my_function".to_string(),
            line: 2,
            column: 1,
        };

        let refs = resolver.resolve(&context);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].definition_file, Path::new("module1.py"));
    }
}
