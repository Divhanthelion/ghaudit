//! Print the tree-sitter syntax tree of a snippet. Use it when writing a rule to see
//! which node types and field names a query needs.
//!
//! ```text
//! echo 'subprocess.run(cmd, shell=True)' | cargo run --example syntax_tree -- python
//! ```
//!
//! Languages: rust, python, javascript, typescript, tsx, go.

use std::io::Read;

fn main() {
    let lang = std::env::args().nth(1).unwrap_or_default();
    let language: tree_sitter::Language = match lang.as_str() {
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "javascript" | "js" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" | "ts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        _ => {
            eprintln!("usage: syntax_tree <rust|python|javascript|typescript|tsx|go> < file");
            std::process::exit(2);
        }
    };
    let mut source = String::new();
    std::io::stdin()
        .read_to_string(&mut source)
        .expect("read stdin");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("grammar loads");
    let tree = parser.parse(&source, None).expect("parse");
    println!("{}", tree.root_node().to_sexp());
}
