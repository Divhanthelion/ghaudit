#!/usr/bin/env python3
"""
Dump Codebase Script for sec_auditor
Outputs all Rust source files in a structured format

Usage:
    python dump_codebase.py [output_file]

Examples:
    python dump_codebase.py                    # Output to stdout
    python dump_codebase.py codebase.txt       # Output to file
    python dump_codebase.py -o codebase.txt    # Output to file
"""

import sys
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional

# File order for logical output
FILE_ORDER = [
    # Core
    "src/main.rs",
    "src/lib.rs",
    "src/config.rs",
    "src/error.rs",
    "src/concurrency.rs",
    # Models
    "src/models/mod.rs",
    "src/models/finding.rs",
    "src/models/repository.rs",
    "src/models/vulnerability.rs",
    # Analyzer
    "src/analyzer/mod.rs",
    "src/analyzer/queries.rs",
    "src/analyzer/sast.rs",
    "src/analyzer/sca.rs",
    "src/analyzer/secrets.rs",
    "src/analyzer/taint.rs",
    "src/analyzer/benchmark.rs",
    "src/analyzer/name_resolution.rs",
    # Crawler
    "src/crawler/mod.rs",
    "src/crawler/git.rs",
    "src/crawler/github.rs",
    # Reporter
    "src/reporter/mod.rs",
    "src/reporter/sarif.rs",
    "src/reporter/text.rs",
    # Provenance
    "src/provenance/mod.rs",
    "src/provenance/slsa.rs",
    # AI
    "src/ai/mod.rs",
    # Privacy
    "src/privacy/mod.rs",
    "src/privacy/anonymizer.rs",
    "src/privacy/local_llm.rs",
    # Crosslang
    "src/crosslang/mod.rs",
    "src/crosslang/apir.rs",
    "src/crosslang/lang_mapping.rs",
]


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.resolve()


def get_all_rust_files(project_root: Path) -> List[Path]:
    """Get all Rust files in the src directory."""
    src_dir = project_root / "src"
    if not src_dir.exists():
        raise FileNotFoundError(f"Source directory not found: {src_dir}")
    return sorted(src_dir.rglob("*.rs"))


def format_file_separator(path: str, is_start: bool = True) -> str:
    """Create a file separator line."""
    sep = "=" * 80
    if is_start:
        return f"\n{sep}\nFILE: {path}\n{sep}\n"
    else:
        return f"\n{sep}\nEND: {path}\n{sep}\n"


def dump_file(file_path: Path, project_root: Path) -> str:
    """Read and format a single file."""
    relative_path = file_path.relative_to(project_root)
    print(f"  Processing: {relative_path}")
    
    try:
        content = file_path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        content = file_path.read_text(encoding='latin-1')
    
    result = []
    result.append(format_file_separator(str(relative_path), is_start=True))
    result.append(content)
    if not content.endswith('\n'):
        result.append('\n')
    result.append(format_file_separator(str(relative_path), is_start=False))
    
    return ''.join(result)


def create_header(project_root: Path, total_files: int) -> str:
    """Create the dump header."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""################################################################################
# SEC_AUDITOR CODEBASE DUMP
# Generated: {timestamp}
# Project: sec_auditor - High-Performance Rust Security Analysis Engine
# Language: Rust
# Total files: {total_files}
################################################################################

"""


def create_footer(total_files: int) -> str:
    """Create the dump footer."""
    return f"""
################################################################################
# END OF CODEBASE DUMP
# Total files: {total_files}
################################################################################
"""


def dump_codebase(output_file: Optional[str] = None) -> str:
    """Dump the entire codebase."""
    project_root = get_project_root()
    
    print(f"Dumping sec_auditor codebase...")
    print(f"Project root: {project_root}")
    
    # Collect all files
    all_files = get_all_rust_files(project_root)
    
    # Create ordered list based on FILE_ORDER, then add any remaining files
    ordered_files = []
    for rel_path in FILE_ORDER:
        full_path = project_root / rel_path
        if full_path in all_files:
            ordered_files.append(full_path)
    
    # Add any files not in the order list
    for file_path in all_files:
        if file_path not in ordered_files:
            ordered_files.append(file_path)
    
    total_files = len(ordered_files)
    print(f"Found {total_files} Rust source files\n")
    
    # Build output
    output_lines = []
    output_lines.append(create_header(project_root, total_files))
    
    print("Dumping files...")
    for file_path in ordered_files:
        output_lines.append(dump_file(file_path, project_root))
    
    output_lines.append(create_footer(total_files))
    
    result = ''.join(output_lines)
    
    # Write output
    if output_file and output_file != '-':
        output_path = Path(output_file)
        output_path.write_text(result, encoding='utf-8')
        
        # Stats
        total_lines = len(result.splitlines())
        file_size = output_path.stat().st_size
        print("\n[OK] Dump complete!")
        print(f"Total lines in output: {total_lines}")
        print(f"Output written to: {output_file}")
        print(f"File size: {file_size / 1024:.2f} KB")
    else:
        print("\n[OK] Dump complete!")
        return result
    
    return result


def main():
    """Main entry point."""
    # Parse arguments
    output_file = None
    args = sys.argv[1:]
    
    if '-o' in args:
        idx = args.index('-o')
        if idx + 1 < len(args):
            output_file = args[idx + 1]
        else:
            print("Error: -o requires an argument", file=sys.stderr)
            sys.exit(1)
    elif args:
        output_file = args[0]
    
    try:
        result = dump_codebase(output_file)
        if not output_file or output_file == '-':
            print(result)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
