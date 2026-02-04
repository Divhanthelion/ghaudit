#!/bin/bash
#
# Dump Codebase Script for sec_auditor
# Outputs all Rust source files in a structured format
#

set -e

# Colors for output (if terminal supports it)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Output file (default: stdout)
OUTPUT_FILE="${1:-/dev/stdout}"

# Project root (script directory)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}Dumping sec_auditor codebase...${NC}"
echo "Project root: $PROJECT_ROOT"
echo "Output: $OUTPUT_FILE"
echo ""

# Create/truncate output file
> "$OUTPUT_FILE"

# Function to append a file with clear delimiters
dump_file() {
    local file="$1"
    local relative_path="${file#$PROJECT_ROOT/}"
    
    echo -e "${GREEN}Processing: $relative_path${NC}"
    
    # Write file separator and contents
    {
        echo ""
        echo "================================================================================"
        echo "FILE: $relative_path"
        echo "================================================================================"
        echo ""
        cat "$file"
        echo ""
        echo "================================================================================"
        echo "END: $relative_path"
        echo "================================================================================"
        echo ""
    } >> "$OUTPUT_FILE"
}

# Write header
{
    echo "################################################################################"
    echo "# SEC_AUDITOR CODEBASE DUMP"
    echo "# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    echo "# Project: sec_auditor - High-Performance Rust Security Analysis Engine"
    echo "# Language: Rust"
    echo "################################################################################"
    echo ""
} > "$OUTPUT_FILE"

# Count total files
TOTAL_FILES=$(find "$PROJECT_ROOT/src" -name "*.rs" -type f 2>/dev/null | wc -l)
echo -e "${YELLOW}Found $TOTAL_FILES Rust source files${NC}"
echo ""

# Dump files in logical order
echo -e "${BLUE}Dumping core files...${NC}"
dump_file "$PROJECT_ROOT/src/main.rs"
dump_file "$PROJECT_ROOT/src/lib.rs"
dump_file "$PROJECT_ROOT/src/config.rs"
dump_file "$PROJECT_ROOT/src/error.rs"
dump_file "$PROJECT_ROOT/src/concurrency.rs"

echo -e "${BLUE}Dumping models...${NC}"
dump_file "$PROJECT_ROOT/src/models/mod.rs"
dump_file "$PROJECT_ROOT/src/models/finding.rs"
dump_file "$PROJECT_ROOT/src/models/repository.rs"
dump_file "$PROJECT_ROOT/src/models/vulnerability.rs"

echo -e "${BLUE}Dumping analyzer...${NC}"
dump_file "$PROJECT_ROOT/src/analyzer/mod.rs"
dump_file "$PROJECT_ROOT/src/analyzer/queries.rs"
dump_file "$PROJECT_ROOT/src/analyzer/sast.rs"
dump_file "$PROJECT_ROOT/src/analyzer/sca.rs"
dump_file "$PROJECT_ROOT/src/analyzer/secrets.rs"
dump_file "$PROJECT_ROOT/src/analyzer/taint.rs"
dump_file "$PROJECT_ROOT/src/analyzer/benchmark.rs"
dump_file "$PROJECT_ROOT/src/analyzer/name_resolution.rs"

echo -e "${BLUE}Dumping crawler...${NC}"
dump_file "$PROJECT_ROOT/src/crawler/mod.rs"
dump_file "$PROJECT_ROOT/src/crawler/git.rs"
dump_file "$PROJECT_ROOT/src/crawler/github.rs"

echo -e "${BLUE}Dumping reporter...${NC}"
dump_file "$PROJECT_ROOT/src/reporter/mod.rs"
dump_file "$PROJECT_ROOT/src/reporter/sarif.rs"
dump_file "$PROJECT_ROOT/src/reporter/text.rs"

echo -e "${BLUE}Dumping provenance...${NC}"
dump_file "$PROJECT_ROOT/src/provenance/mod.rs"
dump_file "$PROJECT_ROOT/src/provenance/slsa.rs"

echo -e "${BLUE}Dumping AI module...${NC}"
dump_file "$PROJECT_ROOT/src/ai/mod.rs"

echo -e "${BLUE}Dumping privacy module...${NC}"
dump_file "$PROJECT_ROOT/src/privacy/mod.rs"
dump_file "$PROJECT_ROOT/src/privacy/anonymizer.rs"
dump_file "$PROJECT_ROOT/src/privacy/local_llm.rs"

echo -e "${BLUE}Dumping crosslang module...${NC}"
dump_file "$PROJECT_ROOT/src/crosslang/mod.rs"
dump_file "$PROJECT_ROOT/src/crosslang/apir.rs"
dump_file "$PROJECT_ROOT/src/crosslang/lang_mapping.rs"

# Write footer
{
    echo ""
    echo "################################################################################"
    echo "# END OF CODEBASE DUMP"
    echo "# Total files: $TOTAL_FILES"
    echo "################################################################################"
} >> "$OUTPUT_FILE"

# Calculate stats
TOTAL_LINES=$(wc -l < "$OUTPUT_FILE")
echo ""
echo -e "${GREEN}✓ Dump complete!${NC}"
echo -e "${YELLOW}Total lines in output: $TOTAL_LINES${NC}"

if [ "$OUTPUT_FILE" != "/dev/stdout" ]; then
    echo -e "${GREEN}Output written to: $OUTPUT_FILE${NC}"
    
    # Show file size
    FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
    echo "File size: $FILE_SIZE"
fi
