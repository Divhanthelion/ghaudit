#
# Dump Codebase Script for sec_auditor (PowerShell)
# Outputs all Rust source files in a structured format
#

param(
    [string]$OutputFile = "codebase_dump.txt"
)

$ErrorActionPreference = "Stop"

# Colors for output
$Green = "`e[32m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Reset = "`e[0m"

# Project root
$ProjectRoot = $PSScriptRoot
if (-not $ProjectRoot) {
    $ProjectRoot = Get-Location
}

Write-Host "${Blue}Dumping sec_auditor codebase...${Reset}"
Write-Host "Project root: $ProjectRoot"
Write-Host "Output: $OutputFile"
Write-Host ""

# Get all Rust files
$Files = Get-ChildItem -Path "$ProjectRoot/src" -Filter "*.rs" -Recurse | Sort-Object FullName
$TotalFiles = $Files.Count

Write-Host "${Yellow}Found $TotalFiles Rust source files${Reset}"
Write-Host ""

# Create StringBuilder for efficiency
$Output = New-Object System.Text.StringBuilder

# Write header
[void]$Output.AppendLine("################################################################################")
[void]$Output.AppendLine("# SEC_AUDITOR CODEBASE DUMP")
[void]$Output.AppendLine("# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")")
[void]$Output.AppendLine("# Project: sec_auditor - High-Performance Rust Security Analysis Engine")
[void]$Output.AppendLine("# Language: Rust")
[void]$Output.AppendLine("################################################################################")
[void]$Output.AppendLine("")

# Function to dump a file
function Dump-File {
    param([System.IO.FileInfo]$File)
    
    $RelativePath = $File.FullName.Substring($ProjectRoot.Length + 1)
    Write-Host "${Green}Processing: $RelativePath${Reset}"
    
    [void]$Output.AppendLine("")
    [void]$Output.AppendLine("================================================================================")
    [void]$Output.AppendLine("FILE: $RelativePath")
    [void]$Output.AppendLine("================================================================================")
    [void]$Output.AppendLine("")
    [void]$Output.AppendLine([System.IO.File]::ReadAllText($File.FullName))
    [void]$Output.AppendLine("")
    [void]$Output.AppendLine("================================================================================")
    [void]$Output.AppendLine("END: $RelativePath")
    [void]$Output.AppendLine("================================================================================")
    [void]$Output.AppendLine("")
}

# Define file order
$FileOrder = @(
    # Core
    "src/main.rs"
    "src/lib.rs"
    "src/config.rs"
    "src/error.rs"
    "src/concurrency.rs"
    # Models
    "src/models/mod.rs"
    "src/models/finding.rs"
    "src/models/repository.rs"
    "src/models/vulnerability.rs"
    # Analyzer
    "src/analyzer/mod.rs"
    "src/analyzer/queries.rs"
    "src/analyzer/sast.rs"
    "src/analyzer/sca.rs"
    "src/analyzer/secrets.rs"
    "src/analyzer/taint.rs"
    "src/analyzer/benchmark.rs"
    "src/analyzer/name_resolution.rs"
    # Crawler
    "src/crawler/mod.rs"
    "src/crawler/git.rs"
    "src/crawler/github.rs"
    # Reporter
    "src/reporter/mod.rs"
    "src/reporter/sarif.rs"
    "src/reporter/text.rs"
    # Provenance
    "src/provenance/mod.rs"
    "src/provenance/slsa.rs"
    # AI
    "src/ai/mod.rs"
    # Privacy
    "src/privacy/mod.rs"
    "src/privacy/anonymizer.rs"
    "src/privacy/local_llm.rs"
    # Crosslang
    "src/crosslang/mod.rs"
    "src/crosslang/apir.rs"
    "src/crosslang/lang_mapping.rs"
)

# Dump files in order
Write-Host "${Blue}Dumping files...${Reset}"
foreach ($RelativePath in $FileOrder) {
    $FullPath = Join-Path $ProjectRoot $RelativePath
    if (Test-Path $FullPath) {
        $File = Get-Item $FullPath
        Dump-File -File $File
    } else {
        Write-Host "Warning: $RelativePath not found" -ForegroundColor Yellow
    }
}

# Write footer
[void]$Output.AppendLine("")
[void]$Output.AppendLine("################################################################################")
[void]$Output.AppendLine("# END OF CODEBASE DUMP")
[void]$Output.AppendLine("# Total files: $TotalFiles")
[void]$Output.AppendLine("################################################################################")

# Write to file
$Output.ToString() | Out-File -FilePath $OutputFile -Encoding UTF8

# Stats
$TotalLines = (Get-Content $OutputFile).Count
$FileSize = (Get-Item $OutputFile).Length

Write-Host ""
Write-Host "${Green}✓ Dump complete!${Reset}"
Write-Host "${Yellow}Total lines in output: $TotalLines${Reset}"
Write-Host "${Green}Output written to: $OutputFile${Reset}"
Write-Host "File size: $([math]::Round($FileSize / 1KB, 2)) KB"
