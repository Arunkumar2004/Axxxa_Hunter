# run.ps1 - cross-platform dispatcher for the Agentic-Bug-Hunter toolkit (Windows PowerShell).
# Runs .sh tools via Git Bash / WSL, .py tools via python (python3 fallback).
#
# Usage:
#   .\tools\run.ps1 recon_engine.sh target.com
#   .\tools\run.ps1 vuln_scanner.sh recon/target.com
#   .\tools\run.ps1 hunt.py --target target.com
#   .\tools\run.ps1 lead_board.py show

param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ToolArgs)

if (-not $ToolArgs -or $ToolArgs.Count -eq 0) {
    Write-Host "Usage: .\tools\run.ps1 <tool> [args...]"
    Write-Host "  .sh  -> runs via Git Bash / WSL"
    Write-Host "  .py  -> runs via python (python3 fallback)"
    exit 1
}

$tool = $ToolArgs[0]
$rest = $ToolArgs[1..($ToolArgs.Count - 1)]

# Resolve tool paths relative to the repo's tools/ dir when invoked bare.
if (-not (Test-Path $tool) -and -not $tool.Contains('\') -and -not $tool.Contains('/')) {
    $candidate = Join-Path $PSScriptRoot $tool
    if (Test-Path $candidate) { $tool = $candidate }
}

# --- locate python -----------------------------------------------------------
function Get-Python {
    foreach ($c in @("python", "python3", "py")) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) { return $c }
    }
    return $null
}

# --- locate bash -------------------------------------------------------------
function Get-Bash {
    $candidates = @(
        "C:\Program Files\Git\bin\bash.exe",
        "C:\Program Files\Git\usr\bin\bash.exe",
        "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    $cmd = Get-Command bash -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Convert-ToForwardSlash([string]$s) {
    return $s -replace '\\', '/'
}

if ($tool -match '\.sh$') {
    $bash = Get-Bash
    if (-not $bash) {
        Write-Host "ERROR: no bash found. Install Git for Windows (https://git-scm.com) or enable WSL."
        exit 1
    }
    $shArgs = @($tool) + $rest | ForEach-Object { Convert-ToForwardSlash ([string]$_) }
    & $bash -lc "$(Convert-ToForwardSlash $tool) $($rest | ForEach-Object { Convert-ToForwardSlash ([string]$_) } | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } })"
    exit $LASTEXITCODE
}

# default: python tool
$py = Get-Python
if (-not $py) {
    Write-Host "ERROR: python not found. Install Python 3.10+."
    exit 1
}
& $py $tool @rest
exit $LASTEXITCODE
