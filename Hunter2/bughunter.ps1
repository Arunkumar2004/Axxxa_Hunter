# bughunter.ps1 - PowerShell CLI dispatcher (Windows).
# Usage:
#   .\bughunter.ps1 recon target.com
#   .\bughunter.ps1 hunt target.com [--quick]
#   .\bughunter.ps1 validate "found IDOR on /api/users/123"
#   .\bughunter.ps1 scope target.com
#   .\bughunter.ps1 leads [show|ingest|next|touch]
#   .\bughunter.ps1 help

param(
    [Parameter(Mandatory = $true)][string]$Command,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Args
)

$py = (Get-Command python -ErrorAction SilentlyContinue) ?? (Get-Command python3 -ErrorAction SilentlyContinue)
if (-not $py) { Write-Host "ERROR: python not found."; exit 1 }

switch ($Command) {
    "recon" {
        if (-not $Args) { Write-Host "Usage: .\bughunter.ps1 recon <target>"; exit 1 }
        & $py.Source "tools\hunt.py" "--target" $Args[0] "--recon-only"
    }
    "hunt" {
        if (-not $Args) { Write-Host "Usage: .\bughunter.ps1 hunt <target> [--quick] [--scan-only]"; exit 1 }
        $t = $Args[0]; $extra = @()
        foreach ($a in $Args[1..($Args.Count-1)]) { $extra += $a }
        & $py.Source "tools\hunt.py" "--target" $t @extra
    }
    "validate" {
        $finding = ($Args -join " ")
        if (-not $finding) { Write-Host "Usage: .\bughunter.ps1 validate <finding>"; exit 1 }
        & $py.Source "tools\validate.py" $finding
    }
    "scope" {
        if (-not $Args) { Write-Host "Usage: .\bughunter.ps1 scope <asset>"; exit 1 }
        & $py.Source "tools\scope_checker.py" $Args[0]
    }
    "leads" {
        if (-not $Args) { $Args = @("show") }
        & $py.Source "tools\lead_board.py" $Args[0] $Args[1..($Args.Count-1)]
    }
    "report" {
        & $py.Source "tools\lead_board.py" show
        Write-Host "`nReport drafting uses the report-writing skill / commands\report.md"
    }
    "arsenal" {
        .\tools\run.ps1 external_arsenal.sh @Args
    }
    "help" {
        Write-Host @"
bughunter.ps1 - Agentic Bug Hunter (Windows)
  recon <target>             full recon pipeline
  hunt <target> [--quick]    full hunt (recon + scan)
  validate <finding>         7-Question Gate
  scope <asset>              scope check
  leads [show|ingest|next]   lead board
  arsenal [tool]             installed tool registry
"@
    }
    default {
        Write-Host "Unknown command: $Command (try: recon|hunt|validate|scope|leads|arsenal|help)"
        exit 1
    }
}
exit $LASTEXITCODE
