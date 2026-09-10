# hunt.ps1 - quick hunt entry point (Windows PowerShell).
# Usage:  .\hunt.ps1 target.com [--quick] [--scan-only]

param(
    [Parameter(Mandatory = $true)][string]$Target,
    [switch]$Quick,
    [switch]$ScanOnly
)

$py = (Get-Command python -ErrorAction SilentlyContinue) ?? (Get-Command python3 -ErrorAction SilentlyContinue)
if (-not $py) {
    Write-Host "ERROR: python not found."
    exit 1
}

$args = @("tools\hunt.py", "--target", $Target)
if ($Quick) { $args += "--quick" }
if ($ScanOnly) { $args += "--scan-only" }

Write-Host "[*] Hunting $Target ..."
& $py.Source @args
exit $LASTEXITCODE
