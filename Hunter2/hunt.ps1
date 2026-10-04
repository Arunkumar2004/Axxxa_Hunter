# hunt.ps1 - quick hunt entry point (Windows PowerShell).
# Usage:  .\hunt.ps1 target.com [--quick] [--scan-only]

param(
    [Parameter(Mandatory = $true)][string]$Target,
    [switch]$Quick,
    [switch]$ScanOnly
)

$py = $null
foreach ($c in 'python','python3','py') {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) {
    Write-Host "ERROR: python not found (python/python3/py)."
    exit 1
}

$args = @("tools\hunt.py", "--target", $Target)
if ($Quick) { $args += "--quick" }
if ($ScanOnly) { $args += "--scan-only" }

Write-Host "[*] Hunting $Target ..."
& $py @args
exit $LASTEXITCODE
