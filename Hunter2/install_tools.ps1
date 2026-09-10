<#
.SYNOPSIS
  Windows entry point for the Bug Hunter dependency manager.
.EXAMPLE
  .\install_tools.ps1 -Profile core -DryRun
  .\install_tools.ps1 -Profile recon -Yes
#!>

[CmdletBinding()]
param(
    [ValidateSet('core','recon','web','api','cloud','secrets','mobile','osint','all')]
    [string]$Profile = 'core',
    [switch]$Yes,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$manager = Join-Path $root 'tools\arsenal.py'

if (-not (Test-Path -LiteralPath $manager)) {
    throw "Missing dependency manager: $manager"
}

$args = @($manager, 'install', '--profile', $Profile)
if ($Yes) { $args += '--yes' }
if ($DryRun) { $args += '--dry-run' }

& python @args
exit $LASTEXITCODE
