<#
.SYNOPSIS
  Install dsh-security-watch into a DeepSeek Harness profile from this checkout.

.DESCRIPTION
  Resolves this script's directory to an absolute path (the plugin manager's
  pnpm runs with the profile directory as its cwd, so relative paths would be
  resolved there) and forwards it to `dsh plugin add`.

  The Desktop application owns its `desktop` profile and refuses CLI management
  of it. Install there through the Plugins page instead: Add plugin → paste the
  absolute path to this directory.

.PARAMETER Profile
  Target profile name. Defaults to `web`.

.PARAMETER DshPath
  Path to the dsh launcher. When omitted the script looks for `dsh` on PATH and
  then the bundled runtime launcher.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
[CmdletBinding()]
param(
  [string]$Profile = 'web',
  [string]$DshPath = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Profile -ieq 'desktop') {
  Write-Host 'The desktop profile is managed by the Electron application.'
  Write-Host 'Open Plugins in the app, choose "Add plugin", and paste this path:'
  Write-Host "  $root"
  exit 1
}

if (-not $DshPath) {
  $onPath = Get-Command dsh -ErrorAction SilentlyContinue
  if ($onPath) {
    $DshPath = $onPath.Source
  } elseif (Test-Path 'D:\deepseek\resources\runtime\cli\bin\dsh.cmd') {
    $DshPath = 'D:\deepseek\resources\runtime\cli\bin\dsh.cmd'
  } else {
    throw 'Could not find the dsh launcher. Pass -DshPath <path>.'
  }
}

Write-Host "dsh:     $DshPath"
Write-Host "profile: $Profile"
Write-Host "source:  $root"

& $DshPath plugin --profile $Profile add $root
if ($LASTEXITCODE -ne 0) {
  throw "dsh plugin add failed with exit code $LASTEXITCODE"
}

Write-Host ''
Write-Host 'Installed. Restart DeepSeek Harness (or let HMR recompose), then refresh the page.'
Write-Host 'The badge appears above your avatar; enabling a plugin triggers one audit.'
