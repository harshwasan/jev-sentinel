<#
.SYNOPSIS
  Starts pi with Jev Sentinel inside one test sandbox.

.DESCRIPTION
  The sandbox is a fresh copy of sandboxes/fixtures/<name> in your temp folder, outside this repo,
  so the agent can never read or edit the extension or these test notes. Settings come from
  sandboxes/_config/<name>.json; decisions are logged to sandboxes/_logs/<name>.jsonl.

.EXAMPLE
  .\start.ps1 02-injection
  .\start.ps1 01-tool-calls -Mode separate
  .\start.ps1 04-pinned-task -Continue
  .\start.ps1 04-pinned-task -Set pinTaskInPrompt=true
  .\start.ps1 01-tool-calls -PiRepo D:\src\pi      # run pi from a source checkout instead of PATH
#>
param(
	[Parameter(Mandatory = $true, Position = 0)][string]$Name,
	# The agent's model. Older models follow planted instructions more readily, which is what these tests need.
	[string]$Model = "gpt-4o-mini",
	[string]$Provider = "openai",
	# Jev question mode for tool calls: intent_risk (default), separate, or combined.
	[ValidateSet("", "intent_risk", "separate", "combined")][string]$Mode = "",
	# Resume the sandbox's most recent session instead of starting a new one.
	[switch]$Continue,
	# Override settings for this run: key=value pairs, e.g. pinTaskInPrompt=true.
	[string[]]$Set = @(),
	# Load CLAUDE.md / AGENTS.md files. Off by default: pi also loads them from every parent folder,
	# so a machine-wide file (e.g. at the drive root) would fill the agent's instructions with unrelated text.
	[switch]$ContextFiles,
	# Path to a pi source checkout. Without it, the `pi` command on PATH is used.
	[string]$PiRepo = ""
)
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$repo = Split-Path $root -Parent
$valid = (Get-ChildItem (Join-Path $root "fixtures") -Directory).Name
# Only exact fixture names, never paths.
if ($Name -notin $valid) { throw "No sandbox '$Name'. Choose one of: $($valid -join ', ')" }
if (-not $env:TYPESAFE_API_KEY) { throw "Set `$env:TYPESAFE_API_KEY first." }

$work = Join-Path ([IO.Path]::GetTempPath()) "pi-jev-sentinel\$Name"
if (-not (Test-Path $work)) { & (Join-Path $root "reset.ps1") $Name | Out-Null }

# Settings live outside the sandbox, so the agent cannot read or edit its own guard settings.
$settings = Get-Content (Join-Path $root "_config\$Name.json") -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Force (Join-Path $root "_logs") | Out-Null
$settings | Add-Member -Force logFile (Join-Path $root "_logs\$Name.jsonl")
$settings | Add-Member -Force logStates $true
if ($Mode) { $settings | Add-Member -Force questionMode $Mode }
foreach ($pair in $Set) {
	$key, $raw = $pair -split "=", 2
	if (-not $key -or $null -eq $raw) { throw "-Set expects key=value, got '$pair'." }
	# true/false and numbers become JSON booleans and numbers; anything else stays a string.
	$value = if ($raw -eq "true") { $true } elseif ($raw -eq "false") { $false } elseif ($raw -match '^-?\d+(\.\d+)?$') { [double]$raw } else { $raw }
	$settings | Add-Member -Force $key.Trim() $value
	Write-Host "Override: $($key.Trim()) = $raw"
}
$active = Join-Path $root "_config\_active-$Name.json"
# WriteAllText writes UTF-8 without a byte-order mark on both Windows PowerShell and PowerShell 7.
[IO.File]::WriteAllText($active, ($settings | ConvertTo-Json -Depth 5))
$env:JEV_SENTINEL_CONFIG = $active

Write-Host "Sandbox:  $work"
Write-Host "Model:    $Provider/$Model"
Write-Host "Log:      $($settings.logFile)   (view with .\log.ps1 $Name)"
Write-Host ""

$piArgs = @("-e", (Join-Path $repo "src\index.ts"), "--provider", $Provider, "--model", $Model)
if ($Continue) { $piArgs += "--continue" }
if (-not $ContextFiles) { $piArgs += "--no-context-files" }

Push-Location $work
try {
	if ($PiRepo) {
		# From source: --tsconfig makes tsx resolve pi's packages to their source files.
		& (Join-Path $PiRepo "node_modules\.bin\tsx.cmd") --tsconfig (Join-Path $PiRepo "tsconfig.json") (Join-Path $PiRepo "packages\coding-agent\src\cli.ts") @piArgs
	} else {
		pi @piArgs
	}
} finally {
	Pop-Location
}
