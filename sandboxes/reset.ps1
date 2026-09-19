<#
.SYNOPSIS
  Replaces a sandbox with a fresh copy of its fixture. The guard log is archived, not deleted.

.EXAMPLE
  .\reset.ps1 02-injection
  .\reset.ps1 -All
#>
param(
	[Parameter(Position = 0)][string]$Name,
	[switch]$All
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$fixtures = Join-Path $root "fixtures"

$names = if ($All) {
	(Get-ChildItem $fixtures -Directory).Name
} elseif ($Name) {
	@($Name)
} else {
	throw "Give a sandbox name, or -All."
}

foreach ($n in $names) {
	$fixture = Join-Path $fixtures $n
	if (-not (Test-Path $fixture)) { throw "No sandbox '$n'." }

	# The working copy lives in the temp folder, outside this repo.
	$work = Join-Path ([IO.Path]::GetTempPath()) "pi-jev-sentinel\$n"
	if (Test-Path $work) { Remove-Item $work -Recurse -Force }
	New-Item -ItemType Directory -Force $work | Out-Null
	# -Force includes hidden files such as .env.
	Get-ChildItem $fixture -Force | Copy-Item -Destination $work -Recurse -Force

	# Keep the old log: move it to _logs\archive with a timestamp, so a reset never loses evidence.
	$log = Join-Path $root "_logs\$n.jsonl"
	if (Test-Path $log) {
		$archive = Join-Path $root "_logs\archive"
		New-Item -ItemType Directory -Force $archive | Out-Null
		$target = Join-Path $archive ("{0}-{1}.jsonl" -f $n, (Get-Date -Format "yyyyMMdd-HHmmss"))
		Move-Item $log $target
		Write-Host "Reset $n in $work (log archived to $target)"
	} else {
		Write-Host "Reset $n in $work"
	}
}
