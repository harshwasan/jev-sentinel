<#
.SYNOPSIS
  Shows what the Jev sentinel decided in a sandbox, newest last.

.EXAMPLE
  .\log.ps1 02-injection            # last 15 decisions
  .\log.ps1 02-injection -Last 50
  .\log.ps1 02-injection -Sent      # exactly what was sent to Jev (check secrets are withheld)
#>
param(
	[Parameter(Mandatory = $true, Position = 0)][string]$Name,
	[int]$Last = 15,
	# Show the Jev requests (the exact state sent) instead of the decisions.
	[switch]$Sent
)
$ErrorActionPreference = "Stop"
$log = Join-Path $PSScriptRoot "_logs\$Name.jsonl"
if (-not (Test-Path $log)) { throw "No log yet for '$Name'. Start it with .\start.ps1 $Name and do something." }

$records = Get-Content $log | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }

function Short([string]$text, [int]$max = 70) {
	if ($null -eq $text) { return "" }
	$one = ($text -replace '\s+', ' ').Trim()
	if ($one.Length -gt $max) { return $one.Substring(0, $max) + "..." }
	return $one
}

if ($Sent) {
	$records | Where-Object { $_.type -eq "jev_request" } | Select-Object -Last $Last | ForEach-Object {
		Write-Host ("[{0}] {1}" -f $_.time, $_.check) -ForegroundColor Cyan
		Write-Host ($_.state | ConvertTo-Json -Depth 8)
		Write-Host ""
	}
	return
}

$records | Where-Object { $_.type -ne "jev_request" } | Select-Object -Last $Last | ForEach-Object {
	$r = $_
	$time = ([datetime]$r.time).ToLocalTime().ToString("HH:mm:ss")
	switch ($r.type) {
		"tool_call" {
			$what = if ($r.input.command) { $r.input.command } elseif ($r.input.path) { $r.input.path } else { ($r.input | ConvertTo-Json -Compress) }
			$result = if ($r.error) { "ERROR" } else { $r.decision }
			$detail = if ($r.error) { $r.error } else { "$($r.reason); rounds=$($r.rounds.Count)" }
			if ($r.tainted) { $detail += "; after earlier flag" }
			if ($r.userChoice) { $detail += "; you chose: $($r.userChoice)" }
			"{0}  CALL    {1,-10} {2,-42} {3}" -f $time, $result, (Short "$($r.tool): $what" 42), (Short $detail 120)
		}
		"tool_output" {
			$result = if ($r.error) { "ERROR" } elseif ($r.status -eq "skipped") { "skipped" } elseif ($r.flagged) { "FLAGGED" } else { "clean" }
			$detail = if ($r.error) { $r.error } elseif ($r.status -eq "skipped") { $r.why } else { "suspicious={0:P0}; parts={1}" -f $r.suspicious, $r.chunks }
			"{0}  OUTPUT  {1,-10} {2,-42} {3}" -f $time, $result, (Short $r.source 42), $detail
		}
		"reply" {
			$result = if ($r.error) { "ERROR" } elseif ($r.flagged) { "FLAGGED" } else { "clean" }
			$detail = if ($r.error) { $r.error } else {
				"harmful={0:P0} relays={1:P0} unsupported={2:P0}" -f $r.scores.harmful_content, $r.scores.relays_injected, $r.scores.unsupported_claims
			}
			"{0}  REPLY   {1,-10} {2,-42} {3}" -f $time, $result, "", $detail
		}
	}
}
