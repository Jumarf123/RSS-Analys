param(
    [string]$ReleaseDir = "rss-analys-release",
    [ValidateSet("fast", "medium", "slow")]
    [string]$Mode = "fast"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$releaseAbs = if ([System.IO.Path]::IsPathRooted($ReleaseDir)) {
    $ReleaseDir
}
else {
    Join-Path $root $ReleaseDir
}
$exe = Join-Path $releaseAbs "RSS-Analys.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "Release executable not found: $exe"
}

$smokeDir = Join-Path $root "smoke_tmp/release_smoke"
if (Test-Path -LiteralPath $smokeDir) {
    Remove-Item -LiteralPath $smokeDir -Recurse -Force
}
New-Item -ItemType Directory -Path $smokeDir -Force | Out-Null

$sample = Join-Path $smokeDir "input.txt"
@(
    "C:\Windows\Temp\x.exe"
    "powershell -enc AAAA"
    "hxxps://example.org/payload"
) | Set-Content -LiteralPath $sample -Encoding UTF8

$answers = Join-Path $smokeDir "answers.txt"
$rows = [System.Collections.Generic.List[string]]::new()
[void]$rows.Add("2") # language EN
switch ($Mode.ToLowerInvariant()) {
    "fast" { [void]$rows.Add("1") }
    "medium" { [void]$rows.Add("2") }
    "slow" { [void]$rows.Add("3") }
}
if ($Mode -ne "slow") {
    [void]$rows.Add("2") # hash sort = no
}
[void]$rows.Add("2") # process scan = no
[void]$rows.Add("2") # dump core = no
[void]$rows.Add($sample)
$rows | Set-Content -LiteralPath $answers -Encoding UTF8

Push-Location $smokeDir
try {
    Get-Content -LiteralPath $answers | & $exe *> "run.log"
}
finally {
    Pop-Location
}

$reportPath = Join-Path $smokeDir "Results/report.html"
$summaryPath = Join-Path $smokeDir "Results/summary/summary.txt"
if (-not (Test-Path -LiteralPath $reportPath)) {
    throw "Smoke run failed: report file missing ($reportPath)"
}
if (-not (Test-Path -LiteralPath $summaryPath)) {
    throw "Smoke run failed: summary file missing ($summaryPath)"
}

Write-Host "Smoke completed."
Write-Host "Report file: $reportPath"
Write-Host "Summary preview:"
Get-Content -LiteralPath $summaryPath | Select-Object -First 18
