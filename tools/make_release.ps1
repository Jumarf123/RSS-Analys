param(
    [string]$ReleaseDir = "rss-analys-release",
    [switch]$SkipBuild
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

if (-not $SkipBuild) {
    cargo build --release
}

$exeSrc = Join-Path $root "target/release/RSS-Analys.exe"
if (-not (Test-Path -LiteralPath $exeSrc)) {
    throw "Release executable not found: $exeSrc"
}

if (Test-Path -LiteralPath $releaseAbs) {
    Remove-Item -LiteralPath $releaseAbs -Recurse -Force
}
New-Item -ItemType Directory -Path $releaseAbs -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $releaseAbs "Results") -Force | Out-Null

Copy-Item -LiteralPath $exeSrc -Destination (Join-Path $releaseAbs "RSS-Analys.exe") -Force
Copy-Item -LiteralPath (Join-Path $root "AGENTS.md") -Destination (Join-Path $releaseAbs "AGENTS.md") -Force
Copy-Item -LiteralPath (Join-Path $root "INFORMATION.md") -Destination (Join-Path $releaseAbs "INFORMATION.md") -Force
Copy-Item -LiteralPath (Join-Path $root "PROJECT_STRUCTURE.md") -Destination (Join-Path $releaseAbs "PROJECT_STRUCTURE.md") -Force

$runMe = @"
@echo off
setlocal
set RSS_ANALYS_NO_TUI=0
set RSS_ANALYS_DEEP_LOOKUP=0
set RSS_ANALYS_CPU_BUDGET_PCT=50
start "" "%~dp0RSS-Analys.exe"
endlocal
"@
[System.IO.File]::WriteAllText((Join-Path $releaseAbs "run_me.bat"), $runMe, [System.Text.Encoding]::ASCII)

$readme = @"
# rss-analys-release

Ready package for GitHub Release.

## Included

- `RSS-Analys.exe`
- `run_me.bat`
- empty `Results/` output directory

## Run

1. Start `run_me.bat`.
2. Select language/options in interactive prompts.
3. Provide `.txt`/`.dmp` file or folder.
4. Open `Results/report.html`.
"@
[System.IO.File]::WriteAllText((Join-Path $releaseAbs "README.md"), $readme, [System.Text.Encoding]::UTF8)

Write-Host "Release package created: $releaseAbs"
