# INFORMATION.md

## Program Purpose

`RSS-Analys` analyzes textual and memory-dump artifacts (`.txt`, `.dmp`) and builds structured investigation outputs for screenshare triage.

## High-Level Pipeline

1. Startup + interactive options (`language`, `analysis mode`, `hash sort`, `process scan mode`, `Dump core`).
2. Input discovery (`.txt` and `.dmp`) with exclusion of service/build folders.
3. DMP conversion/extraction using a built-in strings engine.
4. Fast input preparation and relevance filtering.
5. Content analysis and artifact extraction.
6. Optional process memory scanning and custom-rule matching.
7. Path resolution, classification, and triage signal aggregation.
8. YARA scan over selected PE/JAR targets.
9. Optional custom memory stage: `Dump core` over DMP files.
10. Internal self-trained AI-module stage over aggregated evidence.
    - includes live observer context gathered through all runtime stages
11. Write TXT reports, summary, and HTML report.

## Analysis Modes

- `fast`:
  - fastest profile, key artifacts only
  - enables DMP fast-convert + aggressive fast-prepared input filtering
  - may skip NormalPE(BLAKE3) split for speed
- `medium`:
  - balanced profile with minimal losses
  - full DMP->TXT conversion and fuller input pass
  - keeps deep lookup auto (extended limits)
- `slow`:
  - maximum-detail profile (legacy-style full mode)
  - full DMP->TXT conversion, full input pass
  - forces deep lookup and disables YARA soft-limit
  - forces hash sorting ON

## Main Artifact Categories

- executable artifacts: `allpe`, `NormalPE`, `notfound`
- command detections: `RegKeyDeletion`, `ReplaceClean`, `FilelessExecution`, `DLL`, `ForfilesWmic`, `IOC`
- context trackers: `Start`, `Prefetch`, `DPS`, `links`, `download-links`, `domains`
- beta triage categories: persistence / anti-forensics / data hiding / tool evasion / artifact wipe / suspicious domains
- YARA detections: `Results/yara/yaradetect.txt`
- Dump core memory categories:
  - `open_files_sockets`
  - `command_buffers`
  - `hidden_processes`
  - `shell_history`
  - `network_artifacts`
  - `suspicious_connections`
  - `injected_code`
  - `suspicious_dll`
  - `modified_memory_regions`
  - `event_correlations`
  - `lolbin_abuse`
  - `javaw_betatest`
  - final verdict rows
  - supporting evidence rows
  - module notes

## Dump core Low-Noise Layers

- Network deduplication by `process + endpoint + port + time bucket`.
- Event correlation layer:
  - process creation (`4688` with `CommandLine`) joined with auth/security context (`4624/4625/4648/4672`) by `LogonId` and time bucket.
- LOLBIN scoring:
  - `mshta`, `rundll32`, `regsvr32`, `powershell -enc`, `pwsh -enc`, `wmic process call create`, `cmd.exe /c`
  - signal is emitted only with network context.
- DLL/EXE trust enrichment in HTML:
  - path trust (`system/program/user/temp/unknown`)
  - sign hint (`signed/unsigned/unknown`)
- YARA severity tuning:
  - `obf` / `suspect` only detections are downgraded to low/medium.

## AI Verdict Layer

- It outputs:
  - verdict (`clean` / `suspicious` / `cheat`)
  - confidence score
  - evidence rows used for decision support
- It is designed to reduce noise and speed triage, but it is not a formal proof engine.


- It analyzes **combined output** from:
  - `Strings core` triage artifacts
  - `Dump core` suspicious categories
- It also receives live observer context:
  - stage-by-stage runtime timeline
  - metrics and high-signal evidence snapshots
- It additionally receives `Results/*` context snippets:
  - allows model to inspect broad report outputs (not only tiny final subsets)
- If model stage fails, program safely falls back to deterministic local verdict logic.
- This layer is assistive triage, not formal proof.
- Model persistence and adaptive learning:
  - next runs load this file and skip heavy retraining for fast startup
  - after enough new samples, model retrains automatically (threshold is configurable)

## AI Training Maintenance

  - updates internet keyword packs from online DFIR feeds + local defaults
  - performs controlled long retrain and persists model weights
- `tools/make_release.ps1`
  - builds a ready distribution folder: `rss-analys-release/`
- `tools/smoke_release.ps1`

## Embedded Resources

- `yara/`: embedded rule sources compiled at runtime.
- `blake3/blake3.txt`: hash list used for NormalPE filtering.
- `rss.ico`: Windows resource icon for binary metadata.

## Compatibility Goal of This Recode

This refactor prioritizes architecture quality while preserving runtime behavior and output contracts.
