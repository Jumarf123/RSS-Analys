# PROJECT_STRUCTURE.md

## Repository Layout (Core)

```text
recode_rss-analys/
├─ Cargo.toml
├─ Cargo.lock
├─ build.rs
├─ rss.ico
├─ README.md
├─ AGENTS.md
├─ INFORMATION.md
├─ PROJECT_STRUCTURE.md
├─ blake3/
│  └─ blake3.txt
├─ modules/
│     ├─ internet_keywords.txt
│     └─ live_samples.tsv
├─ tools/
│  ├─ make_release.ps1
│  └─ smoke_release.ps1
├─ for_me/
│  ├─ RSS-Analys.exe
│  ├─ run_me.bat
│  ├─ README_FOR_ME.md
│  └─ modules/
│        ├─ internet_keywords.txt
│        └─ live_samples.tsv
├─ rss-analys-release/
│  ├─ RSS-Analys.exe
│  ├─ run_me.bat
│  ├─ README.md
│  └─ modules/
│        ├─ internet_keywords.txt
│        └─ live_samples.tsv
├─ yara/
│  ├─ CheatA.yar
│  ├─ CheatB.yar
│  ├─ CheatC.yar
│  ├─ doomsday.yar
│  └─ ...
└─ src/
   ├─ main.rs
   └─ app/
      ├─ mod.rs
      ├─ prelude.rs
      ├─ pipeline.rs
      ├─ input_processing.rs
      ├─ analysis.rs
      ├─ report.rs
      ├─ resolve_and_triage.rs
      ├─ yara.rs
      ├─ detectors.rs
      ├─ custom_rules.rs
      ├─ process_scan.rs
      ├─ memory_orbit.rs
```

## Source Responsibilities

- `src/main.rs`
- Binary entry point only. Calls `app::entry_point()`.

- `src/app/mod.rs`
- Combines all modules with `include!` in deterministic order.

- `src/app/prelude.rs`
- Shared imports, constants, regexes, data models, startup prompts/UI helpers.
- Contains `entry_point()`.

- `src/app/pipeline.rs`
- Main `run()` orchestration and analyzer state transitions.
- Coordinates all major stages `[1/8] .. [8/8]`.

- `src/app/input_processing.rs`
- Input search, DMP handling, built-in strings extraction, fast-prepared input cache.

- `src/app/analysis.rs`
- Parallel and streaming analysis over prepared inputs.
- Shared writing helpers and JS payload preparation helpers.

- `src/app/report.rs`
- HTML report builder (`write_html_report`) with pages:
  - `Strings core`
  - `Dump core`
  - `AI overview` panel (verdict/confidence/reason/backend/model/factors)
  - structured tabs with search/pagination (`verdict`, `evidence`, `context`, `notes`, `raw`)
- `Dump core` page includes dedicated tabs:
  - `Results (beta)`
  - `Results (AI)`
  - `betatest`
  - `Event correlations`
  - `LOLBIN abuse`

- `src/app/resolve_and_triage.rs`
- Path normalization/resolution, detector aggregation, status table generation,
  BLAKE3 split logic, and triage category builders.

- `src/app/yara.rs`
- Embedded YARA source collection, compile, scan, and match reporting.

- `src/app/detectors.rs`
- Text cleanup and detector primitives (IOC/fileless/link/path parsing, etc.).

- `src/app/custom_rules.rs`
- Custom rule file parsing, compiled matcher generation, custom-hit aggregation.

- `src/app/process_scan.rs`
- Windows process enumeration/memory read, process dump scanning, process-specific custom checks.

- `src/app/memory_orbit.rs`
- Custom `Dump core` engine:
  - parallel chunk scanning of `.dmp`
  - minidump header metadata extraction
  - heuristic classification into memory artifact categories
  - low-noise post-processing:
    - network deduplication (`process+endpoint+port+time`)
    - event correlation (`4688` + `4624/4625/4648/4672`)
    - LOLBIN scoring with network context
    - javaw-focused betatest enrichment
    - deterministic verdict/evidence rows
  - output writer to `Results/dumpcore/*`

## Execution Flow (Where What Runs)

1. `src/main.rs` starts process and delegates to `app::entry_point()`.
2. `entry_point()` (in `src/app/prelude.rs`) gathers user options (`language`, `analysis mode`, `hash sort`, process and dump options) and calls `run()`.
3. `run()` (in `src/app/pipeline.rs`) executes:
   - input preparation (`src/app/input_processing.rs`)
   - base analysis (`src/app/analysis.rs` + `src/app/detectors.rs`)
   - optional process scan (`src/app/process_scan.rs`)
   - path resolve + triage (`src/app/resolve_and_triage.rs`)
   - YARA scan (`src/app/yara.rs`)
   - optional Dump core scan over DMP (`src/app/memory_orbit.rs`)
   - TXT + summary + HTML report writing (`src/app/report.rs` + summary writer)
4. Program prints result paths and waits for Enter.

## Runtime Output Layout

Main runtime directory: `Results/`

- `Results/allpe/`
- `Results/NormalPE/`
- `Results/notfound/`
- `Results/yara/`
- `Results/summary/`
- `Results/custom/`
- `Results/screenshare/`
- `Results/dumpcore/`
- `Results/report.html`

## Dump core Output Files

`Results/dumpcore/` includes:

- `open_files_sockets.txt`
- `command_buffers.txt`
- `hidden_processes.txt`
- `shell_history.txt`
- `network_artifacts.txt`
- `suspicious_connections.txt`
- `injected_code.txt`
- `suspicious_dll.txt`
- `modified_memory_regions.txt`
- `event_correlations.txt`
- `lolbin_abuse.txt`
- `javaw_betatest.txt`
- `proxy_bypass.txt`
- `risk_verdicts.txt`
- `notes.txt`

These directories are generated by the pipeline and are part of normal execution.
