# AGENTS.md

This repository contains a modularized refactor of `RSS-Analys`.

## Mission

Keep behavior equivalent to the original scanner while improving maintainability.

## Engineering Rules

- Preserve detection semantics and output file format.
- Prefer small, focused changes by module.
- Keep comments in English.
- Do not remove embedded assets without replacing their usage.
- Keep Windows compatibility for process memory scanning paths.
- Keep Dump core report tabs and output filenames stable (`Results/dumpcore/*`).

## Working Areas

- `src/app/prelude.rs`: shared constants, models, startup/UI setup.
- `src/app/pipeline.rs`: main orchestration path (`run`) and analyzer core flow.
- `src/app/input_processing.rs`: input discovery and DMP preparation.
- `src/app/analysis.rs`: content analysis helpers.
- `src/app/report.rs`: HTML report generation.
- `src/app/resolve_and_triage.rs`: resolution/classification/triage.
- `src/app/yara.rs`: YARA compilation and scanning.
- `src/app/detectors.rs`: text cleaning and detector logic.
- `src/app/custom_rules.rs`: custom rule parser/matcher.
- `src/app/process_scan.rs`: process memory scanning and process dump handling.
- `src/app/memory_orbit.rs`: custom `Dump core` engine (parallel dump parser + artifact classifier).
- `tools/make_release.ps1`: release folder builder (`rss-analys-release`).
- `tools/smoke_release.ps1`: quick packaged-build smoke validation.

## Validation Checklist

- `cargo check`
- `cargo test`
- smoke execution with `cargo run`

## Output Compatibility

When changing logic, verify that `Results/*` file names and core formats remain stable.

## Current Dump core Additions

- Event correlations (`4688` + `4624/4625/4648/4672`).
- LOLBIN abuse scoring with required network context.
- Network dedup by process/endpoint/port/time bucket.
- Javaw-focused `betatest` rows.
