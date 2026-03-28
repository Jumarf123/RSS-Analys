// The application is intentionally split into focused source files.
// We use `include!` to preserve the original item visibility and call graph.
include!("prelude.rs");
include!("pipeline.rs");
include!("input_processing.rs");
include!("analysis.rs");
include!("report.rs");
include!("resolve_and_triage.rs");
include!("yara.rs");
include!("detectors.rs");
include!("custom_rules.rs");
include!("process_scan.rs");
include!("memory_orbit.rs");
