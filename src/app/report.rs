// HTML report builder and front-end payload serialization for Results/report.html.

#[allow(clippy::too_many_arguments)]
fn write_html_report(
    path: &Path,
    user_opts: &UserOptions,
    inputs: &[PathBuf],
    dmps: &[PathBuf],
    a: &Analyzer,
    allpe: &BTreeSet<String>,
    normal_pe: &BTreeSet<String>,
    scripts: &BTreeSet<String>,
    file_dates: &BTreeSet<String>,
    dps: &BTreeSet<String>,
    started: &BTreeSet<String>,
    prefetch: &BTreeSet<String>,
    other_disk: &BTreeSet<String>,
    deleted: &BTreeSet<String>,
    trash_deleted: &BTreeSet<String>,
    resolved_pathless: &BTreeSet<String>,
    full_not_found: &BTreeSet<String>,
    pathless_not_found: &BTreeSet<String>,
    slinks: &BTreeSet<String>,
    download_links: &BTreeSet<String>,
    sfiles: &BTreeSet<String>,
    jar_paths: &BTreeSet<String>,
    remote_access_tools: &BTreeSet<String>,
    analysis_tools: &BTreeSet<String>,
    credential_access_hits: &BTreeSet<String>,
    network_tunnel_hits: &BTreeSet<String>,
    remote_domain_hits: &BTreeSet<String>,
    tunnel_domain_hits: &BTreeSet<String>,
    remote_session_hits: &BTreeSet<String>,
    persistence_hits: &BTreeSet<String>,
    anti_forensics_hits: &BTreeSet<String>,
    lolbas_hits: &BTreeSet<String>,
    domain_frequency: &BTreeSet<String>,
    suspicious_domain_hits: &BTreeSet<String>,
    triage_priority_hits: &BTreeSet<String>,
    yara_targets: usize,
    yara_hits: &BTreeSet<String>,
    custom_hits: &[String],
    custom_stats: &CustomScanStats,
    memory_orbit: &MemoryOrbitReport,
) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let default_lang = match user_opts.lang {
        UiLang::Ru => "ru",
        UiLang::En => "en",
    };

    let summary_json = format!(
        "{{\"inputs\":{},\"dmps\":{},\"links\":{},\"regdel\":{},\"replace\":{},\"fileless\":{},\"dll\":{},\"forfiles\":{},\"java_batch\":{},\"ioc\":{},\"allpe\":{},\"normal_pe\":{},\"scripts\":{},\"beta\":{},\"file_dates\":{},\"dps\":{},\"started\":{},\"prefetch\":{},\"otherdisk\":{},\"deleted\":{},\"trash_deleted\":{},\"resolved_names\":{},\"not_found_full\":{},\"not_found_names\":{},\"suspend_links\":{},\"download_links\":{},\"suspect_files\":{},\"yara_targets\":{},\"yara\":{},\"java_paths\":{},\"remote_access_tools\":{},\"analysis_tools\":{},\"credential_access\":{},\"network_tunnels\":{},\"remote_domains\":{},\"tunnel_domains\":{},\"remote_sessions\":{},\"persistence\":{},\"anti_forensics\":{},\"lolbas\":{},\"domain_frequency\":{},\"suspicious_domains\":{},\"triage_priority\":{},\"custom_rules\":{},\"custom_hit_files\":{},\"custom_hits\":{},\"process_scanned\":{},\"process_skipped\":{},\"process_dumps\":{},\"aethertrace_enabled\":{},\"aethertrace_dumps\":{},\"aethertrace_plugins_ok\":{},\"aethertrace_plugin_errors\":{},\"aethertrace_open_files\":{},\"aethertrace_command_buffers\":{},\"aethertrace_hidden_processes\":{},\"aethertrace_shell_history\":{},\"aethertrace_network\":{},\"aethertrace_suspicious_connections\":{},\"aethertrace_injected_code\":{},\"aethertrace_suspicious_dll\":{},\"aethertrace_modified_memory\":{},\"aethertrace_event_correlations\":{},\"aethertrace_lolbin_abuse\":{},\"aethertrace_javaw_betatest\":{},\"aethertrace_proxy_bypass\":{},\"aethertrace_risk_verdicts\":{}}}",
        inputs.len(),
        dmps.len(),
        a.links.len(),
        a.regdel.len(),
        a.replace.len(),
        a.fileless.len(),
        a.dll.len(),
        a.forfiles_wmic.len(),
        a.java_batch.len(),
        a.ioc.len(),
        allpe.len(),
        normal_pe.len(),
        scripts.len(),
        a.beta.len(),
        file_dates.len(),
        dps.len(),
        started.len(),
        prefetch.len(),
        other_disk.len(),
        deleted.len(),
        trash_deleted.len(),
        resolved_pathless.len(),
        full_not_found.len(),
        pathless_not_found.len(),
        slinks.len(),
        download_links.len(),
        sfiles.len(),
        yara_targets,
        yara_hits.len(),
        jar_paths.len(),
        count_non_empty_detector_rows(remote_access_tools),
        count_non_empty_detector_rows(analysis_tools),
        count_non_empty_detector_rows(credential_access_hits),
        count_non_empty_detector_rows(network_tunnel_hits),
        count_non_empty_detector_rows(remote_domain_hits),
        count_non_empty_detector_rows(tunnel_domain_hits),
        count_non_empty_detector_rows(remote_session_hits),
        count_non_empty_detector_rows(persistence_hits),
        count_non_empty_detector_rows(anti_forensics_hits),
        lolbas_hits.len(),
        domain_frequency.len(),
        suspicious_domain_hits.len(),
        count_non_empty_detector_rows(triage_priority_hits),
        custom_stats.rules_loaded,
        custom_stats.hits_by_file.len(),
        total_custom_hits(&custom_stats.hits_by_file),
        custom_stats.process_scanned,
        custom_stats.process_skipped,
        custom_stats.process_dumps,
        usize::from(memory_orbit.enabled),
        memory_orbit.dumps_scanned,
        memory_orbit.plugins_ok,
        memory_orbit.plugin_errors.len(),
        memory_orbit.open_files_or_sockets.len(),
        memory_orbit.command_buffers.len(),
        memory_orbit.hidden_or_terminated_processes.len(),
        memory_orbit.shell_command_history.len(),
        memory_orbit.network_artifacts.len(),
        memory_orbit.suspicious_connections.len(),
        memory_orbit.injected_code_hits.len(),
        memory_orbit.suspicious_dll_hits.len(),
        memory_orbit.modified_memory_regions.len(),
        memory_orbit.event_correlations.len(),
        memory_orbit.lolbin_network_scores.len(),
        memory_orbit.javaw_betatest.len(),
        memory_orbit.proxy_bypass_hits.len(),
        memory_orbit.risk_verdicts.len(),
    );

    let mut html = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Residence Screenshare - RSS-Analys</title>
  <style>
    @import url("https://fonts.googleapis.com/css2?family=Sora:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap");

    :root {
      color-scheme: dark;
      --bg-0: #090202;
      --bg-1: #1a0505;
      --bg-2: #2a0a0a;
      --surface: #160707;
      --surface-soft: #230a0a;
      --surface-raised: #301010;
      --text: #ffe4e4;
      --muted: #d09a9a;
      --line: #5a2424;
      --line-soft: #4a1d1d;
      --primary: #ff4d4d;
      --primary-2: #d62828;
      --primary-soft: rgba(255, 77, 77, 0.18);
      --danger: #ff8d8d;
      --ok: #7de38f;
      --warn: #ffb470;
      --info: #ffb3b3;
      --scroll-track: rgba(24, 7, 7, 0.84);
      --scroll-thumb: #a32020;
      --scroll-thumb-hover: #bf2a2a;
      --scroll-thumb-soft: rgba(163, 32, 32, 0.72);
      --shadow: 0 18px 42px rgba(10, 1, 1, 0.58);
      --radius-lg: 18px;
      --radius-md: 13px;
      --radius-sm: 11px;
    }
    [data-theme="light"] {
      color-scheme: light;
      --bg-0: #fff1f1;
      --bg-1: #ffe4e4;
      --bg-2: #ffd9d9;
      --surface: #ffffff;
      --surface-soft: #fff5f5;
      --surface-raised: #ffecec;
      --text: #321212;
      --muted: #8c5555;
      --line: #e3bcbc;
      --line-soft: #efcece;
      --primary: #c62828;
      --primary-2: #9f1d1d;
      --primary-soft: rgba(198, 40, 40, 0.14);
      --danger: #b43d3d;
      --ok: #1f7a33;
      --warn: #906100;
      --info: #b71c1c;
      --scroll-track: rgba(248, 230, 230, 0.93);
      --scroll-thumb: #d17a7a;
      --scroll-thumb-hover: #bb5f5f;
      --scroll-thumb-soft: rgba(187, 95, 95, 0.8);
      --shadow: 0 14px 34px rgba(122, 24, 24, 0.18);
    }
    * {
      box-sizing: border-box;
      scrollbar-color: var(--scroll-thumb) var(--scroll-track);
      scrollbar-width: thin;
    }
    html, body {
      min-height: 100%;
    }
    body {
      margin: 0;
      font-family: "Sora", "Segoe UI", "Tahoma", sans-serif;
      color: var(--text);
      background:
        radial-gradient(52vmax 52vmax at 9% 8%, rgba(255, 77, 77, 0.2), transparent 60%),
        radial-gradient(46vmax 46vmax at 95% 10%, rgba(214, 40, 40, 0.18), transparent 62%),
        radial-gradient(38vmax 38vmax at 50% 100%, rgba(255, 140, 140, 0.12), transparent 66%),
        linear-gradient(140deg, var(--bg-0) 0%, var(--bg-1) 56%, var(--bg-2) 100%);
      position: relative;
      overflow-x: hidden;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(to right, rgba(255, 255, 255, 0.045) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(255, 255, 255, 0.045) 1px, transparent 1px);
      background-size: 34px 34px;
      opacity: 0.32;
      z-index: 0;
    }
    .wrap {
      position: relative;
      z-index: 1;
      max-width: 1320px;
      margin: 0 auto;
      padding: 24px;
      animation: pageIn 240ms ease-out;
    }
    @keyframes pageIn {
      from {
        opacity: 0;
        transform: translateY(8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    .hero {
      position: relative;
      background:
        linear-gradient(140deg, rgba(255, 77, 77, 0.17), rgba(214, 40, 40, 0.11) 48%, transparent 75%),
        var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      padding: 20px 22px;
      display: flex;
      gap: 16px;
      justify-content: space-between;
      align-items: center;
      box-shadow: var(--shadow);
      flex-wrap: wrap;
      overflow: hidden;
    }
    .hero::after {
      content: "";
      position: absolute;
      inset: 0;
      pointer-events: none;
      background: linear-gradient(to bottom, rgba(255, 255, 255, 0.08), transparent 20%);
      opacity: 0.5;
    }
    .title {
      margin: 0;
      font-size: clamp(1.3rem, 2.35vw, 1.95rem);
      font-weight: 800;
      letter-spacing: 0.01em;
      line-height: 1.2;
      text-wrap: balance;
    }
    .title a {
      color: var(--primary);
      text-decoration: none;
      border-bottom: 1px dashed color-mix(in srgb, var(--primary) 70%, transparent);
      transition: color 120ms ease, border-color 120ms ease;
    }
    .title a:hover {
      color: var(--info);
      border-color: color-mix(in srgb, var(--info) 70%, transparent);
    }
    .title a:focus-visible {
      outline: none;
      box-shadow: 0 0 0 3px rgba(255, 77, 77, 0.3);
      border-radius: 6px;
    }
    .sub {
      margin: 7px 0 0;
      color: var(--muted);
      font-size: 0.93rem;
      letter-spacing: 0.01em;
      text-wrap: pretty;
    }
    .actions {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    .btn {
      border: 1px solid var(--line);
      background: var(--surface-soft);
      color: var(--text);
      border-radius: 12px;
      padding: 10px 13px;
      text-decoration: none;
      cursor: pointer;
      font-family: inherit;
      font-weight: 700;
      font-size: 0.9rem;
      transition: transform 130ms ease, border-color 130ms ease, background 130ms ease;
    }
    .btn:hover {
      transform: translateY(-1px);
      border-color: rgba(255, 77, 77, 0.58);
    }
    .btn:focus-visible {
      outline: none;
      box-shadow: 0 0 0 3px rgba(255, 77, 77, 0.3);
    }
    .btn-primary {
      border: 0;
      color: #ffffff;
      background: linear-gradient(135deg, var(--primary), var(--primary-2));
      box-shadow: 0 10px 22px rgba(140, 25, 25, 0.38);
    }
    .page-switch.active {
      border-color: rgba(255, 127, 127, 0.7);
      background: linear-gradient(135deg, var(--primary-soft), rgba(214, 40, 40, 0.25));
      box-shadow: inset 0 0 0 1px rgba(255, 127, 127, 0.25);
    }
    .btn-icon {
      width: 42px;
      height: 42px;
      padding: 0;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 1.04rem;
      line-height: 1;
    }
    .toolbar {
      margin-top: 14px;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: center;
    }
    .search {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 13px;
      padding: 12px 14px;
      outline: none;
      font-family: inherit;
      background: var(--surface);
      color: var(--text);
      transition: border-color 130ms ease, box-shadow 130ms ease, background 130ms ease;
    }
    .search::placeholder {
      color: var(--muted);
      opacity: 0.86;
    }
    .search:focus {
      border-color: rgba(255, 77, 77, 0.58);
      box-shadow: 0 0 0 4px rgba(255, 77, 77, 0.2);
      background: var(--surface-soft);
    }
    .counter {
      color: var(--muted);
      font-size: 0.88rem;
      font-weight: 600;
      white-space: nowrap;
    }
    .filters {
      margin-top: 10px;
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
      padding: 9px 10px;
      border: 1px solid var(--line-soft);
      border-radius: 13px;
      background: rgba(40, 12, 12, 0.42);
    }
    .filter-title {
      color: var(--muted);
      font-size: 0.82rem;
      font-weight: 700;
      margin-right: 4px;
    }
    .filter-chip {
      border: 1px solid var(--line);
      background: var(--surface-soft);
      color: var(--text);
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 0.76rem;
      font-weight: 700;
      cursor: pointer;
      transition: border-color 120ms ease, background 120ms ease, transform 120ms ease;
    }
    .filter-chip:hover {
      transform: translateY(-1px);
      border-color: rgba(255, 77, 77, 0.52);
    }
    .filter-chip.active {
      color: #fff;
      border-color: rgba(255, 127, 127, 0.64);
      background: linear-gradient(135deg, rgba(255, 127, 127, 0.36), rgba(197, 39, 39, 0.35));
    }
    .filter-chip.muted {
      opacity: 0.45;
    }
    .filter-input {
      border: 1px solid var(--line);
      background: var(--surface-soft);
      color: var(--text);
      border-radius: 10px;
      padding: 6px 9px;
      min-width: 220px;
      font-family: inherit;
      font-size: 0.78rem;
      font-weight: 600;
      outline: none;
    }
    .filter-input:focus {
      border-color: rgba(255, 77, 77, 0.58);
      box-shadow: 0 0 0 3px rgba(255, 77, 77, 0.2);
    }
    [data-theme="light"] .filters {
      background: rgba(255, 255, 255, 0.74);
    }
    .tabs {
      margin-top: 14px;
      display: flex;
      gap: 9px;
      overflow-x: auto;
      overflow-y: hidden;
      padding: 8px;
      border: 1px solid var(--line-soft);
      border-radius: 16px;
      background: rgba(46, 14, 14, 0.44);
      scrollbar-gutter: stable;
      -webkit-overflow-scrolling: touch;
    }
    [data-theme="light"] .tabs {
      background: rgba(255, 255, 255, 0.72);
    }
    .tab {
      border: 1px solid var(--line);
      background: var(--surface-soft);
      border-radius: 999px;
      padding: 9px 14px;
      cursor: pointer;
      white-space: nowrap;
      font-size: 0.86rem;
      color: var(--text);
      font-weight: 700;
      transition: all 130ms ease;
    }
    .tab:hover {
      border-color: rgba(255, 77, 77, 0.5);
    }
    .tab.active {
      background: linear-gradient(135deg, var(--primary-soft), rgba(214, 40, 40, 0.14));
      border-color: rgba(255, 77, 77, 0.56);
      box-shadow: inset 0 0 0 1px rgba(255, 77, 77, 0.26);
    }
    .panel {
      margin-top: 13px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .panel-head {
      padding: 13px 15px;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
      font-size: 0.9rem;
      font-weight: 700;
      background: var(--surface-soft);
    }
    .grid {
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      padding: 12px;
    }
    .card {
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      padding: 11px 13px;
      background: var(--surface-soft);
      position: relative;
      overflow: hidden;
      transition: transform 130ms ease, border-color 130ms ease;
    }
    .card::before {
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 3px;
      background: linear-gradient(180deg, var(--primary), var(--primary-2));
      opacity: 0.62;
    }
    .card:hover {
      transform: translateY(-1px);
      border-color: rgba(255, 77, 77, 0.55);
    }
    .card .k {
      color: var(--muted);
      font-size: 0.79rem;
      margin: 0;
      letter-spacing: 0.01em;
      padding-left: 2px;
    }
    .card .v {
      margin: 6px 0 0;
      font-size: 1.1rem;
      font-weight: 800;
      color: var(--text);
      padding-left: 2px;
    }
    .quick-card {
      width: 100%;
      text-align: left;
      cursor: pointer;
      font-family: inherit;
      color: inherit;
    }
    .quick-card:hover {
      transform: translateY(-1px);
      border-color: rgba(255, 77, 77, 0.65);
    }
    .quick-card:focus-visible {
      outline: none;
      box-shadow: 0 0 0 3px rgba(255, 77, 77, 0.3);
    }
    .block {
      padding: 12px;
      border-top: 1px solid var(--line);
    }
    .block h3 {
      margin: 0 0 8px;
      font-size: 0.9rem;
      color: var(--muted);
      font-weight: 700;
    }
    .mono {
      font-family: "JetBrains Mono", "Cascadia Mono", "Consolas", monospace;
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      line-height: 1.36;
      font-size: 0.83rem;
      max-height: 62vh;
      overflow: auto;
      padding: 13px;
      background: var(--surface-soft);
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      scrollbar-gutter: stable;
    }
    .rows {
      display: grid;
      gap: 8px;
      padding: 10px;
      max-height: 62vh;
      overflow: auto;
      background: var(--surface-soft);
      scrollbar-gutter: stable;
    }
    .memory-top {
      display: flex;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      margin-bottom: 10px;
    }
    .memory-top h3 {
      margin: 0;
    }
    .memory-top .counter {
      font-size: 0.82rem;
    }
    .memory-table-wrap {
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      background: var(--surface-soft);
      max-height: 62vh;
      overflow: auto;
      scrollbar-gutter: stable;
    }
    .memory-table {
      width: 100%;
      min-width: 1320px;
      border-collapse: separate;
      border-spacing: 0;
      font-family: "JetBrains Mono", "Cascadia Mono", "Consolas", monospace;
      font-size: 0.79rem;
      line-height: 1.35;
    }
    .memory-table thead th {
      position: sticky;
      top: 0;
      z-index: 2;
      text-align: left;
      font-weight: 700;
      letter-spacing: 0.01em;
      color: var(--muted);
      background: linear-gradient(180deg, var(--surface), var(--surface-soft));
      border-bottom: 1px solid var(--line);
      padding: 9px 10px;
    }
    .memory-table tbody td {
      border-bottom: 1px solid var(--line-soft);
      padding: 8px 10px;
      vertical-align: top;
      color: var(--text);
    }
    .memory-table tbody tr:hover td {
      background: color-mix(in srgb, var(--surface-raised) 82%, transparent);
    }
    .memory-col-index {
      width: 56px;
      text-align: right;
      color: var(--muted);
    }
    .memory-col-signal {
      width: 124px;
      white-space: nowrap;
    }
    .memory-col-source {
      width: 280px;
      overflow-wrap: anywhere;
    }
    .memory-col-tag {
      width: 200px;
      overflow-wrap: anywhere;
    }
    .memory-col-entity {
      width: 260px;
      overflow-wrap: anywhere;
      color: var(--info);
    }
    .memory-col-file {
      width: 170px;
      overflow-wrap: anywhere;
      color: var(--text-soft);
    }
    .memory-col-sign {
      width: 132px;
      white-space: nowrap;
    }
    .memory-col-trust {
      width: 150px;
      white-space: nowrap;
    }
    .memory-col-time {
      width: 172px;
      white-space: nowrap;
      color: var(--muted);
    }
    .memory-col-details {
      min-width: 360px;
      overflow-wrap: anywhere;
      white-space: pre-wrap;
    }
    .memory-row-high td:first-child {
      box-shadow: inset 3px 0 0 rgba(255, 141, 141, 0.72);
    }
    .memory-row-medium td:first-child {
      box-shadow: inset 3px 0 0 rgba(255, 180, 112, 0.72);
    }
    .memory-row-low td:first-child {
      box-shadow: inset 3px 0 0 rgba(125, 227, 143, 0.72);
    }
    .memory-chip {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.01em;
      background: color-mix(in srgb, var(--surface-soft) 90%, transparent);
      color: var(--text);
      white-space: nowrap;
    }
    .memory-chip::before {
      content: "";
      width: 6px;
      height: 6px;
      border-radius: 999px;
      background: currentColor;
      opacity: 0.84;
    }
    .memory-chip-high {
      color: var(--danger);
      border-color: rgba(255, 141, 141, 0.52);
      background: rgba(255, 141, 141, 0.14);
    }
    .memory-chip-medium {
      color: var(--warn);
      border-color: rgba(255, 180, 112, 0.52);
      background: rgba(255, 180, 112, 0.14);
    }
    .memory-chip-low {
      color: var(--ok);
      border-color: rgba(125, 227, 143, 0.52);
      background: rgba(125, 227, 143, 0.14);
    }
    .memory-select {
      border: 1px solid var(--line);
      background: var(--surface-soft);
      color: var(--text);
      border-radius: 10px;
      padding: 6px 9px;
      min-width: 140px;
      font-family: inherit;
      font-size: 0.77rem;
      font-weight: 700;
      outline: none;
      cursor: pointer;
    }
    .memory-select:focus {
      border-color: rgba(255, 77, 77, 0.58);
      box-shadow: 0 0 0 3px rgba(255, 77, 77, 0.2);
    }
    .memory-pager {
      margin-top: 10px;
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      justify-content: space-between;
      border: 1px solid var(--line-soft);
      border-radius: 12px;
      padding: 8px 10px;
      background: rgba(40, 12, 12, 0.35);
    }
    [data-theme="light"] .memory-pager {
      background: rgba(255, 255, 255, 0.75);
    }
    .memory-pager-left,
    .memory-pager-right {
      display: inline-flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .memory-pager-meta {
      color: var(--muted);
      font-size: 0.8rem;
      font-weight: 700;
    }
    .memory-nav-btn {
      border: 1px solid var(--line);
      background: var(--surface-soft);
      color: var(--text);
      border-radius: 10px;
      padding: 6px 10px;
      font-size: 0.78rem;
      font-weight: 700;
      cursor: pointer;
    }
    .memory-nav-btn[disabled] {
      cursor: default;
      opacity: 0.45;
    }
    .row-item {
      border: 1px solid var(--line);
      background: var(--surface);
      border-radius: var(--radius-sm);
      padding: 9px 10px;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: center;
    }
    .row-left {
      font-family: "JetBrains Mono", "Cascadia Mono", "Consolas", monospace;
      overflow-wrap: anywhere;
      white-space: pre-wrap;
      font-size: 0.82rem;
      line-height: 1.36;
    }
    .row-right {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      justify-content: flex-end;
      align-items: center;
      min-width: 160px;
    }
    .badge {
      font-size: 0.74rem;
      font-weight: 700;
      border-radius: 999px;
      border: 1px solid transparent;
      padding: 4px 9px;
      white-space: nowrap;
      letter-spacing: 0.01em;
    }
    .badge-danger {
      color: var(--danger);
      background: rgba(255, 125, 134, 0.14);
      border-color: rgba(255, 125, 134, 0.45);
    }
    .badge-warn {
      color: var(--warn);
      background: rgba(255, 203, 118, 0.14);
      border-color: rgba(255, 203, 118, 0.45);
    }
    .badge-ok {
      color: var(--ok);
      background: rgba(76, 175, 80, 0.17);
      border-color: rgba(76, 175, 80, 0.52);
    }
    .badge-info {
      color: var(--info);
      background: rgba(140, 200, 255, 0.14);
      border-color: rgba(140, 200, 255, 0.42);
    }
    .empty {
      color: var(--danger);
      font-weight: 700;
      padding: 16px;
    }
    .hide {
      display: none;
    }

    @supports selector(::-webkit-scrollbar) {
      *::-webkit-scrollbar {
        width: 10px;
        height: 10px;
      }
      *::-webkit-scrollbar-track {
        background: var(--scroll-track);
        border-radius: 999px;
      }
      *::-webkit-scrollbar-thumb {
        background: var(--scroll-thumb);
        border-radius: 999px;
        border: 2px solid var(--scroll-track);
      }
      *::-webkit-scrollbar-thumb:hover {
        background: var(--scroll-thumb-hover);
      }
      .tabs::-webkit-scrollbar {
        height: 7px;
      }
      .tabs::-webkit-scrollbar-track {
        background: transparent;
      }
      .tabs::-webkit-scrollbar-thumb {
        background: var(--scroll-thumb-soft);
        border: 0;
      }
    }

    @media (max-width: 860px) {
      .wrap {
        padding: 14px;
      }
      .hero {
        padding: 16px;
      }
      .toolbar {
        grid-template-columns: 1fr;
      }
      .counter {
        justify-self: start;
      }
      .tabs {
        padding: 7px;
      }
      .mono {
        max-height: 56vh;
      }
      .rows {
        max-height: 56vh;
      }
      .memory-table-wrap {
        max-height: 56vh;
      }
      .row-item {
        grid-template-columns: 1fr;
      }
      .row-right {
        justify-content: flex-start;
        min-width: 0;
      }
      .title {
        font-size: clamp(1.16rem, 5vw, 1.6rem);
      }
    }
    @media (prefers-reduced-motion: reduce) {
      * {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
      }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <div>
        <h1 class="title"><a id="titleDiscord" href="https://discord.gg/residencescreenshare" target="_blank" rel="noopener noreferrer">Residence Screenshare</a></h1>
        <p class="sub" id="subtitle">Результаты анализа.</p>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="https://discord.gg/residencescreenshare" target="_blank" rel="noopener noreferrer" id="discordBtn">Discord</a>
        <button class="btn page-switch active" id="pageStringsBtn" type="button">Strings core</button>
        <button class="btn page-switch" id="pageMemoryBtn" type="button">Dump core</button>
        <button class="btn page-switch" id="pageMemoryBetaBtn" type="button">Results (beta)</button>
        <button class="btn btn-icon" id="themeBtn" type="button" aria-label="Toggle theme" title="Toggle theme">&#9728;</button>
        <button class="btn" id="langBtn" type="button">RU / EN</button>
      </div>
    </header>

    <div class="toolbar" id="toolbar">
      <input class="search" id="search" type="search" placeholder="Search in current tab...">
      <div class="counter" id="counter">0</div>
    </div>
    <div class="filters hide" id="diskFilters"></div>

    <nav class="tabs" id="tabs"></nav>

    <section class="panel" id="summaryPanel">
      <div class="panel-head" id="summaryHead">Summary</div>
      <div class="grid" id="summaryGrid"></div>
      <div class="block">
        <h3 id="quickHead">Quick triage</h3>
        <div class="grid" id="quickGrid"></div>
      </div>
      <div class="block">
        <h3 id="inputsHead">Input files</h3>
        <pre class="mono" id="inputsView"></pre>
      </div>
      <div class="block">
        <h3 id="dmpsHead">Converted DMP sources</h3>
        <pre class="mono" id="dmpsView"></pre>
      </div>
    </section>

    <section class="panel" id="dataPanel">
      <div class="panel-head" id="dataHead">Items</div>
      <div class="rows hide" id="rowView"></div>
      <pre class="mono" id="dataView"></pre>
      <div class="empty hide" id="emptyView">No data</div>
      <div class="memory-pager hide" id="dataPager"></div>
    </section>

    <section class="panel hide" id="memoryPanel">
      <div class="panel-head" id="memoryHead">Dump core engine</div>
      <div class="grid" id="memorySummaryGrid"></div>
      <div class="block hide" id="memoryExplorerBlock">
        <div class="memory-top">
          <h3 id="memoryActiveHead">Artifacts</h3>
          <div class="counter" id="memoryLocalCounter"></div>
        </div>
        <div class="filters hide" id="memoryFilters"></div>
        <div class="memory-table-wrap hide" id="memoryTableWrap">
          <table class="memory-table" id="memoryTable">
            <thead id="memoryTableHead"></thead>
            <tbody id="memoryTableBody"></tbody>
          </table>
        </div>
        <div class="memory-pager hide" id="memoryPager"></div>
        <div class="empty hide" id="memoryEmptyView">No data</div>
      </div>
    </section>
  </div>

  <script>
    const DEFAULT_LANG = "__DEFAULT_LANG__";
    const DATA = {
      summary: __SUMMARY__,
      inputs: __INPUTS__,
      dmps: __DMPS__,
      tabs: {
            custom_hits: __CUSTOM_HITS__,
            allpe: __ALLPE__,
            normalpe: __NORMALPE__,
            scripts: __SCRIPTS__,
            beta: __BETA__,
            file_dates: __FILE_DATES__,
            dps: __DPS__,
            start: __START__,
            prefetch: __PREFETCH__,
            otherdisk: __OTHERDISK__,
            deleted: __DELETED__,
            trashdeleted: __TRASHDELETED__,
        files_without_path: __FILES_WITHOUT_PATH__,
        notfound_full: __NOTFOUND_FULL__,
        notfound_names: __NOTFOUND_NAMES__,
        links: __LINKS__,
        download_links: __DOWNLOAD_LINKS__,
        suspend_links: __SUSPEND_LINKS__,
        suspect_file: __SUSPECT_FILE__,
        yara: __YARA__,
        java_paths: __JAVA_PATHS__,
        regdel: __REGDEL__,
        replaceclean: __REPLACECLEAN__,
        fileless: __FILELESS__,
        dll: __DLL__,
        forfiles_wmic: __FORFILES_WMIC__,
        java_batch: __JAVA_BATCH__,
        ioc: __IOC__,
        remote_access_tools: __REMOTE_ACCESS_TOOLS__,
        analysis_tools: __ANALYSIS_TOOLS__,
        credential_access: __CREDENTIAL_ACCESS__,
        network_tunnels: __NETWORK_TUNNELS__,
        remote_domains: __REMOTE_DOMAINS__,
        tunnel_domains: __TUNNEL_DOMAINS__,
        remote_sessions: __REMOTE_SESSIONS__,
        persistence: __PERSISTENCE__,
        anti_forensics: __ANTI_FORENSICS__,
        lolbas: __LOLBAS__,
        domain_frequency: __DOMAIN_FREQUENCY__,
        suspicious_domains: __SUSPICIOUS_DOMAINS__,
        triage_priority: __TRIAGE_PRIORITY__
      }
      ,
      memory: {
        engine: "__AETHERTRACE_ENGINE__",
        runner: "__AETHERTRACE_RUNNER__",
        notes: __AETHERTRACE_NOTES__,
        open_files_sockets: __AETHERTRACE_OPEN_FILES_SOCKETS__,
        command_buffers: __AETHERTRACE_COMMAND_BUFFERS__,
        hidden_processes: __AETHERTRACE_HIDDEN_PROCESSES__,
        shell_history: __AETHERTRACE_SHELL_HISTORY__,
        network_artifacts: __AETHERTRACE_NETWORK__,
        suspicious_connections: __AETHERTRACE_SUSPICIOUS_CONNECTIONS__,
        injected_code: __AETHERTRACE_INJECTED_CODE__,
        suspicious_dll: __AETHERTRACE_SUSPICIOUS_DLL__,
        modified_memory: __AETHERTRACE_MODIFIED_MEMORY__,
        event_correlations: __AETHERTRACE_EVENT_CORRELATIONS__,
        lolbin_abuse: __AETHERTRACE_LOLBIN_ABUSE__,
        javaw_betatest: __AETHERTRACE_JAVAW_BETATEST__,
        proxy_bypass: __AETHERTRACE_PROXY_BYPASS__,
        risk_verdicts: __AETHERTRACE_RISK_VERDICTS__,
        plugin_errors: __AETHERTRACE_PLUGIN_ERRORS__
      }
    };
    const SUSPICIOUS_KWS = __SUSPICIOUS_KWS__;
    const STRUCTURED_TABS = new Set([
      "custom_hits",
      "yara",
      "download_links",
      "suspend_links",
      "suspect_file",
      "remote_access_tools",
      "analysis_tools",
      "credential_access",
      "network_tunnels",
      "remote_domains",
      "tunnel_domains",
      "suspicious_domains",
      "domain_frequency",
      "persistence",
      "anti_forensics",
      "triage_priority",
      "scripts",
      "beta",
      "file_dates",
      "start",
      "prefetch",
      "dps",
      "deleted",
      "trashdeleted"
    ]);

    const TAB_ORDER = [
      "summary",
      "triage_priority",
      "custom_hits",
      "allpe",
      "normalpe",
      "scripts",
      "beta",
      "file_dates",
      "dps",
      "start",
      "prefetch",
      "otherdisk",
      "deleted",
      "trashdeleted",
      "files_without_path",
      "notfound_full",
      "notfound_names",
      "links",
      "download_links",
      "suspend_links",
      "suspect_file",
      "yara",
      "java_paths",
      "regdel",
      "replaceclean",
      "fileless",
      "dll",
      "forfiles_wmic",
      "java_batch",
      "ioc",
      "remote_access_tools",
      "analysis_tools",
      "credential_access",
      "network_tunnels",
      "remote_domains",
      "tunnel_domains",
      "remote_sessions",
      "persistence",
      "anti_forensics",
      "domain_frequency",
      "suspicious_domains"
    ];

    const MEMORY_TAB_ORDER = [
      "memory_summary",
      "memory_high_signal",
      "memory_results_beta",
      "memory_proxy_bypass",
      "memory_risk_verdicts",
      "memory_betatest",
      "memory_event_corr",
      "memory_lolbin",
      "memory_open",
      "memory_buffers",
      "memory_hidden",
      "memory_shell",
      "memory_network",
      "memory_connections",
      "memory_injected",
      "memory_dll",
      "memory_modified",
      "memory_notes"
    ];

    const QUICK_TABS = [
      "triage_priority",
      "remote_access_tools",
      "analysis_tools",
      "credential_access",
      "network_tunnels",
      "remote_domains",
      "tunnel_domains",
      "persistence",
      "remote_sessions",
      "anti_forensics",
      "suspend_links",
      "suspect_file",
      "yara"
    ];
    const QUICK_TAB_SUMMARY_KEY = {
      suspect_file: "suspect_files"
    };

    const I18N = {
      en: {
        title: "Residence Screenshare - RSS-Analys",
        subtitle: "Analysis results.",
        titlePrefix: "Residence Screenshare - ",
        titleDiscord: "Residence Screenshare",
        pageStrings: "Strings core",
        pageMemory: "Dump core",
        pageMemoryBeta: "Results (beta)",
        search: "Search in current tab...",
        empty: "No data",
        items: "Items",
        filtered: "Filtered",
        shown: "Shown",
        diskFilters: "Exclude by disk:",
        resetFilters: "Reset filters",
        excludeDisk: "Exclude",
        excludeWords: "Exclude words:",
        excludeWordsHint: "github discord telegram",
        statusFilter: "Status:",
        statusAll: "All",
        statusDeleted: "Deleted only",
        statusAlive: "No deleted only",
        signalFilter: "Signal:",
        signalAll: "All",
        signalHigh: "High only",
        signalMedium: "Medium only",
        summary: "Summary",
        quickTriage: "Quick triage",
        inputFiles: "Input files",
        dmpFiles: "Converted DMP sources",
        memoryHead: "Dump core engine",
        memoryOpenHead: "Open files / sockets",
        memoryBuffersHead: "Command buffers (input/output)",
        memoryHiddenProcHead: "Hidden / terminated process candidates",
        memoryShellHead: "CMD/PowerShell history",
        memoryNetworkHead: "Network artifacts",
        memoryConnHead: "Suspicious connections",
        memoryInjectHead: "Injected / hidden code artifacts",
        memoryDllHead: "Suspicious DLL artifacts",
        memoryModHead: "Modified memory regions",
        memoryErrorHead: "Plugin errors / notes",
        memoryRunner: "Runner",
        memoryFiltersSignal: "Signal:",
        memoryFiltersSource: "Source:",
        memoryFiltersMarker: "Type:",
        memoryFiltersSign: "Sign:",
        memoryFiltersTrust: "Path trust:",
        memoryFiltersSort: "Sort:",
        memoryAllSources: "All sources",
        memoryAllMarkers: "All types",
        memoryAllSigns: "All sign states",
        memoryAllTrust: "All trust levels",
        memorySortSignalDesc: "Signal (high->low)",
        memorySortSourceAsc: "Source (A->Z)",
        memorySortMarkerAsc: "Type (A->Z)",
        memorySortTimeDesc: "Time (new->old)",
        memoryColIndex: "No.",
        memoryColSignal: "Signal",
        memoryColSource: "Source",
        memoryColTag: "Type",
        memoryColEntity: "Entity",
        memoryColFile: "File",
        memoryColSign: "Sign",
        memoryColTrust: "Path trust",
        memoryColTime: "Time",
        memoryColDetails: "Details",
        memorySignalHigh: "High",
        memorySignalMedium: "Medium",
        memorySignalLow: "Low",
        memoryEntityNone: "n/a",
        memoryTimeUnknown: "n/a",
        memorySignSigned: "signed",
        memorySignUnsigned: "unsigned",
        memorySignUnknown: "unknown",
        memoryTrustSystem: "system",
        memoryTrustProgram: "program",
        memoryTrustUser: "user-writable",
        memoryTrustTemp: "temp/cache",
        memoryTrustUnknown: "unknown",
        memoryPageLabel: "Page",
        memoryPrev: "Prev",
        memoryNext: "Next",
        memoryRowsPerPage: "Rows/page:",
        discord: "Discord",
        themeLight: "Switch to light theme",
        themeDark: "Switch to dark theme",
        file: "File",
        program: "Program",
        rule: "Rule",
        keyword: "Keyword",
        host: "Host",
        time: "Time",
        clean: "No detections",
        parseError: "Parser info",
        tab_summary: "Summary",
        tab_triage_priority: "Priority triage (beta)",
        tab_custom_hits: "Custom hits",
        tab_allpe: "All PE",
        tab_normalpe: "Normal PE",
        tab_scripts: "Scripts",
        tab_beta: "Beta",
        tab_file_dates: "File dates",
        tab_dps: "DPS",
        tab_start: "Started files",
        tab_prefetch: "Prefetch",
        tab_otherdisk: "OtherDisk",
        tab_deleted: "Deleted",
        tab_trashdeleted: "Trash deleted",
        tab_files_without_path: "Resolved names",
        tab_notfound_full: "NotFound paths",
        tab_notfound_names: "NotFound names",
        tab_links: "Links",
        tab_download_links: "Download links",
        tab_suspend_links: "Suspicious links",
        tab_suspect_file: "Suspicious files",
        tab_yara: "YARA detects",
        tab_java_paths: "Java/JAR paths",
        tab_regdel: "RegKeyDeletion",
        tab_replaceclean: "ReplaceClean",
        tab_fileless: "FilelessExecution",
        tab_dll: "DLL",
        tab_forfiles_wmic: "ForfilesWmic",
        tab_java_batch: "JavaBatchExecution",
        tab_ioc: "Command IOC",
        tab_remote_access_tools: "Cheat artifacts (beta)",
        tab_analysis_tools: "Bypass artifacts (beta)",
        tab_credential_access: "Artifact wipe (beta)",
        tab_network_tunnels: "Data hiding (beta)",
        tab_remote_domains: "Trail obfuscation (beta)",
        tab_tunnel_domains: "Tool attacks (beta)",
        tab_remote_sessions: "Persistence (beta)",
        tab_persistence: "Credential access (beta)",
        tab_anti_forensics: "Anti-forensics (beta)",
        tab_lolbas: "Beta misc",
        tab_domain_frequency: "Domain frequency",
        tab_suspicious_domains: "Suspicious domains",
        tab_memory_summary: "Dump core summary",
        tab_memory_high_signal: "Высокий сигнал (merged)",
        tab_memory_results_beta: "Results (beta)",
        tab_memory_proxy_bypass: "Proxy bypass",
        tab_memory_risk_verdicts: "Risk verdicts",
        tab_memory_betatest: "betatest",
        tab_memory_event_corr: "Event correlations",
        tab_memory_lolbin: "LOLBIN abuse",
        tab_memory_open: "Open files / sockets",
        tab_memory_buffers: "Command buffers",
        tab_memory_hidden: "Hidden processes",
        tab_memory_shell: "Shell history",
        tab_memory_network: "Network artifacts",
        tab_memory_connections: "Suspicious connections",
        tab_memory_injected: "Injected code",
        tab_memory_dll: "Suspicious DLL",
        tab_memory_modified: "Modified memory",
        tab_memory_notes: "Engine notes",
        s_inputs: "Input TXT",
        s_dmps: "Converted DMP",
        s_links: "Links",
        s_regdel: "RegKeyDeletion",
        s_replace: "ReplaceClean",
        s_fileless: "FilelessExecution",
        s_dll: "DLL",
        s_forfiles: "ForfilesWmic",
        s_java_batch: "JavaBatchExecution",
        s_ioc: "Command IOC",
        s_custom_rules: "Custom rules",
        s_custom_hit_files: "Custom hit files",
        s_custom_hits: "Custom hits total",
        s_process_scanned: "Processes scanned",
        s_process_skipped: "Processes skipped",
        s_process_dumps: "Process dumps",
        s_aethertrace_enabled: "Dump core enabled",
        s_aethertrace_dumps: "Dump core dumps",
        s_aethertrace_plugins_ok: "Dump core plugins ok",
        s_aethertrace_plugin_errors: "Dump core plugin errors",
        s_aethertrace_open_files: "Dump core open files/sockets",
        s_aethertrace_command_buffers: "Dump core command buffers",
        s_aethertrace_hidden_processes: "Dump core hidden processes",
        s_aethertrace_shell_history: "Dump core shell history",
        s_aethertrace_network: "Dump core network artifacts",
        s_aethertrace_suspicious_connections: "Dump core suspicious connections",
        s_aethertrace_injected_code: "Dump core injected code",
        s_aethertrace_suspicious_dll: "Dump core suspicious DLL",
        s_aethertrace_modified_memory: "Dump core modified memory",
        s_aethertrace_event_correlations: "Dump core event correlations",
        s_aethertrace_lolbin_abuse: "Dump core LOLBIN abuse",
        s_aethertrace_javaw_betatest: "Dump core javaw betatest",
        s_aethertrace_proxy_bypass: "Dump core proxy bypass",
        s_aethertrace_risk_verdicts: "Dump core risk verdicts",
        s_allpe: "allpe",
        s_normal_pe: "NormalPE",
        s_scripts: "Scripts",
        s_beta: "Beta",
        s_file_dates: "File dates",
        s_dps: "DPS rows",
        s_started: "Started files",
        s_prefetch: "Prefetch",
        s_otherdisk: "OtherDisk",
        s_deleted: "Deleted",
        s_trash_deleted: "Trash deleted",
        s_resolved_names: "Resolved names",
        s_not_found_full: "NotFound full paths",
        s_not_found_names: "NotFound names",
        s_suspend_links: "Suspicious links",
        s_download_links: "Download links",
        s_suspect_files: "Suspicious files",
        s_yara_targets: "YARA targets",
        s_yara: "YARA detects",
        s_java_paths: "Java/JAR paths",
        s_remote_access_tools: "Cheat artifacts (beta)",
        s_analysis_tools: "Bypass artifacts (beta)",
        s_credential_access: "Artifact wipe (beta)",
        s_network_tunnels: "Data hiding (beta)",
        s_remote_domains: "Trail obfuscation (beta)",
        s_tunnel_domains: "Tool attacks (beta)",
        s_remote_sessions: "Persistence (beta)",
        s_persistence: "Credential access (beta)",
        s_anti_forensics: "Anti-forensics (beta)",
        s_lolbas: "Beta misc",
        s_domain_frequency: "Domain frequency",
        s_suspicious_domains: "Suspicious domains",
        s_triage_priority: "Priority triage hits (beta)"
      },
      ru: {
        title: "Residence Screenshare - RSS-Analys",
        subtitle: "Результаты анализа.",
        titlePrefix: "Residence Screenshare - ",
        titleDiscord: "Residence Screenshare",
        pageStrings: "Strings core",
        pageMemory: "Dump core",
        pageMemoryBeta: "Results (beta)",
        search: "Поиск по текущей вкладке...",
        empty: "Нет данных",
        items: "Элементы",
        filtered: "Отфильтровано",
        shown: "Показано",
        diskFilters: "Исключить по диску:",
        resetFilters: "Сброс фильтров",
        excludeDisk: "Исключить",
        excludeWords: "Исключить слова:",
        excludeWordsHint: "github discord telegram",
        statusFilter: "Статус:",
        statusAll: "Все",
        statusDeleted: "Только deleted",
        statusAlive: "Только no deleted",
        signalFilter: "Сигнал:",
        signalAll: "Все",
        signalHigh: "Только high",
        signalMedium: "Только medium",
        summary: "Сводка",
        quickTriage: "Быстрый triage",
        inputFiles: "Входные файлы",
        dmpFiles: "Конвертированные DMP",
        memoryHead: "Dump core engine",
        memoryOpenHead: "Открытые файлы / сокеты",
        memoryBuffersHead: "Буферы команд (ввод/вывод)",
        memoryHiddenProcHead: "Кандидаты в скрытые/закрытые процессы",
        memoryShellHead: "История CMD/PowerShell",
        memoryNetworkHead: "Сетевые артефакты",
        memoryConnHead: "Подозрительные соединения",
        memoryInjectHead: "Инъекционный / скрытый код",
        memoryDllHead: "Подозрительные DLL",
        memoryModHead: "Модифицированные области памяти",
        memoryErrorHead: "Ошибки плагинов / заметки",
        memoryRunner: "Runner",
        memoryFiltersSignal: "Сигнал:",
        memoryFiltersSource: "Источник:",
        memoryFiltersMarker: "Тип:",
        memoryFiltersSign: "Подпись:",
        memoryFiltersTrust: "Доверие пути:",
        memoryFiltersSort: "Сортировка:",
        memoryAllSources: "Все источники",
        memoryAllMarkers: "Все типы",
        memoryAllSigns: "Все статусы подписи",
        memoryAllTrust: "Все уровни доверия",
        memorySortSignalDesc: "Сигнал (high->low)",
        memorySortSourceAsc: "Источник (A->Z)",
        memorySortMarkerAsc: "Тип (A->Z)",
        memorySortTimeDesc: "Время (new->old)",
        memoryColIndex: "No.",
        memoryColSignal: "Сигнал",
        memoryColSource: "Источник",
        memoryColTag: "Тип",
        memoryColEntity: "Сущность",
        memoryColFile: "Файл",
        memoryColSign: "Подпись",
        memoryColTrust: "Доверие пути",
        memoryColTime: "Время",
        memoryColDetails: "Детали",
        memorySignalHigh: "High",
        memorySignalMedium: "Medium",
        memorySignalLow: "Low",
        memoryEntityNone: "n/a",
        memoryTimeUnknown: "n/a",
        memorySignSigned: "signed",
        memorySignUnsigned: "unsigned",
        memorySignUnknown: "unknown",
        memoryTrustSystem: "system",
        memoryTrustProgram: "program",
        memoryTrustUser: "user-writable",
        memoryTrustTemp: "temp/cache",
        memoryTrustUnknown: "unknown",
        memoryPageLabel: "Страница",
        memoryPrev: "Назад",
        memoryNext: "Вперед",
        memoryRowsPerPage: "Строк/страница:",
        discord: "Discord",
        themeLight: "Светлая тема",
        themeDark: "Темная тема",
        file: "Файл",
        program: "Программа",
        rule: "Правило",
        keyword: "Ключевое слово",
        host: "Хост",
        time: "Время",
        clean: "Нет детектов",
        parseError: "Служебная строка",
        tab_summary: "Сводка",
        tab_triage_priority: "Приоритетный triage (beta)",
        tab_custom_hits: "Кастомные совпадения",
        tab_allpe: "All PE",
        tab_normalpe: "Normal PE",
        tab_scripts: "Скрипты",
        tab_beta: "Beta",
        tab_file_dates: "Файлы с датами",
        tab_dps: "DPS",
        tab_start: "Запущенные файлы",
        tab_prefetch: "Prefetch",
        tab_otherdisk: "OtherDisk",
        tab_deleted: "Удаленные",
        tab_trashdeleted: "Треш удаленных",
        tab_files_without_path: "Файлы без пути (найдены)",
        tab_notfound_full: "NotFound пути",
        tab_notfound_names: "NotFound имена",
        tab_links: "Ссылки",
        tab_download_links: "Ссылки на загрузку",
        tab_suspend_links: "Подозрительные ссылки",
        tab_suspect_file: "Подозрительные файлы",
        tab_yara: "YARA детекты",
        tab_java_paths: "Java/JAR пути",
        tab_regdel: "RegKeyDeletion",
        tab_replaceclean: "ReplaceClean",
        tab_fileless: "FilelessExecution",
        tab_dll: "DLL",
        tab_forfiles_wmic: "ForfilesWmic",
        tab_java_batch: "JavaBatchExecution",
        tab_ioc: "Командные IOC",
        tab_remote_access_tools: "Чит-артефакты (beta)",
        tab_analysis_tools: "Байпас-артефакты (beta)",
        tab_credential_access: "Очистка следов (beta)",
        tab_network_tunnels: "Скрытие данных (beta)",
        tab_remote_domains: "Маскировка следов (beta)",
        tab_tunnel_domains: "Атаки на инструменты (beta)",
        tab_remote_sessions: "Персистентность (beta)",
        tab_persistence: "Доступ к учеткам (beta)",
        tab_anti_forensics: "Анти-форензика (beta)",
        tab_lolbas: "Beta misc",
        tab_domain_frequency: "Частота доменов",
        tab_suspicious_domains: "Подозрительные домены",
        tab_memory_summary: "Сводка Dump core",
        tab_memory_high_signal: "High signal (merged)",
        tab_memory_results_beta: "Results (beta)",
        tab_memory_proxy_bypass: "Proxy bypass",
        tab_memory_risk_verdicts: "Риск-вердикты",
        tab_memory_betatest: "betatest",
        tab_memory_event_corr: "Корреляции событий",
        tab_memory_lolbin: "LOLBIN abuse",
        tab_memory_open: "Открытые файлы / сокеты",
        tab_memory_buffers: "Буферы команд",
        tab_memory_hidden: "Скрытые процессы",
        tab_memory_shell: "История shell",
        tab_memory_network: "Сетевые артефакты",
        tab_memory_connections: "Подозрительные соединения",
        tab_memory_injected: "Инъекции кода",
        tab_memory_dll: "Подозрительные DLL",
        tab_memory_modified: "Измененная память",
        tab_memory_notes: "Заметки движка",
        s_inputs: "Входные TXT",
        s_dmps: "DMP источники",
        s_links: "Ссылки",
        s_regdel: "RegKeyDeletion",
        s_replace: "ReplaceClean",
        s_fileless: "FilelessExecution",
        s_dll: "DLL",
        s_forfiles: "ForfilesWmic",
        s_java_batch: "JavaBatchExecution",
        s_ioc: "Командные IOC",
        s_custom_rules: "Кастомные правила",
        s_custom_hit_files: "Файлы с совпадениями",
        s_custom_hits: "Всего совпадений",
        s_process_scanned: "Просканировано процессов",
        s_process_skipped: "Пропущено процессов",
        s_process_dumps: "Дампы процессов",
        s_aethertrace_enabled: "Dump core включен",
        s_aethertrace_dumps: "Dump core дампы",
        s_aethertrace_plugins_ok: "Dump core плагинов ok",
        s_aethertrace_plugin_errors: "Dump core ошибок плагинов",
        s_aethertrace_open_files: "Dump core файлы/сокеты",
        s_aethertrace_command_buffers: "Dump core буферы команд",
        s_aethertrace_hidden_processes: "Dump core скрытые процессы",
        s_aethertrace_shell_history: "Dump core история shell",
        s_aethertrace_network: "Dump core сеть",
        s_aethertrace_suspicious_connections: "Dump core подозрительные соединения",
        s_aethertrace_injected_code: "Dump core инъекции кода",
        s_aethertrace_suspicious_dll: "Dump core подозрительные DLL",
        s_aethertrace_modified_memory: "Dump core измененная память",
        s_aethertrace_event_correlations: "Dump core корреляции событий",
        s_aethertrace_lolbin_abuse: "Dump core LOLBIN abuse",
        s_aethertrace_javaw_betatest: "Dump core javaw betatest",
        s_aethertrace_proxy_bypass: "Dump core proxy bypass",
        s_aethertrace_risk_verdicts: "Dump core риск-вердикты",
        s_allpe: "allpe",
        s_normal_pe: "NormalPE",
        s_scripts: "Скрипты",
        s_beta: "Beta",
        s_file_dates: "Файлы с датами",
        s_dps: "DPS строки",
        s_started: "Запущенные файлы",
        s_prefetch: "Prefetch",
        s_otherdisk: "OtherDisk",
        s_deleted: "Удаленные",
        s_trash_deleted: "Треш удаленных",
        s_resolved_names: "Найдено по имени",
        s_not_found_full: "NotFound полные пути",
        s_not_found_names: "NotFound имена",
        s_suspend_links: "Подозрительные ссылки",
        s_download_links: "Ссылки на загрузку",
        s_suspect_files: "Подозрительные файлы",
        s_yara_targets: "YARA цели",
        s_yara: "YARA детекты",
        s_java_paths: "Java/JAR пути",
        s_remote_access_tools: "Чит-артефакты (beta)",
        s_analysis_tools: "Байпас-артефакты (beta)",
        s_credential_access: "Очистка следов (beta)",
        s_network_tunnels: "Скрытие данных (beta)",
        s_remote_domains: "Маскировка следов (beta)",
        s_tunnel_domains: "Атаки на инструменты (beta)",
        s_remote_sessions: "Персистентность (beta)",
        s_persistence: "Доступ к учеткам (beta)",
        s_anti_forensics: "Анти-форензика (beta)",
        s_lolbas: "Beta misc",
        s_domain_frequency: "Частота доменов",
        s_suspicious_domains: "Подозрительные домены",
        s_triage_priority: "Приоритетные triage-совпадения (beta)"
      }
    };

    const THEME_STORE_KEY = "residence_report_theme";

    const state = {
      lang: resolveLang(),
      theme: resolveTheme(),
      page: "strings",
      tab: "summary",
      memoryTab: "memory_summary",
      query: "",
      dataPage: 1,
      dataPageSize: 300,
      excludeDisks: new Set(),
      excludeWords: "",
      statusFilter: "all",
      signalFilter: "all",
      memorySignalFilter: "all",
      memorySourceFilter: "all",
      memoryMarkerFilter: "all",
      memorySignFilter: "all",
      memoryTrustFilter: "all",
      memorySort: "signal_desc",
      memoryPage: 1,
      memoryPageSize: 150,
      tabRowsCache: {},
      tabRowsLowerCache: {},
      memoryBetaRowsCache: null,
      memoryHighRowsCache: null,
      memoryParsedCache: {},
      memoryVolumeLetterMap: {}
    };

    const STATUS_FILTER_TABS = new Set([
      "scripts",
      "start",
      "dps",
      "prefetch",
      "deleted",
      "trashdeleted"
    ]);

    const SIGNAL_FILTER_TABS = new Set([
      "triage_priority",
      "remote_access_tools",
      "analysis_tools",
      "credential_access",
      "network_tunnels",
      "remote_domains",
      "tunnel_domains",
      "remote_sessions",
      "persistence",
      "anti_forensics",
      "suspend_links",
      "suspect_file",
      "yara"
    ]);

    function resolveLang() {
      const stored = localStorage.getItem("residence_report_lang");
      if (stored === "ru" || stored === "en") {
        return stored;
      }
      if (DEFAULT_LANG === "ru" || DEFAULT_LANG === "en") {
        return DEFAULT_LANG;
      }
      const nav = (navigator.language || navigator.userLanguage || "").toLowerCase();
      if (nav.startsWith("ru")) {
        return "ru";
      }
      return "en";
    }

    function resolveTheme() {
      const stored = localStorage.getItem(THEME_STORE_KEY);
      if (stored === "dark" || stored === "light") {
        return stored;
      }
      try {
        if (typeof window.matchMedia === "function") {
          return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
        }
      } catch (_) {
      }
      return "dark";
    }

    function t(key) {
      const dict = I18N[state.lang] || I18N.en;
      return dict[key] || I18N.en[key] || key;
    }

    function applyTheme(theme) {
      const normalized = theme === "light" ? "light" : "dark";
      state.theme = normalized;
      document.documentElement.setAttribute("data-theme", normalized);
      const btn = document.getElementById("themeBtn");
      if (!btn) {
        return;
      }
      const nextTheme = normalized === "dark" ? "light" : "dark";
      const title = nextTheme === "light" ? t("themeLight") : t("themeDark");
      btn.innerHTML = normalized === "dark" ? "&#9728;" : "&#9790;";
      btn.title = title;
      btn.setAttribute("aria-label", title);
    }

    function tabLabel(key) {
      return t(`tab_${key}`);
    }

    function activeTabKey() {
      if (state.page === "memory" || state.page === "memory_beta") {
        return state.memoryTab;
      }
      return state.tab;
    }

    function activeDataTabKey() {
      return state.tab;
    }

    function rowsForMemoryTab(tab) {
      switch (tab) {
        case "memory_results_beta":
          return buildMemoryBetaRows();
        case "memory_high_signal":
          return buildMemoryHighSignalRows();
        case "memory_proxy_bypass":
          return DATA.memory.proxy_bypass || [];
        case "memory_risk_verdicts":
          return DATA.memory.risk_verdicts || [];
        case "memory_betatest":
          return DATA.memory.javaw_betatest || [];
        case "memory_event_corr":
          return DATA.memory.event_correlations || [];
        case "memory_lolbin":
          return DATA.memory.lolbin_abuse || [];
        case "memory_open":
          return DATA.memory.open_files_sockets || [];
        case "memory_buffers":
          return DATA.memory.command_buffers || [];
        case "memory_hidden":
          return DATA.memory.hidden_processes || [];
        case "memory_shell":
          return DATA.memory.shell_history || [];
        case "memory_network":
          return DATA.memory.network_artifacts || [];
        case "memory_connections":
          return DATA.memory.suspicious_connections || [];
        case "memory_injected":
          return DATA.memory.injected_code || [];
        case "memory_dll":
          return DATA.memory.suspicious_dll || [];
        case "memory_modified":
          return DATA.memory.modified_memory || [];
        case "memory_notes": {
          const out = [];
          if (DATA.memory.runner) {
            out.push(`${t("memoryRunner")}: ${DATA.memory.runner}`);
          }
          out.push(...(DATA.memory.notes || []));
          out.push(...(DATA.memory.plugin_errors || []));
          return out;
        }
        default:
          return [];
      }
    }

    function buildMemoryBetaRows() {
      if (Array.isArray(state.memoryBetaRowsCache)) {
        return state.memoryBetaRowsCache;
      }
      const out = new Set();
      const strongRe = /writeprocessmemory|createremotethread|ntcreatethreadex|manualmap|shellcode|process hollow|hollow|inject|kdmapper|keyauth|unknowncheats|download\?key=|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|encodedcommand|appinit_dlls|knowndlls|silentprocessexit|ifeo|eventid=7045|eventid=4672|webhook|reverse shell|meterpreter|beacon|ngrok|cloudflared|tailscale|zerotier|wireguard|proxy-bypass|minecraft_local_proxy|risk-verdict|verdict=bypass/i;
      const noteRe = /\[event:|\[persistence\]|\[minecraft\]|taskscheduler|silentprocessexit|ifeo|appinit_dlls|knowndlls/i;
      const addAll = (rows, re = null) => {
        for (const raw of rows || []) {
          const line = sanitizeUiLine(raw);
          if (!line) {
            continue;
          }
          if (re && !re.test(line)) {
            continue;
          }
          if (isLikelyBenignBetaRow(line)) {
            continue;
          }
          out.add(line);
        }
      };

      addAll(DATA.memory.suspicious_connections);
      addAll(DATA.memory.injected_code);
      addAll(DATA.memory.suspicious_dll);
      addAll(DATA.memory.modified_memory);
      addAll(DATA.memory.hidden_processes, /(hidden process|terminated process|activeprocesslinks|eprocess|ghost|orphan|hollow|pid)/i);
      addAll(DATA.memory.command_buffers, strongRe);
      addAll(DATA.memory.shell_history, strongRe);
      addAll(DATA.memory.network_artifacts, strongRe);
      addAll(DATA.memory.event_correlations);
      addAll(DATA.memory.lolbin_abuse);
      addAll(DATA.memory.javaw_betatest);
      addAll(DATA.memory.proxy_bypass);
      addAll(DATA.memory.risk_verdicts);
      addAll(DATA.memory.notes, noteRe);

      const oldCoreTabs = [
        "triage_priority",
        "remote_access_tools",
        "analysis_tools",
        "credential_access",
        "network_tunnels",
        "remote_domains",
        "tunnel_domains",
        "remote_sessions",
        "persistence",
        "anti_forensics",
        "suspend_links",
        "suspect_file",
        "yara"
      ];
      for (const tab of oldCoreTabs) {
        for (const raw of DATA.tabs[tab] || []) {
          const line = sanitizeUiLine(raw);
          if (!line) {
            continue;
          }
          if (!strongRe.test(line) && tab !== "triage_priority" && tab !== "yara") {
            continue;
          }
          if (isLikelyBenignBetaRow(line)) {
            continue;
          }
          out.add(`[strings-core] [${tab}] ${line}`);
        }
      }
      state.memoryBetaRowsCache = Array.from(out);
      return state.memoryBetaRowsCache;
    }

    function buildMemoryHighSignalRows() {
      if (Array.isArray(state.memoryHighRowsCache)) {
        return state.memoryHighRowsCache;
      }
      const out = new Set();
      const strongRe = /writeprocessmemory|createremotethread|ntcreatethreadex|manualmap|shellcode|process hollow|hollow|inject|kdmapper|keyauth|unknowncheats|download\?key=|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|encodedcommand|appinit_dlls|knowndlls|silentprocessexit|ifeo|eventid=7045|eventid=4672|webhook|reverse shell|meterpreter|beacon|proxy-bypass|minecraft_local_proxy|verdict=bypass|verdict=cheat|cheat|bypass/i;
      const addAll = (rows, re = null) => {
        for (const raw of rows || []) {
          const line = sanitizeUiLine(raw);
          if (!line || /^no\s+/i.test(line)) {
            continue;
          }
          if (re && !re.test(line)) {
            continue;
          }
          if (isLikelyBenignBetaRow(line)) {
            continue;
          }
          out.add(line);
        }
      };
      addAll(DATA.memory.proxy_bypass);
      addAll(DATA.memory.risk_verdicts);
      addAll(DATA.memory.injected_code);
      addAll(DATA.memory.suspicious_connections);
      addAll(DATA.memory.suspicious_dll);
      addAll(DATA.memory.modified_memory);
      addAll(DATA.memory.hidden_processes, /(hidden process|terminated process|activeprocesslinks|eprocess|hollow|orphan|ghost)/i);
      addAll(DATA.memory.command_buffers, strongRe);
      addAll(DATA.memory.shell_history, strongRe);
      addAll(DATA.memory.network_artifacts, strongRe);
      addAll(DATA.memory.event_correlations, /eventid=7045|eventid=4672|eventid=4688|logonid=|proxy-bypass|minecraft_local_proxy/i);
      addAll(DATA.memory.javaw_betatest, strongRe);
      addAll(DATA.memory.lolbin_abuse, strongRe);
      state.memoryHighRowsCache = Array.from(out);
      return state.memoryHighRowsCache;
    }

    function isLikelyBenignBetaRow(line) {
      const lower = String(line || "").toLowerCase();
      if (!lower) {
        return true;
      }
      const hasStrongSignal =
        /writeprocessmemory|createremotethread|ntcreatethreadex|manualmap|shellcode|process hollow|inject|kdmapper|keyauth|unknowncheats|download\?key=|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|encodedcommand|appinit_dlls|knowndlls|silentprocessexit|ifeo|eventid=7045|eventid=4672|webhook|reverse shell|meterpreter|beacon|ngrok|cloudflared|tailscale|zerotier|wireguard|hollow|bypass|cheat|proxy-bypass|minecraft_local_proxy|verdict=bypass/i.test(lower);
      if (hasStrongSignal) {
        return false;
      }
      if (lower.includes("thirdpartynotices.txt")) {
        return true;
      }
      if (lower.includes("\\.cargo\\registry\\") || lower.includes("\\target\\debug\\") || lower.includes("\\target\\release\\")) {
        return true;
      }
      if (lower.includes("\\microsoft visual studio\\") || lower.includes("\\windows kits\\")) {
        return true;
      }
      if (lower.includes("\\knownDlls\\ntdll.dll".toLowerCase()) || lower.includes("\\knowndlls\\kernel32.dll")) {
        return true;
      }
      return false;
    }

    function rowsForCurrentTab() {
      if (state.page === "memory" || state.page === "memory_beta") {
        return rowsForMemoryTab(state.memoryTab)
          .map((line) => sanitizeUiLine(line))
          .filter((line) => line.length > 0);
      }
      if (state.tab === "summary") {
        return [];
      }
      if (!state.tabRowsCache[state.tab]) {
        const rows = (DATA.tabs[state.tab] || [])
          .map((line) => sanitizeUiLine(line))
          .filter((line) => line.length > 0);
        state.tabRowsCache[state.tab] = rows;
        state.tabRowsLowerCache[state.tab] = null;
      }
      return state.tabRowsCache[state.tab];
    }

    function sanitizeUiLine(line) {
      return String(line || "")
        .replace(/[\u0000-\u001F\u007F]+/g, " ")
        .replace(/\s{2,}/g, " ")
        .trim();
    }

    function applySearch(rows) {
      const q = state.query.trim().toLowerCase();
      if (!q) {
        return rows;
      }
      if (state.page === "strings" && state.tab !== "summary") {
        const cachedRows = state.tabRowsCache[state.tab];
        if (cachedRows === rows) {
          let cachedLower = state.tabRowsLowerCache[state.tab];
          if (!Array.isArray(cachedLower) || cachedLower.length !== rows.length) {
            cachedLower = rows.map((line) => line.toLowerCase());
            state.tabRowsLowerCache[state.tab] = cachedLower;
          }
          const out = [];
          for (let i = 0; i < rows.length; i += 1) {
            if (cachedLower[i].includes(q)) {
              out.push(rows[i]);
            }
          }
          return out;
        }
      }
      return rows.filter((line) => line.toLowerCase().includes(q));
    }

    function disksInLine(line) {
      const out = new Set();
      const raw = String(line || "");
      const re = /([A-Za-z])\s*:\s*[\\/]/g;
      let m = null;
      while ((m = re.exec(raw)) !== null) {
        out.add(m[1].toUpperCase());
      }
      return out;
    }

    function applyDiskFilter(rows) {
      if (state.page !== "strings" || !state.excludeDisks || state.excludeDisks.size === 0) {
        return rows;
      }
      return rows.filter((line) => {
        const lineDisks = disksInLine(line);
        for (const disk of state.excludeDisks) {
          if (lineDisks.has(disk)) {
            return false;
          }
        }
        return true;
      });
    }

    function parseExcludeTokens(raw) {
      return String(raw || "")
        .toLowerCase()
        .split(/[,\s]+/)
        .map((x) => x.trim())
        .filter(Boolean);
    }

    function applySuspendLinksExclude(rows) {
      if (state.page !== "strings" || state.tab !== "suspend_links") {
        return rows;
      }
      const tokens = parseExcludeTokens(state.excludeWords);
      if (tokens.length === 0) {
        return rows;
      }
      return rows.filter((line) => {
        const lower = String(line || "").toLowerCase();
        return !tokens.some((token) => lower.includes(token));
      });
    }

    function rowStatusKind(tab, line) {
      const lower = String(line || "").toLowerCase();
      if (tab === "prefetch" || tab === "scripts" || tab === "start" || tab === "dps" || tab === "deleted" || tab === "trashdeleted") {
        if (lower.includes("no deleted")) {
          return "alive";
        }
        if (lower.includes("deleted") || lower.includes("missing")) {
          return "deleted";
        }
      }
      return "other";
    }

    function applyStatusFilter(rows) {
      if (state.page !== "strings" || !STATUS_FILTER_TABS.has(state.tab) || state.statusFilter === "all") {
        return rows;
      }
      return rows.filter((line) => rowStatusKind(state.tab, line) === state.statusFilter);
    }

    function signalForRow(tab, line) {
      const lower = String(line || "").toLowerCase();
      const highSignals = [
        "writeprocessmemory","createremotethread","ntcreatethreadex","manualmap","shellcode",
        "process hollow","kdmapper","xenos","keyauth","unknowncheats","mimikatz","nanodump",
        "wevtutil","vssadmin","bcdedit","wmic","reg add","reg delete","invoke-webrequest",
        "invoke-restmethod","downloadstring","downloadfile","encodedcommand","appinit_dlls",
        "silentprocessexit","ifeo","eventid=7045","eventid=4672","proxy-bypass",
        "minecraft_local_proxy","verdict=bypass","cheat","bypass"
      ];
      if (highSignals.some((k) => lower.includes(k))) {
        return "high";
      }
      const mediumSignals = [
        "proxyenable","proxyserver","autoconfigurl","eventid=4688","eventid=4624","eventid=4625",
        "websocket","wss://","rdp","mstsc","ngrok","cloudflared","tailscale","zerotier","wireguard"
      ];
      if (mediumSignals.some((k) => lower.includes(k))) {
        return "medium";
      }
      return "low";
    }

    function applySignalFilter(rows) {
      if (state.page !== "strings" || !SIGNAL_FILTER_TABS.has(state.tab) || state.signalFilter === "all") {
        return rows;
      }
      return rows.filter((line) => signalForRow(state.tab, line) === state.signalFilter);
    }

    function applyAllFilters(rows) {
      let out = rows;
      out = applySearch(out);
      out = applyDiskFilter(out);
      out = applySuspendLinksExclude(out);
      out = applyStatusFilter(out);
      out = applySignalFilter(out);
      return out;
    }

    function splitOnce(text, sep) {
      const idx = String(text).indexOf(sep);
      if (idx === -1) {
        return [text, ""];
      }
      return [text.slice(0, idx), text.slice(idx + sep.length)];
    }

    function firstKeyword(line) {
      const lower = String(line || "").toLowerCase();
      for (const kw of SUSPICIOUS_KWS) {
        if (lower.includes(String(kw).toLowerCase())) {
          return String(kw);
        }
      }
      return "";
    }

    function fileNameFromPath(path) {
      const normalized = String(path || "").replaceAll("\\\\", "/");
      const parts = normalized.split("/");
      return parts[parts.length - 1] || path;
    }

    function extFromName(name) {
      const i = String(name).lastIndexOf(".");
      if (i < 0 || i === name.length - 1) {
        return "";
      }
      return name.slice(i + 1).toUpperCase();
    }

    function hostFromLink(link) {
      try {
        const withScheme = link.includes("://") ? link : `https://${link}`;
        const u = new URL(withScheme);
        return u.hostname || "";
      } catch (_) {
        return "";
      }
    }

    function parsePipeParts(line) {
      return String(line || "").split(" | ").map((x) => x.trim()).filter((x) => x.length > 0);
    }

    function parseStructuredRow(tab, line) {
      if (line.startsWith("No ")) {
        return { left: line, badges: [{ text: t("clean"), tone: "ok" }] };
      }
      if (tab === "triage_priority") {
        const parts = parsePipeParts(line);
        if (parts.length >= 4) {
          return {
            left: parts.slice(3).join(" | ") || line,
            badges: [
              { text: parts[0], tone: "info" },
              { text: parts[1], tone: "danger" },
              { text: parts[2], tone: "warn" }
            ]
          };
        }
      }
      if (tab === "yara") {
        const [file, rulesRaw] = splitOnce(line, " | ");
        const rules = rulesRaw
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean);
        return {
          left: file || line,
          badges: rules.length
            ? rules.map((r) => ({ text: `${t("rule")}: ${r}`, tone: "danger" }))
            : [{ text: t("rule"), tone: "danger" }]
        };
      }
      if (
        tab === "remote_access_tools" ||
        tab === "analysis_tools" ||
        tab === "credential_access" ||
        tab === "network_tunnels" ||
        tab === "remote_domains" ||
        tab === "tunnel_domains" ||
        tab === "remote_sessions" ||
        tab === "persistence" ||
        tab === "anti_forensics"
      ) {
        const parts = parsePipeParts(line);
        if (parts.length >= 3) {
          return {
            left: parts.slice(2).join(" | "),
            badges: [
              { text: parts[0], tone: "info" },
              { text: parts[1], tone: "warn" }
            ]
          };
        }
      }
      if (tab === "download_links") {
        const [hostRaw, rest] = splitOnce(line, " | ");
        const [file, link] = splitOnce(rest, " | ");
        const ext = extFromName(file);
        const badges = [];
        if (hostRaw) badges.push({ text: `${t("host")}: ${hostRaw}`, tone: "info" });
        if (file) badges.push({ text: `${t("file")}: ${file}`, tone: "warn" });
        if (ext) badges.push({ text: ext, tone: "danger" });
        return { left: link || line, badges };
      }
      if (tab === "suspect_file") {
        const file = fileNameFromPath(line);
        const ext = extFromName(file);
        const kw = firstKeyword(file || line);
        const badges = [];
        if (kw) badges.push({ text: `${t("keyword")}: ${kw}`, tone: "warn" });
        if (ext) badges.push({ text: ext, tone: "danger" });
        return { left: line, badges };
      }
      return { left: line, badges: [] };
    }

    function renderStructuredRows(tab, rows) {
      const container = document.getElementById("rowView");
      container.textContent = "";
      const fragment = document.createDocumentFragment();
      for (const line of rows) {
        const model = parseStructuredRow(tab, line);
        if (!model) {
          continue;
        }
        const item = document.createElement("article");
        item.className = "row-item";

        const left = document.createElement("div");
        left.className = "row-left";
        left.textContent = model.left || line;
        item.appendChild(left);

        const right = document.createElement("div");
        right.className = "row-right";
        for (const badgeModel of model.badges || []) {
          const b = document.createElement("span");
          b.className = `badge badge-${badgeModel.tone || "info"}`;
          b.textContent = badgeModel.text;
          right.appendChild(b);
        }
        item.appendChild(right);
        fragment.appendChild(item);
      }
      container.appendChild(fragment);
    }

    function renderTabs() {
      const host = document.getElementById("tabs");
      host.textContent = "";
      let order = TAB_ORDER;
      if (state.page === "memory" || state.page === "memory_beta") {
        order = MEMORY_TAB_ORDER;
      }
      const active = activeTabKey();
      for (const key of order) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "tab" + (active === key ? " active" : "");
        b.textContent = tabLabel(key);
        b.addEventListener("click", () => {
          if (state.page === "memory" || state.page === "memory_beta") {
            state.memoryTab = key;
            state.memorySignalFilter = "all";
            state.memorySourceFilter = "all";
            state.memoryMarkerFilter = "all";
            state.memorySignFilter = "all";
            state.memoryTrustFilter = "all";
            state.memorySort = "signal_desc";
            state.memoryPage = 1;
          } else {
            state.tab = key;
            state.dataPage = 1;
          }
          state.statusFilter = "all";
          state.signalFilter = "all";
          render();
        });
        host.appendChild(b);
      }
    }

    function renderDiskFilters(allRows) {
      const host = document.getElementById("diskFilters");
      if (!host) {
        return;
      }
      if (state.page !== "strings" || state.tab === "summary") {
        host.textContent = "";
        host.classList.add("hide");
        return;
      }

      const present = new Set();
      for (const row of allRows) {
        for (const d of disksInLine(row)) {
          present.add(d);
        }
      }

      const base = ["C", "D", "E", "F", "G", "H", "X", "Z", "A", "B"];
      const drives = Array.from(new Set([...base, ...present])).sort();
      const showDisk = drives.length > 0;
      const showSuspendExclude = state.tab === "suspend_links";
      const showStatusFilter = STATUS_FILTER_TABS.has(state.tab);
      const showSignalFilter = SIGNAL_FILTER_TABS.has(state.tab);
      if (!showDisk && !showSuspendExclude && !showStatusFilter && !showSignalFilter) {
        host.textContent = "";
        host.classList.add("hide");
        return;
      }

      host.textContent = "";
      host.classList.remove("hide");

      const reset = document.createElement("button");
      reset.type = "button";
      reset.className = "filter-chip";
      reset.textContent = t("resetFilters");
      reset.addEventListener("click", () => {
        state.excludeDisks.clear();
        state.excludeWords = "";
        state.statusFilter = "all";
        state.signalFilter = "all";
        state.dataPage = 1;
        renderData();
      });
      host.appendChild(reset);

      if (showDisk) {
        const title = document.createElement("span");
        title.className = "filter-title";
        title.textContent = t("diskFilters");
        host.appendChild(title);

        for (const drive of drives) {
          const b = document.createElement("button");
          b.type = "button";
          const selected = state.excludeDisks.has(drive);
          b.className = `filter-chip${selected ? " active" : ""}${present.has(drive) ? "" : " muted"}`;
          b.textContent = `${t("excludeDisk")} ${drive}:`;
          b.addEventListener("click", () => {
            if (state.excludeDisks.has(drive)) {
              state.excludeDisks.delete(drive);
            } else {
              state.excludeDisks.add(drive);
            }
            state.dataPage = 1;
            renderData();
          });
          host.appendChild(b);
        }
      }

      if (showSuspendExclude) {
        const title = document.createElement("span");
        title.className = "filter-title";
        title.textContent = t("excludeWords");
        host.appendChild(title);

        const input = document.createElement("input");
        input.type = "search";
        input.className = "filter-input";
        input.placeholder = t("excludeWordsHint");
        input.value = state.excludeWords || "";
        input.addEventListener("input", (e) => {
          state.excludeWords = e.target.value || "";
          state.dataPage = 1;
          renderData(true);
        });
        host.appendChild(input);
      }

      if (showStatusFilter) {
        const title = document.createElement("span");
        title.className = "filter-title";
        title.textContent = t("statusFilter");
        host.appendChild(title);

        const options = [
          { key: "all", label: t("statusAll") },
          { key: "deleted", label: t("statusDeleted") },
          { key: "alive", label: t("statusAlive") }
        ];
        for (const opt of options) {
          const b = document.createElement("button");
          b.type = "button";
          b.className = `filter-chip${state.statusFilter === opt.key ? " active" : ""}`;
          b.textContent = opt.label;
          b.addEventListener("click", () => {
            state.statusFilter = opt.key;
            state.dataPage = 1;
            renderData();
          });
          host.appendChild(b);
        }
      }

      if (showSignalFilter) {
        const title = document.createElement("span");
        title.className = "filter-title";
        title.textContent = t("signalFilter");
        host.appendChild(title);

        const options = [
          { key: "all", label: t("signalAll") },
          { key: "high", label: t("signalHigh") },
          { key: "medium", label: t("signalMedium") }
        ];
        for (const opt of options) {
          const b = document.createElement("button");
          b.type = "button";
          b.className = `filter-chip${state.signalFilter === opt.key ? " active" : ""}`;
          b.textContent = opt.label;
          b.addEventListener("click", () => {
            state.signalFilter = opt.key;
            state.dataPage = 1;
            renderData();
          });
          host.appendChild(b);
        }
      }
    }

    function summaryCountForTab(tabKey) {
      const sumKey = QUICK_TAB_SUMMARY_KEY[tabKey] || tabKey;
      return Number(DATA.summary[sumKey] || 0);
    }

    function renderQuickTriage() {
      const grid = document.getElementById("quickGrid");
      if (!grid) {
        return;
      }
      grid.textContent = "";
      for (const tabKey of QUICK_TABS) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "card quick-card";
        btn.addEventListener("click", () => {
          state.tab = tabKey;
          state.dataPage = 1;
          state.statusFilter = "all";
          state.signalFilter = "all";
          render();
        });

        const title = document.createElement("p");
        title.className = "k";
        title.textContent = tabLabel(tabKey);

        const value = document.createElement("p");
        value.className = "v";
        value.textContent = String(summaryCountForTab(tabKey));

        btn.appendChild(title);
        btn.appendChild(value);
        grid.appendChild(btn);
      }
    }

    function renderSummary() {
      const grid = document.getElementById("summaryGrid");
      grid.textContent = "";
      const keys = [
        "inputs","dmps","links","regdel","replace","fileless","dll","forfiles",
        "java_batch","ioc","custom_rules","custom_hit_files","custom_hits",
        "process_scanned","process_skipped","process_dumps","allpe","normal_pe",
        "aethertrace_enabled","aethertrace_dumps","aethertrace_plugins_ok","aethertrace_plugin_errors",
        "aethertrace_open_files","aethertrace_command_buffers","aethertrace_hidden_processes",
        "aethertrace_shell_history","aethertrace_network","aethertrace_suspicious_connections",
        "aethertrace_injected_code","aethertrace_suspicious_dll","aethertrace_modified_memory",
        "aethertrace_event_correlations","aethertrace_lolbin_abuse","aethertrace_javaw_betatest",
        "aethertrace_proxy_bypass","aethertrace_risk_verdicts",
        "scripts","beta","file_dates","dps","started","prefetch","deleted","trash_deleted","resolved_names",
        "otherdisk",
        "not_found_full","not_found_names","suspend_links","download_links","suspect_files",
        "yara_targets","yara","java_paths",
        "remote_access_tools","analysis_tools","credential_access","network_tunnels",
        "remote_domains","tunnel_domains","remote_sessions","persistence","anti_forensics",
        "domain_frequency","suspicious_domains","triage_priority"
      ];
      for (const k of keys) {
        const card = document.createElement("article");
        card.className = "card";
        const pk = document.createElement("p");
        pk.className = "k";
        pk.textContent = t(`s_${k}`);
        const pv = document.createElement("p");
        pv.className = "v";
        pv.textContent = String(DATA.summary[k] || 0);
        card.appendChild(pk);
        card.appendChild(pv);
        grid.appendChild(card);
      }
      document.getElementById("inputsView").textContent = DATA.inputs.join("\n");
      document.getElementById("dmpsView").textContent = DATA.dmps.join("\n");
      renderQuickTriage();
    }

    function memorySignalRank(signal) {
      if (signal === "high") {
        return 3;
      }
      if (signal === "medium") {
        return 2;
      }
      return 1;
    }

    function memorySignalLabel(signal) {
      if (signal === "high") {
        return t("memorySignalHigh");
      }
      if (signal === "medium") {
        return t("memorySignalMedium");
      }
      return t("memorySignalLow");
    }

    function memorySectionDefaultSignal(tab) {
      if (
        tab === "memory_high_signal" ||
        tab === "memory_results_beta" ||
        tab === "memory_proxy_bypass" ||
        tab === "memory_risk_verdicts" ||
        tab === "memory_betatest" ||
        tab === "memory_lolbin" ||
        tab === "memory_connections" ||
        tab === "memory_injected" ||
        tab === "memory_dll" ||
        tab === "memory_modified" ||
        tab === "memory_hidden"
      ) {
        return "high";
      }
      if (tab === "memory_event_corr") {
        return "medium";
      }
      if (tab === "memory_buffers" || tab === "memory_shell") {
        return "medium";
      }
      if (tab === "memory_network") {
        return "low";
      }
      return "low";
    }

    function memorySectionMarker(tab) {
      const map = {
        memory_open: "open_files_sockets",
        memory_high_signal: "high_signal_merged",
        memory_results_beta: "beta_result",
        memory_proxy_bypass: "proxy_bypass",
        memory_risk_verdicts: "risk_verdict",
        memory_betatest: "javaw_betatest",
        memory_event_corr: "event_correlation",
        memory_lolbin: "lolbin_abuse",
        memory_buffers: "command_buffers",
        memory_hidden: "hidden_process",
        memory_shell: "shell_history",
        memory_network: "network_artifact",
        memory_connections: "suspicious_connection",
        memory_injected: "injected_code",
        memory_dll: "suspicious_dll",
        memory_modified: "modified_memory",
        memory_notes: "engine_note"
      };
      return map[tab] || "artifact";
    }

    function memoryNormalizeMarker(raw, tab) {
      const marker = String(raw || "").trim().toLowerCase();
      if (marker.startsWith("lolbin:")) {
        return marker.includes("high") ? "lolbin_abuse_high" : "lolbin_abuse_medium";
      }
      if (marker.startsWith("event-corr")) {
        return "event_correlation";
      }
      if (marker.startsWith("javaw-betatest")) {
        return "javaw_betatest";
      }
      if (marker.startsWith("risk-")) {
        return "risk_verdict";
      }
      if (marker.startsWith("event:")) {
        return `event_${marker.slice(6) || "generic"}`;
      }
      const map = {
        "open": "open_files_sockets",
        "buffer": "command_buffer",
        "process": "process_candidate",
        "shell": "shell_history",
        "net": "network_artifact",
        "susp-net": "suspicious_connection",
        "inject": "injected_code",
        "dll": "suspicious_dll",
        "mem": "modified_memory",
        "event": "event_trace",
        "persistence": "persistence_trace",
        "proxy": "proxy_trace",
        "proxy-bypass": "proxy_bypass",
        "rdp": "rdp_trace",
        "websocket": "websocket_trace",
        "search-index": "search_index",
        "thumbcache": "thumbcache_iconcache",
        "event-corr": "event_correlation",
        "javaw-betatest": "javaw_betatest",
        "lolbin-high": "lolbin_abuse_high",
        "lolbin-medium": "lolbin_abuse_medium",
        "risk-verdict": "risk_verdict",
        "risk-score": "risk_verdict",
        "risk-evidence": "risk_verdict",
        "comdlg32-mru": "comdlg32_mru",
        "user-mru": "user_mru",
        "minecraft": "minecraft_trace",
        "module": "module_artifact",
        "unloaded-module": "unloaded_module",
        "module-persistence": "module_persistence"
      };
      return map[marker] || marker || memorySectionMarker(tab);
    }

    function memoryResolveVolumeLetter(volumeId, hintText) {
      const key = String(volumeId || "").trim();
      if (!key) {
        return "C";
      }
      const existing = state.memoryVolumeLetterMap[key];
      if (existing) {
        return existing;
      }

      const used = new Set(Object.values(state.memoryVolumeLetterMap));
      const hint = String(hintText || "").toLowerCase();
      if (key === "3" && (!used.has("C") || state.memoryVolumeLetterMap[key] === "C")) {
        state.memoryVolumeLetterMap[key] = "C";
        return "C";
      }
      const hasSystemHint =
        hint.includes("\\windows\\") ||
        hint.includes("\\users\\") ||
        hint.includes("\\program files\\") ||
        hint.includes("\\programdata\\");
      if (hasSystemHint && (!used.has("C") || state.memoryVolumeLetterMap[key] === "C")) {
        state.memoryVolumeLetterMap[key] = "C";
        return "C";
      }

      const fallbackLetters = "DEFGHIJKLMNOPQRSTUVWXYZ".split("");
      for (const letter of fallbackLetters) {
        if (!used.has(letter)) {
          state.memoryVolumeLetterMap[key] = letter;
          return letter;
        }
      }
      state.memoryVolumeLetterMap[key] = "Z";
      return "Z";
    }

    function memoryNormalizeDevicePaths(text) {
      const source = String(text || "");
      if (!source) {
        return "";
      }
      const lower = source.toLowerCase();
      if (
        !lower.includes("harddiskvolume")
        && !lower.includes("\\??\\")
        && !lower.includes("\\\\?\\")
        && !lower.includes("\\global??\\")
        && !/[a-z]:\\/i.test(source)
      ) {
        return source;
      }

      let normalized = source.replace(/\//g, "\\");
      normalized = normalized.replace(/\\(?:\?\?|global\?\?)\\\s*([a-z])\s*:\s*\\*/ig, (full, drive) => {
        return `${String(drive || "").toUpperCase()}:\\`;
      });
      normalized = normalized.replace(/\\\\\?\\\s*([a-z])\s*:\s*\\*/ig, (full, drive) => {
        return `${String(drive || "").toUpperCase()}:\\`;
      });
      normalized = normalized.replace(/\\+device\\+harddiskvolume\s*(\d+)(?:\s*\\?\s*\d+)?(?:\s+[a-z0-9]+)?\s*\\*/ig, (full, volume) => {
        const drive = memoryResolveVolumeLetter(volume, lower);
        return `${drive}:\\`;
      });
      normalized = normalized.replace(/\\\\\?\\([a-z]):\\/ig, (_, drive) => `${String(drive || "").toUpperCase()}:\\`);
      normalized = normalized.replace(/\\\?\?\\([a-z]):\\/ig, (_, drive) => `${String(drive || "").toUpperCase()}:\\`);
      normalized = normalized.replace(/\\global\?\?\\([a-z]):\\/ig, (_, drive) => `${String(drive || "").toUpperCase()}:\\`);
      normalized = normalized.replace(/([a-z]):\\\1:\\/ig, (_, drive) => `${String(drive || "").toUpperCase()}:\\`);
      normalized = normalized.replace(/([a-z]):\\\s*([a-z]):\\/ig, (full, d1, d2) => {
        if (String(d1 || "").toLowerCase() === String(d2 || "").toLowerCase()) {
          return `${String(d1 || "").toUpperCase()}:\\`;
        }
        return full;
      });
      normalized = normalized.replace(/\s+\\([A-Za-z])/g, "\\$1");
      const unc = normalized.startsWith("\\\\");
      normalized = normalized.replace(/\\{2,}/g, "\\");
      if (unc && !normalized.startsWith("\\\\")) {
        normalized = `\\${normalized}`;
      }
      return normalized;
    }

    function memoryExtractTimestamp(text) {
      const raw = String(text || "");
      if (!raw) {
        return { label: "", epoch: 0 };
      }
      if (!/\d{4}|\d{2}\.\d{2}\.\d{4}|[+-]\d{4}/.test(raw)) {
        return { label: "", epoch: 0 };
      }
      const iso = /\b(20\d{2}-\d{2}-\d{2}[ t]\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:z)?)\b/i.exec(raw);
      if (iso) {
        const dt = new Date(iso[1].replace(" ", "T"));
        if (!Number.isNaN(dt.getTime())) {
          return { label: dt.toISOString().replace("T", " ").replace(".000Z", "Z"), epoch: dt.getTime() };
        }
      }
      const tzIso = /\b[+-]\d{4}\s+(20\d{2}-\d{2}-\d{2})\s+(\d{2}):(\d{2}):(\d{2})\b/.exec(raw);
      if (tzIso) {
        const [_, ymd, hh, mi, ss] = tzIso;
        const dt = new Date(`${ymd}T${hh}:${mi}:${ss}Z`);
        if (!Number.isNaN(dt.getTime())) {
          return { label: dt.toISOString().replace("T", " ").replace(".000Z", "Z"), epoch: dt.getTime() };
        }
      }
      const slashTs = /\b(20\d{2})\/(\d{2})\/(\d{2})-(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?\b/.exec(raw);
      if (slashTs) {
        const [_, yyyy, mm, dd, hh, mi, ss] = slashTs;
        const dt = new Date(Date.UTC(Number(yyyy), Number(mm) - 1, Number(dd), Number(hh), Number(mi), Number(ss)));
        if (!Number.isNaN(dt.getTime())) {
          return { label: dt.toISOString().replace("T", " ").replace(".000Z", "Z"), epoch: dt.getTime() };
        }
      }
      const plusTz = /\b(?:\+|-)\d{4}\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\b/.exec(raw);
      if (plusTz) {
        const m = /([+-]\d{2})(\d{2})\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}):(\d{2}):(\d{2})/.exec(plusTz[0]);
        if (m) {
          const [, oh, om, ymd, hh, mi, ss] = m;
          const dt = new Date(`${ymd}T${hh}:${mi}:${ss}${oh}:${om}`);
          if (!Number.isNaN(dt.getTime())) {
            return { label: dt.toISOString().replace("T", " ").replace(".000Z", "Z"), epoch: dt.getTime() };
          }
        }
      }
      const dmy = /\b(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?\b/.exec(raw);
      if (dmy) {
        const [_, dd, mm, yyyy, hh, mi, ss] = dmy;
        const dt = new Date(Date.UTC(Number(yyyy), Number(mm) - 1, Number(dd), Number(hh), Number(mi), Number(ss || "0")));
        if (!Number.isNaN(dt.getTime())) {
          return { label: dt.toISOString().replace("T", " ").replace(".000Z", "Z"), epoch: dt.getTime() };
        }
      }
      const epochMs = /\b(1[6-9]\d{11}|2[0-2]\d{11})\b/.exec(raw);
      if (epochMs) {
        const value = Number(epochMs[1]);
        if (Number.isFinite(value)) {
          const dt = new Date(value);
          if (!Number.isNaN(dt.getTime())) {
            return { label: dt.toISOString().replace("T", " ").replace(".000Z", "Z"), epoch: dt.getTime() };
          }
        }
      }
      const epochSec = /\b(1[6-9]\d{8}|2[0-2]\d{8})\b/.exec(raw);
      if (epochSec) {
        const value = Number(epochSec[1]) * 1000;
        if (Number.isFinite(value)) {
          const dt = new Date(value);
          if (!Number.isNaN(dt.getTime())) {
            return { label: dt.toISOString().replace("T", " ").replace(".000Z", "Z"), epoch: dt.getTime() };
          }
        }
      }
      return { label: "", epoch: 0 };
    }

    function memoryExtractFileName(value) {
      const text = String(value || "").trim();
      if (!text) {
        return "";
      }
      const normalized = memoryNormalizeDevicePaths(text).replace(/"/g, "");
      const m = /([^\\\/\s]+)$/.exec(normalized);
      if (!m) {
        return "";
      }
      const file = m[1] || "";
      if (!file.includes(".")) {
        return "";
      }
      return file;
    }

    function memoryPathTrust(path, message) {
      const text = `${String(path || "")} ${String(message || "")}`.toLowerCase();
      if (!text) {
        return { key: "unknown" };
      }
      if (text.includes("\\windows\\system32\\") || text.includes("\\windows\\syswow64\\") || text.includes("\\windows\\winsxs\\")) {
        return { key: "system" };
      }
      if (text.includes("\\program files\\") || text.includes("\\program files (x86)\\")) {
        return { key: "program" };
      }
      if (text.includes("\\temp\\") || text.includes("\\cache\\") || text.includes("\\appdata\\local\\temp\\")) {
        return { key: "temp" };
      }
      if (text.includes("\\users\\") || text.includes("\\appdata\\") || text.includes("\\downloads\\") || text.includes("\\desktop\\")) {
        return { key: "user" };
      }
      return { key: "unknown" };
    }

    function memoryTrustLabel(trustKey) {
      if (trustKey === "system") {
        return t("memoryTrustSystem");
      }
      if (trustKey === "program") {
        return t("memoryTrustProgram");
      }
      if (trustKey === "user") {
        return t("memoryTrustUser");
      }
      if (trustKey === "temp") {
        return t("memoryTrustTemp");
      }
      return t("memoryTrustUnknown");
    }

    function memorySignKey(path, message, trustKey) {
      const text = `${String(path || "")} ${String(message || "")}`.toLowerCase();
      if (!text) {
        return "unknown";
      }
      const hasBinExt = /\.((exe|dll|sys|drv))\b/i.test(text);
      if (!hasBinExt) {
        return "unknown";
      }
      if (trustKey === "system" || trustKey === "program") {
        return "signed";
      }
      if (trustKey === "user" || trustKey === "temp") {
        return "unsigned";
      }
      return "unknown";
    }

    function memorySignLabel(signKey) {
      if (signKey === "signed") {
        return t("memorySignSigned");
      }
      if (signKey === "unsigned") {
        return t("memorySignUnsigned");
      }
      return t("memorySignUnknown");
    }

    function memoryExtractFirstPath(text) {
      const quoted = /"((?:[a-z]:\\|\\\\\?\\|\\+device\\+harddiskvolume\d+(?:\s+[a-z0-9]+)?\s*\\|\\device\\harddiskvolume\s*\d+(?:\s*\\?\s*\d+)?\s*\\)[^"\r\n<>|]{3,520})"/i.exec(text);
      if (quoted) {
        return memoryNormalizeDevicePaths(quoted[1]);
      }
      const m = /(?:[a-z]:\\|\\\\\?\\|\\+device\\+harddiskvolume\d+(?:\s+[a-z0-9]+)?\s*\\|\\device\\harddiskvolume\s*\d+(?:\s*\\?\s*\d+)?\s*\\)[^\r\n"<>|]{3,520}/i.exec(text);
      return m ? memoryNormalizeDevicePaths(m[0].trim()) : "";
    }

    function memoryExtractEndpoint(text) {
      const url = /(?:https?|wss?|ftp):\/\/[^\s"'<>`]+/i.exec(text);
      if (url) {
        return url[0];
      }
      const ipPort = /(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}/.exec(text);
      if (ipPort) {
        return ipPort[0];
      }
      const hostPort = /\b[a-z0-9][a-z0-9.-]{1,252}\.[a-z]{2,63}:\d{2,5}\b/i.exec(text);
      return hostPort ? hostPort[0] : "";
    }

    function memoryExtractCommand(text) {
      const m = /(?:cmd(?:\.exe)?\s+\/[ck]|powershell(?:\.exe)?|pwsh(?:\.exe)?|reg\s+(?:add|delete|query)|wmic|schtasks|netsh|sc\s+(?:create|config|start|stop)\b).{0,200}/i.exec(text);
      return m ? m[0].trim() : "";
    }

    function memoryLooksTruncatedPath(path) {
      const raw = String(path || "").trim();
      if (!raw) {
        return true;
      }
      const lower = raw.toLowerCase();
      return /^[a-z]:\\program$/i.test(raw)
        || /^[a-z]:\\user$/i.test(raw)
        || /^[a-z]:\\users$/i.test(raw)
        || /^[a-z]:\\windows$/i.test(raw)
        || (lower.includes(":\\program") && !lower.includes(":\\program files") && !lower.includes(":\\programdata\\"));
    }

    function memoryExpandProgramFilesPath(text) {
      const normalized = memoryNormalizeDevicePaths(String(text || ""));
      const m = /(?:[a-z]:\\program files(?:\s*\(x86\))?\\)[^"\r\n<>|]{3,320}/i.exec(normalized);
      return m ? memoryNormalizeDevicePaths(m[0].trim()) : "";
    }

    function memorySelectEntity(message, endpoint, path, command) {
      if (endpoint) {
        return endpoint;
      }
      const cleanPath = memoryNormalizeDevicePaths(path || "");
      const cleanCommand = memoryNormalizeDevicePaths(command || "");
      if (cleanPath && !memoryLooksTruncatedPath(cleanPath)) {
        return cleanPath;
      }
      const expanded = memoryExpandProgramFilesPath(message);
      if (expanded) {
        return expanded;
      }
      if (cleanCommand) {
        const cmdPath = memoryExtractFirstPath(cleanCommand);
        if (cmdPath) {
          return memoryNormalizeDevicePaths(cmdPath);
        }
        return cleanCommand;
      }
      return cleanPath;
    }

    function memorySignalForRow(tab, marker, message, isDefault) {
      if (isDefault) {
        return "low";
      }
      const lower = String(message || "").toLowerCase();
      const markerLc = String(marker || "").toLowerCase();
      if (markerLc === "risk_verdict" || tab === "memory_risk_verdicts") {
        if (lower.includes("verdict=bypass")) {
          return "high";
        }
        if (lower.includes("verdict=cheat") || lower.includes("вердикт=чит")) {
          return "high";
        }
        if (lower.includes("verdict=suspicious") || lower.includes("вердикт=подозрительно")) {
          return "medium";
        }
        return "low";
      }
      if (tab === "memory_proxy_bypass" || markerLc === "proxy_bypass") {
        return "high";
      }
      if (markerLc === "javaw_betatest" || tab === "memory_betatest") {
        return "high";
      }
      if (markerLc.includes("lolbin_abuse_high")) {
        return "high";
      }
      if (markerLc.includes("lolbin_abuse_medium") || tab === "memory_lolbin") {
        return "medium";
      }
      if (markerLc === "event_correlation" || tab === "memory_event_corr") {
        return "medium";
      }
      if (
        String(marker || "").includes("minecraft")
        || lower.includes("block.minecraft.")
        || lower.includes("loot_table/blocks")
      ) {
        const minecraftCheatMarkers = [
          "liquidbounce",
          "meteorclient",
          "wurst",
          "impact client",
          "future client",
          "baritone",
          "forgehax",
          "javaagent",
          "authlib-injector",
          "clicker"
        ];
        if (minecraftCheatMarkers.some((k) => lower.includes(k))) {
          return "high";
        }
        return "low";
      }
      if (marker === "https-endpoint" || marker === "network_artifact") {
        if (
          lower.includes("invoke-webrequest") ||
          lower.includes("invoke-restmethod") ||
          lower.includes(" download?key=") ||
          lower.includes("downloadstring") ||
          lower.includes("downloadfile") ||
          lower.includes("curl ") ||
          lower.includes("wget ") ||
          lower.includes("unknowncheats") ||
          lower.includes("keyauth")
        ) {
          return "high";
        }
        if (
          lower.includes("wss://") ||
          lower.includes("websocket") ||
          lower.includes("proxy") ||
          lower.includes("rdp")
        ) {
          return "medium";
        }
      }
      if (tab === "memory_connections" || tab === "memory_injected" || tab === "memory_dll" || tab === "memory_modified") {
        return "high";
      }
      if (tab === "memory_hidden") {
        if (
          lower.includes("activeprocesslinks") ||
          lower.includes(" eprocess") ||
          lower.includes("hidden process") ||
          lower.includes("terminated process")
        ) {
          return "high";
        }
        return "medium";
      }
      const highKeywords = [
        "writeprocessmemory",
        "createremotethread",
        "ntcreatethreadex",
        "manualmap",
        "shellcode",
        "process hollow",
        "keyauth",
        "unknowncheats",
        "kdmapper",
        "meterpreter",
        "reverse shell",
        "beacon",
        "proxy-bypass",
        "minecraft_local_proxy",
        "verdict=bypass",
        "eventid=7045",
        "eventid=4672",
        "ifeo",
        "silentprocessexit",
        "appinit_dlls",
        "knowndlls"
      ];
      if (highKeywords.some((k) => lower.includes(k))) {
        return "high";
      }
      const mediumKeywords = [
        "proxyenable",
        "proxyserver",
        "autoconfigurl",
        "rdp",
        "mstsc",
        "websocket",
        "wss://",
        "eventid=4688",
        "eventid=4624",
        "eventid=4625"
      ];
      if (mediumKeywords.some((k) => lower.includes(k))) {
        return "medium";
      }
      if (String(marker || "").includes("event") || String(marker || "").includes("persistence")) {
        return "medium";
      }
      return memorySectionDefaultSignal(tab);
    }

    function parseMemoryRows(tab, rows) {
      const out = [];
      const safeRows = Array.isArray(rows) ? rows : [];
      for (let i = 0; i < safeRows.length; i += 1) {
        const cleaned = sanitizeUiLine(safeRows[i]);
        if (!cleaned) {
          continue;
        }
        let source = "-";
        let marker = memorySectionMarker(tab);
        let message = cleaned;

        let rest = cleaned;
        const sourceMatch = /^\[([^\]]+)\]\s*(.*)$/.exec(rest);
        if (sourceMatch) {
          source = sourceMatch[1] || "-";
          rest = (sourceMatch[2] || "").trim();
        }

        const markerMatch = /^\[([^\]]+)\]\s*(.*)$/.exec(rest);
        if (markerMatch) {
          marker = memoryNormalizeMarker(markerMatch[1], tab);
          message = (markerMatch[2] || "").trim() || rest;
        } else {
          marker = memoryNormalizeMarker(marker, tab);
          message = rest || cleaned;
        }

        source = memoryNormalizeDevicePaths(source);
        message = memoryNormalizeDevicePaths(message);
        const isDefault = /^no\s+/i.test(message) || /^no\s+/i.test(cleaned);
        const endpoint = memoryExtractEndpoint(message);
        const path = memoryExtractFirstPath(message);
        const command = memoryNormalizeDevicePaths(memoryExtractCommand(message));
        const entity = memorySelectEntity(message, endpoint, path, command);
        const fileName = memoryExtractFileName(entity) || memoryExtractFileName(path) || memoryExtractFileName(message);
        const trust = memoryPathTrust(entity || path, message);
        const signKey = memorySignKey(entity || path, message, trust.key);
        const stamp = memoryExtractTimestamp(message);
        const signal = memorySignalForRow(tab, marker, message, isDefault);
        const searchBlob = `${source} ${marker} ${entity} ${fileName} ${trust.key} ${signKey} ${message} ${stamp.label} ${cleaned}`.toLowerCase();

        out.push({
          index: i + 1,
          source,
          marker,
          message,
          entity,
          fileName,
          signKey,
          trustKey: trust.key,
          timestamp: stamp.label,
          timestampValue: stamp.epoch,
          signal,
          isDefault,
          searchBlob
        });
      }
      return out;
    }

    function parsedMemoryRowsForTab(tab) {
      if (state.memoryParsedCache[tab]) {
        return state.memoryParsedCache[tab];
      }
      const rows = rowsForMemoryTab(tab)
        .map((line) => sanitizeUiLine(line))
        .filter((line) => line.length > 0);
      const parsed = parseMemoryRows(tab, rows);
      state.memoryParsedCache[tab] = parsed;
      return parsed;
    }

    function applyMemoryFilters(rows) {
      const q = state.query.trim().toLowerCase();
      return rows.filter((row) => {
        if (q && !row.searchBlob.includes(q)) {
          return false;
        }
        if (state.memorySignalFilter !== "all" && row.signal !== state.memorySignalFilter) {
          return false;
        }
        if (state.memorySourceFilter !== "all" && row.source !== state.memorySourceFilter) {
          return false;
        }
        if (state.memoryMarkerFilter !== "all" && row.marker !== state.memoryMarkerFilter) {
          return false;
        }
        if (state.memorySignFilter !== "all" && row.signKey !== state.memorySignFilter) {
          return false;
        }
        if (state.memoryTrustFilter !== "all" && row.trustKey !== state.memoryTrustFilter) {
          return false;
        }
        return true;
      });
    }

    function sortMemoryRows(rows) {
      const out = [...rows];
      if (state.memorySort === "source_asc") {
        out.sort((a, b) => a.source.localeCompare(b.source) || a.index - b.index);
        return out;
      }
      if (state.memorySort === "marker_asc") {
        out.sort((a, b) => a.marker.localeCompare(b.marker) || a.index - b.index);
        return out;
      }
      if (state.memorySort === "time_desc") {
        out.sort((a, b) => {
          const diff = Number(b.timestampValue || 0) - Number(a.timestampValue || 0);
          if (diff !== 0) {
            return diff;
          }
          return a.index - b.index;
        });
        return out;
      }
      out.sort((a, b) => {
        const diff = memorySignalRank(b.signal) - memorySignalRank(a.signal);
        if (diff !== 0) {
          return diff;
        }
        return a.index - b.index;
      });
      return out;
    }

    function renderMemoryFilters(allRows) {
      const host = document.getElementById("memoryFilters");
      if (!host) {
        return;
      }
      const selected = state.memoryTab || "memory_summary";
      if (selected === "memory_summary") {
        host.classList.add("hide");
        host.textContent = "";
        return;
      }

      host.textContent = "";
      host.classList.remove("hide");

      const reset = document.createElement("button");
      reset.type = "button";
      reset.className = "filter-chip";
      reset.textContent = t("resetFilters");
      reset.addEventListener("click", () => {
        state.memorySignalFilter = "all";
        state.memorySourceFilter = "all";
        state.memoryMarkerFilter = "all";
        state.memorySignFilter = "all";
        state.memoryTrustFilter = "all";
        state.memorySort = "signal_desc";
        state.memoryPage = 1;
        renderMemoryPanel();
      });
      host.appendChild(reset);

      const signalTitle = document.createElement("span");
      signalTitle.className = "filter-title";
      signalTitle.textContent = t("memoryFiltersSignal");
      host.appendChild(signalTitle);

      const signalOptions = [
        { key: "all", label: t("signalAll") },
        { key: "high", label: t("memorySignalHigh") },
        { key: "medium", label: t("memorySignalMedium") },
        { key: "low", label: t("memorySignalLow") }
      ];
      for (const opt of signalOptions) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = `filter-chip${state.memorySignalFilter === opt.key ? " active" : ""}`;
        b.textContent = opt.label;
        b.addEventListener("click", () => {
          state.memorySignalFilter = opt.key;
          state.memoryPage = 1;
          renderMemoryPanel();
        });
        host.appendChild(b);
      }

      const sourceTitle = document.createElement("span");
      sourceTitle.className = "filter-title";
      sourceTitle.textContent = t("memoryFiltersSource");
      host.appendChild(sourceTitle);

      const sources = Array.from(new Set(allRows.map((row) => row.source).filter(Boolean))).sort();
      const sourceSelect = document.createElement("select");
      sourceSelect.className = "memory-select";
      sourceSelect.innerHTML = "";
      const sourceDefault = document.createElement("option");
      sourceDefault.value = "all";
      sourceDefault.textContent = t("memoryAllSources");
      sourceSelect.appendChild(sourceDefault);
      for (const source of sources) {
        const opt = document.createElement("option");
        opt.value = source;
        opt.textContent = source;
        sourceSelect.appendChild(opt);
      }
      sourceSelect.value = state.memorySourceFilter;
      sourceSelect.addEventListener("change", (e) => {
        state.memorySourceFilter = e.target.value || "all";
        state.memoryPage = 1;
        renderMemoryPanel();
      });
      host.appendChild(sourceSelect);

      const markerTitle = document.createElement("span");
      markerTitle.className = "filter-title";
      markerTitle.textContent = t("memoryFiltersMarker");
      host.appendChild(markerTitle);

      const markers = Array.from(new Set(allRows.map((row) => row.marker).filter(Boolean))).sort();
      const markerSelect = document.createElement("select");
      markerSelect.className = "memory-select";
      markerSelect.innerHTML = "";
      const markerDefault = document.createElement("option");
      markerDefault.value = "all";
      markerDefault.textContent = t("memoryAllMarkers");
      markerSelect.appendChild(markerDefault);
      for (const marker of markers) {
        const opt = document.createElement("option");
        opt.value = marker;
        opt.textContent = marker;
        markerSelect.appendChild(opt);
      }
      markerSelect.value = state.memoryMarkerFilter;
      markerSelect.addEventListener("change", (e) => {
        state.memoryMarkerFilter = e.target.value || "all";
        state.memoryPage = 1;
        renderMemoryPanel();
      });
      host.appendChild(markerSelect);

      const signTitle = document.createElement("span");
      signTitle.className = "filter-title";
      signTitle.textContent = t("memoryFiltersSign");
      host.appendChild(signTitle);

      const signSelect = document.createElement("select");
      signSelect.className = "memory-select";
      const signOptions = [
        ["all", t("memoryAllSigns")],
        ["signed", t("memorySignSigned")],
        ["unsigned", t("memorySignUnsigned")],
        ["unknown", t("memorySignUnknown")]
      ];
      for (const [value, label] of signOptions) {
        const opt = document.createElement("option");
        opt.value = value;
        opt.textContent = label;
        signSelect.appendChild(opt);
      }
      signSelect.value = state.memorySignFilter;
      signSelect.addEventListener("change", (e) => {
        state.memorySignFilter = e.target.value || "all";
        state.memoryPage = 1;
        renderMemoryPanel();
      });
      host.appendChild(signSelect);

      const trustTitle = document.createElement("span");
      trustTitle.className = "filter-title";
      trustTitle.textContent = t("memoryFiltersTrust");
      host.appendChild(trustTitle);

      const trustSelect = document.createElement("select");
      trustSelect.className = "memory-select";
      const trustOptions = [
        ["all", t("memoryAllTrust")],
        ["system", t("memoryTrustSystem")],
        ["program", t("memoryTrustProgram")],
        ["user", t("memoryTrustUser")],
        ["temp", t("memoryTrustTemp")],
        ["unknown", t("memoryTrustUnknown")]
      ];
      for (const [value, label] of trustOptions) {
        const opt = document.createElement("option");
        opt.value = value;
        opt.textContent = label;
        trustSelect.appendChild(opt);
      }
      trustSelect.value = state.memoryTrustFilter;
      trustSelect.addEventListener("change", (e) => {
        state.memoryTrustFilter = e.target.value || "all";
        state.memoryPage = 1;
        renderMemoryPanel();
      });
      host.appendChild(trustSelect);

      const sortTitle = document.createElement("span");
      sortTitle.className = "filter-title";
      sortTitle.textContent = t("memoryFiltersSort");
      host.appendChild(sortTitle);

      const sortSelect = document.createElement("select");
      sortSelect.className = "memory-select";
      const sorts = [
        ["signal_desc", t("memorySortSignalDesc")],
        ["source_asc", t("memorySortSourceAsc")],
        ["marker_asc", t("memorySortMarkerAsc")],
        ["time_desc", t("memorySortTimeDesc")]
      ];
      for (const [value, label] of sorts) {
        const opt = document.createElement("option");
        opt.value = value;
        opt.textContent = label;
        sortSelect.appendChild(opt);
      }
      sortSelect.value = state.memorySort;
      sortSelect.addEventListener("change", (e) => {
        state.memorySort = e.target.value || "signal_desc";
        state.memoryPage = 1;
        renderMemoryPanel();
      });
      host.appendChild(sortSelect);
    }

    function renderMemoryTable(rows) {
      const wrap = document.getElementById("memoryTableWrap");
      const head = document.getElementById("memoryTableHead");
      const body = document.getElementById("memoryTableBody");
      const empty = document.getElementById("memoryEmptyView");
      const pager = document.getElementById("memoryPager");
      if (!wrap || !head || !body || !empty) {
        return;
      }

      head.textContent = "";
      const headerRow = document.createElement("tr");
      const headers = [
        ["memory-col-index", t("memoryColIndex")],
        ["memory-col-signal", t("memoryColSignal")],
        ["memory-col-source", t("memoryColSource")],
        ["memory-col-tag", t("memoryColTag")],
        ["memory-col-entity", t("memoryColEntity")],
        ["memory-col-file", t("memoryColFile")],
        ["memory-col-sign", t("memoryColSign")],
        ["memory-col-trust", t("memoryColTrust")],
        ["memory-col-time", t("memoryColTime")],
        ["memory-col-details", t("memoryColDetails")]
      ];
      for (const [cls, label] of headers) {
        const th = document.createElement("th");
        th.className = cls;
        th.textContent = label;
        headerRow.appendChild(th);
      }
      head.appendChild(headerRow);

      body.textContent = "";
      if (!rows || rows.length === 0) {
        wrap.classList.add("hide");
        if (pager) {
          pager.classList.add("hide");
        }
        empty.classList.remove("hide");
        empty.textContent = t("empty");
        return;
      }

      wrap.classList.remove("hide");
      empty.classList.add("hide");
      const fragment = document.createDocumentFragment();
      for (const row of rows) {
        const tr = document.createElement("tr");
        tr.className = `memory-row-${row.signal || "low"}`;

        const cIndex = document.createElement("td");
        cIndex.className = "memory-col-index";
        cIndex.textContent = String(row.index || 0);
        tr.appendChild(cIndex);

        const cSignal = document.createElement("td");
        cSignal.className = "memory-col-signal";
        const signalBadge = document.createElement("span");
        signalBadge.className = `memory-chip memory-chip-${row.signal || "low"}`;
        signalBadge.textContent = memorySignalLabel(row.signal || "low");
        cSignal.appendChild(signalBadge);
        tr.appendChild(cSignal);

        const cSource = document.createElement("td");
        cSource.className = "memory-col-source";
        cSource.textContent = row.source || "-";
        tr.appendChild(cSource);

        const cTag = document.createElement("td");
        cTag.className = "memory-col-tag";
        cTag.textContent = row.marker || "-";
        tr.appendChild(cTag);

        const cEntity = document.createElement("td");
        cEntity.className = "memory-col-entity";
        cEntity.textContent = row.entity || t("memoryEntityNone");
        tr.appendChild(cEntity);

        const cFile = document.createElement("td");
        cFile.className = "memory-col-file";
        cFile.textContent = row.fileName || t("memoryEntityNone");
        tr.appendChild(cFile);

        const cSign = document.createElement("td");
        cSign.className = "memory-col-sign";
        cSign.textContent = memorySignLabel(row.signKey || "unknown");
        tr.appendChild(cSign);

        const cTrust = document.createElement("td");
        cTrust.className = "memory-col-trust";
        cTrust.textContent = memoryTrustLabel(row.trustKey || "unknown");
        tr.appendChild(cTrust);

        const cTime = document.createElement("td");
        cTime.className = "memory-col-time";
        cTime.textContent = row.timestamp || t("memoryTimeUnknown");
        tr.appendChild(cTime);

        const cDetails = document.createElement("td");
        cDetails.className = "memory-col-details";
        cDetails.textContent = row.message || "";
        tr.appendChild(cDetails);

        fragment.appendChild(tr);
      }
      body.appendChild(fragment);
    }

    function renderMemoryPager(totalRows, totalPages) {
      const host = document.getElementById("memoryPager");
      if (!host) {
        return;
      }
      host.textContent = "";
      if (!Number.isFinite(totalRows) || totalRows <= 0 || !Number.isFinite(totalPages) || totalPages <= 1) {
        host.classList.add("hide");
        return;
      }
      host.classList.remove("hide");

      const left = document.createElement("div");
      left.className = "memory-pager-left";
      const right = document.createElement("div");
      right.className = "memory-pager-right";

      const prev = document.createElement("button");
      prev.type = "button";
      prev.className = "memory-nav-btn";
      prev.textContent = t("memoryPrev");
      prev.disabled = state.memoryPage <= 1;
      prev.addEventListener("click", () => {
        if (state.memoryPage > 1) {
          state.memoryPage -= 1;
          renderMemoryPanel();
        }
      });
      left.appendChild(prev);

      const next = document.createElement("button");
      next.type = "button";
      next.className = "memory-nav-btn";
      next.textContent = t("memoryNext");
      next.disabled = state.memoryPage >= totalPages;
      next.addEventListener("click", () => {
        if (state.memoryPage < totalPages) {
          state.memoryPage += 1;
          renderMemoryPanel();
        }
      });
      left.appendChild(next);

      const meta = document.createElement("span");
      meta.className = "memory-pager-meta";
      meta.textContent = `${t("memoryPageLabel")} ${state.memoryPage}/${totalPages}`;
      left.appendChild(meta);

      const label = document.createElement("span");
      label.className = "filter-title";
      label.textContent = t("memoryRowsPerPage");
      right.appendChild(label);

      const select = document.createElement("select");
      select.className = "memory-select";
      for (const size of [75, 150, 300, 600]) {
        const opt = document.createElement("option");
        opt.value = String(size);
        opt.textContent = String(size);
        select.appendChild(opt);
      }
      select.value = String(state.memoryPageSize || 150);
      select.addEventListener("change", (e) => {
        const parsed = Number(e.target.value || "150");
        state.memoryPageSize = Number.isFinite(parsed) ? Math.max(50, parsed) : 150;
        state.memoryPage = 1;
        renderMemoryPanel();
      });
      right.appendChild(select);

      host.appendChild(left);
      host.appendChild(right);
    }

    function renderMemoryPanel() {
      const grid = document.getElementById("memorySummaryGrid");
      if (grid) {
        grid.textContent = "";
        const cards = [
          ["aethertrace_enabled", Number(DATA.summary.aethertrace_enabled || 0)],
          ["aethertrace_dumps", Number(DATA.summary.aethertrace_dumps || 0)],
          ["aethertrace_plugins_ok", Number(DATA.summary.aethertrace_plugins_ok || 0)],
          ["aethertrace_plugin_errors", Number(DATA.summary.aethertrace_plugin_errors || 0)],
          ["aethertrace_open_files", Number(DATA.summary.aethertrace_open_files || 0)],
          ["aethertrace_command_buffers", Number(DATA.summary.aethertrace_command_buffers || 0)],
          ["aethertrace_hidden_processes", Number(DATA.summary.aethertrace_hidden_processes || 0)],
          ["aethertrace_shell_history", Number(DATA.summary.aethertrace_shell_history || 0)],
          ["aethertrace_network", Number(DATA.summary.aethertrace_network || 0)],
          ["aethertrace_suspicious_connections", Number(DATA.summary.aethertrace_suspicious_connections || 0)],
          ["aethertrace_injected_code", Number(DATA.summary.aethertrace_injected_code || 0)],
          ["aethertrace_suspicious_dll", Number(DATA.summary.aethertrace_suspicious_dll || 0)],
          ["aethertrace_modified_memory", Number(DATA.summary.aethertrace_modified_memory || 0)],
          ["aethertrace_event_correlations", Number(DATA.summary.aethertrace_event_correlations || 0)],
          ["aethertrace_lolbin_abuse", Number(DATA.summary.aethertrace_lolbin_abuse || 0)],
          ["aethertrace_javaw_betatest", Number(DATA.summary.aethertrace_javaw_betatest || 0)],
          ["aethertrace_proxy_bypass", Number(DATA.summary.aethertrace_proxy_bypass || 0)],
          ["aethertrace_risk_verdicts", Number(DATA.summary.aethertrace_risk_verdicts || 0)]
        ];
        for (const [key, value] of cards) {
          const card = document.createElement("article");
          card.className = "card";
          const pk = document.createElement("p");
          pk.className = "k";
          pk.textContent = t(`s_${key}`);
          const pv = document.createElement("p");
          pv.className = "v";
          pv.textContent = String(value);
          card.appendChild(pk);
          card.appendChild(pv);
          grid.appendChild(card);
        }
      }

      const explorer = document.getElementById("memoryExplorerBlock");
      const localCounter = document.getElementById("memoryLocalCounter");
      const selected = state.memoryTab || "memory_summary";
      const isSummary = selected === "memory_summary";

      if (grid) {
        grid.classList.toggle("hide", !isSummary);
      }
      if (explorer) {
        explorer.classList.toggle("hide", isSummary);
      }
      if (isSummary) {
        document.getElementById("counter").textContent = "";
        if (localCounter) {
          localCounter.textContent = "";
        }
        renderMemoryFilters([]);
        renderMemoryTable([]);
        renderMemoryPager(0, 0);
        return;
      }

      const parsedRows = parsedMemoryRowsForTab(selected);
      renderMemoryFilters(parsedRows);
      const filteredRows = sortMemoryRows(applyMemoryFilters(parsedRows));
      const pageSize = Math.max(50, Number(state.memoryPageSize || 150));
      const totalPages = Math.max(1, Math.ceil(filteredRows.length / pageSize));
      if (state.memoryPage > totalPages) {
        state.memoryPage = totalPages;
      }
      if (state.memoryPage < 1) {
        state.memoryPage = 1;
      }
      const from = (state.memoryPage - 1) * pageSize;
      const pageRows = filteredRows.slice(from, from + pageSize);

      const shownText = `${t("shown")}: ${pageRows.length} / ${filteredRows.length} / ${parsedRows.length}`;
      document.getElementById("counter").textContent = shownText;
      if (localCounter) {
        localCounter.textContent = `${shownText} • ${t("memoryPageLabel")} ${state.memoryPage}/${totalPages}`;
      }

      const activeHead = document.getElementById("memoryActiveHead");
      if (activeHead) {
        activeHead.textContent = `${tabLabel(selected)} • ${t("items")}: ${parsedRows.length}`;
      }

      renderMemoryTable(pageRows);
      renderMemoryPager(filteredRows.length, totalPages);
    }

    function renderDataPager(totalRows, totalPages) {
      const host = document.getElementById("dataPager");
      if (!host) {
        return;
      }
      host.textContent = "";
      if (!Number.isFinite(totalRows) || totalRows <= 0 || !Number.isFinite(totalPages) || totalPages <= 1) {
        host.classList.add("hide");
        return;
      }
      host.classList.remove("hide");

      const left = document.createElement("div");
      left.className = "memory-pager-left";
      const right = document.createElement("div");
      right.className = "memory-pager-right";

      const prev = document.createElement("button");
      prev.type = "button";
      prev.className = "memory-nav-btn";
      prev.textContent = t("memoryPrev");
      prev.disabled = state.dataPage <= 1;
      prev.addEventListener("click", () => {
        if (state.dataPage > 1) {
          state.dataPage -= 1;
          renderData(true);
        }
      });
      left.appendChild(prev);

      const next = document.createElement("button");
      next.type = "button";
      next.className = "memory-nav-btn";
      next.textContent = t("memoryNext");
      next.disabled = state.dataPage >= totalPages;
      next.addEventListener("click", () => {
        if (state.dataPage < totalPages) {
          state.dataPage += 1;
          renderData(true);
        }
      });
      left.appendChild(next);

      const meta = document.createElement("span");
      meta.className = "memory-pager-meta";
      meta.textContent = `${t("memoryPageLabel")} ${state.dataPage}/${totalPages}`;
      left.appendChild(meta);

      const label = document.createElement("span");
      label.className = "filter-title";
      label.textContent = t("memoryRowsPerPage");
      right.appendChild(label);

      const select = document.createElement("select");
      select.className = "memory-select";
      for (const size of [200, 300, 600, 1200]) {
        const opt = document.createElement("option");
        opt.value = String(size);
        opt.textContent = String(size);
        select.appendChild(opt);
      }
      select.value = String(state.dataPageSize || 300);
      select.addEventListener("change", (e) => {
        const parsed = Number(e.target.value || "300");
        state.dataPageSize = Number.isFinite(parsed) ? Math.max(100, parsed) : 300;
        state.dataPage = 1;
        renderData(true);
      });
      right.appendChild(select);

      host.appendChild(left);
      host.appendChild(right);
    }

    function renderData(skipFilterUi = false) {
      const allRows = rowsForCurrentTab();
      if (!skipFilterUi) {
        renderDiskFilters(allRows);
      }
      const tabKey = activeDataTabKey();
      const filtered = applyAllFilters(allRows);
      const pageSize = Math.max(100, Number(state.dataPageSize || 300));
      const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
      if (state.dataPage > totalPages) {
        state.dataPage = totalPages;
      }
      if (state.dataPage < 1) {
        state.dataPage = 1;
      }
      const from = (state.dataPage - 1) * pageSize;
      const pageRows = filtered.slice(from, from + pageSize);
      document.getElementById("counter").textContent =
        `${t("shown")}: ${pageRows.length} / ${filtered.length} / ${allRows.length}`;
      document.getElementById("dataHead").textContent = `${tabLabel(tabKey)} • ${t("items")}: ${allRows.length}`;
      const view = document.getElementById("dataView");
      const rowView = document.getElementById("rowView");
      const empty = document.getElementById("emptyView");
      if (filtered.length === 0) {
        rowView.textContent = "";
        rowView.classList.add("hide");
        view.textContent = "";
        view.classList.remove("hide");
        empty.classList.remove("hide");
        empty.textContent = t("empty");
        renderDataPager(0, 0);
      } else {
        empty.classList.add("hide");
        if (state.page === "strings" && STRUCTURED_TABS.has(tabKey)) {
          view.textContent = "";
          view.classList.add("hide");
          rowView.classList.remove("hide");
          renderStructuredRows(tabKey, pageRows);
        } else {
          rowView.textContent = "";
          rowView.classList.add("hide");
          view.classList.remove("hide");
          view.textContent = pageRows.join("\n");
        }
        renderDataPager(filtered.length, totalPages);
      }
    }

    function renderLabels() {
      document.title = t("title");
      document.getElementById("titleDiscord").textContent = t("titleDiscord");
      document.getElementById("subtitle").textContent = t("subtitle");
      document.getElementById("discordBtn").textContent = t("discord");
      document.getElementById("pageStringsBtn").textContent = t("pageStrings");
      document.getElementById("pageMemoryBtn").textContent = t("pageMemory");
      const pageMemoryBetaBtn = document.getElementById("pageMemoryBetaBtn");
      if (pageMemoryBetaBtn) {
        pageMemoryBetaBtn.textContent = t("pageMemoryBeta");
      }
      document.getElementById("search").placeholder = t("search");
      document.getElementById("summaryHead").textContent = t("summary");
      document.getElementById("quickHead").textContent = t("quickTriage");
      document.getElementById("inputsHead").textContent = t("inputFiles");
      document.getElementById("dmpsHead").textContent = t("dmpFiles");
      const memoryHead = document.getElementById("memoryHead");
      if (memoryHead) {
        memoryHead.textContent = t("memoryHead");
      }
      const memoryActiveHead = document.getElementById("memoryActiveHead");
      if (memoryActiveHead) {
        memoryActiveHead.textContent = tabLabel(state.memoryTab || "memory_summary");
      }
      document.getElementById("langBtn").textContent = state.lang === "ru" ? "EN" : "RU";
      document.title = (state.page === "memory" || state.page === "memory_beta")
        ? `${t("titlePrefix")}${tabLabel(state.memoryTab)}`
        : `${t("titlePrefix")}${tabLabel(state.tab)}`;
      applyTheme(state.theme);
    }

    function render() {
      renderLabels();
      renderTabs();
      const summaryPanel = document.getElementById("summaryPanel");
      const dataPanel = document.getElementById("dataPanel");
      const memoryPanel = document.getElementById("memoryPanel");
      const toolbar = document.getElementById("toolbar");
      const search = document.getElementById("search");
      const counter = document.getElementById("counter");
      const diskFilters = document.getElementById("diskFilters");
      const tabs = document.getElementById("tabs");
      const pageStringsBtn = document.getElementById("pageStringsBtn");
      const pageMemoryBtn = document.getElementById("pageMemoryBtn");
      const pageMemoryBetaBtn = document.getElementById("pageMemoryBetaBtn");

      pageStringsBtn.classList.toggle("active", state.page === "strings");
      pageMemoryBtn.classList.toggle("active", state.page === "memory");
      if (pageMemoryBetaBtn) {
        pageMemoryBetaBtn.classList.toggle("active", state.page === "memory_beta");
      }

      if (state.page === "memory" || state.page === "memory_beta") {
        if (state.page === "memory_beta") {
          state.memoryTab = "memory_results_beta";
        }
        summaryPanel.classList.add("hide");
        dataPanel.classList.add("hide");
        memoryPanel.classList.remove("hide");
        toolbar.classList.remove("hide");
        search.disabled = false;
        tabs.classList.toggle("hide", state.page === "memory_beta");
        if (diskFilters) {
          diskFilters.textContent = "";
          diskFilters.classList.add("hide");
        }
        renderMemoryPanel();
        return;
      }

      memoryPanel.classList.add("hide");
      toolbar.classList.remove("hide");
      tabs.classList.remove("hide");
      if (state.tab === "summary") {
        summaryPanel.classList.remove("hide");
        dataPanel.classList.add("hide");
        search.disabled = true;
        counter.textContent = "";
        if (diskFilters) {
          diskFilters.textContent = "";
          diskFilters.classList.add("hide");
        }
        renderSummary();
      } else {
        summaryPanel.classList.add("hide");
        dataPanel.classList.remove("hide");
        search.disabled = false;
        renderData();
      }
    }

    let searchTimer = null;
    document.getElementById("search").addEventListener("input", (e) => {
      state.query = e.target.value || "";
      if (searchTimer) {
        clearTimeout(searchTimer);
      }
      searchTimer = setTimeout(() => {
        if (state.page === "memory" || state.page === "memory_beta") {
          state.memoryPage = 1;
          renderMemoryPanel();
          return;
        }
        if (state.page === "strings" && state.tab !== "summary") {
          state.dataPage = 1;
          renderData();
        }
      }, 180);
    });

    document.getElementById("pageStringsBtn").addEventListener("click", () => {
      state.page = "strings";
      state.dataPage = 1;
      render();
    });

    document.getElementById("pageMemoryBtn").addEventListener("click", () => {
      state.page = "memory";
      state.memoryTab = "memory_summary";
      state.memorySignalFilter = "all";
      state.memorySourceFilter = "all";
      state.memoryMarkerFilter = "all";
      state.memorySignFilter = "all";
      state.memoryTrustFilter = "all";
      state.memorySort = "signal_desc";
      state.memoryPage = 1;
      render();
    });

    const pageMemoryBetaBtn = document.getElementById("pageMemoryBetaBtn");
    if (pageMemoryBetaBtn) {
      pageMemoryBetaBtn.addEventListener("click", () => {
        state.page = "memory_beta";
        state.memoryTab = "memory_results_beta";
        state.memorySignalFilter = "all";
        state.memorySourceFilter = "all";
        state.memoryMarkerFilter = "all";
        state.memorySignFilter = "all";
        state.memoryTrustFilter = "all";
        state.memorySort = "signal_desc";
        state.memoryPage = 1;
        render();
      });
    }

    document.getElementById("langBtn").addEventListener("click", () => {
      state.lang = state.lang === "ru" ? "en" : "ru";
      localStorage.setItem("residence_report_lang", state.lang);
      render();
    });

    document.getElementById("themeBtn").addEventListener("click", () => {
      const next = state.theme === "dark" ? "light" : "dark";
      localStorage.setItem(THEME_STORE_KEY, next);
      applyTheme(next);
    });

    const systemThemeMedia = typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-color-scheme: light)")
      : null;
    if (systemThemeMedia) {
      const onSystemThemeChange = (event) => {
        if (localStorage.getItem(THEME_STORE_KEY)) {
          return;
        }
        applyTheme(event.matches ? "light" : "dark");
      };
      if (typeof systemThemeMedia.addEventListener === "function") {
        systemThemeMedia.addEventListener("change", onSystemThemeChange);
      } else if (typeof systemThemeMedia.addListener === "function") {
        systemThemeMedia.addListener(onSystemThemeChange);
      }
    }

    render();
  </script>
</body>
</html>
"#
    .to_string();

    html = html.replace("__DEFAULT_LANG__", default_lang);
    html = html.replace("__SUMMARY__", &summary_json);
    html = html.replace("__INPUTS__", &js_array_from_paths(inputs));
    html = html.replace("__DMPS__", &js_array_from_paths(dmps));
    html = html.replace("__CUSTOM_HITS__", &js_array_from_vec(custom_hits));
    html = html.replace("__ALLPE__", &js_array_from_set(allpe));
    html = html.replace("__NORMALPE__", &js_array_from_set(normal_pe));
    html = html.replace("__SCRIPTS__", &js_array_from_set(scripts));
    html = html.replace("__BETA__", &js_array_from_set(&a.beta));
    html = html.replace("__FILE_DATES__", &js_array_from_set(file_dates));
    html = html.replace("__DPS__", &js_array_from_set(dps));
    html = html.replace("__START__", &js_array_from_set(started));
    html = html.replace("__PREFETCH__", &js_array_from_set(prefetch));
    html = html.replace("__OTHERDISK__", &js_array_from_set(other_disk));
    html = html.replace("__DELETED__", &js_array_from_set(deleted));
    html = html.replace("__TRASHDELETED__", &js_array_from_set(trash_deleted));
    html = html.replace(
        "__FILES_WITHOUT_PATH__",
        &js_array_from_set(resolved_pathless),
    );
    html = html.replace("__NOTFOUND_FULL__", &js_array_from_set(full_not_found));
    html = html.replace("__NOTFOUND_NAMES__", &js_array_from_set(pathless_not_found));
    html = html.replace("__LINKS__", &js_array_from_set(&a.links));
    html = html.replace("__DOWNLOAD_LINKS__", &js_array_from_set(download_links));
    html = html.replace("__SUSPEND_LINKS__", &js_array_from_set(slinks));
    html = html.replace("__SUSPECT_FILE__", &js_array_from_set(sfiles));
    html = html.replace("__YARA__", &js_array_from_set(yara_hits));
    html = html.replace("__JAVA_PATHS__", &js_array_from_set(jar_paths));
    html = html.replace("__REGDEL__", &js_array_from_set(&a.regdel));
    html = html.replace("__REPLACECLEAN__", &js_array_from_set(&a.replace));
    html = html.replace("__FILELESS__", &js_array_from_set(&a.fileless));
    html = html.replace("__DLL__", &js_array_from_set(&a.dll));
    html = html.replace("__FORFILES_WMIC__", &js_array_from_set(&a.forfiles_wmic));
    html = html.replace("__JAVA_BATCH__", &js_array_from_set(&a.java_batch));
    html = html.replace("__IOC__", &js_array_from_set(&a.ioc));
    html = html.replace(
        "__REMOTE_ACCESS_TOOLS__",
        &js_array_from_set(remote_access_tools),
    );
    html = html.replace("__ANALYSIS_TOOLS__", &js_array_from_set(analysis_tools));
    html = html.replace(
        "__CREDENTIAL_ACCESS__",
        &js_array_from_set(credential_access_hits),
    );
    html = html.replace(
        "__NETWORK_TUNNELS__",
        &js_array_from_set(network_tunnel_hits),
    );
    html = html.replace("__REMOTE_DOMAINS__", &js_array_from_set(remote_domain_hits));
    html = html.replace("__TUNNEL_DOMAINS__", &js_array_from_set(tunnel_domain_hits));
    html = html.replace(
        "__REMOTE_SESSIONS__",
        &js_array_from_set(remote_session_hits),
    );
    html = html.replace("__PERSISTENCE__", &js_array_from_set(persistence_hits));
    html = html.replace(
        "__ANTI_FORENSICS__",
        &js_array_from_set(anti_forensics_hits),
    );
    html = html.replace("__LOLBAS__", &js_array_from_set(lolbas_hits));
    html = html.replace("__DOMAIN_FREQUENCY__", &js_array_from_set(domain_frequency));
    html = html.replace(
        "__SUSPICIOUS_DOMAINS__",
        &js_array_from_set(suspicious_domain_hits),
    );
    html = html.replace(
        "__TRIAGE_PRIORITY__",
        &js_array_from_set(triage_priority_hits),
    );
    html = html.replace(
        "__AETHERTRACE_ENGINE__",
        &js_escape(&memory_orbit.engine_name),
    );
    html = html.replace(
        "__AETHERTRACE_RUNNER__",
        &js_escape(&memory_orbit.runner_label),
    );
    html = html.replace(
        "__AETHERTRACE_NOTES__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.notes,
            "No engine notes",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_OPEN_FILES_SOCKETS__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.open_files_or_sockets,
            "No open file/socket artifacts were collected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_COMMAND_BUFFERS__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.command_buffers,
            "No command/input-output buffers were collected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_HIDDEN_PROCESSES__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.hidden_or_terminated_processes,
            "No hidden/terminated process artifacts were detected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_SHELL_HISTORY__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.shell_command_history,
            "No shell command history artifacts were collected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_NETWORK__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.network_artifacts,
            "No network artifacts were collected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_SUSPICIOUS_CONNECTIONS__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.suspicious_connections,
            "No suspicious network connections were detected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_INJECTED_CODE__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.injected_code_hits,
            "No injected-code artifacts were detected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_SUSPICIOUS_DLL__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.suspicious_dll_hits,
            "No suspicious DLL artifacts were detected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_MODIFIED_MEMORY__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.modified_memory_regions,
            "No modified memory regions were detected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_EVENT_CORRELATIONS__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.event_correlations,
            "No event correlation artifacts were detected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_LOLBIN_ABUSE__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.lolbin_network_scores,
            "No LOLBIN+network abuse artifacts were detected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_JAVAW_BETATEST__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.javaw_betatest,
            "No javaw.exe betatest artifacts were detected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_PROXY_BYPASS__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.proxy_bypass_hits,
            "No local proxy/tunnel bypass artifacts were detected",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_RISK_VERDICTS__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.risk_verdicts,
            "No risk verdicts were produced",
        )),
    );
    html = html.replace(
        "__AETHERTRACE_PLUGIN_ERRORS__",
        &js_array_from_set(&rows_with_default(
            &memory_orbit.plugin_errors,
            "No plugin execution errors",
        )),
    );
    html = html.replace("__SUSPICIOUS_KWS__", &js_array_from_slice(SUSPICIOUS));

    let mut f = File::create(path)?;
    f.write_all(html.as_bytes())?;
    Ok(())
}


