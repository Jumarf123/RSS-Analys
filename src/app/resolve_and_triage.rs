// Path resolution, normalization, detectors, classification, and triage aggregation logic.

fn write_summary(
    path: &Path,
    inputs: &[PathBuf],
    dmps: &[PathBuf],
    a: &Analyzer,
    all_files: usize,
    allpe: usize,
    resolved: usize,
    nf_full: usize,
    nf_pathless: usize,
    normal_pe: usize,
    susp_links: usize,
    download_links: usize,
    susp_files: usize,
    remote_access_tools: usize,
    analysis_tools: usize,
    credential_access: usize,
    network_tunnels: usize,
    remote_domains: usize,
    tunnel_domains: usize,
    remote_sessions: usize,
    persistence: usize,
    anti_forensics: usize,
    _lolbas: usize,
    domain_frequency: usize,
    suspicious_domains: usize,
    triage_priority: usize,
    scripts: usize,
    beta: usize,
    file_dates: usize,
    dps: usize,
    started: usize,
    prefetch: usize,
    deleted: usize,
    trash_deleted: usize,
    yara_targets: usize,
    has_strings: bool,
    custom_rules: usize,
    custom_hit_files: usize,
    custom_hits_total: usize,
    process_scanned: usize,
    process_skipped: usize,
    process_dumps: usize,
    aethertrace_enabled: bool,
    aethertrace_dumps: usize,
    aethertrace_plugins_ok: usize,
    aethertrace_plugin_errors: usize,
    aethertrace_open_files: usize,
    aethertrace_command_buffers: usize,
    aethertrace_hidden_processes: usize,
    aethertrace_shell_history: usize,
    aethertrace_network: usize,
    aethertrace_suspicious_connections: usize,
    aethertrace_injected_code: usize,
    aethertrace_suspicious_dll: usize,
    aethertrace_modified_memory: usize,
    aethertrace_event_correlations: usize,
    aethertrace_lolbin_abuse: usize,
    aethertrace_javaw_betatest: usize,
    aethertrace_proxy_bypass: usize,
    aethertrace_risk_verdicts: usize,
) -> io::Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let mut f = File::create(path)?;
    writeln!(f, "Input TXT: {}", inputs.len())?;
    for i in inputs {
        writeln!(f, "- {}", i.display())?;
    }
    if !dmps.is_empty() {
        writeln!(f, "\nConverted DMP: {}", dmps.len())?;
        for d in dmps {
            writeln!(f, "- {}", d.display())?;
        }
    }
    writeln!(f, "\nTools:")?;
    writeln!(
        f,
        "- built-in strings engine: {}",
        if has_strings { "active" } else { "inactive" }
    )?;
    writeln!(f, "\nCounts:")?;
    writeln!(f, "- links: {}", a.links.len())?;
    writeln!(f, "- RegKeyDeletion: {}", a.regdel.len())?;
    writeln!(f, "- ReplaceClean: {}", a.replace.len())?;
    writeln!(f, "- FilelessExecution: {}", a.fileless.len())?;
    writeln!(f, "- DLL: {}", a.dll.len())?;
    writeln!(f, "- ForfilesWmic: {}", a.forfiles_wmic.len())?;
    writeln!(f, "- Java / Batch activity: {}", a.java_batch.len())?;
    writeln!(f, "- Command indicators: {}", a.ioc.len())?;
    writeln!(f, "- custom rules loaded: {}", custom_rules)?;
    writeln!(f, "- custom files with hits: {}", custom_hit_files)?;
    writeln!(f, "- custom hits total: {}", custom_hits_total)?;
    writeln!(f, "- processes scanned: {}", process_scanned)?;
    writeln!(f, "- processes skipped: {}", process_skipped)?;
    writeln!(f, "- process dumps: {}", process_dumps)?;
    writeln!(
        f,
        "- Dump core enabled: {}",
        if aethertrace_enabled { "yes" } else { "no" }
    )?;
    writeln!(f, "- Dump core dumps: {}", aethertrace_dumps)?;
    writeln!(f, "- Dump core analyzers ok: {}", aethertrace_plugins_ok)?;
    writeln!(
        f,
        "- Dump core analyzer errors: {}",
        aethertrace_plugin_errors
    )?;
    writeln!(
        f,
        "- Dump core open files/sockets: {}",
        aethertrace_open_files
    )?;
    writeln!(
        f,
        "- Dump core command buffers: {}",
        aethertrace_command_buffers
    )?;
    writeln!(
        f,
        "- Dump core hidden processes: {}",
        aethertrace_hidden_processes
    )?;
    writeln!(
        f,
        "- Dump core shell history: {}",
        aethertrace_shell_history
    )?;
    writeln!(f, "- Dump core network artifacts: {}", aethertrace_network)?;
    writeln!(
        f,
        "- Dump core suspicious connections: {}",
        aethertrace_suspicious_connections
    )?;
    writeln!(
        f,
        "- Dump core injected code: {}",
        aethertrace_injected_code
    )?;
    writeln!(
        f,
        "- Dump core suspicious DLL: {}",
        aethertrace_suspicious_dll
    )?;
    writeln!(
        f,
        "- Dump core modified memory: {}",
        aethertrace_modified_memory
    )?;
    writeln!(
        f,
        "- Dump core event correlations: {}",
        aethertrace_event_correlations
    )?;
    writeln!(f, "- Dump core LOLBIN abuse: {}", aethertrace_lolbin_abuse)?;
    writeln!(
        f,
        "- Dump core javaw betatest: {}",
        aethertrace_javaw_betatest
    )?;
    writeln!(f, "- Dump core proxy bypass: {}", aethertrace_proxy_bypass)?;
    writeln!(
        f,
        "- Dump core risk verdicts: {}",
        aethertrace_risk_verdicts
    )?;
    writeln!(f, "- all_files: {}", all_files)?;
    writeln!(f, "- legacy_binary_profile: {}", allpe)?;
    writeln!(f, "- NormalPE: {}", normal_pe)?;
    writeln!(f, "- scripts: {}", scripts)?;
    writeln!(f, "- beta: {}", beta)?;
    writeln!(f, "- file_dates: {}", file_dates)?;
    writeln!(f, "- DPS: {}", dps)?;
    writeln!(f, "- Start: {}", started)?;
    writeln!(f, "- Prefetch: {}", prefetch)?;
    writeln!(f, "- deleted: {}", deleted)?;
    writeln!(f, "- trashdeleted: {}", trash_deleted)?;
    writeln!(f, "- files_without_path resolved: {}", resolved)?;
    writeln!(f, "- not found full paths: {}", nf_full)?;
    writeln!(f, "- not found names: {}", nf_pathless)?;
    writeln!(f, "- suspend_links: {}", susp_links)?;
    writeln!(f, "- download_links: {}", download_links)?;
    writeln!(f, "- suspect_file: {}", susp_files)?;
    writeln!(f, "- cheat_artifacts_beta: {}", remote_access_tools)?;
    writeln!(f, "- bypass_artifacts_beta: {}", analysis_tools)?;
    writeln!(f, "- artifact_wipe_beta: {}", credential_access)?;
    writeln!(f, "- data_hiding_beta: {}", network_tunnels)?;
    writeln!(f, "- trail_obfuscation_beta: {}", remote_domains)?;
    writeln!(f, "- tool_attack_beta: {}", tunnel_domains)?;
    writeln!(f, "- persistence_beta: {}", remote_sessions)?;
    writeln!(f, "- credential_access_beta: {}", persistence)?;
    writeln!(f, "- anti_forensics_beta: {}", anti_forensics)?;
    writeln!(f, "- domain_frequency: {}", domain_frequency)?;
    writeln!(f, "- suspicious_domains: {}", suspicious_domains)?;
    writeln!(f, "- triage_priority_beta: {}", triage_priority)?;
    writeln!(f, "- YARA targets: {}", yara_targets)?;
    Ok(())
}

fn filter_items_by_ext(items: &BTreeSet<String>, exts: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in items {
        if has_allowed_extension(item, exts) && is_valid_binary_candidate(item) {
            out.insert(item.clone());
        }
    }
    out
}

fn has_allowed_extension(path_or_name: &str, exts: &[&str]) -> bool {
    let lower = path_or_name.to_ascii_lowercase();
    exts.iter().any(|ext| lower.ends_with(&format!(".{ext}")))
}

fn build_file_exists_cache(paths: &BTreeSet<String>) -> HashMap<String, bool> {
    if paths.is_empty() {
        return HashMap::new();
    }

    let items = Arc::new(paths.iter().cloned().collect::<Vec<_>>());
    let workers = choose_exists_cache_workers(items.len());
    if workers <= 1 || items.len() < 512 {
        let mut out = HashMap::with_capacity(items.len());
        let mut parent_cache = HashMap::new();
        for full in items.iter() {
            let normalized = normalize_full_windows_path(full);
            let exists = path_exists_fast_with_parent_cache(&normalized, &mut parent_cache);
            out.insert(normalize_cmp_path(&normalized), exists);
        }
        return out;
    }

    let cursor = AtomicUsize::new(0);
    let parts = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let items = Arc::clone(&items);
            let cursor_ref = &cursor;
            handles.push(scope.spawn(move || {
                let mut local = HashMap::new();
                let mut parent_cache = HashMap::new();
                loop {
                    let idx = cursor_ref.fetch_add(1, Ordering::Relaxed);
                    if idx >= items.len() {
                        break;
                    }
                    let normalized = normalize_full_windows_path(&items[idx]);
                    let exists = path_exists_fast_with_parent_cache(&normalized, &mut parent_cache);
                    local.insert(normalize_cmp_path(&normalized), exists);
                }
                local
            }));
        }

        let mut out_parts = Vec::with_capacity(workers);
        for handle in handles {
            out_parts.push(handle.join().unwrap_or_default());
        }
        out_parts
    });

    let mut out = HashMap::with_capacity(items.len());
    for part in parts {
        for (k, v) in part {
            out.entry(k).or_insert(v);
        }
    }
    out
}

fn path_exists_fast_with_parent_cache(
    normalized_path: &str,
    parent_cache: &mut HashMap<String, bool>,
) -> bool {
    let p = Path::new(normalized_path);
    let Some(parent) = p.parent() else {
        return p.is_file();
    };
    let Some(parent_s) = parent.to_str() else {
        return p.is_file();
    };
    if parent_s.is_empty() {
        return p.is_file();
    }
    let key = normalize_cmp_path(parent_s);
    let parent_exists = *parent_cache.entry(key).or_insert_with(|| parent.is_dir());
    if !parent_exists {
        return false;
    }
    p.is_file()
}

fn choose_exists_cache_workers(item_count: usize) -> usize {
    if item_count == 0 {
        return 1;
    }
    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    let mut workers = cpu.clamp(2, 16).min(cpu_budget);
    workers = workers.min(item_count.max(1));
    workers.min(cpu_budget).max(1)
}

fn resolve_pe_targets(
    full_paths: &BTreeSet<String>,
    names: &BTreeSet<String>,
    name_index: &HashMap<String, BTreeSet<String>>,
    file_exists_cache: Option<&HashMap<String, bool>>,
) -> (
    BTreeSet<String>,
    BTreeSet<String>,
    BTreeSet<String>,
    BTreeSet<String>,
) {
    let mut full_found = BTreeSet::new();
    let mut full_not_found = BTreeSet::new();
    let mut found = BTreeSet::new();
    let mut not_found = BTreeSet::new();
    let mut full_found_names = HashSet::new();

    for full in full_paths {
        let normalized_full = normalize_full_windows_path(full);
        let exists = if let Some(cache) = file_exists_cache {
            cache
                .get(&normalize_cmp_path(&normalized_full))
                .copied()
                .unwrap_or_else(|| Path::new(&normalized_full).is_file())
        } else {
            Path::new(&normalized_full).is_file()
        };
        if exists {
            full_found.insert(normalized_full.clone());
            if let Some(name) = file_name_lower(&normalized_full) {
                full_found_names.insert(name);
            }
        } else if let Some(resolved) = resolve_full_path_from_index(&normalized_full, name_index) {
            full_found.insert(resolved.clone());
            if let Some(name) = file_name_lower(&resolved) {
                full_found_names.insert(name);
            }
        } else {
            full_not_found.insert(normalized_full);
        }
    }

    for name in names {
        if full_found_names.contains(name) {
            continue;
        }
        if let Some(paths) = name_index.get(name) {
            found.extend(paths.iter().cloned());
        } else {
            not_found.insert(name.clone());
        }
    }
    (full_found, full_not_found, found, not_found)
}

fn resolve_java_paths(
    full: &BTreeSet<String>,
    names: &BTreeSet<String>,
    name_index: &HashMap<String, BTreeSet<String>>,
    file_exists_cache: Option<&HashMap<String, bool>>,
) -> BTreeSet<String> {
    let (full_found, _full_not_found, pathless_found, _pathless_not_found) =
        resolve_pe_targets(full, names, name_index, file_exists_cache);
    let mut out = BTreeSet::new();
    out.extend(full_found);
    out.extend(pathless_found);
    out
}

fn resolve_full_path_from_index(
    full: &str,
    name_index: &HashMap<String, BTreeSet<String>>,
) -> Option<String> {
    let name = file_name_lower(full)?;
    let candidates = name_index.get(&name)?;
    if candidates.len() == 1 {
        return candidates.iter().next().cloned();
    }

    if let Some(tail) = device_volume_tail(full) {
        let tail_l = format!("\\{}", tail.to_ascii_lowercase().replace('/', "\\"));
        for c in candidates {
            if normalize_cmp_path(c).ends_with(&tail_l) {
                return Some(c.clone());
            }
        }
    }

    if let Some(suffix) = path_suffix_after_drive(full) {
        let suffix_l = suffix.to_ascii_lowercase().replace('/', "\\");
        for c in candidates {
            if normalize_cmp_path(c).ends_with(&suffix_l) {
                return Some(c.clone());
            }
        }
    }

    None
}

fn normalize_full_windows_path(path: &str) -> String {
    let mut c = path
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>();
    c = c.trim().replace('/', "\\");
    c = c
        .trim_matches(|ch: char| "\"'`".contains(ch))
        .trim_end_matches(|ch: char| ",;:|)]}".contains(ch))
        .to_string();
    c = normalize_drive_prefix_with_spaces(&c);
    if c.starts_with("\\??\\") {
        c = c.trim_start_matches("\\??\\").to_string();
    }
    if c.starts_with("\\\\?\\") {
        c = c.trim_start_matches("\\\\?\\").to_string();
    }
    c = collapse_backslashes_keep_unc(&c);
    c = drop_duplicate_drive_prefix(&c);

    if let Some(rest) = strip_drive_prefix_if_device_path(&c) {
        c = format!("\\{rest}");
    } else if starts_with_ci(&c, "device\\harddiskvolume") {
        c = format!("\\{c}");
    }
    if let Some(mapped) = map_device_path_to_drive(&c) {
        c = mapped;
    }
    if let Some(mapped) = normalize_unc_like_local_path(&c) {
        c = mapped;
    }

    if c.starts_with("\\Users\\")
        || c.starts_with("\\Windows\\")
        || c.starts_with("\\Program Files\\")
        || c.starts_with("\\ProgramData\\")
    {
        c = format!("C:{c}");
    }
    if c.starts_with('\\') && !c.starts_with("\\\\") && device_volume_tail(&c).is_none() {
        c = format!("C:{c}");
    }

    c = uppercase_drive_prefix(&c);
    collapse_backslashes_keep_unc(&c)
}

fn normalize_unc_like_local_path(path: &str) -> Option<String> {
    let p = path.trim().replace('/', "\\");
    let rest = p.strip_prefix("\\\\")?;
    let parts = rest
        .split('\\')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let (drive, start_idx) = if parts[0].len() == 1
        && parts[0].chars().all(|c| c.is_ascii_alphabetic())
        && parts
            .get(1)
            .is_some_and(|segment| known_local_root_segment(segment).is_some())
    {
        (
            parts[0].chars().next()?.to_ascii_uppercase(),
            1usize,
        )
    } else if known_local_root_segment(parts[0]).is_some() {
        ('C', 0usize)
    } else if parts.len() >= 2
        && !is_plausible_unc_host_segment(parts[0])
        && known_local_root_segment(parts[1]).is_some()
    {
        ('C', 1usize)
    } else {
        return None;
    };

    let suffix = parts[start_idx..].join("\\");
    if suffix.is_empty() {
        return None;
    }
    Some(format!("{drive}:\\{suffix}"))
}

fn known_local_root_segment(segment: &str) -> Option<&'static str> {
    let lower = segment.trim().to_ascii_lowercase();
    match lower.as_str() {
        "windows" => Some("Windows"),
        "users" => Some("Users"),
        "program files" => Some("Program Files"),
        "program files (x86)" => Some("Program Files (x86)"),
        "programdata" => Some("ProgramData"),
        "perflogs" => Some("PerfLogs"),
        _ => None,
    }
}

fn is_plausible_unc_host_segment(segment: &str) -> bool {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn normalize_drive_prefix_with_spaces(path: &str) -> String {
    let p = path.trim();
    let bytes = p.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() {
        return p.to_string();
    }

    let mut i = 1usize;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b':' {
        return p.to_string();
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || !(bytes[i] == b'\\' || bytes[i] == b'/') {
        return p.to_string();
    }
    i += 1;
    while i < bytes.len() && (bytes[i] == b'\\' || bytes[i] == b'/') {
        i += 1;
    }
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }

    let drive = (bytes[0] as char).to_ascii_uppercase();
    let rest = p.get(i..).unwrap_or_default().trim_start();
    if rest.is_empty() {
        return format!("{drive}:\\");
    }
    format!("{drive}:\\{}", rest.replace('/', "\\"))
}

fn uppercase_drive_prefix(path: &str) -> String {
    let mut out = path.to_string();
    let bytes = out.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        out.replace_range(0..1, &(bytes[0] as char).to_ascii_uppercase().to_string());
    }
    out
}

fn drop_duplicate_drive_prefix(path: &str) -> String {
    let bytes = path.as_bytes();
    if bytes.len() < 6 {
        return path.to_string();
    }
    if !(bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\') {
        return path.to_string();
    }
    if bytes[3].is_ascii_alphabetic() && bytes[4] == b':' && bytes[5] == b'\\' {
        return format!("{}{}", &path[..3], &path[6..]);
    }
    path.to_string()
}

fn starts_with_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .get(..needle.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(needle))
}

#[cfg(windows)]
fn build_device_volume_map() -> HashMap<String, String> {
    let mut out = HashMap::new();
    for b in b'A'..=b'Z' {
        let letter = b as char;
        let drive = format!("{letter}:");
        let root = PathBuf::from(format!("{drive}\\"));
        if !root.exists() {
            continue;
        }
        let Some(target) = query_dos_device_target(&drive) else {
            continue;
        };
        let norm = target.replace('/', "\\");
        if starts_with_ci(&norm, "\\device\\harddiskvolume") {
            out.insert(norm.to_ascii_lowercase(), drive.clone());
        }
    }
    out
}

#[cfg(not(windows))]
fn build_device_volume_map() -> HashMap<String, String> {
    HashMap::new()
}

#[cfg(windows)]
fn query_dos_device_target(drive: &str) -> Option<String> {
    unsafe extern "system" {
        fn QueryDosDeviceW(lpDeviceName: *const u16, lpTargetPath: *mut u16, ucchMax: u32) -> u32;
    }

    let mut name: Vec<u16> = drive.encode_utf16().collect();
    name.push(0);
    let mut buf = vec![0u16; 4096];
    // SAFETY: pointers are valid for writes/reads and buffers are NUL-terminated.
    let len = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 {
        return None;
    }
    let used = len as usize;
    let first_end = buf[..used].iter().position(|&x| x == 0).unwrap_or(used);
    if first_end == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..first_end]))
}

fn map_device_path_to_drive(path: &str) -> Option<String> {
    map_device_path_to_drive_with_map(path, &DEVICE_VOLUME_MAP)
}

fn map_device_path_to_drive_with_map(path: &str, map: &HashMap<String, String>) -> Option<String> {
    let mut p = path.trim().replace('/', "\\");
    if starts_with_ci(&p, "device\\harddiskvolume") {
        p = format!("\\{p}");
    }
    let lower = p.to_ascii_lowercase();
    let prefix = "\\device\\harddiskvolume";
    if !lower.starts_with(prefix) {
        return None;
    }
    let mut idx = prefix.len();
    let bytes = lower.as_bytes();
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx >= bytes.len() || bytes[idx] != b'\\' {
        return None;
    }
    let volume = p[..idx].to_ascii_lowercase();
    let drive = if let Some(mapped) = map.get(&volume) {
        mapped.clone()
    } else {
        let number = lower[prefix.len()..idx].parse::<u32>().ok()?;
        let letter = fallback_drive_letter_from_volume(number)?;
        format!("{letter}:")
    };
    Some(format!("{drive}{}", &p[idx..]))
}

fn fallback_drive_letter_from_volume(volume_number: u32) -> Option<char> {
    // Heuristic requested by user: HarddiskVolume3 -> C, 4 -> D, ...
    if !(1..=26).contains(&volume_number) {
        return None;
    }
    let letter = (b'A' + (volume_number as u8 - 1)) as char;
    Some(letter)
}

fn strip_drive_prefix_if_device_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    if bytes.len() < 4 {
        return None;
    }
    if !(bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\') {
        return None;
    }
    let rest = &path[3..];
    if starts_with_ci(rest, "device\\harddiskvolume") {
        Some(rest.to_string())
    } else {
        None
    }
}

fn device_volume_tail(path: &str) -> Option<String> {
    let mut p = path.trim().replace('/', "\\");
    if let Some(rest) = strip_drive_prefix_if_device_path(&p) {
        p = format!("\\{rest}");
    } else if starts_with_ci(&p, "device\\harddiskvolume") {
        p = format!("\\{p}");
    }

    let lower = p.to_ascii_lowercase();
    let prefix = "\\device\\harddiskvolume";
    if !lower.starts_with(prefix) {
        return None;
    }
    let mut idx = prefix.len();
    let bytes = lower.as_bytes();
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx >= bytes.len() || bytes[idx] != b'\\' {
        return None;
    }
    let tail = p.get(idx + 1..)?.trim();
    if tail.is_empty() {
        return None;
    }
    Some(tail.to_string())
}

fn path_suffix_after_drive(path: &str) -> Option<String> {
    let p = path.replace('/', "\\");
    let b = p.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
        return Some(p[2..].to_ascii_lowercase());
    }
    None
}

fn dedupe_paths_case_insensitive(items: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut seen = HashSet::new();
    for item in items {
        if seen.insert(normalize_cmp_path(item)) {
            out.insert(item.clone());
        }
    }
    out
}

fn drive_letter_from_path(path: &str) -> Option<char> {
    let n = normalize_full_windows_path(path);
    let b = n.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return Some((b[0] as char).to_ascii_uppercase());
    }
    None
}

fn filter_paths_not_on_primary_disks(
    paths: &BTreeSet<String>,
    primary: &[char],
) -> BTreeSet<String> {
    let primary_set = primary
        .iter()
        .map(|x| x.to_ascii_uppercase())
        .collect::<HashSet<_>>();
    let mut out = BTreeSet::new();
    for p in paths {
        let n = normalize_full_windows_path(p);
        if !is_valid_other_disk_candidate(&n) {
            continue;
        }
        if let Some(letter) = drive_letter_from_normalized_path(&n) {
            if !primary_set.contains(&letter) {
                out.insert(n);
            }
            continue;
        }
        if starts_with_ci(&n, "\\device\\harddiskvolume") {
            out.insert(n);
            continue;
        }
        if is_probable_unc_path(&n) {
            out.insert(n);
        }
    }
    dedupe_paths_case_insensitive(&out)
}

fn is_probable_unc_path(path: &str) -> bool {
    if !path.starts_with("\\\\") {
        return false;
    }
    let rest = &path[2..];
    let mut parts = rest.split('\\');
    let host = parts.next().unwrap_or_default().trim();
    let share = parts.next().unwrap_or_default().trim();
    if host.is_empty() || share.is_empty() {
        return false;
    }
    let host_lower = host.to_ascii_lowercase();
    if [
        "users",
        "windows",
        "program files",
        "programdata",
        "appdata",
        "registry",
        "git",
        "steam",
        "dotnet",
        "microsoft",
    ]
    .contains(&host_lower.as_str())
    {
        return false;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return false;
    }
    if !share
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '$'))
    {
        return false;
    }
    let host_has_dot = host.contains('.');
    let host_has_digit = host.chars().any(|c| c.is_ascii_digit());
    let host_is_ipv4 = {
        let mut count = 0usize;
        let mut ok = true;
        for part in host.split('.') {
            if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
                ok = false;
                break;
            }
            count += 1;
        }
        ok && count == 4
    };
    host_has_dot || host_has_digit || host_is_ipv4
}

fn drive_letter_from_normalized_path(path: &str) -> Option<char> {
    let p = path.trim();
    let b = p.as_bytes();
    if b.is_empty() || !b[0].is_ascii_alphabetic() {
        return None;
    }
    let mut i = 1usize;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    if i < b.len() && b[i] == b':' {
        return Some((b[0] as char).to_ascii_uppercase());
    }
    None
}

fn is_valid_other_disk_candidate(path: &str) -> bool {
    if path.is_empty() || path.len() > 1024 {
        return false;
    }
    if path.chars().any(|c| c.is_control()) {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if is_probable_embedded_source_noise(&lower) {
        return false;
    }
    if lower.starts_with("\\registry\\") || lower.contains("\\registry\\") {
        return false;
    }
    if lower.contains("\\harddiskvolume") && !lower.contains("\\device\\harddiskvolume") {
        return false;
    }
    if has_multiple_absolute_roots(path) {
        return false;
    }
    if !is_valid_candidate_with_exts(path, RESOLVE_EXTS) {
        return false;
    }

    let file_name = Path::new(path)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    if file_name.is_empty() || file_name.contains(" .") || file_name.contains(". ") {
        return false;
    }

    windows_path_segments_are_sane(path)
}

fn has_multiple_absolute_roots(path: &str) -> bool {
    let mut roots = 0usize;
    if path.starts_with("\\\\") {
        roots += 1;
    }
    for (i, _) in path.char_indices() {
        if is_drive_root_at(path, i)
            || starts_with_ci_at(path, i, "\\device\\harddiskvolume")
            || (i == 0 && starts_with_ci_at(path, i, "device\\harddiskvolume"))
        {
            roots += 1;
            if roots > 1 {
                return true;
            }
        }
    }
    false
}

fn windows_path_segments_are_sane(path: &str) -> bool {
    if path.starts_with("\\\\") {
        let mut parts = path[2..].split('\\');
        let host = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        if host.is_empty() || share.is_empty() {
            return false;
        }
        for segment in parts {
            if !is_sane_windows_segment(segment) {
                return false;
            }
        }
        return true;
    }

    if let Some(_) = drive_letter_from_normalized_path(path) {
        for segment in path[3..].split('\\') {
            if !is_sane_windows_segment(segment) {
                return false;
            }
        }
        return true;
    }

    let mut lower = path.to_ascii_lowercase();
    lower = lower.replace('/', "\\");
    let prefix = "\\device\\harddiskvolume";
    if !lower.starts_with(prefix) {
        return false;
    }
    let bytes = lower.as_bytes();
    let mut idx = prefix.len();
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx >= bytes.len() || bytes[idx] != b'\\' {
        return false;
    }
    for segment in path[idx + 1..].split('\\') {
        if !is_sane_windows_segment(segment) {
            return false;
        }
    }
    true
}

fn is_sane_windows_segment(segment: &str) -> bool {
    if segment.is_empty() || segment.len() > 180 {
        return false;
    }
    if segment.starts_with(' ') || segment.ends_with(' ') || segment.ends_with('.') {
        return false;
    }
    if segment
        .chars()
        .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
    {
        return false;
    }
    true
}

fn should_include_deleted_path(path: &str) -> bool {
    let n = normalize_full_windows_path(path);
    if !is_abs_win(&n) {
        return false;
    }
    let Some(file_name) = Path::new(&n).file_name().and_then(OsStr::to_str) else {
        return false;
    };
    if !is_valid_file_name_with_exts(file_name, TRACKED_FILE_EXTS) {
        return false;
    }

    let lower_path = n.to_ascii_lowercase();
    if lower_path.contains(".dll.dll")
        || lower_path.contains(".exe.exe")
        || lower_path.contains(".jar.jar")
        || lower_path.contains(".pf.pf")
    {
        return false;
    }
    if lower_path.starts_with("c:\\.") || lower_path.starts_with("d:\\.") {
        return false;
    }
    if lower_path.contains("\\$recycle.bin\\")
        || lower_path.contains("\\system volume information\\")
        || lower_path.contains("\\windows\\winsxs\\")
        || lower_path.contains("\\windows\\servicing\\")
        || lower_path.contains("\\windows\\installer\\")
    {
        return false;
    }

    let Some(stem) = Path::new(file_name).file_stem().and_then(OsStr::to_str) else {
        return false;
    };
    if !is_high_signal_name_stem(stem) {
        return false;
    }
    let lower_name = file_name.to_ascii_lowercase();
    let ext = Path::new(file_name)
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let suspicious = has_suspicious_keyword(&lower_name) || has_suspicious_keyword(&lower_path);
    if is_common_windows_binary_stem(stem) && !suspicious {
        return false;
    }
    if is_likely_build_artifact_name(stem) && !suspicious {
        return false;
    }

    let in_user_scope = lower_path.contains("\\users\\")
        || lower_path.contains("\\appdata\\")
        || lower_path.contains("\\programdata\\")
        || lower_path.contains("\\desktop\\")
        || lower_path.contains("\\downloads\\")
        || lower_path.contains("\\temp\\")
        || lower_path.contains("\\tlauncher\\")
        || lower_path.contains("\\minecraft\\");
    let high_risk_scope = lower_path.contains("\\downloads\\")
        || lower_path.contains("\\desktop\\")
        || lower_path.contains("\\appdata\\local\\temp\\")
        || lower_path.contains("\\temp\\")
        || lower_path.contains("\\tlauncher\\")
        || lower_path.contains("\\minecraft\\")
        || lower_path.contains("\\users\\public\\")
        || lower_path.contains("\\programdata\\");

    let mut score = 0i32;
    if suspicious {
        score += 3;
    }
    if high_risk_scope {
        score += 1;
    }
    match ext.as_str() {
        "exe" | "jar" | "bat" | "cmd" | "ps1" => score += 1,
        "dll" => score -= 1,
        _ => {}
    }

    if let Some(letter) = drive_letter_from_path(&n) {
        if !PRIMARY_LOCAL_DISKS.contains(&letter) {
            score += 1;
        } else if !in_user_scope && !suspicious {
            return false;
        }
    } else if !suspicious {
        return false;
    }

    if is_likely_build_artifact_name(stem) {
        score -= 2;
    }

    score >= 2
}

fn should_include_deleted_name(name: &str) -> bool {
    let Some(n) = normalize_pathless_name_with_exts(name, TRACKED_FILE_EXTS) else {
        return false;
    };
    if !has_suspicious_keyword(&n) {
        return false;
    }
    let Some(stem) = Path::new(&n).file_stem().and_then(OsStr::to_str) else {
        return false;
    };
    is_high_signal_name_stem(stem)
        && !is_common_windows_binary_stem(stem)
        && !is_likely_build_artifact_name(stem)
}

fn should_include_prefetch_deleted_name(prefetch_name: &str) -> bool {
    let Some(program_hint) = prefetch_program_hint(prefetch_name) else {
        return false;
    };
    let Some(normalized) = normalize_pathless_name_with_exts(&program_hint, TRACKED_FILE_EXTS)
    else {
        return false;
    };
    let Some(stem) = Path::new(&normalized).file_stem().and_then(OsStr::to_str) else {
        return false;
    };
    let lower = normalized.to_ascii_lowercase();
    let suspicious_keyword = SUSPICIOUS.iter().any(|k| lower.contains(k))
        || is_false_positive_suspicious_path_lc(&lower);
    suspicious_keyword
        && is_high_signal_name_stem(stem)
        && !is_common_windows_binary_stem(stem)
        && !is_likely_build_artifact_name(stem)
}

fn is_common_windows_binary_stem(stem: &str) -> bool {
    matches!(
        stem.trim().to_ascii_lowercase().as_str(),
        "svchost"
            | "csrss"
            | "wininit"
            | "winlogon"
            | "smss"
            | "lsass"
            | "services"
            | "dwm"
            | "explorer"
            | "taskhostw"
            | "runtimebroker"
            | "searchindexer"
            | "sihost"
            | "conhost"
            | "dllhost"
            | "sppsvc"
            | "trustedinstaller"
            | "werfault"
            | "wermgr"
            | "rundll32"
            | "regsvr32"
            | "cmd"
            | "powershell"
            | "msbuild"
            | "javaw"
            | "java"
    )
}

fn is_likely_build_artifact_name(stem: &str) -> bool {
    let s = stem.trim().to_ascii_lowercase();
    if s.starts_with("api-ms-win-") || s.starts_with("ext-ms-win-") {
        return true;
    }
    if s.starts_with("lib")
        && (s.contains("rmeta")
            || s.contains("rlib")
            || s.contains("rust")
            || s.contains("cargo")
            || s.contains("bitflags")
            || s.contains("windows")
            || s.contains("serde")
            || s.contains("tokio")
            || s.contains("futures")
            || s.contains("thiserror")
            || s.contains("version_check")
            || s.contains("proc_macro"))
    {
        return true;
    }
    s.contains(".resources")
        || s.contains("build-script")
        || s.contains("thumbcache")
        || s.contains("iconcache")
}

fn is_high_signal_name_stem(stem: &str) -> bool {
    let s = stem.trim().to_ascii_lowercase();
    if s.len() < 4 || s.len() > 96 {
        return false;
    }
    if !s.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' ' | '.'))
    {
        return false;
    }
    if s.contains(".exe") || s.contains(".dll") || s.contains(".jar") || s.contains(".pf") {
        return false;
    }
    let mut alpha = 0usize;
    let mut digit = 0usize;
    for ch in s.chars() {
        if ch.is_ascii_alphabetic() {
            alpha += 1;
        } else if ch.is_ascii_digit() {
            digit += 1;
        }
    }
    if alpha < 3 {
        return false;
    }
    if digit > alpha * 2 {
        return false;
    }
    if s.len() >= 10
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
    {
        return false;
    }
    true
}

fn has_suspicious_keyword(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if is_false_positive_suspicious_path_lc(&lower) {
        return false;
    }
    SUSPICIOUS.iter().any(|k| lower.contains(k))
}

fn is_false_positive_suspicious_path_lc(lower: &str) -> bool {
    if lower.is_empty() {
        return false;
    }
    let file_name = Path::new(lower)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(lower)
        .trim()
        .to_ascii_lowercase();
    FALSE_POSITIVE_SUSPICIOUS_FILE_NAMES
        .iter()
        .any(|name| file_name == *name)
}

fn load_embedded_blake3_hashes() -> HashSet<String> {
    let mut hashes = HashSet::new();
    for f in BLAKE3_HASH_DIR.files() {
        if let Some(content) = f.contents_utf8() {
            for line in content.lines() {
                if let Some(hash) = extract_blake3_token(line) {
                    hashes.insert(hash);
                }
            }
            continue;
        }

        let lossy = String::from_utf8_lossy(f.contents());
        for line in lossy.lines() {
            if let Some(hash) = extract_blake3_token(line) {
                hashes.insert(hash);
            }
        }
    }
    hashes
}

#[derive(Clone)]
struct HashCacheEntry {
    size: u64,
    mtime_ns: u128,
    hash: String,
}

fn split_allpe_by_embedded_blake3(
    allpe: &BTreeSet<String>,
    normal_hashes: &HashSet<String>,
    cache_path: &Path,
    _sort_hash: bool,
) -> io::Result<(BTreeSet<String>, BTreeSet<String>, usize)> {
    if allpe.is_empty() || normal_hashes.is_empty() {
        return Ok((allpe.clone(), BTreeSet::new(), 0));
    }

    let force_full_hash = env::var("RSS_ANALYS_HASH_ALLPE")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false);
    let mut passthrough = BTreeSet::new();
    let mut hash_scope = Vec::new();
    for path in allpe {
        if force_full_hash || should_hash_normalpe_candidate(path) {
            hash_scope.push(path.clone());
        } else {
            passthrough.insert(path.clone());
        }
    }
    let hash_soft_limit = env::var("RSS_ANALYS_HASH_SOFT_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(300, 20_000))
        .unwrap_or(2_400);
    if !force_full_hash && hash_scope.len() > hash_soft_limit {
        let before_hash_scope = hash_scope.len();
        hash_scope.sort_by(|a, b| {
            normalpe_hash_priority(b)
                .cmp(&normalpe_hash_priority(a))
                .then_with(|| a.cmp(b))
        });
        let dropped = hash_scope.split_off(hash_soft_limit);
        passthrough.extend(dropped);
        log_info(&format!(
            "{}: {} -> {}",
            tr_ui("Ограничение BLAKE3 scope", "BLAKE3 scope trim"),
            before_hash_scope,
            hash_scope.len()
        ));
    }

    if hash_scope.is_empty() {
        return Ok((allpe.clone(), BTreeSet::new(), 0));
    }

    let mut cache_map = load_blake3_cache(cache_path);
    let files = Arc::new(hash_scope);
    let known = Arc::new(normal_hashes.clone());
    let cache_ro = Arc::new(cache_map.clone());
    let cfg = choose_blake3_filter_cfg(files.len());
    log_info(tr_ui("Сканирование BLAKE3", "Scanning BLAKE3"));

    let cursor = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel::<(
        Vec<String>,
        Vec<String>,
        Vec<(String, HashCacheEntry)>,
        usize,
    )>();

    for _ in 0..cfg.workers {
        let files = Arc::clone(&files);
        let known = Arc::clone(&known);
        let cache_ro = Arc::clone(&cache_ro);
        let cursor = Arc::clone(&cursor);
        let tx = tx.clone();
        let batch_size = cfg.batch_size;
        let buffer_size_mb = cfg.buffer_size_mb;

        thread::spawn(move || {
            let mut unknown = Vec::new();
            let mut normal = Vec::new();
            let mut updates = Vec::new();
            let mut hits = 0usize;
            let mut buf = vec![0u8; buffer_size_mb * 1024 * 1024];

            loop {
                let start = cursor.fetch_add(batch_size, Ordering::Relaxed);
                if start >= files.len() {
                    break;
                }
                let end = (start + batch_size).min(files.len());
                for p in &files[start..end] {
                    let key = normalize_cmp_path(p);
                    let mut hash_opt = None;

                    if let Ok((size, mtime_ns)) = file_fingerprint(p) {
                        if let Some(cached) = cache_ro.get(&key) {
                            if cached.size == size && cached.mtime_ns == mtime_ns {
                                hash_opt = Some(cached.hash.clone());
                                hits += 1;
                            }
                        }
                        if hash_opt.is_none() {
                            if let Ok(hash) = blake3_file_hex(p, &mut buf) {
                                updates.push((
                                    key.clone(),
                                    HashCacheEntry {
                                        size,
                                        mtime_ns,
                                        hash: hash.clone(),
                                    },
                                ));
                                hash_opt = Some(hash);
                            }
                        }
                    } else if let Ok(hash) = blake3_file_hex(p, &mut buf) {
                        hash_opt = Some(hash);
                    }

                    let Some(hash) = hash_opt else {
                        unknown.push(p.clone());
                        continue;
                    };

                    if known.contains(&hash) {
                        normal.push(p.clone());
                    } else {
                        unknown.push(p.clone());
                    }
                }
            }

            let _ = tx.send((unknown, normal, updates, hits));
        });
    }
    drop(tx);

    let mut allpe_filtered = passthrough;
    let mut normal_pe = BTreeSet::new();
    let mut cache_hits = 0usize;
    for (unknown, normal, updates, hits) in rx {
        allpe_filtered.extend(unknown.into_iter());
        normal_pe.extend(normal.into_iter());
        cache_hits += hits;
        for (k, v) in updates {
            cache_map.insert(k, v);
        }
    }

    save_blake3_cache(cache_path, &cache_map)?;
    Ok((allpe_filtered, normal_pe, cache_hits))
}

fn should_hash_normalpe_candidate(path: &str) -> bool {
    let lower = normalize_cmp_path(path);
    if lower.is_empty() {
        return false;
    }
    if is_build_or_dependency_artifact_path_lc(&lower) {
        return false;
    }
    if has_high_signal_path_keyword_lc(&lower) {
        return true;
    }
    if lower.contains("\\users\\")
        || lower.contains("\\programdata\\")
        || lower.contains("\\downloads\\")
        || lower.contains("\\desktop\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\$recycle.bin\\")
        || lower.contains("\\windows\\temp\\")
        || lower.contains("\\windows\\tasks\\")
        || lower.contains("\\windows\\prefetch\\")
    {
        return true;
    }
    !(lower.starts_with("c:\\windows\\")
        || lower.starts_with("c:\\program files\\")
        || lower.starts_with("c:\\program files (x86)\\"))
}

fn normalpe_hash_priority(path: &str) -> usize {
    let lower = normalize_cmp_path(path);
    let mut score = 0usize;
    if has_high_signal_path_keyword_lc(&lower) {
        score += 80;
    }
    if lower.contains("\\users\\")
        || lower.contains("\\downloads\\")
        || lower.contains("\\desktop\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\programdata\\")
    {
        score += 30;
    }
    if lower.ends_with(".sys") {
        score += 22;
    } else if lower.ends_with(".exe") {
        score += 16;
    } else if lower.ends_with(".dll") {
        score += 12;
    }
    if lower.starts_with("c:\\windows\\") || lower.starts_with("c:\\program files\\") {
        score = score.saturating_sub(10);
    }
    score
}

struct Blake3FilterCfg {
    workers: usize,
    batch_size: usize,
    buffer_size_mb: usize,
}

fn choose_blake3_filter_cfg(file_count: usize) -> Blake3FilterCfg {
    if file_count == 0 {
        return Blake3FilterCfg {
            workers: 1,
            batch_size: 100,
            buffer_size_mb: 4,
        };
    }

    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    let mut workers = cpu.clamp(2, 12).min(cpu_budget);
    workers = workers.min(file_count.max(1));

    let mut sys = System::new();
    sys.refresh_memory();
    let available_gb = (sys.available_memory() / 1024 / 1024 / 1024) as usize;
    let mem_cap = match available_gb {
        0..=3 => 2,
        4..=7 => 4,
        8..=11 => 6,
        12..=15 => 8,
        16..=23 => 10,
        _ => 12,
    };
    workers = workers.min(mem_cap).min(cpu_budget).max(1);

    let batch_size =
        (220 + cpu.saturating_sub(1).min(16) * 20 + available_gb.min(16) * 10).clamp(220, 1200);
    let buffer_size_mb = match available_gb {
        0..=3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        _ => 6,
    };

    Blake3FilterCfg {
        workers,
        batch_size,
        buffer_size_mb,
    }
}

fn load_blake3_cache(path: &Path) -> HashMap<String, HashCacheEntry> {
    let mut out = HashMap::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return out,
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };
        let mut parts = line.split('\t');
        let Some(path_key) = parts.next() else {
            continue;
        };
        let Some(size_s) = parts.next() else {
            continue;
        };
        let Some(mtime_s) = parts.next() else {
            continue;
        };
        let Some(hash) = parts.next() else {
            continue;
        };
        if extract_blake3_token(hash).is_none() {
            continue;
        }
        let Ok(size) = size_s.parse::<u64>() else {
            continue;
        };
        let Ok(mtime_ns) = mtime_s.parse::<u128>() else {
            continue;
        };
        out.insert(
            path_key.to_string(),
            HashCacheEntry {
                size,
                mtime_ns,
                hash: hash.to_ascii_lowercase(),
            },
        );
    }
    out
}

fn save_blake3_cache(path: &Path, map: &HashMap<String, HashCacheEntry>) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = BufWriter::with_capacity(IO_STREAM_BUFFER_BYTES, File::create(path)?);
    for (k, v) in map {
        writeln!(f, "{}\t{}\t{}\t{}", k, v.size, v.mtime_ns, v.hash)?;
    }
    f.flush()?;
    Ok(())
}

fn file_fingerprint(path: &str) -> io::Result<(u64, u128)> {
    let meta = fs::metadata(path)?;
    let size = meta.len();
    let modified = meta.modified().unwrap_or(UNIX_EPOCH);
    let mtime_ns = modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok((size, mtime_ns))
}

fn blake3_file_hex(path: &str, buf: &mut Vec<u8>) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Blake3Hasher::new();
    loop {
        let read = reader.read(buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn extract_blake3_token(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() == 64 && trimmed.as_bytes().iter().all(|b| is_hex_ascii(*b)) {
        return Some(trimmed.to_ascii_lowercase());
    }

    let bytes = trimmed.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    for i in 0..=bytes.len() - 64 {
        let token = &bytes[i..i + 64];
        if !token.iter().all(|b| is_hex_ascii(*b)) {
            continue;
        }
        let left_ok = i == 0 || !is_hex_ascii(bytes[i - 1]);
        let right_ok = i + 64 == bytes.len() || !is_hex_ascii(bytes[i + 64]);
        if left_ok && right_ok {
            let mut out = String::with_capacity(64);
            for b in token {
                out.push((*b as char).to_ascii_lowercase());
            }
            return Some(out);
        }
    }
    None
}

fn is_hex_ascii(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn normalize_cmp_path(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

fn file_name_lower(path_or_name: &str) -> Option<String> {
    Path::new(path_or_name)
        .file_name()
        .and_then(OsStr::to_str)
        .map(|s| s.to_ascii_lowercase())
}

#[cfg(test)]
fn normalize_pathless_name(name: &str) -> Option<String> {
    normalize_pathless_name_with_exts(name, BIN_EXTS)
}

fn normalize_pathless_name_with_exts(name: &str, exts: &[&str]) -> Option<String> {
    let trimmed = name
        .trim()
        .trim_matches(|c: char| "\"'` ,;:|)]}".contains(c))
        .to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    if !is_valid_file_name_with_exts(&trimmed, exts) {
        return None;
    }
    Some(trimmed)
}

fn normalize_pathless_name_any(name: &str) -> Option<String> {
    let trimmed = name
        .trim()
        .trim_matches(|c: char| "\"'` ,;:|)]}".contains(c))
        .to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    if !is_valid_file_name_any(&trimmed) {
        return None;
    }
    Some(trimmed)
}

fn normalize_time_hint(raw: &str) -> Option<String> {
    let value = raw
        .trim()
        .trim_matches(|c: char| "\"'` ,;|)]}([{".contains(c))
        .to_string();
    if value.is_empty() {
        return None;
    }

    if let Some(caps) = YMD_TIME_HINT_RE.captures(&value) {
        let year = caps.get(1)?.as_str().parse::<u32>().ok()?;
        let month = caps.get(2)?.as_str().parse::<u32>().ok()?;
        let day = caps.get(3)?.as_str().parse::<u32>().ok()?;
        if !is_valid_date_ymd(year, month, day) {
            return None;
        }
        let mut out = format!("{year:04}-{month:02}-{day:02}");
        let h = caps.get(4).map(|m| m.as_str());
        let m = caps.get(5).map(|m| m.as_str());
        let s = caps.get(6).map(|m| m.as_str());
        match (h, m, s) {
            (Some(h), Some(mn), Some(sv)) => {
                let hour = h.parse::<u32>().ok()?;
                let minute = mn.parse::<u32>().ok()?;
                let second = sv.parse::<u32>().ok()?;
                if !is_valid_hms(hour, minute, second) {
                    return None;
                }
                out.push_str(&format!(" {hour:02}:{minute:02}:{second:02}"));
                if let Some(frac) = caps
                    .get(7)
                    .map(|m| m.as_str().trim())
                    .filter(|x| !x.is_empty())
                {
                    out.push('.');
                    out.push_str(frac);
                }
                if let Some(tz_raw) = caps
                    .get(8)
                    .map(|m| m.as_str().trim())
                    .filter(|x| !x.is_empty())
                    && let Some(tz) = normalize_tz_suffix(tz_raw)
                {
                    out.push(' ');
                    out.push_str(&tz);
                }
            }
            (None, None, None) => {}
            _ => return None,
        }
        return Some(out);
    }

    if let Some(caps) = DMY_TIME_HINT_RE.captures(&value) {
        let day = caps.get(1)?.as_str().parse::<u32>().ok()?;
        let month = caps.get(2)?.as_str().parse::<u32>().ok()?;
        let year = caps.get(3)?.as_str().parse::<u32>().ok()?;
        if !is_valid_date_ymd(year, month, day) {
            return None;
        }
        let mut out = format!("{year:04}-{month:02}-{day:02}");
        let h = caps.get(4).map(|m| m.as_str());
        let m = caps.get(5).map(|m| m.as_str());
        let s = caps.get(6).map(|m| m.as_str());
        match (h, m, s) {
            (Some(h), Some(mn), Some(sv)) => {
                let hour = h.parse::<u32>().ok()?;
                let minute = mn.parse::<u32>().ok()?;
                let second = sv.parse::<u32>().ok()?;
                if !is_valid_hms(hour, minute, second) {
                    return None;
                }
                out.push_str(&format!(" {hour:02}:{minute:02}:{second:02}"));
                if let Some(frac) = caps
                    .get(7)
                    .map(|m| m.as_str().trim())
                    .filter(|x| !x.is_empty())
                {
                    out.push('.');
                    out.push_str(frac);
                }
            }
            (None, None, None) => {}
            _ => return None,
        }
        return Some(out);
    }
    None
}

fn is_valid_date_ymd(year: u32, month: u32, day: u32) -> bool {
    if !(1990..=2100).contains(&year) {
        return false;
    }
    if !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let dim = days_in_month(year, month);
    day <= dim
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_valid_hms(hour: u32, minute: u32, second: u32) -> bool {
    hour <= 23 && minute <= 59 && second <= 59
}

fn normalize_tz_suffix(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.eq_ignore_ascii_case("z") {
        return Some("Z".to_string());
    }
    let sign = t.chars().next()?;
    if sign != '+' && sign != '-' {
        return None;
    }
    let digits = t.get(1..)?.replace(':', "");
    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let hh = digits.get(0..2)?.parse::<u32>().ok()?;
    let mm = digits.get(2..4)?.parse::<u32>().ok()?;
    if hh > 23 || mm > 59 {
        return None;
    }
    Some(format!("{sign}{hh:02}:{mm:02}"))
}

fn extract_line_time_hints(raw: &str) -> Vec<String> {
    if raw.len() < 10 {
        return Vec::new();
    }
    if !raw.as_bytes().iter().any(|b| b.is_ascii_digit()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in FILE_TIME_HINT_RE
        .find_iter(raw)
        .take(MAX_FILE_TIME_HINTS_PER_ROW)
    {
        let Some(normalized) = normalize_time_hint(m.as_str()) else {
            continue;
        };
        let key = normalized.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(normalized);
        }
    }
    out
}

fn file_time_hint_keys(path_or_name: &str) -> Vec<String> {
    let normalized = normalize_full_windows_path(path_or_name);
    let mut keys = Vec::with_capacity(2);
    let mut seen = HashSet::new();
    if is_abs_win(&normalized) {
        let path_key = format!("p:{}", normalize_cmp_path(&normalized));
        if seen.insert(path_key.clone()) {
            keys.push(path_key);
        }
    }
    if let Some(name) = normalize_pathless_name_any(
        Path::new(&normalized)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(&normalized),
    ) {
        let name_key = format!("n:{name}");
        if seen.insert(name_key.clone()) {
            keys.push(name_key);
        }
    }
    keys
}

fn file_time_hint_value(
    time_hints: &HashMap<String, BTreeSet<String>>,
    path_or_name: &str,
) -> Option<String> {
    let values = collect_file_time_hint_values(time_hints, path_or_name);
    if values.is_empty() {
        None
    } else {
        Some(
            values
                .into_iter()
                .take(MAX_FILE_TIME_HINTS_PER_ROW)
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

fn collect_file_time_hint_values(
    time_hints: &HashMap<String, BTreeSet<String>>,
    path_or_name: &str,
) -> Vec<String> {
    let mut merged = BTreeSet::new();
    for key in file_time_hint_keys(path_or_name) {
        let Some(values) = time_hints.get(&key) else {
            continue;
        };
        merged.extend(values.iter().cloned());
    }
    merged.into_iter().collect()
}

fn build_file_dates_rows(a: &Analyzer) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    files.extend(a.full_paths.iter().cloned());
    files.extend(a.pathless.iter().cloned());
    files.extend(a.java_paths.iter().cloned());
    files.extend(a.scripts.iter().cloned());
    files.extend(a.start.iter().cloned());
    files.extend(a.prefetch.iter().cloned());
    files.extend(a.dps_files.iter().cloned());
    for (file, _) in &a.dps_events {
        files.insert(file.clone());
    }

    let mut out = BTreeSet::new();
    for file in files {
        let values = collect_file_time_hint_values(&a.file_time_hints, &file);
        if values.is_empty() {
            continue;
        }
        out.insert(format!("{file} | {}", values.join(", ")));
    }
    out
}

fn is_valid_binary_candidate(path_or_name: &str) -> bool {
    is_valid_candidate_with_exts(path_or_name, BIN_EXTS)
}

fn is_valid_any_file_candidate(path_or_name: &str) -> bool {
    if path_or_name.is_empty() {
        return false;
    }
    let normalized = normalize_full_windows_path(path_or_name);
    let lower = normalized.to_ascii_lowercase();
    if lower.contains("://") || lower.contains("https:\\") || lower.contains("http:\\") {
        return false;
    }
    if normalized.contains('*')
        || normalized.contains('?')
        || normalized.contains('<')
        || normalized.contains('>')
        || normalized.contains('|')
    {
        return false;
    }
    if is_abs_win(&normalized)
        && (has_multiple_absolute_roots(&normalized)
            || !windows_path_segments_are_sane(&normalized)
            || has_path_quality_red_flags(&normalized))
    {
        return false;
    }

    let file_name = Path::new(&normalized)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(&normalized);

    is_valid_file_name_any(file_name)
}

fn is_valid_candidate_with_exts(path_or_name: &str, exts: &[&str]) -> bool {
    if path_or_name.is_empty() {
        return false;
    }
    let normalized = normalize_full_windows_path(path_or_name);
    let lower = normalized.to_ascii_lowercase();
    if lower.contains("://") || lower.contains("https:\\") || lower.contains("http:\\") {
        return false;
    }
    if normalized.contains('*')
        || normalized.contains('?')
        || normalized.contains('<')
        || normalized.contains('>')
        || normalized.contains('|')
    {
        return false;
    }
    if is_abs_win(&normalized)
        && (has_multiple_absolute_roots(&normalized)
            || !windows_path_segments_are_sane(&normalized)
            || has_path_quality_red_flags(&normalized))
    {
        return false;
    }

    let file_name = Path::new(&normalized)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(&normalized);

    is_valid_file_name_with_exts(file_name, exts)
}

fn is_valid_file_name_any(file_name: &str) -> bool {
    if file_name.is_empty() || file_name.starts_with('.') {
        return false;
    }
    if file_name.ends_with('.') || file_name.ends_with(' ') {
        return false;
    }
    let ext = Path::new(file_name).extension().and_then(OsStr::to_str);
    if let Some(ext) = ext {
        if ext.is_empty() || ext.len() > 16 {
            return false;
        }
        if !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
            return false;
        }
    }
    let Some(stem) = Path::new(file_name).file_stem().and_then(OsStr::to_str) else {
        return false;
    };
    if stem.is_empty() || stem.starts_with('.') {
        return false;
    }
    let Some(first) = stem.chars().next() else {
        return false;
    };
    if !matches!(first, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '$' | '[' | '(') {
        return false;
    }
    if stem.chars().any(|c| "<>:\"/\\|?*".contains(c)) {
        return false;
    }
    if stem.ends_with(' ') || stem.ends_with('.') || stem.contains(" .") || stem.contains(". ") {
        return false;
    }
    if !stem.chars().any(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if !is_plausible_name_stem(stem) {
        return false;
    }
    true
}

fn is_valid_file_name_with_exts(file_name: &str, exts: &[&str]) -> bool {
    if file_name.is_empty() || file_name.starts_with('.') {
        return false;
    }
    let Some(ext) = Path::new(file_name).extension().and_then(OsStr::to_str) else {
        return false;
    };
    if !exts.contains(&ext.to_ascii_lowercase().as_str()) {
        return false;
    }
    let Some(stem) = Path::new(file_name).file_stem().and_then(OsStr::to_str) else {
        return false;
    };
    if stem.is_empty() || stem.starts_with('.') {
        return false;
    }
    let Some(first) = stem.chars().next() else {
        return false;
    };
    if !matches!(first, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '$' | '[' | '(') {
        return false;
    }
    if stem.chars().any(|c| "<>:\"/\\|?*".contains(c)) {
        return false;
    }
    if stem.ends_with(' ') || stem.ends_with('.') || stem.contains(" .") || stem.contains(". ") {
        return false;
    }
    if !stem.chars().any(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if !is_plausible_name_stem(stem) {
        return false;
    }
    true
}

fn is_plausible_name_stem(stem: &str) -> bool {
    let s = stem.trim();
    if s.is_empty() || s.len() > 96 {
        return false;
    }
    if s.contains("  ") {
        return false;
    }
    if s.split_whitespace().count() > 8 {
        return false;
    }
    if s.chars().filter(|c| c.is_ascii_whitespace()).count() > 5 {
        return false;
    }
    if s.chars().any(|c| matches!(c, '{' | '}' | '^' | '`' | '~')) {
        return false;
    }
    if s.matches('%').count() >= 2 {
        return false;
    }
    if !has_balanced_brackets(s, '(', ')') || !has_balanced_brackets(s, '[', ']') {
        return false;
    }
    if s.starts_with('(') && !s.contains(')') {
        return false;
    }
    if s.starts_with('[') && !s.contains(']') {
        return false;
    }

    let alpha = s.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let digits = s.chars().filter(|c| c.is_ascii_digit()).count();
    if alpha == 0 {
        return false;
    }
    if digits > alpha.saturating_mul(3).saturating_add(8) {
        return false;
    }
    if s.len() >= 20
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
    {
        return false;
    }
    true
}

fn has_balanced_brackets(value: &str, open: char, close: char) -> bool {
    let mut depth = 0i32;
    for ch in value.chars() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            if depth == 0 {
                return false;
            }
            depth -= 1;
        }
    }
    depth == 0
}

fn has_path_quality_red_flags(path: &str) -> bool {
    if path.len() > 380 {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("pathext=.com;.exe")
        || lower.contains("logonserver=")
        || lower.contains("allusersprofile=")
        || lower.contains("localappdata=")
        || lower.contains("commonprogramfiles=")
        || lower.contains("commonprogramw6432=")
        || lower.contains("systemroot=")
        || lower.contains("userprofile=")
        || lower.contains("windir=")
    {
        return true;
    }
    if lower.matches(":\\").count() > 2 || lower.matches("\\device\\harddiskvolume").count() > 2 {
        return true;
    }
    if lower.contains("&#x") || lower.contains("~{") {
        return true;
    }
    if lower.matches("\\program files").count() > 1 {
        return true;
    }
    if lower.matches("\\windows\\").count() > 3 {
        return true;
    }
    if lower.contains("::") && !lower.contains("://") {
        return true;
    }
    if lower.matches('%').count() >= 4 {
        return true;
    }

    let segments = path_segments_for_quality(path);
    if segments.is_empty() {
        return true;
    }
    for (idx, segment) in segments.iter().enumerate() {
        let seg = segment.trim();
        if seg.is_empty() || seg.len() > 120 {
            return true;
        }
        if seg.contains("  ") {
            return true;
        }
        if seg.chars().filter(|c| c.is_ascii_whitespace()).count() > 5 {
            return true;
        }
        let seg_lower = seg.to_ascii_lowercase();
        if has_file_like_space_join_pattern(seg) {
            return true;
        }
        if idx + 1 != segments.len() {
            if seg_lower.contains(".exe")
                || seg_lower.contains(".dll")
                || seg_lower.contains(".jar")
                || seg_lower.contains(".bat")
                || seg_lower.contains(".cmd")
                || seg_lower.contains(".ps1")
                || seg_lower.contains(".pf")
            {
                return true;
            }
        } else if seg.contains(' ') && known_file_ext_mentions(&seg_lower) >= 2 {
            return true;
        } else if seg.contains('@') && (seg_lower.contains(".dll") || seg_lower.contains(".exe")) {
            return true;
        } else if seg_lower.contains(".e ") {
            return true;
        }
    }
    false
}

fn path_segments_for_quality(path: &str) -> Vec<&str> {
    if path.starts_with("\\\\") {
        let rest = &path[2..];
        let mut parts = rest.splitn(3, '\\');
        let _host = parts.next();
        let _share = parts.next();
        let tail = parts.next().unwrap_or_default();
        return tail.split('\\').filter(|x| !x.is_empty()).collect();
    }

    if has_drive_root_prefix(path) {
        return path[3..].split('\\').filter(|x| !x.is_empty()).collect();
    }

    let lower = path.to_ascii_lowercase();
    let prefix = "\\device\\harddiskvolume";
    if lower.starts_with(prefix) {
        let bytes = lower.as_bytes();
        let mut idx = prefix.len();
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx < bytes.len() && bytes[idx] == b'\\' {
            return path[idx + 1..]
                .split('\\')
                .filter(|x| !x.is_empty())
                .collect();
        }
    }
    path.split('\\').filter(|x| !x.is_empty()).collect()
}

fn has_file_like_space_join_pattern(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    for i in 1..bytes.len().saturating_sub(1) {
        if bytes[i] != b'.' {
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && bytes[j].is_ascii_alphanumeric() && j - i <= 8 {
            j += 1;
        }
        let ext_len = j.saturating_sub(i + 1);
        if !(1..=8).contains(&ext_len) {
            continue;
        }
        if j < bytes.len() && bytes[j].is_ascii_whitespace() {
            return true;
        }
    }
    false
}

fn known_file_ext_mentions(segment_lower: &str) -> usize {
    [
        ".exe", ".dll", ".jar", ".bat", ".cmd", ".ps1", ".pf", ".msi", ".sys", ".cat", ".ocx",
        ".scr", ".tmp", ".zip", ".rar", ".7z", ".png", ".jpg", ".jpeg", ".svg", ".ico",
    ]
    .iter()
    .filter(|ext| segment_lower.contains(**ext))
    .count()
}

fn make_status_rows(
    found: &BTreeSet<String>,
    deleted: &BTreeSet<String>,
    time_hints: &HashMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in found {
        let ts = file_time_hint_value(time_hints, item).unwrap_or_else(|| "-".to_string());
        out.insert(format!("{item} | {ts} | no deleted"));
    }
    for item in deleted {
        let ts = file_time_hint_value(time_hints, item).unwrap_or_else(|| "-".to_string());
        out.insert(format!("{item} | {ts} | deleted"));
    }
    out
}

fn deleted_status_row(
    group: &str,
    item: &str,
    status: &str,
    time_hints: &HashMap<String, BTreeSet<String>>,
) -> String {
    let ts = file_time_hint_value(time_hints, item).unwrap_or_else(|| "-".to_string());
    format!("{group}: {item} | {ts} | {status}")
}

fn collect_prefetch_program_lookup_names(
    prefetch_full: &BTreeSet<String>,
    prefetch_names: &BTreeSet<String>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    for item in prefetch_full {
        let Some(name) = normalize_prefetch_name(item) else {
            continue;
        };
        for candidate in prefetch_program_candidate_names(&name) {
            out.insert(candidate);
        }
    }
    for item in prefetch_names {
        let Some(name) = normalize_prefetch_name(item) else {
            continue;
        };
        for candidate in prefetch_program_candidate_names(&name) {
            out.insert(candidate);
        }
    }
    out
}

fn prefetch_program_hint(prefetch_name: &str) -> Option<String> {
    let caps = PREFETCH_NAME_RE.captures(prefetch_name)?;
    let base = caps.get(1)?.as_str().trim();
    if base.is_empty() {
        return None;
    }
    Some(base.to_string())
}

fn prefetch_program_candidate_names(prefetch_name: &str) -> Vec<String> {
    let Some(base) = prefetch_program_hint(prefetch_name) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let trimmed = base
        .trim()
        .trim_matches(|x: char| "\"'` ,;|)]}([{".contains(x));
    if trimmed.is_empty() {
        return out;
    }

    if Path::new(trimmed)
        .extension()
        .and_then(OsStr::to_str)
        .is_some()
    {
        if is_valid_file_name_any(trimmed) {
            let name = trimmed.to_ascii_lowercase();
            if seen.insert(name.clone()) {
                out.push(name);
            }
        }
    } else {
        let with_exe = format!("{trimmed}.exe");
        if is_valid_file_name_with_exts(&with_exe, &["exe"]) {
            let name = with_exe.to_ascii_lowercase();
            if seen.insert(name.clone()) {
                out.push(name);
            }
        }
    }

    out
}

fn build_prefetch_program_status_rows(
    found: &BTreeSet<String>,
    deleted: &BTreeSet<String>,
    name_index: &HashMap<String, BTreeSet<String>>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut found_names = BTreeSet::new();
    let mut missing_names = BTreeSet::new();
    for item in found {
        if let Some(name) = normalize_prefetch_name(item) {
            found_names.insert(name);
        }
    }
    for item in deleted {
        if let Some(name) = normalize_prefetch_name(item) {
            missing_names.insert(name);
        }
    }
    for name in &found_names {
        missing_names.remove(name);
    }

    let mut out = BTreeSet::new();
    let mut program_deleted = BTreeSet::new();
    for prefetch_name in &found_names {
        let candidates = prefetch_program_candidate_names(prefetch_name);
        let hint = prefetch_program_hint(prefetch_name).unwrap_or_else(|| "-".to_string());
        let found_program = candidates.iter().find_map(|name| {
            let mut rows = name_index.get(name)?.iter();
            rows.next().cloned()
        });
        if let Some(path) = found_program {
            out.insert(format!("{prefetch_name} | {path} | no deleted"));
        } else {
            out.insert(format!("{prefetch_name} | {hint} | program deleted"));
            program_deleted.insert(hint);
        }
    }
    for item in &missing_names {
        out.insert(format!("{item} | - | prefetch missing"));
    }
    (out, program_deleted)
}

fn build_dps_status_rows(
    events: &BTreeSet<(String, String)>,
    found: &BTreeSet<String>,
) -> BTreeSet<String> {
    let found_cmp = found
        .iter()
        .map(|x| normalize_cmp_path(x))
        .collect::<HashSet<_>>();
    let found_names = found
        .iter()
        .filter_map(|x| file_name_lower(x))
        .collect::<HashSet<_>>();

    let mut out = BTreeSet::new();
    for (file, value) in events {
        let normalized = normalize_full_windows_path(file);
        let display = Path::new(&normalized)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(&normalized)
            .trim()
            .trim_matches(|c: char| "\"'` ,;|)]}([{".contains(c))
            .to_string();
        if display.is_empty() {
            continue;
        }
        let (display_name, exists) = if is_abs_win(&normalized) {
            let present = found_cmp.contains(&normalize_cmp_path(&normalized))
                || file_name_lower(&normalized).is_some_and(|n| found_names.contains(&n));
            (display, present)
        } else if let Some(name_key) = normalize_pathless_name_any(&normalized) {
            if is_excluded_dps_name_lc(&name_key) {
                continue;
            }
            let present = found_names.contains(&name_key);
            (display, present)
        } else {
            continue;
        };
        let status = if exists { "no deleted" } else { "deleted" };
        out.insert(format!("{display_name} | {value} | {status}"));
    }
    out
}

fn suspicious_links(links: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for l in links {
        let lower = l.to_ascii_lowercase();
        if is_link_rule_syntax_noise_lc(&lower) {
            continue;
        }
        let Some((host, path)) = parse_link_host_and_path(l) else {
            continue;
        };
        if path.len() > 260 || looks_noisy_link_suffix(&path) {
            continue;
        }
        let host_l = host.to_ascii_lowercase();
        let combined = format!("{}{}", host_l, path.to_ascii_lowercase());
        if has_suspicious_domain_host(&host_l) || has_suspicious_link_keyword_lc(&combined) {
            out.insert(l.clone());
        }
    }
    out
}

fn collect_download_links(links: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for link in links {
        let Some((host, path)) = parse_link_host_and_path(link) else {
            continue;
        };
        let Some(file) = download_filename_from_link_path(&path) else {
            continue;
        };
        out.insert(format!("{host} | {file} | {link}"));
    }
    out
}

fn parse_link_host_and_path(link: &str) -> Option<(String, String)> {
    let body = if let Some((_, rest)) = link.split_once("://") {
        rest
    } else {
        link
    };
    if body.is_empty() {
        return None;
    }
    let cut = body.find(['/', '?', '#']).unwrap_or(body.len());
    let authority = body.get(..cut)?.trim();
    if authority.is_empty() {
        return None;
    }
    let suffix = body.get(cut..).unwrap_or("");
    if is_link_rule_syntax_noise_lc(&suffix.to_ascii_lowercase()) {
        return None;
    }
    if contains_nested_link_markers(suffix) {
        return None;
    }
    let auth_no_user = authority.rsplit('@').next().unwrap_or(authority);
    let (host_raw, _) = split_host_port(auth_no_user)?;
    let host = host_raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || !valid_host(&host)
        || !has_known_suffix(&host)
        || host_looks_generated(&host)
        || host_looks_like_prefetch_noise(&host)
    {
        return None;
    }

    let path = if suffix.is_empty() {
        "/".to_string()
    } else if suffix.starts_with('/') {
        suffix.to_string()
    } else {
        format!("/{suffix}")
    };
    Some((host, path))
}

fn download_filename_from_link_path(path: &str) -> Option<String> {
    let clean = path.split('?').next()?.split('#').next()?.trim();
    let lower = clean.to_ascii_lowercase();
    if lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://") {
        return None;
    }
    let file = clean.rsplit('/').next()?.trim();
    if file.is_empty() || file == "." || file == ".." {
        return None;
    }
    let file = file.trim_matches(|x: char| "\"'` ,;|)]}([{".contains(x));
    if file.is_empty() {
        return None;
    }
    let dot = file.rfind('.')?;
    if dot == 0 || dot >= file.len() - 1 {
        return None;
    }
    let ext = file[dot + 1..].to_ascii_lowercase();
    if !DOWNLOAD_LINK_EXTS.contains(&ext.as_str()) {
        return None;
    }
    Some(file.to_string())
}

fn suspicious_files(candidates: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for c in candidates {
        let normalized = normalize_full_windows_path(c);
        let lower = normalize_cmp_path(&normalized);
        if lower.is_empty() || lower.len() > 320 {
            continue;
        }
        if is_build_or_dependency_artifact_path_lc(&lower) || is_tool_artifact_path_noise_lc(&lower)
        {
            continue;
        }

        let file_name = Path::new(&lower)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(&lower)
            .to_ascii_lowercase();
        if is_false_positive_suspicious_path_lc(&file_name)
            || is_false_positive_suspicious_path_lc(&lower)
        {
            continue;
        }
        if !file_name.ends_with(".exe")
            && !file_name.ends_with(".dll")
            && !file_name.ends_with(".sys")
        {
            continue;
        }

        let has_high_signal_kw = CHEAT_ARTIFACT_KEYWORDS
            .iter()
            .any(|kw| keyword_match_lc(&lower, kw))
            || BYPASS_ARTIFACT_KEYWORDS
                .iter()
                .any(|kw| keyword_match_lc(&lower, kw))
            || SUSPICIOUS
                .iter()
                .any(|kw| keyword_match_lc(&file_name, kw) && kw.len() >= 5);
        if !has_high_signal_kw {
            continue;
        }

        let trusted_root = lower.starts_with("c:\\windows\\")
            || lower.starts_with("c:\\program files\\")
            || lower.starts_with("c:\\program files (x86)\\");
        let risky_path = lower.contains("\\appdata\\")
            || lower.contains("\\programdata\\")
            || lower.contains("\\users\\public\\")
            || lower.contains("\\temp\\")
            || lower.contains("\\recycle.bin\\")
            || lower.contains("\\drivers\\");
        if trusted_root && !risky_path {
            continue;
        }
        out.insert(normalized);
    }
    out
}

fn collect_keyword_artifacts(
    items: &BTreeSet<String>,
    links: &BTreeSet<String>,
    keywords: &[&str],
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in items {
        let normalized = normalize_full_windows_path(item);
        if normalized.len() > 320 || !is_valid_any_file_candidate(&normalized) {
            continue;
        }
        if normalized.contains('%') || normalized.contains("&#x") {
            continue;
        }
        if normalized.split_whitespace().count() > 28 || normalized.matches('\\').count() > 32 {
            continue;
        }
        let file_name = Path::new(&normalized)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(&normalized);
        let ext = Path::new(file_name)
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let stem_l = Path::new(file_name)
            .file_stem()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if ext != "pf" && tool_stem_has_embedded_extension(&stem_l) {
            continue;
        }
        let lower = normalized.to_ascii_lowercase();
        if is_tool_artifact_path_noise_lc(&lower) {
            continue;
        }
        if is_false_positive_suspicious_path_lc(&lower) {
            continue;
        }
        if let Some(keyword) = find_keyword_hit_in_path_scope_lc(&lower, keywords) {
            out.insert(format!("file | {keyword} | {normalized}"));
        }
    }
    for link in links {
        let Some((host, path)) = parse_link_host_and_path(link) else {
            continue;
        };
        let host_l = host.to_ascii_lowercase();
        if tool_link_host_is_noise(&host_l) {
            continue;
        }
        let Some(clean_path) = normalize_tool_link_path(&path) else {
            continue;
        };
        let high_signal_path = is_high_signal_tool_link_path(&clean_path);
        if is_low_value_tool_link_host(&host_l) && !high_signal_path {
            continue;
        }
        let scoped = format!("{}{}", host_l, clean_path.to_ascii_lowercase());
        let Some(keyword) = find_keyword_hit_lc(&scoped, keywords) else {
            continue;
        };
        let display = if clean_path != "/" && high_signal_path {
            format!("{host_l}{clean_path}")
        } else {
            host_l
        };
        out.insert(format!("link | {keyword} | {display}"));
    }
    out
}

fn collect_keyword_file_artifacts(items: &BTreeSet<String>, keywords: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in items {
        let normalized = normalize_full_windows_path(item);
        if normalized.len() > 320 || !is_valid_any_file_candidate(&normalized) {
            continue;
        }
        if normalized.contains('%') || normalized.contains("&#x") {
            continue;
        }
        if normalized.split_whitespace().count() > 28 || normalized.matches('\\').count() > 32 {
            continue;
        }
        let file_name = Path::new(&normalized)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(&normalized);
        let ext = Path::new(file_name)
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let stem_l = Path::new(file_name)
            .file_stem()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if ext != "pf" && tool_stem_has_embedded_extension(&stem_l) {
            continue;
        }
        let lower = normalized.to_ascii_lowercase();
        if is_tool_artifact_path_noise_lc(&lower) {
            continue;
        }
        if is_false_positive_suspicious_path_lc(&lower) {
            continue;
        }
        if let Some(keyword) = find_keyword_hit_in_path_scope_lc(&lower, keywords) {
            out.insert(format!("file | {keyword} | {normalized}"));
        }
    }
    out
}

fn collect_keyword_link_artifacts(links: &BTreeSet<String>, keywords: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for link in links {
        let Some((host, path)) = parse_link_host_and_path(link) else {
            continue;
        };
        let host_l = host.to_ascii_lowercase();
        if tool_link_host_is_noise(&host_l) {
            continue;
        }
        let Some(clean_path) = normalize_tool_link_path(&path) else {
            continue;
        };
        let high_signal_path = is_high_signal_tool_link_path(&clean_path);
        if is_low_value_tool_link_host(&host_l) && !high_signal_path {
            continue;
        }
        let scoped = format!("{}{}", host_l, clean_path.to_ascii_lowercase());
        let Some(keyword) = find_keyword_hit_lc(&scoped, keywords) else {
            continue;
        };
        let display = if clean_path != "/" && high_signal_path {
            format!("{host_l}{clean_path}")
        } else {
            host_l
        };
        out.insert(format!("link | {keyword} | {display}"));
    }
    out
}

fn tool_stem_has_embedded_extension(stem_lower: &str) -> bool {
    [
        ".exe", ".dll", ".jar", ".bat", ".cmd", ".ps1", ".pf", ".lnk", ".sys", ".cat", ".txt",
        ".xml", ".json", ".qml",
    ]
    .iter()
    .any(|tok| stem_lower.contains(tok))
}

fn collect_domain_frequency(links: &BTreeSet<String>) -> BTreeSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for link in links {
        if let Some((host, _)) = parse_link_host_and_path(link) {
            *counts.entry(host).or_insert(0) += 1;
        }
    }
    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut out = BTreeSet::new();
    let mut kept = 0usize;
    let min_count = if rows.len() > 40_000 {
        16
    } else if rows.len() > 15_000 {
        12
    } else if rows.len() > 6_000 {
        8
    } else {
        4
    };
    for (host, count) in rows {
        let lower = host.to_ascii_lowercase();
        let flagged = has_suspicious_link_keyword_lc(&lower)
            || CHEAT_ARTIFACT_KEYWORDS
                .iter()
                .any(|k| keyword_match_lc(&lower, k))
            || BYPASS_ARTIFACT_KEYWORDS
                .iter()
                .any(|k| keyword_match_lc(&lower, k));
        if count < min_count && !flagged {
            continue;
        }
        if lower.starts_with("www.") && count < min_count.saturating_add(2) && !flagged {
            continue;
        }
        out.insert(format!("{count:>6} | {host}"));
        kept += 1;
        if kept >= 2_500 {
            break;
        }
    }
    if out.is_empty() {
        out.insert("No repeated or flagged domains".to_string());
    }
    out
}

fn collect_remote_domain_hits(links: &BTreeSet<String>) -> BTreeSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for link in links {
        let Some((host, _)) = parse_link_host_and_path(link) else {
            continue;
        };
        let host_l = host.to_ascii_lowercase();
        if !has_remote_access_domain(&host_l)
            && !REMOTE_ACCESS_KEYWORDS
                .iter()
                .any(|k| keyword_match_lc(&host_l, k))
        {
            continue;
        }
        *counts.entry(host_l).or_insert(0) += 1;
    }
    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut out = BTreeSet::new();
    for (host, count) in rows {
        out.insert(format!("{count:>6} | {host}"));
    }
    if out.is_empty() {
        out.insert("No remote-access domains".to_string());
    }
    out
}

fn collect_suspicious_domain_hits(links: &BTreeSet<String>) -> BTreeSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for link in links {
        let Some((host, _)) = parse_link_host_and_path(link) else {
            continue;
        };
        let host_l = host.to_ascii_lowercase();
        if !has_suspicious_link_keyword_lc(&host_l) {
            continue;
        }
        *counts.entry(host_l).or_insert(0) += 1;
    }
    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut out = BTreeSet::new();
    for (host, count) in rows {
        out.insert(format!("{count:>6} | {host}"));
    }
    if out.is_empty() {
        out.insert("No suspicious domains".to_string());
    }
    out
}

fn collect_tunnel_domain_hits(links: &BTreeSet<String>) -> BTreeSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for link in links {
        let Some((host, _)) = parse_link_host_and_path(link) else {
            continue;
        };
        let host_l = host.to_ascii_lowercase();
        if !has_network_tunnel_domain(&host_l)
            && !NETWORK_TUNNEL_KEYWORDS
                .iter()
                .any(|k| keyword_match_lc(&host_l, k))
        {
            continue;
        }
        *counts.entry(host_l).or_insert(0) += 1;
    }
    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut out = BTreeSet::new();
    for (host, count) in rows {
        out.insert(format!("{count:>6} | {host}"));
    }
    if out.is_empty() {
        out.insert("No tunnel domains".to_string());
    }
    out
}

fn collect_persistence_hits(sets: &[&BTreeSet<String>]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            if line.len() > 620 {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.split_whitespace().count() > 96 || is_probable_embedded_source_noise(&lower) {
                continue;
            }
            if !looks_actionable_command_context_lc(&lower) {
                continue;
            }
            let Some(tag) = persistence_tag_from_line(&lower) else {
                continue;
            };
            out.insert(format!("{tag} | {line}"));
        }
    }
    if out.is_empty() {
        out.insert("No persistence artifacts".to_string());
    }
    out
}

fn persistence_tag_from_line(lower: &str) -> Option<&'static str> {
    let reg_write = (has_token_lc(lower, "reg")
        && !has_token_lc(lower, "delete")
        && (has_token_lc(lower, "add")
            || has_token_lc(lower, "import")
            || has_token_lc(lower, "copy")))
        || lower.contains("new-itemproperty")
        || lower.contains("set-itemproperty");

    if lower.contains("__eventfilter")
        || lower.contains("commandlineeventconsumer")
        || lower.contains("filtertoconsumerbinding")
        || lower.contains("active scripteventconsumer")
        || lower.contains("mofcomp")
    {
        return Some("wmi_subscription");
    }

    if lower.contains("\\software\\microsoft\\windows\\currentversion\\runonce")
        && !has_token_lc(lower, "delete")
        && (reg_write || lower.contains("\\registry\\"))
        && looks_suspicious_autorun_payload_lc(lower)
    {
        return Some("run_once");
    }

    if lower.contains("\\software\\microsoft\\windows\\currentversion\\run")
        && !lower.contains("\\runonce")
        && !has_token_lc(lower, "delete")
        && (reg_write || lower.contains("\\registry\\"))
        && looks_suspicious_autorun_payload_lc(lower)
    {
        return Some("run_key");
    }

    if lower.contains("\\microsoft\\windows\\start menu\\programs\\startup\\")
        || lower.contains("\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\")
    {
        return Some("startup_folder");
    }

    if has_token_lc(lower, "schtasks") {
        let has_task_name = lower.contains("/tn ");
        let create_with_payload = lower.contains("/create")
            && has_task_name
            && (lower.contains("/tr ") || lower.contains("/xml "));
        let change_with_payload =
            lower.contains("/change") && has_task_name && lower.contains("/tr ");
        if (create_with_payload || change_with_payload) && looks_suspicious_task_payload_lc(lower) {
            return Some("scheduled_task");
        }
    }
    if has_token_lc(lower, "register-scheduledtask")
        && lower.contains("-taskname")
        && (lower.contains("-action") || lower.contains("-xml"))
        && !has_positional_placeholder_token_lc(lower)
    {
        return Some("scheduled_task");
    }

    if has_token_lc(lower, "sc")
        && (lower.contains(" create ") || lower.contains(" config "))
        && (lower.contains(" binpath=") || lower.contains(" start=") || lower.contains(" obj="))
    {
        return Some("service_autostart");
    }

    if lower.contains("\\system\\currentcontrolset\\services\\")
        && (lower.contains("imagepath") || lower.contains("\\start") || lower.contains(" start "))
    {
        return Some("service_registry");
    }
    None
}

fn looks_suspicious_task_payload_lc(lower: &str) -> bool {
    if has_positional_placeholder_token_lc(lower) {
        return false;
    }
    if lower.contains("/xml ") {
        if lower.contains(".xml") || lower.contains("\\tasks\\") {
            return true;
        }
        return false;
    }
    if !lower.contains("/tr ") {
        return false;
    }
    lower.contains(".exe")
        || lower.contains(".dll")
        || lower.contains(".bat")
        || lower.contains(".cmd")
        || lower.contains(".ps1")
        || lower.contains(".js")
        || lower.contains(".vbs")
        || lower.contains(".jar")
        || lower.contains("cmd.exe")
        || has_token_lc(lower, "powershell")
        || has_token_lc(lower, "pwsh")
        || has_token_lc(lower, "mshta")
        || has_token_lc(lower, "wscript")
        || has_token_lc(lower, "cscript")
        || has_token_lc(lower, "rundll32")
        || has_token_lc(lower, "regsvr32")
}

fn looks_suspicious_autorun_payload_lc(lower: &str) -> bool {
    if has_positional_placeholder_token_lc(lower) {
        return false;
    }
    let has_exec_target = lower.contains(".exe")
        || lower.contains(".dll")
        || lower.contains(".bat")
        || lower.contains(".cmd")
        || lower.contains(".ps1")
        || lower.contains(".js")
        || lower.contains(".vbs")
        || lower.contains(".jar");
    if !has_exec_target {
        return false;
    }
    let suspicious_launcher = lower.contains("cmd.exe")
        || has_token_lc(lower, "powershell")
        || has_token_lc(lower, "pwsh")
        || has_token_lc(lower, "mshta")
        || has_token_lc(lower, "rundll32")
        || has_token_lc(lower, "regsvr32")
        || has_token_lc(lower, "wscript")
        || has_token_lc(lower, "cscript");
    let suspicious_location = lower.contains("\\temp\\")
        || lower.contains("\\downloads\\")
        || lower.contains("\\desktop\\")
        || lower.contains("\\$recycle.bin\\")
        || lower.contains("\\programdata\\");
    let suspicious_name = CHEAT_ARTIFACT_KEYWORDS
        .iter()
        .any(|k| keyword_match_lc(lower, k))
        || BYPASS_ARTIFACT_KEYWORDS
            .iter()
            .any(|k| keyword_match_lc(lower, k));
    suspicious_launcher || suspicious_location || suspicious_name
}

fn collect_anti_forensics_hits(sets: &[&BTreeSet<String>]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            if line.len() > 620 {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.split_whitespace().count() > 96 || is_probable_embedded_source_noise(&lower) {
                continue;
            }
            if !looks_actionable_command_context_lc(&lower) {
                continue;
            }
            let Some(tag) = anti_forensics_tag_from_line(&lower) else {
                continue;
            };
            out.insert(format!("{tag} | {line}"));
        }
    }
    if out.is_empty() {
        out.insert("No anti-forensics artifacts".to_string());
    }
    out
}

fn anti_forensics_tag_from_line(lower: &str) -> Option<&'static str> {
    if (has_token_lc(lower, "wevtutil")
        && (lower.contains(" cl ") || lower.contains(" clear-log ")))
        || lower.contains("clear-eventlog")
        || lower.contains("remove-eventlog")
        || (lower.contains("\\winevt\\logs\\")
            && (has_token_lc(lower, "del")
                || has_token_lc(lower, "erase")
                || lower.contains("remove-item")))
    {
        return Some("event_log_clear");
    }

    if (has_token_lc(lower, "vssadmin")
        && has_token_lc(lower, "delete")
        && has_token_lc(lower, "shadows")
        && (lower.contains("/all") || lower.contains("/shadow=") || lower.contains("/quiet")))
        || (has_token_lc(lower, "wmic")
            && lower.contains("shadowcopy")
            && has_token_lc(lower, "delete"))
    {
        return Some("shadow_copy_delete");
    }

    if has_token_lc(lower, "wbadmin")
        && has_token_lc(lower, "delete")
        && has_token_lc(lower, "catalog")
    {
        return Some("backup_catalog_delete");
    }

    if has_token_lc(lower, "auditpol")
        && (lower.contains("/clear")
            || (has_token_lc(lower, "/remove") && has_token_lc(lower, "/allusers")))
    {
        return Some("audit_policy_clear");
    }

    if has_token_lc(lower, "bcdedit")
        && lower.contains("/set")
        && (lower.contains("recoveryenabled")
            || lower.contains("bootstatuspolicy")
            || lower.contains("testsigning")
            || lower.contains("nointegritychecks"))
    {
        return Some("boot_recovery_tamper");
    }

    if has_token_lc(lower, "fsutil") && lower.contains("usn") && lower.contains("deletejournal") {
        return Some("usn_journal_delete");
    }

    if lower.contains("clear-recyclebin")
        || (lower.contains("$recycle.bin")
            && (has_token_lc(lower, "rd")
                || has_token_lc(lower, "rmdir")
                || has_token_lc(lower, "remove-item")))
    {
        return Some("recyclebin_wipe");
    }

    if has_token_lc(lower, "powercfg")
        && (lower.contains("-h off")
            || lower.contains("/hibernate off")
            || lower.contains("hibernate off"))
    {
        return Some("hiberfil_disable");
    }

    if (lower.contains("hiberfil.sys") || lower.contains("pagefile.sys"))
        && (has_token_lc(lower, "del")
            || has_token_lc(lower, "erase")
            || has_token_lc(lower, "remove-item"))
    {
        return Some("hiber_pagefile_delete");
    }

    if (lower.contains("thumbcache") || lower.contains("\\explorer\\thumbcache"))
        && (has_token_lc(lower, "del")
            || has_token_lc(lower, "erase")
            || has_token_lc(lower, "remove-item"))
    {
        return Some("thumbnail_cache_wipe");
    }

    if has_token_lc(lower, "cipher") && lower.contains("/w:") {
        return Some("disk_wipe_artifact");
    }

    if looks_like_sdelete_command_lc(lower) {
        return Some("secure_delete_tool");
    }
    None
}

fn collect_artifact_wipe_hits(sets: &[&BTreeSet<String>]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            if line.len() > 620 {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.split_whitespace().count() > 96 || is_probable_embedded_source_noise(&lower) {
                continue;
            }
            if !looks_actionable_command_context_lc(&lower) {
                continue;
            }
            let Some(tag) = artifact_wipe_tag_from_line(&lower) else {
                continue;
            };
            out.insert(format!("command | {tag} | {line}"));
        }
    }
    if out.is_empty() {
        out.insert("No artifact wipe artifacts (beta)".to_string());
    }
    out
}

fn artifact_wipe_tag_from_line(lower: &str) -> Option<&'static str> {
    if looks_like_sdelete_command_lc(lower)
        || (has_token_lc(lower, "cipher") && lower.contains("/w:"))
        || (has_token_lc(lower, "bleachbit")
            && (lower.contains(" --clean ")
                || lower.contains(" --wipe")
                || lower.contains(" --shred")
                || lower.contains(" --overwrite")
                || lower.contains(" /clean ")))
        || (has_token_lc(lower, "ccleaner")
            && (lower.contains(" /auto")
                || lower.contains(" /silent")
                || lower.contains(" /clean")
                || lower.contains(" /wipe")))
    {
        return Some("wipe_tool");
    }

    if (has_token_lc(lower, "wevtutil")
        && (lower.contains(" cl ") || lower.contains(" clear-log ")))
        || lower.contains("clear-eventlog")
    {
        return Some("event_log_clear");
    }

    if (has_token_lc(lower, "vssadmin")
        && has_token_lc(lower, "delete")
        && has_token_lc(lower, "shadows")
        && (lower.contains("/all") || lower.contains("/shadow=") || lower.contains("/quiet")))
        || (has_token_lc(lower, "wmic")
            && lower.contains("shadowcopy")
            && has_token_lc(lower, "delete"))
    {
        return Some("shadow_restore_delete");
    }

    if has_token_lc(lower, "wbadmin")
        && has_token_lc(lower, "delete")
        && has_token_lc(lower, "catalog")
    {
        return Some("backup_catalog_delete");
    }

    if has_token_lc(lower, "auditpol")
        && (lower.contains("/clear")
            || (has_token_lc(lower, "/remove") && has_token_lc(lower, "/allusers")))
    {
        return Some("audit_policy_clear");
    }

    if has_token_lc(lower, "reg")
        && has_token_lc(lower, "delete")
        && (lower.contains("hklm\\system\\currentcontrolset\\enum\\usbstor")
            || lower.contains("hkey_local_machine\\system\\currentcontrolset\\enum\\usbstor"))
    {
        return Some("usb_history_delete");
    }

    if lower.contains("\\windows\\prefetch\\")
        && (has_token_lc(lower, "del")
            || has_token_lc(lower, "erase")
            || has_token_lc(lower, "remove-item"))
    {
        return Some("prefetch_wipe");
    }

    if lower.contains("amcache.hve")
        && (has_token_lc(lower, "del")
            || has_token_lc(lower, "erase")
            || has_token_lc(lower, "remove-item"))
    {
        return Some("amcache_wipe");
    }

    if has_token_lc(lower, "fsutil") && lower.contains("usn") && lower.contains("deletejournal") {
        return Some("usn_journal_delete");
    }

    if lower.contains("clear-recyclebin")
        || (lower.contains("$recycle.bin")
            && (has_token_lc(lower, "rd")
                || has_token_lc(lower, "rmdir")
                || has_token_lc(lower, "remove-item")))
    {
        return Some("recyclebin_wipe");
    }

    if has_token_lc(lower, "powercfg")
        && (lower.contains("-h off")
            || lower.contains("/hibernate off")
            || lower.contains("hibernate off"))
    {
        return Some("hiberfil_disable");
    }

    if (lower.contains("hiberfil.sys") || lower.contains("pagefile.sys"))
        && (has_token_lc(lower, "del")
            || has_token_lc(lower, "erase")
            || has_token_lc(lower, "remove-item"))
    {
        return Some("hiber_pagefile_delete");
    }

    if (lower.contains("thumbcache") || lower.contains("\\explorer\\thumbcache"))
        && (has_token_lc(lower, "del")
            || has_token_lc(lower, "erase")
            || has_token_lc(lower, "remove-item"))
    {
        return Some("thumbnail_cache_wipe");
    }
    None
}

fn looks_like_sdelete_command_lc(lower: &str) -> bool {
    if !has_token_lc(lower, "sdelete") {
        return false;
    }
    has_token_lc(lower, "-p")
        || has_token_lc(lower, "-s")
        || has_token_lc(lower, "-z")
        || has_token_lc(lower, "-c")
        || has_token_lc(lower, "-r")
        || lower.contains("/accepteula")
        || lower.contains(":\\")
}

fn collect_data_hiding_hits(
    sets: &[&BTreeSet<String>],
    scope_items: &BTreeSet<String>,
    links: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            if line.len() > 620 {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.split_whitespace().count() > 96 || is_probable_embedded_source_noise(&lower) {
                continue;
            }
            if !looks_actionable_data_hiding_context_lc(&lower) {
                continue;
            }
            let Some(tag) = data_hiding_tag_from_line(&lower) else {
                continue;
            };
            out.insert(format!("command | {tag} | {line}"));
        }
    }

    for row in collect_keyword_file_artifacts(scope_items, BYPASS_ARTIFACT_KEYWORDS) {
        let lower = row.to_ascii_lowercase();
        if lower.contains("openstego")
            || lower.contains("steghide")
            || lower.contains("imdisk")
            || lower.contains("veracrypt")
            || lower.contains("ducky")
        {
            out.insert(row);
        }
    }
    for row in collect_keyword_link_artifacts(links, BYPASS_ARTIFACT_KEYWORDS) {
        let lower = row.to_ascii_lowercase();
        if lower.contains("openstego")
            || lower.contains("steghide")
            || lower.contains("ducky")
            || lower.contains("dnscat")
            || lower.contains("iodine")
            || lower.contains("veracrypt")
            || lower.contains("imdisk")
        {
            out.insert(row);
        }
    }
    if out.is_empty() {
        out.insert("No data-hiding artifacts (beta)".to_string());
    }
    out
}

fn data_hiding_tag_from_line(lower: &str) -> Option<&'static str> {
    if (has_token_lc(lower, "openstego") || has_token_lc(lower, "steghide"))
        && (lower.contains(".exe")
            || has_shell_launcher_lc(lower)
            || lower.contains(" --embed ")
            || lower.contains(" --extract ")
            || lower.contains(" -embed ")
            || lower.contains(" -extract ")
            || lower.contains(" -cf ")
            || lower.contains(" -sf ")
            || lower.contains(" -mf "))
    {
        return Some("steganography_tool");
    }
    if (has_token_lc(lower, "imdisk")
        && (lower.contains("imdisk.exe")
            || has_shell_launcher_lc(lower)
            || lower.contains(" -a ")
            || lower.contains(" -s ")
            || lower.contains(" -m ")
            || lower.contains(" /mount ")
            || lower.contains(" /create ")))
        || (has_token_lc(lower, "ramdisk")
            && (lower.contains("ramdisk.exe")
                || lower.contains(" /mount ")
                || lower.contains(" /create ")))
    {
        return Some("ramdisk_storage");
    }
    if (has_token_lc(lower, "veracrypt") || has_token_lc(lower, "truecrypt"))
        && (lower.contains("veracrypt.exe")
            || has_shell_launcher_lc(lower)
            || lower.contains(" /mount ")
            || lower.contains(" /dismount ")
            || lower.contains(" /auto ")
            || lower.contains(" /q ")
            || lower.contains(" /v ")
            || lower.contains(" /l "))
    {
        return Some("encrypted_container");
    }
    if (has_token_lc(lower, "streams") || lower.contains("streams.exe"))
        && (has_token_lc(lower, "-s")
            || has_token_lc(lower, "-d")
            || has_token_lc(lower, "-accepteula"))
    {
        return Some("ads_streams_tool");
    }
    if has_token_lc(lower, "dir")
        && has_token_lc(lower, "/r")
        && (lower.contains(":\\") || lower.contains("\\users\\"))
    {
        return Some("ads_enumeration");
    }
    if (has_ads_stream_syntax(lower)
        && (has_token_lc(lower, "echo")
            || has_token_lc(lower, "type")
            || has_token_lc(lower, "more")
            || has_token_lc(lower, "copy")
            || has_shell_launcher_lc(lower)))
        || (lower.contains(" -stream ")
            && (has_token_lc(lower, "set-content")
                || has_token_lc(lower, "add-content")
                || has_token_lc(lower, "get-content")))
    {
        return Some("alternate_data_stream");
    }
    if lower.contains("dnscat")
        || lower.contains("dnscat2")
        || lower.contains("iodine")
        || (lower.contains("dns") && lower.contains("tunnel"))
    {
        return Some("dns_tunnel_tool");
    }
    let openvpn_config_target =
        lower.contains(".ovpn") || lower.contains(".conf") || lower.contains("\\config\\");
    if (has_token_lc(lower, "tor")
        && (lower.contains("socks")
            || lower.contains("hiddenservice")
            || lower.contains(" --service ")
            || lower.contains(" --defaults-torrc ")))
        || (has_token_lc(lower, "openvpn")
            && ((lower.contains(" --config ") && openvpn_config_target && !lower.contains("%1"))
                || lower.contains(" --remote ")
                || (lower.contains(" --client ")
                    && (lower.contains(" --remote ") || openvpn_config_target))
                || lower.contains(" --auth-user-pass ")))
        || (has_token_lc(lower, "wireguard")
            && (lower.contains("/installtunnelservice")
                || lower.contains(" wg-quick ")
                || lower.contains(" setconf ")
                || lower.contains(" /tunnelservice")))
    {
        return Some("covert_network_channel");
    }
    if has_token_lc(lower, "duckyscript")
        || has_token_lc(lower, "rubberducky")
        || has_token_lc(lower, "rubber ducky")
    {
        return Some("badusb_payload");
    }
    None
}

fn has_ads_stream_syntax(lower: &str) -> bool {
    if lower.contains("overflow:hidden")
        || lower.contains("visibility:hidden")
        || lower.contains("display:hidden")
    {
        return false;
    }
    for raw in lower.split_whitespace() {
        let token = raw.trim_matches(|c: char| "\"'`()[]{}<>,;".contains(c));
        if token.len() < 6 || token.contains("://") {
            continue;
        }
        let Some(idx) = token.rfind(':') else {
            continue;
        };
        if idx <= 1 || idx + 1 >= token.len() {
            continue;
        }
        let base = &token[..idx];
        let stream = &token[idx + 1..];
        let base_lower = base.to_ascii_lowercase();
        let has_known_ext = [
            ".txt", ".log", ".dat", ".bin", ".jpg", ".jpeg", ".png", ".wav", ".mp3", ".pdf",
            ".doc", ".docx", ".xls", ".xlsx", ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1",
        ]
        .iter()
        .any(|ext| base_lower.ends_with(ext));
        if !has_known_ext {
            continue;
        }
        if stream.len() > 64
            || !stream
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '$'))
        {
            continue;
        }
        return true;
    }
    false
}

fn collect_trail_obfuscation_hits(sets: &[&BTreeSet<String>]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            if line.len() > 620 {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.split_whitespace().count() > 96 || is_probable_embedded_source_noise(&lower) {
                continue;
            }
            if !looks_actionable_command_context_lc(&lower) {
                continue;
            }
            let Some(tag) = trail_obfuscation_tag_from_line(&lower) else {
                continue;
            };
            out.insert(format!("command | {tag} | {line}"));
        }
    }
    if out.is_empty() {
        out.insert("No trail-obfuscation artifacts (beta)".to_string());
    }
    out
}

fn trail_obfuscation_tag_from_line(lower: &str) -> Option<&'static str> {
    if has_token_lc(lower, "timestomp")
        || has_token_lc(lower, "set-mace")
        || has_token_lc(lower, "setmace")
    {
        return Some("mace_timestomp_tool");
    }
    if has_token_lc(lower, "exiftool")
        && (lower.contains("-alldates")
            || lower.contains("-datetimeoriginal")
            || lower.contains("-filemodifydate"))
    {
        return Some("exif_timestamp_forgery");
    }
    if has_token_lc(lower, "touch") && (lower.contains(" -acmr") || lower.contains(" -t ")) {
        return Some("touch_timestamp_change");
    }
    if has_token_lc(lower, "touch")
        && (lower.contains(" -r ") || lower.contains(" --reference="))
        && (lower.contains(":\\") || lower.contains(".exe") || lower.contains(".dll"))
    {
        return Some("touch_timestamp_reference");
    }
    if (lower.contains(".lastwritetime=")
        || lower.contains(".creationtime=")
        || lower.contains(".lastaccesstime=")
        || lower.contains("setfiletime(")
        || lower.contains("set-filetime"))
        && (lower.contains(":\\")
            || lower.contains("\\??\\")
            || lower.contains("\\device\\harddiskvolume")
            || lower.contains(".exe")
            || lower.contains(".dll")
            || lower.contains(".sys"))
    {
        return Some("timestamp_property_change");
    }
    if (has_token_lc(lower, "reg")
        && !has_token_lc(lower, "delete")
        && (has_token_lc(lower, "add")
            || has_token_lc(lower, "import")
            || has_token_lc(lower, "copy")))
        && lower.contains("networkaddress")
    {
        return Some("mac_address_spoof");
    }
    if lower.contains("set-netadapteradvancedproperty")
        && lower.contains("networkaddress")
        && (lower.contains("-registryvalue") || lower.contains("-displayvalue"))
    {
        return Some("mac_address_spoof");
    }
    if has_token_lc(lower, "eventcreate") && (lower.contains(" /t ") || lower.contains(" /id ")) {
        return Some("event_log_flooding");
    }
    None
}

fn collect_tool_evasion_hits(
    sets: &[&BTreeSet<String>],
    scope_items: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            if line.len() > 620 {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.split_whitespace().count() > 96 || is_probable_embedded_source_noise(&lower) {
                continue;
            }
            if !looks_actionable_command_context_lc(&lower) {
                continue;
            }
            let Some(tag) = tool_evasion_tag_from_line(&lower) else {
                continue;
            };
            out.insert(format!("command | {tag} | {line}"));
        }
    }

    for row in collect_keyword_file_artifacts(scope_items, CHEAT_ARTIFACT_KEYWORDS) {
        let lower = row.to_ascii_lowercase();
        if lower.contains("kdmapper")
            || lower.contains("kdu")
            || lower.contains("xenos")
            || lower.contains("injector")
            || lower.contains("bypass")
            || lower.contains("iqvw64e")
            || lower.contains("gdrv")
            || lower.contains("rtcore64")
            || lower.contains("mhyprot")
            || lower.contains("dbutil_2_3")
            || lower.contains("winring0")
        {
            out.insert(row);
        }
    }
    out.extend(collect_driver_mapper_hits(sets, scope_items));

    if out.is_empty() {
        out.insert("No tool/process-attack artifacts (beta)".to_string());
    }
    out
}

fn tool_evasion_tag_from_line(lower: &str) -> Option<&'static str> {
    let has_memory_terms = has_token_lc(lower, "dkom")
        || has_token_lc(lower, "eprocess")
        || has_token_lc(lower, "kpcr")
        || lower.contains("activeprocesslinks");
    let has_evasion_action = has_token_any_lc(
        lower,
        &[
            "unlink", "hide", "hook", "patch", "tamper", "remove", "bypass",
        ],
    );
    if lower.contains("anti-volatility")
        || lower.contains("volatility hook")
        || (has_memory_terms && has_evasion_action)
    {
        return Some("memory_forensics_evasion");
    }
    let boot_terms = has_token_lc(lower, "bootkit")
        || has_token_lc(lower, "rootkit")
        || lower.contains("secure boot")
        || has_token_lc(lower, "uefi");
    let bcd_boot_tamper = has_token_lc(lower, "bcdedit")
        && lower.contains("/set")
        && (lower.contains("testsigning")
            || lower.contains("nointegritychecks")
            || lower.contains("bootstatuspolicy")
            || lower.contains("recoveryenabled")
            || lower.contains("debug"));
    let secureboot_reg_tamper = (has_token_lc(lower, "reg")
        && (has_token_lc(lower, "add")
            || has_token_lc(lower, "import")
            || has_token_lc(lower, "copy")))
        || lower.contains("new-itemproperty")
        || lower.contains("set-itemproperty");
    let secureboot_target = lower.contains("secureboot")
        || lower.contains("\\system\\currentcontrolset\\control\\secureboot");
    let efi_partition_tamper = has_token_any_lc(
        lower,
        &["copy", "move", "xcopy", "ren", "del", "erase", "bcdboot"],
    ) && (lower.contains("\\efi\\")
        || lower.contains("\\efi\\microsoft\\boot\\")
        || lower.contains("efi system partition"));
    if boot_terms
        && (bcd_boot_tamper || (secureboot_reg_tamper && secureboot_target) || efi_partition_tamper)
    {
        return Some("boot_firmware_evasion");
    }
    if has_token_lc(lower, "bcdedit")
        && lower.contains("/set")
        && ((lower.contains("testsigning") && has_token_lc(lower, "on"))
            || (lower.contains("nointegritychecks") && has_token_lc(lower, "on"))
            || (lower.contains("debug") && has_token_lc(lower, "on"))
            || lower.contains("bootstatuspolicy"))
    {
        return Some("boot_policy_tamper");
    }
    if lower.contains("symbol table poisoning") || lower.contains("header/footer randomization") {
        return Some("forensic_carving_evasion");
    }
    if lower.contains("buffer overflow") && lower.contains("sleuth") {
        return Some("forensic_tool_attack");
    }
    None
}

fn collect_driver_mapper_hits(
    sets: &[&BTreeSet<String>],
    scope_items: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            if line.len() > 620 {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.split_whitespace().count() > 96 || is_probable_embedded_source_noise(&lower) {
                continue;
            }
            let has_driver = BYOVD_DRIVER_NAMES.iter().any(|name| lower.contains(name));
            let has_mapper = lower.contains("kdmapper")
                || lower.contains("kdu")
                || lower.contains("mapdriver")
                || (has_token_lc(&lower, "sc")
                    && lower.contains(" create ")
                    && lower.contains(" type=")
                    && lower.contains(" kernel"));
            if has_driver && has_mapper {
                out.insert(format!("command | byovd_driver_mapper | {line}"));
            }
        }
    }
    for path in scope_items {
        let lower = path.to_ascii_lowercase();
        let has_driver = BYOVD_DRIVER_NAMES.iter().any(|name| lower.contains(name));
        if !has_driver {
            continue;
        }
        let risky_drop = lower.contains("\\users\\")
            || lower.contains("\\appdata\\")
            || lower.contains("\\temp\\")
            || lower.contains("\\downloads\\")
            || lower.contains("\\desktop\\")
            || lower.contains("\\programdata\\");
        if !risky_drop {
            continue;
        }
        out.insert(format!("file | vulnerable_driver_drop | {path}"));
    }
    out
}

fn collect_credential_command_hits(sets: &[&BTreeSet<String>]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            if line.len() > 620 {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.split_whitespace().count() > 96 || is_probable_embedded_source_noise(&lower) {
                continue;
            }
            if !looks_actionable_command_context_lc(&lower) {
                continue;
            }
            let Some(tag) = credential_command_tag_from_line(&lower) else {
                continue;
            };
            out.insert(format!("command | {tag} | {line}"));
        }
    }
    out
}

fn credential_command_tag_from_line(lower: &str) -> Option<&'static str> {
    let has_mimikatz_exec = lower.contains("mimikatz.exe")
        || lower.starts_with("mimikatz ")
        || lower.contains("\\mimikatz")
        || lower.contains(" invoke-mimikatz")
        || lower.starts_with("invoke-mimikatz ")
        || lower.contains("sekurlsa::")
        || lower.contains("lsadump::")
        || lower.contains("privilege::debug")
        || lower.contains("token::elevate");
    if has_mimikatz_exec
        && (lower.contains("sekurlsa::")
            || lower.contains("lsadump::")
            || lower.contains("logonpasswords")
            || lower.contains("sam::")
            || lower.contains("lsa::"))
    {
        return Some("mimikatz_credentials");
    }

    if has_token_lc(lower, "reg")
        && has_token_lc(lower, "save")
        && (lower.contains("hklm\\sam")
            || lower.contains("hkey_local_machine\\sam")
            || lower.contains("hklm\\security")
            || lower.contains("hkey_local_machine\\security")
            || lower.contains("hklm\\system")
            || lower.contains("hkey_local_machine\\system"))
    {
        return Some("registry_hive_dump");
    }

    if lower.contains("ntds.dit")
        && (has_token_lc(lower, "copy")
            || has_token_lc(lower, "esentutl")
            || has_token_lc(lower, "robocopy"))
    {
        return Some("ntds_dump_access");
    }

    if lower.contains("lsass.dmp")
        && (has_token_lc(lower, "procdump")
            || has_token_lc(lower, "nanodump")
            || has_token_lc(lower, "dumpert")
            || lower.contains("comsvcs.dll")
            || lower.contains("rundll32")
            || lower.contains("minidump")
            || has_token_lc(lower, "copy")
            || has_token_lc(lower, "move"))
    {
        return Some("lsass_dump_file");
    }

    if lower.contains("lsass")
        && (has_token_lc(lower, "procdump")
            || has_token_lc(lower, "nanodump")
            || has_token_lc(lower, "dumpert")
            || lower.contains("comsvcs.dll")
            || lower.contains("minidump"))
    {
        return Some("lsass_dump");
    }
    None
}

fn collect_network_tunnel_command_hits(sets: &[&BTreeSet<String>]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            if line.len() > 620 {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.split_whitespace().count() > 96 || is_probable_embedded_source_noise(&lower) {
                continue;
            }
            let Some(tag) = network_tunnel_command_tag_from_line(&lower) else {
                continue;
            };
            out.insert(format!("command | {tag} | {line}"));
        }
    }
    out
}

fn network_tunnel_command_tag_from_line(lower: &str) -> Option<&'static str> {
    if has_token_lc(lower, "ngrok")
        && (has_token_lc(lower, "http")
            || has_token_lc(lower, "tcp")
            || has_token_lc(lower, "tls")
            || has_token_lc(lower, "start"))
    {
        return Some("ngrok_tunnel");
    }

    if (has_token_lc(lower, "cloudflared") && has_token_lc(lower, "tunnel"))
        || lower.contains("trycloudflare.com")
    {
        return Some("cloudflare_tunnel");
    }

    if has_token_lc(lower, "chisel")
        && (has_token_lc(lower, "client") || has_token_lc(lower, "server"))
    {
        return Some("chisel_tunnel");
    }

    if has_token_lc(lower, "frpc") || has_token_lc(lower, "frps") {
        return Some("frp_tunnel");
    }

    if (has_token_lc(lower, "ssh") || has_token_lc(lower, "plink"))
        && (lower.contains(" -r ") || lower.contains(" -d "))
    {
        return Some("reverse_tunnel");
    }

    let has_minecraft_ctx = has_token_lc(lower, "minecraft")
        || has_token_lc(lower, "javaw.exe")
        || lower.contains("\\.minecraft\\")
        || lower.contains("\\tlauncher\\");
    let has_local_proxy = lower.contains("127.0.0.1:")
        || lower.contains("localhost:")
        || lower.contains("socks5")
        || lower.contains("proxyenable")
        || lower.contains("proxyserver")
        || lower.contains("autoconfigurl");
    let has_proxy_tool = has_token_lc(lower, "sing-box")
        || has_token_lc(lower, "v2ray")
        || has_token_lc(lower, "xray")
        || has_token_lc(lower, "clash")
        || has_token_lc(lower, "proxifier")
        || has_token_lc(lower, "tun2socks")
        || has_token_lc(lower, "wintun");
    if has_minecraft_ctx && has_local_proxy && has_proxy_tool {
        return Some("minecraft_local_proxy");
    }

    if has_token_lc(lower, "tailscale")
        || has_token_lc(lower, "zerotier")
        || has_token_lc(lower, "wireguard")
        || has_token_lc(lower, "hamachi")
    {
        return Some("mesh_vpn");
    }

    if has_token_lc(lower, "playit")
        || has_token_lc(lower, "localxpose")
        || has_token_lc(lower, "pinggy")
        || has_token_lc(lower, "wstunnel")
    {
        return Some("public_tunnel");
    }
    None
}

fn is_high_signal_network_tunnel_hit(row: &str) -> bool {
    let lower = row.to_ascii_lowercase();
    if lower.starts_with("command |") || lower.starts_with("file |") {
        return true;
    }
    if !lower.starts_with("link |") {
        return true;
    }
    let parts = row.split(" | ").collect::<Vec<_>>();
    if parts.len() < 3 {
        return false;
    }
    let target = parts[2].trim();
    let Some((_, raw_path)) = target.split_once('/') else {
        return false;
    };
    let path = format!("/{}", raw_path.trim());
    if path == "/" {
        return false;
    }
    if download_filename_from_link_path(&path).is_some() {
        return true;
    }
    let path_l = path.to_ascii_lowercase();
    path_l.contains("/download")
        || path_l.contains("/install")
        || path_l.contains("/setup")
        || path_l.contains("/client")
        || path_l.contains("/releases")
}

fn collect_triage_priority_hits(
    remote_access_tools: &BTreeSet<String>,
    analysis_tools: &BTreeSet<String>,
    credential_access_hits: &BTreeSet<String>,
    network_tunnel_hits: &BTreeSet<String>,
    remote_domain_hits: &BTreeSet<String>,
    tunnel_domain_hits: &BTreeSet<String>,
    remote_session_hits: &BTreeSet<String>,
    persistence_hits: &BTreeSet<String>,
    anti_forensics_hits: &BTreeSet<String>,
    suspicious_links: &BTreeSet<String>,
    suspicious_files: &BTreeSet<String>,
    yara_hits: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut ranked = Vec::new();
    push_triage_category(&mut ranked, "yara", yara_hits, 98, 80);
    push_triage_category(
        &mut ranked,
        "cheat_artifacts_beta",
        remote_access_tools,
        90,
        80,
    );
    push_triage_category(&mut ranked, "bypass_artifacts_beta", analysis_tools, 88, 80);
    push_triage_category(
        &mut ranked,
        "artifact_wipe_beta",
        credential_access_hits,
        86,
        80,
    );
    push_triage_category(&mut ranked, "data_hiding_beta", network_tunnel_hits, 82, 70);
    push_triage_category(
        &mut ranked,
        "trail_obfuscation_beta",
        remote_domain_hits,
        80,
        70,
    );
    push_triage_category(&mut ranked, "tool_attack_beta", tunnel_domain_hits, 78, 70);
    push_triage_category(&mut ranked, "persistence_beta", remote_session_hits, 76, 70);
    push_triage_category(
        &mut ranked,
        "credential_access_beta",
        persistence_hits,
        74,
        50,
    );
    push_triage_category(
        &mut ranked,
        "anti_forensics_beta",
        anti_forensics_hits,
        72,
        50,
    );
    push_triage_category(&mut ranked, "suspicious_links", suspicious_links, 68, 60);
    push_triage_category(&mut ranked, "suspicious_files", suspicious_files, 66, 60);
    ranked.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });

    let mut out = BTreeSet::new();
    for (idx, (score, category, row)) in ranked.into_iter().take(160).enumerate() {
        out.insert(format!(
            "{:03} | score={:03} | {} | {}",
            idx + 1,
            score.min(999),
            category,
            row
        ));
    }
    if out.is_empty() {
        out.insert("No priority hits".to_string());
    }
    out
}

fn push_triage_category(
    ranked: &mut Vec<(usize, String, String)>,
    category: &str,
    rows: &BTreeSet<String>,
    base_score: usize,
    max_items: usize,
) {
    for row in rows
        .iter()
        .filter(|x| !is_detector_negative_row(x))
        .take(max_items)
    {
        if category == "yara" && !yara_row_is_high_signal(row) {
            continue;
        }
        let mut score = base_score;
        let lower = row.to_ascii_lowercase();
        if lower.contains("lsass")
            || lower.contains("mimikatz")
            || lower.contains("sekurlsa")
            || lower.contains("nanodump")
        {
            score += 8;
        }
        if lower.contains("wevtutil")
            || lower.contains("vssadmin")
            || lower.contains("bcdedit")
            || lower.contains("wbadmin")
        {
            score += 6;
        }
        if lower.contains("minecraft_local_proxy")
            || lower.contains("proxy-bypass")
            || lower.contains("proxy_bypass")
            || lower.contains("verdict=bypass")
        {
            score += 6;
        }
        if lower.contains("cheatengine")
            || lower.contains("cheat engine")
            || lower.contains("kdmapper")
            || lower.contains("xenos")
            || lower.contains("sdelete")
            || lower.contains("bleachbit")
            || lower.contains("timestomp")
        {
            score += 4;
        }
        if lower.contains("deleted") && !lower.contains("no deleted") {
            score += 2;
        }
        ranked.push((
            score.min(999),
            category.to_string(),
            trim_detector_row_for_report(row, 360),
        ));
    }
}

fn yara_row_is_high_signal(row: &str) -> bool {
    let lower = row.to_ascii_lowercase();
    if SUSPICIOUS.iter().any(|kw| lower.contains(kw)) {
        return true;
    }
    let Some((_, rules_raw)) = row.split_once(" | ") else {
        return true;
    };
    let mut saw_rule = false;
    for rule in rules_raw.split(',').map(|x| x.trim().to_ascii_lowercase()) {
        if rule.is_empty() {
            continue;
        }
        saw_rule = true;
        if !matches!(rule.as_str(), "suspect" | "obf" | "entropy") {
            return true;
        }
    }
    !saw_rule
}

fn trim_detector_row_for_report(row: &str, max_chars: usize) -> String {
    if row.chars().count() <= max_chars {
        return row.to_string();
    }
    row.chars().take(max_chars).collect::<String>() + " ..."
}

fn count_non_empty_detector_rows(rows: &BTreeSet<String>) -> usize {
    rows.iter().filter(|x| !is_detector_negative_row(x)).count()
}

fn is_detector_negative_row(row: &str) -> bool {
    let lower = row.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    lower.starts_with("no ")
}

fn has_positional_placeholder_token_lc(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut digits = 0usize;
        while j < bytes.len() && bytes[j].is_ascii_digit() && digits < 4 {
            j += 1;
            digits += 1;
        }
        if digits > 0 && j < bytes.len() && bytes[j] == b'}' {
            return true;
        }
        i += 1;
    }
    false
}

fn is_command_help_or_usage_noise_lc(lower: &str) -> bool {
    if lower.starts_with("usage:")
        || lower.starts_with("examples:")
        || lower.starts_with("example:")
        || lower.starts_with("syntax:")
    {
        return true;
    }
    if !(lower.contains(" /?") || lower.ends_with("/?")) {
        return false;
    }
    has_token_any_lc(
        lower,
        &[
            "cmd",
            "powershell",
            "pwsh",
            "wmic",
            "reg",
            "schtasks",
            "sc",
            "wevtutil",
            "vssadmin",
            "wbadmin",
            "bcdedit",
            "fsutil",
            "auditpol",
            "cipher",
        ],
    )
}

fn looks_actionable_command_context_lc(lower: &str) -> bool {
    if is_documentation_noise_lc(lower) || is_command_help_or_usage_noise_lc(lower) {
        return false;
    }
    if has_positional_placeholder_token_lc(lower) {
        return false;
    }
    has_shell_launcher_lc(lower)
        || has_token_any_lc(
            lower,
            &[
                "wevtutil",
                "clear-eventlog",
                "remove-eventlog",
                "vssadmin",
                "wbadmin",
                "bcdedit",
                "fsutil",
                "cipher",
                "sdelete",
                "auditpol",
                "clear-recyclebin",
                "del",
                "erase",
                "remove-item",
                "echo",
                "timestomp",
                "set-mace",
                "setmace",
                "exiftool",
                "touch",
                "streams",
                "eventcreate",
                "mimikatz",
                "sekurlsa",
                "lsadump",
                "procdump",
                "nanodump",
                "dumpert",
                "dkom",
                "eprocess",
                "kpcr",
                "bootkit",
                "rootkit",
                "volatility",
                "kdmapper",
                "kdu",
                "xenos",
            ],
        )
}

fn looks_actionable_data_hiding_context_lc(lower: &str) -> bool {
    if is_documentation_noise_lc(lower) || is_command_help_or_usage_noise_lc(lower) {
        return false;
    }
    if has_positional_placeholder_token_lc(lower) {
        return false;
    }
    if has_shell_launcher_lc(lower) {
        return true;
    }
    if (has_token_lc(lower, "openstego") || has_token_lc(lower, "steghide"))
        && (lower.contains(".exe")
            || lower.contains(" --embed ")
            || lower.contains(" --extract ")
            || lower.contains(" -embed ")
            || lower.contains(" -extract ")
            || lower.contains(" -cf ")
            || lower.contains(" -sf ")
            || lower.contains(" -mf "))
    {
        return true;
    }
    if (has_token_lc(lower, "imdisk")
        && (lower.contains("imdisk.exe")
            || has_shell_launcher_lc(lower)
            || lower.contains(" -a ")
            || lower.contains(" -s ")
            || lower.contains(" -m ")
            || lower.contains(" /mount ")
            || lower.contains(" /create ")))
        || (has_token_lc(lower, "ramdisk")
            && (lower.contains("ramdisk.exe")
                || lower.contains(" /mount ")
                || lower.contains(" /create ")))
    {
        return true;
    }
    if (has_token_lc(lower, "veracrypt") || has_token_lc(lower, "truecrypt"))
        && (lower.contains("veracrypt.exe")
            || lower.contains(" /mount ")
            || lower.contains(" /dismount ")
            || lower.contains(" /auto ")
            || lower.contains(" /q ")
            || lower.contains(" /v ")
            || lower.contains(" /l "))
    {
        return true;
    }
    if (has_token_lc(lower, "streams") || lower.contains("streams.exe"))
        && (has_token_lc(lower, "-s")
            || has_token_lc(lower, "-d")
            || has_token_lc(lower, "-accepteula"))
    {
        return true;
    }
    let openvpn_config_target =
        lower.contains(".ovpn") || lower.contains(".conf") || lower.contains("\\config\\");
    if lower.contains("dnscat")
        || lower.contains("dnscat2")
        || lower.contains("iodine")
        || (has_token_lc(lower, "tor")
            && (lower.contains("socks")
                || lower.contains("hiddenservice")
                || lower.contains(" --service ")
                || lower.contains(" --defaults-torrc ")))
        || (has_token_lc(lower, "openvpn")
            && ((lower.contains(" --config ") && openvpn_config_target && !lower.contains("%1"))
                || lower.contains(" --remote ")
                || (lower.contains(" --client ")
                    && (lower.contains(" --remote ") || openvpn_config_target))
                || lower.contains(" --auth-user-pass ")))
        || (has_token_lc(lower, "wireguard")
            && (lower.contains("/installtunnelservice")
                || lower.contains(" wg-quick ")
                || lower.contains(" setconf ")
                || lower.contains(" /tunnelservice")))
    {
        return true;
    }
    (has_ads_stream_syntax(lower)
        && (has_token_lc(lower, "echo")
            || has_token_lc(lower, "type")
            || has_token_lc(lower, "more")
            || has_token_lc(lower, "copy")))
        || (lower.contains(" -stream ")
            && (has_token_lc(lower, "set-content")
                || has_token_lc(lower, "add-content")
                || has_token_lc(lower, "get-content")))
}

fn is_build_or_dependency_artifact_path_lc(lower: &str) -> bool {
    lower.contains("\\target\\debug\\")
        || lower.contains("\\target\\release\\")
        || lower.contains("\\target\\")
        || lower.contains("\\.fingerprint\\")
        || lower.contains("\\deps\\")
        || lower.contains("\\build\\")
        || lower.contains("\\.cargo\\registry\\")
        || lower.contains("\\.cargo\\git\\")
        || lower.contains("\\rustup\\toolchains\\")
        || lower.contains("\\windows kits\\")
        || lower.contains("\\microsoft visual studio\\")
        || lower.contains("\\source\\repos\\")
        || lower.contains("\\node_modules\\")
}

fn has_high_signal_path_keyword_lc(lower: &str) -> bool {
    if lower.is_empty() {
        return false;
    }
    if is_false_positive_suspicious_path_lc(lower) {
        return false;
    }
    let mut scopes = vec![lower.to_string()];
    if let Some(name) = Path::new(lower).file_name().and_then(OsStr::to_str) {
        scopes.push(name.to_ascii_lowercase());
    }
    let tail = lower
        .rsplit('\\')
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\\");
    if !tail.is_empty() {
        scopes.push(tail);
    }

    scopes.iter().any(|scope| {
        SUSPICIOUS.iter().any(|kw| keyword_match_lc(scope, kw))
            || CHEAT_ARTIFACT_KEYWORDS
                .iter()
                .any(|kw| keyword_match_lc(scope, kw))
            || BYPASS_ARTIFACT_KEYWORDS
                .iter()
                .any(|kw| keyword_match_lc(scope, kw))
    })
}

fn find_keyword_hit_in_path_scope_lc<'a>(lower: &str, keywords: &'a [&'a str]) -> Option<&'a str> {
    if lower.is_empty() {
        return None;
    }
    if is_false_positive_suspicious_path_lc(lower) {
        return None;
    }
    let mut scopes = vec![lower.to_string()];
    if let Some(name) = Path::new(lower).file_name().and_then(OsStr::to_str) {
        scopes.push(name.to_ascii_lowercase());
    }
    let tail = lower
        .rsplit('\\')
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\\");
    if !tail.is_empty() {
        scopes.push(tail);
    }
    for scope in scopes {
        if let Some(hit) = find_keyword_hit_lc(&scope, keywords) {
            return Some(hit);
        }
    }
    None
}

fn should_scan_yara_target_screenshare(path: &str) -> bool {
    let lower = normalize_cmp_path(path);
    if lower.is_empty() {
        return false;
    }
    if is_build_or_dependency_artifact_path_lc(&lower) {
        return false;
    }
    let has_high_signal_keyword = has_high_signal_path_keyword_lc(&lower);
    if has_high_signal_keyword {
        return true;
    }

    if lower.starts_with("c:\\windows\\") {
        return lower.contains("\\temp\\")
            || lower.contains("\\tasks\\")
            || lower.contains("\\prefetch\\");
    }

    if lower.contains("\\windows kits\\")
        || lower.contains("\\microsoft visual studio\\")
        || lower.contains("\\dotnet\\")
        || lower.contains("\\winsxs\\")
    {
        return false;
    }

    if lower.starts_with("c:\\program files\\")
        || lower.starts_with("c:\\program files (x86)\\")
        || lower.contains("\\windowsapps\\")
    {
        return false;
    }

    true
}

fn collect_remote_session_hits(sets: &[&BTreeSet<String>]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for set in sets {
        for line in *set {
            let lower = line.to_ascii_lowercase();
            if line.len() > 420 || lower.split_whitespace().count() > 80 {
                continue;
            }
            let Some(keyword) = find_keyword_hit_lc(&lower, REMOTE_SESSION_KEYWORDS) else {
                continue;
            };
            if !has_shell_launcher_lc(&lower)
                && !contains_url_scheme_lc(&lower)
                && !lower.contains(":\\")
                && !lower.contains("processstart,")
            {
                continue;
            }
            out.insert(format!("{keyword} | {line}"));
        }
    }
    if out.is_empty() {
        out.insert("No remote session artifacts".to_string());
    }
    out
}

fn extract_yara_rule_names(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for caps in YARA_RULE_NAME_RE.captures_iter(src) {
        if let Some(rule) = caps.get(1) {
            let name = rule.as_str().trim();
            if !name.is_empty() {
                out.insert(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod resolve_and_triage_tests {
    use super::*;

    #[test]
    fn suspicious_keyword_exclusions_drop_known_false_positive_names() {
        assert!(is_false_positive_suspicious_path_lc("triggerbot.exe"));
        assert!(is_false_positive_suspicious_path_lc(
            r"c:\users\alice\downloads\doomsday.exe"
        ));
        assert!(!has_suspicious_keyword("triggerbot.exe"));
        assert!(!has_suspicious_keyword(
            r"C:\Users\alice\Downloads\doomsday.exe"
        ));
    }

    #[test]
    fn minecraft_local_proxy_tag_requires_minecraft_context() {
        let strong = r#"javaw.exe .minecraft proxyserver=127.0.0.1:10808 sing-box tun2socks"#;
        let weak = r#"proxyserver=127.0.0.1:10808 sing-box tun2socks"#;
        assert_eq!(
            network_tunnel_command_tag_from_line(&strong.to_ascii_lowercase()),
            Some("minecraft_local_proxy")
        );
        assert_eq!(
            network_tunnel_command_tag_from_line(&weak.to_ascii_lowercase()),
            None
        );
    }

    #[test]
    fn normalize_unc_like_local_roots_to_c_drive() {
        assert_eq!(
            normalize_full_windows_path(r"\\WINDOWS\SYSTEM32\APPXDEPLOYMENTCLIENT.DLL"),
            r"C:\WINDOWS\SYSTEM32\APPXDEPLOYMENTCLIENT.DLL"
        );
        assert_eq!(
            normalize_full_windows_path(
                r"\\Program Files\PowerShell\7\System.Reflection.Emit.Lightweight.dll"
            ),
            r"C:\Program Files\PowerShell\7\System.Reflection.Emit.Lightweight.dll"
        );
        assert_eq!(
            normalize_full_windows_path(r"\\22-+3\Windows\System32\gpsvc.dll"),
            r"C:\Windows\System32\gpsvc.dll"
        );
    }

    #[test]
    fn keep_real_unc_paths_untouched() {
        assert_eq!(
            normalize_full_windows_path(r"\\192.168.1.10\share\tool.exe"),
            r"\\192.168.1.10\share\tool.exe"
        );
    }
}
