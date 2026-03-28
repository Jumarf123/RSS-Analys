// Custom rule parser/matcher and custom-hit reporting helpers.

fn load_custom_rules(strings_dir: &Path) -> io::Result<Vec<CustomRule>> {
    if !strings_dir.exists() || !strings_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    let mut stack = vec![strings_dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let rd = match fs::read_dir(&cur) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for entry in rd {
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();

    let mut out = Vec::new();
    for file in files {
        let mut bytes = Vec::new();
        let mut f = match File::open(&file) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if f.read_to_end(&mut bytes).is_err() || bytes.is_empty() {
            continue;
        }
        let text = if looks_utf16(&bytes) {
            decode_utf16(&bytes)
        } else {
            String::from_utf8_lossy(&bytes).to_string()
        };
        let source = file
            .strip_prefix(strings_dir)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| file.display().to_string())
            .replace('/', "\\");
        let fallback_client = file
            .file_stem()
            .and_then(OsStr::to_str)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("Residence Screenshare")
            .to_string();
        let target_process = parse_target_process_from_strings_file_name(&file);
        parse_custom_rules_from_text(
            &text,
            &source,
            &fallback_client,
            target_process.as_deref(),
            &mut out,
        );
    }

    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    for rule in out {
        let key = format!(
            "{}|{}|{}|{}|{}",
            rule.client.to_ascii_lowercase(),
            rule.min_hits,
            rule.source.to_ascii_lowercase(),
            rule.target_process
                .as_ref()
                .map(|x| x.to_ascii_lowercase())
                .unwrap_or_default(),
            rule.patterns
                .iter()
                .map(|x| x.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join("\u{1F}")
        );
        if seen.insert(key) {
            unique.push(rule);
        }
    }
    unique.sort_by(|a, b| {
        a.client
            .to_ascii_lowercase()
            .cmp(&b.client.to_ascii_lowercase())
            .then_with(|| {
                a.source
                    .to_ascii_lowercase()
                    .cmp(&b.source.to_ascii_lowercase())
            })
    });
    Ok(unique)
}

fn parse_target_process_from_strings_file_name(path: &Path) -> Option<String> {
    let ext = path.extension().and_then(OsStr::to_str)?;
    if !ext.eq_ignore_ascii_case("txt") {
        return None;
    }
    let stem = path.file_stem().and_then(OsStr::to_str)?.trim();
    let name = normalize_process_match_name(stem)?;
    if name.chars().all(|c| c.is_ascii_alphanumeric()) {
        Some(name)
    } else {
        None
    }
}

fn parse_custom_rules_from_text(
    text: &str,
    source: &str,
    fallback_client: &str,
    target_process: Option<&str>,
    out: &mut Vec<CustomRule>,
) {
    let lines = text.lines().collect::<Vec<_>>();
    let mut used = vec![false; lines.len()];
    let mut idx = 0usize;

    while idx < lines.len() {
        let raw = lines[idx].trim();
        let header = parse_rule_header(raw);
        let Some(rule_name) = header else {
            idx += 1;
            continue;
        };

        used[idx] = true;
        idx += 1;
        let mut in_block = false;
        let mut patterns = Vec::new();
        let mut min_hits = 1usize;

        while idx < lines.len() {
            let cur = lines[idx].trim();
            if parse_rule_header(cur).is_some() {
                break;
            }
            used[idx] = true;
            if cur == "\"\"\"" {
                in_block = !in_block;
                idx += 1;
                continue;
            }
            if cur.is_empty() || is_custom_comment(cur) {
                idx += 1;
                continue;
            }
            if !in_block && is_min_hits_directive(cur) {
                if let Some(v) = parse_min_hits_line(cur) {
                    min_hits = v.max(1);
                }
                idx += 1;
                continue;
            }
            patterns.push(cur.to_string());
            idx += 1;
        }

        let patterns = normalize_custom_patterns(patterns);
        if patterns.is_empty() {
            continue;
        }
        out.push(CustomRule {
            client: rule_name,
            min_hits: min_hits.min(patterns.len()),
            patterns,
            source: source.to_string(),
            target_process: target_process.map(str::to_string),
        });
    }

    for (line_idx, raw) in lines.iter().enumerate() {
        if used[line_idx] {
            continue;
        }
        let line = raw.trim();
        if line.is_empty() || line == "\"\"\"" || is_custom_comment(line) {
            continue;
        }
        if is_min_hits_directive(line) {
            continue;
        }
        if let Some((client_raw, needle_raw)) = line.split_once(":::") {
            let client = client_raw.trim();
            let needle = needle_raw.trim();
            if client.is_empty() || needle.is_empty() {
                continue;
            }
            out.push(CustomRule {
                client: client.to_string(),
                patterns: vec![needle.to_string()],
                min_hits: 1,
                source: source.to_string(),
                target_process: target_process.map(str::to_string),
            });
            continue;
        }
        out.push(CustomRule {
            client: fallback_client.to_string(),
            patterns: vec![line.to_string()],
            min_hits: 1,
            source: source.to_string(),
            target_process: target_process.map(str::to_string),
        });
    }
}

fn parse_rule_header(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("rule ") {
        return None;
    }
    let mut body = trimmed[5..].trim();
    if let Some(stripped) = body.strip_suffix(':') {
        body = stripped.trim();
    }
    if body.is_empty() {
        return None;
    }
    Some(body.to_string())
}

fn parse_min_hits_line(line: &str) -> Option<usize> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("min") {
        return None;
    }

    let mut rest = trimmed[3..].trim();
    if let Some(v) = rest.strip_prefix(':') {
        rest = v.trim();
    } else if let Some(v) = rest.strip_prefix('=') {
        rest = v.trim();
    } else if rest.starts_with('(') {
        return None;
    }

    if rest.is_empty() {
        return None;
    }

    let digits = rest
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<usize>().ok()
}

fn is_min_hits_directive(line: &str) -> bool {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("min") {
        return false;
    }
    if trimmed.len() == 3 {
        return true;
    }
    let rest = &trimmed[3..];
    rest.chars()
        .next()
        .is_some_and(|c| c.is_ascii_whitespace() || c == ':' || c == '=' || c == '(')
}

fn is_custom_comment(line: &str) -> bool {
    let t = line.trim();
    t.starts_with('#') || t.starts_with("//") || t.starts_with(';')
}

fn normalize_custom_patterns(patterns: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in patterns {
        let trimmed = raw.trim().trim_matches('"').trim();
        if trimmed.is_empty() {
            continue;
        }
        let lowered = trimmed.to_ascii_lowercase();
        if seen.insert(lowered) {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn collect_custom_needles(rules: &[CustomRule]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for rule in rules {
        for pat in &rule.patterns {
            let needle = pat.trim().to_ascii_lowercase();
            if needle.len() < 3 {
                continue;
            }
            if seen.insert(needle.clone()) {
                out.push(needle);
            }
        }
    }
    out
}

fn scan_files_for_custom_hits(
    inputs: &[PreparedInput],
    matcher: &CustomMatcher,
    hits_by_file: &mut BTreeMap<String, Vec<CustomHit>>,
) -> io::Result<usize> {
    let worker_count = choose_custom_scan_workers(inputs.len());
    if worker_count <= 1 || inputs.len() < 6 {
        let mut scanned = 0usize;
        for input in inputs {
            if !input.scan.is_file() {
                continue;
            }
            let hits = scan_single_file_for_custom_hits(&input.scan, matcher)?;
            scanned += 1;
            if !hits.is_empty() {
                hits_by_file.insert(input.source.display().to_string(), hits);
            }
        }
        return Ok(scanned);
    }

    log_info(&format!(
        "{}: {}",
        tr_ui("Потоки кастом-скана", "Custom scan workers"),
        worker_count
    ));

    let cursor = AtomicUsize::new(0);
    let parts = thread::scope(
        |scope| -> io::Result<Vec<(usize, Vec<(String, Vec<CustomHit>)>)>> {
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                handles.push(scope.spawn(|| {
                    let mut scanned = 0usize;
                    let mut local_hits = Vec::new();
                    loop {
                        let idx = cursor.fetch_add(1, Ordering::Relaxed);
                        if idx >= inputs.len() {
                            break;
                        }
                        let input = &inputs[idx];
                        if !input.scan.is_file() {
                            continue;
                        }
                        let hits = scan_single_file_for_custom_hits(&input.scan, matcher)?;
                        scanned += 1;
                        if !hits.is_empty() {
                            local_hits.push((input.source.display().to_string(), hits));
                        }
                    }
                    Ok::<(usize, Vec<(String, Vec<CustomHit>)>), io::Error>((scanned, local_hits))
                }));
            }

            let mut out = Vec::with_capacity(worker_count);
            for handle in handles {
                let part = handle
                    .join()
                    .map_err(|_| io::Error::other("custom scan worker panicked"))??;
                out.push(part);
            }
            Ok(out)
        },
    )?;

    let mut scanned = 0usize;
    for (part_scanned, part_hits) in parts {
        scanned += part_scanned;
        for (file, hits) in part_hits {
            if !hits.is_empty() {
                hits_by_file.insert(file, hits);
            }
        }
    }
    Ok(scanned)
}

fn choose_custom_scan_workers(file_count: usize) -> usize {
    if file_count == 0 {
        return 1;
    }
    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    let mut workers = cpu.clamp(2, 16).min(cpu_budget);
    workers = workers.min(file_count.max(1));
    if file_count < 10 {
        workers = workers.min(3);
    } else if file_count < 32 {
        workers = workers.min(6);
    }
    workers.min(cpu_budget).max(1)
}

fn scan_single_file_for_custom_hits(
    path: &Path,
    matcher: &CustomMatcher,
) -> io::Result<Vec<CustomHit>> {
    let mut acc = CustomAccumulator::new(matcher, None);
    feed_path_to_custom_accumulator(path, &mut acc)?;
    Ok(acc.finish())
}

fn feed_path_to_custom_accumulator(path: &Path, acc: &mut CustomAccumulator<'_>) -> io::Result<()> {
    if path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|e| e.eq_ignore_ascii_case("txt"))
    {
        let mut probe_file = File::open(path)?;
        let mut probe = vec![0u8; 64 * 1024];
        let n = probe_file.read(&mut probe)?;
        probe.truncate(n);
        if looks_utf16(&probe) {
            let mut f = File::open(path)?;
            let mut b = Vec::new();
            f.read_to_end(&mut b)?;
            feed_text_block(acc, &decode_utf16(&b));
            return Ok(());
        }

        let f = File::open(path)?;
        let mut reader = BufReader::with_capacity(IO_STREAM_BUFFER_BYTES, f);
        let mut line = Vec::with_capacity(8192);
        let mut batch = String::with_capacity(CUSTOM_FEED_BATCH_BYTES);
        let mut assembler = LogicalLineAssembler::default();
        loop {
            line.clear();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&line);
            let (line1, line2) = assembler.push_fragment(text.as_ref());
            if let Some(line) = line1 {
                batch.push_str(&line);
                batch.push('\n');
            }
            if let Some(line) = line2 {
                batch.push_str(&line);
                batch.push('\n');
            }
            if batch.len() >= CUSTOM_FEED_BATCH_BYTES {
                acc.feed_text(&batch);
                batch.clear();
                if acc.is_done() {
                    return Ok(());
                }
            }
        }
        if let Some(line) = assembler.finish() {
            batch.push_str(&line);
            batch.push('\n');
        }
        if !batch.is_empty() {
            acc.feed_text(&batch);
        }
        return Ok(());
    }

    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if looks_utf16(&bytes) {
        feed_text_block(acc, &decode_utf16(&bytes));
    } else {
        feed_text_block(acc, &String::from_utf8_lossy(&bytes));
    }
    if acc.is_done() {
        return Ok(());
    }
    for s in extract_strings_system_informer(&bytes, PROCESS_STRINGS_MIN_LEN, false) {
        acc.feed_text(&s);
        if acc.is_done() {
            break;
        }
    }
    Ok(())
}

fn feed_text_block(acc: &mut CustomAccumulator<'_>, text: &str) {
    let mut batch = String::with_capacity(CUSTOM_FEED_BATCH_BYTES);
    let mut assembler = LogicalLineAssembler::default();
    for frag in text.split(|c| c == '\n' || c == '\r' || c == '\0') {
        let (line1, line2) = assembler.push_fragment(frag);
        if let Some(line) = line1 {
            batch.push_str(&line);
            batch.push('\n');
        }
        if let Some(line) = line2 {
            batch.push_str(&line);
            batch.push('\n');
        }
        if batch.len() >= CUSTOM_FEED_BATCH_BYTES {
            acc.feed_text(&batch);
            batch.clear();
            if acc.is_done() {
                return;
            }
        }
    }
    if let Some(line) = assembler.finish() {
        batch.push_str(&line);
        batch.push('\n');
    }
    if !batch.is_empty() {
        acc.feed_text(&batch);
    }
}

fn custom_hits_grouped_lines(hits_by_file: &BTreeMap<String, Vec<CustomHit>>) -> Vec<String> {
    let mut out = Vec::new();
    for (file, hits) in hits_by_file {
        out.push(file.clone());
        for hit in hits {
            out.push(format!(
                "  - rule: {} | matched: {}/{} | min: {} | source: {}",
                hit.client, hit.matched_count, hit.total_patterns, hit.min_hits, hit.source
            ));
        }
        out.push(String::new());
    }
    while out.last().is_some_and(|x| x.is_empty()) {
        out.pop();
    }
    out
}

fn write_lines(path: &Path, items: &[String]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = BufWriter::with_capacity(IO_STREAM_BUFFER_BYTES, File::create(path)?);
    for item in items {
        writeln!(writer, "{item}")?;
    }
    writer.flush()?;
    Ok(())
}

fn write_custom_outputs(
    custom_dir: &Path,
    rules: &[CustomRule],
    stats: &CustomScanStats,
) -> io::Result<()> {
    fs::create_dir_all(custom_dir)?;

    let mut rules_lines = Vec::new();
    for r in rules {
        let scope = r.target_process.as_deref().unwrap_or("all");
        rules_lines.push(format!(
            "{} | min {} | {} | source: {} | process: {}",
            r.client,
            r.min_hits,
            r.patterns.join(" ; "),
            r.source,
            scope
        ));
    }
    if rules_lines.is_empty() {
        rules_lines.push("No custom rules loaded".to_string());
    }
    write_lines(&custom_dir.join("rules_loaded.txt"), &rules_lines)?;

    let grouped = custom_hits_grouped_lines(&stats.hits_by_file);
    let grouped_to_write = if grouped.is_empty() {
        vec!["No custom hits".to_string()]
    } else {
        grouped.clone()
    };
    write_lines(&custom_dir.join("custom_hits.txt"), &grouped_to_write)?;

    let mut flat = BTreeSet::new();
    let mut process_only = BTreeSet::new();
    let process_mark = format!("\\{}\\", "programscustom");
    for (file, hits) in &stats.hits_by_file {
        for hit in hits {
            let row = format!(
                "{file} | rule: {} | matched: {}/{} | min: {} | source: {}",
                hit.client, hit.matched_count, hit.total_patterns, hit.min_hits, hit.source
            );
            flat.insert(row.clone());
            if file
                .to_ascii_lowercase()
                .contains(&process_mark.to_ascii_lowercase())
            {
                process_only.insert(row);
            }
        }
    }
    if flat.is_empty() {
        flat.insert("No custom hits".to_string());
    }
    if process_only.is_empty() {
        process_only.insert("No process custom hits".to_string());
    }
    write_list(&custom_dir.join("custom_hits_flat.txt"), &flat)?;
    write_list(&custom_dir.join("programscustom_hits.txt"), &process_only)?;

    let process_stats = vec![
        format!("rules_loaded: {}", stats.rules_loaded),
        format!("input_files_scanned: {}", stats.input_files_scanned),
        format!("process_scanned: {}", stats.process_scanned),
        format!("process_skipped: {}", stats.process_skipped),
        format!("process_dumps: {}", stats.process_dumps),
        format!("hit_files: {}", stats.hits_by_file.len()),
        format!("hits_total: {}", total_custom_hits(&stats.hits_by_file)),
    ];
    write_lines(&custom_dir.join("stats.txt"), &process_stats)?;
    Ok(())
}

#[derive(Default)]
struct ProcessScanReport {
    process_scanned: usize,
    process_skipped: usize,
    process_dumps: usize,
    dump_files: Vec<PathBuf>,
    process_analyzer: Analyzer,
}

#[cfg(windows)]
fn enable_debug_privilege() -> bool {
    let mut token = HANDLE::default();
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    };
    if opened.is_err() || token.is_invalid() {
        return false;
    }

    let mut luid = LUID::default();
    let looked = unsafe { LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut luid) };
    if looked.is_err() {
        unsafe {
            let _ = CloseHandle(token);
        }
        return false;
    }

    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [Default::default(); 1],
    };
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    let adjusted = unsafe {
        AdjustTokenPrivileges(
            token,
            false,
            Some(&tp as *const TOKEN_PRIVILEGES),
            0,
            None,
            None,
        )
    };
    unsafe {
        let _ = CloseHandle(token);
    }
    adjusted.is_ok()
}

