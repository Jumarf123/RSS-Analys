// Embedded YARA rule loading, compilation, scanning, and match reporting.

fn yara_scan(allpe: &BTreeSet<String>, _cache_root: &Path) -> io::Result<BTreeSet<String>> {
    if allpe.is_empty() {
        let mut out = BTreeSet::new();
        out.insert("No detections".to_string());
        return Ok(out);
    }

    // YARA parser can require deep recursion on large rule sets.
    // Run compile/scan on a worker thread with a larger stack to avoid stack overflow.
    let targets = allpe.clone();
    let handle = thread::Builder::new()
        .name("yara-scan".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || yara_scan_inner(&targets))
        .map_err(|e| io::Error::other(format!("failed to start yara scan thread: {e}")))?;

    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(io::Error::other("yara scan thread panicked")),
    }
}

fn yara_scan_inner(allpe: &BTreeSet<String>) -> io::Result<BTreeSet<String>> {
    let (rules, rule_to_yar) = compile_embedded_yara_rules()?;
    let mut out = BTreeSet::new();
    if rule_to_yar.is_empty() {
        out.insert("No embedded rules".to_string());
        return Ok(out);
    }

    let mut jobs = Vec::new();
    let mut missing_files = 0usize;

    for path in allpe {
        let p = normalize_full_windows_path(path);
        if !Path::new(&p).is_file() {
            missing_files += 1;
            continue;
        }
        jobs.push(p);
    }

    if missing_files > 0 {
        log_info(&format!(
            "{}: {}",
            tr_ui("пропущено отсутствующих файлов", "missing files skipped"),
            missing_files
        ));
    }

    if jobs.is_empty() {
        out.insert("No detections".to_string());
        return Ok(out);
    }

    let rules = Arc::new(rules);
    let rule_to_yar = Arc::new(rule_to_yar);
    let files: Arc<Vec<String>> = Arc::new(jobs);
    let cfg = choose_yara_parallel_cfg(files.len());
    log_info(&format!(
        "{}: {} | {}: {}",
        tr_ui("YARA-потоки", "YARA workers"),
        cfg.workers,
        tr_ui("Файлов к сканированию", "Files queued"),
        files.len()
    ));
    let cursor = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel::<Vec<String>>();

    for _ in 0..cfg.workers {
        let tx = tx.clone();
        let rules = Arc::clone(&rules);
        let rule_to_yar = Arc::clone(&rule_to_yar);
        let files = Arc::clone(&files);
        let cursor = Arc::clone(&cursor);
        let batch_size = cfg.batch_size;

        thread::spawn(move || {
            let mut scanner = Scanner::new(rules.as_ref());
            let mut local = Vec::new();

            loop {
                let start = cursor.fetch_add(batch_size, Ordering::Relaxed);
                if start >= files.len() {
                    break;
                }
                let end = (start + batch_size).min(files.len());
                for path in &files[start..end] {
                    let Ok(r) = scanner.scan_file(path) else {
                        continue;
                    };
                    let report = yara_match_report(&r, &rule_to_yar);
                    if !report.is_empty() {
                        local.push(format!("{path} | {report}"));
                    }
                }
            }

            let _ = tx.send(local);
        });
    }
    drop(tx);

    for detections in rx {
        out.extend(detections);
    }

    if out.is_empty() {
        out.insert("No detections".to_string());
    }
    Ok(out)
}

#[derive(Clone)]
struct EmbeddedYaraSource {
    path: String,
    file_label: String,
    source: String,
}

fn collect_embedded_yara_sources() -> Vec<EmbeddedYaraSource> {
    let mut out = Vec::new();
    for f in YARA_DIR.files() {
        let Some(ext) = f.path().extension().and_then(OsStr::to_str) else {
            continue;
        };
        if !ext.eq_ignore_ascii_case("yar") && !ext.eq_ignore_ascii_case("yara") {
            continue;
        }
        let Some(src) = f.contents_utf8() else {
            continue;
        };
        let path = f.path().display().to_string();
        let file_label = f
            .path()
            .file_stem()
            .and_then(OsStr::to_str)
            .map(str::to_string)
            .unwrap_or_else(|| path.clone());
        out.push(EmbeddedYaraSource {
            path,
            file_label,
            source: src.to_string(),
        });
    }
    out.sort_by(|a, b| {
        a.path
            .to_ascii_lowercase()
            .cmp(&b.path.to_ascii_lowercase())
    });
    out
}

fn build_rule_to_yar_map(sources: &[EmbeddedYaraSource]) -> HashMap<String, BTreeSet<String>> {
    let mut out: HashMap<String, BTreeSet<String>> = HashMap::new();
    for source in sources {
        for rid in extract_yara_rule_names(&source.source) {
            out.entry(rid.to_ascii_lowercase())
                .or_default()
                .insert(source.file_label.clone());
        }
    }
    out
}

fn compile_embedded_yara_rules() -> io::Result<(Rules, HashMap<String, BTreeSet<String>>)> {
    let sources = collect_embedded_yara_sources();
    if sources.is_empty() {
        return Ok((Compiler::new().build(), HashMap::new()));
    }

    let rule_to_yar = build_rule_to_yar_map(&sources);
    log_info(tr_ui(
        "Компиляция встроенных правил сканирования",
        "Compiling embedded scanning rules",
    ));
    let mut compiler = Compiler::new();
    let mut loaded = 0usize;
    for source in &sources {
        if compiler.add_source(source.source.as_str()).is_ok() {
            loaded += 1;
        }
    }
    if loaded == 0 {
        return Ok((compiler.build(), HashMap::new()));
    }

    Ok((compiler.build(), rule_to_yar))
}

fn yara_match_report(
    scan_result: &yara_x::ScanResults<'_, '_>,
    rule_to_yar: &HashMap<String, BTreeSet<String>>,
) -> String {
    let mut hits = Vec::new();
    for mr in scan_result.matching_rules() {
        let rid = mr.identifier().to_string();
        if let Some(yar_names) = rule_to_yar.get(&rid.to_ascii_lowercase()) {
            hits.extend(yar_names.iter().cloned());
        } else {
            hits.push(rid);
        }
    }
    if hits.is_empty() {
        return String::new();
    }
    hits.sort_unstable();
    hits.dedup();
    hits.join(", ")
}

struct YaraParallelCfg {
    workers: usize,
    batch_size: usize,
}

fn choose_yara_parallel_cfg(file_count: usize) -> YaraParallelCfg {
    if file_count == 0 {
        return YaraParallelCfg {
            workers: 1,
            batch_size: 32,
        };
    }

    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);

    let mut sys = System::new();
    sys.refresh_memory();
    let available_gb = (sys.available_memory() / 1024 / 1024 / 1024) as usize;

    let mut workers = if cpu >= 8 {
        cpu.saturating_mul(2)
    } else {
        cpu.saturating_add(2)
    }
    .clamp(2, 48);

    let mem_cap = match available_gb {
        0..=3 => 4,
        4..=7 => 8,
        8..=11 => 14,
        12..=15 => 20,
        16..=23 => 28,
        24..=31 => 36,
        _ => 48,
    };
    workers = workers.min(mem_cap).max(1);
    workers = workers.min(file_count);
    workers = workers.min(cpu_budget).max(1);

    let batch_size = if file_count <= 96 {
        4
    } else if file_count <= 480 {
        12
    } else if file_count <= 2_000 {
        24
    } else {
        48
    };

    YaraParallelCfg {
        workers,
        batch_size,
    }
}

#[derive(Default)]
struct LogicalLineAssembler {
    pending: Option<String>,
}

impl LogicalLineAssembler {
    fn push_fragment(&mut self, raw: &str) -> (Option<String>, Option<String>) {
        let cur = raw
            .trim_matches(|c| c == '\r' || c == '\n' || c == '\0')
            .trim();
        if cur.is_empty() {
            return (self.pending.take(), None);
        }

        let cur_owned = cur.to_string();
        let Some(prev) = self.pending.take() else {
            if line_needs_stitch_continuation(&cur_owned) {
                self.pending = Some(cur_owned);
                return (None, None);
            }
            return (Some(cur_owned), None);
        };

        if should_stitch_line_pair(&prev, &cur_owned) {
            let merged = join_stitched_lines(&prev, &cur_owned);
            if line_needs_stitch_continuation(&merged) {
                self.pending = Some(merged);
                return (None, None);
            }
            return (Some(merged), None);
        }

        let out1 = Some(prev);
        if line_needs_stitch_continuation(&cur_owned) {
            self.pending = Some(cur_owned);
            return (out1, None);
        }
        (out1, Some(cur_owned))
    }

    fn finish(&mut self) -> Option<String> {
        self.pending.take()
    }
}

fn line_needs_stitch_continuation(line: &str) -> bool {
    let t = line.trim();
    if t.len() < 2 || t.len() > LINE_STITCH_MAX_PENDING_BYTES {
        return false;
    }
    if t.ends_with('\\') || t.ends_with('/') || t.ends_with('^') || t.ends_with('`') {
        return true;
    }
    if is_probable_split_path_head(t) {
        return true;
    }
    if !has_unclosed_double_quote(t) {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    lower.contains(":\\")
        || lower.contains("\\device\\harddiskvolume")
        || lower.contains("\\??\\")
        || lower.contains("\\\\?\\")
        || contains_tracked_extension_hint(&lower)
        || has_shell_launcher_lc(&lower)
        || lower.contains("process call create")
}

fn is_probable_split_path_head(line: &str) -> bool {
    let t = line.trim_end();
    if t.len() < 4 || t.len() > LINE_STITCH_MAX_PENDING_BYTES {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    if !(lower.contains(":\\")
        || lower.contains("\\device\\harddiskvolume")
        || lower.contains("\\??\\")
        || lower.contains("\\\\?\\"))
    {
        return false;
    }
    if contains_tracked_extension_hint(&lower) {
        return false;
    }
    if t.contains(';') || t.contains('|') {
        return false;
    }
    let last = t.chars().last().unwrap_or_default();
    last.is_ascii_alphanumeric() || matches!(last, '_' | '-' | ')' | ']' | '}' | '.')
}

fn line_can_be_stitch_tail(line: &str) -> bool {
    let t = line.trim();
    if t.is_empty() {
        return false;
    }
    let first = t.chars().next().unwrap_or_default();
    if matches!(first, '\\' | '/' | '"' | '\'' | '%' | '.') {
        return true;
    }
    if t.len() <= 12
        && t.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '"' | '\'' | '\\' | '/' | 'r' | 'n' | 't'))
    {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    contains_tracked_extension_hint(&lower)
        || lower.contains(":\\")
        || lower.contains("\\")
        || contains_url_scheme_lc(&lower)
        || has_shell_chain_operator(&lower)
        || has_token_any_lc(
            &lower,
            &[
                "cmd",
                "wmic",
                "reg",
                "powershell",
                "pwsh",
                "rundll32",
                "regsvr32",
                "forfiles",
                "java",
                "javaw",
                "/c",
                "/k",
                "call",
            ],
        )
}

fn should_stitch_line_pair(prev: &str, next: &str) -> bool {
    if !line_needs_stitch_continuation(prev) {
        return is_probable_split_path_continuation(prev, next);
    }
    if has_unclosed_double_quote(prev) {
        return true;
    }
    line_can_be_stitch_tail(next)
}

fn is_probable_split_path_continuation(prev: &str, next: &str) -> bool {
    let left = prev.trim_end();
    let right = next.trim_start();
    if left.len() < 4 || right.len() < 4 {
        return false;
    }
    let right_first = right.chars().next().unwrap_or_default();
    if !matches!(right_first, '\\' | '/') {
        return false;
    }
    let left_lower = left.to_ascii_lowercase();
    if !(left_lower.contains(":\\")
        || left_lower.contains("\\device\\harddiskvolume")
        || left_lower.contains("\\??\\")
        || left_lower.contains("\\\\?\\"))
    {
        return false;
    }
    if contains_tracked_extension_hint(&left_lower) {
        return false;
    }
    if left.contains(';') || left.contains('|') {
        return false;
    }
    let right_lower = right.to_ascii_lowercase();
    if !contains_tracked_extension_hint(&right_lower) {
        return false;
    }
    let left_last = left.chars().last().unwrap_or_default();
    if !(left_last.is_ascii_alphanumeric()
        || matches!(left_last, '_' | '-' | ')' | ']' | '}' | '.'))
    {
        return false;
    }
    true
}

fn has_unclosed_double_quote(line: &str) -> bool {
    line.bytes().filter(|b| *b == b'"').count() % 2 == 1
}

fn join_stitched_lines(prev: &str, next: &str) -> String {
    let left = prev.trim_end();
    let right = next.trim_start();
    if left.is_empty() {
        return sanitize_joined_line_tail(right.to_string());
    }
    if right.is_empty() {
        return sanitize_joined_line_tail(left.to_string());
    }

    let left_ends_bs = left.ends_with('\\');
    let left_ends_sl = left.ends_with('/');
    let right_starts_bs = right.starts_with('\\');
    let right_starts_sl = right.starts_with('/');
    let right_starts_quote = right.starts_with('"') || right.starts_with('\'');

    let mut out = String::with_capacity(left.len() + right.len() + 1);
    out.push_str(left);

    if (left_ends_bs && right_starts_bs) || (left_ends_sl && right_starts_sl) {
        let mut chars = right.chars();
        let _ = chars.next();
        out.extend(chars);
        return sanitize_joined_line_tail(out);
    }

    if !(left_ends_bs || left_ends_sl || right_starts_bs || right_starts_sl || right_starts_quote) {
        out.push(' ');
    }
    out.push_str(right);
    sanitize_joined_line_tail(out)
}

fn sanitize_joined_line_tail(mut line: String) -> String {
    line = trim_trailing_literal_escape_suffix(&line).to_string();
    line = trim_trailing_quote_numeric_suffix(&line).to_string();
    line
}

fn trim_trailing_literal_escape_suffix(raw: &str) -> &str {
    let mut out = raw.trim_end_matches(char::is_whitespace);
    loop {
        let Some(next) = out
            .strip_suffix("\\r")
            .or_else(|| out.strip_suffix("\\n"))
            .or_else(|| out.strip_suffix("\\t"))
        else {
            break;
        };
        out = next.trim_end_matches(char::is_whitespace);
    }
    out
}

fn trim_trailing_quote_numeric_suffix(raw: &str) -> &str {
    let trimmed = raw.trim_end_matches(char::is_whitespace);
    let bytes = trimmed.as_bytes();
    if bytes.len() < 3 {
        return trimmed;
    }
    let mut i = bytes.len();
    while i > 0 && bytes[i - 1].is_ascii_digit() {
        i -= 1;
    }
    if i == bytes.len() || i == 0 {
        return trimmed;
    }
    let digits_len = bytes.len() - i;
    if digits_len > 6 {
        return trimmed;
    }
    if bytes[i - 1] != b'"' && bytes[i - 1] != b'\'' {
        return trimmed;
    }
    trimmed[..i].trim_end_matches(char::is_whitespace)
}

