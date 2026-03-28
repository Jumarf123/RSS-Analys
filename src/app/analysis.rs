// Parallel and streaming content analysis, plus generic output helper functions.

fn analyze_file(path: &Path, analyzer: &mut Analyzer, fast_prepared: bool) -> io::Result<()> {
    if path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|e| e.eq_ignore_ascii_case("txt"))
    {
        if fast_prepared {
            return analyze_text_file_stream_fast(path, analyzer);
        }
        return analyze_text_file_stream(path, analyzer);
    }

    let mut f = File::open(path)?;
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    if looks_utf16(&b) {
        analyzer.analyze_text(&decode_utf16(&b));
    } else {
        analyzer.analyze_text(&String::from_utf8_lossy(&b));
    }
    if binary_like(&b) {
        for s in extract_ascii_strings(&b, 6) {
            analyzer.analyze_fragment(&s);
        }
        for s in extract_utf16_ascii_strings(&b, 6) {
            analyzer.analyze_fragment(&s);
        }
    }
    Ok(())
}

fn analyze_text_file_stream_fast(path: &Path, analyzer: &mut Analyzer) -> io::Result<()> {
    let file_size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let worker_count = choose_large_text_workers(file_size);
    if worker_count > 1 {
        let parallel = analyze_text_file_stream_large_parallel_fast(path, worker_count)?;
        merge_analyzer(analyzer, parallel);
        return Ok(());
    }

    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(IO_STREAM_BUFFER_BYTES, f);
    let mut line = Vec::with_capacity(8192);

    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(&line);
        analyzer.process_line_fast_core(text.as_ref());
    }
    Ok(())
}

fn analyze_text_file_stream_large_parallel_fast(
    path: &Path,
    worker_count: usize,
) -> io::Result<Analyzer> {
    let mut senders = Vec::with_capacity(worker_count);
    let mut handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let (tx, rx) = mpsc::sync_channel::<Option<String>>(2);
        senders.push(tx);
        handles.push(thread::spawn(move || {
            let mut local = Analyzer::default();
            while let Ok(chunk) = rx.recv() {
                let Some(text) = chunk else {
                    break;
                };
                local.analyze_text_fast(&text);
            }
            local
        }));
    }

    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(IO_STREAM_BUFFER_BYTES, f);
    let mut line = Vec::with_capacity(8192);
    let mut chunk = String::with_capacity(LARGE_TEXT_CHUNK_TARGET_BYTES + 8192);
    let mut rr = 0usize;

    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        let text = String::from_utf8_lossy(&line);
        chunk.push_str(text.as_ref());
        if chunk.len() >= LARGE_TEXT_CHUNK_TARGET_BYTES {
            let tx = &senders[rr % worker_count];
            tx.send(Some(std::mem::take(&mut chunk)))
                .map_err(|_| io::Error::other("fast text worker disconnected"))?;
            rr += 1;
            chunk = String::with_capacity(LARGE_TEXT_CHUNK_TARGET_BYTES + 8192);
        }
    }

    if !chunk.is_empty() {
        let tx = &senders[rr % worker_count];
        tx.send(Some(chunk))
            .map_err(|_| io::Error::other("fast text worker disconnected"))?;
    }

    for tx in senders {
        let _ = tx.send(None);
    }

    let mut merged = Analyzer::default();
    for handle in handles {
        let part = handle
            .join()
            .map_err(|_| io::Error::other("fast text worker panicked"))?;
        merge_analyzer(&mut merged, part);
    }
    Ok(merged)
}

fn analyze_text_file_stream(path: &Path, analyzer: &mut Analyzer) -> io::Result<()> {
    let mut probe_file = File::open(path)?;
    let mut probe = vec![0u8; 64 * 1024];
    let n = probe_file.read(&mut probe)?;
    probe.truncate(n);

    if looks_utf16(&probe) {
        let mut f = File::open(path)?;
        let mut b = Vec::new();
        f.read_to_end(&mut b)?;
        analyzer.analyze_text(&decode_utf16(&b));
        return Ok(());
    }

    let file_size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let worker_count = choose_large_text_workers(file_size);
    if worker_count > 1 {
        let parallel = analyze_text_file_stream_large_parallel(path, worker_count)?;
        merge_analyzer(analyzer, parallel);
        return Ok(());
    }

    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(IO_STREAM_BUFFER_BYTES, f);
    let mut line = Vec::with_capacity(8192);
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
            analyzer.analyze_fragment(&line);
        }
        if let Some(line) = line2 {
            analyzer.analyze_fragment(&line);
        }
    }
    if let Some(line) = assembler.finish() {
        analyzer.analyze_fragment(&line);
    }

    Ok(())
}

fn choose_large_text_workers(file_size: u64) -> usize {
    if file_size < LARGE_TEXT_PARALLEL_THRESHOLD_BYTES {
        return 1;
    }
    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    let mut workers = cpu.clamp(2, 12).min(cpu_budget);
    if file_size < 192 * 1024 * 1024 {
        workers = workers.min(6);
    }
    workers.min(cpu_budget).max(1)
}

fn analyze_text_file_stream_large_parallel(
    path: &Path,
    worker_count: usize,
) -> io::Result<Analyzer> {
    let mut senders = Vec::with_capacity(worker_count);
    let mut handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let (tx, rx) = mpsc::sync_channel::<Option<String>>(2);
        senders.push(tx);
        handles.push(thread::spawn(move || {
            let mut local = Analyzer::default();
            while let Ok(chunk) = rx.recv() {
                let Some(text) = chunk else {
                    break;
                };
                local.analyze_text(&text);
            }
            local
        }));
    }

    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(IO_STREAM_BUFFER_BYTES, f);
    let mut line = Vec::with_capacity(8192);
    let mut chunk = String::with_capacity(LARGE_TEXT_CHUNK_TARGET_BYTES + 8192);
    let mut rr = 0usize;

    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        let text = String::from_utf8_lossy(&line);
        chunk.push_str(text.as_ref());
        if chunk.len() >= LARGE_TEXT_CHUNK_TARGET_BYTES {
            let tx = &senders[rr % worker_count];
            tx.send(Some(std::mem::take(&mut chunk)))
                .map_err(|_| io::Error::other("large text worker disconnected"))?;
            rr += 1;
            chunk = String::with_capacity(LARGE_TEXT_CHUNK_TARGET_BYTES + 8192);
        }
    }

    if !chunk.is_empty() {
        let tx = &senders[rr % worker_count];
        tx.send(Some(chunk))
            .map_err(|_| io::Error::other("large text worker disconnected"))?;
    }

    for tx in senders {
        let _ = tx.send(None);
    }

    let mut merged = Analyzer::default();
    for handle in handles {
        let part = handle
            .join()
            .map_err(|_| io::Error::other("large text analyze worker panicked"))?;
        merge_analyzer(&mut merged, part);
    }
    Ok(merged)
}

fn analyze_prepared_inputs_parallel(
    inputs: &[PreparedInput],
    lang: UiLang,
) -> io::Result<Analyzer> {
    if inputs.is_empty() {
        return Ok(Analyzer::default());
    }

    let worker_count = choose_input_analyze_workers(inputs.len());
    if worker_count <= 1 || inputs.len() < 4 {
        let mut analyzer = Analyzer::default();
        for input in inputs {
            if !input.scan.is_file() {
                continue;
            }
            analyze_file(&input.scan, &mut analyzer, input.fast_prepared)?;
        }
        return Ok(analyzer);
    }

    log_info(&format!(
        "{}: {}",
        tr(lang, "Потоки анализа входов", "Input analyze workers"),
        worker_count
    ));

    let cursor = AtomicUsize::new(0);
    let parts = thread::scope(|scope| -> io::Result<Vec<Analyzer>> {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            handles.push(scope.spawn(|| {
                let mut local = Analyzer::default();
                loop {
                    let idx = cursor.fetch_add(1, Ordering::Relaxed);
                    if idx >= inputs.len() {
                        break;
                    }
                    let scan = &inputs[idx].scan;
                    if !scan.is_file() {
                        continue;
                    }
                    if let Err(e) = analyze_file(scan, &mut local, inputs[idx].fast_prepared) {
                        eprintln!("input analyze failed {}: {}", scan.display(), e);
                    }
                }
                local
            }));
        }

        let mut out = Vec::with_capacity(worker_count);
        for handle in handles {
            let part = handle
                .join()
                .map_err(|_| io::Error::other("input analyze worker panicked"))?;
            out.push(part);
        }
        Ok(out)
    })?;

    let mut merged = Analyzer::default();
    for part in parts {
        merge_analyzer(&mut merged, part);
    }
    Ok(merged)
}

fn choose_input_analyze_workers(file_count: usize) -> usize {
    if file_count == 0 {
        return 1;
    }
    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    let mut workers = cpu.clamp(2, 12).min(cpu_budget);
    workers = workers.min(file_count.max(1));
    if file_count < 8 {
        workers = workers.min(4);
    } else if file_count < 16 {
        workers = workers.min(6);
    }
    workers.min(cpu_budget).max(1)
}

fn merge_analyzer(dst: &mut Analyzer, mut src: Analyzer) {
    dst.links.append(&mut src.links);
    dst.regdel.append(&mut src.regdel);
    dst.replace.append(&mut src.replace);
    dst.fileless.append(&mut src.fileless);
    dst.dll.append(&mut src.dll);
    dst.forfiles_wmic.append(&mut src.forfiles_wmic);
    dst.java_batch.append(&mut src.java_batch);
    dst.ioc.append(&mut src.ioc);
    dst.full_paths.append(&mut src.full_paths);
    dst.pathless.append(&mut src.pathless);
    dst.java_paths.append(&mut src.java_paths);
    dst.scripts.append(&mut src.scripts);
    dst.start.append(&mut src.start);
    dst.prefetch.append(&mut src.prefetch);
    dst.dps_files.append(&mut src.dps_files);
    dst.dps_events.append(&mut src.dps_events);
    dst.beta.append(&mut src.beta);
    for (k, v) in src.file_time_hints {
        dst.file_time_hints.entry(k).or_default().extend(v);
    }
}

fn read_user_path(prompt: &str) -> io::Result<PathBuf> {
    let mut ui_was_enabled = false;
    if let Some(lock) = RUN_UI.get() {
        if let Ok(mut ui) = lock.lock() {
            if ui.enabled {
                ui.enabled = false;
                ui_was_enabled = true;
            }
        }
    }

    if ui_was_enabled {
        let mut out = io::stdout();
        let _ = execute!(out, Show, LeaveAlternateScreen, ResetColor);
    }

    println!("{prompt}");
    print!("> ");
    io::stdout().flush()?;
    let mut s = String::new();
    let read_result = io::stdin().read_line(&mut s);

    if ui_was_enabled {
        let mut out = io::stdout();
        let _ = execute!(out, EnterAlternateScreen, Hide);
        if let Some(lock) = RUN_UI.get() {
            if let Ok(mut ui) = lock.lock() {
                ui.enabled = true;
                ui.last_cols = 0;
                ui.last_rows = 0;
                ui.last_frame.clear();
                ui.push_log(prompt);
                ui.render();
            }
        }
    }

    read_result?;
    let p = s.trim().trim_matches('"');
    if p.is_empty() {
        return Err(io::Error::other("empty path"));
    }
    Ok(PathBuf::from(p))
}

fn collect_ext(path: &Path, ext: &str) -> io::Result<Vec<PathBuf>> {
    if path.is_file() {
        if path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|x| x.eq_ignore_ascii_case(ext))
        {
            return Ok(vec![path.to_path_buf()]);
        }
        return Ok(Vec::new());
    }
    if !path.is_dir() {
        return Err(io::Error::other("path does not exist"));
    }
    let mut out = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let rd = match fs::read_dir(&cur) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for e in rd {
            let Ok(e) = e else {
                continue;
            };
            let p = e.path();
            let Ok(t) = e.file_type() else {
                continue;
            };
            if t.is_symlink() {
                continue;
            }
            if t.is_dir() {
                if !skip_dir(&p) {
                    stack.push(p);
                }
            } else if t.is_file()
                && p.extension()
                    .and_then(OsStr::to_str)
                    .is_some_and(|x| x.eq_ignore_ascii_case(ext))
            {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn sort_dedupe_paths(v: &mut Vec<PathBuf>) {
    v.sort();
    v.dedup();
}

fn split_full_and_names(
    items: &BTreeSet<String>,
    exts: &[&str],
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut full = BTreeSet::new();
    let mut full_seen = HashSet::new();
    let mut names = BTreeSet::new();

    for item in items {
        let valid = if exts.len() == 1 && exts[0].eq_ignore_ascii_case("pf") {
            normalize_prefetch_name(item).is_some()
        } else {
            is_valid_candidate_with_exts(item, exts)
        };
        if !has_allowed_extension(item, exts) || !valid {
            continue;
        }
        if is_abs_win(item) {
            if full_seen.insert(normalize_cmp_path(item)) {
                full.insert(item.clone());
            }
        } else {
            names.insert(item.to_ascii_lowercase());
        }
    }
    (full, names)
}

fn split_full_and_names_any(items: &BTreeSet<String>) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut full = BTreeSet::new();
    let mut full_seen = HashSet::new();
    let mut names = BTreeSet::new();

    for item in items {
        let normalized = normalize_full_windows_path(item);
        if !is_valid_any_file_candidate(&normalized) {
            continue;
        }
        if is_abs_win(&normalized) {
            if full_seen.insert(normalize_cmp_path(&normalized)) {
                full.insert(normalized);
            }
        } else if let Some(name) = normalize_pathless_name_any(&normalized) {
            names.insert(name);
        }
    }
    (full, names)
}

fn collect_lookup_extensions(target_names: &HashSet<String>) -> HashSet<String> {
    let mut out = HashSet::new();
    for name in target_names {
        let Some(ext) = Path::new(name).extension().and_then(OsStr::to_str) else {
            continue;
        };
        let ext_l = ext.to_ascii_lowercase();
        if ext_l.is_empty() || ext_l.len() > 16 {
            continue;
        }
        if ext_l.chars().all(|c| c.is_ascii_alphanumeric()) {
            out.insert(ext_l);
        }
    }
    if out.is_empty() {
        out.extend(RESOLVE_EXTS.iter().map(|x| x.to_string()));
    }
    out
}

fn select_deep_lookup_names_fast(
    target_names: &HashSet<String>,
    max_names: usize,
) -> HashSet<String> {
    if target_names.is_empty() || max_names == 0 {
        return HashSet::new();
    }
    if target_names.len() <= max_names {
        return target_names.clone();
    }

    let mut prioritized = Vec::new();
    let mut secondary = Vec::new();
    for name in target_names {
        let lower = name.to_ascii_lowercase();
        if is_high_value_lookup_name(&lower) {
            prioritized.push(lower);
        } else {
            secondary.push(lower);
        }
    }
    prioritized.sort();
    prioritized.dedup();
    secondary.sort();
    secondary.dedup();

    let mut out = HashSet::with_capacity(max_names);
    for name in prioritized.into_iter().chain(secondary.into_iter()) {
        if out.len() >= max_names {
            break;
        }
        out.insert(name);
    }
    out
}

fn is_high_value_lookup_name(name_lower: &str) -> bool {
    if is_false_positive_suspicious_path_lc(name_lower) {
        return false;
    }
    let ext = Path::new(name_lower)
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    let high_signal_ext = matches!(
        ext,
        "exe" | "dll" | "sys" | "jar" | "bat" | "cmd" | "ps1" | "vbs" | "js"
    );
    if !high_signal_ext {
        return false;
    }
    if SUSPICIOUS.iter().any(|kw| keyword_match_lc(name_lower, kw))
        || CHEAT_ARTIFACT_KEYWORDS
            .iter()
            .any(|kw| keyword_match_lc(name_lower, kw))
        || BYPASS_ARTIFACT_KEYWORDS
            .iter()
            .any(|kw| keyword_match_lc(name_lower, kw))
    {
        return true;
    }
    if BYOVD_DRIVER_NAMES.iter().any(|n| name_lower == *n) {
        return true;
    }
    name_lower.contains("inject")
        || name_lower.contains("mapper")
        || name_lower.contains("spoofer")
        || name_lower.contains("loader")
        || name_lower.contains("bypass")
        || name_lower.contains("cheat")
}

fn extend_missing_full_path_names(
    lookup_names: &mut HashSet<String>,
    full_paths: &BTreeSet<String>,
) {
    for full in full_paths {
        let normalized = normalize_full_windows_path(full);
        if let Some(name) = file_name_lower(&normalized) {
            lookup_names.insert(name);
        }
    }
}

fn build_seed_name_index(
    target_names: &HashSet<String>,
    seed_paths: &BTreeSet<String>,
) -> HashMap<String, BTreeSet<String>> {
    if target_names.is_empty() || seed_paths.is_empty() {
        return HashMap::new();
    }
    let mut out: HashMap<String, BTreeSet<String>> = HashMap::new();
    for raw in seed_paths {
        let normalized = normalize_full_windows_path(raw);
        if !is_abs_win(&normalized) {
            continue;
        }
        let Some(name) = file_name_lower(&normalized) else {
            continue;
        };
        if !target_names.contains(&name) {
            continue;
        }
        out.entry(name).or_default().insert(normalized);
    }
    out
}

fn merge_hashset_name_index(
    dst: &mut HashMap<String, BTreeSet<String>>,
    src: HashMap<String, BTreeSet<String>>,
) {
    for (name, paths) in src {
        dst.entry(name).or_default().extend(paths);
    }
}

fn build_local_name_index(
    target_names: &HashSet<String>,
    exts: &HashSet<String>,
) -> HashMap<String, BTreeSet<String>> {
    let mut collected: FxHashMap<String, Vec<String>> = FxHashMap::default();
    if target_names.is_empty() {
        return HashMap::new();
    }

    let roots = drive_roots();
    if roots.is_empty() {
        return HashMap::new();
    }

    log_info(&format!(
        "{}: {} {}, {} {}",
        tr_ui("Внутренний поиск", "Internal lookup"),
        target_names.len(),
        tr_ui("имен", "names"),
        roots.len(),
        tr_ui("томов", "volumes")
    ));

    let target_name_buckets = Arc::new(build_target_name_buckets(target_names));
    if target_name_buckets.is_empty() {
        return HashMap::new();
    }
    if exts.is_empty() {
        return HashMap::new();
    }
    let (tx, rx) = mpsc::channel();
    let total = roots.len();
    let scan_cfg = choose_drive_scan_cfg();
    log_info(&format!(
        "{}: {}",
        tr_ui(
            "Внутренний скан: потоков на том",
            "Internal scan: threads per volume"
        ),
        scan_cfg.walk_threads
    ));

    for (idx, root) in roots.into_iter().enumerate() {
        log_info(&format!(
            "{} {}/{}: {}",
            tr_ui("Скан тома", "Scanning volume"),
            idx + 1,
            total,
            root.display()
        ));
        let tx = tx.clone();
        let names = Arc::clone(&target_name_buckets);
        let walk_threads = scan_cfg.walk_threads;
        thread::spawn(move || {
            let partial = scan_root_for_names(
                &root,
                &names,
                walk_threads,
                Duration::from_secs(DEEP_LOOKUP_ROOT_TIMEOUT_SECS),
            );
            let _ = tx.send((root, partial));
        });
    }
    drop(tx);

    for (_root, partial) in rx {
        merge_name_maps(&mut collected, partial);
    }

    let mut out: HashMap<String, BTreeSet<String>> = HashMap::with_capacity(collected.len());
    for (name, paths) in collected {
        let mut set = BTreeSet::new();
        set.extend(paths.into_iter());
        out.insert(name, set);
    }

    let total_paths: usize = out.values().map(BTreeSet::len).sum();
    log_info(&format!(
        "{}: {} {}",
        tr_ui("Внутренний индекс готов", "Internal index ready"),
        total_paths,
        tr_ui("путей", "paths")
    ));
    out
}

fn build_target_name_buckets(
    target_names: &HashSet<String>,
) -> FxHashMap<String, FxHashSet<String>> {
    let mut out: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();
    for name in target_names {
        let lower = name.to_ascii_lowercase();
        let Some((_, ext)) = lower.rsplit_once('.') else {
            continue;
        };
        if ext.is_empty() {
            continue;
        }
        out.entry(ext.to_string()).or_default().insert(lower);
    }
    out
}

fn scan_root_for_names(
    root: &Path,
    target_name_buckets: &FxHashMap<String, FxHashSet<String>>,
    walk_threads: usize,
    timeout: Duration,
) -> FxHashMap<String, Vec<String>> {
    let mut out: FxHashMap<String, Vec<String>> = FxHashMap::default();
    let started = Instant::now();
    let mut seen = 0usize;
    let walker = WalkDir::new(root)
        .parallelism(Parallelism::RayonNewPool(walk_threads.max(1)))
        .follow_links(false)
        .skip_hidden(false)
        .sort(false)
        .process_read_dir(|_, _, _, children| {
            children.retain(|res| {
                let Ok(entry) = res else {
                    return false;
                };
                if entry.file_type.is_dir() && entry.file_name().to_str().is_some_and(skip_dir_name)
                {
                    return false;
                }
                true
            });
        });

    for e in walker {
        seen += 1;
        if seen % 4096 == 0 && started.elapsed() >= timeout {
            break;
        }
        let Ok(entry) = e else {
            continue;
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(file_name) = entry.file_name().to_str() else {
            continue;
        };
        let Some((_, ext)) = file_name.rsplit_once('.') else {
            continue;
        };

        let names_for_ext = if ext.bytes().all(|b| !b.is_ascii_uppercase()) {
            target_name_buckets.get(ext)
        } else {
            let ext_lower = ext.to_ascii_lowercase();
            target_name_buckets.get(ext_lower.as_str())
        };
        let Some(names_for_ext) = names_for_ext else {
            continue;
        };

        let name = if file_name.bytes().all(|b| !b.is_ascii_uppercase()) {
            if !names_for_ext.contains(file_name) {
                continue;
            }
            file_name.to_string()
        } else {
            let lowered = file_name.to_ascii_lowercase();
            if !names_for_ext.contains(&lowered) {
                continue;
            }
            lowered
        };
        let p = entry.path();
        if let Some(s) = p.to_str() {
            out.entry(name).or_default().push(s.replace('/', "\\"));
        }
    }

    out
}

fn merge_name_maps(dst: &mut FxHashMap<String, Vec<String>>, src: FxHashMap<String, Vec<String>>) {
    for (name, paths) in src {
        dst.entry(name).or_default().extend(paths);
    }
}

struct DriveScanCfg {
    walk_threads: usize,
}

fn choose_drive_scan_cfg() -> DriveScanCfg {
    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    let mut sys = System::new();
    sys.refresh_memory();
    let available_gb = (sys.available_memory() / 1024 / 1024 / 1024) as usize;
    let mem_cap = match available_gb {
        0..=3 => 4,
        4..=7 => 6,
        8..=11 => 8,
        12..=15 => 10,
        16..=23 => 12,
        _ => 16,
    };
    // Disk walk is mostly IO-bound, so we can use a slightly wider pool.
    let cpu_soft_cap = ((cpu * 3) / 4).clamp(2, 16);
    let walk_threads = cpu_soft_cap.min(mem_cap).min(cpu_budget).max(1);
    DriveScanCfg { walk_threads }
}

fn drive_roots() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for b in b'A'..=b'Z' {
        let p = PathBuf::from(format!("{}:\\", b as char));
        if p.exists() {
            out.push(p);
        }
    }
    out
}

fn skip_dir(path: &Path) -> bool {
    let Some(n) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    skip_dir_name(n)
}

fn skip_dir_name(n: &str) -> bool {
    matches!(
        n.to_ascii_lowercase().as_str(),
        "system volume information"
            | "$recycle.bin"
            | "recycler"
            | "$windows.~bt"
            | "$windows.~ws"
            | "windows"
            | "program files"
            | "program files (x86)"
            | "winsxs"
            | "msocache"
            | "recovery"
            | "perflogs"
            | ".git"
            | "target"
            | "target_release_check"
            | "node_modules"
            | "results"
            | "tools"
    )
}

fn write_list(path: &Path, items: &BTreeSet<String>) -> io::Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let mut f = File::create(path)?;
    for i in items {
        writeln!(f, "{i}")?;
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
}

fn total_custom_hits(hits_by_file: &BTreeMap<String, Vec<CustomHit>>) -> usize {
    hits_by_file.values().map(Vec::len).sum()
}

fn js_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            '<' => out.push_str("\\u003C"),
            '>' => out.push_str("\\u003E"),
            '&' => out.push_str("\\u0026"),
            c if c.is_control() => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn clamp_html_item(item: &str) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    for ch in item.chars() {
        if count >= HTML_JS_ITEM_MAX_CHARS {
            break;
        }
        out.push(ch);
        count += 1;
    }
    if item.chars().count() > HTML_JS_ITEM_MAX_CHARS {
        out.push_str(" ... [trimmed for HTML]");
    }
    out
}

fn js_array_from_iter_limited<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = String::from("[");
    let mut first = true;
    let mut total = 0usize;
    let mut shown = 0usize;

    for item in items {
        total += 1;
        if shown >= HTML_JS_ARRAY_LIMIT {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        if shown % 24 == 0 {
            out.push('\n');
        }
        out.push('"');
        out.push_str(&js_escape(&clamp_html_item(item)));
        out.push('"');
        shown += 1;
    }

    if total > HTML_JS_ARRAY_LIMIT {
        if !first {
            out.push(',');
        }
        out.push('\n');
        out.push('"');
        out.push_str(&js_escape(&format!(
            "[HTML truncated] showing {} of {} items",
            HTML_JS_ARRAY_LIMIT, total
        )));
        out.push('"');
    }
    if !first {
        out.push('\n');
    }
    out.push(']');
    out
}

fn js_array_from_set(items: &BTreeSet<String>) -> String {
    js_array_from_iter_limited(items.iter().map(String::as_str))
}

fn js_array_from_vec(items: &[String]) -> String {
    js_array_from_iter_limited(items.iter().map(String::as_str))
}

fn js_array_from_slice(items: &[&str]) -> String {
    js_array_from_iter_limited(items.iter().copied())
}

fn js_array_from_paths(items: &[PathBuf]) -> String {
    let mut sorted = BTreeSet::new();
    for p in items {
        sorted.insert(p.display().to_string());
    }
    js_array_from_set(&sorted)
}

