// Input discovery, DMP conversion, fast extraction, and pre-analysis preparation utilities.

fn discover_inputs(exe_dir: &Path, cwd: &Path) -> io::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut txt_exe = collect_ext(exe_dir, "txt")?;
    let mut dmp_exe = collect_ext(exe_dir, "dmp")?;
    let mut txt_project = Vec::new();
    let mut dmp_project = Vec::new();
    if let Some(target_dir) = exe_dir.parent() {
        let in_target = target_dir
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case("target"));
        let is_profile_dir = exe_dir
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| {
                name.eq_ignore_ascii_case("release") || name.eq_ignore_ascii_case("debug")
            });
        if in_target
            && is_profile_dir
            && let Some(project_root) = target_dir.parent()
            && project_root != exe_dir
        {
            txt_project = collect_ext(project_root, "txt")?;
            dmp_project = collect_ext(project_root, "dmp")?;
        }
    }
    // Always include current working directory when it differs from exe dir.
    // This keeps `cargo run` behavior intuitive (inputs near the project root are discovered).
    let include_cwd = cwd != exe_dir;
    let mut txt_cwd = Vec::new();
    let mut dmp_cwd = Vec::new();
    if include_cwd {
        txt_cwd = collect_ext(cwd, "txt")?;
        dmp_cwd = collect_ext(cwd, "dmp")?;
    }
    let excluded_dirs =
        build_discover_input_excluded_dirs(exe_dir, if include_cwd { cwd } else { exe_dir });
    txt_exe.retain(|p| !is_path_inside_any(p, &excluded_dirs));
    dmp_exe.retain(|p| !is_path_inside_any(p, &excluded_dirs));
    txt_project.retain(|p| !is_path_inside_any(p, &excluded_dirs));
    dmp_project.retain(|p| !is_path_inside_any(p, &excluded_dirs));
    txt_cwd.retain(|p| !is_path_inside_any(p, &excluded_dirs));
    dmp_cwd.retain(|p| !is_path_inside_any(p, &excluded_dirs));

    let use_cwd_only = include_cwd && (!txt_cwd.is_empty() || !dmp_cwd.is_empty());
    let mut txt = if use_cwd_only {
        txt_cwd
    } else {
        txt_exe.extend(txt_project);
        txt_exe.extend(txt_cwd);
        txt_exe
    };
    let mut dmp = if use_cwd_only {
        dmp_cwd
    } else {
        dmp_exe.extend(dmp_project);
        dmp_exe.extend(dmp_cwd);
        dmp_exe
    };
    sort_dedupe_paths(&mut txt);
    sort_dedupe_paths(&mut dmp);
    Ok((txt, dmp))
}

fn build_discover_input_excluded_dirs(exe_dir: &Path, cwd: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut push_defaults = |root: &Path| {
        dirs.push(root.join("strings"));
        dirs.push(root.join("results"));
        dirs.push(root.join("programscustom"));
        dirs.push(root.join("cache"));
        dirs.push(root.join("tools"));
        dirs.push(root.join("target"));
        dirs.push(root.join("target_release_check"));
        dirs.push(root.join("deps"));
        dirs.push(root.join(".git"));
        dirs.push(root.join(".vscode"));
    };
    push_defaults(exe_dir);
    if cwd != exe_dir {
        push_defaults(cwd);
    }
    dirs
}

fn is_path_inside_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| is_path_inside(path, root))
}

fn is_path_inside(path: &Path, root: &Path) -> bool {
    let p = normalize_path_for_prefix_cmp(path);
    let mut r = normalize_path_for_prefix_cmp(root);
    while r.ends_with('\\') {
        r.pop();
    }
    p == r || p.starts_with(&(r + "\\"))
}

fn normalize_path_for_prefix_cmp(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn dmp_to_txt(
    dmps: &[PathBuf],
    out_dir: &Path,
    fast_out_dir: &Path,
    fast_needle_matcher: &FastNeedleMatcher,
    prefer_fast_only: bool,
) -> io::Result<(Vec<PathBuf>, HashSet<PathBuf>, HashMap<PathBuf, PathBuf>)> {
    fs::create_dir_all(out_dir)?;
    fs::create_dir_all(fast_out_dir)?;
    let mut out = Vec::new();
    let mut converted_sources = HashSet::new();
    let mut fast_scans = HashMap::new();
    log_info(&format!(
        "{}: {} {}",
        tr_ui(
            "Конвертация DMP в TXT встроенным движком",
            "Converting DMP to TXT via built-in engine"
        ),
        dmps.len().min(DMP_CONVERT_MAX),
        tr_ui("файлов", "files")
    ));
    let dmp_list = dmps
        .iter()
        .take(DMP_CONVERT_MAX)
        .cloned()
        .collect::<Vec<_>>();
    let worker_count = choose_dmp_convert_workers(dmp_list.len());
    if worker_count > 1 {
        log_info(&format!(
            "{}: {}",
            tr_ui("Потоки DMP->TXT", "DMP->TXT workers"),
            worker_count
        ));
    }

    #[derive(Clone)]
    struct DmpConvertOk {
        idx: usize,
        source: PathBuf,
        txt: PathBuf,
        fast_scan: Option<PathBuf>,
    }

    let cursor = AtomicUsize::new(0);
    let parts = thread::scope(|scope| -> Vec<Vec<DmpConvertOk>> {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            handles.push(scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let idx = cursor.fetch_add(1, Ordering::Relaxed);
                    if idx >= dmp_list.len() {
                        break;
                    }
                    let dmp = &dmp_list[idx];
                    if let Some(existing_txt) = find_preexisting_txt_for_dmp(dmp) {
                        let txt_len = fs::metadata(&existing_txt).map(|m| m.len()).unwrap_or(0);
                        log_info(&format!(
                            "{}: {} ({} KB)",
                            tr_ui(
                                "DMP -> TXT (повторно используется)",
                                "DMP -> TXT (reused existing)"
                            ),
                            existing_txt.display(),
                            txt_len / 1024
                        ));
                        local.push(DmpConvertOk {
                            idx,
                            source: dmp.clone(),
                            txt: existing_txt,
                            fast_scan: None,
                        });
                        continue;
                    }
                    let stem = dmp
                        .file_stem()
                        .and_then(OsStr::to_str)
                        .unwrap_or("dump")
                        .replace(
                            |c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-',
                            "_",
                        );
                    let txt = out_dir.join(format!("{idx:04}_{stem}.txt"));
                    let fast_txt = fast_out_dir.join(format!("dmp_{idx:04}_{stem}.fast.txt"));

                    if prefer_fast_only {
                        // First pass: fast-only extraction (no full TXT write).
                        // For large dumps this removes heavy disk I/O and is much faster.
                        let fast_stats = run_builtin_strings_fast_only_with_timeout(
                            dmp,
                            &fast_txt,
                            Duration::from_secs(DMP_STRINGS_TIMEOUT_SECS),
                            fast_needle_matcher,
                        );
                        let Ok(fast_stats) = fast_stats else {
                            eprintln!("DMP convert failed to start: {}", dmp.display());
                            continue;
                        };
                        if !fast_stats.ok {
                            eprintln!("DMP convert timeout/failed: {}", dmp.display());
                            let _ = fs::remove_file(&fast_txt);
                            continue;
                        }
                        let fast_len = fs::metadata(&fast_txt).map(|m| m.len()).unwrap_or(0);
                        if fast_stats.fast_kept > 0 && fast_len > 0 {
                            log_info(&format!(
                                "DMP -> FAST: {} ({} KB, {} lines)",
                                dmp.display(),
                                fast_len / 1024,
                                fast_stats.fast_kept
                            ));
                            let fast_scan_path = fast_txt.clone();
                            local.push(DmpConvertOk {
                                idx,
                                source: dmp.clone(),
                                txt: fast_txt,
                                fast_scan: Some(fast_scan_path),
                            });
                            continue;
                        }
                    }

                    // Full TXT conversion is always used for medium/slow profiles.
                    // In fast profile this is used as fallback when fast pass is empty.
                    let stats_full = run_builtin_strings_to_txt_with_timeout(
                        dmp,
                        &txt,
                        Duration::from_secs(DMP_STRINGS_TIMEOUT_SECS),
                        None,
                        true,
                    );
                    let Ok(stats_full) = stats_full else {
                        eprintln!("DMP full convert failed to start: {}", dmp.display());
                        let _ = fs::remove_file(&txt);
                        let _ = fs::remove_file(&fast_txt);
                        continue;
                    };
                    if !stats_full.ok {
                        eprintln!("DMP full convert timeout/failed: {}", dmp.display());
                        let _ = fs::remove_file(&txt);
                        let _ = fs::remove_file(&fast_txt);
                        continue;
                    }
                    let meta_len = fs::metadata(&txt).map(|m| m.len()).unwrap_or(0);
                    if meta_len == 0 {
                        eprintln!("DMP convert empty output: {}", dmp.display());
                        let _ = fs::remove_file(&txt);
                        let _ = fs::remove_file(&fast_txt);
                        continue;
                    }
                    if !prefer_fast_only {
                        let _ = fs::remove_file(&fast_txt);
                    }
                    log_info(&format!(
                        "DMP -> TXT: {} ({} KB)",
                        dmp.display(),
                        meta_len / 1024
                    ));
                    local.push(DmpConvertOk {
                        idx,
                        source: dmp.clone(),
                        txt,
                        fast_scan: None,
                    });
                }
                local
            }));
        }

        let mut out_parts = Vec::with_capacity(worker_count);
        for handle in handles {
            out_parts.push(handle.join().unwrap_or_default());
        }
        out_parts
    });

    let mut all_rows = parts.into_iter().flatten().collect::<Vec<_>>();
    all_rows.sort_by_key(|x| x.idx);
    for row in all_rows {
        out.push(row.txt.clone());
        converted_sources.insert(row.source.clone());
        if let Some(fast_scan) = row.fast_scan {
            fast_scans.insert(row.source.clone(), fast_scan.clone());
            fast_scans.insert(row.txt, fast_scan);
        }
    }
    Ok((out, converted_sources, fast_scans))
}

fn run_builtin_strings_fast_only_with_timeout(
    dmp: &Path,
    fast_txt: &Path,
    timeout: Duration,
    fast_needle_matcher: &FastNeedleMatcher,
) -> io::Result<BuiltinStringsRunStats> {
    if should_use_builtin_fast_parallel_chunks(dmp)
        && let Ok(stats) = run_builtin_strings_fast_only_parallel_chunks(
            dmp,
            fast_txt,
            timeout,
            fast_needle_matcher,
        )
    {
        return Ok(stats);
    }

    run_builtin_strings_to_txt_with_timeout(
        dmp,
        fast_txt,
        timeout,
        Some(BuiltinFastFilterCfg {
            output: fast_txt,
            fast_needle_matcher,
        }),
        false,
    )
}

fn find_preexisting_txt_for_dmp(dmp: &Path) -> Option<PathBuf> {
    let direct = dmp.with_extension("txt");
    if direct.is_file() && fs::metadata(&direct).map(|m| m.len()).unwrap_or(0) > 0 {
        return Some(direct);
    }

    let stem = dmp.file_stem().and_then(OsStr::to_str)?;
    let parent = dmp.parent()?;
    let mut prefixed = parent.to_path_buf();
    prefixed.push(format!("{stem}.dmp.txt"));
    if prefixed.is_file() && fs::metadata(&prefixed).map(|m| m.len()).unwrap_or(0) > 0 {
        return Some(prefixed);
    }
    None
}

#[derive(Clone, Copy)]
struct FastDmpChunkPlan {
    idx: usize,
    read_start: u64,
    read_end: u64,
    emit_start: u64,
    emit_end: u64,
}

fn should_use_builtin_fast_parallel_chunks(dmp: &Path) -> bool {
    let Ok(meta) = fs::metadata(dmp) else {
        return false;
    };
    if meta.len() < BUILTIN_FAST_DMP_PARALLEL_MIN_BYTES {
        return false;
    }
    thread::available_parallelism()
        .map(|n| n.get() >= 4)
        .unwrap_or(false)
}

fn plan_builtin_fast_chunks(file_len: u64) -> Vec<FastDmpChunkPlan> {
    if file_len == 0 {
        return Vec::new();
    }
    let overlap = BUILTIN_FAST_DMP_PARALLEL_OVERLAP_BYTES as u64;
    let chunk = BUILTIN_FAST_DMP_PARALLEL_CHUNK_BYTES as u64;
    let mut out = Vec::new();
    let mut emit_start = 0u64;
    let mut idx = 0usize;
    while emit_start < file_len {
        let emit_end = (emit_start + chunk).min(file_len);
        let read_start = emit_start.saturating_sub(overlap);
        let read_end = (emit_end + overlap).min(file_len);
        out.push(FastDmpChunkPlan {
            idx,
            read_start,
            read_end,
            emit_start,
            emit_end,
        });
        emit_start = emit_end;
        idx += 1;
    }
    out
}

fn choose_builtin_fast_single_file_workers(file_size: u64, chunk_count: usize) -> usize {
    if chunk_count <= 1 {
        return 1;
    }
    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    if let Some(env_workers) = env::var("RSS_ANALYS_DMP_FAST_WORKERS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
    {
        return env_workers.min(chunk_count).min(cpu_budget).max(1);
    }

    // Keep worker count conservative for one-file scan to avoid random-read thrash on HDDs.
    let mut workers = cpu_budget.min(chunk_count).min(6).max(1);
    if file_size <= 2 * 1024 * 1024 * 1024 {
        workers = workers.min(3);
    } else if file_size <= 6 * 1024 * 1024 * 1024 {
        workers = workers.min(4);
    } else if file_size <= 12 * 1024 * 1024 * 1024 {
        workers = workers.min(5);
    }
    workers.max(1)
}

fn run_builtin_strings_fast_only_parallel_chunks(
    dmp: &Path,
    fast_txt: &Path,
    timeout: Duration,
    fast_needle_matcher: &FastNeedleMatcher,
) -> io::Result<BuiltinStringsRunStats> {
    let file_len = fs::metadata(dmp)?.len();
    let plans = plan_builtin_fast_chunks(file_len);
    if plans.len() <= 1 {
        return run_builtin_strings_to_txt_with_timeout(
            dmp,
            fast_txt,
            timeout,
            Some(BuiltinFastFilterCfg {
                output: fast_txt,
                fast_needle_matcher,
            }),
            false,
        );
    }

    let workers = choose_builtin_fast_single_file_workers(file_len, plans.len());
    if workers <= 1 {
        return run_builtin_strings_to_txt_with_timeout(
            dmp,
            fast_txt,
            timeout,
            Some(BuiltinFastFilterCfg {
                output: fast_txt,
                fast_needle_matcher,
            }),
            false,
        );
    }
    log_info(&format!(
        "{}: {}",
        tr_ui("Параллельные fast-потоки DMP", "Parallel DMP fast workers"),
        workers
    ));

    let parts_dir = fast_txt.with_extension("parts");
    let _ = fs::remove_dir_all(&parts_dir);
    fs::create_dir_all(&parts_dir)?;

    let timeout_hit = AtomicBool::new(false);
    let started = Instant::now();
    let mut worker_error: Option<io::Error> = None;

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        let mut senders = Vec::with_capacity(workers);
        for _ in 0..workers {
            let parts_dir_ref = &parts_dir;
            let timeout_hit_ref = &timeout_hit;
            let (tx, rx) = mpsc::sync_channel::<Option<(FastDmpChunkPlan, Vec<u8>)>>(1);
            senders.push(tx);
            handles.push(scope.spawn(move || -> io::Result<()> {
                while let Ok(task) = rx.recv() {
                    if timeout_hit_ref.load(Ordering::Relaxed) {
                        break;
                    }
                    let Some((plan, buf)) = task else {
                        break;
                    };
                    let part_path = parts_dir_ref.join(format!("{:06}.part", plan.idx));
                    let mut fast_writer =
                        BuiltinFastFilterWriter::new(&part_path, fast_needle_matcher)?;
                    scan_builtin_fast_chunk(
                        &buf,
                        plan.read_start,
                        plan.emit_start,
                        plan.emit_end,
                        &mut fast_writer,
                        started,
                        timeout,
                        timeout_hit_ref,
                    )?;
                    let kept = fast_writer.finish()?;
                    if kept == 0 {
                        let _ = fs::remove_file(part_path);
                    }
                }
                Ok(())
            }));
        }

        let reader_res: io::Result<()> = (|| {
            let mut file = File::open(dmp)?;
            for (dispatch_idx, plan) in plans.iter().copied().enumerate() {
                if timeout_hit.load(Ordering::Relaxed) {
                    break;
                }
                if started.elapsed() >= timeout {
                    timeout_hit.store(true, Ordering::Relaxed);
                    break;
                }
                let read_len_u64 = plan.read_end.saturating_sub(plan.read_start);
                if read_len_u64 == 0 {
                    continue;
                }
                let Ok(read_len) = usize::try_from(read_len_u64) else {
                    continue;
                };
                file.seek(std::io::SeekFrom::Start(plan.read_start))?;
                let mut buf = vec![0u8; read_len];
                file.read_exact(&mut buf)?;
                let tx = &senders[dispatch_idx % workers];
                tx.send(Some((plan, buf)))
                    .map_err(|_| io::Error::other("parallel fast worker disconnected"))?;
            }
            Ok(())
        })();

        if let Err(e) = reader_res {
            timeout_hit.store(true, Ordering::Relaxed);
            if worker_error.is_none() {
                worker_error = Some(e);
            }
        }
        for tx in senders {
            let _ = tx.send(None);
        }

        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if worker_error.is_none() {
                        worker_error = Some(e);
                    }
                }
                Err(_) => {
                    if worker_error.is_none() {
                        worker_error = Some(io::Error::other("parallel fast scan worker panicked"));
                    }
                }
            }
        }
    });

    if let Some(err) = worker_error {
        let _ = fs::remove_dir_all(&parts_dir);
        let _ = fs::remove_file(fast_txt);
        return Err(err);
    }
    if timeout_hit.load(Ordering::Relaxed) {
        let _ = fs::remove_dir_all(&parts_dir);
        let _ = fs::remove_file(fast_txt);
        return Ok(BuiltinStringsRunStats {
            ok: false,
            fast_kept: 0,
        });
    }

    if let Some(parent) = fast_txt.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = BufWriter::with_capacity(IO_STREAM_BUFFER_BYTES, File::create(fast_txt)?);
    let mut last_line = String::new();
    let mut stitch = LogicalLineAssembler::default();
    let mut total_kept = 0usize;
    for plan in &plans {
        let part_path = parts_dir.join(format!("{:06}.part", plan.idx));
        if !part_path.exists() {
            continue;
        }
        let f = File::open(&part_path)?;
        let reader = BufReader::with_capacity(IO_STREAM_BUFFER_BYTES, f);
        for raw in reader.lines() {
            let line = raw?;
            let (line1, line2) = stitch.push_fragment(&line);
            for joined in [line1, line2].into_iter().flatten() {
                let trimmed = joined.trim();
                if trimmed.is_empty() || trimmed.eq_ignore_ascii_case(&last_line) {
                    continue;
                }
                writeln!(out, "{trimmed}")?;
                last_line.clear();
                last_line.push_str(trimmed);
                total_kept += 1;
            }
        }
        let _ = fs::remove_file(part_path);
    }
    if let Some(tail) = stitch.finish() {
        let trimmed = tail.trim();
        if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case(&last_line) {
            writeln!(out, "{trimmed}")?;
            total_kept += 1;
        }
    }
    out.flush()?;
    let _ = fs::remove_dir_all(&parts_dir);
    if total_kept == 0 {
        let _ = fs::remove_file(fast_txt);
    }
    Ok(BuiltinStringsRunStats {
        ok: true,
        fast_kept: total_kept,
    })
}

fn scan_builtin_fast_chunk(
    bytes: &[u8],
    abs_start: u64,
    emit_start: u64,
    emit_end: u64,
    fast_writer: &mut BuiltinFastFilterWriter<'_>,
    started: Instant,
    timeout: Duration,
    timeout_hit: &AtomicBool,
) -> io::Result<()> {
    const GUARD_CHECK_STEP: usize = 1024 * 1024;
    let mut ascii_run = Vec::with_capacity(128);
    let mut ascii_start_abs = 0u64;

    let mut utf16_run = Vec::with_capacity(128);
    let mut utf16_start_abs = 0u64;
    let mut utf16_pending_hi: Option<(u8, u64)> = None;
    let mut next_guard_check = 0usize;

    for (i, &b) in bytes.iter().enumerate() {
        if i >= next_guard_check {
            next_guard_check = next_guard_check.saturating_add(GUARD_CHECK_STEP);
            if timeout_hit.load(Ordering::Relaxed) {
                return Ok(());
            }
            if started.elapsed() >= timeout {
                timeout_hit.store(true, Ordering::Relaxed);
                return Ok(());
            }
        }
        let abs = abs_start + i as u64;

        if is_builtin_strings_printable_ascii(b) {
            if ascii_run.is_empty() {
                ascii_start_abs = abs;
            }
            ascii_run.push(b);
        } else {
            emit_builtin_fast_run(
                &ascii_run,
                ascii_start_abs,
                emit_start,
                emit_end,
                fast_writer,
            )?;
            ascii_run.clear();
        }

        match utf16_pending_hi.take() {
            Some((hi, hi_abs)) => {
                if b == 0 && is_builtin_strings_printable_ascii(hi) {
                    if utf16_run.is_empty() {
                        utf16_start_abs = hi_abs;
                    }
                    utf16_run.push(hi);
                } else {
                    emit_builtin_fast_run(
                        &utf16_run,
                        utf16_start_abs,
                        emit_start,
                        emit_end,
                        fast_writer,
                    )?;
                    utf16_run.clear();
                    if is_builtin_strings_printable_ascii(b) {
                        utf16_pending_hi = Some((b, abs));
                    }
                }
            }
            None => {
                if is_builtin_strings_printable_ascii(b) {
                    utf16_pending_hi = Some((b, abs));
                } else {
                    emit_builtin_fast_run(
                        &utf16_run,
                        utf16_start_abs,
                        emit_start,
                        emit_end,
                        fast_writer,
                    )?;
                    utf16_run.clear();
                }
            }
        }
    }

    emit_builtin_fast_run(
        &ascii_run,
        ascii_start_abs,
        emit_start,
        emit_end,
        fast_writer,
    )?;
    emit_builtin_fast_run(
        &utf16_run,
        utf16_start_abs,
        emit_start,
        emit_end,
        fast_writer,
    )?;
    Ok(())
}

fn emit_builtin_fast_run(
    run: &[u8],
    start_abs: u64,
    emit_start: u64,
    emit_end: u64,
    fast_writer: &mut BuiltinFastFilterWriter<'_>,
) -> io::Result<()> {
    if run.len() < BUILTIN_STRINGS_MIN_LEN {
        return Ok(());
    }
    let run_end = start_abs.saturating_add(run.len() as u64);
    if run_end <= emit_start || start_abs >= emit_end {
        return Ok(());
    }
    fast_writer.push_extracted_run(run)
}

fn choose_dmp_convert_workers(file_count: usize) -> usize {
    if file_count == 0 {
        return 1;
    }
    if file_count == 1 {
        return 1;
    }
    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    cpu.clamp(1, 6).min(file_count).min(cpu_budget).max(1)
}

struct BuiltinFastFilterCfg<'a> {
    output: &'a Path,
    fast_needle_matcher: &'a FastNeedleMatcher,
}

#[derive(Clone, Copy, Default)]
struct BuiltinStringsRunStats {
    ok: bool,
    fast_kept: usize,
}

fn run_builtin_strings_to_txt_with_timeout(
    dmp: &Path,
    txt: &Path,
    timeout: Duration,
    fast_filter: Option<BuiltinFastFilterCfg<'_>>,
    write_full_output: bool,
) -> io::Result<BuiltinStringsRunStats> {
    if should_use_builtin_parallel_inmem(dmp) {
        return run_builtin_strings_to_txt_in_memory(
            dmp,
            txt,
            timeout,
            fast_filter,
            write_full_output,
        );
    }
    run_builtin_strings_to_txt_streaming(dmp, txt, timeout, fast_filter, write_full_output)
}

fn run_builtin_strings_to_txt_streaming(
    dmp: &Path,
    txt: &Path,
    timeout: Duration,
    fast_filter: Option<BuiltinFastFilterCfg<'_>>,
    write_full_output: bool,
) -> io::Result<BuiltinStringsRunStats> {
    if write_full_output && let Some(parent) = txt.parent() {
        fs::create_dir_all(parent)?;
    }
    let (mut fast_writer, fast_output_path) = if let Some(cfg) = fast_filter {
        (
            Some(BuiltinFastFilterWriter::new(
                cfg.output,
                cfg.fast_needle_matcher,
            )?),
            Some(cfg.output.to_path_buf()),
        )
    } else {
        (None, None)
    };
    let mut reader = BufReader::with_capacity(BUILTIN_STRINGS_READ_BUFFER, File::open(dmp)?);
    let mut writer = if write_full_output {
        Some(BufWriter::with_capacity(
            IO_STREAM_BUFFER_BYTES,
            File::create(txt)?,
        ))
    } else {
        None
    };
    let mut buf = vec![0u8; BUILTIN_STRINGS_READ_CHUNK];
    let mut state = BuiltinStringsState::default();

    let started = Instant::now();
    let mut last_heartbeat = Instant::now();
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        for &b in &buf[..read] {
            state.push_byte(b, BUILTIN_STRINGS_MIN_LEN, &mut writer, &mut fast_writer)?;
        }

        let elapsed = started.elapsed();
        if elapsed >= timeout {
            if let Some(w) = writer.as_mut() {
                let _ = w.flush();
            }
            if let Some(filter_writer) = fast_writer.as_mut() {
                let _ = filter_writer.flush_partial();
            }
            return Ok(BuiltinStringsRunStats {
                ok: false,
                fast_kept: 0,
            });
        }
        if last_heartbeat.elapsed() >= Duration::from_secs(DMP_STRINGS_HEARTBEAT_SECS) {
            log_info(&format!(
                "{}: {} {} ({}).",
                tr_ui(
                    "встроенный strings-движок еще работает",
                    "built-in strings engine is still running"
                ),
                elapsed.as_secs(),
                tr_ui("сек", "sec"),
                dmp.display()
            ));
            last_heartbeat = Instant::now();
        }
    }

    state.finish(BUILTIN_STRINGS_MIN_LEN, &mut writer, &mut fast_writer)?;
    if let Some(w) = writer.as_mut() {
        w.flush()?;
    }
    let fast_kept = if let Some(mut filter_writer) = fast_writer {
        filter_writer.finish()?
    } else {
        0
    };
    if fast_kept == 0
        && let Some(path) = fast_output_path
    {
        let _ = fs::remove_file(path);
    }
    Ok(BuiltinStringsRunStats {
        ok: true,
        fast_kept,
    })
}

fn should_use_builtin_parallel_inmem(dmp: &Path) -> bool {
    let Ok(meta) = fs::metadata(dmp) else {
        return false;
    };
    let size = meta.len();
    if !(BUILTIN_STRINGS_INMEM_MIN_BYTES..=BUILTIN_STRINGS_INMEM_MAX_BYTES).contains(&size) {
        return false;
    }
    thread::available_parallelism()
        .map(|n| n.get() > 1)
        .unwrap_or(false)
}

#[derive(Clone)]
struct BuiltinInMemRow {
    start: usize,
    kind: u8,
    bytes: Vec<u8>,
}

fn run_builtin_strings_to_txt_in_memory(
    dmp: &Path,
    txt: &Path,
    timeout: Duration,
    fast_filter: Option<BuiltinFastFilterCfg<'_>>,
    write_full_output: bool,
) -> io::Result<BuiltinStringsRunStats> {
    if write_full_output && let Some(parent) = txt.parent() {
        fs::create_dir_all(parent)?;
    }
    let (mut fast_writer, fast_output_path) = if let Some(cfg) = fast_filter {
        (
            Some(BuiltinFastFilterWriter::new(
                cfg.output,
                cfg.fast_needle_matcher,
            )?),
            Some(cfg.output.to_path_buf()),
        )
    } else {
        (None, None)
    };

    let started = Instant::now();
    let bytes = fs::read(dmp)?;
    if started.elapsed() >= timeout {
        if let Some(filter_writer) = fast_writer.as_mut() {
            let _ = filter_writer.flush_partial();
        }
        return Ok(BuiltinStringsRunStats {
            ok: false,
            fast_kept: 0,
        });
    }

    let (ascii_rows, utf16_rows) = thread::scope(|scope| {
        let ascii_h = scope.spawn(|| collect_builtin_ascii_rows(&bytes, BUILTIN_STRINGS_MIN_LEN));
        let utf16_h = scope.spawn(|| collect_builtin_utf16_rows(&bytes, BUILTIN_STRINGS_MIN_LEN));
        (
            ascii_h.join().unwrap_or_default(),
            utf16_h.join().unwrap_or_default(),
        )
    });

    let mut rows = ascii_rows;
    rows.extend(utf16_rows);
    rows.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.kind.cmp(&b.kind)));

    let mut writer = if write_full_output {
        Some(BufWriter::with_capacity(
            IO_STREAM_BUFFER_BYTES,
            File::create(txt)?,
        ))
    } else {
        None
    };
    for (idx, row) in rows.into_iter().enumerate() {
        if let Some(w) = writer.as_mut() {
            w.write_all(&row.bytes)?;
            w.write_all(b"\n")?;
        }
        if let Some(filter_writer) = fast_writer.as_mut() {
            filter_writer.push_extracted_run(&row.bytes)?;
        }
        if idx % 2048 == 0 && started.elapsed() >= timeout {
            if let Some(w) = writer.as_mut() {
                let _ = w.flush();
            }
            if let Some(filter_writer) = fast_writer.as_mut() {
                let _ = filter_writer.flush_partial();
            }
            return Ok(BuiltinStringsRunStats {
                ok: false,
                fast_kept: 0,
            });
        }
    }

    if let Some(w) = writer.as_mut() {
        w.flush()?;
    }
    let fast_kept = if let Some(mut filter_writer) = fast_writer {
        filter_writer.finish()?
    } else {
        0
    };
    if fast_kept == 0
        && let Some(path) = fast_output_path
    {
        let _ = fs::remove_file(path);
    }
    Ok(BuiltinStringsRunStats {
        ok: true,
        fast_kept,
    })
}

fn collect_builtin_ascii_rows(bytes: &[u8], min_len: usize) -> Vec<BuiltinInMemRow> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && !is_builtin_strings_printable_ascii(bytes[i]) {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_builtin_strings_printable_ascii(bytes[i]) {
            i += 1;
        }
        if i.saturating_sub(start) >= min_len {
            out.push(BuiltinInMemRow {
                start,
                kind: 0,
                bytes: bytes[start..i].to_vec(),
            });
        }
    }
    out
}

fn collect_builtin_utf16_rows(bytes: &[u8], min_len: usize) -> Vec<BuiltinInMemRow> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if is_builtin_strings_printable_ascii(bytes[i]) && bytes[i + 1] == 0 {
            let start = i;
            let mut run = Vec::with_capacity(128);
            while i + 1 < bytes.len()
                && is_builtin_strings_printable_ascii(bytes[i])
                && bytes[i + 1] == 0
            {
                run.push(bytes[i]);
                i += 2;
            }
            if run.len() >= min_len {
                out.push(BuiltinInMemRow {
                    start,
                    kind: 1,
                    bytes: run,
                });
            }
            continue;
        }
        i += 1;
    }
    out
}

#[derive(Default)]
struct BuiltinStringsState {
    ascii_run: Vec<u8>,
    utf16_run: Vec<u8>,
    utf16_pending_hi: Option<u8>,
}

impl BuiltinStringsState {
    #[inline(always)]
    fn push_byte(
        &mut self,
        b: u8,
        min_len: usize,
        writer: &mut Option<BufWriter<File>>,
        fast_writer: &mut Option<BuiltinFastFilterWriter<'_>>,
    ) -> io::Result<()> {
        if is_builtin_strings_printable_ascii(b) {
            self.ascii_run.push(b);
        } else {
            self.flush_ascii(min_len, writer, fast_writer)?;
        }

        match self.utf16_pending_hi.take() {
            Some(hi) => {
                if b == 0 && is_builtin_strings_printable_ascii(hi) {
                    self.utf16_run.push(hi);
                } else {
                    self.flush_utf16(min_len, writer, fast_writer)?;
                    if is_builtin_strings_printable_ascii(b) {
                        self.utf16_pending_hi = Some(b);
                    }
                }
            }
            None => {
                if is_builtin_strings_printable_ascii(b) {
                    self.utf16_pending_hi = Some(b);
                } else {
                    self.flush_utf16(min_len, writer, fast_writer)?;
                }
            }
        }

        Ok(())
    }

    fn finish(
        &mut self,
        min_len: usize,
        writer: &mut Option<BufWriter<File>>,
        fast_writer: &mut Option<BuiltinFastFilterWriter<'_>>,
    ) -> io::Result<()> {
        self.utf16_pending_hi = None;
        self.flush_ascii(min_len, writer, fast_writer)?;
        self.flush_utf16(min_len, writer, fast_writer)?;
        Ok(())
    }

    fn flush_ascii(
        &mut self,
        min_len: usize,
        writer: &mut Option<BufWriter<File>>,
        fast_writer: &mut Option<BuiltinFastFilterWriter<'_>>,
    ) -> io::Result<()> {
        emit_builtin_strings_run(&self.ascii_run, min_len, writer, fast_writer)?;
        self.ascii_run.clear();
        Ok(())
    }

    fn flush_utf16(
        &mut self,
        min_len: usize,
        writer: &mut Option<BufWriter<File>>,
        fast_writer: &mut Option<BuiltinFastFilterWriter<'_>>,
    ) -> io::Result<()> {
        emit_builtin_strings_run(&self.utf16_run, min_len, writer, fast_writer)?;
        self.utf16_run.clear();
        Ok(())
    }
}

fn emit_builtin_strings_run(
    run: &[u8],
    min_len: usize,
    writer: &mut Option<BufWriter<File>>,
    fast_writer: &mut Option<BuiltinFastFilterWriter<'_>>,
) -> io::Result<()> {
    if run.len() < min_len {
        return Ok(());
    }
    if let Some(w) = writer.as_mut() {
        w.write_all(run)?;
        w.write_all(b"\n")?;
    }
    if let Some(filter_writer) = fast_writer.as_mut() {
        filter_writer.push_extracted_run(run)?;
    }
    Ok(())
}

struct BuiltinFastFilterWriter<'a> {
    writer: BufWriter<File>,
    fast_needle_matcher: &'a FastNeedleMatcher,
    last_line: String,
    assembler: LogicalLineAssembler,
    kept: usize,
}

impl<'a> BuiltinFastFilterWriter<'a> {
    fn new(path: &Path, fast_needle_matcher: &'a FastNeedleMatcher) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self {
            writer: BufWriter::with_capacity(IO_STREAM_BUFFER_BYTES, File::create(path)?),
            fast_needle_matcher,
            last_line: String::new(),
            assembler: LogicalLineAssembler::default(),
            kept: 0,
        })
    }

    fn push_fragment(&mut self, fragment: &str) -> io::Result<()> {
        let (line1, line2) = self.assembler.push_fragment(fragment);
        if let Some(line) = line1
            && write_if_relevant_line(
                &mut self.writer,
                &line,
                &mut self.last_line,
                self.fast_needle_matcher,
            )?
        {
            self.kept += 1;
        }
        if let Some(line) = line2
            && write_if_relevant_line(
                &mut self.writer,
                &line,
                &mut self.last_line,
                self.fast_needle_matcher,
            )?
        {
            self.kept += 1;
        }
        Ok(())
    }

    fn push_extracted_run(&mut self, run: &[u8]) -> io::Result<()> {
        if run.is_empty() {
            return Ok(());
        }
        // SAFETY: run is built only from printable ASCII bytes (0x20..0x7e).
        let fragment = unsafe { std::str::from_utf8_unchecked(run) };
        self.push_fragment(fragment)
    }

    fn finish(&mut self) -> io::Result<usize> {
        if let Some(line) = self.assembler.finish()
            && write_if_relevant_line(
                &mut self.writer,
                &line,
                &mut self.last_line,
                self.fast_needle_matcher,
            )?
        {
            self.kept += 1;
        }
        self.writer.flush()?;
        Ok(self.kept)
    }

    fn flush_partial(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[inline(always)]
fn is_builtin_strings_printable_ascii(b: u8) -> bool {
    b >= 0x20 && b <= 0x7e
}

fn prepare_inputs_for_analysis(
    inputs: &[PathBuf],
    out_dir: &Path,
    lang: UiLang,
    fast_needle_matcher: &FastNeedleMatcher,
    prebuilt_fast_inputs: &HashMap<PathBuf, PathBuf>,
    use_fast_prepare: bool,
) -> io::Result<Vec<PreparedInput>> {
    fs::create_dir_all(out_dir)?;
    if inputs.is_empty() {
        return Ok(Vec::new());
    }

    let worker_count = choose_fast_prepare_workers(inputs.len());
    let prepared_rows = if worker_count <= 1 || inputs.len() < 8 {
        let mut rows = Vec::with_capacity(inputs.len());
        for (idx, source) in inputs.iter().enumerate() {
            let prebuilt_scan = prebuilt_fast_inputs.get(source).map(PathBuf::as_path);
            rows.push(prepare_single_input_for_analysis(
                idx,
                source,
                out_dir,
                fast_needle_matcher,
                prebuilt_scan,
                use_fast_prepare,
            ));
        }
        rows
    } else {
        log_info(&format!(
            "{}: {}",
            tr(lang, "Потоки подготовки входов", "Input prepare workers"),
            worker_count
        ));
        let cursor = AtomicUsize::new(0);
        let rows = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let cursor_ref = &cursor;
                handles.push(scope.spawn(move || {
                    let mut local = Vec::new();
                    loop {
                        let idx = cursor_ref.fetch_add(1, Ordering::Relaxed);
                        if idx >= inputs.len() {
                            break;
                        }
                        let source = &inputs[idx];
                        let prebuilt_scan = prebuilt_fast_inputs.get(source).map(PathBuf::as_path);
                        local.push(prepare_single_input_for_analysis(
                            idx,
                            source,
                            out_dir,
                            fast_needle_matcher,
                            prebuilt_scan,
                            use_fast_prepare,
                        ));
                    }
                    local
                }));
            }

            let mut all = Vec::with_capacity(inputs.len());
            for handle in handles {
                let mut part = handle.join().unwrap_or_default();
                all.append(&mut part);
            }
            all
        });
        rows
    };

    let mut prepared_count = 0usize;
    let mut fallback_count = 0usize;
    let mut sorted = prepared_rows;
    sorted.sort_unstable_by_key(|x| x.idx);
    let mut out = Vec::with_capacity(sorted.len());
    for row in sorted {
        if row.prepared {
            prepared_count += 1;
        }
        if row.fallback {
            fallback_count += 1;
        }
        out.push(row.input);
    }

    log_info(&format!(
        "{}: {}, {}: {}",
        tr(lang, "Быстрых входов", "Fast prepared"),
        prepared_count,
        tr(lang, "fallback", "fallback"),
        fallback_count
    ));

    Ok(out)
}

struct PreparedInputRow {
    idx: usize,
    input: PreparedInput,
    prepared: bool,
    fallback: bool,
}

fn prepare_single_input_for_analysis(
    idx: usize,
    source: &Path,
    out_dir: &Path,
    fast_needle_matcher: &FastNeedleMatcher,
    prebuilt_scan: Option<&Path>,
    use_fast_prepare: bool,
) -> PreparedInputRow {
    let mut prepared = PreparedInput {
        source: source.to_path_buf(),
        scan: source.to_path_buf(),
        fast_prepared: false,
    };
    if !source.is_file() {
        return PreparedInputRow {
            idx,
            input: prepared,
            prepared: false,
            fallback: false,
        };
    }

    let cache_stem = cache_safe_stem(source, idx);
    let filtered_txt = out_dir.join(format!("{idx:04}_{cache_stem}.txt"));

    if source
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|e| e.eq_ignore_ascii_case("txt"))
    {
        if !use_fast_prepare {
            return PreparedInputRow {
                idx,
                input: prepared,
                prepared: true,
                fallback: false,
            };
        }
        if source
            .parent()
            .is_some_and(|p| normalize_cmp_path(p.to_string_lossy().as_ref())
                == normalize_cmp_path(out_dir.to_string_lossy().as_ref()))
        {
            prepared.scan = source.to_path_buf();
            prepared.fast_prepared = true;
            return PreparedInputRow {
                idx,
                input: prepared,
                prepared: true,
                fallback: false,
            };
        }
        if let Some(scan_path) = prebuilt_scan {
            let scan_len = fs::metadata(scan_path).map(|m| m.len()).unwrap_or(0);
            if scan_len > 0 {
                prepared.scan = scan_path.to_path_buf();
                prepared.fast_prepared = true;
                return PreparedInputRow {
                    idx,
                    input: prepared,
                    prepared: true,
                    fallback: false,
                };
            }
        }
        let kept =
            extract_relevant_lines_to_file(source, &filtered_txt, fast_needle_matcher).unwrap_or(0);
        if kept > 0 {
            prepared.scan = filtered_txt;
            prepared.fast_prepared = true;
            return PreparedInputRow {
                idx,
                input: prepared,
                prepared: true,
                fallback: false,
            };
        }
        let _ = fs::remove_file(&filtered_txt);
        return PreparedInputRow {
            idx,
            input: prepared,
            prepared: false,
            fallback: true,
        };
    }

    let raw_txt = out_dir.join(format!("{idx:04}_{cache_stem}.strings.txt"));
    let converted = if use_fast_prepare {
        run_builtin_strings_to_txt_with_timeout(
            source,
            &raw_txt,
            Duration::from_secs(FAST_INPUT_STRINGS_TIMEOUT_SECS),
            Some(BuiltinFastFilterCfg {
                output: &filtered_txt,
                fast_needle_matcher,
            }),
            true,
        )
        .unwrap_or_default()
    } else {
        run_builtin_strings_to_txt_with_timeout(
            source,
            &raw_txt,
            Duration::from_secs(FAST_INPUT_STRINGS_TIMEOUT_SECS),
            None,
            true,
        )
        .unwrap_or_default()
    };
    if !converted.ok {
        let _ = fs::remove_file(&raw_txt);
        let _ = fs::remove_file(&filtered_txt);
        return PreparedInputRow {
            idx,
            input: prepared,
            prepared: false,
            fallback: true,
        };
    }

    let raw_len = fs::metadata(&raw_txt).map(|m| m.len()).unwrap_or(0);
    if raw_len == 0 {
        let _ = fs::remove_file(&raw_txt);
        return PreparedInputRow {
            idx,
            input: prepared,
            prepared: false,
            fallback: true,
        };
    }

    if use_fast_prepare && converted.fast_kept > 0 {
        prepared.scan = filtered_txt;
        prepared.fast_prepared = true;
        let _ = fs::remove_file(&raw_txt);
        return PreparedInputRow {
            idx,
            input: prepared,
            prepared: true,
            fallback: false,
        };
    }

    prepared.scan = raw_txt;
    let _ = fs::remove_file(&filtered_txt);
    PreparedInputRow {
        idx,
        input: prepared,
        prepared: true,
        fallback: false,
    }
}

fn choose_fast_prepare_workers(file_count: usize) -> usize {
    if file_count == 0 {
        return 1;
    }
    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    let mut workers = cpu.clamp(2, 12).min(cpu_budget);
    workers = workers.min(file_count.max(1));
    if file_count < 16 {
        workers = workers.min(8);
    }
    workers.min(cpu_budget).max(1)
}

fn cache_safe_stem(path: &Path, idx: usize) -> String {
    let mut stem = path
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("input")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    if stem.is_empty() {
        stem = format!("input_{idx}");
    }
    if stem.len() > 64 {
        stem.truncate(64);
    }
    stem
}

fn extract_relevant_lines_to_file(
    src: &Path,
    dst: &Path,
    fast_needle_matcher: &FastNeedleMatcher,
) -> io::Result<usize> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = BufWriter::with_capacity(IO_STREAM_BUFFER_BYTES, File::create(dst)?);
    let mut kept = 0usize;
    let mut last_line = String::new();
    let mut assembler = LogicalLineAssembler::default();

    let mut probe_file = File::open(src)?;
    let mut probe = vec![0u8; 64 * 1024];
    let n = probe_file.read(&mut probe)?;
    probe.truncate(n);

    if looks_utf16(&probe) {
        let mut f = File::open(src)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        let text = decode_utf16(&bytes);
        for frag in text.split(|c| c == '\n' || c == '\r' || c == '\0') {
            let (line1, line2) = assembler.push_fragment(frag);
            if let Some(line) = line1
                && write_if_relevant_line(&mut writer, &line, &mut last_line, fast_needle_matcher)?
            {
                kept += 1;
            }
            if let Some(line) = line2
                && write_if_relevant_line(&mut writer, &line, &mut last_line, fast_needle_matcher)?
            {
                kept += 1;
            }
        }
    } else {
        let f = File::open(src)?;
        let mut reader = BufReader::with_capacity(IO_STREAM_BUFFER_BYTES, f);
        let mut line = Vec::with_capacity(8192);
        loop {
            line.clear();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&line);
            let (line1, line2) = assembler.push_fragment(text.as_ref());
            if let Some(line) = line1
                && write_if_relevant_line(&mut writer, &line, &mut last_line, fast_needle_matcher)?
            {
                kept += 1;
            }
            if let Some(line) = line2
                && write_if_relevant_line(&mut writer, &line, &mut last_line, fast_needle_matcher)?
            {
                kept += 1;
            }
        }
    }

    if let Some(line) = assembler.finish()
        && write_if_relevant_line(&mut writer, &line, &mut last_line, fast_needle_matcher)?
    {
        kept += 1;
    }

    writer.flush()?;
    if kept == 0 {
        let _ = fs::remove_file(dst);
    }
    Ok(kept)
}

fn write_if_relevant_line(
    writer: &mut BufWriter<File>,
    raw: &str,
    last_line: &mut String,
    fast_needle_matcher: &FastNeedleMatcher,
) -> io::Result<bool> {
    let Some(line) = relevant_line_for_fast_analysis(raw, last_line, fast_needle_matcher) else {
        return Ok(false);
    };
    writeln!(writer, "{line}")?;
    last_line.clear();
    last_line.push_str(&line);
    Ok(true)
}

fn relevant_line_for_fast_analysis(
    raw: &str,
    last_line: &str,
    fast_needle_matcher: &FastNeedleMatcher,
) -> Option<String> {
    let raw = raw.trim();
    if raw.len() < 4 {
        return None;
    }
    if !quick_fast_analysis_gate_raw(raw) {
        return None;
    }
    let raw_lower = raw.to_ascii_lowercase();
    if !quick_fast_analysis_gate_lc(&raw_lower, fast_needle_matcher) {
        return None;
    }
    let line = clean_line_fast_prepared(raw)?;
    let lower = line.to_ascii_lowercase();
    if !should_keep_for_fast_analysis_line_lc(&line, &lower, fast_needle_matcher) {
        return None;
    }
    if line.len() > 4096 && !has_high_value_artifact_hint(&lower) {
        return None;
    }
    if line.eq_ignore_ascii_case(last_line) {
        return None;
    }
    Some(line)
}

fn clean_line_fast_prepared(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len().min(2048));
    let mut prev_space = true;
    for mut ch in raw.chars() {
        if ch != '\t' && ch.is_control() {
            ch = ' ';
        }
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
            continue;
        }
        out.push(ch);
        prev_space = false;
        if out.len() >= 4096 {
            break;
        }
    }
    let trimmed = out.trim();
    if trimmed.len() < 4 {
        return None;
    }
    Some(trimmed.to_string())
}

fn should_keep_for_fast_analysis_line(line: &str, fast_needle_matcher: &FastNeedleMatcher) -> bool {
    let lower = line.to_ascii_lowercase();
    should_keep_for_fast_analysis_line_lc(line, &lower, fast_needle_matcher)
}

fn quick_fast_analysis_gate_raw(raw: &str) -> bool {
    if raw.len() <= 220 {
        return true;
    }
    raw.bytes().any(|b| {
        matches!(
            b,
            b'\\'
                | b'/'
                | b':'
                | b'.'
                | b'='
                | b'_'
                | b'-'
                | b'?'
                | b'@'
                | b'%'
                | b'0'..=b'9'
        )
    })
}

fn quick_fast_analysis_gate_lc(lower: &str, fast_needle_matcher: &FastNeedleMatcher) -> bool {
    if fast_needle_matcher.has_match_in_lower(lower) {
        return true;
    }
    if has_high_value_artifact_hint(lower) {
        return true;
    }
    lower.contains("cmd")
        || lower.contains("powershell")
        || lower.contains("pwsh")
        || lower.contains("reg ")
        || lower.contains("wmic")
        || lower.contains("schtasks")
        || lower.contains("eventid=")
        || lower.contains("proxy")
        || lower.contains("rdp")
        || lower.contains("websocket")
        || lower.contains("inject")
        || lower.contains("hollow")
        || lower.contains("knowndlls")
        || lower.contains("silentprocessexit")
        || lower.contains("ifeo")
}

fn should_keep_for_fast_analysis_line_lc(
    line: &str,
    lower: &str,
    fast_needle_matcher: &FastNeedleMatcher,
) -> bool {
    if fast_needle_matcher.has_match_in_lower(lower) {
        return true;
    }
    if is_probable_embedded_source_noise(lower) && !has_high_value_artifact_hint(lower) {
        return false;
    }

    let has_shell = has_shell_launcher_lc(lower);
    let has_url = contains_url_scheme_lc(lower);
    let has_path = lower.contains(":\\")
        || lower.contains("\\\\")
        || lower.contains("\\device\\harddiskvolume")
        || lower.contains("\\??\\")
        || lower.contains("\\\\?\\");
    let has_ext = contains_tracked_extension_hint(lower);
    let has_susp_kw = SUSPICIOUS.iter().any(|k| lower.contains(k));
    let has_high_risk_kw = lower.contains("unknowncheats")
        || lower.contains("keyauth")
        || lower.contains("kdmapper")
        || lower.contains("manualmap")
        || lower.contains("inject")
        || lower.contains("hollow")
        || lower.contains("silentprocessexit")
        || lower.contains("ifeo")
        || lower.contains("appinit_dlls")
        || lower.contains("knowndlls");
    let has_shell_action = has_shell
        && (lower.contains(" delete ")
            || lower.contains(" add ")
            || lower.contains(" query ")
            || lower.contains(" create ")
            || lower.contains(" encodedcommand")
            || lower.contains(" -enc")
            || lower.contains(" /enc")
            || lower.contains(" frombase64string")
            || lower.contains(" writeprocessmemory")
            || lower.contains(" createremotethread")
            || lower.contains(" ntcreatethreadex")
            || lower.contains(" virtualprotect")
            || lower.contains(" shellcode"));

    if lower.contains("processstart,")
        || lower.contains("regkeydeletion")
        || lower.contains("replaceclean")
        || lower.contains("filelessexecution")
        || lower.contains("eventid=")
    {
        return true;
    }

    if has_url {
        return has_susp_kw
            || has_shell
            || lower.contains("invoke-webrequest")
            || lower.contains("invoke-restmethod")
            || lower.contains("download?key=")
            || lower.contains("downloadstring")
            || lower.contains("downloadfile")
            || lower.contains("webhook")
            || lower.contains("discord.gg/")
            || lower.contains("discord.com/")
            || lower.contains("unknowncheats");
    }

    if has_shell_action {
        return true;
    }

    if has_ext && (has_path || has_shell || has_susp_kw) {
        return true;
    }

    if has_path {
        if lower.contains("\\windows\\system32\\winevt\\logs\\")
            || lower.contains("\\prefetch\\")
            || lower.contains("\\appdata\\")
            || lower.contains("\\programdata\\")
            || lower.contains("\\users\\")
            || lower.contains("\\temp\\")
        {
            return true;
        }
        if lower.contains("\\program files") {
            return has_ext && (has_high_risk_kw || has_shell_action || lower.contains("\\temp\\"));
        }
        return has_ext || has_high_risk_kw || has_susp_kw;
    }

    if (lower.contains("www.") || has_link_like_suffix(lower))
        && line.len() <= 420
        && lower.split_whitespace().count() <= 20
    {
        return has_susp_kw;
    }

    if !has_shell {
        return false;
    }
    is_regdel_lc(line, lower)
        || is_replaceclean_lc(line, lower)
        || is_fileless_lc(lower)
        || is_dll_execution_lc(line, lower)
        || is_forfiles_wmic_lc(lower)
        || is_java_batch_lc(line, lower)
        || is_command_ioc_lc(line, lower)
}

fn has_high_value_artifact_hint(lower: &str) -> bool {
    contains_tracked_extension_hint(lower)
        || lower.contains(":\\")
        || lower.contains("\\\\")
        || lower.contains("\\device\\harddiskvolume")
        || lower.contains("\\??\\")
        || lower.contains("\\\\?\\")
        || lower.contains("processstart,")
        || lower.contains("regkeydeletion")
        || contains_url_scheme_lc(lower)
        || lower.contains("www.")
        || has_link_like_suffix(lower)
}

fn contains_tracked_extension_hint(lower: &str) -> bool {
    [".exe", ".dll", ".jar", ".bat", ".cmd", ".ps1", ".pf"]
        .iter()
        .any(|ext| lower.contains(ext))
}

fn has_link_like_suffix(lower: &str) -> bool {
    [
        ".com", ".net", ".org", ".ru", ".gg", ".io", ".me", ".xyz", ".top", ".site", ".store",
        ".cc", ".co", ".su", ".pw",
    ]
    .iter()
    .any(|sfx| lower.contains(sfx))
}

