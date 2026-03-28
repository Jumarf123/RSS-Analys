// Main pipeline orchestration: run flow, analyzer state machine, and high-level logging.

fn run(user_opts: &UserOptions) -> io::Result<()> {
    let ui_guard = RunUiGuard::start(user_opts.lang);
    let run_started = Instant::now();
    let mut run_live = RunLiveContext::default();
    log_step(tr(user_opts.lang, "Старт программы", "Program start"));
    run_live.note_stage("startup", "pipeline initialized");
    log_info(match user_opts.lang {
        UiLang::Ru => "Язык: RU",
        UiLang::En => "Language: EN",
    });
    log_info(if user_opts.sort_hash {
        "Sort Hash: yes"
    } else {
        "Sort Hash: no"
    });
    match &user_opts.process_scan_mode {
        ProcessScanMode::All => log_info("Process scan: all"),
        ProcessScanMode::None => log_info("Process scan: no"),
        ProcessScanMode::Custom(sel) => {
            let names = if sel.names.is_empty() {
                "-".to_string()
            } else {
                sel.names.iter().cloned().collect::<Vec<_>>().join(", ")
            };
            let pids = if sel.pids.is_empty() {
                "-".to_string()
            } else {
                sel.pids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            log_info(&format!(
                "Process scan: custom | names: {names} | pids: {pids}"
            ));
        }
    }
    log_info(if user_opts.memory_orbit_enabled {
        "Dump core engine: yes"
    } else {
        "Dump core engine: no"
    });
    log_info(&format!(
        "Analysis mode: {}",
        user_opts.analysis_mode.label()
    ));
    run_live.note_metric("options.sort_hash", usize::from(user_opts.sort_hash));
    run_live.note_metric("options.analysis_mode", user_opts.analysis_mode.metric_value());
    run_live.note_metric(
        "options.process_scan",
        usize::from(user_opts.process_scan_mode.enabled()),
    );
    run_live.note_metric(
        "options.dump_core",
        usize::from(user_opts.memory_orbit_enabled),
    );
    #[cfg(windows)]
    {
        let debug_priv = enable_debug_privilege();
        log_info(if debug_priv {
            tr(
                user_opts.lang,
                "SeDebugPrivilege: включен",
                "SeDebugPrivilege: enabled",
            )
        } else {
            tr(
                user_opts.lang,
                "SeDebugPrivilege: не удалось включить",
                "SeDebugPrivilege: failed to enable",
            )
        });
    }
    let exe = env::current_exe()?;
    let exe_dir = exe
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("no exe dir"))?;
    let cwd = env::current_dir()?;
    let results = {
        let preferred = cwd.join("Results");
        if fs::create_dir_all(&preferred).is_ok() {
            preferred
        } else {
            let fallback = exe_dir.join("Results");
            fs::create_dir_all(&fallback)?;
            fallback
        }
    };
    let custom_dir = results.join("custom");
    fs::create_dir_all(&custom_dir)?;
    let programscustom_dir = exe_dir.join("programscustom");
    fs::create_dir_all(&programscustom_dir)?;
    let tools = exe_dir.join("tools");
    fs::create_dir_all(&tools)?;

    log_step(tr(
        user_opts.lang,
        "[1/8] Подготовка встроенного strings-движка",
        "[1/8] Preparing built-in strings engine",
    ));
    run_live.note_stage("stage1", "built-in strings initialized");
    log_info(tr(
        user_opts.lang,
        "Встроенный strings-движок активен",
        "Built-in strings engine is active",
    ));
    let strings_dir = exe_dir.join("strings");
    let custom_rules = load_custom_rules(&strings_dir)?;
    let custom_needles = collect_custom_needles(&custom_rules);
    let fast_needle_matcher = FastNeedleMatcher::build(&custom_needles);

    let prep_started = Instant::now();
    log_step(tr(
        user_opts.lang,
        "[2/8] Поиск входных файлов",
        "[2/8] Searching input files",
    ));
    run_live.note_stage("stage2", "input discovery started");
    let (mut txt_inputs, mut dmp_sources) = discover_inputs(&exe_dir, &cwd)?;
    log_info(&format!(
        "{}: TXT={} DMP={}",
        tr(user_opts.lang, "Найдено входов", "Inputs found"),
        txt_inputs.len(),
        dmp_sources.len()
    ));

    if txt_inputs.is_empty() && dmp_sources.is_empty() {
        let p = read_user_path(tr(
            user_opts.lang,
            "Введите путь к .txt/.dmp или папке:",
            "Enter path to .txt/.dmp file or folder:",
        ))?;
        txt_inputs = collect_ext(&p, "txt")?;
        dmp_sources = collect_ext(&p, "dmp")?;
        sort_dedupe_paths(&mut txt_inputs);
        sort_dedupe_paths(&mut dmp_sources);
    }

    if txt_inputs.is_empty() && dmp_sources.is_empty() {
        return Err(io::Error::other("no .txt or .dmp files"));
    }
    run_live.note_metric("inputs.txt", txt_inputs.len());
    run_live.note_metric("inputs.dmp", dmp_sources.len());
    let parse_env_bool = |name: &str, default: bool| -> bool {
        env::var(name)
            .ok()
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                !matches!(v.as_str(), "0" | "false" | "no" | "off")
            })
            .unwrap_or(default)
    };
    let dump_fast_profile = if dmp_sources.is_empty() {
        false
    } else {
        parse_env_bool(
            "RSS_ANALYS_DUMP_FAST_PROFILE",
            user_opts.analysis_mode.dump_fast_profile_default(),
        )
    };
    let dmp_fast_convert = if dmp_sources.is_empty() {
        false
    } else {
        parse_env_bool(
            "RSS_ANALYS_DMP_FAST_CONVERT",
            user_opts.analysis_mode.dmp_fast_convert_default() && dump_fast_profile,
        )
    };
    let fast_prepare_inputs = parse_env_bool(
        "RSS_ANALYS_FAST_PREPARE_INPUTS",
        user_opts.analysis_mode.fast_prepare_inputs_default(),
    );
    let low_signal_pe_filter = parse_env_bool(
        "RSS_ANALYS_FAST_LOW_SIGNAL_PE_FILTER",
        user_opts.analysis_mode.low_signal_pe_filter_default() && dump_fast_profile,
    );
    let skip_normalpe_for_speed = parse_env_bool(
        "RSS_ANALYS_SKIP_NORMALPE_FOR_SPEED",
        user_opts.analysis_mode.skip_normalpe_for_speed_default() && dump_fast_profile,
    );
    if dump_fast_profile {
        log_info(tr(
            user_opts.lang,
            "Режим DMP-fast: ускоренный пост-анализ (можно отключить RSS_ANALYS_DUMP_FAST_PROFILE=0)",
            "DMP-fast profile: accelerated post-analysis (disable via RSS_ANALYS_DUMP_FAST_PROFILE=0)",
        ));
    } else {
        log_info(tr(
            user_opts.lang,
            "Режим DMP-fast отключен: выбран более полный анализ",
            "DMP-fast profile is disabled: fuller analysis mode is active",
        ));
    }
    if dmp_fast_convert {
        log_info(tr(
            user_opts.lang,
            "Режим DMP-fast-convert: сначала быстрый extraction (можно отключить RSS_ANALYS_DMP_FAST_CONVERT=0)",
            "DMP-fast-convert mode: fast extraction first (disable via RSS_ANALYS_DMP_FAST_CONVERT=0)",
        ));
    }
    if !fast_prepare_inputs {
        log_info(tr(
            user_opts.lang,
            "Подготовка fast-input отключена: используется полный проход по входам",
            "Fast input preparation is disabled: full input pass is used",
        ));
    }

    let prepared_inputs_dir = results.join("cache").join("fast_inputs");
    let mut prebuilt_fast_inputs: HashMap<PathBuf, PathBuf> = HashMap::new();
    let mut inputs = txt_inputs;
    if !dmp_sources.is_empty() {
        log_info(&format!(
            "{}: {}",
            tr(user_opts.lang, "DMP источники", "DMP sources"),
            dmp_sources.len()
        ));
        let (converted, converted_sources, fast_converted) = dmp_to_txt(
            &dmp_sources,
            &results.join("input_from_dmp"),
            &prepared_inputs_dir,
            &fast_needle_matcher,
            dmp_fast_convert,
        )?;
        log_info(&format!(
            "{}: {}",
            tr(
                user_opts.lang,
                "DMP -> TXT (converted/reused)",
                "DMP -> TXT (converted/reused)"
            ),
            converted.len()
        ));
        prebuilt_fast_inputs.extend(fast_converted);
        inputs.extend(converted);
        run_live.note_metric("inputs.dmp_converted", converted_sources.len());
        // Analyze raw DMP only when a specific file was not converted into TXT.
        let mut raw_fallback = 0usize;
        for dmp in &dmp_sources {
            if !converted_sources.contains(dmp) {
                inputs.push(dmp.clone());
                raw_fallback += 1;
            }
        }
        if raw_fallback > 0 {
            log_info(&format!(
                "{}: {}",
                tr(
                    user_opts.lang,
                    "DMP fallback (raw анализ без TXT)",
                    "DMP fallback (raw scan without TXT)"
                ),
                raw_fallback
            ));
        }
    }
    sort_dedupe_paths(&mut inputs);
    if inputs.is_empty() {
        return Err(io::Error::other("no analyzable inputs after preprocessing"));
    }
    let prepared_inputs = prepare_inputs_for_analysis(
        &inputs,
        &prepared_inputs_dir,
        user_opts.lang,
        &fast_needle_matcher,
        &prebuilt_fast_inputs,
        fast_prepare_inputs,
    )?;
    let prepared_cached = prepared_inputs
        .iter()
        .filter(|x| {
            normalize_cmp_path(x.scan.to_string_lossy().as_ref())
                != normalize_cmp_path(x.source.to_string_lossy().as_ref())
        })
        .count();
    if prepared_cached > 0 {
        log_info(&format!(
            "{}: {} / {}",
            tr(
                user_opts.lang,
                "Подготовлено быстрых входов",
                "Prepared fast inputs"
            ),
            prepared_cached,
            prepared_inputs.len()
        ));
    }
    run_live.note_metric("inputs.prepared", prepared_inputs.len());
    run_live.note_metric("inputs.prepared_cached", prepared_cached);
    run_live.note_metric("timing.preparation_ms", prep_started.elapsed().as_millis() as usize);
    run_live.note_stage(
        "stage2",
        &format!(
            "preparation finished: prepared={} cached={} dmp={}",
            prepared_inputs.len(),
            prepared_cached,
            dmp_sources.len()
        ),
    );
    log_info(&format!(
        "{}: {:.1}s",
        tr(user_opts.lang, "Время подготовки", "Preparation time"),
        prep_started.elapsed().as_secs_f64()
    ));

    let analyze_started = Instant::now();
    log_step(tr(
        user_opts.lang,
        "[3/8] Анализ содержимого",
        "[3/8] Content analysis",
    ));
    let mut a = analyze_prepared_inputs_parallel(&prepared_inputs, user_opts.lang)?;
    run_live.note_stage("stage3", "content analysis completed");
    log_info(tr(
        user_opts.lang,
        "Базовый анализ завершен",
        "Base analysis finished",
    ));

    log_step(tr(
        user_opts.lang,
        "[3a] Загрузка кастомных строк",
        "[3a] Loading custom strings",
    ));
    let mut custom_stats = CustomScanStats {
        rules_loaded: custom_rules.len(),
        ..Default::default()
    };
    if custom_rules.is_empty() {
        log_info(tr(
            user_opts.lang,
            "Кастомные правила не найдены (папка strings пуста или отсутствует)",
            "No custom rules found (strings folder is empty or missing)",
        ));
    } else {
        log_info(&format!(
            "{}: {}",
            tr(
                user_opts.lang,
                "Загружено кастомных правил",
                "Custom rules loaded"
            ),
            custom_rules.len()
        ));
    }

    let custom_matcher = CustomMatcher::build(&custom_rules);
    if let Some(matcher) = custom_matcher.as_ref() {
        if matcher.has_unscoped_rules {
            custom_stats.input_files_scanned = scan_files_for_custom_hits(
                &prepared_inputs,
                matcher,
                &mut custom_stats.hits_by_file,
            )?;
            log_info(&format!(
                "{}: {}",
                tr(
                    user_opts.lang,
                    "Кастомный скан входных файлов завершен",
                    "Custom input scan finished"
                ),
                custom_stats.input_files_scanned
            ));
        } else {
            log_info(tr(
                user_opts.lang,
                "Кастомный скан входных файлов пропущен (правила привязаны к процессам)",
                "Custom input scan skipped (rules are process-scoped)",
            ));
        }
    }

    if user_opts.process_scan_mode.enabled() {
        log_step(tr(
            user_opts.lang,
            "[3b] Сканирование памяти доступных процессов",
            "[3b] Scanning memory of accessible processes",
        ));
        let process_report = scan_accessible_processes(
            &programscustom_dir,
            custom_matcher.as_ref(),
            user_opts.process_scan_mode.filter(),
            &mut custom_stats.hits_by_file,
            &fast_needle_matcher,
        )?;
        custom_stats.process_scanned = process_report.process_scanned;
        custom_stats.process_skipped = process_report.process_skipped;
        custom_stats.process_dumps = process_report.process_dumps;
        let mut process_dump_inputs = process_report.dump_files.clone();
        sort_dedupe_paths(&mut process_dump_inputs);
        log_info(&format!(
            "{}: {}, {}: {}, {}: {}",
            tr(user_opts.lang, "Просканировано", "Scanned"),
            custom_stats.process_scanned,
            tr(user_opts.lang, "пропущено", "skipped"),
            custom_stats.process_skipped,
            tr(user_opts.lang, "дампов", "dumps"),
            custom_stats.process_dumps
        ));

        if !process_dump_inputs.is_empty() {
            log_step(tr(
                user_opts.lang,
                "[3c] Анализ дампов процессов",
                "[3c] Analyzing process dumps",
            ));
            log_info(&format!(
                "{}: {}",
                tr(
                    user_opts.lang,
                    "Дампов для анализа",
                    "Process dumps to analyze"
                ),
                process_dump_inputs.len()
            ));
            merge_analyzer(&mut a, process_report.process_analyzer);
        }
    }

    write_custom_outputs(&custom_dir, &custom_rules, &custom_stats)?;
    let custom_hits_lines = custom_hits_grouped_lines(&custom_stats.hits_by_file);
    run_live.note_metric("analysis.links", a.links.len());
    run_live.note_metric("analysis.ioc", a.ioc.len());
    run_live.note_metric("analysis.fileless", a.fileless.len());
    run_live.note_metric("analysis.dll_exec", a.dll.len());
    run_live.note_metric("analysis.beta_rows", a.beta.len());
    run_live.absorb_rows("ioc", &a.ioc, 120);
    run_live.absorb_rows("fileless", &a.fileless, 80);
    run_live.absorb_rows("dll_exec", &a.dll, 80);
    run_live.absorb_rows("beta", &a.beta, 80);
    run_live.note_metric("timing.analysis_ms", analyze_started.elapsed().as_millis() as usize);
    run_live.note_stage(
        "stage3",
        &format!("analysis summary: links={} ioc={}", a.links.len(), a.ioc.len()),
    );
    log_info(&format!(
        "{}: {:.1}s",
        tr(user_opts.lang, "Время анализа", "Analysis time"),
        analyze_started.elapsed().as_secs_f64()
    ));

    let resolve_started = Instant::now();
    log_step(tr(
        user_opts.lang,
        "[4/8] Формирование allpe из извлеченных EXE/DLL",
        "[4/8] Building allpe from extracted EXE/DLL",
    ));
    let mut extracted_full_pe = filter_items_by_ext(&a.full_paths, PE_ONLY_EXTS);
    let mut extracted_pathless_pe = filter_items_by_ext(&a.pathless, PE_ONLY_EXTS);
    let before_full_profile = extracted_full_pe.len();
    extracted_full_pe.retain(|p| !is_build_or_dependency_artifact_path_lc(&normalize_cmp_path(p)));
    let before_pathless_profile = extracted_pathless_pe.len();
    extracted_pathless_pe.retain(|p| !is_build_or_dependency_artifact_path_lc(&normalize_cmp_path(p)));
    let excluded_full_profile = before_full_profile.saturating_sub(extracted_full_pe.len());
    let excluded_pathless_profile =
        before_pathless_profile.saturating_sub(extracted_pathless_pe.len());
    if excluded_full_profile > 0 || excluded_pathless_profile > 0 {
        log_info(&format!(
            "{}: full={}, pathless={}",
            tr_ui("Отсечено build/dependency PE", "Build/dependency PE excluded"),
            excluded_full_profile,
            excluded_pathless_profile
        ));
    }
    if low_signal_pe_filter {
        let before_fast_full = extracted_full_pe.len();
        extracted_full_pe.retain(|p| should_scan_yara_target_screenshare(p));
        let before_fast_pathless = extracted_pathless_pe.len();
        extracted_pathless_pe.retain(|p| {
            has_high_signal_path_keyword_lc(&normalize_cmp_path(p))
                && !is_build_or_dependency_artifact_path_lc(&normalize_cmp_path(p))
        });
        let dropped_fast_full = before_fast_full.saturating_sub(extracted_full_pe.len());
        let dropped_fast_pathless = before_fast_pathless.saturating_sub(extracted_pathless_pe.len());
        if dropped_fast_full > 0 || dropped_fast_pathless > 0 {
            log_info(&format!(
                "{}: full={}, pathless={}",
                tr_ui(
                    "DMP-fast: отсечено low-signal PE",
                    "DMP-fast: low-signal PE excluded"
                ),
                dropped_fast_full,
                dropped_fast_pathless
            ));
        }
    }
    log_info(&format!(
        "{}: {}",
        tr(
            user_opts.lang,
            "Извлечено EXE/DLL с путями",
            "Extracted EXE/DLL with paths"
        ),
        extracted_full_pe.len()
    ));
    log_info(&format!(
        "{}: {}",
        tr(
            user_opts.lang,
            "Извлечено EXE/DLL без пути",
            "Extracted EXE/DLL without path"
        ),
        extracted_pathless_pe.len()
    ));

    let (java_full, java_names) = split_full_and_names(&a.java_paths, JAR_EXTS);
    let (scripts_full, scripts_names) = split_full_and_names(&a.scripts, SCRIPT_EXTS);
    let (start_full, start_names) = split_full_and_names(&a.start, START_EXTS);
    let (prefetch_full, prefetch_names) = split_full_and_names(&a.prefetch, PREFETCH_EXTS);
    let (dps_full, dps_names) = split_full_and_names_any(&a.dps_files);
    let prefetch_program_names =
        collect_prefetch_program_lookup_names(&prefetch_full, &prefetch_names);

    let mut lookup_names: HashSet<String> = HashSet::new();
    lookup_names.extend(extracted_pathless_pe.iter().cloned());
    lookup_names.extend(java_names.iter().cloned());
    lookup_names.extend(scripts_names.iter().cloned());
    lookup_names.extend(start_names.iter().cloned());
    lookup_names.extend(prefetch_names.iter().cloned());
    lookup_names.extend(dps_names.iter().cloned());
    lookup_names.extend(prefetch_program_names);
    extend_missing_full_path_names(&mut lookup_names, &extracted_full_pe);
    extend_missing_full_path_names(&mut lookup_names, &java_full);
    extend_missing_full_path_names(&mut lookup_names, &scripts_full);
    extend_missing_full_path_names(&mut lookup_names, &start_full);
    extend_missing_full_path_names(&mut lookup_names, &prefetch_full);
    extend_missing_full_path_names(&mut lookup_names, &dps_full);

    let mut resolve_full_inputs = BTreeSet::new();
    resolve_full_inputs.extend(extracted_full_pe.iter().cloned());
    resolve_full_inputs.extend(java_full.iter().cloned());
    resolve_full_inputs.extend(scripts_full.iter().cloned());
    resolve_full_inputs.extend(start_full.iter().cloned());
    resolve_full_inputs.extend(prefetch_full.iter().cloned());
    resolve_full_inputs.extend(dps_full.iter().cloned());
    let file_exists_cache = build_file_exists_cache(&resolve_full_inputs);
    let mut name_index = build_seed_name_index(&lookup_names, &resolve_full_inputs);
    let unresolved_lookup_names = lookup_names
        .iter()
        .filter(|name| !name_index.contains_key(*name))
        .cloned()
        .collect::<HashSet<_>>();
    let deep_lookup_mode_raw = env::var("RSS_ANALYS_DEEP_LOOKUP")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let deep_lookup_mode = if deep_lookup_mode_raw.is_empty() {
        if user_opts.analysis_mode.deep_lookup_force_default() {
            "force".to_string()
        } else {
            "auto".to_string()
        }
    } else {
        deep_lookup_mode_raw
    };
    let deep_forced = matches!(
        deep_lookup_mode.as_str(),
        "1" | "true" | "yes" | "on" | "force"
    );
    let deep_disabled = matches!(deep_lookup_mode.as_str(), "0" | "false" | "no" | "off");
    let deep_auto_disabled_for_large_dmp = !deep_forced
        && user_opts.analysis_mode.allow_large_dmp_deep_skip_default()
        && dmp_sources.iter().any(|p| {
            fs::metadata(p)
                .map(|m| m.len() >= 1024 * 1024 * 1024)
                .unwrap_or(false)
        });
    let deep_lookup_auto_limit = env::var("RSS_ANALYS_DEEP_LOOKUP_AUTO_MAX_NAMES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(256, 200_000))
        .unwrap_or(user_opts.analysis_mode.deep_lookup_auto_limit_default());
    let deep_lookup_hard_limit = env::var("RSS_ANALYS_DEEP_LOOKUP_HARD_MAX_NAMES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(512, 400_000))
        .unwrap_or(user_opts.analysis_mode.deep_lookup_hard_limit_default());
    let deep_lookup_names = if deep_forced {
        unresolved_lookup_names.clone()
    } else {
        select_deep_lookup_names_fast(&unresolved_lookup_names, deep_lookup_auto_limit)
    };
    let should_run_deep_lookup = !deep_disabled
        && !deep_auto_disabled_for_large_dmp
        && !deep_lookup_names.is_empty()
        && (deep_forced || deep_lookup_names.len() <= deep_lookup_hard_limit);

    log_info(&format!(
        "{}: {} / {}",
        tr_ui("Быстрый индекс имен", "Fast name index"),
        name_index.len(),
        lookup_names.len()
    ));
    log_info(&format!(
        "{}: {}",
        tr_ui("Не разрешено имен", "Unresolved names"),
        unresolved_lookup_names.len()
    ));
    log_info(&format!(
        "{}: {}",
        tr_ui("Режим deep lookup", "Deep lookup mode"),
        deep_lookup_mode
    ));
    if !deep_forced {
        log_info(&format!(
            "{}: {}",
            tr_ui(
                "Имен для глубокого поиска (быстрый режим)",
                "Names selected for deep lookup (fast mode)"
            ),
            deep_lookup_names.len()
        ));
    }

    if should_run_deep_lookup {
        let lookup_exts = collect_lookup_extensions(&deep_lookup_names);
        let deep_index = build_local_name_index(&deep_lookup_names, &lookup_exts);
        merge_hashset_name_index(&mut name_index, deep_index);
    } else if deep_disabled {
        log_info(tr_ui(
            "Глубокий поиск имен отключен (RSS_ANALYS_DEEP_LOOKUP=0)",
            "Deep name lookup disabled (RSS_ANALYS_DEEP_LOOKUP=0)",
        ));
    } else if deep_auto_disabled_for_large_dmp {
        log_info(tr_ui(
            "Глубокий поиск имен пропущен для большого DMP (включите RSS_ANALYS_DEEP_LOOKUP=1 при необходимости)",
            "Deep name lookup skipped for large DMP (set RSS_ANALYS_DEEP_LOOKUP=1 to force)",
        ));
    } else if deep_lookup_names.len() > deep_lookup_hard_limit && !deep_forced {
        log_info(&format!(
            "{}: {} > {}",
            tr_ui(
                "Глубокий поиск пропущен (слишком много имен)",
                "Deep lookup skipped (too many names)"
            ),
            deep_lookup_names.len(),
            deep_lookup_hard_limit
        ));
        log_info(tr_ui(
            "Для полного режима: RSS_ANALYS_DEEP_LOOKUP=1",
            "For full mode: RSS_ANALYS_DEEP_LOOKUP=1",
        ));
    }
    let (
        (full_found, full_not_found, resolved_pathless, pathless_not_found),
        (scripts_full_found, scripts_full_not_found, scripts_resolved, scripts_names_not_found),
        (start_full_found, start_full_not_found, start_resolved, start_names_not_found),
        (prefetch_full_found, prefetch_full_not_found, prefetch_resolved, prefetch_names_not_found),
        (dps_full_found, dps_full_not_found, dps_resolved, dps_names_not_found),
    ) = if lookup_names.len() >= 1024 {
        thread::scope(|scope| {
            let h_main = scope.spawn(|| {
                resolve_pe_targets(
                    &extracted_full_pe,
                    &extracted_pathless_pe,
                    &name_index,
                    Some(&file_exists_cache),
                )
            });
            let h_scripts = scope.spawn(|| {
                resolve_pe_targets(
                    &scripts_full,
                    &scripts_names,
                    &name_index,
                    Some(&file_exists_cache),
                )
            });
            let h_start = scope.spawn(|| {
                resolve_pe_targets(
                    &start_full,
                    &start_names,
                    &name_index,
                    Some(&file_exists_cache),
                )
            });
            let h_prefetch = scope.spawn(|| {
                resolve_pe_targets(
                    &prefetch_full,
                    &prefetch_names,
                    &name_index,
                    Some(&file_exists_cache),
                )
            });
            let h_dps = scope.spawn(|| {
                resolve_pe_targets(&dps_full, &dps_names, &name_index, Some(&file_exists_cache))
            });
            (
                h_main.join().unwrap_or_default(),
                h_scripts.join().unwrap_or_default(),
                h_start.join().unwrap_or_default(),
                h_prefetch.join().unwrap_or_default(),
                h_dps.join().unwrap_or_default(),
            )
        })
    } else {
        (
            resolve_pe_targets(
                &extracted_full_pe,
                &extracted_pathless_pe,
                &name_index,
                Some(&file_exists_cache),
            ),
            resolve_pe_targets(
                &scripts_full,
                &scripts_names,
                &name_index,
                Some(&file_exists_cache),
            ),
            resolve_pe_targets(
                &start_full,
                &start_names,
                &name_index,
                Some(&file_exists_cache),
            ),
            resolve_pe_targets(
                &prefetch_full,
                &prefetch_names,
                &name_index,
                Some(&file_exists_cache),
            ),
            resolve_pe_targets(&dps_full, &dps_names, &name_index, Some(&file_exists_cache)),
        )
    };

    let mut scripts_found = BTreeSet::new();
    scripts_found.extend(scripts_full_found.iter().cloned());
    scripts_found.extend(scripts_resolved.iter().cloned());
    scripts_found = dedupe_paths_case_insensitive(&scripts_found);
    let mut scripts_deleted = BTreeSet::new();
    scripts_deleted.extend(scripts_full_not_found.iter().cloned());
    scripts_deleted.extend(scripts_names_not_found.iter().cloned());

    let mut start_found = BTreeSet::new();
    start_found.extend(start_full_found.iter().cloned());
    start_found.extend(start_resolved.iter().cloned());
    start_found = dedupe_paths_case_insensitive(&start_found);
    let mut start_deleted = BTreeSet::new();
    start_deleted.extend(start_full_not_found.iter().cloned());
    start_deleted.extend(start_names_not_found.iter().cloned());

    let mut prefetch_found = BTreeSet::new();
    prefetch_found.extend(prefetch_full_found.iter().cloned());
    prefetch_found.extend(prefetch_resolved.iter().cloned());
    prefetch_found = dedupe_paths_case_insensitive(&prefetch_found);
    let mut prefetch_deleted = BTreeSet::new();
    prefetch_deleted.extend(prefetch_full_not_found.iter().cloned());
    prefetch_deleted.extend(prefetch_names_not_found.iter().cloned());

    let mut dps_found = BTreeSet::new();
    dps_found.extend(dps_full_found.iter().cloned());
    dps_found.extend(dps_resolved.iter().cloned());
    dps_found = dedupe_paths_case_insensitive(&dps_found);
    let mut dps_deleted = BTreeSet::new();
    dps_deleted.extend(dps_full_not_found.iter().cloned());
    dps_deleted.extend(dps_names_not_found.iter().cloned());

    let mut allpe = BTreeSet::new();
    allpe.extend(full_found.iter().cloned());
    allpe.extend(resolved_pathless.iter().cloned());
    allpe = dedupe_paths_case_insensitive(&allpe);
    let before_allpe_profile = allpe.len();
    allpe.retain(|p| !is_build_or_dependency_artifact_path_lc(&normalize_cmp_path(p)));
    let excluded_allpe_profile = before_allpe_profile.saturating_sub(allpe.len());
    if excluded_allpe_profile > 0 {
        log_info(&format!(
            "{}: {}",
            tr_ui("Отсечено allpe build/dependency", "allpe build/dependency excluded"),
            excluded_allpe_profile
        ));
    }
    let normal_pe = if skip_normalpe_for_speed {
        log_info(tr(
            user_opts.lang,
            "Фильтр NormalPE (BLAKE3) пропущен для ускорения (можно включить RSS_ANALYS_SKIP_NORMALPE_FOR_SPEED=0)",
            "NormalPE (BLAKE3) filter skipped for speed (set RSS_ANALYS_SKIP_NORMALPE_FOR_SPEED=0 to enable)",
        ));
        BTreeSet::new()
    } else {
        let normal_hashes = load_embedded_blake3_hashes();
        log_info(&format!(
            "{}: {}",
            tr(
                user_opts.lang,
                "Встроенных BLAKE3 из blake3",
                "Embedded BLAKE3 from blake3"
            ),
            normal_hashes.len()
        ));
        if normal_hashes.is_empty() {
            log_info(tr(
                user_opts.lang,
                "blake3/blake3.txt пуст: фильтр NormalPE по хешам пропущен",
                "blake3/blake3.txt is empty: NormalPE hash filter skipped",
            ));
        }
        let blake3_cache = results.join("cache").join("blake3_cache.tsv");
        let (allpe_filtered, normal_pe, cache_hits) = split_allpe_by_embedded_blake3(
            &allpe,
            &normal_hashes,
            &blake3_cache,
            user_opts.sort_hash,
        )?;
        allpe = allpe_filtered;
        log_info(&format!("BLAKE3 cache hit: {}", cache_hits));
        normal_pe
    };
    log_info(&format!(
        "{}: {}",
        tr(
            user_opts.lang,
            "NormalPE (по BLAKE3)",
            "NormalPE (by BLAKE3)"
        ),
        normal_pe.len()
    ));
    log_info(&format!(
        "{}: {}",
        tr(
            user_opts.lang,
            "allpe готово (без NormalPE)",
            "allpe ready (without NormalPE)"
        ),
        allpe.len()
    ));
    log_info(&format!(
        "{}: {} / {} {}",
        tr(user_opts.lang, "Файлы без пути", "Files without path"),
        resolved_pathless.len(),
        tr(user_opts.lang, "не найдено", "not found"),
        pathless_not_found.len()
    ));

    let jar_paths = resolve_java_paths(
        &java_full,
        &java_names,
        &name_index,
        Some(&file_exists_cache),
    );
    let start_status = make_status_rows(&start_found, &start_deleted, &a.file_time_hints);
    let scripts_status = make_status_rows(&scripts_found, &scripts_deleted, &a.file_time_hints);
    let file_dates = build_file_dates_rows(&a);
    let (prefetch_status, prefetch_program_deleted) =
        build_prefetch_program_status_rows(&prefetch_found, &prefetch_deleted, &name_index);
    let dps_status = build_dps_status_rows(&a.dps_events, &dps_found);
    let mut all_found_paths = BTreeSet::new();
    all_found_paths.extend(allpe.iter().cloned());
    all_found_paths.extend(normal_pe.iter().cloned());
    all_found_paths.extend(jar_paths.iter().cloned());
    all_found_paths.extend(scripts_found.iter().cloned());
    all_found_paths.extend(start_found.iter().cloned());
    all_found_paths.extend(dps_found.iter().cloned());
    all_found_paths.extend(prefetch_found.iter().cloned());
    let mut other_disk_candidates = BTreeSet::new();
    other_disk_candidates.extend(all_found_paths.iter().cloned());
    other_disk_candidates.extend(extracted_full_pe.iter().cloned());
    other_disk_candidates.extend(java_full.iter().cloned());
    other_disk_candidates.extend(full_not_found.iter().cloned());
    other_disk_candidates.extend(scripts_full_not_found.iter().cloned());
    other_disk_candidates.extend(start_full_not_found.iter().cloned());
    other_disk_candidates.extend(dps_full_not_found.iter().cloned());
    let other_disk = filter_paths_not_on_primary_disks(&other_disk_candidates, PRIMARY_LOCAL_DISKS);

    log_step(tr(
        user_opts.lang,
        "[5/8] Запись отчетов",
        "[5/8] Writing reports",
    ));
    write_list(&results.join("allpe").join("allpe.txt"), &allpe)?;
    write_list(&results.join("NormalPE").join("NormalPE.txt"), &normal_pe)?;
    write_list(
        &results.join("allpe").join("files_without_path.txt"),
        &resolved_pathless,
    )?;
    write_list(
        &results.join("notfound").join("full_paths_not_found.txt"),
        &full_not_found,
    )?;
    write_list(
        &results
            .join("notfound")
            .join("files_without_path_not_found.txt"),
        &pathless_not_found,
    )?;

    write_list(
        &results.join("RegKeyDeletion").join("RegKeyDeletion.txt"),
        &a.regdel,
    )?;
    write_list(
        &results.join("ReplaceClean").join("ReplaceClean.txt"),
        &a.replace,
    )?;
    write_list(
        &results
            .join("FilelessExecution")
            .join("FilelessExecution.txt"),
        &a.fileless,
    )?;
    write_list(&results.join("DLL").join("DLL.txt"), &a.dll)?;
    write_list(
        &results.join("ForfilesWmic").join("ForfilesWmic.txt"),
        &a.forfiles_wmic,
    )?;
    write_list(
        &results
            .join("JavaBatchExecution")
            .join("JavaBatchExecution.txt"),
        &a.java_batch,
    )?;
    write_list(&results.join("java").join("java.txt"), &a.java_batch)?;

    write_list(&results.join("java").join("jar_paths.txt"), &jar_paths)?;
    write_list(
        &results.join("scripts").join("scripts.txt"),
        &scripts_status,
    )?;
    write_list(&results.join("beta").join("beta.txt"), &a.beta)?;
    write_list(
        &results.join("file_dates").join("file_dates.txt"),
        &file_dates,
    )?;
    write_list(&results.join("DPS").join("DPS.txt"), &dps_status)?;
    write_list(&results.join("Start").join("Start.txt"), &start_status)?;
    write_list(
        &results.join("Prefetch").join("Prefetch.txt"),
        &prefetch_status,
    )?;
    write_list(
        &results.join("otherdisk").join("otherdisk.txt"),
        &other_disk,
    )?;
    write_list(&results.join("links").join("links.txt"), &a.links)?;
    let domain_frequency = collect_domain_frequency(&a.links);
    write_list(
        &results.join("domains").join("domain_frequency.txt"),
        &domain_frequency,
    )?;
    write_list(&results.join("ioc").join("command_ioc.txt"), &a.ioc)?;
    let download_links = collect_download_links(&a.links);
    write_list(
        &results.join("download-links").join("download-links.txt"),
        &download_links,
    )?;

    let slinks = suspicious_links(&a.links);
    write_list(
        &results.join("suspend_links").join("suspend_links.txt"),
        &slinks,
    )?;

    let mut sc = BTreeSet::new();
    sc.extend(allpe.iter().cloned());
    sc.extend(resolved_pathless.iter().cloned());
    sc.extend(extracted_pathless_pe.iter().cloned());
    let sfiles = suspicious_files(&sc);
    write_list(
        &results.join("suspect_file").join("suspect_file.txt"),
        &sfiles,
    )?;

    let mut deleted = BTreeSet::new();
    let mut trash_deleted = BTreeSet::new();
    for item in &full_not_found {
        if should_include_deleted_path(item) {
            deleted.insert(deleted_status_row(
                "allpe_full",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        } else {
            trash_deleted.insert(deleted_status_row(
                "allpe_full",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        }
    }
    for item in &pathless_not_found {
        if should_include_deleted_name(item) {
            deleted.insert(deleted_status_row(
                "allpe_name",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        } else {
            trash_deleted.insert(deleted_status_row(
                "allpe_name",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        }
    }
    for item in &scripts_deleted {
        if should_include_deleted_path(item) {
            deleted.insert(deleted_status_row(
                "scripts",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        } else {
            trash_deleted.insert(deleted_status_row(
                "scripts",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        }
    }
    for item in &start_deleted {
        if should_include_deleted_path(item) {
            deleted.insert(deleted_status_row(
                "start",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        } else {
            trash_deleted.insert(deleted_status_row(
                "start",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        }
    }
    let mut prefetch_found_names = BTreeSet::new();
    for item in prefetch_found
        .iter()
        .filter_map(|x| normalize_prefetch_name(x))
    {
        prefetch_found_names.insert(item);
    }
    for item in prefetch_deleted
        .iter()
        .filter_map(|x| normalize_prefetch_name(x))
    {
        if prefetch_found_names.contains(&item) {
            continue;
        }
        if should_include_prefetch_deleted_name(&item) {
            deleted.insert(deleted_status_row(
                "prefetch",
                &item,
                "prefetch missing",
                &a.file_time_hints,
            ));
        } else {
            trash_deleted.insert(deleted_status_row(
                "prefetch",
                &item,
                "prefetch missing",
                &a.file_time_hints,
            ));
        }
    }
    for item in &prefetch_program_deleted {
        if should_include_deleted_name(item) {
            deleted.insert(deleted_status_row(
                "program",
                item,
                "program deleted",
                &a.file_time_hints,
            ));
        } else {
            trash_deleted.insert(deleted_status_row(
                "program",
                item,
                "program deleted",
                &a.file_time_hints,
            ));
        }
    }
    for item in &dps_deleted {
        if should_include_deleted_path(item) {
            deleted.insert(deleted_status_row(
                "dps",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        } else {
            trash_deleted.insert(deleted_status_row(
                "dps",
                item,
                "deleted",
                &a.file_time_hints,
            ));
        }
    }
    write_list(&results.join("deleted").join("deleted.txt"), &deleted)?;
    write_list(
        &results.join("trashdeleted").join("trashdeleted.txt"),
        &trash_deleted,
    )?;

    let mut tool_scope = BTreeSet::new();
    tool_scope.extend(all_found_paths.iter().cloned());
    tool_scope.extend(full_not_found.iter().cloned());
    tool_scope.extend(pathless_not_found.iter().cloned());
    tool_scope.extend(scripts_deleted.iter().cloned());
    tool_scope.extend(start_deleted.iter().cloned());
    tool_scope.extend(prefetch_deleted.iter().cloned());
    tool_scope.extend(dps_deleted.iter().cloned());
    tool_scope.extend(prefetch_program_deleted.iter().cloned());

    let mut remote_access_tools =
        collect_keyword_file_artifacts(&tool_scope, CHEAT_ARTIFACT_KEYWORDS);
    remote_access_tools.extend(collect_keyword_link_artifacts(
        &slinks,
        CHEAT_ARTIFACT_KEYWORDS,
    ));
    if remote_access_tools.is_empty() {
        remote_access_tools.insert("No cheat artifacts (beta)".to_string());
    }

    let mut analysis_tools = collect_keyword_file_artifacts(&tool_scope, BYPASS_ARTIFACT_KEYWORDS);
    analysis_tools.extend(collect_keyword_link_artifacts(
        &slinks,
        BYPASS_ARTIFACT_KEYWORDS,
    ));
    if analysis_tools.is_empty() {
        analysis_tools.insert("No bypass artifacts (beta)".to_string());
    }

    let command_sets = [
        &a.ioc,
        &a.fileless,
        &a.dll,
        &a.forfiles_wmic,
        &a.regdel,
        &a.replace,
        &a.java_batch,
        &a.start,
    ];

    let credential_access_hits = collect_artifact_wipe_hits(&command_sets);
    let network_tunnel_hits = collect_data_hiding_hits(&command_sets, &tool_scope, &slinks);
    let remote_domain_hits = collect_trail_obfuscation_hits(&command_sets);
    let tunnel_domain_hits = collect_tool_evasion_hits(&command_sets, &tool_scope);
    let remote_session_hits = collect_persistence_hits(&command_sets);
    let persistence_hits = collect_credential_command_hits(&command_sets);
    let anti_forensics_hits = collect_anti_forensics_hits(&command_sets);
    let lolbas_hits = BTreeSet::new();

    let suspicious_domain_hits = collect_suspicious_domain_hits(&a.links);
    run_live.note_metric("signals.suspicious_links", slinks.len());
    run_live.note_metric("signals.suspicious_files", sfiles.len());
    run_live.note_metric(
        "signals.cheat_artifacts",
        count_non_empty_detector_rows(&remote_access_tools),
    );
    run_live.note_metric(
        "signals.bypass_artifacts",
        count_non_empty_detector_rows(&analysis_tools),
    );
    run_live.note_metric(
        "signals.persistence_beta",
        count_non_empty_detector_rows(&remote_session_hits),
    );
    run_live.note_metric(
        "signals.anti_forensics_beta",
        count_non_empty_detector_rows(&anti_forensics_hits),
    );
    run_live.absorb_rows("suspicious_links", &slinks, 80);
    run_live.absorb_rows("suspicious_files", &sfiles, 80);
    run_live.absorb_rows("cheat_artifacts_beta", &remote_access_tools, 120);
    run_live.absorb_rows("bypass_artifacts_beta", &analysis_tools, 120);
    run_live.absorb_rows("suspicious_domains", &suspicious_domain_hits, 80);

    remove_file_if_exists(&results.join("screenshare").join("remote_access_tools.txt"));
    remove_file_if_exists(&results.join("screenshare").join("analysis_tools.txt"));
    remove_file_if_exists(&results.join("screenshare").join("credential_access.txt"));
    remove_file_if_exists(&results.join("screenshare").join("network_tunnels.txt"));
    remove_file_if_exists(&results.join("screenshare").join("remote_domains.txt"));
    remove_file_if_exists(&results.join("screenshare").join("tunnel_domains.txt"));
    remove_file_if_exists(&results.join("screenshare").join("remote_sessions.txt"));
    remove_file_if_exists(&results.join("screenshare").join("persistence.txt"));
    remove_file_if_exists(&results.join("screenshare").join("anti_forensics.txt"));
    remove_file_if_exists(&results.join("lolbas").join("lolbas.txt"));

    write_list(
        &results.join("screenshare").join("cheat_artifacts_beta.txt"),
        &remote_access_tools,
    )?;
    write_list(
        &results
            .join("screenshare")
            .join("bypass_artifacts_beta.txt"),
        &analysis_tools,
    )?;
    write_list(
        &results.join("screenshare").join("artifact_wipe_beta.txt"),
        &credential_access_hits,
    )?;
    write_list(
        &results.join("screenshare").join("data_hiding_beta.txt"),
        &network_tunnel_hits,
    )?;
    write_list(
        &results
            .join("screenshare")
            .join("trail_obfuscation_beta.txt"),
        &remote_domain_hits,
    )?;
    write_list(
        &results.join("screenshare").join("tool_attack_beta.txt"),
        &tunnel_domain_hits,
    )?;
    write_list(
        &results.join("screenshare").join("persistence_beta.txt"),
        &remote_session_hits,
    )?;
    write_list(
        &results
            .join("screenshare")
            .join("credential_access_beta.txt"),
        &persistence_hits,
    )?;
    write_list(
        &results.join("screenshare").join("anti_forensics_beta.txt"),
        &anti_forensics_hits,
    )?;
    write_list(
        &results.join("domains").join("suspicious_domains.txt"),
        &suspicious_domain_hits,
    )?;
    let mut yara_targets = BTreeSet::new();
    yara_targets.extend(allpe.iter().cloned());
    yara_targets.extend(jar_paths.iter().cloned());
    yara_targets.extend(filter_items_by_ext(&start_found, YARA_SCAN_EXTS));
    yara_targets.extend(filter_items_by_ext(&dps_found, YARA_SCAN_EXTS));
    yara_targets = dedupe_paths_case_insensitive(&yara_targets);
    let normal_cmp = normal_pe
        .iter()
        .map(|x| normalize_cmp_path(x))
        .collect::<HashSet<_>>();
    let before_yara_filter = yara_targets.len();
    yara_targets.retain(|x| !normal_cmp.contains(&normalize_cmp_path(x)));
    let excluded_normal = before_yara_filter.saturating_sub(yara_targets.len());
    if excluded_normal > 0 {
        log_info(&format!(
            "{}: {}",
            tr(
                user_opts.lang,
                "Исключено из YARA (NormalPE)",
                "Excluded from YARA (NormalPE)"
            ),
            excluded_normal
        ));
    }
    let before_profile_filter = yara_targets.len();
    yara_targets.retain(|x| should_scan_yara_target_screenshare(x));
    let excluded_profile = before_profile_filter.saturating_sub(yara_targets.len());
    if excluded_profile > 0 {
        log_info(&format!(
            "{}: {}",
            tr(
                user_opts.lang,
                "Исключено из YARA (профиль screenshare)",
                "Excluded from YARA (screenshare profile)"
            ),
            excluded_profile
        ));
    }
    let yara_soft_limit = env::var("RSS_ANALYS_YARA_SOFT_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(50, 400_000))
        .or_else(|| user_opts.analysis_mode.yara_soft_limit_default());
    if let Some(yara_soft_limit) = yara_soft_limit {
        let before_perf_trim = yara_targets.len();
        yara_targets = trim_yara_targets_for_speed(&yara_targets, yara_soft_limit);
        let excluded_perf = before_perf_trim.saturating_sub(yara_targets.len());
        if excluded_perf > 0 {
            log_info(&format!(
                "{}: {}",
                tr(
                    user_opts.lang,
                    "Исключено из YARA (быстрый приоритет)",
                    "Excluded from YARA (fast priority)"
                ),
                excluded_perf
            ));
        }
    } else {
        log_info(tr(
            user_opts.lang,
            "Режим YARA без soft-limit (полный охват целей)",
            "YARA soft-limit disabled (full target coverage)",
        ));
    }
    log_info(&format!(
        "{}: {:.1}s",
        tr(
            user_opts.lang,
            "Время резолва/классификации",
            "Resolve/classification time"
        ),
        resolve_started.elapsed().as_secs_f64()
    ));
    run_live.note_metric("timing.resolve_ms", resolve_started.elapsed().as_millis() as usize);
    run_live.note_stage(
        "stage5",
        &format!("resolve summary: allpe={} suspicious_files={}", allpe.len(), sfiles.len()),
    );

    let yara_started = Instant::now();
    log_step(tr(
        user_opts.lang,
        "[6/8] Сканирование найденных PE/JAR",
        "[6/8] Scanning found PE/JAR files",
    ));
    let yara_hits = match yara_scan(&yara_targets, &tools) {
        Ok(y) => {
            log_info(&format!(
                "{}: {}",
                tr(user_opts.lang, "Детектов", "Detections"),
                y.len()
            ));
            write_list(&results.join("yara").join("yaradetect.txt"), &y)?;
            y
        }
        Err(e) => {
            let mut s = BTreeSet::new();
            s.insert(format!("YARA error: {e}"));
            write_list(&results.join("yara").join("yaradetect.txt"), &s)?;
            s
        }
    };
    log_info(&format!(
        "{}: {:.1}s",
        tr(user_opts.lang, "Время YARA", "YARA time"),
        yara_started.elapsed().as_secs_f64()
    ));
    run_live.note_metric("signals.yara_hits", yara_hits.len());
    run_live.note_metric("timing.yara_ms", yara_started.elapsed().as_millis() as usize);
    run_live.absorb_rows("yara", &yara_hits, 120);
    run_live.note_stage(
        "stage6",
        &format!("yara finished: targets={} hits={}", yara_targets.len(), yara_hits.len()),
    );
    let memory_orbit_report = if user_opts.memory_orbit_enabled {
        log_step(tr(
            user_opts.lang,
            "[6a] Dump core (lite memory forensics)",
            "[6a] Dump core (lite memory forensics)",
        ));
        let started = Instant::now();
        let report = run_memory_orbit_engine(
            &dmp_sources,
            &results,
            user_opts.lang,
            &prebuilt_fast_inputs,
        )?;
        log_info(&format!(
            "{}: {}, {}: {}, {}: {}, {}: {:.1}s",
            tr(user_opts.lang, "Дамп-файлов", "Dumps"),
            report.dumps_scanned,
            tr(user_opts.lang, "Анализаторов успешно", "Analyzers ok"),
            report.plugins_ok,
            tr(user_opts.lang, "ошибок", "errors"),
            report.plugin_errors.len(),
            tr(user_opts.lang, "Время Dump core", "Dump core time"),
            started.elapsed().as_secs_f64()
        ));
        report
    } else {
        MemoryOrbitReport::disabled()
    };
    run_live.note_metric("dumpcore.enabled", usize::from(memory_orbit_report.enabled));
    run_live.note_metric("dumpcore.dumps", memory_orbit_report.dumps_scanned);
    run_live.note_metric("dumpcore.injected", memory_orbit_report.injected_code_hits.len());
    run_live.note_metric(
        "dumpcore.suspicious_conn",
        memory_orbit_report.suspicious_connections.len(),
    );
    run_live.note_metric("dumpcore.suspicious_dll", memory_orbit_report.suspicious_dll_hits.len());
    run_live.note_metric("dumpcore.event_corr", memory_orbit_report.event_correlations.len());
    run_live.note_metric("dumpcore.lolbin", memory_orbit_report.lolbin_network_scores.len());
    run_live.absorb_rows("dumpcore_injected", &memory_orbit_report.injected_code_hits, 100);
    run_live.absorb_rows(
        "dumpcore_network",
        &memory_orbit_report.suspicious_connections,
        100,
    );
    run_live.absorb_rows("dumpcore_dll", &memory_orbit_report.suspicious_dll_hits, 100);
    run_live.absorb_rows("dumpcore_event", &memory_orbit_report.event_correlations, 80);
    run_live.absorb_rows(
        "dumpcore_lolbin",
        &memory_orbit_report.lolbin_network_scores,
        80,
    );
    run_live.note_stage(
        "stage6a",
        &format!(
            "dump core summary: dumps={} injected={} suspicious_conn={}",
            memory_orbit_report.dumps_scanned,
            memory_orbit_report.injected_code_hits.len(),
            memory_orbit_report.suspicious_connections.len()
        ),
    );

    let triage_priority_hits = collect_triage_priority_hits(
        &remote_access_tools,
        &analysis_tools,
        &credential_access_hits,
        &network_tunnel_hits,
        &remote_domain_hits,
        &tunnel_domain_hits,
        &remote_session_hits,
        &persistence_hits,
        &anti_forensics_hits,
        &slinks,
        &sfiles,
        &yara_hits,
    );
    remove_file_if_exists(&results.join("triage").join("priority_hits.txt"));
    write_list(
        &results.join("triage").join("priority_beta.txt"),
        &triage_priority_hits,
    )?;

    log_step(tr(
        user_opts.lang,
        "[7/8] Итоговый триаж",
        "[7/8] Final triage",
    ));

    log_step(tr(
        user_opts.lang,
        "[7a/8] Запись сводки",
        "[7a/8] Writing summary",
    ));
    write_summary(
        &results.join("summary").join("summary.txt"),
        &inputs,
        &dmp_sources,
        &a,
        allpe.len(),
        resolved_pathless.len(),
        full_not_found.len(),
        pathless_not_found.len(),
        normal_pe.len(),
        slinks.len(),
        download_links.len(),
        sfiles.len(),
        count_non_empty_detector_rows(&remote_access_tools),
        count_non_empty_detector_rows(&analysis_tools),
        count_non_empty_detector_rows(&credential_access_hits),
        count_non_empty_detector_rows(&network_tunnel_hits),
        count_non_empty_detector_rows(&remote_domain_hits),
        count_non_empty_detector_rows(&tunnel_domain_hits),
        count_non_empty_detector_rows(&remote_session_hits),
        count_non_empty_detector_rows(&persistence_hits),
        count_non_empty_detector_rows(&anti_forensics_hits),
        lolbas_hits.len(),
        domain_frequency.len(),
        suspicious_domain_hits.len(),
        count_non_empty_detector_rows(&triage_priority_hits),
        scripts_status.len(),
        a.beta.len(),
        file_dates.len(),
        dps_status.len(),
        start_status.len(),
        prefetch_status.len(),
        deleted.len(),
        trash_deleted.len(),
        yara_targets.len(),
        true,
        custom_stats.rules_loaded,
        custom_stats.hits_by_file.len(),
        total_custom_hits(&custom_stats.hits_by_file),
        custom_stats.process_scanned,
        custom_stats.process_skipped,
        custom_stats.process_dumps,
        memory_orbit_report.enabled,
        memory_orbit_report.dumps_scanned,
        memory_orbit_report.plugins_ok,
        memory_orbit_report.plugin_errors.len(),
        memory_orbit_report.open_files_or_sockets.len(),
        memory_orbit_report.command_buffers.len(),
        memory_orbit_report.hidden_or_terminated_processes.len(),
        memory_orbit_report.shell_command_history.len(),
        memory_orbit_report.network_artifacts.len(),
        memory_orbit_report.suspicious_connections.len(),
        memory_orbit_report.injected_code_hits.len(),
        memory_orbit_report.suspicious_dll_hits.len(),
        memory_orbit_report.modified_memory_regions.len(),
        memory_orbit_report.event_correlations.len(),
        memory_orbit_report.lolbin_network_scores.len(),
        memory_orbit_report.javaw_betatest.len(),
        memory_orbit_report.proxy_bypass_hits.len(),
        memory_orbit_report.risk_verdicts.len(),
    )?;

    log_step(tr(user_opts.lang, "[8/8] HTML-отчет", "[8/8] HTML report"));
    let report_path = results.join("report.html");
    write_html_report(
        &report_path,
        user_opts,
        &inputs,
        &dmp_sources,
        &a,
        &allpe,
        &normal_pe,
        &scripts_status,
        &file_dates,
        &dps_status,
        &start_status,
        &prefetch_status,
        &other_disk,
        &deleted,
        &trash_deleted,
        &resolved_pathless,
        &full_not_found,
        &pathless_not_found,
        &slinks,
        &download_links,
        &sfiles,
        &jar_paths,
        &remote_access_tools,
        &analysis_tools,
        &credential_access_hits,
        &network_tunnel_hits,
        &remote_domain_hits,
        &tunnel_domain_hits,
        &remote_session_hits,
        &persistence_hits,
        &anti_forensics_hits,
        &lolbas_hits,
        &domain_frequency,
        &suspicious_domain_hits,
        &triage_priority_hits,
        yara_targets.len(),
        &yara_hits,
        &custom_hits_lines,
        &custom_stats,
        &memory_orbit_report,
    )?;
    log_info(&format!(
        "{}: {}",
        tr(user_opts.lang, "HTML отчет", "HTML report"),
        report_path.display()
    ));

    prompt_line(&format!(
        "{}: {}",
        tr(user_opts.lang, "Результаты", "Results"),
        results.display()
    ));
    prompt_line(&format!(
        "{}: {}",
        tr(user_opts.lang, "Кастомные отчеты", "Custom reports"),
        custom_dir.display()
    ));
    if user_opts.process_scan_mode.enabled() {
        prompt_line(&format!(
            "{}: {}",
            tr(user_opts.lang, "Дампы процессов", "Process dumps"),
            programscustom_dir.display()
        ));
    }
    if user_opts.memory_orbit_enabled {
        prompt_line(&format!(
            "{}: {}",
            tr(user_opts.lang, "Отчет Dump core", "Dump core report"),
            results.join("dumpcore").display()
        ));
    }
    log_info(&format!(
        "{}: {:.1}s",
        tr(user_opts.lang, "Общее время", "Total time"),
        run_started.elapsed().as_secs_f64()
    ));
    drop(ui_guard);
    Ok(())
}

impl Analyzer {
    fn analyze_text(&mut self, text: &str) {
        let mut assembler = LogicalLineAssembler::default();
        for raw in text.split(|c| c == '\n' || c == '\r' || c == '\0') {
            let (line1, line2) = assembler.push_fragment(raw);
            if let Some(line) = line1 {
                self.process_line_core(&line);
            }
            if let Some(line) = line2 {
                self.process_line_core(&line);
            }
        }
        if let Some(line) = assembler.finish() {
            self.process_line_core(&line);
        }
    }

    fn analyze_text_fast(&mut self, text: &str) {
        let mut assembler = LogicalLineAssembler::default();
        for raw in text.split(|c| c == '\n' || c == '\r' || c == '\0') {
            let (line1, line2) = assembler.push_fragment(raw);
            if let Some(line) = line1 {
                self.process_line_fast_core(&line);
            }
            if let Some(line) = line2 {
                self.process_line_fast_core(&line);
            }
        }
        if let Some(line) = assembler.finish() {
            self.process_line_fast_core(&line);
        }
    }

    fn analyze_fragment(&mut self, text: &str) {
        let mut assembler = LogicalLineAssembler::default();
        for raw in text.split(|c| c == '\n' || c == '\r' || c == '\0') {
            let (line1, line2) = assembler.push_fragment(raw);
            if let Some(line) = line1 {
                self.process_line_core(&line);
            }
            if let Some(line) = line2 {
                self.process_line_core(&line);
            }
        }
        if let Some(line) = assembler.finish() {
            self.process_line_core(&line);
        }
    }

    fn process_line_core(&mut self, raw: &str) {
        let Some(mut line) = clean_line(raw) else {
            return;
        };
        let mut lower = line.to_ascii_lowercase();
        if is_probable_embedded_source_noise(&lower) && !has_high_value_artifact_hint(&lower) {
            return;
        }
        // Normalize path fragments only when path-like tokens are present.
        if line.contains('\\')
            || line.contains(":/")
            || line.contains(":\\")
            || line.contains("\\??\\")
            || line.contains("\\\\?\\")
            || line.contains("\\Device\\")
            || line.contains("\\device\\")
        {
            line = normalize_paths_in_text(&line);
            lower = line.to_ascii_lowercase();
            if is_probable_embedded_source_noise(&lower) && !has_high_value_artifact_hint(&lower) {
                return;
            }
        }
        self.collect_links(&line);
        self.collect_files(&line);
        self.collect_process_start(&line);
        self.collect_dps_rows(&line);
        self.analyze_line_normalized_with_lower(&line, &lower);
    }

    fn process_line_fast_core(&mut self, raw: &str) {
        let trimmed = raw.trim();
        if trimmed.len() < 4 || trimmed.len() > 12_000 {
            return;
        }
        if trimmed
            .split_whitespace()
            .any(|token| token.len() > 256 || token.starts_with("crate::"))
        {
            return;
        }

        let mut lower = trimmed.to_ascii_lowercase();
        if is_probable_embedded_source_noise(&lower) && !has_high_value_artifact_hint(&lower) {
            return;
        }

        let mut line = std::borrow::Cow::Borrowed(trimmed);
        if trimmed.contains('\\')
            || trimmed.contains(":/")
            || trimmed.contains(":\\")
            || trimmed.contains("\\??\\")
            || trimmed.contains("\\\\?\\")
            || trimmed.contains("\\Device\\")
            || trimmed.contains("\\device\\")
        {
            let normalized = normalize_paths_in_text(trimmed);
            lower = normalized.to_ascii_lowercase();
            if is_probable_embedded_source_noise(&lower) && !has_high_value_artifact_hint(&lower) {
                return;
            }
            line = std::borrow::Cow::Owned(normalized);
        }

        self.collect_links(line.as_ref());
        self.collect_files(line.as_ref());
        self.collect_process_start(line.as_ref());
        self.collect_dps_rows(line.as_ref());
        self.analyze_line_normalized_with_lower(line.as_ref(), &lower);
    }

    fn collect_links(&mut self, text: &str) {
        if text.len() < 4 || !text.contains('.') {
            return;
        }
        if text.len() > 8192 {
            return;
        }
        let lower = text.to_ascii_lowercase();
        let has_scheme = contains_url_scheme_lc(&lower);
        let has_domain_hint = lower.contains("www.")
            || lower.contains(".com")
            || lower.contains(".net")
            || lower.contains(".org")
            || lower.contains(".ru")
            || lower.contains(".gg")
            || lower.contains(".io")
            || lower.contains(".me")
            || lower.contains(".xyz")
            || lower.contains(".top")
            || lower.contains(".site")
            || lower.contains(".store")
            || lower.contains(".cc")
            || lower.contains(".co")
            || lower.contains(".su")
            || lower.contains(".pw");
        if !has_scheme && !has_domain_hint {
            return;
        }
        if text.len() > 4096 && !has_scheme {
            return;
        }
        if text.split_whitespace().count() > 160 && !has_scheme {
            return;
        }
        let allow_domain_candidates = should_scan_domain_candidates(text, &lower);

        let mut spans = Vec::new();
        for m in URL_RE.find_iter(text) {
            spans.push((m.start(), m.end()));
            if let Some(v) = norm_link_match(text, m.start(), m.end(), true) {
                self.links.insert(v);
            }
        }
        if allow_domain_candidates {
            for m in DOMAIN_RE.find_iter(text) {
                if inside_spans(m.start(), m.end(), &spans) {
                    continue;
                }
                if let Some(v) = norm_link_match(text, m.start(), m.end(), false)
                    && should_keep_domain_without_scheme(&v)
                {
                    self.links.insert(v);
                }
            }
        }
    }

    fn collect_files(&mut self, raw: &str) {
        if !raw.contains('.') {
            return;
        }
        let lower = raw.to_ascii_lowercase();
        if !lower.contains(".exe")
            && !lower.contains(".dll")
            && !lower.contains(".jar")
            && !lower.contains(".bat")
            && !lower.contains(".cmd")
            && !lower.contains(".ps1")
            && !lower.contains(".pf")
        {
            return;
        }
        let line_time_hints = extract_line_time_hints(raw);
        for c in extract_binary_candidates(raw) {
            let Some(n) = norm_file_candidate(&c) else {
                continue;
            };
            let Some(ext) = bin_ext(&n) else {
                continue;
            };
            if ext == "pf" {
                if normalize_prefetch_name(&n).is_none() {
                    continue;
                }
            } else if !is_valid_candidate_with_exts(&n, TRACKED_FILE_EXTS) {
                continue;
            }

            let raw_name = Path::new(&n)
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or(&n)
                .to_ascii_lowercase();

            let Some(name) = normalize_pathless_name_with_exts(&raw_name, TRACKED_FILE_EXTS) else {
                continue;
            };
            for hint in &line_time_hints {
                self.note_file_time_hint(&n, hint);
            }

            if ext == "exe" || ext == "dll" {
                if is_abs_win(&n) {
                    self.full_paths.insert(n.clone());
                } else {
                    self.pathless.insert(name.clone());
                }
            }
            if ext == "jar" {
                if is_abs_win(&n) {
                    self.java_paths.insert(n.clone());
                } else {
                    self.java_paths.insert(name.clone());
                }
            }
            if SCRIPT_EXTS.contains(&ext) {
                if is_abs_win(&n) {
                    self.scripts.insert(n.clone());
                } else {
                    self.scripts.insert(name.clone());
                }
            }
            if ext == "pf" {
                if let Some(prefetch_name) = normalize_prefetch_name(&n) {
                    if is_abs_win(&n) {
                        self.prefetch.insert(normalize_full_windows_path(&n));
                    } else {
                        self.prefetch.insert(prefetch_name);
                    }
                }
            }
        }
    }

    fn collect_process_start(&mut self, raw: &str) {
        if !raw.contains("ProcessStart")
            && !raw.contains("processstart")
            && !raw.contains("PROCESSSTART")
        {
            return;
        }
        let line_time_hints = extract_line_time_hints(raw);
        for caps in PROCESS_START_RE.captures_iter(raw) {
            let Some(path_raw) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(n) = norm_file_candidate(path_raw) else {
                continue;
            };
            for hint in &line_time_hints {
                self.note_file_time_hint(&n, hint);
            }
            let Some(ext) = bin_ext(&n) else {
                continue;
            };
            if !START_EXTS.contains(&ext) {
                continue;
            }
            if is_abs_win(&n) {
                self.start.insert(n);
            } else {
                let raw_name = Path::new(&n)
                    .file_name()
                    .and_then(OsStr::to_str)
                    .unwrap_or(&n)
                    .to_ascii_lowercase();
                if let Some(name) = normalize_pathless_name_with_exts(&raw_name, START_EXTS) {
                    self.start.insert(name);
                }
            }
        }
    }

    fn collect_dps_rows(&mut self, raw: &str) {
        let lower = raw.to_ascii_lowercase();
        if !lower.contains("dps") && !raw.contains('!') {
            return;
        }
        for caps in DPS_RE.captures_iter(raw) {
            let Some(file_raw) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(ts) = caps.get(2).map(|m| m.as_str().trim()) else {
                continue;
            };
            let Some(norm_file) = normalize_dps_file_token(file_raw) else {
                continue;
            };
            self.dps_files.insert(norm_file.clone());
            self.dps_events.insert((norm_file.clone(), ts.to_string()));
            self.note_file_time_hint(&norm_file, ts);
        }
    }

    fn note_file_time_hint(&mut self, path_or_name: &str, raw_hint: &str) {
        let Some(hint) = normalize_time_hint(raw_hint) else {
            return;
        };
        for key in file_time_hint_keys(path_or_name) {
            let entry = self.file_time_hints.entry(key).or_default();
            if entry.len() < MAX_FILE_TIME_HINTS_PER_FILE {
                entry.insert(hint.clone());
            }
        }
    }

    fn analyze_line_normalized_with_lower(&mut self, line: &str, lower: &str) {
        if is_probable_embedded_source_noise(&lower) {
            return;
        }
        if !looks_interesting_fast(&lower) {
            return;
        }
        if !looks_human(line) {
            return;
        }
        let regdel = is_regdel_lc(line, &lower);
        let replace = is_replaceclean_lc(line, &lower);
        let fileless = is_fileless_lc(&lower);
        let dll = is_dll_execution_lc(line, &lower);
        let forfiles_wmic = is_forfiles_wmic_lc(&lower);
        let java_batch = is_java_batch_lc(line, &lower);
        let beta = is_beta_protocol_abuse_lc(line, &lower);
        let ioc = regdel
            || replace
            || fileless
            || dll
            || forfiles_wmic
            || java_batch
            || beta
            || is_command_ioc_lc(line, &lower);

        if regdel {
            self.regdel.insert(line.to_string());
        }
        if replace {
            self.replace.insert(line.to_string());
        }
        if fileless {
            self.fileless.insert(line.to_string());
        }
        if dll {
            self.dll.insert(line.to_string());
        }
        if forfiles_wmic {
            self.forfiles_wmic.insert(line.to_string());
        }
        if java_batch {
            self.java_batch.insert(line.to_string());
        }
        if beta {
            self.beta.insert(line.to_string());
        }
        if ioc {
            self.ioc.insert(line.to_string());
        }
    }
}

fn wait_for_enter() {
    let exit_msg = tr_ui("Нажмите Enter для выхода...", "Press Enter to exit...");
    prompt_line(exit_msg);
    let stdin = io::stdin();
    loop {
        let mut s = String::new();
        if stdin.read_line(&mut s).is_err() {
            break;
        }
        if s.trim().is_empty() {
            break;
        }
        prompt_line(tr_ui(
            "Для выхода нажмите только Enter.",
            "Press only Enter to exit.",
        ));
    }
}

fn log_step(message: &str) {
    if with_run_ui(|ui| {
        ui.update_step(message);
        ui.push_log(&format!("[*] {message}"));
    }) {
        return;
    }
    let mut out = io::stdout();
    let _ = execute!(out, SetForegroundColor(Color::Red));
    println!("[*] {message}");
    let _ = execute!(out, ResetColor);
}

fn log_info(message: &str) {
    if with_run_ui(|ui| {
        ui.push_log(&format!("-> {message}"));
    }) {
        return;
    }
    let mut out = io::stdout();
    let _ = execute!(out, SetForegroundColor(Color::DarkGreen));
    println!("    -> {message}");
    let _ = execute!(out, ResetColor);
}

