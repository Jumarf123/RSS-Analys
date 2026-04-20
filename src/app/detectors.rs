// Low-level text cleaning, pattern detection, link parsing, and string extraction helpers.

fn clean_line(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }

    let raw = trim_trailing_xdigits_suffix(raw);
    let raw = trim_trailing_literal_escape_suffix(raw);
    let raw = trim_trailing_quote_numeric_suffix(raw);
    let mut out = String::with_capacity(raw.len().min(4096));
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
    }

    if out.ends_with(' ') {
        out.pop();
    }

    if out.len() < 4 {
        return None;
    }
    let low = out.to_ascii_lowercase();
    if out.len() > 12_000 {
        return None;
    }
    if out.len() > 6_000 && !has_high_value_artifact_hint(&low) {
        return None;
    }
    if NOISE.iter().any(|n| low.contains(n)) && !has_high_value_artifact_hint(&low) {
        return None;
    }
    Some(out)
}

fn normalize_paths_in_text(line: &str) -> String {
    if !should_try_path_normalization(line) {
        return line.to_string();
    }
    let mut replacements = Vec::<(String, String)>::new();
    for candidate in extract_binary_candidates(line) {
        let Some(normalized) = norm_file_candidate(&candidate) else {
            continue;
        };
        if candidate.eq_ignore_ascii_case(&normalized) {
            continue;
        }
        replacements.push((candidate, normalized));
    }
    if replacements.is_empty() {
        return line.to_string();
    }
    replacements.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    replacements.dedup_by(|a, b| a.0.eq_ignore_ascii_case(&b.0));

    let mut out = line.to_string();
    for (from, to) in replacements {
        out = out.replace(&from, &to);
    }
    out
}

fn should_try_path_normalization(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("\\device\\harddiskvolume")
        || lower.contains("device\\harddiskvolume")
        || lower.contains("\\??\\")
        || lower.contains("\\\\?\\")
        || lower.contains(":\\")
}

fn trim_trailing_xdigits_suffix(raw: &str) -> &str {
    let trimmed = raw.trim_end_matches(char::is_whitespace);
    let bytes = trimmed.as_bytes();
    if bytes.len() < 2 {
        return trimmed;
    }

    let mut i = bytes.len();
    while i > 0 && bytes[i - 1].is_ascii_digit() {
        i -= 1;
    }
    if i == bytes.len() || i == 0 {
        return trimmed;
    }
    if bytes[i - 1] != b'x' && bytes[i - 1] != b'X' {
        return trimmed;
    }
    if i > 1 && !bytes[i - 2].is_ascii_whitespace() {
        return trimmed;
    }

    trimmed[..i - 1].trim_end_matches(char::is_whitespace)
}

fn looks_human(s: &str) -> bool {
    let mut ascii = 0usize;
    let mut allowed = 0usize;
    let mut alpha = 0usize;
    for ch in s.chars() {
        if ch.is_ascii() {
            ascii += 1;
            if ch.is_ascii_alphabetic() {
                alpha += 1;
            }
            if ch.is_ascii_alphanumeric()
                || ch.is_ascii_whitespace()
                || r#"._\-:/\\'"()[]{}=+@,%!?&*<>|;`"#.contains(ch)
            {
                allowed += 1;
            }
        }
    }
    if ascii == 0 || alpha == 0 {
        return false;
    }
    if allowed * 100 < ascii * 85 {
        return false;
    }
    if s.split_whitespace().any(|t| t.len() > 200) {
        return false;
    }
    true
}

fn looks_interesting_fast(lower: &str) -> bool {
    if is_probable_embedded_source_noise(lower) && !has_high_value_artifact_hint(lower) {
        return false;
    }
    [
        "cmd",
        "pwsh",
        "powershell",
        "schtasks",
        "bitsadmin",
        "certutil",
        "mshta",
        "wscript",
        "cscript",
        "reg",
        "delete",
        "add",
        "query",
        "create",
        "hkey",
        "type",
        "echo",
        "copy",
        "iex",
        "iwr",
        "irm",
        "invoke-expression",
        "invoke-webrequest",
        "invoke-restmethod",
        "-uri",
        "downloadstring",
        "downloadfile",
        "frombase64string",
        "encodedcommand",
        "-enc",
        ".ps1",
        ".bat",
        ".cmd",
        "processstart,",
        "!!",
        "http://",
        "https://",
        "ftp://",
        "url protocol",
        "hkey_classes_root",
        "hkcr",
        "shell\\open\\command",
        "%1",
        "base64",
        "regsvr32",
        "rundll32",
        "wmic",
        "java -jar",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

fn is_regdel_lc(s: &str, lower: &str) -> bool {
    if s.len() < 13 {
        return false;
    }
    if is_probable_embedded_source_noise(lower) {
        return false;
    }
    REG_DELETE_CMD_RE.is_match(s) && REG_HIVE_RE.is_match(lower)
}

#[cfg(test)]
fn is_regdel(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    is_regdel_lc(s, &lower)
}

fn is_replaceclean_lc(s: &str, lower: &str) -> bool {
    if !replace_guard(s) {
        return false;
    }
    if is_probable_embedded_source_noise(lower) {
        return false;
    }
    let command_ctx = has_shell_launcher_lc(lower)
        || lower.starts_with("echo ")
        || lower.starts_with("type ")
        || lower.starts_with("copy ");
    if !command_ctx {
        return false;
    }
    if has_token_lc(lower, "echo")
        && ECHO_REDIRECT_RE.is_match(s)
        && echo_redirect_target(s).is_some_and(looks_like_file_operand)
    {
        return true;
    }
    if has_token_lc(lower, "type")
        && TYPE_RE
            .captures(s)
            .and_then(|caps| {
                let src = caps.get(1)?.as_str();
                let dst = caps.get(2)?.as_str();
                Some(looks_like_file_operand(src) && looks_like_file_operand(dst))
            })
            .unwrap_or(false)
    {
        return true;
    }
    if has_token_lc(lower, "copy")
        && COPY_RE
            .captures(s)
            .and_then(|caps| {
                let src = caps.get(1)?.as_str();
                let dst = caps.get(2)?.as_str();
                Some(looks_like_file_operand(src) && looks_like_file_operand(dst))
            })
            .unwrap_or(false)
    {
        return true;
    }
    false
}

#[cfg(test)]
fn is_replaceclean(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    is_replaceclean_lc(s, &lower)
}

fn replace_guard(s: &str) -> bool {
    if s.chars().filter(|c| *c == '?').count() > 1 {
        return false;
    }
    let colons = s.chars().filter(|c| *c == ':').count();
    if colons > 3 && !s.contains("://") {
        return false;
    }
    if s.contains("::")
        && !s.contains("\\\\?\\")
        && !s.contains("http://")
        && !s.contains("https://")
    {
        return false;
    }
    true
}

fn echo_redirect_target(s: &str) -> Option<&str> {
    let idx = s.rfind('>')?;
    let target = s.get(idx + 1..)?.trim();
    if target.is_empty() {
        return None;
    }
    Some(target)
}

fn looks_like_file_operand(token: &str) -> bool {
    let token = token
        .trim()
        .trim_matches(|x: char| "\"'`".contains(x))
        .trim_matches(|x: char| ",;|)]}([{".contains(x));
    if token.is_empty() {
        return false;
    }
    if token.eq_ignore_ascii_case("nul")
        || token.eq_ignore_ascii_case("con")
        || token.eq_ignore_ascii_case("prn")
    {
        return false;
    }
    if token.starts_with('/') || token.starts_with('-') {
        return false;
    }
    if token.contains("\\") || token.contains('/') || token.contains(":\\") {
        return true;
    }
    let name = Path::new(token)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(token);
    let Some(dot) = name.rfind('.') else {
        return false;
    };
    if dot == 0 || dot == name.len() - 1 {
        return false;
    }
    let ext = &name[dot + 1..];
    ext.chars().all(|c| c.is_ascii_alphanumeric()) && ext.len() <= 8
}

fn is_fileless_lc(lower: &str) -> bool {
    if is_probable_embedded_source_noise(lower) {
        return false;
    }
    if is_documentation_noise_lc(lower) {
        return false;
    }
    if has_irm_iex_chain_lc(lower) {
        return true;
    }
    if has_iwr_uri_chain_lc(lower) {
        let starts_with_iwr = lower.starts_with("iwr ") || lower.starts_with("invoke-webrequest ");
        if starts_with_iwr
            || has_token_any_lc(lower, &["powershell", "pwsh", "cmd", "mshta"])
            || has_shell_chain_operator(lower)
        {
            return true;
        }
    }
    let has_launcher = has_token_any_lc(lower, &["powershell", "pwsh", "cmd", "mshta"]);
    let starts_with_exec = lower.starts_with("iex ")
        || lower.starts_with("invoke-expression ")
        || lower.starts_with("iwr ")
        || lower.starts_with("invoke-webrequest ");
    let has_runtime_ctx = has_launcher || starts_with_exec;
    if lower.contains("$encodedcommand") && has_launcher {
        return false;
    }
    if has_token_any_lc(
        lower,
        &[
            "iex",
            "invoke-expression",
            "encodedcommand",
            "-enc",
            "/enc",
            "frombase64string",
            "downloadstring",
            "downloadfile",
        ],
    ) {
        if has_runtime_ctx
            && (contains_url_scheme_lc(lower)
                || lower.contains("base64")
                || lower.contains(" -enc ")
                || lower.contains("/enc ")
                || lower.contains("-encodedcommand"))
        {
            return true;
        }
    }
    let has_exec_chain = has_token_any_lc(
        lower,
        &[
            "iex",
            "iwr",
            "irm",
            "invoke-expression",
            "invoke-webrequest",
            "invoke-restmethod",
            "encodedcommand",
            "-enc",
            "/enc",
            "downloadstring",
            "downloadfile",
            "frombase64string",
        ],
    );
    let has_payload = contains_url_scheme_lc(lower)
        || lower.contains("base64")
        || lower.contains(" -enc ")
        || lower.contains("/enc ")
        || lower.contains("-encodedcommand");
    has_runtime_ctx && has_exec_chain && has_payload
}

fn has_irm_iex_chain_lc(lower: &str) -> bool {
    let has_irm = has_token_any_lc(lower, &["irm", "invoke-restmethod"]);
    let has_iex = has_token_any_lc(lower, &["iex", "invoke-expression"]);
    if !(has_irm && has_iex && contains_url_scheme_lc(lower)) {
        return false;
    }
    lower.contains('|')
        || lower.contains("iex(")
        || lower.contains("iex (")
        || lower.contains("invoke-expression(")
        || lower.contains("invoke-expression (")
        || lower.contains(';')
}

fn has_iwr_uri_chain_lc(lower: &str) -> bool {
    has_token_any_lc(lower, &["iwr", "invoke-webrequest"])
        && has_token_lc(lower, "-uri")
        && contains_url_scheme_lc(lower)
}

fn custom_protocol_scheme_lc(lower: &str) -> Option<String> {
    for caps in CUSTOM_PROTOCOL_SCHEME_RE.captures_iter(lower) {
        let Some(m) = caps.get(1) else {
            continue;
        };
        let scheme = m.as_str().to_ascii_lowercase();
        if matches!(
            scheme.as_str(),
            "http" | "https" | "ftp" | "file" | "ws" | "wss" | "mailto" | "chrome" | "about"
        ) {
            continue;
        }
        return Some(scheme);
    }
    None
}

fn is_beta_protocol_abuse_lc(line: &str, lower: &str) -> bool {
    if is_probable_embedded_source_noise(lower) || is_documentation_noise_lc(lower) {
        return false;
    }
    if lower.len() > 900
        || lower.split_whitespace().count() > 90
        || looks_dense_link_blob_lc(lower)
        || lower.matches("://").count() > 5
    {
        return false;
    }
    if lower.contains("qstr(")
        || lower.contains("youtube terms of service")
        || lower.contains("community guidelines")
        || lower.contains("<a href=")
        || lower.contains("<br>")
        || lower.contains("шаги:")
    {
        return false;
    }

    let has_hkcr = lower.contains("hkey_classes_root\\")
        || lower.contains("hkey_classes_root/")
        || lower.contains("hkcr\\")
        || lower.contains("hkcr/");
    let has_chain = lower.contains("shell\\open\\command") || lower.contains("shell/open/command");
    let has_url_protocol = has_token_lc(lower, "url protocol");
    let has_default_value =
        lower.contains("(default)") || lower.contains("default") || lower.contains("reg_sz");
    let has_percent_arg = lower.contains("\"%1\"") || lower.contains("'%1'");
    let has_exec_path = extract_binary_candidates(line)
        .into_iter()
        .any(|c| norm_file_candidate(&c).is_some())
        || lower.contains(":\\");
    let has_custom_scheme = custom_protocol_scheme_lc(lower).is_some();
    let has_registry_write = (has_token_lc(lower, "reg")
        && (has_token_lc(lower, "add")
            || has_token_lc(lower, "import")
            || has_token_lc(lower, "copy")))
        || lower.contains("new-itemproperty")
        || lower.contains("set-itemproperty");

    if has_hkcr && has_chain && has_default_value && has_percent_arg && has_exec_path {
        return true;
    }
    if has_hkcr && has_url_protocol && has_registry_write {
        return true;
    }
    if has_registry_write && has_chain && has_exec_path && (has_url_protocol || has_hkcr) {
        return true;
    }
    if has_custom_scheme && (has_hkcr || has_registry_write) && has_chain && has_exec_path {
        return true;
    }
    false
}

fn is_documentation_noise_lc(lower: &str) -> bool {
    if lower.starts_with("description:")
        || lower.starts_with("title:")
        || lower.starts_with("reference:")
        || lower.starts_with("references:")
    {
        return true;
    }
    if lower.contains("detects usage of") || lower.contains("detects all variations of") {
        return true;
    }
    if lower.contains("learn.microsoft.com/en-us/powershell/module")
        || lower.contains("view=powershell")
    {
        return true;
    }
    if lower.contains("how to create key in regedit")
        || lower.contains("шаги:")
        || lower.contains("запустите regedit")
        || lower.contains("введите в строке поиска")
    {
        return true;
    }
    false
}

fn is_batch_extension_list_noise_lc(lower: &str) -> bool {
    if lower.contains("pathext=") {
        return true;
    }
    let ext_list_hits = [
        ".com", ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc",
    ]
    .iter()
    .filter(|ext| lower.contains(*ext))
    .count();
    ext_list_hits >= 5
}

fn is_xml_task_blob_noise_lc(lower: &str) -> bool {
    if !lower.contains("<task") {
        return false;
    }
    lower.contains("schemas.microsoft.com/windows/2004/02/mit/task")
        || (lower.contains("<registrationinfo>")
            && lower.contains("<actions")
            && lower.contains("<principals>"))
}

#[cfg(test)]
fn is_fileless(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    is_fileless_lc(&lower)
}

fn contains_ext_marker_lc(h: &str, e: &str) -> bool {
    if e.is_empty() || h.len() < e.len() {
        return false;
    }
    let hb = h.as_bytes();
    let mut start = 0usize;
    while start <= h.len().saturating_sub(e.len()) {
        let Some(pos) = h[start..].find(&e) else {
            break;
        };
        let i = start + pos;
        let r_i = i + e.len();
        let r = r_i == hb.len() || boundary(hb[r_i]);
        if r {
            return true;
        }
        start = i + 1;
    }
    false
}

fn is_java_batch_lc(_s: &str, lower: &str) -> bool {
    if is_probable_embedded_source_noise(lower) {
        return false;
    }
    if is_batch_extension_list_noise_lc(lower) {
        return false;
    }
    if JAVA_JAR_EXEC_RE.is_match(lower) {
        return true;
    }
    let has_batch = contains_ext_marker_lc(lower, ".bat") || contains_ext_marker_lc(lower, ".cmd");
    if !has_batch {
        return false;
    }
    if lower.contains("\\start menu\\programs\\startup\\") {
        return true;
    }
    if lower.contains("\\windows\\winsxs\\") {
        return false;
    }
    if !BATCH_LAUNCH_CTX_RE.is_match(lower)
        && !lower.contains(" /c ")
        && !lower.contains(" /k ")
        && !lower.contains("&&")
        && !lower.contains("||")
        && !lower.contains(" call ")
    {
        return false;
    }
    true
}

fn is_forfiles_wmic_lc(lower: &str) -> bool {
    if is_probable_embedded_source_noise(lower) {
        return false;
    }
    WMIC_PROCESS_CALL_CREATE_RE.is_match(lower)
}

fn is_dll_execution_lc(s: &str, lower: &str) -> bool {
    if is_probable_embedded_source_noise(lower) {
        return false;
    }
    if is_xml_task_blob_noise_lc(lower) {
        return false;
    }
    let injection_hits = count_token_hits_lc(
        lower,
        &[
            "createremotethread",
            "createremotethreadex",
            "writeprocessmemory",
            "virtualallocex",
            "ntcreatethreadex",
            "queueuserapc",
            "setwindowshookex",
            "manualmap",
            "reflectivedll",
            "injectdll",
            "dllinject",
            "loadlibrarya",
            "loadlibraryw",
        ],
    );
    if injection_hits >= 2 && lower.contains("dll") {
        return true;
    }

    if has_token_lc(lower, "rundll32") {
        if RUNDLL32_SCRIPT_RE.is_match(s) {
            return true;
        }
        if lower.contains("comsvcs.dll")
            && (lower.contains("minidump") || lower.contains("fulldump"))
        {
            return true;
        }
        if !RUNDLL32_DLL_ENTRY_RE.is_match(s) {
            return false;
        }
        if is_benign_rundll32_invocation_lc(lower) && !is_high_risk_dll_context_lc(lower) {
            return false;
        }
        return true;
    }
    if has_token_lc(lower, "regsvr32") {
        if !REGSVR32_USAGE_RE.is_match(s) {
            return false;
        }
        if lower.contains("scrobj.dll")
            || contains_url_scheme_lc(lower)
            || lower.contains("/i:http")
            || lower.contains("/i:https")
            || lower.contains("\\\\")
        {
            return true;
        }
        return is_high_risk_dll_context_lc(lower);
    }
    false
}

fn is_benign_rundll32_invocation_lc(lower: &str) -> bool {
    lower.contains("shell32.dll,control_rundll")
        || lower.contains("shell32.dll,options_rundll")
        || lower.contains("appxdeploymentclient.dll,appinstallerupdatealltask")
        || lower.contains("appxdeploymentclient.dll,appxprestagecleanupruntask")
        || lower.contains("speechux.dll,runwizard")
        || lower.contains("windows.statrepositoryclient.dll")
        || lower.contains("windows.statrepositoryclient.dll,staterepositorydomaintenancetasks")
}

fn is_high_risk_dll_context_lc(lower: &str) -> bool {
    contains_url_scheme_lc(lower)
        || lower.contains("\\\\")
        || lower.contains("\\users\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\downloads\\")
        || lower.contains("\\desktop\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\programdata\\")
}

fn is_command_ioc_lc(_s: &str, lower: &str) -> bool {
    if is_probable_embedded_source_noise(lower) {
        return false;
    }
    if is_documentation_noise_lc(lower) {
        return false;
    }
    if lower.len() > 1800 && !contains_url_scheme_lc(lower) {
        return false;
    }
    if lower.split_whitespace().count() > 180 {
        return false;
    }
    if artifact_wipe_tag_from_line(lower).is_some()
        || data_hiding_tag_from_line(lower).is_some()
        || trail_obfuscation_tag_from_line(lower).is_some()
        || tool_evasion_tag_from_line(lower).is_some()
        || anti_forensics_tag_from_line(lower).is_some()
        || credential_command_tag_from_line(lower).is_some()
        || persistence_tag_from_line(lower).is_some()
    {
        return true;
    }
    if has_token_any_lc(lower, &["powershell", "pwsh"])
        && has_token_any_lc(lower, &["-enc", "/enc", "encodedcommand"])
    {
        return true;
    }

    let has_launcher = has_shell_launcher_lc(lower);
    if !has_launcher {
        return false;
    }

    let mut score = 0usize;
    if has_token_any_lc(
        lower,
        &[
            "delete", "add", "query", "create", "call", "/f", "/v", "/ve", "/va",
        ],
    ) {
        score += 1;
    }
    if contains_url_scheme_lc(lower) {
        score += 1;
    }
    if has_token_any_lc(
        lower,
        &[
            "encodedcommand",
            "base64",
            "frombase64string",
            "iex",
            "invoke-expression",
            "iwr",
            "irm",
            "invoke-webrequest",
            "invoke-restmethod",
            "downloadstring",
            "downloadfile",
        ],
    ) {
        score += 2;
    }
    if has_token_any_lc(
        lower,
        &[
            "reg",
            "hkey",
            "wmic",
            "rundll32",
            "regsvr32",
            "forfiles",
            "mshta",
            "wscript",
            "cscript",
            "schtasks",
            "bitsadmin",
            "certutil",
            "wevtutil",
            "vssadmin",
            "wbadmin",
            "bcdedit",
            "fsutil",
            "cipher",
            "sdelete",
            "auditpol",
            "esentutl",
        ],
    ) {
        score += 1;
    }
    if has_token_any_lc(lower, IOC) {
        score += 1;
    }
    if has_shell_chain_operator(lower) {
        score += 1;
    }

    score >= 3
}

fn has_shell_launcher_lc(lower: &str) -> bool {
    has_token_any_lc(
        lower,
        &[
            "cmd",
            "powershell",
            "pwsh",
            "wmic",
            "reg",
            "rundll32",
            "regsvr32",
            "mshta",
            "wscript",
            "cscript",
            "forfiles",
            "java",
            "javaw",
            "schtasks",
            "bitsadmin",
            "certutil",
            "wevtutil",
            "vssadmin",
            "wbadmin",
            "bcdedit",
            "fsutil",
            "cipher",
            "sdelete",
            "auditpol",
            "esentutl",
        ],
    )
}

fn has_shell_chain_operator(lower: &str) -> bool {
    lower.contains("&&")
        || lower.contains("||")
        || lower.contains(" | ")
        || lower.contains(" >")
        || lower.contains(">>")
}

fn contains_url_scheme_lc(lower: &str) -> bool {
    lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://")
}

fn count_token_hits_lc(lower: &str, tokens: &[&str]) -> usize {
    tokens
        .iter()
        .filter(|token| has_token_lc(lower, token))
        .count()
}

fn is_probable_embedded_source_noise(lower: &str) -> bool {
    if (lower.contains("\\n") || lower.contains("\\r\\n"))
        && (lower.contains("\\\"")
            || lower.contains("fn ")
            || lower.contains("assert!(")
            || lower.contains("return "))
    {
        return true;
    }
    if lower.contains("diff --git")
        || lower.contains("@@ -")
        || lower.contains("+++ ")
        || lower.contains("--- ")
    {
        return true;
    }
    if lower.contains("\"status\":\"completed\"")
        || lower.contains("\"commandexecution\"")
        || lower.contains("\"reasoning\"")
        || lower.contains("\"recipient_name\"")
        || lower.contains("\"tool_uses\"")
    {
        return true;
    }
    if lower.contains("readme.md:") || lower.contains("src/main.rs:") {
        return true;
    }
    false
}

#[cfg(test)]
fn is_java_batch(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    is_java_batch_lc(s, &lower)
}

fn has_token_any_lc(lower: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|t| has_token_lc(lower, t))
}

fn has_token_lc(h: &str, t: &str) -> bool {
    if t.is_empty() || h.len() < t.len() {
        return false;
    }
    let hb = h.as_bytes();
    let mut start = 0usize;
    while start <= h.len().saturating_sub(t.len()) {
        let Some(pos) = h[start..].find(&t) else {
            break;
        };
        let i = start + pos;
        let l = i == 0 || boundary(hb[i - 1]);
        let r_i = i + t.len();
        let r = r_i == hb.len() || boundary(hb[r_i]);
        if l && r {
            return true;
        }
        start = i + 1;
    }
    false
}

fn boundary(b: u8) -> bool {
    !b.is_ascii_alphanumeric() && b != b'_'
}

fn extract_binary_candidates(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for m in ROOTED_BIN_RE.find_iter(line) {
        let c = line[m.start()..m.end()].trim().to_string();
        if c.is_empty() {
            continue;
        }
        let key = c.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(c);
        }
    }

    for m in EXT_CHUNK_RE.find_iter(line) {
        let mut start = m.start();
        for (i, ch) in line[..m.start()].char_indices().rev() {
            if is_bin_stop(ch) {
                break;
            }
            start = i;
        }
        let c = line[start..m.end()].trim().to_string();
        if !c.is_empty() {
            let key = c.to_ascii_lowercase();
            if !seen.insert(key) {
                continue;
            }
            out.push(c);
        }
    }
    out
}

fn extract_file_candidates(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for m in ROOTED_FILE_RE.find_iter(line) {
        let c = line[m.start()..m.end()].trim().to_string();
        if c.is_empty() {
            continue;
        }
        let key = c.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(c);
        }
    }

    for m in FILE_EXT_CHUNK_RE.find_iter(line) {
        if !file_ext_boundary_ok(line, m.end()) {
            continue;
        }
        let mut start = m.start();
        for (i, ch) in line[..m.start()].char_indices().rev() {
            if is_bin_stop(ch) {
                break;
            }
            start = i;
        }
        let c = line[start..m.end()].trim().to_string();
        if c.is_empty() {
            continue;
        }
        let key = c.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(c);
        }
    }

    out
}

fn is_bin_stop(ch: char) -> bool {
    matches!(
        ch,
        '\n' | '\r'
            | '\t'
            | '"'
            | '\''
            | '<'
            | '>'
            | '|'
            | ','
            | ';'
            | '@'
            | '#'
            | '$'
            | '^'
            | '&'
            | '`'
    )
}

fn norm_file_candidate(raw: &str) -> Option<String> {
    let mut c = raw
        .trim()
        .trim_matches(|x: char| "\"'`".contains(x))
        .to_string();
    let mut last_match = None;
    for m in EXT_END_RE.find_iter(&c) {
        last_match = Some(m);
    }
    let m = last_match?;
    if m.start() == 0 {
        return None;
    }
    c.truncate(m.end());

    if c.contains("://") || c.contains("http:\\") || c.contains("https:\\") {
        return None;
    }
    if c.starts_with("*:") || c.starts_with("?:") {
        return None;
    }

    c = trim_to_last_path_root(&c);
    c = normalize_full_windows_path(&c);
    c = trim_to_last_path_root(&c);
    c = normalize_full_windows_path(&c);
    if has_broken_device_volume_marker(&c) {
        return None;
    }
    let ext = bin_ext(&c)?;
    if ext == "pf" {
        if normalize_prefetch_name(&c).is_none() {
            return None;
        }
    } else if !is_valid_candidate_with_exts(&c, TRACKED_FILE_EXTS) {
        return None;
    }
    Some(c)
}

fn norm_any_file_candidate(raw: &str) -> Option<String> {
    let mut c = raw
        .trim()
        .trim_matches(|x: char| "\"'`".contains(x))
        .to_string();
    if c.is_empty() {
        return None;
    }

    if let Some(trimmed) = trim_candidate_to_last_known_extension(&c) {
        c = trimmed;
    }

    if c.contains("://") || c.contains("http:\\") || c.contains("https:\\") {
        return None;
    }
    if c.starts_with("*:") || c.starts_with("?:") {
        return None;
    }

    c = trim_to_last_path_root(&c);
    c = normalize_full_windows_path(&c);
    c = trim_to_last_path_root(&c);
    c = normalize_full_windows_path(&c);
    if has_broken_device_volume_marker(&c) {
        return None;
    }

    if !is_abs_win(&c) && !c.contains('\\') && !c.contains('/') && c.contains(char::is_whitespace) {
        if let Some(last) = c.split_whitespace().last() {
            c = last.to_string();
        }
    }

    if !is_valid_any_file_candidate(&c) {
        return None;
    }

    if is_abs_win(&c) {
        Some(c)
    } else {
        normalize_pathless_name_any(&c)
    }
}

fn trim_candidate_to_last_known_extension(raw: &str) -> Option<String> {
    let mut last_match = None;
    for m in FILE_EXT_END_RE.find_iter(raw) {
        if !file_ext_boundary_ok(raw, m.end()) {
            continue;
        }
        last_match = Some(m);
    }
    let m = last_match?;
    if m.start() == 0 {
        return None;
    }
    Some(raw[..m.end()].to_string())
}

fn file_ext_boundary_ok(text: &str, end: usize) -> bool {
    let Some(next) = text.get(end..).and_then(|tail| tail.chars().next()) else {
        return true;
    };
    matches!(
        next,
        ' ' | '\t'
            | '\n'
            | '\r'
            | '"'
            | '\''
            | '`'
            | '<'
            | '>'
            | ','
            | ';'
            | ':'
            | '|'
            | ')'
            | ']'
            | '}'
    )
}

fn trim_to_last_path_root(input: &str) -> String {
    let c = input.trim().replace('/', "\\");
    if let Some(idx) = last_path_root_index(&c) {
        return c[idx..].to_string();
    }
    c
}

fn last_path_root_index(s: &str) -> Option<usize> {
    let mut last = None;
    for (i, _) in s.char_indices() {
        if is_drive_root_at(s, i)
            || starts_with_ci_at(s, i, "\\device\\harddiskvolume")
            || starts_with_ci_at(s, i, "device\\harddiskvolume")
            || starts_with_ci_at(s, i, "\\??\\")
            || starts_with_ci_at(s, i, "\\\\?\\")
        {
            last = Some(i);
        }
    }
    last
}

fn starts_with_ci_at(haystack: &str, idx: usize, needle: &str) -> bool {
    haystack
        .get(idx..idx + needle.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(needle))
}

fn is_drive_root_at(path: &str, idx: usize) -> bool {
    let b = path.as_bytes();
    if idx >= b.len() || !b[idx].is_ascii_alphabetic() {
        return false;
    }
    let mut i = idx + 1;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= b.len() || b[i] != b':' {
        return false;
    }
    i += 1;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i < b.len() && (b[i] == b'\\' || b[i] == b'/')
}

fn has_broken_device_volume_marker(path: &str) -> bool {
    let p = path.to_ascii_lowercase().replace('/', "\\");
    if !p.contains("device\\") {
        return false;
    }

    let needle = "harddiskvolu";
    let mut start = 0usize;
    while let Some(pos) = p[start..].find(needle) {
        let i = start + pos;
        let tail = &p[i + needle.len()..];
        // valid token must continue as: harddiskvolume<digits>\
        if !tail.starts_with("me") {
            return true;
        }
        let bytes = tail.as_bytes();
        let mut j = 2usize;
        if j >= bytes.len() || !bytes[j].is_ascii_digit() {
            return true;
        }
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'\\' {
            return true;
        }
        start = i + needle.len();
    }
    false
}

fn normalize_dps_file_token(raw: &str) -> Option<String> {
    let token = raw
        .trim()
        .trim_matches(|x: char| "\"'`".contains(x))
        .trim_matches(|x: char| ",;|)]}([{".contains(x));
    if token.is_empty() || token.contains("://") {
        return None;
    }
    let normalized = normalize_full_windows_path(token);
    let file_name = Path::new(&normalized)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(&normalized);
    if is_excluded_dps_name_lc(&file_name.to_ascii_lowercase()) {
        return None;
    }
    if is_valid_any_file_candidate(&normalized) {
        return Some(normalized);
    }
    None
}

fn is_excluded_dps_name_lc(name_lc: &str) -> bool {
    DPS_EXCLUDED_NAMES
        .iter()
        .any(|candidate| name_lc.eq_ignore_ascii_case(candidate))
}

fn normalize_prefetch_name(raw: &str) -> Option<String> {
    let normalized = normalize_full_windows_path(raw);
    let file_name = Path::new(&normalized)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(raw)
        .trim()
        .trim_matches(|x: char| "\"'` ,;|)]}([{".contains(x));
    if file_name.is_empty() {
        return None;
    }
    let caps = PREFETCH_NAME_RE.captures(file_name)?;
    let name = caps.get(1)?.as_str();
    if name.is_empty() || name.starts_with('.') {
        return None;
    }
    if name.chars().any(|c| "<>:\"/\\|?*".contains(c)) {
        return None;
    }
    if !name.chars().any(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let hash = caps.get(2)?.as_str().to_ascii_uppercase();
    Some(format!("{name}-{hash}.pf"))
}

fn collapse_backslashes_keep_unc(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '\\' {
            let mut j = i;
            while j < chars.len() && chars[j] == '\\' {
                j += 1;
            }
            let run = j - i;
            if i == 0 && run >= 2 {
                out.push('\\');
                out.push('\\');
            } else {
                out.push('\\');
            }
            i = j;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn bin_ext(p: &str) -> Option<&'static str> {
    let l = p.to_ascii_lowercase();
    for e in BIN_EXTS {
        if l.ends_with(&format!(".{e}")) {
            return Some(e);
        }
    }
    None
}

fn is_abs_win(p: &str) -> bool {
    let p = p.trim();
    has_drive_root_prefix(p)
        || p.starts_with("\\\\")
        || starts_with_ci(p, "\\device\\harddiskvolume")
        || starts_with_ci(p, "device\\harddiskvolume")
}

fn has_drive_root_prefix(path: &str) -> bool {
    let b = path.as_bytes();
    if b.is_empty() || !b[0].is_ascii_alphabetic() {
        return false;
    }
    let mut i = 1usize;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= b.len() || b[i] != b':' {
        return false;
    }
    i += 1;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i < b.len() && (b[i] == b'\\' || b[i] == b'/')
}

fn norm_link_match(text: &str, start: usize, end: usize, scheme_match: bool) -> Option<String> {
    if !link_context_ok(text, start, end, scheme_match) {
        return None;
    }
    let raw = text.get(start..end)?;
    let normalized = norm_link(raw)?;
    if !is_plausible_link(&normalized, scheme_match) {
        return None;
    }
    Some(normalized)
}

fn link_context_ok(text: &str, start: usize, end: usize, scheme_match: bool) -> bool {
    if start >= end || end > text.len() {
        return false;
    }
    let bytes = text.as_bytes();
    if start > 0 {
        let prev = bytes[start - 1];
        if prev == b'@' {
            return false;
        }
        if scheme_match
            && (prev.is_ascii_alphanumeric()
                || matches!(
                    prev,
                    b'/' | b'\\' | b':' | b'-' | b'_' | b'.' | b'*' | b'!' | b'+' | b'='
                ))
        {
            return false;
        }
        if !scheme_match
            && (prev.is_ascii_alphanumeric()
                || matches!(
                    prev,
                    b'\\' | b'/' | b':' | b'-' | b'_' | b'.' | b'*' | b'!' | b'+' | b'='
                ))
        {
            return false;
        }
    }
    if end < bytes.len() {
        let next = bytes[end];
        if scheme_match && next.is_ascii_alphanumeric() {
            return false;
        }
        if !scheme_match
            && (next.is_ascii_alphanumeric()
                || matches!(
                    next,
                    b'\\' | b'/' | b':' | b'-' | b'_' | b'.' | b'*' | b'!' | b'+' | b'='
                ))
        {
            return false;
        }
    }
    true
}

fn norm_link(raw: &str) -> Option<String> {
    let mut c = raw
        .trim()
        .trim_matches(|x: char| "\"'`()[]{}<>,;|".contains(x))
        .to_string();
    c = c.replace("\\/", "/");
    c = c.trim_end_matches('.').to_string();
    if c.is_empty() || c.contains('\\') {
        return None;
    }

    if let Some(p) = c.find("://") {
        let scheme = c[..p].to_ascii_lowercase();
        let rest = &c[p + 3..];
        let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let auth = &rest[..cut];
        let suffix = sanitize_link_suffix(&rest[cut..])?;
        let auth_no_user = auth.rsplit('@').next().unwrap_or(auth);
        let (host, port) = split_host_port(auth_no_user)?;
        if !valid_host(host) {
            return None;
        }
        let host_l = host.to_ascii_lowercase();
        if !has_known_suffix(&host_l) {
            return None;
        }
        let mut out = format!("{scheme}://{host_l}");
        if let Some(port) = port {
            if !is_default_port(&scheme, port) {
                out.push(':');
                out.push_str(&port.to_string());
            }
        }
        out.push_str(&suffix);
        return Some(out);
    }

    let cut = c.find(['/', '?', '#']).unwrap_or(c.len());
    let host_part = &c[..cut];
    let suffix = sanitize_link_suffix(&c[cut..])?;
    let (host, port) = split_host_port(host_part)?;
    if !valid_host(host) {
        return None;
    }
    let host_l = host.to_ascii_lowercase();
    if !has_known_suffix(&host_l) {
        return None;
    }
    let mut out = host_l;
    if let Some(port) = port {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(&suffix);
    Some(out)
}

fn is_plausible_link(link: &str, scheme_match: bool) -> bool {
    if link.len() < 4 || link.len() > 320 || link.chars().any(char::is_control) {
        return false;
    }
    let Some((host, suffix)) = split_link_host_suffix(link) else {
        return false;
    };
    if host.len() > 190 {
        return false;
    }
    if host.matches('.').count() > 8 {
        return false;
    }
    if host_looks_generated(host) {
        return false;
    }
    if host_looks_like_prefetch_noise(host) {
        return false;
    }
    if contains_nested_link_markers(suffix) {
        return false;
    }
    let suffix_l = suffix.to_ascii_lowercase();
    if is_link_rule_syntax_noise_lc(&suffix_l) {
        return false;
    }

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }

    let registrable = registrable_label(host).or_else(|| labels.get(labels.len() - 2).copied());
    let Some(reg_label) = registrable else {
        return false;
    };
    if reg_label.len() < 2 {
        return false;
    }
    if !reg_label.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    if !scheme_match {
        let first = labels[0];
        if first.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            return false;
        }
        if host.len() > 120 {
            return false;
        }
        if looks_noisy_link_suffix(suffix) {
            return false;
        }

        let non_tld = &labels[..labels.len() - 1];
        let digit_only = non_tld
            .iter()
            .filter(|l| l.chars().all(|c| c.is_ascii_digit()))
            .count();
        if digit_only >= 2 {
            return false;
        }
    } else {
        let first = labels[0];
        if first.as_bytes().first().is_some_and(u8::is_ascii_digit) && !is_ipv4_host(host) {
            return false;
        }
        if suffix_l.contains("http://")
            || suffix_l.contains("https://")
            || suffix_l.contains("ftp://")
        {
            return false;
        }
        if looks_noisy_link_suffix(suffix) {
            return false;
        }
    }

    true
}

fn split_link_host_suffix(link: &str) -> Option<(&str, &str)> {
    let body = if let Some(pos) = link.find("://") {
        link.get(pos + 3..)?
    } else {
        link
    };
    let cut = body.find(['/', '?', '#']).unwrap_or(body.len());
    let auth = body.get(..cut)?;
    let suffix = body.get(cut..).unwrap_or("");
    let auth_no_user = auth.rsplit('@').next().unwrap_or(auth);
    let (host, _) = split_host_port(auth_no_user)?;
    Some((host, suffix))
}

fn registrable_label(host: &str) -> Option<&str> {
    let dom = psl::domain(host.as_bytes())?;
    let d = std::str::from_utf8(dom.as_bytes()).ok()?;
    d.split('.').next()
}

fn looks_noisy_link_suffix(suffix: &str) -> bool {
    if suffix.len() > 220 {
        return true;
    }
    let lower = suffix.to_ascii_lowercase();
    if lower.contains("^0https://") || lower.contains("^0http://") || lower.contains("^0ftp://") {
        return true;
    }
    if contains_nested_link_markers(suffix) {
        return true;
    }
    if suffix.contains("namespace-") && suffix.chars().filter(|c| *c == '_').count() >= 3 {
        return true;
    }
    for segment in suffix.split(|c| ['/', '?', '#', '&', '='].contains(&c)) {
        let seg = segment.trim_matches(|c: char| "\"'`()[]{}<>,;|".contains(c));
        if seg.len() >= 90 {
            let dense = seg
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .count();
            if dense + 2 >= seg.len() {
                return true;
            }
        }
    }
    false
}

fn contains_nested_link_markers(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let https_hits = lower.matches("https://").count();
    let http_hits = lower.matches("http://").count();
    let ftp_hits = lower.matches("ftp://").count();
    if https_hits + http_hits + ftp_hits >= 2 {
        return true;
    }
    if lower.contains("-https://")
        || lower.contains("-http://")
        || lower.contains("_https://")
        || lower.contains("_http://")
    {
        return true;
    }
    false
}

fn should_scan_domain_candidates(text: &str, lower: &str) -> bool {
    if looks_dense_link_blob_lc(lower) {
        return false;
    }
    let words = text.split_whitespace().count();
    if text.len() > 1800 {
        return false;
    }
    if words > 64 {
        return false;
    }
    if words <= 2 && text.len() > 360 {
        return false;
    }
    lower.matches("namespace-").count() < 2
}

fn looks_dense_link_blob_lc(lower: &str) -> bool {
    let scheme_hits = lower.matches("https://").count()
        + lower.matches("http://").count()
        + lower.matches("ftp://").count();
    if scheme_hits >= 3 {
        return true;
    }
    if lower.contains("namespace-") && scheme_hits >= 1 {
        return true;
    }
    if scheme_hits >= 2 && (lower.contains("^0") || lower.contains("0,1")) {
        return true;
    }
    lower.len() > 320
        && lower.split_whitespace().count() <= 2
        && lower.matches('/').count() >= 9
        && scheme_hits >= 1
}

fn should_keep_domain_without_scheme(link: &str) -> bool {
    if link.contains("://") {
        return true;
    }
    let Some((host, path)) = parse_link_host_and_path(link) else {
        return false;
    };
    let host_l = host.to_ascii_lowercase();
    if has_remote_access_domain(&host_l) || has_suspicious_link_keyword_lc(&host_l) {
        return true;
    }
    if path != "/" {
        let path_l = path.to_ascii_lowercase();
        return !is_link_rule_syntax_noise_lc(&path_l) && !looks_noisy_link_suffix(&path_l);
    }
    host_l.starts_with("www.")
}

fn normalize_tool_link_path(path: &str) -> Option<String> {
    let base = strip_link_query_fragment(path);
    let mut clean = base
        .trim()
        .trim_end_matches(|c: char| "\"'`()[]{}<>,;|~*".contains(c))
        .to_string();
    if clean.is_empty() {
        return Some("/".to_string());
    }
    if !clean.starts_with('/') {
        clean = format!("/{clean}");
    }
    clean = trim_known_link_file_suffix_noise(&clean);
    let lower = clean.to_ascii_lowercase();
    if lower.contains("^0https://")
        || lower.contains("^0http://")
        || lower.contains("^0ftp://")
        || is_link_rule_syntax_noise_lc(&lower)
        || contains_nested_link_markers(&clean)
        || looks_noisy_link_suffix(&clean)
    {
        return None;
    }
    let last = clean.rsplit('/').next().unwrap_or_default();
    if last.len() == 1 && last.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    if clean.len() > 180 {
        return None;
    }
    Some(clean)
}

fn strip_link_query_fragment(path: &str) -> &str {
    path.split(['?', '#']).next().unwrap_or(path)
}

fn trim_known_link_file_suffix_noise(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    let mut best_cut = None;
    for marker in [
        ".exe", ".msi", ".zip", ".7z", ".rar", ".ps1", ".bat", ".cmd", ".dll", ".php", ".html",
        ".htm", ".ico", ".png", ".svg", ".json", ".xml",
    ] {
        let Some(pos) = lower.rfind(marker) else {
            continue;
        };
        let cut = pos + marker.len();
        if cut >= path.len() {
            continue;
        }
        let tail = &path[cut..];
        if tail.len() <= 12
            && !tail.contains('/')
            && !tail.contains('.')
            && tail.chars().all(|c| c.is_ascii_alphanumeric())
        {
            best_cut = Some(best_cut.map_or(cut, |v: usize| v.max(cut)));
        }
    }
    if let Some(cut) = best_cut {
        path[..cut].to_string()
    } else {
        path.to_string()
    }
}

fn is_high_signal_tool_link_path(path: &str) -> bool {
    if path == "/" {
        return false;
    }
    if download_filename_from_link_path(path).is_some() {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or_default();
    if tool_link_tail_is_noise(last) {
        return false;
    }
    if trimmed.contains("/releases/tag/") {
        return true;
    }
    lower == "/download"
        || lower == "/downloads"
        || lower == "/downloads.php"
        || lower.contains("/downloads/thank-you")
        || lower.ends_with("/latest/download")
        || lower.contains("/files/latest/download")
}

fn tool_link_tail_is_noise(last_segment_lower: &str) -> bool {
    if last_segment_lower.is_empty() {
        return false;
    }
    if has_repeated_half_token(last_segment_lower) {
        return true;
    }
    if last_segment_lower.ends_with("release") && last_segment_lower.len() > "release".len() {
        return true;
    }
    if last_segment_lower.ends_with("download") && last_segment_lower.len() > "download".len() {
        return true;
    }
    let mut suffix_alpha = 0usize;
    let mut cut = last_segment_lower.len();
    for (idx, ch) in last_segment_lower.char_indices().rev() {
        if ch.is_ascii_alphabetic() {
            suffix_alpha += 1;
            cut = idx;
        } else {
            break;
        }
    }
    if (1..=2).contains(&suffix_alpha) && cut > 0 {
        let core = &last_segment_lower[..cut];
        if core.chars().any(|c| c.is_ascii_digit())
            && core
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == 'v' || c == '-')
        {
            return true;
        }
    }
    false
}

fn has_repeated_half_token(value: &str) -> bool {
    if !value.is_ascii() {
        return false;
    }
    if value.len() < 8 || value.len() % 2 != 0 {
        return false;
    }
    let half = value.len() / 2;
    value[..half] == value[half..]
}

fn tool_link_host_is_noise(host: &str) -> bool {
    TOOL_LINK_NOISE_DOMAINS
        .iter()
        .any(|dom| host.eq_ignore_ascii_case(dom) || host.ends_with(&format!(".{dom}")))
}

fn is_low_value_tool_link_host(host: &str) -> bool {
    LOW_VALUE_TOOL_LINK_HOSTS
        .iter()
        .any(|dom| host.eq_ignore_ascii_case(dom) || host.ends_with(&format!(".{dom}")))
}

fn is_tool_artifact_path_noise_lc(lower: &str) -> bool {
    TOOL_PATH_NOISE_MARKERS.iter().any(|m| lower.contains(m))
        || is_build_or_dependency_artifact_path_lc(lower)
        || lower.contains("dmpbench_builtin")
        || lower.contains("\\quick launch\\user pinned\\taskbar\\")
        || lower.contains("acpi.sys[acpimofresource]")
        || lower.contains("{6d809377-6af0-444b-8957-a3773f02200e}")
        || lower.contains("{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}")
}

fn has_remote_access_domain(host: &str) -> bool {
    REMOTE_ACCESS_DOMAINS
        .iter()
        .any(|dom| host.eq_ignore_ascii_case(dom) || host.ends_with(&format!(".{dom}")))
}

fn has_network_tunnel_domain(host: &str) -> bool {
    NETWORK_TUNNEL_DOMAINS
        .iter()
        .any(|dom| host.eq_ignore_ascii_case(dom) || host.ends_with(&format!(".{dom}")))
}

fn has_suspicious_link_keyword_lc(lower: &str) -> bool {
    find_keyword_hit_lc(lower, SUSPICIOUS_LINK_KEYWORDS).is_some()
        || has_suspicious_domain_host(lower)
}

fn has_suspicious_domain_host(host: &str) -> bool {
    SUSPICIOUS_DOMAIN_HOSTS
        .iter()
        .any(|dom| host.eq_ignore_ascii_case(dom) || host.ends_with(&format!(".{dom}")))
}

fn find_keyword_hit_lc<'a>(lower: &str, keywords: &'a [&'a str]) -> Option<&'a str> {
    keywords
        .iter()
        .copied()
        .find(|k| keyword_match_lc(lower, k))
}

fn keyword_match_lc(lower: &str, keyword: &str) -> bool {
    if keyword.is_empty() {
        return false;
    }
    if keyword
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return has_token_lc(lower, keyword);
    }
    if keyword.contains("://") {
        return lower.contains(keyword);
    }
    contains_keyword_phrase_with_boundaries_lc(lower, keyword)
}

fn contains_keyword_phrase_with_boundaries_lc(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let hb = haystack.as_bytes();
    let nb = needle.as_bytes();
    let left_needs_boundary = nb
        .first()
        .copied()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
    let right_needs_boundary = nb
        .last()
        .copied()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');

    let mut start = 0usize;
    while start <= haystack.len().saturating_sub(needle.len()) {
        let Some(pos) = haystack[start..].find(needle) else {
            break;
        };
        let i = start + pos;
        let r_i = i + needle.len();
        let left_ok = !left_needs_boundary || i == 0 || boundary(hb[i - 1]);
        let right_ok = !right_needs_boundary || r_i == hb.len() || boundary(hb[r_i]);
        if left_ok && right_ok {
            return true;
        }
        start = i + 1;
    }
    false
}

fn is_link_rule_syntax_noise_lc(lower: &str) -> bool {
    lower.contains("||")
        || lower.contains("$domain=")
        || lower.contains("$script")
        || lower.contains("$third-party")
        || lower.contains("##")
        || lower.contains("@@")
}

fn is_ipv4_host(host: &str) -> bool {
    let mut count = 0usize;
    for part in host.split('.') {
        if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if part.parse::<u8>().is_err() {
            return false;
        }
        count += 1;
    }
    count == 4
}

fn host_looks_generated(host: &str) -> bool {
    let first = host.split('.').next().unwrap_or_default();
    if first.len() >= 26 {
        let digits = first.chars().filter(|c| c.is_ascii_digit()).count();
        let alpha = first.chars().filter(|c| c.is_ascii_alphabetic()).count();
        if digits >= 5 && alpha >= 5 {
            return true;
        }
    }
    false
}

fn host_looks_like_prefetch_noise(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if !lower.ends_with(".pf") {
        return false;
    }
    if [
        ".exe-", ".dll-", ".sys-", ".scr-", ".bat-", ".cmd-", ".com-", ".ps1-",
    ]
    .iter()
    .any(|pat| lower.contains(pat))
    {
        return true;
    }
    let labels: Vec<&str> = lower.split('.').collect();
    labels.len() >= 3
        && labels
            .iter()
            .any(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_digit()))
}

fn sanitize_link_suffix(suffix: &str) -> Option<String> {
    let mut cut = suffix.len();
    let lower = suffix.to_ascii_lowercase();
    for needle in ["https://", "http://", "ftp://"] {
        let mut start = 1usize;
        while start < lower.len() {
            let Some(pos) = lower[start..].find(needle) else {
                break;
            };
            let idx = start + pos;
            let prev = lower.as_bytes().get(idx.saturating_sub(1)).copied();
            if matches!(prev, Some(b'/') | Some(b'-') | Some(b'_') | Some(b'=')) {
                let mut local_cut = idx;
                if matches!(prev, Some(b'-') | Some(b'_') | Some(b'=')) {
                    local_cut = local_cut.saturating_sub(1);
                }
                cut = cut.min(local_cut);
                break;
            }
            start = idx.saturating_add(needle.len());
        }
    }
    let trimmed = suffix
        .get(..cut)
        .unwrap_or(suffix)
        .trim_end_matches(|c: char| "\"'`()[]{}<>,;|".contains(c));
    if looks_noisy_link_suffix(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if authority.is_empty() || authority.starts_with('[') {
        return None;
    }
    if let Some((h, p)) = authority.rsplit_once(':')
        && !p.is_empty()
        && p.chars().all(|c| c.is_ascii_digit())
    {
        let port = p.parse::<u16>().ok()?;
        return Some((h, Some(port)));
    }
    Some((authority, None))
}

fn is_default_port(scheme: &str, port: u16) -> bool {
    (scheme.eq_ignore_ascii_case("http") && port == 80)
        || (scheme.eq_ignore_ascii_case("https") && port == 443)
        || (scheme.eq_ignore_ascii_case("ftp") && port == 21)
}

fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 {
            return false;
        }
        let b = l.as_bytes();
        if b[0] == b'-' || b[b.len() - 1] == b'-' {
            return false;
        }
        if !b.iter().all(|x| x.is_ascii_alphanumeric() || *x == b'-') {
            return false;
        }
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn has_known_suffix(host: &str) -> bool {
    psl::suffix(host.as_bytes()).is_some_and(|s| s.is_known())
}

fn inside_spans(start: usize, end: usize, spans: &[(usize, usize)]) -> bool {
    spans.iter().any(|(s, e)| start >= *s && end <= *e)
}

fn looks_utf16(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let n = bytes.len().min(40_000);
    let s = &bytes[..n - (n % 2)];
    let mut p = 0usize;
    let mut z = 0usize;
    for ch in s.chunks_exact(2) {
        p += 1;
        if ch[1] == 0 {
            z += 1;
        }
    }
    p > 0 && (z as f64 / p as f64) > 0.45
}

fn decode_utf16(bytes: &[u8]) -> String {
    let mut u = Vec::with_capacity(bytes.len() / 2);
    for ch in bytes.chunks_exact(2) {
        u.push(u16::from_le_bytes([ch[0], ch[1]]));
    }
    String::from_utf16_lossy(&u)
}

fn binary_like(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let s = &bytes[..bytes.len().min(80_000)];
    let mut bad = 0usize;
    for b in s {
        if *b < 0x20 && *b != b'\n' && *b != b'\r' && *b != b'\t' {
            bad += 1;
        }
    }
    (bad as f64 / s.len() as f64) > 0.08
}

fn extract_ascii_strings(bytes: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for b in bytes {
        if (0x20..=0x7e).contains(b) || *b == b'\t' {
            cur.push(*b);
        } else {
            if cur.len() >= min {
                if let Ok(s) = String::from_utf8(cur.clone()) {
                    out.push(s);
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min {
        if let Ok(s) = String::from_utf8(cur) {
            out.push(s);
        }
    }
    out
}

fn extract_utf16_ascii_strings(bytes: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([ch[0], ch[1]]);
        if (0x20..=0x7e).contains(&u) || u == 0x09 {
            cur.push((u as u8) as char);
        } else {
            if cur.len() >= min {
                out.push(cur.clone());
            }
            cur.clear();
        }
    }
    if cur.len() >= min {
        out.push(cur);
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SiCharType {
    None,
    Printable,
    Null,
    Utf16High,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SiPattern {
    None,
    Ascii,
    Unicode,
}

fn extract_strings_system_informer(
    bytes: &[u8],
    min_len: usize,
    extended_charset: bool,
) -> Vec<String> {
    const MAX_WCHARS: usize = 8192;
    if bytes.is_empty() || min_len == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut buf: Vec<u16> = Vec::with_capacity(MAX_WCHARS);
    let mut pattern = SiPattern::None;

    let mut byte1 = 0u8;
    let mut byte2 = 0u8;

    let mut char_type1 = SiCharType::None;
    let mut char_type2 = SiCharType::None;
    let mut char_type3 = SiCharType::None;

    for &byte in bytes {
        let check_utf16_high = extended_charset
            && char_type1 != SiCharType::Utf16High
            && char_type1 != SiCharType::Null;

        let char_type = classify_si_byte(byte, extended_charset, check_utf16_high);
        let mut should_flush = false;

        if char_type2 == SiCharType::Printable
            && char_type1 == SiCharType::Printable
            && char_type == SiCharType::Printable
        {
            match pattern {
                SiPattern::None => {
                    pattern = SiPattern::Ascii;
                    buf.clear();
                    push_si_wchar(&mut buf, byte2 as u16, MAX_WCHARS);
                    push_si_wchar(&mut buf, byte1 as u16, MAX_WCHARS);
                    push_si_wchar(&mut buf, byte as u16, MAX_WCHARS);
                }
                SiPattern::Ascii => {
                    push_si_wchar(&mut buf, byte as u16, MAX_WCHARS);
                }
                SiPattern::Unicode => {
                    if buf.len() >= min_len {
                        should_flush = true;
                    } else {
                        buf.clear();
                        pattern = SiPattern::None;
                    }
                }
            }
        } else if char_type2 == SiCharType::Printable
            && char_type1 == SiCharType::Null
            && char_type == SiCharType::Printable
        {
            match pattern {
                SiPattern::None => {
                    pattern = SiPattern::Unicode;
                    buf.clear();
                    push_si_wchar(&mut buf, byte2 as u16, MAX_WCHARS);
                    push_si_wchar(&mut buf, byte as u16, MAX_WCHARS);
                }
                SiPattern::Unicode => {
                    push_si_wchar(&mut buf, byte as u16, MAX_WCHARS);
                }
                SiPattern::Ascii => {
                    if buf.len() >= min_len {
                        should_flush = true;
                    } else {
                        buf.clear();
                        pattern = SiPattern::None;
                    }
                }
            }
        } else if pattern == SiPattern::Unicode
            && char_type2 == SiCharType::Null
            && char_type1 == SiCharType::Printable
            && char_type == SiCharType::Null
        {
            // ASCII-Unicode continuation
        } else if pattern == SiPattern::Unicode
            && char_type3 == SiCharType::Null
            && char_type2 == SiCharType::Printable
            && char_type1 == SiCharType::Null
            && char_type == SiCharType::None
        {
            // ASCII-Unicode to UTF-16 transition
        } else if (char_type2 == SiCharType::Utf16High || char_type2 == SiCharType::Null)
            && char_type1 != SiCharType::Utf16High
            && char_type == SiCharType::Utf16High
        {
            let code_unit = u16::from_le_bytes([byte1, byte]);
            match pattern {
                SiPattern::None => {
                    pattern = SiPattern::Unicode;
                    buf.clear();
                    push_si_wchar(&mut buf, code_unit, MAX_WCHARS);
                }
                SiPattern::Unicode => {
                    push_si_wchar(&mut buf, code_unit, MAX_WCHARS);
                }
                SiPattern::Ascii => {
                    if buf.len() >= min_len {
                        should_flush = true;
                    } else {
                        buf.clear();
                        pattern = SiPattern::None;
                    }
                }
            }
        } else if pattern == SiPattern::Unicode
            && (char_type3 == SiCharType::Utf16High || char_type3 == SiCharType::Null)
            && char_type2 != SiCharType::Utf16High
            && char_type1 == SiCharType::Utf16High
            && char_type != SiCharType::Utf16High
        {
            // UTF-16 BMP continuation
        } else if pattern == SiPattern::Unicode
            && char_type3 != SiCharType::Utf16High
            && char_type2 == SiCharType::Utf16High
            && char_type1 == SiCharType::Printable
            && char_type == SiCharType::Null
        {
            push_si_wchar(&mut buf, byte1 as u16, MAX_WCHARS);
        } else if pattern != SiPattern::None && buf.len() >= min_len {
            should_flush = true;
        } else {
            buf.clear();
            pattern = SiPattern::None;
        }

        if should_flush {
            if let Some(s) = finalize_si_string(&buf, pattern, min_len) {
                out.push(s);
            }
            buf.clear();
            pattern = SiPattern::None;
        }

        byte2 = byte1;
        byte1 = byte;
        char_type3 = char_type2;
        char_type2 = char_type1;
        char_type1 = char_type;
    }

    if pattern != SiPattern::None
        && buf.len() >= min_len
        && let Some(s) = finalize_si_string(&buf, pattern, min_len)
    {
        out.push(s);
    }

    out
}

fn push_si_wchar(buf: &mut Vec<u16>, value: u16, max: usize) {
    if buf.len() < max {
        buf.push(value);
    }
}

fn finalize_si_string(buf: &[u16], pattern: SiPattern, min_len: usize) -> Option<String> {
    if buf.len() < min_len {
        return None;
    }
    let text = match pattern {
        SiPattern::Ascii => {
            let mut s = String::with_capacity(buf.len());
            for v in buf {
                s.push((*v as u8) as char);
            }
            s
        }
        SiPattern::Unicode => String::from_utf16_lossy(buf),
        SiPattern::None => return None,
    };
    let line = sanitize_scanned_string(&text);
    if line.chars().count() < min_len {
        return None;
    }
    Some(line)
}

fn classify_si_byte(byte: u8, extended_charset: bool, check_utf16_high: bool) -> SiCharType {
    if byte == 0 {
        return SiCharType::Null;
    }
    if is_printable_byte(byte, extended_charset) {
        return SiCharType::Printable;
    }
    if check_utf16_high
        && !is_utf16_high_surrogate_high_byte(byte)
        && !is_utf16_low_surrogate_high_byte(byte)
        && is_utf16_standalone_high_byte(byte)
        && (extended_charset || is_utf16_printable_high_byte(byte))
    {
        return SiCharType::Utf16High;
    }
    SiCharType::None
}

fn is_printable_byte(byte: u8, extended_charset: bool) -> bool {
    if matches!(byte, b'\t' | b'\n' | b'\r') {
        return true;
    }
    if byte < 0x20 || byte == 0x7f {
        return false;
    }
    if !extended_charset {
        return byte <= 0x7e;
    }
    !(0x80..=0x9f).contains(&byte)
}

fn is_utf16_high_surrogate_high_byte(byte: u8) -> bool {
    (0xd8..=0xdb).contains(&byte)
}

fn is_utf16_low_surrogate_high_byte(byte: u8) -> bool {
    (0xdc..=0xdf).contains(&byte)
}

fn is_utf16_standalone_high_byte(byte: u8) -> bool {
    !(0xd8..=0xdf).contains(&byte)
}

fn is_utf16_printable_high_byte(byte: u8) -> bool {
    if byte <= 0x1f {
        return false;
    }
    if (0xd8..=0xdf).contains(&byte) {
        return false;
    }
    if (0xe0..=0xef).contains(&byte) || byte == 0xff {
        return false;
    }
    true
}

impl CustomMatcher {
    fn build(rules: &[CustomRule]) -> Option<Self> {
        if rules.is_empty() {
            return None;
        }
        let mut global_patterns = Vec::new();
        let mut global_index: HashMap<String, usize> = HashMap::new();
        let mut compiled = Vec::new();

        for rule in rules {
            let mut seen_local = HashSet::new();
            let mut ids = Vec::new();
            let mut pats = Vec::new();
            for raw in &rule.patterns {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let lowered = trimmed.to_ascii_lowercase();
                let id = if let Some(id) = global_index.get(&lowered).copied() {
                    id
                } else {
                    let next = global_patterns.len();
                    global_patterns.push(lowered.clone());
                    global_index.insert(lowered, next);
                    next
                };
                if seen_local.insert(id) {
                    ids.push(id);
                    pats.push(trimmed.to_string());
                }
            }
            if ids.is_empty() {
                continue;
            }
            let min_hits = rule.min_hits.max(1).min(ids.len());
            compiled.push(CompiledCustomRule {
                client: rule.client.clone(),
                patterns: pats,
                pattern_ids: ids,
                min_hits,
                source: rule.source.clone(),
                target_process: rule.target_process.clone(),
            });
        }

        if compiled.is_empty() || global_patterns.is_empty() {
            return None;
        }

        let matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .kind(Some(AhoCorasickKind::DFA))
            .build(&global_patterns)
            .or_else(|_| {
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .build(&global_patterns)
            })
            .ok()?;

        let mut pattern_to_rules = vec![Vec::new(); global_patterns.len()];
        for (rid, rule) in compiled.iter().enumerate() {
            for (slot, gid) in rule.pattern_ids.iter().copied().enumerate() {
                pattern_to_rules[gid].push((rid, slot));
            }
        }
        let has_unscoped_rules = compiled.iter().any(|r| r.target_process.is_none());
        let mut scoped_process_names = HashSet::new();
        for rule in &compiled {
            if let Some(name) = &rule.target_process {
                scoped_process_names.insert(name.to_ascii_lowercase());
            }
        }

        Some(Self {
            rules: compiled,
            matcher,
            pattern_to_rules,
            has_unscoped_rules,
            scoped_process_names,
        })
    }

    fn has_rules_for_process(&self, process_name: Option<&str>) -> bool {
        if self.has_unscoped_rules {
            return true;
        }
        let Some(name) = process_name else {
            return false;
        };
        self.scoped_process_names
            .contains(&name.to_ascii_lowercase())
    }
}

impl FastNeedleMatcher {
    fn build(custom_needles: &[String]) -> Self {
        let needles = custom_needles
            .iter()
            .filter_map(|needle| {
                let trimmed = needle.trim();
                if trimmed.len() < 3 {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect::<Vec<_>>();
        let matcher = if needles.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .kind(Some(AhoCorasickKind::DFA))
                .build(&needles)
                .or_else(|_| AhoCorasickBuilder::new().build(&needles))
                .ok()
        };
        Self { needles, matcher }
    }

    fn has_match_in_lower(&self, lower: &str) -> bool {
        if lower.is_empty() {
            return false;
        }
        if let Some(matcher) = &self.matcher {
            return matcher.find(lower).is_some();
        }
        self.needles.iter().any(|needle| lower.contains(needle))
    }
}

impl<'a> CustomAccumulator<'a> {
    fn new(matcher: &'a CustomMatcher, process_name: Option<&str>) -> Self {
        let active_rules = matcher
            .rules
            .iter()
            .map(|rule| rule_matches_process(rule, process_name))
            .collect::<Vec<_>>();
        let matched_slots = matcher
            .rules
            .iter()
            .map(|rule| vec![false; rule.pattern_ids.len()])
            .collect::<Vec<_>>();
        let matched_counts = vec![0usize; matcher.rules.len()];
        let min_hits = matcher
            .rules
            .iter()
            .map(|rule| rule.min_hits)
            .collect::<Vec<_>>();
        let mut rules_done = vec![false; matcher.rules.len()];
        let mut pending_rules = 0usize;
        for (idx, active) in active_rules.iter().copied().enumerate() {
            if active {
                pending_rules += 1;
            } else if idx < rules_done.len() {
                rules_done[idx] = true;
            }
        }
        let mut active_pattern_to_rules = vec![Vec::new(); matcher.pattern_to_rules.len()];
        if pending_rules > 0 {
            for (pid, bindings) in matcher.pattern_to_rules.iter().enumerate() {
                let mut filtered = Vec::with_capacity(bindings.len());
                for (rid, slot) in bindings {
                    if active_rules.get(*rid).copied().unwrap_or(false) {
                        filtered.push((*rid, *slot));
                    }
                }
                active_pattern_to_rules[pid] = filtered;
            }
        }
        Self {
            matcher,
            matched_slots,
            matched_counts,
            min_hits,
            active_rules,
            active_pattern_to_rules,
            rules_done,
            pending_rules,
        }
    }

    fn feed_text(&mut self, text: &str) {
        if text.is_empty() || self.pending_rules == 0 {
            return;
        }
        for found in self.matcher.matcher.find_iter(text) {
            let pid = found.pattern().as_usize();
            if pid >= self.active_pattern_to_rules.len() {
                continue;
            }
            let bindings = &self.active_pattern_to_rules[pid];
            if bindings.is_empty() {
                continue;
            }
            for (rid, slot) in bindings {
                if self.rules_done[*rid] {
                    continue;
                }
                let rule_slots = &mut self.matched_slots[*rid];
                if !rule_slots[*slot] {
                    rule_slots[*slot] = true;
                    let count = &mut self.matched_counts[*rid];
                    *count += 1;
                    if *count >= self.min_hits[*rid] {
                        self.rules_done[*rid] = true;
                        self.pending_rules = self.pending_rules.saturating_sub(1);
                        if self.pending_rules == 0 {
                            return;
                        }
                    }
                }
            }
        }
    }

    fn is_done(&self) -> bool {
        self.pending_rules == 0
    }

    fn finish(self) -> Vec<CustomHit> {
        let mut out = Vec::new();
        for (rid, rule) in self.matcher.rules.iter().enumerate() {
            if !self.active_rules[rid] {
                continue;
            }
            let matched_count = self.matched_counts[rid];
            if matched_count < rule.min_hits {
                continue;
            }
            out.push(CustomHit {
                client: rule.client.clone(),
                source: rule.source.clone(),
                matched_count,
                min_hits: rule.min_hits,
                total_patterns: rule.patterns.len(),
            });
        }
        out.sort_by(|a, b| {
            a.client
                .to_ascii_lowercase()
                .cmp(&b.client.to_ascii_lowercase())
                .then_with(|| {
                    a.source
                        .to_ascii_lowercase()
                        .cmp(&b.source.to_ascii_lowercase())
                })
        });
        out
    }
}

fn rule_matches_process(rule: &CompiledCustomRule, process_name: Option<&str>) -> bool {
    match (&rule.target_process, process_name) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(scope), Some(name)) => scope.eq_ignore_ascii_case(name),
    }
}
