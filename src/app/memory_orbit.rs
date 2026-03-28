// Custom Dump core engine: parallel dump scanning and heuristic artifact extraction.

const DUMP_CORE_MIN_STRING_LEN: usize = 6;
const DUMP_CORE_CHUNK_BYTES: usize = 192 * 1024 * 1024;
const DUMP_CORE_OVERLAP_BYTES: usize = 512 * 1024;
const DUMP_CORE_LIMIT: usize = 120_000;
const DUMP_CORE_OPEN_LIMIT: usize = 30_000;
const DUMP_CORE_NOTES_LIMIT: usize = 30_000;
const DUMP_CORE_VERDICT_LIMIT: usize = 30_000;
const DUMP_CORE_BETATEST_LIMIT: usize = 30_000;
const DUMP_CORE_PROXY_BYPASS_LIMIT: usize = 30_000;
const DUMP_CORE_MAX_LINE_CHARS: usize = 720;
const DUMP_CORE_MAX_SEGMENTS: usize = 400_000;
const DUMP_CORE_MAX_MODULE_ROWS: usize = 120_000;
const DUMP_CORE_MAX_STREAM_ROWS: usize = 240_000;
const DUMP_CORE_MAX_STREAM_COUNT: usize = 16_384;
const DUMP_CORE_PREPARED_CHUNK_TARGET_BYTES: usize = 4 * 1024 * 1024;

const MINIDUMP_STREAM_MODULE_LIST: u32 = 4;
const MINIDUMP_STREAM_MEMORY_LIST: u32 = 5;
const MINIDUMP_STREAM_SYSTEM_INFO: u32 = 7;
const MINIDUMP_STREAM_MEMORY64_LIST: u32 = 9;
const MINIDUMP_STREAM_HANDLE_DATA: u32 = 12;
const MINIDUMP_STREAM_UNLOADED_MODULE_LIST: u32 = 14;
const MINIDUMP_STREAM_MISC_INFO: u32 = 15;

const DUMP_CORE_OPEN_MARKERS: &[&str] = &[
    "\\device\\",
    "\\??\\",
    "\\pipe\\",
    "socket",
    "handle",
    "opensavepidlmru",
    "lastvisitedpidlmru",
    "typedpaths",
    "wordwheelquery",
    "runmru",
    "thumbcache",
    "iconcache",
    "windows.edb",
];
const DUMP_CORE_OPEN_STRONG_MARKERS: &[&str] = &[
    "\\pipe\\",
    "socket",
    "opensavepidlmru",
    "lastvisitedpidlmru",
    "typedpaths",
    "wordwheelquery",
    "runmru",
    "thumbcache",
    "iconcache",
    "windows.edb",
];
const DUMP_CORE_OPEN_NOISE_PATH_MARKERS: &[&str] = &[
    "\\.cargo\\registry\\",
    "\\.cargo\\git\\",
    "\\target\\debug\\",
    "\\target\\release\\",
    "\\target_release_check\\",
    "\\.fingerprint\\",
    "\\incremental\\",
    "\\toolchains\\",
    "\\share\\doc\\rust\\",
    "\\microsoft visual studio\\",
    "\\windows kits\\",
    "\\windowsapps\\",
    "thirdpartynotices.txt",
    "\\node_modules\\",
    "\\site-packages\\",
    "\\__pycache__\\",
    "\\msys64\\",
    "\\perl5\\",
    "\\service worker\\",
    "\\code cache\\",
    "\\cache_data\\",
];
const DUMP_CORE_OPEN_HIGH_RISK_TOOL_MARKERS: &[&str] = &[
    "anydesk",
    "teamviewer",
    "rustdesk",
    "radmin",
    "parsec",
    "hoptodesk",
    "supremo",
    "wireguard",
    "tailscale",
    "zerotier",
    "cloudflared",
    "ngrok",
    "superfreevpn",
    "planetvpn",
    "happ\\tun\\sing-box",
    "cheat engine",
    "processhacker",
    "systeminformer",
    "autoclicker",
    "keyauth",
];

const DUMP_CORE_COMMAND_MARKERS: &[&str] = &[
    "cmd.exe",
    "powershell",
    "pwsh",
    "conhost",
    "history",
    "stdin",
    "stdout",
    "stderr",
    "wevtutil",
    "reg add",
    "reg delete",
    "wmic",
    "schtasks",
    "vssadmin",
    "fsutil",
    "auditpol",
    "bcdedit",
];

const DUMP_CORE_COMMAND_ACTION_MARKERS: &[&str] = &[
    " add ",
    " delete ",
    " query ",
    " create ",
    " config ",
    " start ",
    " stop ",
    " /c ",
    " -enc",
    " encodedcommand",
    " clear ",
    " remove ",
    " set ",
    " export ",
    " import ",
];

const DUMP_CORE_HIDDEN_PROCESS_MARKERS: &[&str] = &[
    "hidden process",
    "ghost process",
    "orphan process",
    "terminated process",
    "process exited",
    "activeprocesslinks",
    "eprocess",
    "hollow",
];

const DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS: &[&str] = &[
    "beacon",
    "reverse shell",
    "meterpreter",
    "ngrok",
    "cloudflared",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "pastebin",
    "webhook",
];

const DUMP_CORE_LOLBIN_MARKERS: &[&str] = &[
    "mshta",
    "rundll32",
    "regsvr32",
    "powershell -enc",
    "powershell -encodedcommand",
    "pwsh -enc",
    "wmic process call create",
    "cmd.exe /c",
];

const DUMP_CORE_LOLBIN_NETWORK_MARKERS: &[&str] = &[
    "http://",
    "https://",
    "wss://",
    "ws://",
    "invoke-webrequest",
    "invoke-restmethod",
    "downloadstring",
    "downloadfile",
    "curl ",
    "wget ",
    "socket",
    "connect",
    "outbound",
    "proxy",
];

const DUMP_CORE_INJECTION_MARKERS: &[&str] = &[
    "writeprocessmemory",
    "createremotethread",
    "ntcreatethreadex",
    "queueuserapc",
    "virtualalloc",
    "virtualprotect",
    "ntmapviewofsection",
    "manualmap",
    "shellcode",
    "rwx",
    "page_execute_readwrite",
    "thread hijack",
];

const DUMP_CORE_INJECTION_PROTECT_MARKERS: &[&str] = &[
    "rwx",
    "execute_readwrite",
    "page_execute_readwrite",
    "virtualprotect",
    "virtualprotectex",
    "ntprotectvirtualmemory",
];

const DUMP_CORE_SUSPICIOUS_DLL_MARKERS: &[&str] = &[
    "appinit_dlls",
    "knowndlls",
    "silentprocessexit",
    "ifeo",
    "__eventfilter",
    "commandlineeventconsumer",
];

const DUMP_CORE_MODIFIED_MEMORY_MARKERS: &[&str] = &[
    "inline hook",
    "trampoline",
    "detour",
    "patched",
    "patch",
    "checksum mismatch",
    "code cave",
    "modified memory",
    "guard page",
    "nop nop",
    "jmp ",
];

const DUMP_CORE_TRUSTED_DLL_DIRS: &[&str] = &[
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\program files\\",
    "\\program files (x86)\\",
];

const DUMP_CORE_SUSPICIOUS_DLL_PATH_MARKERS: &[&str] = &[
    "\\temp\\",
    "\\users\\public\\",
    "\\recycle.bin\\",
    "\\windows\\tasks\\",
];

const DUMP_CORE_NETWORK_CONTEXT_MARKERS: &[&str] = &[
    "tcp",
    "udp",
    "socket",
    "connect",
    "listen",
    "accept",
    "bind",
    "send",
    "recv",
    "proxy",
    "rdp",
    "websocket",
    "ws://",
    "wss://",
    "netstat",
];

const DUMP_CORE_SUSPICIOUS_DOWNLOAD_MARKERS: &[&str] = &[
    "download?key=",
    "invoke-webrequest",
    "invoke-restmethod",
    "powershell -enc",
    "powershell -encodedcommand",
    "downloadstring",
    "downloadfile",
    " -outfile ",
];

const DUMP_CORE_TRUSTED_NETWORK_HOSTS: &[&str] = &[
    "microsoft.com",
    "windowsupdate.com",
    "github.com",
    "githubusercontent.com",
    "githubassets.com",
    "chatgpt.com",
    "openai.com",
    "youtube.com",
    "google.com",
    "googleusercontent.com",
    "gstatic.com",
    "cloudflare.com",
    "mozilla.org",
    "yandex.ru",
    "yandex.com",
    "yandex.net",
    "vk.com",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "steamcommunity.com",
    "steampowered.com",
    "cdn.discordapp.com",
];

const DUMP_CORE_NOISE_MARKERS: &[&str] = &[
    "\"type\":\"commandexecution\"",
    "\"type\":\"reasoning\"",
    "\\\"type\\\":\\\"commandexecution\\\"",
    "\\\"type\\\":\\\"reasoning\\\"",
    "\"tool_uses\"",
    "\"commandactions\"",
    "\"aggregatedoutput\"",
    "\"conversationid\"",
    "\"turn_trace_id\"",
    "\"request_id\"",
    "diff --git",
    "@@ -",
    "createelement(\"svg\"",
    "<x:xmpmeta",
    "xmlns:rdf=",
    "<?xpacket",
    "\\u001b[",
];

const DUMP_CORE_MARKUP_NOISE_MARKERS: &[&str] = &[
    "class=\"btn",
    "target=\"_blank\"",
    "aria-label=\"toggle",
    "id=\"themebtn\"",
    "id=\"pagestringsbtn\"",
    "id=\"pagedumpbtn\"",
    "residence screenshare",
];

const DUMP_CORE_SUSPICIOUS_DLL_NAME_MARKERS: &[&str] = &[
    "inject",
    "manualmap",
    "hollow",
    "hook",
    "spoof",
    "bypass",
    "cheat",
    "mapper",
    "xenos",
    "kdmapper",
    "processhacker",
];

const DUMP_CORE_BENIGN_DRIVER_MARKERS: &[&str] = &["winpmem", "dumpit", "av", "defender"];
const DUMP_CORE_BENIGN_DLL_PATH_MARKERS: &[&str] = &[
    "\\appdata\\local\\temp\\roslyn\\analyzerassemblyloader\\",
    "\\appdata\\local\\temp\\_mei",
    "\\appdata\\local\\discord\\app-",
];
const DUMP_CORE_BENIGN_DLL_NAME_MARKERS: &[&str] = &[
    "microsoft.codeanalysis.",
    "discordhook.dll",
    "discordhook64.dll",
    "discord_overlay_sdk_",
    "msvcp140.dll",
    "msvcp140_codecvt_ids.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "ucrtbase.dll",
    "libcrypto-1_1.dll",
    "libssl-1_1.dll",
    "libffi-7.dll",
    "python38.dll",
    "python39.dll",
    "python310.dll",
    "python311.dll",
    "python312.dll",
    "python313.dll",
    "binary2strings.cp",
];

const DUMP_CORE_SIGNAL_COMDLG_MARKERS: &[&str] = &["opensavepidlmru", "lastvisitedpidlmru"];
const DUMP_CORE_SIGNAL_MRU_MARKERS: &[&str] = &["typedpaths", "wordwheelquery", "runmru"];
const DUMP_CORE_SIGNAL_PROXY_MARKERS: &[&str] = &["proxyenable", "proxyserver", "autoconfigurl"];
const DUMP_CORE_PROXY_TUNNEL_MARKERS: &[&str] = &[
    "socks5",
    "socks4",
    "socks://",
    "tun2socks",
    "tun-in",
    "wintun",
    "sing-box",
    "v2ray",
    "xray",
    "clash",
    "nekoray",
    "proxifier",
    "proxychains",
];
const DUMP_CORE_PROXY_LOCAL_ENDPOINT_MARKERS: &[&str] = &[
    "127.0.0.1:",
    "localhost:",
    "::1",
    "0.0.0.0:",
    "socks5://127.0.0.1",
    "http://127.0.0.1",
];
const DUMP_CORE_PROXY_FALSE_POSITIVE_MARKERS: &[&str] = &["safe mode", "safemode", "faker"];
const DUMP_CORE_PROXY_LOCAL_PORTS: &[u16] =
    &[1080, 10808, 10809, 2080, 2081, 3128, 7890, 7891, 9050, 9090];
const DUMP_CORE_SIGNAL_TLS_MARKERS: &[&str] = &[
    "https://",
    "tls",
    "ssl",
    "x509",
    "certificate",
    "encrypted",
];
const DUMP_CORE_SIGNAL_SEARCH_MARKERS: &[&str] = &[
    "windows.edb",
    "searchindexer",
    "windows search",
    "search-ms",
];
const DUMP_CORE_SIGNAL_THUMBCACHE_MARKERS: &[&str] =
    &["thumbcache", "iconcache", "thumbs.db"];

const DUMP_CORE_EVENT_MARKERS: &[&str] = &[
    "eventid=4624",
    "eventid=4625",
    "eventid=4648",
    "eventid=4634",
    "eventid=4688",
    "eventid=4672",
    "eventid=7045",
    "eventid=6005",
    "eventid=6006",
    "taskscheduler/operational",
    "security.evtx",
    "system.evtx",
];

const DUMP_CORE_MINECRAFT_MARKERS: &[&str] = &[
    "minecraft",
    ".minecraft",
    "javaw.exe",
    "lunarclient",
    "badlion",
    "feather",
    "meteorclient",
    "fabric-loader",
    "forge",
    "autoclicker",
    "killaura",
];
const DUMP_CORE_MINECRAFT_CHEAT_MARKERS: &[&str] = &[
    "liquidbounce",
    "meteorclient",
    "wurst",
    "impact client",
    "future client",
    "baritone",
    "forgehax",
    "javaagent",
    "authlib-injector",
    "clicker",
    "reach",
    "velocity",
    "autoclicker",
];
const DUMP_CORE_BENIGN_KNOWN_DLLS: &[&str] = &[
    "\\knowndlls\\ntdll.dll",
    "\\knowndlls\\kernel32.dll",
    "\\knowndlls\\kernelbase.dll",
    "\\knowndlls\\user32.dll",
    "\\knowndlls\\gdi32.dll",
    "\\knowndlls\\advapi32.dll",
    "\\knowndlls\\ucrtbase.dll",
    "\\knowndlls\\sechost.dll",
];

const DUMP_CORE_PERSISTENCE_MARKERS: &[&str] = &[
    "wmi event subscription",
    "__eventfilter",
    "__filtertoconsumerbinding",
    "commandlineeventconsumer",
    "ifeo",
    "silentprocessexit",
    "appinit_dlls",
    "knowndlls",
    "currentversion\\run",
    "currentversion\\runonce",
];

const DUMP_CORE_SUSPICIOUS_PORTS: &[u16] = &[1337, 2222, 31337, 4444, 6666, 7777, 8081, 9001];

static DUMP_CORE_IP_PORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:\d{1,3}\.){3}\d{1,3}:(\d{2,5})\b").expect("dump core ip:port")
});
static DUMP_CORE_IP_PORT_FULL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b").expect("dump core ip:port full")
});
static DUMP_CORE_HOST_PORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9][a-z0-9.-]{1,252}\.[a-z]{2,63}:(\d{2,5})\b")
        .expect("dump core host:port")
});
static DUMP_CORE_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:[a-z]:\\|\\\\\?\\|\\+device\\+harddiskvolume\s*\d+(?:\s+[a-z0-9]+)?\s*\\)[^\r\n"'<>|]{2,520}"#,
    )
    .expect("dump core path")
});
static DUMP_CORE_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:https?|wss?|ftp)://[^\s"'<>`]+"#).expect("dump core url")
});
static DUMP_CORE_COMMAND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:cmd(?:\.exe)?\s+/[ck]|powershell(?:\.exe)?\b|pwsh(?:\.exe)?\b|wmic\b|reg\s+(?:add|delete|query)\b|netsh\b|schtasks\b|sc\s+(?:create|config|start|stop)\b|rundll32\b|regsvr32\b|mshta\b|wscript\b|cscript\b)"#,
    )
    .expect("dump core command")
});
static DUMP_CORE_EVENT_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\beventid\s*[:=]\s*(\d{4})\b").expect("event id"));
static DUMP_CORE_LOGON_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\blogonid\s*[:=]\s*(0x[0-9a-f]+|\d+)\b").expect("logon id")
});
static DUMP_CORE_PROCESS_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:process path:\s*|app=)\s*"?([a-z]:\\[^"\r\n|]{1,420}?\.exe)\b"#)
        .expect("process path")
});
static DUMP_CORE_EXE_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)([a-z]:\\[^"\r\n|]{1,420}?\.exe)\b"#).expect("exe path")
});
static DUMP_CORE_TS_BUCKET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(20\d{2}-\d{2}-\d{2})[ t](\d{2}):(\d{2})").expect("ts bucket")
});
static DUMP_CORE_TS_SLASH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(20\d{2})/(\d{2})/(\d{2})-(\d{2}):(\d{2})").expect("ts slash")
});
static DUMP_CORE_TS_TZ_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[+-]\d{4}\s+(20\d{2}-\d{2}-\d{2})\s+(\d{2}):(\d{2})")
        .expect("ts tz prefix")
});
static DUMP_CORE_TS_DMY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{2})\.(\d{2})\.(20\d{2})\s+(\d{2}):(\d{2})").expect("ts dmy")
});
static DUMP_CORE_TS_FILESTAMP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(20\d{2}-\d{2}-\d{2})[_-](\d{2})[-:](\d{2})(?:[-:]\d{2})?\b")
        .expect("ts filestamp")
});
static DUMP_CORE_DOS_DRIVE_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\\(?:\?\?|global\?\?)\\\s*([a-z])\s*:\s*\\*"#)
        .expect("dos drive prefix")
});
static DUMP_CORE_DOS_DRIVE_PREFIX_ALT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\\\\\?\\\s*([a-z])\s*:\s*\\*"#).expect("dos drive prefix alt")
});
static DUMP_CORE_DEVICE_VOLUME_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\\+device\\+harddiskvolume\s*(\d+)(?:\s*\\?\s*\d+)?(?:\s+[a-z0-9]+)?\s*\\*"#,
    )
    .expect("device volume prefix")
});

#[derive(Clone, Copy)]
struct DumpCoreChunkPlan {
    read_start: u64,
    emit_start: u64,
    emit_end: u64,
}

#[derive(Clone, Copy, Debug)]
struct DumpCoreSegment {
    file_offset: u64,
    size: u64,
    virtual_base: u64,
}

#[derive(Clone, Copy, Debug)]
struct MinidumpDirectoryEntry {
    stream_type: u32,
    data_size: u32,
    rva: u32,
}

#[derive(Default)]
struct MinidumpLayout {
    rows: Vec<String>,
    segments: Vec<DumpCoreSegment>,
    modules: Vec<String>,
    unloaded_modules: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct MemoryOrbitReport {
    enabled: bool,
    engine_name: String,
    runner_label: String,
    dumps_scanned: usize,
    plugins_ok: usize,
    plugin_errors: BTreeSet<String>,
    open_files_or_sockets: BTreeSet<String>,
    command_buffers: BTreeSet<String>,
    hidden_or_terminated_processes: BTreeSet<String>,
    shell_command_history: BTreeSet<String>,
    network_artifacts: BTreeSet<String>,
    suspicious_connections: BTreeSet<String>,
    injected_code_hits: BTreeSet<String>,
    suspicious_dll_hits: BTreeSet<String>,
    modified_memory_regions: BTreeSet<String>,
    event_correlations: BTreeSet<String>,
    lolbin_network_scores: BTreeSet<String>,
    javaw_betatest: BTreeSet<String>,
    proxy_bypass_hits: BTreeSet<String>,
    risk_verdicts: BTreeSet<String>,
    notes: BTreeSet<String>,
}

#[derive(Default)]
struct DumpCoreScan {
    open_files_or_sockets: BTreeSet<String>,
    command_buffers: BTreeSet<String>,
    hidden_or_terminated_processes: BTreeSet<String>,
    shell_command_history: BTreeSet<String>,
    network_artifacts: BTreeSet<String>,
    suspicious_connections: BTreeSet<String>,
    injected_code_hits: BTreeSet<String>,
    suspicious_dll_hits: BTreeSet<String>,
    modified_memory_regions: BTreeSet<String>,
    javaw_betatest: BTreeSet<String>,
    proxy_bypass_hits: BTreeSet<String>,
    notes: BTreeSet<String>,
    ascii_runs: usize,
    utf16_runs: usize,
    accepted_rows: usize,
    segments_scanned: usize,
}

impl MemoryOrbitReport {
    fn disabled() -> Self {
        let mut out = Self {
            enabled: false,
            engine_name: "Dump core".to_string(),
            runner_label: "Built-in dump scanner (disabled)".to_string(),
            ..Default::default()
        };
        out.notes
            .insert("Dump core engine was disabled by user option.".to_string());
        out
    }
}

fn rows_with_default(rows: &BTreeSet<String>, default_row: &str) -> BTreeSet<String> {
    if rows.is_empty() {
        let mut out = BTreeSet::new();
        out.insert(default_row.to_string());
        out
    } else {
        rows.clone()
    }
}

fn finalize_dump_core_report(report: &mut MemoryOrbitReport, lang: UiLang) {
    report.network_artifacts = dedupe_network_rows(&report.network_artifacts);
    report.suspicious_connections = dedupe_network_rows(&report.suspicious_connections);
    report.event_correlations = build_event_correlations(report);
    report.lolbin_network_scores = build_lolbin_network_scores(report);
    report.javaw_betatest = enrich_javaw_betatest_rows(&report.javaw_betatest);
    report.proxy_bypass_hits = dedupe_network_rows(&report.proxy_bypass_hits);
    report.risk_verdicts = build_risk_verdicts(report, lang);
}

fn extract_row_payload(row: &str) -> &str {
    if let Some(first) = row.find("] [") {
        let rest = &row[first + 3..];
        if let Some(second) = rest.find("] ") {
            return &rest[second + 2..];
        }
    }
    row
}

fn extract_row_endpoint_port(row: &str) -> Option<(String, u16)> {
    let payload = extract_row_payload(row);
    if let Some((ip, port)) = extract_ip_and_port(payload) {
        return Some((ip.to_ascii_lowercase(), port));
    }
    if let Some(url) = extract_first_url(payload)
        && let Some(host) = extract_url_host(url)
    {
        let host_lc = host.to_ascii_lowercase();
        let port = parse_url_port(url).unwrap_or(if url.starts_with("https://") || url.starts_with("wss://") {
            443
        } else {
            80
        });
        return Some((host_lc, port));
    }
    None
}

fn parse_url_port(url: &str) -> Option<u16> {
    let marker = "://";
    let scheme_end = url.find(marker)?;
    let host_start = scheme_end + marker.len();
    let tail = &url[host_start..];
    let host_port = tail
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    let (_, port_raw) = host_port.rsplit_once(':')?;
    port_raw.parse::<u16>().ok()
}

fn extract_row_process_hint(row: &str) -> String {
    let payload = extract_row_payload(row);
    if let Some(cap) = DUMP_CORE_PROCESS_PATH_RE.captures(payload)
        && let Some(path) = cap.get(1).map(|m| m.as_str())
    {
        return path.to_ascii_lowercase();
    }
    if let Some(cap) = DUMP_CORE_EXE_PATH_RE.captures(payload)
        && let Some(path) = cap.get(1).map(|m| m.as_str())
    {
        return path.to_ascii_lowercase();
    }
    "unknown".to_string()
}

fn extract_time_bucket_from_text(text: &str) -> Option<String> {
    if let Some(cap) = DUMP_CORE_TS_BUCKET_RE.captures(text) {
        let d = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        let h = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
        let m = cap.get(3).map(|m| m.as_str()).unwrap_or_default();
        if !d.is_empty() && !h.is_empty() && !m.is_empty() {
            return Some(format!("{d} {h}:{m}"));
        }
    }
    if let Some(cap) = DUMP_CORE_TS_SLASH_RE.captures(text)
    {
        let y = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        let mo = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
        let d = cap.get(3).map(|m| m.as_str()).unwrap_or_default();
        let h = cap.get(4).map(|m| m.as_str()).unwrap_or_default();
        let mi = cap.get(5).map(|m| m.as_str()).unwrap_or_default();
        if !y.is_empty() {
            return Some(format!("{y}-{mo}-{d} {h}:{mi}"));
        }
    }
    if let Some(cap) = DUMP_CORE_TS_TZ_PREFIX_RE.captures(text) {
        let d = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        let h = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
        let mi = cap.get(3).map(|m| m.as_str()).unwrap_or_default();
        if !d.is_empty() && !h.is_empty() && !mi.is_empty() {
            return Some(format!("{d} {h}:{mi}"));
        }
    }
    if let Some(cap) = DUMP_CORE_TS_DMY_RE.captures(text) {
        let dd = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        let mm = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
        let yyyy = cap.get(3).map(|m| m.as_str()).unwrap_or_default();
        let hh = cap.get(4).map(|m| m.as_str()).unwrap_or_default();
        let mi = cap.get(5).map(|m| m.as_str()).unwrap_or_default();
        if !yyyy.is_empty() {
            return Some(format!("{yyyy}-{mm}-{dd} {hh}:{mi}"));
        }
    }
    if let Some(cap) = DUMP_CORE_TS_FILESTAMP_RE.captures(text) {
        let d = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        let h = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
        let mi = cap.get(3).map(|m| m.as_str()).unwrap_or_default();
        if !d.is_empty() && !h.is_empty() && !mi.is_empty() {
            return Some(format!("{d} {h}:{mi}"));
        }
    }
    None
}

fn extract_row_time_bucket(row: &str) -> String {
    let payload = extract_row_payload(row);
    if let Some(bucket) = extract_time_bucket_from_text(payload) {
        return bucket;
    }
    if let Some(bucket) = extract_time_bucket_from_text(row) {
        return bucket;
    }
    "n/a".to_string()
}

fn dedupe_network_rows(rows: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut seen = HashSet::<String>::new();
    for row in rows {
        if let Some((endpoint, port)) = extract_row_endpoint_port(row) {
            let process = extract_row_process_hint(row);
            let bucket = extract_row_time_bucket(row);
            let key = if bucket == "n/a" {
                format!("{process}|{endpoint}|{port}")
            } else {
                format!("{process}|{endpoint}|{port}|{bucket}")
            };
            if !seen.insert(key) {
                continue;
            }
        }
        capped_insert(&mut out, row.clone(), DUMP_CORE_LIMIT);
    }
    out
}

fn build_event_correlations(report: &MemoryOrbitReport) -> BTreeSet<String> {
    #[derive(Clone)]
    struct EvRow {
        id: u32,
        logon: String,
        bucket: String,
        row: String,
        has_commandline: bool,
    }

    let mut auth_by_logon: HashMap<String, Vec<EvRow>> = HashMap::new();
    let mut process_rows = Vec::<EvRow>::new();
    let sources = report
        .notes
        .iter()
        .chain(report.command_buffers.iter())
        .chain(report.shell_command_history.iter())
        .chain(report.network_artifacts.iter());

    for row in sources {
        let payload = extract_row_payload(row);
        let lower = payload.to_ascii_lowercase();
        if !lower.contains("eventid") {
            continue;
        }
        let Some(ev_cap) = DUMP_CORE_EVENT_ID_RE.captures(payload) else {
            continue;
        };
        let Some(ev_raw) = ev_cap.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Ok(event_id) = ev_raw.parse::<u32>() else {
            continue;
        };
        if ![4624_u32, 4625, 4648, 4672, 4688].contains(&event_id) {
            continue;
        }
        let Some(logon_cap) = DUMP_CORE_LOGON_ID_RE.captures(payload) else {
            continue;
        };
        let Some(logon_id) = logon_cap.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let ev = EvRow {
            id: event_id,
            logon: logon_id.to_ascii_lowercase(),
            bucket: extract_row_time_bucket(payload),
            row: payload.to_string(),
            has_commandline: lower.contains("commandline"),
        };
        if event_id == 4688 {
            process_rows.push(ev);
        } else {
            auth_by_logon.entry(ev.logon.clone()).or_default().push(ev);
        }
    }

    let mut out = BTreeSet::new();
    for proc_ev in process_rows {
        if !proc_ev.has_commandline || proc_ev.bucket == "n/a" {
            continue;
        }
        let Some(auth_rows) = auth_by_logon.get(&proc_ev.logon) else {
            continue;
        };
        let mut matched = Vec::<u32>::new();
        for a in auth_rows {
            if a.bucket != "n/a" && a.bucket == proc_ev.bucket {
                matched.push(a.id);
            }
        }
        if matched.is_empty() {
            continue;
        }
        matched.sort_unstable();
        matched.dedup();
        let cmd_hint = extract_command_hint(&proc_ev.row);
        let process_hint = extract_row_process_hint(&proc_ev.row);
        let auth_str = matched
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        capped_insert(
            &mut out,
            format!(
                "[event-corr] logonid={} bucket={} process_event=4688 auth_events={} process={} command={}",
                proc_ev.logon,
                proc_ev.bucket,
                auth_str,
                process_hint,
                cmd_hint
            ),
            DUMP_CORE_LIMIT,
        );
    }
    out
}

fn extract_command_hint(row: &str) -> String {
    let lower = row.to_ascii_lowercase();
    if let Some(idx) = lower.find("commandline") {
        let snippet = row.get(idx..).unwrap_or(row);
        return snippet.chars().take(140).collect::<String>();
    }
    row.chars().take(140).collect::<String>()
}

fn build_lolbin_network_scores(report: &MemoryOrbitReport) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut seen = HashSet::<String>::new();
    for row in report
        .command_buffers
        .iter()
        .chain(report.shell_command_history.iter())
    {
        let payload = extract_row_payload(row);
        let lower = payload.to_ascii_lowercase();
        let marker = if lower.contains("powershell -enc")
            || lower.contains("powershell -encodedcommand")
        {
            Some("powershell -enc")
        } else if lower.contains("pwsh -enc") {
            Some("pwsh -enc")
        } else if lower.contains("wmic process call create") {
            Some("wmic process call create")
        } else if lower.contains("cmd.exe /c") {
            Some("cmd.exe /c")
        } else if has_token_lc(&lower, "mshta") {
            Some("mshta")
        } else if has_token_lc(&lower, "rundll32") {
            Some("rundll32")
        } else if has_token_lc(&lower, "regsvr32") {
            Some("regsvr32")
        } else {
            DUMP_CORE_LOLBIN_MARKERS
                .iter()
                .find(|m| lower.contains(**m))
                .copied()
        };
        let Some(marker) = marker else {
            continue;
        };
        let has_network_context = contains_any(&lower, DUMP_CORE_LOLBIN_NETWORK_MARKERS)
            || DUMP_CORE_URL_RE.is_match(payload)
            || DUMP_CORE_IP_PORT_RE.is_match(payload)
            || DUMP_CORE_HOST_PORT_RE.is_match(payload);
        if !has_network_context {
            continue;
        }
        let endpoint_opt = extract_row_endpoint_port(payload);
        if endpoint_opt.is_none() {
            continue;
        }
        let mut score = 2_i32;
        if lower.contains(" -enc") || lower.contains("encodedcommand") {
            score += 2;
        }
        if contains_any(&lower, DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS) {
            score += 2;
        }
        if DUMP_CORE_URL_RE.is_match(payload)
            || DUMP_CORE_IP_PORT_RE.is_match(payload)
            || DUMP_CORE_HOST_PORT_RE.is_match(payload)
        {
            score += 1;
        }
        let level = if score >= 5 { "high" } else { "medium" };
        let endpoint = endpoint_opt
            .map(|(e, p)| format!("{e}:{p}"))
            .unwrap_or_else(|| "n/a".to_string());
        let process = extract_row_process_hint(payload);
        let bucket = extract_row_time_bucket(payload);
        let key = format!("{marker}|{process}|{endpoint}|{bucket}");
        if !seen.insert(key) {
            continue;
        }
        let clipped = payload.chars().take(220).collect::<String>();
        capped_insert(
            &mut out,
            format!(
                "[lolbin:{level}] marker={marker} process={process} endpoint={endpoint} bucket={bucket} detail={clipped}"
            ),
            DUMP_CORE_LIMIT,
        );
    }
    out
}

fn enrich_javaw_betatest_rows(rows: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for row in rows {
        let payload = extract_row_payload(row);
        let lower = payload.to_ascii_lowercase();
        let mut reasons = Vec::<&str>::new();
        if lower.contains("writeprocessmemory") {
            reasons.push("WriteProcessMemory");
        }
        if lower.contains("createremotethread") || lower.contains("ntcreatethreadex") {
            reasons.push("RemoteThread");
        }
        if lower.contains("manualmap") {
            reasons.push("ManualMap");
        }
        if lower.contains("queueuserapc") {
            reasons.push("QueueUserAPC");
        }
        if lower.contains("shellcode") {
            reasons.push("Shellcode");
        }
        if reasons.is_empty() {
            reasons.push("Behavioral signal");
        }
        capped_insert(
            &mut out,
            format!(
                "{} reason={} detail={}",
                row,
                reasons.join("+"),
                payload.chars().take(220).collect::<String>()
            ),
            DUMP_CORE_BETATEST_LIMIT,
        );
    }
    out
}

fn build_risk_verdicts(report: &MemoryOrbitReport, lang: UiLang) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let injected = report.injected_code_hits.len();
    let dll = report.suspicious_dll_hits.len();
    let net = report.suspicious_connections.len();
    let lolbin = report.lolbin_network_scores.len();
    let javaw = report.javaw_betatest.len();
    let proxy_bypass = report.proxy_bypass_hits.len();
    let corr = report.event_correlations.len();

    let high_score = injected * 4 + javaw * 3 + net * 3 + dll * 2 + lolbin * 2 + proxy_bypass * 4;
    let medium_score = corr * 2 + report.network_artifacts.len() + report.modified_memory_regions.len();
    let (verdict, confidence, why) =
        if proxy_bypass > 0 && (javaw > 0 || net > 0) {
            (
                "bypass",
                95,
                "high-confidence local proxy/tunnel bypass context was detected",
            )
        } else if injected > 0 && (javaw > 0 || net > 0 || dll > 0) {
        (
            "cheat",
            95,
            "multi-signal evidence: injection + network/process artifacts",
        )
    } else if high_score >= 8 || (net > 0 && lolbin > 0) {
        (
            "suspicious",
            84,
            "high-risk behavior with execution/network correlation",
        )
    } else if medium_score >= 4 {
        ("suspicious", 72, "behavioral artifacts require manual review")
    } else {
        ("clean", 66, "no strong malicious correlation was detected")
    };

    let verdict_line = match lang {
        UiLang::Ru => format!(
            "[risk-verdict] verdict={} confidence={}%% reason={}",
            match verdict {
                "bypass" => "bypass",
                "cheat" => "чит",
                "suspicious" => "подозрительно",
                _ => "не чит",
            },
            confidence,
            match verdict {
                "bypass" => {
                    "обнаружено локальное проксирование/туннелирование с контекстом Minecraft"
                }
                "cheat" => "обнаружены множественные сильные сигналы внедрения/связи",
                "suspicious" => "обнаружены высокорисковые поведенческие сигналы",
                _ => "сильной корреляции вредоносного поведения не найдено",
            }
        ),
        UiLang::En => format!(
            "[risk-verdict] verdict={} confidence={}%% reason={}",
            verdict, confidence, why
        ),
    };
    capped_insert(&mut out, verdict_line, DUMP_CORE_VERDICT_LIMIT);
    capped_insert(
        &mut out,
        format!(
            "[risk-score] injected={} javaw={} suspicious_network={} suspicious_dll={} lolbin={} proxy_bypass={} event_corr={}",
            injected, javaw, net, dll, lolbin, proxy_bypass, corr
        ),
        DUMP_CORE_VERDICT_LIMIT,
    );
    for row in report.proxy_bypass_hits.iter().take(8) {
        capped_insert(
            &mut out,
            format!("[risk-evidence] {}", extract_row_payload(row)),
            DUMP_CORE_VERDICT_LIMIT,
        );
    }
    for row in report
        .javaw_betatest
        .iter()
        .take(6)
        .chain(report.lolbin_network_scores.iter().take(6))
        .chain(report.suspicious_connections.iter().take(6))
    {
        capped_insert(
            &mut out,
            format!("[risk-evidence] {}", extract_row_payload(row)),
            DUMP_CORE_VERDICT_LIMIT,
        );
    }
    out
}

fn run_memory_orbit_engine(
    dmp_sources: &[PathBuf],
    results: &Path,
    lang: UiLang,
    fast_inputs_by_source: &HashMap<PathBuf, PathBuf>,
) -> io::Result<MemoryOrbitReport> {
    let out_dir = results.join("dumpcore");
    fs::create_dir_all(&out_dir)?;

    let mut report = MemoryOrbitReport {
        enabled: true,
        engine_name: "Dump core".to_string(),
        runner_label: "Built-in parallel artifact scanner".to_string(),
        ..Default::default()
    };

    let mut unique_sources = dmp_sources.to_vec();
    sort_dedupe_paths(&mut unique_sources);

    if unique_sources.is_empty() {
        report.notes.insert(
            tr(
                lang,
                "DMP не найден: Dump core пропущен.",
                "No DMP sources found: Dump core was skipped.",
            )
            .to_string(),
        );
        persist_dump_core_outputs(&report, &out_dir)?;
        return Ok(report);
    }

    let workers = choose_dump_core_file_workers(unique_sources.len());
    log_info(&format!(
        "{}: {}",
        tr(lang, "Потоки Dump core", "Dump core workers"),
        workers
    ));

    let cursor = AtomicUsize::new(0);
    let scans = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let cursor_ref = &cursor;
            let sources = &unique_sources;
            handles.push(scope.spawn(move || {
                let mut local = Vec::new();
                loop {
                    let idx = cursor_ref.fetch_add(1, Ordering::Relaxed);
                    if idx >= sources.len() {
                        break;
                    }
                    let dmp = sources[idx].clone();
                    let fast_candidate = fast_inputs_by_source
                        .get(&dmp)
                        .cloned()
                        .filter(|p| {
                            p.is_file() && fs::metadata(p).map(|m| m.len()).unwrap_or(0) > 0
                        });
                    if let Some(prepared_txt) = fast_candidate
                        && should_use_dump_core_prepared_text_mode()
                    {
                        local.push((dmp.clone(), scan_dump_core_prepared_text(&prepared_txt, &dmp)));
                    } else {
                        local.push((dmp.clone(), scan_dump_core_single(&dmp)));
                    }
                }
                local
            }));
        }

        let mut combined = Vec::new();
        for handle in handles {
            combined.extend(handle.join().unwrap_or_default());
        }
        combined
    });

    let mut ok_plugins = 0usize;
    for (dmp, scanned) in scans {
        match scanned {
            Ok(scan) => {
                report.dumps_scanned += 1;
                ok_plugins += 10;
                merge_dump_core_scan(&mut report, &dmp, scan);
            }
            Err(err) => {
                report
                    .plugin_errors
                    .insert(format!("{} | {}", dmp.display(), err));
            }
        }
    }
    report.plugins_ok = ok_plugins;

    if report.dumps_scanned == 0 {
        report.notes.insert(
            tr(
                lang,
                "Dump core: ни один дамп не удалось обработать.",
                "Dump core: no dump could be processed.",
            )
            .to_string(),
        );
    }

    finalize_dump_core_report(&mut report, lang);
    persist_dump_core_outputs(&report, &out_dir)?;
    Ok(report)
}

fn persist_dump_core_outputs(report: &MemoryOrbitReport, out_dir: &Path) -> io::Result<()> {
    write_list(
        &out_dir.join("open_files_sockets.txt"),
        &rows_with_default(
            &report.open_files_or_sockets,
            "No open file/socket artifacts were collected",
        ),
    )?;
    write_list(
        &out_dir.join("command_buffers.txt"),
        &rows_with_default(
            &report.command_buffers,
            "No command/input-output buffers were collected",
        ),
    )?;
    write_list(
        &out_dir.join("hidden_processes.txt"),
        &rows_with_default(
            &report.hidden_or_terminated_processes,
            "No hidden/terminated process artifacts were detected",
        ),
    )?;
    write_list(
        &out_dir.join("shell_history.txt"),
        &rows_with_default(
            &report.shell_command_history,
            "No shell command history artifacts were collected",
        ),
    )?;
    write_list(
        &out_dir.join("network_artifacts.txt"),
        &rows_with_default(
            &report.network_artifacts,
            "No network artifacts were collected",
        ),
    )?;
    write_list(
        &out_dir.join("suspicious_connections.txt"),
        &rows_with_default(
            &report.suspicious_connections,
            "No suspicious network connections were detected",
        ),
    )?;
    write_list(
        &out_dir.join("injected_code.txt"),
        &rows_with_default(
            &report.injected_code_hits,
            "No injected-code artifacts were detected",
        ),
    )?;
    write_list(
        &out_dir.join("suspicious_dll.txt"),
        &rows_with_default(
            &report.suspicious_dll_hits,
            "No suspicious DLL artifacts were detected",
        ),
    )?;
    write_list(
        &out_dir.join("modified_memory_regions.txt"),
        &rows_with_default(
            &report.modified_memory_regions,
            "No modified memory regions were detected",
        ),
    )?;
    write_list(
        &out_dir.join("event_correlations.txt"),
        &rows_with_default(
            &report.event_correlations,
            "No event correlation artifacts were detected",
        ),
    )?;
    write_list(
        &out_dir.join("lolbin_abuse.txt"),
        &rows_with_default(
            &report.lolbin_network_scores,
            "No LOLBIN+network abuse artifacts were detected",
        ),
    )?;
    write_list(
        &out_dir.join("javaw_betatest.txt"),
        &rows_with_default(
            &report.javaw_betatest,
            "No javaw.exe betatest artifacts were detected",
        ),
    )?;
    write_list(
        &out_dir.join("proxy_bypass.txt"),
        &rows_with_default(
            &report.proxy_bypass_hits,
            "No local proxy/tunnel bypass artifacts were detected",
        ),
    )?;
    write_list(
        &out_dir.join("risk_verdicts.txt"),
        &rows_with_default(&report.risk_verdicts, "No risk verdicts were produced"),
    )?;
    write_list(
        &out_dir.join("notes.txt"),
        &rows_with_default(&report.notes, "No dump core notes"),
    )?;
    write_list(
        &out_dir.join("plugin_errors.txt"),
        &rows_with_default(&report.plugin_errors, "No plugin execution errors"),
    )?;

    Ok(())
}

fn choose_dump_core_file_workers(file_count: usize) -> usize {
    if file_count <= 1 {
        return 1;
    }
    let cpu = available_cpu_threads();
    let budget = cpu_worker_budget_45_from_cpu(cpu);
    cpu.clamp(1, 8).min(file_count).min(budget).max(1)
}

fn should_use_dump_core_prepared_text_mode() -> bool {
    env::var("RSS_ANALYS_DUMPCORE_RAW")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(true)
}

fn scan_dump_core_prepared_text(prepared_txt: &Path, source_dmp: &Path) -> io::Result<DumpCoreScan> {
    let mut meta_scan = DumpCoreScan::default();
    capped_insert(
        &mut meta_scan.notes,
        format!(
            "[meta] prepared-text mode source={} from={}",
            prepared_txt.display(),
            source_dmp.display()
        ),
        DUMP_CORE_NOTES_LIMIT,
    );

    let file_size = fs::metadata(prepared_txt).map(|m| m.len()).unwrap_or(0);
    let workers = choose_dump_core_prepared_workers(file_size);
    if workers <= 1 {
        let file = File::open(prepared_txt)?;
        let mut reader = BufReader::with_capacity(IO_STREAM_BUFFER_BYTES, file);
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader.read_line(&mut line)?;
            if read == 0 {
                break;
            }
            analyze_dump_core_prepared_line(&line, &mut meta_scan);
            meta_scan.segments_scanned = meta_scan.segments_scanned.saturating_add(1);
        }
        return Ok(meta_scan);
    }

    let mut senders = Vec::with_capacity(workers);
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (tx, rx) = mpsc::sync_channel::<Option<String>>(2);
        senders.push(tx);
        handles.push(thread::spawn(move || {
            let mut local = DumpCoreScan::default();
            while let Ok(chunk) = rx.recv() {
                let Some(text) = chunk else {
                    break;
                };
                for raw in text.split('\n') {
                    analyze_dump_core_prepared_line(raw, &mut local);
                    local.segments_scanned = local.segments_scanned.saturating_add(1);
                }
            }
            local
        }));
    }

    let file = File::open(prepared_txt)?;
    let mut reader = BufReader::with_capacity(IO_STREAM_BUFFER_BYTES, file);
    let mut line = String::new();
    let mut chunk = String::with_capacity(DUMP_CORE_PREPARED_CHUNK_TARGET_BYTES + 8192);
    let mut rr = 0usize;
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        chunk.push_str(&line);
        if chunk.len() >= DUMP_CORE_PREPARED_CHUNK_TARGET_BYTES {
            let tx = &senders[rr % workers];
            tx.send(Some(std::mem::take(&mut chunk)))
                .map_err(|_| io::Error::other("dump core prepared worker disconnected"))?;
            rr += 1;
            chunk = String::with_capacity(DUMP_CORE_PREPARED_CHUNK_TARGET_BYTES + 8192);
        }
    }
    if !chunk.is_empty() {
        let tx = &senders[rr % workers];
        tx.send(Some(chunk))
            .map_err(|_| io::Error::other("dump core prepared worker disconnected"))?;
    }
    for tx in senders {
        let _ = tx.send(None);
    }

    for handle in handles {
        let local = handle
            .join()
            .map_err(|_| io::Error::other("dump core prepared worker panicked"))?;
        merge_dump_scan_sets(
            &mut meta_scan.open_files_or_sockets,
            &local.open_files_or_sockets,
        );
        merge_dump_scan_sets(&mut meta_scan.command_buffers, &local.command_buffers);
        merge_dump_scan_sets(
            &mut meta_scan.hidden_or_terminated_processes,
            &local.hidden_or_terminated_processes,
        );
        merge_dump_scan_sets(&mut meta_scan.shell_command_history, &local.shell_command_history);
        merge_dump_scan_sets(&mut meta_scan.network_artifacts, &local.network_artifacts);
        merge_dump_scan_sets(
            &mut meta_scan.suspicious_connections,
            &local.suspicious_connections,
        );
        merge_dump_scan_sets(&mut meta_scan.injected_code_hits, &local.injected_code_hits);
        merge_dump_scan_sets(&mut meta_scan.suspicious_dll_hits, &local.suspicious_dll_hits);
        merge_dump_scan_sets(
            &mut meta_scan.modified_memory_regions,
            &local.modified_memory_regions,
        );
        merge_dump_scan_sets(&mut meta_scan.javaw_betatest, &local.javaw_betatest);
        merge_dump_scan_notes(&mut meta_scan.notes, &local.notes);
        meta_scan.ascii_runs += local.ascii_runs;
        meta_scan.utf16_runs += local.utf16_runs;
        meta_scan.accepted_rows += local.accepted_rows;
        meta_scan.segments_scanned += local.segments_scanned;
    }

    Ok(meta_scan)
}

fn choose_dump_core_prepared_workers(file_size: u64) -> usize {
    if file_size < 6 * 1024 * 1024 {
        return 1;
    }
    let cpu = available_cpu_threads();
    let budget = cpu_worker_budget_45_from_cpu(cpu);
    cpu.clamp(2, 12).min(budget).max(1)
}

fn scan_dump_core_single(dmp: &Path) -> io::Result<DumpCoreScan> {
    let meta = fs::metadata(dmp)?;
    let file_len = meta.len();
    if file_len == 0 {
        return Err(io::Error::other("empty dump file"));
    }

    let mut scan = DumpCoreScan::default();
    scan.notes.insert(format!(
        "[meta] file={} size_mb={:.2}",
        dmp.display(),
        file_len as f64 / 1024.0 / 1024.0
    ));

    let mut segments = Vec::<DumpCoreSegment>::new();
    if let Some(layout) = parse_minidump_layout(dmp, file_len)? {
        for row in layout.rows {
            capped_insert(&mut scan.notes, format!("[header] {row}"), DUMP_CORE_NOTES_LIMIT);
        }
        apply_minidump_module_artifacts(&mut scan, &layout.modules, false);
        apply_minidump_module_artifacts(&mut scan, &layout.unloaded_modules, true);
        segments = layout.segments;
    } else {
        capped_insert(
            &mut scan.notes,
            "[header] Signature is not MDMP. Scanning as raw dump bytes.".to_string(),
            DUMP_CORE_NOTES_LIMIT,
        );
    }

    if segments.is_empty() {
        segments.push(DumpCoreSegment {
            file_offset: 0,
            size: file_len,
            virtual_base: 0,
        });
    }
    normalize_dump_core_segments(&mut segments, file_len);
    if segments.len() > DUMP_CORE_MAX_SEGMENTS {
        segments.truncate(DUMP_CORE_MAX_SEGMENTS);
        capped_insert(
            &mut scan.notes,
            format!("[meta] segments truncated to {}", DUMP_CORE_MAX_SEGMENTS),
            DUMP_CORE_NOTES_LIMIT,
        );
    }

    let total_segment_bytes = segments.iter().map(|s| s.size).sum::<u64>().max(1);
    let workers = choose_dump_core_chunk_workers(total_segment_bytes, segments.len());
    let started = Instant::now();

    let cursor = AtomicUsize::new(0);
    let mut worker_error: Option<io::Error> = None;
    let mut worker_scans = Vec::new();

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let cursor_ref = &cursor;
            let segments_ref = &segments;
            handles.push(scope.spawn(move || -> io::Result<DumpCoreScan> {
                let mut file = File::open(dmp)?;
                let mut buf = Vec::<u8>::new();
                let mut local = DumpCoreScan::default();
                loop {
                    let idx = cursor_ref.fetch_add(1, Ordering::Relaxed);
                    if idx >= segments_ref.len() {
                        break;
                    }
                    scan_dump_core_segment(&mut file, segments_ref[idx], &mut buf, &mut local)?;
                }
                Ok(local)
            }));
        }

        for handle in handles {
            match handle.join() {
                Ok(Ok(local)) => worker_scans.push(local),
                Ok(Err(err)) => {
                    if worker_error.is_none() {
                        worker_error = Some(err);
                    }
                }
                Err(_) => {
                    if worker_error.is_none() {
                        worker_error = Some(io::Error::other("dump core worker panicked"));
                    }
                }
            }
        }
    });

    if let Some(err) = worker_error {
        return Err(err);
    }

    for local in worker_scans {
        merge_dump_scan_sets(&mut scan.open_files_or_sockets, &local.open_files_or_sockets);
        merge_dump_scan_sets(&mut scan.command_buffers, &local.command_buffers);
        merge_dump_scan_sets(
            &mut scan.hidden_or_terminated_processes,
            &local.hidden_or_terminated_processes,
        );
        merge_dump_scan_sets(&mut scan.shell_command_history, &local.shell_command_history);
        merge_dump_scan_sets(&mut scan.network_artifacts, &local.network_artifacts);
        merge_dump_scan_sets(&mut scan.suspicious_connections, &local.suspicious_connections);
        merge_dump_scan_sets(&mut scan.injected_code_hits, &local.injected_code_hits);
        merge_dump_scan_sets(&mut scan.suspicious_dll_hits, &local.suspicious_dll_hits);
        merge_dump_scan_sets(&mut scan.modified_memory_regions, &local.modified_memory_regions);
        merge_dump_scan_sets(&mut scan.javaw_betatest, &local.javaw_betatest);
        merge_dump_scan_notes(&mut scan.notes, &local.notes);
        scan.ascii_runs += local.ascii_runs;
        scan.utf16_runs += local.utf16_runs;
        scan.accepted_rows += local.accepted_rows;
        scan.segments_scanned += local.segments_scanned;
    }

    capped_insert(
        &mut scan.notes,
        format!(
            "[stats] segments={} ascii_runs={} utf16_runs={} accepted_rows={} elapsed_sec={:.1}",
            scan.segments_scanned,
            scan.ascii_runs,
            scan.utf16_runs,
            scan.accepted_rows,
            started.elapsed().as_secs_f64()
        ),
        DUMP_CORE_NOTES_LIMIT,
    );

    Ok(scan)
}

fn parse_minidump_layout(dmp: &Path, file_len: u64) -> io::Result<Option<MinidumpLayout>> {
    let mut file = File::open(dmp)?;
    let mut header = [0u8; 32];
    if file.read(&mut header)? < 16 {
        return Ok(None);
    }
    if &header[0..4] != b"MDMP" {
        return Ok(None);
    }

    let mut layout = MinidumpLayout::default();
    let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let stream_count = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let stream_rva = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
    layout.rows.push("signature=MDMP".to_string());
    layout.rows.push(format!("version=0x{version:08x}"));
    layout.rows.push(format!("stream_count={stream_count}"));
    layout
        .rows
        .push(format!("stream_directory_rva=0x{stream_rva:08x}"));

    let Ok(stream_count_usize) = usize::try_from(stream_count) else {
        layout
            .rows
            .push("stream_count is too large for this platform".to_string());
        return Ok(Some(layout));
    };
    if stream_count_usize > DUMP_CORE_MAX_STREAM_COUNT {
        layout
            .rows
            .push(format!("stream_count truncated to {}", DUMP_CORE_MAX_STREAM_COUNT));
    }

    let dirs = read_minidump_directories(
        &mut file,
        stream_rva as u64,
        stream_count_usize.min(DUMP_CORE_MAX_STREAM_COUNT),
        file_len,
    )?;
    layout.rows.push(format!("streams_detected={}", dirs.len()));

    for dir in &dirs {
        match dir.stream_type {
            MINIDUMP_STREAM_MEMORY64_LIST => {
                let seg = parse_memory64_stream(&mut file, *dir, file_len)?;
                layout.segments.extend(seg);
            }
            MINIDUMP_STREAM_MEMORY_LIST => {
                let seg = parse_memory_list_stream(&mut file, *dir, file_len)?;
                layout.segments.extend(seg);
            }
            MINIDUMP_STREAM_MODULE_LIST => {
                let rows = parse_module_list_stream(&mut file, *dir, file_len)?;
                layout.modules.extend(rows);
            }
            MINIDUMP_STREAM_UNLOADED_MODULE_LIST => {
                let rows = parse_unloaded_module_stream(&mut file, *dir, file_len)?;
                layout.unloaded_modules.extend(rows);
            }
            MINIDUMP_STREAM_SYSTEM_INFO => {
                if let Some(info) = parse_system_info_stream(&mut file, *dir, file_len)? {
                    layout.rows.push(info);
                }
            }
            MINIDUMP_STREAM_HANDLE_DATA => {
                layout.rows.push("stream_handle_data=present".to_string());
            }
            MINIDUMP_STREAM_MISC_INFO => {
                if let Some(info) = parse_misc_info_stream(&mut file, *dir, file_len)? {
                    layout.rows.push(info);
                }
            }
            _ => {}
        }
    }

    if layout.modules.len() > DUMP_CORE_MAX_MODULE_ROWS {
        layout.modules.truncate(DUMP_CORE_MAX_MODULE_ROWS);
        layout
            .rows
            .push(format!("modules_truncated={}", DUMP_CORE_MAX_MODULE_ROWS));
    }
    if layout.unloaded_modules.len() > DUMP_CORE_MAX_MODULE_ROWS {
        layout.unloaded_modules.truncate(DUMP_CORE_MAX_MODULE_ROWS);
        layout
            .rows
            .push(format!("unloaded_modules_truncated={}", DUMP_CORE_MAX_MODULE_ROWS));
    }
    layout
        .rows
        .push(format!("memory_segments={}", layout.segments.len()));
    layout
        .rows
        .push(format!("modules={}", layout.modules.len()));
    layout
        .rows
        .push(format!("unloaded_modules={}", layout.unloaded_modules.len()));
    Ok(Some(layout))
}

fn read_minidump_directories(
    file: &mut File,
    directory_rva: u64,
    stream_count: usize,
    file_len: u64,
) -> io::Result<Vec<MinidumpDirectoryEntry>> {
    if stream_count == 0 {
        return Ok(Vec::new());
    }
    let bytes_needed = (stream_count as u64).saturating_mul(12);
    if !is_valid_file_range(directory_rva, bytes_needed, file_len) {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(stream_count);
    let mut buf = [0u8; 12];
    for idx in 0..stream_count {
        let off = directory_rva + (idx as u64) * 12;
        read_exact_at(file, off, &mut buf)?;
        let stream_type = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let data_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let rva = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if data_size == 0 {
            continue;
        }
        out.push(MinidumpDirectoryEntry {
            stream_type,
            data_size,
            rva,
        });
    }
    Ok(out)
}

fn parse_memory64_stream(
    file: &mut File,
    dir: MinidumpDirectoryEntry,
    file_len: u64,
) -> io::Result<Vec<DumpCoreSegment>> {
    if dir.data_size < 16 {
        return Ok(Vec::new());
    }
    let stream_off = dir.rva as u64;
    if !is_valid_file_range(stream_off, dir.data_size as u64, file_len) {
        return Ok(Vec::new());
    }

    let number_of_ranges = read_u64_at(file, stream_off)?;
    let base_rva = read_u64_at(file, stream_off + 8)?;
    let descriptor_off = stream_off + 16;
    let descriptor_bytes = number_of_ranges.saturating_mul(16);
    if !is_valid_file_range(descriptor_off, descriptor_bytes, file_len) {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut data_rva = base_rva;
    let max_rows = number_of_ranges.min(DUMP_CORE_MAX_STREAM_ROWS as u64);
    for idx in 0..max_rows {
        let off = descriptor_off + idx.saturating_mul(16);
        let start_of_memory_range = read_u64_at(file, off)?;
        let data_size = read_u64_at(file, off + 8)?;
        if data_size == 0 {
            continue;
        }
        if !is_valid_file_range(data_rva, data_size, file_len) {
            break;
        }
        out.push(DumpCoreSegment {
            file_offset: data_rva,
            size: data_size,
            virtual_base: start_of_memory_range,
        });
        let Some(next_rva) = data_rva.checked_add(data_size) else {
            break;
        };
        data_rva = next_rva;
    }
    Ok(out)
}

fn parse_memory_list_stream(
    file: &mut File,
    dir: MinidumpDirectoryEntry,
    file_len: u64,
) -> io::Result<Vec<DumpCoreSegment>> {
    if dir.data_size < 4 {
        return Ok(Vec::new());
    }
    let stream_off = dir.rva as u64;
    if !is_valid_file_range(stream_off, dir.data_size as u64, file_len) {
        return Ok(Vec::new());
    }

    let number_of_ranges = read_u32_at(file, stream_off)? as usize;
    let descriptor_off = stream_off + 4;
    let descriptor_bytes = (number_of_ranges as u64).saturating_mul(16);
    if !is_valid_file_range(descriptor_off, descriptor_bytes, file_len) {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let max_rows = number_of_ranges.min(DUMP_CORE_MAX_STREAM_ROWS);
    for idx in 0..max_rows {
        let off = descriptor_off + (idx as u64).saturating_mul(16);
        let start_of_memory_range = read_u64_at(file, off)?;
        let data_size = read_u32_at(file, off + 8)? as u64;
        let rva = read_u32_at(file, off + 12)? as u64;
        if data_size == 0 {
            continue;
        }
        if !is_valid_file_range(rva, data_size, file_len) {
            continue;
        }
        out.push(DumpCoreSegment {
            file_offset: rva,
            size: data_size,
            virtual_base: start_of_memory_range,
        });
    }
    Ok(out)
}

fn parse_module_list_stream(
    file: &mut File,
    dir: MinidumpDirectoryEntry,
    file_len: u64,
) -> io::Result<Vec<String>> {
    if dir.data_size < 4 {
        return Ok(Vec::new());
    }
    let stream_off = dir.rva as u64;
    if !is_valid_file_range(stream_off, dir.data_size as u64, file_len) {
        return Ok(Vec::new());
    }
    let number_of_modules = read_u32_at(file, stream_off)? as usize;
    let modules_off = stream_off + 4;
    let module_entry_size = 108u64;
    let max_from_stream = ((dir.data_size as u64).saturating_sub(4) / module_entry_size) as usize;
    let count = number_of_modules.min(max_from_stream).min(DUMP_CORE_MAX_MODULE_ROWS);

    let mut out = Vec::new();
    for idx in 0..count {
        let entry_off = modules_off + (idx as u64) * module_entry_size;
        if !is_valid_file_range(entry_off, module_entry_size, file_len) {
            break;
        }
        let name_rva = read_u32_at(file, entry_off + 24)?;
        if let Some(name) = read_minidump_utf16_string(file, name_rva, file_len)? {
            out.push(name);
        }
    }
    Ok(out)
}

fn parse_unloaded_module_stream(
    file: &mut File,
    dir: MinidumpDirectoryEntry,
    file_len: u64,
) -> io::Result<Vec<String>> {
    if dir.data_size < 12 {
        return Ok(Vec::new());
    }
    let stream_off = dir.rva as u64;
    if !is_valid_file_range(stream_off, dir.data_size as u64, file_len) {
        return Ok(Vec::new());
    }

    let size_of_header = read_u32_at(file, stream_off)? as u64;
    let size_of_entry = read_u32_at(file, stream_off + 4)? as u64;
    let number_of_entries = read_u32_at(file, stream_off + 8)? as usize;
    if size_of_header < 12 || size_of_entry < 24 {
        return Ok(Vec::new());
    }
    let entries_off = stream_off + size_of_header;
    let max_from_stream =
        ((dir.data_size as u64).saturating_sub(size_of_header) / size_of_entry) as usize;
    let count = number_of_entries
        .min(max_from_stream)
        .min(DUMP_CORE_MAX_MODULE_ROWS);

    let mut out = Vec::new();
    for idx in 0..count {
        let entry_off = entries_off + (idx as u64) * size_of_entry;
        if !is_valid_file_range(entry_off, size_of_entry, file_len) {
            break;
        }
        let name_rva = read_u32_at(file, entry_off + 20)?;
        if let Some(name) = read_minidump_utf16_string(file, name_rva, file_len)? {
            out.push(name);
        }
    }
    Ok(out)
}

fn parse_system_info_stream(
    file: &mut File,
    dir: MinidumpDirectoryEntry,
    file_len: u64,
) -> io::Result<Option<String>> {
    if dir.data_size < 24 {
        return Ok(None);
    }
    let off = dir.rva as u64;
    if !is_valid_file_range(off, dir.data_size as u64, file_len) {
        return Ok(None);
    }
    let arch = read_u16_at(file, off)?;
    let major = read_u32_at(file, off + 8)?;
    let minor = read_u32_at(file, off + 12)?;
    let build = read_u32_at(file, off + 16)?;
    Ok(Some(format!(
        "system_info arch={} version={}.{} build={}",
        arch, major, minor, build
    )))
}

fn parse_misc_info_stream(
    file: &mut File,
    dir: MinidumpDirectoryEntry,
    file_len: u64,
) -> io::Result<Option<String>> {
    if dir.data_size < 8 {
        return Ok(None);
    }
    let off = dir.rva as u64;
    if !is_valid_file_range(off, dir.data_size as u64, file_len) {
        return Ok(None);
    }
    let size_of_info = read_u32_at(file, off)?;
    let flags = read_u32_at(file, off + 4)?;
    if dir.data_size >= 12 {
        let process_id = read_u32_at(file, off + 8)?;
        return Ok(Some(format!(
            "misc_info size={} flags=0x{:08x} process_id={}",
            size_of_info, flags, process_id
        )));
    }
    Ok(Some(format!(
        "misc_info size={} flags=0x{:08x}",
        size_of_info, flags
    )))
}

fn read_minidump_utf16_string(
    file: &mut File,
    rva: u32,
    file_len: u64,
) -> io::Result<Option<String>> {
    if rva == 0 {
        return Ok(None);
    }
    let off = rva as u64;
    if !is_valid_file_range(off, 4, file_len) {
        return Ok(None);
    }
    let len_bytes = read_u32_at(file, off)? as u64;
    if len_bytes == 0 || len_bytes % 2 != 0 || len_bytes > 256 * 1024 {
        return Ok(None);
    }
    if !is_valid_file_range(off + 4, len_bytes, file_len) {
        return Ok(None);
    }
    let mut raw = vec![0u8; len_bytes as usize];
    read_exact_at(file, off + 4, &mut raw)?;
    let mut words = Vec::with_capacity(raw.len() / 2);
    for ch in raw.chunks_exact(2) {
        words.push(u16::from_le_bytes([ch[0], ch[1]]));
    }
    let mut text = String::from_utf16_lossy(&words);
    text = sanitize_ui_line(&text);
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(text))
}

fn read_exact_at(file: &mut File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    file.seek(std::io::SeekFrom::Start(offset))?;
    file.read_exact(buf)?;
    Ok(())
}

fn read_u16_at(file: &mut File, offset: u64) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    read_exact_at(file, offset, &mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32_at(file: &mut File, offset: u64) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    read_exact_at(file, offset, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_at(file: &mut File, offset: u64) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    read_exact_at(file, offset, &mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn is_valid_file_range(offset: u64, size: u64, file_len: u64) -> bool {
    if size == 0 {
        return false;
    }
    if offset > file_len {
        return false;
    }
    let Some(end) = offset.checked_add(size) else {
        return false;
    };
    end <= file_len
}

fn apply_minidump_module_artifacts(scan: &mut DumpCoreScan, modules: &[String], unloaded: bool) {
    for module_raw in modules {
        let Some(module_line) = normalize_dump_core_line(module_raw) else {
            continue;
        };
        let lower = module_line.to_ascii_lowercase();
        let tag = if unloaded {
            "[unloaded-module]"
        } else {
            "[module]"
        };
        if unloaded {
            capped_insert(
                &mut scan.hidden_or_terminated_processes,
                format!("{tag} {module_line}"),
                DUMP_CORE_LIMIT,
            );
        }
        if dump_core_is_suspicious_dll(&module_line, &lower) {
            capped_insert(
                &mut scan.suspicious_dll_hits,
                format!("{tag} {module_line}"),
                DUMP_CORE_LIMIT,
            );
        }
        if dump_core_is_actionable_persistence_line(&module_line, &lower) {
            capped_insert(
                &mut scan.notes,
                format!("[module-persistence] {module_line}"),
                DUMP_CORE_NOTES_LIMIT,
            );
        }
    }
}

fn normalize_dump_core_segments(segments: &mut Vec<DumpCoreSegment>, file_len: u64) {
    segments.retain(|seg| {
        seg.size > 0
            && seg.file_offset < file_len
            && seg
                .file_offset
                .checked_add(seg.size)
                .is_some_and(|end| end <= file_len)
    });
    segments.sort_by(|a, b| {
        a.file_offset
            .cmp(&b.file_offset)
            .then_with(|| a.size.cmp(&b.size))
            .then_with(|| a.virtual_base.cmp(&b.virtual_base))
    });
    segments.dedup_by(|a, b| {
        a.file_offset == b.file_offset && a.size == b.size && a.virtual_base == b.virtual_base
    });
}

fn scan_dump_core_segment(
    file: &mut File,
    segment: DumpCoreSegment,
    buf: &mut Vec<u8>,
    out: &mut DumpCoreScan,
) -> io::Result<()> {
    if segment.size == 0 {
        return Ok(());
    }
    out.segments_scanned += 1;

    let mut emit_start = 0u64;
    let overlap = DUMP_CORE_OVERLAP_BYTES as u64;
    let chunk = DUMP_CORE_CHUNK_BYTES as u64;
    while emit_start < segment.size {
        let emit_end = (emit_start + chunk).min(segment.size);
        let rel_read_start = emit_start.saturating_sub(overlap);
        let rel_read_end = (emit_end + overlap).min(segment.size);
        let read_len = rel_read_end.saturating_sub(rel_read_start);
        if read_len == 0 {
            break;
        }
        let Ok(read_len_usize) = usize::try_from(read_len) else {
            break;
        };
        let read_start = segment.file_offset + rel_read_start;
        let plan = DumpCoreChunkPlan {
            read_start,
            emit_start: segment.file_offset + emit_start,
            emit_end: segment.file_offset + emit_end,
        };

        buf.resize(read_len_usize, 0);
        file.seek(std::io::SeekFrom::Start(read_start))?;
        file.read_exact(buf)?;
        scan_dump_core_chunk(buf, plan, out);
        emit_start = emit_end;
    }
    Ok(())
}

fn choose_dump_core_chunk_workers(file_len: u64, chunk_count: usize) -> usize {
    if chunk_count <= 1 {
        return 1;
    }
    let cpu = available_cpu_threads();
    let budget = cpu_worker_budget_45_from_cpu(cpu);
    let mut workers = cpu.clamp(2, 20).min(chunk_count).min(budget);
    if file_len <= 2 * 1024 * 1024 * 1024 {
        workers = workers.min(8);
    } else if file_len <= 6 * 1024 * 1024 * 1024 {
        workers = workers.min(12);
    } else {
        workers = workers.min(16);
    }
    workers.max(1)
}

fn scan_dump_core_chunk(chunk: &[u8], plan: DumpCoreChunkPlan, out: &mut DumpCoreScan) {
    scan_dump_ascii_runs(chunk, plan, out);
    scan_dump_utf16_runs(chunk, plan, out);
}

fn scan_dump_ascii_runs(chunk: &[u8], plan: DumpCoreChunkPlan, out: &mut DumpCoreScan) {
    let mut i = 0usize;
    while i < chunk.len() {
        while i < chunk.len() && !is_dump_core_printable_ascii(chunk[i]) {
            i += 1;
        }
        let start = i;
        while i < chunk.len() && is_dump_core_printable_ascii(chunk[i]) {
            i += 1;
        }
        if i.saturating_sub(start) < DUMP_CORE_MIN_STRING_LEN {
            continue;
        }

        let abs_start = plan.read_start + start as u64;
        if abs_start < plan.emit_start || abs_start >= plan.emit_end {
            continue;
        }

        out.ascii_runs += 1;
        if let Ok(text) = std::str::from_utf8(&chunk[start..i]) {
            analyze_dump_core_line(text, out);
        }
    }
}

fn scan_dump_utf16_runs(chunk: &[u8], plan: DumpCoreChunkPlan, out: &mut DumpCoreScan) {
    let mut i = 0usize;
    while i + 1 < chunk.len() {
        if is_dump_core_printable_ascii(chunk[i]) && chunk[i + 1] == 0 {
            let start = i;
            let mut run = Vec::with_capacity(128);
            while i + 1 < chunk.len() && is_dump_core_printable_ascii(chunk[i]) && chunk[i + 1] == 0
            {
                run.push(chunk[i]);
                i += 2;
            }

            if run.len() < DUMP_CORE_MIN_STRING_LEN {
                continue;
            }

            let abs_start = plan.read_start + start as u64;
            if abs_start < plan.emit_start || abs_start >= plan.emit_end {
                continue;
            }

            out.utf16_runs += 1;
            if let Ok(text) = std::str::from_utf8(&run) {
                analyze_dump_core_line(text, out);
            }
            continue;
        }
        i += 1;
    }
}

#[inline(always)]
fn is_dump_core_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

fn analyze_dump_core_line(raw: &str, out: &mut DumpCoreScan) {
    let Some(line) = normalize_dump_core_line(raw) else {
        return;
    };

    let lower = line.to_ascii_lowercase();
    analyze_dump_core_line_normalized(&line, &lower, out);
}

fn analyze_dump_core_prepared_line(raw: &str, out: &mut DumpCoreScan) {
    let Some(line) = normalize_dump_core_line(raw) else {
        return;
    };
    let lower = line.to_ascii_lowercase();
    if !dump_core_prepared_quick_gate(&lower) {
        return;
    }
    analyze_dump_core_line_normalized(&line, &lower, out);
}

fn analyze_dump_core_line_normalized(line: &str, lower: &str, out: &mut DumpCoreScan) {
    if !dump_core_quick_interesting(&lower) {
        return;
    }
    if dump_core_is_noise_line(&line, &lower) {
        return;
    }
    if !dump_core_has_hard_indicator(&line, &lower) && !looks_human(&line) {
        return;
    }

    out.accepted_rows += 1;
    if dump_core_is_open_artifact(&line, &lower) {
        capped_insert(
            &mut out.open_files_or_sockets,
            format!("[open] {line}"),
            DUMP_CORE_OPEN_LIMIT,
        );
    }
    if dump_core_is_command_buffer(&line, &lower) {
        capped_insert(
            &mut out.command_buffers,
            format!("[buffer] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if dump_core_is_hidden_process(&line, &lower) {
        capped_insert(
            &mut out.hidden_or_terminated_processes,
            format!("[process] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if dump_core_is_shell_history(&line, &lower) {
        capped_insert(
            &mut out.shell_command_history,
            format!("[shell] {line}"),
            DUMP_CORE_LIMIT,
        );
    }

    let network = dump_core_is_network_artifact(&line, &lower);
    if network {
        capped_insert(
            &mut out.network_artifacts,
            format!("[net] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if network && dump_core_is_suspicious_connection(&line, &lower) {
        capped_insert(
            &mut out.suspicious_connections,
            format!("[susp-net] {line}"),
            DUMP_CORE_LIMIT,
        );
    }

    if dump_core_is_injected_code(&line, &lower) {
        capped_insert(
            &mut out.injected_code_hits,
            format!("[inject] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if dump_core_is_suspicious_dll(&line, &lower) {
        capped_insert(
            &mut out.suspicious_dll_hits,
            format!("[dll] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if dump_core_is_modified_memory(&lower) {
        capped_insert(
            &mut out.modified_memory_regions,
            format!("[mem] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if dump_core_is_javaw_betatest_signal(line, &lower) {
        capped_insert(
            &mut out.javaw_betatest,
            format!("[javaw-betatest] {line}"),
            DUMP_CORE_BETATEST_LIMIT,
        );
    }
    if contains_any(&lower, DUMP_CORE_EVENT_MARKERS) {
        let event_tag = dump_core_event_tag(&lower);
        capped_insert(
            &mut out.notes,
            format!("[event:{event_tag}] {line}"),
            DUMP_CORE_NOTES_LIMIT,
        );
    }
    if dump_core_is_minecraft_cheat_signal(&lower) {
        capped_insert(
            &mut out.notes,
            format!("[minecraft] {line}"),
            DUMP_CORE_NOTES_LIMIT,
        );
    }
    if contains_any(&lower, DUMP_CORE_SIGNAL_COMDLG_MARKERS) {
        if !dump_core_is_markup_noise(&lower) && !line.contains('<') && !line.contains("</") {
            capped_insert(
                &mut out.command_buffers,
                format!("[comdlg32-mru] {line}"),
                DUMP_CORE_LIMIT,
            );
        }
    }
    if contains_any(&lower, DUMP_CORE_SIGNAL_MRU_MARKERS) {
        if !dump_core_is_markup_noise(&lower) && !line.contains('<') && !line.contains("</") {
            capped_insert(
                &mut out.command_buffers,
                format!("[user-mru] {line}"),
                DUMP_CORE_LIMIT,
            );
        }
    }
    if contains_any(&lower, DUMP_CORE_SIGNAL_PROXY_MARKERS) {
        capped_insert(
            &mut out.network_artifacts,
            format!("[proxy] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if dump_core_is_proxy_bypass_signal(line, &lower) {
        capped_insert(
            &mut out.proxy_bypass_hits,
            format!("[proxy-bypass] {line}"),
            DUMP_CORE_PROXY_BYPASS_LIMIT,
        );
    }
    if dump_core_has_rdp_signal(&lower) {
        capped_insert(
            &mut out.network_artifacts,
            format!("[rdp] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if dump_core_has_websocket_signal(&line, &lower) {
        capped_insert(
            &mut out.network_artifacts,
            format!("[websocket] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if dump_core_is_actionable_https_endpoint(&line, &lower)
        && lower.contains("https://")
        && contains_any(&lower, DUMP_CORE_SIGNAL_TLS_MARKERS)
    {
        capped_insert(
            &mut out.network_artifacts,
            format!("[https-endpoint] {line}"),
            DUMP_CORE_LIMIT,
        );
    }
    if dump_core_is_actionable_search_index_line(&line, &lower) {
        capped_insert(
            &mut out.notes,
            format!("[search-index] {line}"),
            DUMP_CORE_NOTES_LIMIT,
        );
    }
    if dump_core_is_actionable_thumbcache_line(&line, &lower) {
        capped_insert(
            &mut out.notes,
            format!("[thumbcache] {line}"),
            DUMP_CORE_NOTES_LIMIT,
        );
    }
    if dump_core_is_actionable_persistence_line(&line, &lower) {
        capped_insert(
            &mut out.notes,
            format!("[persistence] {line}"),
            DUMP_CORE_NOTES_LIMIT,
        );
    }
}

fn dump_core_prepared_quick_gate(lower: &str) -> bool {
    if lower.is_empty() {
        return false;
    }
    if contains_any(lower, DUMP_CORE_OPEN_STRONG_MARKERS)
        || contains_any(lower, DUMP_CORE_COMMAND_MARKERS)
        || contains_any(lower, DUMP_CORE_HIDDEN_PROCESS_MARKERS)
        || contains_any(lower, DUMP_CORE_INJECTION_MARKERS)
        || contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_MARKERS)
        || contains_any(lower, DUMP_CORE_MODIFIED_MEMORY_MARKERS)
        || contains_any(lower, DUMP_CORE_SIGNAL_PROXY_MARKERS)
        || dump_core_has_rdp_signal(lower)
        || dump_core_has_websocket_signal("", lower)
        || contains_any(lower, DUMP_CORE_EVENT_MARKERS)
        || contains_any(lower, DUMP_CORE_PERSISTENCE_MARKERS)
        || contains_any(lower, DUMP_CORE_MINECRAFT_CHEAT_MARKERS)
    {
        return true;
    }
    if !dump_core_has_windows_path_hint(lower) {
        return false;
    }
    lower.contains(".exe")
        || lower.contains(".dll")
        || lower.contains(".sys")
        || lower.contains(".bat")
        || lower.contains(".cmd")
        || lower.contains(".ps1")
        || lower.contains(".jar")
        || lower.contains("\\appdata\\")
        || lower.contains("\\programdata\\")
        || lower.contains("\\users\\")
        || lower.contains("\\windows\\tasks\\")
        || lower.contains("\\startup\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\prefetch\\")
}

fn dump_core_is_actionable_search_index_line(line: &str, lower: &str) -> bool {
    if !contains_any(lower, DUMP_CORE_SIGNAL_SEARCH_MARKERS) {
        return false;
    }
    if dump_core_is_noise_line(line, lower) {
        return false;
    }
    if lower.contains("searchindexer.exe") {
        return lower.contains("/embedding")
            || lower.contains("searchprotocolhost.exe")
            || lower.contains("usgthr")
            || lower.contains("\\programdata\\microsoft\\search\\")
            || lower.contains("windows.edb");
    }
    lower.contains("\\programdata\\microsoft\\search\\")
        || lower.contains("windows.edb")
        || lower.contains("\\windows\\system32\\searchfilterhost.exe")
}

fn dump_core_is_actionable_thumbcache_line(line: &str, lower: &str) -> bool {
    if !contains_any(lower, DUMP_CORE_SIGNAL_THUMBCACHE_MARKERS) {
        return false;
    }
    if dump_core_is_noise_line(line, lower) {
        return false;
    }
    let has_thumbcache_path =
        lower.contains("\\appdata\\local\\microsoft\\windows\\explorer\\")
            && (lower.contains("thumbcache_") || lower.contains("iconcache_"));
    if !has_thumbcache_path {
        return false;
    }
    let has_exe_or_dll = lower.contains(".exe") || lower.contains(".dll") || lower.contains(".sys");
    let has_high_signal = contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_NAME_MARKERS)
        || contains_any(lower, DUMP_CORE_MINECRAFT_CHEAT_MARKERS)
        || lower.contains("unknowncheats")
        || lower.contains("keyauth")
        || lower.contains("autoclicker")
        || lower.contains("clicker")
        || lower.contains("bypass");
    if has_high_signal {
        return true;
    }
    let has_risky_user_path = lower.contains("\\users\\")
        && (lower.contains("\\downloads\\")
            || lower.contains("\\desktop\\")
            || lower.contains("\\temp\\")
            || lower.contains("\\appdata\\roaming\\"));
    has_exe_or_dll && has_risky_user_path && (lower.contains("cheat") || lower.contains("bypass"))
}

fn normalize_dump_core_line(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len().min(DUMP_CORE_MAX_LINE_CHARS));
    let mut last_space = false;
    for ch in raw.chars() {
        if out.len() >= DUMP_CORE_MAX_LINE_CHARS {
            break;
        }
        let mapped = match ch {
            '\r' | '\n' | '\t' => ' ',
            c if c.is_control() => ' ',
            c => c,
        };
        if mapped == ' ' {
            if last_space {
                continue;
            }
            out.push(' ');
            last_space = true;
        } else {
            out.push(mapped);
            last_space = false;
        }
    }

    let normalized = normalize_dump_core_windows_fragments(out.trim());
    let normalized = normalized.trim();
    if normalized.len() < DUMP_CORE_MIN_STRING_LEN {
        return None;
    }
    if normalized.split_whitespace().count() > 64 {
        return None;
    }
    if normalized.split_whitespace().any(|t| t.len() > 140) {
        return None;
    }
    Some(normalized.to_string())
}

fn normalize_dump_core_windows_fragments(text: &str) -> String {
    let mut normalized = text.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    if !(lower.contains("\\device\\harddiskvolume")
        || lower.contains("\\??\\")
        || lower.contains("\\\\?\\")
        || lower.contains("\\global??\\"))
    {
        return normalized;
    }

    normalized = DUMP_CORE_DOS_DRIVE_PREFIX_RE
        .replace_all(&normalized, |caps: &regex::Captures<'_>| {
            let letter = caps
                .get(1)
                .and_then(|m| m.as_str().chars().next())
                .unwrap_or('C')
                .to_ascii_uppercase();
            format!("{letter}:\\")
        })
        .to_string();
    normalized = DUMP_CORE_DOS_DRIVE_PREFIX_ALT_RE
        .replace_all(&normalized, |caps: &regex::Captures<'_>| {
            let letter = caps
                .get(1)
                .and_then(|m| m.as_str().chars().next())
                .unwrap_or('C')
                .to_ascii_uppercase();
            format!("{letter}:\\")
        })
        .to_string();
    normalized = DUMP_CORE_DEVICE_VOLUME_PREFIX_RE
        .replace_all(&normalized, |caps: &regex::Captures<'_>| {
            let volume = caps
                .get(1)
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(3);
            let letter = dump_core_drive_letter_from_volume(volume).unwrap_or('C');
            format!("{letter}:\\")
        })
        .to_string();
    normalize_dump_core_duplicated_drive_prefix(&normalized)
}

fn normalize_dump_core_duplicated_drive_prefix(text: &str) -> String {
    if text.len() < 6 {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < text.len() {
        if i + 5 < text.len()
            && bytes[i].is_ascii_alphabetic()
            && bytes[i + 1] == b':'
            && bytes[i + 2] == b'\\'
            && bytes[i + 3].is_ascii_alphabetic()
            && bytes[i + 4] == b':'
            && bytes[i + 5] == b'\\'
            && bytes[i].to_ascii_lowercase() == bytes[i + 3].to_ascii_lowercase()
        {
            out.push((bytes[i] as char).to_ascii_uppercase());
            out.push(':');
            out.push('\\');
            i += 6;
            continue;
        }
        let ch = text[i..].chars().next().unwrap_or_default();
        if ch == '\0' {
            i += 1;
            continue;
        }
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn dump_core_drive_letter_from_volume(volume_number: u32) -> Option<char> {
    if !(1..=26).contains(&volume_number) {
        return None;
    }
    Some((b'A' + (volume_number as u8 - 1)) as char)
}

fn dump_core_event_tag(lower: &str) -> &'static str {
    if lower.contains("eventid=4624")
        || lower.contains("eventid=4625")
        || lower.contains("eventid=4648")
        || lower.contains("eventid=4634")
    {
        return "logon";
    }
    if lower.contains("eventid=4688") {
        return "process-create";
    }
    if lower.contains("eventid=4672") {
        return "privilege";
    }
    if lower.contains("eventid=7045") {
        return "service-install";
    }
    if lower.contains("eventid=6005") || lower.contains("eventid=6006") {
        return "system-state";
    }
    if lower.contains("taskscheduler/operational") {
        return "task-scheduler";
    }
    "generic"
}

fn dump_core_quick_interesting(lower: &str) -> bool {
    if dump_core_has_windows_path_hint(lower) {
        return true;
    }
    if lower.contains(".exe")
        || lower.contains(".dll")
        || lower.contains(".sys")
        || lower.contains("http")
        || lower.contains("socket")
        || lower.contains("proxy")
        || lower.contains("pid")
        || lower.contains("eventid")
        || lower.contains("powershell")
        || lower.contains("cmd.exe")
        || lower.contains("rwx")
        || lower.contains("inject")
        || lower.contains("hollow")
        || contains_any(lower, DUMP_CORE_OPEN_STRONG_MARKERS)
        || dump_core_has_websocket_signal("", lower)
        || contains_any(lower, DUMP_CORE_SIGNAL_SEARCH_MARKERS)
        || contains_any(lower, DUMP_CORE_SIGNAL_THUMBCACHE_MARKERS)
    {
        return true;
    }
    if lower.contains("://") {
        return true;
    }
    if !lower.contains(':') {
        return false;
    }
    if !(lower.contains('.') || lower.contains(" tcp") || lower.contains(" udp")) {
        return false;
    }
    DUMP_CORE_IP_PORT_RE.is_match(lower) || DUMP_CORE_HOST_PORT_RE.is_match(lower)
}

fn dump_core_has_hard_indicator(line: &str, lower: &str) -> bool {
    contains_any(lower, DUMP_CORE_COMMAND_MARKERS)
        || contains_any(lower, DUMP_CORE_HIDDEN_PROCESS_MARKERS)
        || contains_any(lower, DUMP_CORE_INJECTION_MARKERS)
        || contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_MARKERS)
        || contains_any(lower, DUMP_CORE_MODIFIED_MEMORY_MARKERS)
        || contains_any(lower, DUMP_CORE_EVENT_MARKERS)
        || contains_any(lower, DUMP_CORE_SIGNAL_PROXY_MARKERS)
        || dump_core_has_rdp_signal(lower)
        || dump_core_has_websocket_signal("", lower)
        || contains_any(lower, DUMP_CORE_SIGNAL_SEARCH_MARKERS)
        || contains_any(lower, DUMP_CORE_SIGNAL_THUMBCACHE_MARKERS)
        || contains_any(lower, DUMP_CORE_OPEN_STRONG_MARKERS)
        || dump_core_has_windows_path_hint(lower)
        || lower.contains("://")
        || DUMP_CORE_COMMAND_RE.is_match(line)
        || (lower.contains(':')
            && DUMP_CORE_IP_PORT_RE.is_match(line))
        || (lower.contains(':')
            && lower.contains('.')
            && DUMP_CORE_HOST_PORT_RE.is_match(line))
        || (lower.contains("://") && DUMP_CORE_URL_RE.is_match(line))
}

fn dump_core_has_windows_path_hint(lower: &str) -> bool {
    lower.contains(":\\")
        || lower.contains("\\device\\harddiskvolume")
        || lower.contains("\\??\\")
        || lower.contains("\\\\?\\")
        || lower.contains("\\users\\")
        || lower.contains("\\windows\\")
}

fn dump_core_is_minecraft_cheat_signal(lower: &str) -> bool {
    !dump_core_is_minecraft_localization_noise(lower)
        && contains_any(lower, DUMP_CORE_MINECRAFT_MARKERS)
        && contains_any(lower, DUMP_CORE_MINECRAFT_CHEAT_MARKERS)
}

fn dump_core_is_noise_line(line: &str, lower: &str) -> bool {
    if dump_core_is_minecraft_localization_noise(lower) {
        return true;
    }
    if is_probable_embedded_source_noise(lower) && !has_high_value_artifact_hint(lower) {
        return true;
    }
    if dump_core_is_markup_noise(lower) && !has_high_value_artifact_hint(lower) {
        return true;
    }
    if is_documentation_noise_lc(lower) && !has_high_value_artifact_hint(lower) {
        return true;
    }
    if contains_any(lower, DUMP_CORE_NOISE_MARKERS) {
        return true;
    }
    if lower.contains("commandexecution") && lower.contains("aggregatedoutput") {
        return true;
    }
    if dump_core_has_multi_path_stitch_noise(line, lower) {
        return true;
    }
    if dump_core_has_excessive_symbol_ratio(line) && !has_high_value_artifact_hint(lower) {
        return true;
    }
    if dump_core_has_low_information_token_mix(line, lower) && !dump_core_has_hard_indicator(line, lower)
    {
        return true;
    }
    if lower.matches("\\\"").count() >= 6
        && !DUMP_CORE_COMMAND_RE.is_match(line)
        && !DUMP_CORE_PATH_RE.is_match(line)
        && !DUMP_CORE_URL_RE.is_match(line)
    {
        return true;
    }
    false
}

fn dump_core_is_minecraft_localization_noise(lower: &str) -> bool {
    (lower.contains("block.minecraft.") || lower.contains("loot_table/blocks"))
        && !contains_any(lower, DUMP_CORE_MINECRAFT_CHEAT_MARKERS)
}

fn dump_core_has_multi_path_stitch_noise(line: &str, lower: &str) -> bool {
    let rooted_count = line.matches(":\\").count() + lower.matches("\\device\\harddiskvolume").count();
    if rooted_count < 3 {
        return false;
    }
    if contains_any(lower, DUMP_CORE_COMMAND_MARKERS)
        || contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_MARKERS)
        || contains_any(lower, DUMP_CORE_INJECTION_MARKERS)
    {
        return false;
    }
    true
}

fn dump_core_is_env_block_noise(lower: &str) -> bool {
    let mut hits = 0usize;
    for marker in &[
        "allusersprofile=",
        "appdata=",
        "localappdata=",
        "commonprogramfiles=",
        "commonprogramfiles(x86)=",
        "commonprogramw6432=",
        "comspec=",
        "systemroot=",
        "userprofile=",
        "windir=",
        "path=",
    ] {
        if lower.contains(marker) {
            hits += 1;
            if hits >= 3 {
                return true;
            }
        }
    }
    if lower.starts_with("localappdata=") {
        return true;
    }
    if (lower.starts_with("path=")
        || lower.starts_with("public=")
        || lower.starts_with("temp=")
        || lower.starts_with("tmp="))
        && lower.matches('=').count() >= 2
    {
        return true;
    }
    false
}

fn dump_core_is_router_telemetry_blob(line: &str, lower: &str) -> bool {
    let has_router = lower.contains("router: found process path");
    let has_tun = lower.contains("inbound/tun[tun-in]")
        || lower.contains("outbound/socks[proxy]")
        || lower.contains("inbound packet connection");
    let has_stderr_json =
        lower.contains("\"event\":\"stderr\"") || lower.contains("\\\"event\\\":\\\"stderr\\\"");
    if !(has_router || has_tun || has_stderr_json) {
        return false;
    }
    if contains_any(lower, DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS) {
        return false;
    }
    if has_tun && lower.contains("1.1.1.1:53") {
        return true;
    }
    if has_stderr_json {
        return true;
    }
    if has_router
        && !DUMP_CORE_IP_PORT_RE.is_match(line)
        && !DUMP_CORE_HOST_PORT_RE.is_match(line)
        && !lower.contains("wss://")
        && !lower.contains("ws://")
    {
        return true;
    }
    false
}

fn dump_core_is_markup_noise(lower: &str) -> bool {
    contains_any(lower, DUMP_CORE_MARKUP_NOISE_MARKERS)
        || (lower.contains("<a ")
            && lower.contains("</a>")
            && lower.contains("href=\"")
            && lower.contains("class=\""))
        || (lower.contains("<div") && lower.contains("</div>") && lower.contains("class=\""))
}

fn dump_core_has_excessive_symbol_ratio(line: &str) -> bool {
    let mut ascii = 0usize;
    let mut unusual = 0usize;
    for ch in line.chars() {
        if !ch.is_ascii() {
            continue;
        }
        ascii += 1;
        if !ch.is_ascii_alphanumeric()
            && !ch.is_ascii_whitespace()
            && !r#"._\-:/\\'"()[]{}=+@,%!?&*<>|;`"#.contains(ch)
        {
            unusual += 1;
        }
    }
    ascii > 48 && unusual * 100 > ascii * 38
}

fn dump_core_has_low_information_token_mix(line: &str, lower: &str) -> bool {
    if line.len() < 120 {
        return false;
    }
    if DUMP_CORE_COMMAND_RE.is_match(line) && contains_any(lower, DUMP_CORE_COMMAND_ACTION_MARKERS) {
        return false;
    }
    let mut total = 0usize;
    let mut hexlike = 0usize;
    let mut consonant_heavy = 0usize;
    let mut short_alnum = 0usize;
    for raw in line.split_whitespace().take(96) {
        let token = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if token.is_empty() {
            continue;
        }
        total += 1;
        let token_l = token.to_ascii_lowercase();
        if token.len() >= 12 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            hexlike += 1;
            continue;
        }
        if token.len() <= 2 && token.chars().all(|c| c.is_ascii_alphanumeric()) {
            short_alnum += 1;
        }
        if token.len() >= 10 && token.chars().all(|c| c.is_ascii_alphanumeric()) {
            let vowels = token_l.chars().filter(|c| "aeiou".contains(*c)).count();
            if vowels == 0 || vowels * 6 < token.len() {
                consonant_heavy += 1;
            }
        }
    }
    if total < 16 {
        return false;
    }
    (hexlike >= 4 && hexlike * 3 >= total)
        || (consonant_heavy >= 8 && consonant_heavy * 2 >= total)
        || (short_alnum >= 12
            && short_alnum * 2 >= total
            && !contains_any(lower, DUMP_CORE_COMMAND_ACTION_MARKERS))
}

fn dump_core_is_open_artifact(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower) {
        return false;
    }
    if dump_core_is_router_telemetry_blob(line, lower) || dump_core_is_env_block_noise(lower) {
        return false;
    }
    if dump_core_is_benign_operator_command(lower) {
        return false;
    }
    if lower.contains("\"event\":\"stderr\"")
        || lower.contains("\\\"event\\\":\\\"stderr\\\"")
        || lower.contains("\\n+0800 ")
        || lower.contains("decodedx11::checkvideodecoderformat")
    {
        return false;
    }
    let trimmed = line.trim_start();
    if let Some(first) = trimmed.chars().next() {
        if !first.is_ascii_alphabetic()
            && first != '"'
            && first != '\\'
            && first != '/'
            && first != '.'
            && first != '['
        {
            return false;
        }
    }
    if let Some(dev_idx) = lower.find("\\device\\harddiskvolume")
        && dev_idx > 0
        && !trimmed.starts_with("\\Device\\")
        && !trimmed.starts_with("\\device\\")
        && !trimmed.starts_with("\"\\Device\\")
        && !trimmed.starts_with("\"\\device\\")
    {
        return false;
    }
    let has_open_marker = contains_any(lower, DUMP_CORE_OPEN_MARKERS);
    let has_strong_open_marker = contains_any(lower, DUMP_CORE_OPEN_STRONG_MARKERS);
    let has_path = DUMP_CORE_PATH_RE.is_match(line) || dump_core_has_windows_path_hint(lower);
    let has_socket_keyword = contains_any(lower, &["socket", "afd", "\\pipe\\", "handle"]);
    let has_socket_ctx = has_socket_keyword
        && (DUMP_CORE_IP_PORT_RE.is_match(line)
            || DUMP_CORE_HOST_PORT_RE.is_match(line)
            || lower.contains(":443")
            || lower.contains(":3389")
            || lower.contains(":80"));
    if has_socket_ctx {
        return true;
    }
    if !has_path {
        return false;
    }
    if lower.contains("http://") || lower.contains("https://") {
        return false;
    }
    if dump_core_is_open_path_noise(line, lower) {
        return false;
    }
    let path_hits = DUMP_CORE_PATH_RE.find_iter(line).count();
    if path_hits >= 3 {
        return false;
    }
    let has_exec_ext = lower.contains(".exe")
        || lower.contains(".dll")
        || lower.contains(".sys")
        || lower.contains(".bat")
        || lower.contains(".cmd")
        || lower.contains(".ps1")
        || lower.contains(".jar")
        || lower.contains(".lnk");
    let has_sensitive_path = lower.contains("\\appdata\\")
        || lower.contains("\\programdata\\")
        || lower.contains("\\users\\public\\")
        || lower.contains("\\recycle.bin\\")
        || lower.contains("\\windows\\tasks\\")
        || lower.contains("\\startup\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\drivers\\");
    let trusted_root = lower.contains("\\windows\\")
        || lower.contains("\\program files\\")
        || lower.contains("\\program files (x86)\\");
    let has_command_action = contains_any(lower, DUMP_CORE_COMMAND_ACTION_MARKERS)
        || lower.contains(" -command ")
        || lower.contains(" --service")
        || lower.contains(" /service")
        || lower.contains(" /runasservice");
    let has_behavioral_signal = has_command_action
        || contains_any(lower, DUMP_CORE_COMMAND_MARKERS)
        || lower.contains("hostapplication=")
        || lower.contains("process path:");
    let has_high_signal = contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_MARKERS)
        || contains_any(lower, DUMP_CORE_INJECTION_MARKERS)
        || contains_any(lower, DUMP_CORE_HIDDEN_PROCESS_MARKERS)
        || contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_NAME_MARKERS)
        || contains_any(lower, DUMP_CORE_OPEN_HIGH_RISK_TOOL_MARKERS)
        || lower.contains("keyauth")
        || lower.contains("unknowncheats")
        || lower.contains("bypass")
        || lower.contains("cheat");
    if path_hits >= 2
        && !has_socket_ctx
        && !has_command_action
        && !lower.contains(".json")
        && !lower.contains("|app=")
    {
        return false;
    }
    if trusted_root
        && !has_sensitive_path
        && !has_high_signal
        && !has_command_action
        && !has_strong_open_marker
    {
        return false;
    }
    if line.len() > 420 && !has_high_signal && !has_socket_ctx {
        return false;
    }
    if dump_core_has_multi_path_stitch_noise(line, lower) && !has_high_signal {
        return false;
    }
    if has_sensitive_path {
        return (has_exec_ext || has_strong_open_marker || has_open_marker)
            && (has_high_signal || has_behavioral_signal);
    }
    if trusted_root {
        return has_high_signal || (has_strong_open_marker && has_behavioral_signal);
    }
    if has_exec_ext {
        return has_high_signal || has_behavioral_signal;
    }
    (has_strong_open_marker || has_open_marker) && has_high_signal && line.len() <= 520
}

fn dump_core_is_open_path_noise(line: &str, lower: &str) -> bool {
    if dump_core_is_router_telemetry_blob(line, lower) || dump_core_is_env_block_noise(lower) {
        return true;
    }
    if lower.contains("\\system32\\conhost.exe 0xffffffff -forcev1") {
        return true;
    }
    if lower.contains("\\\"path\\\":\\\"c:\\\\") && !contains_any(lower, DUMP_CORE_OPEN_HIGH_RISK_TOOL_MARKERS)
    {
        return true;
    }
    if line.contains("diff --git") || line.contains("@@ -") {
        return true;
    }
    if lower.contains("hash-object --")
        || lower.contains(" rev-parse --")
        || lower.contains(" status -z ")
        || lower.contains(" --show-toplevel")
    {
        return true;
    }
    if dump_core_has_truncated_drive_path(lower) {
        return true;
    }
    if lower.contains("\\global??\\c:\\c:\\")
        || lower.contains("\\??\\c:\\c:\\")
        || lower.contains("c:\\c:\\")
    {
        return true;
    }
    if contains_any(lower, DUMP_CORE_OPEN_NOISE_PATH_MARKERS) {
        return true;
    }
    if lower.starts_with("\\??\\acpi#")
        || lower.starts_with("\\??\\pci#")
        || lower.starts_with("\\??\\usb#")
        || lower.starts_with("\\??\\root#")
        || lower.starts_with("\\??\\hdaudio#")
    {
        return true;
    }
    if lower.contains("block.minecraft.") || lower.contains("loot_table/blocks") {
        return true;
    }
    if dump_core_is_benign_knowndll_entry(lower) {
        return true;
    }
    let doc_ext_noise = lower.contains(".txt")
        || lower.contains(".md")
        || lower.contains(".html")
        || lower.contains(".json")
        || lower.contains(".toml")
        || lower.contains(".rs")
        || lower.contains(".h")
        || lower.contains(".hpp")
        || lower.contains(".c ")
        || lower.contains(".cpp");
    if doc_ext_noise
        && !lower.contains(".exe")
        && !lower.contains(".dll")
        && !lower.contains(".sys")
        && !contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_MARKERS)
        && !contains_any(lower, DUMP_CORE_HIDDEN_PROCESS_MARKERS)
        && !contains_any(lower, DUMP_CORE_COMMAND_MARKERS)
    {
        return true;
    }
    if lower.contains("\\??\\c:") && !lower.contains("\\??\\c:\\") {
        return true;
    }
    false
}

fn dump_core_has_truncated_drive_path(lower: &str) -> bool {
    if lower.contains(":\\program")
        && !lower.contains(":\\program files")
        && !lower.contains(":\\programdata\\")
    {
        return true;
    }
    if lower.contains(":\\user") && !lower.contains(":\\users\\") {
        return true;
    }
    lower.ends_with(":\\program")
        || lower.ends_with(":\\users")
        || lower.ends_with(":\\windows")
        || lower.ends_with(":\\program files")
}

fn dump_core_is_benign_operator_command(lower: &str) -> bool {
    let looks_dev_tool = lower.contains("\\program files\\git\\")
        || lower.contains("\\.cargo\\bin\\cargo.exe")
        || lower.contains("\\.cargo\\bin\\rustc.exe")
        || lower.contains("\\program files\\powershell\\7\\pwsh.exe")
        || lower.contains("\\vscode\\extensions\\")
        || lower.contains("\\program files\\microsoft visual studio\\")
        || lower.contains("\\program files (x86)\\microsoft visual studio\\");
    if !looks_dev_tool {
        return false;
    }
    if contains_any(lower, DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS)
        || contains_any(lower, DUMP_CORE_INJECTION_MARKERS)
        || contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_MARKERS)
        || lower.contains("encodedcommand")
        || lower.contains(" -enc")
        || lower.contains(" download?key=")
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod")
    {
        return false;
    }
    true
}

fn dump_core_is_benign_knowndll_entry(lower: &str) -> bool {
    lower.contains("\\knowndlls\\")
        && DUMP_CORE_BENIGN_KNOWN_DLLS
            .iter()
            .any(|entry| lower.contains(entry))
}

fn dump_core_is_command_buffer(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower) {
        return false;
    }
    if dump_core_is_router_telemetry_blob(line, lower) || dump_core_is_env_block_noise(lower) {
        return false;
    }
    if lower.contains("\"event\":\"stderr\"")
        || lower.contains("\\\"event\\\":\\\"stderr\\\"")
        || lower.contains("\\n+0800 ")
    {
        return false;
    }
    if dump_core_has_multi_path_stitch_noise(line, lower) && !DUMP_CORE_COMMAND_RE.is_match(line) {
        return false;
    }
    if DUMP_CORE_COMMAND_RE.is_match(line) {
        if line.len() > 460 && !contains_any(lower, DUMP_CORE_COMMAND_ACTION_MARKERS) {
            return false;
        }
        if let Some(hit) = DUMP_CORE_COMMAND_RE.find(line)
            && line.len() > 240
            && hit.start() > 120
            && !contains_any(lower, DUMP_CORE_COMMAND_ACTION_MARKERS)
        {
            return false;
        }
        return contains_any(lower, DUMP_CORE_COMMAND_ACTION_MARKERS)
            || lower.contains(" -command ")
            || lower.contains(" -encodedcommand ")
            || lower.contains(" /c ");
    }
    if line.len() > 520 {
        return false;
    }
    if lower.contains("microsoft.powershell.") && !contains_any(lower, DUMP_CORE_COMMAND_ACTION_MARKERS)
    {
        return false;
    }
    let marker_hits = count_contains(lower, DUMP_CORE_COMMAND_MARKERS);
    let has_action = contains_any(lower, DUMP_CORE_COMMAND_ACTION_MARKERS);
    (marker_hits >= 2 && has_action) || marker_hits >= 3
}

fn dump_core_is_shell_history(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower) || line.len() > 560 {
        return false;
    }
    let is_prefix = lower.starts_with("cmd ")
        || lower.starts_with("cmd.exe")
        || lower.starts_with("powershell ")
        || lower.starts_with("powershell.exe")
        || lower.starts_with("pwsh ")
        || lower.starts_with("reg ")
        || lower.starts_with("wmic ")
        || lower.starts_with("netsh ")
        || lower.starts_with("schtasks ")
        || lower.starts_with("sc ")
        || lower.starts_with("rundll32 ")
        || lower.starts_with("regsvr32 ");
    is_prefix && contains_any(lower, DUMP_CORE_COMMAND_ACTION_MARKERS)
}

fn dump_core_is_actionable_persistence_line(line: &str, lower: &str) -> bool {
    if !contains_any(lower, DUMP_CORE_PERSISTENCE_MARKERS) {
        return false;
    }
    if dump_core_is_benign_knowndll_entry(lower) {
        return false;
    }
    if lower.contains("knowndlls") {
        return contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_NAME_MARKERS)
            || lower.contains("\\users\\")
            || lower.contains("\\appdata\\")
            || lower.contains("\\temp\\")
            || lower.contains(".exe")
            || lower.contains(".dll")
            || lower.contains(".sys");
    }
    if lower.contains("currentversion\\run") || lower.contains("currentversion\\runonce") {
        return line.contains(".exe")
            || line.contains(".dll")
            || line.contains(".sys")
            || line.contains(".bat")
            || line.contains(".cmd")
            || line.contains(".ps1");
    }
    true
}

fn dump_core_is_hidden_process(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower) || line.len() > 440 {
        return false;
    }
    let marker_hits = count_contains(lower, DUMP_CORE_HIDDEN_PROCESS_MARKERS);
    if marker_hits >= 2 && (lower.contains("pid") || line.contains(".exe")) {
        return true;
    }
    let has_structure_signal = lower.contains("activeprocesslinks")
        || lower.contains(" eprocess")
        || lower.contains(" hidden process")
        || lower.contains(" ghost process")
        || lower.contains(" orphan process")
        || lower.contains(" terminated process")
        || lower.contains(" process exited");
    (lower.contains("pid") || lower.contains("process"))
        && has_structure_signal
        && (line.contains(".exe")
            || line.contains(" eprocess")
            || line.contains(" activeprocesslinks")
            || lower.contains("pid:"))
}

fn dump_core_is_network_artifact(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower) {
        return false;
    }
    if dump_core_is_benign_operator_command(lower)
        && !contains_any(lower, DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS)
    {
        return false;
    }
    if lower.contains("inbound/tun[tun-in]")
        && (lower.contains("1.1.1.1:53") || lower.contains("router: found process path"))
        && !contains_any(lower, DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS)
    {
        return false;
    }
    if line.len() > 420
        && !contains_any(lower, DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS)
        && !dump_core_has_network_exec_context(line, lower)
    {
        return false;
    }
    let has_ip_port = DUMP_CORE_IP_PORT_RE.is_match(line) || DUMP_CORE_HOST_PORT_RE.is_match(line);
    let has_url = DUMP_CORE_URL_RE.is_match(line);
    let has_ctx = dump_core_has_network_token_marker(lower)
        || contains_any(lower, DUMP_CORE_NETWORK_CONTEXT_MARKERS)
        || contains_any(lower, DUMP_CORE_SIGNAL_PROXY_MARKERS)
        || dump_core_has_rdp_signal(lower);
    if has_ip_port {
        return has_ctx || lower.contains("->");
    }
    if has_url {
        return dump_core_is_actionable_https_endpoint(line, lower);
    }
    if contains_any(lower, DUMP_CORE_SIGNAL_PROXY_MARKERS) {
        return has_token_lc(lower, "proxy")
            || lower.contains("proxyenable")
            || lower.contains("proxyserver")
            || lower.contains("autoconfigurl");
    }
    if dump_core_has_network_token_marker(lower) {
        return contains_any(lower, DUMP_CORE_COMMAND_MARKERS)
            || lower.contains("socket")
            || lower.contains("connect")
            || lower.contains("listen")
            || lower.contains("bind");
    }
    false
}

fn dump_core_has_network_token_marker(lower: &str) -> bool {
    lower.contains("ws://")
        || lower.contains("wss://")
        || lower.contains("http://")
        || lower.contains("https://")
        || has_token_lc(lower, "tcp")
        || has_token_lc(lower, "udp")
        || has_token_lc(lower, "rdp")
        || has_token_lc(lower, "mstsc")
        || has_token_lc(lower, "websocket")
        || has_token_lc(lower, "dns")
        || has_token_lc(lower, "socket")
}

fn dump_core_has_rdp_signal(lower: &str) -> bool {
    has_token_lc(lower, "rdp")
        || lower.contains("mstsc.exe")
        || lower.contains("default.rdp")
        || lower.contains("rdpclip.exe")
        || lower.contains("umrdp.dll")
        || lower.contains("terminal server client")
        || lower.contains(":3389")
}

fn dump_core_has_websocket_signal(line: &str, lower: &str) -> bool {
    if lower.contains("ws://")
        || lower.contains("wss://")
        || lower.contains("sec-websocket-key")
        || lower.contains("sec-websocket-version")
        || lower.contains("sec-websocket-extensions")
    {
        return true;
    }
    if !has_token_lc(lower, "websocket") {
        return false;
    }
    lower.contains("connect")
        || lower.contains("upgrade")
        || lower.contains("socket")
        || lower.contains("outbound")
        || lower.contains("inbound")
        || DUMP_CORE_URL_RE.is_match(line)
}

fn dump_core_is_actionable_https_endpoint(line: &str, lower: &str) -> bool {
    if !DUMP_CORE_URL_RE.is_match(line) || dump_core_is_noise_line(line, lower) {
        return false;
    }
    if line.len() > 520
        && !dump_core_has_network_exec_context(line, lower)
        && !contains_any(lower, DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS)
    {
        return false;
    }

    let trimmed = line.trim_start();
    if (trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with("/*"))
        && !dump_core_has_network_exec_context(line, lower)
    {
        return false;
    }

    // Keep endpoint artifacts when there is concrete execution/network context.
    let has_context = contains_any(lower, DUMP_CORE_NETWORK_CONTEXT_MARKERS)
        || contains_any(lower, DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS)
        || contains_any(lower, DUMP_CORE_SUSPICIOUS_DOWNLOAD_MARKERS)
        || dump_core_has_network_exec_context(line, lower)
        || lower.contains("transmissionendpoint");
    if !has_context {
        return false;
    }
    if lower.contains("crashpad-handler") {
        return false;
    }

    let Some(url) = extract_first_url(line) else {
        return true;
    };
    let Some(host) = extract_url_host(url) else {
        return true;
    };
    let host_lc = host.to_ascii_lowercase();
    let suspicious_host = SUSPICIOUS_DOMAIN_HOSTS
        .iter()
        .any(|x| host_lc.contains(x))
        || NETWORK_TUNNEL_DOMAINS.iter().any(|x| host_lc.contains(x))
        || host_lc.contains("unknowncheats")
        || host_lc.contains("keyauth")
        || host_lc.contains("pastebin");
    if suspicious_host {
        return true;
    }

    if is_trusted_network_host(&host_lc) {
        return contains_any(lower, DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS)
            || contains_any(lower, DUMP_CORE_SUSPICIOUS_DOWNLOAD_MARKERS)
            || dump_core_has_network_exec_context(line, lower);
    }
    true
}

fn dump_core_has_network_exec_context(line: &str, lower: &str) -> bool {
    let _ = line;
    lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod")
        || lower.contains("hostapplication=")
        || lower.contains(" -uri ")
        || lower.contains(" --url=")
        || lower.contains("curl ")
        || lower.contains("wget ")
}

fn dump_core_is_suspicious_connection(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower) {
        return false;
    }
    let has_cmd_context = DUMP_CORE_COMMAND_RE.is_match(line)
        || contains_any(lower, DUMP_CORE_COMMAND_MARKERS)
        || lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains(" -uri ")
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod");
    let has_susp_marker = DUMP_CORE_SUSPICIOUS_NETWORK_MARKERS
        .iter()
        .any(|m| lower.contains(m));

    if let Some(url) = extract_first_url(line)
        && let Some(host) = extract_url_host(url)
    {
        let host_lc = host.to_ascii_lowercase();
        if is_trusted_network_host(&host_lc) && !(has_susp_marker && has_cmd_context) {
            return false;
        }
        if SUSPICIOUS_DOMAIN_HOSTS.iter().any(|x| host_lc.contains(x))
            || NETWORK_TUNNEL_DOMAINS.iter().any(|x| host_lc.contains(x))
        {
            return true;
        }
        if has_susp_marker {
            return true;
        }
        if contains_any(lower, DUMP_CORE_SUSPICIOUS_DOWNLOAD_MARKERS) && has_cmd_context
            || host_lc.contains("unknowncheats")
            || host_lc.contains("keyauth")
            || host_lc.contains("pastebin")
        {
            return true;
        }
        return false;
    }
    if let Some((ip, port)) = extract_ip_and_port(line) {
        if is_public_ipv4(&ip) {
            return DUMP_CORE_SUSPICIOUS_PORTS.contains(&port)
                || (port >= 49152 && contains_any(lower, DUMP_CORE_NETWORK_CONTEXT_MARKERS));
        }
        return false;
    }
    if has_susp_marker
        && (contains_any(lower, DUMP_CORE_NETWORK_CONTEXT_MARKERS) || has_cmd_context)
    {
        return true;
    }
    if let Some(port) = extract_suspicious_port(line) {
        return DUMP_CORE_SUSPICIOUS_PORTS.contains(&port)
            && contains_any(lower, DUMP_CORE_NETWORK_CONTEXT_MARKERS);
    }
    false
}

fn dump_core_is_proxy_bypass_signal(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower) {
        return false;
    }

    let has_proxy_marker = contains_any(lower, DUMP_CORE_SIGNAL_PROXY_MARKERS)
        || contains_any(lower, DUMP_CORE_PROXY_TUNNEL_MARKERS)
        || lower.contains("netsh winhttp set proxy")
        || lower.contains("internet settings\\proxy")
        || lower.contains("proxyoverride");
    if !has_proxy_marker {
        return false;
    }
    if contains_any(lower, DUMP_CORE_PROXY_FALSE_POSITIVE_MARKERS) {
        return false;
    }

    let has_minecraft_context = contains_any(lower, DUMP_CORE_MINECRAFT_MARKERS)
        || lower.contains("\\tlauncher\\")
        || lower.contains("\\minecraft\\")
        || (lower.contains("javaw.exe") && lower.contains("25565"));
    if !has_minecraft_context {
        return false;
    }

    let has_local_endpoint = contains_any(lower, DUMP_CORE_PROXY_LOCAL_ENDPOINT_MARKERS);
    let has_local_proxy_port = extract_suspicious_port(line)
        .map(|port| DUMP_CORE_PROXY_LOCAL_PORTS.contains(&port))
        .unwrap_or(false);
    let has_proxy_command = DUMP_CORE_COMMAND_RE.is_match(line)
        || has_token_lc(lower, "netsh")
        || has_token_lc(lower, "reg add")
        || has_token_lc(lower, "set-itemproperty")
        || has_token_lc(lower, "new-itemproperty")
        || has_token_lc(lower, "proxyenable")
        || has_token_lc(lower, "proxyserver")
        || has_token_lc(lower, "autoconfigurl");
    let has_tunnel_context =
        contains_any(lower, NETWORK_TUNNEL_KEYWORDS) || contains_any(lower, NETWORK_TUNNEL_DOMAINS);

    if lower.contains("internet settings")
        && !has_local_endpoint
        && !has_local_proxy_port
        && !has_proxy_command
    {
        return false;
    }

    (has_local_endpoint || has_local_proxy_port) && (has_proxy_command || has_tunnel_context)
        || (has_tunnel_context && has_proxy_command)
}

fn dump_core_is_suspicious_dll(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower) {
        return false;
    }
    if !lower.contains(".dll") && !lower.contains(".sys") {
        return false;
    }
    if !lower.contains(":\\")
        && !lower.contains("\\device\\harddiskvolume")
        && !lower.contains("\\??\\")
    {
        return false;
    }
    if lower.contains(".dll_imports.lib") || lower.ends_with(".lib") {
        return false;
    }
    if dump_core_is_benign_knowndll_entry(lower) {
        return false;
    }
    if contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_MARKERS) {
        if lower.contains("knowndlls") {
            return !dump_core_is_benign_knowndll_entry(lower);
        }
        return true;
    }
    if BYOVD_DRIVER_NAMES.iter().any(|x| lower.contains(x)) {
        return true;
    }
    if DUMP_CORE_TRUSTED_DLL_DIRS
        .iter()
        .any(|prefix| lower.contains(prefix))
    {
        return false;
    }
    if lower.contains(".sys") && contains_any(lower, DUMP_CORE_BENIGN_DRIVER_MARKERS) {
        return false;
    }
    let has_suspicious_name = contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_NAME_MARKERS);
    let is_known_benign_dll = contains_any(lower, DUMP_CORE_BENIGN_DLL_NAME_MARKERS)
        && (contains_any(lower, DUMP_CORE_BENIGN_DLL_PATH_MARKERS)
            || lower.contains("\\appdata\\local\\temp\\")
            || lower.contains("\\appdata\\local\\discord\\"));
    if is_known_benign_dll {
        return false;
    }
    if contains_any(lower, DUMP_CORE_SUSPICIOUS_DLL_PATH_MARKERS) {
        return lower.contains(".sys") || has_suspicious_name;
    }
    lower.contains("\\appdata\\") && has_suspicious_name
}

fn dump_core_is_injected_code(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower)
        || lower.contains("sha256")
        || lower.contains("sha512")
        || lower.contains("signaturevalue")
    {
        return false;
    }
    let api_hits = count_contains(
        lower,
        &[
            "writeprocessmemory",
            "createremotethread",
            "ntcreatethreadex",
            "queueuserapc",
            "virtualalloc",
            "ntmapviewofsection",
            "manualmap",
            "shellcode",
            "thread hijack",
            "process hollowing",
            "hollow",
        ],
    );
    let protect_hits = count_contains(lower, DUMP_CORE_INJECTION_PROTECT_MARKERS);
    let explicit_combo = (lower.contains("writeprocessmemory")
        && (lower.contains("createremotethread") || lower.contains("ntcreatethreadex")))
        || (lower.contains("virtualalloc")
            && lower.contains("virtualprotect")
            && lower.contains("shellcode"));
    explicit_combo || (api_hits >= 2 && protect_hits >= 1) || (api_hits >= 1 && protect_hits >= 2)
}

fn dump_core_is_modified_memory(lower: &str) -> bool {
    if is_probable_embedded_source_noise(lower) {
        return false;
    }
    let mod_hits = count_contains(lower, DUMP_CORE_MODIFIED_MEMORY_MARKERS);
    let has_ctx = lower.contains("memory")
        || lower.contains("module")
        || lower.contains("section")
        || lower.contains(".text")
        || lower.contains("checksum")
        || lower.contains("0x");
    lower.contains("checksum mismatch") || (mod_hits >= 2 && has_ctx) || (mod_hits >= 1 && has_ctx && lower.contains("rwx"))
}

fn dump_core_is_javaw_betatest_signal(line: &str, lower: &str) -> bool {
    if dump_core_is_noise_line(line, lower) {
        return false;
    }
    if !lower.contains("javaw.exe") && !lower.contains("\\java\\bin\\java.exe") {
        return false;
    }
    let api_hits = count_contains(
        lower,
        &[
            "writeprocessmemory",
            "createremotethread",
            "ntcreatethreadex",
            "queueuserapc",
            "virtualalloc",
            "virtualprotect",
            "ntmapviewofsection",
            "manualmap",
            "process hollowing",
            "thread hijack",
            "setwindowshookex",
            "setthreadcontext",
            "resume thread",
            "shellcode",
        ],
    );
    let has_exec_ctx = lower.contains("inject")
        || lower.contains("hollow")
        || lower.contains("manualmap")
        || lower.contains("shellcode")
        || lower.contains("dll injection");
    let has_loader_ctx = lower.contains("javaagent:")
        || lower.contains("-xbootclasspath")
        || lower.contains("-agentlib")
        || lower.contains("instrumentation");
    if has_exec_ctx && api_hits >= 1 {
        return true;
    }
    (api_hits >= 2 && has_loader_ctx) || (api_hits >= 3)
}

fn count_contains(lower: &str, markers: &[&str]) -> usize {
    markers.iter().filter(|m| lower.contains(*m)).count()
}

fn extract_first_url(line: &str) -> Option<&str> {
    DUMP_CORE_URL_RE.find(line).map(|m| m.as_str())
}

fn extract_url_host(url: &str) -> Option<&str> {
    let marker = "://";
    let scheme_end = url.find(marker)?;
    let host_start = scheme_end + marker.len();
    if host_start >= url.len() {
        return None;
    }
    let tail = &url[host_start..];
    let mut end = tail.len();
    for delim in ['/', '?', '#', ':'] {
        if let Some(idx) = tail.find(delim) {
            end = end.min(idx);
        }
    }
    if end == 0 {
        return None;
    }
    Some(&tail[..end])
}

fn is_trusted_network_host(host_lc: &str) -> bool {
    DUMP_CORE_TRUSTED_NETWORK_HOSTS
        .iter()
        .any(|suffix| host_lc == *suffix || host_lc.ends_with(&format!(".{suffix}")))
}

fn extract_ip_and_port(line: &str) -> Option<(String, u16)> {
    if let Some(cap) = DUMP_CORE_IP_PORT_FULL_RE.captures(line) {
        let ip = cap.get(1).map(|m| m.as_str().to_string())?;
        let port_raw = cap.get(2).map(|m| m.as_str())?;
        if let Ok(port) = port_raw.parse::<u16>() {
            return Some((ip, port));
        }
    }
    None
}

fn is_public_ipv4(ip: &str) -> bool {
    let parts = ip
        .split('.')
        .map(|x| x.parse::<u8>().ok())
        .collect::<Vec<_>>();
    if parts.len() != 4 || parts.iter().any(Option::is_none) {
        return false;
    }
    let a = parts[0].unwrap_or(0);
    let b = parts[1].unwrap_or(0);
    if a == 10 || a == 127 || a == 0 || a == 255 {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && b == 168 {
        return false;
    }
    true
}

fn extract_suspicious_port(line: &str) -> Option<u16> {
    if let Some(cap) = DUMP_CORE_IP_PORT_RE.captures(line)
        && let Some(port_raw) = cap.get(1).map(|m| m.as_str())
        && let Ok(port) = port_raw.parse::<u16>()
    {
        return Some(port);
    }

    if let Some(cap) = DUMP_CORE_HOST_PORT_RE.captures(line)
        && let Some(port_raw) = cap.get(1).map(|m| m.as_str())
        && let Ok(port) = port_raw.parse::<u16>()
    {
        return Some(port);
    }

    None
}

fn contains_any(lower: &str, markers: &[&str]) -> bool {
    markers.iter().any(|m| lower.contains(m))
}

fn capped_insert(set: &mut BTreeSet<String>, value: String, limit: usize) {
    if set.len() >= limit {
        return;
    }
    set.insert(value);
}

fn merge_dump_scan_sets(dst: &mut BTreeSet<String>, src: &BTreeSet<String>) {
    for row in src {
        capped_insert(dst, row.clone(), DUMP_CORE_LIMIT);
    }
}

fn merge_dump_scan_notes(dst: &mut BTreeSet<String>, src: &BTreeSet<String>) {
    for row in src {
        capped_insert(dst, row.clone(), DUMP_CORE_NOTES_LIMIT);
    }
}

fn merge_dump_core_scan(report: &mut MemoryOrbitReport, dmp: &Path, scan: DumpCoreScan) {
    let prefix = dmp
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("dump")
        .to_string();

    merge_prefixed_set(
        &mut report.open_files_or_sockets,
        &scan.open_files_or_sockets,
        &prefix,
        DUMP_CORE_OPEN_LIMIT,
    );
    merge_prefixed_set(
        &mut report.command_buffers,
        &scan.command_buffers,
        &prefix,
        DUMP_CORE_LIMIT,
    );
    merge_prefixed_set(
        &mut report.hidden_or_terminated_processes,
        &scan.hidden_or_terminated_processes,
        &prefix,
        DUMP_CORE_LIMIT,
    );
    merge_prefixed_set(
        &mut report.shell_command_history,
        &scan.shell_command_history,
        &prefix,
        DUMP_CORE_LIMIT,
    );
    merge_prefixed_set(
        &mut report.network_artifacts,
        &scan.network_artifacts,
        &prefix,
        DUMP_CORE_LIMIT,
    );
    merge_prefixed_set(
        &mut report.suspicious_connections,
        &scan.suspicious_connections,
        &prefix,
        DUMP_CORE_LIMIT,
    );
    merge_prefixed_set(
        &mut report.injected_code_hits,
        &scan.injected_code_hits,
        &prefix,
        DUMP_CORE_LIMIT,
    );
    merge_prefixed_set(
        &mut report.suspicious_dll_hits,
        &scan.suspicious_dll_hits,
        &prefix,
        DUMP_CORE_LIMIT,
    );
    merge_prefixed_set(
        &mut report.modified_memory_regions,
        &scan.modified_memory_regions,
        &prefix,
        DUMP_CORE_LIMIT,
    );
    merge_prefixed_set(
        &mut report.javaw_betatest,
        &scan.javaw_betatest,
        &prefix,
        DUMP_CORE_BETATEST_LIMIT,
    );
    merge_prefixed_set(
        &mut report.proxy_bypass_hits,
        &scan.proxy_bypass_hits,
        &prefix,
        DUMP_CORE_PROXY_BYPASS_LIMIT,
    );

    for row in scan.notes {
        capped_insert(
            &mut report.notes,
            format!("[{prefix}] {row}"),
            DUMP_CORE_NOTES_LIMIT,
        );
    }
}

fn merge_prefixed_set(
    dst: &mut BTreeSet<String>,
    src: &BTreeSet<String>,
    prefix: &str,
    limit: usize,
) {
    for row in src {
        capped_insert(dst, format!("[{prefix}] {row}"), limit);
    }
}

#[cfg(test)]
mod dump_core_tests {
    use super::*;

    #[test]
    fn public_ip_detector_filters_private_ranges() {
        assert!(is_public_ipv4("8.8.8.8"));
        assert!(!is_public_ipv4("10.0.0.5"));
        assert!(!is_public_ipv4("172.20.2.1"));
        assert!(!is_public_ipv4("192.168.1.7"));
        assert!(!is_public_ipv4("127.0.0.1"));
    }

    #[test]
    fn suspicious_connection_requires_public_context_or_known_ioc() {
        let line_public = "tcp 45.33.32.156:31337 -> 192.168.0.3:51333";
        let lower_public = line_public.to_ascii_lowercase();
        assert!(dump_core_is_suspicious_connection(line_public, &lower_public));

        let line_private = "tcp 192.168.0.10:31337 -> 192.168.0.3:51333";
        let lower_private = line_private.to_ascii_lowercase();
        assert!(!dump_core_is_suspicious_connection(line_private, &lower_private));
    }

    #[test]
    fn suspicious_dll_rules_skip_trusted_system_paths() {
        let trusted = r"C:\Windows\System32\kernel32.dll";
        let trusted_lower = trusted.to_ascii_lowercase();
        assert!(!dump_core_is_suspicious_dll(trusted, &trusted_lower));

        let suspicious = r"C:\Users\alice\AppData\Roaming\evilhook.dll";
        let suspicious_lower = suspicious.to_ascii_lowercase();
        assert!(dump_core_is_suspicious_dll(suspicious, &suspicious_lower));
    }

    #[test]
    fn injected_code_rule_requires_multi_signal_context() {
        let strong = "writeprocessmemory virtualprotect shellcode";
        assert!(dump_core_is_injected_code(strong, strong));
        let weak = "writeprocessmemory only";
        assert!(!dump_core_is_injected_code(weak, weak));
    }

    #[test]
    fn suspicious_connection_ignores_trusted_hosts() {
        let trusted = "https://chatgpt.com/backend-api/conversation/12345";
        let trusted_lower = trusted.to_ascii_lowercase();
        assert!(!dump_core_is_suspicious_connection(trusted, &trusted_lower));

        let untrusted = "powershell iwr https://api.map4yk.tech/download?key=1";
        let untrusted_lower = untrusted.to_ascii_lowercase();
        assert!(dump_core_is_suspicious_connection(untrusted, &untrusted_lower));
    }

    #[test]
    fn suspicious_connection_ignores_plain_benign_download_pages() {
        let benign = "https://www.python.org/downloads/release/python-31311/";
        let benign_lower = benign.to_ascii_lowercase();
        assert!(!dump_core_is_suspicious_connection(benign, &benign_lower));
    }

    #[test]
    fn suspicious_dll_ignores_known_runtime_temp_payloads() {
        let benign = r"\Device\HarddiskVolume3\Users\alice\AppData\Local\Temp\_MEI120562\VCRUNTIME140.dll";
        let benign_lower = benign.to_ascii_lowercase();
        assert!(!dump_core_is_suspicious_dll(benign, &benign_lower));
    }

    #[test]
    fn suspicious_dll_keeps_temp_sys_driver_alerts() {
        let suspicious = r"\??\C:\Users\alice\AppData\Local\Temp\GPU-Z-v2.sys";
        let suspicious_lower = suspicious.to_ascii_lowercase();
        assert!(dump_core_is_suspicious_dll(suspicious, &suspicious_lower));
    }

    #[test]
    fn suspicious_dll_ignores_known_discord_overlay_modules() {
        let benign = r"\Device\HarddiskVolume3\Users\alice\AppData\Local\Discord\app-1.0.9225\modules\discord_hook-1\discord_hook\aa11\DiscordHook64.dll";
        let benign_lower = benign.to_ascii_lowercase();
        assert!(!dump_core_is_suspicious_dll(benign, &benign_lower));
    }

    #[test]
    fn markup_noise_filter_flags_ui_html_fragments() {
        let noisy =
            r#"<a class="btn btn-primary" href="https://discord.gg/example" target="_blank">"#;
        let noisy_lower = noisy.to_ascii_lowercase();
        assert!(dump_core_is_markup_noise(&noisy_lower));
    }

    #[test]
    fn noise_filter_rejects_embedded_commandexecution_json() {
        let noisy = r#"{"type":"commandExecution","aggregatedOutput":"HTTP/1.1 200 OK"}"#;
        let noisy_lower = noisy.to_ascii_lowercase();
        assert!(dump_core_is_noise_line(noisy, &noisy_lower));
    }

    #[test]
    fn hidden_process_rule_ignores_previous_session_exited_cleanly_noise() {
        let noisy = r#"{"previous_session_pid":20228,"user_experience_metrics.stability.exited_cleanly":true}"#;
        let noisy_lower = noisy.to_ascii_lowercase();
        assert!(!dump_core_is_hidden_process(noisy, &noisy_lower));
    }

    #[test]
    fn hidden_process_rule_ignores_process_user_key_commands() {
        let noisy = r#""rg.exe" -n --hidden -S process_user_key C:\Users\alice"#;
        let noisy_lower = noisy.to_ascii_lowercase();
        assert!(!dump_core_is_hidden_process(noisy, &noisy_lower));
    }

    #[test]
    fn event_tag_mapper_classifies_process_create_events() {
        let line = "eventid=4688 cmd.exe /c whoami";
        assert_eq!(dump_core_event_tag(line), "process-create");
    }

    #[test]
    fn quick_interesting_keeps_search_index_artifacts() {
        let line = r"\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb";
        let lower = line.to_ascii_lowercase();
        assert!(dump_core_quick_interesting(&lower));
    }

    #[test]
    fn network_artifact_filters_plain_reference_url_noise() {
        let line = "https://github.com/rust-lang/rust/issues/1";
        let lower = line.to_ascii_lowercase();
        assert!(!dump_core_is_network_artifact(line, &lower));
        assert!(!dump_core_is_actionable_https_endpoint(line, &lower));
    }

    #[test]
    fn network_artifact_keeps_command_driven_download_urls() {
        let line = "powershell -NoProfile -Command Invoke-RestMethod -Uri 'https://api.map4yk.tech/download?key=abc' -Method Get";
        let lower = line.to_ascii_lowercase();
        assert!(dump_core_is_network_artifact(line, &lower));
        assert!(dump_core_is_actionable_https_endpoint(line, &lower));
    }

    #[test]
    fn network_artifact_skips_crashpad_telemetry_urls() {
        let line = r#""C:\Program Files\Yandex\YandexBrowser\Application\browser.exe" --type=crashpad-handler --url=https://crash-reports.browser.yandex.net/submit"#;
        let lower = line.to_ascii_lowercase();
        assert!(!dump_core_is_actionable_https_endpoint(line, &lower));
    }

    #[test]
    fn network_artifact_ignores_comment_style_doc_links() {
        let line = "# https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Masquerade-PEB.ps1";
        let lower = line.to_ascii_lowercase();
        assert!(!dump_core_is_actionable_https_endpoint(line, &lower));
        assert!(!dump_core_is_network_artifact(line, &lower));
    }

    #[test]
    fn open_artifact_ignores_program_files_third_party_notice_noise() {
        let line = r"\Device\HarddiskVolume3\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\Linux\Linux\ThirdPartyNotices.txt";
        let lower = line.to_ascii_lowercase();
        assert!(!dump_core_is_open_artifact(line, &lower));
    }

    #[test]
    fn open_artifact_keeps_appdata_executable_paths() {
        let line = r"\Device\HarddiskVolume3\Users\alice\AppData\Roaming\evilhook\loader.exe";
        let lower = line.to_ascii_lowercase();
        assert!(dump_core_is_open_artifact(line, &lower));
    }

    #[test]
    fn open_artifact_ignores_router_tun_stderr_blob() {
        let line = r#"{"data":"+0800 2026-02-21 03:30:17 INFO router: found process path: C:\\Windows\\System32\\svchost.exe\n+0800 2026-02-21 03:30:17 INFO [1418516170 0ms] inbound/tun[tun-in]: inbound packet connection to 1.1.1.1:53\n","event":"stderr","process-id":"sing-box-tun"}"#;
        let lower = line.to_ascii_lowercase();
        assert!(!dump_core_is_open_artifact(line, &lower));
    }

    #[test]
    fn open_artifact_ignores_malformed_prefixed_device_path() {
        let line = r#"G\Device\HarddiskVolume3\Program Files\SystemInformer\SystemInformer.exe"#;
        let lower = line.to_ascii_lowercase();
        assert!(!dump_core_is_open_artifact(line, &lower));
    }

    #[test]
    fn normalize_device_harddiskvolume_with_numeric_dup_prefix() {
        let line = r"\DEVICE\HARDDISKVOLUME3 \3\PROGRAM FILES\SYSTEMINFORMER\PLUGINS\USERNOTES.DLL";
        let normalized = normalize_dump_core_line(line).unwrap_or_default();
        let lower = normalized.to_ascii_lowercase();
        assert!(normalized.starts_with("C:\\"));
        assert!(!lower.contains("harddiskvolume"));
        assert!(lower.contains("program files\\systeminformer\\plugins\\usernotes.dll"));
    }

    #[test]
    fn normalize_device_harddiskvolume_with_space_before_user_path() {
        let line = r"\DEVICE\HARDDISKVOLUME3 \USERS\JUMARF\DESKTOP\FIND\JMD_UNPACK\RUN_TMP\JMD_HOOK_AHO_20260221_010551.EXE";
        let normalized = normalize_dump_core_line(line).unwrap_or_default();
        let lower = normalized.to_ascii_lowercase();
        assert!(normalized.starts_with("C:\\"));
        assert!(!lower.contains("harddiskvolume"));
        assert!(lower.contains(
            "users\\jumarf\\desktop\\find\\jmd_unpack\\run_tmp\\jmd_hook_aho_20260221_010551.exe"
        ));
    }

    #[test]
    fn open_artifact_ignores_parenthesized_and_env_blobs() {
        let line_one =
            r#"(c:\Users\jumarf\Documents\cheat\findrust C:\Windows\System32\svchost.exe\System32\svchost.exe"#;
        let lower_one = line_one.to_ascii_lowercase();
        assert!(!dump_core_is_open_artifact(line_one, &lower_one));

        let line_two = r#"LOCALAPPDATA=C:\Users\jumarf\AppData\Local C:\Program Files\SystemInformer\SystemInformer.exeer\SystemInformer.exe"#;
        let lower_two = line_two.to_ascii_lowercase();
        assert!(!dump_core_is_open_artifact(line_two, &lower_two));
    }

    #[test]
    fn minecraft_localization_noise_is_not_cheat_signal() {
        let noisy = r#""block.minecraft.potted_red_tulip": "Maceta con tulip""#;
        let lower = noisy.to_ascii_lowercase();
        assert!(!dump_core_is_minecraft_cheat_signal(&lower));

        let cheat = r#"meteorclient loaded for minecraft clicker module"#;
        let cheat_lower = cheat.to_ascii_lowercase();
        assert!(dump_core_is_minecraft_cheat_signal(&cheat_lower));
    }

    #[test]
    fn benign_knowndll_entries_are_not_suspicious_dlls() {
        let line = r"\KnownDlls\ntdll.dll";
        let lower = line.to_ascii_lowercase();
        assert!(dump_core_is_benign_knowndll_entry(&lower));
        assert!(!dump_core_is_suspicious_dll(line, &lower));
    }

    #[test]
    fn persistence_rule_ignores_benign_knowndll() {
        let line = r"\KnownDlls\ntdll.dll";
        let lower = line.to_ascii_lowercase();
        assert!(!dump_core_is_actionable_persistence_line(line, &lower));
    }

    #[test]
    fn persistence_rule_keeps_silent_process_exit() {
        let line = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\game.exe\SilentProcessExit MonitorProcess";
        let lower = line.to_ascii_lowercase();
        assert!(dump_core_is_actionable_persistence_line(line, &lower));
    }

    #[test]
    fn proxy_bypass_detector_requires_minecraft_and_proxy_context() {
        let strong = r#"javaw.exe --gameDir C:\Users\alice\AppData\Roaming\.minecraft proxyserver=127.0.0.1:10808 sing-box tun2socks"#;
        let strong_lower = strong.to_ascii_lowercase();
        assert!(dump_core_is_proxy_bypass_signal(strong, &strong_lower));

        let weak = r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings /v ProxyEnable /t REG_DWORD /d 1 /f"#;
        let weak_lower = weak.to_ascii_lowercase();
        assert!(!dump_core_is_proxy_bypass_signal(weak, &weak_lower));
    }

    #[test]
    fn proxy_bypass_detector_ignores_faker_and_safemode_markers() {
        let faker_line = r#"javaw.exe --gameDir C:\Users\alice\AppData\Roaming\.minecraft proxyserver=127.0.0.1:10808 faker safemode"#;
        let faker_lower = faker_line.to_ascii_lowercase();
        assert!(!dump_core_is_proxy_bypass_signal(faker_line, &faker_lower));
    }
}
