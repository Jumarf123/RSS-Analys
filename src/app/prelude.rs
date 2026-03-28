// Core imports, constants, shared data models, UI helpers, and startup entry point.

use aho_corasick::{AhoCorasickBuilder, AhoCorasickKind};
use blake3::Hasher as Blake3Hasher;
use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::execute;
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::terminal::{
    self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, SetTitle,
};
use include_dir::{Dir, include_dir};
use jwalk::{Parallelism, WalkDir};
use regex::Regex;
use rustc_hash::{FxHashMap, FxHashSet};
use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};
use sysinfo::System;
use yara_x::{Compiler, Rules, Scanner};

#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
#[cfg(windows)]
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
#[cfg(windows)]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_GUARD,
    PAGE_NOACCESS, VirtualQueryEx,
};
#[cfg(windows)]
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
#[cfg(windows)]
use windows::core::w;

static YARA_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/yara");
static BLAKE3_HASH_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/blake3");
const DMP_CONVERT_MAX: usize = usize::MAX;
const DMP_STRINGS_TIMEOUT_SECS: u64 = 900;
const DMP_STRINGS_HEARTBEAT_SECS: u64 = 15;
const FAST_INPUT_STRINGS_TIMEOUT_SECS: u64 = 180;
const PE_ONLY_EXTS: &[&str] = &["exe", "dll"];
const YARA_SCAN_EXTS: &[&str] = &["exe", "dll", "jar"];
const JAR_EXTS: &[&str] = &["jar"];
const RESOLVE_EXTS: &[&str] = &["exe", "dll", "jar", "bat", "cmd", "ps1", "pf", "txt"];
const SCRIPT_EXTS: &[&str] = &["bat", "cmd", "ps1"];
const PREFETCH_EXTS: &[&str] = &["pf"];
const START_EXTS: &[&str] = &["exe", "dll", "bat", "cmd", "ps1", "jar", "txt"];
const TRACKED_FILE_EXTS: &[&str] = &["exe", "dll", "bat", "cmd", "ps1", "jar", "pf"];
const BIN_EXTS: &[&str] = &["exe", "dll", "bat", "cmd", "ps1", "jar", "pf"];
const DOWNLOAD_LINK_EXTS: &[&str] = &["exe", "dll", "jar", "zip", "rar"];
const PRIMARY_LOCAL_DISKS: &[char] = &['C', 'D'];
const BRAND_SITE: &str = "Residence Screenshare";
const BRAND_DISCORD: &str = "https://discord.gg/residencescreenshare";
const BRAND_WINDOW_TITLE: &str = "RSS-Analys by Residence Screenshare";
const PROCESS_STRINGS_CHUNK_SIZE: usize = 2 * 1024 * 1024;
const PROCESS_STRINGS_OVERLAP: usize = 1024;
const PROCESS_STRINGS_MIN_LEN: usize = 6;
const PROCESS_SCAN_DEFAULT_MAX_MB: usize = 192;
const PROCESS_SCAN_CUSTOM_MAX_MB: usize = 384;
const PROCESS_SCAN_DEFAULT_REGION_MAX_MB: usize = 24;
const PROCESS_SCAN_CUSTOM_REGION_MAX_MB: usize = 64;
const PROCESS_SCAN_DEFAULT_TIMEOUT_SECS: u64 = 35;
const PROCESS_SCAN_CUSTOM_TIMEOUT_SECS: u64 = 90;
const BUILTIN_STRINGS_MIN_LEN: usize = 6;
const BUILTIN_STRINGS_READ_CHUNK: usize = 64 * 1024 * 1024;
const BUILTIN_STRINGS_READ_BUFFER: usize = 64 * 1024 * 1024;
const BUILTIN_STRINGS_INMEM_MIN_BYTES: u64 = 8 * 1024 * 1024;
const BUILTIN_STRINGS_INMEM_MAX_BYTES: u64 = 512 * 1024 * 1024;
const BUILTIN_FAST_DMP_PARALLEL_MIN_BYTES: u64 = 768 * 1024 * 1024;
const BUILTIN_FAST_DMP_PARALLEL_CHUNK_BYTES: usize = 128 * 1024 * 1024;
const BUILTIN_FAST_DMP_PARALLEL_OVERLAP_BYTES: usize = 512 * 1024;
const CUSTOM_FEED_BATCH_BYTES: usize = 64 * 1024;
const CUSTOM_PROCESS_SEEN_LIMIT: usize = 120_000;
const LINE_STITCH_MAX_PENDING_BYTES: usize = 16 * 1024;
const LARGE_TEXT_PARALLEL_THRESHOLD_BYTES: u64 = 12 * 1024 * 1024;
const LARGE_TEXT_CHUNK_TARGET_BYTES: usize = 4 * 1024 * 1024;
const IO_STREAM_BUFFER_BYTES: usize = 1024 * 1024;
const HTML_JS_ARRAY_LIMIT: usize = usize::MAX;
const HTML_JS_ITEM_MAX_CHARS: usize = usize::MAX;
const MAX_FILE_TIME_HINTS_PER_FILE: usize = 256;
const MAX_FILE_TIME_HINTS_PER_ROW: usize = 3;
const DEEP_LOOKUP_MAX_NAMES: usize = 12_000;
const DEEP_LOOKUP_AUTO_MAX_NAMES: usize = 3_000;
const DEEP_LOOKUP_ROOT_TIMEOUT_SECS: u64 = 14;
const YARA_TARGET_SOFT_LIMIT: usize = 1_800;
const RUN_LIVE_TIMELINE_LIMIT: usize = 1_400;
const RUN_LIVE_EVIDENCE_LIMIT: usize = 8_000;

const SUSPICIOUS: &[&str] = &[
    "drip",
    "bypass",
    "cheat",
    "cheatengine",
    "keyauth",
    "vape",
    "crack",
    "celestial",
    "melonity",
    "celka",
    "akrien",
    "minced",
    "bushroot",
    "hitbox",
    "exloader",
    "clickcrystal",
    "autoclicker",
    "autoclick",
    "macro",
    "macros",
    "loader",
    "injector",
    "dllinject",
    "aimassist",
    "aimassistance",
    "killaura",
    "autoattack",
    "wurst",
    "konas",
    "rusherhack",
    "zamorozka",
    "novoline",
    "tenacity",
    "dortware",
    "inertia",
    "phobos",
    "thunderhack",
    "bleachhack",
    "sallos",
    "cyanit",
    "lyvell",
    "xerxes",
    "instavape",
    "placebo",
    "gclient",
    "omicron",
    "xetha",
    "conceal",
    "pandora",
    "rebellion",
	"nursultan",
	"celestial",
	"celka",
	"minced",
	"exloader",
	"macros",
	"catlean",
	"catlavan",
	"thunderhack",
	"bleachhack",
	"wexside",
	"arbuz",
	"zenith",
	"rockstar",
	"melonity",
	"nurik",
];

const REMOTE_ACCESS_KEYWORDS: &[&str] = &[
    "anydesk",
    "teamviewer",
    "rustdesk",
    "parsec",
    "splashtop",
    "screenconnect",
    "connectwisecontrol",
    "supremo",
    "remoteutilities",
    "getscreen",
    "ultraviewer",
    "hoptodesk",
    "zohoassist",
    "ultravnc",
    "tightvnc",
    "realvnc",
    "aeroadmin",
    "ammyy",
    "radmin",
    "dwservice",
    "dwagent",
    "remoting_host",
    "quickassist",
    "nomachine",
    "gotomypc",
    "gotoassist",
    "logmein",
    "logmeinrescue",
    "remotepc",
    "islonline",
    "bomgar",
    "beyondtrust",
    "simplehelp",
    "rescueassist",
];

const CHEAT_ARTIFACT_KEYWORDS: &[&str] = &[
    "cheatengine",
    "cheat engine",
    "keyauth",
    "xenos",
    "extreme injector",
    "gh injector",
    "kdmapper",
    "kdu",
    "hwidspoofer",
    "hwid spoofer",
    "silentaim",
    "killaura",
    "aimassist",
    "autoclicker",
    "wallhack",
    "aimbot",
    "esp",
    "bhop",
    "norecoil",
    "no recoil",
    "mapper",
    "dsefix",
    "iqvw64e",
    "mhyprot",
    "dbutil_2_3",
    "gdrv",
    "rtcore64",
    "capcom.sys",
    "asusgio",
    "winring0",
    "eac bypass",
    "battleye bypass",
    "vgk bypass",
    "vanguard bypass",
	"nursultan",
	"celestial",
	"celka",
	"minced",
	"exloader",
	"macros",
	"catlean",
	"catlavan",
	"thunderhack",
	"bleachhack",
	"wexside",
	"arbuz",
	"zenith",
	"rockstar",
	"melonity",
	"nurik",
];

const BYPASS_ARTIFACT_KEYWORDS: &[&str] = &[
    "sdelete",
    "bleachbit",
    "ccleaner",
    "timestomp",
    "set-mace",
    "setmace",
    "exiftool",
    "openstego",
    "steghide",
    "imdisk",
    "rubber ducky",
    "duckyscript",
    "ducky script",
    "auditpol /clear",
    "wevtutil cl",
    "vssadmin delete shadows",
    "fsutil usn deletejournal",
    "clear-recyclebin",
    "streams.exe",
    "dnscat",
    "iodine",
    "veracrypt",
    "truecrypt",
    "bcdedit /set testsigning on",
    "bcdedit /set nointegritychecks on",
	"Fsutil usn delete journal",
];

const SUSPICIOUS_LINK_KEYWORDS: &[&str] = &[
    "drip",
    "cheatengine",
    "keyauth",
    "vape",
    "celestial",
    "melonity",
    "akrien",
    "minced",
    "exloader",
    "clickcrystal",
    "autoclicker",
    "dllinject",
    "aimassist",
    "killaura",
    "autoattack",
    "wurst",
    "rusherhack",
    "novoline",
    "tenacity",
    "dortware",
    "inertia",
    "phobos",
    "thunderhack",
    "bleachhack",
    "sallos",
    "cyanit",
    "lyvell",
    "xerxes",
    "instavape",
    "xetha",
    "spoofer",
    "kdmapper",
    "xenos",
    "timestomp",
    "sdelete",
    "bleachbit",
	"nursultan",
	"celestial",
	"celka",
	"minced",
	"exloader",
	"macros",
	"catlean",
	"catlavan",
	"thunderhack",
	"bleachhack",
	"wexside",
	"arbuz",
	"zenith",
	"rockstar",
	"melonity",
	"nurik",
];

const SUSPICIOUS_DOMAIN_HOSTS: &[&str] = &[
    "keyauth.win",
    "unknowncheats.me",
    "yougame.biz",
    "elitepvpers.com",
    "guidedhacking.com",
    "mpgh.net",
    "x64.gg",
    "cheater.fun",
	"celka.xyz",
	"nursultan.fun",
];

const BYOVD_DRIVER_NAMES: &[&str] = &[
    "iqvw64e.sys",
    "rtcore64.sys",
    "gdrv.sys",
    "capcom.sys",
    "asusgio.sys",
    "winring0x64.sys",
    "winring0.sys",
    "dbutil_2_3.sys",
    "mhyprot2.sys",
    "eneio64.sys",
];

const REMOTE_ACCESS_DOMAINS: &[&str] = &[
    "anydesk.com",
    "teamviewer.com",
    "rustdesk.com",
    "parsec.app",
    "splashtop.com",
    "dwservice.net",
    "screenconnect.com",
    "getscreen.me",
    "remotedesktop.google.com",
    "remoteassistance.support.services.microsoft.com",
    "nomachine.com",
    "gotomypc.com",
    "gotoassist.com",
    "logmein.com",
    "logmeinrescue.com",
    "remotepc.com",
    "islonline.com",
    "bomgar.com",
    "beyondtrust.com",
    "simple-help.com",
    "rescueassist.com",
];

const REMOTE_SESSION_KEYWORDS: &[&str] = &[
    "anydesk",
    "teamviewer",
    "rustdesk",
    "parsec",
    "splashtop",
    "screenconnect",
    "connectwisecontrol",
    "supremo",
    "remoteutilities",
    "getscreen",
    "ultraviewer",
    "ultravnc",
    "tightvnc",
    "realvnc",
    "aeroadmin",
    "ammyy",
    "radmin",
    "dwagent",
    "dwservice",
    "quickassist",
    "quick assist",
    "remoteassistance",
    "remotedesktop.google.com",
    "remoting_host",
    "chrome remote desktop",
    "mstsc",
    "msra",
    "rdpclip",
    "nomachine",
    "gotomypc",
    "gotoassist",
    "logmein",
    "logmeinrescue",
    "remotepc",
    "islonline",
    "bomgar",
    "beyondtrust",
    "simplehelp",
    "rescueassist",
];

const NETWORK_TUNNEL_KEYWORDS: &[&str] = &[
    "ngrok",
    "cloudflared",
    "trycloudflare",
    "chisel",
    "frpc",
    "frps",
    "localxpose",
    "playit",
    "pinggy",
    "tailscale",
    "zerotier",
    "wireguard",
    "hamachi",
    "wstunnel",
];

const NETWORK_TUNNEL_DOMAINS: &[&str] = &[
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "localxpose.io",
    "playit.gg",
    "pinggy.io",
    "tailscale.com",
    "zerotier.com",
];

const TOOL_LINK_NOISE_DOMAINS: &[&str] = &[
    "yandex.ru",
    "ya.ru",
    "google.com",
    "bing.com",
    "duckduckgo.com",
    "yahoo.com",
    "rambler.ru",
    "translate.yandex.ru",
    "favicon.yandex.net",
    "googletagmanager.com",
    "vk.com",
    "youtube.com",
];

const LOW_VALUE_TOOL_LINK_HOSTS: &[&str] = &[
    "github.com",
    "www.github.com",
    "gitlab.com",
    "www.gitlab.com",
    "bitbucket.org",
    "www.bitbucket.org",
    "sourceforge.net",
    "www.sourceforge.net",
];

const TOOL_PATH_NOISE_MARKERS: &[&str] = &[
    "\\service worker\\cachestorage\\",
    "\\service worker\\scriptcache\\",
    "\\code cache\\",
    "\\gpucache\\",
    "\\cache\\cache_data\\",
    "\\cache\\cache2\\entries\\",
    "\\webcache\\",
    "\\shadercache\\",
    "\\localstate\\appiconcache\\",
    "\\node_modules\\",
    "\\temp\\scoped_dir",
];

const FALSE_POSITIVE_SUSPICIOUS_FILE_NAMES: &[&str] = &[
    "triggerbot.exe",
    "triggerbot64.exe",
    "doomsday.exe",
    "doomsday64.exe",
];

#[inline]
fn available_cpu_threads() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(1)
}

#[inline]
fn cpu_worker_budget_45_from_cpu(cpu: usize) -> usize {
    if cpu <= 2 {
        return 1;
    }
    let ratio = env::var("RSS_ANALYS_CPU_BUDGET_PCT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(25, 95))
        .unwrap_or(50);
    let mut budget = cpu.saturating_mul(ratio).saturating_div(100).max(1);
    if cpu >= 6 {
        budget = budget.min(cpu.saturating_sub(1));
    }
    budget.max(1)
}

const IOC: &[&str] = &[
    "cmd",
    "reg",
    "hkey",
    "delete",
    "type",
    "echo",
    "forfiles",
    "wmic",
    "regsvr32",
    "rundll32",
    "powershell",
    "invoke-expression",
    "encodedcommand",
    "iex",
    "iwr",
    "http",
    "github",
    "pastebin",
    "base64",
    "invoke",
    "download",
];

const NOISE: &[&str] = &[
    "+j(cm:",
    "pgrf:",
    "usbxhci",
    "rtlstringcchcopyw failed",
    "od8_",
    "smctablemanager",
    "fb memory copy failed",
    "frame buffer memory copy failed",
];

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s\"'<>`]+"#).expect("url regex"));
static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{2,5})?(?:/[^\s\"'<>`]*)?"#,
    )
    .expect("domain regex")
});
static EXT_CHUNK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(?:exe|dll|bat|cmd|ps1|jar|pf)\w*").expect("ext chunk"));
static EXT_END_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(exe|dll|bat|cmd|ps1|jar|pf)").expect("ext end"));
static ROOTED_BIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:[a-z]\s*:\s*[\\/]|\\\\\?\\|\\\?\\|\\device\\harddiskvolume\d+\\)[^\r\n"'<>|]{1,520}?\.(?:exe|dll|bat|cmd|ps1|jar|pf)"#,
    )
    .expect("rooted bin")
});
static YARA_RULE_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\s*(?:(?:private|global)\s+)*(?:private|global)?\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
        .expect("yara rule regex")
});
static PROCESS_START_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bprocessstart\s*,\s*([^\r\n]+)").expect("process start"));
static DPS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)!{1,2}([^!\r\n]+?\.[a-z0-9]{1,16})!([0-9]{4}/[0-9]{2}/[0-9]{2}:[0-9]{2}:[0-9]{2}:[0-9]{2})!\d+!")
        .expect("dps row")
});
static CUSTOM_PROTOCOL_SCHEME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b([a-z][a-z0-9+.-]{1,31})://").expect("custom scheme"));
static FILE_TIME_HINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:\d{4}[/-]\d{2}[/-]\d{2}(?:[ T:_-]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)?|\d{2}\.\d{2}\.\d{4}(?:[ T_-]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)?)\b",
    )
    .expect("file time hint")
});
static YMD_TIME_HINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(\d{4})[/-](\d{2})[/-](\d{2})(?:[ T:_-](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:\s*(Z|[+-]\d{2}:?\d{2}))?)?$",
    )
    .expect("ymd time hint")
});
static DMY_TIME_HINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(\d{2})\.(\d{2})\.(\d{4})(?:[ T_-](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?)?$")
        .expect("dmy time hint")
});
static PREFETCH_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^([A-Z0-9._ -]+)-([A-F0-9]{8})\.pf$").expect("prefetch name")
});
static TYPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^\s*(?:cmd(?:\.exe)?\s*/c\s+)?type\s+("[^"]+"|\S+)\s*>\s*("[^"]+"|\S+)\s*$"#)
        .expect("type")
});
static COPY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)^\s*(?:cmd(?:\.exe)?\s*/c\s+)?copy\s+("[^"]+"|\S+)(?:\s+/(?:-?y)|\s+-y)?\s+("[^"]+"|\S+)\s*$"#,
    )
    .expect("copy")
});
static WMIC_PROCESS_CALL_CREATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bwmic(?:\.exe)?\s+process\s+call\s+create\b")
        .expect("wmic process call create")
});
static REG_DELETE_CMD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:cmd(?:\.exe)?\s*/[ck]\s+)?(?:"[^"]*\\)?reg(?:\.exe)?(?:")?\s+delete\b"#)
        .expect("reg delete")
});
static REG_HIVE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:hkey_(?:local_machine|current_user|classes_root|users|current_config)|hk(?:lm|cu|cr|u|cc)|\\registry\\machine|\\registry\\user)\b",
    )
    .expect("reg hive")
});
static ECHO_REDIRECT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\becho\b[^\r\n]{0,260}(?:>>?|1>|2>)[^\r\n]+").expect("echo redirect")
});
static RUNDLL32_DLL_ENTRY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\brundll32(?:\.exe)?\b[^\r\n]{0,260}\.dll\s*,\s*[a-z0-9_@#]+")
        .expect("rundll32 dll entry")
});
static RUNDLL32_SCRIPT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\brundll32(?:\.exe)?\b[^\r\n]{0,260}(?:javascript:|vbscript:|mshtml,runhtmlapplication)",
    )
    .expect("rundll32 script")
});
static REGSVR32_USAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\bregsvr32(?:\.exe)?\b[^\r\n]{0,260}(?:\bscrobj\.dll\b|/i:(?:https?://|\\\\)[^\s"']+|https?://[^\s"']+|\.dll\b)"#,
    )
    .expect("regsvr32 usage")
});
static JAVA_JAR_EXEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bjava(?:w)?(?:\.exe)?\b[^\r\n]{0,140}\s-jar\b\s+("[^"]+\.jar"|\S+\.jar)\b"#)
        .expect("java jar")
});
static BATCH_LAUNCH_CTX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|start|call|schtasks|wscript|cscript)\b",
    )
    .expect("batch launch ctx")
});
static DEVICE_VOLUME_MAP: LazyLock<HashMap<String, String>> =
    LazyLock::new(build_device_volume_map);

#[derive(Default)]
struct Analyzer {
    links: BTreeSet<String>,
    regdel: BTreeSet<String>,
    replace: BTreeSet<String>,
    fileless: BTreeSet<String>,
    dll: BTreeSet<String>,
    forfiles_wmic: BTreeSet<String>,
    java_batch: BTreeSet<String>,
    ioc: BTreeSet<String>,
    full_paths: BTreeSet<String>,
    pathless: BTreeSet<String>,
    java_paths: BTreeSet<String>,
    scripts: BTreeSet<String>,
    start: BTreeSet<String>,
    prefetch: BTreeSet<String>,
    dps_files: BTreeSet<String>,
    dps_events: BTreeSet<(String, String)>,
    beta: BTreeSet<String>,
    file_time_hints: HashMap<String, BTreeSet<String>>,
}

#[derive(Clone, Copy)]
enum UiLang {
    Ru,
    En,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AnalysisMode {
    Fast,
    Medium,
    Slow,
}

impl AnalysisMode {
    fn from_menu(choice: u8) -> Self {
        match choice {
            1 => Self::Fast,
            2 => Self::Medium,
            3 => Self::Slow,
            _ => Self::Fast,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Medium => "medium",
            Self::Slow => "slow",
        }
    }

    fn metric_value(self) -> usize {
        match self {
            Self::Fast => 1,
            Self::Medium => 2,
            Self::Slow => 3,
        }
    }

    fn default_sort_hash(self) -> bool {
        matches!(self, Self::Slow)
    }

    fn dump_fast_profile_default(self) -> bool {
        matches!(self, Self::Fast)
    }

    fn dmp_fast_convert_default(self) -> bool {
        matches!(self, Self::Fast)
    }

    fn fast_prepare_inputs_default(self) -> bool {
        matches!(self, Self::Fast)
    }

    fn low_signal_pe_filter_default(self) -> bool {
        matches!(self, Self::Fast)
    }

    fn skip_normalpe_for_speed_default(self) -> bool {
        matches!(self, Self::Fast)
    }

    fn deep_lookup_force_default(self) -> bool {
        matches!(self, Self::Slow)
    }

    fn deep_lookup_auto_limit_default(self) -> usize {
        match self {
            Self::Fast => DEEP_LOOKUP_AUTO_MAX_NAMES,
            Self::Medium => 6_000,
            Self::Slow => usize::MAX,
        }
    }

    fn deep_lookup_hard_limit_default(self) -> usize {
        match self {
            Self::Fast => DEEP_LOOKUP_MAX_NAMES,
            Self::Medium => DEEP_LOOKUP_MAX_NAMES.saturating_mul(2),
            Self::Slow => usize::MAX,
        }
    }

    fn allow_large_dmp_deep_skip_default(self) -> bool {
        matches!(self, Self::Fast)
    }

    fn yara_soft_limit_default(self) -> Option<usize> {
        match self {
            Self::Fast => Some(160),
            Self::Medium => Some(YARA_TARGET_SOFT_LIMIT),
            Self::Slow => None,
        }
    }
}

struct UserOptions {
    lang: UiLang,
    analysis_mode: AnalysisMode,
    sort_hash: bool,
    process_scan_mode: ProcessScanMode,
    memory_orbit_enabled: bool,
}

#[derive(Clone, Debug)]
struct PreparedInput {
    source: PathBuf,
    scan: PathBuf,
    // True when `scan` already contains aggressively prefiltered fast lines.
    fast_prepared: bool,
}

#[derive(Clone, Debug, Default)]
struct RunLiveContext {
    timeline: Vec<String>,
    metrics: BTreeMap<String, usize>,
    evidence: BTreeSet<String>,
}

impl RunLiveContext {
    fn note_stage(&mut self, stage: &str, detail: &str) {
        let stage = run_live_sanitize(stage, 64);
        let detail = run_live_sanitize(detail, 420);
        if stage.is_empty() || detail.is_empty() {
            return;
        }
        self.timeline.push(format!("[{stage}] {detail}"));
        if self.timeline.len() > RUN_LIVE_TIMELINE_LIMIT {
            let drain = self
                .timeline
                .len()
                .saturating_sub(RUN_LIVE_TIMELINE_LIMIT);
            self.timeline.drain(0..drain);
        }
    }

    fn note_metric(&mut self, key: &str, value: usize) {
        let key = run_live_sanitize(key, 96);
        if key.is_empty() {
            return;
        }
        self.metrics.insert(key, value);
    }

    fn absorb_rows(&mut self, source: &str, rows: &BTreeSet<String>, max_take: usize) {
        let source = run_live_sanitize(source, 48);
        if source.is_empty() || max_take == 0 || rows.is_empty() {
            return;
        }
        for row in rows.iter().take(max_take) {
            let clean = run_live_sanitize(row, 420);
            if clean.is_empty() {
                continue;
            }
            self.evidence.insert(format!("[{source}] {clean}"));
            if self.evidence.len() > RUN_LIVE_EVIDENCE_LIMIT {
                if let Some(first) = self.evidence.iter().next().cloned() {
                    self.evidence.remove(&first);
                } else {
                    break;
                }
            }
        }
    }
}

fn run_live_sanitize(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .replace('\t', " ")
        .replace('\r', " ")
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max_chars)
        .collect::<String>()
}

static UI_LANG: OnceLock<UiLang> = OnceLock::new();
static RUN_UI: OnceLock<Mutex<RunUi>> = OnceLock::new();

#[derive(Clone, Debug)]
struct CustomRule {
    client: String,
    patterns: Vec<String>,
    min_hits: usize,
    source: String,
    target_process: Option<String>,
}

#[derive(Clone, Debug)]
struct CompiledCustomRule {
    client: String,
    patterns: Vec<String>,
    pattern_ids: Vec<usize>,
    min_hits: usize,
    source: String,
    target_process: Option<String>,
}

#[derive(Clone, Debug)]
enum ProcessScanMode {
    None,
    All,
    Custom(ProcessSelection),
}

impl ProcessScanMode {
    fn enabled(&self) -> bool {
        !matches!(self, Self::None)
    }

    fn filter(&self) -> Option<&ProcessSelection> {
        match self {
            Self::Custom(v) => Some(v),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ProcessSelection {
    pids: BTreeSet<u32>,
    names: BTreeSet<String>,
}

impl ProcessSelection {
    fn is_empty(&self) -> bool {
        self.pids.is_empty() && self.names.is_empty()
    }
}

struct CustomMatcher {
    rules: Vec<CompiledCustomRule>,
    matcher: aho_corasick::AhoCorasick,
    pattern_to_rules: Vec<Vec<(usize, usize)>>,
    has_unscoped_rules: bool,
    scoped_process_names: HashSet<String>,
}

struct FastNeedleMatcher {
    needles: Vec<String>,
    matcher: Option<aho_corasick::AhoCorasick>,
}

struct CustomAccumulator<'a> {
    matcher: &'a CustomMatcher,
    matched_slots: Vec<Vec<bool>>,
    matched_counts: Vec<usize>,
    min_hits: Vec<usize>,
    active_rules: Vec<bool>,
    active_pattern_to_rules: Vec<Vec<(usize, usize)>>,
    rules_done: Vec<bool>,
    pending_rules: usize,
}

#[derive(Clone, Debug)]
struct CustomHit {
    client: String,
    source: String,
    matched_count: usize,
    min_hits: usize,
    total_patterns: usize,
}

#[derive(Default)]
struct CustomScanStats {
    rules_loaded: usize,
    input_files_scanned: usize,
    process_scanned: usize,
    process_skipped: usize,
    process_dumps: usize,
    hits_by_file: BTreeMap<String, Vec<CustomHit>>,
}

pub(crate) fn entry_point() {
    set_window_title();
    print_start_banner();
    let user_opts = prompt_user_options();
    let _ = UI_LANG.set(user_opts.lang);

    std::panic::set_hook(Box::new(|info| {
        eprintln!(
            "{}: {info}",
            tr_ui("Критическая ошибка (panic)", "Critical error (panic)")
        );
        eprintln!(
            "{}",
            tr_ui(
                "Программа завершилась аварийно. Проверьте входной файл и повторите запуск.",
                "Program crashed. Check input file and run again."
            )
        );
    }));

    let r = std::panic::catch_unwind(|| run(&user_opts));
    match &r {
        Ok(Ok(_)) => prompt_line(tr_ui("Готово.", "Done.")),
        Ok(Err(e)) => eprintln!("{}: {e}", tr_ui("Ошибка", "Error")),
        Err(_) => eprintln!(
            "{}",
            tr_ui(
                "Ошибка: выполнение прервано из-за panic.",
                "Error: execution was interrupted by panic."
            )
        ),
    }
    wait_for_enter();
    if !matches!(r, Ok(Ok(_))) {
        std::process::exit(1);
    }
}

fn print_start_banner() {
    let mut out = io::stdout();
    let _ = execute!(out, SetForegroundColor(Color::Red));
    println!(
        r#"
██████╗ ███████╗███████╗██╗██████╗ ███████╗███╗   ██╗ ██████╗███████╗
██╔══██╗██╔════╝██╔════╝██║██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝
██████╔╝█████╗  ███████╗██║██║  ██║█████╗  ██╔██╗ ██║██║     █████╗  
██╔══██╗██╔══╝  ╚════██║██║██║  ██║██╔══╝  ██║╚██╗██║██║     ██╔══╝  
██║  ██║███████╗███████║██║██████╔╝███████╗██║ ╚████║╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝
"#
    );
    println!("{BRAND_SITE} | {BRAND_DISCORD}");
    let _ = execute!(out, ResetColor);
}

fn prompt_user_options() -> UserOptions {
    prompt_line("Choose language Ru / En (1/2)");
    let lang = match read_menu_choice_12() {
        2 => UiLang::En,
        _ => UiLang::Ru,
    };

    let analysis_mode = read_analysis_mode(lang);

    let sort_hash = if analysis_mode.default_sort_hash() {
        prompt_line(tr(
            lang,
            "Режим slow: сортировка списка хешей включена автоматически.",
            "Slow mode: hash list sorting is forced on automatically.",
        ));
        true
    } else {
        prompt_line(tr(
            lang,
            "Сортировать список хешей? yes / no (1/2)",
            "Sort hash list? yes / no (1/2)",
        ));
        prompt_line(tr(
            lang,
            "Примечание: если yes, выполнение может быть медленнее примерно на +-1 минуту.",
            "Note: if yes, runtime can be slower by about +-1 minute.",
        ));
        matches!(read_menu_choice_12(), 1)
    };

    let process_scan_mode = read_process_scan_mode(lang);
    prompt_line(tr(
        lang,
        "Использовать движок Dump core? yes / no (1/2)",
        "Use Dump core engine? yes / no (1/2)",
    ));
    prompt_line(tr(
        lang,
        "Опция использует встроенный самописный парсер и работает для DMP.",
        "This option uses a built-in custom parser and works for DMP files.",
    ));
    let memory_orbit_enabled = matches!(read_menu_choice_12(), 1);

    UserOptions {
        lang,
        analysis_mode,
        sort_hash,
        process_scan_mode,
        memory_orbit_enabled,
    }
}

fn read_analysis_mode(lang: UiLang) -> AnalysisMode {
    prompt_line(tr(
        lang,
        "Выбери режим анализа: fast / medium / slow (1/2/3)",
        "Choose analysis mode: fast / medium / slow (1/2/3)",
    ));
    prompt_line(tr(
        lang,
        "1 = fast (только ключевое, максимум скорость), 2 = medium (минимум потерь + быстрее), 3 = slow (максимально подробно, как старый полный режим)",
        "1 = fast (key artifacts, max speed), 2 = medium (minimal losses + faster), 3 = slow (maximum detail, legacy full style)",
    ));
    AnalysisMode::from_menu(read_menu_choice_123())
}

fn prompt_line(message: &str) {
    if with_run_ui(|ui| {
        ui.push_log(message);
    }) {
        return;
    }
    let mut out = io::stdout();
    let _ = execute!(out, SetForegroundColor(Color::Red));
    println!("{message}");
    let _ = execute!(out, ResetColor);
}

fn set_window_title() {
    let mut out = io::stdout();
    let _ = execute!(out, SetTitle(BRAND_WINDOW_TITLE));
}

fn read_menu_choice_12() -> u8 {
    let mut line = String::new();
    for _ in 0..5 {
        line.clear();
        if io::stdin().read_line(&mut line).is_err() {
            continue;
        }
        let s = line.trim();
        if s == "1" {
            return 1;
        }
        if s == "2" {
            return 2;
        }
        prompt_line("Enter 1 or 2");
    }
    1
}

fn read_menu_choice_123() -> u8 {
    let mut line = String::new();
    for _ in 0..6 {
        line.clear();
        if io::stdin().read_line(&mut line).is_err() {
            continue;
        }
        match line.trim() {
            "1" => return 1,
            "2" => return 2,
            "3" => return 3,
            _ => prompt_line("Enter 1, 2 or 3"),
        }
    }
    2
}

fn read_process_scan_mode(lang: UiLang) -> ProcessScanMode {
    prompt_line(tr(
        lang,
        "Сканировать процессы? all / no / custom (1/2/3)",
        "Analyze processes? all / no / custom (1/2/3)",
    ));
    prompt_line(tr(
        lang,
        "1 = все процессы, 2 = нет, 3 = указать свои (имена/PID через пробел, / или запятую)",
        "1 = all processes, 2 = no, 3 = custom list (names/PIDs via space, / or comma)",
    ));
    match read_menu_choice_123() {
        1 => ProcessScanMode::All,
        2 => ProcessScanMode::None,
        3 => {
            let selected = read_custom_process_selection(lang);
            if selected.is_empty() {
                prompt_line(tr(
                    lang,
                    "Список пустой, скан процессов отключен.",
                    "Empty list, process scan disabled.",
                ));
                ProcessScanMode::None
            } else {
                ProcessScanMode::Custom(selected)
            }
        }
        _ => ProcessScanMode::None,
    }
}

fn read_custom_process_selection(lang: UiLang) -> ProcessSelection {
    let mut line = String::new();
    for _ in 0..5 {
        prompt_line(tr(
            lang,
            "Введите процессы (пример: javaw svchost или 123, 124):",
            "Enter processes (example: javaw svchost or 123, 124):",
        ));
        line.clear();
        if io::stdin().read_line(&mut line).is_err() {
            continue;
        }
        let parsed = parse_process_selection_line(&line);
        if !parsed.is_empty() {
            return parsed;
        }
        prompt_line(tr(
            lang,
            "Не удалось распознать ни PID, ни имя процесса. Повторите ввод.",
            "No PID or process name recognized. Try again.",
        ));
    }
    ProcessSelection::default()
}

fn parse_process_selection_line(raw: &str) -> ProcessSelection {
    let mut normalized = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if matches!(ch, ',' | ';' | '/' | '\\' | '|') {
            normalized.push(' ');
        } else {
            normalized.push(ch);
        }
    }

    let mut out = ProcessSelection::default();
    for part in normalized.split_whitespace() {
        let token = part
            .trim_matches(|c: char| matches!(c, '"' | '\'' | '[' | ']' | '(' | ')' | '{' | '}'))
            .trim();
        if token.is_empty() {
            continue;
        }
        if token.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(pid) = token.parse::<u32>() {
                if pid > 0 {
                    out.pids.insert(pid);
                }
            }
            continue;
        }
        if let Some(name) = normalize_process_match_name(token) {
            out.names.insert(name);
        }
    }
    out
}

fn normalize_process_match_name(value: &str) -> Option<String> {
    let mut name = value.trim().to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    if let Some(stem) = name.strip_suffix(".txt") {
        name = stem.to_string();
    }
    if let Some(stem) = name.strip_suffix(".exe") {
        name = stem.to_string();
    }
    if name.is_empty() {
        return None;
    }
    if name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    Some(name)
}

fn tr<'a>(lang: UiLang, ru: &'a str, en: &'a str) -> &'a str {
    match lang {
        UiLang::Ru => ru,
        UiLang::En => en,
    }
}

fn current_ui_lang() -> UiLang {
    *UI_LANG.get().unwrap_or(&UiLang::Ru)
}

fn tr_ui<'a>(ru: &'a str, en: &'a str) -> &'a str {
    tr(current_ui_lang(), ru, en)
}

struct RunUi {
    lang: UiLang,
    started: Instant,
    spinner_idx: usize,
    anim_tick: usize,
    step_current: usize,
    step_total: usize,
    stage: String,
    logs: VecDeque<String>,
    last_frame: Vec<String>,
    last_cols: u16,
    last_rows: u16,
    enabled: bool,
}

impl RunUi {
    fn new(lang: UiLang) -> Self {
        Self {
            lang,
            started: Instant::now(),
            spinner_idx: 0,
            anim_tick: 0,
            step_current: 0,
            step_total: 8,
            stage: tr(lang, "Ожидание запуска", "Waiting for start").to_string(),
            logs: VecDeque::with_capacity(256),
            last_frame: Vec::new(),
            last_cols: 0,
            last_rows: 0,
            enabled: true,
        }
    }

    fn push_log(&mut self, line: &str) {
        let sanitized = sanitize_ui_line(line);
        if sanitized.is_empty() {
            return;
        }
        self.logs.push_back(sanitized);
        if self.logs.len() > 240 {
            self.logs.pop_front();
        }
    }

    fn update_step(&mut self, message: &str) {
        if let Some((cur, total, stage)) = parse_step_marker(message) {
            self.step_current = cur;
            if total > 0 {
                self.step_total = total;
            }
            self.stage = stage;
        } else {
            self.stage = message.to_string();
        }
    }

    fn render(&mut self) {
        if !self.enabled {
            return;
        }
        let Ok((cols, rows)) = terminal::size() else {
            return;
        };
        let cols = cols as usize;
        let rows = rows as usize;
        if cols < 70 || rows < 16 {
            return;
        }

        let right_w = (cols / 3).clamp(28, 62);
        let left_w = cols.saturating_sub(right_w + 7).max(30);
        let title_lines = build_residence_title_lines(cols);
        let top_rows = title_lines.len() + 2;
        let body_rows = rows.saturating_sub(top_rows + 4).max(6);

        self.anim_tick = self.anim_tick.wrapping_add(1);
        self.spinner_idx = (self.spinner_idx + 1) % 12;
        let spinner = [
            "[>       ]",
            "[=>      ]",
            "[==>     ]",
            "[===>    ]",
            "[====>   ]",
            "[=====>  ]",
            "[======> ]",
            "[=======>]",
            "[ ======>]",
            "[  =====>]",
            "[   ====>]",
            "[    ===>]",
        ][self.spinner_idx];
        let elapsed = self.started.elapsed();
        let elapsed_text = format_elapsed_mmss(elapsed);
        let time_label = tr(self.lang, "Время", "Time");
        let loading_label = tr(self.lang, "Загрузка", "Loading");
        let logs_label = tr(self.lang, "Logs", "Logs");
        let progress_label = tr(self.lang, "Прогресс", "Progress");
        let stage_label = tr(self.lang, "Этап", "Stage");

        let mut frame = Vec::with_capacity(rows);
        for line in &title_lines {
            frame.push(truncate_ui_text(line, cols));
        }
        frame.push(format!(
            "{}: {}  |  {} {}  |  {:>2}/{}",
            time_label,
            elapsed_text,
            spinner,
            loading_label,
            self.step_current.min(self.step_total.max(1)),
            self.step_total.max(1)
        ));
        frame.push(format!("{}  |  {}", BRAND_SITE, BRAND_DISCORD));

        let bar_width = left_w.saturating_sub(20).clamp(12, 64);
        let total = self.step_total.max(1);
        let current = self.step_current.min(total);
        let fill = animated_progress_fill(current, total, bar_width, self.anim_tick);
        let bar = format!("[{fill}] {current}/{total}");

        let mut left_lines = Vec::new();
        left_lines.push(format!("{progress_label}: {bar}"));
        left_lines.push(format!("{stage_label}: {}", self.stage));
        left_lines.push(String::new());

        let mut log_rows = self
            .logs
            .iter()
            .rev()
            .take(body_rows)
            .cloned()
            .collect::<Vec<_>>();
        log_rows.reverse();

        frame.push(format!(
            "┌{}┬{}┐",
            "─".repeat(left_w + 2),
            "─".repeat(right_w + 2)
        ));
        frame.push(format!(
            "│ {:<left_w$} │ {:<right_w$} │",
            progress_label, logs_label
        ));
        for idx in 0..body_rows {
            let left = left_lines.get(idx).map(String::as_str).unwrap_or("");
            let right = log_rows.get(idx).map(String::as_str).unwrap_or("");
            frame.push(format!(
                "│ {:<left_w$} │ {:<right_w$} │",
                truncate_ui_text(left, left_w),
                truncate_ui_text(right, right_w)
            ));
        }
        frame.push(format!(
            "└{}┴{}┘",
            "─".repeat(left_w + 2),
            "─".repeat(right_w + 2)
        ));

        while frame.len() < rows {
            frame.push(String::new());
        }
        if frame.len() > rows {
            frame.truncate(rows);
        }

        let mut out = io::stdout();
        let full_redraw = self.last_cols != cols as u16 || self.last_rows != rows as u16;
        let mut wrote_any = false;
        if full_redraw {
            let _ = execute!(out, MoveTo(0, 0), Clear(ClearType::All));
            wrote_any = true;
        }
        if full_redraw {
            let _ = execute!(out, SetForegroundColor(Color::Red));
        }

        let max_lines = self.last_frame.len().max(frame.len());
        for y in 0..max_lines {
            let new_line = frame.get(y).map(String::as_str).unwrap_or("");
            let old_line = self.last_frame.get(y).map(String::as_str).unwrap_or("");
            if !full_redraw && new_line == old_line {
                continue;
            }
            if !wrote_any {
                let _ = execute!(out, SetForegroundColor(Color::Red));
            }
            let _ = execute!(out, MoveTo(0, y as u16));
            let line = fit_ui_text(new_line, cols);
            let _ = write!(out, "{line}");
            wrote_any = true;
        }
        if wrote_any {
            let _ = execute!(out, ResetColor);
            let _ = out.flush();
        }
        self.last_cols = cols as u16;
        self.last_rows = rows as u16;
        self.last_frame = frame;
    }
}

fn build_residence_title_lines(cols: usize) -> Vec<String> {
    if cols >= 90 {
        return vec![
            "██████╗ ███████╗███████╗██╗██████╗ ███████╗███╗   ██╗ ██████╗███████╗".to_string(),
            "██╔══██╗██╔════╝██╔════╝██║██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝".to_string(),
            "██████╔╝█████╗  ███████╗██║██║  ██║█████╗  ██╔██╗ ██║██║     █████╗  ".to_string(),
            "██╔══██╗██╔══╝  ╚════██║██║██║  ██║██╔══╝  ██║╚██╗██║██║     ██╔══╝  ".to_string(),
            "██║  ██║███████╗███████║██║██████╔╝███████╗██║ ╚████║╚██████╗███████╗".to_string(),
            "╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝".to_string(),
        ];
    }
    if cols >= 58 {
        return vec!["RSS-Analys".to_string()];
    }
    vec!["RSS-Analys".to_string()]
}

fn format_elapsed_mmss(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    let mins = secs / 60;
    let rem = secs % 60;
    format!("{mins:02}:{rem:02}")
}

fn animated_progress_fill(current: usize, total: usize, width: usize, tick: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let total = total.max(1);
    let current = current.min(total);
    let filled = width.saturating_mul(current) / total;

    let mut cells = vec!['-'; width];
    for ch in cells.iter_mut().take(filled.min(width)) {
        *ch = '#';
    }

    if current < total {
        if filled == 0 {
            cells[0] = '>';
        } else {
            let span = filled.max(1);
            let period = if span <= 1 { 1 } else { (span - 1) * 2 };
            let phase = if period == 0 { 0 } else { tick % period };
            let idx = if phase < span { phase } else { period - phase };
            let pos = idx.min(span - 1);
            cells[pos] = '>';
        }
    }

    cells.into_iter().collect::<String>()
}

fn parse_step_marker(message: &str) -> Option<(usize, usize, String)> {
    let start = message.find('[')?;
    let end = message[start..].find(']')? + start;
    let marker = message.get(start + 1..end)?.trim();
    if marker.is_empty() {
        return None;
    }

    let stage = message.get(end + 1..).unwrap_or(message).trim().to_string();
    if let Some((cur_raw, total_raw)) = marker.split_once('/') {
        let cur = cur_raw.trim().parse::<usize>().ok()?;
        let total = total_raw.trim().parse::<usize>().ok()?;
        return Some((cur, total, stage));
    }

    let digits = marker
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    let cur = digits.parse::<usize>().ok()?;
    Some((cur, 8, stage))
}

fn truncate_ui_text(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        if used >= width {
            break;
        }
        let ch = if ch.is_control() { ' ' } else { ch };
        out.push(ch);
        used += 1;
    }
    out
}

fn fit_ui_text(text: &str, width: usize) -> String {
    let mut out = truncate_ui_text(text, width);
    let len = out.chars().count();
    if len < width {
        out.push_str(&" ".repeat(width - len));
    }
    out
}

fn sanitize_ui_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(1024));
    let mut last_space = false;
    let mut used = 0usize;
    for ch in text.chars() {
        let mapped = match ch {
            '\r' | '\n' | '\t' => ' ',
            c if c.is_control() => ' ',
            c => c,
        };
        if mapped == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
            out.push(' ');
        } else {
            last_space = false;
            out.push(mapped);
        }
        used += 1;
        if used >= 1000 {
            break;
        }
    }
    out.trim().to_string()
}

fn with_run_ui<F>(f: F) -> bool
where
    F: FnOnce(&mut RunUi),
{
    let Some(lock) = RUN_UI.get() else {
        return false;
    };
    let Ok(mut ui) = lock.lock() else {
        return false;
    };
    if !ui.enabled {
        return false;
    }
    f(&mut ui);
    true
}

struct RunUiGuard {
    active: bool,
    stop: Option<Arc<AtomicUsize>>,
    ticker: Option<thread::JoinHandle<()>>,
}

fn is_run_ui_disabled_by_env() -> bool {
    env::var("RSS_ANALYS_NO_TUI")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

impl RunUiGuard {
    fn start(lang: UiLang) -> Self {
        if is_run_ui_disabled_by_env() {
            return Self {
                active: false,
                stop: None,
                ticker: None,
            };
        }
        if terminal::size().is_err() {
            return Self {
                active: false,
                stop: None,
                ticker: None,
            };
        }
        let mut out = io::stdout();
        let _ = execute!(out, EnterAlternateScreen, Hide);

        if let Some(lock) = RUN_UI.get() {
            if let Ok(mut ui) = lock.lock() {
                *ui = RunUi::new(lang);
                ui.render();
                let guard = Self::start_ticker(true);
                return guard;
            }
            let _ = execute!(out, Show, LeaveAlternateScreen, ResetColor);
            return Self {
                active: false,
                stop: None,
                ticker: None,
            };
        }
        let mut ui = RunUi::new(lang);
        ui.render();
        if RUN_UI.set(Mutex::new(ui)).is_ok() {
            Self::start_ticker(true)
        } else {
            let _ = execute!(out, Show, LeaveAlternateScreen, ResetColor);
            Self {
                active: false,
                stop: None,
                ticker: None,
            }
        }
    }

    fn start_ticker(active: bool) -> Self {
        if !active {
            return Self {
                active: false,
                stop: None,
                ticker: None,
            };
        }
        let stop = Arc::new(AtomicUsize::new(0));
        let stop_flag = Arc::clone(&stop);
        let ticker = thread::spawn(move || {
            loop {
                if stop_flag.load(Ordering::Relaxed) != 0 {
                    break;
                }
                let _ = with_run_ui(|ui| ui.render());
                thread::sleep(Duration::from_millis(280));
            }
        });
        Self {
            active: true,
            stop: Some(stop),
            ticker: Some(ticker),
        }
    }
}

impl Drop for RunUiGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(stop) = &self.stop {
            stop.store(1, Ordering::Relaxed);
        }
        if let Some(ticker) = self.ticker.take() {
            let _ = ticker.join();
        }
        if let Some(lock) = RUN_UI.get() {
            if let Ok(mut ui) = lock.lock() {
                ui.enabled = false;
            }
        }
        let mut out = io::stdout();
        let _ = execute!(out, Show, LeaveAlternateScreen, ResetColor);
    }
}

