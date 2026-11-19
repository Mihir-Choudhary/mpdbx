//! Tables + history → events, locations, process observations, file content (spec §5.2, §5.3).
//! Columns are looked up by name; a missing column skips that event type with a warning, never panics.
use crate::decode::queues::{QueueFact, decode_queue};
use crate::decode::time::{FtClass, Tz, classify_ft, fmt_ft, parse_sql_text_time};
use crate::decode::values::{
    enum_name, fileref, flag_bits, fmt_fileref, fmt_guid, fmt_vsn, hex, known_folder, reg_data,
    reg_type_name,
};
use crate::history::{HistoryLoad, PropVal, StoreKind, StoreRec};
pub use crate::model::Event;
use crate::model::Strength;
use crate::model::{
    DbStatus, DigestAlg, EventKind, Field, FileContent, Ft, HostContext, LocClass, Location,
    ProcessObs, Prov, RawTable, SqlVal,
};
use crate::normalize::path::{PathKey, WinPath, key_of, loc_class, parse_path};
use crate::normalize::volmap::{VolMap, infer_volmap};
use crate::provenance::{ProvMap, ProvRow, TableProv};
use std::collections::HashMap;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LoadOpts {
    pub tz: Tz,
    pub volmap_assert: Vec<(u32, char)>,
}

#[derive(Clone, Debug, Default)]
pub struct Loaded {
    pub events: Vec<Event>,
    pub locations: Vec<Location>,
    pub obs: Vec<ProcessObs>,
    pub contents: Vec<FileContent>,
    pub host: HostContext,
    pub raw: Vec<RawTable>,
    pub volmap: VolMap,
    /// Store record file names; index = `Node::Store` id.
    pub store_files: Vec<String>,
    pub warnings: Vec<String>,
}

/// Name → column index for one table.
struct Cols<'a> {
    table: &'a str,
    idx: HashMap<String, usize>,
}

impl<'a> Cols<'a> {
    fn new(table: &'a str, tp: &TableProv) -> Self {
        let idx = tp
            .info
            .as_ref()
            .map(|i| {
                i.columns
                    .iter()
                    .enumerate()
                    .map(|(n, c)| (c.to_ascii_lowercase(), n))
                    .collect()
            })
            .unwrap_or_default();
        Cols { table, idx }
    }
    fn has(&self, c: &str) -> bool {
        self.idx.contains_key(&c.to_ascii_lowercase())
    }
    fn get<'r>(&self, r: &'r ProvRow, c: &str) -> Option<&'r SqlVal> {
        self.idx
            .get(&c.to_ascii_lowercase())
            .and_then(|&i| r.values.get(i))
    }
    fn text(&self, r: &ProvRow, c: &str) -> Option<String> {
        match self.get(r, c)? {
            SqlVal::Text(s) => Some(s.clone()),
            SqlVal::Int(i) => Some(i.to_string()),
            _ => None,
        }
    }
    fn int(&self, r: &ProvRow, c: &str) -> Option<i64> {
        match self.get(r, c)? {
            SqlVal::Int(i) => Some(*i),
            SqlVal::Text(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
    fn blob<'r>(&self, r: &'r ProvRow, c: &str) -> Option<&'r [u8]> {
        match self.get(r, c)? {
            SqlVal::Blob(b) => Some(b),
            _ => None,
        }
    }
    /// All `required` columns present, else a warning naming the missing ones.
    fn require(&self, required: &[&str], what: &str, warnings: &mut Vec<String>) -> bool {
        let missing: Vec<&str> = required.iter().copied().filter(|c| !self.has(c)).collect();
        if missing.is_empty() {
            return true;
        }
        warnings.push(format!(
            "table {} lacks column(s) {}; {what} events skipped",
            self.table,
            missing.join(", ")
        ));
        false
    }
}

fn raw_of(v: Option<&SqlVal>) -> String {
    match v {
        None | Some(SqlVal::Null) => String::new(),
        Some(SqlVal::Int(i)) => i.to_string(),
        Some(SqlVal::Real(f)) => f.to_string(),
        Some(SqlVal::Text(s)) => s.clone(),
        Some(SqlVal::Blob(b)) => hex(b),
    }
}

/// (display, raw) for any table cell, by column name: FILETIME-like columns, known enums, flag words,
/// 16-byte GUIDs; everything else raw. Used for Bm* events and the Raw tables views.
pub fn decode_cell(name: &str, v: &SqlVal, tz: Tz) -> (String, String) {
    let raw = raw_of(Some(v));
    let timeish = name.ends_with("Time") || name.ends_with("TS") || name.contains("TimeStamp");
    let display = match v {
        SqlVal::Int(i) if timeish => ft_classified(*i, tz),
        SqlVal::Int(i)
            if [
                "ProcessIntegrity",
                "ProcessTaintReason",
                "Action",
                "RuleAction",
                "State",
            ]
            .contains(&name) =>
        {
            enum_name(name, *i)
        }
        SqlVal::Int(i) if name.contains("Flags") => flag_bits(*i as u64),
        // GUID decoding only for columns known to hold GUIDs; digests and other 16-byte blobs stay hex.
        SqlVal::Blob(b) if b.len() == 16 && is_guid_column(name) => {
            fmt_guid(b).unwrap_or_else(|| hex(b))
        }
        _ => raw.clone(),
    };
    (display, raw)
}

fn is_guid_column(name: &str) -> bool {
    [
        "GUID",
        "RuleId",
        "HipsInjectionId",
        "FolderGuardId",
        "LsassReadMemId",
    ]
    .iter()
    .any(|g| name.eq_ignore_ascii_case(g))
        || name.ends_with("Guid")
}

/// Largest gap between a process's start and its BackupProcessInfo insert: the table's ~7-day retention window
/// (FILETIME ticks). Reference copy: every genuine process row < 1 min; date-like module values are years off.
const BPI_MAX_START_LAG: u64 = 7 * 864_000_000_000;

/// FILETIME display with the §6 classes: zero/max/opaque sentinels and an implausible mark.
fn ft_classified(v: i64, tz: Tz) -> String {
    match classify_ft(v) {
        FtClass::Plausible(t) => fmt_ft(t, tz),
        FtClass::Representable(t) => format!("{} (implausible)", fmt_ft(t, tz)),
        FtClass::Zero => "0 (zero)".into(),
        FtClass::Max => format!("{v} (max)"),
        FtClass::Opaque => format!("{v} (opaque)"),
    }
}

fn plausible(v: Option<i64>) -> Option<Ft> {
    match classify_ft(v?) {
        FtClass::Plausible(t) => Some(t),
        _ => None,
    }
}

fn leaf(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// v1 `_rename_kind` (mpdb_core.py:381-390).
pub fn rename_kind(file_name: &str, ofn: &str) -> &'static str {
    let f = file_name.to_lowercase();
    let o = ofn.to_lowercase();
    let re = |p: &str, s: &str| {
        regex_lite::Regex::new(p)
            .map(|r| r.is_match(s))
            .unwrap_or(false)
    };
    let ext = f.rsplit('.').next().unwrap_or("");
    if re(r"\.(mui|efi|tlb)(_[0-9a-f]{8})?$", &f)
        || re(r"_[0-9a-f]{8}$", &f)
        || re(r"^[0-9a-f]{40}$", ext)
        || o.ends_with(".mui")
        || re(r"^[0-9a-f]+_\d+\.\d+", &f)
    {
        "resource/component"
    } else if re(r"\.(exe|dll|sys|scr|com|cpl|ocx)$", &f) {
        "executable rename"
    } else {
        "other"
    }
}

/// v1 unprefixed-OFN rule: Context looks like a PE file name and differs from the path leaf.
fn looks_like_ofn(ctx: &str, path: &str) -> bool {
    let ok = regex_lite::Regex::new(r"(?i)^[\w.\- ]+\.(exe|dll|sys|com|scr|ocx|cpl|mui|efi|drv)$")
        .map(|r| r.is_match(ctx))
        .unwrap_or(false);
    ok && !ctx.eq_ignore_ascii_case(leaf(path))
}

struct B<'o> {
    opts: &'o LoadOpts,
    l: Loaded,
    loc_index: HashMap<PathKey, u32>,
    /// Strength of the spelling resolved by the last `location()` call; taken by the next `push()` with a location.
    pending_strength: Option<Strength>,
}

impl B<'_> {
    /// A raw, unvalidated FILETIME from the evidence: zero, max and out-of-range values are labelled, not rendered as dates.
    fn ft_raw(&self, t: u64) -> String {
        match i64::try_from(t) {
            Ok(v) => ft_classified(v, self.opts.tz),
            Err(_) => format!("{t} (opaque)"),
        }
    }

    fn field(&self, name: &str, display: impl Into<String>, raw: impl Into<String>) -> Field {
        Field {
            name: name.into(),
            display: display.into(),
            raw: raw.into(),
        }
    }

    fn time_field(&self, name: &str, v: Option<i64>) -> Field {
        let raw = v.map(|x| x.to_string()).unwrap_or_default();
        Field {
            name: name.into(),
            display: v
                .map(|x| ft_classified(x, self.opts.tz))
                .unwrap_or_default(),
            raw,
        }
    }

    /// Generic column decoding for tables without a dedicated mapping (Bm*, ProcessBlockHistory, …).
    fn generic_field(&self, name: &str, v: &SqlVal) -> Field {
        let (display, raw) = decode_cell(name, v, self.opts.tz);
        Field {
            name: name.into(),
            display,
            raw,
        }
    }

    fn location(&mut self, raw: &str) -> Option<u32> {
        self.pending_strength = None;
        if raw.trim().is_empty() {
            return None;
        }
        let p = parse_path(raw);
        let (key, strength) = key_of(&p, &self.l.volmap);
        self.pending_strength = Some(strength);
        if let Some(&id) = self.loc_index.get(&key) {
            let loc = &mut self.l.locations[id as usize];
            if !loc.spellings.iter().any(|s| s == raw) {
                loc.spellings.push(raw.to_string());
            }
            // a location is only as certain as its weakest spelling
            loc.key_strength = loc.key_strength.min(strength);
            return Some(id);
        }
        let id = self.l.locations.len() as u32;
        self.l.locations.push(Location {
            id,
            key: key.clone(),
            spellings: vec![raw.to_string()],
            events: Vec::new(),
            class: loc_class(&p, &self.l.volmap),
            key_strength: strength,
        });
        self.loc_index.insert(key, id);
        Some(id)
    }

    fn class(&self, loc: Option<u32>) -> LocClass {
        loc.and_then(|i| self.l.locations.get(i as usize))
            .map(|l| l.class)
            .unwrap_or(LocClass::Unknown)
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        kind: EventKind,
        time: Option<Ft>,
        summary: String,
        location: Option<u32>,
        fields: Vec<Field>,
        prov: Prov,
        flag: bool,
    ) -> u32 {
        let id = self.l.events.len() as u32;
        let wal_flag = matches!(
            &prov,
            Prov::Db {
                status: DbStatus::WalOnly | DbStatus::RemovedByWal,
                ..
            }
        );
        self.l.events.push(Event {
            id,
            kind,
            time,
            time_note: None,
            summary,
            location,
            obs: None,
            content: None,
            store: None,
            fields,
            prov,
            flag: flag || wal_flag,
            path_strength: if location.is_some() {
                self.pending_strength.take().unwrap_or(Strength::Exact)
            } else {
                Strength::Exact
            },
        });
        if let Some(l) = location.and_then(|l| self.l.locations.get_mut(l as usize)) {
            l.events.push(id);
        }
        id
    }

    fn observe(&mut self, event: u32, location: Option<u32>, pid: Option<u32>, start: Option<Ft>) {
        let id = self.l.obs.len() as u32;
        let path_strength = match (location, self.l.events.get(event as usize)) {
            (Some(l), Some(e)) if e.location == Some(l) => e.path_strength,
            _ => Strength::Exact,
        };
        self.l.obs.push(ProcessObs {
            id,
            location,
            pid,
            start,
            event,
            path_strength,
        });
        if let Some(e) = self.l.events.get_mut(event as usize) {
            e.obs = Some(id);
        }
    }

    fn prov(table: &str, r: &ProvRow) -> Prov {
        Prov::Db {
            table: table.into(),
            key: r.key.clone(),
            status: r.status,
            old: r.old.clone(),
        }
    }

    fn host(&mut self, label: impl Into<String>, value: impl Into<String>, prov: Prov) {
        self.l.host.facts.push((label.into(), value.into(), prov));
    }
}

/// Every path string the tables and Store records carry (input to VolMap inference).
fn collect_paths(prov: &ProvMap, hist: &HistoryLoad) -> Vec<WinPath> {
    let mut v = Vec::new();
    let cols: &[(&str, &str)] = &[
        ("BackupProcessInfo", "FilePath"),
        ("AttributePersistContext", "FilePath"),
        ("FileLowFiAsync", "FileName"),
        ("BmProcessInfo", "ImageFileName"),
        ("BmFileInfo", "DosPath"),
        ("BmFileInfo", "NormalizedPath"),
        ("BmFileStartupActions", "FilePath"),
        ("ProcessBlockHistory", "ProcessPath"),
        ("ProcessBlockHistory", "TargetPath"),
        ("SystemFileCache", "SystemFilePath"),
    ];
    for (t, c) in cols {
        if let Some(tp) = prov.tables.get(*t) {
            let cc = Cols::new(t, tp);
            for r in &tp.rows {
                if let Some(s) = cc.text(r, c) {
                    v.push(parse_path(&s));
                }
            }
        }
    }
    // dropped-file queue entries carry paths too (RQ_Recent*Dropped: the key is the path)
    if let Some(tp) = prov.tables.get("RollingQueuesValues") {
        let cc = Cols::new("RollingQueuesValues", tp);
        for r in &tp.rows {
            if matches!(
                cc.text(r, "EntryTable").as_deref(),
                Some("RQ_RecentExecDropped" | "RQ_RecentScriptDropped")
            ) && let Some(k) = cc.text(r, "EntryKey")
            {
                v.push(parse_path(&k));
            }
        }
    }
    for s in &hist.store {
        if let Some(p) = store_file_path(s) {
            v.push(parse_path(&p));
        }
        if let Some(p) = store_image_path(s) {
            v.push(parse_path(&p));
        }
    }
    v
}

fn join_dir(dir: &str, name: &str) -> String {
    if dir.ends_with('\\') {
        format!("{dir}{name}")
    } else {
        format!("{dir}\\{name}")
    }
}

fn store_file_path(s: &StoreRec) -> Option<String> {
    Some(join_dir(
        s.get_str("CONTEXT_DATA_FILEPATH")?,
        s.get_str("CONTEXT_DATA_FILENAME")?,
    ))
}

/// Acting image = `PROCESSDEVICEPATH` (directory) + `PROCESSNAME` (leaf).
fn store_image_path(s: &StoreRec) -> Option<String> {
    Some(join_dir(
        s.get_str("CONTEXT_DATA_PROCESSDEVICEPATH")?,
        s.get_str("CONTEXT_DATA_PROCESSNAME")?,
    ))
}

fn prop_display(name: &str, v: &PropVal, tz: Tz) -> (String, String) {
    match v {
        PropVal::U32(x) if name.ends_with("SCANREASON") => (
            format!("{x} ({})", enum_name("SCANREASON", *x as i64)),
            x.to_string(),
        ),
        PropVal::U32(x) => (x.to_string(), x.to_string()),
        PropVal::U64(x) if name.contains("_AGE") => (
            format!("{x} s (interpretation: seconds since creation/last write/change)"),
            x.to_string(),
        ),
        PropVal::U64(x) if name.ends_with("CreationTime") => (
            i64::try_from(*x)
                .map(|v| ft_classified(v, tz))
                .unwrap_or_else(|_| format!("{x} (opaque)")),
            x.to_string(),
        ),
        PropVal::U64(x) => (x.to_string(), x.to_string()),
        PropVal::Bool(b) => ((*b != 0).to_string(), b.to_string()),
        PropVal::Str(s) => (s.clone(), s.clone()),
        PropVal::Bytes { typ, data } => (format!("type {typ}: {}", hex(data)), hex(data)),
    }
}

pub fn load(prov: &ProvMap, hist: &HistoryLoad, opts: &LoadOpts) -> Loaded {
    let mut b = B {
        opts,
        l: Loaded::default(),
        loc_index: HashMap::new(),
        pending_strength: None,
    };
    b.l.volmap = infer_volmap(&collect_paths(prov, hist), &opts.volmap_assert);

    let mut names: Vec<&String> = prov.tables.keys().collect();
    names.sort();
    for name in names {
        let tp = &prov.tables[name];
        if let Some(e) = &tp.error {
            b.l.warnings.push(format!("table {name}: {e}"));
        }
        let cols = tp
            .info
            .as_ref()
            .map(|i| i.columns.clone())
            .unwrap_or_default();
        b.l.raw.push(RawTable {
            name: name.clone(),
            columns: cols,
            rows: tp
                .rows
                .iter()
                .map(|r| (r.values.clone(), B::prov(name, r)))
                .collect(),
            readable: tp.readable,
        });
        match name.as_str() {
            "BackupProcessInfo" => bpi(&mut b, name, tp),
            "AttributePersistContext" => apc(&mut b, name, tp),
            "FileHashes" => filehashes(&mut b, name, tp),
            "FileLowFiAsync" => lowfi(&mut b, name, tp),
            "AmsiFileCache" => amsicache(&mut b, name, tp),
            "SystemRegistryCache" => regcache(&mut b, name, tp),
            "RollingQueuesValues" => queues(&mut b, name, tp),
            "FolderGuardPaths" => cfa(&mut b, name, tp),
            "SQLiteGlobals" | "DynSigRevisions" | "Engine" | "InventoryState" => {
                host_rows(&mut b, name, tp)
            }
            n if n.starts_with("Bm")
                || [
                    "RansomwareDetections",
                    "ProcessBlockHistory",
                    "SystemFileCache",
                ]
                .contains(&n) =>
            {
                bm(&mut b, name, tp)
            }
            _ => {}
        }
    }
    store(&mut b, hist);
    for s in &hist.scans {
        if s.trailing > 0 {
            b.l.warnings.push(format!(
                "Results record {}: {} trailing bytes after the container (not interpreted)",
                s.file, s.trailing
            ));
        }
        let fields = vec![
            b.field("Category", s.category.clone(), s.category.clone()),
            b.field(
                "GUID",
                s.guid.clone().unwrap_or_default(),
                s.guid.clone().unwrap_or_default(),
            ),
            b.time_field("Start", s.start.and_then(|x| i64::try_from(x).ok())),
            b.time_field("End", s.end.and_then(|x| i64::try_from(x).ok())),
            b.field(
                "Duration",
                match (
                    plausible(s.start.and_then(|x| i64::try_from(x).ok())),
                    plausible(s.end.and_then(|x| i64::try_from(x).ok())),
                ) {
                    (Some(a), Some(e)) if e >= a => format!("{:.1} s", (e - a) as f64 / 1e7),
                    _ => String::new(),
                },
                "",
            ),
            b.field(
                "Unverified section-1 bytes",
                hex(&s.unverified_sec1),
                hex(&s.unverified_sec1),
            ),
            b.field(
                "Unverified section-2 bytes",
                hex(&s.unverified_sec2_tail),
                hex(&s.unverified_sec2_tail),
            ),
        ];
        let prov = Prov::Results {
            file: s.file.clone(),
            section: 2,
            offset: 0,
        };
        b.push(
            EventKind::ScanRun,
            plausible(s.start.and_then(|x| i64::try_from(x).ok())),
            format!("{} scan", s.category),
            None,
            fields,
            prov.clone(),
            false,
        );
        b.host(
            format!("{} scan", s.category),
            format!(
                "{} → {}",
                s.start.map(|t| b.ft_raw(t)).unwrap_or_default(),
                s.end.map(|t| b.ft_raw(t)).unwrap_or_default()
            ),
            prov,
        );
    }
    for e in &hist.errors {
        b.l.warnings.push(format!(
            "history record {} @ {:#x}: {}",
            e.file, e.offset, e.reason
        ));
    }
    b.l
}

fn bpi(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    if !c.require(
        &["FilePath", "FirstStartTime", "InstanceTimeStamp"],
        "process/module first-start",
        &mut b.l.warnings,
    ) {
        return;
    }
    for r in &tp.rows {
        let path = c.text(r, "FilePath").unwrap_or_default();
        let fst = c.int(r, "FirstStartTime");
        let its = c.int(r, "InstanceTimeStamp");
        let loc = b.location(&path);
        // A process start is a plausible FILETIME at most 7 days (BPI retention) before the row was written (reference
        // copy: every genuine process row is < 1 min). Module rows carry a non-time value that can fall in the date range.
        let start = match (plausible(fst), plausible(its)) {
            (Some(f), Some(i)) if i >= f && i - f <= BPI_MAX_START_LAG => Some(f),
            (Some(f), None) => Some(f),
            _ => None,
        };
        let fst_field = match (start, plausible(fst)) {
            (Some(_), _) => b.time_field("FirstStartTime", fst),
            (None, Some(_)) => {
                let raw = fst.map(|x| x.to_string()).unwrap_or_default();
                b.field(
                    "FirstStartTime",
                    format!("{raw} (module value; date-like by chance, not a start time)"),
                    raw,
                )
            }
            // Module rows: the value is not a FILETIME (spec §5.3) — never render it as a date.
            (None, None) => {
                let raw = fst.map(|x| x.to_string()).unwrap_or_default();
                b.field("FirstStartTime", format!("{raw} (opaque)"), raw)
            }
        };
        let mut fields = vec![
            b.field("Path", path.clone(), path.clone()),
            fst_field,
            b.time_field("InstanceTimeStamp", its),
        ];
        if let Some(u) = c.int(r, "NextUSN") {
            fields.push(b.field("NextUSN", u.to_string(), u.to_string()));
        }
        match start {
            Some(start) => {
                let e = b.push(
                    EventKind::ProcessFirstStart,
                    Some(start),
                    format!("Process first start: {}", leaf(&path)),
                    loc,
                    fields,
                    B::prov(t, r),
                    false,
                );
                b.observe(e, loc, None, Some(start));
            }
            None => {
                b.push(
                    EventKind::ModuleFirstLoad,
                    plausible(its),
                    format!("Module first load: {}", leaf(&path)),
                    loc,
                    fields,
                    B::prov(t, r),
                    false,
                );
            }
        }
    }
}

fn apc(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    if !c.require(
        &["FilePath", "Context", "InsertTime"],
        "attribute-context",
        &mut b.l.warnings,
    ) {
        return;
    }
    for r in &tp.rows {
        let raw_path = c.text(r, "FilePath").unwrap_or_default();
        let ctx = c.text(r, "Context").unwrap_or_default();
        let wp = parse_path(&raw_path);
        let tag = wp.tag.clone();
        let path = match &tag {
            Some(tg) => raw_path.get(tg.len() + 1..).unwrap_or("").to_string(),
            None => raw_path.clone(),
        };
        let ins = c.int(r, "InsertTime");
        let loc = b.location(&path);
        let outside = b.class(loc) == LocClass::OutsideSystemDirs;
        let mut fields = vec![
            b.field("Path", path.clone(), raw_path.clone()),
            b.field("Context", ctx.clone(), ctx.clone()),
            b.time_field("InsertTime", ins),
            b.time_field("ExpireTime", c.int(r, "ExpireTime")),
        ];
        if let Some(tg) = &tag {
            fields.push(b.field("Engine tag", tg.clone(), tg.clone()));
        }
        let name = leaf(&path).to_string();
        let (kind, summary, flag) = match (tag.as_deref(), ctx.as_str()) {
            (None, "ExecutedPENoCert") => (
                EventKind::NoCertExec,
                format!("Execution, no embedded cert: {name}"),
                outside,
            ),
            (Some("ENG:OFNSET"), ofn) | (None, ofn)
                if tag.is_some() || looks_like_ofn(ofn, &path) =>
            {
                let inferred = tag.is_none();
                let rk = if ofn.eq_ignore_ascii_case(&name) {
                    "same as file name"
                } else {
                    rename_kind(&name, ofn)
                };
                fields.push(b.field("OriginalFileName", ofn, ofn));
                fields.push(b.field("Rename kind", rk, rk));
                let k = if inferred {
                    EventKind::OfnSetInferred
                } else {
                    EventKind::OfnSet
                };
                (
                    k,
                    format!(
                        "OriginalFileName {ofn} on {name}{}",
                        if inferred { " (inferred)" } else { "" }
                    ),
                    rk == "executable rename" && outside,
                )
            }
            (Some("ENG:OFNPROCESSED"), _) => (
                EventKind::OfnProcessed,
                format!("OFN processed: {name}"),
                false,
            ),
            _ => (
                EventKind::FileContext,
                format!("Defender file context {ctx}: {name}"),
                false,
            ),
        };
        b.push(
            kind,
            plausible(ins),
            summary,
            loc,
            fields,
            B::prov(t, r),
            flag,
        );
    }
}

fn filehashes(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    if !c.require(
        &["VSN", "FileID", "InstanceTimeStamp"],
        "file-hash",
        &mut b.l.warnings,
    ) {
        return;
    }
    // Validated: column "SHA1" holds MD5 (16 B) and column "MD5" holds SHA1 (20 B) (spec §3).
    let map = [
        ("SHA1", DigestAlg::Md5, 16usize),
        ("MD5", DigestAlg::Sha1, 20),
        ("SHA256", DigestAlg::Sha256, 32),
    ];
    for r in &tp.rows {
        let ident = match (c.get(r, "FileID"), c.get(r, "VSN")) {
            (Some(SqlVal::Int(f)), Some(SqlVal::Int(v))) => Some(fileref(*f, *v)),
            _ => None,
        };
        let its = c.int(r, "InstanceTimeStamp");
        let mut fields = match &ident {
            Some(fr) => vec![
                b.field("FileRef", fmt_fileref(fr), raw_of(c.get(r, "FileID"))),
                b.field("Volume serial", fmt_vsn(fr.vsn), raw_of(c.get(r, "VSN"))),
            ],
            None => vec![b.field(
                "FileRef",
                "missing (FileID or VSN not an integer)",
                format!(
                    "{} / {}",
                    raw_of(c.get(r, "FileID")),
                    raw_of(c.get(r, "VSN"))
                ),
            )],
        };
        fields.push(b.time_field("InstanceTimeStamp", its));
        let mut digests = Vec::new();
        for (col, alg, len) in map {
            if let Some(d) = c.blob(r, col) {
                let label = format!("{alg:?}").to_uppercase();
                if d.len() == len {
                    fields.push(b.field(&format!("{label} (column {col})"), hex(d), hex(d)));
                    digests.push((alg, d.to_vec()));
                } else {
                    fields.push(b.field(
                        &format!(
                            "{label} (column {col}; length {} ≠ {len}, kept raw)",
                            d.len()
                        ),
                        hex(d),
                        hex(d),
                    ));
                }
            }
        }
        for col in [
            "USN",
            "LSHASH",
            "LSHASHS",
            "CTPH",
            "PartialCRC1",
            "PartialCRC2",
            "PartialCRC3",
            "KCRC1",
            "KCRC2",
            "KCRC3",
            "KCRC3n",
        ] {
            match c.get(r, col) {
                Some(SqlVal::Null) | None => {}
                Some(SqlVal::Blob(x)) if col == "CTPH" => {
                    fields.push(b.field(col, String::from_utf8_lossy(x).into_owned(), hex(x)))
                }
                Some(v) => fields.push(b.field(col, raw_of(Some(v)), raw_of(Some(v)))),
            }
        }
        let summary = match &ident {
            Some(fr) => format!(
                "File hashed: MFT {} on {}",
                fmt_fileref(fr),
                fmt_vsn(fr.vsn)
            ),
            None => "File hashed: MFT reference missing".to_string(),
        };
        let e = b.push(
            EventKind::FileHashed,
            plausible(its),
            summary,
            None,
            fields,
            B::prov(t, r),
            false,
        );
        if let Some(fr) = ident {
            let id = b.l.contents.len() as u32;
            b.l.contents.push(FileContent {
                id,
                fileref: fr,
                digests,
                event: e,
            });
            b.l.events[e as usize].content = Some(id);
        }
    }
}

fn lowfi(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    if !c.require(
        &["FileName", "InstanceTimeStamp"],
        "LowFi",
        &mut b.l.warnings,
    ) {
        return;
    }
    for r in &tp.rows {
        let path = c.text(r, "FileName").unwrap_or_default();
        let loc = b.location(&path);
        let mut fields = vec![
            b.field("Path", path.clone(), path.clone()),
            b.time_field("InstanceTimeStamp", c.int(r, "InstanceTimeStamp")),
        ];
        if let Some(s) = c.blob(r, "SigSha") {
            fields.push(b.field("Signature SHA", hex(s), hex(s)));
        }
        if let Some(s) = c.int(r, "SigSeq") {
            fields.push(b.field("SigSeq", s.to_string(), s.to_string()));
        }
        b.push(
            EventKind::LowFiHit,
            plausible(c.int(r, "InstanceTimeStamp")),
            format!("LowFi signature hit: {}", leaf(&path)),
            loc,
            fields,
            B::prov(t, r),
            false,
        );
    }
}

fn amsicache(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    if !c.require(
        &["PersistId", "ExpirationDate"],
        "Store-cache expiry",
        &mut b.l.warnings,
    ) {
        return;
    }
    for r in &tp.rows {
        let pid = c.text(r, "PersistId").unwrap_or_default();
        let exp = c.text(r, "ExpirationDate").unwrap_or_default();
        let parsed = parse_sql_text_time(&exp);
        let time = parsed.and_then(|t| plausible(i64::try_from(t).ok()));
        let fields = vec![
            b.field("PersistId (Store file name)", pid.clone(), pid.clone()),
            b.field(
                "ExpirationDate",
                parsed
                    .map(|x| ft_classified(x as i64, b.opts.tz))
                    .unwrap_or_else(|| exp.clone()),
                exp.clone(),
            ),
        ];
        b.push(
            EventKind::StoreExpiry,
            time,
            format!("Store cache expiry: {pid}"),
            None,
            fields,
            B::prov(t, r),
            false,
        );
    }
}

fn regcache(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    if !c.require(
        &["RegPath", "InstanceTimeStamp"],
        "registry-cache",
        &mut b.l.warnings,
    ) {
        return;
    }
    for r in &tp.rows {
        let path = c.text(r, "RegPath").unwrap_or_default();
        let nt = c.int(r, "NewRegType").unwrap_or(-1);
        let ot = c.int(r, "OldRegType").unwrap_or(-1);
        let mut fields = vec![
            b.field("RegPath", path.clone(), path.clone()),
            b.field(
                "RegOperation",
                enum_name("RegOperation", c.int(r, "RegOperation").unwrap_or(-1)),
                raw_of(c.get(r, "RegOperation")),
            ),
            b.field("NewRegType", reg_type_name(nt), nt.to_string()),
            b.field(
                "NewRegData",
                c.blob(r, "NewRegData")
                    .map(|d| reg_data(nt, d))
                    .unwrap_or_default(),
                raw_of(c.get(r, "NewRegData")),
            ),
            b.field("OldRegType", reg_type_name(ot), ot.to_string()),
            b.field(
                "OldRegData",
                c.blob(r, "OldRegData")
                    .map(|d| reg_data(ot, d))
                    .unwrap_or_default(),
                raw_of(c.get(r, "OldRegData")),
            ),
            b.time_field("InstanceTimeStamp", c.int(r, "InstanceTimeStamp")),
        ];
        fields.push(b.field(
            "FileIDHash",
            raw_of(c.get(r, "FileIDHash")),
            raw_of(c.get(r, "FileIDHash")),
        ));
        b.push(
            EventKind::RegistryChange,
            plausible(c.int(r, "InstanceTimeStamp")),
            format!("Registry change: {path}"),
            None,
            fields,
            B::prov(t, r),
            false,
        );
    }
}

fn queues(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    if !c.require(
        &["EntryTable", "EntryKey", "EntryValue", "InsertTime"],
        "rolling-queue",
        &mut b.l.warnings,
    ) {
        return;
    }
    for r in &tp.rows {
        let (qt, k, v) = (
            c.text(r, "EntryTable").unwrap_or_default(),
            c.text(r, "EntryKey").unwrap_or_default(),
            c.text(r, "EntryValue").unwrap_or_default(),
        );
        let ins = c.int(r, "InsertTime");
        let facts = decode_queue(&qt, &k, &v);
        let mut fields = vec![
            b.field("Queue", qt.clone(), qt.clone()),
            b.field("Key", k.clone(), k.clone()),
            b.field("Value", v.clone(), v.clone()),
            b.time_field("InsertTime", ins),
            b.time_field("ExpireTime", c.int(r, "ExpireTime")),
        ];
        let mut flag = false;
        let mut loc = None;
        let mut proc_obs = None;
        for f in &facts {
            match f {
                QueueFact::Threat { name, count } => {
                    flag = true;
                    fields.push(b.field("Threat", format!("{name} ×{count}"), name.clone()));
                }
                QueueFact::Host { field, value } => {
                    b.host(format!("domainInfo {field}"), value.clone(), B::prov(t, r))
                }
                QueueFact::Process { pid, start, suffix } => {
                    fields.push(b.field(
                        "Process",
                        format!("PID {pid} started {}", b.ft_raw(*start)),
                        format!("{pid},{start}"),
                    ));
                    if !suffix.is_empty() {
                        fields.push(b.field("Counter set", suffix.clone(), suffix.clone()));
                    }
                    proc_obs = Some((*pid, *start));
                }
                QueueFact::Dropped { path, script } => {
                    loc = b.location(path);
                    fields.push(b.field(
                        if *script {
                            "Script dropped"
                        } else {
                            "Executable dropped"
                        },
                        path.clone(),
                        path.clone(),
                    ));
                }
                QueueFact::Rdp { field, value } => {
                    b.host(field.clone(), value.clone(), B::prov(t, r))
                }
                QueueFact::RdpLogon {
                    time,
                    ip,
                    user_sid,
                    workstation,
                    session,
                } => {
                    let fl = vec![
                        b.field("Source IP", ip.clone(), ip.clone()),
                        b.field("User SID", user_sid.clone(), user_sid.clone()),
                        b.field("Workstation", workstation.clone(), workstation.clone()),
                        b.field("Session", session.clone(), session.clone()),
                        b.time_field("Logon time", time.and_then(|x| i64::try_from(x).ok())),
                    ];
                    let tm = plausible(time.and_then(|x| i64::try_from(x).ok()));
                    b.push(
                        EventKind::RdpLogon,
                        tm,
                        format!("RDP logon success from {ip}"),
                        None,
                        fl,
                        B::prov(t, r),
                        true,
                    );
                }
                QueueFact::Address { label, addr } => {
                    fields.push(b.field(label, format!("{addr:#x}"), addr.to_string()))
                }
                QueueFact::Generic { key, value } => {
                    fields.push(b.field(key, value.clone(), value.clone()))
                }
            }
        }
        let e = b.push(
            EventKind::QueueEntry,
            plausible(ins),
            format!("{qt}: {k}"),
            loc,
            fields,
            B::prov(t, r),
            flag,
        );
        if let Some((pid, start)) = proc_obs {
            b.observe(e, None, Some(pid), plausible(i64::try_from(start).ok()));
        }
    }
}

fn cfa(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    for r in &tp.rows {
        let sid = c.text(r, "UserId").unwrap_or_default();
        let guid = c.blob(r, "GUID").and_then(fmt_guid).unwrap_or_default();
        let name = known_folder(&guid)
            .map(str::to_string)
            .unwrap_or_else(|| guid.clone());
        let path = c.text(r, "Path").unwrap_or_default();
        let value = if path.is_empty() {
            name
        } else {
            format!("{name} ({path})")
        };
        b.host(
            format!("CFA protected folder ({sid})"),
            value,
            B::prov(t, r),
        );
    }
}

fn host_rows(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    for r in &tp.rows {
        if t == "SQLiteGlobals" {
            let v = format!(
                "{} (current {}, updated {})",
                raw_of(c.get(r, "Version")),
                raw_of(c.get(r, "Current")),
                raw_of(c.get(r, "LastUpdated"))
            );
            b.host("SQLite schema version", v, B::prov(t, r));
        } else {
            let cols = tp
                .info
                .as_ref()
                .map(|i| i.columns.clone())
                .unwrap_or_default();
            let v = cols
                .iter()
                .zip(&r.values)
                .map(|(n, v)| format!("{n}={}", raw_of(Some(v))))
                .collect::<Vec<_>>()
                .join(", ");
            b.host(t.to_string(), v, B::prov(t, r));
        }
    }
}

fn bm(b: &mut B, t: &str, tp: &TableProv) {
    let c = Cols::new(t, tp);
    let time_col = [
        "ProcessStartTime",
        "TimeStamp",
        "DetectionTS",
        "LkgTS",
        "RemedComplTS",
        "InstanceTimeStamp",
    ]
    .into_iter()
    .find(|x| c.has(x));
    let path_col = [
        "ImageFileName",
        "ProcessPath",
        "FilePath",
        "NormalizedPath",
        "DosPath",
        "SystemFilePath",
    ]
    .into_iter()
    .find(|x| c.has(x));
    let cols = tp
        .info
        .as_ref()
        .map(|i| i.columns.clone())
        .unwrap_or_default();
    for r in &tp.rows {
        let tm = time_col.and_then(|x| plausible(c.int(r, x)));
        let path = path_col.and_then(|x| c.text(r, x)).unwrap_or_default();
        let loc = b.location(&path);
        let fields: Vec<Field> = cols
            .iter()
            .zip(&r.values)
            .map(|(n, v)| b.generic_field(n, v))
            .collect();
        let e = b.push(
            EventKind::BmRecord,
            tm,
            format!("{t}: {}", leaf(&path)),
            loc,
            fields,
            B::prov(t, r),
            false,
        );
        if t == "BmProcessInfo" {
            let pid = c.int(r, "PID").and_then(|p| u32::try_from(p).ok());
            b.observe(e, loc, pid, plausible(c.int(r, "ProcessStartTime")));
        }
    }
}

fn store(b: &mut B, hist: &HistoryLoad) {
    for s in &hist.store {
        let sid = b.l.store_files.len() as u32;
        b.l.store_files.push(s.file.clone());
        let mut fields: Vec<Field> = s
            .props
            .iter()
            .map(|p| {
                let (d, r) = prop_display(&p.name, &p.val, b.opts.tz);
                let d = if p.lossy_utf16 {
                    format!("{d} [malformed UTF-16, decoded lossily]")
                } else {
                    d
                };
                b.field(&p.name, d, r)
            })
            .collect();
        for (what, n) in [("record", s.trailing), ("container", s.container_trailing)] {
            if n > 0 {
                fields.push(b.field(
                    &format!("Trailing bytes after the {what}"),
                    n.to_string(),
                    n.to_string(),
                ));
                b.l.warnings.push(format!(
                    "Store record {}: {n} trailing bytes after the {what} (not interpreted)",
                    s.file
                ));
            }
        }
        // provenance points at the property the event is built from
        let off = |name: &str| {
            s.props
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.offset)
                .unwrap_or(0)
        };
        let prov = |o: u32| Prov::Store {
            file: s.file.clone(),
            section: 2,
            offset: o,
        };
        match s.kind {
            StoreKind::Amsi => {
                let app = s.get_str("AMSIApp").unwrap_or("").to_string();
                let op = s.get_str("AMSIOpProcName").unwrap_or("").to_string();
                let e = b.push(EventKind::AmsiScan, None, format!("AMSI scan by {op} ({app})"), None, fields.clone(), prov(off("AMSIOpProcName")), false);
                b.l.events[e as usize].store = Some(sid);
                let pid = match s.get("AMSIPid") {
                    Some(PropVal::U32(p)) => Some(*p),
                    _ => None,
                };
                let start = match s.get("AMSIPidCreationTime") {
                    Some(PropVal::U64(t)) => Some(*t),
                    _ => None,
                };
                if pid.is_some() || start.is_some() {
                    let tm = plausible(start.and_then(|x| i64::try_from(x).ok()));
                    let pe = b.push(EventKind::AmsiProcessStart, tm, format!("Process start (from AMSI): {op}"), None, fields, prov(off("AMSIPidCreationTime")), false);
                    b.l.events[pe as usize].store = Some(sid);
                    b.observe(pe, None, pid, tm);
                }
            }
            StoreKind::Other => b.l.warnings.push(format!(
                "Store record {}: no CONTEXT_DATA or AMSI properties; not interpreted ({} properties)",
                s.file,
                s.props.len()
            )),
            StoreKind::Context => {
                let file = store_file_path(s);
                let floc = file.as_deref().and_then(|p| b.location(p));
                let name = s.get_str("CONTEXT_DATA_FILENAME").unwrap_or("").to_string();
                let actor = s.get_str("CONTEXT_DATA_PROCESSNAME").unwrap_or("").to_string();
                let e = b.push(EventKind::FileScan, None, format!("File scan observed: {name} by {actor}"), floc, fields.clone(), prov(off("CONTEXT_DATA_FILENAME")), false);
                b.l.events[e as usize].store = Some(sid);
                if let Some((pid, start)) = s.ppid() {
                    let iloc = store_image_path(s).and_then(|p| b.location(&p));
                    let pe = b.push(EventKind::StoreProcessStart, plausible(i64::try_from(start).ok()), format!("Process start (from Store): {actor}"), iloc, fields, prov(off("CONTEXT_DATA_PROCESS_PPID")), false);
                    b.l.events[pe as usize].store = Some(sid);
                    b.observe(pe, iloc, Some(pid), plausible(i64::try_from(start).ok()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::embedded_key;
    use crate::model::{DbStatus, DigestAlg, EventKind, Prov};

    fn fx() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    fn loaded() -> Loaded {
        let d = fx().join("multi_commit");
        let img = crate::pager::build(
            &std::fs::read(d.join("mpenginedb.db")).unwrap(),
            std::fs::read(d.join("mpenginedb.db-wal")).ok().as_deref(),
            &embedded_key(),
        )
        .unwrap();
        let prov = crate::provenance::classify(
            &crate::sqldb::open(&img.db_only).unwrap(),
            &crate::sqldb::open(&img.merged).unwrap(),
        );
        let hist = crate::history::load_history(&fx().join("history"), &embedded_key());
        load(&prov, &hist, &LoadOpts::default())
    }

    fn of(l: &Loaded, k: EventKind) -> Vec<&Event> {
        l.events.iter().filter(|e| e.kind == k).collect()
    }

    fn field<'a>(e: &'a Event, name: &str) -> Option<&'a str> {
        e.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.display.as_str())
    }

    #[test]
    fn module_row_uses_instance_ts() {
        let l = loaded();
        let m = of(&l, EventKind::ModuleFirstLoad);
        assert_eq!(m[0].time, Some(134369015368153546 + 5));
        assert_eq!(field(m[0], "FirstStartTime"), Some("42 (opaque)"));
    }

    #[test]
    fn date_like_module_value_is_not_a_process_start() {
        // Real data: DLL/.pyd rows whose FirstStartTime lands in the plausible range by coincidence, years away from
        // their InstanceTimeStamp (genuine process rows: 0 ≤ Instance − First < 1 min on the reference copy).
        let ins: i64 = 134369015368153546;
        let p = synth(
            "BackupProcessInfo",
            &["FilePath", "FirstStartTime", "InstanceTimeStamp"],
            vec![
                vec![
                    Text(r"C:\T\_MEI1\python27.dll".into()),
                    Int(ins - 19_362 * 864_000_000_000),
                    Int(ins),
                ],
                vec![Text(r"C:\T\x.pyd".into()), Int(ins + 5_000_000), Int(ins)],
                vec![Text(r"C:\T\a.exe".into()), Int(ins - 60_000), Int(ins)],
            ],
        );
        let l = load_synth(&p);
        assert_eq!(of(&l, EventKind::ProcessFirstStart).len(), 1);
        assert_eq!(of(&l, EventKind::ModuleFirstLoad).len(), 2);
        assert!(
            field(of(&l, EventKind::ModuleFirstLoad)[0], "FirstStartTime")
                .unwrap()
                .contains("not a start time")
        );
    }

    #[test]
    fn process_start_lag_window_is_seven_days() {
        let ins: i64 = 134369015368153546;
        let day = 864_000_000_000i64;
        let p = synth(
            "BackupProcessInfo",
            &["FilePath", "FirstStartTime", "InstanceTimeStamp"],
            vec![
                vec![Text(r"C:\T\a.exe".into()), Int(ins - 2 * day), Int(ins)],
                vec![Text(r"C:\T\b.dll".into()), Int(ins - 8 * day), Int(ins)],
            ],
        );
        let l = load_synth(&p);
        assert_eq!(of(&l, EventKind::ProcessFirstStart).len(), 1);
        assert_eq!(of(&l, EventKind::ModuleFirstLoad).len(), 1);
    }

    #[test]
    fn filehashes_columns_swapped() {
        let l = loaded();
        let c = &l.contents[0];
        let get = |a| c.digests.iter().find(|d| d.0 == a).map(|d| d.1.clone());
        assert_eq!(get(DigestAlg::Md5), Some(vec![0x11; 16]));
        assert_eq!(get(DigestAlg::Sha1), Some(vec![0x22; 20]));
        assert_eq!(get(DigestAlg::Sha256), Some(vec![0x33; 32]));
        assert_eq!((c.fileref.record, c.fileref.seq), (134407, 9));
    }

    #[test]
    fn missing_column_skips_with_warning() {
        use crate::model::{RowKey, SqlVal};
        use crate::provenance::{ProvMap, ProvRow, TableProv};
        let mut p = ProvMap::default();
        let info = crate::sqldb::TableInfo {
            name: "BackupProcessInfo".into(),
            columns: vec!["ID".into(), "FilePath".into()],
            without_rowid: false,
            pk_cols: vec![0],
            rowid_alias: Some("rowid".into()),
            error: None,
        };
        let row = ProvRow {
            key: RowKey::Rowid(1),
            values: vec![SqlVal::Int(1), SqlVal::Text(r"C:\x".into())],
            status: DbStatus::InBoth,
            old: None,
        };
        p.tables.insert(
            "BackupProcessInfo".into(),
            TableProv {
                info: Some(info),
                readable: true,
                error: None,
                db_only_count: Some(1),
                merged_count: Some(1),
                rows: vec![row],
            },
        );
        let l = load(
            &p,
            &crate::history::HistoryLoad::default(),
            &LoadOpts::default(),
        );
        assert!(l.events.is_empty());
        assert!(
            l.warnings
                .iter()
                .any(|w| w.contains("BackupProcessInfo") && w.contains("FirstStartTime")),
            "{:?}",
            l.warnings
        );
        assert_eq!(l.raw.len(), 1);
    }

    /// One synthetic table with the given columns and rows (all InBoth).
    fn synth(
        table: &str,
        cols: &[&str],
        rows: Vec<Vec<crate::model::SqlVal>>,
    ) -> crate::provenance::ProvMap {
        use crate::provenance::{ProvMap, ProvRow, TableProv};
        let info = crate::sqldb::TableInfo {
            name: table.into(),
            columns: cols.iter().map(|c| c.to_string()).collect(),
            without_rowid: false,
            pk_cols: vec![],
            rowid_alias: Some("rowid".into()),
            error: None,
        };
        let n = rows.len();
        let rows = rows
            .into_iter()
            .enumerate()
            .map(|(i, v)| ProvRow {
                key: crate::model::RowKey::Rowid(i as i64 + 1),
                values: v,
                status: DbStatus::InBoth,
                old: None,
            })
            .collect();
        let mut p = ProvMap::default();
        p.tables.insert(
            table.into(),
            TableProv {
                info: Some(info),
                readable: true,
                error: None,
                db_only_count: Some(n),
                merged_count: Some(n),
                rows,
            },
        );
        p
    }

    fn load_synth(p: &crate::provenance::ProvMap) -> Loaded {
        load(
            p,
            &crate::history::HistoryLoad::default(),
            &LoadOpts::default(),
        )
    }

    use crate::model::SqlVal::{Blob, Int, Null, Text};

    #[test]
    fn bm_file_startup_actions_produce_events() {
        let l = load_synth(&synth(
            "BmFileStartupActions",
            &["FilePath", "FdrThreatRecordId"],
            vec![vec![Text(r"C:\t\a.exe".into()), Int(7)]],
        ));
        let e = of(&l, EventKind::BmRecord);
        assert_eq!(e.len(), 1);
        assert!(e[0].time.is_none() && e[0].location.is_some());
    }

    #[test]
    fn filehashes_null_identity_not_invented() {
        let l = load_synth(&synth(
            "FileHashes",
            &["VSN", "FileID", "InstanceTimeStamp"],
            vec![vec![Null, Null, Int(134369015368153546)]],
        ));
        assert!(l.contents.is_empty());
        let e = of(&l, EventKind::FileHashed);
        assert_eq!(e.len(), 1);
        assert_eq!(
            field(e[0], "FileRef"),
            Some("missing (FileID or VSN not an integer)")
        );
    }

    #[test]
    fn implausible_expiry_not_on_timeline() {
        let l = load_synth(&synth(
            "AmsiFileCache",
            &["PersistId", "ExpirationDate"],
            vec![vec![Text("abc".into()), Text("1601-01-01 00:00:00".into())]],
        ));
        assert_eq!(of(&l, EventKind::StoreExpiry)[0].time, None);
    }

    #[test]
    fn results_tail_kept_as_unverified() {
        let mut h = crate::history::HistoryLoad::default();
        h.scans.push(crate::history::ScanRec {
            file: "Quick/x".into(),
            category: "Quick".into(),
            guid: None,
            start: Some(134369015368153546),
            end: None,
            unverified_sec1: vec![],
            unverified_sec2_tail: vec![0xDE, 0xAD, 0xBE, 0xEF],
            trailing: 0,
        });
        let l = load(
            &crate::provenance::ProvMap::default(),
            &h,
            &LoadOpts::default(),
        );
        assert_eq!(
            field(of(&l, EventKind::ScanRun)[0], "Unverified section-2 bytes"),
            Some("deadbeef")
        );
    }

    #[test]
    fn other_store_bag_is_not_a_file_scan() {
        let mut h = crate::history::HistoryLoad::default();
        h.store.push(crate::history::StoreRec {
            file: "AB".into(),
            kind: crate::history::StoreKind::Other,
            props: vec![crate::history::store::Prop {
                name: "Weird".into(),
                val: crate::history::PropVal::U32(1),
                offset: 4,
                lossy_utf16: false,
            }],
            trailing: 0,
            container_trailing: 0,
        });
        let l = load(
            &crate::provenance::ProvMap::default(),
            &h,
            &LoadOpts::default(),
        );
        assert!(of(&l, EventKind::FileScan).is_empty());
        assert!(l.warnings.iter().any(|w| w.contains("AB")));
    }

    #[test]
    fn bm_observation_start_only_from_process_start_time() {
        let l = load_synth(&synth(
            "BmProcessInfo",
            &["PID", "ImageFileName", "InstanceTimeStamp"],
            vec![vec![
                Int(42),
                Text(r"C:\t\a.exe".into()),
                Int(134369015368153546),
            ]],
        ));
        assert_eq!(l.obs[0].pid, Some(42));
        assert_eq!(l.obs[0].start, None);
    }

    #[test]
    fn bm_fields_are_decoded() {
        let l = load_synth(&synth(
            "BmProcessInfo",
            &[
                "ProcessStartTime",
                "ProcessIntegrity",
                "MonitoringFlags_Flags",
                "HipsInjectionId",
            ],
            vec![vec![
                Int(134369015368153546),
                Int(99),
                Int(5),
                Blob(vec![0; 16]),
            ]],
        ));
        let e = of(&l, EventKind::BmRecord)[0];
        assert_eq!(
            field(e, "ProcessStartTime"),
            Some("2026-10-19 16:38:56.8153546Z")
        );
        assert_eq!(field(e, "ProcessIntegrity"), Some("0x63 (unknown)"));
        assert_eq!(field(e, "MonitoringFlags_Flags"), Some("0x5 = bits 0,2"));
        assert_eq!(
            field(e, "HipsInjectionId"),
            Some("{00000000-0000-0000-0000-000000000000}")
        );
    }

    #[test]
    fn digest_raw_is_hex_not_label() {
        let l = loaded();
        let e = of(&l, EventKind::FileHashed)[0];
        let f = e.fields.iter().find(|f| f.name.starts_with("MD5")).unwrap();
        assert_eq!(f.raw, "11".repeat(16));
        assert!(f.name.contains("column SHA1"));
    }

    #[test]
    fn store_creation_time_zero_is_sentinel() {
        let (d, _) = prop_display(
            "AMSIPidCreationTime",
            &crate::history::PropVal::U64(0),
            Tz::default(),
        );
        assert_eq!(d, "0 (zero)");
    }

    #[test]
    fn nocert_outside_system_flagged_and_removed_row_kept() {
        let l = loaded();
        let n = of(&l, EventKind::NoCertExec);
        assert_eq!(n.len(), 2);
        assert!(n.iter().all(|e| e.flag));
        assert!(n.iter().any(|e| matches!(
            &e.prov,
            Prov::Db {
                status: DbStatus::RemovedByWal,
                ..
            }
        )));
    }

    #[test]
    fn walonly_row_flagged() {
        let l = loaded();
        let e = of(&l, EventKind::ProcessFirstStart)
            .into_iter()
            .find(|e| e.summary.contains("b.exe"))
            .unwrap();
        assert!(matches!(
            &e.prov,
            Prov::Db {
                status: DbStatus::WalOnly,
                ..
            }
        ));
        assert!(e.flag);
    }

    #[test]
    fn ofn_rename_kinds() {
        let l = loaded();
        let exact = of(&l, EventKind::OfnSet)[0];
        assert_eq!(field(exact, "OriginalFileName"), Some("robocopy.exe"));
        assert_eq!(field(exact, "Rename kind"), Some("executable rename"));
        let inf = of(&l, EventKind::OfnSetInferred)[0];
        assert_eq!(field(inf, "OriginalFileName"), Some("cmd.exe"));
        assert!(inf.flag);
    }

    #[test]
    fn same_path_spellings_share_location() {
        let l = loaded();
        let a: Vec<_> = l
            .locations
            .iter()
            .filter(|x| x.key.0 == r"C:\T\A.EXE")
            .collect();
        assert_eq!(a.len(), 1);
        assert!(a[0].events.len() >= 3, "BPI + APC NoCert + OFNPROCESSED");
    }

    #[test]
    fn store_events_have_no_time_and_observations_exist() {
        let l = loaded();
        let scans = of(&l, EventKind::FileScan);
        assert!(scans.iter().all(|e| e.time.is_none() && e.store.is_some()));
        assert!(
            l.obs
                .iter()
                .any(|o| o.pid == Some(4120) && o.start == Some(134369015368153546))
        );
        assert_eq!(l.store_files.len(), 3);
    }

    #[test]
    fn host_context_has_cfa_folder_and_schema() {
        let l = loaded();
        assert!(
            l.host
                .facts
                .iter()
                .any(|f| f.0.contains("S-1-5-18") && f.1.contains("Documents"))
        );
        assert!(
            l.host
                .facts
                .iter()
                .any(|f| f.0 == "SQLite schema version" && f.1.starts_with("41"))
        );
    }

    /// review #5: a Tact queue entry with start 0 must not create an observation with start 1601-01-01.
    #[test]
    fn implausible_tact_start_not_observed() {
        use crate::model::SqlVal::{Int, Text};
        let p = synth(
            "RollingQueuesValues",
            &[
                "EntryTable",
                "EntryKey",
                "EntryValue",
                "InsertTime",
                "ExpireTime",
            ],
            vec![vec![
                Text("Tact-pid:4120,ProcessStart:0".into()),
                Text("k".into()),
                Text("1".into()),
                Int(134369015368153546),
                Int(0),
            ]],
        );
        let l = load_synth(&p);
        assert_eq!(l.obs.len(), 1);
        assert_eq!(l.obs[0].start, None);
        let e = &l.events[l.obs[0].event as usize];
        assert_eq!(field(e, "Process").unwrap(), "PID 4120 started 0 (zero)");
    }

    /// review #10: three rows sharing a ThreatRecordId are all linked pairwise (rule 8).
    #[test]
    fn threat_record_id_links_every_pair() {
        use crate::model::SqlVal::{Int, Text};
        let rows = (0..3)
            .map(|i| vec![Text(format!(r"C:\T\{i}.exe")), Int(77)])
            .collect();
        let p = synth("BmFileActions", &["FilePath", "ThreatRecordId"], rows);
        let mut l = load_synth(&p);
        let (links, _) = crate::correlate::links::link(&mut l, None);
        assert_eq!(links.iter().filter(|k| k.rule == "8").count(), 3);
    }
}
