//! Open pipeline: inputs → decrypted images → provenance → load → links → immutable `Case` (spec §4).
use crate::correlate::links::{MftIndex, link, load_mft_csv};
use crate::correlate::load::{LoadOpts, load};
use crate::crypto::{Key, SQLITE_MAGIC, embedded_key, find_key, key_matches};
use crate::evidence::{Input, MAX_INPUT, read_input};
use crate::history::{HistoryLoad, load_history};
use crate::model::{
    DbStatus, Event, FileContent, Ft, HostContext, Link, Location, Node, ProcessObs, ProcessRun,
    RawTable,
};
use crate::normalize::volmap::VolMap;
use crate::pager::{self, PagerError, WalReport};
use crate::provenance::{ProvMap, classify, classify_table};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};

#[derive(Clone, Debug)]
pub struct InputSummary {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub mtime: Option<Ft>,
    pub changed_during_read: bool,
    pub shared_write_fallback: bool,
}

impl From<&Input> for InputSummary {
    fn from(i: &Input) -> Self {
        InputSummary {
            path: i.path.display().to_string(),
            size: i.size,
            sha256: i.sha256.clone(),
            mtime: i.mtime,
            changed_during_read: i.changed_during_read,
            shared_write_fallback: i.shared_write_fallback,
        }
    }
}

/// (table, db-only count, merged count, counts per status [InBoth, WalOnly, WalModified, RemovedByWal, Unknown])
pub type TableCount = (String, Option<usize>, Option<usize>, [usize; 5]);

#[derive(Clone, Debug)]
pub struct EvidenceReport {
    pub inputs: Vec<InputSummary>,
    pub page_size: u32,
    pub pages: u32,
    pub header_18_19: [u8; 2],
    pub encrypted: bool,
    pub key_source: String,
    pub wal: WalReport,
    pub table_counts: Vec<TableCount>,
    pub volmap: VolMap,
    pub mft: Option<(String, u32, char, u32)>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Case {
    pub evidence: EvidenceReport,
    pub events: Vec<Event>,
    pub locations: Vec<Location>,
    pub obs: Vec<ProcessObs>,
    pub runs: Vec<ProcessRun>,
    pub contents: Vec<FileContent>,
    pub links: Vec<Link>,
    /// Node → indices into `links`.
    pub links_by_node: HashMap<Node, Vec<u32>>,
    pub host: HostContext,
    pub raw: Vec<RawTable>,
    pub store_files: Vec<String>,
    pub opts: LoadOpts,
    /// Every input, for the export guard.
    pub inputs: Vec<Input>,
    /// Lower-case search text per event, built on the worker thread (query::build_index).
    pub index: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct OpenRequest {
    /// `mpenginedb.db` or a `Scans` folder.
    pub path: PathBuf,
    pub key_dll: Option<PathBuf>,
    /// MFTECmd CSV bound to (volume serial, drive letter).
    pub mft: Option<(PathBuf, u32, char)>,
    pub opts: LoadOpts,
}

#[derive(Debug)]
pub enum Progress {
    Stage(&'static str),
    Done(Result<Arc<Case>, OpenError>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    Unreadable(String),
    WrongKey,
    Pager(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Unreadable(e) => write!(f, "input unreadable: {e}"),
            OpenError::WrongKey => write!(
                f,
                "page 1 does not decrypt with the built-in key; supply the matching mpengine.dll"
            ),
            OpenError::Pager(e) => write!(f, "{e}"),
        }
    }
}

/// Test-only trigger for the worker panic path (a per-request marker, so parallel tests cannot interfere).
#[cfg(test)]
pub(crate) const PANIC_MARKER: &str = "__mpdbx_test_panic__";

/// (db, wal if present, History dir if present). A folder must contain `mpenginedb.db`.
pub fn resolve_inputs(
    path: &Path,
) -> Result<(PathBuf, Option<PathBuf>, Option<PathBuf>), OpenError> {
    let (db, dir) = if path.is_dir() {
        (path.join("mpenginedb.db"), path.to_path_buf())
    } else {
        (
            path.to_path_buf(),
            path.parent().map(Path::to_path_buf).unwrap_or_default(),
        )
    };
    if !db.is_file() {
        return Err(OpenError::Unreadable(format!("{} not found", db.display())));
    }
    let mut wal_name = db.clone().into_os_string();
    wal_name.push("-wal");
    let wal = PathBuf::from(wal_name);
    let hist = dir.join("History");
    Ok((
        db,
        wal.is_file().then_some(wal),
        hist.is_dir().then_some(hist),
    ))
}

fn status_ix(s: DbStatus) -> usize {
    match s {
        DbStatus::InBoth => 0,
        DbStatus::WalOnly => 1,
        DbStatus::WalModified => 2,
        DbStatus::RemovedByWal => 3,
        DbStatus::Unknown => 4,
    }
}

pub fn open(req: &OpenRequest, progress: &dyn Fn(Progress)) -> Result<Arc<Case>, OpenError> {
    progress(Progress::Stage("reading evidence"));
    #[cfg(test)]
    if req.path.ends_with(PANIC_MARKER) {
        panic!("injected test panic");
    }
    let (db_path, wal_path, hist_dir) = resolve_inputs(&req.path)?;
    let db = read_input(&db_path, MAX_INPUT).map_err(OpenError::Unreadable)?;
    let mut inputs = vec![db.clone()];
    let mut early_warnings = Vec::new();
    let wal = match &wal_path {
        Some(p) => match read_input(p, MAX_INPUT) {
            Ok(w) => {
                inputs.push(w.clone());
                Some(w)
            }
            Err(e) => {
                // WAL problems are never fatal (§11): load DB-only, keep the WAL protected from exports.
                early_warnings.push(format!(
                    "WAL could not be read ({e}); not applied — DB-only view"
                ));
                inputs.push(Input {
                    path: p.clone(),
                    bytes: Vec::new(),
                    sha256: String::new(),
                    size: 0,
                    mtime: None,
                    changed_during_read: false,
                    shared_write_fallback: false,
                    identity: crate::evidence::file_identity(p),
                });
                None
            }
        },
        None => None,
    };

    progress(Progress::Stage("checking key"));
    let mut key: Key = embedded_key();
    let mut key_source = "built-in mpengine key".to_string();
    let encrypted = !db.bytes.starts_with(SQLITE_MAGIC);
    if encrypted && !key_matches(&key, &db.bytes) {
        let Some(dll) = &req.key_dll else {
            return Err(OpenError::WrongKey);
        };
        let d = read_input(dll, MAX_INPUT).map_err(OpenError::Unreadable)?;
        key = find_key(&d.bytes, &db.bytes).ok_or(OpenError::WrongKey)?;
        key_source = format!("extracted from {}", dll.display());
        inputs.push(d);
    }

    progress(Progress::Stage("decrypting pages and replaying the WAL"));
    let img = pager::build(&db.bytes, wal.as_ref().map(|w| w.bytes.as_slice()), &key).map_err(
        |e| match e {
            PagerError::NotEncryptedOrWrongKey => OpenError::WrongKey,
            PagerError::BadPageSize(p) => OpenError::Pager(format!("invalid page size {p}")),
            PagerError::Empty => OpenError::Pager("database file is empty or truncated".into()),
        },
    )?;

    progress(Progress::Stage("comparing DB-only and merged images"));
    let merged = crate::sqldb::open(&img.merged)
        .map_err(|e| OpenError::Pager(format!("merged image unreadable: {e}")))?;
    let mut warnings: Vec<String> = early_warnings;
    warnings.extend(img.notes.iter().cloned());
    let prov: ProvMap = match crate::sqldb::open(&img.db_only) {
        Ok(a) => classify(&a, &merged),
        Err(e) => {
            warnings.push(format!(
                "DB-only image unreadable ({e}); provenance unknown"
            ));
            let mut p = ProvMap::default();
            for t in merged.tables() {
                let mut tp = classify_table(Some(Err(e.clone())), merged.rows(&t));
                tp.info = Some(t.clone());
                p.tables.insert(t.name.clone(), tp);
            }
            p
        }
    };

    progress(Progress::Stage("reading Scans\\History"));
    let hist = match &hist_dir {
        Some(h) => load_history(h, &key),
        None => HistoryLoad::default(),
    };
    inputs.extend(hist.inputs.iter().cloned());

    let mut mft_info = None;
    let mft: Option<MftIndex> = match &req.mft {
        Some((p, vsn, drive)) => {
            let i = read_input(p, MAX_INPUT).map_err(OpenError::Unreadable)?;
            let idx = load_mft_csv(&i.bytes, *vsn, *drive)
                .map_err(|e| OpenError::Unreadable(format!("MFT CSV: {e}")))?;
            mft_info = Some((p.display().to_string(), *vsn, *drive, idx.skipped));
            inputs.push(i);
            Some(idx)
        }
        None => None,
    };

    progress(Progress::Stage("correlating"));
    let mut l = load(&prov, &hist, &req.opts);
    let (links, runs) = link(&mut l, mft.as_ref());
    let mut links_by_node: HashMap<Node, Vec<u32>> = HashMap::new();
    for (i, k) in links.iter().enumerate() {
        links_by_node.entry(k.a).or_default().push(i as u32);
        links_by_node.entry(k.b).or_default().push(i as u32);
    }

    let mut table_counts: Vec<TableCount> = prov
        .tables
        .iter()
        .map(|(name, tp)| {
            let mut c = [0usize; 5];
            for r in &tp.rows {
                c[status_ix(r.status)] += 1;
            }
            (name.clone(), tp.db_only_count, tp.merged_count, c)
        })
        .collect();
    table_counts.sort_by(|a, b| a.0.cmp(&b.0));
    for i in inputs.iter().filter(|i| !i.sha256.is_empty()) {
        if i.changed_during_read {
            warnings.push(format!(
                "{} changed while it was being read",
                i.path.display()
            ));
        }
        if i.shared_write_fallback {
            warnings.push(format!(
                "{} was open for writing by another program when read",
                i.path.display()
            ));
        }
    }
    warnings.extend(l.warnings.iter().cloned());
    let evidence = EvidenceReport {
        inputs: inputs.iter().map(InputSummary::from).collect(),
        page_size: img.page_size,
        pages: (img.db_only.len() / img.page_size as usize) as u32,
        header_18_19: img.header_18_19,
        encrypted: img.encrypted,
        key_source,
        wal: img.wal.clone(),
        table_counts,
        volmap: l.volmap.clone(),
        mft: mft_info,
        warnings,
    };
    progress(Progress::Stage("building the search index"));
    let mut case = Case {
        evidence,
        events: l.events,
        locations: l.locations,
        obs: l.obs,
        runs,
        contents: l.contents,
        links,
        links_by_node,
        host: l.host,
        raw: l.raw,
        store_files: l.store_files,
        opts: req.opts.clone(),
        inputs,
        index: Vec::new(),
    };
    case.index = crate::query::build_index(&case);
    Ok(Arc::new(case))
}

/// Runs `open` on a worker thread; a panic becomes `Done(Err(Pager("internal error: …")))`.
pub fn open_in_thread(req: OpenRequest) -> Receiver<Progress> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let tx2 = tx.clone();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            open(&req, &|p| {
                let _ = tx2.send(p);
            })
        }));
        let done = match res {
            Ok(r) => r,
            Err(e) => {
                let msg = e
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| e.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".into());
                Err(OpenError::Pager(format!("internal error: {msg}")))
            }
        };
        let _ = tx.send(Progress::Done(done));
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::tests::tmpdir;

    fn fx(v: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(v)
    }

    #[test]
    fn resolve_scans_folder_layout() {
        let d = tmpdir("case_resolve");
        std::fs::write(d.join("mpenginedb.db"), b"x").unwrap();
        std::fs::write(d.join("mpenginedb.db-wal"), b"x").unwrap();
        std::fs::create_dir_all(d.join("History")).unwrap();
        let (db, wal, hist) = resolve_inputs(&d).unwrap();
        assert_eq!(db, d.join("mpenginedb.db"));
        assert_eq!(wal, Some(d.join("mpenginedb.db-wal")));
        assert_eq!(hist, Some(d.join("History")));
        let (db2, wal2, hist2) = resolve_inputs(&d.join("mpenginedb.db")).unwrap();
        assert_eq!(
            (db2, wal2, hist2),
            (
                d.join("mpenginedb.db"),
                Some(d.join("mpenginedb.db-wal")),
                Some(d.join("History"))
            )
        );
        assert!(matches!(
            resolve_inputs(&d.join("nope")),
            Err(OpenError::Unreadable(_))
        ));
    }

    #[test]
    fn opens_fixture_with_counts_and_links() {
        let req = OpenRequest {
            path: fx("multi_commit"),
            key_dll: None,
            mft: None,
            opts: Default::default(),
        };
        let c = open(&req, &|_| {}).unwrap();
        assert_eq!(c.evidence.wal.commits, 5);
        assert!(
            c.evidence
                .inputs
                .iter()
                .any(|i| i.path.ends_with("mpenginedb.db") && i.sha256.len() == 64)
        );
        let bpi = c
            .evidence
            .table_counts
            .iter()
            .find(|t| t.0 == "BackupProcessInfo")
            .unwrap();
        assert_eq!((bpi.1, bpi.2), (Some(2), Some(3)));
        assert_eq!(bpi.3, [1, 1, 1, 0, 0]);
        assert!(!c.links.is_empty());
        let (n, ids) = c.links_by_node.iter().next().unwrap();
        assert!(
            ids.iter()
                .all(|&i| c.links[i as usize].a == *n || c.links[i as usize].b == *n)
        );
    }

    #[test]
    fn wrong_key_error() {
        let d = tmpdir("case_wrongkey");
        let mut db = std::fs::read(fx("nowal").join("mpenginedb.db")).unwrap();
        db[0] ^= 0xFF;
        std::fs::write(d.join("mpenginedb.db"), db).unwrap();
        let req = OpenRequest {
            path: d.clone(),
            key_dll: None,
            mft: None,
            opts: Default::default(),
        };
        assert!(matches!(open(&req, &|_| {}), Err(OpenError::WrongKey)));
    }

    #[test]
    fn unreadable_wal_falls_back_to_db_only() {
        use std::os::windows::fs::OpenOptionsExt;
        let d = tmpdir("case_walunreadable");
        std::fs::copy(
            fx("multi_commit").join("mpenginedb.db"),
            d.join("mpenginedb.db"),
        )
        .unwrap();
        std::fs::copy(
            fx("multi_commit").join("mpenginedb.db-wal"),
            d.join("mpenginedb.db-wal"),
        )
        .unwrap();
        let _lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(d.join("mpenginedb.db-wal"))
            .unwrap();
        let req = OpenRequest {
            path: d.clone(),
            key_dll: None,
            mft: None,
            opts: Default::default(),
        };
        let c = open(&req, &|_| {}).unwrap();
        assert_eq!(c.evidence.wal.frames_applied, 0);
        assert!(
            c.evidence
                .warnings
                .iter()
                .any(|w| w.contains("WAL") && w.contains("not applied")),
            "{:?}",
            c.evidence.warnings
        );
        assert!(
            c.inputs
                .iter()
                .any(|i| i.path.ends_with("mpenginedb.db-wal")),
            "WAL stays protected by the export guard"
        );
    }

    #[test]
    fn progress_reports_stages() {
        let req = OpenRequest {
            path: fx("nowal"),
            key_dll: None,
            mft: None,
            opts: Default::default(),
        };
        let stages = std::cell::RefCell::new(Vec::new());
        open(&req, &|p| {
            if let Progress::Stage(s) = p {
                stages.borrow_mut().push(s)
            }
        })
        .unwrap();
        assert!(stages.borrow().len() >= 4);
    }

    #[test]
    fn panic_in_worker_reported() {
        let rx = open_in_thread(OpenRequest {
            path: fx(PANIC_MARKER),
            key_dll: None,
            mft: None,
            opts: Default::default(),
        });
        let mut done = None;
        for p in rx.iter() {
            if let Progress::Done(r) = p {
                done = Some(r);
            }
        }
        assert!(matches!(done, Some(Err(OpenError::Pager(m))) if m.contains("internal error")));
    }
}
