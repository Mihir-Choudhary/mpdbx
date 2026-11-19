//! Typed views over a `Case` (spec §8.2 Artifacts) — shared by the UI grid and the exporters.
use crate::case::Case;
use crate::correlate::load::decode_cell;
use crate::decode::time::fmt_ft;
use crate::decode::values::{fmt_fileref, fmt_vsn, hex};
use crate::model::{
    DbStatus, DigestAlg, Event, EventKind, LocClass, Node, Prov, RowKey, SqlVal, Strength,
};

#[derive(Clone, Debug)]
pub struct ViewRow {
    pub cells: Vec<String>,
    /// (field name, raw value) for decoded cells.
    pub raw: Vec<(String, String)>,
    pub prov: Option<Prov>,
    pub node: Option<Node>,
}

#[derive(Clone, Debug)]
pub struct View {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<ViewRow>,
}

pub const VIEW_NAMES: &[&str] = &[
    "Timeline",
    "Locations",
    "Process runs",
    "File content & hashes",
    "No-cert executions",
    "Renamed binaries (OFN)",
    "Defender file contexts",
    "Store provenance",
    "AMSI",
    "Scan history",
    "Queues",
    "RDP",
    "Host context",
    "CFA folders",
    "Registry cache",
    "LowFi hits",
];

/// Analyst-facing event-type names.
pub fn kind_label(k: EventKind) -> &'static str {
    use EventKind::*;
    match k {
        ProcessFirstStart => "Process first start",
        ModuleFirstLoad => "Module first load",
        NoCertExec => "No-cert execution",
        OfnSet => "OriginalFileName set",
        OfnSetInferred => "OriginalFileName (inferred)",
        OfnProcessed => "OFN processed",
        FileContext => "Defender file context",
        LowFiHit => "LowFi signature hit",
        FileHashed => "File hashed",
        StoreProcessStart => "Process start (Store)",
        FileScan => "File scan (Store)",
        AmsiScan => "AMSI scan",
        AmsiProcessStart => "Process start (AMSI)",
        StoreExpiry => "Store cache expiry",
        RegistryChange => "Registry change",
        QueueEntry => "Queue entry",
        RdpLogon => "RDP logon",
        ScanRun => "Scan run",
        BmRecord => "Behaviour-monitor record",
    }
}

pub fn status_label(s: DbStatus) -> &'static str {
    match s {
        DbStatus::InBoth => "DB",
        DbStatus::WalOnly => "WAL-only",
        DbStatus::WalModified => "WAL-modified",
        DbStatus::RemovedByWal => "Removed by WAL",
        DbStatus::Unknown => "unknown",
    }
}

pub fn class_label(c: LocClass) -> &'static str {
    match c {
        LocClass::SystemDir => "system dir",
        LocClass::OutsideSystemDirs => "outside system dirs",
        LocClass::Unknown => "unknown",
    }
}

pub fn strength_label(s: Strength) -> &'static str {
    match s {
        Strength::Exact => "● exact",
        Strength::Partial => "◐ partial",
        Strength::Heuristic => "○ heuristic",
    }
}

pub fn key_label(k: &RowKey) -> String {
    let vals = |v: &[SqlVal]| {
        v.iter()
            .map(|x| decode_cell("", x, Default::default()).1)
            .collect::<Vec<_>>()
            .join(", ")
    };
    match k {
        RowKey::Rowid(i) => format!("rowid {i}"),
        RowKey::Pk(v) => format!("pk ({})", vals(v)),
        RowKey::Full(v) => format!("row ({})", vals(v)),
    }
}

/// (source, key, status) for exports and the inspector.
pub fn prov_cols(p: &Prov) -> (String, String, String) {
    match p {
        Prov::Db {
            table, key, status, ..
        } => (table.clone(), key_label(key), status_label(*status).into()),
        Prov::Store {
            file,
            section,
            offset,
        } => (
            format!("Store {file} §{section}@{offset:#x}"),
            file.clone(),
            "Store".into(),
        ),
        Prov::Results {
            file,
            section,
            offset,
        } => (
            format!("Results {file} §{section}@{offset:#x}"),
            file.clone(),
            "Results".into(),
        ),
    }
}

#[derive(Clone, Copy)]
enum Col {
    Time,
    Kind,
    Summary,
    Path,
    Name,
    Class,
    Status,
    Flag,
    StoreRec,
    /// Field with exactly this name.
    F(&'static str),
}

fn field<'a>(e: &'a Event, name: &str) -> Option<&'a crate::model::Field> {
    e.fields.iter().find(|f| f.name == name)
}

fn event_row(c: &Case, e: &Event, cols: &[(&str, Col)]) -> ViewRow {
    let loc = e.location.and_then(|l| c.locations.get(l as usize));
    let mut raw = Vec::new();
    let cells = cols
        .iter()
        .map(|(_, col)| match col {
            Col::Time => match e.time {
                Some(t) => {
                    raw.push(("time".to_string(), t.to_string()));
                    if e.time_note.is_some() {
                        format!("≈ {}", fmt_ft(t, c.opts.tz))
                    } else {
                        fmt_ft(t, c.opts.tz)
                    }
                }
                None => String::new(),
            },
            Col::Kind => kind_label(e.kind).to_string(),
            Col::Summary => e.summary.clone(),
            Col::Path => loc
                .and_then(|l| l.spellings.first().cloned())
                .unwrap_or_default(),
            Col::Name => loc
                .map(|l| l.key.0.rsplit('\\').next().unwrap_or("").to_string())
                .unwrap_or_default(),
            Col::Class => loc
                .map(|l| class_label(l.class).to_string())
                .unwrap_or_default(),
            Col::Status => prov_cols(&e.prov).2,
            Col::Flag => {
                if e.flag {
                    "▲".into()
                } else {
                    String::new()
                }
            }
            Col::StoreRec => e
                .store
                .and_then(|s| c.store_files.get(s as usize).cloned())
                .unwrap_or_default(),
            Col::F(p) => match field(e, p) {
                Some(f) => {
                    if f.raw != f.display && !f.raw.is_empty() {
                        raw.push((f.name.clone(), f.raw.clone()));
                    }
                    f.display.clone()
                }
                None => String::new(),
            },
        })
        .collect();
    ViewRow {
        cells,
        raw,
        prov: Some(e.prov.clone()),
        node: Some(Node::Event(e.id)),
    }
}

fn event_view(
    c: &Case,
    name: &str,
    kinds: &[EventKind],
    ids: Option<&[u32]>,
    cols: &[(&str, Col)],
) -> View {
    let all: Vec<u32>;
    let ids = match ids {
        Some(i) => i,
        None => {
            all = crate::query::apply(c, &[], &Default::default());
            &all
        }
    };
    let rows = ids
        .iter()
        .filter_map(|&i| c.events.get(i as usize))
        .filter(|e| kinds.is_empty() || kinds.contains(&e.kind))
        .map(|e| event_row(c, e, cols))
        .collect();
    View {
        name: name.into(),
        columns: cols.iter().map(|x| x.0.to_string()).collect(),
        rows,
    }
}

fn simple(name: &str, columns: &[&str], rows: Vec<ViewRow>) -> View {
    View {
        name: name.into(),
        columns: columns.iter().map(|s| s.to_string()).collect(),
        rows,
    }
}

/// A typed view; `ids` (event ids, in display order) restricts event-based views.
pub fn build_view(c: &Case, name: &str, ids: Option<&[u32]>) -> View {
    use Col::*;
    use EventKind as K;
    match name {
        "Timeline" => event_view(
            c,
            name,
            &[],
            ids,
            &[
                ("Time", Time),
                ("Type", Kind),
                ("Summary", Summary),
                ("Path", Path),
                ("Source", Status),
                ("Flag", Flag),
            ],
        ),
        "No-cert executions" => event_view(
            c,
            name,
            &[K::NoCertExec],
            ids,
            &[
                ("Inserted", Time),
                ("File", Name),
                ("Location", Class),
                ("Path", Path),
                ("Source", Status),
            ],
        ),
        "Renamed binaries (OFN)" => event_view(
            c,
            name,
            &[K::OfnSet, K::OfnSetInferred],
            ids,
            &[
                ("Inserted", Time),
                ("File", Name),
                ("OriginalFileName", F("OriginalFileName")),
                ("Rename kind", F("Rename kind")),
                ("Rule", Kind),
                ("Location", Class),
                ("Path", Path),
                ("Source", Status),
            ],
        ),
        "Defender file contexts" => event_view(
            c,
            name,
            &[K::FileContext, K::OfnProcessed],
            ids,
            &[
                ("Inserted", Time),
                ("Context", F("Context")),
                ("Engine tag", F("Engine tag")),
                ("Path", Path),
                ("Source", Status),
            ],
        ),
        "Store provenance" => event_view(
            c,
            name,
            &[K::FileScan, K::StoreProcessStart],
            ids,
            &[
                ("Time", Time),
                ("Type", Kind),
                ("File", F("CONTEXT_DATA_FILENAME")),
                ("Directory", F("CONTEXT_DATA_FILEPATH")),
                ("Acting process", F("CONTEXT_DATA_PROCESSNAME")),
                ("PID", F("CONTEXT_DATA_PROCESS_ID")),
                ("Process id (pid,start)", F("CONTEXT_DATA_PROCESS_PPID")),
                ("Scan reason", F("CONTEXT_DATA_SCANREASON")),
                ("Store record", StoreRec),
            ],
        ),
        "AMSI" => event_view(
            c,
            name,
            &[K::AmsiScan, K::AmsiProcessStart],
            ids,
            &[
                ("Time", Time),
                ("Type", Kind),
                ("App", F("AMSIApp")),
                ("Process", F("AMSIOpProcName")),
                ("PID", F("AMSIPid")),
                ("Process created", F("AMSIPidCreationTime")),
                ("Store record", StoreRec),
            ],
        ),
        "Scan history" => event_view(
            c,
            name,
            &[K::ScanRun],
            ids,
            &[
                ("Start", Time),
                ("End", F("End")),
                ("Duration", F("Duration")),
                ("Category", F("Category")),
                ("GUID", F("GUID")),
            ],
        ),
        "Queues" => event_view(
            c,
            name,
            &[K::QueueEntry],
            ids,
            &[
                ("Inserted", Time),
                ("Queue", F("Queue")),
                ("Key", F("Key")),
                ("Value", F("Value")),
                ("Expires", F("ExpireTime")),
                ("Source", Status),
            ],
        ),
        "RDP" => event_view(
            c,
            name,
            &[K::RdpLogon],
            ids,
            &[
                ("Logon", Time),
                ("Source IP", F("Source IP")),
                ("User SID", F("User SID")),
                ("Workstation", F("Workstation")),
                ("Session", F("Session")),
                ("Source", Status),
            ],
        ),
        "Registry cache" => event_view(
            c,
            name,
            &[K::RegistryChange],
            ids,
            &[
                ("Time", Time),
                ("Key", F("RegPath")),
                ("Operation", F("RegOperation")),
                ("New type", F("NewRegType")),
                ("New data", F("NewRegData")),
                ("Old type", F("OldRegType")),
                ("Old data", F("OldRegData")),
                ("Source", Status),
            ],
        ),
        "LowFi hits" => event_view(
            c,
            name,
            &[K::LowFiHit],
            ids,
            &[
                ("Time", Time),
                ("Path", Path),
                ("Signature SHA (not a file hash)", F("Signature SHA")),
                ("SigSeq", F("SigSeq")),
                ("Source", Status),
            ],
        ),
        "Locations" => simple(
            name,
            &["Path", "Class", "Events", "Key strength", "Spellings"],
            c.locations
                .iter()
                .map(|l| ViewRow {
                    cells: vec![
                        l.spellings
                            .first()
                            .cloned()
                            .unwrap_or_else(|| l.key.0.clone()),
                        class_label(l.class).into(),
                        l.events.len().to_string(),
                        strength_label(l.key_strength).into(),
                        l.spellings.join(" | "),
                    ],
                    raw: vec![("key".into(), l.key.0.clone())],
                    prov: None,
                    node: Some(Node::Location(l.id)),
                })
                .collect(),
        ),
        "Process runs" => simple(
            name,
            &["Start", "Image", "PIDs", "Observations", "Sources"],
            c.runs
                .iter()
                .map(|r| {
                    let obs: Vec<_> = r
                        .obs
                        .iter()
                        .filter_map(|&o| c.obs.get(o as usize))
                        .collect();
                    let start = obs.iter().filter_map(|o| o.start).min();
                    let image = obs
                        .iter()
                        .find_map(|o| o.location)
                        .and_then(|l| c.locations.get(l as usize))
                        .map(|l| l.spellings[0].clone())
                        .unwrap_or_default();
                    let mut pids: Vec<String> = obs
                        .iter()
                        .filter_map(|o| o.pid)
                        .map(|p| p.to_string())
                        .collect();
                    pids.dedup();
                    let mut src: Vec<String> = obs
                        .iter()
                        .map(|o| format!("{:?}", c.events[o.event as usize].kind))
                        .collect();
                    src.sort();
                    src.dedup();
                    ViewRow {
                        cells: vec![
                            start.map(|t| fmt_ft(t, c.opts.tz)).unwrap_or_default(),
                            image,
                            pids.join(", "),
                            obs.len().to_string(),
                            src.join(", "),
                        ],
                        raw: start
                            .map(|t| vec![("start".to_string(), t.to_string())])
                            .unwrap_or_default(),
                        prov: None,
                        node: Some(Node::Run(r.id)),
                    }
                })
                .collect(),
        ),
        "File content & hashes" => simple(
            name,
            &[
                "Hashed",
                "FileRef",
                "Volume serial",
                "MD5",
                "SHA1",
                "SHA256",
                "Path (MFT CSV)",
            ],
            c.contents
                .iter()
                .map(|fc| {
                    let d = |a| {
                        fc.digests
                            .iter()
                            .find(|x| x.0 == a)
                            .map(|x| hex(&x.1))
                            .unwrap_or_default()
                    };
                    let mft: Vec<String> = c
                        .links_by_node
                        .get(&Node::Content(fc.id))
                        .into_iter()
                        .flatten()
                        .map(|&i| &c.links[i as usize])
                        .filter(|k| k.rule == "3")
                        .filter_map(|k| {
                            k.note
                                .strip_prefix(crate::correlate::links::MFT_NOTE)
                                .map(str::to_string)
                        })
                        .collect();
                    let ev = &c.events[fc.event as usize];
                    ViewRow {
                        cells: vec![
                            ev.time.map(|t| fmt_ft(t, c.opts.tz)).unwrap_or_default(),
                            fmt_fileref(&fc.fileref),
                            fmt_vsn(fc.fileref.vsn),
                            d(DigestAlg::Md5),
                            d(DigestAlg::Sha1),
                            d(DigestAlg::Sha256),
                            mft.join(" | "),
                        ],
                        raw: {
                            let mut r: Vec<(String, String)> = ev
                                .fields
                                .iter()
                                .filter(|f| f.name == "FileRef" || f.name == "Volume serial")
                                .map(|f| {
                                    (
                                        if f.name == "FileRef" {
                                            "FileID".to_string()
                                        } else {
                                            "VSN".to_string()
                                        },
                                        f.raw.clone(),
                                    )
                                })
                                .collect();
                            if let Some(t) = ev.time {
                                r.push(("hashed".into(), t.to_string()));
                            }
                            r
                        },
                        prov: Some(ev.prov.clone()),
                        node: Some(Node::Content(fc.id)),
                    }
                })
                .collect(),
        ),
        "Host context" => simple(
            name,
            &["Fact", "Value", "Source"],
            c.host
                .facts
                .iter()
                .map(|(k, v, p)| ViewRow {
                    cells: vec![k.clone(), v.clone(), prov_cols(p).0],
                    raw: vec![],
                    prov: Some(p.clone()),
                    node: None,
                })
                .collect(),
        ),
        "CFA folders" => simple(
            name,
            &["User (SID)", "Protected folder"],
            c.host
                .facts
                .iter()
                .filter(|f| f.0.starts_with("CFA protected folder"))
                .map(|(k, v, p)| ViewRow {
                    cells: vec![
                        k.trim_start_matches("CFA protected folder (")
                            .trim_end_matches(')')
                            .to_string(),
                        v.clone(),
                    ],
                    raw: vec![],
                    prov: Some(p.clone()),
                    node: None,
                })
                .collect(),
        ),
        _ => simple(name, &["(unknown view)"], vec![]),
    }
}

/// Every row of one table, decoded where a decoder applies, plus the provenance status.
pub fn raw_view(c: &Case, table: &str) -> View {
    let Some(t) = c.raw.iter().find(|r| r.name == table) else {
        return simple(table, &["(no such table)"], vec![]);
    };
    let mut columns = t.columns.clone();
    let mut status_col = "Status".to_string();
    while columns.iter().any(|c| c.eq_ignore_ascii_case(&status_col)) {
        status_col = format!("[{status_col}]");
    }
    columns.push(status_col);
    let rows = t
        .rows
        .iter()
        .map(|(vals, p)| {
            let mut raw = Vec::new();
            let mut cells: Vec<String> = t
                .columns
                .iter()
                .zip(vals)
                .map(|(n, v)| {
                    let (d, r) = decode_cell(n, v, c.opts.tz);
                    raw.push((n.clone(), r));
                    d
                })
                .collect();
            cells.resize(t.columns.len(), String::new());
            cells.push(prov_cols(p).2);
            ViewRow {
                cells,
                raw,
                prov: Some(p.clone()),
                node: None,
            }
        })
        .collect();
    View {
        name: format!("raw {table}"),
        columns,
        rows,
    }
}

/// Fixture access for the crate's own integration tests (not part of the tool's behaviour).
#[doc(hidden)]
pub mod tests_support {
    pub fn case() -> std::sync::Arc<crate::case::Case> {
        let p =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit");
        crate::case::open(
            &crate::case::OpenRequest {
                path: p,
                key_dll: None,
                mft: None,
                opts: Default::default(),
            },
            &|_| {},
        )
        .unwrap()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::case::{Case, OpenRequest, open};
    use std::sync::Arc;

    pub(crate) fn case() -> Arc<Case> {
        let p =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit");
        open(
            &OpenRequest {
                path: p,
                key_dll: None,
                mft: None,
                opts: Default::default(),
            },
            &|_| {},
        )
        .unwrap()
    }

    #[test]
    fn every_view_builds_on_fixture() {
        let c = case();
        let want = [
            ("Timeline", c.events.len()),
            ("Locations", c.locations.len()),
            ("Process runs", c.runs.len()),
            ("File content & hashes", 1),
            ("No-cert executions", 2),
            ("Renamed binaries (OFN)", 2),
            ("Defender file contexts", 2),
            ("Store provenance", 3),
            ("AMSI", 2),
            ("Scan history", 1),
            ("Queues", 2),
            ("RDP", 0),
            ("CFA folders", 1),
            ("Registry cache", 1),
            ("LowFi hits", 1),
        ];
        for (name, n) in want {
            let v = build_view(&c, name, None);
            assert_eq!(v.rows.len(), n, "{name}");
            assert!(
                v.rows.iter().all(|r| r.cells.len() == v.columns.len()),
                "{name}: ragged rows"
            );
        }
        assert!(build_view(&c, "Host context", None).rows.len() >= 2);
        assert_eq!(VIEW_NAMES.len(), want.len() + 1);
    }

    #[test]
    fn timeline_respects_given_ids_and_order() {
        let c = case();
        let v = build_view(&c, "Timeline", Some(&[3, 1]));
        assert_eq!(v.rows.len(), 2);
        assert_eq!(v.rows[0].node, Some(crate::model::Node::Event(3)));
    }

    #[test]
    fn time_and_identity_columns_carry_raw_values() {
        let c = case();
        let v = build_view(&c, "Timeline", None);
        assert!(
            v.rows
                .iter()
                .filter(|r| !r.cells[0].is_empty())
                .all(|r| r.raw.iter().any(|(k, _)| k == "time"))
        );
        let fc = build_view(&c, "File content & hashes", None);
        assert!(
            fc.rows[0]
                .raw
                .iter()
                .any(|(k, x)| k == "FileID" && x == "2533274790530311")
        );
        let pr = build_view(&c, "Process runs", None);
        assert!(
            pr.rows
                .iter()
                .filter(|r| !r.cells[0].is_empty())
                .all(|r| r.raw.iter().any(|(k, _)| k == "start"))
        );
    }

    #[test]
    fn field_lookup_is_exact() {
        let mut c = (*case()).clone();
        let e = c
            .events
            .iter_mut()
            .find(|e| e.kind == crate::model::EventKind::AmsiProcessStart)
            .unwrap();
        e.fields.retain(|f| f.name != "AMSIPid");
        let v = build_view(&c, "AMSI", None);
        let pid = v.columns.iter().position(|x| x == "PID").unwrap();
        assert!(
            v.rows.iter().all(|r| !r.cells[pid].contains("2026")),
            "PID must not fall back to AMSIPidCreationTime"
        );
    }

    #[test]
    fn hashes_in_raw_tables_are_hex_not_guids() {
        let c = case();
        let v = raw_view(&c, "FileHashes");
        let col = v.columns.iter().position(|x| x == "SHA1").unwrap();
        assert_eq!(v.rows[0].cells[col], "11".repeat(16));
    }

    #[test]
    fn provenance_column_never_shadows_a_table_column() {
        let mut c = (*case()).clone();
        c.raw.push(crate::model::RawTable {
            name: "T".into(),
            columns: vec!["Status".into()],
            rows: vec![(
                vec![crate::model::SqlVal::Text("pending".into())],
                crate::model::Prov::Store {
                    file: "f".into(),
                    section: 2,
                    offset: 0,
                },
            )],
            readable: true,
        });
        let v = raw_view(&c, "T");
        assert_eq!(v.columns.len(), 2);
        assert_ne!(v.columns[0], v.columns[1]);
        assert_eq!(v.rows[0].cells[0], "pending");
    }

    #[test]
    fn raw_view_decodes_filetimes_and_keeps_status() {
        let c = case();
        let v = raw_view(&c, "BackupProcessInfo");
        let col = v
            .columns
            .iter()
            .position(|x| x == "FirstStartTime")
            .unwrap();
        assert!(v.rows.iter().any(|r| r.cells[col].ends_with('Z')));
        let st = v.columns.iter().position(|x| x == "Status").unwrap();
        assert!(v.rows.iter().any(|r| r.cells[st] == "WAL-only"));
        assert!(
            v.rows
                .iter()
                .all(|r| r.raw.iter().any(|(k, _)| k == "FirstStartTime"))
        );
    }
}
