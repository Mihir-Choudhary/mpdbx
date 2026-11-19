//! Oracle: per-table counts and WAL-only rowid sets equal the Python v1 tool on the local reference copies.
//! Local evidence only (`#[ignore]`): set `MPDBX_COPIES` to the folder holding the reference copies and run
//! `python tests/oracle/gen_oracle.py target/oracle_tmp` first.
use mpdbx::case::{OpenRequest, open};
use mpdbx::model::{DbStatus, Prov, RowKey};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const COPIES: &[(&str, &str)] = &[
    ("mpdb_1640", "live/mpdb_1640"),
    ("mpdb_1637", "live/mpdb_1637"),
    ("mpdb_1640b", "live/mpdb_1640b"),
    ("mpdb_1642", "live/mpdb_1642"),
    ("mpdb_explorer_live", "live/mpdb_explorer_live"),
    ("Defender_now", "live/Defender_now"),
    ("vss9_Defender_Scans", "vss9/Defender_Scans"),
];

fn oracle_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/oracle")
}

fn copies() -> PathBuf {
    PathBuf::from(
        std::env::var_os("MPDBX_COPIES").expect("set MPDBX_COPIES to the reference copies folder"),
    )
}

fn req(dir: &str) -> OpenRequest {
    OpenRequest {
        path: copies().join(dir).join("mpenginedb.db"),
        key_dll: None,
        mft: None,
        opts: Default::default(),
    }
}

#[test]
#[ignore]
fn oracle_counts_match_v1() {
    for (name, dir) in COPIES {
        let v: serde_json::Value = serde_json::from_slice(
            &std::fs::read(oracle_dir().join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        let case = open(&req(dir), &|_| {}).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        // Union of both oracle schemas: an endpoint lacking a table must count 0, and no unexpected tables.
        let mut names: BTreeSet<String> =
            v["merged"].as_object().unwrap().keys().cloned().collect();
        names.extend(v["db_only"].as_object().unwrap().keys().cloned());
        let ours: BTreeSet<String> = case
            .evidence
            .table_counts
            .iter()
            .map(|r| r.0.clone())
            .collect();
        assert_eq!(ours, names, "{name}: table set");
        for t in &names {
            let row = case
                .evidence
                .table_counts
                .iter()
                .find(|r| &r.0 == t)
                .unwrap();
            let want = |k: &str| v[k].get(t).and_then(|x| x.as_u64()).unwrap_or(0) as usize;
            assert_eq!(
                row.2.unwrap_or(0),
                want("merged"),
                "{name}: merged count of {t}"
            );
            assert_eq!(
                row.1.unwrap_or(0),
                want("db_only"),
                "{name}: db-only count of {t}"
            );
        }
        for (t, ids) in v["wal_only"].as_object().unwrap() {
            let want: BTreeSet<i64> = ids
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_i64().unwrap())
                .collect();
            let raw = case.raw.iter().find(|r| &r.name == t).unwrap();
            let got: BTreeSet<i64> = raw
                .rows
                .iter()
                .filter_map(|(_, p)| match p {
                    Prov::Db {
                        key: RowKey::Rowid(i),
                        status: DbStatus::WalOnly,
                        ..
                    } => Some(*i),
                    _ => None,
                })
                .collect();
            assert_eq!(got, want, "{name}: WAL-only rowids of {t}");
        }
        assert!(
            case.evidence.wal.stop.is_none(),
            "{name}: intact reference WAL must validate fully: {:?}",
            case.evidence.wal.stop
        );
        eprintln!(
            "{name}: OK ({} tables, WAL {} frames / {} commits)",
            v["merged"].as_object().unwrap().len(),
            case.evidence.wal.frames_applied,
            case.evidence.wal.commits
        );
    }
}

/// Correlation summary for the main reference copy, pinned after manual review (counts only, no evidence content).
#[test]
#[ignore]
fn golden_summary() {
    let case = open(&req(COPIES[4].1), &|_| {}).unwrap();
    let mut s: BTreeMap<String, usize> = BTreeMap::new();
    for e in &case.events {
        *s.entry(format!("event {:?}", e.kind)).or_default() += 1;
    }
    for k in &case.links {
        *s.entry(format!("link {} {:?}", k.rule, k.strength))
            .or_default() += 1;
    }
    s.insert("runs".into(), case.runs.len());
    s.insert("locations".into(), case.locations.len());
    let text: String = s.iter().map(|(k, v)| format!("{k}\t{v}\n")).collect();
    let golden = oracle_dir().join("golden_explorer_live.txt");
    match std::fs::read_to_string(&golden) {
        Ok(g) => assert_eq!(text, g),
        Err(_) => {
            std::fs::write(&golden, &text).unwrap();
            eprintln!("golden written for review:\n{text}");
        }
    }
}
