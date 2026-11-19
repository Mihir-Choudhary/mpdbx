use mpdbx::correlate::load::{LoadOpts, load};
use mpdbx::crypto::embedded_key;
use mpdbx::model::EventKind;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A reference copy under `MPDBX_COPIES` (local evidence, never committed); `None` when the variable is unset.
fn copy_dir(rel: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("MPDBX_COPIES").map(|r| std::path::PathBuf::from(r).join(rel))
}

fn fx() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn loaded() -> mpdbx::correlate::load::Loaded {
    let d = fx().join("multi_commit");
    let db = std::fs::read(d.join("mpenginedb.db")).unwrap();
    let wal = std::fs::read(d.join("mpenginedb.db-wal")).unwrap();
    let img = mpdbx::pager::build(&db, Some(&wal), &embedded_key()).unwrap();
    let prov = mpdbx::provenance::classify(
        &mpdbx::sqldb::open(&img.db_only).unwrap(),
        &mpdbx::sqldb::open(&img.merged).unwrap(),
    );
    let hist = mpdbx::history::load_history(&fx().join("history"), &embedded_key());
    load(&prov, &hist, &LoadOpts::default())
}

#[test]
fn load_event_counts() {
    let l = loaded();
    let m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fx().join("multi_commit/manifest.json")).unwrap())
            .unwrap();
    let mut got: BTreeMap<String, u64> = BTreeMap::new();
    for e in &l.events {
        *got.entry(format!("{:?}", e.kind)).or_default() += 1;
    }
    for (k, v) in m["expect_events"].as_object().unwrap() {
        assert_eq!(got.get(k).copied().unwrap_or(0), v.as_u64().unwrap(), "{k}");
    }
    assert_eq!(got.get(&format!("{:?}", EventKind::RdpLogon)), None);
    // Only the two deliberately malformed Store fixtures warn.
    assert_eq!(l.warnings.len(), 2, "{:?}", l.warnings);
    assert!(l.warnings.iter().all(|w| w.starts_with("history record 33333") || w.starts_with("history record 44444")));
}

/// Local evidence only: the loader runs on the real reference copy without warnings other than history errors.
#[test]
#[ignore]
fn real_live_loads() {
    let Some(d) = copy_dir("live/mpdb_explorer_live") else {
        eprintln!("skipped: set MPDBX_COPIES to the reference copies folder");
        return;
    };
    let db = std::fs::read(d.join("mpenginedb.db")).unwrap();
    let wal = std::fs::read(d.join("mpenginedb.db-wal")).ok();
    let img = mpdbx::pager::build(&db, wal.as_deref(), &embedded_key()).unwrap();
    let prov = mpdbx::provenance::classify(
        &mpdbx::sqldb::open(&img.db_only).unwrap(),
        &mpdbx::sqldb::open(&img.merged).unwrap(),
    );
    let hist = mpdbx::history::load_history(&d.join("History"), &embedded_key());
    let l = load(&prov, &hist, &LoadOpts::default());
    let mut got: BTreeMap<String, u64> = BTreeMap::new();
    for e in &l.events {
        *got.entry(format!("{:?}", e.kind)).or_default() += 1;
    }
    eprintln!(
        "wal: {:?}\nevents: {got:?}\nlocations {} obs {} contents {} host {}\nvolmap {:?}\nwarnings {:?}",
        img.wal,
        l.locations.len(),
        l.obs.len(),
        l.contents.len(),
        l.host.facts.len(),
        l.volmap.map,
        l.warnings
    );
    assert!(got.get("ProcessFirstStart").copied().unwrap_or(0) > 100);
    let mut l = l;
    let t0 = std::time::Instant::now();
    let (links, runs) = mpdbx::correlate::links::link(&mut l, None);
    let mut by: BTreeMap<String, u64> = BTreeMap::new();
    for k in &links {
        *by.entry(format!("{} {:?}", k.rule, k.strength))
            .or_default() += 1;
    }
    eprintln!("links {by:?}\nruns {} in {:?}", runs.len(), t0.elapsed());
}

#[test]
fn link_counts() {
    let mut l = loaded();
    let (links, runs) = mpdbx::correlate::links::link(&mut l, None);
    let m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fx().join("multi_commit/manifest.json")).unwrap())
            .unwrap();
    let mut got: BTreeMap<String, u64> = BTreeMap::new();
    for k in &links {
        *got.entry(k.rule.to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, u64> = m["expect_links"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
        .collect();
    assert_eq!(got, want);
    assert_eq!(runs.len() as u64, m["expect_runs"].as_u64().unwrap());
    let scan = l
        .events
        .iter()
        .find(|e| e.kind == EventKind::FileScan && e.store == Some(0))
        .unwrap();
    assert!(
        scan.time.is_some() && scan.time_note.is_some(),
        "rule 7 estimate on the CTX scan"
    );
}

/// review #14: Store events point at the property they were built from (not offset 0).
#[test]
fn store_events_carry_property_offsets() {
    let p =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit");
    let c = mpdbx::case::open(
        &mpdbx::case::OpenRequest {
            path: p,
            key_dll: None,
            mft: None,
            opts: Default::default(),
        },
        &|_| {},
    )
    .unwrap();
    let store: Vec<_> = c
        .events
        .iter()
        .filter_map(|e| match &e.prov {
            mpdbx::model::Prov::Store { offset, .. } => Some(*offset),
            _ => None,
        })
        .collect();
    assert!(!store.is_empty());
    assert!(store.iter().all(|&o| o > 0), "{store:?}");
}
