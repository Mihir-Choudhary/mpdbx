use mpdbx::crypto::embedded_key;
use mpdbx::pager::{self, WalStop};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn fx(variant: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(variant)
}

struct Manifest {
    counts: BTreeMap<String, i64>,
    frames_applied: u32,
    commits: u32,
    stop: Option<String>,
}

fn manifest(variant: &str) -> Manifest {
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fx(variant).join("manifest.json")).unwrap()).unwrap();
    let counts = v["expect_counts"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, n)| (k.clone(), n.as_i64().unwrap()))
        .collect();
    Manifest {
        counts,
        frames_applied: v["frames_applied"].as_u64().unwrap() as u32,
        commits: v["commits"].as_u64().unwrap() as u32,
        stop: v["stop"].as_str().map(str::to_string),
    }
}

fn build(variant: &str) -> pager::Images {
    let db = std::fs::read(fx(variant).join("mpenginedb.db")).unwrap();
    let wal = std::fs::read(fx(variant).join("mpenginedb.db-wal")).ok();
    pager::build(&db, wal.as_deref(), &embedded_key()).unwrap()
}

fn counts(image: &[u8]) -> BTreeMap<String, i64> {
    let mut img = image.to_vec();
    img[18] = 1;
    img[19] = 1;
    let mut c = rusqlite::Connection::open_in_memory().unwrap();
    c.deserialize_read_exact(rusqlite::MAIN_DB, &img[..], img.len(), true)
        .unwrap();
    let tables: Vec<String> = c
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    tables
        .into_iter()
        .map(|t| {
            let n: i64 = c
                .query_row(&format!("SELECT count(*) FROM \"{t}\""), [], |r| r.get(0))
                .unwrap();
            (t, n)
        })
        .collect()
}

fn stop_kind(s: &Option<WalStop>) -> Option<&'static str> {
    s.as_ref().map(|s| match s {
        WalStop::SaltMismatch { .. } => "salt",
        WalStop::ChecksumMismatch { .. } => "checksum",
        WalStop::Truncated { .. } => "truncated",
        WalStop::BadPageNo { .. } => "badpage",
    })
}

const VARIANTS: &[&str] = &[
    "multi_commit",
    "nowal",
    "empty_wal",
    "header_only",
    "bad_header_ck",
    "uncommitted_tail",
    "ck_fail_mid",
    "salt_reset_stale",
    "salt_first_frame",
    "truncated",
    "ps65536",
    "growth",
];

#[test]
fn every_variant_matches_manifest() {
    for v in VARIANTS {
        let m = manifest(v);
        let img = build(v);
        let got = counts(&img.merged);
        for (t, n) in &m.counts {
            assert_eq!(got.get(t), Some(n), "{v}: table {t}");
        }
        assert_eq!(
            img.wal.frames_applied, m.frames_applied,
            "{v}: frames_applied"
        );
        assert_eq!(img.wal.commits, m.commits, "{v}: commits");
        assert_eq!(stop_kind(&img.wal.stop), m.stop.as_deref(), "{v}: stop");
    }
}

#[test]
fn wal_salt_mismatch_first_frame_applies_nothing() {
    let img = build("salt_first_frame");
    assert_eq!(img.wal.frames_applied, 0);
    assert_eq!(img.merged, img.db_only);
}

#[test]
fn ck_fail_mid_never_resumes() {
    let img = build("ck_fail_mid");
    assert!(matches!(
        img.wal.stop,
        Some(WalStop::ChecksumMismatch { frame: 3, .. })
    ));
    assert_eq!(img.wal.frames_valid, 3);
}

#[test]
fn ps65536_roundtrip() {
    let img = build("ps65536");
    assert_eq!(img.page_size, 65536);
    assert_eq!(img.merged.len() % 65536, 0);
}

#[test]
fn truncated_frame_reports_offset() {
    let img = build("truncated");
    match img.wal.stop {
        Some(WalStop::Truncated { offset }) => assert_eq!(offset, 32 + 6 * (24 + 4096)),
        ref other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn header_flags_preserved_in_images() {
    let img = build("multi_commit");
    assert_eq!(img.header_18_19, [2, 2]);
    assert_eq!(&img.db_only[..16], b"SQLite format 3\0");
}

#[test]
fn bad_header_ck_reports_invalid_header() {
    let img = build("bad_header_ck");
    assert!(img.wal.present);
    assert!(!img.wal.header_valid);
    assert_eq!(img.merged, img.db_only);
}
