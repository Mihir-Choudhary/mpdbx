//! Evidence safety: loading, querying and building every view writes nothing (spec §4, §12).
use mpdbx::case::{OpenRequest, open};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

type Snap = BTreeMap<PathBuf, (u64, Option<SystemTime>)>;

fn snap(dir: &Path, recursive: bool) -> Snap {
    let mut m = Snap::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return m };
    for e in rd.flatten() {
        let p = e.path();
        if let Ok(md) = e.metadata() {
            if md.is_dir() {
                if recursive {
                    m.extend(snap(&p, true));
                }
            } else {
                m.insert(p, (md.len(), md.modified().ok()));
            }
        }
    }
    m
}

fn sqlite_temps(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with("etilqs_")).collect())
        .unwrap_or_default()
}

fn exercise(path: &Path) {
    let c = open(&OpenRequest { path: path.to_path_buf(), key_dll: None, mft: None, opts: Default::default() }, &|_| {}).unwrap();
    let q = mpdbx::query::Query { terms: mpdbx::query::parse("-type:module nocert:yes", Default::default()).unwrap(), ..Default::default() };
    let _ = mpdbx::query::apply(&c, &c.index, &q);
    for v in mpdbx::views::VIEW_NAMES {
        let _ = mpdbx::views::build_view(&c, v, None);
    }
    for t in &c.raw {
        let _ = mpdbx::views::raw_view(&c, &t.name);
    }
    let _ = mpdbx::export::report::report(&c, &Default::default());
}

fn check(dirs: &[PathBuf], cases: &[PathBuf]) {
    let temp = std::env::temp_dir();
    let before: Vec<Snap> = dirs.iter().map(|d| snap(d, true)).collect();
    let temps_before = sqlite_temps(&temp);
    for c in cases {
        exercise(c);
    }
    for (d, b) in dirs.iter().zip(&before) {
        assert_eq!(&snap(d, true), b, "files created or modified under {}", d.display());
    }
    let new_temps: Vec<String> = sqlite_temps(&temp).into_iter().filter(|n| !temps_before.contains(n)).collect();
    assert!(new_temps.is_empty(), "SQLite temp files appeared: {new_temps:?}");
}

#[test]
fn open_writes_nothing() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fx = root.join("tests/fixtures");
    let cases: Vec<PathBuf> = ["multi_commit", "nowal", "ck_fail_mid", "salt_reset_stale", "ps65536", "growth"].iter().map(|v| fx.join(v)).collect();
    // fixture tree + crate root files (not target/, which cargo itself writes)
    let mut dirs = vec![fx.clone()];
    dirs.push(root.join("src"));
    check(&dirs, &cases);
    let top: Vec<_> = std::fs::read_dir(&root).unwrap().flatten().filter(|e| e.path().is_file()).map(|e| e.file_name()).collect();
    assert!(top.iter().all(|n| !n.to_string_lossy().starts_with("etilqs_")));
}

/// Local evidence only.
#[test]
#[ignore]
fn open_writes_nothing_reference() {
    let d = PathBuf::from(r"C:\dfir_research\copies\live\mpdb_explorer_live");
    check(&[d.clone()], &[d]);
}
