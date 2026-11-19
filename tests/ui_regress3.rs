//! GUI regression tests (sorting, Files & processes search, routine events in targeted lists,
//! MFT-resolved locations in pivots and filters, export from Files & processes).
use egui_kittest::Harness;
use mpdbx::model::{DbStatus, EventKind, Node, Prov};
use mpdbx::ui::app::{App, Tab};
use mpdbx::ui::artifacts::{Source, cell_cmp};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn fx() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit")
}

fn wait(h: &mut Harness<'static, App>) {
    let t = Instant::now();
    while h.state().is_loading() {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
        assert!(t.elapsed() < Duration::from_secs(20));
    }
    h.run();
}

fn loaded() -> Harness<'static, App> {
    let mut h = Harness::builder()
        .with_size((1600.0, 1000.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), App::new(Some(fx())));
    wait(&mut h);
    h
}

/// Binds an MFT CSV that places the first hashed file at a path no table mentions (an MFT-only location).
fn bind_mft(h: &mut Harness<'static, App>, tag: &str) -> PathBuf {
    let c = h.state().case.clone().unwrap();
    let fr = c.contents.first().expect("fixture has file hashes").fileref;
    let dir = std::env::temp_dir().join(format!("mpdbx_r3_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("mft.csv");
    std::fs::write(&csv, format!("EntryNumber,SequenceNumber,ParentPath,FileName\r\n{},{},.\\MftOnly,only_in_mft.bin\r\n", fr.record, fr.seq)).unwrap();
    h.state_mut()
        .reopen_with(|r| r.mft = Some((csv.clone(), fr.vsn, 'C')));
    wait(h);
    dir
}

fn mft_location(h: &Harness<'static, App>) -> u32 {
    let c = h.state().case.clone().unwrap();
    c.locations
        .iter()
        .find(|l| l.key.0.ends_with(r"\MFTONLY\ONLY_IN_MFT.BIN"))
        .expect("MFT location")
        .id
}

fn cleanup(d: &Path) {
    let _ = std::fs::remove_dir_all(d);
}

/// Numeric and non-numeric cells in one column still sort consistently (no "10" < "15a" < "2" < "10" cycle).
#[test]
fn cell_order_is_total() {
    use std::cmp::Ordering::*;
    let s = |x: &str| Some(x.to_string());
    let (a, b, c) = (s("10"), s("15a"), s("2"));
    assert_eq!(
        cell_cmp(a.as_ref(), c.as_ref()),
        Greater,
        "numbers compare as numbers"
    );
    assert_eq!(
        cell_cmp(a.as_ref(), b.as_ref()),
        Less,
        "numbers before text"
    );
    assert_eq!(
        cell_cmp(c.as_ref(), b.as_ref()),
        Less,
        "numbers before text"
    );
    let mut v: Vec<Option<String>> = ["15a", "2", "x", "10", "", "-1", "1e3", "abc"]
        .iter()
        .map(|x| s(x))
        .collect();
    v.push(None);
    v.sort_by(|x, y| cell_cmp(x.as_ref(), y.as_ref()));
    for i in 0..v.len() {
        for j in i..v.len() {
            assert_ne!(
                cell_cmp(v[i].as_ref(), v[j].as_ref()),
                Greater,
                "{:?} after {:?}",
                v[i],
                v[j]
            );
        }
    }
}

/// Text shown only in a grid cell is found on node-backed views too.
#[test]
fn files_tab_search_matches_cell_text() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Artifacts;
    h.state_mut().artifacts.current = Source::Typed("Locations".into());
    h.run();
    let v = h.state().artifacts.view.clone().unwrap();
    let class = v
        .rows
        .iter()
        .map(|r| r.cells[1].clone())
        .find(|x| !x.is_empty())
        .unwrap();
    let want = v
        .rows
        .iter()
        .filter(|r| {
            r.cells
                .iter()
                .any(|x| x.to_lowercase().contains(&class.to_lowercase()))
        })
        .count();
    h.state_mut().search = format!("\"{class}\"");
    h.run();
    assert!(
        h.state().artifacts.rows.len() >= want && want > 0,
        "class label '{class}' finds its rows"
    );
}

/// A /regex/ on a raw table (rows without a model node) is matched against the cells.
#[test]
fn files_tab_regex_on_raw_table() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Artifacts;
    let c = h.state().case.clone().unwrap();
    let t = c
        .events
        .iter()
        .find_map(|e| match &e.prov {
            Prov::Db { table, .. } if table == "BackupProcessInfo" => Some(table.clone()),
            _ => None,
        })
        .unwrap();
    h.state_mut().artifacts.current = Source::Raw(t);
    h.run();
    let all = h.state().artifacts.rows.len();
    assert!(all > 0);
    h.state_mut().search = r"/\.exe/".into();
    h.run();
    let n = h.state().artifacts.rows.len();
    assert!(n > 0 && n <= all, "regex matched {n} of {all} raw rows");
    h.state_mut().search = "/zz_no_such_value_zz/".into();
    h.run();
    assert_eq!(h.state().artifacts.rows.len(), 0);
}

/// An MFT-only location stays visible when searching for its file name.
#[test]
fn files_tab_finds_mft_only_location() {
    let mut h = loaded();
    let dir = bind_mft(&mut h, "loc");
    let l = mft_location(&h);
    h.state_mut().tab = Tab::Artifacts;
    h.state_mut().artifacts.current = Source::Typed("Locations".into());
    h.state_mut().search = "name:only_in_mft.bin".into();
    h.run();
    let v = h.state().artifacts.view.clone().unwrap();
    let kept: Vec<_> = h
        .state()
        .artifacts
        .rows
        .iter()
        .map(|&i| v.rows[i].node)
        .collect();
    assert!(
        kept.contains(&Some(Node::Location(l))),
        "MFT-only location kept: {kept:?}"
    );
    cleanup(&dir);
}

/// "Red flags" and "Found only in the WAL" list flagged routine events (the WAL-only FileHashes row).
#[test]
fn targeted_quick_views_include_routine_events() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Timeline;
    h.run();
    let c = h.state().case.clone().unwrap();
    let wal_hash = c
        .events
        .iter()
        .find(|e| {
            e.kind == EventKind::FileHashed
                && e.flag
                && matches!(
                    e.prov,
                    Prov::Db {
                        status: DbStatus::WalOnly,
                        ..
                    }
                )
        })
        .expect("fixture has a WAL-only FileHashes row")
        .id;
    assert!(
        !h.state().timeline.show_routine,
        "precondition: routine events hidden"
    );
    for (name, _, f) in mpdbx::ui::timeline::quick_views() {
        if name != "Red flags" && name != "Found only in the WAL" {
            continue;
        }
        h.state_mut().timeline.open_list(name, f);
        h.run();
        assert!(
            h.state().timeline.ids.contains(&wal_hash),
            "{name} lists the WAL-only FileHashed event"
        );
    }
    // the broad list still hides it
    let all = mpdbx::ui::timeline::quick_views()
        .into_iter()
        .find(|q| q.0 == "All activity")
        .unwrap();
    h.state_mut().timeline.open_list(all.0, all.2);
    h.run();
    assert!(!h.state().timeline.ids.contains(&wal_hash));
}

/// "Same location" after a quick view drops the quick view's filters and shows routine events at the location.
#[test]
fn pivot_after_quick_view_shows_everything_there() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Timeline;
    h.run();
    let c = h.state().case.clone().unwrap();
    let e = c
        .events
        .iter()
        .find(|e| e.kind == EventKind::ModuleFirstLoad && e.location.is_some())
        .expect("fixture has a module load");
    let l = e.location.unwrap();
    let unsigned = mpdbx::ui::timeline::quick_views()
        .into_iter()
        .find(|q| q.0 == "Unsigned programs")
        .unwrap();
    h.state_mut().timeline.open_list(unsigned.0, unsigned.2);
    h.run();
    h.state_mut()
        .apply_pivot(mpdbx::ui::inspector::Pivot::Location(l));
    h.run();
    let want: Vec<u32> = c
        .events
        .iter()
        .filter(|x| x.location == Some(l))
        .map(|x| x.id)
        .collect();
    let mut got = h.state().timeline.ids.clone();
    got.sort();
    assert_eq!(
        got, want,
        "every event at the location, routine ones included"
    );
}

/// "Same location" and loc: reach FileHashes events through their MFT-resolved path.
#[test]
fn mft_location_pivot_and_loc_filter() {
    let mut h = loaded();
    let dir = bind_mft(&mut h, "pivot");
    let l = mft_location(&h);
    let c = h.state().case.clone().unwrap();
    let hashed = c.contents.first().unwrap().event;
    h.state_mut().tab = Tab::Timeline;
    h.run();
    h.state_mut()
        .apply_pivot(mpdbx::ui::inspector::Pivot::Location(l));
    h.run();
    assert!(
        h.state().timeline.ids.contains(&hashed),
        "pivot reaches the hashed file"
    );
    let class = c.locations[l as usize].class;
    let q = match class {
        mpdbx::model::LocClass::SystemDir => "loc:system",
        mpdbx::model::LocClass::OutsideSystemDirs => "loc:outside",
        mpdbx::model::LocClass::Unknown => "loc:unknown",
    };
    let terms = mpdbx::query::parse(q, Default::default()).unwrap();
    let ids = mpdbx::query::apply(
        &c,
        &c.index,
        &mpdbx::query::Query {
            terms,
            ..Default::default()
        },
    );
    assert!(ids.contains(&hashed), "{q} matches the hashed file");
    cleanup(&dir);
}

/// "This list" from Files & processes reflects the current search even before the tab has been redrawn.
#[test]
fn export_from_files_tab_uses_current_search() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Artifacts;
    h.state_mut().artifacts.current = Source::Typed("No-cert executions".into());
    h.run();
    let all = h.state().artifacts.rows.len();
    h.state_mut().search = "zz_no_such_value_zz".into();
    let v = h.state_mut().current_view().unwrap();
    assert!(all > 0);
    assert_eq!(v.rows.len(), 0, "export follows the new search");
}
