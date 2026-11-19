//! GUI regression tests (analyst-first layout).
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use mpdbx::model::EventKind;
use mpdbx::ui::app::{App, Tab};
use std::path::PathBuf;
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

#[test]
fn search_reaches_routine_events() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Timeline;
    h.state_mut().search = "type:filehashed".into();
    h.run();
    let c = h.state().case.clone().unwrap();
    let ids = h.state().timeline.ids.clone();
    assert!(
        !ids.is_empty()
            && ids
                .iter()
                .all(|&i| c.events[i as usize].kind == EventKind::FileHashed)
    );
}

#[test]
fn finding_card_clears_the_search() {
    let mut h = loaded();
    h.state_mut().search = "nonexistent-name".into();
    h.state_mut().tab = Tab::Findings;
    h.run();
    h.get_all_by_label_contains("Unsigned programs run outside system folders")
        .next()
        .unwrap()
        .click();
    h.run();
    assert_eq!(h.state().search, "");
    assert_eq!(h.state().timeline.ids.len(), 2);
}

#[test]
fn quick_views_use_exact_predicates() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Timeline;
    h.run();
    let c = h.state().case.clone().unwrap();
    for (name, _, f) in mpdbx::ui::timeline::quick_views() {
        if name != "Renamed executables" && name != "Detections & signatures" {
            continue;
        }
        h.state_mut().timeline.open_list(name, f);
        h.run();
        for &i in &h.state().timeline.ids {
            let e = &c.events[i as usize];
            let f = |n: &str| {
                e.fields
                    .iter()
                    .find(|x| x.name == n)
                    .map(|x| x.display.clone())
            };
            if name == "Renamed executables" {
                assert_eq!(
                    f("Rename kind").as_deref(),
                    Some("executable rename"),
                    "{}",
                    e.summary
                );
            } else {
                assert!(
                    e.kind == EventKind::LowFiHit
                        || (e.kind == EventKind::QueueEntry && f("Threat").is_some()),
                    "{}",
                    e.summary
                );
            }
        }
    }
}

#[test]
fn first_pivot_from_files_tab_is_kept() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Artifacts;
    h.run();
    let c = h.state().case.clone().unwrap();
    let l = c.events.iter().find_map(|e| e.location).unwrap();
    h.state_mut()
        .apply_pivot(mpdbx::ui::inspector::Pivot::Location(l));
    h.run();
    assert_eq!(h.state().timeline.query.facets.location, Some(l));
    assert!(
        h.state()
            .timeline
            .ids
            .iter()
            .all(|&i| c.events[i as usize].location == Some(l))
    );
}

#[test]
fn pivot_drops_the_card_event_set() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Findings;
    h.run();
    h.get_all_by_label_contains("Unsigned programs run outside system folders")
        .next()
        .unwrap()
        .click();
    h.run();
    let c = h.state().case.clone().unwrap();
    let e = c
        .events
        .iter()
        .find(|e| e.kind == EventKind::NoCertExec && e.location.is_some())
        .unwrap();
    let l = e.location.unwrap();
    h.state_mut()
        .apply_pivot(mpdbx::ui::inspector::Pivot::Location(l));
    h.run();
    assert!(h.state().timeline.query.facets.only.is_none());
    let all_at_l = c.events.iter().filter(|x| x.location == Some(l)).count();
    assert!(h.state().timeline.ids.len() > 1 || all_at_l == 1);
}

#[test]
fn mft_binding_keeps_bookmarks() {
    let mut h = loaded();
    let c = h.state().case.clone().unwrap();
    let id = c
        .events
        .iter()
        .find(|e| e.kind == EventKind::NoCertExec)
        .unwrap()
        .id;
    h.state_mut().selected = Some(mpdbx::model::Node::Event(id));
    h.run();
    mpdbx::ui::inspector::toggle_bookmark(
        &c,
        &mut h.state_mut().bookmarks,
        mpdbx::model::Node::Event(id),
    );
    let vsn = c
        .contents
        .first()
        .map(|x| x.fileref.vsn)
        .expect("fixture has file hashes");
    let dir = std::env::temp_dir().join(format!("mpdbx_mft_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("mft.csv");
    std::fs::write(
        &csv,
        "EntryNumber,SequenceNumber,ParentPath,FileName\r\n7,1,.\\T,a.exe\r\n",
    )
    .unwrap();
    h.state_mut()
        .reopen_with(|r| r.mft = Some((csv.clone(), vsn, 'C')));
    wait(&mut h);
    assert!(h.state().case.as_ref().unwrap().evidence.mft.is_some());
    assert_eq!(
        h.state().bookmarks.items.len(),
        1,
        "bookmark survives MFT enrichment"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn invalid_wal_header_is_not_reported_as_validated() {
    let mut w = mpdbx::pager::WalReport {
        present: true,
        header_valid: false,
        ..Default::default()
    };
    assert!(!mpdbx::ui::evidence_tab::wal_stop_text(&w).contains("fully validated"));
    w.header_valid = true;
    assert!(mpdbx::ui::evidence_tab::wal_stop_text(&w).contains("fully validated"));
    w.present = false;
    assert_eq!(mpdbx::ui::evidence_tab::wal_stop_text(&w), "no WAL file");
}

/// review #3: "This list" exported from Findings (Timeline never shown) contains the Timeline rows, not nothing.
#[test]
fn export_from_findings_uses_current_rows() {
    let mut h = loaded();
    assert_eq!(h.state().tab, Tab::Findings);
    assert!(
        h.state().timeline.ids.is_empty(),
        "precondition: Timeline not computed yet"
    );
    let v = h.state_mut().current_view().unwrap();
    assert!(!v.rows.is_empty());
    assert_eq!(v.rows.len(), h.state().timeline.ids.len());
}

/// review #8: the Files & processes search speaks the same query language as the Timeline.
#[test]
fn files_tab_search_uses_query_language() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Artifacts;
    h.state_mut().artifacts.current =
        mpdbx::ui::artifacts::Source::Typed("No-cert executions".into());
    h.run();
    let all = h.state().artifacts.rows.len();
    assert!(all >= 2);
    h.state_mut().search = "\"a.exe\"".into();
    h.run();
    let quoted = h.state().artifacts.rows.len();
    assert!(
        quoted >= 1 && quoted < all,
        "quoted value filters rows ({quoted} of {all})"
    );
    h.state_mut().search = "-a.exe".into();
    h.run();
    assert_eq!(
        h.state().artifacts.rows.len(),
        all - quoted,
        "negation honoured"
    );
    let c = h.state().case.clone().unwrap();
    let sha = c
        .contents
        .iter()
        .find_map(|x| {
            x.digests
                .iter()
                .find(|d| d.0 == mpdbx::model::DigestAlg::Sha256)
                .map(|d| mpdbx::decode::values::hex(&d.1))
        })
        .unwrap();
    h.state_mut().artifacts.current =
        mpdbx::ui::artifacts::Source::Typed("File content & hashes".into());
    h.state_mut().search = format!("sha256:{}", &sha[..8]);
    h.run();
    assert_eq!(
        h.state().artifacts.rows.len(),
        1,
        "digest pivot finds its content row"
    );
}

/// review #13: a selected location survives a reload of the same evidence (time-zone change).
#[test]
fn location_selection_survives_reload() {
    let mut h = loaded();
    let c = h.state().case.clone().unwrap();
    let l = c.events.iter().find_map(|e| e.location).unwrap();
    let key = c.locations[l as usize].key.clone();
    h.state_mut().selected = Some(mpdbx::model::Node::Location(l));
    h.run();
    h.state_mut().set_tz_text("+05:30");
    wait(&mut h);
    let c2 = h.state().case.clone().unwrap();
    match h.state().selected {
        Some(mpdbx::model::Node::Location(m)) => assert_eq!(c2.locations[m as usize].key, key),
        other => panic!("selection lost: {other:?}"),
    }
}

/// review #15: with an MFT CSV bound, a hashed file is found by its resolved path; Store events by record file name.
#[test]
fn search_finds_mft_paths_and_store_files() {
    let p = fx();
    let c = mpdbx::case::open(
        &mpdbx::case::OpenRequest {
            path: p.clone(),
            key_dll: None,
            mft: None,
            opts: Default::default(),
        },
        &|_| {},
    )
    .unwrap();
    let fr = c.contents.first().unwrap().fileref;
    let dir = std::env::temp_dir().join(format!("mpdbx_mft15_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("mft.csv");
    std::fs::write(&csv, format!("EntryNumber,SequenceNumber,ParentPath,FileName\r\n{},{},.\\Evidence,resolved_by_mft.bin\r\n", fr.record, fr.seq)).unwrap();
    let c = mpdbx::case::open(
        &mpdbx::case::OpenRequest {
            path: p,
            key_dll: None,
            mft: Some((csv, fr.vsn, 'C')),
            opts: Default::default(),
        },
        &|_| {},
    )
    .unwrap();
    let run = |q: &str| {
        let terms = mpdbx::query::parse(q, Default::default()).unwrap();
        mpdbx::query::apply(
            &c,
            &c.index,
            &mpdbx::query::Query {
                terms,
                ..Default::default()
            },
        )
    };
    let hits = run("path:*\\evidence\\resolved_by_mft.bin");
    assert!(
        hits.iter()
            .any(|&i| c.events[i as usize].kind == EventKind::FileHashed),
        "path: reaches MFT-resolved paths"
    );
    assert!(
        !run("resolved_by_mft").is_empty(),
        "free text reaches MFT-resolved paths"
    );
    let store = c
        .events
        .iter()
        .find_map(|e| e.store)
        .map(|s| c.store_files[s as usize].to_lowercase())
        .unwrap();
    assert!(
        run(&store).len() >= 2,
        "Store record file name finds its events"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// review #17: numeric cells sort numerically in Files & processes.
#[test]
fn numbers_sort_as_numbers() {
    use mpdbx::ui::artifacts::cell_cmp;
    let (two, ten) = ("2".to_string(), "10".to_string());
    assert_eq!(cell_cmp(Some(&two), Some(&ten)), std::cmp::Ordering::Less);
    let (a, b) = ("a".to_string(), "b".to_string());
    assert_eq!(cell_cmp(Some(&a), Some(&b)), std::cmp::Ordering::Less);
}
