//! Inspector, pivots, history and bookmarks (headless).
use eframe::egui;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use mpdbx::model::{EventKind, Node};
use mpdbx::ui::app::{App, Tab};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn loaded() -> Harness<'static, App> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit");
    let mut h = Harness::builder()
        .with_size((1600.0, 1000.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), App::new(Some(p)));
    let t = Instant::now();
    while h.state().is_loading() {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
        assert!(t.elapsed() < Duration::from_secs(20));
    }
    // the inspector lives beside the lists (the app opens on Findings)
    h.state_mut().tab = Tab::Timeline;
    h.run();
    h
}

fn select_kind(h: &mut Harness<'static, App>, k: EventKind) -> u32 {
    let c = h.state().case.clone().unwrap();
    let id = c.events.iter().find(|e| e.kind == k).unwrap().id;
    h.state_mut().selected = Some(Node::Event(id));
    h.run();
    id
}

#[test]
fn select_shows_related_with_rule() {
    let mut h = loaded();
    select_kind(&mut h, EventKind::NoCertExec);
    assert!(h.query_all_by_label_contains("rule 6").count() >= 1);
    assert!(h.query_all_by_label_contains("Provenance").count() >= 1);
}

#[test]
fn pivot_same_location_filters_timeline() {
    let mut h = loaded();
    select_kind(&mut h, EventKind::NoCertExec);
    h.get_by_label("Same location").click();
    h.run();
    let c = h.state().case.clone().unwrap();
    assert_eq!(h.state().tab, Tab::Timeline);
    let ids = h.state().timeline.ids.clone();
    assert!(!ids.is_empty());
    let loc = c.events[ids[0] as usize].location;
    assert!(ids.iter().all(|&i| c.events[i as usize].location == loc));
}

#[test]
fn alt_left_returns_to_previous_selection() {
    let mut h = loaded();
    let first = select_kind(&mut h, EventKind::NoCertExec);
    let second = select_kind(&mut h, EventKind::LowFiHit);
    assert_eq!(h.state().selected, Some(Node::Event(second)));
    h.key_press_modifiers(egui::Modifiers::ALT, egui::Key::ArrowLeft);
    h.run();
    assert_eq!(h.state().selected, Some(Node::Event(first)));
    h.key_press_modifiers(egui::Modifiers::ALT, egui::Key::ArrowRight);
    h.run();
    assert_eq!(h.state().selected, Some(Node::Event(second)));
}

#[test]
fn clicking_a_related_item_navigates() {
    let mut h = loaded();
    select_kind(&mut h, EventKind::NoCertExec);
    h.get_all_by_label_contains("rule 6")
        .next()
        .unwrap()
        .click();
    h.run_steps(10);
    let c = h.state().case.clone().unwrap();
    assert!(
        matches!(h.state().selected, Some(Node::Event(i)) if c.events[i as usize].kind == EventKind::ProcessFirstStart)
    );
}

#[test]
fn bookmark_then_report_contains_note() {
    let mut h = loaded();
    select_kind(&mut h, EventKind::NoCertExec);
    h.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::B);
    h.run();
    assert_eq!(h.state().bookmarks.items.len(), 1);
    h.state_mut().bookmarks.items[0].note = "analyst note 7".into();
    let c = h.state().case.clone().unwrap();
    let html = mpdbx::export::report::report(&c, &h.state().bookmarks);
    assert!(html.contains("analyst note 7"));
    h.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::B);
    h.run();
    assert!(h.state().bookmarks.items.is_empty(), "Ctrl+B toggles");
}

#[test]
fn case_change_clears_selection_and_swaps_bookmarks() {
    let mut h = loaded();
    select_kind(&mut h, EventKind::NoCertExec);
    h.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::B);
    h.run();
    assert_eq!(h.state().bookmarks.items.len(), 1);
    let other = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nowal");
    h.state_mut().open_path(other);
    let t = Instant::now();
    while h.state().is_loading() {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
        assert!(t.elapsed() < Duration::from_secs(20));
    }
    h.run();
    assert_eq!(h.state().selected, None);
    assert!(
        h.state().bookmarks.items.is_empty(),
        "bookmarks belong to the other evidence"
    );
    let first = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit");
    h.state_mut().open_path(first);
    let t = Instant::now();
    while h.state().is_loading() {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
        assert!(t.elapsed() < Duration::from_secs(20));
    }
    h.run();
    assert_eq!(
        h.state().bookmarks.items.len(),
        1,
        "restored when the same evidence is reopened"
    );
}

#[test]
fn loaded_bookmarks_file_is_protected_from_exports() {
    let mut h = loaded();
    let d = std::env::temp_dir().join(format!("mpdbx_ui_bm_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("notes.mpdbx.json");
    std::fs::write(&f, br#"{"items":[]}"#).unwrap();
    h.state_mut().load_bookmarks_from(&f).unwrap();
    let g = h.state().output_guard().unwrap();
    assert_eq!(
        g.check_file(&f, true),
        Err(mpdbx::export::guard::GuardError::IsInput)
    );
}

#[test]
fn copy_event_copies_one_tsv_row() {
    let mut h = loaded();
    let id = select_kind(&mut h, EventKind::NoCertExec);
    let c = h.state().case.clone().unwrap();
    let row = mpdbx::ui::app::row_tsv(&c, id, mpdbx::decode::time::Tz::default());
    assert!(!row.contains('\n'));
    assert_eq!(
        row.matches('\t').count(),
        4,
        "Time, Type, Source, Summary, Path"
    );
    h.event(egui::Event::Copy);
    h.run();
    assert_eq!(h.state().last_copied.as_deref(), Some(row.as_str()));
}

#[test]
fn same_location_pivot_is_exact() {
    let mut h = loaded();
    let id = select_kind(&mut h, EventKind::NoCertExec);
    h.get_by_label("Same location").click();
    h.run();
    let c = h.state().case.clone().unwrap();
    let loc = c.events[id as usize].location;
    assert_eq!(h.state().timeline.query.facets.location, loc);
}

#[test]
fn digest_pivot_falls_back_to_sha1() {
    let mut c = (*mpdbx::views::tests_support::case()).clone();
    c.contents[0]
        .digests
        .retain(|d| d.0 != mpdbx::model::DigestAlg::Sha256);
    let p = mpdbx::ui::inspector::digest_pivot(&c, 0).unwrap();
    assert!(matches!(p, mpdbx::ui::inspector::Pivot::Search(ref s) if s.starts_with("sha1:")));
}

#[test]
fn value_filter_query_is_quoted() {
    assert_eq!(
        mpdbx::ui::inspector::value_query("Asr Obfus"),
        "\"asr obfus\""
    );
    assert_eq!(mpdbx::ui::inspector::value_query("say \"x\""), "\"say x\"");
}
