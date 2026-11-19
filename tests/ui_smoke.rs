//! Headless UI tests with egui_kittest (no window, no GPU).
use eframe::egui;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use mpdbx::ui::app::{App, Tab};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn fx(v: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(v)
}

pub fn harness(app: App) -> Harness<'static, App> {
    Harness::builder()
        .with_size((1280.0, 800.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), app)
}

pub fn loaded() -> Harness<'static, App> {
    let mut h = harness(App::new(Some(fx("multi_commit"))));
    let t = Instant::now();
    while h.state().is_loading() {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
        assert!(t.elapsed() < Duration::from_secs(20), "case did not load");
    }
    h.run();
    h
}

#[test]
fn empty_state_shows_open_hint() {
    let mut h = harness(App::new(None));
    h.run();
    h.get_by_label("Open mpenginedb.db or a Scans folder");
    assert!(h.query_by_label_contains("ONE VSS shadow copy").is_some());
}

#[test]
fn loads_fixture_and_shows_tabs() {
    let h = loaded();
    assert!(h.state().case.is_some(), "error: {:?}", h.state().error);
    for t in ["Findings", "Timeline", "Files & processes", "Evidence"] {
        h.get_by_label(t);
    }
    assert_eq!(
        h.state().tab,
        Tab::Findings,
        "opens on the Findings home page"
    );
    assert!(h.query_by_label_contains("Needs attention").is_some());
}

#[test]
fn ctrl4_switches_to_evidence() {
    let mut h = loaded();
    h.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::Num4);
    h.run();
    assert_eq!(h.state().tab, Tab::Evidence);
}

#[test]
fn finding_card_opens_its_list() {
    let mut h = loaded();
    h.get_all_by_label_contains("Unsigned programs run outside system folders")
        .next()
        .unwrap()
        .click();
    h.run();
    assert_eq!(h.state().tab, Tab::Timeline);
    assert_eq!(
        h.state().timeline.title.as_deref(),
        Some("Unsigned programs run outside system folders")
    );
    let c = h.state().case.clone().unwrap();
    let ids = h.state().timeline.ids.clone();
    assert_eq!(ids.len(), 2);
    assert!(
        ids.iter()
            .all(|&i| c.events[i as usize].kind == mpdbx::model::EventKind::NoCertExec)
    );
}

#[test]
fn typing_a_search_on_findings_shows_results() {
    let mut h = loaded();
    h.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::F);
    h.run();
    h.event(egui::Event::Text("exe".into()));
    h.run();
    assert_eq!(h.state().search, "exe");
    assert_eq!(h.state().tab, Tab::Timeline);
}

#[test]
fn routine_events_hidden_until_asked() {
    let mut h = loaded();
    h.state_mut().tab = Tab::Timeline;
    h.run();
    let c = h.state().case.clone().unwrap();
    let routine = |ids: &[u32]| {
        ids.iter()
            .filter(|&&i| mpdbx::ui::timeline::ROUTINE.contains(&c.events[i as usize].kind))
            .count()
    };
    assert_eq!(routine(&h.state().timeline.ids), 0);
    let shown = h.state().timeline.ids.len();
    h.get_by_label("Show routine events").click();
    h.run();
    assert!(routine(&h.state().timeline.ids) > 0);
    assert_eq!(
        h.state().timeline.ids.len(),
        c.events.len().min(h.state().timeline.ids.len())
    );
    assert!(h.state().timeline.ids.len() > shown);
}

#[test]
fn wrong_key_prompts_for_dll() {
    let d = std::env::temp_dir().join(format!("mpdbx_ui_wrongkey_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let mut db = std::fs::read(fx("nowal").join("mpenginedb.db")).unwrap();
    db[0] ^= 0xFF;
    std::fs::write(d.join("mpenginedb.db"), db).unwrap();
    let mut h = harness(App::new(Some(d)));
    let t = Instant::now();
    while h.state().is_loading() {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
        assert!(t.elapsed() < Duration::from_secs(20));
    }
    h.run();
    assert!(
        h.query_all_by_label_contains("mpengine.dll").count() >= 2,
        "message and Choose button"
    );
}

#[test]
fn second_open_while_loading_is_ignored() {
    let mut app = App::new(Some(fx("multi_commit")));
    assert!(app.is_loading());
    let before = app.last_request.clone().unwrap().path;
    app.open_path(fx("nowal"));
    assert_eq!(app.last_request.unwrap().path, before);
}

#[test]
fn ctrl_f_focuses_search() {
    let mut h = loaded();
    h.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::F);
    h.run();
    let focused = h.ctx.memory(|m| m.focused());
    assert_eq!(focused, Some(egui::Id::unique(mpdbx::ui::app::SEARCH_ID)));
}

#[test]
fn index_is_built_off_the_ui_thread() {
    let h = loaded();
    let c = h.state().case.clone().unwrap();
    assert_eq!(
        c.index.len(),
        c.events.len(),
        "Case carries the search index built by the worker"
    );
}

#[test]
fn failed_reopen_keeps_tz_consistent_with_case() {
    let mut h = loaded();
    h.state_mut().last_request.as_mut().unwrap().path = fx("does_not_exist");
    h.state_mut().set_tz_text("+05:30");
    let t = Instant::now();
    while h.state().is_loading() {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
        assert!(t.elapsed() < Duration::from_secs(20));
    }
    h.run();
    let app = h.state();
    assert_eq!(
        app.tz,
        app.case.as_ref().unwrap().opts.tz,
        "displayed zone must match the loaded case"
    );
    assert_eq!(app.tz_text, "Z");
}

#[test]
fn theme_preference_follows_app_setting() {
    let mut h = loaded();
    h.state_mut().dark = false;
    h.run();
    assert_eq!(
        h.ctx.options(|o| o.theme_preference),
        egui::ThemePreference::Light
    );
}
