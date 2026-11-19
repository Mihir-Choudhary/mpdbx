//! Timeline tab: grid, facets, search, sorting (headless).
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use mpdbx::model::EventKind;
use mpdbx::ui::app::App;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn loaded() -> Harness<'static, App> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit");
    let mut h = Harness::builder()
        .with_size((1440.0, 900.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), App::new(Some(p)));
    let t = Instant::now();
    while h.state().is_loading() {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
        assert!(t.elapsed() < Duration::from_secs(20));
    }
    // these tests exercise the filter machinery over every event
    h.state_mut().tab = mpdbx::ui::app::Tab::Timeline;
    h.state_mut().timeline.show_routine = true;
    h.state_mut().timeline.mark_dirty();
    h.run();
    h
}

fn rows(h: &Harness<'static, App>) -> usize {
    h.state().timeline.ids.len()
}

#[test]
fn timeline_lists_every_event_initially() {
    let h = loaded();
    assert_eq!(rows(&h), h.state().case.as_ref().unwrap().events.len());
    let n = h.state().case.as_ref().unwrap().events.len();
    h.get_by_label(&format!("{n} events"));
    assert_eq!(h.state().timeline.title.as_deref(), Some("All activity"));
}

#[test]
fn facet_uncheck_hides_kind() {
    let mut h = loaded();
    let before = rows(&h);
    h.get_by_label("▸ More filters").click();
    h.run();
    h.get_by_label("Module first load (1)").click();
    h.run();
    assert_eq!(rows(&h), before - 1);
    let c = h.state().case.clone().unwrap();
    assert!(
        h.state()
            .timeline
            .ids
            .iter()
            .all(|&i| c.events[i as usize].kind != EventKind::ModuleFirstLoad)
    );
}

#[test]
fn search_filters_rows() {
    let mut h = loaded();
    h.state_mut().search = "nocert:yes type:nocert".into();
    h.run();
    assert_eq!(rows(&h), 2);
}

#[test]
fn bad_query_shows_error_keeps_rows() {
    let mut h = loaded();
    h.state_mut().search = "type:nocert".into();
    h.run();
    h.state_mut().search = "after:notadate".into();
    h.run();
    assert_eq!(rows(&h), 2, "last valid query stays applied");
    assert!(h.query_by_label_contains("not a date").is_some());
}

#[test]
fn sort_by_time_toggles_descending() {
    let mut h = loaded();
    h.get_by_label("Time ▲").click();
    h.run();
    let c = h.state().case.clone().unwrap();
    let times: Vec<Option<u64>> = h
        .state()
        .timeline
        .ids
        .iter()
        .map(|&i| c.events[i as usize].time)
        .filter(|t| t.is_some())
        .collect();
    assert!(
        times.windows(2).all(|w| w[0] >= w[1]),
        "descending after one click"
    );
}

#[test]
fn red_flags_preset_shows_only_flagged() {
    let mut h = loaded();
    h.get_by_label("Red flags").click();
    h.run();
    let c = h.state().case.clone().unwrap();
    assert!(
        rows(&h) > 0
            && h.state()
                .timeline
                .ids
                .iter()
                .all(|&i| c.events[i as usize].flag)
    );
    h.get_by_label("Show all activity").click();
    h.run();
    assert_eq!(rows(&h), c.events.len());
}

#[test]
fn clicking_a_row_selects_its_event() {
    let mut h = loaded();
    h.get_all_by_label("LowFi signature hit").next().unwrap().click();
    h.run();
    let c = h.state().case.clone().unwrap();
    let sel = h.state().selected.unwrap();
    assert!(
        matches!(sel, mpdbx::model::Node::Event(i) if c.events[i as usize].kind == EventKind::LowFiHit)
    );
}
