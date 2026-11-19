//! Artifacts and Evidence tabs (headless).
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use mpdbx::model::{Node, Strength};
use mpdbx::ui::app::{App, Tab};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn wait(h: &mut Harness<'static, App>) {
    let t = Instant::now();
    while h.state().is_loading() {
        h.step();
        std::thread::sleep(Duration::from_millis(10));
        assert!(t.elapsed() < Duration::from_secs(20));
    }
    h.run();
}

fn loaded(tab: Tab) -> Harness<'static, App> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit");
    let mut h = Harness::builder().with_size((1600.0, 1000.0)).build_ui_state(|ui, app: &mut App| app.show(ui), App::new(Some(p)));
    wait(&mut h);
    h.state_mut().tab = tab;
    h.run();
    h
}

#[test]
fn artifacts_lists_all_views_and_raw_tables() {
    let h = loaded(Tab::Artifacts);
    for v in mpdbx::views::VIEW_NAMES.iter().filter(|v| **v != "Timeline") {
        assert!(h.query_by_label_contains(&format!("{v}  (")).is_some(), "{v}");
    }
    let c = h.state().case.clone().unwrap();
    for t in &c.raw {
        assert!(h.query_by_label_contains(&format!("{}  (", t.name)).is_some(), "raw {}", t.name);
    }
}

#[test]
fn raw_table_shows_decoded_filetime() {
    let mut h = loaded(Tab::Artifacts);
    h.get_by_label_contains("BackupProcessInfo  (").click();
    h.run();
    let v = h.state().artifacts.view.clone().unwrap();
    let col = v.columns.iter().position(|x| x == "FirstStartTime").unwrap();
    assert!(v.rows.iter().any(|r| r.cells[col].ends_with('Z')));
    assert!(h.query_all_by_label_contains("2026-10-19").count() >= 1);
}

#[test]
fn artifact_row_click_selects_its_node() {
    let mut h = loaded(Tab::Artifacts);
    h.get_by_label_contains("Locations  (").click();
    h.run();
    let first = h.state().artifacts.view.clone().unwrap().rows[h.state().artifacts.rows[0]].cells[0].clone();
    h.get_all_by_label(&first).next().unwrap().click();
    h.run_steps(6);
    assert!(matches!(h.state().selected, Some(Node::Location(_))));
}

#[test]
fn evidence_shows_wal_report() {
    let h = loaded(Tab::Evidence);
    assert!(h.query_by_label_contains("frames total / validated / applied").is_some());
    assert!(h.query_by_label_contains("commits applied").is_some());
    let sha = h.state().case.as_ref().unwrap().evidence.inputs[0].sha256.clone();
    h.get_by_label(&sha);
}

#[test]
fn confirm_volmap_reloads_with_assertion() {
    let mut h = loaded(Tab::Evidence);
    h.state_mut().confirm_volume(3, 'C');
    wait(&mut h);
    let c = h.state().case.clone().unwrap();
    assert_eq!(c.opts.volmap_assert, vec![(3, 'C')]);
    assert_eq!(c.evidence.volmap.map.get(&3).map(|m| (m.0, m.1)), Some(('C', Strength::Exact)));
}
