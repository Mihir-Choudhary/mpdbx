//! Artifacts tab: every typed view and every raw table in the shared grid (spec §8.2).
use crate::case::Case;
use crate::model::{DbStatus, Node, Prov};
use crate::ui::grid::{ColSpec, GridEvent, GridState, RowStyle, grid};
use crate::ui::theme::{Comp, Semantic};
use crate::views::{VIEW_NAMES, View, build_view, raw_view};
use eframe::egui::{self, RichText};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Typed(String),
    Raw(String),
}

pub struct ArtifactsState {
    pub current: Source,
    pub view: Option<View>,
    /// Row indices of `view` matching the search, in display order.
    pub rows: Vec<usize>,
    pub grid: GridState,
    built_for: Option<(usize, Source)>,
    filtered_for: Option<String>,
    counts: Vec<(String, usize)>,
    counts_for: usize,
}

impl Default for ArtifactsState {
    fn default() -> Self {
        ArtifactsState {
            current: Source::Typed("No-cert executions".into()),
            view: None,
            rows: Vec::new(),
            grid: GridState::default(),
            built_for: None,
            filtered_for: None,
            counts: Vec::new(),
            counts_for: 0,
        }
    }
}

fn mono(title: &str) -> bool {
    let t = title.to_ascii_lowercase();
    ["time", "inserted", "path", "file", "sha", "md5", "fileref", "key", "guid", "start", "end", "hashed", "logon", "expires", "directory"]
        .iter()
        .any(|k| t.contains(k))
}

impl ArtifactsState {
    fn refresh(&mut self, c: &Arc<Case>, search: &str) {
        let ptr = Arc::as_ptr(c) as usize;
        if self.counts_for != ptr {
            self.counts = VIEW_NAMES.iter().filter(|n| **n != "Timeline").map(|n| (n.to_string(), build_view(c, n, None).rows.len())).collect();
            self.counts_for = ptr;
            self.built_for = None;
        }
        let key = (ptr, self.current.clone());
        if self.built_for.as_ref() != Some(&key) {
            self.view = Some(match &self.current {
                Source::Typed(n) => build_view(c, n, None),
                Source::Raw(t) => raw_view(c, t),
            });
            self.built_for = Some(key);
            self.filtered_for = None;
            self.grid = GridState::default();
        }
        if self.filtered_for.as_deref() != Some(search) {
            let needle = search.trim().to_lowercase();
            let v = self.view.as_ref().unwrap();
            self.rows = (0..v.rows.len())
                .filter(|&i| needle.is_empty() || v.rows[i].cells.iter().any(|c| c.to_lowercase().contains(&needle)))
                .collect();
            self.sort();
            self.filtered_for = Some(search.to_string());
        }
    }

    fn sort(&mut self) {
        let (Some((col, desc)), Some(v)) = (self.grid.sort, self.view.as_ref()) else { return };
        self.rows.sort_by(|&a, &b| {
            let o = v.rows[a].cells.get(col).cmp(&v.rows[b].cells.get(col));
            if desc { o.reverse() } else { o }
        });
    }
}

fn list_entry(ui: &mut egui::Ui, selected: bool, label: String) -> bool {
    ui.add(egui::Button::selectable(selected, label).truncate()).clicked()
}

pub fn show(ui: &mut egui::Ui, c: &Arc<Case>, search: &str, st: &mut ArtifactsState, th: &Semantic, comp: &Comp, selected: &mut Option<Node>) {
    st.refresh(c, search);
    egui::Panel::left("artifact_list").default_size(250.0).resizable(true).show(ui, |ui| {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.label(RichText::new("Views").strong());
            let mut pick = None;
            for (n, k) in &st.counts {
                if list_entry(ui, st.current == Source::Typed(n.clone()), format!("{n}  ({k})")) {
                    pick = Some(Source::Typed(n.clone()));
                }
            }
            ui.add_space(8.0);
            ui.label(RichText::new("Raw tables").strong());
            ui.label(RichText::new("every table, decoded where a decoder applies").small().color(th.text_muted));
            for t in &c.raw {
                let mark = if t.readable { "" } else { " ⚠" };
                if list_entry(ui, st.current == Source::Raw(t.name.clone()), format!("{}  ({}){mark}", t.name, t.rows.len())) {
                    pick = Some(Source::Raw(t.name.clone()));
                }
            }
            if let Some(p) = pick {
                st.current = p;
                st.refresh(c, search);
            }
        });
    });
    egui::CentralPanel::default().show(ui, |ui| {
        let Some(v) = st.view.clone() else { return };
        ui.horizontal(|ui| {
            ui.label(RichText::new(&v.name).strong().size(15.0));
            ui.label(RichText::new(format!("{} of {} rows", st.rows.len(), v.rows.len())).color(th.text_muted));
            if !search.trim().is_empty() {
                ui.label(RichText::new(format!("filtered by \"{}\"", search.trim())).color(th.text_muted));
            }
        });
        // width: full FILETIME display for time-like columns; the longest of title/sample values (capped) otherwise
        let cols: Vec<ColSpec> = v
            .columns
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let sample = v.rows.iter().take(200).filter_map(|r| r.cells.get(i)).map(|c| c.chars().count()).max().unwrap_or(0);
                let tl = t.to_ascii_lowercase();
                let timeish = tl.contains("time") || tl.ends_with("ts") || tl.contains("date") || ["inserted", "start", "end", "hashed", "logon", "expires"].contains(&tl.as_str());
                let w = if timeish { 215.0 } else { (sample.max(t.len()) as f32 * 7.6 + 16.0).clamp(70.0, 360.0) };
                ColSpec::new(t, w, mono(t))
            })
            .collect();
        let rows = st.rows.clone();
        let sel = *selected;
        let cell = |r: usize, col: usize| v.rows[rows[r]].cells.get(col).cloned().unwrap_or_default();
        let style = |r: usize| {
            let row = &v.rows[rows[r]];
            let tint = match &row.prov {
                Some(Prov::Db { status: DbStatus::WalOnly, .. }) => Some(th.walonly),
                Some(Prov::Db { status: DbStatus::WalModified, .. }) => Some(th.walmod),
                Some(Prov::Db { status: DbStatus::RemovedByWal, .. }) => Some(th.removed),
                _ => None,
            };
            RowStyle { tint, flag: false, selected: row.node.is_some() && row.node == sel }
        };
        let evs = grid(ui, "artifact_grid", &cols, rows.len(), &mut st.grid, th, comp, &cell, &style);
        for e in evs {
            match e {
                GridEvent::Sorted => st.sort(),
                GridEvent::Click(r) | GridEvent::DoubleClick(r) => {
                    if let Some(n) = st.rows.get(r).and_then(|&i| v.rows[i].node) {
                        *selected = Some(n);
                    }
                }
            }
        }
    });
}
