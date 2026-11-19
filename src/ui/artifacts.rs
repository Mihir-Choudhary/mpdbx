//! Artifacts tab: every typed view and every raw table in the shared grid (spec §8.2).
use crate::case::Case;
use crate::decode::time::Tz;
use crate::model::{DbStatus, Node, Prov};
use crate::query::{Query, Term, apply, parse};
use crate::ui::grid::{ColSpec, GridEvent, GridState, RowStyle, grid};
use crate::ui::theme::{Comp, Semantic};
use crate::views::{VIEW_NAMES, View, build_view, raw_view};
use eframe::egui::{self, RichText};
use std::collections::HashSet;
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
    [
        "time",
        "inserted",
        "path",
        "file",
        "sha",
        "md5",
        "fileref",
        "key",
        "guid",
        "start",
        "end",
        "hashed",
        "logon",
        "expires",
        "directory",
    ]
    .iter()
    .any(|k| t.contains(k))
}

impl ArtifactsState {
    pub fn refresh(&mut self, c: &Arc<Case>, search: &str, tz: Tz) {
        let ptr = Arc::as_ptr(c) as usize;
        if self.counts_for != ptr {
            self.counts = VIEW_NAMES
                .iter()
                .filter(|n| **n != "Timeline")
                .map(|n| (n.to_string(), build_view(c, n, None).rows.len()))
                .collect();
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
            let v = self.view.as_ref().unwrap();
            let f = RowFilter::new(c, search, tz);
            self.rows = (0..v.rows.len())
                .filter(|&i| f.keeps(c, v.rows[i].node, &v.rows[i].cells))
                .collect();
            self.sort();
            self.filtered_for = Some(search.to_string());
        }
    }

    fn sort(&mut self) {
        let (Some((col, desc)), Some(v)) = (self.grid.sort, self.view.as_ref()) else {
            return;
        };
        self.rows.sort_by(|&a, &b| {
            let o = cell_cmp(v.rows[a].cells.get(col), v.rows[b].cells.get(col));
            if desc { o.reverse() } else { o }
        });
    }
}

/// Numbers compare as numbers ("10" after "2") and sort before everything else; the rest compares as text.
/// Keeping the two groups apart makes this a total order (mixing numeric and text comparisons would not be).
pub fn cell_cmp(a: Option<&String>, b: Option<&String>) -> std::cmp::Ordering {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let num = |s: Option<&String>| {
        s.and_then(|x| x.trim().parse::<f64>().ok())
            .filter(|f| f.is_finite())
    };
    match (num(a), num(b)) {
        (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(Equal),
        (Some(_), None) => Less,
        (None, Some(_)) => Greater,
        (None, None) => a.cmp(&b),
    }
}

/// A search term that can also be judged against the text shown in a row's cells.
enum CellTerm {
    Text(String),
    Regex(regex_lite::Regex),
}

impl CellTerm {
    fn hit(&self, cells: &[String]) -> bool {
        match self {
            CellTerm::Text(t) => cells.iter().any(|x| x.to_lowercase().contains(t.as_str())),
            CellTerm::Regex(r) => cells.iter().any(|x| r.is_match(x)),
        }
    }
}

/// The top-bar search applied to a view.
/// - A query with structured terms (path:, sha256:, type:, …) is judged on the row's events exactly as the Timeline
///   does; rows without a model node cannot satisfy it.
/// - A free-text / regex query is judged term by term on the row's events and on the text shown in its cells, so a
///   value displayed only in the grid ("WAL-only", "heuristic", …) is found too.
///
/// An unparsable search falls back to a plain substring over the cells.
pub struct RowFilter {
    /// Events satisfying the whole query (structured queries only).
    events: Option<HashSet<u32>>,
    /// Free-text / regex terms with the events each one matches on its own.
    cell_terms: Vec<(bool, CellTerm, HashSet<u32>)>,
    structured: bool,
    active: bool,
}

impl RowFilter {
    pub fn new(c: &Case, search: &str, tz: Tz) -> RowFilter {
        let s = search.trim();
        let none = RowFilter {
            events: None,
            cell_terms: vec![],
            structured: false,
            active: false,
        };
        if s.is_empty() {
            return none;
        }
        match parse(s, tz) {
            Ok(terms) if !terms.is_empty() => {
                let structured = terms
                    .iter()
                    .any(|(_, t)| !matches!(t, Term::Text(_) | Term::Regex(_)));
                if structured {
                    let q = Query {
                        terms,
                        ..Default::default()
                    };
                    let ids: HashSet<u32> = apply(c, &c.index, &q).into_iter().collect();
                    return RowFilter {
                        events: Some(ids),
                        active: true,
                        structured,
                        ..none
                    };
                }
                let cell_terms = terms
                    .into_iter()
                    .map(|(neg, t)| {
                        let q = Query {
                            terms: vec![(false, t.clone())],
                            ..Default::default()
                        };
                        let ids: HashSet<u32> = apply(c, &c.index, &q).into_iter().collect();
                        let ct = match t {
                            Term::Text(x) => CellTerm::Text(x.to_lowercase()),
                            Term::Regex(r) => CellTerm::Regex(r),
                            _ => unreachable!("structured terms handled above"),
                        };
                        (neg, ct, ids)
                    })
                    .collect();
                RowFilter {
                    cell_terms,
                    active: true,
                    ..none
                }
            }
            _ => RowFilter {
                cell_terms: vec![(false, CellTerm::Text(s.to_lowercase()), HashSet::new())],
                active: true,
                ..none
            },
        }
    }

    /// The events a row's node stands for. A location also stands for the hashed contents an MFT CSV placed there
    /// (rule 3), so an MFT-only location is reached through its FileHashes events.
    fn node_events(c: &Case, n: Node) -> Vec<u32> {
        match n {
            Node::Event(e) => vec![e],
            Node::Location(l) => {
                let mut v = c
                    .locations
                    .get(l as usize)
                    .map(|x| x.events.clone())
                    .unwrap_or_default();
                for &i in c.links_by_node.get(&n).into_iter().flatten() {
                    let k = &c.links[i as usize];
                    if k.rule != "3" {
                        continue;
                    }
                    if let (Node::Content(x), _) | (_, Node::Content(x)) = (k.a, k.b) {
                        v.extend(c.contents.get(x as usize).map(|x| x.event));
                    }
                }
                v
            }
            Node::Run(r) => c
                .runs
                .get(r as usize)
                .map(|x| {
                    x.obs
                        .iter()
                        .filter_map(|&o| c.obs.get(o as usize))
                        .map(|o| o.event)
                        .collect()
                })
                .unwrap_or_default(),
            Node::Content(k) => c
                .contents
                .get(k as usize)
                .map(|x| vec![x.event])
                .unwrap_or_default(),
            Node::Store(s) => c
                .events
                .iter()
                .filter(|e| e.store == Some(s))
                .map(|e| e.id)
                .collect(),
        }
    }

    pub fn keeps(&self, c: &Case, node: Option<Node>, cells: &[String]) -> bool {
        if !self.active {
            return true;
        }
        let evs = node.map(|n| Self::node_events(c, n)).unwrap_or_default();
        if self.structured {
            let ids = self.events.as_ref().expect("structured filter has events");
            return evs.iter().any(|e| ids.contains(e));
        }
        self.cell_terms
            .iter()
            .all(|(neg, t, ids)| (t.hit(cells) || evs.iter().any(|e| ids.contains(e))) != *neg)
    }
}

fn list_entry(ui: &mut egui::Ui, selected: bool, label: String) -> bool {
    ui.add(egui::Button::selectable(selected, label).truncate())
        .clicked()
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut egui::Ui,
    c: &Arc<Case>,
    search: &str,
    tz: Tz,
    st: &mut ArtifactsState,
    th: &Semantic,
    comp: &Comp,
    selected: &mut Option<Node>,
) {
    st.refresh(c, search, tz);
    egui::Panel::left("artifact_list")
        .default_size(250.0)
        .resizable(true)
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.label(RichText::new("Views").strong());
                    let mut pick = None;
                    for (n, k) in &st.counts {
                        if list_entry(
                            ui,
                            st.current == Source::Typed(n.clone()),
                            format!("{n}  ({k})"),
                        ) {
                            pick = Some(Source::Typed(n.clone()));
                        }
                    }
                    ui.add_space(8.0);
                    ui.label(RichText::new("Raw tables").strong());
                    ui.label(
                        RichText::new("every table, decoded where a decoder applies")
                            .small()
                            .color(th.text_muted),
                    );
                    for t in &c.raw {
                        let mark = if t.readable { "" } else { " ⚠" };
                        if list_entry(
                            ui,
                            st.current == Source::Raw(t.name.clone()),
                            format!("{}  ({}){mark}", t.name, t.rows.len()),
                        ) {
                            pick = Some(Source::Raw(t.name.clone()));
                        }
                    }
                    if let Some(p) = pick {
                        st.current = p;
                        st.refresh(c, search, tz);
                    }
                });
        });
    egui::CentralPanel::default().show(ui, |ui| {
        let Some(v) = st.view.clone() else { return };
        ui.horizontal(|ui| {
            ui.label(RichText::new(&v.name).strong().size(15.0));
            ui.label(
                RichText::new(format!("{} of {} rows", st.rows.len(), v.rows.len()))
                    .color(th.text_muted),
            );
            if !search.trim().is_empty() {
                ui.label(
                    RichText::new(format!("filtered by \"{}\"", search.trim()))
                        .color(th.text_muted),
                );
            }
        });
        // width: full FILETIME display for time-like columns; the longest of title/sample values (capped) otherwise
        let cols: Vec<ColSpec> = v
            .columns
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let sample = v
                    .rows
                    .iter()
                    .take(200)
                    .filter_map(|r| r.cells.get(i))
                    .map(|c| c.chars().count())
                    .max()
                    .unwrap_or(0);
                let tl = t.to_ascii_lowercase();
                let timeish = tl.contains("time")
                    || tl.ends_with("ts")
                    || tl.contains("date")
                    || ["inserted", "start", "end", "hashed", "logon", "expires"]
                        .contains(&tl.as_str());
                let w = if timeish {
                    215.0
                } else {
                    (sample.max(t.len()) as f32 * 7.6 + 16.0).clamp(70.0, 360.0)
                };
                ColSpec::new(t, w, mono(t))
            })
            .collect();
        let rows = st.rows.clone();
        let sel = *selected;
        let cell =
            |r: usize, col: usize| v.rows[rows[r]].cells.get(col).cloned().unwrap_or_default();
        let style = |r: usize| {
            let row = &v.rows[rows[r]];
            let tint = match &row.prov {
                Some(Prov::Db {
                    status: DbStatus::WalOnly,
                    ..
                }) => Some(th.walonly),
                Some(Prov::Db {
                    status: DbStatus::WalModified,
                    ..
                }) => Some(th.walmod),
                Some(Prov::Db {
                    status: DbStatus::RemovedByWal,
                    ..
                }) => Some(th.removed),
                _ => None,
            };
            RowStyle {
                tint,
                flag: false,
                selected: row.node.is_some() && row.node == sel,
            }
        };
        let evs = grid(
            ui,
            "artifact_grid",
            &cols,
            rows.len(),
            &mut st.grid,
            th,
            comp,
            &cell,
            &style,
        );
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
