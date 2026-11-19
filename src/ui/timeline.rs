//! Timeline tab: brushable histogram, facet sidebar with presets, virtualised grid (spec §8.2).
use crate::case::Case;
use crate::decode::time::{Tz, fmt_ft};
use crate::model::{DbStatus, EventKind, LocClass, Node, Strength};
use crate::query::{
    FacetCounts, FacetSel, Histogram, QErr, Query, Special, TimeSel, apply, facet_counts_q,
    histogram, parse, source_table,
};
use crate::ui::grid::{ColSpec, GridEvent, GridState, RowStyle, grid};
use crate::ui::theme::{Comp, Semantic};
use crate::views::{class_label, kind_label, status_label, strength_label};
use eframe::egui::{self, RichText, Sense};
use std::collections::HashSet;
use std::sync::Arc;

const TIME: usize = 0;
const COLS: [(&str, f32, bool); 6] = [
    ("Time", 205.0, true),
    ("What", 165.0, false),
    ("Name", 190.0, true),
    ("Details", 280.0, false),
    ("Path", 300.0, true),
    ("Source", 95.0, false),
];

/// Event types hidden unless asked for: high-volume background records that rarely answer a first question.
pub const ROUTINE: [EventKind; 5] = [
    EventKind::ModuleFirstLoad,
    EventKind::FileHashed,
    EventKind::StoreExpiry,
    EventKind::OfnProcessed,
    EventKind::FileContext,
];

/// Name shown for the quick views (title, hover text, filters).
pub fn quick_views() -> Vec<(&'static str, &'static str, FacetSel)> {
    use EventKind::*;
    let k = |v: &[EventKind]| Some(v.iter().copied().collect::<HashSet<_>>());
    vec![
        (
            "All activity",
            "everything except routine background records (see 'Show routine events')",
            FacetSel::default(),
        ),
        (
            "Red flags",
            "unsigned runs outside system folders, renamed executables, threats, RDP logons, WAL-only/removed rows",
            FacetSel {
                flagged_only: true,
                ..Default::default()
            },
        ),
        (
            "Programs run",
            "process starts and first runs of unsigned binaries",
            FacetSel {
                kinds: k(&[
                    ProcessFirstStart,
                    NoCertExec,
                    StoreProcessStart,
                    AmsiProcessStart,
                ]),
                ..Default::default()
            },
        ),
        (
            "Unsigned programs",
            "first runs of binaries with no embedded certificate",
            FacetSel {
                kinds: k(&[NoCertExec]),
                ..Default::default()
            },
        ),
        (
            "Renamed executables",
            "OriginalFileName of an executable differs from its file name (any folder)",
            FacetSel {
                special: Some(Special::RenamedExe),
                ..Default::default()
            },
        ),
        (
            "File scans",
            "files a process created/opened, from the scan cache",
            FacetSel {
                kinds: k(&[FileScan, AmsiScan]),
                ..Default::default()
            },
        ),
        (
            "Detections & signatures",
            "threats from the recent-threats queue and low-fidelity signature hits",
            FacetSel {
                special: Some(Special::Detections),
                ..Default::default()
            },
        ),
        (
            "Found only in the WAL",
            "rows that exist only in, were changed by, or were removed by the WAL",
            FacetSel {
                status: Some(
                    [
                        Some(DbStatus::WalOnly),
                        Some(DbStatus::WalModified),
                        Some(DbStatus::RemovedByWal),
                    ]
                    .into(),
                ),
                ..Default::default()
            },
        ),
    ]
}

#[derive(Default)]
pub struct TimelineState {
    /// Visible event ids in display order.
    pub ids: Vec<u32>,
    /// Facet counts over the events matching the search and window (before facets).
    pub counts: FacetCounts,
    pub query: Query,
    pub error: Option<QErr>,
    pub grid: GridState,
    pub hist: Histogram,
    case_ptr: usize,
    last_search: Option<(String, Tz)>,
    dirty: bool,
    brush: Option<(f32, f32)>,
    kinds_present: Vec<EventKind>,
    tables_present: Vec<String>,
    sorted_once: bool,
    /// Title of the list being shown (quick view or Findings card); None = custom filters.
    pub title: Option<String>,
    /// Include ROUTINE event types when no event-type filter is set.
    pub show_routine: bool,
    show_more: bool,
}

impl TimelineState {
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// "Same location" / "Same process run" from the inspector: every event at that location or in that run, so
    /// filters left over from a quick view or card (event types, red flags, WAL status, …) are dropped.
    pub fn pivot_to(&mut self, location: Option<u32>, run: Option<u32>) {
        self.query.facets = FacetSel {
            time: self.query.facets.time,
            ..Default::default()
        };
        self.set_pivot(location, run);
    }

    /// Set or clear the exact location / process-run filter, keeping the other filters.
    pub fn set_pivot(&mut self, location: Option<u32>, run: Option<u32>) {
        self.query.facets.location = location;
        self.query.facets.run = run;
        if location.is_some() || run.is_some() {
            self.title = None;
            self.query.facets.only = None;
        }
        self.dirty = true;
    }

    /// Open a named list (Findings card or quick view): replaces filters and time window.
    pub fn open_list(&mut self, title: &str, facets: FacetSel) {
        self.query.facets = facets;
        self.query.window = None;
        self.title = Some(title.to_string());
        self.dirty = true;
    }

    /// The query actually run: routine types are dropped from broad lists only. Any filter that picks out particular
    /// events (types, a search, a card, a quick-view predicate, red flags, WAL status, source table, a location or
    /// process run, no-cert locations) shows its routine matches too.
    pub fn effective_query(&self) -> Query {
        let mut q = self.query.clone();
        let f = &q.facets;
        let targeted = f.kinds.is_some()
            || f.only.is_some()
            || f.special.is_some()
            || f.flagged_only
            || f.status.is_some()
            || f.tables.is_some()
            || f.location.is_some()
            || f.run.is_some()
            || f.nocert_only
            || !q.terms.is_empty();
        if !self.show_routine && !targeted {
            q.facets.kinds = Some(
                self.kinds_present
                    .iter()
                    .copied()
                    .filter(|k| !ROUTINE.contains(k))
                    .collect(),
            );
        }
        q
    }

    /// Apply a pivot from the inspector.
    pub fn set_window(&mut self, w: Option<(u64, u64)>) {
        self.query.window = w;
        self.dirty = true;
    }

    /// Reset per-case state when a different case is shown (call before `open_list` for a new case).
    pub fn bind(&mut self, case: &Arc<Case>) {
        let ptr = Arc::as_ptr(case) as usize;
        if ptr != self.case_ptr {
            self.case_ptr = ptr;
            self.query = Query::default();
            self.title = Some("All activity".into());
            self.last_search = None;
            let mut k: Vec<EventKind> = Vec::new();
            for e in &case.events {
                if !k.contains(&e.kind) {
                    k.push(e.kind);
                }
            }
            self.kinds_present = k;
            let mut t: Vec<String> = case.events.iter().map(source_table).collect();
            t.sort();
            t.dedup();
            self.tables_present = t;
            if !self.sorted_once {
                self.grid.sort = Some((TIME, false));
                self.sorted_once = true;
            }
            self.dirty = true;
        }
    }

    /// Bring `ids` up to date for this case, search and zone (used before exporting from another tab).
    pub fn ensure(&mut self, case: &Arc<Case>, search: &str, tz: Tz) {
        self.refresh(case, search, tz);
    }

    fn refresh(&mut self, case: &Arc<Case>, search: &str, tz: Tz) {
        self.bind(case);
        if self.last_search.as_ref() != Some(&(search.to_string(), tz)) {
            self.last_search = Some((search.to_string(), tz));
            match parse(search, tz) {
                Ok(t) => {
                    self.query.terms = t;
                    self.error = None;
                }
                Err(e) => self.error = Some(e),
            }
            self.dirty = true;
        }
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let idx = &case.index;
        let q = self.effective_query();
        self.counts = facet_counts_q(case, idx, &q);
        let mut no_window = q.clone();
        no_window.window = None;
        self.hist = histogram(case, &apply(case, idx, &no_window), 240);
        let mut ids = apply(case, idx, &q);
        sort_ids(case, &mut ids, self.grid.sort);
        self.ids = ids;
    }
}

/// Summary without what the What and Name columns already say ("LowFi signature hit: x.exe" → "").
pub fn details(e: &crate::model::Event, name: &str) -> String {
    let s = e.summary.as_str();
    let rest = s
        .strip_prefix(kind_label(e.kind))
        .and_then(|r| r.strip_prefix(": "))
        .unwrap_or(s);
    if !name.is_empty() && rest.eq_ignore_ascii_case(name) {
        String::new()
    } else {
        rest.to_string()
    }
}

/// Last path component (file name) of a displayed path.
pub fn leaf(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Stable sort by the displayed value of a column (ties keep their current order; untimed rows stay last).
pub(crate) fn sort_ids(case: &Case, ids: &mut [u32], sort: Option<(usize, bool)>) {
    let Some((col, desc)) = sort else { return };
    let path = |i: u32| {
        case.events[i as usize]
            .location
            .and_then(|l| case.locations.get(l as usize))
            .map(|l| l.spellings[0].as_str())
            .unwrap_or("")
    };
    match col {
        0 => ids.sort_by(|&a, &b| {
            let (ta, tb) = (case.events[a as usize].time, case.events[b as usize].time);
            match (ta, tb) {
                (Some(x), Some(y)) => {
                    if desc {
                        y.cmp(&x)
                    } else {
                        x.cmp(&y)
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        }),
        _ => {
            ids.sort_by(|&a, &b| {
                let (ea, eb) = (&case.events[a as usize], &case.events[b as usize]);
                let o = match col {
                    1 => kind_label(ea.kind).cmp(kind_label(eb.kind)),
                    2 => leaf(path(a))
                        .to_lowercase()
                        .cmp(&leaf(path(b)).to_lowercase()),
                    3 => details(ea, leaf(path(a))).cmp(&details(eb, leaf(path(b)))),
                    5 => crate::views::prov_cols(&ea.prov)
                        .2
                        .cmp(&crate::views::prov_cols(&eb.prov).2),
                    _ => path(a).cmp(path(b)),
                };
                if desc { o.reverse() } else { o }
            });
        }
    }
}

/// Checkbox group over a `None = all` facet. Unchecking the last value selects nothing (it does not reset);
/// "all"/"none" links switch the whole group.
fn facet_group<T: Clone + Eq + std::hash::Hash>(
    ui: &mut egui::Ui,
    sel: &mut Option<HashSet<T>>,
    all: &[T],
    label: &dyn Fn(&T) -> String,
    count: &dyn Fn(&T) -> usize,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        if ui.small_button("all").clicked() {
            *sel = None;
            changed = true;
        }
        if ui.small_button("none").clicked() {
            *sel = Some(HashSet::new());
            changed = true;
        }
    });
    for v in all {
        let mut on = sel.as_ref().is_none_or(|s| s.contains(v));
        if ui
            .checkbox(&mut on, format!("{} ({})", label(v), count(v)))
            .changed()
        {
            changed = true;
            let s = sel.get_or_insert_with(|| all.iter().cloned().collect());
            if on {
                s.insert(v.clone());
            } else {
                s.remove(v);
            }
            if all.iter().all(|x| s.contains(x)) {
                *sel = None;
            }
        }
    }
    changed
}

fn n_of<T: PartialEq>(v: &[(T, usize)], k: &T) -> usize {
    v.iter().find(|x| &x.0 == k).map(|x| x.1).unwrap_or(0)
}

fn facets_panel(ui: &mut egui::Ui, st: &mut TimelineState, th: &Semantic) {
    let mut changed = false;
    ui.label(RichText::new("Quick views").strong().size(14.0));
    ui.add_space(2.0);
    for (name, hover, f) in quick_views() {
        let on = st.title.as_deref() == Some(name);
        if ui
            .add(
                egui::Button::selectable(on, RichText::new(name).size(13.5))
                    .min_size(egui::vec2(ui.available_width(), 26.0)),
            )
            .on_hover_text(hover)
            .clicked()
        {
            st.open_list(name, f);
        }
    }
    ui.add_space(6.0);
    if ui.checkbox(&mut st.show_routine, "Show routine events").on_hover_text("module loads, file hashes, cache expiries, OFN-processed and file-context records (thousands of rows of background activity)").changed() {
        changed = true;
    }
    ui.add_space(4.0);
    ui.separator();
    let label = if st.show_more {
        "▾ More filters"
    } else {
        "▸ More filters"
    };
    if ui
        .add(egui::Button::new(RichText::new(label).strong()).frame(false))
        .on_hover_text("filter by type, location, provenance, link strength, table")
        .clicked()
    {
        st.show_more = !st.show_more;
    }
    if !st.show_more {
        if changed {
            st.dirty = true;
        }
        return;
    }
    let counts = st.counts.clone();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let f = &mut st.query.facets;
            changed |= ui
                .checkbox(
                    &mut f.flagged_only,
                    RichText::new("Flagged only").color(th.flag),
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut f.nocert_only,
                    format!("Locations with a no-cert execution ({})", counts.nocert),
                )
                .changed();
            ui.horizontal(|ui| {
                ui.label("Time:");
                for (v, l) in [
                    (TimeSel::All, "all".to_string()),
                    (TimeSel::Timed, format!("timed ({})", counts.timed)),
                    (TimeSel::Untimed, format!("no time ({})", counts.no_time)),
                ] {
                    changed |= ui.selectable_value(&mut f.time, v, l).changed();
                }
            });
            let kinds = st.kinds_present.clone();
            egui::CollapsingHeader::new("Event type")
                .default_open(true)
                .show(ui, |ui| {
                    changed |=
                        facet_group(ui, &mut f.kinds, &kinds, &|k| kind_label(*k).into(), &|k| {
                            n_of(&counts.kinds, k)
                        });
                });
            egui::CollapsingHeader::new("Location")
                .default_open(true)
                .show(ui, |ui| {
                    let all = [
                        LocClass::OutsideSystemDirs,
                        LocClass::SystemDir,
                        LocClass::Unknown,
                    ];
                    changed |=
                        facet_group(ui, &mut f.loc, &all, &|c| class_label(*c).into(), &|c| {
                            n_of(&counts.loc, c)
                        });
                });
            egui::CollapsingHeader::new("Provenance")
                .default_open(true)
                .show(ui, |ui| {
                    let all = [
                        Some(DbStatus::InBoth),
                        Some(DbStatus::WalOnly),
                        Some(DbStatus::WalModified),
                        Some(DbStatus::RemovedByWal),
                        Some(DbStatus::Unknown),
                        None,
                    ];
                    let label = |s: &Option<DbStatus>| {
                        s.map(|x| status_label(x).to_string())
                            .unwrap_or_else(|| "Store / Results records".into())
                    };
                    changed |= facet_group(ui, &mut f.status, &all, &label, &|s| {
                        n_of(&counts.status, s)
                    });
                });
            egui::CollapsingHeader::new("Strongest link")
                .default_open(false)
                .show(ui, |ui| {
                    let all = [
                        Some(Strength::Exact),
                        Some(Strength::Partial),
                        Some(Strength::Heuristic),
                        None,
                    ];
                    let label = |s: &Option<Strength>| {
                        s.map(|x| strength_label(x).to_string())
                            .unwrap_or_else(|| "not linked".into())
                    };
                    changed |= facet_group(ui, &mut f.strength, &all, &label, &|s| {
                        n_of(&counts.strength, s)
                    });
                });
            egui::CollapsingHeader::new("Source table")
                .default_open(false)
                .show(ui, |ui| {
                    let tables = st.tables_present.clone();
                    changed |= facet_group(ui, &mut f.tables, &tables, &|t| t.clone(), &|t| {
                        n_of(&counts.tables, t)
                    });
                });
        });
    if changed {
        st.dirty = true;
        st.title = None;
    }
}

fn histogram_ui(ui: &mut egui::Ui, st: &mut TimelineState, th: &Semantic, comp: &Comp, tz: Tz) {
    let h = st.hist.clone();
    let width = ui.available_width();
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(width, comp.hist_h), Sense::click_and_drag());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 4.0, th.bg_raised);
    if h.counts.is_empty() {
        p.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "no timed events",
            egui::FontId::proportional(12.0),
            th.text_muted,
        );
        return;
    }
    let n = h.counts.len() as f32;
    let bw = rect.width() / n;
    let max = *h.counts.iter().max().unwrap_or(&1) as f32;
    let span = h.width * h.counts.len() as u64;
    let x_of =
        |t: u64| rect.left() + (t.saturating_sub(h.start) as f32 / span as f32) * rect.width();
    let t_of = |x: f32| {
        h.start + (((x - rect.left()) / rect.width()).clamp(0.0, 1.0) * span as f32) as u64
    };
    if let Some((a, b)) = st.query.window {
        let r = egui::Rect::from_x_y_ranges(x_of(a)..=x_of(b).max(x_of(a) + 2.0), rect.y_range());
        p.rect_filled(r, 0.0, th.accent_weak);
    }
    for (i, &c) in h.counts.iter().enumerate() {
        if c == 0 {
            continue;
        }
        let bh = ((c as f32).sqrt() / max.sqrt()) * (rect.height() - 6.0);
        let x = rect.left() + i as f32 * bw;
        let r = egui::Rect::from_min_max(
            egui::pos2(x + 0.5, rect.bottom() - bh - 2.0),
            egui::pos2((x + bw - 0.5).max(x + 1.5), rect.bottom() - 2.0),
        );
        p.rect_filled(r, 1.0, th.accent);
    }
    if let Some(pos) = resp.hover_pos() {
        let i = (((pos.x - rect.left()) / bw) as usize).min(h.counts.len() - 1);
        let t0 = h.start + i as u64 * h.width;
        resp.clone().on_hover_text(format!(
            "{} · {} events\ndrag to select a window · double-click to reset",
            fmt_ft(t0, tz),
            h.counts[i]
        ));
    }
    if resp.drag_started() {
        // drag_started fires after the pointer has moved past egui's drag threshold: start from the press origin
        let origin = ui
            .input(|i| i.pointer.press_origin())
            .or(resp.interact_pointer_pos());
        if let (Some(o), Some(now)) = (origin, resp.interact_pointer_pos()) {
            st.brush = Some((o.x, now.x));
        }
    }
    if resp.dragged()
        && let (Some(b), Some(pos)) = (st.brush.as_mut(), resp.interact_pointer_pos())
    {
        b.1 = pos.x;
    }
    if let Some((a, b)) = st.brush {
        let r = egui::Rect::from_x_y_ranges(a.min(b)..=a.max(b), rect.y_range());
        p.rect_stroke(
            r,
            0.0,
            egui::Stroke::new(1.0, th.focus),
            egui::StrokeKind::Inside,
        );
    }
    if resp.drag_stopped()
        && let Some((a, b)) = st.brush.take()
        && (a - b).abs() > 3.0
    {
        st.query.window = Some((t_of(a.min(b)), t_of(a.max(b))));
        st.dirty = true;
    }
    if resp.double_clicked() {
        st.query.window = None;
        st.dirty = true;
    }
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(
                fmt_ft(h.start, tz)
                    .get(..16)
                    .unwrap_or("")
                    .replace('T', " "),
            )
            .small()
            .color(th.text_muted),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(
                    fmt_ft(h.start + span, tz)
                        .get(..16)
                        .unwrap_or("")
                        .replace('T', " "),
                )
                .small()
                .color(th.text_muted),
            );
        });
    });
}

/// The whole Timeline tab. `selected` is the inspector selection.
#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut egui::Ui,
    case: &Arc<Case>,
    search: &str,
    tz: Tz,
    st: &mut TimelineState,
    th: &Semantic,
    comp: &Comp,
    selected: &mut Option<Node>,
) {
    st.refresh(case, search, tz);
    egui::Panel::left("facets")
        .default_size(comp.facets_w)
        .resizable(true)
        .show(ui, |ui| {
            facets_panel(ui, st, th);
        });
    egui::CentralPanel::default().show(ui, |ui| {
        histogram_ui(ui, st, th, comp, tz);
        if st.dirty {
            st.refresh(case, search, tz);
        }
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(st.title.clone().unwrap_or_else(|| "Custom filter".into()))
                    .strong()
                    .size(16.0),
            );
            ui.label(RichText::new(format!("{} events", st.ids.len())).color(th.text_muted));
            if (st.title.as_deref() != Some("All activity") || st.query.window.is_some())
                && ui.small_button("Show all activity").clicked()
            {
                st.open_list("All activity", FacetSel::default());
            }
            if let Some((a, b)) = st.query.window {
                ui.label(
                    RichText::new(format!("window {} → {}", fmt_ft(a, tz), fmt_ft(b, tz)))
                        .color(th.text_muted),
                );
                if ui.small_button("✕ window").clicked() {
                    st.set_window(None);
                }
            }
            if let Some(l) = st.query.facets.location {
                let name = case
                    .locations
                    .get(l as usize)
                    .map(|x| x.spellings[0].clone())
                    .unwrap_or_default();
                ui.label(RichText::new(format!("location = {name}")).color(th.accent));
                if ui.small_button("✕ location").clicked() {
                    st.set_pivot(None, st.query.facets.run);
                }
            }
            if let Some(r) = st.query.facets.run {
                ui.label(RichText::new(format!("process run #{r}")).color(th.accent));
                if ui.small_button("✕ run").clicked() {
                    st.set_pivot(st.query.facets.location, None);
                }
            }
            if let Some(e) = &st.error {
                ui.label(
                    RichText::new(format!(
                        "search: {} (at {}); showing the last valid search",
                        e.msg, e.pos
                    ))
                    .color(th.flag),
                );
            }
        });
        let cols: Vec<ColSpec> = COLS
            .iter()
            .map(|(t, w, m)| ColSpec::new(t, *w, *m))
            .collect();
        let ids = st.ids.clone();
        let sel = *selected;
        let path_of = |e: &crate::model::Event| -> String {
            e.location
                .and_then(|l| case.locations.get(l as usize))
                .map(|l| l.spellings[0].clone())
                .unwrap_or_default()
        };
        if ids.is_empty() && st.error.is_none() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("Nothing matches").strong().size(15.0));
                ui.label(
                    RichText::new(
                        "Clear the search, pick another quick view, or tick 'Show routine events'.",
                    )
                    .color(th.text_muted),
                );
            });
        }
        let cell = |r: usize, c: usize| -> String {
            let e = &case.events[ids[r] as usize];
            match c {
                0 => match e.time {
                    Some(t) if e.time_note.is_some() => format!("≈ {}", fmt_ft(t, tz)),
                    Some(t) => fmt_ft(t, tz),
                    None => "—".into(),
                },
                1 => kind_label(e.kind).into(),
                2 => leaf(&path_of(e)).to_string(),
                3 => details(e, leaf(&path_of(e))),
                5 => crate::views::prov_cols(&e.prov).2,
                _ => path_of(e),
            }
        };
        let style = |r: usize| -> RowStyle {
            let e = &case.events[ids[r] as usize];
            let tint = match &e.prov {
                crate::model::Prov::Db {
                    status: DbStatus::WalOnly,
                    ..
                } => Some(th.walonly),
                crate::model::Prov::Db {
                    status: DbStatus::WalModified,
                    ..
                } => Some(th.walmod),
                crate::model::Prov::Db {
                    status: DbStatus::RemovedByWal,
                    ..
                } => Some(th.removed),
                _ => None,
            };
            RowStyle {
                tint,
                flag: e.flag,
                selected: sel == Some(Node::Event(e.id)),
            }
        };
        let evs = grid(
            ui,
            "timeline_grid",
            &cols,
            ids.len(),
            &mut st.grid,
            th,
            comp,
            &cell,
            &style,
        );
        for ev in evs {
            match ev {
                GridEvent::Sorted => {
                    let mut ids = std::mem::take(&mut st.ids);
                    sort_ids(case, &mut ids, st.grid.sort);
                    st.ids = ids;
                }
                GridEvent::Click(r) | GridEvent::DoubleClick(r) => {
                    *selected = st.ids.get(r).map(|&i| Node::Event(i))
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case() -> Arc<Case> {
        crate::views::tests::case()
    }

    #[test]
    fn path_sort_uses_displayed_spelling() {
        let mut c = (*case()).clone();
        let a = c.events.iter().position(|e| e.location.is_some()).unwrap();
        let b = c
            .events
            .iter()
            .rposition(|e| e.location.is_some() && e.location != c.events[a].location)
            .unwrap();
        let (la, lb) = (
            c.events[a].location.unwrap() as usize,
            c.events[b].location.unwrap() as usize,
        );
        c.locations[la].spellings[0] = r"\?\C:\a.exe".into();
        c.locations[la].key.0 = r"C:\A.EXE".into();
        c.locations[lb].spellings[0] = r"C:\b.exe".into();
        c.locations[lb].key.0 = r"C:\Z.EXE".into();
        let mut ids = vec![b as u32, a as u32];
        sort_ids(&c, &mut ids, Some((4, false)));
        assert_eq!(
            ids,
            vec![b as u32, a as u32],
            "displayed spellings decide the order, not the identity keys"
        );
    }

    #[test]
    fn text_sort_is_stable_both_ways() {
        let c = case();
        let same: Vec<u32> = c
            .events
            .iter()
            .filter(|e| e.kind == crate::model::EventKind::NoCertExec)
            .map(|e| e.id)
            .collect();
        assert_eq!(same.len(), 2);
        let mut ids = vec![same[1], same[0]];
        sort_ids(&c, &mut ids, Some((1, false)));
        assert_eq!(ids, vec![same[1], same[0]]);
        sort_ids(&c, &mut ids, Some((1, true)));
        assert_eq!(ids, vec![same[1], same[0]]);
    }
}
