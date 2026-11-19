//! Right-hand inspector: decoded fields with raw toggles, provenance, related records grouped by entity with link
//! strength and rule, on-demand time proximity (rule 10), pivots, bookmarks (spec §8.2).
use crate::bookmarks::{Bookmark, Bookmarks, natural_key};
use crate::case::Case;
use crate::decode::time::{Tz, fmt_ft};
use crate::decode::values::{fmt_fileref, fmt_vsn, hex};
use crate::model::{Event, Ft, Node, Strength};
use crate::ui::theme::Semantic;
use crate::views::{class_label, kind_label, prov_cols, strength_label};
use eframe::egui::{self, Color32, RichText};
use std::collections::HashSet;

/// Requests the inspector hands back to the app.
#[derive(Clone, Debug, PartialEq)]
pub enum Pivot {
    /// Timeline window of ±secs around a time.
    Window(Ft, u32),
    /// Replace the search with this query and show the Timeline.
    Search(String),
    /// Exact location filter.
    Location(u32),
    /// Exact process-run filter.
    Run(u32),
}

/// Free-text search for one field value (quotes group; embedded quotes are dropped).
pub fn value_query(v: &str) -> String {
    format!("\"{}\"", v.replace('"', "").to_lowercase())
}

/// Same-digest pivot on the strongest validated digest available (SHA256, else SHA1, else MD5).
pub fn digest_pivot(c: &Case, content: u32) -> Option<Pivot> {
    use crate::model::DigestAlg::*;
    let x = c.contents.get(content as usize)?;
    [Sha256, Sha1, Md5].iter().find_map(|a| {
        x.digests.iter().find(|d| d.0 == *a).map(|d| {
            let name = match a {
                Sha256 => "sha256",
                Sha1 => "sha1",
                Md5 => "md5",
            };
            Pivot::Search(format!("{name}:{}", hex(&d.1)))
        })
    })
}

/// The process run an event's observation belongs to.
pub fn run_of_event(c: &Case, e: &Event) -> Option<u32> {
    let o = e.obs?;
    c.runs.iter().find(|r| r.obs.contains(&o)).map(|r| r.id)
}

pub struct InspectorState {
    pub history: Vec<Node>,
    pub pos: usize,
    pub show_raw: HashSet<String>,
    /// Rule-10 proximity window in seconds.
    pub window_s: u32,
    pub show_nearby: bool,
}

impl Default for InspectorState {
    fn default() -> Self {
        InspectorState { history: Vec::new(), pos: 0, show_raw: HashSet::new(), window_s: 5, show_nearby: false }
    }
}

impl InspectorState {
    /// Record a selection made elsewhere (grid click, pivot) so Alt+←/→ can walk back to it.
    pub fn track(&mut self, sel: Option<Node>) {
        let Some(n) = sel else { return };
        if self.history.get(self.pos) == Some(&n) {
            return;
        }
        if !self.history.is_empty() {
            self.history.truncate(self.pos + 1);
        }
        self.history.push(n);
        self.pos = self.history.len() - 1;
    }

    pub fn back(&mut self) -> Option<Node> {
        if self.pos > 0 {
            self.pos -= 1;
        }
        self.history.get(self.pos).copied()
    }

    pub fn forward(&mut self) -> Option<Node> {
        if self.pos + 1 < self.history.len() {
            self.pos += 1;
        }
        self.history.get(self.pos).copied()
    }
}

pub fn strength_color(s: Strength, th: &Semantic) -> Color32 {
    match s {
        Strength::Exact => th.exact,
        Strength::Partial => th.partial,
        Strength::Heuristic => th.heuristic,
    }
}

fn dot(s: Strength) -> &'static str {
    match s {
        Strength::Exact => "●",
        Strength::Partial => "◐",
        Strength::Heuristic => "○",
    }
}

/// Short human label for any node (used in Related lists).
pub fn node_label(c: &Case, n: Node, tz: Tz) -> String {
    match n {
        Node::Event(i) => c
            .events
            .get(i as usize)
            .map(|e| format!("{} · {}", e.time.map(|t| fmt_ft(t, tz)).unwrap_or_else(|| "no time".into()), e.summary))
            .unwrap_or_default(),
        Node::Location(i) => c.locations.get(i as usize).map(|l| format!("Location {}", l.spellings[0])).unwrap_or_default(),
        Node::Run(i) => {
            let obs: Vec<_> = c.runs.get(i as usize).map(|r| r.obs.iter().filter_map(|&o| c.obs.get(o as usize)).collect()).unwrap_or_default();
            let start = obs.iter().filter_map(|o| o.start).min().map(|t| fmt_ft(t, tz)).unwrap_or_default();
            let pid = obs.iter().find_map(|o| o.pid).map(|p| format!(" PID {p}")).unwrap_or_default();
            format!("Process run{pid} started {start}")
        }
        Node::Content(i) => c.contents.get(i as usize).map(|x| format!("File content MFT {} on {}", fmt_fileref(&x.fileref), fmt_vsn(x.fileref.vsn))).unwrap_or_default(),
        Node::Store(i) => c.store_files.get(i as usize).map(|f| format!("Store record {f}")).unwrap_or_default(),
    }
}

fn section(ui: &mut egui::Ui, title: &str, th: &Semantic) {
    ui.add_space(6.0);
    ui.label(RichText::new(title).strong().color(th.text_muted));
}

fn copy_btn(ui: &mut egui::Ui, text: &str) {
    if ui.small_button("⧉").on_hover_text("copy").clicked() {
        ui.ctx().copy_text(text.to_string());
    }
}

fn field_rows(ui: &mut egui::Ui, e: &Event, st: &mut InspectorState, th: &Semantic, pivot: &mut Option<Pivot>) {
    egui::Grid::new(("fields", e.id)).num_columns(3).striped(true).spacing([8.0, 3.0]).show(ui, |ui| {
        for f in &e.fields {
            ui.label(RichText::new(&f.name).color(th.text_muted));
            let raw_on = st.show_raw.contains(&f.name);
            let shown = if raw_on { &f.raw } else { &f.display };
            ui.add(egui::Label::new(RichText::new(shown).monospace()).wrap());
            ui.horizontal(|ui| {
                copy_btn(ui, shown);
                if !f.display.trim().is_empty() && ui.small_button("filter").on_hover_text("show events containing this value").clicked() {
                    *pivot = Some(Pivot::Search(value_query(&f.display)));
                }
                if !f.raw.is_empty() && f.raw != f.display && ui.selectable_label(raw_on, "raw").on_hover_text("show the raw stored value").clicked() {
                    if raw_on {
                        st.show_raw.remove(&f.name);
                    } else {
                        st.show_raw.insert(f.name.clone());
                    }
                }
            });
            ui.end_row();
        }
    });
}

/// Events within ±window of a time (rule 10, computed on demand, never stored as links).
fn nearby(c: &Case, t: Ft, secs: u32, me: u32) -> Vec<u32> {
    let w = secs as u64 * 10_000_000;
    let mut v: Vec<u32> = c.events.iter().filter(|e| e.id != me && e.time.is_some_and(|x| x.abs_diff(t) <= w)).map(|e| e.id).collect();
    v.sort_by_key(|&i| c.events[i as usize].time);
    v
}

pub fn toggle_bookmark(c: &Case, bm: &mut Bookmarks, n: Node) {
    let key = natural_key(c, n);
    if let Some(i) = bm.items.iter().position(|b| b.node == key) {
        bm.items.remove(i);
    } else {
        bm.items.push(Bookmark { node: key, tag: String::new(), note: String::new() });
    }
}

/// Returns a pivot request; `selected` may be changed by clicking a related record.
pub fn show(ui: &mut egui::Ui, c: &Case, st: &mut InspectorState, selected: &mut Option<Node>, bm: &mut Bookmarks, th: &Semantic, tz: Tz) -> Option<Pivot> {
    let mut pivot = None;
    let Some(node) = *selected else {
        ui.label(RichText::new("Select a row to inspect it.").color(th.text_muted));
        return None;
    };
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        // header
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(st.pos > 0, egui::Button::new("◀")).on_hover_text("back (Alt+←)").clicked() {
                *selected = st.back();
            }
            if ui.add_enabled(st.pos + 1 < st.history.len(), egui::Button::new("▶")).on_hover_text("forward (Alt+→)").clicked() {
                *selected = st.forward();
            }
            let key = natural_key(c, node);
            let marked = bm.items.iter().any(|b| b.node == key);
            if ui.selectable_label(marked, if marked { "★ Bookmarked" } else { "☆ Bookmark" }).on_hover_text("Ctrl+B").clicked() {
                toggle_bookmark(c, bm, node);
            }
        });
        if let Some(b) = bm.items.iter_mut().find(|b| b.node == natural_key(c, node)) {
            ui.horizontal(|ui| {
                let l = ui.label("Tag");
                ui.add(egui::TextEdit::singleline(&mut b.tag).desired_width(120.0)).labelled_by(l.id);
            });
            ui.add(egui::TextEdit::multiline(&mut b.note).hint_text("note for the report").desired_rows(2).desired_width(f32::INFINITY));
        }
        ui.separator();
        match node {
            Node::Event(i) => {
                let Some(e) = c.events.get(i as usize) else { return };
                ui.horizontal_wrapped(|ui| {
                    egui::Frame::new().fill(th.accent_weak).corner_radius(4).inner_margin(egui::Margin::symmetric(6, 2)).show(ui, |ui| {
                        ui.label(RichText::new(kind_label(e.kind)).small().strong());
                    });
                    if e.flag {
                        ui.label(RichText::new("▲ red flag").color(th.flag).small());
                    }
                });
                ui.add(egui::Label::new(RichText::new(&e.summary).strong().size(15.0)).wrap());
                if let Some(t) = e.time {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(fmt_ft(t, tz)).monospace());
                        copy_btn(ui, &fmt_ft(t, tz));
                    });
                    if let Some(n) = &e.time_note {
                        ui.label(RichText::new(n).italics().color(th.partial));
                    }
                } else {
                    ui.label(RichText::new("no time recorded").color(th.text_muted));
                }
                if let Some(l) = e.location.and_then(|l| c.locations.get(l as usize)) {
                    ui.horizontal_wrapped(|ui| {
                        ui.add(egui::Label::new(RichText::new(&l.spellings[0]).monospace()).wrap());
                        copy_btn(ui, &l.spellings[0]);
                    });
                    ui.label(RichText::new(class_label(l.class)).small().color(th.text_muted));
                }
                section(ui, "Pivots", th);
                ui.horizontal_wrapped(|ui| {
                    if let Some(t) = e.time {
                        if ui.button(format!("±{}s window", st.window_s)).on_hover_text("show this time window in the Timeline").clicked() {
                            pivot = Some(Pivot::Window(t, st.window_s));
                        }
                    }
                    if let Some(l) = e.location {
                        if ui.button("Same location").on_hover_text("exactly this location (not a substring match)").clicked() {
                            pivot = Some(Pivot::Location(l));
                        }
                    }
                    if let Some(p) = e.content.and_then(|x| digest_pivot(c, x)) {
                        if ui.button("Same digest").clicked() {
                            pivot = Some(p);
                        }
                    }
                    if let Some(r) = run_of_event(c, e) {
                        if ui.button("Same process run").on_hover_text("events of this process run (PID + start / path + start)").clicked() {
                            pivot = Some(Pivot::Run(r));
                        }
                    }
                });
                section(ui, "Fields", th);
                field_rows(ui, e, st, th, &mut pivot);
                section(ui, "Provenance", th);
                let (src, key, status) = prov_cols(&e.prov);
                ui.label(RichText::new(format!("{src} · {key} · {status}")).monospace());
                if let crate::model::Prov::Db { old: Some(old), .. } = &e.prov {
                    ui.label(RichText::new("DB-only (before the WAL) values:").color(th.partial));
                    let shown: Vec<String> = old.iter().map(|v| crate::correlate::load::decode_cell("", v, tz).1).collect();
                    ui.add(egui::Label::new(RichText::new(shown.join(" | ")).monospace().small()).wrap());
                }
                related(ui, c, node, selected, th, tz);
                section(ui, "Nearby in time (rule 10, heuristic)", th);
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut st.window_s).range(1..=86_400).suffix(" s"));
                    ui.checkbox(&mut st.show_nearby, "show");
                });
                if st.show_nearby {
                    if let Some(t) = e.time {
                        let near = nearby(c, t, st.window_s, e.id);
                        ui.label(RichText::new(format!("{} events", near.len())).small().color(th.text_muted));
                        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
                        egui::ScrollArea::vertical().id_salt(("nearby", e.id)).max_height(260.0).show_rows(ui, row_h, near.len(), |ui, range| {
                            for &j in &near[range] {
                                let ej = &c.events[j as usize];
                                let d = ej.time.unwrap_or(t) as i128 - t as i128;
                                let txt = format!("○ {:+.3}s · {}", d as f64 / 1e7, ej.summary);
                                if ui.add(egui::Label::new(RichText::new(txt).color(th.heuristic)).sense(egui::Sense::click()).truncate()).clicked() {
                                    *selected = Some(Node::Event(j));
                                }
                            }
                        });
                    }
                }
            }
            other => {
                ui.add(egui::Label::new(RichText::new(node_label(c, other, tz)).strong().size(15.0)).wrap());
                match other {
                    Node::Location(i) => {
                        if let Some(l) = c.locations.get(i as usize) {
                            ui.label(format!("{} · key strength {}", class_label(l.class), strength_label(l.key_strength)));
                            section(ui, "Spellings", th);
                            for s in &l.spellings {
                                ui.label(RichText::new(s).monospace());
                            }
                            if ui.button("Same location in Timeline").clicked() {
                                pivot = Some(Pivot::Location(i));
                            }
                        }
                    }
                    Node::Content(i) => {
                        if let Some(p) = digest_pivot(c, i) {
                            if ui.button("Same digest in Timeline").clicked() {
                                pivot = Some(p);
                            }
                        }
                        if let Some(x) = c.contents.get(i as usize) {
                            for (a, d) in &x.digests {
                                ui.horizontal(|ui| {
                                    ui.label(format!("{a:?}"));
                                    ui.label(RichText::new(hex(d)).monospace());
                                    copy_btn(ui, &hex(d));
                                });
                            }
                        }
                    }
                    Node::Run(i) => {
                        if ui.button("This run in Timeline").clicked() {
                            pivot = Some(Pivot::Run(i));
                        }
                        if let Some(r) = c.runs.get(i as usize) {
                            section(ui, "Observations", th);
                            for &o in &r.obs {
                                let ob = &c.obs[o as usize];
                                ui.label(RichText::new(format!(
                                    "PID {} · start {} · {}",
                                    ob.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                                    ob.start.map(|t| fmt_ft(t, tz)).unwrap_or_else(|| "?".into()),
                                    kind_label(c.events[ob.event as usize].kind)
                                )).monospace());
                            }
                        }
                    }
                    _ => {}
                }
                related(ui, c, other, selected, th, tz);
            }
        }
    });
    pivot
}

fn related(ui: &mut egui::Ui, c: &Case, node: Node, selected: &mut Option<Node>, th: &Semantic, tz: Tz) {
    section(ui, "Related records", th);
    let Some(ids) = c.links_by_node.get(&node) else {
        ui.label(RichText::new("none").color(th.text_muted));
        return;
    };
    let mut groups: Vec<(&str, Vec<(Node, &crate::model::Link)>)> = vec![("Events", vec![]), ("Process runs", vec![]), ("Locations", vec![]), ("File content", vec![]), ("Store records", vec![])];
    for &i in ids {
        let k = &c.links[i as usize];
        let other = if k.a == node { k.b } else { k.a };
        let g = match other {
            Node::Event(_) => 0,
            Node::Run(_) => 1,
            Node::Location(_) => 2,
            Node::Content(_) => 3,
            Node::Store(_) => 4,
        };
        groups[g].1.push((other, k));
    }
    for (title, items) in groups.iter_mut() {
        if items.is_empty() {
            continue;
        }
        items.sort_by(|a, b| b.1.strength.cmp(&a.1.strength));
        egui::CollapsingHeader::new(format!("{title} ({})", items.len())).id_salt((node_label(c, node, tz), *title)).default_open(items.len() <= 25).show(ui, |ui| {
            let row_h = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
            egui::ScrollArea::vertical().id_salt(("rel", *title)).max_height(320.0).show_rows(ui, row_h, items.len(), |ui, range| {
                for (other, k) in &items[range] {
                    let text = format!("{} rule {} · {} — {}", dot(k.strength), k.rule, k.note, node_label(c, *other, tz));
                    let r = ui.add(egui::Label::new(RichText::new(text).color(strength_color(k.strength, th))).sense(egui::Sense::click()).truncate());
                    if r.on_hover_text(format!("{} · rule {}: {}", strength_label(k.strength), k.rule, k.note)).clicked() {
                        *selected = Some(*other);
                    }
                }
            });
        });
    }

}
