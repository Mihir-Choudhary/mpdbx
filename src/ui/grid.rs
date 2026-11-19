//! Virtualised data grid shared by the Timeline and Artifacts tabs (spec §8.2).
//! Only the visible rows are laid out, so 100k+ rows stay smooth. Sorting is done by the caller.
use crate::ui::theme::{Comp, Semantic};
use eframe::egui::{self, Color32, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct ColSpec {
    pub title: String,
    pub width: f32,
    /// Monospace + middle ellipsis (paths, hashes, times).
    pub mono: bool,
}

impl ColSpec {
    pub fn new(title: &str, width: f32, mono: bool) -> Self {
        ColSpec {
            title: title.into(),
            width,
            mono,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GridState {
    /// (column, descending)
    pub sort: Option<(usize, bool)>,
    pub hidden: HashSet<usize>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RowStyle {
    pub tint: Option<Color32>,
    pub flag: bool,
    pub selected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GridEvent {
    /// Header clicked: new sort state is already stored in `GridState`.
    Sorted,
    Click(usize),
    DoubleClick(usize),
}

/// Middle-ellipsis to roughly `max_chars`, keeping the start and the (usually more telling) end.
pub fn middle(s: &str, max_chars: usize) -> String {
    let n = s.chars().count();
    if n <= max_chars || max_chars < 5 {
        return s.to_string();
    }
    let keep = max_chars - 1;
    let head: String = s.chars().take(keep / 3).collect();
    let tail: String = s.chars().skip(n - (keep - keep / 3)).collect();
    format!("{head}…{tail}")
}

/// Draws the grid; `cell(row, col)` returns display text, `style(row)` the row decoration.
#[allow(clippy::too_many_arguments)]
pub fn grid(
    ui: &mut egui::Ui,
    id: &str,
    cols: &[ColSpec],
    n_rows: usize,
    st: &mut GridState,
    th: &Semantic,
    comp: &Comp,
    cell: &dyn Fn(usize, usize) -> String,
    style: &dyn Fn(usize) -> RowStyle,
) -> Vec<GridEvent> {
    let mut events = Vec::new();
    let visible: Vec<usize> = (0..cols.len()).filter(|c| !st.hidden.contains(c)).collect();
    let mut events_out = Vec::new();
    // horizontal scrolling when the columns are wider than the panel (TableBuilder scrolls vertically only)
    egui::ScrollArea::horizontal()
        .id_salt((id, "h"))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let mut tb = TableBuilder::new(ui)
                .id_salt(id)
                .striped(true)
                .resizable(true)
                .sense(Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
            let last = visible.len().saturating_sub(1);
            for (k, &c) in visible.iter().enumerate() {
                tb = tb.column(if k == last {
                    Column::remainder().at_least(80.0).clip(true)
                } else {
                    Column::initial(cols[c].width).at_least(28.0).clip(true)
                });
            }
            let font = if comp.row_h <= 20.0 { 12.5 } else { 13.5 };
            tb.header(comp.row_h + 4.0, |mut header| {
                for &c in &visible {
                    header.col(|ui| {
                        let arrow = match st.sort {
                            Some((sc, false)) if sc == c => " ▲",
                            Some((sc, true)) if sc == c => " ▼",
                            _ => "",
                        };
                        let r = ui.add(
                            egui::Button::new(
                                RichText::new(format!("{}{arrow}", cols[c].title)).strong(),
                            )
                            .frame(false),
                        );
                        if r.clicked() {
                            st.sort = match st.sort {
                                Some((sc, desc)) if sc == c => Some((c, !desc)),
                                _ => Some((c, false)),
                            };
                            events.push(GridEvent::Sorted);
                        }
                        r.context_menu(|ui| {
                            ui.label(RichText::new("Columns").strong());
                            for (i, cs) in cols.iter().enumerate() {
                                let mut on = !st.hidden.contains(&i);
                                if ui.checkbox(&mut on, &cs.title).changed() {
                                    if on {
                                        st.hidden.remove(&i);
                                    } else if st.hidden.len() + 1 < cols.len() {
                                        st.hidden.insert(i);
                                    }
                                }
                            }
                        });
                    });
                }
            })
            .body(|body| {
                body.rows(comp.row_h, n_rows, |mut row| {
                    let i = row.index();
                    let s = style(i);
                    row.set_selected(s.selected);
                    let mut clicked = false;
                    let mut dbl = false;
                    for (k, &c) in visible.iter().enumerate() {
                        row.col(|ui| {
                            if let Some(t) = s.tint {
                                ui.painter().rect_filled(
                                    ui.max_rect().expand2(egui::vec2(4.0, 1.0)),
                                    0.0,
                                    t,
                                );
                            }
                            if k == 0 && s.flag {
                                ui.label(RichText::new("▲").color(th.flag).size(font));
                            }
                            let text = cell(i, c);
                            let max_chars =
                                ((ui.available_width() / (font * 0.56)).max(4.0)) as usize;
                            let shown = if cols[c].mono {
                                middle(&text, max_chars)
                            } else {
                                text.clone()
                            };
                            let mut rt = RichText::new(shown).size(font);
                            if cols[c].mono {
                                rt = rt.monospace();
                            }
                            let mut lbl = egui::Label::new(rt).sense(Sense::click());
                            if !cols[c].mono {
                                lbl = lbl.truncate();
                            }
                            let r = ui.add(lbl);
                            let r = if text.chars().count() > max_chars {
                                r.on_hover_text(&text)
                            } else {
                                r
                            };
                            clicked |= r.clicked();
                            dbl |= r.double_clicked();
                        });
                    }
                    let rr = row.response();
                    if clicked || rr.clicked() {
                        events.push(GridEvent::Click(i));
                    }
                    if dbl || rr.double_clicked() {
                        events.push(GridEvent::DoubleClick(i));
                    }
                });
            });
            events_out = events;
        });
    events_out
}
