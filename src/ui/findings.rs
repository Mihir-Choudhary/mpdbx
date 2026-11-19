//! Findings (home) tab: one card per question an analyst asks first, each opening the matching filtered list.
use crate::case::Case;
use crate::model::{DbStatus, EventKind, LocClass, Prov};
use crate::query::FacetSel;
use crate::ui::theme::Semantic;
use eframe::egui::{self, RichText, Sense};
use std::collections::HashSet;

/// Where a card leads.
#[derive(Clone, Debug)]
pub enum FindingAction {
    /// Timeline with these filters; the title is shown above the list.
    Timeline { title: String, facets: FacetSel },
    /// A "Files & processes" view by name.
    View(String),
    Evidence,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Flag,
    Info,
}

pub struct Card {
    pub level: Level,
    pub title: &'static str,
    pub explain: &'static str,
    pub count: usize,
    pub examples: Vec<String>,
    pub action: FindingAction,
}

fn leaf(c: &Case, loc: Option<u32>) -> Option<String> {
    let l = c.locations.get(loc? as usize)?;
    Some(l.spellings[0].rsplit(['\\', '/']).next().unwrap_or("").to_string())
}

/// Matching event ids and up to 3 distinct example names.
fn tally(c: &Case, pred: &dyn Fn(&crate::model::Event) -> bool) -> (HashSet<u32>, Vec<String>) {
    let mut n = HashSet::new();
    let mut ex: Vec<String> = Vec::new();
    for e in c.events.iter().filter(|e| pred(e)) {
        n.insert(e.id);
        if ex.len() < 3 {
            if let Some(name) = leaf(c, e.location) {
                if !name.is_empty() && !ex.contains(&name) {
                    ex.push(name);
                }
            }
        }
    }
    (n, ex)
}

fn class(c: &Case, e: &crate::model::Event) -> LocClass {
    e.location.and_then(|l| c.locations.get(l as usize)).map(|l| l.class).unwrap_or(LocClass::Unknown)
}

fn field<'a>(e: &'a crate::model::Event, name: &str) -> Option<&'a str> {
    e.fields.iter().find(|f| f.name == name).map(|f| f.display.as_str())
}

fn wal(e: &crate::model::Event) -> bool {
    matches!(e.prov, Prov::Db { status: DbStatus::WalOnly | DbStatus::WalModified | DbStatus::RemovedByWal, .. })
}

/// The cards, red flags first; cards with nothing to show are kept (a 0 is a finding too) but drawn muted.
pub fn cards(c: &Case) -> Vec<Card> {
    use EventKind::*;
    let mut v = Vec::new();
    let mut add = |level, title: &'static str, explain, (ids, examples): (HashSet<u32>, Vec<String>)| {
        let count = ids.len();
        let action = FindingAction::Timeline { title: title.into(), facets: FacetSel { only: Some(std::sync::Arc::new(ids)), ..Default::default() } };
        v.push(Card { level, title, explain, count, examples, action })
    };
    add(
        Level::Flag,
        "Unsigned programs run outside system folders",
        "First run of a binary with no embedded certificate, not under Windows or Program Files.",
        tally(c, &|e| e.kind == NoCertExec && class(c, e) == LocClass::OutsideSystemDirs),
    );
    add(
        Level::Flag,
        "Renamed executables outside system folders",
        "The file's OriginalFileName (set at creation) differs from its name, e.g. a copied robocopy.exe renamed.",
        tally(c, &|e| matches!(e.kind, OfnSet | OfnSetInferred) && field(e, "Rename kind") == Some("executable rename") && class(c, e) == LocClass::OutsideSystemDirs),
    );
    add(
        Level::Flag,
        "Threat detections",
        "Behaviour or signature detections Defender keeps in its recent-threats queue.",
        tally(c, &|e| e.kind == QueueEntry && field(e, "Threat").is_some()),
    );
    add(
        Level::Flag,
        "RDP logons",
        "Successful inbound RDP logons recorded by Defender (source IP, user, workstation).",
        tally(c, &|e| e.kind == RdpLogon),
    );
    add(
        Level::Flag,
        "Rows found only in the WAL (or deleted by it)",
        "Newest activity not yet written into the main database, and rows the WAL removed or changed.",
        tally(c, &|e| wal(e)),
    );
    add(
        Level::Info,
        "Programs started",
        "First start of each program in Defender's ~7-day window (time = process creation), plus starts seen in scans.",
        tally(c, &|e| matches!(e.kind, ProcessFirstStart | StoreProcessStart | AmsiProcessStart)),
    );
    add(
        Level::Info,
        "All unsigned program runs",
        "Every first run of a binary without an embedded certificate, including system folders.",
        tally(c, &|e| e.kind == NoCertExec),
    );
    add(
        Level::Info,
        "Files scanned on create/open",
        "Scans\\History\\Store records (~1 hour cache): which process created or opened which file.",
        tally(c, &|e| matches!(e.kind, FileScan | AmsiScan)),
    );
    add(
        Level::Info,
        "Signature hits (low-fidelity)",
        "Files that matched a low-fidelity signature and were sent for a closer look.",
        tally(c, &|e| e.kind == LowFiHit),
    );
    v.push(Card {
        level: Level::Info,
        title: "File hashes",
        explain: "MD5 / SHA1 / SHA256 of files Defender hashed, by MFT reference.",
        count: c.contents.len(),
        examples: Vec::new(),
        action: FindingAction::View("File content & hashes".into()),
    });
    v.push(Card {
        level: Level::Info,
        title: "Host context",
        explain: "Hostname, IP addresses and DNS suffixes, protected folders, schema and scan history.",
        count: c.host.facts.len(),
        examples: c.host.facts.iter().filter(|f| f.0.to_ascii_lowercase().contains("hostname")).map(|f| f.1.clone()).take(1).collect(),
        action: FindingAction::View("Host context".into()),
    });
    v
}

const GAP: f32 = 10.0;
const CARD_H: f32 = 104.0;
const CARD_MIN_W: f32 = 300.0;
const PAGE_MAX_W: f32 = 1320.0;

/// Text limited to `rows` lines with an ellipsis (keeps every card the same height).
fn clamped(text: &str, size: f32, color: egui::Color32, width: f32, rows: usize, mono: bool) -> egui::text::LayoutJob {
    let font = if mono { egui::FontId::monospace(size) } else { egui::FontId::proportional(size) };
    let mut job = egui::text::LayoutJob::single_section(text.to_owned(), egui::TextFormat { font_id: font, color, ..Default::default() });
    job.wrap = egui::text::TextWrapping { max_width: width, max_rows: rows, break_anywhere: false, overflow_character: Some('…') };
    job
}

/// One fixed-size, fully clickable card.
fn card_ui(ui: &mut egui::Ui, card: &Card, th: &Semantic, width: f32) -> bool {
    let flagged = card.level == Level::Flag;
    let accent = if flagged { th.flag } else { th.accent };
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(width, CARD_H), Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    let hover = resp.hovered();
    let p = ui.painter();
    p.rect(
        rect,
        6.0,
        if hover { th.bg_input } else { th.bg_raised },
        egui::Stroke::new(if hover { 1.5 } else { 1.0 }, if flagged || hover { accent } else { th.border }),
        egui::StrokeKind::Inside,
    );
    // accent bar on the left edge
    p.rect_filled(egui::Rect::from_min_size(rect.min, egui::vec2(4.0, rect.height())), egui::CornerRadius { nw: 6, sw: 6, ne: 0, se: 0 }, accent);
    let inner = rect.shrink2(egui::vec2(16.0, 10.0));
    let mut c = ui.new_child(egui::UiBuilder::new().max_rect(inner).layout(egui::Layout::top_down(egui::Align::Min)));
    c.spacing_mut().item_spacing.y = 3.0;
    c.horizontal(|ui| {
        ui.label(RichText::new(card.count.to_string()).strong().size(22.0).color(accent));
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(card.title).strong().size(14.5).color(th.text_primary)).truncate().selectable(false));
    });
    c.add(egui::Label::new(clamped(card.explain, 12.5, th.text_muted, inner.width(), 2, false)).selectable(false));
    if !card.examples.is_empty() {
        c.add(egui::Label::new(clamped(&format!("e.g. {}", card.examples.join(" · ")), 12.0, th.text_mono, inner.width(), 1, true)).selectable(false));
    }
    resp.clicked()
}

/// Lay cards out in equal columns; returns the clicked card's action.
fn card_grid(ui: &mut egui::Ui, cards: &[&Card], th: &Semantic, width: f32) -> Option<FindingAction> {
    let ncol = (((width + GAP) / (CARD_MIN_W + GAP)).floor() as usize).clamp(1, 3);
    let w = ((width - GAP * (ncol as f32 - 1.0)) / ncol as f32).floor();
    let mut act = None;
    for row in cards.chunks(ncol) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = GAP;
            for card in row {
                if card_ui(ui, card, th, w) {
                    act = Some(card.action.clone());
                }
            }
        });
        ui.add_space(GAP);
    }
    act
}

fn heading(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    ui.add_space(6.0);
    ui.label(RichText::new(text).strong().size(15.0).color(color));
    ui.add_space(4.0);
}

pub fn show(ui: &mut egui::Ui, c: &Case, th: &Semantic) -> Option<FindingAction> {
    let mut act = None;
    let cards = cards(c);
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        let full = ui.available_width();
        let width = full.min(PAGE_MAX_W);
        ui.horizontal(|ui| {
            ui.add_space(((full - width) / 2.0).max(0.0));
            ui.vertical(|ui| {
                ui.set_width(width);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("What stands out in this database").strong().size(20.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Evidence and integrity").clicked() {
                            act = Some(FindingAction::Evidence);
                        }
                        if ui.button("Open full timeline →").clicked() {
                            act = Some(FindingAction::Timeline { title: "All activity".into(), facets: FacetSel::default() });
                        }
                    });
                });
                ui.label(RichText::new("Click a card to see exactly those events.").color(th.text_muted));
                ui.add_space(6.0);

                let hits: Vec<&Card> = cards.iter().filter(|k| k.level == Level::Flag && k.count > 0).collect();
                let clear: Vec<&Card> = cards.iter().filter(|k| k.level == Level::Flag && k.count == 0).collect();
                heading(ui, if hits.is_empty() { "Needs attention: nothing flagged" } else { "Needs attention" }, th.flag);
                if let Some(a) = card_grid(ui, &hits, th, width) {
                    act = Some(a);
                }
                if !clear.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("✓ Checked, nothing found:").color(th.text_muted));
                        for k in &clear {
                            ui.label(RichText::new(k.title).color(th.text_muted)).on_hover_text(k.explain);
                        }
                    });
                    ui.add_space(6.0);
                }
                let info: Vec<&Card> = cards.iter().filter(|k| k.level == Level::Info).collect();
                heading(ui, "Overview", th.text_primary);
                if let Some(a) = card_grid(ui, &info, th, width) {
                    act = Some(a);
                }
                ui.add_space(12.0);
            });
        });
    });
    act
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cards_count_fixture_findings() {
        let c = crate::views::tests::case();
        let cards = cards(&c);
        let get = |t: &str| cards.iter().find(|k| k.title == t).unwrap().count;
        assert_eq!(get("Unsigned programs run outside system folders"), 2);
        assert_eq!(get("Threat detections"), 1);
        assert!(get("Rows found only in the WAL (or deleted by it)") > 0);
        assert_eq!(get("RDP logons"), 0);
        assert!(cards.iter().take_while(|k| k.level == Level::Flag).count() >= 5, "red flags first");
        // the list a card opens is exactly what it counted
        for k in &cards {
            if let FindingAction::Timeline { facets, .. } = &k.action {
                let q = crate::query::Query { facets: facets.clone(), ..Default::default() };
                assert_eq!(crate::query::apply(&c, &c.index, &q).len(), k.count, "{}", k.title);
            }
        }
    }
}
