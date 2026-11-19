//! Application shell: top bar, tabs, background loading, empty state (spec §8.2).
use crate::case::{Case, OpenError, OpenRequest, Progress, open_in_thread};
use crate::model::Node;
use crate::correlate::load::LoadOpts;
use crate::decode::time::{Tz, parse_tz};
use crate::ui::theme::{self, Comp, Semantic};
use eframe::egui::{self, RichText};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Findings,
    Timeline,
    Artifacts,
    Evidence,
}

pub const EMPTY_HINT: &str = "Open mpenginedb.db or a Scans folder";
pub const ACQUIRE_HINT: &str = "Work on a copy taken from one VSS snapshot, e.g.\n  esentutl /y \"C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\mpenginedb.db\" /d <dest>\\mpenginedb.db /vss\n  (repeat for mpenginedb.db-wal and copy Scans\\History from the same snapshot)";
/// (query, what it finds) shown in the search help.
pub const SEARCH_EXAMPLES: &[(&str, &str)] = &[
    ("rustc.exe", "anything mentioning a name (free text)"),
    (r"path:c:\users\*", "events under a folder (wildcards * and ?)"),
    ("name:*.ps1", "by file name"),
    ("sha256:4510b0", "files whose SHA256 starts with these digits"),
    ("pid:4120", "everything tied to a process ID"),
    ("type:nocert", "one event type (e.g. nocert, processfirststart, ofnset)"),
    ("src:walonly", "rows that exist only in the WAL"),
    ("after:2026-10-19 before:2026-10-20", "a time range (display time zone)"),
    ("-type:module", "exclude something (minus sign)"),
    ("/mimi.*katz/", "regular expression"),
];

/// egui id of the search box (Ctrl+F focuses it).
pub const SEARCH_ID: &str = "mpdbx_search";
const LABEL_MAX: usize = 40;

pub struct App {
    pub case: Option<Arc<Case>>,
    loading: Option<Receiver<Progress>>,
    pub stage: String,
    pub error: Option<String>,
    /// Informational message (e.g. evidence changed on disk between loads).
    pub notice: Option<String>,
    /// Set when the last open failed because the built-in key does not match.
    pub needs_key_dll: bool,
    pub last_request: Option<OpenRequest>,
    pub tab: Tab,
    pub dark: bool,
    pub compact: bool,
    /// Display zone of the loaded case (committed only when a load with it succeeds).
    pub tz: Tz,
    pub tz_text: String,
    pub search: String,
    pub timeline: crate::ui::timeline::TimelineState,
    /// Inspector selection.
    pub selected: Option<crate::model::Node>,
    pub inspector: crate::ui::inspector::InspectorState,
    pub show_inspector: bool,
    pub artifacts: crate::ui::artifacts::ArtifactsState,
    pub evidence_ui: crate::ui::evidence_tab::EvidenceState,
    pub bookmarks: crate::bookmarks::Bookmarks,
    /// Bookmark sets of other evidence opened in this session, keyed by DB SHA256.
    bookmark_sets: std::collections::HashMap<String, crate::bookmarks::Bookmarks>,
    /// Non-evidence inputs read by the UI (e.g. a loaded bookmarks file): protected from exports too.
    extra_inputs: Vec<crate::evidence::Input>,
    /// Last text put on the clipboard by a row copy (for tests and the status line).
    pub last_copied: Option<String>,
    applied_theme: Option<(bool, bool)>,
}

/// Middle-ellipsis for long labels.
pub fn ellipsize(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max / 2).collect();
    let tail: String = s.chars().skip(n - (max - max / 2 - 1)).collect();
    format!("{head}…{tail}")
}

impl App {
    pub fn new(preload: Option<PathBuf>) -> Self {
        let mut a = App {
            case: None,
            loading: None,
            stage: String::new(),
            error: None,
            notice: None,
            needs_key_dll: false,
            last_request: None,
            tab: Tab::Findings,
            dark: true,
            compact: true,
            tz: Tz::default(),
            tz_text: "Z".into(),
            search: String::new(),
            timeline: Default::default(),
            selected: None,
            inspector: Default::default(),
            show_inspector: true,
            artifacts: Default::default(),
            evidence_ui: Default::default(),
            bookmarks: Default::default(),
            bookmark_sets: Default::default(),
            extra_inputs: Vec::new(),
            last_copied: None,
            applied_theme: None,
        };
        if let Some(p) = preload {
            a.open_path(p);
        }
        a
    }

    pub fn is_loading(&self) -> bool {
        self.loading.is_some()
    }

    pub fn semantic(&self) -> Semantic {
        if self.dark {
            theme::dark()
        } else {
            theme::light()
        }
    }

    pub fn comp(&self) -> Comp {
        theme::comp(self.compact)
    }

    pub fn open_path(&mut self, path: PathBuf) {
        let req = OpenRequest {
            path,
            key_dll: None,
            mft: None,
            opts: LoadOpts {
                tz: self.tz,
                volmap_assert: Vec::new(),
            },
        };
        self.open(req);
    }

    /// Starts a load. Only one load runs at a time: further requests are ignored until it finishes.
    pub fn open(&mut self, req: OpenRequest) {
        if self.is_loading() {
            self.notice = Some(
                "A case is still loading; wait for it to finish before opening another.".into(),
            );
            return;
        }
        self.error = None;
        self.needs_key_dll = false;
        self.stage = "starting".into();
        self.last_request = Some(req.clone());
        self.loading = Some(open_in_thread(req));
    }

    /// Re-open the current evidence with changed options (time zone, volume map, MFT CSV).
    pub fn reopen_with(&mut self, f: impl FnOnce(&mut OpenRequest)) {
        if let Some(mut r) = self.last_request.clone() {
            f(&mut r);
            self.open(r);
        }
    }

    /// Apply a time-zone entry: a valid, different zone reloads the case with it; the zone is committed only
    /// when that load succeeds (see `poll`), so the display never disagrees with the loaded case.
    pub fn set_tz_text(&mut self, s: &str) {
        match parse_tz(s) {
            Some(t) if t != self.tz && self.last_request.is_some() => {
                self.tz_text = t.suffix();
                self.reopen_with(|r| r.opts.tz = t);
            }
            Some(t) if self.last_request.is_none() => {
                self.tz = t;
                self.tz_text = t.suffix();
            }
            _ => self.tz_text = self.tz.suffix(),
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.loading else { return };
        let mut done = None;
        while let Ok(p) = rx.try_recv() {
            match p {
                Progress::Stage(s) => self.stage = s.to_string(),
                Progress::Done(r) => done = Some(r),
            }
        }
        match done {
            Some(Ok(case)) => {
                if let Some(old) = &self.case {
                    let same_db = old.evidence.inputs.first().map(|i| &i.path)
                        == case.evidence.inputs.first().map(|i| &i.path);
                    let changed = old
                        .evidence
                        .inputs
                        .iter()
                        .zip(&case.evidence.inputs)
                        .any(|(a, b)| a.path == b.path && a.sha256 != b.sha256);
                    if same_db && changed {
                        self.notice = Some("The evidence files changed on disk since they were first opened; the view now shows the new contents.".into());
                    }
                }
                self.tz = case.opts.tz;
                self.tz_text = self.tz.suffix();
                // evidence identity = every input's SHA256 (DB, WAL, history records): same DB + different WAL is a different case
                let sha = |c: &Case| c.evidence.inputs.iter().map(|i| i.sha256.as_str()).collect::<Vec<_>>().join(":");
                let new_sha = sha(&case);
                let old_sha = self.case.as_deref().map(sha);
                if old_sha.as_deref() != Some(new_sha.as_str()) {
                    // different evidence: park this case's bookmarks, bring back any earlier set, reset selection
                    if let Some(o) = old_sha {
                        self.bookmark_sets.insert(o, std::mem::take(&mut self.bookmarks));
                    }
                    self.bookmarks = self.bookmark_sets.remove(&new_sha).unwrap_or_default();
                    self.selected = None;
                    self.inspector = Default::default();
                } else if let (Some(old), Some(n)) = (self.case.clone(), self.selected) {
                    // same evidence reloaded (time zone, volume map, MFT): remap the selection by natural key
                    let key = crate::bookmarks::natural_key(&old, n);
                    self.selected = case.events.iter().map(|e| Node::Event(e.id)).find(|m| crate::bookmarks::natural_key(&case, *m) == key);
                    self.inspector = Default::default();
                }
                self.case = Some(case);
                self.loading = None;
            }
            Some(Err(e)) => {
                self.needs_key_dll = e == OpenError::WrongKey;
                self.error = Some(e.to_string());
                self.tz_text = self.tz.suffix();
                self.loading = None;
            }
            None => ctx.request_repaint_after(Duration::from_millis(30)),
        }
    }

    fn keys(&mut self, ctx: &egui::Context) {
        let (k1, k2, k3, k4, kf) = ctx.input(|i| {
            let c = i.modifiers.ctrl;
            (
                c && i.key_pressed(egui::Key::Num1),
                c && i.key_pressed(egui::Key::Num2),
                c && i.key_pressed(egui::Key::Num3),
                c && i.key_pressed(egui::Key::Num4),
                c && i.key_pressed(egui::Key::F),
            )
        });
        for (k, t) in [(k1, Tab::Findings), (k2, Tab::Timeline), (k3, Tab::Artifacts), (k4, Tab::Evidence)] {
            if k {
                self.tab = t;
            }
        }
        if kf {
            ctx.memory_mut(|m| m.request_focus(egui::Id::unique(SEARCH_ID)));
        }
        // selection shortcuts - not while typing in a text field
        if !ctx.egui_wants_keyboard_input() {
            let (back, fwd, bm, copy, enter, export) = ctx.input(|i| {
                (
                    i.modifiers.alt && i.key_pressed(egui::Key::ArrowLeft),
                    i.modifiers.alt && i.key_pressed(egui::Key::ArrowRight),
                    i.modifiers.ctrl && i.key_pressed(egui::Key::B),
                    i.events.iter().any(|ev| matches!(ev, egui::Event::Copy)) || (i.modifiers.ctrl && i.key_pressed(egui::Key::C)),
                    i.key_pressed(egui::Key::Enter),
                    i.modifiers.ctrl && i.key_pressed(egui::Key::E),
                )
            });
            if back {
                if let Some(n) = self.inspector.back() {
                    self.selected = Some(n);
                }
            }
            if fwd {
                if let Some(n) = self.inspector.forward() {
                    self.selected = Some(n);
                }
            }
            if let (Some(c), Some(n)) = (self.case.clone(), self.selected) {
                if bm {
                    crate::ui::inspector::toggle_bookmark(&c, &mut self.bookmarks, n);
                }
                if copy {
                    if let crate::model::Node::Event(i) = n {
                        let row = row_tsv(&c, i, self.tz);
                        ctx.copy_text(row.clone());
                        self.last_copied = Some(row);
                    }
                }
                if enter {
                    if let Some(&li) = c.links_by_node.get(&n).and_then(|v| v.first()) {
                        let k = &c.links[li as usize];
                        self.selected = Some(if k.a == n { k.b } else { k.a });
                    }
                }
            }
            if export {
                self.export_current(false);
            }
        }
        let dropped: Option<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .find(|p| !p.as_os_str().is_empty())
        });
        if let Some(p) = dropped {
            self.open_path(p);
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let s = self.semantic();
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let idle = !self.is_loading();
            ui.add_enabled_ui(idle, |ui| {
                ui.menu_button(RichText::new("Open ▾").strong(), |ui| {
                    if ui.button("Scans folder…").on_hover_text("a copied Defender Scans folder (DB, WAL and History)").clicked() {
                        ui.close();
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.open_path(p);
                        }
                    }
                    if ui.button("mpenginedb.db file…").clicked() {
                        ui.close();
                        if let Some(p) = rfd::FileDialog::new().add_filter("Defender engine DB", &["db"]).pick_file() {
                            self.open_path(p);
                        }
                    }
                });
            });
            if let Some(c) = &self.case {
                let db = c.evidence.inputs.first();
                let full = db.map(|i| i.path.clone()).unwrap_or_default();
                let name = full.rsplit(['\\', '/']).nth(1).unwrap_or("case").to_string();
                ui.label(RichText::new(ellipsize(&name, LABEL_MAX)).strong().size(15.0))
                    .on_hover_text(format!("{full}\nSHA256 {}", db.map(|i| i.sha256.clone()).unwrap_or_default()));
            }
            ui.add_space(12.0);
            let sr = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .id(egui::Id::unique(SEARCH_ID))
                    .hint_text("Search names, paths, hashes, PIDs…   (Ctrl+F)")
                    .desired_width(380.0),
            );
            // searching from the home page shows results in the Timeline
            if sr.changed() && self.tab == Tab::Findings {
                self.tab = Tab::Timeline;
            }
            if !self.search.is_empty() && ui.small_button("✕").on_hover_text("clear search").clicked() {
                self.search.clear();
            }
            ui.menu_button("?", |ui| {
                ui.label(RichText::new("Search examples — click to use").strong());
                for (q, what) in SEARCH_EXAMPLES {
                    if ui.button(RichText::new(*q).monospace()).on_hover_text(*what).clicked() {
                        self.search = q.to_string();
                        self.tab = Tab::Timeline;
                        ui.close();
                    }
                    ui.label(RichText::new(*what).small().color(s.text_muted));
                }
            })
            .response
            .on_hover_text("search help");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.menu_button("⋮ Settings", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Time zone");
                        let mut text = self.tz_text.clone();
                        let tz = ui.add(egui::TextEdit::singleline(&mut text).desired_width(64.0)).on_hover_text("Z or ±HH:MM (fixed offset, no DST); reloads the case");
                        self.tz_text = text.clone();
                        if tz.lost_focus() {
                            self.set_tz_text(&text);
                        }
                    });
                    ui.checkbox(&mut self.dark, "Dark theme");
                    ui.checkbox(&mut self.compact, "Compact rows");
                    ui.checkbox(&mut self.show_inspector, "Detail panel");
                    ui.separator();
                    ui.add_enabled_ui(self.case.is_some(), |ui| {
                        if ui.button("Load bookmarks…").clicked() {
                            self.load_bookmarks();
                            ui.close();
                        }
                        if ui.button(format!("Save bookmarks ({})…", self.bookmarks.items.len())).clicked() {
                            self.save_bookmarks();
                            ui.close();
                        }
                    });
                });
                ui.add_enabled_ui(self.case.is_some(), |ui| {
                    ui.menu_button("Export ▾", |ui| {
                        if ui.button("This list as CSV…   (Ctrl+E)").clicked() {
                            self.export_current(false);
                            ui.close();
                        }
                        if ui.button("This list as JSON…").clicked() {
                            self.export_current(true);
                            ui.close();
                        }
                        if ui.button("Report (HTML): findings + bookmarks…").clicked() {
                            self.export_report();
                            ui.close();
                        }
                        if ui.button("Everything (all views + raw tables, CSV)…").clicked() {
                            self.export_everything();
                            ui.close();
                        }
                    });
                });
            });
        });
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            for (t, label) in [(Tab::Findings, "Findings"), (Tab::Timeline, "Timeline"), (Tab::Artifacts, "Files & processes"), (Tab::Evidence, "Evidence")] {
                if ui.add(egui::Button::selectable(self.tab == t, RichText::new(label).size(14.0))).clicked() {
                    self.tab = t;
                }
            }
            if !self.bookmarks.items.is_empty() {
                ui.label(RichText::new(format!("★ {} bookmarked", self.bookmarks.items.len())).color(s.partial));
            }
            if self.is_loading() {
                ui.spinner();
                ui.label(RichText::new(&self.stage).color(s.text_muted));
            }
            if let Some(n) = self.notice.clone() {
                ui.label(RichText::new(n).color(s.partial));
                if ui.small_button("✕").clicked() {
                    self.notice = None;
                }
            }
        });
        ui.add_space(2.0);
    }

    fn empty_state(&mut self, ui: &mut egui::Ui) {
        let s = self.semantic();
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() * 0.25);
            ui.label(
                RichText::new(EMPTY_HINT)
                    .size(theme::prim::FONT[3])
                    .strong(),
            );
            ui.add_space(theme::prim::SP[1]);
            ui.label("Drop a copied Scans folder or mpenginedb.db here, or use Open ▾ (top left).");
            ui.add_space(theme::prim::SP[3]);
            ui.label(RichText::new(ACQUIRE_HINT).monospace().color(s.text_muted));
        });
    }

    fn error_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.semantic();
        if self.needs_key_dll {
            let mut close = false;
            let mut chosen = None;
            egui::Modal::new(egui::Id::unique("wrong_key")).show(ui.ctx(), |ui| {
                ui.label(RichText::new("Wrong engine key").strong());
                ui.label("This database does not decrypt with the built-in key.");
                ui.label("Choose the mpengine.dll from the same machine (Defender\\Definition Updates\\{GUID}\\mpengine.dll).");
                ui.horizontal(|ui| {
                    if ui.button("Choose mpengine.dll…").clicked() {
                        chosen = rfd::FileDialog::new().add_filter("mpengine.dll", &["dll"]).pick_file();
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
            if let Some(p) = chosen {
                self.reopen_with(|r| r.key_dll = Some(p));
            } else if close {
                self.needs_key_dll = false;
            }
        } else if let Some(e) = self.error.clone() {
            egui::Frame::new()
                .fill(s.bg_raised)
                .stroke(egui::Stroke::new(1.0, s.flag))
                .inner_margin(theme::prim::SP[2])
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(e).color(s.flag));
                        if ui.small_button("✕").clicked() {
                            self.error = None;
                        }
                    });
                });
        }
    }

    fn apply_pivot(&mut self, p: crate::ui::inspector::Pivot) {
        use crate::ui::inspector::Pivot;
        match p {
            Pivot::Window(t, s) => {
                let w = s as u64 * 10_000_000;
                self.timeline.set_window(Some((t.saturating_sub(w), t + w)));
            }
            Pivot::Search(q) => {
                self.search = q;
                self.timeline.mark_dirty();
            }
            Pivot::Location(l) => self.timeline.set_pivot(Some(l), None),
            Pivot::Run(r) => self.timeline.set_pivot(None, Some(r)),
        }
        self.tab = Tab::Timeline;
    }

    fn guard(&self) -> Option<(Arc<Case>, crate::export::guard::OutputGuard)> {
        let c = self.case.clone()?;
        let mut inputs: Vec<&crate::evidence::Input> = c.inputs.iter().collect();
        inputs.extend(self.extra_inputs.iter());
        let g = crate::export::guard::OutputGuard::new(&inputs);
        Some((c, g))
    }

    /// Output guard over the evidence and every other file the UI has read.
    pub fn output_guard(&self) -> Option<crate::export::guard::OutputGuard> {
        self.guard().map(|g| g.1)
    }

    /// Load bookmarks from a file (one read: the parsed bytes are the protected file).
    pub fn load_bookmarks_from(&mut self, p: &std::path::Path) -> Result<usize, String> {
        let i = crate::evidence::read_input(p, 64 * 1024 * 1024)?;
        let b = crate::bookmarks::from_bytes(&i.bytes).map_err(|e| format!("{}: {e}", p.display()))?;
        let n = b.items.len();
        self.bookmarks = b;
        self.extra_inputs.push(i);
        Ok(n)
    }

    fn report_result(&mut self, r: Result<String, String>) {
        match r {
            Ok(m) => self.notice = Some(m),
            Err(e) => self.error = Some(e),
        }
    }

    /// The view currently on screen: Timeline = its filtered, sorted rows; Artifacts = the selected view's visible rows.
    pub fn current_view(&self) -> Option<crate::views::View> {
        let c = self.case.as_ref()?;
        if self.tab == Tab::Artifacts {
            if let Some(v) = &self.artifacts.view {
                let mut out = v.clone();
                out.rows = self.artifacts.rows.iter().filter_map(|&i| v.rows.get(i).cloned()).collect();
                return Some(out);
            }
        }
        Some(crate::views::build_view(c, "Timeline", Some(&self.timeline.ids)))
    }

    /// Record a volume mapping as an analyst assertion and reload the case.
    pub fn confirm_volume(&mut self, n: u32, d: char) {
        self.reopen_with(|r| {
            r.opts.volmap_assert.retain(|x| x.0 != n);
            r.opts.volmap_assert.push((n, d));
        });
    }

    /// Writes `body` to a user-chosen file. The native save dialog has already confirmed any overwrite;
    /// evidence inputs are still refused.
    fn write_chosen(&self, path: &std::path::Path, body: &[u8]) -> Result<String, String> {
        use std::io::Write;
        let (_, g) = self.guard().ok_or("no case loaded")?;
        g.check_file(path, true).map_err(|e| e.to_string())?;
        let mut f = crate::export::table::open_target(&g, path, true).map_err(|e| e.to_string())?;
        f.write_all(body).map_err(|e| e.to_string())?;
        Ok(format!("wrote {}", path.display()))
    }

    fn export_current(&mut self, json: bool) {
        let Some(v) = self.current_view() else { return };
        let Some(c) = self.case.clone() else { return };
        let ext = if json { "json" } else { "csv" };
        let Some(p) = rfd::FileDialog::new().add_filter(ext, &[ext]).set_file_name(format!("{}.{ext}", v.name)).save_file() else { return };
        let mut buf = Vec::new();
        let r = if json { crate::export::table::write_json(&c, &v, &mut buf) } else { crate::export::table::write_csv(&v, &mut buf) };
        let r = r.map_err(|e| e.to_string()).and_then(|_| self.write_chosen(&p, &buf));
        self.report_result(r);
    }

    fn export_report(&mut self) {
        let Some(c) = self.case.clone() else { return };
        let Some(p) = rfd::FileDialog::new().add_filter("html", &["html"]).set_file_name("mpdbx-report.html").save_file() else { return };
        let html = crate::export::report::report(&c, &self.bookmarks);
        let r = self.write_chosen(&p, html.as_bytes());
        self.report_result(r);
    }

    fn export_everything(&mut self) {
        let Some((c, g)) = self.guard() else { return };
        let Some(dir) = rfd::FileDialog::new().pick_folder() else { return };
        let r = crate::export::table::export_all(&c, &dir, false, &g, false)
            .map(|f| format!("wrote {} files to {}", f.len(), dir.display()))
            .map_err(|e| e.to_string());
        self.report_result(r);
    }

    fn save_bookmarks(&mut self) {
        let Some((_, g)) = self.guard() else { return };
        let Some(p) = rfd::FileDialog::new().add_filter("mpdbx bookmarks", &["json"]).set_file_name("case.mpdbx.json").save_file() else { return };
        let n = self.bookmarks.items.len();
        let r = crate::bookmarks::save(&self.bookmarks, &p, &g, true).map(|_| format!("saved {n} bookmarks to {}", p.display())).map_err(|e| e.to_string());
        self.report_result(r);
    }

    fn load_bookmarks(&mut self) {
        let Some(p) = rfd::FileDialog::new().add_filter("mpdbx bookmarks", &["json"]).pick_file() else { return };
        match self.load_bookmarks_from(&p) {
            Ok(n) => self.notice = Some(format!("loaded {n} bookmarks")),
            Err(e) => self.error = Some(e),
        }
    }

    /// Body of each tab.
    fn body(&mut self, ui: &mut egui::Ui) {
        let Some(c) = self.case.clone() else { return };
        let (th, comp) = (self.semantic(), self.comp());
        match self.tab {
            Tab::Findings => {
                use crate::ui::findings::FindingAction;
                match crate::ui::findings::show(ui, &c, &th) {
                    Some(FindingAction::Timeline { title, facets }) => {
                        self.timeline.bind(&c);
                        self.timeline.open_list(&title, facets);
                        self.tab = Tab::Timeline;
                    }
                    Some(FindingAction::View(v)) => {
                        self.artifacts.current = crate::ui::artifacts::Source::Typed(v);
                        self.tab = Tab::Artifacts;
                    }
                    Some(FindingAction::Evidence) => self.tab = Tab::Evidence,
                    None => {}
                }
            }
            Tab::Timeline => {
                if self.show_inspector && self.selected.is_some() {
                    egui::Panel::right("inspector").default_size(comp.inspector_w).min_size(300.0).resizable(true).show(ui, |ui| {
                        if let Some(p) = crate::ui::inspector::show(ui, &c, &mut self.inspector, &mut self.selected, &mut self.bookmarks, &th, self.tz) {
                            self.apply_pivot(p);
                        }
                    });
                }
                crate::ui::timeline::show(
                    ui,
                    &c,
                    &self.search,
                    self.tz,
                    &mut self.timeline,
                    &th,
                    &comp,
                    &mut self.selected,
                );
                return;
            }
            Tab::Artifacts => {
                if self.show_inspector && self.selected.is_some() {
                    egui::Panel::right("inspector_a").default_size(comp.inspector_w).min_size(300.0).resizable(true).show(ui, |ui| {
                        if let Some(p) = crate::ui::inspector::show(ui, &c, &mut self.inspector, &mut self.selected, &mut self.bookmarks, &th, self.tz) {
                            self.apply_pivot(p);
                        }
                    });
                }
                crate::ui::artifacts::show(ui, &c, &self.search, &mut self.artifacts, &th, &comp, &mut self.selected);
            }
            Tab::Evidence => {
                use crate::ui::evidence_tab::EvidenceAction;
                match crate::ui::evidence_tab::show(ui, &c, &mut self.evidence_ui, &th, self.tz) {
                    Some(EvidenceAction::ConfirmVolume(n, d)) => self.confirm_volume(n, d),
                    Some(EvidenceAction::BindMft { path, vsn, drive }) => self.reopen_with(|r| r.mft = Some((path, vsn, drive))),
                    None => {}
                }
            }
        };
    }

    /// Whole UI for one frame (also driven directly by the headless UI tests).
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.applied_theme.is_none() {
            theme::install_fonts(&ctx);
        }
        if self.applied_theme != Some((self.dark, self.compact)) {
            theme::apply(&ctx, &self.semantic(), &self.comp());
            self.applied_theme = Some((self.dark, self.compact));
        }
        self.poll(&ctx);
        self.keys(&ctx);
        self.inspector.track(self.selected);
        egui::Panel::top("top_bar").show(ui, |ui| self.top_bar(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            self.error_panel(ui);
            if self.case.is_none() && !self.is_loading() {
                self.empty_state(ui);
            } else {
                self.body(ui);
            }
        });
    }
}

/// One Timeline row as TSV (Time, Type, Source, Summary, Path); tabs/newlines inside values become spaces.
pub fn row_tsv(c: &Case, id: u32, tz: Tz) -> String {
    let Some(e) = c.events.get(id as usize) else { return String::new() };
    let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
    let cols = [
        e.time.map(|t| crate::decode::time::fmt_ft(t, tz)).unwrap_or_default(),
        crate::views::kind_label(e.kind).to_string(),
        crate::views::prov_cols(&e.prov).2,
        e.summary.clone(),
        e.location.and_then(|l| c.locations.get(l as usize)).map(|l| l.spellings[0].clone()).unwrap_or_default(),
    ];
    cols.iter().map(|s| clean(s)).collect::<Vec<_>>().join("\t")
}

/// eframe adapter.
pub struct EframeApp(pub App);

impl eframe::App for EframeApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.0.show(ui);
    }
}
