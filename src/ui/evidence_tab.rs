//! Evidence tab: inputs and hashes, page/WAL report, per-table provenance counts, volume map, MFT CSV binding,
//! warnings (spec §8.2).
use crate::case::Case;
use crate::decode::time::{Tz, fmt_ft};
use crate::decode::values::fmt_vsn;
use crate::model::Strength;
use crate::ui::theme::Semantic;
use eframe::egui::{self, RichText};

/// Requests from the Evidence tab (the app reloads the case for them).
#[derive(Clone, Debug, PartialEq)]
pub enum EvidenceAction {
    ConfirmVolume(u32, char),
    BindMft { path: std::path::PathBuf, vsn: u32, drive: char },
}

#[derive(Default)]
pub struct EvidenceState {
    mft_path: Option<std::path::PathBuf>,
    mft_vsn: Option<u32>,
    mft_drive: String,
}

fn kv(ui: &mut egui::Ui, k: &str, v: impl Into<String>, th: &Semantic) {
    ui.label(RichText::new(k).color(th.text_muted));
    ui.label(RichText::new(v.into()).monospace());
    ui.end_row();
}

fn heading(ui: &mut egui::Ui, t: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(t).strong().size(15.0));
    ui.separator();
}

pub fn show(ui: &mut egui::Ui, c: &Case, st: &mut EvidenceState, th: &Semantic, tz: Tz) -> Option<EvidenceAction> {
    let mut action = None;
    let e = &c.evidence;
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        heading(ui, "Inputs");
        egui::Grid::new("inputs").striped(true).num_columns(5).spacing([12.0, 4.0]).show(ui, |ui| {
            for h in ["File", "Bytes", "SHA256", "Modified", "Notes"] {
                ui.label(RichText::new(h).strong());
            }
            ui.end_row();
            for i in &e.inputs {
                ui.label(RichText::new(&i.path).monospace());
                ui.label(i.size.to_string());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&i.sha256).monospace().small());
                    if ui.small_button("⧉").on_hover_text("copy SHA256").clicked() {
                        ui.ctx().copy_text(i.sha256.clone());
                    }
                });
                ui.label(i.mtime.map(|t| fmt_ft(t, tz)).unwrap_or_default());
                let mut n = Vec::new();
                if i.changed_during_read {
                    n.push("changed while read");
                }
                if i.shared_write_fallback {
                    n.push("open for writing elsewhere");
                }
                ui.label(RichText::new(n.join(", ")).color(th.flag));
                ui.end_row();
            }
        });

        heading(ui, "Database and WAL");
        let w = &e.wal;
        egui::Grid::new("db").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
            kv(ui, "Page size / pages", format!("{} / {}", e.page_size, e.pages), th);
            kv(ui, "Encrypted", e.encrypted.to_string(), th);
            kv(ui, "Key", e.key_source.clone(), th);
            kv(ui, "Header bytes 18–19", format!("{:?} (2,2 = WAL mode; loaded as a rollback-journal copy)", e.header_18_19), th);
            kv(ui, "WAL present / header valid", format!("{} / {}", w.present, w.header_valid), th);
            kv(ui, "WAL frames total / validated / applied", format!("{} / {} / {}", w.frames_total, w.frames_valid, w.frames_applied), th);
            kv(ui, "WAL commits applied", w.commits.to_string(), th);
            kv(ui, "WAL frames after the last commit (ignored)", w.ignored_tail_frames.to_string(), th);
            kv(ui, "WAL stop", w.stop.as_ref().map(|s| format!("{s:?}")).unwrap_or_else(|| "none — checksum chain fully validated".into()), th);
            kv(ui, "WAL salts", format!("{:#010x} {:#010x}", w.salts.0, w.salts.1), th);
        });

        heading(ui, "Tables (DB-only vs DB+WAL)");
        egui::Grid::new("tables").striped(true).num_columns(8).spacing([12.0, 3.0]).show(ui, |ui| {
            for h in ["Table", "DB-only", "Merged", "DB", "WAL-only", "WAL-modified", "Removed by WAL", "unknown"] {
                ui.label(RichText::new(h).strong());
            }
            ui.end_row();
            for (n, a, b, s) in &e.table_counts {
                let o = |x: &Option<usize>| x.map(|v| v.to_string()).unwrap_or_else(|| "—".into());
                ui.label(RichText::new(n).monospace());
                ui.label(o(a));
                ui.label(o(b));
                for (k, v) in s.iter().enumerate() {
                    let col = match (k, *v > 0) {
                        (1, true) => th.partial,
                        (2, true) => th.partial,
                        (3, true) => th.flag,
                        (4, true) => th.flag,
                        _ => th.text_primary,
                    };
                    ui.label(RichText::new(v.to_string()).color(col));
                }
                ui.end_row();
            }
        });

        heading(ui, "Volume map (\\Device\\HarddiskVolumeN → drive)");
        if e.volmap.map.is_empty() {
            ui.label(RichText::new("No device paths could be mapped (needs ≥ 2 identical volume-relative paths on one drive).").color(th.text_muted));
        }
        for (n, (d, s, support)) in &e.volmap.map {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("HarddiskVolume{n} → {d}:")).monospace().strong());
                let (txt, col) = match s {
                    Strength::Exact => ("● analyst assertion", th.exact),
                    _ => ("○ inferred (heuristic)", th.heuristic),
                };
                ui.label(RichText::new(txt).color(col));
                if *s != Strength::Exact && ui.button("Confirm").on_hover_text("record as an analyst assertion and reload").clicked() {
                    action = Some(EvidenceAction::ConfirmVolume(*n, *d));
                }
            });
            ui.label(RichText::new(format!("supporting paths: {}", support.join(" · "))).small().color(th.text_muted));
        }

        heading(ui, "MFT CSV (resolve FileHashes MFT references to paths)");
        match &e.mft {
            Some((p, vsn, d, skipped)) => {
                ui.label(format!("bound: {p} → volume {} as {d}: ({skipped} rows skipped)", fmt_vsn(*vsn)));
            }
            None => {
                let mut vsns: Vec<u32> = c.contents.iter().map(|x| x.fileref.vsn).collect();
                vsns.sort();
                vsns.dedup();
                if vsns.is_empty() {
                    ui.label(RichText::new("No FileHashes rows in this case.").color(th.text_muted));
                } else {
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Choose MFTECmd $MFT CSV…").clicked() {
                            st.mft_path = rfd::FileDialog::new().add_filter("csv", &["csv"]).pick_file();
                        }
                        if let Some(p) = &st.mft_path {
                            ui.label(RichText::new(p.display().to_string()).monospace().small());
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.label("Volume serial:");
                        for v in &vsns {
                            if ui.selectable_label(st.mft_vsn == Some(*v), fmt_vsn(*v)).clicked() {
                                st.mft_vsn = Some(*v);
                            }
                        }
                        ui.label("Drive:");
                        let r = ui.add(egui::TextEdit::singleline(&mut st.mft_drive).desired_width(24.0).char_limit(1));
                        r.on_hover_text("drive letter the CSV's volume-relative paths belong to");
                    });
                    let drive = st.mft_drive.chars().next().filter(|c| c.is_ascii_alphabetic()).map(|c| c.to_ascii_uppercase());
                    let ready = st.mft_path.is_some() && st.mft_vsn.is_some() && drive.is_some();
                    if ui.add_enabled(ready, egui::Button::new("Bind and reload")).clicked() {
                        if let (Some(path), Some(vsn), Some(drive)) = (st.mft_path.clone(), st.mft_vsn, drive) {
                            action = Some(EvidenceAction::BindMft { path, vsn, drive });
                        }
                    }
                }
            }
        }

        heading(ui, &format!("Warnings ({})", e.warnings.len()));
        if e.warnings.is_empty() {
            ui.label(RichText::new("none").color(th.text_muted));
        }
        for wn in &e.warnings {
            ui.label(RichText::new(wn).color(th.partial));
        }
    });
    action
}
