//! Design tokens in three layers — primitive → semantic → component — mapped onto egui (spec §8.1).
//! Changing the look means editing this file only.
use eframe::egui::{self, Color32, CornerRadius, Stroke, Visuals};

/// Layer 1 — primitives (raw values; never used directly by widgets).
pub mod prim {
    use eframe::egui::Color32;
    const fn hex(v: u32) -> Color32 {
        Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
    }
    /// Neutral ramp n0 … n950 (from the approved C1 mockups).
    pub const N: [Color32; 11] = [
        hex(0x0b0f14),
        hex(0x0f141b),
        hex(0x121922),
        hex(0x151c26),
        hex(0x1b2533),
        hex(0x263040),
        hex(0x33415a),
        hex(0x6f7f95),
        hex(0x9fb0c8),
        hex(0xd7dce4),
        hex(0xf5f7fa),
    ];
    pub const WHITE: Color32 = hex(0xffffff);
    pub const SLATE700: Color32 = hex(0x1b2533);
    pub const SLATE500: Color32 = hex(0x4f5d70);
    pub const SLATE100: Color32 = hex(0xeef2f7);
    pub const BLUE500: Color32 = hex(0x2f81f7);
    pub const BLUE600: Color32 = hex(0x1f6feb);
    pub const BLUE700: Color32 = hex(0x0b4fbf);
    pub const AMBER400: Color32 = hex(0xffd166);
    pub const AMBER900: Color32 = hex(0x3a3016);
    pub const AMBER100: Color32 = hex(0xfff4d6);
    pub const RED400: Color32 = hex(0xff7b8a);
    pub const RED900: Color32 = hex(0x3a1d22);
    pub const RED600: Color32 = hex(0xb42318);
    pub const RED100: Color32 = hex(0xfde8e8);
    pub const GREEN400: Color32 = hex(0x3fb950);
    pub const GREEN700: Color32 = hex(0x1a7f37);
    pub const VIOLET400: Color32 = hex(0xb392f0);
    pub const VIOLET700: Color32 = hex(0x6639ba);
    pub const SP: [f32; 5] = [4.0, 8.0, 12.0, 16.0, 24.0];
    pub const RADIUS: [u8; 2] = [4, 6];
    pub const FONT: [f32; 4] = [12.0, 13.0, 15.0, 18.0];
}

/// Layer 2 — semantic roles.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Semantic {
    pub dark: bool,
    pub bg_app: Color32,
    pub bg_panel: Color32,
    pub bg_raised: Color32,
    pub bg_input: Color32,
    pub border: Color32,
    pub text_primary: Color32,
    pub text_muted: Color32,
    pub text_mono: Color32,
    pub accent: Color32,
    pub accent_weak: Color32,
    /// Row tint for WAL-only rows.
    pub walonly: Color32,
    pub walmod: Color32,
    pub removed: Color32,
    pub flag: Color32,
    pub exact: Color32,
    pub partial: Color32,
    pub heuristic: Color32,
    pub focus: Color32,
}

pub fn dark() -> Semantic {
    use prim::*;
    Semantic {
        dark: true,
        bg_app: N[1],
        bg_panel: N[2],
        bg_raised: N[3],
        bg_input: N[0],
        border: N[5],
        text_primary: N[9],
        text_muted: N[8],
        text_mono: N[9],
        accent: BLUE500,
        accent_weak: Color32::from_rgba_unmultiplied(0x1f, 0x6f, 0xeb, 0x40),
        walonly: AMBER900,
        walmod: Color32::from_rgb(0x2b, 0x24, 0x10),
        removed: Color32::from_rgb(0x2a, 0x1f, 0x3a),
        flag: RED400,
        exact: GREEN400,
        partial: AMBER400,
        heuristic: N[7],
        focus: BLUE500,
    }
}

pub fn light() -> Semantic {
    use prim::*;
    Semantic {
        dark: false,
        bg_app: N[10],
        bg_panel: WHITE,
        bg_raised: SLATE100,
        bg_input: WHITE,
        border: N[9],
        text_primary: SLATE700,
        text_muted: SLATE500,
        text_mono: SLATE700,
        accent: BLUE600,
        accent_weak: Color32::from_rgba_unmultiplied(0x1f, 0x6f, 0xeb, 0x30),
        walonly: AMBER100,
        walmod: Color32::from_rgb(0xfb, 0xf0, 0xd0),
        removed: Color32::from_rgb(0xef, 0xe7, 0xfb),
        flag: RED600,
        exact: GREEN700,
        partial: Color32::from_rgb(0x9a, 0x67, 0x00),
        heuristic: SLATE500,
        focus: BLUE700,
    }
}

/// Layer 3 — component sizes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Comp {
    pub row_h: f32,
    pub inspector_w: f32,
    pub facets_w: f32,
    pub hist_h: f32,
}

pub fn comp(compact: bool) -> Comp {
    Comp {
        row_h: if compact { 20.0 } else { 24.0 },
        inspector_w: 360.0,
        facets_w: 220.0,
        hist_h: 56.0,
    }
}

/// Windows system fonts used as fallbacks (read at start-up, never bundled — keeps the exe small):
/// Consolas for monospace (paths, hashes, times), Segoe UI and Segoe UI Symbol for symbols such as
/// ● ◐ ○ ▲ ★ ≈ → that the built-in font lacks. Missing files are skipped.
pub fn install_fonts(ctx: &egui::Context) {
    use egui::epaint::text::{FontInsert, FontPriority, InsertFontFamily};
    use egui::{FontData, FontFamily};
    let dir = std::env::var_os("WINDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "C:\\Windows".into())
        .join("Fonts");
    let fonts: [(&str, &str, &[(FontFamily, FontPriority)]); 3] = [
        (
            "consola",
            "consola.ttf",
            &[(FontFamily::Monospace, FontPriority::Highest)],
        ),
        (
            "segoeui",
            "segoeui.ttf",
            &[
                (FontFamily::Proportional, FontPriority::Lowest),
                (FontFamily::Monospace, FontPriority::Lowest),
            ],
        ),
        (
            "seguisym",
            "seguisym.ttf",
            &[
                (FontFamily::Proportional, FontPriority::Lowest),
                (FontFamily::Monospace, FontPriority::Lowest),
            ],
        ),
    ];
    for (name, file, fams) in fonts {
        if let Ok(bytes) = std::fs::read(dir.join(file)) {
            ctx.add_font(FontInsert {
                name: name.into(),
                data: FontData::from_owned(bytes),
                families: fams
                    .iter()
                    .map(|(family, priority)| InsertFontFamily {
                        family: family.clone(),
                        priority: *priority,
                    })
                    .collect(),
            });
        }
    }
}

/// Map the semantic tokens onto egui's visuals and spacing.
pub fn apply(ctx: &egui::Context, s: &Semantic, _c: &Comp) {
    let mut v = if s.dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    v.panel_fill = s.bg_panel;
    v.window_fill = s.bg_raised;
    v.extreme_bg_color = s.bg_input;
    v.faint_bg_color = s.bg_raised;
    v.override_text_color = Some(s.text_primary);
    v.hyperlink_color = s.accent;
    v.selection.bg_fill = s.accent_weak;
    v.selection.stroke = Stroke::new(1.0, s.focus);
    v.window_stroke = Stroke::new(1.0, s.border);
    let r = CornerRadius::same(prim::RADIUS[0]);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = r;
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, s.border);
    v.widgets.noninteractive.bg_fill = s.bg_panel;
    v.widgets.inactive.bg_fill = s.bg_raised;
    v.widgets.inactive.weak_bg_fill = s.bg_raised;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, s.accent);
    v.widgets.active.bg_fill = s.accent_weak;
    // Pin the theme so a Windows light/dark switch cannot swap egui to its own default style underneath.
    let t = if s.dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    };
    ctx.set_theme(if s.dark {
        egui::ThemePreference::Dark
    } else {
        egui::ThemePreference::Light
    });
    ctx.set_visuals_of(t, v);
    ctx.global_style_mut(|st| {
        st.spacing.item_spacing = egui::vec2(prim::SP[1], prim::SP[0] + 2.0);
        st.spacing.button_padding = egui::vec2(prim::SP[1], prim::SP[0]);
        st.spacing.window_margin = egui::Margin::same(prim::SP[2] as i8);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lum(c: Color32) -> f64 {
        let ch = |v: u8| {
            let s = v as f64 / 255.0;
            if s <= 0.03928 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * ch(c.r()) + 0.7152 * ch(c.g()) + 0.0722 * ch(c.b())
    }

    fn contrast(a: Color32, b: Color32) -> f64 {
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn text_contrast_at_least_4_5() {
        for s in [dark(), light()] {
            for bg in [s.bg_app, s.bg_panel, s.bg_raised, s.bg_input] {
                for fg in [s.text_primary, s.text_muted, s.text_mono] {
                    assert!(
                        contrast(fg, bg) >= 4.5,
                        "{fg:?} on {bg:?}: {:.2}",
                        contrast(fg, bg)
                    );
                }
            }
        }
    }

    #[test]
    fn component_sizes() {
        assert_eq!(comp(true).row_h, 20.0);
        assert_eq!(comp(false).row_h, 24.0);
        assert_eq!(
            (
                comp(true).inspector_w,
                comp(true).facets_w,
                comp(true).hist_h
            ),
            (360.0, 220.0, 56.0)
        );
    }
}
