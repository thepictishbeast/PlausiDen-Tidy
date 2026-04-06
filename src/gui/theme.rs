//! Visual theme for the Tidy GUI.
//!
//! A civil-rights tool has to feel approachable, not like a tactical
//! hacker console. The palette leans warm-neutral with calm blues for
//! primary actions and clear red/yellow reserved exclusively for
//! destructive or risky operations.

use egui::{Color32, Style, Visuals};

/// Brand palette.
pub struct Palette;

impl Palette {
    pub const BG: Color32 = Color32::from_rgb(20, 22, 28);
    pub const BG_PANEL: Color32 = Color32::from_rgb(28, 30, 38);
    pub const BG_ELEVATED: Color32 = Color32::from_rgb(36, 40, 50);
    pub const ACCENT: Color32 = Color32::from_rgb(96, 160, 255);
    pub const ACCENT_DIM: Color32 = Color32::from_rgb(64, 120, 200);
    pub const TEXT: Color32 = Color32::from_rgb(235, 236, 240);
    pub const TEXT_DIM: Color32 = Color32::from_rgb(160, 164, 180);
    pub const BORDER: Color32 = Color32::from_rgb(48, 52, 62);

    pub const CRITICAL: Color32 = Color32::from_rgb(228, 94, 110);
    pub const HIGH: Color32 = Color32::from_rgb(240, 166, 92);
    pub const MEDIUM: Color32 = Color32::from_rgb(226, 200, 100);
    pub const LOW: Color32 = Color32::from_rgb(110, 180, 240);
    pub const TRASH: Color32 = Color32::from_rgb(120, 200, 140);
    pub const OK: Color32 = Color32::from_rgb(120, 200, 140);
    pub const WARN_BG: Color32 = Color32::from_rgb(80, 48, 30);
}

/// Install the Tidy theme into an egui context.
pub fn apply(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    install_visuals(&mut style);
    install_spacing(&mut style);
    ctx.set_style(style);
}

fn install_visuals(style: &mut Style) {
    let mut v = Visuals::dark();
    v.override_text_color = Some(Palette::TEXT);
    v.panel_fill = Palette::BG;
    v.window_fill = Palette::BG_PANEL;
    v.extreme_bg_color = Palette::BG;
    v.faint_bg_color = Palette::BG_PANEL;
    v.code_bg_color = Palette::BG_ELEVATED;

    v.widgets.noninteractive.bg_fill = Palette::BG_PANEL;
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, Palette::BORDER);
    v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, Palette::TEXT_DIM);

    v.widgets.inactive.bg_fill = Palette::BG_ELEVATED;
    v.widgets.inactive.weak_bg_fill = Palette::BG_PANEL;
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, Palette::BORDER);
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, Palette::TEXT);

    v.widgets.hovered.bg_fill = Palette::ACCENT_DIM;
    v.widgets.hovered.weak_bg_fill = Palette::BG_ELEVATED;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, Palette::ACCENT);
    v.widgets.hovered.fg_stroke = egui::Stroke::new(1.5, Palette::TEXT);

    v.widgets.active.bg_fill = Palette::ACCENT;
    v.widgets.active.weak_bg_fill = Palette::ACCENT_DIM;
    v.widgets.active.bg_stroke = egui::Stroke::new(1.5, Palette::ACCENT);
    v.widgets.active.fg_stroke = egui::Stroke::new(2.0, Palette::TEXT);

    v.selection.bg_fill = Palette::ACCENT_DIM;
    v.selection.stroke = egui::Stroke::new(1.5, Palette::ACCENT);

    v.window_rounding = egui::Rounding::same(10.0);
    v.menu_rounding = egui::Rounding::same(8.0);
    v.widgets.noninteractive.rounding = egui::Rounding::same(6.0);
    v.widgets.inactive.rounding = egui::Rounding::same(6.0);
    v.widgets.hovered.rounding = egui::Rounding::same(6.0);
    v.widgets.active.rounding = egui::Rounding::same(6.0);

    style.visuals = v;
}

fn install_spacing(style: &mut Style) {
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.menu_margin = egui::Margin::same(6.0);
    style.spacing.window_margin = egui::Margin::same(12.0);
    style.spacing.indent = 18.0;
}

/// Map an importance level to its badge colour.
pub fn importance_color(imp: crate::importance::Importance) -> Color32 {
    match imp {
        crate::importance::Importance::Critical => Palette::CRITICAL,
        crate::importance::Importance::High => Palette::HIGH,
        crate::importance::Importance::Medium => Palette::MEDIUM,
        crate::importance::Importance::Low => Palette::LOW,
        crate::importance::Importance::Trash => Palette::TRASH,
    }
}

/// Label text for an importance level.
pub fn importance_label(imp: crate::importance::Importance) -> &'static str {
    match imp {
        crate::importance::Importance::Critical => "CRITICAL",
        crate::importance::Importance::High => "HIGH",
        crate::importance::Importance::Medium => "MEDIUM",
        crate::importance::Importance::Low => "LOW",
        crate::importance::Importance::Trash => "TRASH",
    }
}
