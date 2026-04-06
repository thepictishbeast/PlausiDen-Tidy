//! `tidy-gui` — the primary desktop interface for PlausiDen-Tidy.

use plausiden_tidy::gui::TidyApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("PlausiDen Tidy"),
        ..Default::default()
    };

    eframe::run_native(
        "PlausiDen Tidy",
        options,
        Box::new(|cc| Ok(Box::new(TidyApp::new(cc)))),
    )
}
