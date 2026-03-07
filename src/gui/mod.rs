mod app;
mod table_view;
mod filters;
mod export;

use std::path::PathBuf;

pub fn launch(mft_path: Option<PathBuf>) {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("ResidentReaper - Resident Hunter")
            .with_inner_size([1200.0, 800.0])
            .with_icon(load_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "ResidentReaper",
        options,
        Box::new(move |cc| {
            Ok(Box::new(app::ResidentHunterApp::new(cc, mft_path)))
        }),
    )
    .expect("Failed to launch GUI");
}

fn load_icon() -> eframe::egui::IconData {
    let icon_bytes = include_bytes!("../../icon.png");
    let image = image::load_from_memory(icon_bytes)
        .expect("Failed to decode icon.png")
        .into_rgba8();
    let (width, height) = image.dimensions();
    eframe::egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    }
}
