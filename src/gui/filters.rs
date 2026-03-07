use eframe::egui;

use crate::core::resident::ResidentEntry;

#[derive(Default)]
pub struct FilterState {
    pub search_filter: String,
    pub extension_filter: String,
    pub min_size: String,
    pub max_size: String,
}

impl FilterState {
    pub fn is_active(&self) -> bool {
        !self.search_filter.is_empty()
            || !self.extension_filter.is_empty()
            || !self.min_size.is_empty()
            || !self.max_size.is_empty()
    }

    pub fn matches(&self, entry: &ResidentEntry) -> bool {
        if !self.search_filter.is_empty() {
            let query = self.search_filter.to_lowercase();
            let full_path = if entry.parent_path.is_empty() || entry.parent_path == "." {
                entry.file_name.to_lowercase()
            } else {
                format!("{}\\{}", entry.parent_path, entry.file_name).to_lowercase()
            };
            if !full_path.contains(&query) {
                return false;
            }
        }

        if !self.extension_filter.is_empty() {
            let exts: Vec<&str> = self.extension_filter.split(',').map(|s| s.trim()).collect();
            let entry_ext = entry.extension.to_lowercase();
            if !exts.iter().any(|e| e.to_lowercase() == entry_ext) {
                return false;
            }
        }

        if !self.min_size.is_empty() {
            if let Ok(min) = self.min_size.parse::<u32>() {
                if entry.data_size < min {
                    return false;
                }
            }
        }

        if !self.max_size.is_empty() {
            if let Ok(max) = self.max_size.parse::<u32>() {
                if entry.data_size > max {
                    return false;
                }
            }
        }

        true
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Draw the filter panel UI. Returns true if filters changed.
    pub fn ui(&mut self, ui: &mut egui::Ui) -> bool {
        let mut changed = false;

        ui.horizontal(|ui| {
            ui.label("Filters:");
            ui.separator();

            ui.label("Search:");
            if ui
                .add(egui::TextEdit::singleline(&mut self.search_filter).desired_width(200.0))
                .changed()
            {
                changed = true;
            }

            ui.label("Ext:");
            let ext_response = ui.add(
                egui::TextEdit::singleline(&mut self.extension_filter).desired_width(80.0),
            );
            if ext_response.changed() {
                changed = true;
            }

            ui.label("Min Size:");
            let min_response = ui.add(
                egui::TextEdit::singleline(&mut self.min_size).desired_width(60.0),
            );
            if min_response.changed() {
                changed = true;
            }

            ui.label("Max Size:");
            let max_response = ui.add(
                egui::TextEdit::singleline(&mut self.max_size).desired_width(60.0),
            );
            if max_response.changed() {
                changed = true;
            }

            if ui.button("Clear").clicked() {
                self.clear();
                changed = true;
            }
        });

        changed
    }
}
