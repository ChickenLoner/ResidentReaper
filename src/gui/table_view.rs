use std::collections::HashSet;

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::core::resident::ResidentEntry;
use crate::core::types::format_timestamp_filetime;

/// Which column to sort by.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    EntryNumber,
    FileName,
    Extension,
    ParentPath,
    DataSize,
    Created,
    Modified,
    StreamName,
}

impl Default for SortColumn {
    fn default() -> Self {
        SortColumn::EntryNumber
    }
}

/// Draw the resident entries table. Returns true if selection changed.
pub fn draw_table(
    ui: &mut egui::Ui,
    entries: &[ResidentEntry],
    _filtered_indices: &[usize],
    selected: &mut HashSet<usize>,
    sort_column: &mut SortColumn,
    sort_ascending: &mut bool,
    sorted_indices: &[usize],
) -> bool {
    let mut selection_changed = false;

    let available_height = ui.available_height() - 40.0; // Reserve space for bottom bar

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(30.0)) // Checkbox
        .column(Column::initial(80.0).at_least(60.0)) // Entry#
        .column(Column::initial(200.0).at_least(100.0)) // FileName
        .column(Column::initial(60.0).at_least(40.0)) // Ext
        .column(Column::initial(250.0).at_least(100.0)) // ParentPath
        .column(Column::initial(80.0).at_least(60.0)) // Size
        .column(Column::initial(180.0).at_least(120.0)) // Created
        .column(Column::initial(180.0).at_least(120.0)) // Modified
        .column(Column::initial(100.0).at_least(60.0)) // Stream
        .min_scrolled_height(available_height)
        .max_scroll_height(available_height)
        .header(20.0, |mut header| {
            header.col(|ui| {
                // Select all checkbox
                let all_selected = !sorted_indices.is_empty()
                    && sorted_indices
                        .iter()
                        .all(|&i| selected.contains(&i));
                let mut check = all_selected;
                if ui.checkbox(&mut check, "").changed() {
                    if check {
                        for &i in sorted_indices {
                            selected.insert(i);
                        }
                    } else {
                        selected.clear();
                    }
                    selection_changed = true;
                }
            });
            let columns = [
                ("Entry#", SortColumn::EntryNumber),
                ("FileName", SortColumn::FileName),
                ("Ext", SortColumn::Extension),
                ("ParentPath", SortColumn::ParentPath),
                ("Size", SortColumn::DataSize),
                ("Created", SortColumn::Created),
                ("Modified", SortColumn::Modified),
                ("Stream", SortColumn::StreamName),
            ];
            for (label, col) in columns {
                header.col(|ui| {
                    let text = if *sort_column == col {
                        if *sort_ascending {
                            format!("{} ^", label)
                        } else {
                            format!("{} v", label)
                        }
                    } else {
                        label.to_string()
                    };
                    if ui.selectable_label(*sort_column == col, text).clicked() {
                        if *sort_column == col {
                            *sort_ascending = !*sort_ascending;
                        } else {
                            *sort_column = col;
                            *sort_ascending = true;
                        }
                    }
                });
            }
        })
        .body(|body| {
            body.rows(20.0, sorted_indices.len(), |mut row| {
                let display_idx = row.index();
                let entry_idx = sorted_indices[display_idx];
                let entry = &entries[entry_idx];

                row.col(|ui| {
                    let mut is_selected = selected.contains(&entry_idx);
                    if ui.checkbox(&mut is_selected, "").changed() {
                        if is_selected {
                            selected.insert(entry_idx);
                        } else {
                            selected.remove(&entry_idx);
                        }
                        selection_changed = true;
                    }
                });
                row.col(|ui| {
                    ui.label(entry.entry_number.to_string());
                });
                row.col(|ui| {
                    ui.label(&entry.file_name);
                });
                row.col(|ui| {
                    ui.label(&entry.extension);
                });
                row.col(|ui| {
                    ui.label(&entry.parent_path);
                });
                row.col(|ui| {
                    ui.label(format_size(entry.data_size));
                });
                row.col(|ui| {
                    ui.label(format_timestamp_filetime(entry.si_created));
                });
                row.col(|ui| {
                    ui.label(format_timestamp_filetime(entry.si_modified));
                });
                row.col(|ui| {
                    ui.label(&entry.stream_name);
                });
            });
        });

    selection_changed
}

/// Sort the filtered indices based on the selected column.
pub fn sort_indices(
    entries: &[ResidentEntry],
    filtered_indices: &[usize],
    column: SortColumn,
    ascending: bool,
) -> Vec<usize> {
    let mut sorted = filtered_indices.to_vec();

    sorted.sort_by(|&a, &b| {
        let ea = &entries[a];
        let eb = &entries[b];
        let cmp = match column {
            SortColumn::EntryNumber => ea.entry_number.cmp(&eb.entry_number),
            SortColumn::FileName => ea.file_name.to_lowercase().cmp(&eb.file_name.to_lowercase()),
            SortColumn::Extension => ea.extension.cmp(&eb.extension),
            SortColumn::ParentPath => ea.parent_path.to_lowercase().cmp(&eb.parent_path.to_lowercase()),
            SortColumn::DataSize => ea.data_size.cmp(&eb.data_size),
            SortColumn::Created => ea.si_created.cmp(&eb.si_created),
            SortColumn::Modified => ea.si_modified.cmp(&eb.si_modified),
            SortColumn::StreamName => ea.stream_name.cmp(&eb.stream_name),
        };
        if ascending { cmp } else { cmp.reverse() }
    });

    sorted
}

fn format_size(bytes: u32) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
