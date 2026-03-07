use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc;

use eframe::egui;

use crate::core::resident::ResidentEntry;
use super::export;
use super::filters::FilterState;
use super::table_view::{self, SortColumn};

enum ParseMessage {
    Progress(u64, u64),
    Entry(ResidentEntry),
    Done { total_scanned: u64 },
    Error(String),
}

enum ParseState {
    Idle,
    Parsing {
        progress: f32,
        entries_found: usize,
    },
    Done {
        total_entries: u64,
        resident_found: usize,
    },
    Error(String),
}

pub struct ResidentHunterApp {
    // File state
    mft_path: Option<PathBuf>,

    // Parse state
    parse_state: ParseState,
    entries: Vec<ResidentEntry>,
    filtered_indices: Vec<usize>,
    sorted_indices: Vec<usize>,

    // Filter state
    filters: FilterState,

    // Selection state
    selected: HashSet<usize>,

    // Sort state
    sort_column: SortColumn,
    sort_ascending: bool,

    // Background work
    parse_rx: Option<mpsc::Receiver<ParseMessage>>,

    // Status message
    status_message: String,
}

impl ResidentHunterApp {
    pub fn new(_cc: &eframe::CreationContext<'_>, mft_path: Option<PathBuf>) -> Self {
        let mut app = Self {
            mft_path: mft_path.clone(),
            parse_state: ParseState::Idle,
            entries: Vec::new(),
            filtered_indices: Vec::new(),
            sorted_indices: Vec::new(),
            filters: FilterState::default(),
            selected: HashSet::new(),
            sort_column: SortColumn::default(),
            sort_ascending: true,
            parse_rx: None,
            status_message: String::from("Ready. Open an $MFT file to begin scanning."),
        };

        // Auto-load if path was provided
        if let Some(path) = mft_path {
            app.start_parsing(path);
        }

        app
    }

    fn start_parsing(&mut self, path: PathBuf) {
        self.mft_path = Some(path.clone());
        self.entries.clear();
        self.filtered_indices.clear();
        self.sorted_indices.clear();
        self.selected.clear();
        self.parse_state = ParseState::Parsing {
            progress: 0.0,
            entries_found: 0,
        };

        let (tx, rx) = mpsc::channel();
        self.parse_rx = Some(rx);

        std::thread::spawn(move || {
            let result = crate::core::resident::scan_resident_data(
                &path,
                |entry| {
                    let _ = tx.send(ParseMessage::Entry(entry));
                },
                |current, total| {
                    let _ = tx.send(ParseMessage::Progress(current, total));
                },
            );

            match result {
                Ok(scan_result) => {
                    let _ = tx.send(ParseMessage::Done {
                        total_scanned: scan_result.total_entries_scanned,
                    });
                }
                Err(e) => {
                    let _ = tx.send(ParseMessage::Error(e.to_string()));
                }
            }
        });
    }

    fn process_messages(&mut self) {
        if let Some(ref rx) = self.parse_rx {
            // Process all available messages this frame
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ParseMessage::Progress(current, total) => {
                        let progress = if total > 0 {
                            current as f32 / total as f32
                        } else {
                            0.0
                        };
                        self.parse_state = ParseState::Parsing {
                            progress,
                            entries_found: self.entries.len(),
                        };
                    }
                    ParseMessage::Entry(entry) => {
                        self.entries.push(entry);
                    }
                    ParseMessage::Done { total_scanned } => {
                        self.parse_state = ParseState::Done {
                            total_entries: total_scanned,
                            resident_found: self.entries.len(),
                        };
                        self.parse_rx = None;
                        self.refilter();
                        self.status_message = format!(
                            "Done. Scanned {} entries, found {} with resident data.",
                            total_scanned,
                            self.entries.len()
                        );
                        break;
                    }
                    ParseMessage::Error(e) => {
                        self.parse_state = ParseState::Error(e.clone());
                        self.parse_rx = None;
                        self.status_message = format!("Error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    fn refilter(&mut self) {
        if self.filters.is_active() {
            self.filtered_indices = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| self.filters.matches(e))
                .map(|(i, _)| i)
                .collect();
        } else {
            self.filtered_indices = (0..self.entries.len()).collect();
        }
        self.resort();
    }

    fn resort(&mut self) {
        self.sorted_indices = table_view::sort_indices(
            &self.entries,
            &self.filtered_indices,
            self.sort_column,
            self.sort_ascending,
        );
    }
}

impl eframe::App for ResidentHunterApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process background messages
        let was_parsing = matches!(self.parse_state, ParseState::Parsing { .. });
        self.process_messages();

        // Request repaint during parsing
        if matches!(self.parse_state, ParseState::Parsing { .. }) {
            ctx.request_repaint();
        }

        // Top panel: file open + status
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Open $MFT...").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Select $MFT file")
                        .pick_file()
                    {
                        self.start_parsing(path);
                    }
                }

                ui.separator();

                // Show current file
                if let Some(ref path) = self.mft_path {
                    ui.label(format!("File: {}", path.display()));
                }

                ui.separator();

                // Status
                match &self.parse_state {
                    ParseState::Idle => {
                        ui.label(&self.status_message);
                    }
                    ParseState::Parsing {
                        progress,
                        entries_found,
                    } => {
                        ui.spinner();
                        ui.label(format!(
                            "Scanning... {:.1}% ({} resident found)",
                            progress * 100.0,
                            entries_found
                        ));
                    }
                    ParseState::Done {
                        total_entries,
                        resident_found,
                    } => {
                        ui.label(format!(
                            "Scanned {} entries | {} resident found | {} shown",
                            total_entries,
                            resident_found,
                            self.filtered_indices.len()
                        ));
                    }
                    ParseState::Error(e) => {
                        ui.colored_label(egui::Color32::RED, format!("Error: {}", e));
                    }
                }
            });

            // Progress bar during parsing
            if let ParseState::Parsing { progress, .. } = &self.parse_state {
                ui.add(egui::ProgressBar::new(*progress).show_percentage());
            }
        });

        // Filter panel
        egui::TopBottomPanel::top("filter_panel").show(ctx, |ui| {
            if self.filters.ui(ui) {
                self.refilter();
            }
        });

        // Hex viewer panel (shown when exactly one entry is selected)
        if self.selected.len() == 1 {
            if let Some(&idx) = self.selected.iter().next() {
                let entry = &self.entries[idx];
                egui::TopBottomPanel::bottom("hex_panel")
                    .resizable(true)
                    .default_height(200.0)
                    .min_height(100.0)
                    .max_height(400.0)
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(format!(
                                "Hex View: {} ({} bytes)",
                                entry.file_name, entry.data_size
                            ));
                            if ui.button("Copy Hex").clicked() {
                                let hex = export::bytes_to_hex(&entry.data);
                                ctx.copy_text(hex);
                                self.status_message = "Hex copied to clipboard.".to_string();
                            }
                            if ui.button("Copy ASCII").clicked() {
                                let ascii = export::bytes_to_ascii(&entry.data);
                                ctx.copy_text(ascii);
                                self.status_message = "ASCII copied to clipboard.".to_string();
                            }
                            if ui.button("Copy Hex Dump").clicked() {
                                let dump = format_hex_dump(&entry.data);
                                ctx.copy_text(dump);
                                self.status_message = "Hex dump copied to clipboard.".to_string();
                            }
                        });
                        ui.separator();
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut format_hex_dump(&entry.data).as_str())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .interactive(false),
                            );
                        });
                    });
            }
        }

        // Bottom panel: export buttons
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let selected_count = self.selected.len();

                if ui
                    .add_enabled(
                        selected_count > 0,
                        egui::Button::new(format!("Export Selected ({})", selected_count)),
                    )
                    .clicked()
                {
                    self.export_selected();
                }

                if ui
                    .add_enabled(
                        !self.filtered_indices.is_empty(),
                        egui::Button::new(format!(
                            "Export All Filtered ({})",
                            self.filtered_indices.len()
                        )),
                    )
                    .clicked()
                {
                    self.export_filtered();
                }

                ui.separator();
                ui.label(&self.status_message);
            });
        });

        // Central panel: table
        egui::CentralPanel::default().show(ctx, |ui| {
            let prev_sort_col = self.sort_column;
            let prev_sort_asc = self.sort_ascending;

            table_view::draw_table(
                ui,
                &self.entries,
                &self.filtered_indices,
                &mut self.selected,
                &mut self.sort_column,
                &mut self.sort_ascending,
                &self.sorted_indices,
            );

            // Re-sort if sort changed
            if self.sort_column != prev_sort_col || self.sort_ascending != prev_sort_asc {
                self.resort();
            }
        });

        // If parsing just finished, refilter
        if was_parsing && !matches!(self.parse_state, ParseState::Parsing { .. }) {
            self.refilter();
        }
    }
}

impl ResidentHunterApp {
    fn export_selected(&mut self) {
        if self.selected.is_empty() {
            return;
        }

        if let Some(dir) = rfd::FileDialog::new()
            .set_title("Select export directory")
            .pick_folder()
        {
            let entries_to_export: Vec<&ResidentEntry> = self
                .selected
                .iter()
                .filter_map(|&i| self.entries.get(i))
                .collect();

            match export::export_entries_to_directory(&entries_to_export, &dir) {
                Ok(count) => {
                    self.status_message =
                        format!("Exported {} files to {}", count, dir.display());
                }
                Err(e) => {
                    self.status_message = format!("Export error: {}", e);
                }
            }
        }
    }

    fn export_filtered(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }

        if let Some(dir) = rfd::FileDialog::new()
            .set_title("Select export directory")
            .pick_folder()
        {
            let entries_to_export: Vec<&ResidentEntry> = self
                .filtered_indices
                .iter()
                .filter_map(|&i| self.entries.get(i))
                .collect();

            match export::export_entries_to_directory(&entries_to_export, &dir) {
                Ok(count) => {
                    self.status_message =
                        format!("Exported {} files to {}", count, dir.display());
                }
                Err(e) => {
                    self.status_message = format!("Export error: {}", e);
                }
            }
        }
    }
}

/// Format bytes as a classic hex dump: offset | hex bytes | ASCII
fn format_hex_dump(data: &[u8]) -> String {
    let mut result = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        result.push_str(&format!("{:08X}  ", offset));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            result.push_str(&format!("{:02X} ", byte));
            if j == 7 {
                result.push(' ');
            }
        }
        // Pad if less than 16 bytes
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                result.push_str("   ");
                if j == 7 {
                    result.push(' ');
                }
            }
        }

        result.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }
        result.push_str("|\n");
    }
    result
}
