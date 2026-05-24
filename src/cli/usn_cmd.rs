use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;

use indicatif::{ProgressBar, ProgressStyle};

use crate::core::mft_csv::MftCsvRow;
use crate::core::mft_parser;
use crate::core::types::Result;
use crate::core::usn_csv::UsnCsvRow;
use crate::core::usn_parser::{self, UsnPathEntry};

use super::UsnArgs;

const RENAME_OLD_NAME: u32 = 0x00001000;

/// Path entry with sequence number for validation.
struct PathInfo {
    path: String,
    sequence_number: u16,
}

/// Resolve full path for a given (entry, seq) pair.
/// Priority: rewind map (historical state) → MFT (current state) → PathUnknown.
/// Rewind map reflects filesystem state at the moment of the USN event being resolved.
/// Depth limit of 64 prevents cycles from corrupt parent references.
fn resolve_full_path(
    entry: u64,
    seq: u16,
    rewind_map: &HashMap<(u64, u16), UsnPathEntry>,
    mft_paths: &[Option<PathInfo>],
    depth: u8,
) -> String {
    if depth == 0 {
        return format!(".\\PathUnknown\\Directory with ID 0x{:08X}-{:08X}", entry, seq);
    }
    if entry == 5 {
        return ".".to_string();
    }

    // Rewind map first: reflects historical name at the moment of the event
    if let Some(rewind_entry) = rewind_map.get(&(entry, seq)) {
        if rewind_entry.parent_entry_number == entry {
            return format!(".\\PathUnknown\\Directory with ID 0x{:08X}-{:08X}", entry, seq);
        }
        let parent_path = resolve_full_path(
            rewind_entry.parent_entry_number,
            rewind_entry.parent_sequence_number,
            rewind_map,
            mft_paths,
            depth - 1,
        );
        if parent_path == "." {
            return format!(".\\{}", rewind_entry.name);
        }
        return format!("{}\\{}", parent_path, rewind_entry.name);
    }

    // MFT fallback: for entries never seen in journal (no rename history)
    if let Some(Some(info)) = mft_paths.get(entry as usize) {
        if info.sequence_number == seq {
            return info.path.clone();
        }
    }

    format!(".\\PathUnknown\\Directory with ID 0x{:08X}-{:08X}", entry, seq)
}

pub fn run(args: UsnArgs) -> Result<()> {
    let auto_named = args.output.is_none();
    let output = args.output.unwrap_or_else(|| super::default_output_name("J"));

    eprintln!("ResidentReaper - Parsing $J: {}", args.file.display());

    // Optionally parse MFT: build parent path lookup AND write MFT CSV
    let parent_paths: Vec<Option<PathInfo>> = if let Some(ref mft_path) = args.mft {
        eprintln!("Loading $MFT for path resolution: {}", mft_path.display());

        let mft_output = derive_mft_output_path(&output, auto_named);
        eprintln!("Also writing MFT output to: {}", mft_output.display());

        let total = mft_parser::get_entry_count(mft_path)?;
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} MFT entries ({per_sec})")
                .unwrap()
                .progress_chars("=>-"),
        );

        let mft_file = File::create(&mft_output)?;
        let mft_buf = BufWriter::with_capacity(256 * 1024, mft_file);
        let mut mft_csv_writer = csv::Writer::from_writer(mft_buf);

        let mut path_vec: Vec<Option<PathInfo>> = (0..total as usize).map(|_| None).collect();
        let mut mft_count: u64 = 0;

        mft_parser::parse_mft_entries(mft_path, false, |info| {
            if !info.is_ads {
                let idx = info.entry_number as usize;
                if idx < path_vec.len() {
                    let full_path = if info.parent_path == "." && info.file_name == "." {
                        ".".to_string()
                    } else if info.parent_path == "." {
                        let mut s = String::with_capacity(2 + info.file_name.len());
                        s.push_str(".\\");
                        s.push_str(&info.file_name);
                        s
                    } else {
                        let mut s = String::with_capacity(info.parent_path.len() + 1 + info.file_name.len());
                        s.push_str(&info.parent_path);
                        s.push('\\');
                        s.push_str(&info.file_name);
                        s
                    };
                    path_vec[idx] = Some(PathInfo {
                        path: full_path,
                        sequence_number: info.sequence_number,
                    });
                }
            }

            let row: MftCsvRow = info.into();
            mft_csv_writer.serialize(&row).map_err(|e| {
                crate::core::types::ReaperError::Csv(e.to_string())
            })?;

            mft_count += 1;
            if mft_count % 1000 == 0 {
                pb.set_position(mft_count);
            }

            Ok(())
        })?;

        mft_csv_writer.flush().map_err(|e| crate::core::types::ReaperError::Io(e))?;
        pb.finish_with_message("done");
        eprintln!("MFT: {} entries written to {}", mft_count, mft_output.display());

        path_vec
    } else {
        Vec::new()
    };

    let source_file = {
        let fname = args.file.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("$J");
        format!(".\\{}", fname)
    };

    // Collect all records into memory for reverse-chronological path resolution
    eprintln!("Collecting USN records...");
    let file_size = std::fs::metadata(&args.file)?.len();
    let pb_collect = ProgressBar::new(file_size);
    pb_collect.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.green/black}] {bytes}/{total_bytes} ({per_sec}) collecting")
            .unwrap()
            .progress_chars("=>-"),
    );
    let records = usn_parser::collect_records(&args.file)?;
    pb_collect.finish_and_clear();
    eprintln!("Collected {} records", records.len());

    let has_paths = !parent_paths.is_empty();
    let n = records.len();

    // Pre-compute parent paths for every record
    let resolved_paths: Vec<String> = if !args.raw {
        // True reverse-chronological rewind:
        // Walk records newest→oldest, maintaining a rewind map of each entry's name
        // at each point in time. RenameOldName events expose the pre-rename name for
        // all chronologically earlier records.
        eprintln!("Computing historical paths (rewind)...");
        let pb_rewind = ProgressBar::new(n as u64);
        pb_rewind.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.yellow/black}] {pos}/{len} records ({per_sec}) rewinding")
                .unwrap()
                .progress_chars("=>-"),
        );

        let mut rewind_map: HashMap<(u64, u16), UsnPathEntry> = HashMap::new();
        let mut paths = vec![String::new(); n];

        for i in (0..n).rev() {
            let record = &records[i];

            // Resolve parent path BEFORE updating the map for this record.
            // The map reflects state from records [i+1..n], i.e. what happened
            // AFTER the current event — which is what was true at the moment of event i.
            paths[i] = resolve_full_path(
                record.parent_entry_number,
                record.parent_sequence_number,
                &rewind_map,
                &parent_paths,
                64,
            );

            // Update map to expose pre-event name for chronologically earlier records.
            let key = (record.entry_number, record.sequence_number);
            if record.reason & RENAME_OLD_NAME != 0 {
                // This record IS the old-name event: overwrite so earlier records
                // see the name that existed before this rename.
                rewind_map.insert(key, UsnPathEntry {
                    name: record.name.clone(),
                    parent_entry_number: record.parent_entry_number,
                    parent_sequence_number: record.parent_sequence_number,
                });
            } else {
                // Only insert if not yet seen: first insertion going backwards = most
                // recent state, which is the name at the time of all prior events
                // (unless a later RenameOldName overwrites it).
                rewind_map.entry(key).or_insert_with(|| UsnPathEntry {
                    name: record.name.clone(),
                    parent_entry_number: record.parent_entry_number,
                    parent_sequence_number: record.parent_sequence_number,
                });
            }

            let processed = n - i;
            if processed % 10_000 == 0 {
                pb_rewind.set_position(processed as u64);
            }
        }

        pb_rewind.finish_and_clear();
        eprintln!("Rewind complete. Rewind map: {} entries", rewind_map.len());
        paths
    } else {
        // --raw: MFT-only resolution, no rewind
        records.iter().map(|record| {
            if !has_paths {
                return String::new();
            }
            let idx = record.parent_entry_number as usize;
            if idx < parent_paths.len() {
                match &parent_paths[idx] {
                    Some(info) if info.sequence_number == record.parent_sequence_number => {
                        info.path.clone()
                    }
                    _ => format!(
                        ".\\PathUnknown\\Directory with ID 0x{:08X}-{:08X}",
                        record.parent_entry_number,
                        record.parent_sequence_number
                    ),
                }
            } else {
                format!(
                    ".\\PathUnknown\\Directory with ID 0x{:08X}-{:08X}",
                    record.parent_entry_number,
                    record.parent_sequence_number
                )
            }
        }).collect()
    };

    // Write CSV in original chronological order
    let file = File::create(&output)?;
    let buf_writer = BufWriter::with_capacity(256 * 1024, file);
    let mut csv_writer = csv::Writer::from_writer(buf_writer);

    let pb_write = ProgressBar::new(n as u64);
    pb_write.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.green/black}] {pos}/{len} records ({per_sec}) writing")
            .unwrap()
            .progress_chars("=>-"),
    );

    for (i, record) in records.into_iter().enumerate() {
        let row = UsnCsvRow::from_record(record, resolved_paths[i].clone(), source_file.clone());
        csv_writer.serialize(&row).map_err(|e| {
            crate::core::types::ReaperError::Csv(e.to_string())
        })?;
        if (i + 1) % 10_000 == 0 {
            pb_write.set_position((i + 1) as u64);
        }
    }

    csv_writer.flush().map_err(|e| crate::core::types::ReaperError::Io(e))?;
    pb_write.finish_and_clear();

    eprintln!("Complete. {} USN records written to {}", n, output.display());

    Ok(())
}

/// Derive MFT output CSV path alongside the USN output.
fn derive_mft_output_path(usn_output: &std::path::Path, auto_named: bool) -> std::path::PathBuf {
    if auto_named {
        let dir = usn_output.parent().unwrap_or(std::path::Path::new("."));
        dir.join(super::default_output_name("MFT"))
    } else {
        let stem = usn_output
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("output");
        let ext = usn_output
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("csv");
        let mft_name = format!("{}_MFT_Output.{}", stem, ext);
        usn_output.with_file_name(mft_name)
    }
}
