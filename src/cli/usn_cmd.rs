use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;

use indicatif::{ProgressBar, ProgressStyle};

use crate::core::mft_csv::MftCsvRow;
use crate::core::mft_parser;
use crate::core::types::Result;
use crate::core::usn_csv::UsnCsvRow;
use crate::core::usn_parser;

use super::UsnArgs;

pub fn run(args: UsnArgs) -> Result<()> {
    let auto_named = args.output.is_none();
    let output = args.output.unwrap_or_else(|| super::default_output_name("J"));

    eprintln!(
        "ResidentReaper - Parsing $J: {}",
        args.file.display()
    );

    // Optionally parse MFT: build parent path lookup AND write MFT CSV
    let parent_paths = if let Some(ref mft_path) = args.mft {
        eprintln!("Loading $MFT for path resolution: {}", mft_path.display());

        // Derive MFT output path: use timestamp-based name in same directory as USN output
        let mft_output = derive_mft_output_path(&output, auto_named);
        eprintln!("Also writing MFT output to: {}", mft_output.display());

        let mft_source_file = mft_path.display().to_string();

        // Get total entry count for progress bar
        let total = mft_parser::get_entry_count(mft_path)?;
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} MFT entries ({per_sec})")
                .unwrap()
                .progress_chars("=>-"),
        );

        // Set up MFT CSV writer
        let mft_file = File::create(&mft_output)?;
        let mft_buf = BufWriter::new(mft_file);
        let mut mft_csv_writer = csv::Writer::from_writer(mft_buf);

        let mut map = HashMap::new();
        let mut mft_count: u64 = 0;

        mft_parser::parse_mft_entries(mft_path, false, |info| {
            // Build path map from non-ADS entries
            if !info.is_ads {
                let full_path = if info.parent_path == "." {
                    format!(".\\{}", info.file_name)
                } else {
                    format!("{}\\{}", info.parent_path, info.file_name)
                };
                map.insert(info.entry_number, full_path);
            }

            // Write MFT CSV row
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

        mft_csv_writer.flush().map_err(|e| {
            crate::core::types::ReaperError::Io(e)
        })?;

        pb.finish_with_message("done");
        eprintln!(
            "MFT: {} entries written to {}",
            mft_count,
            mft_output.display()
        );

        map
    } else {
        HashMap::new()
    };

    // Source file name (MFTECmd uses the path as provided on command line)
    let source_file = args.file.display().to_string();

    // Get file size for progress
    let file_size = std::fs::metadata(&args.file)?.len();
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.green/black}] {bytes}/{total_bytes} ({per_sec})")
            .unwrap()
            .progress_chars("=>-"),
    );

    // Set up CSV writer
    let file = File::create(&output)?;
    let buf_writer = BufWriter::new(file);
    let mut csv_writer = csv::Writer::from_writer(buf_writer);

    let mut count: u64 = 0;

    usn_parser::parse_usn_journal(&args.file, |record| {
        let parent_path = parent_paths
            .get(&record.parent_entry_number)
            .cloned()
            .unwrap_or_default();

        let row = UsnCsvRow::from_record(record, parent_path, source_file.clone());
        csv_writer.serialize(&row).map_err(|e| {
            crate::core::types::ReaperError::Csv(e.to_string())
        })?;

        count += 1;
        if count % 5000 == 0 {
            pb.set_position(count * 100); // Approximate progress
        }

        Ok(())
    })?;

    csv_writer.flush().map_err(|e| {
        crate::core::types::ReaperError::Io(e)
    })?;

    pb.finish_with_message("done");

    eprintln!(
        "Complete. {} USN records written to {}",
        count,
        output.display()
    );

    Ok(())
}

/// Derive MFT output CSV path.
/// If auto-named (no -o given), use timestamp format in same directory.
/// If user specified -o, derive from that name: e.g., "usn.csv" -> "usn_MFT_Output.csv"
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
