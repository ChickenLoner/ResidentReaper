use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;

use indicatif::{ProgressBar, ProgressStyle};

use crate::core::mft_parser;
use crate::core::types::Result;
use crate::core::usn_csv::UsnCsvRow;
use crate::core::usn_parser;

use super::UsnArgs;

pub fn run(args: UsnArgs) -> Result<()> {
    eprintln!(
        "ResidentReaper - Parsing $J: {}",
        args.file.display()
    );

    // Optionally build a parent path lookup from MFT
    let parent_paths = if let Some(ref mft_path) = args.mft {
        eprintln!("Loading $MFT for path resolution: {}", mft_path.display());
        build_path_map(mft_path)?
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
    let file = File::create(&args.output)?;
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
        args.output.display()
    );

    Ok(())
}

/// Build a map of entry_number -> full_path from an MFT file for parent path resolution.
fn build_path_map(mft_path: &std::path::Path) -> Result<HashMap<u64, String>> {
    let mut map = HashMap::new();

    mft_parser::parse_mft_entries(mft_path, false, |info| {
        // Only store non-ADS rows for path lookup
        if !info.is_ads {
            let full_path = if info.parent_path == "." {
                format!(".\\{}", info.file_name)
            } else {
                format!("{}\\{}", info.parent_path, info.file_name)
            };
            map.insert(info.entry_number, full_path);
        }
        Ok(())
    })?;

    Ok(map)
}
