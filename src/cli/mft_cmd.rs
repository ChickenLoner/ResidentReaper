use std::fs::File;
use std::io::BufWriter;

use indicatif::{ProgressBar, ProgressStyle};

use crate::core::mft_csv::MftCsvRow;
use crate::core::mft_parser;
use crate::core::types::Result;

use super::MftArgs;

pub fn run(args: MftArgs) -> Result<()> {
    eprintln!(
        "ResidentSpecter - Parsing $MFT: {}",
        args.file.display()
    );

    // Get total entry count for progress bar
    let total = mft_parser::get_entry_count(&args.file)?;

    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} entries ({per_sec})")
            .unwrap()
            .progress_chars("=>-"),
    );

    // Set up CSV writer
    let file = File::create(&args.output)?;
    let buf_writer = BufWriter::new(file);
    let mut csv_writer = csv::Writer::from_writer(buf_writer);

    let mut count: u64 = 0;

    mft_parser::parse_mft_entries(&args.file, args.allocated_only, |info| {
        let row: MftCsvRow = info.into();
        csv_writer.serialize(&row).map_err(|e| {
            crate::core::types::SpecterError::Csv(e.to_string())
        })?;

        count += 1;
        if count % 1000 == 0 {
            pb.set_position(count);
        }

        Ok(())
    })?;

    csv_writer.flush().map_err(|e| {
        crate::core::types::SpecterError::Io(e)
    })?;

    pb.finish_with_message("done");

    eprintln!(
        "Complete. {} entries written to {}",
        count,
        args.output.display()
    );

    Ok(())
}
