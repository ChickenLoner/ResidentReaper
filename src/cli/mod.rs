pub mod mft_cmd;
pub mod usn_cmd;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::core::types::Result;

#[derive(Parser)]
#[command(
    name = "ResidentReaper",
    version,
    about = "NTFS forensic tool - MFT/USN parser and resident data hunter",
    long_about = "\
ResidentReaper - A fast NTFS forensic tool written in Rust

Parses $MFT and $J (USN Journal) artifacts from NTFS file systems,
and hunts for resident data hidden inside MFT entries.

MODES:
  mft   Parse $MFT to CSV (MFTECmd-compatible, 34 columns)
  usn   Parse $J (USN Journal) to CSV (13 columns)
  hunt  Launch Resident Hunter GUI to browse/export resident data

EXAMPLES:
  Parse $MFT to CSV:
    ResidentReaper mft -f \\$MFT -o mft_output.csv

  Parse $MFT (allocated entries only):
    ResidentReaper mft -f \\$MFT -o mft_output.csv --allocated-only

  Parse USN Journal:
    ResidentReaper usn -f \\$J -o usn_output.csv

  Parse USN Journal with path resolution (also outputs MFT CSV):
    ResidentReaper usn -f \\$J -o usn_output.csv --mft \\$MFT

  Launch Resident Hunter GUI:
    ResidentReaper hunt

  Launch Resident Hunter GUI with pre-loaded MFT:
    ResidentReaper hunt -f \\$MFT",
    after_help = "\
OUTPUT DETAILS:
  MFT CSV (34 columns):
    EntryNumber, SequenceNumber, InUse, ParentEntryNumber,
    ParentSequenceNumber, ParentPath, FileName, Extension, FileSize,
    ReferenceCount, ReparseTarget, IsDirectory, HasAds, IsAds, SI<FN,
    uSecZeros, Copied, SiFlags, NameType, Created0x10, Created0x30,
    LastModified0x10, LastModified0x30, LastRecordChange0x10,
    LastRecordChange0x30, LastAccess0x10, LastAccess0x30,
    UpdateSequenceNumber, LogfileSequenceNumber, SecurityId,
    ObjectIdFileDroid, LoggedUtilStream, ZoneIdContents, SourceFile

  USN Journal CSV (13 columns):
    Name, Extension, EntryNumber, SequenceNumber, ParentEntryNumber,
    ParentSequenceNumber, ParentPath, UpdateSequenceNumber,
    UpdateTimestamp, UpdateReasons, FileAttributes, OffsetToData,
    SourceFile

NOTE:
  When using 'usn --mft', the MFT is parsed in a single pass to both
  resolve parent paths for USN records and produce a full MFT CSV output
  (saved as <usn_output>_MFT_Output.csv alongside the USN output)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Parse $MFT file and output CSV (MFTECmd-compatible, 34 columns)
    #[command(
        long_about = "\
Parse an NTFS $MFT file and output a CSV with 34 columns, compatible
with MFTECmd output format (99.997% cell accuracy, identical row counts).

Includes forensic flags: SI<FN timestamp anomalies, uSecZeros, Copied.
Detects ADS (Alternate Data Streams) and extracts Zone.Identifier content."
    )]
    Mft(MftArgs),

    /// Parse $J (USN Journal) file and output CSV (13 columns)
    #[command(
        long_about = "\
Parse an NTFS $J (USN Journal / UsnJrnl:$J) file and output a CSV
with 13 columns, compatible with MFTECmd output format.

When --mft is provided:
  - Parent paths are resolved using the MFT
  - A full MFT CSV is also produced (saved as <output>_MFT_Output.csv)"
    )]
    Usn(UsnArgs),

    /// Launch Resident Hunter GUI - browse and export resident data from MFT
    #[command(
        long_about = "\
Launch the Resident Hunter GUI to scan MFT entries for resident data
(files stored inline within MFT records, typically under 700 bytes).

Features:
  - Scan $MFT and find all resident files
  - Search/filter by path, extension, or size range
  - View hex dump of resident data inline
  - Copy hex, ASCII, or full hex dump to clipboard
  - Export selected or filtered entries to a directory"
    )]
    Hunt(HuntArgs),
}

#[derive(clap::Args)]
pub struct MftArgs {
    /// Path to $MFT file
    #[arg(short, long)]
    pub file: PathBuf,

    /// Path to output CSV file
    #[arg(short, long)]
    pub output: PathBuf,

    /// Only output allocated (in-use) entries
    #[arg(long, default_value_t = false)]
    pub allocated_only: bool,

    /// Increase logging verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(clap::Args)]
pub struct UsnArgs {
    /// Path to $J / UsnJrnl:$J file
    #[arg(short, long)]
    pub file: PathBuf,

    /// Path to output CSV file
    #[arg(short, long)]
    pub output: PathBuf,

    /// Provide $MFT to resolve parent paths and also output MFT CSV
    #[arg(long)]
    pub mft: Option<PathBuf>,

    /// Increase logging verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(clap::Args)]
pub struct HuntArgs {
    /// Pre-load this $MFT file on startup
    #[arg(short, long)]
    pub file: Option<PathBuf>,
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Mft(args) => mft_cmd::run(args),
        Commands::Usn(args) => usn_cmd::run(args),
        Commands::Hunt(args) => {
            #[cfg(feature = "gui")]
            {
                crate::gui::launch(args.file);
                Ok(())
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = args;
                eprintln!("GUI not compiled. Rebuild with: cargo build --features gui");
                std::process::exit(1);
            }
        }
    }
}
