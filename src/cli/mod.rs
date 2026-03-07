pub mod mft_cmd;
pub mod usn_cmd;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::core::types::Result;

#[derive(Parser)]
#[command(
    name = "ResidentReaper",
    version,
    about = "NTFS forensic tool - MFT/USN parser and resident data hunter"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Parse $MFT file and output CSV (MFTECmd-compatible)
    Mft(MftArgs),

    /// Parse $J (USN Journal) file and output CSV
    Usn(UsnArgs),

    /// Launch Resident Hunter GUI
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

    /// Optional: $MFT file to resolve parent paths
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
