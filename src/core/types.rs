use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReaperError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("MFT parse error: {0}")]
    MftParse(String),

    #[error("USN parse error: {0}")]
    UsnParse(String),

    #[error("CSV error: {0}")]
    Csv(String),

    #[error("{0}")]
    Other(String),
}

#[cfg(feature = "cli")]
impl From<csv::Error> for ReaperError {
    fn from(e: csv::Error) -> Self {
        ReaperError::Csv(e.to_string())
    }
}


pub type Result<T> = std::result::Result<T, ReaperError>;

/// Format a chrono DateTime<Utc> to MFTECmd format: yyyy-MM-dd HH:mm:ss.fffffff
pub fn format_datetime_mftecmd(dt: &DateTime<Utc>) -> String {
    let nanos = dt.timestamp_subsec_nanos();
    let ticks = nanos / 100; // Convert nanos to 100ns ticks
    format!(
        "{}.{:07}",
        dt.format("%Y-%m-%d %H:%M:%S"),
        ticks
    )
}

/// Format an optional DateTime to MFTECmd format, returning empty string for None.
pub fn format_datetime_opt(dt: &Option<DateTime<Utc>>) -> String {
    match dt {
        Some(d) => format_datetime_mftecmd(d),
        None => String::new(),
    }
}

/// Format a Windows FILETIME timestamp (100ns ticks since 1601-01-01) to MFTECmd-compatible string.
pub fn format_timestamp_filetime(filetime: u64) -> String {
    if filetime == 0 {
        return String::new();
    }
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if filetime < EPOCH_DIFF {
        return String::new();
    }
    let unix_100ns = filetime - EPOCH_DIFF;
    let secs = (unix_100ns / 10_000_000) as i64;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;

    match DateTime::from_timestamp(secs, nanos) {
        Some(dt) => format_datetime_mftecmd(&dt),
        None => String::new(),
    }
}

/// Extract file extension from a filename.
pub fn extract_extension(filename: &str) -> String {
    if let Some(pos) = filename.rfind('.') {
        if pos > 0 && pos < filename.len() - 1 {
            return filename[pos + 1..].to_lowercase();
        }
    }
    String::new()
}

/// Decode Windows file attributes flags to a human-readable string.
pub fn decode_file_attributes(attrs: u32) -> String {
    let mut flags = Vec::new();
    if attrs & 0x0001 != 0 { flags.push("ReadOnly"); }
    if attrs & 0x0002 != 0 { flags.push("Hidden"); }
    if attrs & 0x0004 != 0 { flags.push("System"); }
    if attrs & 0x0010 != 0 { flags.push("Directory"); }
    if attrs & 0x0020 != 0 { flags.push("Archive"); }
    if attrs & 0x0040 != 0 { flags.push("Device"); }
    if attrs & 0x0080 != 0 { flags.push("Normal"); }
    if attrs & 0x0100 != 0 { flags.push("Temporary"); }
    if attrs & 0x0200 != 0 { flags.push("SparseFile"); }
    if attrs & 0x0400 != 0 { flags.push("ReparsePoint"); }
    if attrs & 0x0800 != 0 { flags.push("Compressed"); }
    if attrs & 0x1000 != 0 { flags.push("Offline"); }
    if attrs & 0x2000 != 0 { flags.push("NotContentIndexed"); }
    if attrs & 0x4000 != 0 { flags.push("Encrypted"); }
    flags.join("|")
}
