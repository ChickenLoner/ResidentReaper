use std::fmt::Write;

use chrono::{DateTime, Datelike, Timelike, Utc};
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
/// Uses direct field access instead of chrono's format() pattern parsing.
pub fn format_datetime_mftecmd(dt: &DateTime<Utc>) -> String {
    let nanos = dt.timestamp_subsec_nanos();
    let ticks = nanos / 100; // Convert nanos to 100ns ticks
    let mut buf = String::with_capacity(28);
    let _ = write!(
        buf,
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:07}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        ticks
    );
    buf
}

/// Format an optional DateTime to MFTECmd format, returning empty string for None.
pub fn format_datetime_opt(dt: &Option<DateTime<Utc>>) -> String {
    match dt {
        Some(d) => format_datetime_mftecmd(d),
        None => String::new(),
    }
}

/// Windows FILETIME epoch offset: 100ns ticks between 1601-01-01 and 1970-01-01.
const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// Format a Windows FILETIME timestamp (100ns ticks since 1601-01-01) to MFTECmd-compatible string.
/// Optimized: avoids chrono format() pattern parsing.
pub fn format_timestamp_filetime(filetime: u64) -> String {
    if filetime == 0 || filetime < FILETIME_EPOCH_DIFF {
        return String::new();
    }
    let unix_100ns = filetime - FILETIME_EPOCH_DIFF;
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

/// Decode Windows file attributes flags to a human-readable pipe-separated string.
/// Optimized: writes directly to string buffer instead of allocating Vec.
pub fn decode_file_attributes(attrs: u32) -> String {
    if attrs == 0 {
        return String::new();
    }
    let mut buf = String::with_capacity(64);
    let mut first = true;

    macro_rules! flag {
        ($mask:expr, $name:expr) => {
            if attrs & $mask != 0 {
                if !first { buf.push('|'); }
                buf.push_str($name);
                first = false;
            }
        };
    }

    flag!(0x0001, "ReadOnly");
    flag!(0x0002, "Hidden");
    flag!(0x0004, "System");
    flag!(0x0010, "Directory");
    flag!(0x0020, "Archive");
    flag!(0x0040, "Device");
    flag!(0x0080, "Normal");
    flag!(0x0100, "Temporary");
    flag!(0x0200, "SparseFile");
    flag!(0x0400, "ReparsePoint");
    flag!(0x0800, "Compressed");
    flag!(0x1000, "Offline");
    flag!(0x2000, "NotContentIndexed");
    flag!(0x4000, "Encrypted");
    buf
}
