//! Low-level NTFS structure definitions and constants.

use chrono::{DateTime, Utc};

/// Windows FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
pub const EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// Convert a Windows FILETIME (u64) to chrono DateTime<Utc>.
pub fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 || filetime < EPOCH_DIFF {
        return None;
    }
    let unix_100ns = filetime - EPOCH_DIFF;
    let secs = (unix_100ns / 10_000_000) as i64;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Check if a FILETIME has zero sub-second precision (microsecond zeros).
/// This is a timestomping indicator — legitimate timestamps usually have non-zero sub-seconds.
pub fn has_usec_zeros(filetime: u64) -> bool {
    if filetime == 0 {
        return false;
    }
    // The last 7 digits (100ns ticks within a second) are all zero
    (filetime % 10_000_000) == 0
}

/// MFT Entry signature constants.
pub const SIGNATURE_FILE: [u8; 4] = *b"FILE";
pub const SIGNATURE_BAAD: [u8; 4] = *b"BAAD";

/// Attribute type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AttributeType {
    StandardInformation = 0x10,
    AttributeList = 0x20,
    FileName = 0x30,
    ObjectId = 0x40,
    SecurityDescriptor = 0x50,
    VolumeName = 0x60,
    VolumeInformation = 0x70,
    Data = 0x80,
    IndexRoot = 0x90,
    IndexAllocation = 0xA0,
    Bitmap = 0xB0,
    ReparsePoint = 0xC0,
    EaInformation = 0xD0,
    Ea = 0xE0,
    LoggedUtilityStream = 0x100,
    End = 0xFFFF_FFFF,
}

impl AttributeType {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0x10 => Some(Self::StandardInformation),
            0x20 => Some(Self::AttributeList),
            0x30 => Some(Self::FileName),
            0x40 => Some(Self::ObjectId),
            0x50 => Some(Self::SecurityDescriptor),
            0x60 => Some(Self::VolumeName),
            0x70 => Some(Self::VolumeInformation),
            0x80 => Some(Self::Data),
            0x90 => Some(Self::IndexRoot),
            0xA0 => Some(Self::IndexAllocation),
            0xB0 => Some(Self::Bitmap),
            0xC0 => Some(Self::ReparsePoint),
            0xD0 => Some(Self::EaInformation),
            0xE0 => Some(Self::Ea),
            0x100 => Some(Self::LoggedUtilityStream),
            0xFFFF_FFFF => Some(Self::End),
            _ => None,
        }
    }
}

/// MFT Entry flags.
pub const ENTRY_FLAG_IN_USE: u16 = 0x0001;
pub const ENTRY_FLAG_DIRECTORY: u16 = 0x0002;

/// File attribute flags (from $STANDARD_INFORMATION).
/// Matches MFTECmd's Flag enum ToString() output.
/// When unknown bits are present, C#'s [Flags] ToString() outputs the raw signed value.
pub fn decode_si_flags(flags: u32) -> String {
    if flags == 0 {
        return "None".to_string();
    }
    let known_bits: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0020 | 0x0040 | 0x0080
        | 0x0100 | 0x0200 | 0x0400 | 0x0800 | 0x1000 | 0x2000 | 0x4000
        | 0x1000_0000 | 0x2000_0000 | 0x0004_0000;

    // If there are unknown bits, C# outputs raw signed integer
    if flags & !known_bits != 0 {
        return (flags as i32).to_string();
    }

    let mut buf = String::with_capacity(64);
    let mut first = true;

    macro_rules! flag {
        ($mask:expr, $name:expr) => {
            if flags & $mask != 0 {
                if !first { buf.push('|'); }
                buf.push_str($name);
                first = false;
            }
        };
    }

    flag!(0x0001, "ReadOnly");
    flag!(0x0002, "Hidden");
    flag!(0x0004, "System");
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
    flag!(0x1000_0000, "IsDirectory");
    flag!(0x2000_0000, "IsIndexView");
    flag!(0x0004_0000, "RecallOnOpen");
    buf
}

/// FILE_NAME namespace values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileNamespace {
    Posix = 0,
    Win32 = 1,
    Dos = 2,
    Win32AndDos = 3,
}

impl FileNamespace {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Posix),
            1 => Some(Self::Win32),
            2 => Some(Self::Dos),
            3 => Some(Self::Win32AndDos),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Posix => "Posix",
            Self::Win32 => "Windows",
            Self::Dos => "Dos",
            Self::Win32AndDos => "DosWindows",
        }
    }
}

/// Decode UTF-16LE bytes to a String without intermediate Vec allocation.
pub fn decode_utf16le(data: &[u8]) -> String {
    let char_count = data.len() / 2;
    if char_count <= 128 {
        let mut buf = [0u16; 128];
        for (i, chunk) in data.chunks_exact(2).enumerate() {
            buf[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        String::from_utf16_lossy(&buf[..char_count])
    } else {
        let u16s: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    }
}

/// Format a GUID from 16 raw bytes into standard string form.
pub fn format_guid(data: &[u8]) -> String {
    if data.len() < 16 {
        return String::new();
    }
    let d1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let d2 = u16::from_le_bytes([data[4], data[5]]);
    let d3 = u16::from_le_bytes([data[6], data[7]]);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3,
        data[8], data[9], data[10], data[11],
        data[12], data[13], data[14], data[15],
    )
}
