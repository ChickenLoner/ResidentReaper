use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt};
use memmap2::Mmap;

use super::types::{Result, SpecterError};

/// Parsed USN_RECORD_V2 entry.
pub struct UsnRecord {
    pub name: String,
    pub extension: String,
    pub entry_number: u64,
    pub sequence_number: u16,
    pub parent_entry_number: u64,
    pub parent_sequence_number: u16,
    pub usn: i64,
    pub timestamp: u64, // Windows FILETIME
    pub reason: u32,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
}

/// USN reason flag definitions matching MFTECmd output strings.
const USN_REASONS: &[(u32, &str)] = &[
    (0x00000001, "DATA_OVERWRITE"),
    (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"),
    (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"),
    (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"),
    (0x00200000, "STREAM_CHANGE"),
    (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"),
    (0x80000000, "CLOSE"),
];

/// Source info flag definitions.
const USN_SOURCE_INFO: &[(u32, &str)] = &[
    (0x00000001, "DATA_MANAGEMENT"),
    (0x00000002, "AUXILIARY_DATA"),
    (0x00000004, "REPLICATION_MANAGEMENT"),
    (0x00000008, "CLIENT_REPLICATION_MANAGEMENT"),
];

/// Decode USN reason flags to pipe-separated string.
pub fn decode_reason(reason: u32) -> String {
    let mut flags = Vec::new();
    for &(flag, name) in USN_REASONS {
        if reason & flag != 0 {
            flags.push(name);
        }
    }
    flags.join("|")
}

/// Decode USN source info flags to pipe-separated string.
pub fn decode_source_info(source: u32) -> String {
    if source == 0 {
        return String::new();
    }
    let mut flags = Vec::new();
    for &(flag, name) in USN_SOURCE_INFO {
        if source & flag != 0 {
            flags.push(name);
        }
    }
    flags.join("|")
}

/// Parse a $J (USN Journal) file and yield records via callback.
pub fn parse_usn_journal<F>(
    usn_path: &Path,
    mut callback: F,
) -> Result<u64>
where
    F: FnMut(UsnRecord) -> Result<()>,
{
    let file = std::fs::File::open(usn_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let data = &mmap[..];
    let len = data.len();

    let mut offset: usize = 0;
    let mut count: u64 = 0;

    // Skip leading zeros (sparse file region)
    offset = skip_zeros(data, offset);

    while offset + 60 <= len {
        // Read record length
        let record_len = read_u32_le(data, offset) as usize;

        // If record_len is 0, skip to next non-zero region
        if record_len == 0 {
            offset = skip_zeros(data, offset);
            continue;
        }

        // Validate record length
        if record_len < 60 || offset + record_len > len {
            // Try to advance past corrupt data
            offset += 8;
            offset = skip_zeros(data, offset);
            continue;
        }

        // Read major version
        let major_version = read_u16_le(data, offset + 4);

        if major_version == 2 {
            match parse_usn_v2(data, offset, record_len) {
                Ok(record) => {
                    callback(record)?;
                    count += 1;
                }
                Err(_) => {
                    // Skip corrupt record
                }
            }
        } else if major_version == 3 {
            match parse_usn_v3(data, offset, record_len) {
                Ok(record) => {
                    callback(record)?;
                    count += 1;
                }
                Err(_) => {
                    // Skip corrupt record
                }
            }
        }
        // else: unknown version, skip

        offset += record_len;
        // Align to 8-byte boundary
        offset = (offset + 7) & !7;
    }

    Ok(count)
}

/// Parse a USN_RECORD_V2 at the given offset.
fn parse_usn_v2(data: &[u8], offset: usize, _record_len: usize) -> Result<UsnRecord> {
    // V2 layout:
    // 0:  RecordLength (4)
    // 4:  MajorVersion (2)
    // 6:  MinorVersion (2)
    // 8:  FileReferenceNumber (8)
    // 16: ParentFileReferenceNumber (8)
    // 24: Usn (8)
    // 32: TimeStamp (8)
    // 40: Reason (4)
    // 44: SourceInfo (4)
    // 48: SecurityId (4)
    // 52: FileAttributes (4)
    // 56: FileNameLength (2)
    // 58: FileNameOffset (2)
    // 60: FileName (variable, UTF-16LE)

    let file_ref = read_u64_le(data, offset + 8);
    let parent_ref = read_u64_le(data, offset + 16);
    let usn = read_i64_le(data, offset + 24);
    let timestamp = read_u64_le(data, offset + 32);
    let reason = read_u32_le(data, offset + 40);
    let source_info = read_u32_le(data, offset + 44);
    let security_id = read_u32_le(data, offset + 48);
    let file_attributes = read_u32_le(data, offset + 52);
    let file_name_length = read_u16_le(data, offset + 56) as usize;
    let file_name_offset = read_u16_le(data, offset + 58) as usize;

    // Decompose file reference: lower 48 bits = entry, upper 16 bits = sequence
    let entry_number = file_ref & 0x0000_FFFF_FFFF_FFFF;
    let sequence_number = (file_ref >> 48) as u16;
    let parent_entry_number = parent_ref & 0x0000_FFFF_FFFF_FFFF;
    let parent_sequence_number = (parent_ref >> 48) as u16;

    // Read filename (UTF-16LE)
    let name_start = offset + file_name_offset;
    let name_end = name_start + file_name_length;
    if name_end > data.len() {
        return Err(SpecterError::UsnParse("Filename extends beyond data".into()));
    }
    let name = decode_utf16le(&data[name_start..name_end]);
    let extension = super::types::extract_extension(&name);

    Ok(UsnRecord {
        name,
        extension,
        entry_number,
        sequence_number,
        parent_entry_number,
        parent_sequence_number,
        usn,
        timestamp,
        reason,
        source_info,
        security_id,
        file_attributes,
    })
}

/// Parse a USN_RECORD_V3 at the given offset.
/// V3 uses 128-bit file references instead of 64-bit.
fn parse_usn_v3(data: &[u8], offset: usize, _record_len: usize) -> Result<UsnRecord> {
    // V3 layout:
    // 0:  RecordLength (4)
    // 4:  MajorVersion (2)
    // 6:  MinorVersion (2)
    // 8:  FileReferenceNumber (16) - 128-bit
    // 24: ParentFileReferenceNumber (16) - 128-bit
    // 40: Usn (8)
    // 48: TimeStamp (8)
    // 56: Reason (4)
    // 60: SourceInfo (4)
    // 64: SecurityId (4)
    // 68: FileAttributes (4)
    // 72: FileNameLength (2)
    // 74: FileNameOffset (2)
    // 76: FileName (variable, UTF-16LE)

    if offset + 76 > data.len() {
        return Err(SpecterError::UsnParse("V3 record too short".into()));
    }

    // For V3, use lower 64 bits of 128-bit reference (same decomposition)
    let file_ref = read_u64_le(data, offset + 8);
    let parent_ref = read_u64_le(data, offset + 24);
    let usn = read_i64_le(data, offset + 40);
    let timestamp = read_u64_le(data, offset + 48);
    let reason = read_u32_le(data, offset + 56);
    let source_info = read_u32_le(data, offset + 60);
    let security_id = read_u32_le(data, offset + 64);
    let file_attributes = read_u32_le(data, offset + 68);
    let file_name_length = read_u16_le(data, offset + 72) as usize;
    let file_name_offset = read_u16_le(data, offset + 74) as usize;

    let entry_number = file_ref & 0x0000_FFFF_FFFF_FFFF;
    let sequence_number = (file_ref >> 48) as u16;
    let parent_entry_number = parent_ref & 0x0000_FFFF_FFFF_FFFF;
    let parent_sequence_number = (parent_ref >> 48) as u16;

    let name_start = offset + file_name_offset;
    let name_end = name_start + file_name_length;
    if name_end > data.len() {
        return Err(SpecterError::UsnParse("V3 filename extends beyond data".into()));
    }
    let name = decode_utf16le(&data[name_start..name_end]);
    let extension = super::types::extract_extension(&name);

    Ok(UsnRecord {
        name,
        extension,
        entry_number,
        sequence_number,
        parent_entry_number,
        parent_sequence_number,
        usn,
        timestamp,
        reason,
        source_info,
        security_id,
        file_attributes,
    })
}

/// Skip zero-filled regions in the data. Returns the next non-zero offset.
fn skip_zeros(data: &[u8], mut offset: usize) -> usize {
    // Skip in 4KB chunks first for efficiency
    while offset + 4096 <= data.len() {
        if data[offset..offset + 4096].iter().all(|&b| b == 0) {
            offset += 4096;
        } else {
            break;
        }
    }
    // Fine-grained skip in 8-byte chunks (record alignment)
    while offset + 8 <= data.len() {
        if data[offset..offset + 8].iter().all(|&b| b == 0) {
            offset += 8;
        } else {
            break;
        }
    }
    offset
}

/// Decode UTF-16LE bytes to a String.
fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

// Helper functions for reading little-endian values from a byte slice.

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    let mut cursor = std::io::Cursor::new(&data[offset..offset + 2]);
    cursor.read_u16::<LittleEndian>().unwrap_or(0)
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    let mut cursor = std::io::Cursor::new(&data[offset..offset + 4]);
    cursor.read_u32::<LittleEndian>().unwrap_or(0)
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    let mut cursor = std::io::Cursor::new(&data[offset..offset + 8]);
    cursor.read_u64::<LittleEndian>().unwrap_or(0)
}

fn read_i64_le(data: &[u8], offset: usize) -> i64 {
    let mut cursor = std::io::Cursor::new(&data[offset..offset + 8]);
    cursor.read_i64::<LittleEndian>().unwrap_or(0)
}
