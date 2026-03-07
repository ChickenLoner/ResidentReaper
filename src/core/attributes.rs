//! Parsed attribute structs for NTFS MFT attributes.
//!
//! Each parser takes raw resident data bytes and returns a typed struct.

use super::mft_entry::RawAttribute;
use super::ntfs::{self, FileNamespace};

/// Parsed $STANDARD_INFORMATION (0x10) attribute.
#[derive(Debug, Clone)]
pub struct StandardInfo {
    pub created: u64,
    pub modified: u64,
    pub record_modified: u64,
    pub accessed: u64,
    pub flags: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub usn: u64,
}

impl StandardInfo {
    pub fn from_resident_data(data: &[u8]) -> Option<Self> {
        if data.len() < 48 {
            return None;
        }
        let created = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let modified = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let record_modified = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let accessed = u64::from_le_bytes(data[24..32].try_into().ok()?);
        let flags = u32::from_le_bytes(data[32..36].try_into().ok()?);

        // Extended fields (NTFS 3.0+, data >= 72 bytes)
        let (owner_id, security_id, usn) = if data.len() >= 72 {
            let oid = u32::from_le_bytes(data[48..52].try_into().unwrap_or([0; 4]));
            let sid = u32::from_le_bytes(data[52..56].try_into().unwrap_or([0; 4]));
            let usn = u64::from_le_bytes(data[64..72].try_into().unwrap_or([0; 8]));
            (oid, sid, usn)
        } else {
            (0, 0, 0)
        };

        Some(StandardInfo {
            created,
            modified,
            record_modified,
            accessed,
            flags,
            owner_id,
            security_id,
            usn,
        })
    }
}

/// Parsed $FILE_NAME (0x30) attribute.
#[derive(Debug, Clone)]
pub struct FileNameInfo {
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub created: u64,
    pub modified: u64,
    pub record_modified: u64,
    pub accessed: u64,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub name_type: FileNamespace,
    pub name: String,
}

impl FileNameInfo {
    pub fn from_resident_data(data: &[u8]) -> Option<Self> {
        if data.len() < 66 {
            return None;
        }

        // Parent directory MFT reference (8 bytes): lower 48 bits = entry, upper 16 = seq
        let parent_ref = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let parent_entry = parent_ref & 0x0000_FFFF_FFFF_FFFF;
        let parent_sequence = (parent_ref >> 48) as u16;

        let created = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let modified = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let record_modified = u64::from_le_bytes(data[24..32].try_into().ok()?);
        let accessed = u64::from_le_bytes(data[32..40].try_into().ok()?);
        let allocated_size = u64::from_le_bytes(data[40..48].try_into().ok()?);
        let real_size = u64::from_le_bytes(data[48..56].try_into().ok()?);
        let flags = u32::from_le_bytes(data[56..60].try_into().ok()?);

        // Byte 64: name length in characters, byte 65: namespace
        let name_length = data[64] as usize;
        let namespace_byte = data[65];
        let name_type = FileNamespace::from_u8(namespace_byte).unwrap_or(FileNamespace::Win32);

        // Name starts at byte 66, UTF-16LE
        let name_end = 66 + name_length * 2;
        let name = if name_end <= data.len() {
            ntfs::decode_utf16le(&data[66..name_end])
        } else {
            String::new()
        };

        Some(FileNameInfo {
            parent_entry,
            parent_sequence,
            created,
            modified,
            record_modified,
            accessed,
            allocated_size,
            real_size,
            flags,
            name_type,
            name,
        })
    }

    /// Is this a Win32-visible name (not pure DOS)?
    pub fn is_win32_name(&self) -> bool {
        matches!(
            self.name_type,
            FileNamespace::Win32 | FileNamespace::Win32AndDos | FileNamespace::Posix
        )
    }
}

/// Parsed $OBJECT_ID (0x40) attribute.
#[derive(Debug, Clone)]
pub struct ObjectIdInfo {
    pub object_id: String,
    pub birth_volume_id: String,
    pub birth_object_id: String,
    pub domain_id: String,
}

impl ObjectIdInfo {
    pub fn from_resident_data(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let object_id = ntfs::format_guid(&data[0..16]);
        let birth_volume_id = if data.len() >= 32 {
            ntfs::format_guid(&data[16..32])
        } else {
            String::new()
        };
        let birth_object_id = if data.len() >= 48 {
            ntfs::format_guid(&data[32..48])
        } else {
            String::new()
        };
        let domain_id = if data.len() >= 64 {
            ntfs::format_guid(&data[48..64])
        } else {
            String::new()
        };
        Some(ObjectIdInfo {
            object_id,
            birth_volume_id,
            birth_object_id,
            domain_id,
        })
    }
}

/// Parsed $REPARSE_POINT (0xC0) attribute — extract target path.
#[derive(Debug, Clone)]
pub struct ReparsePointInfo {
    pub reparse_tag: u32,
    pub target: String,
}

impl ReparsePointInfo {
    pub fn from_resident_data(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let reparse_tag = u32::from_le_bytes(data[0..4].try_into().ok()?);

        // Microsoft reparse points (IO_REPARSE_TAG_MOUNT_POINT=0xA0000003, SYMLINK=0xA000000C)
        let target = match reparse_tag {
            0xA000_0003 => Self::parse_mount_point(data),
            0xA000_000C => Self::parse_symlink(data),
            _ => String::new(),
        };

        Some(ReparsePointInfo {
            reparse_tag,
            target,
        })
    }

    fn parse_mount_point(data: &[u8]) -> String {
        // Mount point reparse data buffer:
        // offset 8: SubstituteNameOffset (2), SubstituteNameLength (2),
        //           PrintNameOffset (2), PrintNameLength (2)
        // offset 16: PathBuffer start
        if data.len() < 16 {
            return String::new();
        }
        let sub_offset = u16::from_le_bytes([data[8], data[9]]) as usize;
        let sub_length = u16::from_le_bytes([data[10], data[11]]) as usize;
        let print_offset = u16::from_le_bytes([data[12], data[13]]) as usize;
        let print_length = u16::from_le_bytes([data[14], data[15]]) as usize;

        let path_start = 16;

        // Prefer PrintName if available
        if print_length > 0 {
            let start = path_start + print_offset;
            let end = start + print_length;
            if end <= data.len() {
                return ntfs::decode_utf16le(&data[start..end]);
            }
        }

        // Fallback to SubstituteName
        if sub_length > 0 {
            let start = path_start + sub_offset;
            let end = start + sub_length;
            if end <= data.len() {
                let s = ntfs::decode_utf16le(&data[start..end]);
                return s.strip_prefix("\\??\\").unwrap_or(&s).to_string();
            }
        }

        String::new()
    }

    fn parse_symlink(data: &[u8]) -> String {
        // Symlink reparse data buffer:
        // offset 8: SubstituteNameOffset (2), SubstituteNameLength (2),
        //           PrintNameOffset (2), PrintNameLength (2), Flags (4)
        // offset 20: PathBuffer start
        if data.len() < 20 {
            return String::new();
        }
        let print_offset = u16::from_le_bytes([data[12], data[13]]) as usize;
        let print_length = u16::from_le_bytes([data[14], data[15]]) as usize;
        let sub_offset = u16::from_le_bytes([data[8], data[9]]) as usize;
        let sub_length = u16::from_le_bytes([data[10], data[11]]) as usize;

        let path_start = 20;

        if print_length > 0 {
            let start = path_start + print_offset;
            let end = start + print_length;
            if end <= data.len() {
                return ntfs::decode_utf16le(&data[start..end]);
            }
        }

        if sub_length > 0 {
            let start = path_start + sub_offset;
            let end = start + sub_length;
            if end <= data.len() {
                let s = ntfs::decode_utf16le(&data[start..end]);
                return s.strip_prefix("\\??\\").unwrap_or(&s).to_string();
            }
        }

        String::new()
    }
}

/// Info extracted from a $DATA (0x80) attribute.
#[derive(Debug, Clone)]
pub struct DataAttrInfo {
    pub stream_name: String,
    pub is_resident: bool,
    pub data_size: u64,
    pub resident_data: Vec<u8>,
}

impl DataAttrInfo {
    pub fn from_raw(attr: &RawAttribute) -> Self {
        let data_size = if attr.is_resident {
            attr.data_size as u64
        } else {
            attr.file_size
        };

        DataAttrInfo {
            stream_name: attr.name.clone(),
            is_resident: attr.is_resident,
            data_size,
            resident_data: attr.resident_data.clone(),
        }
    }
}

/// Parsed $LOGGED_UTILITY_STREAM (0x100) — typically EFS data.
#[derive(Debug, Clone)]
pub struct LoggedUtilStreamInfo {
    pub stream_name: String,
    pub data_size: u64,
    pub resident_data: Vec<u8>,
}

impl LoggedUtilStreamInfo {
    pub fn from_raw(attr: &RawAttribute) -> Self {
        LoggedUtilStreamInfo {
            stream_name: attr.name.clone(),
            data_size: if attr.is_resident {
                attr.data_size as u64
            } else {
                attr.file_size
            },
            resident_data: attr.resident_data.clone(),
        }
    }
}

/// Parsed entry from an $ATTRIBUTE_LIST (0x20) attribute.
/// Each entry points to where an attribute actually resides (possibly in an extension record).
#[derive(Debug, Clone)]
pub struct AttributeListEntry {
    pub attr_type: u32,
    pub record_length: u16,
    pub name_length: u8,
    pub name_offset: u8,
    pub starting_vcn: u64,
    pub mft_reference_entry: u64,
    pub mft_reference_seq: u16,
    pub attribute_id: u16,
}

/// Parse all entries from a resident $ATTRIBUTE_LIST attribute.
pub fn parse_attribute_list(data: &[u8]) -> Vec<AttributeListEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + 26 <= data.len() {
        let attr_type = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        let record_length = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        if record_length < 26 || offset + record_length as usize > data.len() {
            break;
        }

        let name_length = data[offset + 6];
        let name_offset = data[offset + 7];
        let starting_vcn = u64::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);

        // MFT reference: 6 bytes entry + 2 bytes sequence
        let mft_ref = u64::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]);
        let mft_reference_entry = mft_ref & 0x0000_FFFF_FFFF_FFFF;
        let mft_reference_seq = (mft_ref >> 48) as u16;

        let attribute_id = u16::from_le_bytes([data[offset + 24], data[offset + 25]]);

        entries.push(AttributeListEntry {
            attr_type,
            record_length,
            name_length,
            name_offset,
            starting_vcn,
            mft_reference_entry,
            mft_reference_seq,
            attribute_id,
        });

        offset += record_length as usize;
    }

    entries
}

/// Try to extract Zone.Identifier contents from a resident ADS named "Zone.Identifier".
/// Returns the ZoneId content as a string (typically "ZoneId=3" etc.).
pub fn extract_zone_id(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    // Zone.Identifier is a text stream, usually ASCII/UTF-8
    let text = String::from_utf8_lossy(data);
    // MFTECmd outputs just the content, trimmed
    text.trim().to_string()
}
