//! MFT entry parsing: header, fixup arrays, and raw attribute iteration.

use super::ntfs::{self, AttributeType};
use super::types::ReaperError;

/// Parsed MFT entry header.
#[derive(Debug, Clone)]
pub struct EntryHeader {
    pub signature: [u8; 4],
    pub fixup_offset: u16,
    pub fixup_count: u16,
    pub logfile_sequence_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16,
    pub used_size: u32,
    pub allocated_size: u32,
    pub base_record_entry: u64,
    pub base_record_sequence: u16,
    pub first_attribute_id: u16,
    pub record_number: u64,
}

impl EntryHeader {
    pub fn is_valid(&self) -> bool {
        self.signature == ntfs::SIGNATURE_FILE
    }

    pub fn is_in_use(&self) -> bool {
        self.flags & ntfs::ENTRY_FLAG_IN_USE != 0
    }

    pub fn is_directory(&self) -> bool {
        self.flags & ntfs::ENTRY_FLAG_DIRECTORY != 0
    }
}

/// A raw attribute as found in an MFT entry.
#[derive(Debug, Clone)]
pub struct RawAttribute {
    pub attr_type: AttributeType,
    pub record_length: u32,
    pub is_resident: bool,
    pub name: String,
    pub instance: u16,
    // Resident-specific
    pub data_size: u32,
    pub data_offset: u16,
    // Non-resident specific
    pub file_size: u64,
    pub allocated_size: u64,
    /// The raw data bytes for resident attributes.
    pub resident_data: Vec<u8>,
}

/// A parsed MFT entry with header and borrowed or owned data.
/// Uses a local buffer with fixups applied, avoiding full-entry cloning
/// when the entry has no fixups to apply.
pub struct MftEntry {
    pub header: EntryHeader,
    pub data: Vec<u8>,
}

impl MftEntry {
    /// Parse an MFT entry from a byte slice. Copies the buffer and applies fixup array.
    pub fn from_slice(buffer: &[u8], entry_number: u64) -> Result<Self, ReaperError> {
        if buffer.len() < 56 {
            return Err(ReaperError::MftParse("Buffer too small for MFT entry".into()));
        }

        let header = parse_entry_header(buffer, entry_number)?;

        if !header.is_valid() {
            return Err(ReaperError::MftParse(format!(
                "Invalid entry signature for entry {}",
                entry_number
            )));
        }

        // Only copy the used portion of the entry (not the full allocated size)
        let used = (header.used_size as usize).min(buffer.len());
        let mut data = buffer[..used].to_vec();

        // Apply fixup array
        apply_fixup(&header, &mut data);

        Ok(MftEntry { header, data })
    }

    /// Iterate over all attributes in this entry.
    pub fn iter_attributes(&self) -> AttributeIterator<'_> {
        AttributeIterator {
            data: &self.data,
            offset: self.header.first_attribute_offset as usize,
            exhausted: false,
        }
    }
}

/// Parse the 56-byte MFT entry header directly from a byte slice.
fn parse_entry_header(data: &[u8], entry_number: u64) -> Result<EntryHeader, ReaperError> {
    let mut signature = [0u8; 4];
    signature.copy_from_slice(&data[0..4]);

    if signature != ntfs::SIGNATURE_FILE && signature != ntfs::SIGNATURE_BAAD && signature != [0; 4] {
        return Err(ReaperError::MftParse(format!(
            "Unknown signature {:?} at entry {}",
            signature, entry_number
        )));
    }

    let fixup_offset = u16::from_le_bytes([data[4], data[5]]);
    let fixup_count = u16::from_le_bytes([data[6], data[7]]);
    let lsn = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let sequence = u16::from_le_bytes([data[16], data[17]]);
    let hard_link_count = u16::from_le_bytes([data[18], data[19]]);
    let first_attr_offset = u16::from_le_bytes([data[20], data[21]]);
    let flags = u16::from_le_bytes([data[22], data[23]]);
    let used_size = u32::from_le_bytes(data[24..28].try_into().unwrap());
    let allocated_size = u32::from_le_bytes(data[28..32].try_into().unwrap());

    // Base record reference (8 bytes): lower 48 bits = entry, upper 16 bits = sequence
    let base_ref = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let base_record_entry = base_ref & 0x0000_FFFF_FFFF_FFFF;
    let base_record_sequence = (base_ref >> 48) as u16;

    let first_attribute_id = u16::from_le_bytes([data[40], data[41]]);

    Ok(EntryHeader {
        signature,
        fixup_offset,
        fixup_count,
        logfile_sequence_number: lsn,
        sequence_number: sequence,
        hard_link_count,
        first_attribute_offset: first_attr_offset,
        flags,
        used_size,
        allocated_size,
        base_record_entry,
        base_record_sequence,
        first_attribute_id,
        record_number: entry_number,
    })
}

/// Apply the fixup array to the entry buffer.
/// The fixup array replaces the last two bytes of each 512-byte sector.
fn apply_fixup(header: &EntryHeader, buffer: &mut [u8]) {
    let fixup_start = header.fixup_offset as usize;
    let num_fixups = header.fixup_count as usize;

    if num_fixups < 2 || fixup_start + num_fixups * 2 > buffer.len() {
        return;
    }

    // Read fixup bytes before modifying the buffer
    let fixup_end = fixup_start + num_fixups * 2;
    if fixup_end > buffer.len() {
        return;
    }

    // Copy fixup bytes to avoid borrow issues
    let mut fixup_bytes = [0u8; 34]; // max 17 fixups * 2 bytes (covers up to 8KB entries)
    let copy_len = (num_fixups * 2).min(fixup_bytes.len());
    fixup_bytes[..copy_len].copy_from_slice(&buffer[fixup_start..fixup_start + copy_len]);

    for i in 1..num_fixups {
        let sector_end = i * 512;
        if sector_end > buffer.len() {
            break;
        }
        let fix_offset = i * 2;
        if fix_offset + 1 < copy_len {
            buffer[sector_end - 2] = fixup_bytes[fix_offset];
            buffer[sector_end - 1] = fixup_bytes[fix_offset + 1];
        }
    }
}

/// Iterator over raw attributes in an MFT entry.
pub struct AttributeIterator<'a> {
    data: &'a [u8],
    offset: usize,
    exhausted: bool,
}

impl<'a> Iterator for AttributeIterator<'a> {
    type Item = RawAttribute;

    fn next(&mut self) -> Option<RawAttribute> {
        loop {
            if self.exhausted || self.offset + 16 > self.data.len() {
                return None;
            }

            // Read attribute type code (4 bytes)
            let type_code = u32::from_le_bytes([
                self.data[self.offset],
                self.data[self.offset + 1],
                self.data[self.offset + 2],
                self.data[self.offset + 3],
            ]);

            // 0xFFFFFFFF = end marker
            if type_code == 0xFFFF_FFFF {
                self.exhausted = true;
                return None;
            }

            let attr_type = match AttributeType::from_u32(type_code) {
                Some(t) => t,
                None => {
                    // Unknown attribute type — skip if we can read length
                    let record_length = u32::from_le_bytes([
                        self.data[self.offset + 4],
                        self.data[self.offset + 5],
                        self.data[self.offset + 6],
                        self.data[self.offset + 7],
                    ]);
                    if record_length == 0 {
                        self.exhausted = true;
                        return None;
                    }
                    self.offset += record_length as usize;
                    continue;
                }
            };

            let record_length = u32::from_le_bytes([
                self.data[self.offset + 4],
                self.data[self.offset + 5],
                self.data[self.offset + 6],
                self.data[self.offset + 7],
            ]);

            if record_length == 0 || self.offset + record_length as usize > self.data.len() {
                self.exhausted = true;
                return None;
            }

            let form_code = self.data[self.offset + 8]; // 0=resident, 1=non-resident
            let name_length = self.data[self.offset + 9] as usize; // in characters
            let name_offset = u16::from_le_bytes([
                self.data[self.offset + 10],
                self.data[self.offset + 11],
            ]);
            let instance = u16::from_le_bytes([
                self.data[self.offset + 14],
                self.data[self.offset + 15],
            ]);

            // Read attribute name if present
            let name = if name_length > 0 {
                let name_start = self.offset + name_offset as usize;
                let name_end = name_start + name_length * 2;
                if name_end <= self.data.len() {
                    ntfs::decode_utf16le(&self.data[name_start..name_end])
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            let (is_resident, data_size, data_offset_val, file_size, allocated_size, resident_data) =
                if form_code == 0 {
                    // Resident: offset 16..24
                    let ds = u32::from_le_bytes([
                        self.data[self.offset + 16],
                        self.data[self.offset + 17],
                        self.data[self.offset + 18],
                        self.data[self.offset + 19],
                    ]);
                    let do_ = u16::from_le_bytes([
                        self.data[self.offset + 20],
                        self.data[self.offset + 21],
                    ]);

                    // Extract resident data bytes
                    let rd_start = self.offset + do_ as usize;
                    let rd_end = rd_start + ds as usize;
                    let rd = if rd_end <= self.data.len() {
                        self.data[rd_start..rd_end].to_vec()
                    } else {
                        Vec::new()
                    };

                    (true, ds, do_, 0u64, 0u64, rd)
                } else {
                    // Non-resident: offset 16..64
                    let alloc_len = if self.offset + 48 <= self.data.len() {
                        u64::from_le_bytes([
                            self.data[self.offset + 40],
                            self.data[self.offset + 41],
                            self.data[self.offset + 42],
                            self.data[self.offset + 43],
                            self.data[self.offset + 44],
                            self.data[self.offset + 45],
                            self.data[self.offset + 46],
                            self.data[self.offset + 47],
                        ])
                    } else {
                        0
                    };
                    let fs = if self.offset + 56 <= self.data.len() {
                        u64::from_le_bytes([
                            self.data[self.offset + 48],
                            self.data[self.offset + 49],
                            self.data[self.offset + 50],
                            self.data[self.offset + 51],
                            self.data[self.offset + 52],
                            self.data[self.offset + 53],
                            self.data[self.offset + 54],
                            self.data[self.offset + 55],
                        ])
                    } else {
                        0
                    };
                    (false, 0, 0, fs, alloc_len, Vec::new())
                };

            let attr = RawAttribute {
                attr_type,
                record_length,
                is_resident,
                name,
                instance,
                data_size,
                data_offset: data_offset_val,
                file_size,
                allocated_size,
                resident_data,
            };

            self.offset += record_length as usize;
            return Some(attr);
        }
    }
}
