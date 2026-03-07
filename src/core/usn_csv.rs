use serde::Serialize;

use super::types::{decode_file_attributes, format_timestamp_filetime};
use super::usn_parser::{UsnRecord, decode_reason};

/// CSV row matching MFTECmd USN Journal output format exactly.
/// Columns: Name, Extension, EntryNumber, SequenceNumber, ParentEntryNumber,
///          ParentSequenceNumber, ParentPath, UpdateSequenceNumber, UpdateTimestamp,
///          UpdateReasons, FileAttributes, OffsetToData, SourceFile
#[derive(Serialize)]
pub struct UsnCsvRow {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Extension")]
    pub extension: String,
    #[serde(rename = "EntryNumber")]
    pub entry_number: u64,
    #[serde(rename = "SequenceNumber")]
    pub sequence_number: u16,
    #[serde(rename = "ParentEntryNumber")]
    pub parent_entry_number: u64,
    #[serde(rename = "ParentSequenceNumber")]
    pub parent_sequence_number: u16,
    #[serde(rename = "ParentPath")]
    pub parent_path: String,
    #[serde(rename = "UpdateSequenceNumber")]
    pub update_sequence_number: i64,
    #[serde(rename = "UpdateTimestamp")]
    pub update_timestamp: String,
    #[serde(rename = "UpdateReasons")]
    pub update_reasons: String,
    #[serde(rename = "FileAttributes")]
    pub file_attributes: String,
    #[serde(rename = "OffsetToData")]
    pub offset_to_data: i64,
    #[serde(rename = "SourceFile")]
    pub source_file: String,
}

impl UsnCsvRow {
    pub fn from_record(record: UsnRecord, parent_path: String, source_file: String) -> Self {
        UsnCsvRow {
            name: record.name,
            extension: record.extension,
            entry_number: record.entry_number,
            sequence_number: record.sequence_number,
            parent_entry_number: record.parent_entry_number,
            parent_sequence_number: record.parent_sequence_number,
            parent_path,
            update_sequence_number: record.usn,
            update_timestamp: format_timestamp_filetime(record.timestamp),
            update_reasons: decode_reason(record.reason),
            file_attributes: decode_file_attributes(record.file_attributes),
            offset_to_data: record.offset_to_data,
            source_file,
        }
    }
}
