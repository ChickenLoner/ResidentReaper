use serde::Serialize;

use super::mft_parser::MftEntryInfo;
use super::types::format_datetime_opt;

/// CSV row matching MFTECmd output format.
#[derive(Serialize)]
pub struct MftCsvRow {
    #[serde(rename = "EntryNumber")]
    pub entry_number: u64,
    #[serde(rename = "SequenceNumber")]
    pub sequence_number: u16,
    #[serde(rename = "InUse")]
    pub in_use: bool,
    #[serde(rename = "ParentEntryNumber")]
    pub parent_entry_number: u64,
    #[serde(rename = "ParentSequenceNumber")]
    pub parent_sequence_number: u16,
    #[serde(rename = "ParentPath")]
    pub parent_path: String,
    #[serde(rename = "FileName")]
    pub file_name: String,
    #[serde(rename = "Extension")]
    pub extension: String,
    #[serde(rename = "FileSize")]
    pub file_size: u64,
    #[serde(rename = "IsDirectory")]
    pub is_directory: bool,
    #[serde(rename = "HasAds")]
    pub has_ads: bool,
    #[serde(rename = "IsAds")]
    pub is_ads: bool,
    #[serde(rename = "Created0x10")]
    pub created_0x10: String,
    #[serde(rename = "LastModified0x10")]
    pub last_modified_0x10: String,
    #[serde(rename = "LastAccess0x10")]
    pub last_access_0x10: String,
    #[serde(rename = "LastRecordChange0x10")]
    pub last_record_change_0x10: String,
    #[serde(rename = "Created0x30")]
    pub created_0x30: String,
    #[serde(rename = "LastModified0x30")]
    pub last_modified_0x30: String,
    #[serde(rename = "LastAccess0x30")]
    pub last_access_0x30: String,
    #[serde(rename = "LastRecordChange0x30")]
    pub last_record_change_0x30: String,
    #[serde(rename = "ReferenceCount")]
    pub reference_count: u16,
    #[serde(rename = "LogfileSequenceNumber")]
    pub logfile_sequence_number: u64,
    #[serde(rename = "SecurityId")]
    pub security_id: u32,
    #[serde(rename = "ObjectIdFileDroid")]
    pub object_id_file_droid: String,
    #[serde(rename = "ZoneIdContents")]
    pub zone_id_contents: String,
}

impl From<MftEntryInfo> for MftCsvRow {
    fn from(info: MftEntryInfo) -> Self {
        MftCsvRow {
            entry_number: info.entry_number,
            sequence_number: info.sequence_number,
            in_use: info.in_use,
            parent_entry_number: info.parent_entry_number,
            parent_sequence_number: info.parent_sequence_number,
            parent_path: info.parent_path,
            file_name: info.file_name,
            extension: info.extension,
            file_size: info.file_size,
            is_directory: info.is_directory,
            has_ads: info.has_ads,
            is_ads: info.is_ads,
            created_0x10: format_datetime_opt(&info.si_created),
            last_modified_0x10: format_datetime_opt(&info.si_modified),
            last_access_0x10: format_datetime_opt(&info.si_accessed),
            last_record_change_0x10: format_datetime_opt(&info.si_record_modified),
            created_0x30: format_datetime_opt(&info.fn_created),
            last_modified_0x30: format_datetime_opt(&info.fn_modified),
            last_access_0x30: format_datetime_opt(&info.fn_accessed),
            last_record_change_0x30: format_datetime_opt(&info.fn_record_modified),
            reference_count: info.reference_count,
            logfile_sequence_number: info.logfile_sequence_number,
            security_id: info.security_id,
            object_id_file_droid: info.object_id_file_droid,
            zone_id_contents: info.zone_id_contents,
        }
    }
}
