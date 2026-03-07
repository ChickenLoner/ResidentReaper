use serde::Serialize;

use super::mft_parser::MftEntryInfo;
use super::ntfs;
use super::types::format_timestamp_filetime;

/// Format bool as C#-style "True"/"False" for MFTECmd compatibility.
fn bool_str(v: bool) -> String {
    if v { "True".to_string() } else { "False".to_string() }
}

/// CSV row matching MFTECmd output format exactly.
/// 34 columns in the exact MFTECmd order.
#[derive(Serialize)]
pub struct MftCsvRow {
    #[serde(rename = "EntryNumber")]
    pub entry_number: u64,
    #[serde(rename = "SequenceNumber")]
    pub sequence_number: u16,
    #[serde(rename = "InUse")]
    pub in_use: String,
    #[serde(rename = "ParentEntryNumber")]
    pub parent_entry_number: u64,
    #[serde(rename = "ParentSequenceNumber")]
    pub parent_sequence_number: String,
    #[serde(rename = "ParentPath")]
    pub parent_path: String,
    #[serde(rename = "FileName")]
    pub file_name: String,
    #[serde(rename = "Extension")]
    pub extension: String,
    #[serde(rename = "FileSize")]
    pub file_size: u64,
    #[serde(rename = "ReferenceCount")]
    pub reference_count: u16,
    #[serde(rename = "ReparseTarget")]
    pub reparse_target: String,
    #[serde(rename = "IsDirectory")]
    pub is_directory: String,
    #[serde(rename = "HasAds")]
    pub has_ads: String,
    #[serde(rename = "IsAds")]
    pub is_ads: String,
    #[serde(rename = "SI<FN")]
    pub timestomped: String,
    #[serde(rename = "uSecZeros")]
    pub usec_zeros: String,
    #[serde(rename = "Copied")]
    pub copied: String,
    #[serde(rename = "SiFlags")]
    pub si_flags: String,
    #[serde(rename = "NameType")]
    pub name_type: String,
    #[serde(rename = "Created0x10")]
    pub created_0x10: String,
    #[serde(rename = "Created0x30")]
    pub created_0x30: String,
    #[serde(rename = "LastModified0x10")]
    pub last_modified_0x10: String,
    #[serde(rename = "LastModified0x30")]
    pub last_modified_0x30: String,
    #[serde(rename = "LastRecordChange0x10")]
    pub last_record_change_0x10: String,
    #[serde(rename = "LastRecordChange0x30")]
    pub last_record_change_0x30: String,
    #[serde(rename = "LastAccess0x10")]
    pub last_access_0x10: String,
    #[serde(rename = "LastAccess0x30")]
    pub last_access_0x30: String,
    #[serde(rename = "UpdateSequenceNumber")]
    pub update_sequence_number: u64,
    #[serde(rename = "LogfileSequenceNumber")]
    pub logfile_sequence_number: u64,
    #[serde(rename = "SecurityId")]
    pub security_id: u32,
    #[serde(rename = "ObjectIdFileDroid")]
    pub object_id_file_droid: String,
    #[serde(rename = "LoggedUtilStream")]
    pub logged_util_stream: String,
    #[serde(rename = "ZoneIdContents")]
    pub zone_id_contents: String,
    #[serde(rename = "SourceFile")]
    pub source_file: String,
}

impl From<MftEntryInfo> for MftCsvRow {
    fn from(info: MftEntryInfo) -> Self {
        MftCsvRow {
            entry_number: info.entry_number,
            sequence_number: info.sequence_number,
            in_use: bool_str(info.in_use),
            parent_entry_number: info.parent_entry_number,
            parent_sequence_number: if info.parent_sequence_number > 0 {
                info.parent_sequence_number.to_string()
            } else {
                String::new()
            },
            parent_path: info.parent_path,
            file_name: info.file_name,
            extension: info.extension,
            file_size: info.file_size,
            reference_count: info.reference_count,
            reparse_target: info.reparse_target,
            is_directory: bool_str(info.is_directory),
            has_ads: bool_str(info.has_ads),
            is_ads: bool_str(info.is_ads),
            timestomped: bool_str(info.timestomped),
            usec_zeros: bool_str(info.usec_zeros),
            copied: bool_str(info.copied),
            si_flags: ntfs::decode_si_flags(info.si_flags),
            name_type: info.name_type,
            created_0x10: format_timestamp_filetime(info.si_created),
            created_0x30: format_timestamp_filetime(info.fn_created),
            last_modified_0x10: format_timestamp_filetime(info.si_modified),
            last_modified_0x30: format_timestamp_filetime(info.fn_modified),
            last_record_change_0x10: format_timestamp_filetime(info.si_record_modified),
            last_record_change_0x30: format_timestamp_filetime(info.fn_record_modified),
            last_access_0x10: format_timestamp_filetime(info.si_accessed),
            last_access_0x30: format_timestamp_filetime(info.fn_accessed),
            update_sequence_number: info.usn,
            logfile_sequence_number: info.logfile_sequence_number,
            security_id: info.security_id,
            object_id_file_droid: info.object_id_file_droid,
            logged_util_stream: info.logged_util_stream,
            zone_id_contents: info.zone_id_contents,
            source_file: info.source_file,
        }
    }
}
