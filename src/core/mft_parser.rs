use std::path::Path;

use chrono::{DateTime, Utc};
use mft::attribute::header::ResidentialHeader;
use mft::attribute::MftAttributeType;
use mft::MftParser;

use super::types::{Result, SpecterError};

/// Information extracted from an MFT entry for CSV output.
pub struct MftEntryInfo {
    pub entry_number: u64,
    pub sequence_number: u16,
    pub in_use: bool,
    pub parent_entry_number: u64,
    pub parent_sequence_number: u16,
    pub parent_path: String,
    pub file_name: String,
    pub extension: String,
    pub file_size: u64,
    pub is_directory: bool,
    pub has_ads: bool,
    pub is_ads: bool,
    pub si_created: Option<DateTime<Utc>>,
    pub si_modified: Option<DateTime<Utc>>,
    pub si_accessed: Option<DateTime<Utc>>,
    pub si_record_modified: Option<DateTime<Utc>>,
    pub fn_created: Option<DateTime<Utc>>,
    pub fn_modified: Option<DateTime<Utc>>,
    pub fn_accessed: Option<DateTime<Utc>>,
    pub fn_record_modified: Option<DateTime<Utc>>,
    pub reference_count: u16,
    pub logfile_sequence_number: u64,
    pub security_id: u32,
    pub object_id_file_droid: String,
    pub zone_id_contents: String,
}

/// Parse an MFT file and yield entries one at a time via a callback.
pub fn parse_mft_entries<F>(
    mft_path: &Path,
    allocated_only: bool,
    mut callback: F,
) -> Result<u64>
where
    F: FnMut(MftEntryInfo) -> Result<()>,
{
    let mut parser = MftParser::from_path(mft_path)
        .map_err(|e| SpecterError::MftParse(e.to_string()))?;

    let total_entries = parser.get_entry_count();
    let mut processed: u64 = 0;

    for entry_idx in 0..total_entries {
        let entry = match parser.get_entry(entry_idx) {
            Ok(e) => e,
            Err(_) => {
                processed += 1;
                continue;
            }
        };

        let in_use = entry.is_allocated();
        if allocated_only && !in_use {
            processed += 1;
            continue;
        }

        let is_dir = entry.is_dir();

        let full_path = match parser.get_full_path_for_entry(&entry) {
            Ok(Some(p)) => p.to_string_lossy().to_string(),
            _ => String::new(),
        };

        let (parent_path, file_name) = split_path(&full_path);
        let extension = super::types::extract_extension(&file_name);

        let mut si_created: Option<DateTime<Utc>> = None;
        let mut si_modified: Option<DateTime<Utc>> = None;
        let mut si_accessed: Option<DateTime<Utc>> = None;
        let mut si_record_modified: Option<DateTime<Utc>> = None;
        let mut security_id: u32 = 0;

        let mut fn_created: Option<DateTime<Utc>> = None;
        let mut fn_modified: Option<DateTime<Utc>> = None;
        let mut fn_accessed: Option<DateTime<Utc>> = None;
        let mut fn_record_modified: Option<DateTime<Utc>> = None;
        let mut parent_entry_number: u64 = 0;
        let mut parent_sequence_number: u16 = 0;

        let mut file_size: u64 = 0;
        let mut data_attr_count = 0u32;
        let mut has_named_data = false;
        let mut object_id_file_droid = String::new();

        for attr_result in entry.iter_attributes() {
            let attr = match attr_result {
                Ok(a) => a,
                Err(_) => continue,
            };

            match attr.header.type_code {
                MftAttributeType::StandardInformation => {
                    if let Some(content) = attr.data.into_standard_info() {
                        si_created = Some(content.created);
                        si_modified = Some(content.modified);
                        si_accessed = Some(content.accessed);
                        si_record_modified = Some(content.mft_modified);
                        security_id = content.security_id;
                    }
                }
                MftAttributeType::FileName => {
                    if let Some(content) = attr.data.into_file_name() {
                        fn_created = Some(content.created);
                        fn_modified = Some(content.modified);
                        fn_accessed = Some(content.accessed);
                        fn_record_modified = Some(content.mft_modified);
                        parent_entry_number = content.parent.entry;
                        parent_sequence_number = content.parent.sequence;
                    }
                }
                MftAttributeType::DATA => {
                    data_attr_count += 1;
                    let attr_name = attr.header.name.as_str();
                    if !attr_name.is_empty() {
                        has_named_data = true;
                    }
                    if attr_name.is_empty() && file_size == 0 {
                        match &attr.header.residential_header {
                            ResidentialHeader::Resident(hdr) => {
                                file_size = hdr.data_size as u64;
                            }
                            ResidentialHeader::NonResident(hdr) => {
                                file_size = hdr.file_size;
                            }
                        }
                    }
                }
                MftAttributeType::ObjectId => {
                    if let Some(content) = attr.data.into_object_id() {
                        object_id_file_droid = content.object_id.to_string();
                    }
                }
                _ => {}
            }
        }

        let has_ads = data_attr_count > 1 || has_named_data;

        let info = MftEntryInfo {
            entry_number: entry.header.record_number,
            sequence_number: entry.header.sequence,
            in_use,
            parent_entry_number,
            parent_sequence_number,
            parent_path,
            file_name,
            extension,
            file_size,
            is_directory: is_dir,
            has_ads,
            is_ads: false,
            si_created,
            si_modified,
            si_accessed,
            si_record_modified,
            fn_created,
            fn_modified,
            fn_accessed,
            fn_record_modified,
            reference_count: entry.header.hard_link_count,
            logfile_sequence_number: entry.header.metadata_transaction_journal,
            security_id,
            object_id_file_droid,
            zone_id_contents: String::new(),
        };

        callback(info)?;
        processed += 1;
    }

    Ok(processed)
}

/// Get the total number of entries in an MFT file.
pub fn get_entry_count(mft_path: &Path) -> Result<u64> {
    let parser = MftParser::from_path(mft_path)
        .map_err(|e| SpecterError::MftParse(e.to_string()))?;
    Ok(parser.get_entry_count())
}

fn split_path(full_path: &str) -> (String, String) {
    let normalized = full_path.replace('/', "\\");
    if let Some(pos) = normalized.rfind('\\') {
        let parent = &normalized[..pos];
        let name = &normalized[pos + 1..];
        (
            if parent.is_empty() { "\\".to_string() } else { parent.to_string() },
            name.to_string(),
        )
    } else {
        (".".to_string(), normalized)
    }
}
