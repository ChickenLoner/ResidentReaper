use std::path::Path;

use chrono::{DateTime, Utc};
use mft::attribute::MftAttributeType;
use mft::MftParser;

use super::types::{Result, SpecterError, extract_extension};

/// A resident data entry found in an MFT record.
#[derive(Clone)]
pub struct ResidentEntry {
    pub entry_number: u64,
    pub sequence_number: u16,
    pub file_name: String,
    pub parent_path: String,
    pub data_size: u32,
    pub extension: String,
    pub si_created: Option<DateTime<Utc>>,
    pub si_modified: Option<DateTime<Utc>>,
    pub data: Vec<u8>,
    pub is_ads: bool,
    pub stream_name: String,
}

/// Scan an MFT file for entries with resident DATA attributes.
pub fn scan_resident_data<F, P>(
    mft_path: &Path,
    mut on_entry: F,
    mut on_progress: P,
) -> Result<ScanResult>
where
    F: FnMut(ResidentEntry),
    P: FnMut(u64, u64),
{
    let mut parser = MftParser::from_path(mft_path)
        .map_err(|e| SpecterError::MftParse(e.to_string()))?;

    let total_entries = parser.get_entry_count();
    let mut resident_count: u64 = 0;

    for entry_idx in 0..total_entries {
        if entry_idx % 10000 == 0 {
            on_progress(entry_idx, total_entries);
        }

        let entry = match parser.get_entry(entry_idx) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.is_allocated() {
            continue;
        }

        let full_path = match parser.get_full_path_for_entry(&entry) {
            Ok(Some(p)) => p.to_string_lossy().to_string(),
            _ => String::new(),
        };

        let (parent_path, file_name) = split_path(&full_path);
        let extension = extract_extension(&file_name);

        let mut si_created: Option<DateTime<Utc>> = None;
        let mut si_modified: Option<DateTime<Utc>> = None;

        struct ResidentDataInfo {
            data: Vec<u8>,
            stream_name: String,
            is_ads: bool,
            data_size: u32,
        }
        let mut resident_datas: Vec<ResidentDataInfo> = Vec::new();

        for attr_result in entry.iter_attributes() {
            let attr = match attr_result {
                Ok(a) => a,
                Err(_) => continue,
            };

            match attr.header.type_code {
                MftAttributeType::StandardInformation => {
                    if let Some(si) = attr.data.into_standard_info() {
                        si_created = Some(si.created);
                        si_modified = Some(si.modified);
                    }
                }
                MftAttributeType::DATA => {
                    // form_code == 0 means resident
                    if attr.header.form_code == 0 {
                        if let Some(data_attr) = attr.data.into_data() {
                            let data_bytes = data_attr.data().to_vec();
                            if !data_bytes.is_empty() {
                                let stream_name = attr.header.name.clone();
                                let is_ads = !stream_name.is_empty();
                                resident_datas.push(ResidentDataInfo {
                                    data_size: data_bytes.len() as u32,
                                    data: data_bytes,
                                    stream_name,
                                    is_ads,
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        for rd in resident_datas {
            let resident = ResidentEntry {
                entry_number: entry.header.record_number,
                sequence_number: entry.header.sequence,
                file_name: file_name.clone(),
                parent_path: parent_path.clone(),
                data_size: rd.data_size,
                extension: extension.clone(),
                si_created,
                si_modified,
                data: rd.data,
                is_ads: rd.is_ads,
                stream_name: rd.stream_name,
            };

            on_entry(resident);
            resident_count += 1;
        }
    }

    on_progress(total_entries, total_entries);

    Ok(ScanResult {
        total_entries_scanned: total_entries,
        resident_entries_found: resident_count,
    })
}

pub struct ScanResult {
    pub total_entries_scanned: u64,
    pub resident_entries_found: u64,
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
