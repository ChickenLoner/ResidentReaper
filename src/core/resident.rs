use std::collections::HashMap;
use std::path::Path;

use super::attributes::{FileNameInfo, StandardInfo};
use super::mft_entry::MftEntry;
use super::ntfs::{AttributeType, FileNamespace};
use super::types::{Result, SpecterError};

/// A resident data entry found in an MFT record.
#[derive(Clone)]
pub struct ResidentEntry {
    pub entry_number: u64,
    pub sequence_number: u16,
    pub file_name: String,
    pub parent_path: String,
    pub data_size: u32,
    pub extension: String,
    pub si_created: u64,
    pub si_modified: u64,
    pub data: Vec<u8>,
    pub is_ads: bool,
    pub stream_name: String,
}

pub struct ScanResult {
    pub total_entries_scanned: u64,
    pub resident_entries_found: u64,
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
    let file = std::fs::File::open(mft_path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let data = &mmap[..];

    let entry_size = detect_entry_size(data)?;
    let total_entries = data.len() / entry_size;

    // Pass 1: build path map
    let mut path_entries: HashMap<u64, PathEntry> = HashMap::with_capacity(total_entries);
    for entry_idx in 0..total_entries {
        let offset = entry_idx * entry_size;
        let end = offset + entry_size;
        if end > data.len() {
            break;
        }
        let entry = match MftEntry::from_buffer(data[offset..end].to_vec(), entry_idx as u64) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if let Some(fn_info) = find_best_filename(&entry) {
            path_entries.insert(
                entry_idx as u64,
                PathEntry {
                    name: fn_info.name,
                    parent_entry: fn_info.parent_entry,
                },
            );
        }
    }
    let full_paths = build_all_paths(&path_entries);

    // Pass 2: find resident DATA attributes
    let mut resident_count: u64 = 0;

    for entry_idx in 0..total_entries {
        if entry_idx % 10000 == 0 {
            on_progress(entry_idx as u64, total_entries as u64);
        }

        let offset = entry_idx * entry_size;
        let end = offset + entry_size;
        if end > data.len() {
            break;
        }

        let entry = match MftEntry::from_buffer(data[offset..end].to_vec(), entry_idx as u64) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.header.is_in_use() {
            continue;
        }

        let full_path = full_paths
            .get(&(entry_idx as u64))
            .cloned()
            .unwrap_or_default();
        let (parent_path, file_name) = split_path(&full_path);
        let extension = super::types::extract_extension(&file_name);

        let mut si_created: u64 = 0;
        let mut si_modified: u64 = 0;

        struct ResidentDataInfo {
            data: Vec<u8>,
            stream_name: String,
            is_ads: bool,
            data_size: u32,
        }
        let mut resident_datas: Vec<ResidentDataInfo> = Vec::new();

        for attr in entry.iter_attributes() {
            match attr.attr_type {
                AttributeType::StandardInformation => {
                    if attr.is_resident {
                        if let Some(si) = StandardInfo::from_resident_data(&attr.resident_data) {
                            si_created = si.created;
                            si_modified = si.modified;
                        }
                    }
                }
                AttributeType::Data => {
                    if attr.is_resident && !attr.resident_data.is_empty() {
                        let stream_name = attr.name.clone();
                        let is_ads = !stream_name.is_empty();
                        resident_datas.push(ResidentDataInfo {
                            data_size: attr.resident_data.len() as u32,
                            data: attr.resident_data.clone(),
                            stream_name,
                            is_ads,
                        });
                    }
                }
                _ => {}
            }
        }

        for rd in resident_datas {
            let resident = ResidentEntry {
                entry_number: entry.header.record_number,
                sequence_number: entry.header.sequence_number,
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

    on_progress(total_entries as u64, total_entries as u64);

    Ok(ScanResult {
        total_entries_scanned: total_entries as u64,
        resident_entries_found: resident_count,
    })
}

// --- Path resolution helpers (same logic as mft_parser) ---

struct PathEntry {
    name: String,
    parent_entry: u64,
}

fn detect_entry_size(data: &[u8]) -> Result<usize> {
    if data.len() < 56 {
        return Err(SpecterError::MftParse("MFT file too small".into()));
    }
    let entry_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as usize;
    if entry_size == 0 || entry_size > 16384 {
        return Err(SpecterError::MftParse(format!(
            "Invalid entry size: {}",
            entry_size
        )));
    }
    Ok(entry_size)
}

fn find_best_filename(entry: &MftEntry) -> Option<FileNameInfo> {
    let mut best: Option<FileNameInfo> = None;
    for attr in entry.iter_attributes() {
        if attr.attr_type != AttributeType::FileName || !attr.is_resident {
            continue;
        }
        if let Some(fn_info) = FileNameInfo::from_resident_data(&attr.resident_data) {
            let dominated = match &best {
                None => true,
                Some(prev) => {
                    fn_info.is_win32_name() && !prev.is_win32_name()
                        || (fn_info.name_type == FileNamespace::Win32
                            && prev.name_type != FileNamespace::Win32)
                }
            };
            if dominated {
                best = Some(fn_info);
            }
        }
    }
    best
}

fn build_all_paths(path_entries: &HashMap<u64, PathEntry>) -> HashMap<u64, String> {
    let mut resolved: HashMap<u64, String> = HashMap::with_capacity(path_entries.len());
    for &entry_id in path_entries.keys() {
        if !resolved.contains_key(&entry_id) {
            resolve_path_with_depth(entry_id, path_entries, &mut resolved, 0);
        }
    }
    resolved
}

fn resolve_path_with_depth(
    entry_id: u64,
    path_entries: &HashMap<u64, PathEntry>,
    resolved: &mut HashMap<u64, String>,
    depth: u32,
) -> String {
    if depth > 256 {
        return String::from("[Orphaned]");
    }
    if let Some(path) = resolved.get(&entry_id) {
        return path.clone();
    }
    let pe = match path_entries.get(&entry_id) {
        Some(pe) => pe,
        None => {
            let path = String::from("[Unknown]");
            resolved.insert(entry_id, path.clone());
            return path;
        }
    };
    let parent_id = pe.parent_entry;
    let name = &pe.name;

    if entry_id == 5 {
        let path = String::from(".");
        resolved.insert(entry_id, path.clone());
        return path;
    }
    if parent_id == 5 {
        let path = name.clone();
        resolved.insert(entry_id, path.clone());
        return path;
    }
    if parent_id == entry_id {
        let path = format!("[Orphaned]\\{}", name);
        resolved.insert(entry_id, path.clone());
        return path;
    }

    let parent_path = resolve_path_with_depth(parent_id, path_entries, resolved, depth + 1);
    let full_path = if parent_path.is_empty() || parent_path == "." {
        name.clone()
    } else {
        format!("{}\\{}", parent_path, name)
    };
    resolved.insert(entry_id, full_path.clone());
    full_path
}

fn split_path(full_path: &str) -> (String, String) {
    let normalized = full_path.replace('/', "\\");
    if let Some(pos) = normalized.rfind('\\') {
        let parent = &normalized[..pos];
        let name = &normalized[pos + 1..];
        (
            if parent.is_empty() {
                "\\".to_string()
            } else {
                parent.to_string()
            },
            name.to_string(),
        )
    } else {
        (".".to_string(), normalized)
    }
}
