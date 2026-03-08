//! Two-pass MFT parser using memory-mapped I/O and custom attribute parsing.
//!
//! Pass 1: Extract file names + parent refs → build full path map in memory.
//! Pass 2: Extract all attributes → emit MftEntryInfo via callback.
//!
//! Matches MFTECmd behavior:
//! - One CSV row per $FILE_NAME attribute (ordered by NameType, DOS skipped by default)
//! - Separate ADS rows for named DATA streams
//! - FN (0x30) timestamps only when they differ from SI (0x10) timestamps
//! - Extension records (base_record != 0) are skipped
//! - Zone.Identifier extracted on ADS rows
//! - Forensic flags: SI<FN (timestomped), uSecZeros, Copied

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use super::attributes::{
    self, DataAttrInfo, FileNameInfo, LoggedUtilStreamInfo, ObjectIdInfo, ReparsePointInfo,
    StandardInfo,
};
use super::mft_entry::MftEntry;
use super::ntfs::{self, AttributeType};
use super::types::{Result, ReaperError};

/// Information extracted from an MFT entry for CSV output.
/// Matches MFTECmd's 34 CSV columns exactly.
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
    pub reference_count: u16,
    pub reparse_target: String,
    pub is_directory: bool,
    pub has_ads: bool,
    pub is_ads: bool,
    // Forensic flags
    pub timestomped: bool,
    pub usec_zeros: bool,
    pub copied: bool,
    pub si_flags: u32,
    pub name_type: String,
    // $STANDARD_INFORMATION timestamps (raw FILETIME)
    pub si_created: u64,
    pub si_modified: u64,
    pub si_accessed: u64,
    pub si_record_modified: u64,
    // $FILE_NAME timestamps - only populated when different from SI (or when no SI exists)
    pub fn_created: u64,
    pub fn_modified: u64,
    pub fn_accessed: u64,
    pub fn_record_modified: u64,
    pub usn: u64,
    pub logfile_sequence_number: u64,
    pub security_id: u32,
    pub object_id_file_droid: String,
    pub logged_util_stream: String,
    pub zone_id_contents: String,
    pub source_file: String,
}

/// Lightweight entry info for path resolution (pass 1).
struct PathEntry {
    name: String,
    parent_entry: u64,
}

/// Parse an MFT file using a fast two-pass approach.
/// Matches MFTECmd behavior: one row per FN attribute, ADS rows, conditional FN timestamps.
pub fn parse_mft_entries<F>(
    mft_path: &Path,
    allocated_only: bool,
    mut callback: F,
) -> Result<u64>
where
    F: FnMut(MftEntryInfo) -> Result<()>,
{
    let mft_path_str = format!(".\\{}", mft_path.file_name().unwrap_or_default().to_string_lossy());
    let file = std::fs::File::open(mft_path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let data = &mmap[..];

    let entry_size = detect_entry_size(data)?;
    let total_entries = data.len() / entry_size;

    // === PASS 1: Build path map + extension record reverse map ===
    let mut path_entries: HashMap<u64, PathEntry> = HashMap::with_capacity(total_entries);
    // Map: base_entry_number -> list of extension entry numbers
    let mut extension_map: HashMap<u64, Vec<u64>> = HashMap::new();

    for entry_idx in 0..total_entries {
        let offset = entry_idx * entry_size;
        let end = offset + entry_size;
        if end > data.len() {
            break;
        }

        let entry = match MftEntry::from_slice(&data[offset..end], entry_idx as u64) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Track extension records: if base_record_entry > 0, this is an extension
        if entry.header.base_record_entry > 0 {
            extension_map
                .entry(entry.header.base_record_entry)
                .or_default()
                .push(entry_idx as u64);
        }

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

    // Fixup: for entries that only have a DOS/short name, check extension records
    // for a Win32 long name (needed for correct path resolution of WinSxS dirs etc.)
    for (base_entry, ext_entries) in &extension_map {
        // Only fixup entries that exist and have a short name
        let needs_fixup = path_entries.get(base_entry).map_or(false, |pe| {
            pe.name.contains('~') && pe.name.len() <= 12
        });
        if !needs_fixup {
            continue;
        }
        for &ext_num in ext_entries {
            let ext_offset = ext_num as usize * entry_size;
            let ext_end = ext_offset + entry_size;
            if ext_end > data.len() {
                continue;
            }
            let ext_entry = match MftEntry::from_slice(&data[ext_offset..ext_end], ext_num) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if let Some(fn_info) = find_best_filename(&ext_entry) {
                if fn_info.is_win32_name() && !fn_info.name.contains('~') {
                    path_entries.insert(
                        *base_entry,
                        PathEntry {
                            name: fn_info.name,
                            parent_entry: fn_info.parent_entry,
                        },
                    );
                    break;
                }
            }
        }
    }

    let full_paths = build_all_paths(&path_entries);

    // === PASS 2: Extract full attributes + write output ===
    let mut processed: u64 = 0;

    for entry_idx in 0..total_entries {
        let offset = entry_idx * entry_size;
        let end = offset + entry_size;
        if end > data.len() {
            break;
        }

        let entry = match MftEntry::from_slice(&data[offset..end], entry_idx as u64) {
            Ok(e) => e,
            Err(_) => {
                processed += 1;
                continue;
            }
        };

        // Skip extension records (MFTECmd behavior: base_record != 0 means extension)
        if entry.header.base_record_entry > 0 {
            processed += 1;
            continue;
        }

        let in_use = entry.header.is_in_use();
        if allocated_only && !in_use {
            processed += 1;
            continue;
        }

        let is_dir = entry.header.is_directory();

        // Collect all attributes from the base entry
        let mut si: Option<StandardInfo> = None;
        let mut fn_attrs: Vec<FileNameInfo> = Vec::new();
        let mut object_id: Option<ObjectIdInfo> = None;
        let mut reparse: Option<ReparsePointInfo> = None;
        let mut logged_util: Option<LoggedUtilStreamInfo> = None;
        let mut data_attrs: Vec<DataAttrInfo> = Vec::new();
        for attr in entry.iter_attributes() {
            collect_attribute(
                &attr, &mut si, &mut fn_attrs, &mut object_id, &mut reparse,
                &mut logged_util, &mut data_attrs,
            );
        }

        // Merge attributes from extension records (using reverse map built in Pass 1)
        if let Some(ext_entries) = extension_map.get(&(entry_idx as u64)) {
            for &ext_entry_num in ext_entries {
                let ext_offset = ext_entry_num as usize * entry_size;
                let ext_end = ext_offset + entry_size;
                if ext_end > data.len() {
                    continue;
                }
                let ext_entry = match MftEntry::from_slice(
                    &data[ext_offset..ext_end],
                    ext_entry_num,
                ) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for attr in ext_entry.iter_attributes() {
                    collect_attribute(
                        &attr, &mut si, &mut fn_attrs, &mut object_id, &mut reparse,
                        &mut logged_util, &mut data_attrs,
                    );
                }
            }
        }

        // If no FN attributes found, skip (shouldn't happen for valid entries)
        if fn_attrs.is_empty() {
            processed += 1;
            continue;
        }

        // Sort FN attributes by NameType (MFTECmd: OrderBy NameType)
        fn_attrs.sort_by_key(|f| f.name_type as u8);

        // Deduplicate DATA attributes by stream name (extension merging may bring duplicates)
        data_attrs.sort_by(|a, b| a.stream_name.cmp(&b.stream_name));
        data_attrs.dedup_by(|a, b| a.stream_name == b.stream_name);

        // Reference count = number of non-DOS FN attributes (MFTECmd behavior)
        let reference_count = fn_attrs.iter()
            .filter(|f| f.name_type != ntfs::FileNamespace::Dos)
            .count() as u16;

        // Determine file size from unnamed DATA attribute.
        // If no unnamed DATA exists but named streams do (e.g. $Secure, $UsnJrnl),
        // MFTECmd uses the first named stream's size.
        let mut file_size: u64 = 0;
        let mut first_named_size: u64 = 0;
        let mut has_unnamed_data = false;
        for da in &data_attrs {
            if da.stream_name.is_empty() {
                has_unnamed_data = true;
                if file_size == 0 {
                    file_size = da.data_size;
                }
            } else if first_named_size == 0 {
                first_named_size = da.data_size;
            }
        }
        if !has_unnamed_data && file_size == 0 {
            file_size = first_named_size;
        }

        // ADS = named DATA streams
        let ads: Vec<&DataAttrInfo> = data_attrs.iter().filter(|d| !d.stream_name.is_empty()).collect();
        let has_ads = !ads.is_empty();

        // Extract Zone.Identifier content from ADS
        let mut zone_id_contents = String::new();
        for da in &ads {
            if da.stream_name == "Zone.Identifier" {
                if da.is_resident && !da.resident_data.is_empty() {
                    zone_id_contents = attributes::extract_zone_id(&da.resident_data);
                } else if !da.is_resident {
                    zone_id_contents = "(Zone.Identifier data is non-resident)".to_string();
                }
            }
        }

        // SI data
        let (si_created, si_modified, si_accessed, si_record_modified, si_flags, security_id, usn) =
            match &si {
                Some(s) => (
                    s.created,
                    s.modified,
                    s.accessed,
                    s.record_modified,
                    s.flags,
                    s.security_id,
                    s.usn,
                ),
                None => (0, 0, 0, 0, 0, 0, 0),
            };

        let mut reparse_target = reparse.map(|r| r.target).unwrap_or_default();
        let mut logged_util_str = logged_util.map(|l| l.stream_name).unwrap_or_default();
        let mut object_id_str = object_id.map(|o| o.object_id).unwrap_or_default();

        // Pre-compute values constant across all FN iterations
        let record_number = entry.header.record_number;
        let seq_number = entry.header.sequence_number;
        let lsn = entry.header.logfile_sequence_number;

        // Filter out DOS-only FN attributes upfront
        let emit_fns: Vec<&FileNameInfo> = fn_attrs.iter()
            .filter(|f| f.name_type != ntfs::FileNamespace::Dos)
            .collect();
        let is_last_fn = emit_fns.len() == 1;

        // Emit one row per FN attribute (MFTECmd behavior)
        for (fn_idx, fn_info) in emit_fns.iter().enumerate() {
            let last_fn = is_last_fn || fn_idx == emit_fns.len() - 1;

            let parent_path = resolve_parent_path(&full_paths, fn_info.parent_entry, entry_idx as u64);

            let extension = if !is_dir {
                extract_extension_dotted(&fn_info.name)
            } else {
                String::new()
            };

            // FN timestamps: only include when different from SI (MFTECmd behavior)
            let (fn_created, fn_modified, fn_accessed, fn_record_modified) = if si.is_some() {
                let fc = if fn_info.created != si_created { fn_info.created } else { 0 };
                let fm = if fn_info.modified != si_modified { fn_info.modified } else { 0 };
                let fa = if fn_info.accessed != si_accessed { fn_info.accessed } else { 0 };
                let fr = if fn_info.record_modified != si_record_modified { fn_info.record_modified } else { 0 };
                (fc, fm, fa, fr)
            } else {
                (fn_info.created, fn_info.modified, fn_info.accessed, fn_info.record_modified)
            };

            // For entries without SI, MFTECmd puts FN timestamps in 0x10 columns
            let (eff_si_created, eff_si_modified, eff_si_accessed, eff_si_record_modified) = if si.is_some() {
                (si_created, si_modified, si_accessed, si_record_modified)
            } else {
                (0, fn_info.modified, fn_info.record_modified, fn_info.accessed)
            };

            let timestomped = fn_created != 0 && si_created != 0 && si_created < fn_created;
            let usec_zeros = has_millisecond_zero(eff_si_created)
                || has_millisecond_zero(eff_si_modified);
            let copied = si_modified != 0 && si_created != 0 && si_modified < si_created;

            // On the last FN iteration, move strings instead of cloning
            let (rt, oid, lus, sf) = if last_fn && ads.is_empty() {
                (
                    std::mem::take(&mut reparse_target),
                    std::mem::take(&mut object_id_str),
                    std::mem::take(&mut logged_util_str),
                    mft_path_str.clone(),
                )
            } else {
                (
                    reparse_target.clone(),
                    object_id_str.clone(),
                    logged_util_str.clone(),
                    mft_path_str.clone(),
                )
            };

            let info = MftEntryInfo {
                entry_number: record_number,
                sequence_number: seq_number,
                in_use,
                parent_entry_number: fn_info.parent_entry,
                parent_sequence_number: fn_info.parent_sequence,
                parent_path,
                file_name: fn_info.name.clone(),
                extension,
                file_size,
                reference_count,
                reparse_target: rt,
                is_directory: is_dir,
                has_ads,
                is_ads: false,
                timestomped,
                usec_zeros,
                copied,
                si_flags,
                name_type: fn_info.name_type.as_str().to_string(),
                si_created: eff_si_created,
                si_modified: eff_si_modified,
                si_accessed: eff_si_accessed,
                si_record_modified: eff_si_record_modified,
                fn_created,
                fn_modified,
                fn_accessed,
                fn_record_modified,
                usn,
                logfile_sequence_number: lsn,
                security_id,
                object_id_file_droid: oid,
                logged_util_stream: lus,
                zone_id_contents: String::new(),
                source_file: sf,
            };

            callback(info)?;

            // Emit ADS rows after each FN row
            for (ads_idx, da) in ads.iter().enumerate() {
                let ads_ext = extract_extension_dotted(&da.stream_name);
                let ads_zone = if da.stream_name == "Zone.Identifier" {
                    zone_id_contents.clone()
                } else {
                    String::new()
                };

                let ads_parent = resolve_parent_path(&full_paths, fn_info.parent_entry, entry_idx as u64);

                // Move on last ADS of last FN
                let (ads_oid, ads_lus, ads_sf) = if last_fn && ads_idx == ads.len() - 1 {
                    (
                        std::mem::take(&mut object_id_str),
                        std::mem::take(&mut logged_util_str),
                        mft_path_str.clone(),
                    )
                } else {
                    (object_id_str.clone(), logged_util_str.clone(), mft_path_str.clone())
                };

                let mut ads_filename = String::with_capacity(fn_info.name.len() + 1 + da.stream_name.len());
                ads_filename.push_str(&fn_info.name);
                ads_filename.push(':');
                ads_filename.push_str(&da.stream_name);

                let ads_info = MftEntryInfo {
                    entry_number: record_number,
                    sequence_number: seq_number,
                    in_use,
                    parent_entry_number: fn_info.parent_entry,
                    parent_sequence_number: fn_info.parent_sequence,
                    parent_path: ads_parent,
                    file_name: ads_filename,
                    extension: ads_ext,
                    file_size: da.data_size,
                    reference_count,
                    reparse_target: String::new(),
                    is_directory: false,
                    has_ads: false,
                    is_ads: true,
                    timestomped,
                    usec_zeros,
                    copied,
                    si_flags,
                    name_type: fn_info.name_type.as_str().to_string(),
                    si_created: eff_si_created,
                    si_modified: eff_si_modified,
                    si_accessed: eff_si_accessed,
                    si_record_modified: eff_si_record_modified,
                    fn_created,
                    fn_modified,
                    fn_accessed,
                    fn_record_modified,
                    usn,
                    logfile_sequence_number: lsn,
                    security_id,
                    object_id_file_droid: ads_oid,
                    logged_util_stream: ads_lus,
                    zone_id_contents: ads_zone,
                    source_file: ads_sf,
                };
                callback(ads_info)?;
            }
        }

        processed += 1;
    }

    Ok(processed)
}

/// Resolve parent path for an FN attribute's parent_entry.
fn resolve_parent_path(full_paths: &HashMap<u64, String>, parent_entry: u64, entry_idx: u64) -> String {
    match full_paths.get(&parent_entry) {
        Some(p) if p == "." || parent_entry == 5 => ".".to_string(),
        Some(p) => {
            let mut s = String::with_capacity(2 + p.len());
            s.push_str(".\\");
            s.push_str(p);
            s
        }
        None => {
            full_paths
                .get(&entry_idx)
                .and_then(|p| {
                    p.rfind('\\').map(|pos| {
                        let parent = &p[..pos];
                        if parent == "." {
                            ".".to_string()
                        } else {
                            let mut s = String::with_capacity(2 + parent.len());
                            s.push_str(".\\");
                            s.push_str(parent);
                            s
                        }
                    })
                })
                .unwrap_or_else(|| ".".to_string())
        }
    }
}

/// Get the total number of entries in an MFT file.
pub fn get_entry_count(mft_path: &Path) -> Result<u64> {
    let file = std::fs::File::open(mft_path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    let mut buf = [0u8; 56];
    let mut reader = std::io::BufReader::new(file);
    reader.read_exact(&mut buf)?;

    // allocated_size at offset 28 (4 bytes LE)
    let entry_size = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
    if entry_size == 0 {
        return Ok(0);
    }

    Ok(file_size / entry_size as u64)
}

/// Detect the MFT entry size from the first entry header.
fn detect_entry_size(data: &[u8]) -> Result<usize> {
    if data.len() < 56 {
        return Err(ReaperError::MftParse("MFT file too small".into()));
    }
    let entry_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as usize;
    if entry_size == 0 || entry_size > 16384 {
        return Err(ReaperError::MftParse(format!(
            "Invalid entry size: {}",
            entry_size
        )));
    }
    Ok(entry_size)
}

/// Collect a single attribute into the appropriate collection.
fn collect_attribute(
    attr: &super::mft_entry::RawAttribute,
    si: &mut Option<StandardInfo>,
    fn_attrs: &mut Vec<FileNameInfo>,
    object_id: &mut Option<ObjectIdInfo>,
    reparse: &mut Option<ReparsePointInfo>,
    logged_util: &mut Option<LoggedUtilStreamInfo>,
    data_attrs: &mut Vec<DataAttrInfo>,
) {
    match attr.attr_type {
        AttributeType::StandardInformation => {
            if attr.is_resident && si.is_none() {
                *si = StandardInfo::from_resident_data(&attr.resident_data);
            }
        }
        AttributeType::FileName => {
            if attr.is_resident {
                if let Some(fn_info) = FileNameInfo::from_resident_data(&attr.resident_data) {
                    fn_attrs.push(fn_info);
                }
            }
        }
        AttributeType::ObjectId => {
            if attr.is_resident && object_id.is_none() {
                *object_id = ObjectIdInfo::from_resident_data(&attr.resident_data);
            }
        }
        AttributeType::Data => {
            data_attrs.push(DataAttrInfo::from_raw(attr));
        }
        AttributeType::ReparsePoint => {
            if attr.is_resident && reparse.is_none() {
                *reparse = ReparsePointInfo::from_resident_data(&attr.resident_data);
            }
        }
        AttributeType::LoggedUtilityStream => {
            if logged_util.is_none() {
                *logged_util = Some(LoggedUtilStreamInfo::from_raw(attr));
            }
        }
        _ => {}
    }
}

/// Find the best file name attribute from an MFT entry (for path building).
/// Prefers Win32 > Win32AndDos > Posix, skips DOS-only names.
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
                        || (fn_info.name_type == ntfs::FileNamespace::Win32
                            && prev.name_type != ntfs::FileNamespace::Win32)
                }
            };
            if dominated {
                best = Some(fn_info);
            }
        }
    }

    best
}

/// Check if a FILETIME has millisecond == 0 (MFTECmd uSecZeros check).
/// FILETIME is 100ns ticks since 1601-01-01. Millisecond zero means the
/// fractional-second part (below 1 second) has no millisecond component.
fn has_millisecond_zero(filetime: u64) -> bool {
    if filetime == 0 {
        return false;
    }
    // 10_000 ticks = 1 millisecond
    // Check if the millisecond component within the second is 0
    let ticks_within_second = filetime % 10_000_000; // ticks within current second
    let milliseconds = ticks_within_second / 10_000; // millisecond component
    milliseconds == 0
}

/// Extract file extension with leading dot (MFTECmd uses Path.GetExtension which includes the dot).
/// C# Path.GetExtension(".config") returns ".config", so pos == 0 is valid.
fn extract_extension_dotted(filename: &str) -> String {
    if let Some(pos) = filename.rfind('.') {
        if pos < filename.len() - 1 {
            return filename[pos..].to_string();
        }
    }
    String::new()
}

/// Build full paths for all entries from the path_entries map.
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
