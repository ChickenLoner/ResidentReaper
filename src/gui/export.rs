use std::path::Path;

use crate::core::resident::ResidentEntry;

/// Export selected resident entries to a directory.
/// Each file is saved as `{entry_number}_{filename}`.
pub fn export_entries_to_directory(
    entries: &[&ResidentEntry],
    output_dir: &Path,
) -> Result<usize, String> {
    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    let mut exported = 0;
    for entry in entries {
        let safe_name = sanitize_filename(&entry.file_name);
        let filename = if entry.is_ads {
            format!(
                "{}_{}_ADS_{}",
                entry.entry_number,
                safe_name,
                sanitize_filename(&entry.stream_name)
            )
        } else {
            format!("{}_{}", entry.entry_number, safe_name)
        };

        let path = output_dir.join(&filename);
        std::fs::write(&path, &entry.data)
            .map_err(|e| format!("Failed to write {}: {}", filename, e))?;
        exported += 1;
    }

    Ok(exported)
}

/// Export a single entry with a save-as dialog path.
pub fn export_single_entry(entry: &ResidentEntry, output_path: &Path) -> Result<(), String> {
    std::fs::write(output_path, &entry.data)
        .map_err(|e| format!("Failed to write file: {}", e))
}

/// Convert resident data bytes to a hex string for clipboard.
pub fn bytes_to_hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Sanitize a filename by replacing invalid characters.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}
