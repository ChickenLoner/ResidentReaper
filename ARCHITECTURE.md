# ResidentReaper Architecture

## Overview

**ResidentReaper** is a Rust-based NTFS forensic tool for parsing MFT and USN Journal artifacts. Outputs MFTECmd-compatible CSV. Has both CLI and egui-based GUI.

- **Version:** 1.2.0 | **License:** MIT | **Author:** Warawut Manosong
- **Build:** `--features cli` (default) or `--features cli,gui`

---

## Directory Structure

```
ResidentReaper/
├── Cargo.toml
├── build.rs                  # icon.png → icon.ico, Windows PE metadata via winres
├── icon.png
└── src/
    ├── main.rs               # Entry point, feature dispatch
    ├── core/                 # Low-level NTFS parsing
    │   ├── types.rs          # ReaperError, timestamp formatters, attribute decoders
    │   ├── ntfs.rs           # NTFS constants, AttributeType enum, FILETIME conversion
    │   ├── mft_entry.rs      # MFT entry header parsing, fixup, attribute iteration
    │   ├── attributes.rs     # Parsed attribute structs (SI, FN, ObjectId, Data, ...)
    │   ├── mft_parser.rs     # Two-pass MFT parser → MftEntryInfo callback
    │   ├── mft_csv.rs        # MftEntryInfo → 34-column MFTECmd-compatible CSV row
    │   ├── usn_parser.rs     # USN Journal V2/V3 parser → UsnRecord callback
    │   ├── usn_csv.rs        # UsnRecord → 13-column CSV row
    │   └── resident.rs       # Resident DATA scanner → ResidentEntry (GUI use)
    ├── cli/
    │   ├── mod.rs            # Clap arg structs, subcommand dispatch, output naming
    │   ├── mft_cmd.rs        # `mft` subcommand: parse → CSV + progress bar
    │   └── usn_cmd.rs        # `usn` subcommand: parse $J + optional $MFT → CSV
    └── gui/
        ├── mod.rs            # eframe window setup, icon loading
        ├── app.rs            # ResidentHunterApp: state, bg thread, egui update loop
        ├── table_view.rs     # Sortable egui_extras table of ResidentEntry rows
        ├── filters.rs        # FilterState: search, extension, size filters
        └── export.rs         # File export, hex/ASCII formatting, filename sanitize
```

---

## Module Responsibilities

### `core/types.rs`
- `ReaperError` — error enum (IO, MftParse, UsnParse, Csv, Generic)
- `format_datetime_mftecmd()` — `DateTime<Utc>` → `yyyy-MM-dd HH:mm:ss.fffffff`
- `format_timestamp_filetime()` — FILETIME u64 → MFTECmd string
- `extract_extension()`, `decode_file_attributes()`

### `core/ntfs.rs`
- Constants: `EPOCH_DIFF`, `SIGNATURE_FILE`, entry flags
- `AttributeType` enum: `0x10` SI, `0x20` AttrList, `0x30` FN, `0x40` ObjectId, `0x80` Data, `0xC0` Reparse, `0x100` LoggedUtilStream
- `FileNamespace` enum: Posix, Win32, Dos, Win32AndDos
- `filetime_to_datetime()`, `decode_utf16le()`, `format_guid()`, `decode_si_flags()`

### `core/mft_entry.rs`
- `EntryHeader` — 56-byte header (signature, flags, offsets, LSN, seq)
- `MftEntry::from_slice()` — parse + apply fixup array
- `MftEntry::iter_attributes()` — iterate `RawAttribute` over entry buffer

### `core/attributes.rs`
High-level attribute parsers from raw resident data:

| Struct | Attribute | Key Fields |
|--------|-----------|------------|
| `StandardInfo` | 0x10 | created/modified/record_modified/accessed, flags, security_id, USN |
| `FileNameInfo` | 0x30 | parent ref, timestamps, allocated/real size, namespace, name |
| `ObjectIdInfo` | 0x40 | object_id, birth_volume_id, birth_object_id, domain_id (GUIDs) |
| `ReparsePointInfo` | 0xC0 | reparse_tag, target path (mount points & symlinks) |
| `DataAttrInfo` | 0x80 | stream_name, is_resident, data_size, resident bytes |
| `LoggedUtilStreamInfo` | 0x100 | stream_name, data_size, resident bytes |

### `core/mft_parser.rs`
Two-pass parser. Emits `MftEntryInfo` via callback.

**Pass 1** — Build `HashMap<u64, PathEntry>` from all $FILE_NAME attributes. Merge extension records. Recursively resolve full paths.

**Pass 2** — Emit one CSV row per non-DOS $FILE_NAME. Emit additional rows for ADS (named $DATA streams) after each FN row.

**Forensic flags computed here:**
- `si_lt_fn` — SI created < FN created (timestomped)
- `usec_zeros` — sub-second precision = 0 (manual timestamp set)
- `copied` — SI modified < SI created (copied file)

### `core/mft_csv.rs`
`MftCsvRow` — serde-serialize to 34 MFTECmd-compatible columns. `From<MftEntryInfo>` impl.

### `core/usn_parser.rs`
- Parses USN V2 (60+ byte) and V3 (76+ byte) records from sparse $J file
- `skip_zeros()` — skips 4KB blocks, then 8-byte chunks to handle sparse regions
- `decode_reason()` / `decode_source_info()` — flags → pipe-separated string
- `collect_records()` — collects all records into `Vec<UsnRecord>` for rewind processing
- `UsnPathEntry` — name + parent ref for one `(entry, seq)` allocation in the rewind map

### `core/usn_csv.rs`
`UsnCsvRow` — serde-serialize to 13 columns. `from_record(record, parent_path, source_file)`.

### `core/resident.rs`
Same two-pass logic as `mft_parser` but collects `ResidentEntry` (includes raw bytes) for GUI display and export. Emits entries via callback with progress %.

### `cli/mod.rs`
Clap-derived `Cli` → `Commands`:
- `Commands::Mft(MftArgs)` — file, output, allocated_only, verbose
- `Commands::Usn(UsnArgs)` — file, output, mft (optional), raw, verbose
- `Commands::Hunt(HuntArgs)` — file (optional pre-load)

`UsnArgs::raw` — disables rewind; MFT resolution still applies if `-m` given.

`default_output_name()` — generates `<yyyyMMddHHmmss>_<LABEL>_Output.csv`.

### `cli/mft_cmd.rs`
1. `get_entry_count()` for indicatif progress bar
2. Create CSV writer (256KB BufWriter)
3. `parse_mft_entries()` callback → `MftCsvRow` → serialize
4. Flush, report

### `cli/usn_cmd.rs`
1. If `-m`: parse $MFT → `Vec<Option<PathInfo>>` indexed by entry number; write MFT CSV
2. `collect_records()` — load all USN records into memory
3. If rewind (default): walk records newest→oldest, build `HashMap<(entry, seq), UsnPathEntry>`, resolve each record's `ParentPath` BEFORE updating the map
   - `RenameOldName`: overwrite map entry (exposes pre-rename name for earlier records)
   - All others: `or_insert` (first-seen = most recent state going backwards)
   - `resolve_full_path()`: rewind map first (historical), MFT fallback (entries not in journal)
4. If `--raw`: MFT-only path lookup, no rewind map
5. Emit `UsnCsvRow` in original chronological order

### `gui/app.rs`
`ResidentHunterApp` state machine:
- `ParseState`: Idle → Parsing(%) → Done(counts) | Error
- Background thread sends `ParseMessage` (Progress, Entry, Done, Error) via channel
- `process_messages()` drains channel each frame
- `refilter()` / `resort()` called when filters or sort column changes

UI panels: top bar (open file, status, progress) → filter row → central table → hex viewer (single selection) → bottom export bar.

---

## Data Flow

### MFT → CSV
```
residentreaper mft -f $MFT
    → cli/mod.rs: parse args
    → cli/mft_cmd.rs::run()
        → mft_parser::get_entry_count()         [quick scan for total]
        → mft_parser::parse_mft_entries()
            → mft_entry::MftEntry::from_slice()  [per 1KB entry]
            → attributes: parse SI, FN, Data, ...
            → Pass 1: build path_map
            → Pass 2: emit MftEntryInfo via callback
        → mft_csv::MftCsvRow::from()
        → csv::Writer::serialize()
    → <timestamp>_MFT_Output.csv (34 cols)
```

### USN → CSV (with rewind path resolution)
```
residentreaper usn -f $J [-m $MFT] [--raw]
    → cli/usn_cmd.rs::run()
        → [if -m] mft_parser::parse_mft_entries() [build Vec<Option<PathInfo>>; write MFT CSV]
        → usn_parser::collect_records()           [load all records into Vec]
        → [if not --raw] rewind pass (newest→oldest):
            → for each record (reverse):
                → resolve_full_path(parent_entry, parent_seq, rewind_map, mft_paths)
                    → rewind_map first (historical state at event time)
                    → mft_paths fallback (entries never seen in journal)
                → update rewind_map:
                    RenameOldName → overwrite (expose pre-rename name)
                    others        → or_insert (most recent state wins)
        → [if --raw] MFT-only lookup per record
        → emit Vec<UsnCsvRow> in original chronological order
        → csv::Writer::serialize()
    → <timestamp>_J_Output.csv (13 cols)
```

### Resident Data Hunt (GUI)
```
residentreaper hunt [-f $MFT]
    → gui::launch()
    → eframe::run_native() → ResidentHunterApp::new()
    → start_parsing() spawns background thread
        → resident::scan_resident_data()
            → Pass 1: build path_map
            → Pass 2: find resident DATA attrs
            → send ParseMessage::Entry per ResidentEntry
    → main thread: process_messages() → refilter() → resort()
    → egui renders sortable table, hex viewer, export
```

---

## CSV Output Formats

### MFT (34 columns)
```
EntryNumber, SequenceNumber, InUse,
ParentEntryNumber, ParentSequenceNumber, ParentPath,
FileName, Extension, FileSize, ReferenceCount, ReparseTarget,
IsDirectory, HasAds, IsAds,
SI<FN, uSecZeros, Copied, SiFlags, NameType,
Created0x10, Created0x30, LastModified0x10, LastModified0x30,
LastRecordChange0x10, LastRecordChange0x30, LastAccess0x10, LastAccess0x30,
UpdateSequenceNumber, LogfileSequenceNumber, SecurityId,
ObjectIdFileDroid, LoggedUtilStream, ZoneIdContents, SourceFile
```
- `0x10` = $STANDARD_INFORMATION timestamps; `0x30` = $FILE_NAME timestamps
- Booleans: `"True"` / `"False"` (C# MFTECmd style)
- ADS entries get separate rows; `IsAds=True`, FileName includes `:stream_name`

### USN (13 columns)
```
Name, Extension,
EntryNumber, SequenceNumber, ParentEntryNumber, ParentSequenceNumber, ParentPath,
UpdateSequenceNumber, UpdateTimestamp, UpdateReasons,
FileAttributes, OffsetToData, SourceFile
```
- `UpdateReasons`: pipe-separated flags (e.g., `DataOverwrite|FileCreate|Close`)
- `ParentPath`: resolved via rewind by default (historical path at event time); MFT supplements for entries absent from journal; `--raw` uses MFT only; empty if neither `-m` nor rewind active

---

## Key Dependencies

| Crate | Feature | Purpose |
|-------|---------|---------|
| `memmap2` 0.9 | core | Memory-mapped I/O for large files |
| `byteorder` 1 | core | Little-endian byte reads |
| `chrono` 0.4 | core | DateTime, FILETIME conversion |
| `serde` 1 | core | Derive Serialize/Deserialize |
| `thiserror` 2 | core | Error enum derivation |
| `log` + `env_logger` | core | Logging facade + env config |
| `clap` 4 | cli | Arg parsing with derive |
| `csv` 1 | cli | CSV serialization (256KB buffer) |
| `indicatif` 0.17 | cli | Progress bars |
| `eframe` + `egui_extras` 0.31 | gui | Native window + table widget |
| `rfd` 0.15 | gui | Native file/folder dialogs |
| `image` 0.25 | gui + build | PNG/ICO encoding |
| `winres` 0.1 | build (Win) | Windows PE resource embedding |

---

## Performance Design

- **memmap2** — zero-copy file access; no buffered reads for large $MFT
- **Two-pass parsing** — path map built in pass 1; no repeated parent lookups in pass 2
- **Stack-buffered UTF-16LE** — 128-char stack buffer avoids heap alloc for common filenames
- **256KB CSV BufWriter** — amortizes syscall cost per row
- **Sparse-skip in USN** — 4KB block skip → 8-byte scan to handle sparse $J efficiently
- **Extension record merging** — single-pass collection of extension attributes
- **USN rewind in-memory** — all records loaded once; single reverse pass builds rewind map + resolves paths simultaneously; output written in forward order

---

## Forensic Capabilities

| Flag | Column | Detection |
|------|--------|-----------|
| Timestomping | `SI<FN` | SI created < FN created |
| File copy | `Copied` | SI modified < SI created |
| Manual timestamp | `uSecZeros` | sub-second precision = 0 |
| ADS presence | `HasAds` / `IsAds` | named $DATA streams |
| Reparse targets | `ReparseTarget` | mount points, symlinks |
| Download mark | `ZoneIdContents` | Zone.Identifier ADS content |
| Resident recovery | GUI Hunt | raw bytes of small resident files |
| USN timeline | USN CSV | full change-reason history |
| USN path rewind | `ParentPath` | historical path at event time, not current MFT state |

---

## Feature Flags

```toml
[features]
default = ["cli"]
cli  = ["dep:clap", "dep:csv", "dep:indicatif"]
gui  = ["dep:eframe", "dep:egui_extras", "dep:image", "dep:rfd"]
```

Release profile: `opt-level=3`, LTO enabled, symbols stripped.
