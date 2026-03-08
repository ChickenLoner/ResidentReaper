<p align="center">
  <img src="icon.png" alt="ResidentReaper" width="180"/>
</p>

<h1 align="center">ResidentReaper</h1>

<p align="center">
  A fast NTFS forensic tool written in Rust — parses <code>$MFT</code> and <code>$J</code> (USN Journal) artifacts, and hunts for resident data hidden inside MFT entries.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.1.0-green?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust"/>
</p>

---

## What is ResidentReaper?

ResidentReaper is a DFIR tool inspired by [MFTECmd](https://github.com/EricZimmerman/MFTECmd) by Eric Zimmerman. It reconstructs the full lifecycle of files on NTFS systems by parsing `$MFT` and `$J` (USN Journal) artifacts.

It operates in three modes:

| Mode | Description |
|------|-------------|
| **`mft`** | Parses `$MFT` to CSV with output compatible with MFTECmd (99.997% cell accuracy, identical row counts). |
| **`usn`** | Parses `$J` (USN Journal) to CSV with MFTECmd-compatible output. Optionally resolves parent paths via `$MFT` and outputs MFT CSV as well. |
| **`hunt`** | GUI mode — scans MFT entries for resident data (files stored inline), browse/filter/export them with inline hex viewer. |

### MFTECmd Compatibility

ResidentReaper's CSV output is designed to be a drop-in replacement for MFTECmd:

| Metric | $MFT | $J (USN Journal) |
|--------|------|-------------------|
| Row count | Exact match | Exact match |
| Column headers | Identical (34 columns) | Identical (13 columns) |
| Cell accuracy | 99.997% | 98.4%* |
| Timestamps | Identical (7-digit fractional seconds) | Identical |
| Forensic flags | SI<FN, uSecZeros, Copied | N/A |
| ADS detection | Zone.Identifier extraction | N/A |

*ParentPath differences due to sequence number validation for reused MFT entries — our tool resolves the current path while MFTECmd shows `PathUnknown`.

## Download

Grab the latest binaries from the [Releases](https://github.com/ChickenLoner/ResidentReaper/releases) page:

| Platform | File |
|----------|------|
| Windows  | `ResidentReaper.exe` |
| Linux    | `ResidentReaper` |

## Usage

### Parse $MFT to CSV

```bash
# Auto-named output (e.g., 20260308120000_MFT_Output.csv)
ResidentReaper mft -f $MFT

# Custom output path
ResidentReaper mft -f $MFT -o mft_output.csv

# Allocated entries only
ResidentReaper mft -f $MFT --allocated-only
```

### Parse $J (USN Journal) to CSV

```bash
# Auto-named output (e.g., 20260308120000_J_Output.csv)
ResidentReaper usn -f $J

# With parent path resolution (also outputs MFT CSV)
ResidentReaper usn -f $J -m $MFT

# Custom output path
ResidentReaper usn -f $J -o usn.csv -m $MFT
```

When `-m` / `--mft` is provided, ResidentReaper parses the MFT in a single pass to both resolve parent paths for USN records and produce a full MFT CSV output alongside the USN CSV.

### Resident Hunter (GUI)

```bash
ResidentReaper hunt
# Or pre-load an MFT file:
ResidentReaper hunt -f $MFT
```

The GUI lets you:
- Scan an `$MFT` for resident data (files stored directly inside MFT entries)
- Browse results in a sortable, filterable table with horizontal scrolling
- Search by full path (combined parent path + filename)
- Filter by extension and size range
- View resident data inline with a hex dump viewer
- Copy hex, ASCII, or full hex dump to clipboard
- Select and export resident files to a directory

### Options

| Flag | Description |
|------|-------------|
| `-f, --file` | Path to the artifact file (required) |
| `-o, --output` | Path to output CSV file (auto-named with timestamp if omitted) |
| `--allocated-only` | Only output allocated (in-use) MFT entries (mft mode) |
| `-m, --mft <path>` | Provide $MFT to resolve parent paths and output MFT CSV (usn mode) |
| `-v, --verbose` | Increase logging verbosity |

### Default Output Filenames

If `-o` is not specified, output files are auto-named with a timestamp:

| Mode | Default Filename |
|------|-----------------|
| `mft` | `<yyyyMMddHHmmss>_MFT_Output.csv` |
| `usn` | `<yyyyMMddHHmmss>_J_Output.csv` |
| `usn --mft` | Both `_J_Output.csv` and `_MFT_Output.csv` |

## CSV Output Columns

### $MFT Output (34 columns)

EntryNumber, SequenceNumber, InUse, ParentEntryNumber, ParentSequenceNumber, ParentPath, FileName, Extension, FileSize, ReferenceCount, ReparseTarget, IsDirectory, HasAds, IsAds, SI<FN, uSecZeros, Copied, SiFlags, NameType, Created0x10, Created0x30, LastModified0x10, LastModified0x30, LastRecordChange0x10, LastRecordChange0x30, LastAccess0x10, LastAccess0x30, UpdateSequenceNumber, LogfileSequenceNumber, SecurityId, ObjectIdFileDroid, LoggedUtilStream, ZoneIdContents, SourceFile

### $J (USN Journal) Output (13 columns)

Name, Extension, EntryNumber, SequenceNumber, ParentEntryNumber, ParentSequenceNumber, ParentPath, UpdateSequenceNumber, UpdateTimestamp, UpdateReasons, FileAttributes, OffsetToData, SourceFile

## Analysis Scripts

The `scripts/` directory contains standalone Python analysis scripts that work with ResidentReaper's CSV output. No dependencies required — Python 3.8+ stdlib only.

| Script | Input | Description |
|--------|-------|-------------|
| `timeline.py` | MFT and/or USN CSV | Unified chronological timeline from all MFT timestamps and USN events. Supports `--start`, `--end`, `--path`, `--ext` filters. |
| `usn_activity.py` | USN CSV | USN Journal activity analysis: reason summaries, hourly heatmap, busiest dates, directory hotspots. |
| `prefetch_activity.py` | USN CSV | Program execution timeline from `.pf` (Prefetch) file activity in USN Journal. |
| `download_detector.py` | USN CSV | Detects files downloaded via **certutil** (CryptnetUrlCache + INetCache correlation) and **BITS** (BIT*.tmp rename chains). |
| `user_files.py` | MFT CSV | Lists all files in Downloads, Desktop, and Documents per user profile. |

### Examples

```bash
# Build a timeline from MFT + USN
python scripts/timeline.py --mft mft.csv --usn usn.csv --start 2025-01-01

# USN activity summary
python scripts/usn_activity.py -f usn.csv --top-dirs 30

# Prefetch execution timeline
python scripts/prefetch_activity.py -f usn.csv

# Detect certutil/BITS downloads
python scripts/download_detector.py -f usn.csv

# List user files (Downloads, Desktop, Documents)
python scripts/user_files.py -f mft.csv --include-deleted
```

## Building from Source

**Requirements:** [Rust](https://rustup.rs/) toolchain (1.75+)

```bash
# CLI only (default)
cargo build --release

# CLI + GUI
cargo build --release --features gui
```

The binary will be at `target/release/resident-reaper.exe` (Windows) or `target/release/resident-reaper` (Linux).

### Linux GUI Dependencies

```bash
sudo apt-get install -y libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libxkbcommon-dev libssl-dev libfontconfig1-dev
```

## License

[MIT](LICENSE)
