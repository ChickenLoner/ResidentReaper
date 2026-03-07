<p align="center">
  <img src="icon.png" alt="ResidentSpecter" width="180"/>
</p>

<h1 align="center">ResidentSpecter</h1>

<p align="center">
  A fast NTFS forensic tool written in Rust — parses <code>$MFT</code> and <code>$J</code> (USN Journal) artifacts, and hunts for resident data hidden inside MFT entries.
</p>

<p align="center">
  <a href="https://github.com/ChickenLoner/ResidentSpecter/releases"><img src="https://img.shields.io/github/v/release/ChickenLoner/ResidentSpecter?style=flat-square" alt="Release"/></a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust"/>
</p>

---

## What is ResidentSpecter?

ResidentSpecter is a DFIR tool inspired by [MFTECmd](https://github.com/EricZimmerman/MFTECmd) by Eric Zimmerman. It reconstructs the full lifecycle of files on NTFS systems by parsing `$MFT` and `$J` (USN Journal) artifacts.

It operates in three modes:

| Mode | Description |
|------|-------------|
| **`mft`** | Parses `$MFT` to CSV with output compatible with MFTECmd (99.997% cell accuracy, identical row counts). |
| **`usn`** | Parses `$J` (USN Journal) to CSV with MFTECmd-compatible output. Optionally resolves parent paths via `$MFT`. |
| **`hunt`** | GUI mode — scans MFT entries for resident data (files stored inline), browse/filter/export them. |

### MFTECmd Compatibility

ResidentSpecter's CSV output is designed to be a drop-in replacement for MFTECmd:

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

Grab the latest binaries from the [Releases](https://github.com/ChickenLoner/ResidentSpecter/releases) page:

| Platform | File |
|----------|------|
| Windows  | `ResidentSpecter.exe` |
| Linux    | `ResidentSpecter` |

## Usage

### Parse $MFT to CSV

```bash
ResidentSpecter mft -f <path_to_$MFT> -o output.csv
```

### Parse $J (USN Journal) to CSV

```bash
ResidentSpecter usn -f <path_to_$J> -o usn_output.csv
```

### Parse $J with parent path resolution (provide $MFT)

```bash
ResidentSpecter usn -f <path_to_$J> -o usn_output.csv --mft <path_to_$MFT>
```

### Resident Hunter (GUI)

```bash
ResidentSpecter hunt
# Or pre-load an MFT file:
ResidentSpecter hunt -f <path_to_$MFT>
```

The GUI lets you:
- Scan an `$MFT` for resident data (files stored directly inside MFT entries)
- Browse results in a sortable, filterable table
- Filter by filename, extension, size range, or path
- Select and export resident files to a directory
- Copy hex data to clipboard

### Options

| Flag | Description |
|------|-------------|
| `-f, --file` | Path to the artifact file (required) |
| `-o, --output` | Path to the output CSV file (required) |
| `--allocated-only` | Only output allocated (in-use) MFT entries |
| `--mft <path>` | (usn mode) Provide $MFT to resolve parent paths |
| `-v, --verbose` | Increase logging verbosity |

## CSV Output Columns

### $MFT Output (34 columns)

EntryNumber, SequenceNumber, InUse, ParentEntryNumber, ParentSequenceNumber, ParentPath, FileName, Extension, FileSize, ReferenceCount, ReparseTarget, IsDirectory, HasAds, IsAds, SI<FN, uSecZeros, Copied, SiFlags, NameType, Created0x10, Created0x30, LastModified0x10, LastModified0x30, LastRecordChange0x10, LastRecordChange0x30, LastAccess0x10, LastAccess0x30, UpdateSequenceNumber, LogfileSequenceNumber, SecurityId, ObjectIdFileDroid, LoggedUtilStream, ZoneIdContents, SourceFile

### $J (USN Journal) Output (13 columns)

Name, Extension, EntryNumber, SequenceNumber, ParentEntryNumber, ParentSequenceNumber, ParentPath, UpdateSequenceNumber, UpdateTimestamp, UpdateReasons, FileAttributes, OffsetToData, SourceFile

## Building from Source

**Requirements:** [Rust](https://rustup.rs/) toolchain (1.75+)

```bash
# CLI only (default)
cargo build --release

# CLI + GUI
cargo build --release --features gui
```

The binary will be at `target/release/resident-specter.exe` (Windows) or `target/release/resident-specter` (Linux).

### Linux GUI Dependencies

```bash
sudo apt-get install -y libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libxkbcommon-dev libssl-dev libfontconfig1-dev
```

## License

[MIT](LICENSE)
