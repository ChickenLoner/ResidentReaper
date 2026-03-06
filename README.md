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

ResidentSpecter is a DFIR tool inspired by [MFTECmd](https://github.com/EricZimmerman/MFTECmd) by Eric Zimmerman. It is designed to reconstruct the full lifecycle of files on NTFS systems by correlating data from `$MFT` and `$J` (USN Journal).

It operates in two modes:

| Mode | Description |
|------|-------------|
| **CLI Parser** | Parses `$MFT` and `$J` artifacts to CSV — output is compatible with MFTECmd. Faster, written in Rust. |
| **Resident Hunter** | GUI mode that scans MFT entries for resident data (files stored inline in the MFT), lets you browse, filter, and export them. |

## Download

Grab the latest binaries from the [Releases](https://github.com/ChickenLoner/ResidentSpecter/releases) page:

| Platform | File |
|----------|------|
| Windows  | `ResidentSpecter.exe` |
| Linux    | `ResidentSpecter` |

## Usage

### Mode 1: CLI Parser

**Parse $MFT to CSV:**
```bash
ResidentSpecter mft -f <path_to_$MFT> -o output.csv
```

**Parse $J (USN Journal) to CSV:**
```bash
ResidentSpecter usn -f <path_to_$J> -o usn_output.csv
```

**Parse $J with parent path resolution (provide $MFT):**
```bash
ResidentSpecter usn -f <path_to_$J> -o usn_output.csv --mft <path_to_$MFT>
```

**Options:**
| Flag | Description |
|------|-------------|
| `-f, --file` | Path to the artifact file (required) |
| `-o, --output` | Path to the output CSV file (required) |
| `--allocated-only` | Only output allocated (in-use) MFT entries |
| `--mft <path>` | (usn mode) Provide $MFT to resolve parent paths |
| `-v, --verbose` | Increase logging verbosity |

### Mode 2: Resident Hunter (GUI)

```bash
ResidentSpecter hunt
```

Or pre-load an MFT file:
```bash
ResidentSpecter hunt -f <path_to_$MFT>
```

The GUI lets you:
- Scan an `$MFT` for resident data (files stored directly inside MFT entries)
- Browse results in a sortable, filterable table
- Filter by filename, extension, size range, or path
- Select and export resident files to a directory
- Copy hex data to clipboard

## CSV Output Columns

### $MFT Output
EntryNumber, SequenceNumber, InUse, ParentEntryNumber, ParentSequenceNumber, ParentPath, FileName, Extension, FileSize, IsDirectory, HasAds, IsAds, Created0x10, LastModified0x10, LastAccess0x10, LastRecordChange0x10, Created0x30, LastModified0x30, LastAccess0x30, LastRecordChange0x30, ReferenceCount, LogfileSequenceNumber, SecurityId, ObjectIdFileDroid, ZoneIdContents

### $J (USN Journal) Output
Name, Extension, EntryNumber, SequenceNumber, ParentEntryNumber, ParentSequenceNumber, ParentPath, UpdateTimestamp, UpdateReasons, FileAttributes, UpdateSequenceNumber, SourceInfo, SecurityId

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
