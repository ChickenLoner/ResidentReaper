# ResidentReaper

NTFS forensic tool — parses $MFT and USN $J, outputs MFTECmd-compatible CSV. Rust 2021, MIT.

## Commands

```bash
cargo build --release                        # CLI only (default)
cargo build --release --features gui         # CLI + GUI
cargo test
```

Linux release uses cargo-zigbuild targeting glibc 2.17 (see release.yml). Local dev: plain `cargo build`.

Linux GUI build needs system packages: `libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev libfontconfig1-dev`

## Non-Obvious Constraints

**MFTECmd compatibility is a hard requirement.** CSV columns, order, and types must match exactly:
- Booleans: `"True"` / `"False"` (not `true`/`false`)
- Timestamps: `yyyy-MM-dd HH:mm:ss.fffffff` (7 decimal places)
- ADS rows emitted after their parent FN row, same `EntryNumber`

**Two-pass MFT parsing** is load-bearing — don't collapse into one pass:
- Pass 1: builds full path map from all $FILE_NAME attrs (handles orphans and extension records)
- Pass 2: emits CSV rows; ADS rows follow immediately after each FN row

**USN path resolution** uses `Vec<Option<PathInfo>>` indexed by entry number with sequence validation — not a HashMap. Sequence mismatch = empty path (correct behavior, not a bug).

**MFT entry size** is detected from the first entry's `allocated_size` field, not hardcoded to 1024.

**Forensic flags** computed in `mft_parser.rs`, not `mft_csv.rs`. Don't move the logic.

**USN Rewind is default — true reverse-chronological.** Algorithm: collect all records → walk newest→oldest, maintaining rewind map of `(entry, seq) → (name, parent_entry, parent_seq)`. On `RenameOldName`: overwrite map entry (exposes pre-rename name for earlier records). All others: `or_insert` (first-seen going backwards = most recent state). Resolve parent path BEFORE updating map for each record — so map reflects state at the moment of each event. `resolve_full_path` checks rewind map first (historical), MFT second (fallback for entries never in journal). `--raw` disables rewind; MFT-only resolution applies if `-m` given.

## Architecture

See `ARCHITECTURE.md` for full module map, data flow, and CSV column specs.
