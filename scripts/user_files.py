#!/usr/bin/env python3
"""
ResidentReaper User Files Lister

Lists files in key user directories (Downloads, Desktop, Documents) for each
user profile, combining MFT and USN Journal data. MFT provides current/allocated
files; USN Journal reveals deleted files no longer present in MFT.

Output uses a tree-style layout for easy browsing.

Usage:
    python user_files.py -f mft.csv
    python user_files.py -f mft.csv --usn usn.csv
    python user_files.py -f mft.csv --depth 3
    python user_files.py -f mft.csv --usn usn.csv -o report.csv
"""

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime


# Directories of interest under each user profile
TARGET_DIRS = ["desktop", "downloads", "documents"]
FOLDER_LABELS = {"desktop": "Desktop", "downloads": "Downloads", "documents": "Documents"}

# Pattern to match user profile paths: .\Users\<username>\<target_dir>\...
USER_PATH_RE = re.compile(
    r"^\.?\\?Users\\([^\\]+)\\(" + "|".join(TARGET_DIRS) + r")(\\.*)?$",
    re.IGNORECASE,
)


def parse_timestamp(ts_str):
    """Parse ResidentReaper timestamp format: yyyy-MM-dd HH:mm:ss.fffffff"""
    if not ts_str or not ts_str.strip():
        return None
    ts_str = ts_str.strip()
    try:
        if "." in ts_str:
            date_part, frac = ts_str.rsplit(".", 1)
            frac = frac[:6].ljust(6, "0")
            return datetime.strptime(f"{date_part}.{frac}", "%Y-%m-%d %H:%M:%S.%f")
        else:
            return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def fmt_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""


def fmt_ts_short(ts):
    return ts.strftime("%Y-%m-%d %H:%M") if ts else ""


def build_full_path(parent_path, filename):
    if not parent_path or parent_path == ".":
        return filename
    return f"{parent_path}\\{filename}"


def format_size(size_bytes):
    """Format byte count to human-readable string."""
    if isinstance(size_bytes, str):
        try:
            size_bytes = int(size_bytes)
        except (ValueError, TypeError):
            return ""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def safe_int(val, default=0):
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def get_depth(rel_dir):
    """Get directory depth of a relative path. Empty = 0, 'a' = 1, 'a\\b' = 2."""
    if not rel_dir:
        return 0
    return rel_dir.count("\\") + 1


# ---------------------------------------------------------------------------
# MFT loader
# ---------------------------------------------------------------------------

def load_mft_files(mft_path):
    """Load user files from MFT CSV. Returns dict: {username: {folder: [entries]}}"""
    user_files = defaultdict(lambda: defaultdict(list))

    with open(mft_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("IsDirectory") == "True":
                continue
            if row.get("IsAds") == "True":
                continue

            filename = row.get("FileName", "")
            parent_path = row.get("ParentPath", "")
            full_path = build_full_path(parent_path, filename)

            match = USER_PATH_RE.match(full_path)
            if not match:
                continue

            username = match.group(1)
            folder = match.group(2).lower()
            rest = (match.group(3) or "").lstrip("\\")

            if rest and "\\" in rest:
                rel_dir = rest.rsplit("\\", 1)[0]
            else:
                rel_dir = ""

            in_use = row.get("InUse", "") == "True"
            created = parse_timestamp(row.get("Created0x10", ""))
            modified = parse_timestamp(row.get("LastModified0x10", ""))

            user_files[username][folder].append({
                "FileName": filename,
                "Extension": row.get("Extension", "").lower(),
                "FileSize": safe_int(row.get("FileSize", "")),
                "RelDir": rel_dir,
                "Created": created,
                "Modified": modified,
                "Source": "MFT (Deleted)" if not in_use else "MFT",
                "EntryNumber": row.get("EntryNumber", ""),
            })

    return user_files


# ---------------------------------------------------------------------------
# USN loader — finds deleted files not in MFT
# ---------------------------------------------------------------------------

def load_usn_deleted(usn_path, mft_known):
    """Scan USN Journal for FileDelete events in user directories.

    mft_known: set of (username_lower, folder, filename_lower, reldir_lower)
    from MFT to avoid duplicating files already found.
    """
    user_files = defaultdict(lambda: defaultdict(list))

    with open(usn_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            reasons = row.get("UpdateReasons", "")
            if "FileDelete" not in reasons:
                continue

            filename = row.get("Name", "")
            parent_path = row.get("ParentPath", "")
            full_path = build_full_path(parent_path, filename)

            match = USER_PATH_RE.match(full_path)
            if not match:
                continue

            username = match.group(1)
            folder = match.group(2).lower()
            rest = (match.group(3) or "").lstrip("\\")

            if rest and "\\" in rest:
                rel_dir = rest.rsplit("\\", 1)[0]
            else:
                rel_dir = ""

            key = (username.lower(), folder, filename.lower(), rel_dir.lower())
            if key in mft_known:
                continue
            mft_known.add(key)

            ts = parse_timestamp(row.get("UpdateTimestamp", ""))

            user_files[username][folder].append({
                "FileName": filename,
                "Extension": row.get("Extension", "").lower(),
                "FileSize": 0,
                "RelDir": rel_dir,
                "Created": None,
                "Modified": ts,
                "Source": "USN (Deleted)",
                "EntryNumber": row.get("EntryNumber", ""),
            })

    return user_files


def build_mft_known_set(user_files):
    """Build a set of known files from MFT for deduplication."""
    known = set()
    for username, folders in user_files.items():
        for folder, files in folders.items():
            for f in files:
                key = (username.lower(), folder, f["FileName"].lower(), f["RelDir"].lower())
                known.add(key)
    return known


def merge_user_files(mft_files, usn_files):
    """Merge USN-discovered deleted files into the MFT results."""
    for username, folders in usn_files.items():
        for folder, files in folders.items():
            mft_files[username][folder].extend(files)
    return mft_files


# ---------------------------------------------------------------------------
# Tree display
# ---------------------------------------------------------------------------

def build_tree(files):
    """Build a nested tree structure from flat file list.

    Returns: dict where keys are directory names, values are either:
      - nested dicts (subdirectories)
      - file entry lists (under special key None)
    """
    tree = {}

    for f in files:
        rel_dir = f["RelDir"]
        parts = rel_dir.split("\\") if rel_dir else []

        node = tree
        for part in parts:
            if part not in node:
                node[part] = {}
            if not isinstance(node[part], dict):
                node[part] = {}
            node = node[part]

        if None not in node:
            node[None] = []
        node[None].append(f)

    return tree


def count_tree_files(tree):
    """Count total files in a tree recursively."""
    count = len(tree.get(None, []))
    for k, v in tree.items():
        if k is not None and isinstance(v, dict):
            count += count_tree_files(v)
    return count


def print_tree(tree, prefix="    ", max_depth=None, current_depth=0):
    """Print tree structure with connectors, respecting max_depth."""
    dirs = sorted([k for k in tree if k is not None])
    files = tree.get(None, [])

    # Sort files by modified time (most recent first)
    files = sorted(files, key=lambda x: x["Modified"] or datetime.min, reverse=True)

    items = []
    for d in dirs:
        items.append(("dir", d))
    for f in files:
        items.append(("file", f))

    for idx, (item_type, item) in enumerate(items):
        is_last = idx == len(items) - 1
        connector = "`-- " if is_last else "|-- "
        continuation = "    " if is_last else "|   "

        if item_type == "dir":
            subtree_count = count_tree_files(tree[item])

            if max_depth is not None and current_depth >= max_depth:
                # Collapsed — show count only
                print(f"{prefix}{connector}{item}/ ({subtree_count} files, use --depth {current_depth + 2} to expand)")
            else:
                print(f"{prefix}{connector}{item}/ ({subtree_count} files)")
                print_tree(tree[item], prefix + continuation,
                           max_depth=max_depth, current_depth=current_depth + 1)
        else:
            f = item
            mod_str = fmt_ts_short(f["Modified"]) if f["Modified"] else ""
            size_str = format_size(f["FileSize"]) if f["FileSize"] else ""
            source_tag = ""
            if "Deleted" in f["Source"]:
                source_tag = " [DELETED]"
                if "USN" in f["Source"]:
                    source_tag = " [DELETED - USN]"

            detail_parts = []
            if size_str:
                detail_parts.append(size_str)
            if mod_str:
                detail_parts.append(mod_str)
            detail = f"  ({', '.join(detail_parts)})" if detail_parts else ""

            print(f"{prefix}{connector}{f['FileName']}{detail}{source_tag}")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(user_files, has_usn, max_depth):
    """Print user files report with tree layout."""
    if not user_files:
        print("\n  No user files found in target directories.")
        return

    total_files = sum(
        len(files) for folders in user_files.values() for files in folders.values()
    )
    total_size = sum(
        f["FileSize"] for folders in user_files.values()
        for files in folders.values() for f in files
    )
    total_deleted = sum(
        1 for folders in user_files.values()
        for files in folders.values() for f in files
        if "Deleted" in f["Source"]
    )

    print(f"\n  ======================================================================")
    print(f"   ResidentReaper - User Files Report")
    print(f"  ======================================================================")
    print(f"\n  Users:       {len(user_files)}")
    print(f"  Total files: {total_files:,}")
    print(f"  Total size:  {format_size(total_size)}")
    if total_deleted:
        print(f"  Deleted:     {total_deleted:,}")
        if has_usn:
            usn_deleted = sum(
                1 for folders in user_files.values()
                for files in folders.values() for f in files
                if "USN" in f["Source"]
            )
            if usn_deleted:
                print(f"    from USN:  {usn_deleted:,} (not in MFT)")

    for username in sorted(user_files.keys()):
        folders = user_files[username]
        user_total = sum(len(f) for f in folders.values())
        user_size = sum(f["FileSize"] for files in folders.values() for f in files)
        user_deleted = sum(
            1 for files in folders.values() for f in files if "Deleted" in f["Source"]
        )

        print(f"\n  {'=' * 68}")
        size_info = f", {format_size(user_size)}" if user_size else ""
        del_info = f", {user_deleted} deleted" if user_deleted else ""
        print(f"  User: {username}  ({user_total} files{size_info}{del_info})")
        print(f"  {'=' * 68}")

        for folder_key in TARGET_DIRS:
            files = folders.get(folder_key, [])
            if not files:
                continue

            label = FOLDER_LABELS[folder_key]
            folder_size = sum(f["FileSize"] for f in files)
            folder_deleted = sum(1 for f in files if "Deleted" in f["Source"])

            size_info = f", {format_size(folder_size)}" if folder_size else ""
            del_info = f", {folder_deleted} deleted" if folder_deleted else ""
            print(f"\n    {label}/ ({len(files)} files{size_info}{del_info})")
            print(f"    {'.' * 64}")

            # Extension summary
            ext_counts = Counter()
            for f in files:
                ext = f["Extension"] if f["Extension"] else "(none)"
                ext_counts[ext] += 1
            ext_parts = [f"{ext}({cnt})" for ext, cnt in ext_counts.most_common(8)]
            remaining = len(ext_counts) - 8
            if remaining > 0:
                ext_parts.append(f"+{remaining} more")
            print(f"    Types: {', '.join(ext_parts)}")

            # Time range
            timestamps = [f["Modified"] for f in files if f["Modified"]]
            if timestamps:
                earliest = min(timestamps)
                latest = max(timestamps)
                print(f"    Range: {fmt_ts_short(earliest)} .. {fmt_ts_short(latest)}")

            print()

            # Build and print tree
            tree = build_tree(files)
            print_tree(tree, max_depth=max_depth)

    print()


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def export_csv(user_files, output_path):
    """Export all files to CSV."""
    headers = ["Username", "Folder", "FileName", "Extension", "FileSize",
               "RelativeDir", "FullPath", "Created", "Modified", "Source", "EntryNumber"]

    rows = []
    for username in sorted(user_files.keys()):
        for folder_key in TARGET_DIRS:
            for entry in user_files[username].get(folder_key, []):
                rel_dir = entry["RelDir"]
                if rel_dir:
                    full = f".\\Users\\{username}\\{FOLDER_LABELS[folder_key]}\\{rel_dir}\\{entry['FileName']}"
                else:
                    full = f".\\Users\\{username}\\{FOLDER_LABELS[folder_key]}\\{entry['FileName']}"

                rows.append({
                    "Username": username,
                    "Folder": FOLDER_LABELS[folder_key],
                    "FileName": entry["FileName"],
                    "Extension": entry["Extension"],
                    "FileSize": entry["FileSize"] if entry["FileSize"] else "",
                    "RelativeDir": rel_dir,
                    "FullPath": full,
                    "Created": fmt_ts(entry["Created"]),
                    "Modified": fmt_ts(entry["Modified"]),
                    "Source": entry["Source"],
                    "EntryNumber": entry["EntryNumber"],
                })

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"  Exported {len(rows)} entries to {output_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ResidentReaper User Files Lister - Tree view of user profile directories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
target directories:
  For each user under \\Users\\<username>, scans:
    Desktop, Downloads, Documents (including subdirectories)

data sources:
  MFT:  Shows current and deleted-but-still-allocated files
  USN:  Reveals files that were deleted and whose MFT entries were reused
        (these files would be invisible to MFT-only analysis)

examples:
  python user_files.py -f mft.csv
  python user_files.py -f mft.csv --usn usn.csv
  python user_files.py -f mft.csv --depth 3
  python user_files.py -f mft.csv --usn usn.csv -o report.csv
""",
    )
    parser.add_argument("-f", "--file", required=True, help="Path to MFT CSV file")
    parser.add_argument("--usn", help="Path to USN Journal CSV file (for deleted file recovery)")
    parser.add_argument("-o", "--output", help="Export to CSV file")
    parser.add_argument("--depth", type=int, default=1,
                        help="Max subdirectory depth to expand in tree (default: 1)")

    args = parser.parse_args()

    print(f"  Scanning MFT: {args.file}", file=sys.stderr)
    user_files = load_mft_files(args.file)

    mft_total = sum(len(f) for folders in user_files.values() for f in folders.values())
    print(f"  MFT: {mft_total:,} files across {len(user_files)} user(s)", file=sys.stderr)

    has_usn = False
    if args.usn:
        has_usn = True
        print(f"  Scanning USN: {args.usn}", file=sys.stderr)
        known = build_mft_known_set(user_files)
        usn_files = load_usn_deleted(args.usn, known)
        usn_total = sum(len(f) for folders in usn_files.values() for f in folders.values())
        print(f"  USN: {usn_total:,} additional deleted files found", file=sys.stderr)
        user_files = merge_user_files(user_files, usn_files)

    print_report(user_files, has_usn, args.depth)

    if args.output:
        export_csv(user_files, args.output)


if __name__ == "__main__":
    main()
