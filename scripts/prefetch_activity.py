#!/usr/bin/env python3
"""
ResidentReaper Prefetch Activity Tracker

Tracks program execution evidence by analyzing .pf (Prefetch) file activity
from USN Journal CSV output. Prefetch files in Windows\\Prefetch are
created/modified when programs execute, making them key execution artifacts.

Usage:
    python prefetch_activity.py -f usn.csv
    python prefetch_activity.py -f usn.csv -o prefetch_report.csv
"""

import argparse
import csv
import re
import sys
from datetime import datetime


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


def parse_prefetch_name(pf_filename):
    """Parse prefetch filename to extract executable name and hash.

    Prefetch format: EXECUTABLE_NAME-XXXXXXXX.pf
    e.g., CMD.EXE-4A81B364.pf -> (CMD.EXE, 4A81B364)
    """
    name = pf_filename.upper()
    if not name.endswith(".PF"):
        return None, None

    base = name[:-3]  # Remove .pf
    match = re.match(r"^(.+)-([0-9A-F]{8})$", base)
    if match:
        return match.group(1), match.group(2)
    return base, None


def build_full_path(parent_path, filename):
    if not parent_path or parent_path == ".":
        return filename
    return f"{parent_path}\\{filename}"


def load_usn_prefetch(usn_path):
    """Extract prefetch-related USN records."""
    records = []
    with open(usn_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ext = row.get("Extension", "").lower()
            if ext != ".pf":
                continue

            filename = row.get("Name", "")
            parent_path = row.get("ParentPath", "")
            full_path = build_full_path(parent_path, filename)
            exe_name, pf_hash = parse_prefetch_name(filename)
            ts = parse_timestamp(row.get("UpdateTimestamp", ""))

            records.append({
                "FileName": filename,
                "ExeName": exe_name or filename,
                "PrefetchHash": pf_hash or "",
                "FullPath": full_path,
                "Timestamp": ts,
                "UpdateReasons": row.get("UpdateReasons", ""),
                "EntryNumber": row.get("EntryNumber", ""),
            })
    return records


def print_timeline(records):
    """Print chronological prefetch execution timeline."""
    print(f"\n{'='*70}")
    print(f"  Prefetch Execution Timeline")
    print(f"{'='*70}")
    print(f"  Total .pf events: {len(records):,}\n")

    if not records:
        print("  No prefetch activity found.\n")
        return

    events = [r for r in records if r["Timestamp"]]
    events.sort(key=lambda x: x["Timestamp"])

    print(f"  {'Timestamp':<22s} {'Executable':<30s} {'Event'}")
    print(f"  {'-'*22} {'-'*30} {'-'*40}")

    for e in events:
        ts = e["Timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {ts:<22s} {e['ExeName']:<30s} {e['UpdateReasons']}")

    print(f"\n  Total: {len(events)} events")
    print()


def export_csv(records, output_path):
    """Export prefetch timeline to CSV."""
    headers = ["Timestamp", "ExeName", "PrefetchHash", "FileName",
               "FullPath", "EntryNumber", "UpdateReasons"]

    rows = []
    for r in records:
        if r["Timestamp"]:
            rows.append({
                "Timestamp": r["Timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f"),
                "ExeName": r["ExeName"],
                "PrefetchHash": r["PrefetchHash"],
                "FileName": r["FileName"],
                "FullPath": r["FullPath"],
                "EntryNumber": r["EntryNumber"],
                "UpdateReasons": r["UpdateReasons"],
            })

    rows.sort(key=lambda x: x["Timestamp"])

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Written {len(rows)} prefetch events to {output_path}", file=sys.stderr)


def default_output_name():
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{ts}_Prefetch_Timeline.csv"


def main():
    parser = argparse.ArgumentParser(
        description="ResidentReaper Prefetch Activity Tracker — Program execution timeline from .pf files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
how it works:
  Windows Prefetch files (C:\\Windows\\Prefetch\\*.pf) are created/updated
  when programs execute. This script finds all .pf file activity in USN
  Journal output to build a chronological execution timeline.

  USN records on .pf files:
    - FileCreate             = first execution (prefetch file created)
    - DataExtend/DataOverwrite = subsequent executions (prefetch updated)

examples:
  python prefetch_activity.py -f usn.csv
  python prefetch_activity.py -f usn.csv -o prefetch.csv
""",
    )
    parser.add_argument("-f", "--file", required=True, help="Path to USN Journal CSV file")
    parser.add_argument("-o", "--output", help="Output CSV file [default: <timestamp>_Prefetch_Timeline.csv]")

    args = parser.parse_args()

    output = args.output or default_output_name()

    print(f"Loading USN: {args.file}", file=sys.stderr)
    records = load_usn_prefetch(args.file)
    print(f"Found {len(records)} prefetch USN records", file=sys.stderr)

    export_csv(records, output)
    print_timeline(records)


if __name__ == "__main__":
    main()
