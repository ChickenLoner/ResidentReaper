#!/usr/bin/env python3
"""
ResidentReaper Timeline Builder

Builds a unified chronological timeline from MFT and/or USN Journal CSV outputs.
Merges all timestamp events into a single sorted view for DFIR analysis.

Usage:
    python timeline.py --mft mft.csv --usn usn.csv
    python timeline.py --mft mft.csv --start 2026-01-01 --end 2026-03-08
    python timeline.py --usn usn.csv --path "Users\\Admin" --ext .exe,.dll
    python timeline.py --mft mft.csv -o timeline_output.csv
"""

import argparse
import csv
import sys
from datetime import datetime

# MFT timestamp columns and their event type labels
MFT_TIMESTAMP_COLUMNS = [
    ("Created0x10", "SI Created"),
    ("Created0x30", "FN Created"),
    ("LastModified0x10", "SI Modified"),
    ("LastModified0x30", "FN Modified"),
    ("LastRecordChange0x10", "SI RecordChange"),
    ("LastRecordChange0x30", "FN RecordChange"),
    ("LastAccess0x10", "SI Accessed"),
    ("LastAccess0x30", "FN Accessed"),
]

TIMELINE_HEADERS = ["Timestamp", "Source", "EventType", "EntryNumber", "FileName", "Extension", "FullPath", "Details"]


def parse_timestamp(ts_str):
    """Parse ResidentReaper timestamp format: yyyy-MM-dd HH:mm:ss.fffffff"""
    if not ts_str or not ts_str.strip():
        return None
    ts_str = ts_str.strip()
    try:
        # Handle 7-digit fractional seconds by truncating to 6 (microseconds)
        if "." in ts_str:
            date_part, frac = ts_str.rsplit(".", 1)
            frac = frac[:6].ljust(6, "0")
            return datetime.strptime(f"{date_part}.{frac}", "%Y-%m-%d %H:%M:%S.%f")
        else:
            return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def build_full_path(parent_path, filename):
    """Combine parent path and filename into full path."""
    if not parent_path or parent_path == ".":
        return filename
    return f"{parent_path}\\{filename}"


def load_mft_events(mft_path, filters):
    """Extract timeline events from MFT CSV."""
    events = []
    with open(mft_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            filename = row.get("FileName", "")
            parent_path = row.get("ParentPath", "")
            extension = row.get("Extension", "")
            entry_number = row.get("EntryNumber", "")
            full_path = build_full_path(parent_path, filename)

            if not apply_filters(full_path, extension, filters):
                continue

            # Build detail string with forensic flags
            details_parts = []
            if row.get("IsDirectory") == "True":
                details_parts.append("Directory")
            if row.get("IsAds") == "True":
                details_parts.append(f"ADS")
            if row.get("SI<FN") == "True":
                details_parts.append("TIMESTOMPED")
            if row.get("uSecZeros") == "True":
                details_parts.append("uSecZeros")
            if row.get("Copied") == "True":
                details_parts.append("Copied")
            details = ", ".join(details_parts)

            for col, event_type in MFT_TIMESTAMP_COLUMNS:
                ts = parse_timestamp(row.get(col, ""))
                if ts and apply_time_filters(ts, filters):
                    events.append({
                        "Timestamp": ts,
                        "Source": "MFT",
                        "EventType": event_type,
                        "EntryNumber": entry_number,
                        "FileName": filename,
                        "Extension": extension,
                        "FullPath": full_path,
                        "Details": details,
                    })

    return events


def load_usn_events(usn_path, filters):
    """Extract timeline events from USN Journal CSV."""
    events = []
    with open(usn_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            filename = row.get("Name", "")
            parent_path = row.get("ParentPath", "")
            extension = row.get("Extension", "")
            entry_number = row.get("EntryNumber", "")
            full_path = build_full_path(parent_path, filename)

            if not apply_filters(full_path, extension, filters):
                continue

            ts = parse_timestamp(row.get("UpdateTimestamp", ""))
            if not ts or not apply_time_filters(ts, filters):
                continue

            reasons = row.get("UpdateReasons", "")

            events.append({
                "Timestamp": ts,
                "Source": "USN",
                "EventType": reasons,
                "EntryNumber": entry_number,
                "FileName": filename,
                "Extension": extension,
                "FullPath": full_path,
                "Details": row.get("FileAttributes", ""),
            })

    return events


def apply_filters(full_path, extension, filters):
    """Apply path and extension filters."""
    if filters.get("path"):
        if filters["path"].lower() not in full_path.lower():
            return False
    if filters.get("extensions"):
        if extension.lower() not in filters["extensions"]:
            return False
    return True


def apply_time_filters(ts, filters):
    """Apply start/end time filters."""
    if filters.get("start") and ts < filters["start"]:
        return False
    if filters.get("end") and ts > filters["end"]:
        return False
    return True


def parse_date_arg(date_str):
    """Parse a date argument (yyyy-MM-dd or yyyy-MM-dd HH:mm:ss)."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    print(f"Error: Cannot parse date '{date_str}'. Use yyyy-MM-dd or yyyy-MM-dd HH:mm:ss", file=sys.stderr)
    sys.exit(1)


def format_timestamp(ts):
    """Format timestamp for output."""
    return ts.strftime("%Y-%m-%d %H:%M:%S.%f")


def print_table(events, limit=None):
    """Print events as a formatted table to stdout."""
    if not events:
        print("No events found matching the filters.")
        return

    display = events[:limit] if limit else events

    # Calculate column widths
    widths = {h: len(h) for h in TIMELINE_HEADERS}
    for e in display:
        for h in TIMELINE_HEADERS:
            val = format_timestamp(e[h]) if h == "Timestamp" else str(e.get(h, ""))
            widths[h] = max(widths[h], min(len(val), 80))

    # Print header
    header_line = " | ".join(h.ljust(widths[h]) for h in TIMELINE_HEADERS)
    print(header_line)
    print("-" * len(header_line))

    # Print rows
    for e in display:
        row_parts = []
        for h in TIMELINE_HEADERS:
            val = format_timestamp(e[h]) if h == "Timestamp" else str(e.get(h, ""))
            row_parts.append(val.ljust(widths[h])[:widths[h]])
        print(" | ".join(row_parts))

    total = len(events)
    shown = len(display)
    if shown < total:
        print(f"\n... showing {shown} of {total} events. Use -o to export all, or --limit to adjust.")
    else:
        print(f"\nTotal: {total} events")


def write_csv(events, output_path):
    """Write events to CSV file."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=TIMELINE_HEADERS)
        writer.writeheader()
        for e in events:
            row = dict(e)
            row["Timestamp"] = format_timestamp(e["Timestamp"])
            writer.writerow(row)
    print(f"Written {len(events)} events to {output_path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="ResidentReaper Timeline Builder - Unified chronological timeline from MFT/USN CSVs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python timeline.py --mft mft.csv --usn usn.csv
  python timeline.py --mft mft.csv --start 2026-01-01 --end 2026-03-08
  python timeline.py --usn usn.csv --path "Users\\\\Admin" --ext .exe,.dll
  python timeline.py --mft mft.csv -o timeline.csv --limit 0
""",
    )
    parser.add_argument("--mft", help="Path to MFT CSV file")
    parser.add_argument("--usn", help="Path to USN Journal CSV file")
    parser.add_argument("-o", "--output", help="Output CSV file (default: print to stdout)")
    parser.add_argument("--start", help="Start date filter (yyyy-MM-dd or yyyy-MM-dd HH:mm:ss)")
    parser.add_argument("--end", help="End date filter (yyyy-MM-dd or yyyy-MM-dd HH:mm:ss)")
    parser.add_argument("--path", help="Filter by path substring (case-insensitive)")
    parser.add_argument("--ext", help="Filter by extension (comma-separated, e.g. .exe,.dll)")
    parser.add_argument("--limit", type=int, default=1000, help="Max rows to display in stdout mode (0=unlimited, default: 1000)")

    args = parser.parse_args()

    if not args.mft and not args.usn:
        parser.error("At least one of --mft or --usn is required")

    # Build filters
    filters = {}
    if args.start:
        filters["start"] = parse_date_arg(args.start)
    if args.end:
        filters["end"] = parse_date_arg(args.end)
    if args.path:
        filters["path"] = args.path
    if args.ext:
        filters["extensions"] = {e.strip().lower() for e in args.ext.split(",")}

    # Collect events
    events = []
    if args.mft:
        print(f"Loading MFT: {args.mft}", file=sys.stderr)
        events.extend(load_mft_events(args.mft, filters))
        print(f"  {len(events)} MFT events", file=sys.stderr)

    usn_start = len(events)
    if args.usn:
        print(f"Loading USN: {args.usn}", file=sys.stderr)
        events.extend(load_usn_events(args.usn, filters))
        print(f"  {len(events) - usn_start} USN events", file=sys.stderr)

    # Sort chronologically
    events.sort(key=lambda e: e["Timestamp"])

    print(f"Total: {len(events)} timeline events", file=sys.stderr)

    # Output
    if args.output:
        write_csv(events, args.output)
    else:
        limit = args.limit if args.limit > 0 else None
        print_table(events, limit=limit)


if __name__ == "__main__":
    main()
